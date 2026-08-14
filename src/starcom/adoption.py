from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import json
import re
import sqlite3
from typing import Any, Mapping

from .canonical import canonical_json, sha256_digest, utc_now
from .continuity import ContinuityService
from .db import Database
from .errors import (
    AuthorizationError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    StateTransitionError,
    ValidationError,
)
from .ledger import EventLedger
from .qualification import QualificationArtifactKind, QualificationLab
from .qualification_decision import (
    C3DecisionRecord,
    C3DecisionService,
    C3DecisionVerdict,
)
from .trust import AuthorizationDecision, TrustPlane


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ROLLBACK_FIELDS = frozenset(
    {
        "strategy",
        "steps",
        "verification_steps",
        "abort_conditions",
        "requires_separate_execution_authorization",
    }
)


class C3AdoptionStatus(str, Enum):
    AUTHORIZED_NOT_EXECUTED = "C3_ADOPTION_AUTHORIZED_NOT_EXECUTED"


@dataclass(frozen=True)
class C3AdoptionPreparation:
    c3_run_id: str
    c3_decision_id: str
    candidate_artifact_id: str
    candidate_material_sha256: str
    decision_payload_sha256: str
    qualification_head_hash: str
    rollback_plan: Mapping[str, Any]
    rollback_plan_json: str
    rollback_plan_sha256: str
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]


@dataclass(frozen=True)
class C3AdoptionRecord:
    adoption_id: str
    c3_run_id: str
    c3_decision_id: str
    candidate_artifact_id: str
    candidate_material_sha256: str
    decision_payload_sha256: str
    qualification_head_hash: str
    authorization_decision_id: str
    rollback_plan: Mapping[str, Any]
    rollback_plan_sha256: str
    status: C3AdoptionStatus
    authorized_at: str
    authorized_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C3AdoptionVerification:
    adoption_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C3AdoptionService:
    """Authorize one selected C3 candidate without executing adoption."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        trust: TrustPlane,
        continuity: ContinuityService,
        decisions: C3DecisionService,
        qualification: QualificationLab,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self.continuity = continuity
        self.decisions = decisions
        self.qualification = qualification
        self._initialize_schema()

    @staticmethod
    def _required_text(value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{field} must be a non-empty string")
        return value

    @staticmethod
    def _timestamp(value: object, field: str = "timestamp") -> str:
        if not isinstance(value, str):
            raise ValidationError(f"{field} must be RFC 3339")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError(f"{field} must be RFC 3339") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValidationError(f"{field} must be timezone-aware")
        return value

    @staticmethod
    def _as_datetime(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    @staticmethod
    def _string_list(value: object, field: str) -> list[str]:
        if (
            not isinstance(value, list)
            or not value
            or not all(isinstance(item, str) and item.strip() for item in value)
        ):
            raise ValidationError(
                f"{field} must be a non-empty list of non-empty strings"
            )
        return list(value)

    @classmethod
    def _rollback_contract(
        cls,
        rollback_plan: Mapping[str, Any],
    ) -> tuple[dict[str, object], str, str]:
        if not isinstance(rollback_plan, Mapping):
            raise ValidationError("rollback_plan must be a JSON object")
        observed = frozenset(rollback_plan)
        if observed != _ROLLBACK_FIELDS:
            raise ValidationError(
                "rollback_plan fields do not match the required contract",
                {
                    "missing": sorted(_ROLLBACK_FIELDS - observed),
                    "unexpected": sorted(observed - _ROLLBACK_FIELDS),
                },
            )
        strategy = cls._required_text(rollback_plan["strategy"], "strategy")
        steps = cls._string_list(rollback_plan["steps"], "steps")
        verification_steps = cls._string_list(
            rollback_plan["verification_steps"],
            "verification_steps",
        )
        abort_conditions = cls._string_list(
            rollback_plan["abort_conditions"],
            "abort_conditions",
        )
        separate = rollback_plan["requires_separate_execution_authorization"]
        if type(separate) is not bool or separate is not True:
            raise ValidationError(
                "requires_separate_execution_authorization must be exactly true"
            )
        normalized: dict[str, object] = {
            "strategy": strategy,
            "steps": steps,
            "verification_steps": verification_steps,
            "abort_conditions": abort_conditions,
            "requires_separate_execution_authorization": True,
        }
        rollback_plan_json = canonical_json(normalized)
        return normalized, rollback_plan_json, sha256_digest(normalized)

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c3_adoptions (
                    adoption_id TEXT PRIMARY KEY,
                    c3_run_id TEXT NOT NULL UNIQUE,
                    c3_decision_id TEXT NOT NULL UNIQUE,
                    candidate_artifact_id TEXT NOT NULL,
                    candidate_material_sha256 TEXT NOT NULL
                        CHECK (length(candidate_material_sha256) = 64),
                    decision_payload_sha256 TEXT NOT NULL
                        CHECK (length(decision_payload_sha256) = 64),
                    qualification_head_hash TEXT NOT NULL
                        CHECK (length(qualification_head_hash) = 64),
                    authorization_decision_id TEXT NOT NULL UNIQUE,
                    rollback_plan_json TEXT NOT NULL,
                    rollback_plan_sha256 TEXT NOT NULL
                        CHECK (length(rollback_plan_sha256) = 64),
                    status TEXT NOT NULL CHECK (
                        status = 'C3_ADOPTION_AUTHORIZED_NOT_EXECUTED'
                    ),
                    authorized_at TEXT NOT NULL,
                    authorized_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (c3_run_id)
                        REFERENCES c3_qualification_bindings(c3_run_id),
                    FOREIGN KEY (c3_decision_id)
                        REFERENCES c3_decisions(decision_id),
                    FOREIGN KEY (candidate_artifact_id)
                        REFERENCES qualification_artifacts(artifact_id),
                    FOREIGN KEY (authorization_decision_id)
                        REFERENCES trust_decisions(decision_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS c3_adoptions_no_update
                BEFORE UPDATE ON c3_adoptions
                BEGIN
                    SELECT RAISE(ABORT, 'c3 adoption authorizations are immutable');
                END
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS c3_adoptions_no_delete
                BEFORE DELETE ON c3_adoptions
                BEGIN
                    SELECT RAISE(ABORT, 'c3 adoption authorizations are immutable');
                END
                """
            )

    @staticmethod
    def _record_from_row(row: sqlite3.Row) -> C3AdoptionRecord:
        try:
            rollback_plan = json.loads(str(row["rollback_plan_json"]))
        except (json.JSONDecodeError, TypeError) as exc:
            raise IntegrityError(
                "stored C3 adoption rollback plan is invalid",
                {"adoption_id": str(row["adoption_id"])},
            ) from exc
        if not isinstance(rollback_plan, dict):
            raise IntegrityError(
                "stored C3 adoption rollback plan is invalid",
                {"adoption_id": str(row["adoption_id"])},
            )
        return C3AdoptionRecord(
            adoption_id=str(row["adoption_id"]),
            c3_run_id=str(row["c3_run_id"]),
            c3_decision_id=str(row["c3_decision_id"]),
            candidate_artifact_id=str(row["candidate_artifact_id"]),
            candidate_material_sha256=str(row["candidate_material_sha256"]),
            decision_payload_sha256=str(row["decision_payload_sha256"]),
            qualification_head_hash=str(row["qualification_head_hash"]),
            authorization_decision_id=str(row["authorization_decision_id"]),
            rollback_plan=rollback_plan,
            rollback_plan_sha256=str(row["rollback_plan_sha256"]),
            status=C3AdoptionStatus(str(row["status"])),
            authorized_at=str(row["authorized_at"]),
            authorized_by=str(row["authorized_by"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def get_adoption(self, adoption_id: str) -> C3AdoptionRecord:
        adoption_id = self._required_text(adoption_id, "adoption_id")
        row = self.database.connection.execute(
            "SELECT * FROM c3_adoptions WHERE adoption_id = ?",
            (adoption_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C3 adoption authorization does not exist",
                {"adoption_id": adoption_id},
            )
        return self._record_from_row(row)

    def _decision_for_run(self, c3_run_id: str) -> C3DecisionRecord:
        row = self.database.connection.execute(
            "SELECT decision_id FROM c3_decisions WHERE c3_run_id = ?",
            (c3_run_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C3 signed decision does not exist for the run",
                {"c3_run_id": c3_run_id},
            )
        decision_id = str(row["decision_id"])
        verification = self.decisions.verify_decision(decision_id)
        if not verification.ok:
            raise IntegrityError(
                "C3 signed decision verification failed",
                {
                    "decision_id": decision_id,
                    "defects": list(verification.defects),
                },
            )
        return self.decisions.get_decision(decision_id)

    def _selected_candidate(
        self,
        decision: C3DecisionRecord,
    ) -> tuple[str, str]:
        candidate_id = decision.selected_candidate_artifact_id
        if (
            decision.verdict is not C3DecisionVerdict.CANDIDATE_SELECTED
            or candidate_id is None
        ):
            raise StateTransitionError(
                "C3 adoption authorization requires a selected C3 candidate"
            )
        frozen = self.database.connection.execute(
            """
            SELECT * FROM c3_decision_evidence
            WHERE decision_id = ? AND kind = 'CANDIDATE' AND artifact_id = ?
            """,
            (decision.decision_id, candidate_id),
        ).fetchone()
        if frozen is None:
            raise IntegrityError(
                "selected candidate is missing from the signed decision evidence",
                {
                    "decision_id": decision.decision_id,
                    "candidate_artifact_id": candidate_id,
                },
            )
        artifact = self.qualification.get_artifact(candidate_id)
        frozen_digest = str(frozen["material_sha256"])
        if (
            artifact.kind is not QualificationArtifactKind.CANDIDATE
            or artifact.qualification_run_id != decision.qualification_run_id
            or artifact.material_sha256 != frozen_digest
        ):
            raise IntegrityError(
                "selected candidate material does not match the signed decision",
                {
                    "decision_id": decision.decision_id,
                    "candidate_artifact_id": candidate_id,
                },
            )
        return candidate_id, frozen_digest

    def prepare(
        self,
        c3_run_id: str,
        rollback_plan: Mapping[str, Any],
    ) -> C3AdoptionPreparation:
        c3_run_id = self._required_text(c3_run_id, "c3_run_id")
        normalized, rollback_plan_json, rollback_plan_sha256 = (
            self._rollback_contract(rollback_plan)
        )
        decision = self._decision_for_run(c3_run_id)
        candidate_id, candidate_digest = self._selected_candidate(decision)
        action = "c3.adoption.authorize"
        resource = f"continuity:c3:{c3_run_id}:adoption:{candidate_id}"
        context = {
            "authorization_mode": "AUTHORIZE_ONLY_NOT_EXECUTE",
            "c3_decision_id": decision.decision_id,
            "candidate_artifact_id": candidate_id,
            "candidate_material_sha256": candidate_digest,
            "decision_payload_sha256": decision.payload_sha256,
            "qualification_head_hash": decision.qualification_head_hash,
            "rollback_plan_sha256": rollback_plan_sha256,
        }
        return C3AdoptionPreparation(
            c3_run_id=c3_run_id,
            c3_decision_id=decision.decision_id,
            candidate_artifact_id=candidate_id,
            candidate_material_sha256=candidate_digest,
            decision_payload_sha256=decision.payload_sha256,
            qualification_head_hash=decision.qualification_head_hash,
            rollback_plan=normalized,
            rollback_plan_json=rollback_plan_json,
            rollback_plan_sha256=rollback_plan_sha256,
            action=action,
            resource=resource,
            mission_id=c3_run_id,
            context=context,
        )

    @staticmethod
    def _expected_request(
        preparation: C3AdoptionPreparation,
        actor: str,
    ) -> tuple[str, str, str, str, dict[str, object]]:
        return (
            actor,
            preparation.action,
            preparation.resource,
            preparation.mission_id,
            dict(preparation.context),
        )

    def _assert_authorization(
        self,
        authorization_decision_id: str,
        *,
        preparation: C3AdoptionPreparation,
        actor: str,
    ) -> AuthorizationDecision:
        verification = self.trust.verify_decision(authorization_decision_id)
        if not verification.ok:
            raise AuthorizationError(
                "C3 adoption authorization decision failed verification",
                {
                    "decision_id": authorization_decision_id,
                    "defects": list(verification.defects),
                },
            )
        try:
            decision = self.trust.get_decision(authorization_decision_id)
        except NotFoundError as exc:
            raise AuthorizationError(
                "C3 adoption authorization decision does not exist"
            ) from exc
        expected = self._expected_request(preparation, actor)
        observed = (
            decision.request.subject,
            decision.request.action,
            decision.request.resource,
            decision.request.mission_id,
            dict(decision.request.context),
        )
        if not decision.allowed or observed != expected:
            raise AuthorizationError(
                "authorization decision does not exactly match C3 adoption",
                {
                    "decision_id": authorization_decision_id,
                    "allowed": decision.allowed,
                    "expected": list(expected),
                    "observed": list(observed),
                },
            )
        return decision

    @staticmethod
    def _ledger_payload(record: C3AdoptionRecord) -> dict[str, object]:
        return {
            "adoption_id": record.adoption_id,
            "authorization_decision_id": record.authorization_decision_id,
            "c3_decision_id": record.c3_decision_id,
            "c3_run_id": record.c3_run_id,
            "candidate_artifact_id": record.candidate_artifact_id,
            "candidate_material_sha256": record.candidate_material_sha256,
            "decision_payload_sha256": record.decision_payload_sha256,
            "qualification_head_hash": record.qualification_head_hash,
            "rollback_plan_sha256": record.rollback_plan_sha256,
            "status": record.status.value,
        }

    @staticmethod
    def _chronology(
        decision: C3DecisionRecord,
        authorization: AuthorizationDecision,
        authorized_at: str,
    ) -> None:
        if C3AdoptionService._as_datetime(authorization.decided_at) < (
            C3AdoptionService._as_datetime(decision.admitted_at)
        ):
            raise StateTransitionError(
                "authorization predates the signed C3 decision admission"
            )
        if C3AdoptionService._as_datetime(authorized_at) < (
            C3AdoptionService._as_datetime(authorization.decided_at)
        ):
            raise StateTransitionError(
                "adoption authorization predates the TrustPlane decision"
            )

    def _authorization_consumption(
        self,
        authorization_decision_id: str,
    ) -> sqlite3.Row | None:
        return self.database.connection.execute(
            """
            SELECT * FROM continuity_authorization_consumptions
            WHERE decision_id = ?
            """,
            (authorization_decision_id,),
        ).fetchone()

    def authorize_adoption(
        self,
        adoption_id: str,
        *,
        c3_run_id: str,
        authorization_decision_id: str,
        rollback_plan: Mapping[str, Any],
        actor: str,
        occurred_at: str | None = None,
    ) -> C3AdoptionRecord:
        adoption_id = self._required_text(adoption_id, "adoption_id")
        c3_run_id = self._required_text(c3_run_id, "c3_run_id")
        authorization_decision_id = self._required_text(
            authorization_decision_id,
            "authorization_decision_id",
        )
        actor = self._required_text(actor, "actor")
        authorized_at = self._timestamp(occurred_at or utc_now())
        preparation = self.prepare(c3_run_id, rollback_plan)
        decision = self.decisions.get_decision(preparation.c3_decision_id)
        authorization = self._assert_authorization(
            authorization_decision_id,
            preparation=preparation,
            actor=actor,
        )
        self._chronology(decision, authorization, authorized_at)

        existing = self.database.connection.execute(
            "SELECT * FROM c3_adoptions WHERE adoption_id = ?",
            (adoption_id,),
        ).fetchone()
        if existing is not None:
            exact = (
                str(existing["c3_run_id"]) == c3_run_id
                and str(existing["c3_decision_id"]) == preparation.c3_decision_id
                and str(existing["candidate_artifact_id"])
                == preparation.candidate_artifact_id
                and str(existing["candidate_material_sha256"])
                == preparation.candidate_material_sha256
                and str(existing["decision_payload_sha256"])
                == preparation.decision_payload_sha256
                and str(existing["qualification_head_hash"])
                == preparation.qualification_head_hash
                and str(existing["authorization_decision_id"])
                == authorization_decision_id
                and str(existing["rollback_plan_json"])
                == preparation.rollback_plan_json
                and str(existing["rollback_plan_sha256"])
                == preparation.rollback_plan_sha256
                and str(existing["authorized_by"]) == actor
            )
            if not exact:
                raise ConflictError(
                    "adoption_id was reused with different authorization material",
                    {"adoption_id": adoption_id},
                )
            verification = self.verify_adoption(adoption_id)
            if not verification.ok:
                raise IntegrityError(
                    "existing C3 adoption authorization failed verification",
                    {
                        "adoption_id": adoption_id,
                        "defects": list(verification.defects),
                    },
                )
            return self._record_from_row(existing)

        consumption = self._authorization_consumption(
            authorization_decision_id
        )
        if consumption is not None:
            raise AuthorizationError(
                "authorization decision or operation was already consumed",
                {
                    "decision_id": authorization_decision_id,
                    "operation_id": str(consumption["operation_id"]),
                },
            )

        competitor = self.database.connection.execute(
            """
            SELECT adoption_id FROM c3_adoptions
            WHERE c3_run_id = ? OR c3_decision_id = ?
            """,
            (c3_run_id, preparation.c3_decision_id),
        ).fetchone()
        if competitor is not None:
            raise ConflictError(
                "C3 run or signed decision already has an adoption authorization",
                {
                    "c3_run_id": c3_run_id,
                    "adoption_id": str(competitor["adoption_id"]),
                },
            )

        try:
            with self.database.transaction() as connection:
                race = connection.execute(
                    """
                    SELECT adoption_id FROM c3_adoptions
                    WHERE adoption_id = ? OR c3_run_id = ?
                       OR c3_decision_id = ? OR authorization_decision_id = ?
                    """,
                    (
                        adoption_id,
                        c3_run_id,
                        preparation.c3_decision_id,
                        authorization_decision_id,
                    ),
                ).fetchone()
                if race is not None:
                    raise ConflictError(
                        "C3 adoption authorization appeared during admission",
                        {"adoption_id": str(race["adoption_id"])},
                    )
                current_preparation = self.prepare(c3_run_id, rollback_plan)
                if current_preparation != preparation:
                    raise ConflictError(
                        "C3 adoption material changed during authorization",
                        {"c3_run_id": c3_run_id},
                    )
                current_decision = self.decisions.get_decision(
                    current_preparation.c3_decision_id
                )
                current_authorization = self._assert_authorization(
                    authorization_decision_id,
                    preparation=current_preparation,
                    actor=actor,
                )
                self._chronology(
                    current_decision,
                    current_authorization,
                    authorized_at,
                )
                self.continuity._consume_authorization(
                    connection,
                    decision_id=authorization_decision_id,
                    operation_kind="C3_ADOPTION_AUTHORIZED",
                    operation_id=adoption_id,
                    actor=actor,
                    occurred_at=authorized_at,
                )
                provisional = C3AdoptionRecord(
                    adoption_id=adoption_id,
                    c3_run_id=c3_run_id,
                    c3_decision_id=current_preparation.c3_decision_id,
                    candidate_artifact_id=(
                        current_preparation.candidate_artifact_id
                    ),
                    candidate_material_sha256=(
                        current_preparation.candidate_material_sha256
                    ),
                    decision_payload_sha256=(
                        current_preparation.decision_payload_sha256
                    ),
                    qualification_head_hash=(
                        current_preparation.qualification_head_hash
                    ),
                    authorization_decision_id=authorization_decision_id,
                    rollback_plan=dict(current_preparation.rollback_plan),
                    rollback_plan_sha256=(
                        current_preparation.rollback_plan_sha256
                    ),
                    status=C3AdoptionStatus.AUTHORIZED_NOT_EXECUTED,
                    authorized_at=authorized_at,
                    authorized_by=actor,
                    ledger_event_id="pending",
                    ledger_hash="pending",
                )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"continuity:c3:{c3_run_id}:adoption",
                    C3AdoptionStatus.AUTHORIZED_NOT_EXECUTED.value,
                    self._ledger_payload(provisional),
                    actor=actor,
                    occurred_at=authorized_at,
                )
                connection.execute(
                    """
                    INSERT INTO c3_adoptions (
                        adoption_id, c3_run_id, c3_decision_id,
                        candidate_artifact_id, candidate_material_sha256,
                        decision_payload_sha256, qualification_head_hash,
                        authorization_decision_id, rollback_plan_json,
                        rollback_plan_sha256, status, authorized_at,
                        authorized_by, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        adoption_id,
                        c3_run_id,
                        current_preparation.c3_decision_id,
                        current_preparation.candidate_artifact_id,
                        current_preparation.candidate_material_sha256,
                        current_preparation.decision_payload_sha256,
                        current_preparation.qualification_head_hash,
                        authorization_decision_id,
                        current_preparation.rollback_plan_json,
                        current_preparation.rollback_plan_sha256,
                        C3AdoptionStatus.AUTHORIZED_NOT_EXECUTED.value,
                        authorized_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "C3 adoption authorization conflicts with immutable state",
                {
                    "adoption_id": adoption_id,
                    "c3_run_id": c3_run_id,
                },
            ) from exc
        return self.get_adoption(adoption_id)

    def _expected_preparation_from_record(
        self,
        record: C3AdoptionRecord,
        rollback_plan_json: str,
    ) -> C3AdoptionPreparation:
        return C3AdoptionPreparation(
            c3_run_id=record.c3_run_id,
            c3_decision_id=record.c3_decision_id,
            candidate_artifact_id=record.candidate_artifact_id,
            candidate_material_sha256=record.candidate_material_sha256,
            decision_payload_sha256=record.decision_payload_sha256,
            qualification_head_hash=record.qualification_head_hash,
            rollback_plan=dict(record.rollback_plan),
            rollback_plan_json=rollback_plan_json,
            rollback_plan_sha256=record.rollback_plan_sha256,
            action="c3.adoption.authorize",
            resource=(
                f"continuity:c3:{record.c3_run_id}:adoption:"
                f"{record.candidate_artifact_id}"
            ),
            mission_id=record.c3_run_id,
            context={
                "authorization_mode": "AUTHORIZE_ONLY_NOT_EXECUTE",
                "c3_decision_id": record.c3_decision_id,
                "candidate_artifact_id": record.candidate_artifact_id,
                "candidate_material_sha256": (
                    record.candidate_material_sha256
                ),
                "decision_payload_sha256": record.decision_payload_sha256,
                "qualification_head_hash": record.qualification_head_hash,
                "rollback_plan_sha256": record.rollback_plan_sha256,
            },
        )

    def verify_adoption(self, adoption_id: str) -> C3AdoptionVerification:
        adoption_id = self._required_text(adoption_id, "adoption_id")
        row = self.database.connection.execute(
            "SELECT * FROM c3_adoptions WHERE adoption_id = ?",
            (adoption_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C3 adoption authorization does not exist",
                {"adoption_id": adoption_id},
            )
        defects: list[str] = []
        try:
            record = self._record_from_row(row)
        except (IntegrityError, ValueError):
            defects.append("C3_ADOPTION_ROLLBACK_INVALID")
            rollback_plan: dict[str, object] = {}
            rollback_json = str(row["rollback_plan_json"])
            record = C3AdoptionRecord(
                adoption_id=str(row["adoption_id"]),
                c3_run_id=str(row["c3_run_id"]),
                c3_decision_id=str(row["c3_decision_id"]),
                candidate_artifact_id=str(row["candidate_artifact_id"]),
                candidate_material_sha256=str(
                    row["candidate_material_sha256"]
                ),
                decision_payload_sha256=str(
                    row["decision_payload_sha256"]
                ),
                qualification_head_hash=str(row["qualification_head_hash"]),
                authorization_decision_id=str(
                    row["authorization_decision_id"]
                ),
                rollback_plan=rollback_plan,
                rollback_plan_sha256=str(row["rollback_plan_sha256"]),
                status=C3AdoptionStatus.AUTHORIZED_NOT_EXECUTED,
                authorized_at=str(row["authorized_at"]),
                authorized_by=str(row["authorized_by"]),
                ledger_event_id=str(row["ledger_event_id"]),
                ledger_hash=str(row["ledger_hash"]),
            )
        else:
            rollback_json = str(row["rollback_plan_json"])
            try:
                normalized, canonical_rollback, rollback_digest = (
                    self._rollback_contract(record.rollback_plan)
                )
            except ValidationError:
                defects.append("C3_ADOPTION_ROLLBACK_INVALID")
            else:
                if canonical_rollback != rollback_json:
                    defects.append("C3_ADOPTION_ROLLBACK_NOT_CANONICAL")
                if rollback_digest != record.rollback_plan_sha256:
                    defects.append("C3_ADOPTION_ROLLBACK_SHA256_MISMATCH")
                record = C3AdoptionRecord(
                    **{
                        **record.__dict__,
                        "rollback_plan": normalized,
                    }
                )

        if str(row["status"]) != C3AdoptionStatus.AUTHORIZED_NOT_EXECUTED.value:
            defects.append("C3_ADOPTION_STATUS_INVALID")
        for field in (
            "candidate_material_sha256",
            "decision_payload_sha256",
            "qualification_head_hash",
            "rollback_plan_sha256",
            "ledger_hash",
        ):
            if not _SHA256.fullmatch(str(row[field])):
                defects.append(f"C3_ADOPTION_{field.upper()}_INVALID")

        decision_verification = self.decisions.verify_decision(
            record.c3_decision_id
        )
        defects.extend(
            f"C3_ADOPTION_DECISION:{defect}"
            for defect in decision_verification.defects
        )
        decision: C3DecisionRecord | None = None
        try:
            decision = self.decisions.get_decision(record.c3_decision_id)
        except NotFoundError:
            defects.append("C3_ADOPTION_DECISION_MISSING")
        if decision is not None:
            if decision.c3_run_id != record.c3_run_id:
                defects.append("C3_ADOPTION_DECISION_RUN_MISMATCH")
            if (
                decision.verdict is not C3DecisionVerdict.CANDIDATE_SELECTED
                or decision.selected_candidate_artifact_id
                != record.candidate_artifact_id
            ):
                defects.append("C3_ADOPTION_SELECTED_CANDIDATE_MISMATCH")
            if decision.payload_sha256 != record.decision_payload_sha256:
                defects.append("C3_ADOPTION_DECISION_PAYLOAD_SHA256_MISMATCH")
            if decision.qualification_head_hash != record.qualification_head_hash:
                defects.append("C3_ADOPTION_QUALIFICATION_HEAD_MISMATCH")

        frozen = self.database.connection.execute(
            """
            SELECT * FROM c3_decision_evidence
            WHERE decision_id = ? AND kind = 'CANDIDATE' AND artifact_id = ?
            """,
            (record.c3_decision_id, record.candidate_artifact_id),
        ).fetchone()
        if frozen is None:
            defects.append("C3_ADOPTION_FROZEN_CANDIDATE_MISSING")
        else:
            if str(frozen["material_sha256"]) != (
                record.candidate_material_sha256
            ):
                defects.append("C3_ADOPTION_FROZEN_CANDIDATE_DIGEST_MISMATCH")
        try:
            artifact = self.qualification.get_artifact(
                record.candidate_artifact_id
            )
        except NotFoundError:
            defects.append("C3_ADOPTION_CANDIDATE_MISSING")
        else:
            if artifact.kind is not QualificationArtifactKind.CANDIDATE:
                defects.append("C3_ADOPTION_CANDIDATE_KIND_MISMATCH")
            if artifact.material_sha256 != record.candidate_material_sha256:
                defects.append("C3_ADOPTION_CANDIDATE_DIGEST_MISMATCH")

        authorization_verification = self.trust.verify_decision(
            record.authorization_decision_id
        )
        defects.extend(
            f"C3_ADOPTION_AUTHORIZATION:{defect}"
            for defect in authorization_verification.defects
        )
        authorization: AuthorizationDecision | None = None
        try:
            authorization = self.trust.get_decision(
                record.authorization_decision_id
            )
        except NotFoundError:
            defects.append("C3_ADOPTION_AUTHORIZATION_MISSING")

        preparation = self._expected_preparation_from_record(
            record,
            rollback_json,
        )
        if authorization is not None:
            expected = self._expected_request(
                preparation,
                record.authorized_by,
            )
            observed = (
                authorization.request.subject,
                authorization.request.action,
                authorization.request.resource,
                authorization.request.mission_id,
                dict(authorization.request.context),
            )
            if not authorization.allowed or observed != expected:
                defects.append("C3_ADOPTION_AUTHORIZATION_REQUEST_MISMATCH")
            if decision is not None:
                if self._as_datetime(authorization.decided_at) < (
                    self._as_datetime(decision.admitted_at)
                ):
                    defects.append("C3_ADOPTION_AUTHORIZATION_PREDATES_DECISION")
            if self._as_datetime(record.authorized_at) < (
                self._as_datetime(authorization.decided_at)
            ):
                defects.append(
                    "C3_ADOPTION_AUTHORIZED_AT_PREDATES_AUTHORIZATION"
                )

        consumption = self._authorization_consumption(
            record.authorization_decision_id
        )
        if consumption is None:
            defects.append("C3_ADOPTION_AUTHORIZATION_CONSUMPTION_MISSING")
        else:
            expected_consumption = (
                "C3_ADOPTION_AUTHORIZED",
                record.adoption_id,
                record.authorized_at,
                record.authorized_by,
            )
            observed_consumption = (
                str(consumption["operation_kind"]),
                str(consumption["operation_id"]),
                str(consumption["consumed_at"]),
                str(consumption["consumed_by"]),
            )
            if observed_consumption != expected_consumption:
                defects.append(
                    "C3_ADOPTION_AUTHORIZATION_CONSUMPTION_MISMATCH"
                )

        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (record.ledger_event_id,),
        ).fetchone()
        stream = f"continuity:c3:{record.c3_run_id}:adoption"
        if event is None:
            defects.append("C3_ADOPTION_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != stream:
                defects.append("C3_ADOPTION_LEDGER_STREAM_MISMATCH")
            if str(event["kind"]) != record.status.value:
                defects.append("C3_ADOPTION_LEDGER_KIND_MISMATCH")
            if str(event["actor"]) != record.authorized_by:
                defects.append("C3_ADOPTION_LEDGER_ACTOR_MISMATCH")
            if str(event["occurred_at"]) != record.authorized_at:
                defects.append("C3_ADOPTION_LEDGER_TIMESTAMP_MISMATCH")
            if str(event["record_hash"]) != record.ledger_hash:
                defects.append("C3_ADOPTION_LEDGER_HASH_MISMATCH")
            try:
                event_payload = json.loads(str(event["payload_json"]))
            except (json.JSONDecodeError, TypeError):
                defects.append("C3_ADOPTION_LEDGER_PAYLOAD_INVALID")
            else:
                if event_payload != self._ledger_payload(record):
                    defects.append("C3_ADOPTION_LEDGER_PAYLOAD_MISMATCH")
        chain = self.ledger.verify(stream)
        defects.extend(
            f"C3_ADOPTION_LEDGER_CHAIN:{defect.code}"
            for defect in chain.defects
        )
        return C3AdoptionVerification(
            adoption_id=adoption_id,
            defects=tuple(dict.fromkeys(defects)),
        )
