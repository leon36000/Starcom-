from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import json
import re
import sqlite3
from typing import Any, Mapping, Protocol

from .adoption import C3AdoptionService, C3AdoptionStatus
from .canonical import canonical_json, sha256_digest, utc_now
from .continuity import ContinuityService
from .db import Database
from .durable import DurableOutbox, EffectLease, EffectStatus
from .errors import (
    AuthorizationError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    StateTransitionError,
    ValidationError,
)
from .ledger import EventLedger
from .trust import AuthorizationDecision, TrustPlane


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PLAN_FIELDS = frozenset(
    {
        "component_ref",
        "source_digest",
        "target_environment",
        "sandbox_profile",
        "preconditions",
        "postconditions",
        "requires_network",
        "network_allowlist",
        "requires_separate_rollback_authorization",
    }
)


class C3AdoptionExecutionStatus(str, Enum):
    REQUESTED_NOT_EXECUTED = "C3_ADOPTION_EXECUTION_REQUESTED_NOT_EXECUTED"
    RUNNING = "C3_ADOPTION_EXECUTION_RUNNING"
    SUCCEEDED = "C3_ADOPTION_EXECUTION_SUCCEEDED"
    FAILED_NO_EFFECT = "C3_ADOPTION_EXECUTION_FAILED_NO_EFFECT"
    FAILED_ROLLED_BACK = "C3_ADOPTION_EXECUTION_FAILED_ROLLED_BACK"
    ROLLBACK_FAILED = "C3_ADOPTION_EXECUTION_ROLLBACK_FAILED"

    @property
    def terminal(self) -> bool:
        return self in {
            self.SUCCEEDED,
            self.FAILED_NO_EFFECT,
            self.FAILED_ROLLED_BACK,
            self.ROLLBACK_FAILED,
        }


@dataclass(frozen=True)
class C3AdoptionExecutionPreparation:
    execution_id: str
    adoption_id: str
    c3_run_id: str
    c3_decision_id: str
    candidate_artifact_id: str
    candidate_material_sha256: str
    decision_payload_sha256: str
    qualification_head_hash: str
    rollback_plan_sha256: str
    executor_id: str
    execution_plan: Mapping[str, Any]
    execution_plan_json: str
    execution_plan_sha256: str
    outbox_effect_id: str
    idempotency_key: str
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]


@dataclass(frozen=True)
class C3AdoptionExecutionRecord:
    execution_id: str
    adoption_id: str
    c3_run_id: str
    c3_decision_id: str
    candidate_artifact_id: str
    candidate_material_sha256: str
    decision_payload_sha256: str
    qualification_head_hash: str
    rollback_plan_sha256: str
    executor_id: str
    execution_plan: Mapping[str, Any]
    execution_plan_sha256: str
    authorization_decision_id: str
    outbox_effect_id: str
    idempotency_key: str
    status: C3AdoptionExecutionStatus
    requested_at: str
    requested_by: str
    transition_sequence: int
    execution_receipt: Mapping[str, Any] | None
    execution_receipt_sha256: str | None
    rollback_receipt: Mapping[str, Any] | None
    rollback_receipt_sha256: str | None
    effect_started: bool
    error: str | None


@dataclass(frozen=True)
class C3ExecutorResult:
    succeeded: bool
    effect_started: bool
    pre_state_digest: str
    post_state_digest: str | None
    receipt: Mapping[str, Any]
    error: str | None = None


@dataclass(frozen=True)
class C3RollbackResult:
    succeeded: bool
    restored_state_digest: str | None
    receipt: Mapping[str, Any]
    error: str | None = None


@dataclass(frozen=True)
class C3AdoptionExecutionVerification:
    execution_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C3AdoptionExecutor(Protocol):
    executor_id: str

    def validate(self, request: C3AdoptionExecutionRecord) -> None: ...

    def execute(self, request: C3AdoptionExecutionRecord) -> C3ExecutorResult: ...

    def rollback(
        self,
        request: C3AdoptionExecutionRecord,
        execution_result: C3ExecutorResult | None,
        reason: str,
    ) -> C3RollbackResult: ...


class DisabledC3AdoptionExecutor:
    executor_id = "disabled"

    def validate(self, request: C3AdoptionExecutionRecord) -> None:
        raise StateTransitionError("C3 adoption execution is disabled")

    def execute(self, request: C3AdoptionExecutionRecord) -> C3ExecutorResult:
        raise StateTransitionError("C3 adoption execution is disabled")

    def rollback(
        self,
        request: C3AdoptionExecutionRecord,
        execution_result: C3ExecutorResult | None,
        reason: str,
    ) -> C3RollbackResult:
        return C3RollbackResult(
            succeeded=False,
            restored_state_digest=None,
            receipt={
                "executor_id": self.executor_id,
                "idempotency_key": request.idempotency_key,
                "reason": reason,
            },
            error="C3 adoption execution is disabled",
        )


class C3AdoptionExecutionService:
    """Separately authorize, persist, and verify durable C3 adoption execution."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        trust: TrustPlane,
        continuity: ContinuityService,
        adoption: C3AdoptionService,
        outbox: DurableOutbox,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self.continuity = continuity
        self.adoption = adoption
        self.outbox = outbox
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
    def _digest(value: object, field: str) -> str:
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
        return value

    @staticmethod
    def _string_list(
        value: object,
        field: str,
        *,
        allow_empty: bool = False,
    ) -> list[str]:
        if not isinstance(value, list) or (not allow_empty and not value):
            qualifier = "" if allow_empty else "non-empty "
            raise ValidationError(f"{field} must be a {qualifier}list")
        if not all(isinstance(item, str) and item.strip() for item in value):
            raise ValidationError(f"{field} must contain only non-empty strings")
        return list(value)

    @classmethod
    def _plan_contract(
        cls,
        execution_plan: Mapping[str, Any],
    ) -> tuple[dict[str, object], str, str]:
        if not isinstance(execution_plan, Mapping):
            raise ValidationError("execution_plan must be a JSON object")
        observed = frozenset(execution_plan)
        if observed != _PLAN_FIELDS:
            raise ValidationError(
                "execution_plan fields do not match the required contract",
                {
                    "missing": sorted(_PLAN_FIELDS - observed),
                    "unexpected": sorted(observed - _PLAN_FIELDS),
                },
            )
        requires_network = execution_plan["requires_network"]
        if type(requires_network) is not bool:
            raise ValidationError("requires_network must be a boolean")
        allowlist = cls._string_list(
            execution_plan["network_allowlist"],
            "network_allowlist",
            allow_empty=True,
        )
        if requires_network and not allowlist:
            raise ValidationError("network access requires a non-empty allowlist")
        if not requires_network and allowlist:
            raise ValidationError("network allowlist must be empty when network is disabled")
        rollback_authorization = execution_plan[
            "requires_separate_rollback_authorization"
        ]
        if type(rollback_authorization) is not bool or rollback_authorization is not False:
            raise ValidationError(
                "requires_separate_rollback_authorization must be exactly false"
            )
        normalized: dict[str, object] = {
            "component_ref": cls._required_text(
                execution_plan["component_ref"], "component_ref"
            ),
            "source_digest": cls._digest(
                execution_plan["source_digest"], "source_digest"
            ),
            "target_environment": cls._required_text(
                execution_plan["target_environment"], "target_environment"
            ),
            "sandbox_profile": cls._required_text(
                execution_plan["sandbox_profile"], "sandbox_profile"
            ),
            "preconditions": cls._string_list(
                execution_plan["preconditions"], "preconditions"
            ),
            "postconditions": cls._string_list(
                execution_plan["postconditions"], "postconditions"
            ),
            "requires_network": requires_network,
            "network_allowlist": allowlist,
            "requires_separate_rollback_authorization": False,
        }
        serialized = canonical_json(normalized)
        return normalized, serialized, sha256_digest(normalized)

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c3_adoption_execution_requests (
                    execution_id TEXT PRIMARY KEY,
                    adoption_id TEXT NOT NULL UNIQUE,
                    c3_run_id TEXT NOT NULL,
                    c3_decision_id TEXT NOT NULL,
                    candidate_artifact_id TEXT NOT NULL,
                    candidate_material_sha256 TEXT NOT NULL
                        CHECK (length(candidate_material_sha256) = 64),
                    decision_payload_sha256 TEXT NOT NULL
                        CHECK (length(decision_payload_sha256) = 64),
                    qualification_head_hash TEXT NOT NULL
                        CHECK (length(qualification_head_hash) = 64),
                    rollback_plan_sha256 TEXT NOT NULL
                        CHECK (length(rollback_plan_sha256) = 64),
                    executor_id TEXT NOT NULL,
                    execution_plan_json TEXT NOT NULL,
                    execution_plan_sha256 TEXT NOT NULL
                        CHECK (length(execution_plan_sha256) = 64),
                    authorization_decision_id TEXT NOT NULL UNIQUE,
                    outbox_effect_id TEXT NOT NULL UNIQUE,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    requested_at TEXT NOT NULL,
                    requested_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (adoption_id) REFERENCES c3_adoptions(adoption_id),
                    FOREIGN KEY (authorization_decision_id)
                        REFERENCES trust_decisions(decision_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c3_adoption_execution_transitions (
                    execution_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL CHECK (sequence >= 1),
                    status TEXT NOT NULL CHECK (status IN (
                        'C3_ADOPTION_EXECUTION_REQUESTED_NOT_EXECUTED',
                        'C3_ADOPTION_EXECUTION_RUNNING',
                        'C3_ADOPTION_EXECUTION_SUCCEEDED',
                        'C3_ADOPTION_EXECUTION_FAILED_NO_EFFECT',
                        'C3_ADOPTION_EXECUTION_FAILED_ROLLED_BACK',
                        'C3_ADOPTION_EXECUTION_ROLLBACK_FAILED'
                    )),
                    worker_id TEXT,
                    effect_started INTEGER NOT NULL CHECK (effect_started IN (0, 1)),
                    execution_receipt_json TEXT,
                    execution_receipt_sha256 TEXT,
                    rollback_receipt_json TEXT,
                    rollback_receipt_sha256 TEXT,
                    error TEXT,
                    occurred_at TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    PRIMARY KEY (execution_id, sequence),
                    FOREIGN KEY (execution_id)
                        REFERENCES c3_adoption_execution_requests(execution_id)
                )
                """
            )
            for table in (
                "c3_adoption_execution_requests",
                "c3_adoption_execution_transitions",
            ):
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {table}_no_update
                    BEFORE UPDATE ON {table}
                    BEGIN SELECT RAISE(ABORT, '{table} rows are immutable'); END
                    """
                )
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {table}_no_delete
                    BEFORE DELETE ON {table}
                    BEGIN SELECT RAISE(ABORT, '{table} rows are immutable'); END
                    """
                )

    def _clean_adoption(self, adoption_id: str):  # type: ignore[no-untyped-def]
        adoption = self.adoption.get_adoption(adoption_id)
        verification = self.adoption.verify_adoption(adoption_id)
        if not verification.ok:
            raise IntegrityError(
                "C3 adoption authorization verification failed",
                {"adoption_id": adoption_id, "defects": list(verification.defects)},
            )
        if adoption.status is not C3AdoptionStatus.AUTHORIZED_NOT_EXECUTED:
            raise StateTransitionError(
                "C3 adoption execution requires an authorized non-executed adoption"
            )
        return adoption

    @staticmethod
    def _effect_id(execution_id: str) -> str:
        return f"c3-adoption-execution:{execution_id}"

    @staticmethod
    def _idempotency_key(execution_id: str) -> str:
        return f"starcom:c3:adoption-execution:{execution_id}"

    def prepare(
        self,
        execution_id: str,
        *,
        adoption_id: str,
        executor_id: str,
        execution_plan: Mapping[str, Any],
    ) -> C3AdoptionExecutionPreparation:
        execution_id = self._required_text(execution_id, "execution_id")
        adoption_id = self._required_text(adoption_id, "adoption_id")
        executor_id = self._required_text(executor_id, "executor_id")
        plan, plan_json, plan_sha256 = self._plan_contract(execution_plan)
        adoption = self._clean_adoption(adoption_id)
        effect_id = self._effect_id(execution_id)
        idempotency_key = self._idempotency_key(execution_id)
        resource = (
            f"continuity:c3:{adoption.c3_run_id}:adoption:{adoption_id}:execution:"
            f"{adoption.candidate_artifact_id}"
        )
        context = {
            "execution_mode": "DURABLE_OUTBOX_SEPARATE_WORKER",
            "execution_id": execution_id,
            "adoption_id": adoption_id,
            "c3_decision_id": adoption.c3_decision_id,
            "candidate_artifact_id": adoption.candidate_artifact_id,
            "candidate_material_sha256": adoption.candidate_material_sha256,
            "decision_payload_sha256": adoption.decision_payload_sha256,
            "qualification_head_hash": adoption.qualification_head_hash,
            "rollback_plan_sha256": adoption.rollback_plan_sha256,
            "executor_id": executor_id,
            "execution_plan_sha256": plan_sha256,
            "outbox_effect_id": effect_id,
            "idempotency_key": idempotency_key,
        }
        return C3AdoptionExecutionPreparation(
            execution_id=execution_id,
            adoption_id=adoption_id,
            c3_run_id=adoption.c3_run_id,
            c3_decision_id=adoption.c3_decision_id,
            candidate_artifact_id=adoption.candidate_artifact_id,
            candidate_material_sha256=adoption.candidate_material_sha256,
            decision_payload_sha256=adoption.decision_payload_sha256,
            qualification_head_hash=adoption.qualification_head_hash,
            rollback_plan_sha256=adoption.rollback_plan_sha256,
            executor_id=executor_id,
            execution_plan=plan,
            execution_plan_json=plan_json,
            execution_plan_sha256=plan_sha256,
            outbox_effect_id=effect_id,
            idempotency_key=idempotency_key,
            action="c3.adoption.execute",
            resource=resource,
            mission_id=adoption.c3_run_id,
            context=context,
        )

    @staticmethod
    def _expected_authorization(
        preparation: C3AdoptionExecutionPreparation,
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
        decision_id: str,
        *,
        preparation: C3AdoptionExecutionPreparation,
        actor: str,
    ) -> AuthorizationDecision:
        verification = self.trust.verify_decision(decision_id)
        if not verification.ok:
            raise AuthorizationError(
                "C3 adoption execution decision failed verification",
                {"decision_id": decision_id, "defects": list(verification.defects)},
            )
        try:
            decision = self.trust.get_decision(decision_id)
        except NotFoundError as exc:
            raise AuthorizationError(
                "C3 adoption execution decision does not exist"
            ) from exc
        observed = (
            decision.request.subject,
            decision.request.action,
            decision.request.resource,
            decision.request.mission_id,
            dict(decision.request.context),
        )
        expected = self._expected_authorization(preparation, actor)
        if not decision.allowed or observed != expected:
            raise AuthorizationError(
                "authorization decision does not exactly match C3 adoption execution",
                {"decision_id": decision_id, "allowed": decision.allowed},
            )
        return decision

    def _consumption(self, decision_id: str) -> sqlite3.Row | None:
        return self.database.connection.execute(
            """
            SELECT * FROM continuity_authorization_consumptions
            WHERE decision_id = ?
            """,
            (decision_id,),
        ).fetchone()

    @staticmethod
    def _stream(value: C3AdoptionExecutionPreparation | C3AdoptionExecutionRecord) -> str:
        return (
            f"continuity:c3:{value.c3_run_id}:adoption:{value.adoption_id}:execution:"
            f"{value.execution_id}"
        )

    @staticmethod
    def _outbox_payload(
        preparation: C3AdoptionExecutionPreparation,
    ) -> dict[str, object]:
        return {
            "execution_id": preparation.execution_id,
            "adoption_id": preparation.adoption_id,
            "c3_run_id": preparation.c3_run_id,
            "candidate_artifact_id": preparation.candidate_artifact_id,
            "executor_id": preparation.executor_id,
            "execution_plan_sha256": preparation.execution_plan_sha256,
            "idempotency_key": preparation.idempotency_key,
        }

    @staticmethod
    def _event_payload(
        value: C3AdoptionExecutionPreparation | C3AdoptionExecutionRecord,
        authorization_decision_id: str,
        *,
        sequence: int,
        status: C3AdoptionExecutionStatus,
        worker_id: str | None,
        effect_started: bool,
        execution_receipt_sha256: str | None,
        rollback_receipt_sha256: str | None,
        error: str | None,
    ) -> dict[str, object]:
        return {
            "execution_id": value.execution_id,
            "adoption_id": value.adoption_id,
            "c3_run_id": value.c3_run_id,
            "c3_decision_id": value.c3_decision_id,
            "candidate_artifact_id": value.candidate_artifact_id,
            "candidate_material_sha256": value.candidate_material_sha256,
            "decision_payload_sha256": value.decision_payload_sha256,
            "qualification_head_hash": value.qualification_head_hash,
            "rollback_plan_sha256": value.rollback_plan_sha256,
            "executor_id": value.executor_id,
            "execution_plan_sha256": value.execution_plan_sha256,
            "authorization_decision_id": authorization_decision_id,
            "outbox_effect_id": value.outbox_effect_id,
            "idempotency_key": value.idempotency_key,
            "sequence": sequence,
            "status": status.value,
            "worker_id": worker_id,
            "effect_started": effect_started,
            "execution_receipt_sha256": execution_receipt_sha256,
            "rollback_receipt_sha256": rollback_receipt_sha256,
            "error": error,
        }

    def request_execution(
        self,
        execution_id: str,
        *,
        adoption_id: str,
        executor_id: str,
        execution_plan: Mapping[str, Any],
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> C3AdoptionExecutionRecord:
        authorization_decision_id = self._required_text(
            authorization_decision_id, "authorization_decision_id"
        )
        actor = self._required_text(actor, "actor")
        requested_at = self._timestamp(occurred_at or utc_now())
        preparation = self.prepare(
            execution_id,
            adoption_id=adoption_id,
            executor_id=executor_id,
            execution_plan=execution_plan,
        )
        existing = self.database.connection.execute(
            """
            SELECT * FROM c3_adoption_execution_requests
            WHERE execution_id = ?
            """,
            (preparation.execution_id,),
        ).fetchone()
        if existing is not None:
            exact = (
                str(existing["adoption_id"]) == preparation.adoption_id
                and str(existing["executor_id"]) == preparation.executor_id
                and str(existing["execution_plan_json"])
                == preparation.execution_plan_json
                and str(existing["authorization_decision_id"])
                == authorization_decision_id
                and str(existing["requested_by"]) == actor
            )
            if not exact:
                raise ConflictError(
                    "execution_id was reused with different execution material",
                    {"execution_id": preparation.execution_id},
                )
            verification = self.verify_execution(preparation.execution_id)
            if not verification.ok:
                raise IntegrityError(
                    "existing C3 adoption execution failed verification",
                    {
                        "execution_id": preparation.execution_id,
                        "defects": list(verification.defects),
                    },
                )
            return self.get_execution(preparation.execution_id)

        decision = self._assert_authorization(
            authorization_decision_id,
            preparation=preparation,
            actor=actor,
        )
        adoption = self.adoption.get_adoption(adoption_id)
        if self._as_datetime(decision.decided_at) < self._as_datetime(
            adoption.authorized_at
        ):
            raise StateTransitionError(
                "execution authorization predates adoption authorization"
            )
        if self._as_datetime(requested_at) < self._as_datetime(decision.decided_at):
            raise StateTransitionError(
                "execution request predates TrustPlane authorization"
            )

        competitor = self.database.connection.execute(
            """
            SELECT execution_id FROM c3_adoption_execution_requests
            WHERE adoption_id = ? OR authorization_decision_id = ?
               OR outbox_effect_id = ? OR idempotency_key = ?
            """,
            (
                preparation.adoption_id,
                authorization_decision_id,
                preparation.outbox_effect_id,
                preparation.idempotency_key,
            ),
        ).fetchone()
        if competitor is not None:
            raise ConflictError(
                "execution material is already bound",
                {"execution_id": str(competitor["execution_id"])},
            )
        if self._consumption(authorization_decision_id) is not None:
            raise AuthorizationError("authorization decision was already consumed")

        initial_payload = self._event_payload(
            preparation,
            authorization_decision_id,
            sequence=1,
            status=C3AdoptionExecutionStatus.REQUESTED_NOT_EXECUTED,
            worker_id=None,
            effect_started=False,
            execution_receipt_sha256=None,
            rollback_receipt_sha256=None,
            error=None,
        )
        try:
            with self.database.transaction() as connection:
                current = self.prepare(
                    execution_id,
                    adoption_id=adoption_id,
                    executor_id=executor_id,
                    execution_plan=execution_plan,
                )
                if current != preparation:
                    raise ConflictError(
                        "execution material changed during admission"
                    )
                current_decision = self._assert_authorization(
                    authorization_decision_id,
                    preparation=current,
                    actor=actor,
                )
                if self._as_datetime(requested_at) < self._as_datetime(
                    current_decision.decided_at
                ):
                    raise StateTransitionError(
                        "execution request predates TrustPlane authorization"
                    )
                self.continuity._consume_authorization(
                    connection,
                    decision_id=authorization_decision_id,
                    operation_kind="C3_ADOPTION_EXECUTION_REQUESTED",
                    operation_id=execution_id,
                    actor=actor,
                    occurred_at=requested_at,
                )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    self._stream(current),
                    C3AdoptionExecutionStatus.REQUESTED_NOT_EXECUTED.value,
                    initial_payload,
                    actor=actor,
                    occurred_at=requested_at,
                )
                connection.execute(
                    """
                    INSERT INTO c3_adoption_execution_requests (
                        execution_id, adoption_id, c3_run_id, c3_decision_id,
                        candidate_artifact_id, candidate_material_sha256,
                        decision_payload_sha256, qualification_head_hash,
                        rollback_plan_sha256, executor_id, execution_plan_json,
                        execution_plan_sha256, authorization_decision_id,
                        outbox_effect_id, idempotency_key, requested_at,
                        requested_by, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        current.execution_id,
                        current.adoption_id,
                        current.c3_run_id,
                        current.c3_decision_id,
                        current.candidate_artifact_id,
                        current.candidate_material_sha256,
                        current.decision_payload_sha256,
                        current.qualification_head_hash,
                        current.rollback_plan_sha256,
                        current.executor_id,
                        current.execution_plan_json,
                        current.execution_plan_sha256,
                        authorization_decision_id,
                        current.outbox_effect_id,
                        current.idempotency_key,
                        requested_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO c3_adoption_execution_transitions (
                        execution_id, sequence, status, worker_id,
                        effect_started, execution_receipt_json,
                        execution_receipt_sha256, rollback_receipt_json,
                        rollback_receipt_sha256, error, occurred_at,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, 1, ?, NULL, 0, NULL, NULL, NULL, NULL,
                              NULL, ?, ?, ?)
                    """,
                    (
                        current.execution_id,
                        C3AdoptionExecutionStatus.REQUESTED_NOT_EXECUTED.value,
                        requested_at,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
                self.outbox.enqueue_in_transaction(
                    connection,
                    effect_id=current.outbox_effect_id,
                    topic="c3.adoption.execute",
                    payload=self._outbox_payload(current),
                    max_attempts=3,
                    available_at=requested_at,
                    actor=actor,
                    occurred_at=requested_at,
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "C3 adoption execution conflicts with immutable state",
                {"execution_id": execution_id},
            ) from exc
        return self.get_execution(execution_id)

    @staticmethod
    def _decode_object(raw: object, field: str) -> dict[str, Any] | None:
        if raw is None:
            return None
        try:
            value = json.loads(str(raw))
        except (json.JSONDecodeError, TypeError) as exc:
            raise IntegrityError(f"stored {field} is invalid") from exc
        if not isinstance(value, dict):
            raise IntegrityError(f"stored {field} must be an object")
        return value

    def get_execution(self, execution_id: str) -> C3AdoptionExecutionRecord:
        execution_id = self._required_text(execution_id, "execution_id")
        request = self.database.connection.execute(
            """
            SELECT * FROM c3_adoption_execution_requests
            WHERE execution_id = ?
            """,
            (execution_id,),
        ).fetchone()
        if request is None:
            raise NotFoundError(
                "C3 adoption execution does not exist",
                {"execution_id": execution_id},
            )
        transition = self.database.connection.execute(
            """
            SELECT * FROM c3_adoption_execution_transitions
            WHERE execution_id = ? ORDER BY sequence DESC LIMIT 1
            """,
            (execution_id,),
        ).fetchone()
        if transition is None:
            raise IntegrityError("C3 adoption execution has no transition")
        try:
            plan = json.loads(str(request["execution_plan_json"]))
        except (json.JSONDecodeError, TypeError) as exc:
            raise IntegrityError("stored execution plan is invalid") from exc
        if not isinstance(plan, dict):
            raise IntegrityError("stored execution plan must be an object")
        return C3AdoptionExecutionRecord(
            execution_id=str(request["execution_id"]),
            adoption_id=str(request["adoption_id"]),
            c3_run_id=str(request["c3_run_id"]),
            c3_decision_id=str(request["c3_decision_id"]),
            candidate_artifact_id=str(request["candidate_artifact_id"]),
            candidate_material_sha256=str(
                request["candidate_material_sha256"]
            ),
            decision_payload_sha256=str(request["decision_payload_sha256"]),
            qualification_head_hash=str(request["qualification_head_hash"]),
            rollback_plan_sha256=str(request["rollback_plan_sha256"]),
            executor_id=str(request["executor_id"]),
            execution_plan=plan,
            execution_plan_sha256=str(request["execution_plan_sha256"]),
            authorization_decision_id=str(
                request["authorization_decision_id"]
            ),
            outbox_effect_id=str(request["outbox_effect_id"]),
            idempotency_key=str(request["idempotency_key"]),
            status=C3AdoptionExecutionStatus(str(transition["status"])),
            requested_at=str(request["requested_at"]),
            requested_by=str(request["requested_by"]),
            transition_sequence=int(transition["sequence"]),
            execution_receipt=self._decode_object(
                transition["execution_receipt_json"], "execution receipt"
            ),
            execution_receipt_sha256=(
                str(transition["execution_receipt_sha256"])
                if transition["execution_receipt_sha256"] is not None
                else None
            ),
            rollback_receipt=self._decode_object(
                transition["rollback_receipt_json"], "rollback receipt"
            ),
            rollback_receipt_sha256=(
                str(transition["rollback_receipt_sha256"])
                if transition["rollback_receipt_sha256"] is not None
                else None
            ),
            effect_started=bool(int(transition["effect_started"])),
            error=(
                str(transition["error"])
                if transition["error"] is not None
                else None
            ),
        )

    @staticmethod
    def _receipt_material(
        value: Mapping[str, Any] | None,
        field: str,
    ) -> tuple[str | None, str | None]:
        if value is None:
            return None, None
        if not isinstance(value, Mapping):
            raise ValidationError(f"{field} must be a JSON object")
        normalized = dict(value)
        return canonical_json(normalized), sha256_digest(normalized)

    def append_transition(
        self,
        execution_id: str,
        *,
        status: C3AdoptionExecutionStatus,
        worker_id: str | None,
        effect_started: bool,
        execution_receipt: Mapping[str, Any] | None,
        rollback_receipt: Mapping[str, Any] | None,
        error: object,
        occurred_at: str,
    ) -> C3AdoptionExecutionRecord:
        occurred_at = self._timestamp(occurred_at)
        current = self.get_execution(execution_id)
        if current.status.terminal:
            raise StateTransitionError("terminal C3 adoption execution is immutable")
        if status is C3AdoptionExecutionStatus.RUNNING:
            if current.status not in {
                C3AdoptionExecutionStatus.REQUESTED_NOT_EXECUTED,
                C3AdoptionExecutionStatus.RUNNING,
            }:
                raise StateTransitionError("illegal C3 execution transition")
        elif status is C3AdoptionExecutionStatus.FAILED_NO_EFFECT:
            if current.status not in {
                C3AdoptionExecutionStatus.REQUESTED_NOT_EXECUTED,
                C3AdoptionExecutionStatus.RUNNING,
            }:
                raise StateTransitionError("illegal no-effect failure transition")
        elif current.status is not C3AdoptionExecutionStatus.RUNNING:
            raise StateTransitionError("terminal execution requires RUNNING")
        if status is C3AdoptionExecutionStatus.SUCCEEDED and not effect_started:
            raise ValidationError("success must declare an effect")
        if status is C3AdoptionExecutionStatus.FAILED_NO_EFFECT and effect_started:
            raise ValidationError("FAILED_NO_EFFECT cannot declare an effect")
        if status in {
            C3AdoptionExecutionStatus.FAILED_ROLLED_BACK,
            C3AdoptionExecutionStatus.ROLLBACK_FAILED,
        } and not effect_started:
            raise ValidationError(
                "rollback outcomes require an effect or uncertain effect"
            )
        execution_json, execution_sha256 = self._receipt_material(
            execution_receipt, "execution_receipt"
        )
        rollback_json, rollback_sha256 = self._receipt_material(
            rollback_receipt, "rollback_receipt"
        )
        normalized_error = str(error).strip()[:4096] if error is not None else None
        if status is C3AdoptionExecutionStatus.RUNNING:
            execution_json = None
            execution_sha256 = None
            rollback_json = None
            rollback_sha256 = None
            normalized_error = None
        elif execution_json is None:
            raise ValidationError("terminal execution requires a receipt")
        if status in {
            C3AdoptionExecutionStatus.FAILED_ROLLED_BACK,
            C3AdoptionExecutionStatus.ROLLBACK_FAILED,
        } and rollback_json is None:
            raise ValidationError("rollback outcome requires a rollback receipt")
        if status in {
            C3AdoptionExecutionStatus.SUCCEEDED,
            C3AdoptionExecutionStatus.FAILED_NO_EFFECT,
        } and rollback_json is not None:
            raise ValidationError("non-rollback outcome cannot include rollback")

        sequence = current.transition_sequence + 1
        payload = self._event_payload(
            current,
            current.authorization_decision_id,
            sequence=sequence,
            status=status,
            worker_id=worker_id,
            effect_started=effect_started,
            execution_receipt_sha256=execution_sha256,
            rollback_receipt_sha256=rollback_sha256,
            error=normalized_error,
        )
        try:
            with self.database.transaction() as connection:
                latest = connection.execute(
                    """
                    SELECT MAX(sequence) FROM c3_adoption_execution_transitions
                    WHERE execution_id = ?
                    """,
                    (execution_id,),
                ).fetchone()[0]
                if int(latest) != current.transition_sequence:
                    raise ConflictError("execution transition changed concurrently")
                receipt = self.ledger.append_in_transaction(
                    connection,
                    self._stream(current),
                    status.value,
                    payload,
                    actor=worker_id or current.requested_by,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO c3_adoption_execution_transitions (
                        execution_id, sequence, status, worker_id,
                        effect_started, execution_receipt_json,
                        execution_receipt_sha256, rollback_receipt_json,
                        rollback_receipt_sha256, error, occurred_at,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        execution_id,
                        sequence,
                        status.value,
                        worker_id,
                        1 if effect_started else 0,
                        execution_json,
                        execution_sha256,
                        rollback_json,
                        rollback_sha256,
                        normalized_error,
                        occurred_at,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "execution transition conflicts with immutable state"
            ) from exc
        return self.get_execution(execution_id)

    @staticmethod
    def terminal_result_digest(record: C3AdoptionExecutionRecord) -> str:
        if not record.status.terminal:
            raise ValidationError(
                "terminal result digest requires a terminal execution"
            )
        return sha256_digest(
            {
                "execution_id": record.execution_id,
                "status": record.status.value,
                "execution_receipt_sha256": record.execution_receipt_sha256,
                "rollback_receipt_sha256": record.rollback_receipt_sha256,
                "effect_started": record.effect_started,
                "error": record.error,
            }
        )

    def verify_execution(self, execution_id: str) -> C3AdoptionExecutionVerification:
        execution_id = self._required_text(execution_id, "execution_id")
        request = self.database.connection.execute(
            """
            SELECT * FROM c3_adoption_execution_requests
            WHERE execution_id = ?
            """,
            (execution_id,),
        ).fetchone()
        if request is None:
            raise NotFoundError(
                "C3 adoption execution does not exist",
                {"execution_id": execution_id},
            )
        defects: list[str] = []
        try:
            record = self.get_execution(execution_id)
            preparation = self.prepare(
                execution_id,
                adoption_id=record.adoption_id,
                executor_id=record.executor_id,
                execution_plan=record.execution_plan,
            )
        except (IntegrityError, NotFoundError, StateTransitionError, ValidationError):
            return C3AdoptionExecutionVerification(
                execution_id=execution_id,
                defects=("C3_EXECUTION_STORED_RECORD_INVALID",),
            )

        _, canonical_plan, plan_sha256 = self._plan_contract(record.execution_plan)
        if canonical_plan != str(request["execution_plan_json"]):
            defects.append("C3_EXECUTION_PLAN_NOT_CANONICAL")
        if plan_sha256 != record.execution_plan_sha256:
            defects.append("C3_EXECUTION_PLAN_SHA256_MISMATCH")
        expected_binding = (
            preparation.c3_run_id,
            preparation.c3_decision_id,
            preparation.candidate_artifact_id,
            preparation.candidate_material_sha256,
            preparation.decision_payload_sha256,
            preparation.qualification_head_hash,
            preparation.rollback_plan_sha256,
            preparation.outbox_effect_id,
            preparation.idempotency_key,
        )
        observed_binding = (
            record.c3_run_id,
            record.c3_decision_id,
            record.candidate_artifact_id,
            record.candidate_material_sha256,
            record.decision_payload_sha256,
            record.qualification_head_hash,
            record.rollback_plan_sha256,
            record.outbox_effect_id,
            record.idempotency_key,
        )
        if observed_binding != expected_binding:
            defects.append("C3_EXECUTION_ADOPTION_BINDING_MISMATCH")

        authorization_verification = self.trust.verify_decision(
            record.authorization_decision_id
        )
        defects.extend(
            f"C3_EXECUTION_AUTHORIZATION:{defect}"
            for defect in authorization_verification.defects
        )
        try:
            authorization = self.trust.get_decision(
                record.authorization_decision_id
            )
        except NotFoundError:
            defects.append("C3_EXECUTION_AUTHORIZATION_MISSING")
            authorization = None
        if authorization is not None:
            observed_authorization = (
                authorization.request.subject,
                authorization.request.action,
                authorization.request.resource,
                authorization.request.mission_id,
                dict(authorization.request.context),
            )
            if (
                not authorization.allowed
                or observed_authorization
                != self._expected_authorization(preparation, record.requested_by)
            ):
                defects.append("C3_EXECUTION_AUTHORIZATION_REQUEST_MISMATCH")
            try:
                adoption = self.adoption.get_adoption(record.adoption_id)
            except NotFoundError:
                defects.append("C3_EXECUTION_ADOPTION_MISSING")
            else:
                if self._as_datetime(authorization.decided_at) < self._as_datetime(
                    adoption.authorized_at
                ):
                    defects.append("C3_EXECUTION_AUTHORIZATION_PREDATES_ADOPTION")
            if self._as_datetime(record.requested_at) < self._as_datetime(
                authorization.decided_at
            ):
                defects.append("C3_EXECUTION_REQUEST_PREDATES_AUTHORIZATION")

        consumption = self._consumption(record.authorization_decision_id)
        if consumption is None:
            defects.append("C3_EXECUTION_AUTHORIZATION_CONSUMPTION_MISSING")
        elif (
            str(consumption["operation_kind"]),
            str(consumption["operation_id"]),
            str(consumption["consumed_at"]),
            str(consumption["consumed_by"]),
        ) != (
            "C3_ADOPTION_EXECUTION_REQUESTED",
            record.execution_id,
            record.requested_at,
            record.requested_by,
        ):
            defects.append("C3_EXECUTION_AUTHORIZATION_CONSUMPTION_MISMATCH")

        transitions = self.database.connection.execute(
            """
            SELECT * FROM c3_adoption_execution_transitions
            WHERE execution_id = ? ORDER BY sequence
            """,
            (execution_id,),
        ).fetchall()
        prior: C3AdoptionExecutionStatus | None = None
        for expected_sequence, transition in enumerate(transitions, start=1):
            sequence = int(transition["sequence"])
            if sequence != expected_sequence:
                defects.append(
                    f"C3_EXECUTION_TRANSITION_SEQUENCE_MISMATCH:{sequence}"
                )
            try:
                status = C3AdoptionExecutionStatus(str(transition["status"]))
            except ValueError:
                defects.append(f"C3_EXECUTION_STATUS_INVALID:{sequence}")
                continue
            if expected_sequence == 1:
                if status is not C3AdoptionExecutionStatus.REQUESTED_NOT_EXECUTED:
                    defects.append("C3_EXECUTION_INITIAL_STATUS_INVALID")
            else:
                if prior is not None and prior.terminal:
                    defects.append(
                        f"C3_EXECUTION_TRANSITION_AFTER_TERMINAL:{sequence}"
                    )
                if status is C3AdoptionExecutionStatus.RUNNING:
                    if prior not in {
                        C3AdoptionExecutionStatus.REQUESTED_NOT_EXECUTED,
                        C3AdoptionExecutionStatus.RUNNING,
                    }:
                        defects.append(
                            f"C3_EXECUTION_RUNNING_PREDECESSOR_INVALID:{sequence}"
                        )
                elif status is C3AdoptionExecutionStatus.FAILED_NO_EFFECT:
                    if prior not in {
                        C3AdoptionExecutionStatus.REQUESTED_NOT_EXECUTED,
                        C3AdoptionExecutionStatus.RUNNING,
                    }:
                        defects.append(
                            f"C3_EXECUTION_NO_EFFECT_PREDECESSOR_INVALID:{sequence}"
                        )
                elif prior is not C3AdoptionExecutionStatus.RUNNING:
                    defects.append(
                        f"C3_EXECUTION_TERMINAL_PREDECESSOR_INVALID:{sequence}"
                    )
            prior = status

            execution_json = transition["execution_receipt_json"]
            execution_sha256 = transition["execution_receipt_sha256"]
            rollback_json = transition["rollback_receipt_json"]
            rollback_sha256 = transition["rollback_receipt_sha256"]
            if execution_json is not None:
                try:
                    execution_value = json.loads(str(execution_json))
                except (json.JSONDecodeError, TypeError):
                    defects.append(f"C3_EXECUTION_RECEIPT_INVALID:{sequence}")
                else:
                    if (
                        not isinstance(execution_value, dict)
                        or sha256_digest(execution_value)
                        != str(execution_sha256)
                    ):
                        defects.append(
                            f"C3_EXECUTION_RECEIPT_SHA256_MISMATCH:{sequence}"
                        )
                    elif canonical_json(execution_value) != str(execution_json):
                        defects.append(
                            f"C3_EXECUTION_RECEIPT_NOT_CANONICAL:{sequence}"
                        )
            elif execution_sha256 is not None:
                defects.append(
                    f"C3_EXECUTION_RECEIPT_LINKAGE_INVALID:{sequence}"
                )
            if rollback_json is not None:
                try:
                    rollback_value = json.loads(str(rollback_json))
                except (json.JSONDecodeError, TypeError):
                    defects.append(f"C3_ROLLBACK_RECEIPT_INVALID:{sequence}")
                else:
                    if (
                        not isinstance(rollback_value, dict)
                        or sha256_digest(rollback_value) != str(rollback_sha256)
                    ):
                        defects.append(
                            f"C3_ROLLBACK_RECEIPT_SHA256_MISMATCH:{sequence}"
                        )
                    elif canonical_json(rollback_value) != str(rollback_json):
                        defects.append(
                            f"C3_ROLLBACK_RECEIPT_NOT_CANONICAL:{sequence}"
                        )
            elif rollback_sha256 is not None:
                defects.append(
                    f"C3_ROLLBACK_RECEIPT_LINKAGE_INVALID:{sequence}"
                )

            effect_started = bool(int(transition["effect_started"]))
            if status.terminal and execution_json is None:
                defects.append(
                    f"C3_EXECUTION_TERMINAL_RECEIPT_MISSING:{sequence}"
                )
            if status is C3AdoptionExecutionStatus.SUCCEEDED and (
                not effect_started or rollback_json is not None
            ):
                defects.append(
                    f"C3_EXECUTION_SUCCESS_SEMANTICS_INVALID:{sequence}"
                )
            if status is C3AdoptionExecutionStatus.FAILED_NO_EFFECT and (
                effect_started or rollback_json is not None
            ):
                defects.append(
                    f"C3_EXECUTION_FAILED_NO_EFFECT_SEMANTICS_INVALID:{sequence}"
                )
            if status in {
                C3AdoptionExecutionStatus.FAILED_ROLLED_BACK,
                C3AdoptionExecutionStatus.ROLLBACK_FAILED,
            } and (not effect_started or rollback_json is None):
                defects.append(
                    f"C3_EXECUTION_ROLLBACK_SEMANTICS_INVALID:{sequence}"
                )

            event = self.database.connection.execute(
                "SELECT * FROM ledger_events WHERE event_id = ?",
                (str(transition["ledger_event_id"]),),
            ).fetchone()
            if event is None:
                defects.append(f"C3_EXECUTION_LEDGER_EVENT_MISSING:{sequence}")
            else:
                expected_actor = (
                    str(transition["worker_id"])
                    if transition["worker_id"] is not None
                    else record.requested_by
                )
                expected_event_payload = self._event_payload(
                    record,
                    record.authorization_decision_id,
                    sequence=sequence,
                    status=status,
                    worker_id=(
                        str(transition["worker_id"])
                        if transition["worker_id"] is not None
                        else None
                    ),
                    effect_started=effect_started,
                    execution_receipt_sha256=(
                        str(execution_sha256)
                        if execution_sha256 is not None
                        else None
                    ),
                    rollback_receipt_sha256=(
                        str(rollback_sha256)
                        if rollback_sha256 is not None
                        else None
                    ),
                    error=(
                        str(transition["error"])
                        if transition["error"] is not None
                        else None
                    ),
                )
                if str(event["stream_id"]) != self._stream(record):
                    defects.append(
                        f"C3_EXECUTION_LEDGER_STREAM_MISMATCH:{sequence}"
                    )
                if str(event["kind"]) != status.value:
                    defects.append(
                        f"C3_EXECUTION_LEDGER_KIND_MISMATCH:{sequence}"
                    )
                if str(event["actor"]) != expected_actor:
                    defects.append(
                        f"C3_EXECUTION_LEDGER_ACTOR_MISMATCH:{sequence}"
                    )
                if str(event["occurred_at"]) != str(transition["occurred_at"]):
                    defects.append(
                        f"C3_EXECUTION_LEDGER_TIME_MISMATCH:{sequence}"
                    )
                if str(event["record_hash"]) != str(transition["ledger_hash"]):
                    defects.append(
                        f"C3_EXECUTION_LEDGER_HASH_MISMATCH:{sequence}"
                    )
                try:
                    event_payload = json.loads(str(event["payload_json"]))
                except (json.JSONDecodeError, TypeError):
                    defects.append(
                        f"C3_EXECUTION_LEDGER_PAYLOAD_INVALID:{sequence}"
                    )
                else:
                    if event_payload != expected_event_payload:
                        defects.append(
                            f"C3_EXECUTION_LEDGER_PAYLOAD_MISMATCH:{sequence}"
                        )

        defects.extend(
            f"C3_EXECUTION_LEDGER_CHAIN:{defect.code}"
            for defect in self.ledger.verify(self._stream(record)).defects
        )

        try:
            effect = self.outbox.get(record.outbox_effect_id)
        except NotFoundError:
            defects.append("C3_EXECUTION_OUTBOX_EFFECT_MISSING")
        else:
            expected_outbox_payload = self._outbox_payload(preparation)
            if effect.topic != "c3.adoption.execute":
                defects.append("C3_EXECUTION_OUTBOX_TOPIC_MISMATCH")
            if effect.payload != expected_outbox_payload:
                defects.append("C3_EXECUTION_OUTBOX_PAYLOAD_MISMATCH")
            expected_request_digest = sha256_digest(
                {
                    "effect_id": record.outbox_effect_id,
                    "topic": "c3.adoption.execute",
                    "payload": expected_outbox_payload,
                    "max_attempts": 3,
                }
            )
            if effect.request_digest != expected_request_digest:
                defects.append("C3_EXECUTION_OUTBOX_REQUEST_DIGEST_MISMATCH")
            if record.status.terminal:
                if effect.status is not EffectStatus.SUCCEEDED:
                    defects.append("C3_EXECUTION_OUTBOX_NOT_SUCCEEDED")
                if effect.result_digest != self.terminal_result_digest(record):
                    defects.append("C3_EXECUTION_OUTBOX_RESULT_DIGEST_MISMATCH")
            elif effect.status not in {EffectStatus.PENDING, EffectStatus.LEASED}:
                defects.append("C3_EXECUTION_OUTBOX_STATUS_INVALID")
            defects.extend(
                f"C3_EXECUTION_OUTBOX_LEDGER:{defect.code}"
                for defect in self.ledger.verify(
                    f"durable:effect:{record.outbox_effect_id}"
                ).defects
            )

        if transitions and str(request["ledger_event_id"]) != str(
            transitions[0]["ledger_event_id"]
        ):
            defects.append("C3_EXECUTION_REQUEST_LEDGER_BINDING_MISMATCH")
        if transitions and str(request["ledger_hash"]) != str(
            transitions[0]["ledger_hash"]
        ):
            defects.append("C3_EXECUTION_REQUEST_LEDGER_HASH_MISMATCH")
        return C3AdoptionExecutionVerification(
            execution_id=execution_id,
            defects=tuple(dict.fromkeys(defects)),
        )


class C3AdoptionExecutionWorker:
    """Claim durable effects and drive one injected idempotent executor."""

    def __init__(
        self,
        service: C3AdoptionExecutionService,
        outbox: DurableOutbox,
        executor: C3AdoptionExecutor | None = None,
    ) -> None:
        self.service = service
        self.outbox = outbox
        self.executor = executor or DisabledC3AdoptionExecutor()

    @staticmethod
    def _exception_receipt(
        request: C3AdoptionExecutionRecord,
        phase: str,
        error: BaseException,
    ) -> dict[str, object]:
        return {
            "executor_id": request.executor_id,
            "idempotency_key": request.idempotency_key,
            "phase": phase,
            "exception_type": type(error).__name__,
            "message": str(error)[:4096],
        }

    def _terminalize(
        self,
        lease: EffectLease,
        request: C3AdoptionExecutionRecord,
        *,
        worker_id: str,
        status: C3AdoptionExecutionStatus,
        effect_started: bool,
        execution_receipt: Mapping[str, Any],
        rollback_receipt: Mapping[str, Any] | None,
        error: object,
        now: str,
    ) -> C3AdoptionExecutionRecord:
        terminal = self.service.append_transition(
            request.execution_id,
            status=status,
            worker_id=worker_id,
            effect_started=effect_started,
            execution_receipt=execution_receipt,
            rollback_receipt=rollback_receipt,
            error=error,
            occurred_at=now,
        )
        self.outbox.succeed(
            lease.effect_id,
            worker_id=worker_id,
            lease_token=lease.lease_token,
            result_digest=self.service.terminal_result_digest(terminal),
            occurred_at=now,
        )
        return terminal

    def process_next(
        self,
        *,
        worker_id: str,
        now: str,
        lease_seconds: int = 60,
    ) -> C3AdoptionExecutionRecord | None:
        leases = self.outbox.claim(
            worker_id,
            now=now,
            lease_seconds=lease_seconds,
            limit=1,
            topic="c3.adoption.execute",
        )
        if not leases:
            return None
        lease = leases[0]
        execution_id = lease.payload.get("execution_id")
        if not isinstance(execution_id, str) or not execution_id:
            raise IntegrityError("execution effect lacks execution_id")
        request = self.service.get_execution(execution_id)
        if request.outbox_effect_id != lease.effect_id:
            raise IntegrityError("execution effect binding mismatch")
        if request.status.terminal:
            self.outbox.succeed(
                lease.effect_id,
                worker_id=worker_id,
                lease_token=lease.lease_token,
                result_digest=self.service.terminal_result_digest(request),
                occurred_at=now,
            )
            return request
        verification = self.service.verify_execution(execution_id)
        if not verification.ok:
            return self._terminalize(
                lease,
                request,
                worker_id=worker_id,
                status=C3AdoptionExecutionStatus.FAILED_NO_EFFECT,
                effect_started=False,
                execution_receipt={
                    "phase": "pre-effect-verification",
                    "defects": list(verification.defects),
                    "idempotency_key": request.idempotency_key,
                },
                rollback_receipt=None,
                error="pre-effect execution verification failed",
                now=now,
            )
        if request.executor_id != self.executor.executor_id:
            return self._terminalize(
                lease,
                request,
                worker_id=worker_id,
                status=C3AdoptionExecutionStatus.FAILED_NO_EFFECT,
                effect_started=False,
                execution_receipt={
                    "phase": "executor-selection",
                    "expected_executor_id": request.executor_id,
                    "observed_executor_id": self.executor.executor_id,
                    "idempotency_key": request.idempotency_key,
                },
                rollback_receipt=None,
                error="executor identity mismatch",
                now=now,
            )
        request = self.service.append_transition(
            execution_id,
            status=C3AdoptionExecutionStatus.RUNNING,
            worker_id=worker_id,
            effect_started=False,
            execution_receipt=None,
            rollback_receipt=None,
            error=None,
            occurred_at=now,
        )
        try:
            self.executor.validate(request)
        except Exception as exc:
            return self._terminalize(
                lease,
                request,
                worker_id=worker_id,
                status=C3AdoptionExecutionStatus.FAILED_NO_EFFECT,
                effect_started=False,
                execution_receipt=self._exception_receipt(
                    request, "validate", exc
                ),
                rollback_receipt=None,
                error=exc,
                now=now,
            )
        try:
            result = self.executor.execute(request)
        except Exception as exc:
            execution_receipt = self._exception_receipt(
                request, "execute-uncertain", exc
            )
            try:
                rollback = self.executor.rollback(
                    request,
                    None,
                    f"uncertain execution exception: {type(exc).__name__}",
                )
            except Exception as rollback_exc:
                rollback = C3RollbackResult(
                    succeeded=False,
                    restored_state_digest=None,
                    receipt=self._exception_receipt(
                        request, "rollback-exception", rollback_exc
                    ),
                    error=str(rollback_exc),
                )
            return self._terminalize(
                lease,
                request,
                worker_id=worker_id,
                status=(
                    C3AdoptionExecutionStatus.FAILED_ROLLED_BACK
                    if rollback.succeeded
                    else C3AdoptionExecutionStatus.ROLLBACK_FAILED
                ),
                effect_started=True,
                execution_receipt=execution_receipt,
                rollback_receipt=dict(rollback.receipt),
                error=rollback.error or exc,
                now=now,
            )

        self.service._digest(result.pre_state_digest, "pre_state_digest")
        if result.post_state_digest is not None:
            self.service._digest(result.post_state_digest, "post_state_digest")
        execution_receipt = {
            "executor_id": request.executor_id,
            "idempotency_key": request.idempotency_key,
            "succeeded": result.succeeded,
            "effect_started": result.effect_started,
            "pre_state_digest": result.pre_state_digest,
            "post_state_digest": result.post_state_digest,
            "adapter_receipt": dict(result.receipt),
        }
        if result.succeeded:
            if not result.effect_started:
                raise IntegrityError("executor reported success without an effect")
            return self._terminalize(
                lease,
                request,
                worker_id=worker_id,
                status=C3AdoptionExecutionStatus.SUCCEEDED,
                effect_started=True,
                execution_receipt=execution_receipt,
                rollback_receipt=None,
                error=result.error,
                now=now,
            )
        if not result.effect_started:
            return self._terminalize(
                lease,
                request,
                worker_id=worker_id,
                status=C3AdoptionExecutionStatus.FAILED_NO_EFFECT,
                effect_started=False,
                execution_receipt=execution_receipt,
                rollback_receipt=None,
                error=result.error,
                now=now,
            )
        try:
            rollback = self.executor.rollback(
                request,
                result,
                result.error or "post-effect execution failure",
            )
        except Exception as exc:
            rollback = C3RollbackResult(
                succeeded=False,
                restored_state_digest=None,
                receipt=self._exception_receipt(
                    request, "rollback-exception", exc
                ),
                error=str(exc),
            )
        if rollback.restored_state_digest is not None:
            self.service._digest(
                rollback.restored_state_digest,
                "restored_state_digest",
            )
        rollback_receipt = {
            "executor_id": request.executor_id,
            "idempotency_key": request.idempotency_key,
            "succeeded": rollback.succeeded,
            "restored_state_digest": rollback.restored_state_digest,
            "adapter_receipt": dict(rollback.receipt),
        }
        return self._terminalize(
            lease,
            request,
            worker_id=worker_id,
            status=(
                C3AdoptionExecutionStatus.FAILED_ROLLED_BACK
                if rollback.succeeded
                else C3AdoptionExecutionStatus.ROLLBACK_FAILED
            ),
            effect_started=True,
            execution_receipt=execution_receipt,
            rollback_receipt=rollback_receipt,
            error=rollback.error or result.error,
            now=now,
        )
