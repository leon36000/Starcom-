from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import re
import sqlite3
from typing import Any, Mapping, Protocol, Sequence

from .adoption_execution import (
    C3AdoptionExecutionRecord,
    C3AdoptionExecutionStatus,
    C3AdoptionExecutionVerification,
)
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
from .trust import AuthorizationDecision, TrustPlane


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_INPUT_GATE_EFFECT = "C4_ARCHITECTURE_INPUT_FROZEN_NO_CANDIDATE"
_INPUT_EVENT_KIND = "C4_ARCHITECTURE_INPUT_FROZEN"
_ALLOWED_TERMINAL = frozenset(
    {
        C3AdoptionExecutionStatus.SUCCEEDED,
        C3AdoptionExecutionStatus.FAILED_NO_EFFECT,
        C3AdoptionExecutionStatus.FAILED_ROLLED_BACK,
    }
)


class C4ExecutionEvidenceSource(Protocol):
    def get_execution(self, execution_id: str) -> C3AdoptionExecutionRecord: ...

    def verify_execution(
        self,
        execution_id: str,
    ) -> C3AdoptionExecutionVerification: ...

    @staticmethod
    def terminal_result_digest(record: C3AdoptionExecutionRecord) -> str: ...


@dataclass(frozen=True)
class C4ArchitectureInputPreparation:
    input_set_id: str
    execution_ids: tuple[str, ...]
    member_count: int
    success_count: int
    negative_evidence_count: int
    input_set_digest: str
    author_identities: tuple[str, ...]
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]


@dataclass(frozen=True)
class C4ArchitectureInputSet:
    input_set_id: str
    member_count: int
    success_count: int
    negative_evidence_count: int
    input_set_digest: str
    author_identities: tuple[str, ...]
    authorization_decision_id: str
    frozen_at: str
    frozen_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C4ArchitectureInputVerification:
    input_set_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C4ArchitectureInputService:
    """Freeze clean terminal C3 execution evidence for C4 architecture work."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        trust: TrustPlane,
        continuity: ContinuityService,
        executions: C4ExecutionEvidenceSource,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self.continuity = continuity
        self.executions = executions
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
    def _sha256(value: object, field: str) -> str:
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise IntegrityError(
                f"{field} is not a lowercase SHA-256 digest",
                {"field": field},
            )
        return value

    @classmethod
    def _execution_id_tuple(
        cls,
        execution_ids: Sequence[str],
    ) -> tuple[str, ...]:
        if isinstance(execution_ids, (str, bytes)) or not isinstance(
            execution_ids, Sequence
        ):
            raise ValidationError("execution_ids must be a sequence of strings")
        normalized = tuple(
            cls._required_text(execution_id, "execution_id")
            for execution_id in execution_ids
        )
        if not normalized:
            raise ValidationError("execution_ids must be non-empty")
        if tuple(sorted(normalized)) != normalized:
            raise ValidationError("execution_ids must be lexicographically sorted")
        if len(set(normalized)) != len(normalized):
            raise ValidationError("execution_ids must be duplicate-free")
        return normalized

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c4_architecture_input_sets (
                    input_set_id TEXT PRIMARY KEY,
                    member_count INTEGER NOT NULL CHECK (member_count >= 1),
                    success_count INTEGER NOT NULL CHECK (success_count >= 1),
                    negative_evidence_count INTEGER NOT NULL
                        CHECK (negative_evidence_count >= 0),
                    input_set_digest TEXT NOT NULL
                        CHECK (length(input_set_digest) = 64),
                    author_identities_json TEXT NOT NULL,
                    authorization_decision_id TEXT NOT NULL UNIQUE,
                    frozen_at TEXT NOT NULL,
                    frozen_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    CHECK (
                        member_count = success_count + negative_evidence_count
                    ),
                    FOREIGN KEY (authorization_decision_id)
                        REFERENCES trust_decisions(decision_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c4_architecture_input_members (
                    input_set_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                    execution_id TEXT NOT NULL,
                    member_json TEXT NOT NULL,
                    member_sha256 TEXT NOT NULL
                        CHECK (length(member_sha256) = 64),
                    PRIMARY KEY (input_set_id, ordinal),
                    UNIQUE (input_set_id, execution_id),
                    FOREIGN KEY (input_set_id)
                        REFERENCES c4_architecture_input_sets(input_set_id)
                )
                """
            )
            for table in (
                "c4_architecture_input_sets",
                "c4_architecture_input_members",
            ):
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {table}_no_update
                    BEFORE UPDATE ON {table}
                    BEGIN SELECT RAISE(
                        ABORT, '{table} rows are immutable'
                    ); END
                    """
                )
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {table}_no_delete
                    BEFORE DELETE ON {table}
                    BEGIN SELECT RAISE(
                        ABORT, '{table} rows are immutable'
                    ); END
                    """
                )

    def _snapshot_execution(self, execution_id: str) -> dict[str, object]:
        verification = self.executions.verify_execution(execution_id)
        if not verification.ok:
            raise IntegrityError(
                "C3 execution verification failed for C4 architecture input",
                {
                    "execution_id": execution_id,
                    "defects": list(verification.defects),
                },
            )
        record = self.executions.get_execution(execution_id)
        if not record.status.terminal:
            raise StateTransitionError(
                "C4 architecture input requires terminal C3 executions",
                {
                    "execution_id": execution_id,
                    "status": record.status.value,
                },
            )
        if record.status is C3AdoptionExecutionStatus.ROLLBACK_FAILED:
            raise StateTransitionError(
                "rollback-failed C3 execution cannot enter C4 architecture input",
                {"execution_id": execution_id},
            )
        if record.status not in _ALLOWED_TERMINAL:
            raise StateTransitionError(
                "C3 execution status is not eligible for C4 architecture input",
                {
                    "execution_id": execution_id,
                    "status": record.status.value,
                },
            )
        terminal_result_digest = self.executions.terminal_result_digest(record)
        self._sha256(terminal_result_digest, "terminal_result_digest")
        for field, value in (
            ("candidate_material_sha256", record.candidate_material_sha256),
            ("decision_payload_sha256", record.decision_payload_sha256),
            ("qualification_head_hash", record.qualification_head_hash),
            ("execution_plan_sha256", record.execution_plan_sha256),
        ):
            self._sha256(value, field)
        if record.execution_receipt_sha256 is None:
            raise IntegrityError(
                "terminal C3 execution lacks an execution receipt digest",
                {"execution_id": execution_id},
            )
        self._sha256(
            record.execution_receipt_sha256,
            "execution_receipt_sha256",
        )
        if record.status is C3AdoptionExecutionStatus.FAILED_ROLLED_BACK:
            if record.rollback_receipt_sha256 is None:
                raise IntegrityError(
                    "rolled-back C3 execution lacks a rollback receipt digest",
                    {"execution_id": execution_id},
                )
            self._sha256(
                record.rollback_receipt_sha256,
                "rollback_receipt_sha256",
            )
        requested_by = self._required_text(record.requested_by, "requested_by")
        return {
            "execution_id": record.execution_id,
            "adoption_id": record.adoption_id,
            "c3_run_id": record.c3_run_id,
            "c3_decision_id": record.c3_decision_id,
            "candidate_artifact_id": record.candidate_artifact_id,
            "candidate_material_sha256": record.candidate_material_sha256,
            "decision_payload_sha256": record.decision_payload_sha256,
            "qualification_head_hash": record.qualification_head_hash,
            "executor_id": record.executor_id,
            "execution_plan_sha256": record.execution_plan_sha256,
            "authorization_decision_id": record.authorization_decision_id,
            "status": record.status.value,
            "execution_receipt_sha256": record.execution_receipt_sha256,
            "rollback_receipt_sha256": record.rollback_receipt_sha256,
            "effect_started": record.effect_started,
            "error": record.error.strip() if record.error else None,
            "requested_at": record.requested_at,
            "requested_by": requested_by,
            "transition_sequence": record.transition_sequence,
            "terminal_result_digest": terminal_result_digest,
        }

    @staticmethod
    def _stream(input_set_id: str) -> str:
        return f"continuity:c4:architecture-input:{input_set_id}"

    @staticmethod
    def _context(
        *,
        input_set_id: str,
        execution_ids: tuple[str, ...],
        member_count: int,
        success_count: int,
        negative_evidence_count: int,
        input_set_digest: str,
        author_identities: tuple[str, ...],
    ) -> dict[str, object]:
        return {
            "input_set_id": input_set_id,
            "execution_ids": list(execution_ids),
            "member_count": member_count,
            "success_count": success_count,
            "negative_evidence_count": negative_evidence_count,
            "input_set_digest": input_set_digest,
            "author_identities": list(author_identities),
            "gate_effect": _INPUT_GATE_EFFECT,
        }

    def prepare_freeze(
        self,
        input_set_id: str,
        execution_ids: Sequence[str],
    ) -> C4ArchitectureInputPreparation:
        input_set_id = self._required_text(input_set_id, "input_set_id")
        normalized_ids = self._execution_id_tuple(execution_ids)
        members = tuple(
            self._snapshot_execution(execution_id)
            for execution_id in normalized_ids
        )
        success_count = sum(
            1
            for member in members
            if member["status"]
            == C3AdoptionExecutionStatus.SUCCEEDED.value
        )
        if success_count < 1:
            raise StateTransitionError(
                "C4 architecture input requires at least one successful C3 execution"
            )
        negative_evidence_count = len(members) - success_count
        input_set_digest = sha256_digest(list(members))
        author_identities = tuple(
            sorted({str(member["requested_by"]) for member in members})
        )
        context = self._context(
            input_set_id=input_set_id,
            execution_ids=normalized_ids,
            member_count=len(members),
            success_count=success_count,
            negative_evidence_count=negative_evidence_count,
            input_set_digest=input_set_digest,
            author_identities=author_identities,
        )
        return C4ArchitectureInputPreparation(
            input_set_id=input_set_id,
            execution_ids=normalized_ids,
            member_count=len(members),
            success_count=success_count,
            negative_evidence_count=negative_evidence_count,
            input_set_digest=input_set_digest,
            author_identities=author_identities,
            action="c4.architecture-input.freeze",
            resource=self._stream(input_set_id),
            mission_id=f"c4-architecture:{input_set_id}",
            context=context,
        )

    def _assert_authorization(
        self,
        decision_id: str,
        *,
        preparation: C4ArchitectureInputPreparation,
        actor: str,
    ) -> AuthorizationDecision:
        decision_id = self._required_text(decision_id, "authorization_decision_id")
        verification = self.trust.verify_decision(decision_id)
        if not verification.ok:
            raise AuthorizationError(
                "C4 input authorization decision failed verification",
                {
                    "decision_id": decision_id,
                    "defects": list(verification.defects),
                },
            )
        try:
            decision = self.trust.get_decision(decision_id)
        except NotFoundError as exc:
            raise AuthorizationError(
                "C4 input authorization decision does not exist"
            ) from exc
        observed = (
            decision.request.subject,
            decision.request.action,
            decision.request.resource,
            decision.request.mission_id,
            dict(decision.request.context),
        )
        expected = (
            actor,
            preparation.action,
            preparation.resource,
            preparation.mission_id,
            dict(preparation.context),
        )
        if not decision.allowed or observed != expected:
            raise AuthorizationError(
                "authorization decision does not exactly match C4 input freeze",
                {
                    "decision_id": decision_id,
                    "allowed": decision.allowed,
                    "expected": list(expected),
                    "observed": list(observed),
                },
            )
        return decision

    @staticmethod
    def _ledger_payload(
        record: C4ArchitectureInputSet,
    ) -> dict[str, object]:
        return {
            "input_set_id": record.input_set_id,
            "member_count": record.member_count,
            "success_count": record.success_count,
            "negative_evidence_count": record.negative_evidence_count,
            "input_set_digest": record.input_set_digest,
            "author_identities": list(record.author_identities),
            "authorization_decision_id": record.authorization_decision_id,
            "gate_effect": _INPUT_GATE_EFFECT,
        }

    @staticmethod
    def _from_row(row: sqlite3.Row) -> C4ArchitectureInputSet:
        try:
            authors = json.loads(str(row["author_identities_json"]))
        except (json.JSONDecodeError, TypeError) as exc:
            raise IntegrityError("stored C4 input authors are invalid") from exc
        if (
            not isinstance(authors, list)
            or not all(isinstance(item, str) and item for item in authors)
        ):
            raise IntegrityError("stored C4 input authors are invalid")
        return C4ArchitectureInputSet(
            input_set_id=str(row["input_set_id"]),
            member_count=int(row["member_count"]),
            success_count=int(row["success_count"]),
            negative_evidence_count=int(row["negative_evidence_count"]),
            input_set_digest=str(row["input_set_digest"]),
            author_identities=tuple(authors),
            authorization_decision_id=str(row["authorization_decision_id"]),
            frozen_at=str(row["frozen_at"]),
            frozen_by=str(row["frozen_by"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def get_input_set(self, input_set_id: str) -> C4ArchitectureInputSet:
        input_set_id = self._required_text(input_set_id, "input_set_id")
        row = self.database.connection.execute(
            """
            SELECT * FROM c4_architecture_input_sets
            WHERE input_set_id = ?
            """,
            (input_set_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C4 architecture input set does not exist",
                {"input_set_id": input_set_id},
            )
        return self._from_row(row)

    def get_members(
        self,
        input_set_id: str,
    ) -> tuple[Mapping[str, Any], ...]:
        self.get_input_set(input_set_id)
        rows = self.database.connection.execute(
            """
            SELECT * FROM c4_architecture_input_members
            WHERE input_set_id = ? ORDER BY ordinal
            """,
            (input_set_id,),
        ).fetchall()
        members: list[Mapping[str, Any]] = []
        for row in rows:
            try:
                value = json.loads(str(row["member_json"]))
            except (json.JSONDecodeError, TypeError) as exc:
                raise IntegrityError(
                    "stored C4 architecture input member is invalid",
                    {"ordinal": int(row["ordinal"])},
                ) from exc
            if not isinstance(value, dict):
                raise IntegrityError(
                    "stored C4 architecture input member must be an object",
                    {"ordinal": int(row["ordinal"])},
                )
            members.append(value)
        return tuple(members)

    def freeze(
        self,
        input_set_id: str,
        execution_ids: Sequence[str],
        *,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> C4ArchitectureInputSet:
        input_set_id = self._required_text(input_set_id, "input_set_id")
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now())
        preparation = self.prepare_freeze(input_set_id, execution_ids)
        decision = self._assert_authorization(
            authorization_decision_id,
            preparation=preparation,
            actor=actor,
        )
        if self._as_datetime(occurred_at) < self._as_datetime(decision.decided_at):
            raise StateTransitionError(
                "C4 input freeze predates TrustPlane authorization"
            )

        existing = self.database.connection.execute(
            """
            SELECT * FROM c4_architecture_input_sets
            WHERE input_set_id = ?
            """,
            (input_set_id,),
        ).fetchone()
        if existing is not None:
            record = self._from_row(existing)
            expected = (
                preparation.member_count,
                preparation.success_count,
                preparation.negative_evidence_count,
                preparation.input_set_digest,
                preparation.author_identities,
                authorization_decision_id,
                actor,
            )
            observed = (
                record.member_count,
                record.success_count,
                record.negative_evidence_count,
                record.input_set_digest,
                record.author_identities,
                record.authorization_decision_id,
                record.frozen_by,
            )
            if observed != expected:
                raise ConflictError(
                    "input_set_id was reused with different C4 material",
                    {"input_set_id": input_set_id},
                )
            stored_execution_ids = tuple(
                str(member["execution_id"])
                for member in self.get_members(input_set_id)
            )
            if stored_execution_ids != preparation.execution_ids:
                raise ConflictError(
                    "input_set_id was reused with different C4 members",
                    {"input_set_id": input_set_id},
                )
            verification = self.verify_input_set(input_set_id)
            if not verification.ok:
                raise IntegrityError(
                    "existing C4 architecture input set failed verification",
                    {
                        "input_set_id": input_set_id,
                        "defects": list(verification.defects),
                    },
                )
            return record

        members = tuple(
            self._snapshot_execution(execution_id)
            for execution_id in preparation.execution_ids
        )
        provisional = C4ArchitectureInputSet(
            input_set_id=input_set_id,
            member_count=preparation.member_count,
            success_count=preparation.success_count,
            negative_evidence_count=preparation.negative_evidence_count,
            input_set_digest=preparation.input_set_digest,
            author_identities=preparation.author_identities,
            authorization_decision_id=authorization_decision_id,
            frozen_at=occurred_at,
            frozen_by=actor,
            ledger_event_id="pending",
            ledger_hash="pending",
        )
        try:
            with self.database.transaction() as connection:
                race = connection.execute(
                    """
                    SELECT input_set_id FROM c4_architecture_input_sets
                    WHERE input_set_id = ? OR authorization_decision_id = ?
                    """,
                    (input_set_id, authorization_decision_id),
                ).fetchone()
                if race is not None:
                    raise ConflictError(
                        "C4 input set appeared during freeze",
                        {"input_set_id": input_set_id},
                    )
                current = self.prepare_freeze(input_set_id, execution_ids)
                if current != preparation:
                    raise ConflictError(
                        "C3 execution evidence changed during C4 input freeze",
                        {"input_set_id": input_set_id},
                    )
                current_decision = self._assert_authorization(
                    authorization_decision_id,
                    preparation=current,
                    actor=actor,
                )
                if self._as_datetime(occurred_at) < self._as_datetime(
                    current_decision.decided_at
                ):
                    raise StateTransitionError(
                        "C4 input freeze predates TrustPlane authorization"
                    )
                self.continuity._consume_authorization(
                    connection,
                    decision_id=authorization_decision_id,
                    operation_kind=_INPUT_EVENT_KIND,
                    operation_id=input_set_id,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    self._stream(input_set_id),
                    _INPUT_EVENT_KIND,
                    self._ledger_payload(provisional),
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO c4_architecture_input_sets (
                        input_set_id, member_count, success_count,
                        negative_evidence_count, input_set_digest,
                        author_identities_json, authorization_decision_id,
                        frozen_at, frozen_by, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        input_set_id,
                        preparation.member_count,
                        preparation.success_count,
                        preparation.negative_evidence_count,
                        preparation.input_set_digest,
                        canonical_json(list(preparation.author_identities)),
                        authorization_decision_id,
                        occurred_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
                for ordinal, member in enumerate(members):
                    connection.execute(
                        """
                        INSERT INTO c4_architecture_input_members (
                            input_set_id, ordinal, execution_id,
                            member_json, member_sha256
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            input_set_id,
                            ordinal,
                            str(member["execution_id"]),
                            canonical_json(member),
                            sha256_digest(member),
                        ),
                    )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "C4 architecture input conflicts with immutable state",
                {"input_set_id": input_set_id},
            ) from exc
        return self.get_input_set(input_set_id)

    def _expected_preparation_from_members(
        self,
        record: C4ArchitectureInputSet,
        members: tuple[Mapping[str, Any], ...],
    ) -> C4ArchitectureInputPreparation:
        execution_ids = tuple(str(member["execution_id"]) for member in members)
        return C4ArchitectureInputPreparation(
            input_set_id=record.input_set_id,
            execution_ids=execution_ids,
            member_count=record.member_count,
            success_count=record.success_count,
            negative_evidence_count=record.negative_evidence_count,
            input_set_digest=record.input_set_digest,
            author_identities=record.author_identities,
            action="c4.architecture-input.freeze",
            resource=self._stream(record.input_set_id),
            mission_id=f"c4-architecture:{record.input_set_id}",
            context=self._context(
                input_set_id=record.input_set_id,
                execution_ids=execution_ids,
                member_count=record.member_count,
                success_count=record.success_count,
                negative_evidence_count=record.negative_evidence_count,
                input_set_digest=record.input_set_digest,
                author_identities=record.author_identities,
            ),
        )

    def verify_input_set(
        self,
        input_set_id: str,
    ) -> C4ArchitectureInputVerification:
        input_set_id = self._required_text(input_set_id, "input_set_id")
        row = self.database.connection.execute(
            """
            SELECT * FROM c4_architecture_input_sets
            WHERE input_set_id = ?
            """,
            (input_set_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C4 architecture input set does not exist",
                {"input_set_id": input_set_id},
            )
        defects: list[str] = []
        try:
            record = self._from_row(row)
        except IntegrityError:
            return C4ArchitectureInputVerification(
                input_set_id=input_set_id,
                defects=("C4_INPUT_ROW_INVALID",),
            )
        member_rows = self.database.connection.execute(
            """
            SELECT * FROM c4_architecture_input_members
            WHERE input_set_id = ? ORDER BY ordinal
            """,
            (input_set_id,),
        ).fetchall()
        members: list[Mapping[str, Any]] = []
        execution_ids: list[str] = []
        for expected_ordinal, member_row in enumerate(member_rows):
            ordinal = int(member_row["ordinal"])
            if ordinal != expected_ordinal:
                defects.append(f"C4_INPUT_MEMBER_ORDINAL_MISMATCH:{ordinal}")
            try:
                member = json.loads(str(member_row["member_json"]))
            except (json.JSONDecodeError, TypeError):
                defects.append(f"C4_INPUT_MEMBER_JSON_INVALID:{ordinal}")
                continue
            if not isinstance(member, dict):
                defects.append(f"C4_INPUT_MEMBER_JSON_INVALID:{ordinal}")
                continue
            if canonical_json(member) != str(member_row["member_json"]):
                defects.append(f"C4_INPUT_MEMBER_NOT_CANONICAL:{ordinal}")
            if sha256_digest(member) != str(member_row["member_sha256"]):
                defects.append(f"C4_INPUT_MEMBER_SHA256_MISMATCH:{ordinal}")
            if member.get("execution_id") != str(member_row["execution_id"]):
                defects.append(f"C4_INPUT_MEMBER_EXECUTION_ID_MISMATCH:{ordinal}")
            members.append(member)
            execution_ids.append(str(member.get("execution_id", "")))

        if len(members) != record.member_count:
            defects.append("C4_INPUT_MEMBER_COUNT_MISMATCH")
        success_count = sum(
            1
            for member in members
            if member.get("status")
            == C3AdoptionExecutionStatus.SUCCEEDED.value
        )
        negative_count = len(members) - success_count
        if success_count != record.success_count:
            defects.append("C4_INPUT_SUCCESS_COUNT_MISMATCH")
        if negative_count != record.negative_evidence_count:
            defects.append("C4_INPUT_NEGATIVE_COUNT_MISMATCH")
        if success_count < 1:
            defects.append("C4_INPUT_SUCCESS_REQUIRED")
        computed_digest = sha256_digest(list(members))
        if computed_digest != record.input_set_digest:
            defects.append("C4_INPUT_SET_DIGEST_MISMATCH")
        authors = tuple(
            sorted(
                {
                    str(member.get("requested_by"))
                    for member in members
                    if isinstance(member.get("requested_by"), str)
                    and str(member.get("requested_by"))
                }
            )
        )
        if authors != record.author_identities:
            defects.append("C4_INPUT_AUTHOR_IDENTITIES_MISMATCH")
        if tuple(execution_ids) != tuple(sorted(execution_ids)) or len(
            set(execution_ids)
        ) != len(execution_ids):
            defects.append("C4_INPUT_EXECUTION_ORDER_INVALID")

        for ordinal, member in enumerate(members):
            execution_id = str(member.get("execution_id", ""))
            if not execution_id:
                defects.append(f"C4_INPUT_EXECUTION_ID_INVALID:{ordinal}")
                continue
            try:
                verification = self.executions.verify_execution(execution_id)
            except NotFoundError:
                defects.append(f"C4_INPUT_EXECUTION_MISSING:{execution_id}")
                continue
            defects.extend(
                f"C4_INPUT_EXECUTION:{execution_id}:{defect}"
                for defect in verification.defects
            )
            if verification.ok:
                try:
                    current = self._snapshot_execution(execution_id)
                except (
                    IntegrityError,
                    NotFoundError,
                    StateTransitionError,
                    ValidationError,
                ):
                    defects.append(f"C4_INPUT_EXECUTION_INVALID:{execution_id}")
                else:
                    if current != member:
                        defects.append(f"C4_INPUT_MEMBER_STALE:{execution_id}")

        preparation = self._expected_preparation_from_members(
            record,
            tuple(members),
        )
        decision_verification = self.trust.verify_decision(
            record.authorization_decision_id
        )
        defects.extend(
            f"C4_INPUT_AUTHORIZATION:{defect}"
            for defect in decision_verification.defects
        )
        try:
            decision = self.trust.get_decision(record.authorization_decision_id)
        except NotFoundError:
            defects.append("C4_INPUT_AUTHORIZATION_MISSING")
            decision = None
        if decision is not None:
            observed = (
                decision.request.subject,
                decision.request.action,
                decision.request.resource,
                decision.request.mission_id,
                dict(decision.request.context),
            )
            expected = (
                record.frozen_by,
                preparation.action,
                preparation.resource,
                preparation.mission_id,
                dict(preparation.context),
            )
            if not decision.allowed or observed != expected:
                defects.append("C4_INPUT_AUTHORIZATION_REQUEST_MISMATCH")
            if self._as_datetime(record.frozen_at) < self._as_datetime(
                decision.decided_at
            ):
                defects.append("C4_INPUT_FROZEN_AT_PREDATES_AUTHORIZATION")

        consumption = self.database.connection.execute(
            """
            SELECT * FROM continuity_authorization_consumptions
            WHERE decision_id = ?
            """,
            (record.authorization_decision_id,),
        ).fetchone()
        if consumption is None:
            defects.append("C4_INPUT_AUTHORIZATION_CONSUMPTION_MISSING")
        elif (
            str(consumption["operation_kind"]),
            str(consumption["operation_id"]),
            str(consumption["consumed_at"]),
            str(consumption["consumed_by"]),
        ) != (
            _INPUT_EVENT_KIND,
            record.input_set_id,
            record.frozen_at,
            record.frozen_by,
        ):
            defects.append("C4_INPUT_AUTHORIZATION_CONSUMPTION_MISMATCH")

        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (record.ledger_event_id,),
        ).fetchone()
        if event is None:
            defects.append("C4_INPUT_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != self._stream(record.input_set_id):
                defects.append("C4_INPUT_LEDGER_STREAM_MISMATCH")
            if str(event["kind"]) != _INPUT_EVENT_KIND:
                defects.append("C4_INPUT_LEDGER_KIND_MISMATCH")
            if str(event["actor"]) != record.frozen_by:
                defects.append("C4_INPUT_LEDGER_ACTOR_MISMATCH")
            if str(event["occurred_at"]) != record.frozen_at:
                defects.append("C4_INPUT_LEDGER_TIMESTAMP_MISMATCH")
            if str(event["record_hash"]) != record.ledger_hash:
                defects.append("C4_INPUT_LEDGER_HASH_MISMATCH")
            try:
                payload = json.loads(str(event["payload_json"]))
            except (json.JSONDecodeError, TypeError):
                defects.append("C4_INPUT_LEDGER_PAYLOAD_INVALID")
            else:
                if payload != self._ledger_payload(record):
                    defects.append("C4_INPUT_LEDGER_PAYLOAD_MISMATCH")
        chain = self.ledger.verify(self._stream(record.input_set_id))
        defects.extend(
            f"C4_INPUT_LEDGER_CHAIN:{defect.code}"
            for defect in chain.defects
        )
        return C4ArchitectureInputVerification(
            input_set_id=input_set_id,
            defects=tuple(dict.fromkeys(defects)),
        )
