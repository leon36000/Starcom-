from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
import sqlite3
from typing import Mapping

from .adoption_execution import C3AdoptionExecutionService
from .canonical import utc_now
from .continuity_crypto import OpenSSLEd25519Verifier
from .errors import (
    AuthorizationError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    StateTransitionError,
    ValidationError,
)


_NOT_IMPLEMENTED = "C4 architecture review is not implemented"
_MAX_PUBLIC_KEY_BYTES = 8 * 1024
_ROOT_ACTION = "c4.architecture-reviewer.accept"
_ROOT_PURPOSE = "C4_ARCHITECTURE_REVIEW"
_ROOT_EVENT_KIND = "C4_ARCHITECTURE_REVIEWER_ACCEPTED"


class C4ArchitectureReviewVerdict(str, Enum):
    ACCEPTED = "C4_ARCHITECTURE_ACCEPTED"
    REJECTED = "C4_ARCHITECTURE_REJECTED"
    REWORK_REQUIRED = "C4_ARCHITECTURE_REWORK_REQUIRED"


@dataclass(frozen=True)
class C4ArchitectureReviewerRootPreparation:
    key_id: str
    reviewer_identity: str
    algorithm: str
    purpose: str
    fingerprint_sha256: str
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, str]


@dataclass(frozen=True)
class C4ArchitectureReviewerRoot:
    key_id: str
    reviewer_identity: str
    algorithm: str
    purpose: str
    public_key_pem: bytes
    fingerprint_sha256: str
    authorization_decision_id: str
    accepted_at: str
    accepted_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C4ArchitectureReviewerRootVerification:
    key_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


@dataclass(frozen=True)
class C4ArchitectureReviewFinding:
    review_id: str
    ordinal: int
    finding_id: str
    code: str
    severity: str
    evidence_sha256: str
    description: str


@dataclass(frozen=True)
class C4ArchitectureReview:
    review_id: str
    candidate_id: str
    architecture_id: str
    input_set_id: str
    manifest_sha256: str
    input_set_digest: str
    key_id: str
    reviewer_identity: str
    reviewed_at_utc: str
    structural_verification_result: str
    security_verification_result: str
    evidence_binding_result: str
    verdict: C4ArchitectureReviewVerdict
    gate_effect: str
    payload: bytes
    payload_sha256: str
    signature: bytes
    signature_sha256: str
    admitted_at: str
    admitted_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C4ArchitectureReviewVerification:
    review_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C4ArchitectureReviewService:
    """C4 independent-review authority boundary."""

    def __init__(
        self,
        database,
        ledger,
        trust,
        continuity,
        inputs,
        candidates,
        signature_verifier=None,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self.continuity = continuity
        self.inputs = inputs
        self.candidates = candidates
        self.signature_verifier = signature_verifier or OpenSSLEd25519Verifier()
        self._assert_canonical_graph()
        self._initialize_schema()

    def _assert_canonical_graph(self) -> None:
        executions = getattr(self.inputs, "executions", None)
        if type(executions) is not C3AdoptionExecutionService:
            raise ValidationError(
                "C4 architecture review requires the canonical C3 execution service"
            )

        adoption = getattr(executions, "adoption", None)
        decisions = getattr(adoption, "decisions", None)
        qualification = getattr(adoption, "qualification", None)
        c3 = getattr(decisions, "c3", None)
        certification = getattr(decisions, "certification", None)
        recollection = getattr(certification, "recollection", None)
        census = getattr(certification, "census", None)
        research = getattr(recollection, "research", None)
        outbox = getattr(executions, "outbox", None)

        expected = (
            (self.ledger, "database", self.database),
            (self.trust, "database", self.database),
            (self.trust, "ledger", self.ledger),
            (self.continuity, "database", self.database),
            (self.continuity, "ledger", self.ledger),
            (self.continuity, "trust", self.trust),
            (self.inputs, "database", self.database),
            (self.inputs, "ledger", self.ledger),
            (self.inputs, "trust", self.trust),
            (self.inputs, "continuity", self.continuity),
            (self.candidates, "database", self.database),
            (self.candidates, "ledger", self.ledger),
            (self.candidates, "trust", self.trust),
            (self.candidates, "continuity", self.continuity),
            (self.candidates, "inputs", self.inputs),
            (executions, "database", self.database),
            (executions, "ledger", self.ledger),
            (executions, "trust", self.trust),
            (executions, "continuity", self.continuity),
            (adoption, "database", self.database),
            (adoption, "ledger", self.ledger),
            (adoption, "trust", self.trust),
            (adoption, "continuity", self.continuity),
            (adoption, "decisions", decisions),
            (adoption, "qualification", qualification),
            (decisions, "database", self.database),
            (decisions, "ledger", self.ledger),
            (decisions, "continuity", self.continuity),
            (decisions, "qualification", qualification),
            (decisions, "c3", c3),
            (c3, "database", self.database),
            (c3, "ledger", self.ledger),
            (c3, "qualification", qualification),
            (c3, "certification", certification),
            (qualification, "database", self.database),
            (qualification, "ledger", self.ledger),
            (certification, "database", self.database),
            (certification, "ledger", self.ledger),
            (certification, "continuity", self.continuity),
            (certification, "recollection", recollection),
            (certification, "census", census),
            (recollection, "database", self.database),
            (recollection, "ledger", self.ledger),
            (recollection, "continuity", self.continuity),
            (recollection, "research", research),
            (census, "database", self.database),
            (census, "ledger", self.ledger),
            (census, "recollection", recollection),
            (census, "research", research),
            (research, "database", self.database),
            (research, "ledger", self.ledger),
            (outbox, "database", self.database),
            (outbox, "ledger", self.ledger),
        )
        if any(
            item is None or getattr(item, attribute, None) is not value
            for item, attribute, value in expected
        ):
            raise ValidationError(
                "C4 architecture review dependencies must share one canonical graph"
            )

    @staticmethod
    def _required_text(value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{field} must be a non-empty string")
        return value

    @staticmethod
    def _bounded_bytes(value: object, field: str) -> bytes:
        if not isinstance(value, bytes) or not value or len(value) > _MAX_PUBLIC_KEY_BYTES:
            raise ValidationError(f"{field} must be non-empty bytes within the size limit")
        return value

    @staticmethod
    def _timestamp(value: object) -> str:
        if not isinstance(value, str):
            raise ValidationError("timestamp must be RFC 3339")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError("timestamp must be RFC 3339") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValidationError("timestamp must be timezone-aware")
        return value

    @staticmethod
    def _as_datetime(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    @staticmethod
    def _fingerprint(public_key_pem: bytes) -> str:
        return hashlib.sha256(public_key_pem).hexdigest()

    @staticmethod
    def _stream(key_id: str) -> str:
        return f"continuity:c4:architecture-reviewer:{key_id}"

    @staticmethod
    def _mission(key_id: str) -> str:
        return f"c4-architecture-reviewer:{key_id}"

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c4_architecture_reviewer_roots (
                    key_id TEXT PRIMARY KEY,
                    reviewer_identity TEXT NOT NULL,
                    algorithm TEXT NOT NULL CHECK (algorithm = 'Ed25519'),
                    purpose TEXT NOT NULL CHECK (purpose = 'C4_ARCHITECTURE_REVIEW'),
                    public_key_pem BLOB NOT NULL,
                    fingerprint_sha256 TEXT NOT NULL UNIQUE CHECK (length(fingerprint_sha256) = 64),
                    authorization_decision_id TEXT NOT NULL UNIQUE,
                    accepted_at TEXT NOT NULL,
                    accepted_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (authorization_decision_id) REFERENCES trust_decisions(decision_id)
                )
                """
            )
            for operation in ("UPDATE", "DELETE"):
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS c4_architecture_reviewer_roots_no_{operation.lower()}
                    BEFORE {operation} ON c4_architecture_reviewer_roots
                    BEGIN SELECT RAISE(ABORT, 'reviewer roots are immutable'); END
                    """
                )

    def prepare_reviewer_root(
        self, key_id: str, reviewer_identity: str, public_key_pem: bytes
    ) -> C4ArchitectureReviewerRootPreparation:
        key_id = self._required_text(key_id, "key_id")
        reviewer_identity = self._required_text(reviewer_identity, "reviewer_identity")
        public_key_pem = self._bounded_bytes(public_key_pem, "public_key_pem")
        if not self.signature_verifier.validate_public_key(public_key_pem):
            raise ValidationError("public_key_pem must be a valid Ed25519 public key")
        fingerprint = self._fingerprint(public_key_pem)
        context = {
            "algorithm": "Ed25519",
            "fingerprint_sha256": fingerprint,
            "purpose": _ROOT_PURPOSE,
            "reviewer_identity": reviewer_identity,
        }
        return C4ArchitectureReviewerRootPreparation(
            key_id, reviewer_identity, "Ed25519", _ROOT_PURPOSE, fingerprint,
            _ROOT_ACTION, self._stream(key_id), self._mission(key_id), context,
        )

    @staticmethod
    def _root_from_row(row: sqlite3.Row) -> C4ArchitectureReviewerRoot:
        return C4ArchitectureReviewerRoot(
            str(row["key_id"]), str(row["reviewer_identity"]), str(row["algorithm"]),
            str(row["purpose"]), bytes(row["public_key_pem"]),
            str(row["fingerprint_sha256"]), str(row["authorization_decision_id"]),
            str(row["accepted_at"]), str(row["accepted_by"]),
            str(row["ledger_event_id"]), str(row["ledger_hash"]),
        )

    def _assert_authorization(
        self,
        decision_id: str,
        preparation: C4ArchitectureReviewerRootPreparation,
        actor: str,
    ):
        verification = self.trust.verify_decision(decision_id)
        if not verification.ok:
            raise AuthorizationError(
                "reviewer-root authorization decision failed verification"
            )
        try:
            decision = self.trust.get_decision(decision_id)
        except NotFoundError as exc:
            raise AuthorizationError(
                "reviewer-root authorization decision does not exist"
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
                "reviewer-root authorization does not exactly match acceptance"
            )
        return decision

    @staticmethod
    def _root_payload(
        preparation: C4ArchitectureReviewerRootPreparation,
        authorization_decision_id: str,
    ) -> dict[str, str]:
        return {
            "key_id": preparation.key_id,
            "reviewer_identity": preparation.reviewer_identity,
            "algorithm": preparation.algorithm,
            "purpose": preparation.purpose,
            "fingerprint_sha256": preparation.fingerprint_sha256,
            "authorization_decision_id": authorization_decision_id,
        }

    @staticmethod
    def _root_row_matches(
        row: sqlite3.Row,
        preparation: C4ArchitectureReviewerRootPreparation,
        public_key_pem: bytes,
        authorization_decision_id: str,
        actor: str,
    ) -> bool:
        raw_public_key = row["public_key_pem"]
        if not isinstance(raw_public_key, (bytes, bytearray, memoryview)):
            return False
        return (
            str(row["key_id"]),
            str(row["reviewer_identity"]),
            str(row["algorithm"]),
            str(row["purpose"]),
            bytes(raw_public_key),
            str(row["fingerprint_sha256"]),
            str(row["authorization_decision_id"]),
            str(row["accepted_by"]),
        ) == (
            preparation.key_id,
            preparation.reviewer_identity,
            preparation.algorithm,
            preparation.purpose,
            public_key_pem,
            preparation.fingerprint_sha256,
            authorization_decision_id,
            actor,
        )

    @staticmethod
    def _find_root_binding(
        connection: sqlite3.Connection,
        preparation: C4ArchitectureReviewerRootPreparation,
        authorization_decision_id: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT * FROM c4_architecture_reviewer_roots
            WHERE key_id = ? OR fingerprint_sha256 = ?
               OR authorization_decision_id = ?
            ORDER BY
                CASE
                    WHEN key_id = ? THEN 0
                    WHEN fingerprint_sha256 = ? THEN 1
                    ELSE 2
                END,
                key_id
            LIMIT 1
            """,
            (
                preparation.key_id,
                preparation.fingerprint_sha256,
                authorization_decision_id,
                preparation.key_id,
                preparation.fingerprint_sha256,
            ),
        ).fetchone()

    def _verified_root_from_row(
        self,
        row: sqlite3.Row,
        preparation: C4ArchitectureReviewerRootPreparation,
        public_key_pem: bytes,
        authorization_decision_id: str,
        actor: str,
    ) -> C4ArchitectureReviewerRoot:
        if not self._root_row_matches(
            row,
            preparation,
            public_key_pem,
            authorization_decision_id,
            actor,
        ):
            raise ConflictError(
                "reviewer-root key, fingerprint, or authorization is already bound",
                {"existing_key_id": str(row["key_id"])},
            )
        verification = self.verify_reviewer_root(preparation.key_id)
        if not verification.ok:
            raise IntegrityError(
                "stored reviewer root failed verification",
                {"defects": list(verification.defects)},
            )
        try:
            return self._root_from_row(row)
        except (TypeError, ValueError) as exc:
            raise IntegrityError("stored reviewer root is malformed") from exc

    def accept_reviewer_root(
        self,
        key_id: str,
        reviewer_identity: str,
        public_key_pem: bytes,
        *,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> C4ArchitectureReviewerRoot:
        preparation = self.prepare_reviewer_root(
            key_id,
            reviewer_identity,
            public_key_pem,
        )
        authorization_decision_id = self._required_text(
            authorization_decision_id,
            "authorization_decision_id",
        )
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now())
        if actor == preparation.reviewer_identity:
            raise StateTransitionError("reviewer cannot authorize their own root")

        existing = self._find_root_binding(
            self.database.connection,
            preparation,
            authorization_decision_id,
        )
        if existing is not None:
            return self._verified_root_from_row(
                existing,
                preparation,
                public_key_pem,
                authorization_decision_id,
                actor,
            )

        decision = self._assert_authorization(
            authorization_decision_id,
            preparation,
            actor,
        )
        if self._as_datetime(occurred_at) < self._as_datetime(decision.decided_at):
            raise ValidationError("reviewer-root acceptance predates authorization")
        payload = self._root_payload(preparation, authorization_decision_id)

        try:
            with self.database.transaction() as connection:
                current_preparation = self.prepare_reviewer_root(
                    key_id,
                    reviewer_identity,
                    public_key_pem,
                )
                if current_preparation != preparation:
                    raise ConflictError(
                        "reviewer-root material changed during acceptance"
                    )
                if actor == current_preparation.reviewer_identity:
                    raise StateTransitionError(
                        "reviewer cannot authorize their own root"
                    )

                race = self._find_root_binding(
                    connection,
                    current_preparation,
                    authorization_decision_id,
                )
                if race is not None:
                    return self._verified_root_from_row(
                        race,
                        current_preparation,
                        public_key_pem,
                        authorization_decision_id,
                        actor,
                    )

                current_decision = self._assert_authorization(
                    authorization_decision_id,
                    current_preparation,
                    actor,
                )
                if self._as_datetime(occurred_at) < self._as_datetime(
                    current_decision.decided_at
                ):
                    raise ValidationError(
                        "reviewer-root acceptance predates authorization"
                    )
                self.continuity._consume_authorization(
                    connection,
                    decision_id=authorization_decision_id,
                    operation_kind=_ROOT_EVENT_KIND,
                    operation_id=current_preparation.key_id,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    current_preparation.resource,
                    _ROOT_EVENT_KIND,
                    payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO c4_architecture_reviewer_roots (
                        key_id, reviewer_identity, algorithm, purpose,
                        public_key_pem, fingerprint_sha256,
                        authorization_decision_id, accepted_at, accepted_by,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        current_preparation.key_id,
                        current_preparation.reviewer_identity,
                        current_preparation.algorithm,
                        current_preparation.purpose,
                        sqlite3.Binary(public_key_pem),
                        current_preparation.fingerprint_sha256,
                        authorization_decision_id,
                        occurred_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            race = self._find_root_binding(
                self.database.connection,
                preparation,
                authorization_decision_id,
            )
            if race is not None and self._root_row_matches(
                race,
                preparation,
                public_key_pem,
                authorization_decision_id,
                actor,
            ):
                return self._verified_root_from_row(
                    race,
                    preparation,
                    public_key_pem,
                    authorization_decision_id,
                    actor,
                )
            raise ConflictError(
                "reviewer root conflicts with immutable state"
            ) from exc
        return self.get_reviewer_root(preparation.key_id)

    def get_reviewer_root(self, key_id: str) -> C4ArchitectureReviewerRoot:
        key_id = self._required_text(key_id, "key_id")
        row = self.database.connection.execute(
            "SELECT * FROM c4_architecture_reviewer_roots WHERE key_id = ?", (key_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("C4 architecture reviewer root does not exist", {"key_id": key_id})
        return self._root_from_row(row)

    def verify_reviewer_root(
        self,
        key_id: str,
    ) -> C4ArchitectureReviewerRootVerification:
        key_id = self._required_text(key_id, "key_id")
        row = self.database.connection.execute(
            "SELECT * FROM c4_architecture_reviewer_roots WHERE key_id = ?",
            (key_id,),
        ).fetchone()
        if row is None:
            return C4ArchitectureReviewerRootVerification(
                key_id,
                ("REVIEWER_ROOT_NOT_FOUND",),
            )

        defects: list[str] = []
        reviewer_identity = str(row["reviewer_identity"])
        algorithm = str(row["algorithm"])
        purpose = str(row["purpose"])
        stored_fingerprint = str(row["fingerprint_sha256"])
        decision_id = str(row["authorization_decision_id"])
        accepted_at = str(row["accepted_at"])
        accepted_by = str(row["accepted_by"])

        try:
            self._required_text(reviewer_identity, "reviewer_identity")
        except ValidationError:
            defects.append("REVIEWER_ROOT_IDENTITY_MISMATCH")
        if algorithm != "Ed25519":
            defects.append("REVIEWER_ROOT_ALGORITHM_MISMATCH")
        if purpose != _ROOT_PURPOSE:
            defects.append("REVIEWER_ROOT_PURPOSE_MISMATCH")
        try:
            self._required_text(accepted_by, "accepted_by")
        except ValidationError:
            defects.append("REVIEWER_ROOT_ACCEPTANCE_ACTOR_INVALID")
        if accepted_by == reviewer_identity:
            defects.append("REVIEWER_ROOT_ACCEPTANCE_SELF_AUTHORIZATION")

        public_key: bytes | None = None
        fingerprint: str | None = None
        raw_public_key = row["public_key_pem"]
        if isinstance(raw_public_key, (bytes, bytearray, memoryview)):
            public_key = bytes(raw_public_key)
            if not public_key or len(public_key) > _MAX_PUBLIC_KEY_BYTES:
                defects.append("REVIEWER_ROOT_PUBLIC_KEY_INVALID")
            else:
                fingerprint = self._fingerprint(public_key)
                try:
                    public_key_valid = self.signature_verifier.validate_public_key(
                        public_key
                    )
                except (OSError, TypeError, ValueError):
                    public_key_valid = False
                if not public_key_valid:
                    defects.append("REVIEWER_ROOT_PUBLIC_KEY_INVALID")
        else:
            defects.append("REVIEWER_ROOT_PUBLIC_KEY_INVALID")
        if fingerprint is None or fingerprint != stored_fingerprint:
            defects.append("REVIEWER_ROOT_FINGERPRINT_MISMATCH")

        accepted_time: datetime | None = None
        try:
            accepted_time = self._as_datetime(self._timestamp(accepted_at))
        except (ValidationError, ValueError):
            defects.append("REVIEWER_ROOT_ACCEPTANCE_CHRONOLOGY_INVALID")

        expected_context: dict[str, str] | None = None
        if fingerprint is not None and reviewer_identity.strip():
            expected_context = {
                "algorithm": "Ed25519",
                "fingerprint_sha256": fingerprint,
                "purpose": _ROOT_PURPOSE,
                "reviewer_identity": reviewer_identity,
            }

        decision_verification_ok = False
        try:
            decision_verification = self.trust.verify_decision(decision_id)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError, sqlite3.Error):
            defects.append("REVIEWER_ROOT_DECISION_INVALID")
        else:
            decision_verification_ok = decision_verification.ok
            defects.extend(
                f"REVIEWER_ROOT_DECISION:{defect}"
                for defect in decision_verification.defects
            )
            if not decision_verification_ok:
                defects.append("REVIEWER_ROOT_DECISION_INVALID")

        try:
            decision = self.trust.get_decision(decision_id)
        except (
            NotFoundError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ):
            decision = None
            defects.append("REVIEWER_ROOT_DECISION_INVALID")

        if decision is not None:
            request_mismatch = False
            if not decision.allowed:
                request_mismatch = True
            if decision.request.subject != accepted_by:
                defects.append("REVIEWER_ROOT_ACCEPTANCE_ACTOR_MISMATCH")
                request_mismatch = True
            if decision.request.action != _ROOT_ACTION:
                defects.append("REVIEWER_ROOT_DECISION_ACTION_MISMATCH")
                request_mismatch = True
            if decision.request.resource != self._stream(key_id):
                defects.append("REVIEWER_ROOT_DECISION_RESOURCE_MISMATCH")
                request_mismatch = True
            if decision.request.mission_id != self._mission(key_id):
                defects.append("REVIEWER_ROOT_DECISION_MISSION_MISMATCH")
                request_mismatch = True

            try:
                decision_context = dict(decision.request.context)
            except (TypeError, ValueError):
                decision_context = None
                request_mismatch = True
            if decision_context is None or expected_context is None:
                request_mismatch = True
            else:
                if (
                    decision_context.get("reviewer_identity")
                    != reviewer_identity
                ):
                    defects.append("REVIEWER_ROOT_IDENTITY_MISMATCH")
                if decision_context.get("algorithm") != "Ed25519":
                    defects.append(
                        "REVIEWER_ROOT_DECISION_ALGORITHM_MISMATCH"
                    )
                if decision_context.get("purpose") != _ROOT_PURPOSE:
                    defects.append("REVIEWER_ROOT_DECISION_PURPOSE_MISMATCH")
                if (
                    decision_context.get("fingerprint_sha256")
                    != fingerprint
                ):
                    defects.append(
                        "REVIEWER_ROOT_DECISION_FINGERPRINT_MISMATCH"
                    )
                if decision_context != expected_context:
                    request_mismatch = True
            if request_mismatch:
                defects.append("REVIEWER_ROOT_DECISION_REQUEST_MISMATCH")
                defects.append("REVIEWER_ROOT_DECISION_INVALID")

            decision_time: datetime | None = None
            try:
                decision_time = self._as_datetime(
                    self._timestamp(decision.decided_at)
                )
            except (ValidationError, ValueError):
                defects.append("REVIEWER_ROOT_ACCEPTANCE_CHRONOLOGY_INVALID")
            if (
                accepted_time is not None
                and decision_time is not None
                and accepted_time < decision_time
            ):
                defects.append("REVIEWER_ROOT_ACCEPTANCE_PREDATES_DECISION")

        consumption = self.database.connection.execute(
            """
            SELECT * FROM continuity_authorization_consumptions
            WHERE decision_id = ?
            """,
            (decision_id,),
        ).fetchone()
        consumption_mismatch = False
        if consumption is None:
            defects.append("REVIEWER_ROOT_AUTHORIZATION_CONSUMPTION_MISSING")
            consumption_mismatch = True
        else:
            if str(consumption["operation_kind"]) != _ROOT_EVENT_KIND:
                defects.append(
                    "REVIEWER_ROOT_AUTHORIZATION_CONSUMPTION_KIND_MISMATCH"
                )
                consumption_mismatch = True
            if str(consumption["operation_id"]) != key_id:
                defects.append(
                    "REVIEWER_ROOT_AUTHORIZATION_CONSUMPTION_ID_MISMATCH"
                )
                consumption_mismatch = True
            if str(consumption["consumed_by"]) != accepted_by:
                defects.append(
                    "REVIEWER_ROOT_AUTHORIZATION_CONSUMPTION_ACTOR_MISMATCH"
                )
                consumption_mismatch = True
            if str(consumption["consumed_at"]) != accepted_at:
                defects.append(
                    "REVIEWER_ROOT_AUTHORIZATION_CONSUMPTION_TIME_MISMATCH"
                )
                consumption_mismatch = True
        if consumption_mismatch:
            defects.append(
                "REVIEWER_ROOT_AUTHORIZATION_CONSUMPTION_MISMATCH"
            )

        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (str(row["ledger_event_id"]),),
        ).fetchone()
        expected_payload = {
            "key_id": str(row["key_id"]),
            "reviewer_identity": reviewer_identity,
            "algorithm": algorithm,
            "purpose": purpose,
            "fingerprint_sha256": stored_fingerprint,
            "authorization_decision_id": decision_id,
        }
        event_mismatch = False
        if event is None:
            defects.append("REVIEWER_ROOT_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != self._stream(key_id):
                defects.append("REVIEWER_ROOT_LEDGER_STREAM_MISMATCH")
                event_mismatch = True
            if str(event["kind"]) != _ROOT_EVENT_KIND:
                defects.append("REVIEWER_ROOT_LEDGER_KIND_MISMATCH")
                event_mismatch = True
            if str(event["actor"]) != accepted_by:
                defects.append("REVIEWER_ROOT_LEDGER_ACTOR_MISMATCH")
                event_mismatch = True
            if str(event["occurred_at"]) != accepted_at:
                defects.append("REVIEWER_ROOT_LEDGER_TIME_MISMATCH")
                event_mismatch = True
            if str(event["record_hash"]) != str(row["ledger_hash"]):
                defects.append("REVIEWER_ROOT_LEDGER_HASH_MISMATCH")
                event_mismatch = True
            try:
                payload = json.loads(str(event["payload_json"]))
                if not isinstance(payload, dict):
                    raise ValueError("root event payload must be an object")
            except (json.JSONDecodeError, TypeError, ValueError):
                defects.append("REVIEWER_ROOT_LEDGER_PAYLOAD_INVALID")
                event_mismatch = True
            else:
                if payload != expected_payload:
                    defects.append("REVIEWER_ROOT_LEDGER_PAYLOAD_MISMATCH")
                    event_mismatch = True
            if event_mismatch:
                defects.append("REVIEWER_ROOT_LEDGER_EVENT_MISMATCH")

        try:
            chain = self.ledger.verify(self._stream(key_id))
        except (json.JSONDecodeError, TypeError, ValueError, sqlite3.Error):
            defects.append("REVIEWER_ROOT_LEDGER_CHAIN_INVALID")
        else:
            if not chain.ok:
                defects.extend(
                    f"REVIEWER_ROOT_LEDGER_CHAIN:{defect.code}"
                    for defect in chain.defects
                )
                defects.append("REVIEWER_ROOT_LEDGER_CHAIN_INVALID")

        if not decision_verification_ok:
            defects.append("REVIEWER_ROOT_DECISION_INVALID")
        return C4ArchitectureReviewerRootVerification(
            key_id,
            tuple(dict.fromkeys(defects)),
        )

    def admit_review(
        self,
        candidate_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        *,
        actor: str,
        occurred_at: str | None = None,
    ) -> C4ArchitectureReview:
        candidate_id = self._required_text(candidate_id, "candidate_id")
        key_id = self._required_text(key_id, "key_id")
        actor = self._required_text(actor, "actor")
        self._timestamp(occurred_at or utc_now())
        if not isinstance(payload, bytes) or not payload:
            raise ValidationError("payload must be non-empty bytes")
        if not isinstance(signature, bytes) or not signature:
            raise ValidationError("signature must be non-empty bytes")

        root_verification = self.verify_reviewer_root(key_id)
        if not root_verification.ok:
            raise IntegrityError(
                "reviewer root failed verification",
                {"defects": list(root_verification.defects)},
            )
        root = self.get_reviewer_root(key_id)
        try:
            signature_ok = self.signature_verifier.verify(
                root.public_key_pem,
                payload,
                signature,
            )
        except (OSError, TypeError, ValueError) as exc:
            raise IntegrityError("C4 architecture review signature verification failed") from exc
        if not signature_ok:
            raise IntegrityError("C4 architecture review signature verification failed")

        try:
            decoded = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValidationError("review payload must be valid UTF-8") from exc

        def reject_duplicate_keys(pairs):  # type: ignore[no-untyped-def]
            value: dict[str, object] = {}
            for name, item in pairs:
                if name in value:
                    raise ValidationError(f"duplicate JSON key: {name}")
                value[name] = item
            return value

        try:
            parsed = json.loads(decoded, object_pairs_hook=reject_duplicate_keys)
        except ValidationError:
            raise
        except json.JSONDecodeError as exc:
            raise ValidationError("review payload must be valid JSON") from exc
        if not isinstance(parsed, dict):
            raise ValidationError("review payload must be a JSON object")

        raise StateTransitionError(_NOT_IMPLEMENTED)

    def get_review(self, review_id: str) -> C4ArchitectureReview:
        raise StateTransitionError(_NOT_IMPLEMENTED)

    def get_review_for_candidate(self, candidate_id: str) -> C4ArchitectureReview:
        raise StateTransitionError(_NOT_IMPLEMENTED)

    def get_findings(self, review_id: str) -> tuple[C4ArchitectureReviewFinding, ...]:
        raise StateTransitionError(_NOT_IMPLEMENTED)

    def verify_review(self, review_id: str) -> C4ArchitectureReviewVerification:
        return C4ArchitectureReviewVerification(review_id, ("NOT_IMPLEMENTED",))
