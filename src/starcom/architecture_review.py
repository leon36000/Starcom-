from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
import re
import sqlite3
from typing import Mapping

from .adoption_execution import C3AdoptionExecutionService
from .canonical import sha256_digest, utc_now
from .continuity_crypto import (
    MAX_PAYLOAD_BYTES,
    MAX_SIGNATURE_BYTES,
    OpenSSLEd25519Verifier,
)
from .errors import (
    AuthorizationError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    StateTransitionError,
    ValidationError,
)


_MAX_PUBLIC_KEY_BYTES = 8 * 1024
_MAX_IDENTIFIER_UTF8_BYTES = 256
_MAX_NARRATIVE_UTF8_BYTES = 16 * 1024
_MAX_IDENTITY_LIST_ITEMS = 256
_MAX_FINDINGS = 256
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ENVIRONMENT_FIELDS = frozenset({"description", "environment_type"})
_INDEPENDENCE_FIELDS = frozenset({"excluded_identities", "statement"})
_FINDING_FIELDS = frozenset(
    {"finding_id", "code", "severity", "evidence_sha256", "description"}
)
_ENVIRONMENT_TYPES = frozenset(
    {"ISOLATED_WORKTREE", "OFFLINE_EVIDENCE_BUNDLE", "OTHER_ISOLATED"}
)
_FINDING_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})
_FINDING_CODES = frozenset(
    {
        "STRUCTURAL_CONTRACT_VIOLATION",
        "AUTHORITY_BOUNDARY_VIOLATION",
        "MISSION_FABRIC_INCOMPLETE",
        "COMPONENT_BINDING_INVALID",
        "VERTICAL_BENCHMARK_INSUFFICIENT",
        "NON_FUNCTIONAL_REQUIREMENT_INSUFFICIENT",
        "DEFAULT_DENY_VIOLATION",
        "TRUST_BOUNDARY_VIOLATION",
        "EVIDENCE_MISSING",
        "EVIDENCE_DIGEST_MISMATCH",
        "EVIDENCE_STALE",
        "INDEPENDENCE_VIOLATION",
        "CHRONOLOGY_VIOLATION",
        "UNCLASSIFIED_REVIEW_FINDING",
    }
)
_ROOT_ACTION = "c4.architecture-reviewer.accept"
_ROOT_PURPOSE = "C4_ARCHITECTURE_REVIEW"
_ROOT_EVENT_KIND = "C4_ARCHITECTURE_REVIEWER_ACCEPTED"
_REVIEW_EVENT_KIND = "C4_ARCHITECTURE_REVIEW_ADMITTED"
_REVIEW_GATE_EFFECT = "NO_PUBLICATION_NO_DEPLOYMENT"
_REVIEW_TOP_LEVEL_KEYS = frozenset(
    {
        "review_id",
        "candidate_id",
        "architecture_id",
        "input_set_id",
        "manifest_sha256",
        "input_set_digest",
        "reviewer_identity",
        "reviewer_environment",
        "independence_basis",
        "reviewed_at_utc",
        "structural_verification_result",
        "security_verification_result",
        "evidence_binding_result",
        "verdict",
        "findings",
        "gate_effect",
    }
)
_VERIFICATION_RESULTS = frozenset({"PASS", "FAIL"})


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
    def _required_text(
        value: object,
        field: str,
        *,
        maximum_utf8_bytes: int = _MAX_IDENTIFIER_UTF8_BYTES,
    ) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{field} must be a non-empty string")
        try:
            encoded = value.encode("utf-8")
        except UnicodeError as exc:
            raise ValidationError(f"{field} must be valid UTF-8 text") from exc
        if len(encoded) > maximum_utf8_bytes:
            raise ValidationError(f"{field} exceeds the UTF-8 size limit")
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
    def _canonical_utc_timestamp(value: object, field: str) -> str:
        if not isinstance(value, str):
            raise ValidationError(f"{field} must be a canonical UTC timestamp")
        try:
            parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError as exc:
            raise ValidationError(f"{field} must be a canonical UTC timestamp") from exc
        if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
            raise ValidationError(f"{field} must be a canonical UTC timestamp")
        return value

    @staticmethod
    def _sha256_text(value: object, field: str) -> str:
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
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
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c4_architecture_reviews (
                    review_id TEXT PRIMARY KEY,
                    candidate_id TEXT NOT NULL UNIQUE,
                    architecture_id TEXT NOT NULL,
                    input_set_id TEXT NOT NULL,
                    manifest_sha256 TEXT NOT NULL
                        CHECK (length(manifest_sha256) = 64),
                    input_set_digest TEXT NOT NULL
                        CHECK (length(input_set_digest) = 64),
                    key_id TEXT NOT NULL,
                    reviewer_identity TEXT NOT NULL,
                    reviewed_at_utc TEXT NOT NULL,
                    structural_verification_result TEXT NOT NULL
                        CHECK (structural_verification_result IN ('PASS', 'FAIL')),
                    security_verification_result TEXT NOT NULL
                        CHECK (security_verification_result IN ('PASS', 'FAIL')),
                    evidence_binding_result TEXT NOT NULL
                        CHECK (evidence_binding_result IN ('PASS', 'FAIL')),
                    verdict TEXT NOT NULL CHECK (verdict IN (
                        'C4_ARCHITECTURE_ACCEPTED',
                        'C4_ARCHITECTURE_REJECTED',
                        'C4_ARCHITECTURE_REWORK_REQUIRED'
                    )),
                    gate_effect TEXT NOT NULL
                        CHECK (gate_effect = 'NO_PUBLICATION_NO_DEPLOYMENT'),
                    payload BLOB NOT NULL,
                    payload_sha256 TEXT NOT NULL UNIQUE
                        CHECK (length(payload_sha256) = 64),
                    signature BLOB NOT NULL,
                    signature_sha256 TEXT NOT NULL
                        CHECK (length(signature_sha256) = 64),
                    admitted_at TEXT NOT NULL,
                    admitted_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (candidate_id)
                        REFERENCES c4_architecture_candidates(candidate_id),
                    FOREIGN KEY (input_set_id)
                        REFERENCES c4_architecture_input_sets(input_set_id),
                    FOREIGN KEY (key_id)
                        REFERENCES c4_architecture_reviewer_roots(key_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c4_architecture_review_findings (
                    review_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                    finding_id TEXT NOT NULL,
                    code TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    evidence_sha256 TEXT NOT NULL
                        CHECK (length(evidence_sha256) = 64),
                    description TEXT NOT NULL,
                    PRIMARY KEY (review_id, ordinal),
                    UNIQUE (review_id, finding_id),
                    FOREIGN KEY (review_id)
                        REFERENCES c4_architecture_reviews(review_id)
                )
                """
            )
            for table in (
                "c4_architecture_reviews",
                "c4_architecture_review_findings",
            ):
                for operation in ("UPDATE", "DELETE"):
                    connection.execute(
                        f"""
                        CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.lower()}
                        BEFORE {operation} ON {table}
                        BEGIN SELECT RAISE(ABORT, '{table} rows are immutable'); END
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
                event_payload = json.loads(str(event["payload_json"]))
                if not isinstance(event_payload, dict):
                    raise ValueError("root event payload must be an object")
            except (json.JSONDecodeError, TypeError, ValueError):
                defects.append("REVIEWER_ROOT_LEDGER_PAYLOAD_INVALID")
                event_mismatch = True
            else:
                if event_payload != expected_payload:
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

    @staticmethod
    def _bounded_transport_bytes(
        value: object,
        field: str,
        maximum: int,
    ) -> bytes:
        if not isinstance(value, bytes) or not value or len(value) > maximum:
            raise ValidationError(f"{field} must be non-empty bytes within the size limit")
        return value

    @staticmethod
    def _closed_object(
        value: object,
        field: str,
        fields: frozenset[str],
    ) -> dict[str, object]:
        if not isinstance(value, dict) or frozenset(value) != fields:
            raise ValidationError(f"{field} must use the exact closed schema")
        return value

    @staticmethod
    def _reject_duplicate_object(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValidationError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    @staticmethod
    def _reject_json_constant(value: str) -> object:
        raise ValidationError(f"non-standard JSON constant is forbidden: {value}")

    @classmethod
    def _strict_json_object(cls, payload: bytes) -> dict[str, object]:
        try:
            text = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValidationError("review payload must be valid UTF-8") from exc
        try:
            decoded = json.loads(
                text,
                object_pairs_hook=cls._reject_duplicate_object,
                parse_constant=cls._reject_json_constant,
            )
        except json.JSONDecodeError as exc:
            raise ValidationError("review payload must be valid JSON") from exc
        except RecursionError as exc:
            raise ValidationError("review payload JSON nesting is invalid") from exc
        if not isinstance(decoded, dict):
            raise ValidationError("review payload must be a JSON object")
        return decoded

    @staticmethod
    def _digest(value: object, field: str) -> str:
        if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
            raise ValidationError(
                f"{field} must be exactly 64 lowercase hexadecimal characters"
            )
        return value

    @staticmethod
    def _canonical_review_timestamp(value: object) -> str:
        if not isinstance(value, str):
            raise ValidationError("reviewed_at_utc must use canonical UTC spelling")
        try:
            parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError as exc:
            raise ValidationError(
                "reviewed_at_utc must use canonical UTC spelling"
            ) from exc
        if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
            raise ValidationError(
                "reviewed_at_utc must round-trip to canonical UTC spelling"
            )
        return value

    @staticmethod
    def _enum(value: object, field: str, allowed: frozenset[str]) -> str:
        if not isinstance(value, str) or value not in allowed:
            raise ValidationError(f"{field} is outside the closed enum")
        return value

    @classmethod
    def _excluded_identities(cls, value: object) -> list[str]:
        if not isinstance(value, list) or len(value) > _MAX_IDENTITY_LIST_ITEMS:
            raise ValidationError(
                "independence_basis.excluded_identities exceeds the list boundary"
            )
        identities = [
            cls._required_text(item, "independence_basis.excluded_identities[]")
            for item in value
        ]
        if identities != sorted(identities) or len(identities) != len(set(identities)):
            raise ValidationError(
                "independence_basis.excluded_identities must be sorted and duplicate-free"
            )
        return identities

    @classmethod
    def _findings(cls, value: object) -> list[dict[str, object]]:
        if not isinstance(value, list) or len(value) > _MAX_FINDINGS:
            raise ValidationError("findings must be a bounded list")
        findings: list[dict[str, object]] = []
        finding_ids: list[str] = []
        for ordinal, item in enumerate(value):
            finding = cls._closed_object(
                item,
                f"findings[{ordinal}]",
                _FINDING_FIELDS,
            )
            finding_id = cls._required_text(
                finding["finding_id"],
                f"findings[{ordinal}].finding_id",
            )
            cls._enum(finding["code"], f"findings[{ordinal}].code", _FINDING_CODES)
            cls._enum(
                finding["severity"],
                f"findings[{ordinal}].severity",
                _FINDING_SEVERITIES,
            )
            cls._digest(
                finding["evidence_sha256"],
                f"findings[{ordinal}].evidence_sha256",
            )
            cls._required_text(
                finding["description"],
                f"findings[{ordinal}].description",
                maximum_utf8_bytes=_MAX_NARRATIVE_UTF8_BYTES,
            )
            finding_ids.append(finding_id)
            findings.append(finding)
        if finding_ids != sorted(finding_ids) or len(finding_ids) != len(set(finding_ids)):
            raise ValidationError("findings must be sorted by unique finding_id")
        return findings

    @classmethod
    def _parse_review_payload(cls, payload: bytes) -> dict[str, object]:
        review = cls._closed_object(
            cls._strict_json_object(payload),
            "review payload",
            _REVIEW_TOP_LEVEL_KEYS,
        )
        for field in (
            "review_id",
            "candidate_id",
            "architecture_id",
            "input_set_id",
            "reviewer_identity",
        ):
            cls._required_text(review[field], field)
        cls._digest(review["manifest_sha256"], "manifest_sha256")
        cls._digest(review["input_set_digest"], "input_set_digest")
        cls._canonical_review_timestamp(review["reviewed_at_utc"])

        environment = cls._closed_object(
            review["reviewer_environment"],
            "reviewer_environment",
            _ENVIRONMENT_FIELDS,
        )
        cls._required_text(
            environment["description"],
            "reviewer_environment.description",
            maximum_utf8_bytes=_MAX_NARRATIVE_UTF8_BYTES,
        )
        cls._enum(
            environment["environment_type"],
            "reviewer_environment.environment_type",
            _ENVIRONMENT_TYPES,
        )

        independence = cls._closed_object(
            review["independence_basis"],
            "independence_basis",
            _INDEPENDENCE_FIELDS,
        )
        cls._excluded_identities(independence["excluded_identities"])
        cls._required_text(
            independence["statement"],
            "independence_basis.statement",
            maximum_utf8_bytes=_MAX_NARRATIVE_UTF8_BYTES,
        )

        results = tuple(
            cls._enum(review[field], field, _VERIFICATION_RESULTS)
            for field in (
                "structural_verification_result",
                "security_verification_result",
                "evidence_binding_result",
            )
        )
        verdict = cls._enum(
            review["verdict"],
            "verdict",
            frozenset(member.value for member in C4ArchitectureReviewVerdict),
        )
        if review["gate_effect"] != _REVIEW_GATE_EFFECT:
            raise ValidationError(
                "gate_effect must remain NO_PUBLICATION_NO_DEPLOYMENT"
            )
        findings = cls._findings(review["findings"])
        has_failure = "FAIL" in results
        if verdict == C4ArchitectureReviewVerdict.ACCEPTED.value:
            if has_failure or findings:
                raise ValidationError(
                    "accepted review requires all PASS results and no findings"
                )
        elif not has_failure or not findings:
            raise ValidationError(
                "rejected or rework review requires a FAIL result and finding"
            )
        return review

    @staticmethod
    def _review_stream(candidate_id: str) -> str:
        return f"continuity:c4:architecture-review:{candidate_id}"

    @staticmethod
    def _blob_from_row(row: sqlite3.Row, field: str) -> bytes:
        value = row[field]
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise IntegrityError(f"stored C4 review {field} is not binary")
        return bytes(value)

    @classmethod
    def _review_from_row(cls, row: sqlite3.Row) -> C4ArchitectureReview:
        try:
            verdict = C4ArchitectureReviewVerdict(str(row["verdict"]))
        except ValueError as exc:
            raise IntegrityError("stored C4 review verdict is invalid") from exc
        gate_effect = str(row["gate_effect"])
        if gate_effect != _REVIEW_GATE_EFFECT:
            raise IntegrityError("stored C4 review gate effect is invalid")
        payload = cls._blob_from_row(row, "payload")
        signature = cls._blob_from_row(row, "signature")
        return C4ArchitectureReview(
            review_id=cls._required_text(row["review_id"], "review_id"),
            candidate_id=cls._required_text(row["candidate_id"], "candidate_id"),
            architecture_id=cls._required_text(
                row["architecture_id"], "architecture_id"
            ),
            input_set_id=cls._required_text(row["input_set_id"], "input_set_id"),
            manifest_sha256=cls._sha256_text(
                row["manifest_sha256"], "manifest_sha256"
            ),
            input_set_digest=cls._sha256_text(
                row["input_set_digest"], "input_set_digest"
            ),
            key_id=cls._required_text(row["key_id"], "key_id"),
            reviewer_identity=cls._required_text(
                row["reviewer_identity"], "reviewer_identity"
            ),
            reviewed_at_utc=cls._canonical_review_timestamp(row["reviewed_at_utc"]),
            structural_verification_result=cls._enum(
                row["structural_verification_result"],
                "structural_verification_result",
                _VERIFICATION_RESULTS,
            ),
            security_verification_result=cls._enum(
                row["security_verification_result"],
                "security_verification_result",
                _VERIFICATION_RESULTS,
            ),
            evidence_binding_result=cls._enum(
                row["evidence_binding_result"],
                "evidence_binding_result",
                _VERIFICATION_RESULTS,
            ),
            verdict=verdict,
            gate_effect=gate_effect,
            payload=payload,
            payload_sha256=cls._sha256_text(row["payload_sha256"], "payload_sha256"),
            signature=signature,
            signature_sha256=cls._sha256_text(
                row["signature_sha256"], "signature_sha256"
            ),
            admitted_at=cls._timestamp(row["admitted_at"]),
            admitted_by=cls._required_text(row["admitted_by"], "admitted_by"),
            ledger_event_id=cls._required_text(
                row["ledger_event_id"], "ledger_event_id"
            ),
            ledger_hash=cls._sha256_text(row["ledger_hash"], "ledger_hash"),
        )

    @classmethod
    def _finding_from_row(cls, row: sqlite3.Row) -> C4ArchitectureReviewFinding:
        return C4ArchitectureReviewFinding(
            review_id=cls._required_text(row["review_id"], "review_id"),
            ordinal=int(row["ordinal"]),
            finding_id=cls._required_text(row["finding_id"], "finding_id"),
            code=cls._enum(row["code"], "finding.code", _FINDING_CODES),
            severity=cls._enum(
                row["severity"], "finding.severity", _FINDING_SEVERITIES
            ),
            evidence_sha256=cls._digest(
                row["evidence_sha256"], "finding.evidence_sha256"
            ),
            description=cls._required_text(
                row["description"],
                "finding.description",
                maximum_utf8_bytes=_MAX_NARRATIVE_UTF8_BYTES,
            ),
        )

    @staticmethod
    def _findings_payload(
        findings: list[dict[str, object]] | tuple[C4ArchitectureReviewFinding, ...],
    ) -> list[dict[str, object]]:
        if findings and isinstance(findings[0], C4ArchitectureReviewFinding):
            return [
                {
                    "finding_id": finding.finding_id,
                    "code": finding.code,
                    "severity": finding.severity,
                    "evidence_sha256": finding.evidence_sha256,
                    "description": finding.description,
                }
                for finding in findings  # type: ignore[union-attr]
            ]
        return [dict(finding) for finding in findings]  # type: ignore[arg-type]

    @classmethod
    def _review_event_payload(
        cls,
        review: C4ArchitectureReview,
        findings: list[dict[str, object]] | tuple[C4ArchitectureReviewFinding, ...],
    ) -> dict[str, object]:
        finding_payload = cls._findings_payload(findings)
        return {
            "review_id": review.review_id,
            "candidate_id": review.candidate_id,
            "architecture_id": review.architecture_id,
            "input_set_id": review.input_set_id,
            "manifest_sha256": review.manifest_sha256,
            "input_set_digest": review.input_set_digest,
            "key_id": review.key_id,
            "reviewer_identity": review.reviewer_identity,
            "payload_sha256": review.payload_sha256,
            "signature_sha256": review.signature_sha256,
            "structural_verification_result": review.structural_verification_result,
            "security_verification_result": review.security_verification_result,
            "evidence_binding_result": review.evidence_binding_result,
            "verdict": review.verdict.value,
            "findings_count": len(finding_payload),
            "findings_digest": sha256_digest(finding_payload),
            "gate_effect": review.gate_effect,
        }

    def _verified_root_snapshot(
        self,
        connection: sqlite3.Connection,
        key_id: str,
    ) -> C4ArchitectureReviewerRoot:
        row = connection.execute(
            "SELECT * FROM c4_architecture_reviewer_roots WHERE key_id = ?",
            (key_id,),
        ).fetchone()
        if row is None:
            raise IntegrityError("C4 architecture reviewer root does not exist")
        try:
            root = self._root_from_row(row)
        except (TypeError, ValueError) as exc:
            raise IntegrityError("C4 architecture reviewer root is malformed") from exc
        verification = self.verify_reviewer_root(key_id)
        if not verification.ok:
            raise IntegrityError(
                "C4 architecture reviewer root failed verification",
                {"defects": list(verification.defects)},
            )
        try:
            current = self.get_reviewer_root(key_id)
        except (NotFoundError, TypeError, ValueError) as exc:
            raise IntegrityError(
                "C4 architecture reviewer root changed during verification"
            ) from exc
        if current != root:
            raise IntegrityError("C4 architecture reviewer root changed during verification")
        return root

    def _verify_review_signature(
        self,
        root: C4ArchitectureReviewerRoot,
        payload: bytes,
        signature: bytes,
    ) -> None:
        try:
            valid = self.signature_verifier.verify(
                root.public_key_pem,
                payload,
                signature,
            )
        except (OSError, TypeError, ValueError) as exc:
            raise IntegrityError(
                "C4 architecture review signature verification failed"
            ) from exc
        if not valid:
            raise IntegrityError("C4 architecture review signature verification failed")

    def _verified_candidate_and_input(
        self,
        candidate_id: str,
        input_set_id: str,
    ) -> tuple[object, object, tuple[Mapping[str, object], ...]]:
        try:
            candidate = self.candidates.get_candidate(candidate_id)
            candidate_verification = self.candidates.verify_candidate(candidate_id)
        except (NotFoundError, ValidationError, TypeError, ValueError) as exc:
            raise IntegrityError("C4 architecture candidate could not be verified") from exc
        if not candidate_verification.ok:
            raise IntegrityError(
                "C4 architecture candidate failed verification",
                {"candidate_id": candidate_id, "defects": list(candidate_verification.defects)},
            )
        try:
            input_set = self.inputs.get_input_set(input_set_id)
            input_verification = self.inputs.verify_input_set(input_set_id)
            members = tuple(self.inputs.get_members(input_set_id))
        except (NotFoundError, ValidationError, TypeError, ValueError) as exc:
            raise IntegrityError("C4 architecture input set could not be verified") from exc
        if not input_verification.ok:
            raise IntegrityError(
                "C4 architecture input set failed verification",
                {"input_set_id": input_set_id, "defects": list(input_verification.defects)},
            )
        return candidate, input_set, members

    def _authorization_subject(self, decision_id: object, field: str) -> str:
        try:
            decision_id = self._required_text(decision_id, field)
            verification = self.trust.verify_decision(decision_id)
            if not verification.ok:
                raise IntegrityError(
                    f"{field} failed authorization verification",
                    {"defects": list(verification.defects)},
                )
            decision = self.trust.get_decision(decision_id)
            return self._required_text(decision.request.subject, f"{field}.subject")
        except (NotFoundError, ValidationError, TypeError, ValueError) as exc:
            raise IntegrityError(f"{field} is not a valid authorization decision") from exc

    def _assert_review_bindings(
        self,
        review: dict[str, object],
        *,
        candidate: object,
        input_set: object,
        members: tuple[Mapping[str, object], ...],
        root: C4ArchitectureReviewerRoot,
        actor: str,
        admitted_at: str,
    ) -> None:
        expected_bindings = {
            "candidate_id": getattr(candidate, "candidate_id"),
            "architecture_id": getattr(candidate, "architecture_id"),
            "input_set_id": getattr(candidate, "input_set_id"),
            "manifest_sha256": getattr(candidate, "manifest_sha256"),
            "input_set_digest": getattr(candidate, "input_set_digest"),
        }
        for field, expected in expected_bindings.items():
            if review[field] != expected:
                raise IntegrityError(
                    f"C4 review {field} does not bind the immutable candidate/input",
                    {"field": field},
                )
        if getattr(input_set, "input_set_id") != review["input_set_id"]:
            raise IntegrityError("C4 review input set binding is inconsistent")
        if getattr(input_set, "input_set_digest") != review["input_set_digest"]:
            raise IntegrityError("C4 review input-set digest is inconsistent")
        status = getattr(getattr(candidate, "status"), "value", getattr(candidate, "status"))
        if status != "C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED":
            raise IntegrityError("C4 architecture candidate is not awaiting review")
        if review["reviewer_identity"] != root.reviewer_identity:
            raise StateTransitionError(
                "signed reviewer identity does not match the accepted reviewer root"
            )
        if root.reviewer_identity == root.accepted_by or root.reviewer_identity == actor:
            raise StateTransitionError("reviewer identity is not independent of administrative actors")

        reviewed_at = self._as_datetime(str(review["reviewed_at_utc"]))
        candidate_at = self._as_datetime(self._timestamp(getattr(candidate, "created_at")))
        input_at = self._as_datetime(self._timestamp(getattr(input_set, "frozen_at")))
        admitted_at_value = self._as_datetime(self._timestamp(admitted_at))
        root_at = self._as_datetime(self._timestamp(root.accepted_at))
        if reviewed_at <= candidate_at:
            raise StateTransitionError("signed review predates or equals candidate creation")
        if reviewed_at <= input_at:
            raise StateTransitionError("signed review predates or equals input freeze")
        if admitted_at_value < reviewed_at:
            raise StateTransitionError("review admission predates signed review")
        if admitted_at_value < root_at:
            raise StateTransitionError("review admission predates reviewer-root acceptance")

        candidate_subject = self._authorization_subject(
            getattr(candidate, "authorization_decision_id"),
            "candidate.authorization_decision_id",
        )
        input_subject = self._authorization_subject(
            getattr(input_set, "authorization_decision_id"),
            "input_set.authorization_decision_id",
        )
        static_identities = {
            self._required_text(getattr(candidate, "created_by"), "candidate.created_by"),
            self._required_text(getattr(input_set, "frozen_by"), "input_set.frozen_by"),
            candidate_subject,
            input_subject,
        }
        for ordinal, member in enumerate(members):
            try:
                requested_by = self._required_text(
                    member.get("requested_by"),
                    f"input member {ordinal}.requested_by",
                )
            except AttributeError as exc:
                raise IntegrityError("C4 input member is not a mapping") from exc
            static_identities.add(requested_by)
        independence = self._closed_object(
            review["independence_basis"],
            "independence_basis",
            _INDEPENDENCE_FIELDS,
        )
        declared = independence["excluded_identities"]
        if declared != sorted(static_identities):
            raise StateTransitionError(
                "signed independence exclusion set does not match static provenance"
            )
        if root.reviewer_identity in static_identities:
            raise StateTransitionError("reviewer identity collides with static provenance")

    @staticmethod
    def _replay_matches(
        row: sqlite3.Row,
        *,
        candidate_id: str,
        review_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        actor: str,
    ) -> bool:
        raw_payload = row["payload"]
        raw_signature = row["signature"]
        if not isinstance(raw_payload, (bytes, bytearray, memoryview)):
            return False
        if not isinstance(raw_signature, (bytes, bytearray, memoryview)):
            return False
        return (
            str(row["candidate_id"]) == candidate_id
            and str(row["review_id"]) == review_id
            and str(row["key_id"]) == key_id
            and bytes(raw_payload) == payload
            and bytes(raw_signature) == signature
            and str(row["admitted_by"]) == actor
        )

    def _existing_review_row(
        self,
        review_id: str,
        candidate_id: str,
    ) -> sqlite3.Row | None:
        return self.database.connection.execute(
            """
            SELECT * FROM c4_architecture_reviews
            WHERE review_id = ? OR candidate_id = ?
            ORDER BY review_id
            LIMIT 1
            """,
            (review_id, candidate_id),
        ).fetchone()

    def _resolve_replay(
        self,
        row: sqlite3.Row,
        *,
        candidate_id: str,
        review_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        actor: str,
    ) -> C4ArchitectureReview:
        if not self._replay_matches(
            row,
            candidate_id=candidate_id,
            review_id=review_id,
            key_id=key_id,
            payload=payload,
            signature=signature,
            actor=actor,
        ):
            raise ConflictError(
                "C4 review identifier or candidate already binds different material"
            )
        record = self._review_from_row(row)
        verification = self.verify_review(record.review_id)
        if not verification.ok:
            raise IntegrityError(
                "existing C4 architecture review failed verification",
                {"review_id": record.review_id, "defects": list(verification.defects)},
            )
        return record

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
        admitted_at = self._timestamp(occurred_at or utc_now())
        payload = self._bounded_transport_bytes(
            payload,
            "payload",
            MAX_PAYLOAD_BYTES,
        )
        signature = self._bounded_transport_bytes(
            signature,
            "signature",
            MAX_SIGNATURE_BYTES,
        )

        try:
            with self.database.transaction() as connection:
                verified_root = self._verified_root_snapshot(connection, key_id)
                self._verify_review_signature(verified_root, payload, signature)
        except sqlite3.Error as exc:
            raise IntegrityError("reviewer root verification snapshot failed") from exc

        parsed = self._parse_review_payload(payload)
        if parsed["candidate_id"] != candidate_id:
            raise IntegrityError("review payload candidate_id does not match the request")
        review_id = self._required_text(parsed["review_id"], "review_id")
        existing = self._existing_review_row(review_id, candidate_id)
        if existing is not None:
            return self._resolve_replay(
                existing,
                candidate_id=candidate_id,
                review_id=review_id,
                key_id=key_id,
                payload=payload,
                signature=signature,
                actor=actor,
            )
        candidate, input_set, members = self._verified_candidate_and_input(
            candidate_id,
            self._required_text(parsed["input_set_id"], "input_set_id"),
        )
        self._assert_review_bindings(
            parsed,
            candidate=candidate,
            input_set=input_set,
            members=members,
            root=verified_root,
            actor=actor,
            admitted_at=admitted_at,
        )

        findings = parsed["findings"]
        if not isinstance(findings, list):
            raise IntegrityError("parsed C4 review findings are malformed")
        provisional = C4ArchitectureReview(
            review_id=review_id,
            candidate_id=candidate_id,
            architecture_id=self._required_text(
                parsed["architecture_id"], "architecture_id"
            ),
            input_set_id=self._required_text(parsed["input_set_id"], "input_set_id"),
            manifest_sha256=self._digest(parsed["manifest_sha256"], "manifest_sha256"),
            input_set_digest=self._digest(
                parsed["input_set_digest"], "input_set_digest"
            ),
            key_id=key_id,
            reviewer_identity=self._required_text(
                parsed["reviewer_identity"], "reviewer_identity"
            ),
            reviewed_at_utc=self._canonical_review_timestamp(
                parsed["reviewed_at_utc"]
            ),
            structural_verification_result=self._enum(
                parsed["structural_verification_result"],
                "structural_verification_result",
                _VERIFICATION_RESULTS,
            ),
            security_verification_result=self._enum(
                parsed["security_verification_result"],
                "security_verification_result",
                _VERIFICATION_RESULTS,
            ),
            evidence_binding_result=self._enum(
                parsed["evidence_binding_result"],
                "evidence_binding_result",
                _VERIFICATION_RESULTS,
            ),
            verdict=C4ArchitectureReviewVerdict(
                self._enum(
                    parsed["verdict"],
                    "verdict",
                    frozenset(member.value for member in C4ArchitectureReviewVerdict),
                )
            ),
            gate_effect=_REVIEW_GATE_EFFECT,
            payload=payload,
            payload_sha256=sha256_digest(payload),
            signature=signature,
            signature_sha256=sha256_digest(signature),
            admitted_at=admitted_at,
            admitted_by=actor,
            ledger_event_id="pending",
            ledger_hash="pending",
        )
        event_payload = self._review_event_payload(provisional, findings)
        try:
            with self.database.transaction() as connection:
                current_root = self._verified_root_snapshot(connection, key_id)
                self._verify_review_signature(current_root, payload, signature)
                current_parsed = self._parse_review_payload(payload)
                current_candidate, current_input, current_members = (
                    self._verified_candidate_and_input(
                        candidate_id,
                        self._required_text(
                            current_parsed["input_set_id"], "input_set_id"
                        ),
                    )
                )
                self._assert_review_bindings(
                    current_parsed,
                    candidate=current_candidate,
                    input_set=current_input,
                    members=current_members,
                    root=current_root,
                    actor=actor,
                    admitted_at=admitted_at,
                )
                race = connection.execute(
                    """
                    SELECT * FROM c4_architecture_reviews
                    WHERE review_id = ? OR candidate_id = ?
                    ORDER BY review_id
                    LIMIT 1
                    """,
                    (review_id, candidate_id),
                ).fetchone()
                if race is not None:
                    raise ConflictError(
                        "C4 review appeared during admission",
                        {"review_id": review_id, "candidate_id": candidate_id},
                    )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    self._review_stream(candidate_id),
                    _REVIEW_EVENT_KIND,
                    event_payload,
                    actor=actor,
                    occurred_at=admitted_at,
                )
                connection.execute(
                    """
                    INSERT INTO c4_architecture_reviews (
                        review_id, candidate_id, architecture_id, input_set_id,
                        manifest_sha256, input_set_digest, key_id,
                        reviewer_identity, reviewed_at_utc,
                        structural_verification_result,
                        security_verification_result, evidence_binding_result,
                        verdict, gate_effect, payload, payload_sha256,
                        signature, signature_sha256, admitted_at, admitted_by,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        provisional.review_id,
                        provisional.candidate_id,
                        provisional.architecture_id,
                        provisional.input_set_id,
                        provisional.manifest_sha256,
                        provisional.input_set_digest,
                        provisional.key_id,
                        provisional.reviewer_identity,
                        provisional.reviewed_at_utc,
                        provisional.structural_verification_result,
                        provisional.security_verification_result,
                        provisional.evidence_binding_result,
                        provisional.verdict.value,
                        provisional.gate_effect,
                        sqlite3.Binary(provisional.payload),
                        provisional.payload_sha256,
                        sqlite3.Binary(provisional.signature),
                        provisional.signature_sha256,
                        provisional.admitted_at,
                        provisional.admitted_by,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
                for ordinal, finding in enumerate(findings):
                    if not isinstance(finding, dict):
                        raise IntegrityError("parsed C4 finding is malformed")
                    connection.execute(
                        """
                        INSERT INTO c4_architecture_review_findings (
                            review_id, ordinal, finding_id, code, severity,
                            evidence_sha256, description
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            review_id,
                            ordinal,
                            self._required_text(finding["finding_id"], "finding_id"),
                            self._enum(finding["code"], "finding.code", _FINDING_CODES),
                            self._enum(
                                finding["severity"],
                                "finding.severity",
                                _FINDING_SEVERITIES,
                            ),
                            self._digest(
                                finding["evidence_sha256"],
                                "finding.evidence_sha256",
                            ),
                            self._required_text(
                                finding["description"],
                                "finding.description",
                                maximum_utf8_bytes=_MAX_NARRATIVE_UTF8_BYTES,
                            ),
                        ),
                    )
        except ConflictError:
            raise
        except sqlite3.IntegrityError as exc:
            race = self._existing_review_row(review_id, candidate_id)
            if race is not None:
                return self._resolve_replay(
                    race,
                    candidate_id=candidate_id,
                    review_id=review_id,
                    key_id=key_id,
                    payload=payload,
                    signature=signature,
                    actor=actor,
                )
            raise ConflictError(
                "C4 architecture review conflicts with immutable state",
                {"review_id": review_id, "candidate_id": candidate_id},
            ) from exc
        return self.get_review(review_id)

    def get_review(self, review_id: str) -> C4ArchitectureReview:
        review_id = self._required_text(review_id, "review_id")
        row = self.database.connection.execute(
            "SELECT * FROM c4_architecture_reviews WHERE review_id = ?",
            (review_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("C4 architecture review does not exist", {"review_id": review_id})
        try:
            return self._review_from_row(row)
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            raise IntegrityError("stored C4 architecture review is malformed") from exc

    def get_review_for_candidate(self, candidate_id: str) -> C4ArchitectureReview:
        candidate_id = self._required_text(candidate_id, "candidate_id")
        row = self.database.connection.execute(
            "SELECT * FROM c4_architecture_reviews WHERE candidate_id = ?",
            (candidate_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C4 architecture review for candidate does not exist",
                {"candidate_id": candidate_id},
            )
        try:
            return self._review_from_row(row)
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            raise IntegrityError("stored C4 architecture review is malformed") from exc

    def get_findings(self, review_id: str) -> tuple[C4ArchitectureReviewFinding, ...]:
        review = self.get_review(review_id)
        rows = self.database.connection.execute(
            """
            SELECT * FROM c4_architecture_review_findings
            WHERE review_id = ? ORDER BY ordinal
            """,
            (review.review_id,),
        ).fetchall()
        findings: list[C4ArchitectureReviewFinding] = []
        for expected_ordinal, row in enumerate(rows):
            try:
                finding = self._finding_from_row(row)
            except (KeyError, TypeError, ValueError, ValidationError) as exc:
                raise IntegrityError("stored C4 architecture finding is malformed") from exc
            if finding.ordinal != expected_ordinal or finding.review_id != review.review_id:
                raise IntegrityError("stored C4 architecture finding ordering is invalid")
            findings.append(finding)
        return tuple(findings)

    def verify_review(self, review_id: str) -> C4ArchitectureReviewVerification:
        review_id = self._required_text(review_id, "review_id")
        defects: list[str] = []
        row = self.database.connection.execute(
            "SELECT * FROM c4_architecture_reviews WHERE review_id = ?",
            (review_id,),
        ).fetchone()
        if row is None:
            return C4ArchitectureReviewVerification(review_id, ("REVIEW_NOT_FOUND",))

        def add(code: str) -> None:
            if code not in defects:
                defects.append(code)

        try:
            record = self._review_from_row(row)
        except (IntegrityError, KeyError, TypeError, ValueError, ValidationError):
            add("REVIEW_ROW_INVALID")
            return C4ArchitectureReviewVerification(review_id, tuple(defects))

        if record.review_id != review_id:
            add("REVIEW_ID_MISMATCH")
        if not record.payload:
            add("REVIEW_PAYLOAD_EMPTY")
        elif sha256_digest(record.payload) != record.payload_sha256:
            add("REVIEW_PAYLOAD_DIGEST_MISMATCH")
        if not record.signature:
            add("REVIEW_SIGNATURE_EMPTY")
        elif sha256_digest(record.signature) != record.signature_sha256:
            add("REVIEW_SIGNATURE_DIGEST_MISMATCH")

        root: C4ArchitectureReviewerRoot | None = None
        try:
            root_verification = self.verify_reviewer_root(record.key_id)
        except (IntegrityError, NotFoundError, sqlite3.Error, TypeError, ValueError):
            root_verification = None
            add("REVIEWER_ROOT_VERIFICATION_FAILED")
        if root_verification is not None and not root_verification.ok:
            add("REVIEWER_ROOT_INVALID")
        try:
            root = self.get_reviewer_root(record.key_id)
        except (IntegrityError, NotFoundError, TypeError, ValueError):
            add("REVIEWER_ROOT_NOT_FOUND")
        if root is not None and not defects[-1:] == ["REVIEWER_ROOT_NOT_FOUND"]:
            try:
                self._verify_review_signature(root, record.payload, record.signature)
            except (IntegrityError, OSError, TypeError, ValueError):
                add("REVIEW_SIGNATURE_INVALID")

        parsed: dict[str, object] | None = None
        try:
            parsed = self._parse_review_payload(record.payload)
        except (ValidationError, TypeError, ValueError, json.JSONDecodeError):
            add("REVIEW_PAYLOAD_INVALID")

        if parsed is not None:
            stored_values = {
                "review_id": record.review_id,
                "candidate_id": record.candidate_id,
                "architecture_id": record.architecture_id,
                "input_set_id": record.input_set_id,
                "manifest_sha256": record.manifest_sha256,
                "input_set_digest": record.input_set_digest,
                "reviewer_identity": record.reviewer_identity,
                "reviewed_at_utc": record.reviewed_at_utc,
                "structural_verification_result": record.structural_verification_result,
                "security_verification_result": record.security_verification_result,
                "evidence_binding_result": record.evidence_binding_result,
                "verdict": record.verdict.value,
                "gate_effect": record.gate_effect,
            }
            for field, expected in stored_values.items():
                if parsed.get(field) != expected:
                    add(f"REVIEW_STORED_FIELD_MISMATCH:{field}")

        stored_findings: tuple[C4ArchitectureReviewFinding, ...] = ()
        try:
            finding_rows = self.database.connection.execute(
                """
                SELECT * FROM c4_architecture_review_findings
                WHERE review_id = ? ORDER BY ordinal
                """,
                (review_id,),
            ).fetchall()
            parsed_findings: list[C4ArchitectureReviewFinding] = []
            for expected_ordinal, finding_row in enumerate(finding_rows):
                finding = self._finding_from_row(finding_row)
                if finding.ordinal != expected_ordinal:
                    add("REVIEW_FINDING_ORDINAL_INVALID")
                parsed_findings.append(finding)
            stored_findings = tuple(parsed_findings)
        except (IntegrityError, KeyError, TypeError, ValueError, ValidationError):
            add("REVIEW_FINDINGS_INVALID")

        if parsed is not None:
            signed_findings = parsed.get("findings")
            if not isinstance(signed_findings, list):
                add("REVIEW_SIGNED_FINDINGS_INVALID")
            else:
                stored_finding_payload = self._findings_payload(stored_findings)
                if stored_finding_payload != signed_findings:
                    add("REVIEW_FINDINGS_MISMATCH")

        candidate: object | None = None
        input_set: object | None = None
        members: tuple[Mapping[str, object], ...] = ()
        if parsed is not None:
            try:
                candidate, input_set, members = self._verified_candidate_and_input(
                    record.candidate_id,
                    record.input_set_id,
                )
            except (IntegrityError, NotFoundError, ValidationError, TypeError, ValueError):
                add("REVIEW_CANDIDATE_OR_INPUT_INVALID")
            if candidate is not None and input_set is not None and root is not None:
                try:
                    self._assert_review_bindings(
                        parsed,
                        candidate=candidate,
                        input_set=input_set,
                        members=members,
                        root=root,
                        actor=record.admitted_by,
                        admitted_at=record.admitted_at,
                    )
                except (IntegrityError, StateTransitionError, ValidationError, TypeError, ValueError):
                    add("REVIEW_BINDING_INVALID")

        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (record.ledger_event_id,),
        ).fetchone()
        expected_event_payload = self._review_event_payload(record, stored_findings)
        if event is None:
            add("REVIEW_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != self._review_stream(record.candidate_id):
                add("REVIEW_LEDGER_STREAM_MISMATCH")
            if str(event["kind"]) != _REVIEW_EVENT_KIND:
                add("REVIEW_LEDGER_KIND_MISMATCH")
            if str(event["actor"]) != record.admitted_by:
                add("REVIEW_LEDGER_ACTOR_MISMATCH")
            if str(event["occurred_at"]) != record.admitted_at:
                add("REVIEW_LEDGER_TIME_MISMATCH")
            if str(event["record_hash"]) != record.ledger_hash:
                add("REVIEW_LEDGER_HASH_MISMATCH")
            try:
                event_payload = json.loads(str(event["payload_json"]))
            except (json.JSONDecodeError, TypeError, ValueError):
                add("REVIEW_LEDGER_PAYLOAD_INVALID")
            else:
                if event_payload != expected_event_payload:
                    add("REVIEW_LEDGER_PAYLOAD_MISMATCH")
        try:
            chain = self.ledger.verify(self._review_stream(record.candidate_id))
        except (json.JSONDecodeError, TypeError, ValueError, sqlite3.Error):
            add("REVIEW_LEDGER_CHAIN_INVALID")
        else:
            if not chain.ok:
                add("REVIEW_LEDGER_CHAIN_INVALID")

        return C4ArchitectureReviewVerification(review_id, tuple(defects))
