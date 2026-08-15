from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
import re
import sqlite3
from typing import Any, Mapping

from .architecture_candidate import (
    C4ArchitectureCandidate,
    C4ArchitectureCandidateService,
    C4ArchitectureCandidateStatus,
)
from .architecture_input import (
    C4ArchitectureInputService,
    C4ArchitectureInputSet,
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
_MAX_PUBLIC_KEY_BYTES = 8 * 1024
_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
_MAX_SIGNATURE_BYTES = 1024
_ROOT_EVENT_KIND = "C4_ARCHITECTURE_REVIEWER_ACCEPTED"
_ROOT_GATE_EFFECT = "REVIEWER_TRUST_ROOT_ACCEPTED_NO_REVIEW"
_REVIEW_EVENT_KIND = "C4_ARCHITECTURE_REVIEW_ADMITTED"
_REVIEW_GATE_EFFECT = "NO_PUBLICATION_NO_DEPLOYMENT"
_VERIFICATION_RESULTS = frozenset({"PASS", "FAIL"})
_PAYLOAD_FIELDS = frozenset(
    {
        "review_id",
        "candidate_id",
        "architecture_id",
        "architecture_version",
        "input_set_id",
        "input_set_digest",
        "manifest_sha256",
        "reviewer_identity",
        "reviewer_environment",
        "reviewed_at",
        "independence_basis",
        "structural_verification_result",
        "security_verification_result",
        "evidence_binding_result",
        "findings",
        "verdict",
        "gate_effect",
    }
)
_FINDING_FIELDS = frozenset(
    {
        "finding_id",
        "code",
        "severity",
        "title",
        "description",
        "affected_ids",
        "evidence_refs",
        "recommendation",
    }
)


class C4ArchitectureReviewVerdict(str, Enum):
    ACCEPTED = "C4_ARCHITECTURE_ACCEPTED"
    REJECTED = "C4_ARCHITECTURE_REJECTED"
    REWORK_REQUIRED = "C4_ARCHITECTURE_REWORK_REQUIRED"


class C4ArchitectureFindingSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class C4ArchitectureFindingCode(str, Enum):
    AUTHORITY_ADR_GAP = "AUTHORITY_ADR_GAP"
    PORT_OWNERSHIP_GAP = "PORT_OWNERSHIP_GAP"
    MISSION_FABRIC_GAP = "MISSION_FABRIC_GAP"
    CAPABILITY_TEST_PROOF_GAP = "CAPABILITY_TEST_PROOF_GAP"
    COMPONENT_BINDING_GAP = "COMPONENT_BINDING_GAP"
    VERTICAL_BENCHMARK_GAP = "VERTICAL_BENCHMARK_GAP"
    NON_FUNCTIONAL_REQUIREMENT_GAP = "NON_FUNCTIONAL_REQUIREMENT_GAP"
    SECURITY_CONTROL_GAP = "SECURITY_CONTROL_GAP"
    EVIDENCE_BINDING_GAP = "EVIDENCE_BINDING_GAP"
    INDEPENDENCE_OR_PROVENANCE_GAP = "INDEPENDENCE_OR_PROVENANCE_GAP"
    DOCUMENTATION_IMPROVEMENT = "DOCUMENTATION_IMPROVEMENT"


@dataclass(frozen=True)
class C4ArchitectureReviewerRootPreparation:
    key_id: str
    public_key_fingerprint_sha256: str
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]


@dataclass(frozen=True)
class C4ArchitectureReviewerRoot:
    key_id: str
    public_key_fingerprint_sha256: str
    accepted_at: str
    accepted_by: str
    authorization_decision_id: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C4ArchitectureReview:
    review_id: str
    candidate_id: str
    architecture_id: str
    architecture_version: str
    input_set_id: str
    input_set_digest: str
    manifest_sha256: str
    key_id: str
    payload_sha256: str
    signature_sha256: str
    reviewer_identity: str
    reviewer_environment: str
    reviewed_at: str
    independence_basis: str
    structural_verification_result: str
    security_verification_result: str
    evidence_binding_result: str
    finding_count: int
    verdict: C4ArchitectureReviewVerdict
    admitted_at: str
    admitted_by: str
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
class C4ArchitectureReviewVerification:
    review_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C4ArchitectureReviewService:
    """Admit exact-byte independent reviews for immutable C4 candidates."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        trust: TrustPlane,
        continuity: ContinuityService,
        inputs: C4ArchitectureInputService,
        candidates: C4ArchitectureCandidateService,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self.continuity = continuity
        self.inputs = inputs
        self.candidates = candidates
        self._initialize_schema()

    @staticmethod
    def _required_text(value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{field} must be a non-empty string")
        return value.strip()

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
    def _bounded_bytes(value: object, field: str, maximum: int) -> bytes:
        if not isinstance(value, bytes) or not value or len(value) > maximum:
            raise ValidationError(
                f"{field} must be non-empty bytes within the size limit",
                {"maximum_bytes": maximum},
            )
        return value

    @staticmethod
    def _fingerprint(value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    @staticmethod
    def _bytes_sha256(value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    @staticmethod
    def _digest(value: object, field: str) -> str:
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
        return value

    @classmethod
    def _sorted_strings(
        cls,
        value: object,
        field: str,
        *,
        allow_empty: bool = False,
    ) -> tuple[str, ...]:
        if not isinstance(value, list) or (not allow_empty and not value):
            qualifier = "" if allow_empty else "non-empty "
            raise ValidationError(f"{field} must be a {qualifier}list")
        normalized = tuple(cls._required_text(item, field) for item in value)
        if normalized != tuple(sorted(normalized)):
            raise ValidationError(f"{field} must be sorted")
        if len(set(normalized)) != len(normalized):
            raise ValidationError(f"{field} must be duplicate-free")
        return normalized

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c4_architecture_reviewer_roots (
                    key_id TEXT PRIMARY KEY,
                    public_key BLOB NOT NULL,
                    public_key_fingerprint_sha256 TEXT NOT NULL UNIQUE
                        CHECK (length(public_key_fingerprint_sha256) = 64),
                    accepted_at TEXT NOT NULL,
                    accepted_by TEXT NOT NULL,
                    authorization_decision_id TEXT NOT NULL UNIQUE,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (authorization_decision_id)
                        REFERENCES trust_decisions(decision_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c4_architecture_reviews (
                    review_id TEXT PRIMARY KEY,
                    candidate_id TEXT NOT NULL UNIQUE,
                    architecture_id TEXT NOT NULL,
                    architecture_version TEXT NOT NULL
                        CHECK (architecture_version = '3.2'),
                    input_set_id TEXT NOT NULL,
                    input_set_digest TEXT NOT NULL
                        CHECK (length(input_set_digest) = 64),
                    manifest_sha256 TEXT NOT NULL
                        CHECK (length(manifest_sha256) = 64),
                    key_id TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    payload_sha256 TEXT NOT NULL
                        CHECK (length(payload_sha256) = 64),
                    signature BLOB NOT NULL,
                    signature_sha256 TEXT NOT NULL
                        CHECK (length(signature_sha256) = 64),
                    reviewer_identity TEXT NOT NULL,
                    reviewer_environment TEXT NOT NULL,
                    reviewed_at TEXT NOT NULL,
                    independence_basis TEXT NOT NULL,
                    structural_verification_result TEXT NOT NULL
                        CHECK (structural_verification_result IN ('PASS','FAIL')),
                    security_verification_result TEXT NOT NULL
                        CHECK (security_verification_result IN ('PASS','FAIL')),
                    evidence_binding_result TEXT NOT NULL
                        CHECK (evidence_binding_result IN ('PASS','FAIL')),
                    finding_count INTEGER NOT NULL CHECK (finding_count >= 0),
                    verdict TEXT NOT NULL CHECK (verdict IN (
                        'C4_ARCHITECTURE_ACCEPTED',
                        'C4_ARCHITECTURE_REJECTED',
                        'C4_ARCHITECTURE_REWORK_REQUIRED'
                    )),
                    gate_effect TEXT NOT NULL
                        CHECK (gate_effect = 'NO_PUBLICATION_NO_DEPLOYMENT'),
                    admitted_at TEXT NOT NULL,
                    admitted_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
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
                    finding_json TEXT NOT NULL,
                    finding_sha256 TEXT NOT NULL
                        CHECK (length(finding_sha256) = 64),
                    PRIMARY KEY (review_id, ordinal),
                    UNIQUE (review_id, finding_id),
                    FOREIGN KEY (review_id)
                        REFERENCES c4_architecture_reviews(review_id)
                )
                """
            )
            for table in (
                "c4_architecture_reviewer_roots",
                "c4_architecture_reviews",
                "c4_architecture_review_findings",
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

    @staticmethod
    def _root_stream(key_id: str) -> str:
        return f"continuity:c4:architecture-reviewer:{key_id}"

    @staticmethod
    def _review_stream(review_id: str) -> str:
        return f"continuity:c4:architecture-review:{review_id}"

    @staticmethod
    def _root_context(key_id: str, fingerprint: str) -> dict[str, object]:
        return {
            "key_id": key_id,
            "public_key_fingerprint_sha256": fingerprint,
            "algorithm": "Ed25519",
            "purpose": "C4_ARCHITECTURE_INDEPENDENT_REVIEW",
            "gate_effect": _ROOT_GATE_EFFECT,
        }

    def prepare_reviewer_root(
        self,
        key_id: str,
        public_key: bytes,
    ) -> C4ArchitectureReviewerRootPreparation:
        key_id = self._required_text(key_id, "key_id")
        public_key = self._bounded_bytes(
            public_key,
            "public_key",
            _MAX_PUBLIC_KEY_BYTES,
        )
        if not self.continuity.signature_verifier.validate_public_key(public_key):
            raise ValidationError("public_key must be a valid Ed25519 public key")
        fingerprint = self._fingerprint(public_key)
        return C4ArchitectureReviewerRootPreparation(
            key_id=key_id,
            public_key_fingerprint_sha256=fingerprint,
            action="c4.architecture-reviewer.accept",
            resource=self._root_stream(key_id),
            mission_id=f"c4-architecture-reviewer:{key_id}",
            context=self._root_context(key_id, fingerprint),
        )

    def _assert_root_authorization(
        self,
        decision_id: str,
        *,
        preparation: C4ArchitectureReviewerRootPreparation,
        actor: str,
    ) -> AuthorizationDecision:
        decision_id = self._required_text(
            decision_id,
            "authorization_decision_id",
        )
        verification = self.trust.verify_decision(decision_id)
        if not verification.ok:
            raise AuthorizationError(
                "C4 reviewer-root authorization decision failed verification",
                {
                    "decision_id": decision_id,
                    "defects": list(verification.defects),
                },
            )
        try:
            decision = self.trust.get_decision(decision_id)
        except NotFoundError as exc:
            raise AuthorizationError(
                "C4 reviewer-root authorization decision does not exist"
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
                "authorization decision does not exactly match C4 reviewer root",
                {
                    "decision_id": decision_id,
                    "allowed": decision.allowed,
                },
            )
        return decision

    @staticmethod
    def _root_from_row(row: sqlite3.Row) -> C4ArchitectureReviewerRoot:
        return C4ArchitectureReviewerRoot(
            key_id=str(row["key_id"]),
            public_key_fingerprint_sha256=str(
                row["public_key_fingerprint_sha256"]
            ),
            accepted_at=str(row["accepted_at"]),
            accepted_by=str(row["accepted_by"]),
            authorization_decision_id=str(row["authorization_decision_id"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    @staticmethod
    def _root_ledger_payload(
        root: C4ArchitectureReviewerRoot,
    ) -> dict[str, object]:
        return {
            "key_id": root.key_id,
            "public_key_fingerprint_sha256": (
                root.public_key_fingerprint_sha256
            ),
            "algorithm": "Ed25519",
            "purpose": "C4_ARCHITECTURE_INDEPENDENT_REVIEW",
            "authorization_decision_id": root.authorization_decision_id,
            "gate_effect": _ROOT_GATE_EFFECT,
        }

    def get_reviewer_root(self, key_id: str) -> C4ArchitectureReviewerRoot:
        key_id = self._required_text(key_id, "key_id")
        row = self.database.connection.execute(
            """
            SELECT * FROM c4_architecture_reviewer_roots
            WHERE key_id = ?
            """,
            (key_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C4 architecture reviewer root does not exist",
                {"key_id": key_id},
            )
        return self._root_from_row(row)

    def _root_key(self, key_id: str) -> bytes:
        row = self.database.connection.execute(
            """
            SELECT public_key FROM c4_architecture_reviewer_roots
            WHERE key_id = ?
            """,
            (key_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C4 architecture reviewer root does not exist",
                {"key_id": key_id},
            )
        return bytes(row["public_key"])

    def accept_reviewer_root(
        self,
        key_id: str,
        public_key: bytes,
        *,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> C4ArchitectureReviewerRoot:
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now())
        preparation = self.prepare_reviewer_root(key_id, public_key)
        existing = self.database.connection.execute(
            """
            SELECT * FROM c4_architecture_reviewer_roots
            WHERE key_id = ?
            """,
            (preparation.key_id,),
        ).fetchone()
        if existing is not None:
            exact = (
                bytes(existing["public_key"]) == public_key
                and str(existing["authorization_decision_id"])
                == authorization_decision_id
                and str(existing["accepted_by"]) == actor
            )
            if not exact:
                raise ConflictError(
                    "reviewer key_id was reused with different root material",
                    {"key_id": preparation.key_id},
                )
            verification = self.verify_reviewer_root(preparation.key_id)
            if not verification.ok:
                raise IntegrityError(
                    "existing C4 reviewer root failed verification",
                    {
                        "key_id": preparation.key_id,
                        "defects": list(verification.defects),
                    },
                )
            return self._root_from_row(existing)

        decision = self._assert_root_authorization(
            authorization_decision_id,
            preparation=preparation,
            actor=actor,
        )
        if self._as_datetime(occurred_at) < self._as_datetime(decision.decided_at):
            raise StateTransitionError(
                "reviewer-root acceptance predates TrustPlane authorization"
            )
        provisional = C4ArchitectureReviewerRoot(
            key_id=preparation.key_id,
            public_key_fingerprint_sha256=(
                preparation.public_key_fingerprint_sha256
            ),
            accepted_at=occurred_at,
            accepted_by=actor,
            authorization_decision_id=authorization_decision_id,
            ledger_event_id="pending",
            ledger_hash="pending",
        )
        try:
            with self.database.transaction() as connection:
                race = connection.execute(
                    """
                    SELECT key_id FROM c4_architecture_reviewer_roots
                    WHERE key_id = ? OR authorization_decision_id = ?
                    """,
                    (preparation.key_id, authorization_decision_id),
                ).fetchone()
                if race is not None:
                    raise ConflictError(
                        "C4 reviewer root appeared during acceptance"
                    )
                current = self.prepare_reviewer_root(key_id, public_key)
                if current != preparation:
                    raise ConflictError(
                        "reviewer-root material changed during acceptance"
                    )
                current_decision = self._assert_root_authorization(
                    authorization_decision_id,
                    preparation=current,
                    actor=actor,
                )
                if self._as_datetime(occurred_at) < self._as_datetime(
                    current_decision.decided_at
                ):
                    raise StateTransitionError(
                        "reviewer-root acceptance predates TrustPlane authorization"
                    )
                self.continuity._consume_authorization(
                    connection,
                    decision_id=authorization_decision_id,
                    operation_kind=_ROOT_EVENT_KIND,
                    operation_id=preparation.key_id,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    self._root_stream(preparation.key_id),
                    _ROOT_EVENT_KIND,
                    self._root_ledger_payload(provisional),
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO c4_architecture_reviewer_roots (
                        key_id, public_key,
                        public_key_fingerprint_sha256, accepted_at,
                        accepted_by, authorization_decision_id,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        preparation.key_id,
                        public_key,
                        preparation.public_key_fingerprint_sha256,
                        occurred_at,
                        actor,
                        authorization_decision_id,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "C4 reviewer root conflicts with immutable state",
                {"key_id": preparation.key_id},
            ) from exc
        return self.get_reviewer_root(preparation.key_id)

    def verify_reviewer_root(
        self,
        key_id: str,
    ) -> C4ArchitectureReviewerRootVerification:
        key_id = self._required_text(key_id, "key_id")
        row = self.database.connection.execute(
            """
            SELECT * FROM c4_architecture_reviewer_roots
            WHERE key_id = ?
            """,
            (key_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C4 architecture reviewer root does not exist",
                {"key_id": key_id},
            )
        root = self._root_from_row(row)
        public_key = bytes(row["public_key"])
        defects: list[str] = []
        fingerprint = self._fingerprint(public_key)
        if fingerprint != root.public_key_fingerprint_sha256:
            defects.append("C4_REVIEWER_ROOT_FINGERPRINT_MISMATCH")
        if not self.continuity.signature_verifier.validate_public_key(public_key):
            defects.append("C4_REVIEWER_ROOT_PUBLIC_KEY_INVALID")

        preparation = C4ArchitectureReviewerRootPreparation(
            key_id=root.key_id,
            public_key_fingerprint_sha256=(
                root.public_key_fingerprint_sha256
            ),
            action="c4.architecture-reviewer.accept",
            resource=self._root_stream(root.key_id),
            mission_id=f"c4-architecture-reviewer:{root.key_id}",
            context=self._root_context(
                root.key_id,
                root.public_key_fingerprint_sha256,
            ),
        )
        decision_verification = self.trust.verify_decision(
            root.authorization_decision_id
        )
        defects.extend(
            f"C4_REVIEWER_ROOT_AUTHORIZATION:{defect}"
            for defect in decision_verification.defects
        )
        try:
            decision = self.trust.get_decision(root.authorization_decision_id)
        except NotFoundError:
            defects.append("C4_REVIEWER_ROOT_AUTHORIZATION_MISSING")
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
                root.accepted_by,
                preparation.action,
                preparation.resource,
                preparation.mission_id,
                dict(preparation.context),
            )
            if not decision.allowed or observed != expected:
                defects.append(
                    "C4_REVIEWER_ROOT_AUTHORIZATION_REQUEST_MISMATCH"
                )
            if self._as_datetime(root.accepted_at) < self._as_datetime(
                decision.decided_at
            ):
                defects.append(
                    "C4_REVIEWER_ROOT_ACCEPTED_AT_PREDATES_AUTHORIZATION"
                )

        consumption = self.database.connection.execute(
            """
            SELECT * FROM continuity_authorization_consumptions
            WHERE decision_id = ?
            """,
            (root.authorization_decision_id,),
        ).fetchone()
        if consumption is None:
            defects.append(
                "C4_REVIEWER_ROOT_AUTHORIZATION_CONSUMPTION_MISSING"
            )
        elif (
            str(consumption["operation_kind"]),
            str(consumption["operation_id"]),
            str(consumption["consumed_at"]),
            str(consumption["consumed_by"]),
        ) != (
            _ROOT_EVENT_KIND,
            root.key_id,
            root.accepted_at,
            root.accepted_by,
        ):
            defects.append(
                "C4_REVIEWER_ROOT_AUTHORIZATION_CONSUMPTION_MISMATCH"
            )

        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (root.ledger_event_id,),
        ).fetchone()
        if event is None:
            defects.append("C4_REVIEWER_ROOT_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != self._root_stream(root.key_id):
                defects.append("C4_REVIEWER_ROOT_LEDGER_STREAM_MISMATCH")
            if str(event["kind"]) != _ROOT_EVENT_KIND:
                defects.append("C4_REVIEWER_ROOT_LEDGER_KIND_MISMATCH")
            if str(event["actor"]) != root.accepted_by:
                defects.append("C4_REVIEWER_ROOT_LEDGER_ACTOR_MISMATCH")
            if str(event["occurred_at"]) != root.accepted_at:
                defects.append("C4_REVIEWER_ROOT_LEDGER_TIMESTAMP_MISMATCH")
            if str(event["record_hash"]) != root.ledger_hash:
                defects.append("C4_REVIEWER_ROOT_LEDGER_HASH_MISMATCH")
            try:
                payload = json.loads(str(event["payload_json"]))
            except (json.JSONDecodeError, TypeError):
                defects.append("C4_REVIEWER_ROOT_LEDGER_PAYLOAD_INVALID")
            else:
                if payload != self._root_ledger_payload(root):
                    defects.append("C4_REVIEWER_ROOT_LEDGER_PAYLOAD_MISMATCH")
        chain = self.ledger.verify(self._root_stream(root.key_id))
        defects.extend(
            f"C4_REVIEWER_ROOT_LEDGER_CHAIN:{defect.code}"
            for defect in chain.defects
        )
        return C4ArchitectureReviewerRootVerification(
            key_id=key_id,
            defects=tuple(dict.fromkeys(defects)),
        )

    def _clean_root(
        self,
        key_id: str,
    ) -> tuple[C4ArchitectureReviewerRoot, bytes]:
        try:
            root = self.get_reviewer_root(key_id)
            verification = self.verify_reviewer_root(key_id)
            public_key = self._root_key(key_id)
        except NotFoundError as exc:
            raise IntegrityError(
                "C4 reviewer root is not accepted",
                {"key_id": key_id},
            ) from exc
        if not verification.ok:
            raise IntegrityError(
                "C4 reviewer root verification failed",
                {
                    "key_id": key_id,
                    "defects": list(verification.defects),
                },
            )
        return root, public_key

    @staticmethod
    def _decode_payload(payload: bytes) -> dict[str, object]:
        def reject_duplicates(
            pairs: list[tuple[str, object]],
        ) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate key: {key}")
                result[key] = value
            return result

        try:
            value = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=reject_duplicates,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValidationError(
                "C4 architecture review payload must be valid UTF-8 JSON"
            ) from exc
        if not isinstance(value, dict):
            raise ValidationError(
                "C4 architecture review payload must be a JSON object"
            )
        observed = frozenset(value)
        if observed != _PAYLOAD_FIELDS:
            raise ValidationError(
                "C4 architecture review payload fields do not match contract",
                {
                    "missing": sorted(_PAYLOAD_FIELDS - observed),
                    "unexpected": sorted(observed - _PAYLOAD_FIELDS),
                },
            )
        return value

    def _normalize_findings(
        self,
        value: object,
    ) -> list[dict[str, object]]:
        if not isinstance(value, list):
            raise ValidationError("findings must be a list")
        normalized: list[dict[str, object]] = []
        finding_ids: list[str] = []
        for raw in value:
            if not isinstance(raw, Mapping):
                raise ValidationError("finding entries must be JSON objects")
            observed = frozenset(raw)
            if observed != _FINDING_FIELDS:
                raise ValidationError(
                    "finding fields do not match contract",
                    {
                        "missing": sorted(_FINDING_FIELDS - observed),
                        "unexpected": sorted(observed - _FINDING_FIELDS),
                    },
                )
            finding_id = self._required_text(raw["finding_id"], "finding_id")
            try:
                code = C4ArchitectureFindingCode(str(raw["code"]))
            except ValueError as exc:
                raise ValidationError("unknown C4 architecture finding code") from exc
            try:
                severity = C4ArchitectureFindingSeverity(
                    str(raw["severity"])
                )
            except ValueError as exc:
                raise ValidationError(
                    "unknown C4 architecture finding severity"
                ) from exc
            affected_ids = self._sorted_strings(
                raw["affected_ids"],
                "affected_ids",
            )
            evidence_refs = self._sorted_strings(
                raw["evidence_refs"],
                "evidence_refs",
            )
            finding_ids.append(finding_id)
            normalized.append(
                {
                    "finding_id": finding_id,
                    "code": code.value,
                    "severity": severity.value,
                    "title": self._required_text(raw["title"], "title"),
                    "description": self._required_text(
                        raw["description"],
                        "description",
                    ),
                    "affected_ids": list(affected_ids),
                    "evidence_refs": list(evidence_refs),
                    "recommendation": self._required_text(
                        raw["recommendation"],
                        "recommendation",
                    ),
                }
            )
        if finding_ids != sorted(finding_ids):
            raise ValidationError("findings must be sorted by finding_id")
        if len(set(finding_ids)) != len(finding_ids):
            raise ValidationError("finding_id values must be unique")
        return normalized

    def _parse_payload(self, payload: bytes) -> dict[str, object]:
        value = self._decode_payload(payload)
        for field in (
            "review_id",
            "candidate_id",
            "architecture_id",
            "architecture_version",
            "input_set_id",
            "input_set_digest",
            "manifest_sha256",
            "reviewer_identity",
            "reviewer_environment",
            "reviewed_at",
            "independence_basis",
            "structural_verification_result",
            "security_verification_result",
            "evidence_binding_result",
            "verdict",
            "gate_effect",
        ):
            value[field] = self._required_text(value[field], field)
        if value["architecture_version"] != "3.2":
            raise ValidationError("architecture_version must equal 3.2")
        for field in ("input_set_digest", "manifest_sha256"):
            value[field] = self._digest(value[field], field)
        for field in (
            "structural_verification_result",
            "security_verification_result",
            "evidence_binding_result",
        ):
            if value[field] not in _VERIFICATION_RESULTS:
                raise ValidationError(f"{field} must be PASS or FAIL")
        value["reviewed_at"] = self._timestamp(
            value["reviewed_at"],
            "reviewed_at",
        )
        try:
            verdict = C4ArchitectureReviewVerdict(str(value["verdict"]))
        except ValueError as exc:
            raise ValidationError("unknown C4 architecture review verdict") from exc
        value["verdict"] = verdict.value
        if value["gate_effect"] != _REVIEW_GATE_EFFECT:
            raise ValidationError(
                "gate_effect must equal NO_PUBLICATION_NO_DEPLOYMENT"
            )
        value["findings"] = self._normalize_findings(value["findings"])
        self._assert_verdict_consistency(value)
        return value

    @staticmethod
    def _assert_verdict_consistency(value: Mapping[str, object]) -> None:
        findings = value["findings"]
        if not isinstance(findings, list):
            raise ValidationError("findings must be a list")
        verdict = C4ArchitectureReviewVerdict(str(value["verdict"]))
        results = (
            str(value["structural_verification_result"]),
            str(value["security_verification_result"]),
            str(value["evidence_binding_result"]),
        )
        severities = {
            C4ArchitectureFindingSeverity(str(finding["severity"]))
            for finding in findings
            if isinstance(finding, Mapping)
        }
        if verdict is C4ArchitectureReviewVerdict.ACCEPTED:
            if any(result != "PASS" for result in results) or severities.intersection(
                {
                    C4ArchitectureFindingSeverity.MEDIUM,
                    C4ArchitectureFindingSeverity.HIGH,
                    C4ArchitectureFindingSeverity.CRITICAL,
                }
            ):
                raise StateTransitionError(
                    "accepted C4 review is inconsistent with results or findings"
                )
            return
        if not findings:
            raise StateTransitionError(
                "rejected or rework C4 review requires findings"
            )
        if verdict is C4ArchitectureReviewVerdict.REJECTED:
            if "FAIL" not in results or (
                C4ArchitectureFindingSeverity.CRITICAL not in severities
            ):
                raise StateTransitionError(
                    "rejected C4 review requires a failed result and critical finding"
                )
            return
        if C4ArchitectureFindingSeverity.CRITICAL in severities:
            raise StateTransitionError(
                "rework C4 review cannot contain a critical finding"
            )
        if "FAIL" not in results and not severities.intersection(
            {
                C4ArchitectureFindingSeverity.MEDIUM,
                C4ArchitectureFindingSeverity.HIGH,
            }
        ):
            raise StateTransitionError(
                "rework C4 review requires a failed result or blocking finding"
            )

    def _clean_material(
        self,
        candidate_id: str,
    ) -> tuple[
        C4ArchitectureCandidate,
        C4ArchitectureInputSet,
        Mapping[str, Any],
        tuple[Mapping[str, Any], ...],
    ]:
        candidate_verification = self.candidates.verify_candidate(candidate_id)
        if not candidate_verification.ok:
            raise IntegrityError(
                "C4 architecture candidate failed verification",
                {
                    "candidate_id": candidate_id,
                    "defects": list(candidate_verification.defects),
                },
            )
        candidate = self.candidates.get_candidate(candidate_id)
        if candidate.status is not C4ArchitectureCandidateStatus.NOT_REVIEWED:
            raise StateTransitionError(
                "C4 architecture review requires an unreviewed candidate"
            )
        input_verification = self.inputs.verify_input_set(candidate.input_set_id)
        if not input_verification.ok:
            raise IntegrityError(
                "C4 architecture input set failed verification",
                {
                    "input_set_id": candidate.input_set_id,
                    "defects": list(input_verification.defects),
                },
            )
        input_set = self.inputs.get_input_set(candidate.input_set_id)
        if candidate.input_set_digest != input_set.input_set_digest:
            raise IntegrityError(
                "candidate input-set digest does not match current input set"
            )
        manifest = self.candidates.get_manifest(candidate_id)
        if sha256_digest(manifest) != candidate.manifest_sha256:
            raise IntegrityError(
                "candidate manifest digest does not match current manifest"
            )
        members = self.inputs.get_members(input_set.input_set_id)
        return candidate, input_set, manifest, members

    @staticmethod
    def _collect_evidence_refs(
        candidate: C4ArchitectureCandidate,
        input_set: C4ArchitectureInputSet,
        manifest: Mapping[str, Any],
        members: tuple[Mapping[str, Any], ...],
    ) -> set[str]:
        refs = {
            candidate.candidate_id,
            candidate.architecture_id,
            candidate.manifest_sha256,
            input_set.input_set_id,
            input_set.input_set_digest,
        }
        for member in members:
            for field in (
                "execution_id",
                "candidate_artifact_id",
                "terminal_result_digest",
            ):
                value = member.get(field)
                if isinstance(value, str) and value:
                    refs.add(value)
        for adr in manifest.get("authority_adrs", []):
            if isinstance(adr, Mapping):
                refs.add(str(adr.get("adr_id", "")))
                refs.update(str(item) for item in adr.get("affected_port_ids", []))
                refs.update(
                    str(item) for item in adr.get("evidence_execution_ids", [])
                )
        for port in manifest.get("ports", []):
            if isinstance(port, Mapping):
                for field in ("port_id", "capability_id", "contract_digest"):
                    value = port.get(field)
                    if isinstance(value, str) and value:
                        refs.add(value)
                refs.update(str(item) for item in port.get("test_ids", []))
                refs.update(str(item) for item in port.get("proof_ids", []))
        for binding in manifest.get("component_bindings", []):
            if isinstance(binding, Mapping):
                for field in (
                    "binding_id",
                    "execution_id",
                    "candidate_artifact_id",
                    "candidate_material_sha256",
                ):
                    value = binding.get(field)
                    if isinstance(value, str) and value:
                        refs.add(value)
        benchmark = manifest.get("vertical_benchmark")
        if isinstance(benchmark, Mapping):
            for field in (
                "benchmark_id",
                "end_to_end_test_id",
                "end_to_end_proof_id",
            ):
                value = benchmark.get(field)
                if isinstance(value, str) and value:
                    refs.add(value)
            for map_field in ("stage_test_ids", "stage_proof_ids"):
                stage_map = benchmark.get(map_field)
                if isinstance(stage_map, Mapping):
                    for values in stage_map.values():
                        if isinstance(values, list):
                            refs.update(str(item) for item in values)
        for nfr in manifest.get("non_functional_requirements", []):
            if isinstance(nfr, Mapping):
                value = nfr.get("requirement_id")
                if isinstance(value, str) and value:
                    refs.add(value)
                refs.update(str(item) for item in nfr.get("test_ids", []))
                refs.update(str(item) for item in nfr.get("proof_ids", []))
        refs.discard("")
        return refs

    @staticmethod
    def _assert_payload_binding(
        value: Mapping[str, object],
        candidate: C4ArchitectureCandidate,
        input_set: C4ArchitectureInputSet,
    ) -> None:
        expected = {
            "candidate_id": candidate.candidate_id,
            "architecture_id": candidate.architecture_id,
            "architecture_version": candidate.architecture_version,
            "input_set_id": input_set.input_set_id,
            "input_set_digest": input_set.input_set_digest,
            "manifest_sha256": candidate.manifest_sha256,
        }
        mismatches = {
            field: {
                "expected": expected_value,
                "observed": value[field],
            }
            for field, expected_value in expected.items()
            if value[field] != expected_value
        }
        if mismatches:
            raise StateTransitionError(
                "signed C4 review does not match candidate and input material",
                {"mismatches": mismatches},
            )

    @staticmethod
    def _assert_finding_evidence(
        findings: list[dict[str, object]],
        allowed_refs: set[str],
    ) -> None:
        for finding in findings:
            refs = set(str(item) for item in finding["evidence_refs"])
            affected = set(str(item) for item in finding["affected_ids"])
            unknown = sorted((refs | affected) - allowed_refs)
            if unknown:
                raise StateTransitionError(
                    "C4 review finding references evidence outside candidate or input",
                    {
                        "finding_id": finding["finding_id"],
                        "unknown_refs": unknown,
                    },
                )

    @staticmethod
    def _assert_independence(
        reviewer_identity: str,
        *,
        candidate: C4ArchitectureCandidate,
        input_set: C4ArchitectureInputSet,
        root: C4ArchitectureReviewerRoot,
        admission_actor: str,
    ) -> None:
        disallowed = {
            candidate.created_by.strip(),
            input_set.frozen_by.strip(),
            root.accepted_by.strip(),
            admission_actor.strip(),
            *(identity.strip() for identity in input_set.author_identities),
        }
        if reviewer_identity.strip() in disallowed:
            raise StateTransitionError(
                "reviewer identity is not independent",
                {
                    "reviewer_identity": reviewer_identity,
                    "disallowed_identities": sorted(disallowed),
                },
            )

    def _latest_material_time(
        self,
        candidate: C4ArchitectureCandidate,
        input_set: C4ArchitectureInputSet,
        members: tuple[Mapping[str, Any], ...],
    ) -> str:
        times = [candidate.created_at, input_set.frozen_at]
        for member in members:
            requested_at = member.get("requested_at")
            if isinstance(requested_at, str):
                times.append(self._timestamp(requested_at, "requested_at"))
        return max(times, key=self._as_datetime)

    def _assert_chronology(
        self,
        reviewed_at: str,
        admitted_at: str,
        *,
        candidate: C4ArchitectureCandidate,
        input_set: C4ArchitectureInputSet,
        members: tuple[Mapping[str, Any], ...],
        root: C4ArchitectureReviewerRoot,
    ) -> None:
        latest_material = self._latest_material_time(
            candidate,
            input_set,
            members,
        )
        if self._as_datetime(reviewed_at) < self._as_datetime(latest_material):
            raise StateTransitionError(
                "review timestamp predates C4 material"
            )
        if self._as_datetime(admitted_at) < self._as_datetime(reviewed_at):
            raise StateTransitionError("review admission predates review timestamp")
        if self._as_datetime(admitted_at) < self._as_datetime(root.accepted_at):
            raise StateTransitionError("review admission predates reviewer-root acceptance")

    @staticmethod
    def _review_from_row(row: sqlite3.Row) -> C4ArchitectureReview:
        return C4ArchitectureReview(
            review_id=str(row["review_id"]),
            candidate_id=str(row["candidate_id"]),
            architecture_id=str(row["architecture_id"]),
            architecture_version=str(row["architecture_version"]),
            input_set_id=str(row["input_set_id"]),
            input_set_digest=str(row["input_set_digest"]),
            manifest_sha256=str(row["manifest_sha256"]),
            key_id=str(row["key_id"]),
            payload_sha256=str(row["payload_sha256"]),
            signature_sha256=str(row["signature_sha256"]),
            reviewer_identity=str(row["reviewer_identity"]),
            reviewer_environment=str(row["reviewer_environment"]),
            reviewed_at=str(row["reviewed_at"]),
            independence_basis=str(row["independence_basis"]),
            structural_verification_result=str(
                row["structural_verification_result"]
            ),
            security_verification_result=str(
                row["security_verification_result"]
            ),
            evidence_binding_result=str(row["evidence_binding_result"]),
            finding_count=int(row["finding_count"]),
            verdict=C4ArchitectureReviewVerdict(str(row["verdict"])),
            admitted_at=str(row["admitted_at"]),
            admitted_by=str(row["admitted_by"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def get_review(self, review_id: str) -> C4ArchitectureReview:
        review_id = self._required_text(review_id, "review_id")
        row = self.database.connection.execute(
            "SELECT * FROM c4_architecture_reviews WHERE review_id = ?",
            (review_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C4 architecture review does not exist",
                {"review_id": review_id},
            )
        try:
            return self._review_from_row(row)
        except ValueError as exc:
            raise IntegrityError("stored C4 review verdict is invalid") from exc

    def get_findings(
        self,
        review_id: str,
    ) -> tuple[Mapping[str, Any], ...]:
        self.get_review(review_id)
        rows = self.database.connection.execute(
            """
            SELECT * FROM c4_architecture_review_findings
            WHERE review_id = ? ORDER BY ordinal
            """,
            (review_id,),
        ).fetchall()
        findings: list[Mapping[str, Any]] = []
        for row in rows:
            try:
                finding = json.loads(str(row["finding_json"]))
            except (json.JSONDecodeError, TypeError) as exc:
                raise IntegrityError(
                    "stored C4 review finding is invalid",
                    {"ordinal": int(row["ordinal"])},
                ) from exc
            if not isinstance(finding, dict):
                raise IntegrityError(
                    "stored C4 review finding must be an object",
                    {"ordinal": int(row["ordinal"])},
                )
            findings.append(finding)
        return tuple(findings)

    @staticmethod
    def _review_ledger_payload(
        review: C4ArchitectureReview,
    ) -> dict[str, object]:
        return {
            "review_id": review.review_id,
            "candidate_id": review.candidate_id,
            "architecture_id": review.architecture_id,
            "architecture_version": review.architecture_version,
            "input_set_id": review.input_set_id,
            "input_set_digest": review.input_set_digest,
            "manifest_sha256": review.manifest_sha256,
            "key_id": review.key_id,
            "payload_sha256": review.payload_sha256,
            "signature_sha256": review.signature_sha256,
            "reviewer_identity": review.reviewer_identity,
            "finding_count": review.finding_count,
            "verdict": review.verdict.value,
            "gate_effect": _REVIEW_GATE_EFFECT,
        }

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
        payload = self._bounded_bytes(payload, "payload", _MAX_PAYLOAD_BYTES)
        signature = self._bounded_bytes(
            signature,
            "signature",
            _MAX_SIGNATURE_BYTES,
        )
        admitted_at = self._timestamp(occurred_at or utc_now())
        root, public_key = self._clean_root(key_id)
        if not self.continuity.signature_verifier.verify(
            public_key,
            payload,
            signature,
        ):
            raise IntegrityError("C4 architecture review signature is invalid")
        value = self._parse_payload(payload)
        if value["candidate_id"] != candidate_id:
            raise StateTransitionError(
                "signed C4 review targets another candidate"
            )
        candidate, input_set, manifest, members = self._clean_material(candidate_id)
        self._assert_payload_binding(value, candidate, input_set)
        findings = value["findings"]
        if not isinstance(findings, list):
            raise ValidationError("findings must be a list")
        allowed_refs = self._collect_evidence_refs(
            candidate,
            input_set,
            manifest,
            members,
        )
        self._assert_finding_evidence(findings, allowed_refs)
        reviewer_identity = str(value["reviewer_identity"])
        self._assert_independence(
            reviewer_identity,
            candidate=candidate,
            input_set=input_set,
            root=root,
            admission_actor=actor,
        )
        self._assert_chronology(
            str(value["reviewed_at"]),
            admitted_at,
            candidate=candidate,
            input_set=input_set,
            members=members,
            root=root,
        )
        review_id = str(value["review_id"])
        payload_sha256 = self._bytes_sha256(payload)
        signature_sha256 = self._bytes_sha256(signature)

        existing = self.database.connection.execute(
            "SELECT * FROM c4_architecture_reviews WHERE review_id = ?",
            (review_id,),
        ).fetchone()
        if existing is not None:
            exact = (
                str(existing["candidate_id"]) == candidate_id
                and str(existing["key_id"]) == key_id
                and bytes(existing["payload"]) == payload
                and bytes(existing["signature"]) == signature
                and str(existing["admitted_by"]) == actor
            )
            if not exact:
                raise ConflictError(
                    "review_id was reused with different C4 review material",
                    {"review_id": review_id},
                )
            verification = self.verify_review(review_id)
            if not verification.ok:
                raise IntegrityError(
                    "existing C4 architecture review failed verification",
                    {
                        "review_id": review_id,
                        "defects": list(verification.defects),
                    },
                )
            return self._review_from_row(existing)
        competitor = self.database.connection.execute(
            """
            SELECT review_id FROM c4_architecture_reviews
            WHERE candidate_id = ?
            """,
            (candidate_id,),
        ).fetchone()
        if competitor is not None:
            raise ConflictError(
                "C4 candidate already has an independent review",
                {
                    "candidate_id": candidate_id,
                    "review_id": str(competitor["review_id"]),
                },
            )

        provisional = C4ArchitectureReview(
            review_id=review_id,
            candidate_id=candidate.candidate_id,
            architecture_id=candidate.architecture_id,
            architecture_version=candidate.architecture_version,
            input_set_id=input_set.input_set_id,
            input_set_digest=input_set.input_set_digest,
            manifest_sha256=candidate.manifest_sha256,
            key_id=key_id,
            payload_sha256=payload_sha256,
            signature_sha256=signature_sha256,
            reviewer_identity=reviewer_identity,
            reviewer_environment=str(value["reviewer_environment"]),
            reviewed_at=str(value["reviewed_at"]),
            independence_basis=str(value["independence_basis"]),
            structural_verification_result=str(
                value["structural_verification_result"]
            ),
            security_verification_result=str(
                value["security_verification_result"]
            ),
            evidence_binding_result=str(value["evidence_binding_result"]),
            finding_count=len(findings),
            verdict=C4ArchitectureReviewVerdict(str(value["verdict"])),
            admitted_at=admitted_at,
            admitted_by=actor,
            ledger_event_id="pending",
            ledger_hash="pending",
        )
        try:
            with self.database.transaction() as connection:
                race = connection.execute(
                    """
                    SELECT review_id FROM c4_architecture_reviews
                    WHERE review_id = ? OR candidate_id = ?
                    """,
                    (review_id, candidate_id),
                ).fetchone()
                if race is not None:
                    raise ConflictError(
                        "C4 architecture review appeared during admission"
                    )
                current_root, current_public_key = self._clean_root(key_id)
                if not self.continuity.signature_verifier.verify(
                    current_public_key,
                    payload,
                    signature,
                ):
                    raise IntegrityError(
                        "C4 architecture review signature is invalid"
                    )
                current_value = self._parse_payload(payload)
                current_candidate, current_input, current_manifest, current_members = (
                    self._clean_material(candidate_id)
                )
                self._assert_payload_binding(
                    current_value,
                    current_candidate,
                    current_input,
                )
                current_findings = current_value["findings"]
                if not isinstance(current_findings, list):
                    raise ValidationError("findings must be a list")
                self._assert_finding_evidence(
                    current_findings,
                    self._collect_evidence_refs(
                        current_candidate,
                        current_input,
                        current_manifest,
                        current_members,
                    ),
                )
                self._assert_independence(
                    str(current_value["reviewer_identity"]),
                    candidate=current_candidate,
                    input_set=current_input,
                    root=current_root,
                    admission_actor=actor,
                )
                self._assert_chronology(
                    str(current_value["reviewed_at"]),
                    admitted_at,
                    candidate=current_candidate,
                    input_set=current_input,
                    members=current_members,
                    root=current_root,
                )
                if current_value != value:
                    raise ConflictError(
                        "C4 review payload changed during admission"
                    )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    self._review_stream(review_id),
                    _REVIEW_EVENT_KIND,
                    self._review_ledger_payload(provisional),
                    actor=actor,
                    occurred_at=admitted_at,
                )
                connection.execute(
                    """
                    INSERT INTO c4_architecture_reviews (
                        review_id, candidate_id, architecture_id,
                        architecture_version, input_set_id,
                        input_set_digest, manifest_sha256, key_id,
                        payload, payload_sha256, signature,
                        signature_sha256, reviewer_identity,
                        reviewer_environment, reviewed_at,
                        independence_basis,
                        structural_verification_result,
                        security_verification_result,
                        evidence_binding_result, finding_count,
                        verdict, gate_effect, admitted_at, admitted_by,
                        ledger_event_id, ledger_hash
                    ) VALUES (
                        ?, ?, ?, '3.2', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        review_id,
                        candidate.candidate_id,
                        candidate.architecture_id,
                        input_set.input_set_id,
                        input_set.input_set_digest,
                        candidate.manifest_sha256,
                        key_id,
                        payload,
                        payload_sha256,
                        signature,
                        signature_sha256,
                        reviewer_identity,
                        str(value["reviewer_environment"]),
                        str(value["reviewed_at"]),
                        str(value["independence_basis"]),
                        str(value["structural_verification_result"]),
                        str(value["security_verification_result"]),
                        str(value["evidence_binding_result"]),
                        len(findings),
                        str(value["verdict"]),
                        _REVIEW_GATE_EFFECT,
                        admitted_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
                for ordinal, finding in enumerate(findings):
                    connection.execute(
                        """
                        INSERT INTO c4_architecture_review_findings (
                            review_id, ordinal, finding_id,
                            finding_json, finding_sha256
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            review_id,
                            ordinal,
                            str(finding["finding_id"]),
                            canonical_json(finding),
                            sha256_digest(finding),
                        ),
                    )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "C4 architecture review conflicts with immutable state",
                {"review_id": review_id},
            ) from exc
        return self.get_review(review_id)

    @staticmethod
    def _payload_matches_record(
        value: Mapping[str, object],
        record: C4ArchitectureReview,
    ) -> bool:
        expected = {
            "review_id": record.review_id,
            "candidate_id": record.candidate_id,
            "architecture_id": record.architecture_id,
            "architecture_version": record.architecture_version,
            "input_set_id": record.input_set_id,
            "input_set_digest": record.input_set_digest,
            "manifest_sha256": record.manifest_sha256,
            "reviewer_identity": record.reviewer_identity,
            "reviewer_environment": record.reviewer_environment,
            "reviewed_at": record.reviewed_at,
            "independence_basis": record.independence_basis,
            "structural_verification_result": (
                record.structural_verification_result
            ),
            "security_verification_result": (
                record.security_verification_result
            ),
            "evidence_binding_result": record.evidence_binding_result,
            "verdict": record.verdict.value,
            "gate_effect": _REVIEW_GATE_EFFECT,
        }
        return all(
            value.get(field) == expected_value
            for field, expected_value in expected.items()
        ) and isinstance(value.get("findings"), list) and len(
            value["findings"]
        ) == record.finding_count

    def verify_review(
        self,
        review_id: str,
    ) -> C4ArchitectureReviewVerification:
        review_id = self._required_text(review_id, "review_id")
        row = self.database.connection.execute(
            "SELECT * FROM c4_architecture_reviews WHERE review_id = ?",
            (review_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C4 architecture review does not exist",
                {"review_id": review_id},
            )
        defects: list[str] = []
        try:
            record = self._review_from_row(row)
        except ValueError:
            return C4ArchitectureReviewVerification(
                review_id=review_id,
                defects=("C4_REVIEW_ROW_INVALID",),
            )
        payload = bytes(row["payload"])
        signature = bytes(row["signature"])
        if self._bytes_sha256(payload) != record.payload_sha256:
            defects.append("C4_REVIEW_PAYLOAD_SHA256_MISMATCH")
        if self._bytes_sha256(signature) != record.signature_sha256:
            defects.append("C4_REVIEW_SIGNATURE_SHA256_MISMATCH")

        root: C4ArchitectureReviewerRoot | None = None
        public_key: bytes | None = None
        try:
            root = self.get_reviewer_root(record.key_id)
            root_verification = self.verify_reviewer_root(record.key_id)
            public_key = self._root_key(record.key_id)
        except NotFoundError:
            defects.append("C4_REVIEW_REVIEWER_ROOT_MISSING")
        else:
            defects.extend(
                f"C4_REVIEW_REVIEWER_ROOT:{defect}"
                for defect in root_verification.defects
            )
        if public_key is not None and not self.continuity.signature_verifier.verify(
            public_key,
            payload,
            signature,
        ):
            defects.append("C4_REVIEW_SIGNATURE_INVALID")

        parsed: dict[str, object] | None = None
        try:
            parsed = self._parse_payload(payload)
        except (StateTransitionError, ValidationError):
            defects.append("C4_REVIEW_PAYLOAD_INVALID")
        if parsed is not None and not self._payload_matches_record(parsed, record):
            defects.append("C4_REVIEW_PAYLOAD_RECORD_MISMATCH")

        finding_rows = self.database.connection.execute(
            """
            SELECT * FROM c4_architecture_review_findings
            WHERE review_id = ? ORDER BY ordinal
            """,
            (review_id,),
        ).fetchall()
        stored_findings: list[dict[str, object]] = []
        for expected_ordinal, finding_row in enumerate(finding_rows):
            ordinal = int(finding_row["ordinal"])
            if ordinal != expected_ordinal:
                defects.append(f"C4_REVIEW_FINDING_ORDINAL_MISMATCH:{ordinal}")
            try:
                finding = json.loads(str(finding_row["finding_json"]))
            except (json.JSONDecodeError, TypeError):
                defects.append(f"C4_REVIEW_FINDING_JSON_INVALID:{ordinal}")
                continue
            if not isinstance(finding, dict):
                defects.append(f"C4_REVIEW_FINDING_JSON_INVALID:{ordinal}")
                continue
            if canonical_json(finding) != str(finding_row["finding_json"]):
                defects.append(f"C4_REVIEW_FINDING_NOT_CANONICAL:{ordinal}")
            if sha256_digest(finding) != str(finding_row["finding_sha256"]):
                defects.append(f"C4_REVIEW_FINDING_SHA256_MISMATCH:{ordinal}")
            if finding.get("finding_id") != str(finding_row["finding_id"]):
                defects.append(f"C4_REVIEW_FINDING_ID_MISMATCH:{ordinal}")
            stored_findings.append(finding)
        if len(stored_findings) != record.finding_count:
            defects.append("C4_REVIEW_FINDING_COUNT_MISMATCH")
        if parsed is not None and parsed.get("findings") != stored_findings:
            defects.append("C4_REVIEW_FINDINGS_PAYLOAD_MISMATCH")

        candidate: C4ArchitectureCandidate | None = None
        input_set: C4ArchitectureInputSet | None = None
        manifest: Mapping[str, Any] | None = None
        members: tuple[Mapping[str, Any], ...] = ()
        try:
            candidate_verification = self.candidates.verify_candidate(
                record.candidate_id
            )
        except (NotFoundError, AssertionError):
            defects.append("C4_REVIEW_CANDIDATE_MISSING")
        else:
            defects.extend(
                f"C4_REVIEW_CANDIDATE:{defect}"
                for defect in candidate_verification.defects
            )
            try:
                candidate = self.candidates.get_candidate(record.candidate_id)
                manifest = self.candidates.get_manifest(record.candidate_id)
            except (NotFoundError, AssertionError):
                defects.append("C4_REVIEW_CANDIDATE_MISSING")
        try:
            input_verification = self.inputs.verify_input_set(record.input_set_id)
        except (NotFoundError, AssertionError):
            defects.append("C4_REVIEW_INPUT_MISSING")
        else:
            defects.extend(
                f"C4_REVIEW_INPUT:{defect}"
                for defect in input_verification.defects
            )
            try:
                input_set = self.inputs.get_input_set(record.input_set_id)
                members = self.inputs.get_members(record.input_set_id)
            except (NotFoundError, AssertionError):
                defects.append("C4_REVIEW_INPUT_MISSING")

        if candidate is not None:
            if record.architecture_id != candidate.architecture_id:
                defects.append("C4_REVIEW_ARCHITECTURE_ID_MISMATCH")
            if record.architecture_version != candidate.architecture_version:
                defects.append("C4_REVIEW_ARCHITECTURE_VERSION_MISMATCH")
            if record.input_set_id != candidate.input_set_id:
                defects.append("C4_REVIEW_INPUT_SET_ID_MISMATCH")
            if record.input_set_digest != candidate.input_set_digest:
                defects.append("C4_REVIEW_INPUT_SET_DIGEST_MISMATCH")
            if record.manifest_sha256 != candidate.manifest_sha256:
                defects.append("C4_REVIEW_MANIFEST_SHA256_MISMATCH")
        if input_set is not None and record.input_set_digest != (
            input_set.input_set_digest
        ):
            defects.append("C4_REVIEW_INPUT_SET_DIGEST_MISMATCH")

        if (
            parsed is not None
            and candidate is not None
            and input_set is not None
            and manifest is not None
        ):
            try:
                self._assert_payload_binding(parsed, candidate, input_set)
            except StateTransitionError:
                defects.append("C4_REVIEW_MATERIAL_BINDING_MISMATCH")
            findings = parsed.get("findings")
            if isinstance(findings, list):
                try:
                    self._assert_finding_evidence(
                        findings,
                        self._collect_evidence_refs(
                            candidate,
                            input_set,
                            manifest,
                            members,
                        ),
                    )
                except StateTransitionError:
                    defects.append("C4_REVIEW_FINDING_EVIDENCE_INVALID")
                try:
                    self._assert_verdict_consistency(parsed)
                except StateTransitionError:
                    defects.append("C4_REVIEW_VERDICT_INCONSISTENT")
            if root is not None:
                try:
                    self._assert_independence(
                        record.reviewer_identity,
                        candidate=candidate,
                        input_set=input_set,
                        root=root,
                        admission_actor=record.admitted_by,
                    )
                except StateTransitionError:
                    defects.append("C4_REVIEW_INDEPENDENCE_INVALID")
                try:
                    self._assert_chronology(
                        record.reviewed_at,
                        record.admitted_at,
                        candidate=candidate,
                        input_set=input_set,
                        members=members,
                        root=root,
                    )
                except StateTransitionError:
                    defects.append("C4_REVIEW_CHRONOLOGY_INVALID")

        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (record.ledger_event_id,),
        ).fetchone()
        if event is None:
            defects.append("C4_REVIEW_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != self._review_stream(review_id):
                defects.append("C4_REVIEW_LEDGER_STREAM_MISMATCH")
            if str(event["kind"]) != _REVIEW_EVENT_KIND:
                defects.append("C4_REVIEW_LEDGER_KIND_MISMATCH")
            if str(event["actor"]) != record.admitted_by:
                defects.append("C4_REVIEW_LEDGER_ACTOR_MISMATCH")
            if str(event["occurred_at"]) != record.admitted_at:
                defects.append("C4_REVIEW_LEDGER_TIMESTAMP_MISMATCH")
            if str(event["record_hash"]) != record.ledger_hash:
                defects.append("C4_REVIEW_LEDGER_HASH_MISMATCH")
            try:
                event_payload = json.loads(str(event["payload_json"]))
            except (json.JSONDecodeError, TypeError):
                defects.append("C4_REVIEW_LEDGER_PAYLOAD_INVALID")
            else:
                if event_payload != self._review_ledger_payload(record):
                    defects.append("C4_REVIEW_LEDGER_PAYLOAD_MISMATCH")
        chain = self.ledger.verify(self._review_stream(review_id))
        defects.extend(
            f"C4_REVIEW_LEDGER_CHAIN:{defect.code}"
            for defect in chain.defects
        )
        return C4ArchitectureReviewVerification(
            review_id=review_id,
            defects=tuple(dict.fromkeys(defects)),
        )
