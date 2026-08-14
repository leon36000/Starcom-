from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
import re
import sqlite3
from typing import Any, Mapping

from .canonical import canonical_json, sha256_digest, utc_now
from .continuity import (
    ContinuityService,
    OpenSSLEd25519Verifier,
    SignatureVerifier,
)
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
_DESCRIPTOR_FIELDS = frozenset(
    {
        "executor_id",
        "implementation_name",
        "implementation_version",
        "implementation_digest",
        "artifact_digest",
        "entrypoint",
        "supported_sandbox_profiles",
        "network_mode",
        "capabilities",
    }
)
_QUALIFICATION_FIELDS = frozenset(
    {
        "qualification_id",
        "executor_id",
        "descriptor_digest",
        "report_digest",
        "test_suite_digest",
        "reviewer_identity",
        "reviewer_environment",
        "independence_basis",
        "sandbox_profiles_tested",
        "network_mode_tested",
        "verdict",
        "qualified_at",
        "gate_effect",
    }
)
_MAX_PUBLIC_KEY_BYTES = 8 * 1024
_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
_MAX_SIGNATURE_BYTES = 1024


class C3ExecutorNetworkMode(str, Enum):
    DENY = "DENY"
    ALLOWLIST_ONLY = "ALLOWLIST_ONLY"


class C3ExecutorState(str, Enum):
    REGISTERED_DISABLED = "C3_EXECUTOR_REGISTERED_DISABLED"
    QUALIFIED_DISABLED = "C3_EXECUTOR_QUALIFIED_DISABLED"
    ENABLED = "C3_EXECUTOR_ENABLED"
    REVOKED = "C3_EXECUTOR_REVOKED"


@dataclass(frozen=True)
class C3ExecutorDescriptor:
    executor_id: str
    implementation_name: str
    implementation_version: str
    implementation_digest: str
    artifact_digest: str
    entrypoint: str
    supported_sandbox_profiles: tuple[str, ...]
    network_mode: C3ExecutorNetworkMode
    capabilities: tuple[str, ...]
    descriptor_digest: str
    registered_at: str
    registered_by: str
    authorization_decision_id: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C3ExecutorQualifierRoot:
    key_id: str
    public_key_fingerprint_sha256: str
    accepted_at: str
    accepted_by: str
    authorization_decision_id: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C3ExecutorQualification:
    qualification_id: str
    executor_id: str
    key_id: str
    payload_sha256: str
    signature_sha256: str
    reviewer_identity: str
    qualified_at: str
    admitted_at: str
    admitted_by: str
    authorization_decision_id: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C3ExecutorCurrent:
    executor_id: str
    state: C3ExecutorState
    transition_sequence: int
    transitioned_at: str
    transitioned_by: str
    authorization_decision_id: str


@dataclass(frozen=True)
class C3ExecutorPreparation:
    operation: str
    executor_id: str
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]


@dataclass(frozen=True)
class C3ExecutorRegistryVerification:
    executor_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


@dataclass(frozen=True)
class C3ExecutorAttestation:
    executor_id: str
    state: C3ExecutorState
    implementation_version: str
    implementation_digest: str
    sandbox_profile: str
    network_mode: C3ExecutorNetworkMode
    registry_head_hash: str


class C3ExecutorRegistry:
    """Register, qualify, enable, revoke and attest C3 executors."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        trust: TrustPlane,
        signature_verifier: SignatureVerifier | None = None,
        continuity: ContinuityService | None = None,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self.signature_verifier = signature_verifier or OpenSSLEd25519Verifier()
        self.continuity = continuity or ContinuityService(database, ledger, trust)
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
    def _bounded_bytes(value: object, field: str, maximum: int) -> bytes:
        if not isinstance(value, bytes) or not value or len(value) > maximum:
            raise ValidationError(
                f"{field} must be non-empty bytes within the size limit",
                {"maximum_bytes": maximum},
            )
        return value

    @classmethod
    def _sorted_unique_strings(
        cls, value: object, field: str
    ) -> tuple[str, ...]:
        if not isinstance(value, list) or not value:
            raise ValidationError(f"{field} must be a non-empty list")
        normalized = tuple(cls._required_text(item, field) for item in value)
        if tuple(sorted(normalized)) != normalized or len(set(normalized)) != len(normalized):
            raise ValidationError(f"{field} must be sorted and duplicate-free")
        return normalized

    @classmethod
    def _descriptor_material(
        cls, descriptor: Mapping[str, Any]
    ) -> tuple[dict[str, object], str, str]:
        if not isinstance(descriptor, Mapping):
            raise ValidationError("descriptor must be a JSON object")
        observed = frozenset(descriptor)
        if observed != _DESCRIPTOR_FIELDS:
            raise ValidationError(
                "descriptor fields do not match the required contract",
                {
                    "missing": sorted(_DESCRIPTOR_FIELDS - observed),
                    "unexpected": sorted(observed - _DESCRIPTOR_FIELDS),
                },
            )
        try:
            network_mode = C3ExecutorNetworkMode(str(descriptor["network_mode"]))
        except ValueError as exc:
            raise ValidationError("unknown executor network_mode") from exc
        normalized: dict[str, object] = {
            "executor_id": cls._required_text(descriptor["executor_id"], "executor_id"),
            "implementation_name": cls._required_text(
                descriptor["implementation_name"], "implementation_name"
            ),
            "implementation_version": cls._required_text(
                descriptor["implementation_version"], "implementation_version"
            ),
            "implementation_digest": cls._digest(
                descriptor["implementation_digest"], "implementation_digest"
            ),
            "artifact_digest": cls._digest(
                descriptor["artifact_digest"], "artifact_digest"
            ),
            "entrypoint": cls._required_text(descriptor["entrypoint"], "entrypoint"),
            "supported_sandbox_profiles": list(
                cls._sorted_unique_strings(
                    descriptor["supported_sandbox_profiles"],
                    "supported_sandbox_profiles",
                )
            ),
            "network_mode": network_mode.value,
            "capabilities": list(
                cls._sorted_unique_strings(descriptor["capabilities"], "capabilities")
            ),
        }
        serialized = canonical_json(normalized)
        return normalized, serialized, sha256_digest(normalized)

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c3_executor_descriptors (
                    executor_id TEXT PRIMARY KEY,
                    descriptor_json TEXT NOT NULL,
                    descriptor_digest TEXT NOT NULL CHECK (length(descriptor_digest) = 64),
                    implementation_name TEXT NOT NULL,
                    implementation_version TEXT NOT NULL,
                    implementation_digest TEXT NOT NULL CHECK (length(implementation_digest) = 64),
                    artifact_digest TEXT NOT NULL CHECK (length(artifact_digest) = 64),
                    entrypoint TEXT NOT NULL,
                    supported_sandbox_profiles_json TEXT NOT NULL,
                    network_mode TEXT NOT NULL CHECK (network_mode IN ('DENY','ALLOWLIST_ONLY')),
                    capabilities_json TEXT NOT NULL,
                    registered_at TEXT NOT NULL,
                    registered_by TEXT NOT NULL,
                    authorization_decision_id TEXT NOT NULL UNIQUE,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (authorization_decision_id) REFERENCES trust_decisions(decision_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c3_executor_qualifier_roots (
                    key_id TEXT PRIMARY KEY,
                    public_key BLOB NOT NULL,
                    public_key_fingerprint_sha256 TEXT NOT NULL UNIQUE CHECK (length(public_key_fingerprint_sha256) = 64),
                    accepted_at TEXT NOT NULL,
                    accepted_by TEXT NOT NULL,
                    authorization_decision_id TEXT NOT NULL UNIQUE,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (authorization_decision_id) REFERENCES trust_decisions(decision_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c3_executor_qualifications (
                    qualification_id TEXT PRIMARY KEY,
                    executor_id TEXT NOT NULL UNIQUE,
                    key_id TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
                    signature BLOB NOT NULL,
                    signature_sha256 TEXT NOT NULL CHECK (length(signature_sha256) = 64),
                    reviewer_identity TEXT NOT NULL,
                    qualified_at TEXT NOT NULL,
                    admitted_at TEXT NOT NULL,
                    admitted_by TEXT NOT NULL,
                    authorization_decision_id TEXT NOT NULL UNIQUE,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (executor_id) REFERENCES c3_executor_descriptors(executor_id),
                    FOREIGN KEY (key_id) REFERENCES c3_executor_qualifier_roots(key_id),
                    FOREIGN KEY (authorization_decision_id) REFERENCES trust_decisions(decision_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c3_executor_transitions (
                    executor_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL CHECK (sequence >= 1),
                    state TEXT NOT NULL CHECK (state IN (
                        'C3_EXECUTOR_REGISTERED_DISABLED',
                        'C3_EXECUTOR_QUALIFIED_DISABLED',
                        'C3_EXECUTOR_ENABLED',
                        'C3_EXECUTOR_REVOKED'
                    )),
                    operation TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    transitioned_at TEXT NOT NULL,
                    transitioned_by TEXT NOT NULL,
                    authorization_decision_id TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    PRIMARY KEY (executor_id, sequence),
                    FOREIGN KEY (executor_id) REFERENCES c3_executor_descriptors(executor_id),
                    FOREIGN KEY (authorization_decision_id) REFERENCES trust_decisions(decision_id)
                )
                """
            )
            for table in (
                "c3_executor_descriptors",
                "c3_executor_qualifier_roots",
                "c3_executor_qualifications",
                "c3_executor_transitions",
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

    @staticmethod
    def _stream(executor_id: str) -> str:
        return f"continuity:c3:executor:{executor_id}"

    @staticmethod
    def _mission(executor_id: str) -> str:
        return f"c3-executor:{executor_id}"

    @staticmethod
    def _resource(executor_id: str, operation: str) -> str:
        return f"continuity:c3:executor:{executor_id}:{operation}"

    @staticmethod
    def _fingerprint(public_key: bytes) -> str:
        return hashlib.sha256(public_key).hexdigest()

    @staticmethod
    def _operation_kind(operation: str) -> str:
        return {
            "REGISTER": "C3_EXECUTOR_REGISTERED",
            "QUALIFIER_ROOT": "C3_EXECUTOR_QUALIFIER_ACCEPTED",
            "QUALIFY": "C3_EXECUTOR_QUALIFIED",
            "ENABLE": "C3_EXECUTOR_ENABLED",
            "REVOKE": "C3_EXECUTOR_REVOKED",
        }[operation]

    def _assert_authorization(
        self,
        decision_id: str,
        *,
        preparation: C3ExecutorPreparation,
        actor: str,
    ) -> AuthorizationDecision:
        verification = self.trust.verify_decision(decision_id)
        if not verification.ok:
            raise AuthorizationError(
                "C3 executor authorization decision failed verification",
                {"decision_id": decision_id, "defects": list(verification.defects)},
            )
        try:
            decision = self.trust.get_decision(decision_id)
        except NotFoundError as exc:
            raise AuthorizationError("C3 executor authorization decision does not exist") from exc
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
                "authorization decision does not exactly match C3 executor operation",
                {"decision_id": decision_id, "allowed": decision.allowed},
            )
        return decision

    def _consumption(self, decision_id: str) -> sqlite3.Row | None:
        return self.database.connection.execute(
            "SELECT * FROM continuity_authorization_consumptions WHERE decision_id = ?",
            (decision_id,),
        ).fetchone()

    @staticmethod
    def _descriptor_from_row(row: sqlite3.Row) -> C3ExecutorDescriptor:
        profiles = json.loads(str(row["supported_sandbox_profiles_json"]))
        capabilities = json.loads(str(row["capabilities_json"]))
        return C3ExecutorDescriptor(
            executor_id=str(row["executor_id"]),
            implementation_name=str(row["implementation_name"]),
            implementation_version=str(row["implementation_version"]),
            implementation_digest=str(row["implementation_digest"]),
            artifact_digest=str(row["artifact_digest"]),
            entrypoint=str(row["entrypoint"]),
            supported_sandbox_profiles=tuple(profiles),
            network_mode=C3ExecutorNetworkMode(str(row["network_mode"])),
            capabilities=tuple(capabilities),
            descriptor_digest=str(row["descriptor_digest"]),
            registered_at=str(row["registered_at"]),
            registered_by=str(row["registered_by"]),
            authorization_decision_id=str(row["authorization_decision_id"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def get_descriptor(self, executor_id: str) -> C3ExecutorDescriptor:
        executor_id = self._required_text(executor_id, "executor_id")
        row = self.database.connection.execute(
            "SELECT * FROM c3_executor_descriptors WHERE executor_id = ?",
            (executor_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("C3 executor does not exist", {"executor_id": executor_id})
        try:
            return self._descriptor_from_row(row)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise IntegrityError("stored C3 executor descriptor is invalid") from exc

    def get_current(self, executor_id: str) -> C3ExecutorCurrent:
        executor_id = self._required_text(executor_id, "executor_id")
        row = self.database.connection.execute(
            """
            SELECT * FROM c3_executor_transitions
            WHERE executor_id = ? ORDER BY sequence DESC LIMIT 1
            """,
            (executor_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("C3 executor does not exist", {"executor_id": executor_id})
        return C3ExecutorCurrent(
            executor_id,
            C3ExecutorState(str(row["state"])),
            int(row["sequence"]),
            str(row["transitioned_at"]),
            str(row["transitioned_by"]),
            str(row["authorization_decision_id"]),
        )

    def prepare_registration(
        self, descriptor: Mapping[str, Any]
    ) -> C3ExecutorPreparation:
        normalized, _, digest = self._descriptor_material(descriptor)
        executor_id = str(normalized["executor_id"])
        return C3ExecutorPreparation(
            "REGISTER",
            executor_id,
            "c3.executor.register",
            self._resource(executor_id, "register"),
            self._mission(executor_id),
            {
                "descriptor_digest": digest,
                "implementation_version": normalized["implementation_version"],
                "implementation_digest": normalized["implementation_digest"],
                "artifact_digest": normalized["artifact_digest"],
                "network_mode": normalized["network_mode"],
                "supported_sandbox_profiles": normalized[
                    "supported_sandbox_profiles"
                ],
                "requested_state": C3ExecutorState.REGISTERED_DISABLED.value,
            },
        )

    def register(
        self,
        descriptor: Mapping[str, Any],
        *,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> C3ExecutorDescriptor:
        normalized, descriptor_json, descriptor_digest = self._descriptor_material(
            descriptor
        )
        executor_id = str(normalized["executor_id"])
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now())
        existing = self.database.connection.execute(
            "SELECT * FROM c3_executor_descriptors WHERE executor_id = ?",
            (executor_id,),
        ).fetchone()
        if existing is not None:
            if (
                str(existing["descriptor_json"]) != descriptor_json
                or str(existing["authorization_decision_id"])
                != authorization_decision_id
                or str(existing["registered_by"]) != actor
            ):
                raise ConflictError(
                    "executor_id was reused with different registration material",
                    {"executor_id": executor_id},
                )
            verification = self.verify(executor_id)
            if not verification.ok:
                raise IntegrityError(
                    "existing C3 executor registration failed verification",
                    {"executor_id": executor_id, "defects": list(verification.defects)},
                )
            return self._descriptor_from_row(existing)
        preparation = self.prepare_registration(descriptor)
        decision = self._assert_authorization(
            authorization_decision_id, preparation=preparation, actor=actor
        )
        if self._as_datetime(occurred_at) < self._as_datetime(decision.decided_at):
            raise StateTransitionError("registration predates TrustPlane authorization")
        if self._consumption(authorization_decision_id) is not None:
            raise AuthorizationError("authorization decision was already consumed")
        payload = {
            "executor_id": executor_id,
            "descriptor_digest": descriptor_digest,
            "state": C3ExecutorState.REGISTERED_DISABLED.value,
            "authorization_decision_id": authorization_decision_id,
        }
        try:
            with self.database.transaction() as connection:
                current_decision = self._assert_authorization(
                    authorization_decision_id,
                    preparation=preparation,
                    actor=actor,
                )
                if self._as_datetime(occurred_at) < self._as_datetime(
                    current_decision.decided_at
                ):
                    raise StateTransitionError(
                        "registration predates TrustPlane authorization"
                    )
                self.continuity._consume_authorization(
                    connection,
                    decision_id=authorization_decision_id,
                    operation_kind=self._operation_kind("REGISTER"),
                    operation_id=executor_id,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    self._stream(executor_id),
                    C3ExecutorState.REGISTERED_DISABLED.value,
                    payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO c3_executor_descriptors (
                        executor_id, descriptor_json, descriptor_digest,
                        implementation_name, implementation_version,
                        implementation_digest, artifact_digest, entrypoint,
                        supported_sandbox_profiles_json, network_mode,
                        capabilities_json, registered_at, registered_by,
                        authorization_decision_id, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        executor_id,
                        descriptor_json,
                        descriptor_digest,
                        normalized["implementation_name"],
                        normalized["implementation_version"],
                        normalized["implementation_digest"],
                        normalized["artifact_digest"],
                        normalized["entrypoint"],
                        canonical_json(normalized["supported_sandbox_profiles"]),
                        normalized["network_mode"],
                        canonical_json(normalized["capabilities"]),
                        occurred_at,
                        actor,
                        authorization_decision_id,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO c3_executor_transitions (
                        executor_id, sequence, state, operation, metadata_json,
                        transitioned_at, transitioned_by,
                        authorization_decision_id, ledger_event_id, ledger_hash
                    ) VALUES (?, 1, ?, 'REGISTER', ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        executor_id,
                        C3ExecutorState.REGISTERED_DISABLED.value,
                        canonical_json(payload),
                        occurred_at,
                        actor,
                        authorization_decision_id,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("C3 executor registration conflicts with immutable state") from exc
        return self.get_descriptor(executor_id)

    def prepare_qualifier_root(
        self, key_id: str, public_key: bytes
    ) -> C3ExecutorPreparation:
        key_id = self._required_text(key_id, "key_id")
        public_key = self._bounded_bytes(
            public_key, "public_key", _MAX_PUBLIC_KEY_BYTES
        )
        if not self.signature_verifier.validate_public_key(public_key):
            raise ValidationError("public_key must be a valid Ed25519 public key")
        fingerprint = self._fingerprint(public_key)
        return C3ExecutorPreparation(
            "QUALIFIER_ROOT",
            key_id,
            "c3.executor.qualifier.accept",
            f"continuity:c3:executor-qualifier:{key_id}",
            f"c3-executor-qualifier:{key_id}",
            {
                "key_id": key_id,
                "public_key_fingerprint_sha256": fingerprint,
                "algorithm": "Ed25519",
                "purpose": "C3_EXECUTOR_QUALIFICATION",
            },
        )

    def accept_qualifier_root(
        self,
        key_id: str,
        public_key: bytes,
        *,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> C3ExecutorQualifierRoot:
        preparation = self.prepare_qualifier_root(key_id, public_key)
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now())
        existing = self.database.connection.execute(
            "SELECT * FROM c3_executor_qualifier_roots WHERE key_id = ?",
            (key_id,),
        ).fetchone()
        if existing is not None:
            if (
                bytes(existing["public_key"]) != public_key
                or str(existing["authorization_decision_id"])
                != authorization_decision_id
                or str(existing["accepted_by"]) != actor
            ):
                raise ConflictError("qualifier key_id was reused with different material")
            return C3ExecutorQualifierRoot(
                key_id,
                str(existing["public_key_fingerprint_sha256"]),
                str(existing["accepted_at"]),
                str(existing["accepted_by"]),
                str(existing["authorization_decision_id"]),
                str(existing["ledger_event_id"]),
                str(existing["ledger_hash"]),
            )
        decision = self._assert_authorization(
            authorization_decision_id, preparation=preparation, actor=actor
        )
        if self._as_datetime(occurred_at) < self._as_datetime(decision.decided_at):
            raise StateTransitionError("qualifier-root acceptance predates authorization")
        fingerprint = self._fingerprint(public_key)
        payload = {
            "key_id": key_id,
            "public_key_fingerprint_sha256": fingerprint,
            "algorithm": "Ed25519",
            "purpose": "C3_EXECUTOR_QUALIFICATION",
            "authorization_decision_id": authorization_decision_id,
        }
        try:
            with self.database.transaction() as connection:
                self._assert_authorization(
                    authorization_decision_id, preparation=preparation, actor=actor
                )
                self.continuity._consume_authorization(
                    connection,
                    decision_id=authorization_decision_id,
                    operation_kind=self._operation_kind("QUALIFIER_ROOT"),
                    operation_id=key_id,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"continuity:c3:executor-qualifier:{key_id}",
                    "C3_EXECUTOR_QUALIFIER_ACCEPTED",
                    payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO c3_executor_qualifier_roots (
                        key_id, public_key, public_key_fingerprint_sha256,
                        accepted_at, accepted_by, authorization_decision_id,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        key_id,
                        public_key,
                        fingerprint,
                        occurred_at,
                        actor,
                        authorization_decision_id,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("qualifier root conflicts with immutable state") from exc
        return self.accept_qualifier_root(
            key_id,
            public_key,
            authorization_decision_id=authorization_decision_id,
            actor=actor,
            occurred_at=occurred_at,
        )

    def _qualification_material(
        self,
        executor_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        *,
        require_registered_state: bool,
    ) -> tuple[dict[str, Any], str, str, C3ExecutorDescriptor, sqlite3.Row]:
        executor_id = self._required_text(executor_id, "executor_id")
        key_id = self._required_text(key_id, "key_id")
        payload = self._bounded_bytes(payload, "payload", _MAX_PAYLOAD_BYTES)
        signature = self._bounded_bytes(
            signature, "signature", _MAX_SIGNATURE_BYTES
        )
        descriptor = self.get_descriptor(executor_id)
        if require_registered_state and self.get_current(executor_id).state is not (
            C3ExecutorState.REGISTERED_DISABLED
        ):
            raise StateTransitionError(
                "executor qualification requires REGISTERED_DISABLED"
            )
        root = self.database.connection.execute(
            "SELECT * FROM c3_executor_qualifier_roots WHERE key_id = ?",
            (key_id,),
        ).fetchone()
        if root is None:
            raise StateTransitionError("qualifier root is not accepted")
        public_key = bytes(root["public_key"])
        if not self.signature_verifier.verify(public_key, payload, signature):
            raise IntegrityError("executor qualification signature is invalid")
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("qualification payload must be UTF-8 JSON") from exc
        if not isinstance(value, dict) or frozenset(value) != _QUALIFICATION_FIELDS:
            raise ValidationError("qualification payload fields do not match schema")
        qualification_id = self._required_text(
            value["qualification_id"], "qualification_id"
        )
        if self._required_text(value["executor_id"], "executor_id") != executor_id:
            raise StateTransitionError("qualification executor_id mismatch")
        if self._digest(value["descriptor_digest"], "descriptor_digest") != (
            descriptor.descriptor_digest
        ):
            raise StateTransitionError("qualification descriptor digest mismatch")
        self._digest(value["report_digest"], "report_digest")
        self._digest(value["test_suite_digest"], "test_suite_digest")
        reviewer = self._required_text(value["reviewer_identity"], "reviewer_identity")
        if reviewer == descriptor.registered_by:
            raise StateTransitionError("qualifier must be independent from registrant")
        self._required_text(value["reviewer_environment"], "reviewer_environment")
        self._required_text(value["independence_basis"], "independence_basis")
        tested_profiles = self._sorted_unique_strings(
            value["sandbox_profiles_tested"], "sandbox_profiles_tested"
        )
        if tested_profiles != descriptor.supported_sandbox_profiles:
            raise StateTransitionError("qualification sandbox profile mismatch")
        if str(value["network_mode_tested"]) != descriptor.network_mode.value:
            raise StateTransitionError("qualification network mode mismatch")
        if value["verdict"] != "QUALIFIED":
            raise StateTransitionError("qualification verdict must be QUALIFIED")
        if value["gate_effect"] != "QUALIFIED_DISABLED_NO_ENABLEMENT":
            raise StateTransitionError("qualification gate effect is invalid")
        qualified_at = self._timestamp(value["qualified_at"], "qualified_at")
        if self._as_datetime(qualified_at) < self._as_datetime(
            descriptor.registered_at
        ) or self._as_datetime(qualified_at) < self._as_datetime(
            str(root["accepted_at"])
        ):
            raise StateTransitionError("qualification predates its authorities")
        value["qualification_id"] = qualification_id
        value["reviewer_identity"] = reviewer
        value["qualified_at"] = qualified_at
        return (
            value,
            hashlib.sha256(payload).hexdigest(),
            hashlib.sha256(signature).hexdigest(),
            descriptor,
            root,
        )

    def prepare_qualification(
        self,
        executor_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
    ) -> C3ExecutorPreparation:
        value, payload_sha, signature_sha, descriptor, _ = (
            self._qualification_material(
                executor_id,
                key_id,
                payload,
                signature,
                require_registered_state=True,
            )
        )
        return C3ExecutorPreparation(
            "QUALIFY",
            executor_id,
            "c3.executor.qualify",
            self._resource(executor_id, "qualify"),
            self._mission(executor_id),
            {
                "qualification_id": value["qualification_id"],
                "key_id": key_id,
                "descriptor_digest": descriptor.descriptor_digest,
                "payload_sha256": payload_sha,
                "signature_sha256": signature_sha,
                "report_digest": value["report_digest"],
                "test_suite_digest": value["test_suite_digest"],
                "reviewer_identity": value["reviewer_identity"],
                "gate_effect": value["gate_effect"],
                "prior_state": C3ExecutorState.REGISTERED_DISABLED.value,
                "requested_state": C3ExecutorState.QUALIFIED_DISABLED.value,
            },
        )

    def qualify(
        self,
        executor_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        *,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> C3ExecutorQualification:
        value, payload_sha, signature_sha, descriptor, _ = (
            self._qualification_material(
                executor_id,
                key_id,
                payload,
                signature,
                require_registered_state=True,
            )
        )
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now())
        qualification_id = str(value["qualification_id"])
        existing = self.database.connection.execute(
            "SELECT * FROM c3_executor_qualifications WHERE executor_id = ?",
            (executor_id,),
        ).fetchone()
        if existing is not None:
            if (
                bytes(existing["payload"]) != payload
                or bytes(existing["signature"]) != signature
                or str(existing["authorization_decision_id"])
                != authorization_decision_id
                or str(existing["admitted_by"]) != actor
            ):
                raise ConflictError("executor qualification material conflicts")
            return self._qualification_from_row(existing)
        preparation = self.prepare_qualification(
            executor_id, key_id, payload, signature
        )
        decision = self._assert_authorization(
            authorization_decision_id, preparation=preparation, actor=actor
        )
        if self._as_datetime(occurred_at) < self._as_datetime(decision.decided_at):
            raise StateTransitionError("qualification admission predates authorization")
        if self._as_datetime(occurred_at) < self._as_datetime(
            str(value["qualified_at"])
        ):
            raise StateTransitionError("qualification admission predates review")
        metadata = {
            "qualification_id": qualification_id,
            "key_id": key_id,
            "payload_sha256": payload_sha,
            "signature_sha256": signature_sha,
            "reviewer_identity": value["reviewer_identity"],
            "descriptor_digest": descriptor.descriptor_digest,
        }
        event_payload = {
            "executor_id": executor_id,
            "state": C3ExecutorState.QUALIFIED_DISABLED.value,
            "authorization_decision_id": authorization_decision_id,
            **metadata,
        }
        try:
            with self.database.transaction() as connection:
                if self.get_current(executor_id).state is not (
                    C3ExecutorState.REGISTERED_DISABLED
                ):
                    raise StateTransitionError(
                        "executor qualification requires REGISTERED_DISABLED"
                    )
                self._assert_authorization(
                    authorization_decision_id,
                    preparation=preparation,
                    actor=actor,
                )
                self.continuity._consume_authorization(
                    connection,
                    decision_id=authorization_decision_id,
                    operation_kind=self._operation_kind("QUALIFY"),
                    operation_id=qualification_id,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    self._stream(executor_id),
                    C3ExecutorState.QUALIFIED_DISABLED.value,
                    event_payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO c3_executor_qualifications (
                        qualification_id, executor_id, key_id, payload,
                        payload_sha256, signature, signature_sha256,
                        reviewer_identity, qualified_at, admitted_at,
                        admitted_by, authorization_decision_id,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        qualification_id,
                        executor_id,
                        key_id,
                        payload,
                        payload_sha,
                        signature,
                        signature_sha,
                        value["reviewer_identity"],
                        value["qualified_at"],
                        occurred_at,
                        actor,
                        authorization_decision_id,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO c3_executor_transitions (
                        executor_id, sequence, state, operation, metadata_json,
                        transitioned_at, transitioned_by,
                        authorization_decision_id, ledger_event_id, ledger_hash
                    ) VALUES (?, 2, ?, 'QUALIFY', ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        executor_id,
                        C3ExecutorState.QUALIFIED_DISABLED.value,
                        canonical_json(metadata),
                        occurred_at,
                        actor,
                        authorization_decision_id,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("executor qualification conflicts with immutable state") from exc
        return self._qualification_from_row(
            self.database.connection.execute(
                "SELECT * FROM c3_executor_qualifications WHERE executor_id = ?",
                (executor_id,),
            ).fetchone()
        )

    @staticmethod
    def _qualification_from_row(row: sqlite3.Row) -> C3ExecutorQualification:
        return C3ExecutorQualification(
            str(row["qualification_id"]),
            str(row["executor_id"]),
            str(row["key_id"]),
            str(row["payload_sha256"]),
            str(row["signature_sha256"]),
            str(row["reviewer_identity"]),
            str(row["qualified_at"]),
            str(row["admitted_at"]),
            str(row["admitted_by"]),
            str(row["authorization_decision_id"]),
            str(row["ledger_event_id"]),
            str(row["ledger_hash"]),
        )

    def _qualification_for_executor(self, executor_id: str) -> sqlite3.Row:
        row = self.database.connection.execute(
            "SELECT * FROM c3_executor_qualifications WHERE executor_id = ?",
            (executor_id,),
        ).fetchone()
        if row is None:
            raise StateTransitionError("executor has no accepted qualification")
        return row

    def prepare_enable(self, executor_id: str) -> C3ExecutorPreparation:
        descriptor = self.get_descriptor(executor_id)
        current = self.get_current(executor_id)
        if current.state is C3ExecutorState.REVOKED:
            raise StateTransitionError("revoked executor cannot be enabled")
        if current.state is not C3ExecutorState.QUALIFIED_DISABLED:
            raise StateTransitionError("enable requires QUALIFIED_DISABLED")
        qualification = self._qualification_for_executor(executor_id)
        return C3ExecutorPreparation(
            "ENABLE",
            executor_id,
            "c3.executor.enable",
            self._resource(executor_id, "enable"),
            self._mission(executor_id),
            {
                "descriptor_digest": descriptor.descriptor_digest,
                "qualification_id": str(qualification["qualification_id"]),
                "qualification_payload_sha256": str(
                    qualification["payload_sha256"]
                ),
                "prior_state": current.state.value,
                "requested_state": C3ExecutorState.ENABLED.value,
            },
        )

    def enable(
        self,
        executor_id: str,
        *,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> C3ExecutorCurrent:
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now())
        current = self.get_current(executor_id)
        if current.state is C3ExecutorState.ENABLED:
            if (
                current.authorization_decision_id == authorization_decision_id
                and current.transitioned_by == actor
            ):
                return current
            raise ConflictError("executor already enabled by different material")
        preparation = self.prepare_enable(executor_id)
        decision = self._assert_authorization(
            authorization_decision_id, preparation=preparation, actor=actor
        )
        if self._as_datetime(occurred_at) < self._as_datetime(decision.decided_at):
            raise StateTransitionError("enablement predates authorization")
        metadata = dict(preparation.context)
        payload = {
            "executor_id": executor_id,
            "state": C3ExecutorState.ENABLED.value,
            "authorization_decision_id": authorization_decision_id,
            **metadata,
        }
        try:
            with self.database.transaction() as connection:
                if self.get_current(executor_id).state is not (
                    C3ExecutorState.QUALIFIED_DISABLED
                ):
                    raise StateTransitionError("enable requires QUALIFIED_DISABLED")
                self._assert_authorization(
                    authorization_decision_id,
                    preparation=preparation,
                    actor=actor,
                )
                self.continuity._consume_authorization(
                    connection,
                    decision_id=authorization_decision_id,
                    operation_kind=self._operation_kind("ENABLE"),
                    operation_id=executor_id,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    self._stream(executor_id),
                    C3ExecutorState.ENABLED.value,
                    payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO c3_executor_transitions (
                        executor_id, sequence, state, operation, metadata_json,
                        transitioned_at, transitioned_by,
                        authorization_decision_id, ledger_event_id, ledger_hash
                    ) VALUES (?, 3, ?, 'ENABLE', ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        executor_id,
                        C3ExecutorState.ENABLED.value,
                        canonical_json(metadata),
                        occurred_at,
                        actor,
                        authorization_decision_id,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("executor enablement conflicts with immutable state") from exc
        return self.get_current(executor_id)

    def prepare_revoke(
        self, executor_id: str, *, reason: str
    ) -> C3ExecutorPreparation:
        descriptor = self.get_descriptor(executor_id)
        current = self.get_current(executor_id)
        if current.state is C3ExecutorState.REVOKED:
            raise StateTransitionError("executor is already revoked")
        reason = self._required_text(reason, "reason")
        return C3ExecutorPreparation(
            "REVOKE",
            executor_id,
            "c3.executor.revoke",
            self._resource(executor_id, "revoke"),
            self._mission(executor_id),
            {
                "descriptor_digest": descriptor.descriptor_digest,
                "reason": reason,
                "reason_sha256": sha256_digest(reason),
                "prior_state": current.state.value,
                "requested_state": C3ExecutorState.REVOKED.value,
            },
        )

    def revoke(
        self,
        executor_id: str,
        *,
        reason: str,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> C3ExecutorCurrent:
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now())
        preparation = self.prepare_revoke(executor_id, reason=reason)
        decision = self._assert_authorization(
            authorization_decision_id, preparation=preparation, actor=actor
        )
        if self._as_datetime(occurred_at) < self._as_datetime(decision.decided_at):
            raise StateTransitionError("revocation predates authorization")
        current = self.get_current(executor_id)
        sequence = current.transition_sequence + 1
        metadata = dict(preparation.context)
        payload = {
            "executor_id": executor_id,
            "state": C3ExecutorState.REVOKED.value,
            "authorization_decision_id": authorization_decision_id,
            **metadata,
        }
        try:
            with self.database.transaction() as connection:
                latest = self.get_current(executor_id)
                if latest != current:
                    raise ConflictError("executor state changed during revocation")
                self._assert_authorization(
                    authorization_decision_id,
                    preparation=preparation,
                    actor=actor,
                )
                self.continuity._consume_authorization(
                    connection,
                    decision_id=authorization_decision_id,
                    operation_kind=self._operation_kind("REVOKE"),
                    operation_id=executor_id,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    self._stream(executor_id),
                    C3ExecutorState.REVOKED.value,
                    payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO c3_executor_transitions (
                        executor_id, sequence, state, operation, metadata_json,
                        transitioned_at, transitioned_by,
                        authorization_decision_id, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, 'REVOKE', ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        executor_id,
                        sequence,
                        C3ExecutorState.REVOKED.value,
                        canonical_json(metadata),
                        occurred_at,
                        actor,
                        authorization_decision_id,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("executor revocation conflicts with immutable state") from exc
        return self.get_current(executor_id)

    def verify(self, executor_id: str) -> C3ExecutorRegistryVerification:
        executor_id = self._required_text(executor_id, "executor_id")
        row = self.database.connection.execute(
            "SELECT * FROM c3_executor_descriptors WHERE executor_id = ?",
            (executor_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("C3 executor does not exist", {"executor_id": executor_id})
        defects: list[str] = []
        try:
            descriptor_value = json.loads(str(row["descriptor_json"]))
            normalized, serialized, digest = self._descriptor_material(descriptor_value)
        except (json.JSONDecodeError, TypeError, ValidationError):
            defects.append("C3_EXECUTOR_DESCRIPTOR_INVALID")
            normalized = {}
            serialized = ""
            digest = ""
        columns_match = bool(normalized) and (
            str(row["implementation_name"]) == normalized["implementation_name"]
            and str(row["implementation_version"])
            == normalized["implementation_version"]
            and str(row["implementation_digest"])
            == normalized["implementation_digest"]
            and str(row["artifact_digest"]) == normalized["artifact_digest"]
            and str(row["entrypoint"]) == normalized["entrypoint"]
            and str(row["network_mode"]) == normalized["network_mode"]
            and str(row["supported_sandbox_profiles_json"])
            == canonical_json(normalized["supported_sandbox_profiles"])
            and str(row["capabilities_json"])
            == canonical_json(normalized["capabilities"])
        )
        if (
            serialized != str(row["descriptor_json"])
            or digest != str(row["descriptor_digest"])
            or not columns_match
        ):
            defects.append("C3_EXECUTOR_DESCRIPTOR_DIGEST_MISMATCH")
        transitions = self.database.connection.execute(
            "SELECT * FROM c3_executor_transitions WHERE executor_id = ? ORDER BY sequence",
            (executor_id,),
        ).fetchall()
        expected_prior: C3ExecutorState | None = None
        for index, transition in enumerate(transitions, start=1):
            sequence = int(transition["sequence"])
            if sequence != index:
                defects.append(f"C3_EXECUTOR_TRANSITION_SEQUENCE_MISMATCH:{sequence}")
            try:
                state = C3ExecutorState(str(transition["state"]))
            except ValueError:
                defects.append(f"C3_EXECUTOR_STATE_INVALID:{sequence}")
                continue
            if index == 1 and state is not C3ExecutorState.REGISTERED_DISABLED:
                defects.append("C3_EXECUTOR_INITIAL_STATE_INVALID")
            if index > 1:
                legal = (
                    expected_prior is C3ExecutorState.REGISTERED_DISABLED
                    and state
                    in {
                        C3ExecutorState.QUALIFIED_DISABLED,
                        C3ExecutorState.REVOKED,
                    }
                ) or (
                    expected_prior is C3ExecutorState.QUALIFIED_DISABLED
                    and state in {C3ExecutorState.ENABLED, C3ExecutorState.REVOKED}
                ) or (
                    expected_prior is C3ExecutorState.ENABLED
                    and state is C3ExecutorState.REVOKED
                )
                if not legal:
                    defects.append(f"C3_EXECUTOR_TRANSITION_ILLEGAL:{sequence}")
            expected_prior = state
            decision_id = str(transition["authorization_decision_id"])
            decision_verification = self.trust.verify_decision(decision_id)
            defects.extend(
                f"C3_EXECUTOR_DECISION:{sequence}:{item}"
                for item in decision_verification.defects
            )
            consumption = self._consumption(decision_id)
            if consumption is None:
                defects.append(f"C3_EXECUTOR_CONSUMPTION_MISSING:{sequence}")
            event = self.database.connection.execute(
                "SELECT * FROM ledger_events WHERE event_id = ?",
                (str(transition["ledger_event_id"]),),
            ).fetchone()
            if event is None:
                defects.append(f"C3_EXECUTOR_LEDGER_EVENT_MISSING:{sequence}")
            else:
                if str(event["stream_id"]) != self._stream(executor_id):
                    defects.append(f"C3_EXECUTOR_LEDGER_STREAM_MISMATCH:{sequence}")
                if str(event["kind"]) != state.value:
                    defects.append(f"C3_EXECUTOR_LEDGER_KIND_MISMATCH:{sequence}")
                if str(event["actor"]) != str(transition["transitioned_by"]):
                    defects.append(f"C3_EXECUTOR_LEDGER_ACTOR_MISMATCH:{sequence}")
                if str(event["occurred_at"]) != str(transition["transitioned_at"]):
                    defects.append(f"C3_EXECUTOR_LEDGER_TIME_MISMATCH:{sequence}")
                if str(event["record_hash"]) != str(transition["ledger_hash"]):
                    defects.append(f"C3_EXECUTOR_LEDGER_HASH_MISMATCH:{sequence}")
        defects.extend(
            f"C3_EXECUTOR_LEDGER_CHAIN:{item.code}"
            for item in self.ledger.verify(self._stream(executor_id)).defects
        )
        qualification = self.database.connection.execute(
            "SELECT * FROM c3_executor_qualifications WHERE executor_id = ?",
            (executor_id,),
        ).fetchone()
        if qualification is not None:
            root = self.database.connection.execute(
                "SELECT * FROM c3_executor_qualifier_roots WHERE key_id = ?",
                (str(qualification["key_id"]),),
            ).fetchone()
            if root is None:
                defects.append("C3_EXECUTOR_QUALIFIER_ROOT_MISSING")
            else:
                public_key = bytes(root["public_key"])
                if (
                    self._fingerprint(public_key)
                    != str(root["public_key_fingerprint_sha256"])
                    or not self.signature_verifier.validate_public_key(public_key)
                ):
                    defects.append("C3_EXECUTOR_QUALIFIER_ROOT_INVALID")
                if not self.signature_verifier.verify(
                    public_key,
                    bytes(qualification["payload"]),
                    bytes(qualification["signature"]),
                ):
                    defects.append("C3_EXECUTOR_QUALIFICATION_SIGNATURE_INVALID")
            if hashlib.sha256(bytes(qualification["payload"])).hexdigest() != str(
                qualification["payload_sha256"]
            ):
                defects.append("C3_EXECUTOR_QUALIFICATION_PAYLOAD_SHA256_MISMATCH")
            if hashlib.sha256(bytes(qualification["signature"])).hexdigest() != str(
                qualification["signature_sha256"]
            ):
                defects.append("C3_EXECUTOR_QUALIFICATION_SIGNATURE_SHA256_MISMATCH")
        return C3ExecutorRegistryVerification(
            executor_id, tuple(dict.fromkeys(defects))
        )

    def attest(
        self,
        executor_id: str,
        *,
        implementation_version: str,
        implementation_digest: str,
        sandbox_profile: str,
        requires_network: bool,
    ) -> C3ExecutorAttestation:
        verification = self.verify(executor_id)
        if not verification.ok:
            raise IntegrityError(
                "C3 executor registry verification failed",
                {"executor_id": executor_id, "defects": list(verification.defects)},
            )
        descriptor = self.get_descriptor(executor_id)
        current = self.get_current(executor_id)
        if current.state is not C3ExecutorState.ENABLED:
            raise StateTransitionError("C3 executor is not enabled")
        if implementation_version != descriptor.implementation_version:
            raise StateTransitionError("executor implementation version mismatch")
        if implementation_digest != descriptor.implementation_digest:
            raise StateTransitionError("executor implementation digest mismatch")
        if sandbox_profile not in descriptor.supported_sandbox_profiles:
            raise StateTransitionError("executor sandbox profile is not qualified")
        if requires_network and descriptor.network_mode is not (
            C3ExecutorNetworkMode.ALLOWLIST_ONLY
        ):
            raise StateTransitionError("executor network mode forbids requested network")
        head = self.database.connection.execute(
            """
            SELECT record_hash FROM ledger_events WHERE stream_id = ?
            ORDER BY sequence DESC LIMIT 1
            """,
            (self._stream(executor_id),),
        ).fetchone()
        if head is None:
            raise IntegrityError("executor registry ledger head is missing")
        return C3ExecutorAttestation(
            executor_id,
            current.state,
            descriptor.implementation_version,
            descriptor.implementation_digest,
            sandbox_profile,
            descriptor.network_mode,
            str(head["record_hash"]),
        )
