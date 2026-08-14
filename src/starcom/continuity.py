from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
from typing import Protocol

from .canonical import canonical_json, sha256_digest, utc_now
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
from .trust import TrustPlane


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_PUBLIC_KEY_BYTES = 8 * 1024
_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
_MAX_SIGNATURE_BYTES = 1024


class IncidentStatus(str, Enum):
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    RECOVERY_PUBLISHED_RECOLLECT_REQUIRED = "RECOVERY_PUBLISHED_RECOLLECT_REQUIRED"


class SignatureVerifier(Protocol):
    def validate_public_key(self, public_key_pem: bytes) -> bool: ...

    def verify(self, public_key_pem: bytes, payload: bytes, signature: bytes) -> bool: ...


class OpenSSLEd25519Verifier:
    """Exact-byte Ed25519 verification through a bounded OpenSSL process."""

    def __init__(self, executable: str = "openssl", timeout_seconds: float = 5.0) -> None:
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def _run(self, arguments: list[str]) -> subprocess.CompletedProcess[bytes] | None:
        try:
            return subprocess.run(
                [self.executable, *arguments],
                check=False,
                capture_output=True,
                timeout=self.timeout_seconds,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return None

    @staticmethod
    def _bounded(value: bytes, *, maximum: int) -> bool:
        return isinstance(value, bytes) and 0 < len(value) <= maximum

    def validate_public_key(self, public_key_pem: bytes) -> bool:
        if not self._bounded(public_key_pem, maximum=_MAX_PUBLIC_KEY_BYTES):
            return False
        with tempfile.TemporaryDirectory(prefix="starcom-ed25519-") as directory:
            key_path = Path(directory) / "reviewer-public.pem"
            key_path.write_bytes(public_key_pem)
            result = self._run(
                ["pkey", "-pubin", "-in", str(key_path), "-text_pub", "-noout"]
            )
            return bool(
                result is not None
                and result.returncode == 0
                and b"ED25519" in result.stdout.upper()
            )

    def verify(self, public_key_pem: bytes, payload: bytes, signature: bytes) -> bool:
        if not self.validate_public_key(public_key_pem):
            return False
        if not self._bounded(payload, maximum=_MAX_PAYLOAD_BYTES):
            return False
        if not self._bounded(signature, maximum=_MAX_SIGNATURE_BYTES):
            return False
        with tempfile.TemporaryDirectory(prefix="starcom-ed25519-") as directory:
            root = Path(directory)
            key_path = root / "reviewer-public.pem"
            payload_path = root / "disposition.json"
            signature_path = root / "disposition.sig"
            key_path.write_bytes(public_key_pem)
            payload_path.write_bytes(payload)
            signature_path.write_bytes(signature)
            result = self._run(
                [
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(key_path),
                    "-rawin",
                    "-in",
                    str(payload_path),
                    "-sigfile",
                    str(signature_path),
                ]
            )
            return bool(result is not None and result.returncode == 0)


@dataclass(frozen=True)
class IncidentRecord:
    incident_id: str
    reviewed_archive_sha256: str
    status: IncidentStatus
    disposition: str
    created_at: str
    created_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class TrustRootReceipt:
    key_id: str
    fingerprint_sha256: str
    accepted_at: str
    accepted_by: str
    decision_id: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class ReviewAdmission:
    review_id: str
    incident_id: str
    key_id: str
    payload_sha256: str
    signature_sha256: str
    disposition: str
    reviewer_identity: str
    admitted_at: str
    admitted_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class RecoveryPublication:
    publication_id: str
    incident_id: str
    review_id: str
    idempotency_key: str
    decision_id: str
    status: IncidentStatus
    published_at: str
    published_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class ContinuityVerification:
    incident_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class ContinuityService:
    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        trust: TrustPlane,
        signature_verifier: SignatureVerifier | None = None,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self.signature_verifier = signature_verifier or OpenSSLEd25519Verifier()
        self._initialize_schema()

    @staticmethod
    def _required_text(value: str, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{field} must be a non-empty string")
        return value

    @staticmethod
    def _timestamp(value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise ValidationError("timestamp must be RFC 3339") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValidationError("timestamp must be timezone-aware")
        return value

    @staticmethod
    def _digest(value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    @staticmethod
    def _validate_sha256(value: str, field: str) -> str:
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
        return value

    @staticmethod
    def _bounded_bytes(value: bytes, field: str, maximum: int) -> bytes:
        if not isinstance(value, bytes) or not value or len(value) > maximum:
            raise ValidationError(
                f"{field} must be non-empty bytes within the size limit",
                {"maximum_bytes": maximum},
            )
        return value

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS continuity_incidents (
                    incident_id TEXT PRIMARY KEY,
                    reviewed_archive_sha256 TEXT NOT NULL CHECK (length(reviewed_archive_sha256) = 64),
                    status TEXT NOT NULL CHECK (status IN (
                        'RECOVERY_REQUIRED',
                        'RECOVERY_PUBLISHED_RECOLLECT_REQUIRED'
                    )),
                    disposition TEXT NOT NULL CHECK (disposition = 'RECOLLECT_REQUIRED'),
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS continuity_authorization_consumptions (
                    decision_id TEXT PRIMARY KEY,
                    operation_kind TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    consumed_at TEXT NOT NULL,
                    consumed_by TEXT NOT NULL,
                    UNIQUE (operation_kind, operation_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS continuity_trust_roots (
                    key_id TEXT PRIMARY KEY,
                    public_key_pem BLOB NOT NULL,
                    fingerprint_sha256 TEXT NOT NULL UNIQUE CHECK (length(fingerprint_sha256) = 64),
                    decision_id TEXT NOT NULL UNIQUE,
                    accepted_at TEXT NOT NULL,
                    accepted_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (decision_id) REFERENCES continuity_authorization_consumptions(decision_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS continuity_reviews (
                    review_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    payload_sha256 TEXT NOT NULL UNIQUE CHECK (length(payload_sha256) = 64),
                    signature BLOB NOT NULL,
                    signature_sha256 TEXT NOT NULL CHECK (length(signature_sha256) = 64),
                    reviewer_identity TEXT NOT NULL,
                    review_environment TEXT NOT NULL,
                    reviewed_archive_sha256 TEXT NOT NULL CHECK (length(reviewed_archive_sha256) = 64),
                    reviewed_at_utc TEXT NOT NULL,
                    independence_basis TEXT NOT NULL,
                    independent_identity_status TEXT NOT NULL CHECK (independent_identity_status = 'SATISFIED'),
                    receipt_result TEXT NOT NULL CHECK (receipt_result IN ('PASS', 'FAIL', 'INCONCLUSIVE')),
                    wave_order_result TEXT NOT NULL CHECK (wave_order_result IN (
                        'CONFIRMS_W3_TO_W2', 'DOES_NOT_CONFIRM', 'INCONCLUSIVE'
                    )),
                    attempt_boundary_result TEXT NOT NULL CHECK (attempt_boundary_result IN (
                        'POSSIBLE_UNQUANTIFIED_CONFIRMED', 'BOUNDED', 'INCONCLUSIVE'
                    )),
                    disposition TEXT NOT NULL CHECK (disposition IN (
                        'CONFIRM_NONCONFORMING', 'RECOLLECT_REQUIRED', 'EVIDENCE_INVALID', 'INCONCLUSIVE'
                    )),
                    gate_effect TEXT NOT NULL CHECK (gate_effect = 'NO_GATE_CHANGE'),
                    admitted_at TEXT NOT NULL,
                    admitted_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (incident_id) REFERENCES continuity_incidents(incident_id),
                    FOREIGN KEY (key_id) REFERENCES continuity_trust_roots(key_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS continuity_recovery_publications (
                    publication_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL UNIQUE,
                    review_id TEXT NOT NULL UNIQUE,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    decision_id TEXT NOT NULL UNIQUE,
                    status_before TEXT NOT NULL CHECK (status_before = 'RECOVERY_REQUIRED'),
                    status_after TEXT NOT NULL CHECK (
                        status_after = 'RECOVERY_PUBLISHED_RECOLLECT_REQUIRED'
                    ),
                    published_at TEXT NOT NULL,
                    published_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (incident_id) REFERENCES continuity_incidents(incident_id),
                    FOREIGN KEY (review_id) REFERENCES continuity_reviews(review_id),
                    FOREIGN KEY (decision_id) REFERENCES continuity_authorization_consumptions(decision_id)
                )
                """
            )
            for table in (
                "continuity_authorization_consumptions",
                "continuity_trust_roots",
                "continuity_reviews",
                "continuity_recovery_publications",
            ):
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {table}_no_update
                    BEFORE UPDATE ON {table}
                    BEGIN SELECT RAISE(ABORT, '{table} records are immutable'); END
                    """
                )
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {table}_no_delete
                    BEFORE DELETE ON {table}
                    BEGIN SELECT RAISE(ABORT, '{table} records are immutable'); END
                    """
                )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS continuity_incidents_no_delete
                BEFORE DELETE ON continuity_incidents
                BEGIN SELECT RAISE(ABORT, 'continuity incidents are immutable'); END
                """
            )

    def _incident_from_row(self, row: sqlite3.Row) -> IncidentRecord:
        return IncidentRecord(
            incident_id=str(row["incident_id"]),
            reviewed_archive_sha256=str(row["reviewed_archive_sha256"]),
            status=IncidentStatus(str(row["status"])),
            disposition=str(row["disposition"]),
            created_at=str(row["created_at"]),
            created_by=str(row["created_by"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    @staticmethod
    def _trust_root_from_row(row: sqlite3.Row) -> TrustRootReceipt:
        return TrustRootReceipt(
            key_id=str(row["key_id"]),
            fingerprint_sha256=str(row["fingerprint_sha256"]),
            accepted_at=str(row["accepted_at"]),
            accepted_by=str(row["accepted_by"]),
            decision_id=str(row["decision_id"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    @staticmethod
    def _review_from_row(row: sqlite3.Row) -> ReviewAdmission:
        return ReviewAdmission(
            review_id=str(row["review_id"]),
            incident_id=str(row["incident_id"]),
            key_id=str(row["key_id"]),
            payload_sha256=str(row["payload_sha256"]),
            signature_sha256=str(row["signature_sha256"]),
            disposition=str(row["disposition"]),
            reviewer_identity=str(row["reviewer_identity"]),
            admitted_at=str(row["admitted_at"]),
            admitted_by=str(row["admitted_by"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    @staticmethod
    def _publication_from_row(row: sqlite3.Row) -> RecoveryPublication:
        return RecoveryPublication(
            publication_id=str(row["publication_id"]),
            incident_id=str(row["incident_id"]),
            review_id=str(row["review_id"]),
            idempotency_key=str(row["idempotency_key"]),
            decision_id=str(row["decision_id"]),
            status=IncidentStatus(str(row["status_after"])),
            published_at=str(row["published_at"]),
            published_by=str(row["published_by"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def create_incident(
        self,
        incident_id: str,
        *,
        reviewed_archive_sha256: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> IncidentRecord:
        incident_id = self._required_text(incident_id, "incident_id")
        actor = self._required_text(actor, "actor")
        reviewed_archive_sha256 = self._validate_sha256(
            reviewed_archive_sha256, "reviewed_archive_sha256"
        )
        occurred_at = self._timestamp(occurred_at or utc_now())
        existing = self.database.connection.execute(
            "SELECT * FROM continuity_incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        if existing is not None:
            if str(existing["reviewed_archive_sha256"]) != reviewed_archive_sha256:
                raise ConflictError("incident identifier already binds another archive", {"incident_id": incident_id})
            return self._incident_from_row(existing)

        payload = {
            "incident_id": incident_id,
            "reviewed_archive_sha256": reviewed_archive_sha256,
            "status": IncidentStatus.RECOVERY_REQUIRED.value,
            "disposition": "RECOLLECT_REQUIRED",
        }
        try:
            with self.database.transaction() as connection:
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"continuity:incident:{incident_id}",
                    "CONTINUITY_INCIDENT_CREATED",
                    payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO continuity_incidents (
                        incident_id, reviewed_archive_sha256, status, disposition,
                        created_at, created_by, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, 'RECOLLECT_REQUIRED', ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        reviewed_archive_sha256,
                        IncidentStatus.RECOVERY_REQUIRED.value,
                        occurred_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("incident already exists", {"incident_id": incident_id}) from exc
        return self.get_incident(incident_id)

    def get_incident(self, incident_id: str) -> IncidentRecord:
        incident_id = self._required_text(incident_id, "incident_id")
        row = self.database.connection.execute(
            "SELECT * FROM continuity_incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("continuity incident does not exist", {"incident_id": incident_id})
        return self._incident_from_row(row)

    def _assert_authorization(
        self,
        decision_id: str,
        *,
        actor: str,
        action: str,
        resource: str,
    ) -> None:
        decision_id = self._required_text(decision_id, "decision_id")
        verification = self.trust.verify_decision(decision_id)
        if not verification.ok:
            raise AuthorizationError(
                "authorization decision failed verification",
                {"decision_id": decision_id, "defects": list(verification.defects)},
            )
        try:
            decision = self.trust.get_decision(decision_id)
        except NotFoundError as exc:
            raise AuthorizationError("authorization decision does not exist") from exc
        expected = (actor, action, resource)
        observed = (
            decision.request.subject,
            decision.request.action,
            decision.request.resource,
        )
        if not decision.allowed or observed != expected:
            raise AuthorizationError(
                "authorization decision does not exactly match the operation",
                {
                    "decision_id": decision_id,
                    "allowed": decision.allowed,
                    "expected": list(expected),
                    "observed": list(observed),
                },
            )

    @staticmethod
    def _consume_authorization(
        connection: sqlite3.Connection,
        *,
        decision_id: str,
        operation_kind: str,
        operation_id: str,
        actor: str,
        occurred_at: str,
    ) -> None:
        try:
            connection.execute(
                """
                INSERT INTO continuity_authorization_consumptions (
                    decision_id, operation_kind, operation_id, consumed_at, consumed_by
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (decision_id, operation_kind, operation_id, occurred_at, actor),
            )
        except sqlite3.IntegrityError as exc:
            raise AuthorizationError(
                "authorization decision or operation was already consumed",
                {"decision_id": decision_id, "operation_id": operation_id},
            ) from exc

    def accept_trust_root(
        self,
        key_id: str,
        public_key_pem: bytes,
        *,
        decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> TrustRootReceipt:
        key_id = self._required_text(key_id, "key_id")
        actor = self._required_text(actor, "actor")
        public_key_pem = self._bounded_bytes(
            public_key_pem, "public_key_pem", _MAX_PUBLIC_KEY_BYTES
        )
        occurred_at = self._timestamp(occurred_at or utc_now())
        fingerprint = self._digest(public_key_pem)
        existing = self.database.connection.execute(
            "SELECT * FROM continuity_trust_roots WHERE key_id = ?", (key_id,)
        ).fetchone()
        if existing is not None:
            if (
                bytes(existing["public_key_pem"]) == public_key_pem
                and str(existing["decision_id"]) == decision_id
                and str(existing["accepted_by"]) == actor
            ):
                return self._trust_root_from_row(existing)
            raise ConflictError("trust-root identifier already binds different material", {"key_id": key_id})
        if not self.signature_verifier.validate_public_key(public_key_pem):
            raise ValidationError("public key is not an accepted Ed25519 key")
        resource = f"continuity:trust-root:{key_id}"
        self._assert_authorization(
            decision_id,
            actor=actor,
            action="continuity.trust-root.accept",
            resource=resource,
        )
        payload = {
            "key_id": key_id,
            "fingerprint_sha256": fingerprint,
            "decision_id": decision_id,
        }
        try:
            with self.database.transaction() as connection:
                self._consume_authorization(
                    connection,
                    decision_id=decision_id,
                    operation_kind="TRUST_ROOT_ACCEPTED",
                    operation_id=key_id,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"continuity:trust-root:{key_id}",
                    "CONTINUITY_TRUST_ROOT_ACCEPTED",
                    payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO continuity_trust_roots (
                        key_id, public_key_pem, fingerprint_sha256, decision_id,
                        accepted_at, accepted_by, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        key_id,
                        sqlite3.Binary(public_key_pem),
                        fingerprint,
                        decision_id,
                        occurred_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("trust root violates an integrity constraint", {"key_id": key_id}) from exc
        row = self.database.connection.execute(
            "SELECT * FROM continuity_trust_roots WHERE key_id = ?", (key_id,)
        ).fetchone()
        assert row is not None
        return self._trust_root_from_row(row)

    def _parse_review(self, payload: bytes) -> dict[str, object]:
        payload = self._bounded_bytes(payload, "payload", _MAX_PAYLOAD_BYTES)
        try:
            decoded = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("signed disposition must be UTF-8 JSON") from exc
        if not isinstance(decoded, dict):
            raise ValidationError("signed disposition must be a JSON object")

        text_fields = (
            "review_id",
            "reviewer_identity",
            "review_environment",
            "reviewed_at_utc",
            "independence_basis",
            "reasoning",
        )
        for field in text_fields:
            self._required_text(decoded.get(field), field)  # type: ignore[arg-type]
        self._timestamp(str(decoded["reviewed_at_utc"]))
        self._validate_sha256(decoded.get("reviewed_archive_sha256"), "reviewed_archive_sha256")  # type: ignore[arg-type]
        for field in ("commands_and_exit_codes", "evidence_paths_and_hashes"):
            if not isinstance(decoded.get(field), list):
                raise ValidationError(f"{field} must be an array")

        allowed_values = {
            "receipt_snapshot_observation_result": {"PASS", "FAIL", "INCONCLUSIVE"},
            "wave_order_result": {"CONFIRMS_W3_TO_W2", "DOES_NOT_CONFIRM", "INCONCLUSIVE"},
            "attempt_boundary_result": {
                "POSSIBLE_UNQUANTIFIED_CONFIRMED",
                "BOUNDED",
                "INCONCLUSIVE",
            },
            "disposition": {
                "CONFIRM_NONCONFORMING",
                "RECOLLECT_REQUIRED",
                "EVIDENCE_INVALID",
                "INCONCLUSIVE",
            },
        }
        for field, allowed in allowed_values.items():
            value = decoded.get(field)
            if value not in allowed:
                raise ValidationError(f"{field} has an unsupported value")
        if decoded.get("gate_effect") != "NO_GATE_CHANGE":
            raise ValidationError("gate_effect must be NO_GATE_CHANGE")
        if decoded.get("independent_identity_status") != "SATISFIED":
            raise ValidationError("independent_identity_status must be SATISFIED")
        return decoded

    def admit_review(
        self,
        incident_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        *,
        actor: str,
        occurred_at: str | None = None,
    ) -> ReviewAdmission:
        incident = self.get_incident(incident_id)
        key_id = self._required_text(key_id, "key_id")
        actor = self._required_text(actor, "actor")
        signature = self._bounded_bytes(signature, "signature", _MAX_SIGNATURE_BYTES)
        occurred_at = self._timestamp(occurred_at or utc_now())
        decoded = self._parse_review(payload)
        review_id = str(decoded["review_id"])
        if str(decoded["reviewed_archive_sha256"]) != incident.reviewed_archive_sha256:
            raise ValidationError("signed disposition targets a different archive")
        root = self.database.connection.execute(
            "SELECT * FROM continuity_trust_roots WHERE key_id = ?", (key_id,)
        ).fetchone()
        if root is None:
            raise AuthorizationError("reviewer trust root is not accepted", {"key_id": key_id})
        public_key = bytes(root["public_key_pem"])
        if not self.signature_verifier.verify(public_key, payload, signature):
            raise IntegrityError("independent disposition signature is invalid")
        payload_sha256 = self._digest(payload)
        signature_sha256 = self._digest(signature)
        existing = self.database.connection.execute(
            "SELECT * FROM continuity_reviews WHERE review_id = ?", (review_id,)
        ).fetchone()
        if existing is not None:
            if (
                str(existing["incident_id"]) == incident_id
                and str(existing["key_id"]) == key_id
                and bytes(existing["payload"]) == payload
                and bytes(existing["signature"]) == signature
            ):
                return self._review_from_row(existing)
            raise ConflictError("review identifier already binds different signed bytes", {"review_id": review_id})

        event_payload = {
            "review_id": review_id,
            "incident_id": incident_id,
            "key_id": key_id,
            "payload_sha256": payload_sha256,
            "signature_sha256": signature_sha256,
            "reviewer_identity": decoded["reviewer_identity"],
            "reviewed_archive_sha256": decoded["reviewed_archive_sha256"],
            "disposition": decoded["disposition"],
        }
        try:
            with self.database.transaction() as connection:
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"continuity:incident:{incident_id}",
                    "CONTINUITY_REVIEW_ADMITTED",
                    event_payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO continuity_reviews (
                        review_id, incident_id, key_id, payload, payload_sha256,
                        signature, signature_sha256, reviewer_identity,
                        review_environment, reviewed_archive_sha256, reviewed_at_utc,
                        independence_basis, independent_identity_status, receipt_result,
                        wave_order_result, attempt_boundary_result, disposition, gate_effect,
                        admitted_at, admitted_by, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        review_id,
                        incident_id,
                        key_id,
                        sqlite3.Binary(payload),
                        payload_sha256,
                        sqlite3.Binary(signature),
                        signature_sha256,
                        str(decoded["reviewer_identity"]),
                        str(decoded["review_environment"]),
                        str(decoded["reviewed_archive_sha256"]),
                        str(decoded["reviewed_at_utc"]),
                        str(decoded["independence_basis"]),
                        str(decoded["independent_identity_status"]),
                        str(decoded["receipt_snapshot_observation_result"]),
                        str(decoded["wave_order_result"]),
                        str(decoded["attempt_boundary_result"]),
                        str(decoded["disposition"]),
                        str(decoded["gate_effect"]),
                        occurred_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("review violates an integrity constraint", {"review_id": review_id}) from exc
        row = self.database.connection.execute(
            "SELECT * FROM continuity_reviews WHERE review_id = ?", (review_id,)
        ).fetchone()
        assert row is not None
        return self._review_from_row(row)

    @staticmethod
    def _review_is_recovery_eligible(row: sqlite3.Row) -> bool:
        return (
            str(row["receipt_result"]) == "PASS"
            and str(row["wave_order_result"]) == "CONFIRMS_W3_TO_W2"
            and str(row["attempt_boundary_result"]) == "POSSIBLE_UNQUANTIFIED_CONFIRMED"
            and str(row["disposition"]) == "RECOLLECT_REQUIRED"
            and str(row["gate_effect"]) == "NO_GATE_CHANGE"
            and str(row["independent_identity_status"]) == "SATISFIED"
        )

    def publish_recovery(
        self,
        incident_id: str,
        review_id: str,
        *,
        publication_id: str,
        idempotency_key: str,
        decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> RecoveryPublication:
        incident_id = self._required_text(incident_id, "incident_id")
        review_id = self._required_text(review_id, "review_id")
        publication_id = self._required_text(publication_id, "publication_id")
        idempotency_key = self._required_text(idempotency_key, "idempotency_key")
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now())
        existing = self.database.connection.execute(
            "SELECT * FROM continuity_recovery_publications WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        if existing is not None:
            if (
                str(existing["publication_id"]) == publication_id
                and str(existing["review_id"]) == review_id
                and str(existing["idempotency_key"]) == idempotency_key
                and str(existing["decision_id"]) == decision_id
                and str(existing["published_by"]) == actor
            ):
                return self._publication_from_row(existing)
            raise ConflictError("incident recovery was already published", {"incident_id": incident_id})

        incident = self.get_incident(incident_id)
        if incident.status is not IncidentStatus.RECOVERY_REQUIRED:
            raise StateTransitionError("incident is not awaiting recovery publication")
        review = self.database.connection.execute(
            "SELECT * FROM continuity_reviews WHERE review_id = ? AND incident_id = ?",
            (review_id, incident_id),
        ).fetchone()
        if review is None:
            raise NotFoundError("admitted review does not exist", {"review_id": review_id})
        if not self._review_is_recovery_eligible(review):
            raise StateTransitionError("signed review does not authorize recollection recovery")
        self._assert_authorization(
            decision_id,
            actor=actor,
            action="continuity.recovery.publish",
            resource=f"continuity:incident:{incident_id}",
        )
        status_after = IncidentStatus.RECOVERY_PUBLISHED_RECOLLECT_REQUIRED.value
        event_payload = {
            "publication_id": publication_id,
            "incident_id": incident_id,
            "review_id": review_id,
            "idempotency_key": idempotency_key,
            "decision_id": decision_id,
            "disposition": "RECOLLECT_REQUIRED",
            "review_payload_sha256": str(review["payload_sha256"]),
            "status_before": IncidentStatus.RECOVERY_REQUIRED.value,
            "status_after": status_after,
        }
        try:
            with self.database.transaction() as connection:
                current = connection.execute(
                    "SELECT status FROM continuity_incidents WHERE incident_id = ?",
                    (incident_id,),
                ).fetchone()
                if current is None:
                    raise NotFoundError("continuity incident does not exist", {"incident_id": incident_id})
                if str(current["status"]) != IncidentStatus.RECOVERY_REQUIRED.value:
                    raise StateTransitionError("incident status changed before recovery publication")
                self._consume_authorization(
                    connection,
                    decision_id=decision_id,
                    operation_kind="RECOVERY_PUBLISHED",
                    operation_id=publication_id,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"continuity:incident:{incident_id}",
                    "CONTINUITY_RECOVERY_PUBLISHED",
                    event_payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO continuity_recovery_publications (
                        publication_id, incident_id, review_id, idempotency_key,
                        decision_id, status_before, status_after, published_at,
                        published_by, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        publication_id,
                        incident_id,
                        review_id,
                        idempotency_key,
                        decision_id,
                        IncidentStatus.RECOVERY_REQUIRED.value,
                        status_after,
                        occurred_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
                connection.execute(
                    "UPDATE continuity_incidents SET status = ? WHERE incident_id = ?",
                    (status_after, incident_id),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("recovery publication violates an integrity constraint") from exc
        row = self.database.connection.execute(
            "SELECT * FROM continuity_recovery_publications WHERE publication_id = ?",
            (publication_id,),
        ).fetchone()
        assert row is not None
        return self._publication_from_row(row)

    def _event_defects(
        self,
        *,
        event_id: str,
        expected_hash: str,
        expected_kind: str,
        expected_payload: dict[str, object],
        label: str,
    ) -> list[str]:
        row = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        if row is None:
            return [f"{label}_LEDGER_EVENT_MISSING"]
        defects: list[str] = []
        if str(row["record_hash"]) != expected_hash:
            defects.append(f"{label}_LEDGER_HASH_MISMATCH")
        if str(row["kind"]) != expected_kind:
            defects.append(f"{label}_LEDGER_KIND_MISMATCH")
        try:
            payload = json.loads(str(row["payload_json"]))
        except json.JSONDecodeError:
            defects.append(f"{label}_LEDGER_PAYLOAD_INVALID")
        else:
            if payload != expected_payload:
                defects.append(f"{label}_LEDGER_PAYLOAD_MISMATCH")
        return defects

    def verify_incident(self, incident_id: str) -> ContinuityVerification:
        incident_id = self._required_text(incident_id, "incident_id")
        defects: list[str] = []
        incident_row = self.database.connection.execute(
            "SELECT * FROM continuity_incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        if incident_row is None:
            return ContinuityVerification(incident_id, ("INCIDENT_NOT_FOUND",))

        incident_payload = {
            "incident_id": incident_id,
            "reviewed_archive_sha256": str(incident_row["reviewed_archive_sha256"]),
            "status": IncidentStatus.RECOVERY_REQUIRED.value,
            "disposition": "RECOLLECT_REQUIRED",
        }
        defects.extend(
            self._event_defects(
                event_id=str(incident_row["ledger_event_id"]),
                expected_hash=str(incident_row["ledger_hash"]),
                expected_kind="CONTINUITY_INCIDENT_CREATED",
                expected_payload=incident_payload,
                label="INCIDENT",
            )
        )

        review_rows = self.database.connection.execute(
            "SELECT * FROM continuity_reviews WHERE incident_id = ? ORDER BY review_id",
            (incident_id,),
        ).fetchall()
        for review in review_rows:
            review_id = str(review["review_id"])
            root = self.database.connection.execute(
                "SELECT * FROM continuity_trust_roots WHERE key_id = ?",
                (str(review["key_id"]),),
            ).fetchone()
            payload = bytes(review["payload"])
            signature = bytes(review["signature"])
            if self._digest(payload) != str(review["payload_sha256"]):
                defects.append(f"REVIEW_PAYLOAD_DIGEST_MISMATCH:{review_id}")
            if self._digest(signature) != str(review["signature_sha256"]):
                defects.append(f"REVIEW_SIGNATURE_DIGEST_MISMATCH:{review_id}")
            if root is None:
                defects.append(f"REVIEW_TRUST_ROOT_MISSING:{review_id}")
            else:
                key_id = str(root["key_id"])
                public_key = bytes(root["public_key_pem"])
                if self._digest(public_key) != str(root["fingerprint_sha256"]):
                    defects.append(f"TRUST_ROOT_FINGERPRINT_MISMATCH:{key_id}")

                decision_id = str(root["decision_id"])
                decision_verification = self.trust.verify_decision(decision_id)
                if not decision_verification.ok:
                    defects.append(f"TRUST_ROOT_DECISION_INVALID:{key_id}")
                else:
                    try:
                        decision = self.trust.get_decision(decision_id)
                    except NotFoundError:
                        defects.append(f"TRUST_ROOT_DECISION_INVALID:{key_id}")
                    else:
                        expected_request = (
                            str(root["accepted_by"]),
                            "continuity.trust-root.accept",
                            f"continuity:trust-root:{key_id}",
                        )
                        observed_request = (
                            decision.request.subject,
                            decision.request.action,
                            decision.request.resource,
                        )
                        if not decision.allowed or observed_request != expected_request:
                            defects.append(f"TRUST_ROOT_DECISION_INVALID:{key_id}")

                consumption = self.database.connection.execute(
                    "SELECT * FROM continuity_authorization_consumptions WHERE decision_id = ?",
                    (decision_id,),
                ).fetchone()
                if consumption is None or (
                    str(consumption["operation_kind"]) != "TRUST_ROOT_ACCEPTED"
                    or str(consumption["operation_id"]) != key_id
                    or str(consumption["consumed_by"]) != str(root["accepted_by"])
                ):
                    defects.append(
                        f"TRUST_ROOT_AUTHORIZATION_CONSUMPTION_MISMATCH:{key_id}"
                    )

                trust_root_payload = {
                    "key_id": key_id,
                    "fingerprint_sha256": str(root["fingerprint_sha256"]),
                    "decision_id": decision_id,
                }
                defects.extend(
                    self._event_defects(
                        event_id=str(root["ledger_event_id"]),
                        expected_hash=str(root["ledger_hash"]),
                        expected_kind="CONTINUITY_TRUST_ROOT_ACCEPTED",
                        expected_payload=trust_root_payload,
                        label=f"TRUST_ROOT:{key_id}",
                    )
                )

                if not self.signature_verifier.verify(public_key, payload, signature):
                    defects.append(f"REVIEW_SIGNATURE_INVALID:{review_id}")
            try:
                decoded = self._parse_review(payload)
            except ValidationError:
                defects.append(f"REVIEW_FIELDS_INVALID:{review_id}")
                decoded = None
            if decoded is not None:
                comparisons = {
                    "reviewer_identity": "reviewer_identity",
                    "review_environment": "review_environment",
                    "reviewed_archive_sha256": "reviewed_archive_sha256",
                    "reviewed_at_utc": "reviewed_at_utc",
                    "independence_basis": "independence_basis",
                    "independent_identity_status": "independent_identity_status",
                    "receipt_snapshot_observation_result": "receipt_result",
                    "wave_order_result": "wave_order_result",
                    "attempt_boundary_result": "attempt_boundary_result",
                    "disposition": "disposition",
                    "gate_effect": "gate_effect",
                }
                for payload_field, column in comparisons.items():
                    if str(decoded[payload_field]) != str(review[column]):
                        defects.append(f"REVIEW_STORED_FIELD_MISMATCH:{review_id}:{column}")
                if str(decoded["reviewed_archive_sha256"]) != str(
                    incident_row["reviewed_archive_sha256"]
                ):
                    defects.append(f"REVIEW_ARCHIVE_MISMATCH:{review_id}")
            review_event_payload = {
                "review_id": review_id,
                "incident_id": incident_id,
                "key_id": str(review["key_id"]),
                "payload_sha256": str(review["payload_sha256"]),
                "signature_sha256": str(review["signature_sha256"]),
                "reviewer_identity": str(review["reviewer_identity"]),
                "reviewed_archive_sha256": str(review["reviewed_archive_sha256"]),
                "disposition": str(review["disposition"]),
            }
            defects.extend(
                self._event_defects(
                    event_id=str(review["ledger_event_id"]),
                    expected_hash=str(review["ledger_hash"]),
                    expected_kind="CONTINUITY_REVIEW_ADMITTED",
                    expected_payload=review_event_payload,
                    label=f"REVIEW:{review_id}",
                )
            )

        publication = self.database.connection.execute(
            "SELECT * FROM continuity_recovery_publications WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        observed_status = str(incident_row["status"])
        if publication is None:
            if observed_status != IncidentStatus.RECOVERY_REQUIRED.value:
                defects.append("INCIDENT_STATUS_WITHOUT_PUBLICATION")
        else:
            publication_id = str(publication["publication_id"])
            if observed_status != IncidentStatus.RECOVERY_PUBLISHED_RECOLLECT_REQUIRED.value:
                defects.append("INCIDENT_PUBLICATION_STATUS_MISMATCH")
            review = self.database.connection.execute(
                "SELECT * FROM continuity_reviews WHERE review_id = ?",
                (str(publication["review_id"]),),
            ).fetchone()
            if review is None:
                defects.append(f"PUBLICATION_REVIEW_MISSING:{publication_id}")
            elif not self._review_is_recovery_eligible(review):
                defects.append(f"PUBLICATION_REVIEW_INELIGIBLE:{publication_id}")
            decision_id = str(publication["decision_id"])
            verification = self.trust.verify_decision(decision_id)
            if not verification.ok:
                defects.append(f"PUBLICATION_DECISION_INVALID:{publication_id}")
            else:
                try:
                    decision = self.trust.get_decision(decision_id)
                except NotFoundError:
                    defects.append(f"PUBLICATION_DECISION_MISSING:{publication_id}")
                else:
                    expected_request = (
                        str(publication["published_by"]),
                        "continuity.recovery.publish",
                        f"continuity:incident:{incident_id}",
                    )
                    observed_request = (
                        decision.request.subject,
                        decision.request.action,
                        decision.request.resource,
                    )
                    if not decision.allowed or observed_request != expected_request:
                        defects.append(f"PUBLICATION_DECISION_MISMATCH:{publication_id}")
            consumption = self.database.connection.execute(
                "SELECT * FROM continuity_authorization_consumptions WHERE decision_id = ?",
                (decision_id,),
            ).fetchone()
            if consumption is None or (
                str(consumption["operation_kind"]) != "RECOVERY_PUBLISHED"
                or str(consumption["operation_id"]) != publication_id
            ):
                defects.append(f"PUBLICATION_AUTHORIZATION_CONSUMPTION_MISMATCH:{publication_id}")
            review_digest = str(review["payload_sha256"]) if review is not None else ""
            publication_payload = {
                "publication_id": publication_id,
                "incident_id": incident_id,
                "review_id": str(publication["review_id"]),
                "idempotency_key": str(publication["idempotency_key"]),
                "decision_id": decision_id,
                "disposition": "RECOLLECT_REQUIRED",
                "review_payload_sha256": review_digest,
                "status_before": IncidentStatus.RECOVERY_REQUIRED.value,
                "status_after": IncidentStatus.RECOVERY_PUBLISHED_RECOLLECT_REQUIRED.value,
            }
            defects.extend(
                self._event_defects(
                    event_id=str(publication["ledger_event_id"]),
                    expected_hash=str(publication["ledger_hash"]),
                    expected_kind="CONTINUITY_RECOVERY_PUBLISHED",
                    expected_payload=publication_payload,
                    label=f"PUBLICATION:{publication_id}",
                )
            )

        if not self.ledger.verify(f"continuity:incident:{incident_id}").ok:
            defects.append("INCIDENT_LEDGER_CHAIN_INVALID")
        for key_id in {
            str(row["key_id"])
            for row in review_rows
        }:
            if not self.ledger.verify(f"continuity:trust-root:{key_id}").ok:
                defects.append(f"TRUST_ROOT_LEDGER_CHAIN_INVALID:{key_id}")
        return ContinuityVerification(incident_id, tuple(dict.fromkeys(defects)))
