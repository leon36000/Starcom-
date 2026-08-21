from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from collections.abc import Mapping, Sequence
from typing import Any, Callable

from .canonical import canonical_json, parse_strict_json_object, sha256_digest, utc_now
from .db import Database
from .errors import (
    AuthorizationError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    StarcomError,
    ValidationError,
)
from .ledger import EventLedger
from .trust import AuthorizationDecision, AuthorizationRequest, TrustPlane


_COMMAND_ACTION = "cockpit.command.authorize"
_COMMAND_STATUS = "COCKPIT_COMMAND_AUTHORIZED_NOT_EXECUTED"
_SNAPSHOT_KEYS = frozenset(
    {
        "project_state",
        "current_phase",
        "test_count",
        "canonical_truth",
        "services",
        "alerts",
        "updated_at_utc",
    }
)
_SERVICE_KEYS = frozenset({"service_id", "status"})
_ALERT_KEYS = frozenset({"alert_id", "severity", "message"})
_COMMAND_TYPES = frozenset(
    {"START", "PAUSE", "RESUME", "CANCEL", "APPROVE", "REJECT"}
)
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,190}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_JSON_BYTES = 256 * 1024
_DEFAULT_BODY_LIMIT = 64 * 1024


class CockpitCommandType(str, Enum):
    START = "START"
    PAUSE = "PAUSE"
    RESUME = "RESUME"
    CANCEL = "CANCEL"
    APPROVE = "APPROVE"
    REJECT = "REJECT"


class CockpitCommandStatus(str, Enum):
    AUTHORIZED_NOT_EXECUTED = _COMMAND_STATUS


@dataclass(frozen=True)
class CockpitSnapshotPreparation:
    snapshot_id: str
    payload: Mapping[str, Any]
    snapshot_digest: str
    updated_at_utc: str


@dataclass(frozen=True)
class CockpitSnapshot:
    snapshot_id: str
    project_state: str
    current_phase: str
    test_count: int
    canonical_truth: str
    services: tuple[Mapping[str, str], ...]
    alerts: tuple[Mapping[str, str], ...]
    updated_at_utc: str
    snapshot_digest: str
    admitted_at: str
    admitted_by: str
    ledger_event_id: str
    ledger_hash: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "project_state": self.project_state,
            "current_phase": self.current_phase,
            "test_count": self.test_count,
            "canonical_truth": self.canonical_truth,
            "services": [dict(item) for item in self.services],
            "alerts": [dict(item) for item in self.alerts],
            "updated_at_utc": self.updated_at_utc,
            "snapshot_digest": self.snapshot_digest,
        }


@dataclass(frozen=True)
class CockpitSessionCredentials:
    session_id: str
    subject: str
    token: str
    csrf_token: str
    expires_at: str


@dataclass(frozen=True)
class CockpitSession:
    session_id: str
    subject: str
    expires_at: str
    token_hash: str
    csrf_hash: str


@dataclass(frozen=True)
class CockpitCommandPreparation:
    command_id: str
    session_id: str
    session_subject: str
    snapshot_id: str
    snapshot_digest: str
    command_type: CockpitCommandType
    target: str
    parameters: Mapping[str, Any]
    parameters_digest: str
    request_digest: str
    action: str
    resource: str
    mission_id: str
    authorization_context: Mapping[str, Any]


@dataclass(frozen=True)
class CockpitCommandRecord:
    command_id: str
    session_id: str
    session_subject: str
    snapshot_id: str
    snapshot_digest: str
    command_type: CockpitCommandType
    target: str
    parameters: Mapping[str, Any]
    parameters_digest: str
    request_digest: str
    authorization_decision_id: str
    status: CockpitCommandStatus
    authorized_at: str
    authorized_by: str
    ledger_event_id: str
    ledger_hash: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "session_id": self.session_id,
            "session_subject": self.session_subject,
            "snapshot_id": self.snapshot_id,
            "snapshot_digest": self.snapshot_digest,
            "command_type": self.command_type.value,
            "target": self.target,
            "parameters": dict(self.parameters),
            "parameters_digest": self.parameters_digest,
            "request_digest": self.request_digest,
            "authorization_decision_id": self.authorization_decision_id,
            "status": self.status.value,
            "authorized_at": self.authorized_at,
            "authorized_by": self.authorized_by,
        }


@dataclass(frozen=True)
class CockpitVerification:
    object_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class _HttpFailure(Exception):
    def __init__(self, status: str, message: str, code: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code


def _text(value: object, field_name: str, *, max_length: int = 256) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field_name} must be a non-empty string")
    if len(value) > max_length:
        raise ValidationError(f"{field_name} is too long")
    return value


def _identifier(value: object, field_name: str) -> str:
    result = _text(value, field_name)
    if not _ID_RE.fullmatch(result):
        raise ValidationError(f"{field_name} has an invalid identifier")
    return result


def _timestamp(value: object, field_name: str) -> str:
    result = _text(value, field_name)
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{field_name} must be RFC 3339") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError(f"{field_name} must be timezone-aware")
    return result


def _hash_secret(value: object, field_name: str) -> str:
    raw = _text(value, field_name, max_length=4096)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _digest(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise ValidationError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _json_object(value: object, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{field_name} must be an object")
    result = dict(value)
    if any(not isinstance(key, str) for key in result):
        raise ValidationError(f"{field_name} keys must be strings")
    try:
        encoded = canonical_json(result).encode("utf-8")
    except (TypeError, ValueError, ValidationError) as exc:
        raise ValidationError(f"{field_name} must contain canonical JSON values") from exc
    if len(encoded) > _MAX_JSON_BYTES:
        raise ValidationError(f"{field_name} is too large")
    return result


def _closed_entry(
    value: object,
    *,
    field_name: str,
    keys: frozenset[str],
) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != set(keys):
        raise ValidationError(f"{field_name} has an unexpected or missing field")
    result = dict(value)
    for key, item in result.items():
        result[key] = _text(item, f"{field_name}.{key}")
    return result


def _entries(
    value: object,
    *,
    field_name: str,
    keys: frozenset[str],
    identity_key: str,
) -> tuple[Mapping[str, str], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValidationError(f"{field_name} must be a sequence")
    result = tuple(
        _closed_entry(item, field_name=f"{field_name}[{index}]", keys=keys)
        for index, item in enumerate(value)
    )
    identities = tuple(str(item[identity_key]) for item in result)
    if identities != tuple(sorted(identities)) or len(set(identities)) != len(identities):
        raise ValidationError(f"{field_name} must be sorted and unique")
    return result


def _snapshot_payload(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_SNAPSHOT_KEYS):
        raise ValidationError("snapshot payload has an unexpected or missing field")
    raw = dict(value)
    payload = {
        "project_state": _text(raw["project_state"], "project_state"),
        "current_phase": _text(raw["current_phase"], "current_phase"),
        "test_count": raw["test_count"],
        "canonical_truth": _text(raw["canonical_truth"], "canonical_truth"),
        "services": [
            dict(item)
            for item in _entries(
                raw["services"],
                field_name="services",
                keys=_SERVICE_KEYS,
                identity_key="service_id",
            )
        ],
        "alerts": [
            dict(item)
            for item in _entries(
                raw["alerts"],
                field_name="alerts",
                keys=_ALERT_KEYS,
                identity_key="alert_id",
            )
        ],
        "updated_at_utc": _timestamp(raw["updated_at_utc"], "updated_at_utc"),
    }
    if type(payload["test_count"]) is not int or payload["test_count"] < 0:
        raise ValidationError("test_count must be a non-negative integer")
    canonical_json(payload)
    return payload


def _decode_canonical_object(raw: object, field_name: str) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw or len(raw.encode("utf-8")) > _MAX_JSON_BYTES:
        raise ValueError(f"{field_name} is not bounded canonical JSON")

    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key {key}")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=no_duplicates)
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise ValueError(f"{field_name} is not canonical JSON")
    return value


class CockpitService:
    def __init__(self, database: Database, ledger: EventLedger, trust: TrustPlane) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self._initialize_schema()

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS cockpit_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
                    updated_at_utc TEXT NOT NULL,
                    admitted_at TEXT NOT NULL,
                    admitted_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS cockpit_sessions (
                    session_id TEXT PRIMARY KEY,
                    subject TEXT NOT NULL,
                    token_hash TEXT NOT NULL CHECK (length(token_hash) = 64),
                    csrf_hash TEXT NOT NULL CHECK (length(csrf_hash) = 64),
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS cockpit_commands (
                    command_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    session_subject TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL,
                    snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
                    command_type TEXT NOT NULL CHECK (
                        command_type IN ('START','PAUSE','RESUME','CANCEL','APPROVE','REJECT')
                    ),
                    target TEXT NOT NULL,
                    parameters_json TEXT NOT NULL,
                    parameters_digest TEXT NOT NULL CHECK (length(parameters_digest) = 64),
                    request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
                    authorization_decision_id TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL CHECK (
                        status = 'COCKPIT_COMMAND_AUTHORIZED_NOT_EXECUTED'
                    ),
                    authorized_at TEXT NOT NULL,
                    authorized_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (snapshot_id) REFERENCES cockpit_snapshots(snapshot_id),
                    FOREIGN KEY (session_id) REFERENCES cockpit_sessions(session_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS cockpit_command_transitions (
                    transition_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    command_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL CHECK (sequence >= 1),
                    from_status TEXT,
                    to_status TEXT NOT NULL CHECK (
                        to_status = 'COCKPIT_COMMAND_AUTHORIZED_NOT_EXECUTED'
                    ),
                    actor TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    UNIQUE (command_id, sequence),
                    FOREIGN KEY (command_id) REFERENCES cockpit_commands(command_id)
                )
                """
            )
            for table, label in (
                ("cockpit_snapshots", "cockpit snapshots"),
                ("cockpit_sessions", "cockpit sessions"),
                ("cockpit_commands", "cockpit commands"),
                ("cockpit_command_transitions", "cockpit command transitions"),
            ):
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {table}_no_update
                    BEFORE UPDATE ON {table}
                    BEGIN SELECT RAISE(ABORT, '{label} are immutable'); END
                    """
                )
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {table}_no_delete
                    BEFORE DELETE ON {table}
                    BEGIN SELECT RAISE(ABORT, '{label} are immutable'); END
                    """
                )

    def prepare_snapshot(
        self,
        snapshot_id: str,
        payload: Mapping[str, object],
    ) -> CockpitSnapshotPreparation:
        snapshot_id = _identifier(snapshot_id, "snapshot_id")
        selected = _snapshot_payload(payload)
        return CockpitSnapshotPreparation(
            snapshot_id=snapshot_id,
            payload=selected,
            snapshot_digest=sha256_digest(selected),
            updated_at_utc=str(selected["updated_at_utc"]),
        )

    @staticmethod
    def _snapshot_from_row(row: sqlite3.Row) -> CockpitSnapshot:
        payload = _snapshot_payload(
            _decode_canonical_object(str(row["payload_json"]), "snapshot payload")
        )
        return CockpitSnapshot(
            snapshot_id=str(row["snapshot_id"]),
            project_state=str(payload["project_state"]),
            current_phase=str(payload["current_phase"]),
            test_count=int(payload["test_count"]),
            canonical_truth=str(payload["canonical_truth"]),
            services=tuple(dict(item) for item in payload["services"]),
            alerts=tuple(dict(item) for item in payload["alerts"]),
            updated_at_utc=str(payload["updated_at_utc"]),
            snapshot_digest=str(row["snapshot_digest"]),
            admitted_at=str(row["admitted_at"]),
            admitted_by=str(row["admitted_by"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def admit_snapshot(
        self,
        preparation: CockpitSnapshotPreparation,
        *,
        actor: str,
        occurred_at: str | None = None,
    ) -> CockpitSnapshot:
        if not isinstance(preparation, CockpitSnapshotPreparation):
            raise ValidationError("preparation must be a CockpitSnapshotPreparation")
        canonical = self.prepare_snapshot(preparation.snapshot_id, preparation.payload)
        if canonical != preparation:
            raise IntegrityError("snapshot preparation is not canonical")
        actor = _identifier(actor, "actor")
        occurred_at = _timestamp(occurred_at or utc_now(), "occurred_at")
        try:
            with self.database.transaction() as connection:
                existing = connection.execute(
                    "SELECT * FROM cockpit_snapshots WHERE snapshot_id = ?",
                    (preparation.snapshot_id,),
                ).fetchone()
                if existing is not None:
                    current = self._snapshot_from_row(existing)
                    if (
                        current.snapshot_digest != preparation.snapshot_digest
                        or current.admitted_by != actor
                    ):
                        raise ConflictError(
                            "snapshot replay changed immutable material",
                            {"snapshot_id": preparation.snapshot_id},
                        )
                    if not self.verify_snapshot(preparation.snapshot_id).ok:
                        raise IntegrityError("snapshot replay found corrupted state")
                    return current
                payload = {
                    "snapshot_id": preparation.snapshot_id,
                    "snapshot": dict(preparation.payload),
                    "snapshot_digest": preparation.snapshot_digest,
                }
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"cockpit:snapshot:{preparation.snapshot_id}",
                    "COCKPIT_SNAPSHOT_ADMITTED",
                    payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO cockpit_snapshots (
                        snapshot_id, payload_json, snapshot_digest, updated_at_utc,
                        admitted_at, admitted_by, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        preparation.snapshot_id,
                        canonical_json(dict(preparation.payload)),
                        preparation.snapshot_digest,
                        preparation.updated_at_utc,
                        occurred_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM cockpit_snapshots WHERE snapshot_id = ?",
                    (preparation.snapshot_id,),
                ).fetchone()
                assert row is not None
                return self._snapshot_from_row(row)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("snapshot admission conflicted", {"snapshot_id": preparation.snapshot_id}) from exc

    def get_latest_snapshot(self) -> CockpitSnapshot:
        row = self.database.connection.execute(
            """
            SELECT * FROM cockpit_snapshots
            ORDER BY updated_at_utc DESC, snapshot_id DESC LIMIT 1
            """
        ).fetchone()
        if row is None:
            raise NotFoundError("no cockpit snapshot exists")
        return self._snapshot_from_row(row)

    def get_snapshot(self, snapshot_id: str) -> CockpitSnapshot:
        snapshot_id = _identifier(snapshot_id, "snapshot_id")
        row = self.database.connection.execute(
            "SELECT * FROM cockpit_snapshots WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("cockpit snapshot does not exist", {"snapshot_id": snapshot_id})
        return self._snapshot_from_row(row)

    def verify_snapshot(self, snapshot_id: str) -> CockpitVerification:
        snapshot_id = _identifier(snapshot_id, "snapshot_id")
        defects: list[str] = []
        connection = self.database.connection
        row = connection.execute(
            "SELECT * FROM cockpit_snapshots WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchone()
        if row is None:
            return CockpitVerification(snapshot_id, ("SNAPSHOT_NOT_FOUND",))
        payload: dict[str, Any] | None = None
        try:
            payload = _decode_canonical_object(str(row["payload_json"]), "snapshot payload")
            canonical = self.prepare_snapshot(snapshot_id, payload)
            if str(row["snapshot_digest"]) != canonical.snapshot_digest:
                defects.append("SNAPSHOT_DIGEST_MISMATCH")
            if str(row["updated_at_utc"]) != canonical.updated_at_utc:
                defects.append("SNAPSHOT_TIMESTAMP_MISMATCH")
        except (TypeError, ValueError, ValidationError):
            defects.append("SNAPSHOT_PAYLOAD_INVALID")
        ledger_row = connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (str(row["ledger_event_id"]),),
        ).fetchone()
        if ledger_row is None:
            defects.append("SNAPSHOT_LEDGER_EVENT_MISSING")
        else:
            if str(ledger_row["record_hash"]) != str(row["ledger_hash"]):
                defects.append("SNAPSHOT_LEDGER_HASH_MISMATCH")
            if str(ledger_row["stream_id"]) != f"cockpit:snapshot:{snapshot_id}":
                defects.append("SNAPSHOT_LEDGER_STREAM_MISMATCH")
            if str(ledger_row["kind"]) != "COCKPIT_SNAPSHOT_ADMITTED":
                defects.append("SNAPSHOT_LEDGER_KIND_MISMATCH")
            if str(ledger_row["actor"]) != str(row["admitted_by"]):
                defects.append("SNAPSHOT_LEDGER_ACTOR_MISMATCH")
            if str(ledger_row["occurred_at"]) != str(row["admitted_at"]):
                defects.append("SNAPSHOT_LEDGER_TIMESTAMP_MISMATCH")
            if payload is not None:
                expected = {
                    "snapshot_id": snapshot_id,
                    "snapshot": payload,
                    "snapshot_digest": str(row["snapshot_digest"]),
                }
                try:
                    if json.loads(str(ledger_row["payload_json"])) != expected:
                        defects.append("SNAPSHOT_LEDGER_PAYLOAD_MISMATCH")
                except (TypeError, ValueError, json.JSONDecodeError):
                    defects.append("SNAPSHOT_LEDGER_PAYLOAD_INVALID")
            if not self.ledger.verify(str(ledger_row["stream_id"])).ok:
                defects.append("SNAPSHOT_LEDGER_CHAIN_INVALID")
        return CockpitVerification(snapshot_id, tuple(dict.fromkeys(defects)))

    def create_session(
        self,
        session_id: str,
        subject: str,
        *,
        token: str | None = None,
        csrf_token: str | None = None,
        expires_at: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> CockpitSessionCredentials:
        session_id = _identifier(session_id, "session_id")
        subject = _identifier(subject, "subject")
        actor = _identifier(actor, "actor")
        token = token or secrets.token_urlsafe(32)
        csrf_token = csrf_token or secrets.token_urlsafe(32)
        token_hash = _hash_secret(token, "token")
        csrf_hash = _hash_secret(csrf_token, "csrf_token")
        expires_at = _timestamp(expires_at, "expires_at")
        occurred_at = _timestamp(occurred_at or utc_now(), "occurred_at")
        if datetime.fromisoformat(expires_at.replace("Z", "+00:00")) <= datetime.fromisoformat(
            occurred_at.replace("Z", "+00:00")
        ):
            raise ValidationError("expires_at must be after occurred_at")
        try:
            with self.database.transaction() as connection:
                existing = connection.execute(
                    "SELECT * FROM cockpit_sessions WHERE session_id = ?",
                    (session_id,),
                ).fetchone()
                if existing is not None:
                    if (
                        str(existing["subject"]) != subject
                        or str(existing["token_hash"]) != token_hash
                        or str(existing["csrf_hash"]) != csrf_hash
                        or str(existing["expires_at"]) != expires_at
                    ):
                        raise ConflictError("session replay changed immutable material", {"session_id": session_id})
                    return CockpitSessionCredentials(session_id, subject, token, csrf_token, expires_at)
                payload = {
                    "session_id": session_id,
                    "subject": subject,
                    "token_hash": token_hash,
                    "csrf_hash": csrf_hash,
                    "expires_at": expires_at,
                }
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"cockpit:session:{session_id}",
                    "COCKPIT_SESSION_CREATED",
                    payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO cockpit_sessions (
                        session_id, subject, token_hash, csrf_hash, expires_at,
                        created_at, created_by, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        subject,
                        token_hash,
                        csrf_hash,
                        expires_at,
                        occurred_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("session admission conflicted", {"session_id": session_id}) from exc
        return CockpitSessionCredentials(session_id, subject, token, csrf_token, expires_at)

    def authenticate(self, session_id: str, token: str, *, now: str | None = None) -> CockpitSession:
        session_id = _identifier(session_id, "session_id")
        token_hash = _hash_secret(token, "token")
        now_value = _timestamp(now or utc_now(), "now")
        row = self.database.connection.execute(
            "SELECT * FROM cockpit_sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if row is None:
            raise AuthorizationError("cockpit session is not valid")
        if datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00")) <= datetime.fromisoformat(
            now_value.replace("Z", "+00:00")
        ):
            raise AuthorizationError("cockpit session has expired")
        if not hmac.compare_digest(token_hash, str(row["token_hash"])):
            raise AuthorizationError("cockpit bearer token is not valid")
        return CockpitSession(
            session_id=session_id,
            subject=str(row["subject"]),
            expires_at=str(row["expires_at"]),
            token_hash=str(row["token_hash"]),
            csrf_hash=str(row["csrf_hash"]),
        )

    def verify_csrf(self, session: CockpitSession, csrf_token: str) -> None:
        if not hmac.compare_digest(_hash_secret(csrf_token, "csrf_token"), session.csrf_hash):
            raise AuthorizationError("cockpit CSRF token is not valid")

    def _snapshot_preparation_for_command(
        self,
        command_id: str,
        session_id: str,
        snapshot_id: str,
        command_type: CockpitCommandType | str,
        target: str,
        parameters: Mapping[str, object],
    ) -> CockpitCommandPreparation:
        command_id = _identifier(command_id, "command_id")
        session_id = _identifier(session_id, "session_id")
        snapshot_id = _identifier(snapshot_id, "snapshot_id")
        target = _text(target, "target")
        try:
            selected_type = command_type if isinstance(command_type, CockpitCommandType) else CockpitCommandType(str(command_type))
        except ValueError as exc:
            raise ValidationError("command_type is not supported") from exc
        snapshot = self.get_snapshot(snapshot_id)
        snapshot_verification = self.verify_snapshot(snapshot_id)
        if not snapshot_verification.ok:
            raise IntegrityError(
                "command cannot bind to a dirty snapshot",
                {"snapshot_id": snapshot_id, "defects": list(snapshot_verification.defects)},
            )
        session_row = self.database.connection.execute(
            "SELECT subject FROM cockpit_sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if session_row is None:
            raise NotFoundError("cockpit session does not exist", {"session_id": session_id})
        selected_parameters = _json_object(parameters, "parameters")
        parameters_digest = sha256_digest(selected_parameters)
        material = {
            "command_id": command_id,
            "session_id": session_id,
            "session_subject": str(session_row["subject"]),
            "snapshot_id": snapshot_id,
            "snapshot_digest": snapshot.snapshot_digest,
            "command_type": selected_type.value,
            "target": target,
            "parameters": selected_parameters,
            "parameters_digest": parameters_digest,
        }
        request_digest = sha256_digest(material)
        context = {
            "command_id": command_id,
            "session_id": session_id,
            "session_subject": str(session_row["subject"]),
            "snapshot_id": snapshot_id,
            "snapshot_digest": snapshot.snapshot_digest,
            "command_type": selected_type.value,
            "target": target,
            "parameters_digest": parameters_digest,
        }
        return CockpitCommandPreparation(
            command_id=command_id,
            session_id=session_id,
            session_subject=str(session_row["subject"]),
            snapshot_id=snapshot_id,
            snapshot_digest=snapshot.snapshot_digest,
            command_type=selected_type,
            target=target,
            parameters=selected_parameters,
            parameters_digest=parameters_digest,
            request_digest=request_digest,
            action=_COMMAND_ACTION,
            resource=f"cockpit:command:{command_id}",
            mission_id=f"cockpit-command:{command_id}",
            authorization_context=context,
        )

    def prepare_command(
        self,
        command_id: str,
        session_id: str,
        snapshot_id: str,
        command_type: CockpitCommandType | str,
        target: str,
        parameters: Mapping[str, object],
    ) -> CockpitCommandPreparation:
        return self._snapshot_preparation_for_command(
            command_id,
            session_id,
            snapshot_id,
            command_type,
            target,
            parameters,
        )

    def _canonical_command_preparation(
        self,
        preparation: CockpitCommandPreparation,
    ) -> CockpitCommandPreparation:
        if not isinstance(preparation, CockpitCommandPreparation):
            raise ValidationError("preparation must be a CockpitCommandPreparation")
        canonical = self.prepare_command(
            preparation.command_id,
            preparation.session_id,
            preparation.snapshot_id,
            preparation.command_type,
            preparation.target,
            preparation.parameters,
        )
        if canonical != preparation:
            raise IntegrityError("command preparation is not canonical")
        return canonical

    def _verified_decision(
        self,
        preparation: CockpitCommandPreparation,
        decision_id: str,
        actor: str,
    ) -> AuthorizationDecision:
        decision_id = _text(decision_id, "authorization_decision_id")
        actor = _identifier(actor, "actor")
        decision = self.trust.get_decision(decision_id)
        verification = self.trust.verify_decision(decision_id)
        if not verification.ok:
            raise IntegrityError("cockpit authorization decision is dirty", {"defects": list(verification.defects)})
        if not decision.allowed:
            raise AuthorizationError("cockpit command is denied by TrustPlane")
        expected = AuthorizationRequest(
            subject=actor,
            action=preparation.action,
            resource=preparation.resource,
            mission_id=preparation.mission_id,
            context=dict(preparation.authorization_context),
        )
        if decision.request != expected:
            raise AuthorizationError("cockpit authorization context does not match")
        return decision

    @staticmethod
    def _command_from_row(row: sqlite3.Row) -> CockpitCommandRecord:
        return CockpitCommandRecord(
            command_id=str(row["command_id"]),
            session_id=str(row["session_id"]),
            session_subject=str(row["session_subject"]),
            snapshot_id=str(row["snapshot_id"]),
            snapshot_digest=str(row["snapshot_digest"]),
            command_type=CockpitCommandType(str(row["command_type"])),
            target=str(row["target"]),
            parameters=_decode_canonical_object(str(row["parameters_json"]), "parameters"),
            parameters_digest=str(row["parameters_digest"]),
            request_digest=str(row["request_digest"]),
            authorization_decision_id=str(row["authorization_decision_id"]),
            status=CockpitCommandStatus(str(row["status"])),
            authorized_at=str(row["authorized_at"]),
            authorized_by=str(row["authorized_by"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def authorize_command(
        self,
        preparation: CockpitCommandPreparation,
        *,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> CockpitCommandRecord:
        preparation = self._canonical_command_preparation(preparation)
        actor = _identifier(actor, "actor")
        authorization_decision_id = _text(authorization_decision_id, "authorization_decision_id")
        used = self.database.connection.execute(
            "SELECT command_id FROM cockpit_commands WHERE authorization_decision_id = ?",
            (authorization_decision_id,),
        ).fetchone()
        if used is not None and str(used["command_id"]) != preparation.command_id:
            raise ConflictError("authorization decision was already consumed by another command")
        decision = self._verified_decision(preparation, authorization_decision_id, actor)
        occurred_at = _timestamp(occurred_at or utc_now(), "occurred_at")
        try:
            with self.database.transaction() as connection:
                session_row = connection.execute(
                    "SELECT * FROM cockpit_sessions WHERE session_id = ?",
                    (preparation.session_id,),
                ).fetchone()
                if session_row is None or str(session_row["subject"]) != actor:
                    raise AuthorizationError("command session subject does not match actor")
                if datetime.fromisoformat(str(session_row["expires_at"]).replace("Z", "+00:00")) <= datetime.fromisoformat(
                    occurred_at.replace("Z", "+00:00")
                ):
                    raise AuthorizationError("command session has expired")
                snapshot_row = connection.execute(
                    "SELECT snapshot_digest FROM cockpit_snapshots WHERE snapshot_id = ?",
                    (preparation.snapshot_id,),
                ).fetchone()
                if snapshot_row is None or str(snapshot_row["snapshot_digest"]) != preparation.snapshot_digest:
                    raise IntegrityError("snapshot changed during command admission")
                existing = connection.execute(
                    "SELECT * FROM cockpit_commands WHERE command_id = ?",
                    (preparation.command_id,),
                ).fetchone()
                if existing is not None:
                    current = self._command_from_row(existing)
                    if (
                        current.request_digest != preparation.request_digest
                        or current.authorization_decision_id != decision.decision_id
                        or current.authorized_by != actor
                    ):
                        raise ConflictError("command replay changed immutable material")
                    if not self.verify_command(preparation.command_id).ok:
                        raise IntegrityError("command replay found corrupted state")
                    return current
                competitor = connection.execute(
                    "SELECT command_id FROM cockpit_commands WHERE authorization_decision_id = ?",
                    (decision.decision_id,),
                ).fetchone()
                if competitor is not None:
                    raise ConflictError("authorization decision was already consumed")
                decision = self._verified_decision(preparation, decision.decision_id, actor)
                event_payload = {
                    "command": {
                        "command_id": preparation.command_id,
                        "session_id": preparation.session_id,
                        "session_subject": preparation.session_subject,
                        "snapshot_id": preparation.snapshot_id,
                        "snapshot_digest": preparation.snapshot_digest,
                        "command_type": preparation.command_type.value,
                        "target": preparation.target,
                        "parameters": dict(preparation.parameters),
                        "parameters_digest": preparation.parameters_digest,
                        "request_digest": preparation.request_digest,
                    },
                    "authorization_decision_id": decision.decision_id,
                    "status": _COMMAND_STATUS,
                    "authorized_by": actor,
                }
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"cockpit:command:{preparation.command_id}",
                    "COCKPIT_COMMAND_AUTHORIZED",
                    event_payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO cockpit_commands (
                        command_id, session_id, session_subject, snapshot_id,
                        snapshot_digest, command_type, target, parameters_json,
                        parameters_digest, request_digest, authorization_decision_id,
                        status, authorized_at, authorized_by, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        preparation.command_id,
                        preparation.session_id,
                        preparation.session_subject,
                        preparation.snapshot_id,
                        preparation.snapshot_digest,
                        preparation.command_type.value,
                        preparation.target,
                        canonical_json(dict(preparation.parameters)),
                        preparation.parameters_digest,
                        preparation.request_digest,
                        decision.decision_id,
                        _COMMAND_STATUS,
                        occurred_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO cockpit_command_transitions (
                        command_id, sequence, from_status, to_status, actor,
                        occurred_at, ledger_event_id, ledger_hash
                    ) VALUES (?, 1, NULL, ?, ?, ?, ?, ?)
                    """,
                    (
                        preparation.command_id,
                        _COMMAND_STATUS,
                        actor,
                        occurred_at,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM cockpit_commands WHERE command_id = ?",
                    (preparation.command_id,),
                ).fetchone()
                assert row is not None
                return self._command_from_row(row)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("command admission conflicted", {"command_id": preparation.command_id}) from exc

    def get_command(self, command_id: str) -> CockpitCommandRecord:
        command_id = _identifier(command_id, "command_id")
        row = self.database.connection.execute(
            "SELECT * FROM cockpit_commands WHERE command_id = ?",
            (command_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("cockpit command does not exist", {"command_id": command_id})
        return self._command_from_row(row)

    def verify_command(self, command_id: str) -> CockpitVerification:
        command_id = _identifier(command_id, "command_id")
        defects: list[str] = []
        connection = self.database.connection
        row = connection.execute(
            "SELECT * FROM cockpit_commands WHERE command_id = ?",
            (command_id,),
        ).fetchone()
        if row is None:
            return CockpitVerification(command_id, ("COMMAND_NOT_FOUND",))
        parameters: dict[str, Any] | None = None
        preparation: CockpitCommandPreparation | None = None
        try:
            parameters = _decode_canonical_object(str(row["parameters_json"]), "parameters")
            preparation = self.prepare_command(
                str(row["command_id"]),
                str(row["session_id"]),
                str(row["snapshot_id"]),
                str(row["command_type"]),
                str(row["target"]),
                parameters,
            )
            if str(row["snapshot_digest"]) != preparation.snapshot_digest:
                defects.append("COMMAND_SNAPSHOT_DIGEST_MISMATCH")
            if str(row["parameters_digest"]) != preparation.parameters_digest:
                defects.append("COMMAND_PARAMETERS_DIGEST_MISMATCH")
            if str(row["request_digest"]) != preparation.request_digest:
                defects.append("COMMAND_REQUEST_DIGEST_MISMATCH")
            if str(row["status"]) != _COMMAND_STATUS:
                defects.append("COMMAND_STATUS_INVALID")
        except (TypeError, ValueError, ValidationError, IntegrityError, sqlite3.Error):
            defects.append("COMMAND_FIELDS_INVALID")
        transitions = connection.execute(
            "SELECT * FROM cockpit_command_transitions WHERE command_id = ? ORDER BY sequence",
            (command_id,),
        ).fetchall()
        if len(transitions) != 1:
            defects.append("COMMAND_TRANSITION_COUNT_INVALID")
        else:
            transition = transitions[0]
            if transition["from_status"] is not None or str(transition["to_status"]) != _COMMAND_STATUS:
                defects.append("COMMAND_TRANSITION_INVALID")
            if str(transition["ledger_event_id"]) != str(row["ledger_event_id"]):
                defects.append("COMMAND_TRANSITION_LEDGER_EVENT_MISMATCH")
            if str(transition["ledger_hash"]) != str(row["ledger_hash"]):
                defects.append("COMMAND_TRANSITION_LEDGER_HASH_MISMATCH")
            if str(transition["actor"]) != str(row["authorized_by"]):
                defects.append("COMMAND_TRANSITION_ACTOR_MISMATCH")
            if str(transition["occurred_at"]) != str(row["authorized_at"]):
                defects.append("COMMAND_TRANSITION_TIMESTAMP_MISMATCH")
        decision: AuthorizationDecision | None = None
        if preparation is not None:
            try:
                decision = self.trust.get_decision(str(row["authorization_decision_id"]))
                if not self.trust.verify_decision(decision.decision_id).ok:
                    defects.append("COMMAND_AUTHORIZATION_DECISION_INVALID")
                expected = AuthorizationRequest(
                    subject=str(row["authorized_by"]),
                    action=preparation.action,
                    resource=preparation.resource,
                    mission_id=preparation.mission_id,
                    context=dict(preparation.authorization_context),
                )
                if not decision.allowed:
                    defects.append("COMMAND_AUTHORIZATION_NOT_ALLOWED")
                if decision.request != expected:
                    defects.append("COMMAND_AUTHORIZATION_CONTEXT_MISMATCH")
                used_count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM cockpit_commands WHERE authorization_decision_id = ?",
                        (decision.decision_id,),
                    ).fetchone()[0]
                )
                if used_count != 1:
                    defects.append("COMMAND_AUTHORIZATION_SINGLE_USE_INVALID")
            except Exception:
                defects.append("COMMAND_AUTHORIZATION_MISSING")
        ledger_row = connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (str(row["ledger_event_id"]),),
        ).fetchone()
        if ledger_row is None:
            defects.append("COMMAND_LEDGER_EVENT_MISSING")
        else:
            if str(ledger_row["record_hash"]) != str(row["ledger_hash"]):
                defects.append("COMMAND_LEDGER_HASH_MISMATCH")
            if str(ledger_row["stream_id"]) != f"cockpit:command:{command_id}":
                defects.append("COMMAND_LEDGER_STREAM_MISMATCH")
            if str(ledger_row["kind"]) != "COCKPIT_COMMAND_AUTHORIZED":
                defects.append("COMMAND_LEDGER_KIND_MISMATCH")
            if str(ledger_row["actor"]) != str(row["authorized_by"]):
                defects.append("COMMAND_LEDGER_ACTOR_MISMATCH")
            if str(ledger_row["occurred_at"]) != str(row["authorized_at"]):
                defects.append("COMMAND_LEDGER_TIMESTAMP_MISMATCH")
            if preparation is not None and decision is not None and parameters is not None:
                expected_payload = {
                    "command": {
                        "command_id": preparation.command_id,
                        "session_id": preparation.session_id,
                        "session_subject": preparation.session_subject,
                        "snapshot_id": preparation.snapshot_id,
                        "snapshot_digest": preparation.snapshot_digest,
                        "command_type": preparation.command_type.value,
                        "target": preparation.target,
                        "parameters": parameters,
                        "parameters_digest": preparation.parameters_digest,
                        "request_digest": preparation.request_digest,
                    },
                    "authorization_decision_id": decision.decision_id,
                    "status": _COMMAND_STATUS,
                    "authorized_by": str(row["authorized_by"]),
                }
                try:
                    if json.loads(str(ledger_row["payload_json"])) != expected_payload:
                        defects.append("COMMAND_LEDGER_PAYLOAD_MISMATCH")
                except (TypeError, ValueError, json.JSONDecodeError):
                    defects.append("COMMAND_LEDGER_PAYLOAD_INVALID")
            if not self.ledger.verify(str(ledger_row["stream_id"])).ok:
                defects.append("COMMAND_LEDGER_CHAIN_INVALID")
        return CockpitVerification(command_id, tuple(dict.fromkeys(defects)))


class CockpitWSGIApp:
    """Bounded WSGI surface for local visualization and command authorization."""

    _HTML = (
        b"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        b"<meta name='viewport' content='width=device-width,initial-scale=1'>"
        b"<title>STARCOM Cockpit</title></head><body>"
        b"<main><h1>STARCOM Cockpit</h1><p>Local authorization surface.</p></main>"
        b"</body></html>"
    )

    def __init__(self, service: CockpitService, *, max_body_bytes: int = _DEFAULT_BODY_LIMIT) -> None:
        if not isinstance(max_body_bytes, int) or max_body_bytes < 1:
            raise ValidationError("max_body_bytes must be a positive integer")
        self.service = service
        self.max_body_bytes = max_body_bytes

    @staticmethod
    def _headers(content_type: str, length: int) -> list[tuple[str, str]]:
        return [
            ("Content-Type", content_type),
            ("Content-Length", str(length)),
            (
                "Content-Security-Policy",
                "default-src 'none'; base-uri 'none'; "
                "frame-ancestors 'none'; form-action 'none'",
            ),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            ("Cache-Control", "no-store"),
        ]

    @staticmethod
    def _header(environ: Mapping[str, object], name: str) -> str | None:
        value = environ.get(name)
        return str(value) if isinstance(value, str) else None

    def _session(self, environ: Mapping[str, object], *, csrf: bool = False):
        session_id = self._header(environ, "HTTP_X_COCKPIT_SESSION")
        authorization = self._header(environ, "HTTP_AUTHORIZATION")
        if not session_id or not authorization or not authorization.startswith("Bearer "):
            raise _HttpFailure("401 Unauthorized", "authentication is required", "AUTHENTICATION_REQUIRED")
        token = authorization[7:]
        try:
            session = self.service.authenticate(session_id, token)
        except AuthorizationError as exc:
            raise _HttpFailure("401 Unauthorized", str(exc), exc.code) from exc
        if csrf:
            csrf_token = self._header(environ, "HTTP_X_CSRF_TOKEN")
            if not csrf_token:
                raise _HttpFailure("403 Forbidden", "CSRF token is required", "CSRF_REQUIRED")
            try:
                self.service.verify_csrf(session, csrf_token)
            except AuthorizationError as exc:
                raise _HttpFailure("403 Forbidden", str(exc), exc.code) from exc
        return session

    def _body(self, environ: Mapping[str, object]) -> bytes:
        raw_length = self._header(environ, "CONTENT_LENGTH")
        if raw_length is not None:
            try:
                length = int(raw_length)
            except ValueError as exc:
                raise ValidationError("Content-Length must be an integer") from exc
            if length < 0:
                raise ValidationError("Content-Length cannot be negative")
            if length > self.max_body_bytes:
                raise _HttpFailure("413 Request Entity Too Large", "request body is too large", "BODY_TOO_LARGE")
        else:
            length = self.max_body_bytes + 1
        stream = environ.get("wsgi.input")
        if not hasattr(stream, "read"):
            raise ValidationError("request body stream is missing")
        body = stream.read(length)
        if not isinstance(body, bytes):
            raise ValidationError("request body must be bytes")
        if len(body) > self.max_body_bytes:
            raise _HttpFailure("413 Request Entity Too Large", "request body is too large", "BODY_TOO_LARGE")
        return body

    @staticmethod
    def _json_response(value: object) -> tuple[str, bytes]:
        body = canonical_json(value).encode("utf-8")
        return "application/json; charset=utf-8", body

    def _dispatch(self, environ: Mapping[str, object]) -> tuple[str, str, bytes, list[tuple[str, str]]]:
        method = self._header(environ, "REQUEST_METHOD") or ""
        path = self._header(environ, "PATH_INFO") or ""
        if path == "/":
            if method != "GET":
                raise _HttpFailure("405 Method Not Allowed", "method is not allowed", "METHOD_NOT_ALLOWED")
            return "200 OK", "text/html; charset=utf-8", self._HTML, [("Allow", "GET")]
        if path == "/api/v1/health":
            if method != "GET":
                raise _HttpFailure("405 Method Not Allowed", "method is not allowed", "METHOD_NOT_ALLOWED")
            content_type, body = self._json_response({"ok": True, "service": "starcom-cockpit"})
            return "200 OK", content_type, body, [("Allow", "GET")]
        if path == "/api/v1/snapshot":
            if method != "GET":
                raise _HttpFailure("405 Method Not Allowed", "method is not allowed", "METHOD_NOT_ALLOWED")
            self._session(environ)
            snapshot = self.service.get_latest_snapshot()
            content_type, body = self._json_response(snapshot.to_public_dict())
            return "200 OK", content_type, body, [("Allow", "GET")]
        if path == "/api/v1/commands" and method == "POST":
            session = self._session(environ, csrf=True)
            content_type = (self._header(environ, "CONTENT_TYPE") or "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                raise _HttpFailure("415 Unsupported Media Type", "application/json is required", "CONTENT_TYPE_REQUIRED")
            payload = parse_strict_json_object(self._body(environ), max_bytes=self.max_body_bytes, label="command")
            expected_keys = {
                "command_id",
                "snapshot_id",
                "command_type",
                "target",
                "parameters",
                "authorization_decision_id",
            }
            if set(payload) != expected_keys:
                raise ValidationError("command body has an unexpected or missing field")
            preparation = self.service.prepare_command(
                str(payload["command_id"]),
                session.session_id,
                str(payload["snapshot_id"]),
                str(payload["command_type"]),
                str(payload["target"]),
                payload["parameters"],  # type: ignore[arg-type]
            )
            record = self.service.authorize_command(
                preparation,
                authorization_decision_id=str(payload["authorization_decision_id"]),
                actor=session.subject,
            )
            content_type, body = self._json_response(record.to_public_dict())
            return "201 Created", content_type, body, [("Allow", "POST")]
        if path == "/api/v1/commands" and method != "POST":
            raise _HttpFailure("405 Method Not Allowed", "method is not allowed", "METHOD_NOT_ALLOWED")
        command_prefix = "/api/v1/commands/"
        if path.startswith(command_prefix) and len(path) > len(command_prefix):
            if method != "GET":
                raise _HttpFailure("405 Method Not Allowed", "method is not allowed", "METHOD_NOT_ALLOWED")
            self._session(environ)
            command = self.service.get_command(path[len(command_prefix) :])
            content_type, body = self._json_response(command.to_public_dict())
            return "200 OK", content_type, body, [("Allow", "GET")]
        raise _HttpFailure("404 Not Found", "route does not exist", "NOT_FOUND")

    def __call__(
        self,
        environ: Mapping[str, object],
        start_response: Callable[..., object],
    ) -> list[bytes]:
        try:
            status, content_type, body, extra_headers = self._dispatch(environ)
        except _HttpFailure as exc:
            status = exc.status
            content_type, body = self._json_response(
                {"error": exc.code, "message": exc.message}
            )
            extra_headers = []
        except StarcomError as exc:
            status = {
                "VALIDATION_ERROR": "400 Bad Request",
                "AUTHORIZATION_DENIED": "403 Forbidden",
                "CONFLICT": "409 Conflict",
                "NOT_FOUND": "404 Not Found",
                "INTEGRITY_ERROR": "409 Conflict",
            }.get(exc.code, "400 Bad Request")
            content_type, body = self._json_response(exc.to_dict())
            extra_headers = []
        except Exception:
            status = "500 Internal Server Error"
            content_type, body = self._json_response(
                {"error": "INTERNAL_ERROR", "message": "request could not be completed"}
            )
            extra_headers = []
        headers = self._headers(content_type, len(body)) + extra_headers
        start_response(status, headers)
        return [body]


CockpitCommand = CockpitCommandRecord
