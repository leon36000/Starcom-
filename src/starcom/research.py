from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import json
import re
import sqlite3
from typing import Any, Mapping
from uuid import uuid4

from .canonical import canonical_json, sha256_digest, utc_now
from .db import Database
from .errors import ConflictError, NotFoundError, StateTransitionError, ValidationError
from .ledger import EventLedger


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ReceiptOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    POLICY_BLOCK = "POLICY_BLOCK"
    ACCESS_BLOCK = "ACCESS_BLOCK"
    NETWORK_ERROR = "NETWORK_ERROR"
    NO_RESPONSE = "NO_RESPONSE"


class AttemptStatus(str, Enum):
    STARTED = "STARTED"
    RECEIPTED = "RECEIPTED"


@dataclass(frozen=True)
class Campaign:
    campaign_id: str
    name: str
    max_wave: int
    created_at: str
    updated_at: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class ResearchAttempt:
    attempt_id: str
    campaign_id: str
    wave: int
    request_key: str
    source_id: str
    request: Mapping[str, Any]
    request_digest: str
    status: AttemptStatus
    receipt_id: str | None
    started_at: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class ResearchReceipt:
    receipt_id: str
    attempt_id: str
    outcome: ReceiptOutcome
    status_code: int | None
    snapshot_digest: str | None
    metadata: Mapping[str, Any]
    received_at: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class ResearchObservation:
    observation_id: str
    attempt_id: str
    snapshot_digest: str
    content_digest: str
    data: Mapping[str, Any]
    observed_at: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class CursorCheckpoint:
    cursor_id: str
    campaign_id: str
    wave: int
    cursor_key: str
    value: Any
    value_digest: str
    attempt_id: str
    checkpoint_at: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class CampaignVerification:
    campaign_id: str
    attempt_count: int
    receipt_count: int
    observation_count: int
    cursor_count: int
    wave_sequence: tuple[int, ...]
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class ResearchCampaign:
    """Fail-closed campaign ledger requiring a durable pre-request attempt."""

    def __init__(self, database: Database, ledger: EventLedger) -> None:
        self.database = database
        self.ledger = ledger
        self._initialize_schema()

    @staticmethod
    def _required_text(value: str, name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{name} must be a non-empty string")
        return value

    @staticmethod
    def _validate_time(value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError("timestamp must be RFC 3339") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValidationError("timestamp must be timezone-aware")
        return value

    @staticmethod
    def _validate_digest(value: str, name: str) -> str:
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            raise ValidationError(f"{name} must be a lowercase SHA-256 hex digest")
        return value

    def _verify_row_ledger_link(
        self,
        row: sqlite3.Row,
        *,
        entity_prefix: str,
        entity_id: str,
        expected_stream: str,
        expected_kind: str,
        expected_occurred_at: str,
        expected_payload: Mapping[str, Any] | None,
        defects: list[str],
    ) -> None:
        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (str(row["ledger_event_id"]),),
        ).fetchone()
        if event is None:
            defects.append(f"{entity_prefix}_LEDGER_EVENT_MISSING:{entity_id}")
            return
        if str(event["stream_id"]) != expected_stream:
            defects.append(f"{entity_prefix}_LEDGER_STREAM_MISMATCH:{entity_id}")
        if str(event["kind"]) != expected_kind:
            defects.append(f"{entity_prefix}_LEDGER_KIND_MISMATCH:{entity_id}")
        if str(event["occurred_at"]) != expected_occurred_at:
            defects.append(f"{entity_prefix}_LEDGER_TIME_MISMATCH:{entity_id}")
        if str(event["record_hash"]) != str(row["ledger_hash"]):
            defects.append(f"{entity_prefix}_LEDGER_HASH_MISMATCH:{entity_id}")
        try:
            payload = json.loads(str(event["payload_json"]))
            if not isinstance(payload, dict):
                raise ValueError("ledger payload must decode to an object")
        except (json.JSONDecodeError, TypeError, ValueError):
            defects.append(f"{entity_prefix}_LEDGER_PAYLOAD_INVALID:{entity_id}")
            return
        if expected_payload is not None and payload != dict(expected_payload):
            defects.append(f"{entity_prefix}_LEDGER_PAYLOAD_MISMATCH:{entity_id}")

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS research_campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    max_wave INTEGER NOT NULL CHECK (max_wave >= 0),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS research_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    wave INTEGER NOT NULL CHECK (wave >= 1),
                    request_key TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
                    status TEXT NOT NULL CHECK (status IN ('STARTED','RECEIPTED')),
                    receipt_id TEXT UNIQUE,
                    started_at TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    UNIQUE (campaign_id, request_key),
                    FOREIGN KEY (campaign_id) REFERENCES research_campaigns(campaign_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS research_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    attempt_id TEXT NOT NULL UNIQUE,
                    outcome TEXT NOT NULL CHECK (
                        outcome IN ('SUCCESS','POLICY_BLOCK','ACCESS_BLOCK','NETWORK_ERROR','NO_RESPONSE')
                    ),
                    status_code INTEGER,
                    snapshot_digest TEXT,
                    metadata_json TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (attempt_id) REFERENCES research_attempts(attempt_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS research_observations (
                    observation_id TEXT PRIMARY KEY,
                    attempt_id TEXT NOT NULL,
                    snapshot_digest TEXT NOT NULL CHECK (length(snapshot_digest) = 64),
                    content_digest TEXT NOT NULL CHECK (length(content_digest) = 64),
                    data_json TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (attempt_id) REFERENCES research_attempts(attempt_id)
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS research_observations_attempt_idx "
                "ON research_observations(attempt_id, observation_id)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS research_cursors (
                    cursor_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    wave INTEGER NOT NULL CHECK (wave >= 1),
                    cursor_key TEXT NOT NULL,
                    value_json TEXT NOT NULL,
                    value_digest TEXT NOT NULL CHECK (length(value_digest) = 64),
                    attempt_id TEXT NOT NULL,
                    checkpoint_at TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    UNIQUE (campaign_id, wave, cursor_key),
                    FOREIGN KEY (campaign_id) REFERENCES research_campaigns(campaign_id),
                    FOREIGN KEY (attempt_id) REFERENCES research_attempts(attempt_id)
                )
                """
            )
            for table in (
                "research_receipts",
                "research_observations",
                "research_cursors",
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
    def _row_to_campaign(row: sqlite3.Row) -> Campaign:
        return Campaign(
            campaign_id=str(row["campaign_id"]),
            name=str(row["name"]),
            max_wave=int(row["max_wave"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    @staticmethod
    def _row_to_attempt(row: sqlite3.Row) -> ResearchAttempt:
        return ResearchAttempt(
            attempt_id=str(row["attempt_id"]),
            campaign_id=str(row["campaign_id"]),
            wave=int(row["wave"]),
            request_key=str(row["request_key"]),
            source_id=str(row["source_id"]),
            request=dict(json.loads(str(row["request_json"]))),
            request_digest=str(row["request_digest"]),
            status=AttemptStatus(str(row["status"])),
            receipt_id=str(row["receipt_id"]) if row["receipt_id"] is not None else None,
            started_at=str(row["started_at"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def create(
        self,
        *,
        campaign_id: str | None = None,
        name: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> Campaign:
        campaign_id = self._required_text(campaign_id or str(uuid4()), "campaign_id")
        name = self._required_text(name, "name")
        actor = self._required_text(actor, "actor")
        occurred_at = self._validate_time(occurred_at or utc_now())
        try:
            with self.database.transaction() as connection:
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"research:campaign:{campaign_id}",
                    "CAMPAIGN_CREATED",
                    {"campaign_id": campaign_id, "name": name},
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO research_campaigns (
                        campaign_id, name, max_wave, created_at, updated_at,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, 0, ?, ?, ?, ?)
                    """,
                    (
                        campaign_id,
                        name,
                        occurred_at,
                        occurred_at,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("campaign already exists", {"campaign_id": campaign_id}) from exc
        return self.get_campaign(campaign_id)

    def get_campaign(self, campaign_id: str) -> Campaign:
        row = self.database.connection.execute(
            "SELECT * FROM research_campaigns WHERE campaign_id = ?",
            (campaign_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("campaign does not exist", {"campaign_id": campaign_id})
        return self._row_to_campaign(row)

    def get_attempt(self, attempt_id: str) -> ResearchAttempt:
        row = self.database.connection.execute(
            "SELECT * FROM research_attempts WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("research attempt does not exist", {"attempt_id": attempt_id})
        return self._row_to_attempt(row)

    def begin_attempt(
        self,
        campaign_id: str,
        *,
        wave: int,
        request_key: str,
        source_id: str,
        request: Mapping[str, Any],
        actor: str,
        attempt_id: str | None = None,
        occurred_at: str | None = None,
    ) -> ResearchAttempt:
        campaign_id = self._required_text(campaign_id, "campaign_id")
        request_key = self._required_text(request_key, "request_key")
        source_id = self._required_text(source_id, "source_id")
        actor = self._required_text(actor, "actor")
        attempt_id = self._required_text(attempt_id or str(uuid4()), "attempt_id")
        if not isinstance(wave, int) or wave < 1:
            raise ValidationError("wave must be an integer >= 1")
        occurred_at = self._validate_time(occurred_at or utc_now())
        request_json = canonical_json(dict(request))
        request_material = {
            "campaign_id": campaign_id,
            "wave": wave,
            "source_id": source_id,
            "request": dict(request),
        }
        request_digest = sha256_digest(request_material)

        with self.database.transaction() as connection:
            campaign = connection.execute(
                "SELECT * FROM research_campaigns WHERE campaign_id = ?",
                (campaign_id,),
            ).fetchone()
            if campaign is None:
                raise NotFoundError("campaign does not exist", {"campaign_id": campaign_id})
            existing = connection.execute(
                """
                SELECT * FROM research_attempts
                WHERE campaign_id = ? AND request_key = ?
                """,
                (campaign_id, request_key),
            ).fetchone()
            if existing is not None:
                if str(existing["request_digest"]) != request_digest:
                    raise ConflictError(
                        "request key was reused with a different research request",
                        {"campaign_id": campaign_id, "request_key": request_key},
                    )
                return self._row_to_attempt(existing)
            max_wave = int(campaign["max_wave"])
            if wave < max_wave:
                raise StateTransitionError(
                    "wave regression is forbidden",
                    {
                        "campaign_id": campaign_id,
                        "current_max_wave": max_wave,
                        "requested_wave": wave,
                    },
                )
            receipt = self.ledger.append_in_transaction(
                connection,
                f"research:campaign:{campaign_id}",
                "RESEARCH_ATTEMPT_STARTED",
                {
                    "attempt_id": attempt_id,
                    "campaign_id": campaign_id,
                    "wave": wave,
                    "request_key": request_key,
                    "source_id": source_id,
                    "request": dict(request),
                    "request_digest": request_digest,
                    "pre_request_persisted": True,
                },
                actor=actor,
                occurred_at=occurred_at,
            )
            try:
                connection.execute(
                    """
                    INSERT INTO research_attempts (
                        attempt_id, campaign_id, wave, request_key, source_id,
                        request_json, request_digest, status, receipt_id,
                        started_at, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
                    """,
                    (
                        attempt_id,
                        campaign_id,
                        wave,
                        request_key,
                        source_id,
                        request_json,
                        request_digest,
                        AttemptStatus.STARTED.value,
                        occurred_at,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("research attempt already exists") from exc
            connection.execute(
                """
                UPDATE research_campaigns
                SET max_wave = CASE WHEN max_wave < ? THEN ? ELSE max_wave END,
                    updated_at = ?, ledger_event_id = ?, ledger_hash = ?
                WHERE campaign_id = ?
                """,
                (
                    wave,
                    wave,
                    occurred_at,
                    receipt.event_id,
                    receipt.record_hash,
                    campaign_id,
                ),
            )
            row = connection.execute(
                "SELECT * FROM research_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            assert row is not None
            return self._row_to_attempt(row)

    def record_receipt(
        self,
        attempt_id: str,
        *,
        receipt_id: str | None = None,
        outcome: ReceiptOutcome,
        status_code: int | None,
        snapshot_digest: str | None,
        metadata: Mapping[str, Any],
        actor: str,
        occurred_at: str | None = None,
    ) -> ResearchReceipt:
        attempt_id = self._required_text(attempt_id, "attempt_id")
        receipt_id = self._required_text(receipt_id or str(uuid4()), "receipt_id")
        actor = self._required_text(actor, "actor")
        if not isinstance(outcome, ReceiptOutcome):
            try:
                outcome = ReceiptOutcome(str(outcome))
            except ValueError as exc:
                raise ValidationError("unknown receipt outcome") from exc
        if status_code is not None and (
            not isinstance(status_code, int) or not 100 <= status_code <= 599
        ):
            raise ValidationError("status_code must be between 100 and 599")
        if outcome is ReceiptOutcome.SUCCESS and snapshot_digest is None:
            raise StateTransitionError("successful receipt requires a snapshot digest")
        if snapshot_digest is not None:
            snapshot_digest = self._validate_digest(snapshot_digest, "snapshot_digest")
        occurred_at = self._validate_time(occurred_at or utc_now())
        metadata_json = canonical_json(dict(metadata))

        try:
            with self.database.transaction() as connection:
                attempt = connection.execute(
                    "SELECT * FROM research_attempts WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()
                if attempt is None:
                    raise NotFoundError(
                        "research attempt does not exist",
                        {"attempt_id": attempt_id},
                    )
                if attempt["receipt_id"] is not None:
                    raise ConflictError(
                        "research attempt already has a receipt",
                        {"attempt_id": attempt_id},
                    )
                campaign_id = str(attempt["campaign_id"])
                payload = {
                    "receipt_id": receipt_id,
                    "attempt_id": attempt_id,
                    "outcome": outcome.value,
                    "status_code": status_code,
                    "snapshot_digest": snapshot_digest,
                    "metadata": dict(metadata),
                }
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"research:campaign:{campaign_id}",
                    "RESEARCH_RECEIPT_RECORDED",
                    payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO research_receipts (
                        receipt_id, attempt_id, outcome, status_code,
                        snapshot_digest, metadata_json, received_at,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        receipt_id,
                        attempt_id,
                        outcome.value,
                        status_code,
                        snapshot_digest,
                        metadata_json,
                        occurred_at,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
                connection.execute(
                    """
                    UPDATE research_attempts
                    SET status = ?, receipt_id = ?
                    WHERE attempt_id = ?
                    """,
                    (AttemptStatus.RECEIPTED.value, receipt_id, attempt_id),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("receipt already exists", {"receipt_id": receipt_id}) from exc
        return ResearchReceipt(
            receipt_id=receipt_id,
            attempt_id=attempt_id,
            outcome=outcome,
            status_code=status_code,
            snapshot_digest=snapshot_digest,
            metadata=dict(metadata),
            received_at=occurred_at,
            ledger_event_id=receipt.event_id,
            ledger_hash=receipt.record_hash,
        )

    def record_observation(
        self,
        attempt_id: str,
        *,
        observation_id: str | None = None,
        snapshot_digest: str,
        content_digest: str,
        data: Mapping[str, Any],
        actor: str,
        occurred_at: str | None = None,
    ) -> ResearchObservation:
        attempt_id = self._required_text(attempt_id, "attempt_id")
        observation_id = self._required_text(
            observation_id or str(uuid4()), "observation_id"
        )
        snapshot_digest = self._validate_digest(snapshot_digest, "snapshot_digest")
        content_digest = self._validate_digest(content_digest, "content_digest")
        actor = self._required_text(actor, "actor")
        occurred_at = self._validate_time(occurred_at or utc_now())
        data_json = canonical_json(dict(data))

        try:
            with self.database.transaction() as connection:
                attempt = connection.execute(
                    "SELECT * FROM research_attempts WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()
                if attempt is None:
                    raise NotFoundError("research attempt does not exist")
                receipt_row = connection.execute(
                    "SELECT * FROM research_receipts WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()
                if receipt_row is None:
                    raise StateTransitionError(
                        "observation requires a terminal receipt for the attempt"
                    )
                if str(receipt_row["outcome"]) != ReceiptOutcome.SUCCESS.value:
                    raise StateTransitionError(
                        "observations may only be attached to successful receipts"
                    )
                if str(receipt_row["snapshot_digest"]) != snapshot_digest:
                    raise StateTransitionError(
                        "observation snapshot does not match receipt snapshot"
                    )
                campaign_id = str(attempt["campaign_id"])
                payload = {
                    "observation_id": observation_id,
                    "attempt_id": attempt_id,
                    "snapshot_digest": snapshot_digest,
                    "content_digest": content_digest,
                    "data": dict(data),
                }
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"research:campaign:{campaign_id}",
                    "RESEARCH_OBSERVATION_RECORDED",
                    payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO research_observations (
                        observation_id, attempt_id, snapshot_digest,
                        content_digest, data_json, observed_at,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        observation_id,
                        attempt_id,
                        snapshot_digest,
                        content_digest,
                        data_json,
                        occurred_at,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "observation already exists", {"observation_id": observation_id}
            ) from exc
        return ResearchObservation(
            observation_id=observation_id,
            attempt_id=attempt_id,
            snapshot_digest=snapshot_digest,
            content_digest=content_digest,
            data=dict(data),
            observed_at=occurred_at,
            ledger_event_id=receipt.event_id,
            ledger_hash=receipt.record_hash,
        )

    def checkpoint_cursor(
        self,
        campaign_id: str,
        *,
        wave: int,
        cursor_key: str,
        value: Any,
        attempt_id: str,
        actor: str,
        cursor_id: str | None = None,
        occurred_at: str | None = None,
    ) -> CursorCheckpoint:
        campaign_id = self._required_text(campaign_id, "campaign_id")
        cursor_key = self._required_text(cursor_key, "cursor_key")
        attempt_id = self._required_text(attempt_id, "attempt_id")
        actor = self._required_text(actor, "actor")
        cursor_id = self._required_text(cursor_id or str(uuid4()), "cursor_id")
        if not isinstance(wave, int) or wave < 1:
            raise ValidationError("wave must be an integer >= 1")
        occurred_at = self._validate_time(occurred_at or utc_now())
        value_json = canonical_json(value)
        value_digest = sha256_digest(value)

        try:
            with self.database.transaction() as connection:
                attempt = connection.execute(
                    "SELECT * FROM research_attempts WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()
                if attempt is None:
                    raise NotFoundError("research attempt does not exist")
                if str(attempt["campaign_id"]) != campaign_id:
                    raise StateTransitionError("cursor attempt belongs to a different campaign")
                if int(attempt["wave"]) != wave:
                    raise StateTransitionError("cursor wave does not match attempt wave")
                receipt_row = connection.execute(
                    "SELECT * FROM research_receipts WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()
                if receipt_row is None:
                    raise StateTransitionError("cursor checkpoint requires an attempt receipt")
                payload = {
                    "cursor_id": cursor_id,
                    "campaign_id": campaign_id,
                    "wave": wave,
                    "cursor_key": cursor_key,
                    "value": value,
                    "value_digest": value_digest,
                    "attempt_id": attempt_id,
                }
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"research:campaign:{campaign_id}",
                    "RESEARCH_CURSOR_CHECKPOINTED",
                    payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO research_cursors (
                        cursor_id, campaign_id, wave, cursor_key, value_json,
                        value_digest, attempt_id, checkpoint_at,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cursor_id,
                        campaign_id,
                        wave,
                        cursor_key,
                        value_json,
                        value_digest,
                        attempt_id,
                        occurred_at,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "cursor checkpoint already exists",
                {"campaign_id": campaign_id, "wave": wave, "cursor_key": cursor_key},
            ) from exc
        return CursorCheckpoint(
            cursor_id=cursor_id,
            campaign_id=campaign_id,
            wave=wave,
            cursor_key=cursor_key,
            value=json.loads(value_json),
            value_digest=value_digest,
            attempt_id=attempt_id,
            checkpoint_at=occurred_at,
            ledger_event_id=receipt.event_id,
            ledger_hash=receipt.record_hash,
        )

    def verify(self, campaign_id: str) -> CampaignVerification:
        campaign = self.database.connection.execute(
            "SELECT * FROM research_campaigns WHERE campaign_id = ?",
            (campaign_id,),
        ).fetchone()
        if campaign is None:
            raise NotFoundError("campaign does not exist", {"campaign_id": campaign_id})
        attempts = self.database.connection.execute(
            """
            SELECT a.*, e.sequence AS ledger_sequence
            FROM research_attempts AS a
            LEFT JOIN ledger_events AS e ON e.event_id = a.ledger_event_id
            WHERE a.campaign_id = ?
            ORDER BY e.sequence, a.attempt_id
            """,
            (campaign_id,),
        ).fetchall()
        defects: list[str] = []
        wave_sequence = tuple(int(row["wave"]) for row in attempts)
        prior_wave = 0
        receipt_count = 0
        observation_count = 0
        cursor_count = 0

        for attempt in attempts:
            attempt_id = str(attempt["attempt_id"])
            wave = int(attempt["wave"])
            if wave < prior_wave:
                defects.append(f"WAVE_REGRESSION:{prior_wave}->{wave}:{attempt_id}")
            prior_wave = wave
            request: dict[str, Any] | None = None
            try:
                decoded_request = json.loads(str(attempt["request_json"]))
                if not isinstance(decoded_request, dict):
                    raise ValueError("request_json must decode to an object")
                request = decoded_request
            except (json.JSONDecodeError, TypeError, ValueError):
                defects.append(f"ATTEMPT_REQUEST_JSON_INVALID:{attempt_id}")
            else:
                expected_request_digest = sha256_digest(
                    {
                        "campaign_id": campaign_id,
                        "wave": wave,
                        "source_id": str(attempt["source_id"]),
                        "request": request,
                    }
                )
                if expected_request_digest != str(attempt["request_digest"]):
                    defects.append(f"ATTEMPT_REQUEST_DIGEST_MISMATCH:{attempt_id}")
            attempt_payload = None
            if request is not None:
                attempt_payload = {
                    "attempt_id": attempt_id,
                    "campaign_id": campaign_id,
                    "wave": wave,
                    "request_key": str(attempt["request_key"]),
                    "source_id": str(attempt["source_id"]),
                    "request": request,
                    "request_digest": str(attempt["request_digest"]),
                    "pre_request_persisted": True,
                }
            self._verify_row_ledger_link(
                attempt,
                entity_prefix="ATTEMPT",
                entity_id=attempt_id,
                expected_stream=f"research:campaign:{campaign_id}",
                expected_kind="RESEARCH_ATTEMPT_STARTED",
                expected_occurred_at=str(attempt["started_at"]),
                expected_payload=attempt_payload,
                defects=defects,
            )

            receipt = self.database.connection.execute(
                "SELECT * FROM research_receipts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if receipt is None:
                defects.append(f"ATTEMPT_RECEIPT_MISSING:{attempt_id}")
                if (
                    str(attempt["status"]) != AttemptStatus.STARTED.value
                    or attempt["receipt_id"] is not None
                ):
                    defects.append(f"ATTEMPT_RECEIPT_LINKAGE_INVALID:{attempt_id}")
                continue
            receipt_count += 1
            if (
                str(attempt["status"]) != AttemptStatus.RECEIPTED.value
                or str(attempt["receipt_id"]) != str(receipt["receipt_id"])
            ):
                defects.append(f"ATTEMPT_RECEIPT_LINKAGE_INVALID:{attempt_id}")

            receipt_id = str(receipt["receipt_id"])
            receipt_metadata: dict[str, Any] | None = None
            try:
                decoded_metadata = json.loads(str(receipt["metadata_json"]))
                if not isinstance(decoded_metadata, dict):
                    raise ValueError("metadata_json must decode to an object")
                receipt_metadata = decoded_metadata
            except (json.JSONDecodeError, TypeError, ValueError):
                defects.append(f"RECEIPT_METADATA_JSON_INVALID:{receipt_id}")
            try:
                outcome = ReceiptOutcome(str(receipt["outcome"]))
            except ValueError:
                outcome = None
                defects.append(f"RECEIPT_OUTCOME_INVALID:{receipt_id}")
            receipt_payload = None
            if receipt_metadata is not None:
                receipt_payload = {
                    "receipt_id": receipt_id,
                    "attempt_id": attempt_id,
                    "outcome": str(receipt["outcome"]),
                    "status_code": receipt["status_code"],
                    "snapshot_digest": receipt["snapshot_digest"],
                    "metadata": receipt_metadata,
                }
            self._verify_row_ledger_link(
                receipt,
                entity_prefix="RECEIPT",
                entity_id=receipt_id,
                expected_stream=f"research:campaign:{campaign_id}",
                expected_kind="RESEARCH_RECEIPT_RECORDED",
                expected_occurred_at=str(receipt["received_at"]),
                expected_payload=receipt_payload,
                defects=defects,
            )

            observations = self.database.connection.execute(
                """
                SELECT * FROM research_observations
                WHERE attempt_id = ? ORDER BY observation_id
                """,
                (attempt_id,),
            ).fetchall()
            observation_count += len(observations)
            if outcome is ReceiptOutcome.SUCCESS and not observations:
                defects.append(f"SUCCESS_OBSERVATION_MISSING:{attempt_id}")
            snapshot = receipt["snapshot_digest"]
            if outcome is ReceiptOutcome.SUCCESS and (
                snapshot is None or not _SHA256_RE.fullmatch(str(snapshot))
            ):
                defects.append(f"SUCCESS_SNAPSHOT_INVALID:{attempt_id}")
            for observation in observations:
                observation_id = str(observation["observation_id"])
                observation_data: dict[str, Any] | None = None
                try:
                    decoded_data = json.loads(str(observation["data_json"]))
                    if not isinstance(decoded_data, dict):
                        raise ValueError("data_json must decode to an object")
                    observation_data = decoded_data
                except (json.JSONDecodeError, TypeError, ValueError):
                    defects.append(f"OBSERVATION_DATA_JSON_INVALID:{observation_id}")
                observation_payload = None
                if observation_data is not None:
                    observation_payload = {
                        "observation_id": observation_id,
                        "attempt_id": attempt_id,
                        "snapshot_digest": str(observation["snapshot_digest"]),
                        "content_digest": str(observation["content_digest"]),
                        "data": observation_data,
                    }
                self._verify_row_ledger_link(
                    observation,
                    entity_prefix="OBSERVATION",
                    entity_id=observation_id,
                    expected_stream=f"research:campaign:{campaign_id}",
                    expected_kind="RESEARCH_OBSERVATION_RECORDED",
                    expected_occurred_at=str(observation["observed_at"]),
                    expected_payload=observation_payload,
                    defects=defects,
                )
                if outcome is ReceiptOutcome.SUCCESS and str(
                    observation["snapshot_digest"]
                ) != str(snapshot):
                    defects.append(f"OBSERVATION_SNAPSHOT_MISMATCH:{observation_id}")
                if not _SHA256_RE.fullmatch(str(observation["content_digest"])):
                    defects.append(f"OBSERVATION_CONTENT_DIGEST_INVALID:{observation_id}")

            cursors = self.database.connection.execute(
                """
                SELECT * FROM research_cursors
                WHERE attempt_id = ? ORDER BY cursor_id
                """,
                (attempt_id,),
            ).fetchall()
            cursor_count += len(cursors)
            if outcome is ReceiptOutcome.SUCCESS and not cursors:
                defects.append(f"SUCCESS_CURSOR_MISSING:{attempt_id}")
            for cursor in cursors:
                cursor_id = str(cursor["cursor_id"])
                if str(cursor["campaign_id"]) != campaign_id or int(cursor["wave"]) != wave:
                    defects.append(f"CURSOR_LINKAGE_INVALID:{cursor_id}")
                value: Any | None = None
                value_valid = False
                try:
                    value = json.loads(str(cursor["value_json"]))
                    value_valid = True
                except (json.JSONDecodeError, TypeError):
                    defects.append(f"CURSOR_VALUE_JSON_INVALID:{cursor_id}")
                if value_valid and sha256_digest(value) != str(cursor["value_digest"]):
                    defects.append(f"CURSOR_DIGEST_MISMATCH:{cursor_id}")
                cursor_payload = None
                if value_valid:
                    cursor_payload = {
                        "cursor_id": cursor_id,
                        "campaign_id": str(cursor["campaign_id"]),
                        "wave": int(cursor["wave"]),
                        "cursor_key": str(cursor["cursor_key"]),
                        "value": value,
                        "value_digest": str(cursor["value_digest"]),
                        "attempt_id": attempt_id,
                    }
                self._verify_row_ledger_link(
                    cursor,
                    entity_prefix="CURSOR",
                    entity_id=cursor_id,
                    expected_stream=f"research:campaign:{campaign_id}",
                    expected_kind="RESEARCH_CURSOR_CHECKPOINTED",
                    expected_occurred_at=str(cursor["checkpoint_at"]),
                    expected_payload=cursor_payload,
                    defects=defects,
                )

        expected_max_wave = max(wave_sequence, default=0)
        if int(campaign["max_wave"]) != expected_max_wave:
            defects.append("CAMPAIGN_MAX_WAVE_MISMATCH")
        if not self.ledger.verify(f"research:campaign:{campaign_id}").ok:
            defects.append("CAMPAIGN_LEDGER_CHAIN_INVALID")

        return CampaignVerification(
            campaign_id=campaign_id,
            attempt_count=len(attempts),
            receipt_count=receipt_count,
            observation_count=observation_count,
            cursor_count=cursor_count,
            wave_sequence=wave_sequence,
            defects=tuple(dict.fromkeys(defects)),
        )
