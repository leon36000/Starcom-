from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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


class EffectStatus(str, Enum):
    PENDING = "PENDING"
    LEASED = "LEASED"
    SUCCEEDED = "SUCCEEDED"
    TERMINAL_FAILED = "TERMINAL_FAILED"


@dataclass(frozen=True)
class EffectRecord:
    effect_id: str
    idempotency_key: str
    topic: str
    payload: Mapping[str, Any]
    request_digest: str
    status: EffectStatus
    attempt_count: int
    max_attempts: int
    available_at: str
    lease_owner: str | None
    lease_token: str | None
    lease_expires_at: str | None
    last_error: str | None
    result_digest: str | None
    created_at: str
    updated_at: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class EffectLease:
    effect_id: str
    idempotency_key: str
    topic: str
    payload: Mapping[str, Any]
    worker_id: str
    lease_token: str
    lease_expires_at: str
    attempt_count: int
    max_attempts: int


class DurableOutbox:
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
    def _parse_time(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError("timestamp must be RFC 3339") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValidationError("timestamp must be timezone-aware")
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _format_time(value: datetime) -> str:
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    @staticmethod
    def _validate_digest(value: str) -> str:
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            raise ValidationError("result_digest must be a lowercase SHA-256 hex digest")
        return value

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS durable_effects (
                    effect_id TEXT PRIMARY KEY,
                    topic TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
                    status TEXT NOT NULL CHECK (
                        status IN ('PENDING','LEASED','SUCCEEDED','TERMINAL_FAILED')
                    ),
                    attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0),
                    max_attempts INTEGER NOT NULL CHECK (max_attempts >= 1),
                    available_at TEXT NOT NULL,
                    lease_owner TEXT,
                    lease_token TEXT UNIQUE,
                    lease_expires_at TEXT,
                    last_error TEXT,
                    result_digest TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64)
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS durable_effects_claim_idx "
                "ON durable_effects(status, available_at, created_at, effect_id)"
            )

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> EffectRecord:
        return EffectRecord(
            effect_id=str(row["effect_id"]),
            idempotency_key=str(row["effect_id"]),
            topic=str(row["topic"]),
            payload=dict(json.loads(str(row["payload_json"]))),
            request_digest=str(row["request_digest"]),
            status=EffectStatus(str(row["status"])),
            attempt_count=int(row["attempt_count"]),
            max_attempts=int(row["max_attempts"]),
            available_at=str(row["available_at"]),
            lease_owner=str(row["lease_owner"]) if row["lease_owner"] is not None else None,
            lease_token=str(row["lease_token"]) if row["lease_token"] is not None else None,
            lease_expires_at=(
                str(row["lease_expires_at"]) if row["lease_expires_at"] is not None else None
            ),
            last_error=str(row["last_error"]) if row["last_error"] is not None else None,
            result_digest=(
                str(row["result_digest"]) if row["result_digest"] is not None else None
            ),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def get(self, effect_id: str) -> EffectRecord:
        row = self.database.connection.execute(
            "SELECT * FROM durable_effects WHERE effect_id = ?",
            (effect_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("effect does not exist", {"effect_id": effect_id})
        return self._row_to_record(row)

    def enqueue_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        effect_id: str | None = None,
        topic: str,
        payload: Mapping[str, Any],
        max_attempts: int = 3,
        available_at: str | None = None,
        actor: str,
        occurred_at: str | None = None,
    ) -> EffectRecord:
        effect_id = self._required_text(effect_id or str(uuid4()), "effect_id")
        topic = self._required_text(topic, "topic")
        actor = self._required_text(actor, "actor")
        if not isinstance(max_attempts, int) or max_attempts < 1:
            raise ValidationError("max_attempts must be an integer >= 1")
        occurred_at = occurred_at or utc_now()
        self._parse_time(occurred_at)
        available_at = available_at or occurred_at
        self._parse_time(available_at)
        payload_json = canonical_json(dict(payload))
        request_material = {
            "effect_id": effect_id,
            "topic": topic,
            "payload": dict(payload),
            "max_attempts": max_attempts,
        }
        request_digest = sha256_digest(request_material)

        existing = connection.execute(
            "SELECT * FROM durable_effects WHERE effect_id = ?",
            (effect_id,),
        ).fetchone()
        if existing is not None:
            if str(existing["request_digest"]) != request_digest:
                raise ConflictError(
                    "effect idempotency key was reused with a different payload",
                    {"effect_id": effect_id},
                )
            return self._row_to_record(existing)
        receipt = self.ledger.append_in_transaction(
            connection,
            f"durable:effect:{effect_id}",
            "EFFECT_ENQUEUED",
            request_material | {"available_at": available_at},
            actor=actor,
            occurred_at=occurred_at,
        )
        connection.execute(
            """
            INSERT INTO durable_effects (
                effect_id, topic, payload_json, request_digest, status,
                attempt_count, max_attempts, available_at, lease_owner,
                lease_token, lease_expires_at, last_error, result_digest,
                created_at, updated_at, ledger_event_id, ledger_hash
            ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, NULL, NULL, NULL, NULL, NULL, ?, ?, ?, ?)
            """,
            (
                effect_id,
                topic,
                payload_json,
                request_digest,
                EffectStatus.PENDING.value,
                max_attempts,
                available_at,
                occurred_at,
                occurred_at,
                receipt.event_id,
                receipt.record_hash,
            ),
        )
        row = connection.execute(
            "SELECT * FROM durable_effects WHERE effect_id = ?",
            (effect_id,),
        ).fetchone()
        assert row is not None
        return self._row_to_record(row)

    def enqueue(
        self,
        *,
        effect_id: str | None = None,
        topic: str,
        payload: Mapping[str, Any],
        max_attempts: int = 3,
        available_at: str | None = None,
        actor: str,
        occurred_at: str | None = None,
    ) -> EffectRecord:
        with self.database.transaction() as connection:
            return self.enqueue_in_transaction(
                connection,
                effect_id=effect_id,
                topic=topic,
                payload=payload,
                max_attempts=max_attempts,
                available_at=available_at,
                actor=actor,
                occurred_at=occurred_at,
            )


    def claim(
        self,
        worker_id: str,
        *,
        now: str | None = None,
        lease_seconds: int = 60,
        limit: int = 1,
        topic: str | None = None,
    ) -> list[EffectLease]:
        worker_id = self._required_text(worker_id, "worker_id")
        if topic is not None:
            topic = self._required_text(topic, "topic")
        if not isinstance(lease_seconds, int) or lease_seconds < 1:
            raise ValidationError("lease_seconds must be an integer >= 1")
        if not isinstance(limit, int) or limit < 1:
            raise ValidationError("limit must be an integer >= 1")
        now = now or utc_now()
        now_value = self._parse_time(now)
        expires_at = self._format_time(now_value + timedelta(seconds=lease_seconds))
        leases: list[EffectLease] = []

        with self.database.transaction() as connection:
            conditions = ["status = ?", "available_at <= ?"]
            parameters: list[object] = [
                EffectStatus.PENDING.value,
                now,
            ]
            if topic is not None:
                conditions.append("topic = ?")
                parameters.append(topic)
            parameters.append(limit)
            rows = connection.execute(
                "SELECT * FROM durable_effects WHERE "
                + " AND ".join(conditions)
                + " ORDER BY available_at, created_at, effect_id LIMIT ?",
                tuple(parameters),
            ).fetchall()
            for row in rows:
                effect_id = str(row["effect_id"])
                lease_token = str(uuid4())
                attempt_count = int(row["attempt_count"]) + 1
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"durable:effect:{effect_id}",
                    "EFFECT_LEASED",
                    {
                        "effect_id": effect_id,
                        "worker_id": worker_id,
                        "lease_token": lease_token,
                        "lease_expires_at": expires_at,
                        "attempt_count": attempt_count,
                    },
                    actor=worker_id,
                    occurred_at=now,
                )
                updated = connection.execute(
                    """
                    UPDATE durable_effects
                    SET status = ?, attempt_count = ?, lease_owner = ?,
                        lease_token = ?, lease_expires_at = ?, updated_at = ?,
                        ledger_event_id = ?, ledger_hash = ?
                    WHERE effect_id = ? AND status = ?
                    """,
                    (
                        EffectStatus.LEASED.value,
                        attempt_count,
                        worker_id,
                        lease_token,
                        expires_at,
                        now,
                        receipt.event_id,
                        receipt.record_hash,
                        effect_id,
                        EffectStatus.PENDING.value,
                    ),
                )
                if updated.rowcount != 1:
                    raise ConflictError("effect was claimed concurrently", {"effect_id": effect_id})
                leases.append(
                    EffectLease(
                        effect_id=effect_id,
                        idempotency_key=effect_id,
                        topic=str(row["topic"]),
                        payload=dict(json.loads(str(row["payload_json"]))),
                        worker_id=worker_id,
                        lease_token=lease_token,
                        lease_expires_at=expires_at,
                        attempt_count=attempt_count,
                        max_attempts=int(row["max_attempts"]),
                    )
                )
        return leases

    def _require_lease(
        self,
        row: sqlite3.Row,
        *,
        worker_id: str,
        lease_token: str,
        occurred_at: str,
    ) -> None:
        if str(row["status"]) != EffectStatus.LEASED.value:
            raise StateTransitionError("effect does not have an active lease")
        if str(row["lease_owner"]) != worker_id or str(row["lease_token"]) != lease_token:
            raise StateTransitionError("lease owner or token does not match")
        expires_at = self._parse_time(str(row["lease_expires_at"]))
        if self._parse_time(occurred_at) >= expires_at:
            raise StateTransitionError("lease has expired")

    def succeed(
        self,
        effect_id: str,
        *,
        worker_id: str,
        lease_token: str,
        result_digest: str,
        occurred_at: str | None = None,
    ) -> EffectRecord:
        effect_id = self._required_text(effect_id, "effect_id")
        worker_id = self._required_text(worker_id, "worker_id")
        lease_token = self._required_text(lease_token, "lease_token")
        result_digest = self._validate_digest(result_digest)
        occurred_at = occurred_at or utc_now()
        self._parse_time(occurred_at)
        with self.database.transaction() as connection:
            return self.succeed_in_transaction(
                connection,
                effect_id=effect_id,
                worker_id=worker_id,
                lease_token=lease_token,
                result_digest=result_digest,
                occurred_at=occurred_at,
            )

    def succeed_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        effect_id: str,
        worker_id: str,
        lease_token: str,
        result_digest: str,
        occurred_at: str,
    ) -> EffectRecord:
        """Mark a leased effect successful inside a caller-owned transaction."""
        effect_id = self._required_text(effect_id, "effect_id")
        worker_id = self._required_text(worker_id, "worker_id")
        lease_token = self._required_text(lease_token, "lease_token")
        result_digest = self._validate_digest(result_digest)
        self._parse_time(occurred_at)
        row = connection.execute(
            "SELECT * FROM durable_effects WHERE effect_id = ?",
            (effect_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("effect does not exist", {"effect_id": effect_id})
        self._require_lease(
            row,
            worker_id=worker_id,
            lease_token=lease_token,
            occurred_at=occurred_at,
        )
        receipt = self.ledger.append_in_transaction(
            connection,
            f"durable:effect:{effect_id}",
            "EFFECT_SUCCEEDED",
            {
                "effect_id": effect_id,
                "worker_id": worker_id,
                "attempt_count": int(row["attempt_count"]),
                "result_digest": result_digest,
            },
            actor=worker_id,
            occurred_at=occurred_at,
        )
        connection.execute(
            """
            UPDATE durable_effects
            SET status = ?, result_digest = ?, lease_owner = NULL,
                lease_token = NULL, lease_expires_at = NULL,
                updated_at = ?, ledger_event_id = ?, ledger_hash = ?
            WHERE effect_id = ?
            """,
            (
                EffectStatus.SUCCEEDED.value,
                result_digest,
                occurred_at,
                receipt.event_id,
                receipt.record_hash,
                effect_id,
            ),
        )
        updated = connection.execute(
            "SELECT * FROM durable_effects WHERE effect_id = ?",
            (effect_id,),
        ).fetchone()
        assert updated is not None
        return self._row_to_record(updated)

    def fail(
        self,
        effect_id: str,
        *,
        worker_id: str,
        lease_token: str,
        error: str,
        retry_delay_seconds: int,
        occurred_at: str | None = None,
    ) -> EffectRecord:
        effect_id = self._required_text(effect_id, "effect_id")
        worker_id = self._required_text(worker_id, "worker_id")
        lease_token = self._required_text(lease_token, "lease_token")
        error = self._required_text(error, "error")
        if not isinstance(retry_delay_seconds, int) or retry_delay_seconds < 0:
            raise ValidationError("retry_delay_seconds must be an integer >= 0")
        occurred_at = occurred_at or utc_now()
        now_value = self._parse_time(occurred_at)
        with self.database.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM durable_effects WHERE effect_id = ?",
                (effect_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError("effect does not exist", {"effect_id": effect_id})
            self._require_lease(
                row,
                worker_id=worker_id,
                lease_token=lease_token,
                occurred_at=occurred_at,
            )
            exhausted = int(row["attempt_count"]) >= int(row["max_attempts"])
            next_status = (
                EffectStatus.TERMINAL_FAILED if exhausted else EffectStatus.PENDING
            )
            available_at = self._format_time(
                now_value + timedelta(seconds=retry_delay_seconds)
            )
            event_kind = (
                "EFFECT_TERMINALLY_FAILED" if exhausted else "EFFECT_RETRY_SCHEDULED"
            )
            receipt = self.ledger.append_in_transaction(
                connection,
                f"durable:effect:{effect_id}",
                event_kind,
                {
                    "effect_id": effect_id,
                    "worker_id": worker_id,
                    "attempt_count": int(row["attempt_count"]),
                    "max_attempts": int(row["max_attempts"]),
                    "error": error,
                    "available_at": available_at,
                },
                actor=worker_id,
                occurred_at=occurred_at,
            )
            connection.execute(
                """
                UPDATE durable_effects
                SET status = ?, available_at = ?, last_error = ?,
                    lease_owner = NULL, lease_token = NULL,
                    lease_expires_at = NULL, updated_at = ?,
                    ledger_event_id = ?, ledger_hash = ?
                WHERE effect_id = ?
                """,
                (
                    next_status.value,
                    available_at,
                    error,
                    occurred_at,
                    receipt.event_id,
                    receipt.record_hash,
                    effect_id,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM durable_effects WHERE effect_id = ?",
                (effect_id,),
            ).fetchone()
            assert updated is not None
            return self._row_to_record(updated)

    def recover_expired(self, *, now: str | None = None) -> int:
        now = now or utc_now()
        self._parse_time(now)
        recovered = 0
        with self.database.transaction() as connection:
            rows = connection.execute(
                """
                SELECT * FROM durable_effects
                WHERE status = ? AND lease_expires_at <= ?
                ORDER BY lease_expires_at, effect_id
                """,
                (EffectStatus.LEASED.value, now),
            ).fetchall()
            for row in rows:
                effect_id = str(row["effect_id"])
                exhausted = int(row["attempt_count"]) >= int(row["max_attempts"])
                next_status = (
                    EffectStatus.TERMINAL_FAILED if exhausted else EffectStatus.PENDING
                )
                event_kind = (
                    "EFFECT_TERMINALLY_FAILED"
                    if exhausted
                    else "EFFECT_LEASE_RECOVERED"
                )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"durable:effect:{effect_id}",
                    event_kind,
                    {
                        "effect_id": effect_id,
                        "expired_worker": str(row["lease_owner"]),
                        "expired_lease_token": str(row["lease_token"]),
                        "attempt_count": int(row["attempt_count"]),
                        "max_attempts": int(row["max_attempts"]),
                    },
                    actor="durable-engine",
                    occurred_at=now,
                )
                connection.execute(
                    """
                    UPDATE durable_effects
                    SET status = ?, available_at = ?, last_error = ?,
                        lease_owner = NULL, lease_token = NULL,
                        lease_expires_at = NULL, updated_at = ?,
                        ledger_event_id = ?, ledger_hash = ?
                    WHERE effect_id = ?
                    """,
                    (
                        next_status.value,
                        now,
                        "lease expired",
                        now,
                        receipt.event_id,
                        receipt.record_hash,
                        effect_id,
                    ),
                )
                recovered += 1
        return recovered
