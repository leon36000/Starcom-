from __future__ import annotations

from dataclasses import dataclass
import json
import sqlite3
from typing import Any
from uuid import uuid4

from .canonical import canonical_json, sha256_digest, utc_now
from .db import Database
from .errors import ConflictError, ValidationError


GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class LedgerEvent:
    event_id: str
    stream_id: str
    sequence: int
    kind: str
    payload: Any
    actor: str
    occurred_at: str
    prev_hash: str
    record_hash: str


@dataclass(frozen=True)
class EventReceipt:
    event_id: str
    stream_id: str
    sequence: int
    occurred_at: str
    prev_hash: str
    record_hash: str


@dataclass(frozen=True)
class ChainDefect:
    code: str
    stream_id: str
    sequence: int | None
    event_id: str | None
    message: str


@dataclass(frozen=True)
class ChainVerification:
    checked_events: int
    checked_streams: int
    defects: tuple[ChainDefect, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class EventLedger:
    def __init__(self, database: Database) -> None:
        self.database = database

    @staticmethod
    def _validate_text(value: str, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{field} must be a non-empty string")
        return value

    @staticmethod
    def _hash_material(
        *,
        event_id: str,
        stream_id: str,
        sequence: int,
        kind: str,
        payload: Any,
        actor: str,
        occurred_at: str,
        prev_hash: str,
    ) -> dict[str, Any]:
        return {
            "actor": actor,
            "event_id": event_id,
            "kind": kind,
            "occurred_at": occurred_at,
            "payload": payload,
            "prev_hash": prev_hash,
            "sequence": sequence,
            "stream_id": stream_id,
        }

    def head(self, stream_id: str) -> str:
        self._validate_text(stream_id, "stream_id")
        row = self.database.connection.execute(
            "SELECT record_hash FROM ledger_events WHERE stream_id = ? "
            "ORDER BY sequence DESC LIMIT 1",
            (stream_id,),
        ).fetchone()
        return str(row["record_hash"]) if row is not None else GENESIS_HASH

    def append(
        self,
        stream_id: str,
        kind: str,
        payload: Any,
        *,
        actor: str,
        expected_head: str | None = None,
        event_id: str | None = None,
        occurred_at: str | None = None,
    ) -> EventReceipt:
        with self.database.transaction() as connection:
            return self.append_in_transaction(
                connection,
                stream_id,
                kind,
                payload,
                actor=actor,
                expected_head=expected_head,
                event_id=event_id,
                occurred_at=occurred_at,
            )

    def append_in_transaction(
        self,
        connection: sqlite3.Connection,
        stream_id: str,
        kind: str,
        payload: Any,
        *,
        actor: str,
        expected_head: str | None = None,
        event_id: str | None = None,
        occurred_at: str | None = None,
    ) -> EventReceipt:
        """Append using an already-open Database transaction."""
        stream_id = self._validate_text(stream_id, "stream_id")
        kind = self._validate_text(kind, "kind")
        actor = self._validate_text(actor, "actor")
        event_id = self._validate_text(event_id or str(uuid4()), "event_id")
        occurred_at = self._validate_text(occurred_at or utc_now(), "occurred_at")
        payload_json = canonical_json(payload)

        row = connection.execute(
            "SELECT sequence, record_hash FROM ledger_events "
            "WHERE stream_id = ? ORDER BY sequence DESC LIMIT 1",
            (stream_id,),
        ).fetchone()
        if row is None:
            sequence = 1
            prev_hash = GENESIS_HASH
        else:
            sequence = int(row["sequence"]) + 1
            prev_hash = str(row["record_hash"])

        if expected_head is not None and expected_head != prev_hash:
            raise ConflictError(
                "stream head does not match expected head",
                {
                    "stream_id": stream_id,
                    "expected_head": expected_head,
                    "actual_head": prev_hash,
                },
            )

        material = self._hash_material(
            event_id=event_id,
            stream_id=stream_id,
            sequence=sequence,
            kind=kind,
            payload=json.loads(payload_json),
            actor=actor,
            occurred_at=occurred_at,
            prev_hash=prev_hash,
        )
        record_hash = sha256_digest(material)
        try:
            connection.execute(
                """
                INSERT INTO ledger_events (
                    event_id, stream_id, sequence, kind, payload_json,
                    actor, occurred_at, prev_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    stream_id,
                    sequence,
                    kind,
                    payload_json,
                    actor,
                    occurred_at,
                    prev_hash,
                    record_hash,
                ),
            )
        except sqlite3.IntegrityError as exc:
            if connection.execute(
                "SELECT 1 FROM ledger_events WHERE event_id = ?",
                (event_id,),
            ).fetchone():
                raise ConflictError(
                    "event_id already exists",
                    {"event_id": event_id},
                ) from exc
            raise ConflictError(
                "ledger append violates an integrity constraint",
                {"stream_id": stream_id, "sequence": sequence},
            ) from exc

        return EventReceipt(
            event_id=event_id,
            stream_id=stream_id,
            sequence=sequence,
            occurred_at=occurred_at,
            prev_hash=prev_hash,
            record_hash=record_hash,
        )

    def read_stream(self, stream_id: str) -> list[LedgerEvent]:
        self._validate_text(stream_id, "stream_id")
        rows = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE stream_id = ? ORDER BY sequence",
            (stream_id,),
        ).fetchall()
        return [self._row_to_event(row) for row in rows]

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> LedgerEvent:
        return LedgerEvent(
            event_id=str(row["event_id"]),
            stream_id=str(row["stream_id"]),
            sequence=int(row["sequence"]),
            kind=str(row["kind"]),
            payload=json.loads(str(row["payload_json"])),
            actor=str(row["actor"]),
            occurred_at=str(row["occurred_at"]),
            prev_hash=str(row["prev_hash"]),
            record_hash=str(row["record_hash"]),
        )

    def verify(self, stream_id: str | None = None) -> ChainVerification:
        parameters: tuple[str, ...] = ()
        where = ""
        if stream_id is not None:
            self._validate_text(stream_id, "stream_id")
            where = "WHERE stream_id = ?"
            parameters = (stream_id,)
        rows = self.database.connection.execute(
            f"SELECT * FROM ledger_events {where} ORDER BY stream_id, sequence",
            parameters,
        ).fetchall()

        defects: list[ChainDefect] = []
        previous_by_stream: dict[str, tuple[int, str]] = {}
        checked_streams: set[str] = set()

        for row in rows:
            current_stream = str(row["stream_id"])
            sequence = int(row["sequence"])
            event_id = str(row["event_id"])
            checked_streams.add(current_stream)
            prior = previous_by_stream.get(current_stream)
            expected_sequence = 1 if prior is None else prior[0] + 1
            expected_prev_hash = GENESIS_HASH if prior is None else prior[1]

            if sequence != expected_sequence:
                defects.append(
                    ChainDefect(
                        "SEQUENCE_MISMATCH",
                        current_stream,
                        sequence,
                        event_id,
                        f"expected sequence {expected_sequence}, observed {sequence}",
                    )
                )
            observed_prev_hash = str(row["prev_hash"])
            if observed_prev_hash != expected_prev_hash:
                defects.append(
                    ChainDefect(
                        "PREVIOUS_HASH_MISMATCH",
                        current_stream,
                        sequence,
                        event_id,
                        "previous hash does not match the preceding record",
                    )
                )

            try:
                payload = json.loads(str(row["payload_json"]))
            except json.JSONDecodeError:
                defects.append(
                    ChainDefect(
                        "PAYLOAD_JSON_INVALID",
                        current_stream,
                        sequence,
                        event_id,
                        "payload_json is not valid JSON",
                    )
                )
                payload = {"_invalid_payload": str(row["payload_json"])}

            computed_hash = sha256_digest(
                self._hash_material(
                    event_id=event_id,
                    stream_id=current_stream,
                    sequence=sequence,
                    kind=str(row["kind"]),
                    payload=payload,
                    actor=str(row["actor"]),
                    occurred_at=str(row["occurred_at"]),
                    prev_hash=observed_prev_hash,
                )
            )
            observed_hash = str(row["record_hash"])
            if computed_hash != observed_hash:
                defects.append(
                    ChainDefect(
                        "RECORD_HASH_MISMATCH",
                        current_stream,
                        sequence,
                        event_id,
                        "record hash does not commit to the stored event",
                    )
                )
            previous_by_stream[current_stream] = (sequence, observed_hash)

        return ChainVerification(
            checked_events=len(rows),
            checked_streams=len(checked_streams),
            defects=tuple(defects),
        )
