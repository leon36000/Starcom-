from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import json
import sqlite3
from typing import Any, Mapping

from .canonical import canonical_json, sha256_digest, utc_now
from .db import Database
from .errors import ConflictError, IntegrityError, NotFoundError, ValidationError
from .ledger import EventLedger


class QualificationArtifactKind(str, Enum):
    CANDIDATE = "CANDIDATE"
    EVALUATION = "EVALUATION"
    DECISION = "DECISION"
    ADOPTION = "ADOPTION"


@dataclass(frozen=True)
class QualificationRun:
    qualification_run_id: str
    name: str
    created_at: str
    created_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class QualificationArtifact:
    artifact_id: str
    qualification_run_id: str
    kind: QualificationArtifactKind
    material: Mapping[str, Any]
    material_sha256: str
    recorded_at: str
    recorded_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class QualificationVerification:
    qualification_run_id: str
    artifact_counts: Mapping[str, int]
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class QualificationLab:
    """Generic append-only qualification evidence ledger, independent of C3."""

    def __init__(self, database: Database, ledger: EventLedger) -> None:
        self.database = database
        self.ledger = ledger
        self._initialize_schema()

    @staticmethod
    def _required_text(value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{field} must be a non-empty string")
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
    def _artifact_kind(value: object) -> QualificationArtifactKind:
        if isinstance(value, QualificationArtifactKind):
            return value
        try:
            return QualificationArtifactKind(str(value))
        except ValueError as exc:
            raise ValidationError("unknown qualification artifact kind") from exc

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS qualification_runs (
                    qualification_run_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS qualification_artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    qualification_run_id TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK (
                        kind IN ('CANDIDATE','EVALUATION','DECISION','ADOPTION')
                    ),
                    material_json TEXT NOT NULL,
                    material_sha256 TEXT NOT NULL CHECK (length(material_sha256) = 64),
                    recorded_at TEXT NOT NULL,
                    recorded_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (qualification_run_id)
                        REFERENCES qualification_runs(qualification_run_id)
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS qualification_artifacts_run_idx
                ON qualification_artifacts(qualification_run_id, kind, artifact_id)
                """
            )
            for table in ("qualification_runs", "qualification_artifacts"):
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

    @staticmethod
    def _run_from_row(row: sqlite3.Row) -> QualificationRun:
        return QualificationRun(
            qualification_run_id=str(row["qualification_run_id"]),
            name=str(row["name"]),
            created_at=str(row["created_at"]),
            created_by=str(row["created_by"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    @staticmethod
    def _artifact_from_row(row: sqlite3.Row) -> QualificationArtifact:
        decoded = json.loads(str(row["material_json"]))
        if not isinstance(decoded, dict):
            raise ValidationError("qualification artifact material must be a JSON object")
        return QualificationArtifact(
            artifact_id=str(row["artifact_id"]),
            qualification_run_id=str(row["qualification_run_id"]),
            kind=QualificationArtifactKind(str(row["kind"])),
            material=decoded,
            material_sha256=str(row["material_sha256"]),
            recorded_at=str(row["recorded_at"]),
            recorded_by=str(row["recorded_by"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def get_run(self, qualification_run_id: str) -> QualificationRun:
        qualification_run_id = self._required_text(
            qualification_run_id,
            "qualification_run_id",
        )
        row = self.database.connection.execute(
            "SELECT * FROM qualification_runs WHERE qualification_run_id = ?",
            (qualification_run_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "qualification run does not exist",
                {"qualification_run_id": qualification_run_id},
            )
        return self._run_from_row(row)

    def get_artifact(self, artifact_id: str) -> QualificationArtifact:
        artifact_id = self._required_text(artifact_id, "artifact_id")
        row = self.database.connection.execute(
            "SELECT * FROM qualification_artifacts WHERE artifact_id = ?",
            (artifact_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "qualification artifact does not exist",
                {"artifact_id": artifact_id},
            )
        return self._artifact_from_row(row)

    def create_run(
        self,
        qualification_run_id: str,
        *,
        name: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> QualificationRun:
        qualification_run_id = self._required_text(
            qualification_run_id,
            "qualification_run_id",
        )
        name = self._required_text(name, "name")
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now())

        existing = self.database.connection.execute(
            "SELECT * FROM qualification_runs WHERE qualification_run_id = ?",
            (qualification_run_id,),
        ).fetchone()
        if existing is not None:
            run = self._run_from_row(existing)
            if run.name != name or run.created_by != actor:
                raise ConflictError(
                    "qualification_run_id was reused with different run material",
                    {"qualification_run_id": qualification_run_id},
                )
            verification = self.verify(qualification_run_id)
            if not verification.ok:
                raise IntegrityError(
                    "existing qualification run failed verification",
                    {
                        "qualification_run_id": qualification_run_id,
                        "defects": list(verification.defects),
                    },
                )
            return run

        try:
            with self.database.transaction() as connection:
                race = connection.execute(
                    "SELECT * FROM qualification_runs WHERE qualification_run_id = ?",
                    (qualification_run_id,),
                ).fetchone()
                if race is not None:
                    raise ConflictError(
                        "qualification run appeared during creation",
                        {"qualification_run_id": qualification_run_id},
                    )
                payload = {
                    "qualification_run_id": qualification_run_id,
                    "name": name,
                }
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"qualification:run:{qualification_run_id}",
                    "QUALIFICATION_RUN_CREATED",
                    payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO qualification_runs (
                        qualification_run_id, name, created_at, created_by,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        qualification_run_id,
                        name,
                        occurred_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "qualification run already exists",
                {"qualification_run_id": qualification_run_id},
            ) from exc
        return self.get_run(qualification_run_id)

    def record_artifact(
        self,
        qualification_run_id: str,
        *,
        artifact_id: str,
        kind: QualificationArtifactKind,
        material: Mapping[str, Any],
        actor: str,
        occurred_at: str | None = None,
    ) -> QualificationArtifact:
        qualification_run_id = self._required_text(
            qualification_run_id,
            "qualification_run_id",
        )
        artifact_id = self._required_text(artifact_id, "artifact_id")
        kind = self._artifact_kind(kind)
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now())
        if not isinstance(material, Mapping):
            raise ValidationError("material must be a mapping")
        material_value = dict(material)
        material_json = canonical_json(material_value)
        material_sha256 = sha256_digest(material_value)
        self.get_run(qualification_run_id)

        existing = self.database.connection.execute(
            "SELECT * FROM qualification_artifacts WHERE artifact_id = ?",
            (artifact_id,),
        ).fetchone()
        if existing is not None:
            exact = (
                str(existing["qualification_run_id"]) == qualification_run_id
                and str(existing["kind"]) == kind.value
                and str(existing["material_json"]) == material_json
                and str(existing["material_sha256"]) == material_sha256
                and str(existing["recorded_by"]) == actor
            )
            if not exact:
                raise ConflictError(
                    "artifact_id was reused with different qualification material",
                    {"artifact_id": artifact_id},
                )
            verification = self.verify(qualification_run_id)
            if not verification.ok:
                raise IntegrityError(
                    "existing qualification artifact failed verification",
                    {
                        "artifact_id": artifact_id,
                        "defects": list(verification.defects),
                    },
                )
            return self._artifact_from_row(existing)

        try:
            with self.database.transaction() as connection:
                run = connection.execute(
                    "SELECT 1 FROM qualification_runs WHERE qualification_run_id = ?",
                    (qualification_run_id,),
                ).fetchone()
                if run is None:
                    raise NotFoundError(
                        "qualification run does not exist",
                        {"qualification_run_id": qualification_run_id},
                    )
                race = connection.execute(
                    "SELECT 1 FROM qualification_artifacts WHERE artifact_id = ?",
                    (artifact_id,),
                ).fetchone()
                if race is not None:
                    raise ConflictError(
                        "qualification artifact appeared during recording",
                        {"artifact_id": artifact_id},
                    )
                payload = {
                    "artifact_id": artifact_id,
                    "qualification_run_id": qualification_run_id,
                    "kind": kind.value,
                    "material": material_value,
                    "material_sha256": material_sha256,
                }
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"qualification:run:{qualification_run_id}",
                    "QUALIFICATION_ARTIFACT_RECORDED",
                    payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO qualification_artifacts (
                        artifact_id, qualification_run_id, kind, material_json,
                        material_sha256, recorded_at, recorded_by,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        artifact_id,
                        qualification_run_id,
                        kind.value,
                        material_json,
                        material_sha256,
                        occurred_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "qualification artifact already exists",
                {"artifact_id": artifact_id},
            ) from exc
        return self.get_artifact(artifact_id)

    @staticmethod
    def _event_payload(event: sqlite3.Row) -> dict[str, object] | None:
        try:
            value = json.loads(str(event["payload_json"]))
        except (json.JSONDecodeError, TypeError):
            return None
        return value if isinstance(value, dict) else None

    def verify(self, qualification_run_id: str) -> QualificationVerification:
        qualification_run_id = self._required_text(
            qualification_run_id,
            "qualification_run_id",
        )
        run = self.database.connection.execute(
            "SELECT * FROM qualification_runs WHERE qualification_run_id = ?",
            (qualification_run_id,),
        ).fetchone()
        if run is None:
            raise NotFoundError(
                "qualification run does not exist",
                {"qualification_run_id": qualification_run_id},
            )

        stream_id = f"qualification:run:{qualification_run_id}"
        defects: list[str] = []
        counts = {kind.value: 0 for kind in QualificationArtifactKind}
        expected_event_ids = {str(run["ledger_event_id"])}

        run_event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (str(run["ledger_event_id"]),),
        ).fetchone()
        expected_run_payload = {
            "qualification_run_id": qualification_run_id,
            "name": str(run["name"]),
        }
        if run_event is None:
            defects.append("QUALIFICATION_RUN_LEDGER_EVENT_MISSING")
        else:
            if str(run_event["stream_id"]) != stream_id:
                defects.append("QUALIFICATION_RUN_LEDGER_STREAM_MISMATCH")
            if str(run_event["kind"]) != "QUALIFICATION_RUN_CREATED":
                defects.append("QUALIFICATION_RUN_LEDGER_KIND_MISMATCH")
            if str(run_event["actor"]) != str(run["created_by"]):
                defects.append("QUALIFICATION_RUN_LEDGER_ACTOR_MISMATCH")
            if str(run_event["occurred_at"]) != str(run["created_at"]):
                defects.append("QUALIFICATION_RUN_LEDGER_TIMESTAMP_MISMATCH")
            if str(run_event["record_hash"]) != str(run["ledger_hash"]):
                defects.append("QUALIFICATION_RUN_LEDGER_HASH_MISMATCH")
            payload = self._event_payload(run_event)
            if payload is None:
                defects.append("QUALIFICATION_RUN_LEDGER_PAYLOAD_INVALID")
            elif payload != expected_run_payload:
                defects.append("QUALIFICATION_RUN_LEDGER_PAYLOAD_MISMATCH")

        artifacts = self.database.connection.execute(
            """
            SELECT * FROM qualification_artifacts
            WHERE qualification_run_id = ? ORDER BY artifact_id
            """,
            (qualification_run_id,),
        ).fetchall()
        for artifact in artifacts:
            artifact_id = str(artifact["artifact_id"])
            expected_event_ids.add(str(artifact["ledger_event_id"]))
            kind = None
            try:
                kind = QualificationArtifactKind(str(artifact["kind"]))
            except ValueError:
                defects.append(f"QUALIFICATION_ARTIFACT_KIND_INVALID:{artifact_id}")
            else:
                counts[kind.value] += 1

            material: dict[str, object] | None = None
            try:
                decoded = json.loads(str(artifact["material_json"]))
                if not isinstance(decoded, dict):
                    raise ValueError("material must decode to an object")
                material = decoded
            except (json.JSONDecodeError, TypeError, ValueError):
                defects.append(f"QUALIFICATION_ARTIFACT_MATERIAL_INVALID:{artifact_id}")
            else:
                if sha256_digest(material) != str(artifact["material_sha256"]):
                    defects.append(
                        f"QUALIFICATION_ARTIFACT_MATERIAL_DIGEST_MISMATCH:{artifact_id}"
                    )

            event = self.database.connection.execute(
                "SELECT * FROM ledger_events WHERE event_id = ?",
                (str(artifact["ledger_event_id"]),),
            ).fetchone()
            expected_payload = None
            if kind is not None and material is not None:
                expected_payload = {
                    "artifact_id": artifact_id,
                    "qualification_run_id": qualification_run_id,
                    "kind": kind.value,
                    "material": material,
                    "material_sha256": str(artifact["material_sha256"]),
                }
            if event is None:
                defects.append(
                    f"QUALIFICATION_ARTIFACT_LEDGER_EVENT_MISSING:{artifact_id}"
                )
                continue
            if str(event["stream_id"]) != stream_id:
                defects.append(
                    f"QUALIFICATION_ARTIFACT_LEDGER_STREAM_MISMATCH:{artifact_id}"
                )
            if str(event["kind"]) != "QUALIFICATION_ARTIFACT_RECORDED":
                defects.append(
                    f"QUALIFICATION_ARTIFACT_LEDGER_KIND_MISMATCH:{artifact_id}"
                )
            if str(event["actor"]) != str(artifact["recorded_by"]):
                defects.append(
                    f"QUALIFICATION_ARTIFACT_LEDGER_ACTOR_MISMATCH:{artifact_id}"
                )
            if str(event["occurred_at"]) != str(artifact["recorded_at"]):
                defects.append(
                    f"QUALIFICATION_ARTIFACT_LEDGER_TIMESTAMP_MISMATCH:{artifact_id}"
                )
            if str(event["record_hash"]) != str(artifact["ledger_hash"]):
                defects.append(
                    f"QUALIFICATION_ARTIFACT_LEDGER_HASH_MISMATCH:{artifact_id}"
                )
            event_payload = self._event_payload(event)
            if event_payload is None:
                defects.append(
                    f"QUALIFICATION_ARTIFACT_LEDGER_PAYLOAD_INVALID:{artifact_id}"
                )
            elif expected_payload is not None and event_payload != expected_payload:
                defects.append(
                    f"QUALIFICATION_ARTIFACT_LEDGER_PAYLOAD_MISMATCH:{artifact_id}"
                )

        stream_events = self.database.connection.execute(
            "SELECT event_id FROM ledger_events WHERE stream_id = ?",
            (stream_id,),
        ).fetchall()
        for event in stream_events:
            event_id = str(event["event_id"])
            if event_id not in expected_event_ids:
                defects.append(f"QUALIFICATION_LEDGER_EVENT_UNBOUND:{event_id}")

        chain = self.ledger.verify(stream_id)
        defects.extend(
            f"QUALIFICATION_LEDGER_CHAIN:{defect.code}"
            for defect in chain.defects
        )
        return QualificationVerification(
            qualification_run_id=qualification_run_id,
            artifact_counts=counts,
            defects=tuple(dict.fromkeys(defects)),
        )
