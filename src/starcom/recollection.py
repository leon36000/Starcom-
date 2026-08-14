from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import sqlite3

from .canonical import utc_now
from .continuity import ContinuityService, IncidentStatus
from .db import Database
from .errors import ConflictError, IntegrityError, NotFoundError, StateTransitionError, ValidationError
from .ledger import EventLedger
from .research import ResearchCampaign


@dataclass(frozen=True)
class C2RecollectionRecord:
    recollection_id: str
    incident_id: str
    campaign_id: str
    minimum_identity_target: int
    started_at: str
    started_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C2RecollectionVerification:
    recollection_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C2RecollectionService:
    """Bind Task 5 C2 recollection to a verified, explicitly published C1 recovery."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        continuity: ContinuityService,
        research: ResearchCampaign,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.continuity = continuity
        self.research = research
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
    def _minimum_target(value: int) -> int:
        if type(value) is not int or value < 800:
            raise ValidationError("minimum_identity_target must be >= 800")
        return value

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c2_recollections (
                    recollection_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL UNIQUE,
                    campaign_id TEXT NOT NULL UNIQUE,
                    minimum_identity_target INTEGER NOT NULL CHECK (minimum_identity_target >= 800),
                    started_at TEXT NOT NULL,
                    started_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (incident_id) REFERENCES continuity_incidents(incident_id),
                    FOREIGN KEY (campaign_id) REFERENCES research_campaigns(campaign_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS c2_recollections_no_update
                BEFORE UPDATE ON c2_recollections
                BEGIN SELECT RAISE(ABORT, 'c2 recollection records are immutable'); END
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS c2_recollections_no_delete
                BEFORE DELETE ON c2_recollections
                BEGIN SELECT RAISE(ABORT, 'c2 recollection records are immutable'); END
                """
            )

    @staticmethod
    def _from_row(row: sqlite3.Row) -> C2RecollectionRecord:
        return C2RecollectionRecord(
            recollection_id=str(row["recollection_id"]),
            incident_id=str(row["incident_id"]),
            campaign_id=str(row["campaign_id"]),
            minimum_identity_target=int(row["minimum_identity_target"]),
            started_at=str(row["started_at"]),
            started_by=str(row["started_by"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def _require_clean_published_c1(self, incident_id: str) -> None:
        incident = self.continuity.get_incident(incident_id)
        if incident.status != IncidentStatus.RECOVERY_PUBLISHED_RECOLLECT_REQUIRED:
            raise StateTransitionError(
                "C1 recovery must be published before C2 recollection",
                {"incident_id": incident_id, "status": incident.status.value},
            )
        verification = self.continuity.verify_incident(incident_id)
        if not verification.ok:
            raise IntegrityError(
                "C1 incident verification failed",
                {"incident_id": incident_id, "defects": list(verification.defects)},
            )

    def get(self, recollection_id: str) -> C2RecollectionRecord:
        recollection_id = self._required_text(recollection_id, "recollection_id")
        row = self.database.connection.execute(
            "SELECT * FROM c2_recollections WHERE recollection_id = ?",
            (recollection_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C2 recollection does not exist",
                {"recollection_id": recollection_id},
            )
        return self._from_row(row)

    def start(
        self,
        recollection_id: str,
        *,
        incident_id: str,
        campaign_id: str,
        minimum_identity_target: int,
        actor: str,
        occurred_at: str | None = None,
    ) -> C2RecollectionRecord:
        recollection_id = self._required_text(recollection_id, "recollection_id")
        incident_id = self._required_text(incident_id, "incident_id")
        campaign_id = self._required_text(campaign_id, "campaign_id")
        actor = self._required_text(actor, "actor")
        minimum_identity_target = self._minimum_target(minimum_identity_target)
        occurred_at = self._timestamp(occurred_at or utc_now())

        self._require_clean_published_c1(incident_id)
        self.research.get_campaign(campaign_id)

        existing = self.database.connection.execute(
            "SELECT * FROM c2_recollections WHERE recollection_id = ?",
            (recollection_id,),
        ).fetchone()
        if existing is not None:
            record = self._from_row(existing)
            expected = (
                incident_id,
                campaign_id,
                minimum_identity_target,
                actor,
            )
            observed = (
                record.incident_id,
                record.campaign_id,
                record.minimum_identity_target,
                record.started_by,
            )
            if observed != expected:
                raise ConflictError(
                    "recollection_id was reused with different C2 binding material",
                    {"recollection_id": recollection_id},
                )
            verification = self.verify(recollection_id)
            if not verification.ok:
                raise IntegrityError(
                    "existing C2 recollection failed verification",
                    {"recollection_id": recollection_id, "defects": list(verification.defects)},
                )
            return record

        with self.database.transaction() as connection:
            incident_row = connection.execute(
                "SELECT status FROM continuity_incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
            if incident_row is None:
                raise NotFoundError("continuity incident does not exist", {"incident_id": incident_id})
            if str(incident_row["status"]) != IncidentStatus.RECOVERY_PUBLISHED_RECOLLECT_REQUIRED.value:
                raise StateTransitionError(
                    "C1 recovery must be published before C2 recollection",
                    {"incident_id": incident_id, "status": str(incident_row["status"])},
                )
            attempt_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM research_attempts WHERE campaign_id = ?",
                    (campaign_id,),
                ).fetchone()[0]
            )
            if attempt_count != 0:
                raise StateTransitionError(
                    "C2 campaign must be empty at binding",
                    {"campaign_id": campaign_id, "attempt_count": attempt_count},
                )
            race_existing = connection.execute(
                "SELECT * FROM c2_recollections WHERE recollection_id = ?",
                (recollection_id,),
            ).fetchone()
            if race_existing is not None:
                raise ConflictError(
                    "C2 recollection appeared during binding",
                    {"recollection_id": recollection_id},
                )
            payload = {
                "recollection_id": recollection_id,
                "incident_id": incident_id,
                "campaign_id": campaign_id,
                "minimum_identity_target": minimum_identity_target,
                "c1_required_status": IncidentStatus.RECOVERY_PUBLISHED_RECOLLECT_REQUIRED.value,
                "pre_binding_attempt_count": 0,
            }
            receipt = self.ledger.append_in_transaction(
                connection,
                f"continuity:c2:{recollection_id}",
                "C2_RECOLLECTION_STARTED",
                payload,
                actor=actor,
                occurred_at=occurred_at,
            )
            try:
                connection.execute(
                    """
                    INSERT INTO c2_recollections (
                        recollection_id, incident_id, campaign_id, minimum_identity_target,
                        started_at, started_by, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        recollection_id,
                        incident_id,
                        campaign_id,
                        minimum_identity_target,
                        occurred_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError(
                    "C2 incident or campaign is already bound to another recollection",
                    {"incident_id": incident_id, "campaign_id": campaign_id},
                ) from exc
        return self.get(recollection_id)

    def verify(self, recollection_id: str) -> C2RecollectionVerification:
        record = self.get(recollection_id)
        defects: list[str] = []

        try:
            incident = self.continuity.get_incident(record.incident_id)
        except NotFoundError:
            defects.append("C2_C1_INCIDENT_MISSING")
        else:
            if incident.status != IncidentStatus.RECOVERY_PUBLISHED_RECOLLECT_REQUIRED:
                defects.append("C2_C1_STATUS_MISMATCH")
            c1_verification = self.continuity.verify_incident(record.incident_id)
            defects.extend(f"C2_C1:{defect}" for defect in c1_verification.defects)

        try:
            self.research.get_campaign(record.campaign_id)
        except NotFoundError:
            defects.append("C2_CAMPAIGN_MISSING")

        if record.minimum_identity_target < 800:
            defects.append("C2_MINIMUM_IDENTITY_TARGET_INVALID")

        try:
            binding_time = datetime.fromisoformat(record.started_at.replace("Z", "+00:00"))
        except ValueError:
            defects.append("C2_STARTED_AT_INVALID")
            binding_time = None
        if binding_time is not None:
            attempt_rows = self.database.connection.execute(
                "SELECT attempt_id, started_at FROM research_attempts WHERE campaign_id = ?",
                (record.campaign_id,),
            ).fetchall()
            for attempt in attempt_rows:
                try:
                    attempt_time = datetime.fromisoformat(str(attempt["started_at"]).replace("Z", "+00:00"))
                except ValueError:
                    defects.append(f"C2_ATTEMPT_TIME_INVALID:{attempt['attempt_id']}")
                    continue
                if attempt_time < binding_time:
                    defects.append(f"C2_PRE_BINDING_ATTEMPT:{attempt['attempt_id']}")

        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (record.ledger_event_id,),
        ).fetchone()
        expected_stream = f"continuity:c2:{record.recollection_id}"
        expected_payload = {
            "recollection_id": record.recollection_id,
            "incident_id": record.incident_id,
            "campaign_id": record.campaign_id,
            "minimum_identity_target": record.minimum_identity_target,
            "c1_required_status": IncidentStatus.RECOVERY_PUBLISHED_RECOLLECT_REQUIRED.value,
            "pre_binding_attempt_count": 0,
        }
        if event is None:
            defects.append("C2_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != expected_stream:
                defects.append("C2_LEDGER_STREAM_MISMATCH")
            if str(event["kind"]) != "C2_RECOLLECTION_STARTED":
                defects.append("C2_LEDGER_KIND_MISMATCH")
            if str(event["actor"]) != record.started_by:
                defects.append("C2_LEDGER_ACTOR_MISMATCH")
            if str(event["occurred_at"]) != record.started_at:
                defects.append("C2_LEDGER_TIMESTAMP_MISMATCH")
            if str(event["record_hash"]) != record.ledger_hash:
                defects.append("C2_LEDGER_HASH_MISMATCH")
            try:
                event_payload = json.loads(str(event["payload_json"]))
            except (json.JSONDecodeError, TypeError):
                defects.append("C2_LEDGER_PAYLOAD_INVALID")
            else:
                if event_payload != expected_payload:
                    defects.append("C2_LEDGER_PAYLOAD_MISMATCH")

        chain = self.ledger.verify(expected_stream)
        defects.extend(f"C2_LEDGER_CHAIN:{defect.code}" for defect in chain.defects)

        return C2RecollectionVerification(
            recollection_id=record.recollection_id,
            defects=tuple(defects),
        )
