from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import sqlite3

from .canonical import utc_now
from .db import Database
from .errors import ConflictError, IntegrityError, NotFoundError, StateTransitionError, ValidationError
from .ledger import EventLedger
from .recollection import C2RecollectionService
from .research import ReceiptOutcome, ResearchCampaign


@dataclass(frozen=True)
class C2CensusIdentity:
    identity_id: str
    recollection_id: str
    campaign_id: str
    identity_key: str
    source_id: str
    attempt_id: str
    observation_id: str
    evidence_digest: str
    recorded_at: str
    recorded_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C2CensusVerification:
    recollection_id: str
    identity_count: int
    required_target: int
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


@dataclass(frozen=True)
class C2CensusAssessment:
    recollection_id: str
    identity_count: int
    required_target: int
    eligible_for_independent_certification: bool
    defects: tuple[str, ...]


class C2CensusService:
    """Evidence-bound identity accounting for a verified C2 recollection."""

    def __init__(self, database: Database, ledger: EventLedger, recollection: C2RecollectionService, research: ResearchCampaign) -> None:
        self.database = database
        self.ledger = ledger
        self.recollection = recollection
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

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS c2_census_identities (
                    identity_id TEXT PRIMARY KEY,
                    recollection_id TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    identity_key TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    attempt_id TEXT NOT NULL,
                    observation_id TEXT NOT NULL UNIQUE,
                    evidence_digest TEXT NOT NULL CHECK (length(evidence_digest) = 64),
                    recorded_at TEXT NOT NULL,
                    recorded_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    UNIQUE (recollection_id, identity_key),
                    FOREIGN KEY (recollection_id) REFERENCES c2_recollections(recollection_id),
                    FOREIGN KEY (campaign_id) REFERENCES research_campaigns(campaign_id),
                    FOREIGN KEY (attempt_id) REFERENCES research_attempts(attempt_id),
                    FOREIGN KEY (observation_id) REFERENCES research_observations(observation_id)
                )
            """)
            connection.execute("""
                CREATE TRIGGER IF NOT EXISTS c2_census_identities_no_update
                BEFORE UPDATE ON c2_census_identities
                BEGIN SELECT RAISE(ABORT, 'c2 census identities are immutable'); END
            """)
            connection.execute("""
                CREATE TRIGGER IF NOT EXISTS c2_census_identities_no_delete
                BEFORE DELETE ON c2_census_identities
                BEGIN SELECT RAISE(ABORT, 'c2 census identities are immutable'); END
            """)

    @staticmethod
    def _from_row(row: sqlite3.Row) -> C2CensusIdentity:
        return C2CensusIdentity(
            identity_id=str(row["identity_id"]), recollection_id=str(row["recollection_id"]),
            campaign_id=str(row["campaign_id"]), identity_key=str(row["identity_key"]),
            source_id=str(row["source_id"]), attempt_id=str(row["attempt_id"]),
            observation_id=str(row["observation_id"]), evidence_digest=str(row["evidence_digest"]),
            recorded_at=str(row["recorded_at"]), recorded_by=str(row["recorded_by"]),
            ledger_event_id=str(row["ledger_event_id"]), ledger_hash=str(row["ledger_hash"]),
        )

    def get_identity(self, identity_id: str) -> C2CensusIdentity:
        identity_id = self._required_text(identity_id, "identity_id")
        row = self.database.connection.execute("SELECT * FROM c2_census_identities WHERE identity_id = ?", (identity_id,)).fetchone()
        if row is None:
            raise NotFoundError("C2 census identity does not exist", {"identity_id": identity_id})
        return self._from_row(row)

    def _require_clean_recollection(self, recollection_id: str):  # type: ignore[no-untyped-def]
        verification = self.recollection.verify(recollection_id)
        if not verification.ok:
            raise IntegrityError("C2 recollection verification failed", {"recollection_id": recollection_id, "defects": list(verification.defects)})
        return self.recollection.get(recollection_id)

    def _linked_evidence(self, *, campaign_id: str, source_id: str, attempt_id: str, observation_id: str) -> str:
        row = self.database.connection.execute("""
            SELECT a.campaign_id, a.source_id, r.outcome,
                   o.attempt_id AS observation_attempt_id, o.content_digest AS evidence_digest
            FROM research_attempts a
            JOIN research_receipts r ON r.attempt_id = a.attempt_id
            JOIN research_observations o ON o.attempt_id = a.attempt_id
            WHERE a.attempt_id = ? AND o.observation_id = ?
        """, (attempt_id, observation_id)).fetchone()
        if row is None:
            raise StateTransitionError("identity requires an observation linked to the research attempt", {"attempt_id": attempt_id, "observation_id": observation_id})
        if str(row["campaign_id"]) != campaign_id:
            raise StateTransitionError("identity evidence belongs to a different campaign")
        if str(row["source_id"]) != source_id:
            raise StateTransitionError("identity source does not match attempt")
        if str(row["outcome"]) != ReceiptOutcome.SUCCESS.value:
            raise StateTransitionError("identity evidence requires a successful attempt")
        if str(row["observation_attempt_id"]) != attempt_id:
            raise StateTransitionError("identity observation belongs to a different attempt")
        return str(row["evidence_digest"])

    def register_identity(self, recollection_id: str, *, identity_id: str, identity_key: str, source_id: str, attempt_id: str, observation_id: str, actor: str, occurred_at: str | None = None) -> C2CensusIdentity:
        recollection_id = self._required_text(recollection_id, "recollection_id")
        identity_id = self._required_text(identity_id, "identity_id")
        identity_key = self._required_text(identity_key, "identity_key")
        source_id = self._required_text(source_id, "source_id")
        attempt_id = self._required_text(attempt_id, "attempt_id")
        observation_id = self._required_text(observation_id, "observation_id")
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now())

        recollection = self._require_clean_recollection(recollection_id)
        self.research.get_campaign(recollection.campaign_id)
        evidence_digest = self._linked_evidence(campaign_id=recollection.campaign_id, source_id=source_id, attempt_id=attempt_id, observation_id=observation_id)

        existing = self.database.connection.execute("SELECT * FROM c2_census_identities WHERE recollection_id = ? AND identity_key = ?", (recollection_id, identity_key)).fetchone()
        if existing is not None:
            record = self._from_row(existing)
            observed = (record.campaign_id, record.source_id, record.attempt_id, record.observation_id, record.evidence_digest, record.recorded_by)
            expected = (recollection.campaign_id, source_id, attempt_id, observation_id, evidence_digest, actor)
            if observed != expected:
                raise ConflictError("identity_key was reused with different census evidence", {"recollection_id": recollection_id, "identity_key": identity_key})
            return record

        payload = {
            "identity_id": identity_id, "recollection_id": recollection_id,
            "campaign_id": recollection.campaign_id, "identity_key": identity_key,
            "source_id": source_id, "attempt_id": attempt_id,
            "observation_id": observation_id, "evidence_digest": evidence_digest,
        }
        try:
            with self.database.transaction() as connection:
                race = connection.execute("SELECT 1 FROM c2_census_identities WHERE recollection_id = ? AND identity_key = ?", (recollection_id, identity_key)).fetchone()
                if race is not None:
                    raise ConflictError("C2 census identity appeared during registration")
                receipt = self.ledger.append_in_transaction(connection, f"continuity:c2:{recollection_id}:census", "C2_CENSUS_IDENTITY_RECORDED", payload, actor=actor, occurred_at=occurred_at)
                connection.execute("""
                    INSERT INTO c2_census_identities (
                        identity_id, recollection_id, campaign_id, identity_key, source_id,
                        attempt_id, observation_id, evidence_digest, recorded_at, recorded_by,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (identity_id, recollection_id, recollection.campaign_id, identity_key, source_id, attempt_id, observation_id, evidence_digest, occurred_at, actor, receipt.event_id, receipt.record_hash))
        except sqlite3.IntegrityError as exc:
            raise ConflictError("identity evidence is already counted", {"identity_id": identity_id, "observation_id": observation_id}) from exc
        return self.get_identity(identity_id)

    def verify(self, recollection_id: str) -> C2CensusVerification:
        recollection_id = self._required_text(recollection_id, "recollection_id")
        defects: list[str] = []
        recollection = self.recollection.get(recollection_id)
        c2_verification = self.recollection.verify(recollection_id)
        defects.extend(f"C2_CENSUS_C2:{item}" for item in c2_verification.defects)
        research_verification = self.research.verify(recollection.campaign_id)
        defects.extend(f"C2_CENSUS_RESEARCH:{item}" for item in research_verification.defects)
        rows = self.database.connection.execute("SELECT * FROM c2_census_identities WHERE recollection_id = ? ORDER BY identity_key, identity_id", (recollection_id,)).fetchall()
        stream_id = f"continuity:c2:{recollection_id}:census"

        for row in rows:
            record = self._from_row(row)
            label = record.identity_id
            if record.campaign_id != recollection.campaign_id:
                defects.append(f"C2_IDENTITY_CAMPAIGN_MISMATCH:{label}")
            evidence = self.database.connection.execute("""
                SELECT a.campaign_id, a.source_id, r.outcome,
                       o.attempt_id AS observation_attempt_id, o.content_digest
                FROM research_attempts a
                JOIN research_receipts r ON r.attempt_id = a.attempt_id
                JOIN research_observations o ON o.attempt_id = a.attempt_id
                WHERE a.attempt_id = ? AND o.observation_id = ?
            """, (record.attempt_id, record.observation_id)).fetchone()
            if evidence is None:
                defects.append(f"C2_IDENTITY_EVIDENCE_MISSING:{label}")
            else:
                if str(evidence["campaign_id"]) != record.campaign_id:
                    defects.append(f"C2_IDENTITY_EVIDENCE_CAMPAIGN_MISMATCH:{label}")
                if str(evidence["source_id"]) != record.source_id:
                    defects.append(f"C2_IDENTITY_SOURCE_MISMATCH:{label}")
                if str(evidence["outcome"]) != ReceiptOutcome.SUCCESS.value:
                    defects.append(f"C2_IDENTITY_ATTEMPT_NOT_SUCCESS:{label}")
                if str(evidence["observation_attempt_id"]) != record.attempt_id:
                    defects.append(f"C2_IDENTITY_OBSERVATION_ATTEMPT_MISMATCH:{label}")
                if str(evidence["content_digest"]) != record.evidence_digest:
                    defects.append(f"C2_IDENTITY_EVIDENCE_DIGEST_MISMATCH:{label}")

            event = self.database.connection.execute("SELECT * FROM ledger_events WHERE event_id = ?", (record.ledger_event_id,)).fetchone()
            expected_payload = {
                "identity_id": record.identity_id, "recollection_id": record.recollection_id,
                "campaign_id": record.campaign_id, "identity_key": record.identity_key,
                "source_id": record.source_id, "attempt_id": record.attempt_id,
                "observation_id": record.observation_id, "evidence_digest": record.evidence_digest,
            }
            if event is None:
                defects.append(f"C2_IDENTITY_LEDGER_EVENT_MISSING:{label}")
            else:
                if str(event["stream_id"]) != stream_id:
                    defects.append(f"C2_IDENTITY_LEDGER_STREAM_MISMATCH:{label}")
                if str(event["kind"]) != "C2_CENSUS_IDENTITY_RECORDED":
                    defects.append(f"C2_IDENTITY_LEDGER_KIND_MISMATCH:{label}")
                if str(event["actor"]) != record.recorded_by:
                    defects.append(f"C2_IDENTITY_LEDGER_ACTOR_MISMATCH:{label}")
                if str(event["occurred_at"]) != record.recorded_at:
                    defects.append(f"C2_IDENTITY_LEDGER_TIMESTAMP_MISMATCH:{label}")
                if str(event["record_hash"]) != record.ledger_hash:
                    defects.append(f"C2_IDENTITY_LEDGER_HASH_MISMATCH:{label}")
                try:
                    event_payload = json.loads(str(event["payload_json"]))
                except (json.JSONDecodeError, TypeError):
                    defects.append(f"C2_IDENTITY_LEDGER_PAYLOAD_INVALID:{label}")
                else:
                    if event_payload != expected_payload:
                        defects.append(f"C2_IDENTITY_LEDGER_PAYLOAD_MISMATCH:{label}")

        chain = self.ledger.verify(stream_id)
        defects.extend(f"C2_CENSUS_LEDGER_CHAIN:{item.code}" for item in chain.defects)
        return C2CensusVerification(recollection_id, len(rows), recollection.minimum_identity_target, tuple(defects))

    def assess(self, recollection_id: str) -> C2CensusAssessment:
        verification = self.verify(recollection_id)
        return C2CensusAssessment(
            recollection_id=verification.recollection_id,
            identity_count=verification.identity_count,
            required_target=verification.required_target,
            eligible_for_independent_certification=(verification.ok and verification.identity_count >= verification.required_target),
            defects=verification.defects,
        )
