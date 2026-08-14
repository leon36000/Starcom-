from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
import unittest

from starcom.census import C2CensusService
from starcom.db import Database
from starcom.errors import ConflictError, IntegrityError, StateTransitionError
from starcom.ledger import EventLedger
from starcom.recollection import C2RecollectionRecord, C2RecollectionVerification
from starcom.research import ReceiptOutcome, ResearchCampaign


T0 = "2026-08-14T05:00:00.000000Z"
T1 = "2026-08-14T05:01:00.000000Z"
T2 = "2026-08-14T05:02:00.000000Z"
T3 = "2026-08-14T05:03:00.000000Z"
SNAPSHOT = hashlib.sha256(b"snapshot").hexdigest()


class FakeRecollectionService:
    def __init__(self, record: C2RecollectionRecord) -> None:
        self.record = record
        self.defects: tuple[str, ...] = ()

    def get(self, recollection_id: str) -> C2RecollectionRecord:
        if recollection_id != self.record.recollection_id:
            raise AssertionError("unexpected recollection id")
        return self.record

    def verify(self, recollection_id: str) -> C2RecollectionVerification:
        self.get(recollection_id)
        return C2RecollectionVerification(recollection_id, self.defects)


class C2CensusIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tempdir.name) / "census.sqlite3")
        self.db.initialize()
        self.ledger = EventLedger(self.db)
        self.research = ResearchCampaign(self.db, self.ledger)
        self.research.create(
            campaign_id="c2-campaign",
            name="C2 live census fixture",
            actor="owner",
            occurred_at=T0,
        )
        self.recollection_record = C2RecollectionRecord(
            recollection_id="c2-run",
            incident_id="task5",
            campaign_id="c2-campaign",
            minimum_identity_target=800,
            started_at=T0,
            started_by="owner",
            ledger_event_id="fixture-c2-event",
            ledger_hash="f" * 64,
        )
        self.recollection = FakeRecollectionService(self.recollection_record)
        self.census = C2CensusService(
            self.db,
            self.ledger,
            self.recollection,  # type: ignore[arg-type]
            self.research,
        )
        self._prepared_attempt = False

    def tearDown(self) -> None:
        self.db.close()
        self.tempdir.cleanup()

    def prepare_success_attempt(self, *, source_id: str = "github") -> str:
        if self._prepared_attempt:
            return "attempt-1"
        self.research.begin_attempt(
            "c2-campaign",
            attempt_id="attempt-1",
            wave=1,
            request_key="request-1",
            source_id=source_id,
            request={"url": "https://example.invalid/source"},
            actor="researcher",
            occurred_at=T1,
        )
        self.research.record_receipt(
            "attempt-1",
            receipt_id="receipt-1",
            outcome=ReceiptOutcome.SUCCESS,
            status_code=200,
            snapshot_digest=SNAPSHOT,
            metadata={"fixture": True},
            actor="researcher",
            occurred_at=T1,
        )
        self.research.checkpoint_cursor(
            "c2-campaign",
            wave=1,
            cursor_key="page",
            value={"page": 1},
            attempt_id="attempt-1",
            actor="researcher",
            cursor_id="cursor-1",
            occurred_at=T2,
        )
        self._prepared_attempt = True
        return "attempt-1"

    def add_observation(self, index: int, *, attempt_id: str = "attempt-1") -> tuple[str, str]:
        observation_id = f"observation-{index:04d}"
        digest = hashlib.sha256(f"identity-{index:04d}".encode()).hexdigest()
        self.research.record_observation(
            attempt_id,
            observation_id=observation_id,
            snapshot_digest=SNAPSHOT,
            content_digest=digest,
            data={"identity": f"identity-{index:04d}", "fixture": True},
            actor="researcher",
            occurred_at=T2,
        )
        return observation_id, digest

    def register(self, index: int, *, identity_key: str | None = None, source_id: str = "github"):
        return self.census.register_identity(
            "c2-run",
            identity_id=f"identity-record-{index:04d}",
            identity_key=identity_key or f"identity-{index:04d}",
            source_id=source_id,
            attempt_id="attempt-1",
            observation_id=f"observation-{index:04d}",
            actor="researcher",
            occurred_at=T3,
        )

    def test_below_threshold_is_clean_but_not_eligible(self) -> None:
        self.prepare_success_attempt()
        _, digest = self.add_observation(1)

        record = self.register(1)
        assessment = self.census.assess("c2-run")

        self.assertEqual(record.evidence_digest, digest)
        self.assertEqual(assessment.identity_count, 1)
        self.assertEqual(assessment.required_target, 800)
        self.assertEqual(assessment.defects, ())
        self.assertFalse(assessment.eligible_for_independent_certification)

    def test_exact_replay_is_idempotent_and_conflicting_identity_key_is_rejected(self) -> None:
        self.prepare_success_attempt()
        self.add_observation(1)
        self.add_observation(2)
        first = self.register(1, identity_key="same-person")

        replay = self.census.register_identity(
            "c2-run",
            identity_id="ignored-on-exact-replay",
            identity_key="same-person",
            source_id="github",
            attempt_id="attempt-1",
            observation_id="observation-0001",
            actor="researcher",
            occurred_at=T3,
        )

        self.assertEqual(first, replay)
        with self.assertRaises(ConflictError):
            self.census.register_identity(
                "c2-run",
                identity_id="identity-conflict",
                identity_key="same-person",
                source_id="github",
                attempt_id="attempt-1",
                observation_id="observation-0002",
                actor="researcher",
                occurred_at=T3,
            )
        self.assertEqual(self.census.assess("c2-run").identity_count, 1)

    def test_foreign_source_and_dirty_c2_are_rejected(self) -> None:
        self.prepare_success_attempt(source_id="github")
        self.add_observation(1)

        with self.assertRaisesRegex(StateTransitionError, "identity source does not match attempt"):
            self.register(1, source_id="gitlab")

        self.recollection.defects = ("C2_LEDGER_CHAIN:HASH_MISMATCH",)
        with self.assertRaisesRegex(IntegrityError, "C2 recollection verification failed"):
            self.register(1)

    def test_verifier_detects_repointed_identity_event(self) -> None:
        self.prepare_success_attempt()
        self.add_observation(1)
        record = self.register(1)
        forged = self.ledger.append(
            "continuity:c2:shadow:census",
            "C2_CENSUS_IDENTITY_RECORDED",
            {
                "identity_id": record.identity_id,
                "recollection_id": record.recollection_id,
                "campaign_id": record.campaign_id,
                "identity_key": record.identity_key,
                "source_id": record.source_id,
                "attempt_id": record.attempt_id,
                "observation_id": record.observation_id,
                "evidence_digest": record.evidence_digest,
            },
            actor="researcher",
            occurred_at=T3,
        )
        self.db.connection.execute("DROP TRIGGER c2_census_identities_no_update")
        self.db.connection.execute(
            "UPDATE c2_census_identities SET ledger_event_id = ?, ledger_hash = ? WHERE identity_id = ?",
            (forged.event_id, forged.record_hash, record.identity_id),
        )

        verification = self.census.verify("c2-run")

        self.assertFalse(verification.ok)
        self.assertIn(f"C2_IDENTITY_LEDGER_STREAM_MISMATCH:{record.identity_id}", verification.defects)

    def test_800_unique_evidence_bound_identities_become_pre_certification_eligible(self) -> None:
        self.prepare_success_attempt()
        for index in range(800):
            self.add_observation(index)
            self.register(index)

        assessment = self.census.assess("c2-run")

        self.assertEqual(assessment.identity_count, 800)
        self.assertEqual(assessment.required_target, 800)
        self.assertEqual(assessment.defects, ())
        self.assertTrue(assessment.eligible_for_independent_certification)


if __name__ == "__main__":
    unittest.main()
