from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from starcom.continuity import ContinuityService
from starcom.db import Database
from starcom.errors import ConflictError, IntegrityError, StateTransitionError, ValidationError
from starcom.ledger import EventLedger
from starcom.recollection import C2RecollectionService
from starcom.research import ResearchCampaign
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule, TrustPlane


T0 = "2026-08-14T04:00:00.000000Z"
T1 = "2026-08-14T04:01:00.000000Z"
T2 = "2026-08-14T04:02:00.000000Z"
T3 = "2026-08-14T04:03:00.000000Z"
T4 = "2026-08-14T04:04:00.000000Z"
T5 = "2026-08-14T04:05:00.000000Z"
ARCHIVE_SHA256 = "5609915904205503ebcdcc548d9b8171fd6d9ba9bf9d1bb9f1ebb036bf8fae7f"
PUBLIC_KEY = b"test-public-key"


class DigestVerifier:
    def validate_public_key(self, public_key_pem: bytes) -> bool:
        return public_key_pem == PUBLIC_KEY

    def verify(self, public_key_pem: bytes, payload: bytes, signature: bytes) -> bool:
        return signature == hashlib.sha256(public_key_pem + payload).digest()


class C2RecollectionGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tempdir.name) / "c2.sqlite3")
        self.db.initialize()
        self.ledger = EventLedger(self.db)
        self.trust = TrustPlane(self.db, self.ledger)
        self.continuity = ContinuityService(self.db, self.ledger, self.trust, DigestVerifier())
        self.research = ResearchCampaign(self.db, self.ledger)
        self.c2 = C2RecollectionService(self.db, self.ledger, self.continuity, self.research)
        self.continuity.create_incident(
            "task5",
            reviewed_archive_sha256=ARCHIVE_SHA256,
            actor="owner",
            occurred_at=T0,
        )
        self.research.create(
            campaign_id="c2-campaign",
            name="Task 5 C2 live recollection",
            actor="owner",
            occurred_at=T0,
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tempdir.cleanup()

    @staticmethod
    def review_payload() -> bytes:
        value = {
            "review_id": "review-c2",
            "reviewer_identity": "independent-c2-fixture",
            "review_environment": "isolated-c2-fixture",
            "reviewed_archive_sha256": ARCHIVE_SHA256,
            "reviewed_at_utc": T1,
            "independence_basis": "fresh fixture process",
            "independent_identity_status": "SATISFIED",
            "commands_and_exit_codes": [{"command": "verify", "exit_code": 0}],
            "receipt_snapshot_observation_result": "PASS",
            "wave_order_result": "CONFIRMS_W3_TO_W2",
            "attempt_boundary_result": "POSSIBLE_UNQUANTIFIED_CONFIRMED",
            "disposition": "RECOLLECT_REQUIRED",
            "evidence_paths_and_hashes": [{"path": "review.json", "sha256": "a" * 64}],
            "reasoning": "The fixture confirms recollection is required.",
            "gate_effect": "NO_GATE_CHANGE",
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def sign(payload: bytes) -> bytes:
        return hashlib.sha256(PUBLIC_KEY + payload).digest()

    def allow(self, action: str, resource: str, rule_id: str, now: str) -> str:
        self.trust.add_rule(
            PolicyRule(rule_id, PolicyEffect.ALLOW, "owner", action, resource),
            actor="owner",
            occurred_at=T0,
        )
        decision = self.trust.authorize(
            AuthorizationRequest(subject="owner", action=action, resource=resource),
            now=now,
        )
        self.assertTrue(decision.allowed)
        return decision.decision_id

    def publish_c1_recovery(self) -> None:
        root_decision = self.allow(
            "continuity.trust-root.accept",
            "continuity:trust-root:reviewer-c2",
            "allow-c2-root",
            T1,
        )
        self.continuity.accept_trust_root(
            "reviewer-c2",
            PUBLIC_KEY,
            decision_id=root_decision,
            actor="owner",
            occurred_at=T1,
        )
        payload = self.review_payload()
        review = self.continuity.admit_review(
            "task5",
            "reviewer-c2",
            payload,
            self.sign(payload),
            actor="owner",
            occurred_at=T2,
        )
        recovery_decision = self.allow(
            "continuity.recovery.publish",
            "continuity:incident:task5",
            "allow-c2-recovery",
            T3,
        )
        self.continuity.publish_recovery(
            "task5",
            review.review_id,
            publication_id="publication-c2",
            idempotency_key="publish-c2-recovery",
            decision_id=recovery_decision,
            actor="owner",
            occurred_at=T3,
        )

    def start(self, **overrides: object):
        values: dict[str, object] = {
            "recollection_id": "recollection-c2",
            "incident_id": "task5",
            "campaign_id": "c2-campaign",
            "minimum_identity_target": 800,
            "actor": "owner",
            "occurred_at": T4,
        }
        values.update(overrides)
        return self.c2.start(**values)  # type: ignore[arg-type]

    def test_generic_research_remains_available_before_c1(self) -> None:
        attempt = self.research.begin_attempt(
            "c2-campaign",
            attempt_id="generic-attempt",
            wave=1,
            request_key="generic-key",
            source_id="generic-source",
            request={"url": "https://example.invalid"},
            actor="researcher",
            occurred_at=T1,
        )
        self.assertEqual(attempt.campaign_id, "c2-campaign")

    def test_start_blocks_before_c1_recovery_publication(self) -> None:
        with self.assertRaisesRegex(
            StateTransitionError,
            "C1 recovery must be published before C2 recollection",
        ):
            self.start()

    def test_start_rejects_preexisting_research_attempts(self) -> None:
        self.publish_c1_recovery()
        self.research.begin_attempt(
            "c2-campaign",
            attempt_id="preexisting-attempt",
            wave=1,
            request_key="preexisting-key",
            source_id="source-1",
            request={"url": "https://example.invalid"},
            actor="researcher",
            occurred_at=T3,
        )
        with self.assertRaisesRegex(StateTransitionError, "C2 campaign must be empty at binding"):
            self.start()

    def test_start_requires_minimum_identity_target_of_800(self) -> None:
        self.publish_c1_recovery()
        with self.assertRaisesRegex(ValidationError, "minimum_identity_target must be >= 800"):
            self.start(minimum_identity_target=799)

    def test_clean_c1_can_start_idempotent_verified_recollection(self) -> None:
        self.publish_c1_recovery()

        first = self.start()
        replay = self.start(occurred_at=T5)

        self.assertEqual(first, replay)
        self.assertEqual(first.incident_id, "task5")
        self.assertEqual(first.campaign_id, "c2-campaign")
        self.assertEqual(first.minimum_identity_target, 800)
        verification = self.c2.verify(first.recollection_id)
        self.assertTrue(verification.ok, verification.defects)
        event = self.db.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (first.ledger_event_id,),
        ).fetchone()
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["kind"], "C2_RECOLLECTION_STARTED")
        self.assertEqual(event["stream_id"], "continuity:c2:recollection-c2")

    def test_conflicting_recollection_replay_is_rejected(self) -> None:
        self.publish_c1_recovery()
        self.start()
        with self.assertRaises(ConflictError):
            self.start(minimum_identity_target=900)

    def test_start_rejects_tampered_c1_evidence(self) -> None:
        self.publish_c1_recovery()
        self.db.connection.execute("DROP TRIGGER continuity_reviews_no_update")
        self.db.connection.execute(
            "UPDATE continuity_reviews SET payload = ? WHERE review_id = ?",
            (self.review_payload() + b" ", "review-c2"),
        )
        with self.assertRaisesRegex(IntegrityError, "C1 incident verification failed"):
            self.start()

    def test_verifier_detects_repointed_binding_event_stream(self) -> None:
        self.publish_c1_recovery()
        record = self.start()
        payload = {
            "recollection_id": record.recollection_id,
            "incident_id": record.incident_id,
            "campaign_id": record.campaign_id,
            "minimum_identity_target": record.minimum_identity_target,
            "c1_required_status": "RECOVERY_PUBLISHED_RECOLLECT_REQUIRED",
            "pre_binding_attempt_count": 0,
        }
        forged = self.ledger.append(
            "continuity:c2:shadow",
            "C2_RECOLLECTION_STARTED",
            payload,
            actor="owner",
            occurred_at=T4,
        )
        self.db.connection.execute("DROP TRIGGER c2_recollections_no_update")
        self.db.connection.execute(
            "UPDATE c2_recollections SET ledger_event_id = ?, ledger_hash = ? WHERE recollection_id = ?",
            (forged.event_id, forged.record_hash, record.recollection_id),
        )

        verification = self.c2.verify(record.recollection_id)

        self.assertFalse(verification.ok)
        self.assertIn("C2_LEDGER_STREAM_MISMATCH", verification.defects)


if __name__ == "__main__":
    unittest.main()
