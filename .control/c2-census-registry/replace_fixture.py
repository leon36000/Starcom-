from __future__ import annotations

from pathlib import Path


PATH = Path("tests/test_census.py")

CONTENT = '''from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from starcom.census import C2CensusService
from starcom.continuity import ContinuityService
from starcom.db import Database
from starcom.errors import ConflictError, IntegrityError, StateTransitionError
from starcom.ledger import EventLedger
from starcom.recollection import C2RecollectionService
from starcom.research import ReceiptOutcome, ResearchCampaign
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule, TrustPlane


T0 = "2026-08-14T05:00:00.000000Z"
T1 = "2026-08-14T05:01:00.000000Z"
T2 = "2026-08-14T05:02:00.000000Z"
T3 = "2026-08-14T05:03:00.000000Z"
T4 = "2026-08-14T05:04:00.000000Z"
T5 = "2026-08-14T05:05:00.000000Z"
T6 = "2026-08-14T05:06:00.000000Z"
T7 = "2026-08-14T05:07:00.000000Z"
ARCHIVE_SHA256 = "5609915904205503ebcdcc548d9b8171fd6d9ba9bf9d1bb9f1ebb036bf8fae7f"
PUBLIC_KEY = b"c2-census-test-public-key"
SNAPSHOT = hashlib.sha256(b"snapshot").hexdigest()


class DigestVerifier:
    def validate_public_key(self, public_key_pem: bytes) -> bool:
        return public_key_pem == PUBLIC_KEY

    def verify(self, public_key_pem: bytes, payload: bytes, signature: bytes) -> bool:
        return signature == hashlib.sha256(public_key_pem + payload).digest()


class C2CensusIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tempdir.name) / "census.sqlite3")
        self.db.initialize()
        self.ledger = EventLedger(self.db)
        self.trust = TrustPlane(self.db, self.ledger)
        self.continuity = ContinuityService(
            self.db,
            self.ledger,
            self.trust,
            DigestVerifier(),
        )
        self.research = ResearchCampaign(self.db, self.ledger)
        self.recollection = C2RecollectionService(
            self.db,
            self.ledger,
            self.continuity,
            self.research,
        )
        self.continuity.create_incident(
            "task5",
            reviewed_archive_sha256=ARCHIVE_SHA256,
            actor="owner",
            occurred_at=T0,
        )
        self.research.create(
            campaign_id="c2-campaign",
            name="C2 live census fixture",
            actor="owner",
            occurred_at=T0,
        )
        self.publish_c1_recovery()
        self.recollection.start(
            "c2-run",
            incident_id="task5",
            campaign_id="c2-campaign",
            minimum_identity_target=800,
            actor="owner",
            occurred_at=T4,
        )
        self.census = C2CensusService(
            self.db,
            self.ledger,
            self.recollection,
            self.research,
        )
        self._prepared_attempt = False

    def tearDown(self) -> None:
        self.db.close()
        self.tempdir.cleanup()

    @staticmethod
    def review_payload() -> bytes:
        value = {
            "review_id": "review-c2-census",
            "reviewer_identity": "independent-c2-census-fixture",
            "review_environment": "isolated-c2-census-fixture",
            "reviewed_archive_sha256": ARCHIVE_SHA256,
            "reviewed_at_utc": T1,
            "independence_basis": "fresh deterministic fixture process",
            "independent_identity_status": "SATISFIED",
            "commands_and_exit_codes": [{"command": "verify", "exit_code": 0}],
            "receipt_snapshot_observation_result": "PASS",
            "wave_order_result": "CONFIRMS_W3_TO_W2",
            "attempt_boundary_result": "POSSIBLE_UNQUANTIFIED_CONFIRMED",
            "disposition": "RECOLLECT_REQUIRED",
            "evidence_paths_and_hashes": [
                {"path": "review.json", "sha256": "a" * 64}
            ],
            "reasoning": "The deterministic fixture confirms recollection is required.",
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
            "continuity:trust-root:reviewer-c2-census",
            "allow-c2-census-root",
            T1,
        )
        self.continuity.accept_trust_root(
            "reviewer-c2-census",
            PUBLIC_KEY,
            decision_id=root_decision,
            actor="owner",
            occurred_at=T1,
        )
        payload = self.review_payload()
        review = self.continuity.admit_review(
            "task5",
            "reviewer-c2-census",
            payload,
            self.sign(payload),
            actor="owner",
            occurred_at=T2,
        )
        recovery_decision = self.allow(
            "continuity.recovery.publish",
            "continuity:incident:task5",
            "allow-c2-census-recovery",
            T3,
        )
        self.continuity.publish_recovery(
            "task5",
            review.review_id,
            publication_id="publication-c2-census",
            idempotency_key="publish-c2-census-recovery",
            decision_id=recovery_decision,
            actor="owner",
            occurred_at=T3,
        )
        verification = self.continuity.verify_incident("task5")
        self.assertTrue(verification.ok, verification.defects)

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
            occurred_at=T5,
        )
        self.research.record_receipt(
            "attempt-1",
            receipt_id="receipt-1",
            outcome=ReceiptOutcome.SUCCESS,
            status_code=200,
            snapshot_digest=SNAPSHOT,
            metadata={"fixture": True},
            actor="researcher",
            occurred_at=T5,
        )
        self.research.checkpoint_cursor(
            "c2-campaign",
            wave=1,
            cursor_key="page",
            value={"page": 1},
            attempt_id="attempt-1",
            actor="researcher",
            cursor_id="cursor-1",
            occurred_at=T6,
        )
        self._prepared_attempt = True
        return "attempt-1"

    def add_observation(
        self,
        index: int,
        *,
        attempt_id: str = "attempt-1",
    ) -> tuple[str, str]:
        observation_id = f"observation-{index:04d}"
        digest = hashlib.sha256(f"identity-{index:04d}".encode()).hexdigest()
        self.research.record_observation(
            attempt_id,
            observation_id=observation_id,
            snapshot_digest=SNAPSHOT,
            content_digest=digest,
            data={"identity": f"identity-{index:04d}", "fixture": True},
            actor="researcher",
            occurred_at=T6,
        )
        return observation_id, digest

    def register(
        self,
        index: int,
        *,
        identity_key: str | None = None,
        source_id: str = "github",
    ):
        return self.census.register_identity(
            "c2-run",
            identity_id=f"identity-record-{index:04d}",
            identity_key=identity_key or f"identity-{index:04d}",
            source_id=source_id,
            attempt_id="attempt-1",
            observation_id=f"observation-{index:04d}",
            actor="researcher",
            occurred_at=T7,
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
            occurred_at=T7,
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
                occurred_at=T7,
            )
        self.assertEqual(self.census.assess("c2-run").identity_count, 1)

    def test_foreign_source_and_dirty_c2_are_rejected(self) -> None:
        self.prepare_success_attempt(source_id="github")
        self.add_observation(1)

        with self.assertRaisesRegex(
            StateTransitionError,
            "identity source does not match attempt",
        ):
            self.register(1, source_id="gitlab")

        self.db.connection.execute("DROP TRIGGER c2_recollections_no_update")
        self.db.connection.execute(
            "UPDATE c2_recollections SET ledger_hash = ? WHERE recollection_id = ?",
            ("0" * 64, "c2-run"),
        )
        with self.assertRaisesRegex(
            IntegrityError,
            "C2 recollection verification failed",
        ):
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
            occurred_at=T7,
        )
        self.db.connection.execute("DROP TRIGGER c2_census_identities_no_update")
        self.db.connection.execute(
            """
            UPDATE c2_census_identities
            SET ledger_event_id = ?, ledger_hash = ?
            WHERE identity_id = ?
            """,
            (forged.event_id, forged.record_hash, record.identity_id),
        )

        verification = self.census.verify("c2-run")

        self.assertFalse(verification.ok)
        self.assertIn(
            f"C2_IDENTITY_LEDGER_STREAM_MISMATCH:{record.identity_id}",
            verification.defects,
        )

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
'''


def main() -> int:
    source = PATH.read_text(encoding="utf-8")
    if "class FakeRecollectionService" not in source:
        raise SystemExit("fixture replacement refused: fake recollection marker missing")
    if source.count("C2CensusIdentityTests") != 1:
        raise SystemExit("fixture replacement refused: unexpected census test shape")
    PATH.write_text(CONTENT, encoding="utf-8")
    print("replaced fake C2 fixture with real C1 publication and C2 binding")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
