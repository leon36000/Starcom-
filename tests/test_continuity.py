from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from starcom.continuity import ContinuityService, IncidentStatus, OpenSSLEd25519Verifier
from starcom.db import Database
from starcom.errors import AuthorizationError, ConflictError, IntegrityError, StateTransitionError, ValidationError
from starcom.ledger import EventLedger
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule, TrustPlane


T0 = "2026-08-13T12:00:00.000000Z"
T1 = "2026-08-13T12:01:00.000000Z"
T2 = "2026-08-13T12:02:00.000000Z"
T3 = "2026-08-13T12:03:00.000000Z"
ARCHIVE_SHA256 = "5609915904205503ebcdcc548d9b8171fd6d9ba9bf9d1bb9f1ebb036bf8fae7f"
PUBLIC_KEY = b"test-public-key"
ED25519_PAYLOAD = base64.b64decode("eyJtZXNzYWdlIjoic3RhcmNvbS1lZDI1NTE5LWZpeHR1cmUifQ==")
ED25519_PUBLIC_KEY = base64.b64decode("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQXlETWM5Y2FCOXZUTjMreWVSQUY0WUl6T09Denp3aUk2OERHUk5BV0VpZ0E9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=")
ED25519_SIGNATURE = base64.b64decode("sVvNoBFRlOSidG1OKKKO0lDRhhn5eKazwxnlSWTkV0syiaWL++h4h7sJ5zKcKt+oCIrLTCVyG4XH+CgjaA2aBQ==")


class DigestVerifier:
    def validate_public_key(self, public_key_pem: bytes) -> bool:
        return public_key_pem == PUBLIC_KEY

    def verify(self, public_key_pem: bytes, payload: bytes, signature: bytes) -> bool:
        expected = hashlib.sha256(public_key_pem + payload).digest()
        return signature == expected


class ContinuityServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tempdir.name) / "continuity.sqlite3")
        self.db.initialize()
        self.ledger = EventLedger(self.db)
        self.trust = TrustPlane(self.db, self.ledger)
        self.service = ContinuityService(self.db, self.ledger, self.trust, DigestVerifier())
        self.service.create_incident(
            "task5", reviewed_archive_sha256=ARCHIVE_SHA256, actor="owner", occurred_at=T0
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tempdir.cleanup()

    @staticmethod
    def sign(payload: bytes) -> bytes:
        return hashlib.sha256(PUBLIC_KEY + payload).digest()

    @staticmethod
    def review_payload(**overrides: object) -> bytes:
        payload: dict[str, object] = {
            "review_id": "review-1",
            "reviewer_identity": "independent-agent-1",
            "review_environment": "isolated-worker-1",
            "reviewed_archive_sha256": ARCHIVE_SHA256,
            "reviewed_at_utc": T1,
            "independence_basis": "fresh process and isolated extraction",
            "independent_identity_status": "SATISFIED",
            "commands_and_exit_codes": [{"command": "verify", "exit_code": 0}],
            "receipt_snapshot_observation_result": "PASS",
            "wave_order_result": "CONFIRMS_W3_TO_W2",
            "attempt_boundary_result": "POSSIBLE_UNQUANTIFIED_CONFIRMED",
            "disposition": "RECOLLECT_REQUIRED",
            "evidence_paths_and_hashes": [{"path": "review.json", "sha256": "a" * 64}],
            "reasoning": "The evidence confirms the nonconforming wave order.",
            "gate_effect": "NO_GATE_CHANGE",
        }
        payload.update(overrides)
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def allow(self, action: str, resource: str, rule_id: str) -> str:
        self.trust.add_rule(
            PolicyRule(rule_id, PolicyEffect.ALLOW, "owner", action, resource),
            actor="owner",
            occurred_at=T0,
        )
        decision = self.trust.authorize(
            AuthorizationRequest(subject="owner", action=action, resource=resource), now=T1
        )
        self.assertTrue(decision.allowed)
        return decision.decision_id

    def accept_root(self) -> None:
        decision_id = self.allow(
            "continuity.trust-root.accept",
            "continuity:trust-root:reviewer-1",
            "allow-root",
        )
        self.service.accept_trust_root(
            "reviewer-1", PUBLIC_KEY, decision_id=decision_id, actor="owner", occurred_at=T1
        )

    def admit_review(self, payload: bytes | None = None):
        raw = payload or self.review_payload()
        return self.service.admit_review(
            "task5",
            "reviewer-1",
            raw,
            self.sign(raw),
            actor="owner",
            occurred_at=T2,
        )

    def publication_decision(self, action: str = "continuity.recovery.publish") -> str:
        return self.allow(action, "continuity:incident:task5", f"allow-{action}")

    def test_openssl_verifies_exact_public_fixture(self) -> None:
        verifier = OpenSSLEd25519Verifier()
        self.assertTrue(verifier.validate_public_key(ED25519_PUBLIC_KEY))
        self.assertTrue(verifier.verify(ED25519_PUBLIC_KEY, ED25519_PAYLOAD, ED25519_SIGNATURE))
        self.assertFalse(verifier.verify(ED25519_PUBLIC_KEY, ED25519_PAYLOAD + b" ", ED25519_SIGNATURE))

    def test_default_deny_blocks_trust_root_acceptance(self) -> None:
        decision = self.trust.authorize(
            AuthorizationRequest(
                subject="owner",
                action="continuity.trust-root.accept",
                resource="continuity:trust-root:reviewer-1",
            ),
            now=T1,
        )
        with self.assertRaises(AuthorizationError):
            self.service.accept_trust_root(
                "reviewer-1", PUBLIC_KEY, decision_id=decision.decision_id, actor="owner", occurred_at=T1
            )

    def test_review_admission_is_exact_and_idempotent(self) -> None:
        self.accept_root()
        payload = self.review_payload()
        signature = self.sign(payload)
        first = self.service.admit_review(
            "task5", "reviewer-1", payload, signature, actor="owner", occurred_at=T2
        )
        second = self.service.admit_review(
            "task5", "reviewer-1", payload, signature, actor="owner", occurred_at=T3
        )
        self.assertEqual(first, second)
        self.assertEqual(first.disposition, "RECOLLECT_REQUIRED")
        with self.assertRaises(IntegrityError):
            self.service.admit_review(
                "task5", "reviewer-1", payload + b" ", signature, actor="owner", occurred_at=T3
            )

    def test_missing_required_review_field_is_rejected(self) -> None:
        self.accept_root()
        decoded = json.loads(self.review_payload())
        del decoded["independence_basis"]
        payload = json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode("utf-8")
        with self.assertRaises(ValidationError):
            self.service.admit_review(
                "task5", "reviewer-1", payload, self.sign(payload), actor="owner", occurred_at=T2
            )

    def test_recovery_requires_exact_signed_findings(self) -> None:
        self.accept_root()
        review = self.admit_review(self.review_payload(wave_order_result="DOES_NOT_CONFIRM"))
        decision_id = self.publication_decision()
        with self.assertRaises(StateTransitionError):
            self.service.publish_recovery(
                "task5",
                review.review_id,
                publication_id="publication-1",
                idempotency_key="recover-task5",
                decision_id=decision_id,
                actor="owner",
                occurred_at=T3,
            )

    def test_recovery_requires_exact_trust_decision(self) -> None:
        self.accept_root()
        review = self.admit_review()
        decision_id = self.publication_decision("continuity.recovery.preview")
        with self.assertRaises(AuthorizationError):
            self.service.publish_recovery(
                "task5",
                review.review_id,
                publication_id="publication-1",
                idempotency_key="recover-task5",
                decision_id=decision_id,
                actor="owner",
                occurred_at=T3,
            )

    def test_publication_is_one_time_and_preserves_recollect_required(self) -> None:
        self.accept_root()
        review = self.admit_review()
        decision_id = self.publication_decision()
        first = self.service.publish_recovery(
            "task5",
            review.review_id,
            publication_id="publication-1",
            idempotency_key="recover-task5",
            decision_id=decision_id,
            actor="owner",
            occurred_at=T3,
        )
        second = self.service.publish_recovery(
            "task5",
            review.review_id,
            publication_id="publication-1",
            idempotency_key="recover-task5",
            decision_id=decision_id,
            actor="owner",
            occurred_at=T3,
        )
        self.assertEqual(first, second)
        self.assertEqual(first.status, IncidentStatus.RECOVERY_PUBLISHED_RECOLLECT_REQUIRED)
        self.assertEqual(self.service.get_incident("task5").disposition, "RECOLLECT_REQUIRED")
        with self.assertRaises(ConflictError):
            self.service.publish_recovery(
                "task5",
                review.review_id,
                publication_id="publication-2",
                idempotency_key="different",
                decision_id=decision_id,
                actor="owner",
                occurred_at=T3,
            )

    def test_verifier_detects_review_payload_tampering(self) -> None:
        self.accept_root()
        review = self.admit_review()
        decision_id = self.publication_decision()
        self.service.publish_recovery(
            "task5",
            review.review_id,
            publication_id="publication-1",
            idempotency_key="recover-task5",
            decision_id=decision_id,
            actor="owner",
            occurred_at=T3,
        )
        self.db.connection.execute("DROP TRIGGER continuity_reviews_no_update")
        self.db.connection.execute(
            "UPDATE continuity_reviews SET payload = ? WHERE review_id = ?",
            (self.review_payload(reasoning="tampered"), review.review_id),
        )
        verification = self.service.verify_incident("task5")
        self.assertFalse(verification.ok)
        self.assertIn("REVIEW_PAYLOAD_DIGEST_MISMATCH:review-1", verification.defects)
        self.assertIn("REVIEW_SIGNATURE_INVALID:review-1", verification.defects)


if __name__ == "__main__":
    unittest.main()
