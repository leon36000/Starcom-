from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from starcom.census import C2CensusService
from starcom.certification import C2CertificationService
from starcom.continuity import ContinuityService, IncidentStatus
from starcom.db import Database
from starcom.errors import ConflictError, IntegrityError, StateTransitionError
from starcom.ledger import EventLedger
from starcom.recollection import C2RecollectionService
from starcom.research import ReceiptOutcome, ResearchCampaign
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule, TrustPlane


C0 = "2026-08-14T06:00:00.000000Z"
C1 = "2026-08-14T06:01:00.000000Z"
C2 = "2026-08-14T06:02:00.000000Z"
C3 = "2026-08-14T06:03:00.000000Z"
C4 = "2026-08-14T06:04:00.000000Z"
C5 = "2026-08-14T06:05:00.000000Z"
C6 = "2026-08-14T06:06:00.000000Z"
C7 = "2026-08-14T06:07:00.000000Z"
C8 = "2026-08-14T06:08:00.000000Z"
C9 = "2026-08-14T06:09:00.000000Z"
C10 = "2026-08-14T06:10:00.000000Z"
C11 = "2026-08-14T06:11:00.000000Z"
ARCHIVE_SHA256 = "5609915904205503ebcdcc548d9b8171fd6d9ba9bf9d1bb9f1ebb036bf8fae7f"
REVIEWER_KEY = b"c2-certification-reviewer-key"
CERTIFIER_KEY = b"c2-independent-certifier-key"
SNAPSHOT_DIGEST = hashlib.sha256(b"c2-certification-snapshot").hexdigest()


class DigestVerifier:
    VALID_KEYS = {REVIEWER_KEY, CERTIFIER_KEY}

    def validate_public_key(self, public_key_pem: bytes) -> bool:
        return public_key_pem in self.VALID_KEYS

    def verify(self, public_key_pem: bytes, payload: bytes, signature: bytes) -> bool:
        return (
            public_key_pem in self.VALID_KEYS
            and signature == hashlib.sha256(public_key_pem + payload).digest()
        )


class C2SignedCertificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tempdir.name) / "certification.sqlite3")
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
        self.census = C2CensusService(
            self.db,
            self.ledger,
            self.recollection,
            self.research,
        )
        self.certification = C2CertificationService(
            self.db,
            self.ledger,
            self.continuity,
            self.recollection,
            self.census,
        )
        self.continuity.create_incident(
            "task5",
            reviewed_archive_sha256=ARCHIVE_SHA256,
            actor="owner",
            occurred_at=C0,
        )
        self.research.create(
            campaign_id="c2-campaign",
            name="Task 5 independently certified C2 census",
            actor="owner",
            occurred_at=C0,
        )
        self.publish_c1_recovery()
        self.recollection.start(
            "c2-run",
            incident_id="task5",
            campaign_id="c2-campaign",
            minimum_identity_target=800,
            actor="owner",
            occurred_at=C4,
        )
        self.accept_certifier_root()
        self.prepare_success_attempt()

    def tearDown(self) -> None:
        self.db.close()
        self.tempdir.cleanup()

    @staticmethod
    def sign(key: bytes, payload: bytes) -> bytes:
        return hashlib.sha256(key + payload).digest()

    @staticmethod
    def review_payload() -> bytes:
        value = {
            "review_id": "review-certification",
            "reviewer_identity": "independent-c1-reviewer",
            "review_environment": "isolated-certification-fixture",
            "reviewed_archive_sha256": ARCHIVE_SHA256,
            "reviewed_at_utc": C1,
            "independence_basis": "separate deterministic fixture identity",
            "independent_identity_status": "SATISFIED",
            "commands_and_exit_codes": [{"command": "verify", "exit_code": 0}],
            "receipt_snapshot_observation_result": "PASS",
            "wave_order_result": "CONFIRMS_W3_TO_W2",
            "attempt_boundary_result": "POSSIBLE_UNQUANTIFIED_CONFIRMED",
            "disposition": "RECOLLECT_REQUIRED",
            "evidence_paths_and_hashes": [
                {"path": "review.json", "sha256": "a" * 64}
            ],
            "reasoning": "The fixture confirms recollection is required.",
            "gate_effect": "NO_GATE_CHANGE",
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def allow(self, action: str, resource: str, rule_id: str, now: str) -> str:
        self.trust.add_rule(
            PolicyRule(rule_id, PolicyEffect.ALLOW, "owner", action, resource),
            actor="owner",
            occurred_at=C0,
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
            "continuity:trust-root:reviewer-certification",
            "allow-certification-reviewer-root",
            C1,
        )
        self.continuity.accept_trust_root(
            "reviewer-certification",
            REVIEWER_KEY,
            decision_id=root_decision,
            actor="owner",
            occurred_at=C1,
        )
        payload = self.review_payload()
        review = self.continuity.admit_review(
            "task5",
            "reviewer-certification",
            payload,
            self.sign(REVIEWER_KEY, payload),
            actor="owner",
            occurred_at=C2,
        )
        recovery_decision = self.allow(
            "continuity.recovery.publish",
            "continuity:incident:task5",
            "allow-certification-recovery",
            C3,
        )
        publication = self.continuity.publish_recovery(
            "task5",
            review.review_id,
            publication_id="publication-certification",
            idempotency_key="publish-certification-recovery",
            decision_id=recovery_decision,
            actor="owner",
            occurred_at=C3,
        )
        self.assertEqual(
            publication.status,
            IncidentStatus.RECOVERY_PUBLISHED_RECOLLECT_REQUIRED,
        )

    def accept_certifier_root(self) -> None:
        decision_id = self.allow(
            "continuity.trust-root.accept",
            "continuity:trust-root:certifier-c2",
            "allow-independent-certifier-root",
            C5,
        )
        self.continuity.accept_trust_root(
            "certifier-c2",
            CERTIFIER_KEY,
            decision_id=decision_id,
            actor="owner",
            occurred_at=C5,
        )
        verification = self.continuity.verify_trust_root("certifier-c2")
        self.assertTrue(verification.ok, verification.defects)

    def prepare_success_attempt(self) -> None:
        self.research.begin_attempt(
            "c2-campaign",
            attempt_id="attempt-certification",
            wave=1,
            request_key="request-certification",
            source_id="github",
            request={"url": "https://example.invalid/census"},
            actor="collector",
            occurred_at=C6,
        )
        self.research.record_receipt(
            "attempt-certification",
            receipt_id="receipt-certification",
            outcome=ReceiptOutcome.SUCCESS,
            status_code=200,
            snapshot_digest=SNAPSHOT_DIGEST,
            metadata={"fixture": True},
            actor="collector",
            occurred_at=C6,
        )
        self.research.checkpoint_cursor(
            "c2-campaign",
            wave=1,
            cursor_key="page",
            value={"page": 1},
            attempt_id="attempt-certification",
            cursor_id="cursor-certification",
            actor="collector",
            occurred_at=C7,
        )

    def add_identity(self, index: int, *, occurred_at: str = C8) -> None:
        identity_key = f"identity-{index:04d}"
        observation_id = f"observation-{index:04d}"
        content_digest = hashlib.sha256(identity_key.encode("utf-8")).hexdigest()
        self.research.record_observation(
            "attempt-certification",
            observation_id=observation_id,
            snapshot_digest=SNAPSHOT_DIGEST,
            content_digest=content_digest,
            data={"identity": identity_key, "fixture": True},
            actor="collector",
            occurred_at=C7,
        )
        self.census.register_identity(
            "c2-run",
            identity_id=f"identity-record-{index:04d}",
            identity_key=identity_key,
            source_id="github",
            attempt_id="attempt-certification",
            observation_id=observation_id,
            actor="collector",
            occurred_at=occurred_at,
        )

    def add_identities(self, count: int) -> None:
        for index in range(count):
            self.add_identity(index)

    def certification_payload(
        self,
        *,
        certificate_id: str = "certificate-c2-800",
        certifier_identity: str = "independent-certifier",
    ) -> bytes:
        snapshot = self.certification.snapshot("c2-run")
        value = {
            "certificate_id": certificate_id,
            "recollection_id": snapshot.recollection_id,
            "incident_id": snapshot.incident_id,
            "campaign_id": snapshot.campaign_id,
            "identity_count": snapshot.identity_count,
            "required_target": snapshot.required_target,
            "identity_set_digest": snapshot.identity_set_digest,
            "certifier_identity": certifier_identity,
            "certifier_environment": "isolated-independent-certifier",
            "certified_at_utc": C9,
            "independence_basis": "separate identity, key and execution boundary",
            "independent_identity_status": "SATISFIED",
            "census_verification_result": "PASS",
            "verdict": "C2_CENSUS_CERTIFIED",
            "gate_effect": "NO_CANONICAL_PROMOTION",
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def admit(
        self,
        payload: bytes,
        signature: bytes | None = None,
        *,
        occurred_at: str = C10,
    ):
        return self.certification.admit_certification(
            "c2-run",
            "certifier-c2",
            payload,
            signature if signature is not None else self.sign(CERTIFIER_KEY, payload),
            actor="admission-agent",
            occurred_at=occurred_at,
        )

    def admit_valid_800(self):
        self.add_identities(800)
        payload = self.certification_payload()
        return self.admit(payload), payload

    def test_below_target_is_rejected(self) -> None:
        self.add_identity(0)
        payload = self.certification_payload(certificate_id="certificate-below-target")

        with self.assertRaisesRegex(
            StateTransitionError,
            "C2 census is not eligible for independent certification",
        ):
            self.admit(payload)

    def test_invalid_exact_byte_signature_is_rejected(self) -> None:
        self.add_identities(800)
        payload = self.certification_payload(certificate_id="certificate-invalid-signature")

        with self.assertRaisesRegex(
            IntegrityError,
            "C2 certification signature is invalid",
        ):
            self.admit(payload, b"invalid-signature")

    def test_non_independent_certifier_is_rejected(self) -> None:
        self.add_identities(800)
        payload = self.certification_payload(
            certificate_id="certificate-not-independent",
            certifier_identity="collector",
        )

        with self.assertRaisesRegex(
            StateTransitionError,
            "certifier identity is not independent",
        ):
            self.admit(payload)

    def test_exact_800_member_certificate_is_stored_verified_and_idempotent(self) -> None:
        certificate, payload = self.admit_valid_800()
        signature = self.sign(CERTIFIER_KEY, payload)

        self.assertEqual(certificate.identity_count, 800)
        self.assertEqual(certificate.required_target, 800)
        self.assertEqual(certificate.payload_sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(certificate.signature_sha256, hashlib.sha256(signature).hexdigest())
        stored = self.db.connection.execute(
            "SELECT payload, signature FROM c2_certifications WHERE certificate_id = ?",
            (certificate.certificate_id,),
        ).fetchone()
        self.assertIsNotNone(stored)
        assert stored is not None
        self.assertEqual(bytes(stored["payload"]), payload)
        self.assertEqual(bytes(stored["signature"]), signature)
        member_count = self.db.connection.execute(
            "SELECT COUNT(*) FROM c2_certification_members WHERE certificate_id = ?",
            (certificate.certificate_id,),
        ).fetchone()[0]
        self.assertEqual(member_count, 800)
        verification = self.certification.verify_certificate(certificate.certificate_id)
        self.assertTrue(verification.ok, verification.defects)

        replay = self.admit(payload, signature, occurred_at=C11)
        self.assertEqual(replay, certificate)

    def test_modified_payload_with_original_signature_is_rejected(self) -> None:
        self.add_identities(800)
        payload = self.certification_payload(certificate_id="certificate-payload-tamper")
        signature = self.sign(CERTIFIER_KEY, payload)

        with self.assertRaisesRegex(
            IntegrityError,
            "C2 certification signature is invalid",
        ):
            self.admit(payload + b" ", signature)

    def test_membership_tampering_is_detected(self) -> None:
        certificate, _ = self.admit_valid_800()
        self.db.connection.execute("DROP TRIGGER c2_certification_members_no_update")
        self.db.connection.execute(
            """
            UPDATE c2_certification_members
            SET evidence_digest = ?
            WHERE certificate_id = ? AND ordinal = 0
            """,
            ("0" * 64, certificate.certificate_id),
        )

        verification = self.certification.verify_certificate(certificate.certificate_id)

        self.assertFalse(verification.ok)
        self.assertIn("C2_CERT_MEMBER_MATERIAL_MISMATCH:0", verification.defects)

    def test_certification_event_repointing_is_detected(self) -> None:
        certificate, _ = self.admit_valid_800()
        payload = {
            "certificate_id": certificate.certificate_id,
            "recollection_id": certificate.recollection_id,
            "key_id": certificate.key_id,
            "payload_sha256": certificate.payload_sha256,
            "signature_sha256": certificate.signature_sha256,
            "identity_count": certificate.identity_count,
            "required_target": certificate.required_target,
            "identity_set_digest": certificate.identity_set_digest,
            "verdict": "C2_CENSUS_CERTIFIED",
        }
        forged = self.ledger.append(
            "continuity:c2:shadow:certification",
            "C2_CENSUS_CERTIFICATION_ADMITTED",
            payload,
            actor="admission-agent",
            occurred_at=C10,
        )
        self.db.connection.execute("DROP TRIGGER c2_certifications_no_update")
        self.db.connection.execute(
            """
            UPDATE c2_certifications
            SET ledger_event_id = ?, ledger_hash = ?
            WHERE certificate_id = ?
            """,
            (forged.event_id, forged.record_hash, certificate.certificate_id),
        )

        verification = self.certification.verify_certificate(certificate.certificate_id)

        self.assertFalse(verification.ok)
        self.assertIn("C2_CERT_LEDGER_STREAM_MISMATCH", verification.defects)

    def test_certified_snapshot_remains_stable_after_later_identity(self) -> None:
        certificate, payload = self.admit_valid_800()
        original_digest = certificate.identity_set_digest
        self.add_identity(800, occurred_at=C11)
        assessment = self.census.assess("c2-run")
        self.assertEqual(assessment.identity_count, 801)

        verification = self.certification.verify_certificate(certificate.certificate_id)
        self.assertTrue(verification.ok, verification.defects)
        member_count = self.db.connection.execute(
            "SELECT COUNT(*) FROM c2_certification_members WHERE certificate_id = ?",
            (certificate.certificate_id,),
        ).fetchone()[0]
        self.assertEqual(member_count, 800)
        self.assertEqual(
            self.certification.get_certificate(certificate.certificate_id).identity_set_digest,
            original_digest,
        )

        enlarged_payload = self.certification_payload(
            certificate_id=certificate.certificate_id
        )
        self.assertNotEqual(enlarged_payload, payload)
        with self.assertRaises(ConflictError):
            self.admit(enlarged_payload)


if __name__ == "__main__":
    unittest.main()
