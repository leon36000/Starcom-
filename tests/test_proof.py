from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from starcom.db import Database
from starcom.errors import ConflictError, StateTransitionError, ValidationError
from starcom.ledger import EventLedger
from starcom.proof import ClaimStatus, ProofEngine, VerificationVerdict


NOW = "2026-08-13T12:00:00.000000Z"
LATER = "2026-08-13T12:10:00.000000Z"
LATEST = "2026-08-13T12:20:00.000000Z"
DIGEST = "a" * 64


class ProofEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tempdir.name) / "proof.sqlite3")
        self.db.initialize()
        self.ledger = EventLedger(self.db)
        self.proof = ProofEngine(self.db, self.ledger)

    def tearDown(self) -> None:
        self.db.close()
        self.tempdir.cleanup()

    def create_claim(self, claim_id: str = "claim-1"):
        return self.proof.create_claim(
            claim_id=claim_id,
            subject_type="mission",
            subject_id="mission-1",
            statement="Mission result satisfies the approved acceptance criteria.",
            author="agent:builder",
            policy_version="policy-v1",
            occurred_at=NOW,
        )

    def attach(self, claim_id: str = "claim-1"):
        return self.proof.attach_evidence(
            claim_id,
            evidence_id="evidence-1",
            kind="test-report",
            uri="artifact://tests/report.txt",
            digest=DIGEST,
            metadata={"tests": 42},
            attached_by="agent:builder",
            occurred_at=LATER,
        )

    def approve(self, claim_id: str = "claim-1"):
        return self.proof.verify_claim(
            claim_id,
            verifier="agent:reviewer",
            verdict=VerificationVerdict.APPROVED,
            notes="Evidence independently reproduced.",
            occurred_at=LATEST,
        )

    def test_claim_creation_is_draft_and_ledgered(self) -> None:
        claim = self.create_claim()
        self.assertEqual(claim.status, ClaimStatus.DRAFT)
        self.assertEqual(claim.author, "agent:builder")
        self.assertEqual(len(claim.ledger_hash), 64)
        self.assertTrue(self.ledger.verify().ok)

    def test_evidence_attachment_validates_digest_and_updates_status(self) -> None:
        self.create_claim()
        evidence = self.attach()
        claim = self.proof.get_claim("claim-1")
        self.assertEqual(evidence.digest, DIGEST)
        self.assertEqual(claim.status, ClaimStatus.EVIDENCE_ATTACHED)
        with self.assertRaisesRegex(ValidationError, "SHA-256"):
            self.proof.attach_evidence(
                "claim-1",
                evidence_id="bad",
                kind="test-report",
                uri="artifact://bad",
                digest="not-a-digest",
                metadata={},
                attached_by="agent:builder",
                occurred_at=LATER,
            )

    def test_duplicate_evidence_id_is_rejected(self) -> None:
        self.create_claim()
        self.attach()
        with self.assertRaisesRegex(ConflictError, "evidence"):
            self.attach()

    def test_author_cannot_verify_own_claim(self) -> None:
        self.create_claim()
        self.attach()
        with self.assertRaisesRegex(StateTransitionError, "author"):
            self.proof.verify_claim(
                "claim-1",
                verifier="agent:builder",
                verdict=VerificationVerdict.APPROVED,
                notes="self review",
                occurred_at=LATEST,
            )

    def test_approval_requires_evidence(self) -> None:
        self.create_claim()
        with self.assertRaisesRegex(StateTransitionError, "evidence"):
            self.approve()

    def test_rejected_verification_prevents_certification(self) -> None:
        self.create_claim()
        self.attach()
        verification = self.proof.verify_claim(
            "claim-1",
            verifier="agent:reviewer",
            verdict=VerificationVerdict.REJECTED,
            notes="Evidence did not reproduce.",
            occurred_at=LATEST,
        )
        self.assertEqual(verification.verdict, VerificationVerdict.REJECTED)
        self.assertEqual(self.proof.get_claim("claim-1").status, ClaimStatus.REJECTED)
        with self.assertRaisesRegex(StateTransitionError, "approved"):
            self.proof.certify_claim(
                "claim-1",
                certifier="agent:certifier",
                occurred_at="2026-08-13T12:30:00.000000Z",
            )

    def test_certifier_must_be_distinct_from_author_and_verifier(self) -> None:
        self.create_claim()
        self.attach()
        self.approve()
        for actor in ("agent:builder", "agent:reviewer"):
            with self.subTest(actor=actor):
                with self.assertRaisesRegex(StateTransitionError, "distinct"):
                    self.proof.certify_claim(
                        "claim-1",
                        certifier=actor,
                        occurred_at="2026-08-13T12:30:00.000000Z",
                    )

    def test_certificate_is_terminal_verifiable_and_idempotent(self) -> None:
        self.create_claim()
        self.attach()
        verification = self.approve()
        first = self.proof.certify_claim(
            "claim-1",
            certifier="agent:certifier",
            occurred_at="2026-08-13T12:30:00.000000Z",
        )
        second = self.proof.certify_claim(
            "claim-1",
            certifier="agent:certifier",
            occurred_at="2026-08-13T12:30:00.000000Z",
        )
        self.assertEqual(first, second)
        self.assertEqual(first.verification_id, verification.verification_id)
        self.assertEqual(len(first.certificate_digest), 64)
        self.assertEqual(self.proof.get_claim("claim-1").status, ClaimStatus.CERTIFIED)
        self.assertTrue(self.proof.verify_certificate(first.certificate_id).ok)
        cert_events = [e for e in self.ledger.read_stream("proof:claim:claim-1") if e.kind == "CLAIM_CERTIFIED"]
        self.assertEqual(len(cert_events), 1)

    def test_certificate_tampering_is_detected(self) -> None:
        self.create_claim()
        self.attach()
        self.approve()
        certificate = self.proof.certify_claim(
            "claim-1",
            certifier="agent:certifier",
            occurred_at="2026-08-13T12:30:00.000000Z",
        )
        self.db.connection.execute("DROP TRIGGER proof_certificates_no_update")
        self.db.connection.execute(
            "UPDATE proof_certificates SET certificate_digest = ? WHERE certificate_id = ?",
            ("0" * 64, certificate.certificate_id),
        )
        verification = self.proof.verify_certificate(certificate.certificate_id)
        self.assertFalse(verification.ok)
        self.assertIn("CERTIFICATE_DIGEST_MISMATCH", verification.defects)

    def test_certificate_verifier_reports_malformed_evidence_metadata_json(self) -> None:
        self.create_claim()
        self.attach()
        self.approve()
        certificate = self.proof.certify_claim(
            "claim-1",
            certifier="agent:certifier",
            occurred_at="2026-08-13T12:30:00.000000Z",
        )
        self.db.connection.execute("DROP TRIGGER proof_evidence_no_update")
        self.db.connection.execute(
            "UPDATE proof_evidence SET metadata_json = ? WHERE evidence_id = ?",
            ("{", "evidence-1"),
        )

        verification = self.proof.verify_certificate(certificate.certificate_id)

        self.assertFalse(verification.ok)
        self.assertIn(
            "EVIDENCE_METADATA_JSON_INVALID:evidence-1",
            verification.defects,
        )


if __name__ == "__main__":
    unittest.main()
