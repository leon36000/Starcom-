from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from starcom.certification import C2CertificationRecord, C2CertificationVerification
from starcom.continuity import ContinuityService
from starcom.db import Database
from starcom.errors import IntegrityError, StateTransitionError
from starcom.ledger import EventLedger
from starcom.qualification import QualificationArtifactKind, QualificationLab
from starcom.qualification_decision import C3DecisionService
from starcom.qualification_gate import C3QualificationGate, C3QualificationVerification
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule, TrustPlane


H0 = "2026-08-14T11:00:00.000000Z"
H1 = "2026-08-14T11:01:00.000000Z"
H2 = "2026-08-14T11:02:00.000000Z"
H3 = "2026-08-14T11:03:00.000000Z"
H4 = "2026-08-14T11:04:00.000000Z"
CERTIFICATE_ID = "certificate-c3-hardening"
DECISION_KEY = b"c3-hardening-decision-key"


class DigestVerifier:
    def validate_public_key(self, public_key_pem: bytes) -> bool:
        return public_key_pem == DECISION_KEY

    def verify(self, public_key_pem: bytes, payload: bytes, signature: bytes) -> bool:
        return (
            public_key_pem == DECISION_KEY
            and signature == hashlib.sha256(public_key_pem + payload).digest()
        )


class FakeCertificationService:
    def __init__(self, record: C2CertificationRecord) -> None:
        self.record = record

    def get_certificate(self, certificate_id: str) -> C2CertificationRecord:
        if certificate_id != self.record.certificate_id:
            raise AssertionError("unexpected certificate id")
        return self.record

    def verify_certificate(self, certificate_id: str) -> C2CertificationVerification:
        self.get_certificate(certificate_id)
        return C2CertificationVerification(certificate_id, ())


class C3DecisionHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.database = Database(Path(self.tempdir.name) / "c3-hardening.sqlite3")
        self.database.initialize()
        self.ledger = EventLedger(self.database)
        self.trust = TrustPlane(self.database, self.ledger)
        self.continuity = ContinuityService(
            self.database,
            self.ledger,
            self.trust,
            DigestVerifier(),
        )
        self.qualification = QualificationLab(self.database, self.ledger)
        with self.database.transaction() as connection:
            connection.execute(
                "CREATE TABLE c2_certifications (certificate_id TEXT PRIMARY KEY)"
            )
            connection.execute(
                "INSERT INTO c2_certifications (certificate_id) VALUES (?)",
                (CERTIFICATE_ID,),
            )
        certificate = C2CertificationRecord(
            certificate_id=CERTIFICATE_ID,
            recollection_id="c2-hardening",
            incident_id="task5-hardening",
            campaign_id="campaign-hardening",
            key_id="c2-key",
            payload_sha256="a" * 64,
            signature_sha256="b" * 64,
            certifier_identity="c2-certifier",
            identity_count=800,
            required_target=800,
            identity_set_digest="c" * 64,
            certified_at_utc=H0,
            admitted_at=H0,
            admitted_by="c2-admission-agent",
            ledger_event_id="c2-event",
            ledger_hash="d" * 64,
        )
        self.certification = FakeCertificationService(certificate)
        self.c3 = C3QualificationGate(
            self.database,
            self.ledger,
            self.certification,  # type: ignore[arg-type]
            self.qualification,
        )
        self.qualification.create_run(
            "qualification-hardening",
            name="C3 decision hardening fixture",
            actor="lab-owner",
            occurred_at=H0,
        )
        self.c3.start(
            "c3-hardening",
            qualification_run_id="qualification-hardening",
            certificate_id=CERTIFICATE_ID,
            actor="c3-owner",
            occurred_at=H1,
        )
        self.decision = C3DecisionService(
            self.database,
            self.ledger,
            self.continuity,
            self.certification,  # type: ignore[arg-type]
            self.c3,
            self.qualification,
        )
        self._accept_root()
        self._add_evidence()

    def tearDown(self) -> None:
        self.database.close()
        self.tempdir.cleanup()

    def _accept_root(self) -> None:
        self.trust.add_rule(
            PolicyRule(
                "allow-c3-hardening-root",
                PolicyEffect.ALLOW,
                "owner",
                "continuity.trust-root.accept",
                "continuity:trust-root:c3-hardening-key",
            ),
            actor="owner",
            occurred_at=H0,
        )
        authorization = self.trust.authorize(
            AuthorizationRequest(
                subject="owner",
                action="continuity.trust-root.accept",
                resource="continuity:trust-root:c3-hardening-key",
            ),
            now=H1,
        )
        self.assertTrue(authorization.allowed)
        self.continuity.accept_trust_root(
            "c3-hardening-key",
            DECISION_KEY,
            decision_id=authorization.decision_id,
            actor="owner",
            occurred_at=H1,
        )

    def _add_evidence(self) -> None:
        self.qualification.record_artifact(
            "qualification-hardening",
            artifact_id="candidate-hardening",
            kind=QualificationArtifactKind.CANDIDATE,
            material={"component_id": "candidate-hardening"},
            actor="candidate-author",
            occurred_at=H2,
        )
        self.qualification.record_artifact(
            "qualification-hardening",
            artifact_id="evaluation-hardening",
            kind=QualificationArtifactKind.EVALUATION,
            material={
                "candidate_artifact_id": "candidate-hardening",
                "score": 91,
            },
            actor="evaluator",
            occurred_at=H3,
        )

    @staticmethod
    def _sign(payload: bytes) -> bytes:
        return hashlib.sha256(DECISION_KEY + payload).digest()

    def _payload(self, decision_id: str = "decision-hardening") -> bytes:
        snapshot = self.decision.snapshot("c3-hardening")
        value = {
            "decision_id": decision_id,
            "c3_run_id": snapshot.c3_run_id,
            "qualification_run_id": snapshot.qualification_run_id,
            "certificate_id": snapshot.certificate_id,
            "qualification_head_hash": snapshot.qualification_head_hash,
            "candidate_count": snapshot.candidate_count,
            "evaluation_count": snapshot.evaluation_count,
            "candidate_set_digest": snapshot.candidate_set_digest,
            "evaluation_set_digest": snapshot.evaluation_set_digest,
            "verdict": "C3_CANDIDATE_SELECTED",
            "selected_candidate_artifact_id": "candidate-hardening",
            "decision_maker_identity": "independent-decision-maker",
            "decision_maker_environment": "isolated-hardening-fixture",
            "decided_at_utc": H4,
            "independence_basis": "separate deterministic identity",
            "independent_identity_status": "SATISFIED",
            "qualification_verification_result": "PASS",
            "gate_effect": "NO_ADOPTION_EXECUTED",
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _admit(self, payload: bytes, *, occurred_at: str = H4):
        return self.decision.admit_decision(
            "c3-hardening",
            "c3-hardening-key",
            payload,
            self._sign(payload),
            actor="decision-admission-agent",
            occurred_at=occurred_at,
        )

    def test_admission_timestamp_cannot_predate_signed_decision(self) -> None:
        payload = self._payload()

        with self.assertRaisesRegex(
            StateTransitionError,
            "admission predates the signed C3 decision",
        ):
            self._admit(payload, occurred_at=H3)

        count = self.database.connection.execute(
            "SELECT COUNT(*) FROM c3_decisions"
        ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_verifier_fails_closed_on_malformed_frozen_evidence_timestamp(self) -> None:
        record = self._admit(self._payload())
        self.database.connection.execute("DROP TRIGGER c3_decision_evidence_no_update")
        self.database.connection.execute(
            """
            UPDATE c3_decision_evidence SET recorded_at = ?
            WHERE decision_id = ? AND kind = 'CANDIDATE' AND ordinal = 0
            """,
            ("not-a-timestamp", record.decision_id),
        )

        verification = self.decision.verify_decision(record.decision_id)

        self.assertFalse(verification.ok)
        self.assertIn(
            "C3_DECISION_EVIDENCE_RECORDED_AT_INVALID:CANDIDATE:0",
            verification.defects,
        )

    def test_verifier_fails_closed_when_payload_and_decision_time_are_corrupt(self) -> None:
        record = self._admit(self._payload())
        self.database.connection.execute("DROP TRIGGER c3_decisions_no_update")
        self.database.connection.execute(
            "UPDATE c3_decisions SET payload = ?, decided_at_utc = ? WHERE decision_id = ?",
            (b"{not-json", "not-a-timestamp", record.decision_id),
        )

        verification = self.decision.verify_decision(record.decision_id)

        self.assertFalse(verification.ok)
        self.assertIn("C3_DECISION_PAYLOAD_INVALID", verification.defects)
        self.assertIn(
            "C3_DECISION_SEMANTICS_OR_CHRONOLOGY_INVALID",
            verification.defects,
        )

    def test_trust_root_is_rechecked_inside_admission_transaction(self) -> None:
        payload = self._payload()
        original = self.decision._assert_trust_root
        calls = 0

        def changing_root(key_id: str) -> bytes:
            nonlocal calls
            calls += 1
            if calls >= 2:
                raise IntegrityError("simulated trust-root change")
            return original(key_id)

        self.decision._assert_trust_root = changing_root  # type: ignore[method-assign]

        with self.assertRaisesRegex(IntegrityError, "simulated trust-root change"):
            self._admit(payload)
        self.assertEqual(calls, 2)
        count = self.database.connection.execute(
            "SELECT COUNT(*) FROM c3_decisions"
        ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_c3_is_rechecked_inside_admission_transaction(self) -> None:
        payload = self._payload()
        original = self.c3.verify
        calls = 0

        def changing_c3(c3_run_id: str) -> C3QualificationVerification:
            nonlocal calls
            calls += 1
            if calls >= 2:
                return C3QualificationVerification(
                    c3_run_id=c3_run_id,
                    defects=("SIMULATED_C3_CHANGE",),
                )
            return original(c3_run_id)

        self.c3.verify = changing_c3  # type: ignore[method-assign]

        with self.assertRaisesRegex(IntegrityError, "C3 qualification verification failed"):
            self._admit(payload)
        self.assertEqual(calls, 2)
        count = self.database.connection.execute(
            "SELECT COUNT(*) FROM c3_decisions"
        ).fetchone()[0]
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
