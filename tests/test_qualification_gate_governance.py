from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from starcom.certification import C2CertificationRecord, C2CertificationVerification
from starcom.db import Database
from starcom.errors import NotFoundError
from starcom.ledger import EventLedger
from starcom.qualification import QualificationArtifactKind, QualificationLab
from starcom.qualification_gate import C3QualificationGate


G0 = "2026-08-14T08:00:00.000000Z"
G1 = "2026-08-14T08:01:00.000000Z"
G2 = "2026-08-14T08:02:00.000000Z"
G3 = "2026-08-14T08:03:00.000000Z"
CERTIFICATE_ID = "certificate-governance"


class FakeCertificationService:
    def __init__(self, record: C2CertificationRecord) -> None:
        self.record = record

    def get_certificate(self, certificate_id: str) -> C2CertificationRecord:
        if certificate_id != self.record.certificate_id:
            raise NotFoundError(
                "C2 certification does not exist",
                {"certificate_id": certificate_id},
            )
        return self.record

    def verify_certificate(self, certificate_id: str) -> C2CertificationVerification:
        self.get_certificate(certificate_id)
        return C2CertificationVerification(certificate_id, ())


class C3ArtifactGovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.database = Database(Path(self.tempdir.name) / "c3-governance.sqlite3")
        self.database.initialize()
        self.ledger = EventLedger(self.database)
        self.qualification = QualificationLab(self.database, self.ledger)
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE c2_certifications (
                    certificate_id TEXT PRIMARY KEY
                )
                """
            )
            connection.execute(
                "INSERT INTO c2_certifications (certificate_id) VALUES (?)",
                (CERTIFICATE_ID,),
            )
        certificate = C2CertificationRecord(
            certificate_id=CERTIFICATE_ID,
            recollection_id="c2-run",
            incident_id="task5",
            campaign_id="c2-campaign",
            key_id="certifier-key",
            payload_sha256="a" * 64,
            signature_sha256="b" * 64,
            certifier_identity="independent-certifier",
            identity_count=800,
            required_target=800,
            identity_set_digest="c" * 64,
            certified_at_utc=G0,
            admitted_at=G0,
            admitted_by="admission-agent",
            ledger_event_id="certificate-event",
            ledger_hash="d" * 64,
        )
        self.certification = FakeCertificationService(certificate)
        self.gate = C3QualificationGate(
            self.database,
            self.ledger,
            self.certification,  # type: ignore[arg-type]
            self.qualification,
        )
        self.qualification.create_run(
            "qualification-run",
            name="C3 governed qualification run",
            actor="lab-owner",
            occurred_at=G0,
        )

    def tearDown(self) -> None:
        self.database.close()
        self.tempdir.cleanup()

    def start(self) -> None:
        self.gate.start(
            "c3-run",
            qualification_run_id="qualification-run",
            certificate_id=CERTIFICATE_ID,
            actor="c3-owner",
            occurred_at=G1,
        )

    def record(
        self,
        *,
        artifact_id: str,
        kind: QualificationArtifactKind,
        occurred_at: str,
    ) -> None:
        self.qualification.record_artifact(
            "qualification-run",
            artifact_id=artifact_id,
            kind=kind,
            material={"component_id": artifact_id},
            actor="evaluator",
            occurred_at=occurred_at,
        )

    def test_generic_lab_keeps_structural_decision_and_adoption_artifacts_valid(self) -> None:
        self.qualification.create_run(
            "generic-run",
            name="Generic qualification evidence",
            actor="lab-owner",
            occurred_at=G0,
        )
        self.qualification.record_artifact(
            "generic-run",
            artifact_id="generic-decision",
            kind=QualificationArtifactKind.DECISION,
            material={"decision": "defer"},
            actor="evaluator",
            occurred_at=G1,
        )
        self.qualification.record_artifact(
            "generic-run",
            artifact_id="generic-adoption",
            kind=QualificationArtifactKind.ADOPTION,
            material={"adoption": "none"},
            actor="evaluator",
            occurred_at=G2,
        )

        verification = self.qualification.verify("generic-run")

        self.assertTrue(verification.ok, verification.defects)

    def test_c3_allows_candidate_and_evaluation_artifacts(self) -> None:
        self.start()
        self.record(
            artifact_id="candidate-after-bind",
            kind=QualificationArtifactKind.CANDIDATE,
            occurred_at=G2,
        )
        self.record(
            artifact_id="evaluation-after-bind",
            kind=QualificationArtifactKind.EVALUATION,
            occurred_at=G3,
        )

        verification = self.gate.verify("c3-run")

        self.assertTrue(verification.ok, verification.defects)

    def test_c3_rejects_ungoverned_decision_artifact(self) -> None:
        self.start()
        self.record(
            artifact_id="decision-after-bind",
            kind=QualificationArtifactKind.DECISION,
            occurred_at=G2,
        )

        verification = self.gate.verify("c3-run")

        self.assertFalse(verification.ok)
        self.assertIn(
            "C3_UNGOVERNED_DECISION_ARTIFACT:decision-after-bind",
            verification.defects,
        )

    def test_c3_rejects_unauthorized_adoption_artifact(self) -> None:
        self.start()
        self.record(
            artifact_id="adoption-after-bind",
            kind=QualificationArtifactKind.ADOPTION,
            occurred_at=G2,
        )

        verification = self.gate.verify("c3-run")

        self.assertFalse(verification.ok)
        self.assertIn(
            "C3_UNAUTHORIZED_ADOPTION_ARTIFACT:adoption-after-bind",
            verification.defects,
        )


if __name__ == "__main__":
    unittest.main()
