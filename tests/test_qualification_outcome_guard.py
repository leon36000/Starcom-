from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tempfile
import unittest

from starcom.db import Database
from starcom.errors import NotFoundError
from starcom.ledger import EventLedger
from starcom.qualification import QualificationArtifactKind, QualificationLab
from starcom.qualification_gate import C3QualificationGate


T0 = "2026-08-14T09:00:00.000000Z"
T1 = "2026-08-14T09:01:00.000000Z"
T2 = "2026-08-14T09:02:00.000000Z"
CERTIFICATE_ID = "certificate-outcome-guard"


@dataclass(frozen=True)
class FakeCertificate:
    certificate_id: str = CERTIFICATE_ID
    recollection_id: str = "c2-run"
    incident_id: str = "task5"
    campaign_id: str = "c2-campaign"
    identity_count: int = 800
    required_target: int = 800
    identity_set_digest: str = "a" * 64


@dataclass(frozen=True)
class FakeCertificateVerification:
    certificate_id: str
    defects: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.defects


class FakeCertificationService:
    def __init__(self) -> None:
        self.certificate = FakeCertificate()

    def get_certificate(self, certificate_id: str) -> FakeCertificate:
        if certificate_id != self.certificate.certificate_id:
            raise NotFoundError(
                "C2 certification does not exist",
                {"certificate_id": certificate_id},
            )
        return self.certificate

    def verify_certificate(self, certificate_id: str) -> FakeCertificateVerification:
        self.get_certificate(certificate_id)
        return FakeCertificateVerification(certificate_id)


class C3UngovernedOutcomeGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tempdir.name) / "outcome-guard.sqlite3")
        self.db.initialize()
        self.ledger = EventLedger(self.db)
        with self.db.transaction() as connection:
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
        self.qualification = QualificationLab(self.db, self.ledger)
        self.certification = FakeCertificationService()
        self.gate = C3QualificationGate(
            self.db,
            self.ledger,
            self.certification,  # type: ignore[arg-type]
            self.qualification,
        )
        self.qualification.create_run(
            "qualification-run",
            name="Outcome guard fixture",
            actor="lab-owner",
            occurred_at=T0,
        )
        self.gate.start(
            "c3-run",
            qualification_run_id="qualification-run",
            certificate_id=CERTIFICATE_ID,
            actor="c3-owner",
            occurred_at=T1,
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tempdir.cleanup()

    def record(self, artifact_id: str, kind: QualificationArtifactKind) -> None:
        self.qualification.record_artifact(
            "qualification-run",
            artifact_id=artifact_id,
            kind=kind,
            material={"artifact_id": artifact_id, "kind": kind.value},
            actor="evaluator",
            occurred_at=T2,
        )

    def test_candidate_and_evaluation_artifacts_remain_permitted(self) -> None:
        self.record("candidate-a", QualificationArtifactKind.CANDIDATE)
        self.record("evaluation-a", QualificationArtifactKind.EVALUATION)

        laboratory = self.qualification.verify("qualification-run")
        c3 = self.gate.verify("c3-run")

        self.assertTrue(laboratory.ok, laboratory.defects)
        self.assertTrue(c3.ok, c3.defects)

    def test_generic_decision_is_clean_in_lab_but_fails_closed_in_c3(self) -> None:
        self.record("decision-a", QualificationArtifactKind.DECISION)

        laboratory = self.qualification.verify("qualification-run")
        c3 = self.gate.verify("c3-run")

        self.assertTrue(laboratory.ok, laboratory.defects)
        self.assertFalse(c3.ok)
        self.assertIn(
            "C3_UNGOVERNED_DECISION_ARTIFACT:decision-a",
            c3.defects,
        )

    def test_generic_adoption_is_clean_in_lab_but_fails_closed_in_c3(self) -> None:
        self.record("adoption-a", QualificationArtifactKind.ADOPTION)

        laboratory = self.qualification.verify("qualification-run")
        c3 = self.gate.verify("c3-run")

        self.assertTrue(laboratory.ok, laboratory.defects)
        self.assertFalse(c3.ok)
        self.assertIn(
            "C3_UNAUTHORIZED_ADOPTION_ARTIFACT:adoption-a",
            c3.defects,
        )


if __name__ == "__main__":
    unittest.main()
