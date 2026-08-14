from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from starcom.canonical import sha256_digest
from starcom.certification import C2CertificationRecord, C2CertificationVerification
from starcom.continuity import ContinuityService
from starcom.db import Database
from starcom.errors import ConflictError, IntegrityError, StateTransitionError, ValidationError
from starcom.ledger import EventLedger
from starcom.qualification import QualificationArtifactKind, QualificationLab
from starcom.qualification_decision import C3DecisionService, C3DecisionVerdict
from starcom.qualification_gate import C3QualificationGate
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule, TrustPlane


D0 = "2026-08-14T10:00:00.000000Z"
D1 = "2026-08-14T10:01:00.000000Z"
D2 = "2026-08-14T10:02:00.000000Z"
D3 = "2026-08-14T10:03:00.000000Z"
D4 = "2026-08-14T10:04:00.000000Z"
D5 = "2026-08-14T10:05:00.000000Z"
CERTIFICATE_ID = "certificate-c3-decision"
DECISION_KEY = b"c3-independent-decision-key"


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


class C3SignedDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.database = Database(Path(self.tempdir.name) / "c3-decision.sqlite3")
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
        self.certificate = C2CertificationRecord(
            certificate_id=CERTIFICATE_ID,
            recollection_id="c2-run",
            incident_id="task5",
            campaign_id="c2-campaign",
            key_id="c2-certifier-key",
            payload_sha256="a" * 64,
            signature_sha256="b" * 64,
            certifier_identity="c2-certifier",
            identity_count=800,
            required_target=800,
            identity_set_digest="c" * 64,
            certified_at_utc=D0,
            admitted_at=D0,
            admitted_by="c2-admission-agent",
            ledger_event_id="c2-certificate-event",
            ledger_hash="d" * 64,
        )
        self.certification = FakeCertificationService(self.certificate)
        self.c3 = C3QualificationGate(
            self.database,
            self.ledger,
            self.certification,  # type: ignore[arg-type]
            self.qualification,
        )
        self.qualification.create_run(
            "qualification-run",
            name="C3 signed decision fixture",
            actor="lab-owner",
            occurred_at=D0,
        )
        self.c3.start(
            "c3-run",
            qualification_run_id="qualification-run",
            certificate_id=CERTIFICATE_ID,
            actor="c3-owner",
            occurred_at=D1,
        )
        self.decision = C3DecisionService(
            self.database,
            self.ledger,
            self.continuity,
            self.certification,  # type: ignore[arg-type]
            self.c3,
            self.qualification,
        )
        self.accept_decision_root()

    def tearDown(self) -> None:
        self.database.close()
        self.tempdir.cleanup()

    def accept_decision_root(self) -> None:
        self.trust.add_rule(
            PolicyRule(
                "allow-c3-decision-root",
                PolicyEffect.ALLOW,
                "owner",
                "continuity.trust-root.accept",
                "continuity:trust-root:c3-decision-maker",
            ),
            actor="owner",
            occurred_at=D0,
        )
        authorization = self.trust.authorize(
            AuthorizationRequest(
                subject="owner",
                action="continuity.trust-root.accept",
                resource="continuity:trust-root:c3-decision-maker",
            ),
            now=D1,
        )
        self.assertTrue(authorization.allowed)
        self.continuity.accept_trust_root(
            "c3-decision-maker",
            DECISION_KEY,
            decision_id=authorization.decision_id,
            actor="owner",
            occurred_at=D1,
        )
        verification = self.continuity.verify_trust_root("c3-decision-maker")
        self.assertTrue(verification.ok, verification.defects)

    @staticmethod
    def sign(payload: bytes) -> bytes:
        return hashlib.sha256(DECISION_KEY + payload).digest()

    def add_candidate(
        self,
        artifact_id: str = "candidate-a",
        *,
        actor: str = "candidate-author",
        occurred_at: str = D2,
    ) -> None:
        self.qualification.record_artifact(
            "qualification-run",
            artifact_id=artifact_id,
            kind=QualificationArtifactKind.CANDIDATE,
            material={
                "component_id": artifact_id,
                "version": "1.0.0",
            },
            actor=actor,
            occurred_at=occurred_at,
        )

    def add_evaluation(
        self,
        artifact_id: str = "evaluation-a",
        *,
        candidate_id: str = "candidate-a",
        actor: str = "evaluator",
        occurred_at: str = D3,
    ) -> None:
        self.qualification.record_artifact(
            "qualification-run",
            artifact_id=artifact_id,
            kind=QualificationArtifactKind.EVALUATION,
            material={
                "candidate_artifact_id": candidate_id,
                "score": 92,
            },
            actor=actor,
            occurred_at=occurred_at,
        )

    def add_minimum_evidence(self) -> None:
        self.add_candidate()
        self.add_evaluation()

    def payload(
        self,
        *,
        decision_id: str = "decision-a",
        verdict: C3DecisionVerdict = C3DecisionVerdict.CANDIDATE_SELECTED,
        selected_candidate_artifact_id: str | None = "candidate-a",
        decision_maker_identity: str = "independent-decision-maker",
        decided_at_utc: str = D4,
    ) -> bytes:
        snapshot = self.decision.snapshot("c3-run")
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
            "verdict": verdict.value,
            "selected_candidate_artifact_id": selected_candidate_artifact_id,
            "decision_maker_identity": decision_maker_identity,
            "decision_maker_environment": "isolated-c3-decision-fixture",
            "decided_at_utc": decided_at_utc,
            "independence_basis": "separate deterministic decision identity",
            "independent_identity_status": "SATISFIED",
            "qualification_verification_result": "PASS",
            "gate_effect": "NO_ADOPTION_EXECUTED",
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def admit(self, payload: bytes, *, occurred_at: str = D4):
        return self.decision.admit_decision(
            "c3-run",
            "c3-decision-maker",
            payload,
            self.sign(payload),
            actor="decision-admission-agent",
            occurred_at=occurred_at,
        )

    def test_snapshot_is_deterministic_and_binds_candidate_evaluation_sets(self) -> None:
        self.add_candidate("candidate-b", actor="candidate-author-b")
        self.add_candidate("candidate-a")
        self.add_evaluation("evaluation-b", candidate_id="candidate-b", actor="evaluator-b")
        self.add_evaluation("evaluation-a")

        first = self.decision.snapshot("c3-run")
        second = self.decision.snapshot("c3-run")

        self.assertEqual(first, second)
        self.assertEqual(
            [member["artifact_id"] for member in first.candidates],
            ["candidate-a", "candidate-b"],
        )
        self.assertEqual(
            [member["artifact_id"] for member in first.evaluations],
            ["evaluation-a", "evaluation-b"],
        )
        self.assertEqual(first.candidate_count, 2)
        self.assertEqual(first.evaluation_count, 2)
        self.assertEqual(first.candidate_set_digest, sha256_digest(list(first.candidates)))
        self.assertEqual(
            first.evaluation_set_digest,
            sha256_digest(list(first.evaluations)),
        )
        self.assertEqual(
            first.qualification_head_hash,
            self.ledger.head("qualification:run:qualification-run"),
        )
        self.assertEqual(first.latest_evidence_at, D3)

    def test_exact_signed_selection_is_admitted_verified_and_idempotent(self) -> None:
        self.add_minimum_evidence()
        payload = self.payload()

        first = self.admit(payload)
        replay = self.admit(payload, occurred_at=D5)

        self.assertEqual(first, replay)
        self.assertEqual(first.verdict, C3DecisionVerdict.CANDIDATE_SELECTED)
        self.assertEqual(first.selected_candidate_artifact_id, "candidate-a")
        stored = self.database.connection.execute(
            "SELECT payload, signature FROM c3_decisions WHERE decision_id = ?",
            (first.decision_id,),
        ).fetchone()
        self.assertIsNotNone(stored)
        assert stored is not None
        self.assertEqual(bytes(stored["payload"]), payload)
        self.assertEqual(bytes(stored["signature"]), self.sign(payload))
        verification = self.decision.verify_decision(first.decision_id)
        self.assertTrue(verification.ok, verification.defects)

    def test_exact_signed_no_selection_is_valid(self) -> None:
        self.add_minimum_evidence()
        payload = self.payload(
            verdict=C3DecisionVerdict.NO_SELECTION,
            selected_candidate_artifact_id=None,
        )

        record = self.admit(payload)

        self.assertEqual(record.verdict, C3DecisionVerdict.NO_SELECTION)
        self.assertIsNone(record.selected_candidate_artifact_id)
        self.assertTrue(self.decision.verify_decision(record.decision_id).ok)

    def test_decision_requires_candidate_and_evaluation_evidence(self) -> None:
        empty_payload = self.payload(
            verdict=C3DecisionVerdict.NO_SELECTION,
            selected_candidate_artifact_id=None,
        )
        with self.assertRaisesRegex(
            StateTransitionError,
            "candidate and evaluation evidence",
        ):
            self.admit(empty_payload)

        self.add_candidate()
        candidate_only_payload = self.payload()
        with self.assertRaisesRegex(
            StateTransitionError,
            "candidate and evaluation evidence",
        ):
            self.admit(candidate_only_payload)

    def test_selected_candidate_must_belong_to_snapshot(self) -> None:
        self.add_minimum_evidence()
        payload = self.payload(selected_candidate_artifact_id="candidate-missing")

        with self.assertRaisesRegex(
            StateTransitionError,
            "selected candidate is not present",
        ):
            self.admit(payload)

    def test_modified_payload_or_signature_is_rejected(self) -> None:
        self.add_minimum_evidence()
        payload = self.payload()

        with self.assertRaises(IntegrityError):
            self.decision.admit_decision(
                "c3-run",
                "c3-decision-maker",
                payload + b" ",
                self.sign(payload),
                actor="decision-admission-agent",
                occurred_at=D4,
            )
        with self.assertRaises(IntegrityError):
            self.decision.admit_decision(
                "c3-run",
                "c3-decision-maker",
                payload,
                b"invalid-signature",
                actor="decision-admission-agent",
                occurred_at=D4,
            )

        decoded = json.loads(payload.decode("utf-8"))
        del decoded["gate_effect"]
        missing_field = json.dumps(
            decoded,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        with self.assertRaises(ValidationError):
            self.decision.admit_decision(
                "c3-run",
                "c3-decision-maker",
                missing_field,
                self.sign(missing_field),
                actor="decision-admission-agent",
                occurred_at=D4,
            )

        duplicate_key = payload.decode("utf-8").replace(
            '"decision_id":"decision-a"',
            '"decision_id":"decision-a","decision_id":"decision-b"',
            1,
        ).encode("utf-8")
        with self.assertRaises(ValidationError):
            self.decision.admit_decision(
                "c3-run",
                "c3-decision-maker",
                duplicate_key,
                self.sign(duplicate_key),
                actor="decision-admission-agent",
                occurred_at=D4,
            )

    def test_decision_maker_must_be_independent_and_after_latest_evidence(self) -> None:
        self.add_minimum_evidence()
        disallowed = (
            "c2-certifier",
            "c3-owner",
            "lab-owner",
            "candidate-author",
            "evaluator",
        )
        for index, identity in enumerate(disallowed):
            with self.subTest(identity=identity):
                payload = self.payload(
                    decision_id=f"decision-disallowed-{index}",
                    decision_maker_identity=identity,
                )
                with self.assertRaisesRegex(
                    StateTransitionError,
                    "decision maker is not independent",
                ):
                    self.admit(payload)

        early = self.payload(
            decision_id="decision-too-early",
            decided_at_utc=D2,
        )
        with self.assertRaisesRegex(
            StateTransitionError,
            "decision predates the latest qualification evidence",
        ):
            self.admit(early)

    def test_second_decision_for_same_c3_run_is_rejected(self) -> None:
        self.add_minimum_evidence()
        self.admit(self.payload(decision_id="decision-first"))
        second = self.payload(
            decision_id="decision-second",
            verdict=C3DecisionVerdict.NO_SELECTION,
            selected_candidate_artifact_id=None,
        )

        with self.assertRaises(ConflictError):
            self.admit(second)

    def test_snapshot_is_rechecked_inside_admission_transaction(self) -> None:
        self.add_minimum_evidence()
        payload = self.payload()
        original = self.decision._snapshot_from_connection
        calls = 0

        def changed_snapshot(connection, c3_run_id):  # type: ignore[no-untyped-def]
            nonlocal calls
            calls += 1
            snapshot = original(connection, c3_run_id)
            if calls >= 2:
                return replace(snapshot, qualification_head_hash="0" * 64)
            return snapshot

        self.decision._snapshot_from_connection = changed_snapshot  # type: ignore[method-assign]

        with self.assertRaisesRegex(
            ConflictError,
            "qualification evidence changed during C3 decision admission",
        ):
            self.admit(payload)
        count = self.database.connection.execute(
            "SELECT COUNT(*) FROM c3_decisions",
        ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_verifier_detects_membership_and_decision_ledger_tampering(self) -> None:
        self.add_minimum_evidence()
        record = self.admit(self.payload())
        candidate = self.qualification.get_artifact("candidate-a")

        self.database.connection.execute("DROP TRIGGER c3_decision_evidence_no_update")
        self.database.connection.execute(
            """
            UPDATE c3_decision_evidence SET material_sha256 = ?
            WHERE decision_id = ? AND kind = 'CANDIDATE' AND ordinal = 0
            """,
            ("0" * 64, record.decision_id),
        )
        membership_verification = self.decision.verify_decision(record.decision_id)
        self.assertFalse(membership_verification.ok)
        self.assertIn(
            "C3_DECISION_EVIDENCE_MATERIAL_SHA256_MISMATCH:CANDIDATE:0",
            membership_verification.defects,
        )
        self.database.connection.execute(
            """
            UPDATE c3_decision_evidence SET material_sha256 = ?
            WHERE decision_id = ? AND kind = 'CANDIDATE' AND ordinal = 0
            """,
            (candidate.material_sha256, record.decision_id),
        )

        self.database.connection.execute("DROP TRIGGER ledger_events_no_update")
        self.database.connection.execute(
            "UPDATE ledger_events SET actor = ? WHERE event_id = ?",
            ("intruder", record.ledger_event_id),
        )
        ledger_verification = self.decision.verify_decision(record.decision_id)
        self.assertFalse(ledger_verification.ok)
        self.assertIn(
            "C3_DECISION_LEDGER_ACTOR_MISMATCH",
            ledger_verification.defects,
        )

    def test_later_qualification_evidence_makes_decision_stale(self) -> None:
        self.add_minimum_evidence()
        record = self.admit(self.payload())
        self.add_evaluation(
            "evaluation-later",
            actor="later-evaluator",
            occurred_at=D5,
        )

        verification = self.decision.verify_decision(record.decision_id)

        self.assertFalse(verification.ok)
        self.assertIn("C3_DECISION_SNAPSHOT_STALE", verification.defects)


if __name__ == "__main__":
    unittest.main()
