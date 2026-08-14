from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from starcom.census import C2CensusService
from starcom.certification import C2CertificationService
from starcom.continuity import ContinuityService
from starcom.db import Database
from starcom.errors import ConflictError, IntegrityError, NotFoundError, StateTransitionError
from starcom.ledger import EventLedger
from starcom.qualification import QualificationArtifactKind, QualificationLab
from starcom.qualification_gate import C3QualificationGate
from starcom.recollection import C2RecollectionService
from starcom.research import ReceiptOutcome, ResearchCampaign
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule, TrustPlane


B0 = "2026-08-14T07:00:00.000000Z"
B1 = "2026-08-14T07:01:00.000000Z"
B2 = "2026-08-14T07:02:00.000000Z"
B3 = "2026-08-14T07:03:00.000000Z"
B4 = "2026-08-14T07:04:00.000000Z"
B5 = "2026-08-14T07:05:00.000000Z"
B6 = "2026-08-14T07:06:00.000000Z"
B7 = "2026-08-14T07:07:00.000000Z"
B8 = "2026-08-14T07:08:00.000000Z"
B9 = "2026-08-14T07:09:00.000000Z"
B10 = "2026-08-14T07:10:00.000000Z"
Q0 = "2026-08-14T07:20:00.000000Z"
Q1 = "2026-08-14T07:21:00.000000Z"
Q2 = "2026-08-14T07:22:00.000000Z"
Q3 = "2026-08-14T07:23:00.000000Z"
ARCHIVE_SHA256 = "5609915904205503ebcdcc548d9b8171fd6d9ba9bf9d1bb9f1ebb036bf8fae7f"
REVIEWER_KEY = b"c3-gate-reviewer-key"
CERTIFIER_KEY = b"c3-gate-independent-certifier-key"
SNAPSHOT_DIGEST = hashlib.sha256(b"c3-gate-snapshot").hexdigest()
CERTIFICATE_ID = "certificate-c3-gate"


class DigestVerifier:
    VALID_KEYS = {REVIEWER_KEY, CERTIFIER_KEY}

    def validate_public_key(self, public_key_pem: bytes) -> bool:
        return public_key_pem in self.VALID_KEYS

    def verify(self, public_key_pem: bytes, payload: bytes, signature: bytes) -> bool:
        return (
            public_key_pem in self.VALID_KEYS
            and signature == hashlib.sha256(public_key_pem + payload).digest()
        )


def sign(key: bytes, payload: bytes) -> bytes:
    return hashlib.sha256(key + payload).digest()


def review_payload() -> bytes:
    value = {
        "review_id": "review-c3-gate",
        "reviewer_identity": "independent-c1-reviewer",
        "review_environment": "isolated-c3-gate-fixture",
        "reviewed_archive_sha256": ARCHIVE_SHA256,
        "reviewed_at_utc": B1,
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


def allow(
    trust: TrustPlane,
    *,
    action: str,
    resource: str,
    rule_id: str,
    now: str,
) -> str:
    trust.add_rule(
        PolicyRule(rule_id, PolicyEffect.ALLOW, "owner", action, resource),
        actor="owner",
        occurred_at=B0,
    )
    decision = trust.authorize(
        AuthorizationRequest(subject="owner", action=action, resource=resource),
        now=now,
    )
    if not decision.allowed:
        raise AssertionError("fixture authorization unexpectedly denied")
    return decision.decision_id


def build_certified_fixture(path: Path) -> None:
    database = Database(path)
    database.initialize()
    try:
        ledger = EventLedger(database)
        trust = TrustPlane(database, ledger)
        continuity = ContinuityService(database, ledger, trust, DigestVerifier())
        research = ResearchCampaign(database, ledger)
        recollection = C2RecollectionService(database, ledger, continuity, research)
        census = C2CensusService(database, ledger, recollection, research)
        certification = C2CertificationService(
            database,
            ledger,
            continuity,
            recollection,
            census,
        )

        continuity.create_incident(
            "task5",
            reviewed_archive_sha256=ARCHIVE_SHA256,
            actor="owner",
            occurred_at=B0,
        )
        research.create(
            campaign_id="c2-campaign",
            name="Task 5 certified census for C3 gate",
            actor="owner",
            occurred_at=B0,
        )
        reviewer_decision = allow(
            trust,
            action="continuity.trust-root.accept",
            resource="continuity:trust-root:reviewer-c3-gate",
            rule_id="allow-c3-reviewer-root",
            now=B1,
        )
        continuity.accept_trust_root(
            "reviewer-c3-gate",
            REVIEWER_KEY,
            decision_id=reviewer_decision,
            actor="owner",
            occurred_at=B1,
        )
        disposition = review_payload()
        review = continuity.admit_review(
            "task5",
            "reviewer-c3-gate",
            disposition,
            sign(REVIEWER_KEY, disposition),
            actor="owner",
            occurred_at=B2,
        )
        recovery_decision = allow(
            trust,
            action="continuity.recovery.publish",
            resource="continuity:incident:task5",
            rule_id="allow-c3-recovery",
            now=B3,
        )
        continuity.publish_recovery(
            "task5",
            review.review_id,
            publication_id="publication-c3-gate",
            idempotency_key="publish-c3-gate-recovery",
            decision_id=recovery_decision,
            actor="owner",
            occurred_at=B3,
        )
        recollection.start(
            "c2-run",
            incident_id="task5",
            campaign_id="c2-campaign",
            minimum_identity_target=800,
            actor="owner",
            occurred_at=B4,
        )
        certifier_decision = allow(
            trust,
            action="continuity.trust-root.accept",
            resource="continuity:trust-root:certifier-c3-gate",
            rule_id="allow-c3-certifier-root",
            now=B5,
        )
        continuity.accept_trust_root(
            "certifier-c3-gate",
            CERTIFIER_KEY,
            decision_id=certifier_decision,
            actor="owner",
            occurred_at=B5,
        )
        research.begin_attempt(
            "c2-campaign",
            attempt_id="attempt-c3-gate",
            wave=1,
            request_key="request-c3-gate",
            source_id="github",
            request={"url": "https://example.invalid/c3-census"},
            actor="collector",
            occurred_at=B6,
        )
        research.record_receipt(
            "attempt-c3-gate",
            receipt_id="receipt-c3-gate",
            outcome=ReceiptOutcome.SUCCESS,
            status_code=200,
            snapshot_digest=SNAPSHOT_DIGEST,
            metadata={"fixture": True},
            actor="collector",
            occurred_at=B6,
        )
        research.checkpoint_cursor(
            "c2-campaign",
            wave=1,
            cursor_key="page",
            value={"page": 1},
            attempt_id="attempt-c3-gate",
            cursor_id="cursor-c3-gate",
            actor="collector",
            occurred_at=B7,
        )
        for index in range(800):
            identity_key = f"identity-{index:04d}"
            observation_id = f"observation-{index:04d}"
            content_digest = hashlib.sha256(identity_key.encode("utf-8")).hexdigest()
            research.record_observation(
                "attempt-c3-gate",
                observation_id=observation_id,
                snapshot_digest=SNAPSHOT_DIGEST,
                content_digest=content_digest,
                data={"identity": identity_key, "fixture": True},
                actor="collector",
                occurred_at=B7,
            )
            census.register_identity(
                "c2-run",
                identity_id=f"identity-record-{index:04d}",
                identity_key=identity_key,
                source_id="github",
                attempt_id="attempt-c3-gate",
                observation_id=observation_id,
                actor="collector",
                occurred_at=B8,
            )
        snapshot = certification.snapshot("c2-run")
        certificate_value = {
            "certificate_id": CERTIFICATE_ID,
            "recollection_id": snapshot.recollection_id,
            "incident_id": snapshot.incident_id,
            "campaign_id": snapshot.campaign_id,
            "identity_count": snapshot.identity_count,
            "required_target": snapshot.required_target,
            "identity_set_digest": snapshot.identity_set_digest,
            "certifier_identity": "independent-certifier",
            "certifier_environment": "isolated-c3-certifier",
            "certified_at_utc": B9,
            "independence_basis": "separate identity, key and execution boundary",
            "independent_identity_status": "SATISFIED",
            "census_verification_result": "PASS",
            "verdict": "C2_CENSUS_CERTIFIED",
            "gate_effect": "NO_CANONICAL_PROMOTION",
        }
        payload = json.dumps(
            certificate_value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        certificate = certification.admit_certification(
            "c2-run",
            "certifier-c3-gate",
            payload,
            sign(CERTIFIER_KEY, payload),
            actor="admission-agent",
            occurred_at=B10,
        )
        verification = certification.verify_certificate(certificate.certificate_id)
        if not verification.ok:
            raise AssertionError(verification.defects)
    finally:
        database.close()


class C3QualificationGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture_directory = tempfile.TemporaryDirectory()
        cls.fixture_path = Path(cls.fixture_directory.name) / "certified.sqlite3"
        build_certified_fixture(cls.fixture_path)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_directory.cleanup()

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "qualification-gate.sqlite3"
        shutil.copy2(self.fixture_path, self.db_path)
        self.db = Database(self.db_path)
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
        self.qualification = QualificationLab(self.db, self.ledger)
        self.gate = C3QualificationGate(
            self.db,
            self.ledger,
            self.certification,
            self.qualification,
        )
        self.qualification.create_run(
            "qualification-run",
            name="C3 component qualification and bakeoffs",
            actor="lab-owner",
            occurred_at=Q0,
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tempdir.cleanup()

    def start(self, **overrides: object):
        values: dict[str, object] = {
            "c3_run_id": "c3-run",
            "qualification_run_id": "qualification-run",
            "certificate_id": CERTIFICATE_ID,
            "actor": "c3-owner",
            "occurred_at": Q1,
        }
        values.update(overrides)
        return self.gate.start(**values)  # type: ignore[arg-type]

    def expected_payload(self, binding) -> dict[str, object]:  # type: ignore[no-untyped-def]
        return {
            "c3_run_id": binding.c3_run_id,
            "qualification_run_id": binding.qualification_run_id,
            "certificate_id": binding.certificate_id,
            "recollection_id": binding.recollection_id,
            "incident_id": binding.incident_id,
            "campaign_id": binding.campaign_id,
            "identity_count": binding.identity_count,
            "required_target": binding.required_target,
            "identity_set_digest": binding.identity_set_digest,
            "qualification_head_hash_at_bind": binding.qualification_head_hash_at_bind,
            "pre_binding_artifact_count": 0,
        }

    def test_missing_certificate_fails_closed(self) -> None:
        with self.assertRaises(NotFoundError):
            self.start(certificate_id="missing-certificate")

    def test_dirty_certificate_fails_closed(self) -> None:
        self.db.connection.execute("DROP TRIGGER c2_certifications_no_update")
        self.db.connection.execute(
            "UPDATE c2_certifications SET identity_set_digest = ? WHERE certificate_id = ?",
            ("0" * 64, CERTIFICATE_ID),
        )

        with self.assertRaisesRegex(
            IntegrityError,
            "C2 certification verification failed",
        ):
            self.start()

    def test_nonempty_qualification_run_is_rejected(self) -> None:
        self.qualification.record_artifact(
            "qualification-run",
            artifact_id="candidate-before-c3",
            kind=QualificationArtifactKind.CANDIDATE,
            material={"component_id": "candidate-before-c3"},
            actor="evaluator",
            occurred_at=Q0,
        )

        with self.assertRaisesRegex(
            StateTransitionError,
            "qualification run must be empty at C3 binding",
        ):
            self.start()

    def test_clean_certificate_binds_empty_run_idempotently_without_adoption(self) -> None:
        binding = self.start()
        replay = self.start(occurred_at=Q2)

        self.assertEqual(binding, replay)
        self.assertEqual(binding.certificate_id, CERTIFICATE_ID)
        self.assertEqual(binding.recollection_id, "c2-run")
        self.assertEqual(binding.incident_id, "task5")
        self.assertEqual(binding.campaign_id, "c2-campaign")
        self.assertEqual(binding.identity_count, 800)
        self.assertEqual(binding.required_target, 800)
        run = self.qualification.get_run("qualification-run")
        self.assertEqual(binding.qualification_head_hash_at_bind, run.ledger_hash)
        artifact_count = self.db.connection.execute(
            "SELECT COUNT(*) FROM qualification_artifacts WHERE qualification_run_id = ?",
            ("qualification-run",),
        ).fetchone()[0]
        self.assertEqual(artifact_count, 0)
        verification = self.gate.verify(binding.c3_run_id)
        self.assertTrue(verification.ok, verification.defects)
        event = self.db.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (binding.ledger_event_id,),
        ).fetchone()
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["stream_id"], "continuity:c3:c3-run")
        self.assertEqual(event["kind"], "C3_QUALIFICATION_STARTED")

    def test_conflicting_replay_and_certificate_or_run_reuse_are_rejected(self) -> None:
        self.start()
        self.qualification.create_run(
            "qualification-run-2",
            name="Second qualification run",
            actor="lab-owner",
            occurred_at=Q2,
        )

        with self.assertRaises(ConflictError):
            self.start(qualification_run_id="qualification-run-2")
        with self.assertRaises(ConflictError):
            self.gate.start(
                "c3-run-2",
                qualification_run_id="qualification-run-2",
                certificate_id=CERTIFICATE_ID,
                actor="c3-owner",
                occurred_at=Q2,
            )
        with self.assertRaises(ConflictError):
            self.gate.start(
                "c3-run-3",
                qualification_run_id="qualification-run",
                certificate_id=CERTIFICATE_ID,
                actor="c3-owner",
                occurred_at=Q2,
            )

    def test_verifier_detects_repointed_binding_event_stream(self) -> None:
        binding = self.start()
        forged = self.ledger.append(
            "continuity:c3:shadow",
            "C3_QUALIFICATION_STARTED",
            self.expected_payload(binding),
            actor=binding.started_by,
            occurred_at=binding.started_at,
        )
        self.db.connection.execute("DROP TRIGGER c3_qualification_bindings_no_update")
        self.db.connection.execute(
            """
            UPDATE c3_qualification_bindings
            SET ledger_event_id = ?, ledger_hash = ?
            WHERE c3_run_id = ?
            """,
            (forged.event_id, forged.record_hash, binding.c3_run_id),
        )

        verification = self.gate.verify(binding.c3_run_id)

        self.assertFalse(verification.ok)
        self.assertIn("C3_LEDGER_STREAM_MISMATCH", verification.defects)

    def test_later_artifacts_are_allowed_but_bind_boundary_tampering_is_detected(self) -> None:
        binding = self.start()
        artifact = self.qualification.record_artifact(
            "qualification-run",
            artifact_id="candidate-after-c3",
            kind=QualificationArtifactKind.CANDIDATE,
            material={"component_id": "candidate-after-c3"},
            actor="evaluator",
            occurred_at=Q2,
        )
        clean = self.gate.verify(binding.c3_run_id)
        self.assertTrue(clean.ok, clean.defects)

        self.db.connection.execute("DROP TRIGGER c3_qualification_bindings_no_update")
        self.db.connection.execute(
            """
            UPDATE c3_qualification_bindings
            SET qualification_head_hash_at_bind = ?
            WHERE c3_run_id = ?
            """,
            (artifact.ledger_hash, binding.c3_run_id),
        )

        verification = self.gate.verify(binding.c3_run_id)

        self.assertFalse(verification.ok)
        self.assertIn("C3_QUALIFICATION_HEAD_AT_BIND_MISMATCH", verification.defects)
        self.assertIn("C3_LEDGER_PAYLOAD_MISMATCH", verification.defects)

    def test_verifier_detects_certificate_tampering_after_binding(self) -> None:
        binding = self.start()
        self.db.connection.execute("DROP TRIGGER c2_certifications_no_update")
        self.db.connection.execute(
            "UPDATE c2_certifications SET identity_set_digest = ? WHERE certificate_id = ?",
            ("0" * 64, CERTIFICATE_ID),
        )

        verification = self.gate.verify(binding.c3_run_id)

        self.assertFalse(verification.ok)
        self.assertTrue(
            any(defect.startswith("C3_CERTIFICATE:") for defect in verification.defects),
            verification.defects,
        )


if __name__ == "__main__":
    unittest.main()
