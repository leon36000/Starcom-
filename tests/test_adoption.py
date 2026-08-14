from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from starcom.adoption import C3AdoptionService, C3AdoptionStatus
from starcom.certification import C2CertificationRecord, C2CertificationVerification
from starcom.continuity import ContinuityService
from starcom.db import Database
from starcom.errors import (
    AuthorizationError,
    ConflictError,
    IntegrityError,
    StateTransitionError,
    ValidationError,
)
from starcom.ledger import EventLedger
from starcom.qualification import QualificationArtifactKind, QualificationLab
from starcom.qualification_decision import (
    C3DecisionService,
    C3DecisionVerdict,
    C3DecisionVerification,
)
from starcom.qualification_gate import C3QualificationGate
from starcom.trust import (
    AuthorizationRequest,
    DecisionVerification,
    PolicyEffect,
    PolicyRule,
    TrustPlane,
)


A0 = "2026-08-14T13:00:00.000000Z"
A1 = "2026-08-14T13:01:00.000000Z"
A2 = "2026-08-14T13:02:00.000000Z"
A3 = "2026-08-14T13:03:00.000000Z"
A4 = "2026-08-14T13:04:00.000000Z"
A5 = "2026-08-14T13:05:00.000000Z"
A6 = "2026-08-14T13:06:00.000000Z"
A7 = "2026-08-14T13:07:00.000000Z"
A8 = "2026-08-14T13:08:00.000000Z"
CERTIFICATE_ID = "certificate-adoption"
DECISION_KEY = b"c3-adoption-decision-key"


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


class C3AdoptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.database = Database(Path(self.tempdir.name) / "adoption.sqlite3")
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
            recollection_id="c2-adoption",
            incident_id="task5-adoption",
            campaign_id="campaign-adoption",
            key_id="c2-key",
            payload_sha256="a" * 64,
            signature_sha256="b" * 64,
            certifier_identity="c2-certifier",
            identity_count=800,
            required_target=800,
            identity_set_digest="c" * 64,
            certified_at_utc=A0,
            admitted_at=A0,
            admitted_by="c2-admission-agent",
            ledger_event_id="c2-certificate-event",
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
            "qualification-adoption",
            name="C3 adoption authorization fixture",
            actor="lab-owner",
            occurred_at=A0,
        )
        self.c3.start(
            "c3-adoption",
            qualification_run_id="qualification-adoption",
            certificate_id=CERTIFICATE_ID,
            actor="c3-owner",
            occurred_at=A1,
        )
        self.decisions = C3DecisionService(
            self.database,
            self.ledger,
            self.continuity,
            self.certification,  # type: ignore[arg-type]
            self.c3,
            self.qualification,
        )
        self._accept_decision_root()
        self._add_candidate_and_evaluation()
        self.adoptions = C3AdoptionService(
            self.database,
            self.ledger,
            self.trust,
            self.continuity,
            self.decisions,
            self.qualification,
        )
        self.rule_counter = 0

    def tearDown(self) -> None:
        self.database.close()
        self.tempdir.cleanup()

    def _accept_decision_root(self) -> None:
        self.trust.add_rule(
            PolicyRule(
                "allow-adoption-decision-key",
                PolicyEffect.ALLOW,
                "owner",
                "continuity.trust-root.accept",
                "continuity:trust-root:c3-adoption-decision-key",
            ),
            actor="owner",
            occurred_at=A0,
        )
        authorization = self.trust.authorize(
            AuthorizationRequest(
                subject="owner",
                action="continuity.trust-root.accept",
                resource="continuity:trust-root:c3-adoption-decision-key",
            ),
            now=A1,
        )
        self.assertTrue(authorization.allowed)
        self.continuity.accept_trust_root(
            "c3-adoption-decision-key",
            DECISION_KEY,
            decision_id=authorization.decision_id,
            actor="owner",
            occurred_at=A1,
        )

    def _add_candidate_and_evaluation(self) -> None:
        self.qualification.record_artifact(
            "qualification-adoption",
            artifact_id="candidate-a",
            kind=QualificationArtifactKind.CANDIDATE,
            material={
                "component_id": "candidate-a",
                "version": "1.0.0",
                "source": "native-fixture",
            },
            actor="candidate-author",
            occurred_at=A2,
        )
        self.qualification.record_artifact(
            "qualification-adoption",
            artifact_id="evaluation-a",
            kind=QualificationArtifactKind.EVALUATION,
            material={
                "candidate_artifact_id": "candidate-a",
                "score": 95,
            },
            actor="evaluator",
            occurred_at=A3,
        )

    @staticmethod
    def valid_rollback() -> dict[str, object]:
        return {
            "strategy": "Restore the pre-adoption snapshot and verify sovereign state.",
            "steps": [
                "Stop before external execution.",
                "Restore the recorded pre-adoption snapshot.",
            ],
            "verification_steps": [
                "Verify the candidate remains inactive.",
                "Verify all STARCOM ledgers remain clean.",
            ],
            "abort_conditions": [
                "Any digest mismatch.",
                "Any missing independent execution authorization.",
            ],
            "requires_separate_execution_authorization": True,
        }

    @staticmethod
    def _sign(payload: bytes) -> bytes:
        return hashlib.sha256(DECISION_KEY + payload).digest()

    def admit_c3_decision(
        self,
        *,
        decision_id: str = "decision-selected",
        verdict: C3DecisionVerdict = C3DecisionVerdict.CANDIDATE_SELECTED,
        selected_candidate_artifact_id: str | None = "candidate-a",
        decided_at: str = A4,
        admitted_at: str = A5,
    ):
        snapshot = self.decisions.snapshot("c3-adoption")
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
            "decision_maker_identity": "independent-decision-maker",
            "decision_maker_environment": "isolated-adoption-fixture",
            "decided_at_utc": decided_at,
            "independence_basis": "separate key, identity, process, and review",
            "independent_identity_status": "SATISFIED",
            "qualification_verification_result": "PASS",
            "gate_effect": "NO_ADOPTION_EXECUTED",
        }
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return self.decisions.admit_decision(
            "c3-adoption",
            "c3-adoption-decision-key",
            payload,
            self._sign(payload),
            actor="decision-admission-agent",
            occurred_at=admitted_at,
        )

    def allow_request(
        self,
        request: AuthorizationRequest,
        *,
        now: str = A6,
    ):
        self.rule_counter += 1
        self.trust.add_rule(
            PolicyRule(
                f"allow-adoption-{self.rule_counter}",
                PolicyEffect.ALLOW,
                request.subject,
                request.action,
                request.resource,
            ),
            actor="owner",
            occurred_at=A0,
        )
        decision = self.trust.authorize(request, now=now)
        self.assertTrue(decision.allowed)
        return decision

    @staticmethod
    def request_for(
        preparation,
        *,
        actor: str = "owner",
        action: str | None = None,
        resource: str | None = None,
        mission_id: str | None | object = ...,
        context: dict[str, object] | None = None,
    ) -> AuthorizationRequest:
        resolved_mission = preparation.mission_id if mission_id is ... else mission_id
        return AuthorizationRequest(
            subject=actor,
            action=action or preparation.action,
            resource=resource or preparation.resource,
            mission_id=resolved_mission,  # type: ignore[arg-type]
            context=context if context is not None else dict(preparation.context),
        )

    def exact_authorization(self, preparation, *, actor: str = "owner", now: str = A6):
        return self.allow_request(
            self.request_for(preparation, actor=actor),
            now=now,
        )

    def authorize(
        self,
        authorization_decision_id: str,
        *,
        adoption_id: str = "adoption-a",
        actor: str = "owner",
        occurred_at: str = A7,
        rollback_plan: dict[str, object] | None = None,
    ):
        return self.adoptions.authorize_adoption(
            adoption_id,
            c3_run_id="c3-adoption",
            authorization_decision_id=authorization_decision_id,
            rollback_plan=rollback_plan or self.valid_rollback(),
            actor=actor,
            occurred_at=occurred_at,
        )

    def test_preparation_is_deterministic_and_binds_exact_authorization_context(self) -> None:
        decision = self.admit_c3_decision()
        rollback = self.valid_rollback()

        first = self.adoptions.prepare("c3-adoption", rollback)
        second = self.adoptions.prepare("c3-adoption", rollback)

        self.assertEqual(first, second)
        candidate = self.qualification.get_artifact("candidate-a")
        self.assertEqual(first.c3_decision_id, decision.decision_id)
        self.assertEqual(first.candidate_artifact_id, "candidate-a")
        self.assertEqual(first.candidate_material_sha256, candidate.material_sha256)
        self.assertEqual(first.decision_payload_sha256, decision.payload_sha256)
        self.assertEqual(first.qualification_head_hash, decision.qualification_head_hash)
        self.assertEqual(first.action, "c3.adoption.authorize")
        self.assertEqual(
            first.resource,
            "continuity:c3:c3-adoption:adoption:candidate-a",
        )
        self.assertEqual(first.mission_id, "c3-adoption")
        self.assertEqual(
            first.context,
            {
                "authorization_mode": "AUTHORIZE_ONLY_NOT_EXECUTE",
                "c3_decision_id": decision.decision_id,
                "candidate_artifact_id": "candidate-a",
                "candidate_material_sha256": candidate.material_sha256,
                "decision_payload_sha256": decision.payload_sha256,
                "qualification_head_hash": decision.qualification_head_hash,
                "rollback_plan_sha256": first.rollback_plan_sha256,
            },
        )
        count = self.database.connection.execute(
            "SELECT COUNT(*) FROM c3_adoptions"
        ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_default_deny_blocks_adoption_authorization(self) -> None:
        self.admit_c3_decision()
        preparation = self.adoptions.prepare("c3-adoption", self.valid_rollback())
        denied = self.trust.authorize(self.request_for(preparation), now=A6)
        self.assertFalse(denied.allowed)

        with self.assertRaises(AuthorizationError):
            self.authorize(denied.decision_id)

        self.assertEqual(
            self.database.connection.execute(
                "SELECT COUNT(*) FROM c3_adoptions"
            ).fetchone()[0],
            0,
        )

    def test_exact_authorization_creates_verified_not_executed_receipt(self) -> None:
        self.admit_c3_decision()
        preparation = self.adoptions.prepare("c3-adoption", self.valid_rollback())
        authorization = self.exact_authorization(preparation)

        first = self.authorize(authorization.decision_id)
        replay = self.authorize(authorization.decision_id, occurred_at=A8)

        self.assertEqual(first, replay)
        self.assertEqual(first.status, C3AdoptionStatus.AUTHORIZED_NOT_EXECUTED)
        self.assertEqual(first.rollback_plan, self.valid_rollback())
        verification = self.adoptions.verify_adoption(first.adoption_id)
        self.assertTrue(verification.ok, verification.defects)
        consumption = self.database.connection.execute(
            """
            SELECT * FROM continuity_authorization_consumptions
            WHERE decision_id = ?
            """,
            (authorization.decision_id,),
        ).fetchone()
        self.assertIsNotNone(consumption)
        assert consumption is not None
        self.assertEqual(consumption["operation_kind"], "C3_ADOPTION_AUTHORIZED")
        self.assertEqual(consumption["operation_id"], first.adoption_id)
        with self.assertRaises(sqlite3.IntegrityError):
            self.database.connection.execute(
                "UPDATE c3_adoptions SET status = ? WHERE adoption_id = ?",
                ("EXECUTED", first.adoption_id),
            )

    def test_no_selection_decision_is_rejected(self) -> None:
        self.admit_c3_decision(
            decision_id="decision-no-selection",
            verdict=C3DecisionVerdict.NO_SELECTION,
            selected_candidate_artifact_id=None,
        )

        with self.assertRaisesRegex(
            StateTransitionError,
            "selected C3 candidate",
        ):
            self.adoptions.prepare("c3-adoption", self.valid_rollback())

    def test_invalid_rollback_contracts_are_rejected(self) -> None:
        self.admit_c3_decision()
        valid = self.valid_rollback()
        invalid = [
            {},
            {**valid, "unexpected": "field"},
            {**valid, "strategy": ""},
            {**valid, "steps": []},
            {**valid, "steps": [""]},
            {**valid, "verification_steps": "not-a-list"},
            {**valid, "abort_conditions": []},
            {**valid, "requires_separate_execution_authorization": False},
            {**valid, "requires_separate_execution_authorization": 1},
        ]
        for index, rollback in enumerate(invalid):
            with self.subTest(index=index):
                with self.assertRaises(ValidationError):
                    self.adoptions.prepare("c3-adoption", rollback)

    def test_wrong_actor_resource_mission_or_context_is_rejected(self) -> None:
        self.admit_c3_decision()
        preparation = self.adoptions.prepare("c3-adoption", self.valid_rollback())
        wrong_requests = (
            self.request_for(preparation, actor="intruder"),
            self.request_for(preparation, resource="continuity:c3:other:adoption:candidate-a"),
            self.request_for(preparation, mission_id="other-c3-run"),
            self.request_for(
                preparation,
                context={**dict(preparation.context), "authorization_mode": "EXECUTE"},
            ),
        )
        for index, request in enumerate(wrong_requests):
            with self.subTest(index=index):
                decision = self.allow_request(request)
                with self.assertRaises(AuthorizationError):
                    self.authorize(decision.decision_id)

    def test_authorization_and_adoption_chronology_is_enforced(self) -> None:
        self.admit_c3_decision(admitted_at=A5)
        preparation = self.adoptions.prepare("c3-adoption", self.valid_rollback())
        early_authorization = self.exact_authorization(preparation, now=A4)
        with self.assertRaisesRegex(
            StateTransitionError,
            "authorization predates the signed C3 decision admission",
        ):
            self.authorize(early_authorization.decision_id)

        valid_authorization = self.exact_authorization(preparation, now=A6)
        with self.assertRaisesRegex(
            StateTransitionError,
            "adoption authorization predates the TrustPlane decision",
        ):
            self.authorize(valid_authorization.decision_id, occurred_at=A5)

    def test_second_adoption_and_authorization_reuse_are_rejected(self) -> None:
        self.admit_c3_decision()
        preparation = self.adoptions.prepare("c3-adoption", self.valid_rollback())
        first_authorization = self.exact_authorization(preparation)
        self.authorize(first_authorization.decision_id)

        second_authorization = self.exact_authorization(preparation, now=A7)
        with self.assertRaises(ConflictError):
            self.authorize(
                second_authorization.decision_id,
                adoption_id="adoption-second",
                occurred_at=A8,
            )

        reused_authorization = self.exact_authorization(preparation, now=A7)
        self.database.connection.execute(
            """
            INSERT INTO continuity_authorization_consumptions (
                decision_id, operation_kind, operation_id, consumed_at, consumed_by
            ) VALUES (?, 'OTHER_OPERATION', 'other-operation', ?, 'owner')
            """,
            (reused_authorization.decision_id, A7),
        )
        with self.assertRaises(AuthorizationError):
            self.authorize(
                reused_authorization.decision_id,
                adoption_id="adoption-reused-auth",
                occurred_at=A8,
            )

    def test_transaction_rechecks_decision_and_trustplane(self) -> None:
        self.admit_c3_decision()
        preparation = self.adoptions.prepare("c3-adoption", self.valid_rollback())
        authorization = self.exact_authorization(preparation)

        original_decision_verify = self.decisions.verify_decision
        decision_calls = 0

        def changing_decision(decision_id: str) -> C3DecisionVerification:
            nonlocal decision_calls
            decision_calls += 1
            if decision_calls >= 2:
                return C3DecisionVerification(
                    decision_id=decision_id,
                    defects=("SIMULATED_DECISION_CHANGE",),
                )
            return original_decision_verify(decision_id)

        self.decisions.verify_decision = changing_decision  # type: ignore[method-assign]
        with self.assertRaises(IntegrityError):
            self.authorize(authorization.decision_id)
        self.assertGreaterEqual(decision_calls, 2)
        self.decisions.verify_decision = original_decision_verify  # type: ignore[method-assign]

        original_trust_verify = self.trust.verify_decision
        trust_calls = 0

        def changing_trust(decision_id: str) -> DecisionVerification:
            nonlocal trust_calls
            trust_calls += 1
            if trust_calls >= 2:
                return DecisionVerification(
                    decision_id=decision_id,
                    defects=("SIMULATED_TRUST_CHANGE",),
                )
            return original_trust_verify(decision_id)

        self.trust.verify_decision = changing_trust  # type: ignore[method-assign]
        with self.assertRaises(AuthorizationError):
            self.authorize(authorization.decision_id)
        self.assertGreaterEqual(trust_calls, 2)
        self.assertEqual(
            self.database.connection.execute(
                "SELECT COUNT(*) FROM c3_adoptions"
            ).fetchone()[0],
            0,
        )

    def test_verifier_detects_row_rollback_consumption_and_ledger_tampering(self) -> None:
        self.admit_c3_decision()
        preparation = self.adoptions.prepare("c3-adoption", self.valid_rollback())
        authorization = self.exact_authorization(preparation)
        record = self.authorize(authorization.decision_id)

        self.database.connection.execute("DROP TRIGGER c3_adoptions_no_update")
        self.database.connection.execute(
            "UPDATE c3_adoptions SET rollback_plan_json = ? WHERE adoption_id = ?",
            ("{not-json", record.adoption_id),
        )
        rollback_verification = self.adoptions.verify_adoption(record.adoption_id)
        self.assertFalse(rollback_verification.ok)
        self.assertIn("C3_ADOPTION_ROLLBACK_INVALID", rollback_verification.defects)

        self.database.connection.execute(
            """
            UPDATE continuity_authorization_consumptions SET operation_id = ?
            WHERE decision_id = ?
            """,
            ("wrong-operation", authorization.decision_id),
        )
        consumption_verification = self.adoptions.verify_adoption(record.adoption_id)
        self.assertIn(
            "C3_ADOPTION_AUTHORIZATION_CONSUMPTION_MISMATCH",
            consumption_verification.defects,
        )

        self.database.connection.execute("DROP TRIGGER ledger_events_no_update")
        self.database.connection.execute(
            "UPDATE ledger_events SET actor = ? WHERE event_id = ?",
            ("intruder", record.ledger_event_id),
        )
        ledger_verification = self.adoptions.verify_adoption(record.adoption_id)
        self.assertIn(
            "C3_ADOPTION_LEDGER_ACTOR_MISMATCH",
            ledger_verification.defects,
        )

    def test_later_qualification_evidence_makes_adoption_stale(self) -> None:
        self.admit_c3_decision()
        preparation = self.adoptions.prepare("c3-adoption", self.valid_rollback())
        authorization = self.exact_authorization(preparation)
        record = self.authorize(authorization.decision_id)
        self.qualification.record_artifact(
            "qualification-adoption",
            artifact_id="evaluation-later",
            kind=QualificationArtifactKind.EVALUATION,
            material={
                "candidate_artifact_id": "candidate-a",
                "score": 96,
            },
            actor="later-evaluator",
            occurred_at=A8,
        )

        verification = self.adoptions.verify_adoption(record.adoption_id)

        self.assertFalse(verification.ok)
        self.assertIn(
            "C3_ADOPTION_DECISION:C3_DECISION_SNAPSHOT_STALE",
            verification.defects,
        )

    def test_service_has_no_execution_method(self) -> None:
        self.assertFalse(hasattr(self.adoptions, "execute"))
        self.assertFalse(hasattr(self.adoptions, "install"))
        self.assertFalse(hasattr(self.adoptions, "enable"))
        self.assertFalse(hasattr(self.adoptions, "deploy"))
        self.assertFalse(hasattr(self.adoptions, "run"))
        self.assertEqual(
            [status.value for status in C3AdoptionStatus],
            ["C3_ADOPTION_AUTHORIZED_NOT_EXECUTED"],
        )


if __name__ == "__main__":
    unittest.main()
