from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from starcom.db import Database
from starcom.errors import ConflictError, StateTransitionError
from starcom.ledger import EventLedger
from starcom.mission import MissionKernel, MissionState
from starcom.proof import ProofEngine, VerificationVerdict
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule, TrustPlane


T0 = "2026-08-13T12:00:00.000000Z"
T1 = "2026-08-13T12:01:00.000000Z"
T2 = "2026-08-13T12:02:00.000000Z"
T3 = "2026-08-13T12:03:00.000000Z"
T4 = "2026-08-13T12:04:00.000000Z"


class MissionKernelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tempdir.name) / "mission.sqlite3")
        self.db.initialize()
        self.ledger = EventLedger(self.db)
        self.trust = TrustPlane(self.db, self.ledger)
        self.proof = ProofEngine(self.db, self.ledger)
        self.kernel = MissionKernel(self.db, self.ledger, self.trust, self.proof)
        self.trust.add_rule(
            PolicyRule(
                "mission-operators",
                PolicyEffect.ALLOW,
                "agent:operator",
                "mission:*",
                "mission:*",
            ),
            actor="owner",
            occurred_at=T0,
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tempdir.cleanup()

    def create(self, mission_id: str = "mission-1"):
        return self.kernel.create(
            mission_id=mission_id,
            title="Build verified core",
            objective="Produce a proof-gated vertical slice.",
            owner="owner",
            occurred_at=T0,
        )

    def decision(self, action: str, mission_id: str = "mission-1"):
        return self.trust.authorize(
            AuthorizationRequest(
                subject="agent:operator",
                action=action,
                resource=f"mission:{mission_id}",
                mission_id=mission_id,
                context={"environment": "test"},
            ),
            now=T1,
        )

    def move_to_running(self, mission_id: str = "mission-1") -> None:
        self.create(mission_id)
        self.kernel.transition(
            mission_id,
            MissionState.PLANNED,
            actor="agent:operator",
            idempotency_key="plan",
            occurred_at=T1,
        )
        authorize = self.decision("mission:authorize", mission_id)
        self.kernel.transition(
            mission_id,
            MissionState.AUTHORIZED,
            actor="agent:operator",
            idempotency_key="authorize",
            authorization_decision_id=authorize.decision_id,
            occurred_at=T2,
        )
        run = self.decision("mission:run", mission_id)
        self.kernel.transition(
            mission_id,
            MissionState.RUNNING,
            actor="agent:operator",
            idempotency_key="run",
            authorization_decision_id=run.decision_id,
            occurred_at=T3,
        )

    def certificate(self, mission_id: str = "mission-1"):
        claim = self.proof.create_claim(
            claim_id=f"claim-{mission_id}",
            subject_type="mission",
            subject_id=mission_id,
            statement="Mission acceptance criteria passed.",
            author="agent:builder",
            policy_version="policy-v1",
            occurred_at=T1,
        )
        self.proof.attach_evidence(
            claim.claim_id,
            evidence_id=f"evidence-{mission_id}",
            kind="test-report",
            uri="artifact://tests/report.txt",
            digest="b" * 64,
            metadata={"passed": True},
            attached_by="agent:builder",
            occurred_at=T2,
        )
        self.proof.verify_claim(
            claim.claim_id,
            verifier="agent:reviewer",
            verdict=VerificationVerdict.APPROVED,
            notes="Reproduced independently.",
            occurred_at=T3,
        )
        return self.proof.certify_claim(
            claim.claim_id,
            certifier="agent:certifier",
            occurred_at=T4,
        )

    def test_legal_path_reaches_running_with_explicit_authorizations(self) -> None:
        self.move_to_running()
        mission = self.kernel.get("mission-1")
        self.assertEqual(mission.state, MissionState.RUNNING)
        self.assertEqual(mission.revision, 3)
        self.assertTrue(self.ledger.verify("mission:mission-1").ok)

    def test_illegal_transition_is_rejected_without_writing_event(self) -> None:
        self.create()
        before = len(self.ledger.read_stream("mission:mission-1"))
        with self.assertRaisesRegex(StateTransitionError, "CREATED.*RUNNING"):
            self.kernel.transition(
                "mission-1",
                MissionState.RUNNING,
                actor="agent:operator",
                idempotency_key="skip",
                occurred_at=T1,
            )
        self.assertEqual(len(self.ledger.read_stream("mission:mission-1")), before)

    def test_sensitive_transition_requires_matching_allowed_decision(self) -> None:
        self.create()
        self.kernel.transition(
            "mission-1",
            MissionState.PLANNED,
            actor="agent:operator",
            idempotency_key="plan",
            occurred_at=T1,
        )
        with self.assertRaisesRegex(StateTransitionError, "authorization"):
            self.kernel.transition(
                "mission-1",
                MissionState.AUTHORIZED,
                actor="agent:operator",
                idempotency_key="authorize-missing",
                occurred_at=T2,
            )
        wrong = self.decision("mission:run")
        with self.assertRaisesRegex(StateTransitionError, "does not match"):
            self.kernel.transition(
                "mission-1",
                MissionState.AUTHORIZED,
                actor="agent:operator",
                idempotency_key="authorize-wrong",
                authorization_decision_id=wrong.decision_id,
                occurred_at=T2,
            )

    def test_authorization_decision_cannot_be_reused(self) -> None:
        self.create()
        self.kernel.transition(
            "mission-1",
            MissionState.PLANNED,
            actor="agent:operator",
            idempotency_key="plan",
            occurred_at=T1,
        )
        authorization = self.decision("mission:authorize")
        self.kernel.transition(
            "mission-1",
            MissionState.AUTHORIZED,
            actor="agent:operator",
            idempotency_key="authorize",
            authorization_decision_id=authorization.decision_id,
            occurred_at=T2,
        )
        with self.assertRaisesRegex(ConflictError, "authorization decision"):
            self.kernel.transition(
                "mission-1",
                MissionState.CANCELLED,
                actor="agent:operator",
                idempotency_key="cancel",
                authorization_decision_id=authorization.decision_id,
                occurred_at=T3,
            )

    def test_terminal_state_is_immutable(self) -> None:
        self.create()
        self.kernel.transition(
            "mission-1",
            MissionState.CANCELLED,
            actor="owner",
            idempotency_key="cancel",
            occurred_at=T1,
        )
        with self.assertRaisesRegex(StateTransitionError, "terminal"):
            self.kernel.transition(
                "mission-1",
                MissionState.PLANNED,
                actor="owner",
                idempotency_key="revive",
                occurred_at=T2,
            )

    def test_success_requires_valid_certificate_for_same_mission(self) -> None:
        self.move_to_running()
        with self.assertRaisesRegex(StateTransitionError, "certificate"):
            self.kernel.transition(
                "mission-1",
                MissionState.SUCCEEDED,
                actor="agent:operator",
                idempotency_key="success-missing",
                occurred_at=T4,
            )
        wrong = self.certificate("mission-other")
        with self.assertRaisesRegex(StateTransitionError, "different mission"):
            self.kernel.transition(
                "mission-1",
                MissionState.SUCCEEDED,
                actor="agent:operator",
                idempotency_key="success-wrong",
                certificate_id=wrong.certificate_id,
                occurred_at=T4,
            )
        right = self.certificate("mission-1")
        receipt = self.kernel.transition(
            "mission-1",
            MissionState.SUCCEEDED,
            actor="agent:operator",
            idempotency_key="success",
            certificate_id=right.certificate_id,
            occurred_at=T4,
        )
        self.assertEqual(receipt.to_state, MissionState.SUCCEEDED)
        self.assertEqual(self.kernel.get("mission-1").state, MissionState.SUCCEEDED)

    def test_idempotent_replay_returns_same_receipt_without_new_event(self) -> None:
        self.create()
        first = self.kernel.transition(
            "mission-1",
            MissionState.PLANNED,
            actor="agent:operator",
            idempotency_key="plan",
            reason="approved plan",
            occurred_at=T1,
        )
        count = len(self.ledger.read_stream("mission:mission-1"))
        second = self.kernel.transition(
            "mission-1",
            MissionState.PLANNED,
            actor="agent:operator",
            idempotency_key="plan",
            reason="approved plan",
            occurred_at=T1,
        )
        self.assertEqual(first, second)
        self.assertEqual(len(self.ledger.read_stream("mission:mission-1")), count)

    def test_same_idempotency_key_with_different_payload_is_rejected(self) -> None:
        self.create()
        self.kernel.transition(
            "mission-1",
            MissionState.PLANNED,
            actor="agent:operator",
            idempotency_key="same",
            reason="one",
            occurred_at=T1,
        )
        with self.assertRaisesRegex(ConflictError, "idempotency"):
            self.kernel.transition(
                "mission-1",
                MissionState.PLANNED,
                actor="agent:operator",
                idempotency_key="same",
                reason="two",
                occurred_at=T1,
            )


if __name__ == "__main__":
    unittest.main()
