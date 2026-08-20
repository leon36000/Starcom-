from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from types import SimpleNamespace

from starcom.canonical import canonical_json, sha256_digest
from starcom.continuity import ContinuityService
from starcom.db import Database
from starcom.errors import ConflictError, IntegrityError, StateTransitionError, ValidationError
from starcom.ledger import EventLedger
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule, TrustPlane
from starcom.execution_plan import C5ExecutionPlanService


T0 = "2026-08-20T12:00:00.000000Z"
T1 = "2026-08-20T12:01:00.000000Z"
T2 = "2026-08-20T12:02:00.000000Z"
T3 = "2026-08-20T12:03:00.000000Z"
T4 = "2026-08-20T12:04:00.000000Z"
PUBLIC_KEY = b"c5-plan-public-key"


class RecordingSignatureVerifier:
    def validate_public_key(self, public_key_pem: bytes) -> bool:
        return public_key_pem == PUBLIC_KEY

    @staticmethod
    def sign(public_key_pem: bytes, payload: bytes) -> bytes:
        return hashlib.sha256(public_key_pem + payload).digest()

    def verify(self, public_key_pem: bytes, payload: bytes, signature: bytes) -> bool:
        return signature == self.sign(public_key_pem, payload)


class FakeArchitecture:
    def __init__(self) -> None:
        self.clean = True
        self.database = None
        self.ledger = None
        self.continuity = None
        self.baseline = SimpleNamespace(
            baseline_id="baseline-1",
            architecture_id="starcom-v3.2-baseline",
            c3_run_id="c3-run-1",
            architecture_version="3.2.0",
            payload_sha256="a" * 64,
            c3_snapshot_digest="b" * 64,
            designed_at_utc=T2,
            admitted_at=T3,
            architect_identity="c4-architect",
            architect_environment="c4-isolated",
            reviewer_identity="c4-reviewer",
            reviewer_environment="c4-review-isolated",
            admitted_by="c4-admitter",
        )
        self.snapshot_value = SimpleNamespace(
            c3_snapshot_digest="b" * 64,
            snapshot_digest="c" * 64,
            latest_evidence_at=T1,
            decision_decided_at=T1,
            adoption_authorized_at=None,
            execution_requested_at=None,
            material_identities=("c3-decision-maker", "c3-evidence-author"),
        )

    def get_baseline(self, baseline_id: str):
        if baseline_id not in {
            self.baseline.baseline_id,
            self.baseline.architecture_id,
            self.baseline.c3_run_id,
        }:
            raise KeyError(baseline_id)
        return self.baseline

    def verify_baseline(self, baseline_id: str):
        if not self.clean:
            return SimpleNamespace(
                baseline_id=baseline_id,
                defects=("C4_TAMPERED",),
                ok=False,
            )
        return SimpleNamespace(baseline_id=baseline_id, defects=(), ok=True)

    def snapshot(self, architecture_id: str):
        self.get_baseline(architecture_id)
        return self.snapshot_value


class PlanGraph:
    def __init__(self, root: Path) -> None:
        self.database = Database(root / "execution-plan.sqlite3")
        self.database.initialize()
        self.ledger = EventLedger(self.database)
        self.trust = TrustPlane(self.database, self.ledger)
        self.verifier = RecordingSignatureVerifier()
        self.continuity = ContinuityService(self.database, self.ledger, self.trust, self.verifier)
        self.architecture = FakeArchitecture()
        self.architecture.database = self.database
        self.architecture.ledger = self.ledger
        self.architecture.continuity = self.continuity
        self.service = C5ExecutionPlanService(
            self.database,
            self.ledger,
            self.trust,
            self.continuity,
            self.architecture,
            signature_verifier=self.verifier,
        )

    def close(self) -> None:
        self.database.close()

    def accept_root(self) -> None:
        self.trust.add_rule(
            PolicyRule(
                "c5-root-rule",
                PolicyEffect.ALLOW,
                "c5-root-operator",
                "continuity.trust-root.accept",
                "continuity:trust-root:c5-root",
            ),
            actor="policy-owner",
            occurred_at=T0,
        )
        decision = self.trust.authorize(
            AuthorizationRequest(
                "c5-root-operator",
                "continuity.trust-root.accept",
                "continuity:trust-root:c5-root",
            ),
            now=T1,
        )
        self.continuity.accept_trust_root(
            "c5-root",
            PUBLIC_KEY,
            decision_id=decision.decision_id,
            actor="c5-root-operator",
            occurred_at=T1,
        )

    def payload(self, **overrides: object) -> bytes:
        snapshot = self.service.snapshot("starcom-v3.2-baseline")
        value: dict[str, object] = {
            "plan_id": "plan-1",
            "plan_version": "1.0.0",
            "architecture_id": "starcom-v3.2-baseline",
            "architecture_version": "3.2.0",
            "architecture_payload_sha256": self.architecture.baseline.payload_sha256,
            "c3_snapshot_digest": snapshot.c3_snapshot_digest,
            "work_items": [
                {
                    "work_item_id": "item-1",
                    "phase": "foundation",
                    "title": "Verify baseline inputs",
                    "owner_role": "planner",
                    "dependencies": [],
                    "input_digests": ["1" * 64],
                    "outputs": ["baseline-proof"],
                    "acceptance_checks": ["proof-is-verifiable"],
                    "risk_level": "LOW",
                    "human_gate_required": True,
                }
            ],
            "execution_policy": {
                "max_parallelism": 1,
                "fail_closed": True,
                "require_proof": True,
                "stop_on_verification_failure": True,
                "human_gate_actions": ["approve-foundation"],
            },
            "release_gates": [
                {
                    "gate_id": "gate-1",
                    "title": "Foundation proof gate",
                    "required_work_item_ids": ["item-1"],
                    "proof_digests": ["2" * 64],
                    "human_gate_required": True,
                }
            ],
            "risk_register_digest": "3" * 64,
            "resource_model_digest": "4" * 64,
            "verification_strategy_digest": "5" * 64,
            "planner_identity": "independent-planner",
            "planner_environment": "c5-plan-worktree",
            "reviewer_identity": "independent-plan-reviewer",
            "reviewer_environment": "c5-review-worktree",
            "planned_at_utc": T4,
            "independence_basis": {
                "excluded_identities": [
                    "c3-decision-maker",
                    "c3-evidence-author",
                    "c4-admitter",
                    "c4-architect",
                    "c4-reviewer",
                ],
                "statement": "planner and reviewer are isolated from C4 and C3 material actors",
            },
            "execution_status": "NOT_STARTED",
            "gate_effect": "C5_EXECUTION_PLAN_ADMITTED_NOT_STARTED",
        }
        value.update(overrides)
        return canonical_json(value).encode("utf-8")


class C5ExecutionPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.graph = PlanGraph(Path(self.tempdir.name))

    def tearDown(self) -> None:
        self.graph.close()
        self.tempdir.cleanup()

    def test_public_contract_is_deterministic(self) -> None:
        first = self.graph.service.snapshot("starcom-v3.2-baseline")
        second = self.graph.service.snapshot("starcom-v3.2-baseline")
        self.assertEqual(first, second)
        preparation = self.graph.service.prepare("plan-1", "starcom-v3.2-baseline")
        self.assertEqual(preparation.plan_id, "plan-1")
        self.assertEqual(preparation.plan_version, "1.0.0")
        self.assertEqual(preparation.c4_snapshot_digest, first.snapshot_digest)
        self.assertEqual(preparation.execution_status, "NOT_STARTED")

    def test_strict_contract_rejects_malformed_payloads(self) -> None:
        malformed = [
            b'{"plan_id":"a","plan_id":"b"}',
            b"\xff",
            self.graph.payload(plan_version="9.9.9"),
            self.graph.payload(architecture_payload_sha256="A" * 64),
            self.graph.payload(execution_status="STARTED"),
            self.graph.payload(execution_policy={
                "max_parallelism": 1,
                "fail_closed": False,
                "require_proof": True,
                "stop_on_verification_failure": True,
                "human_gate_actions": [],
            }),
            self.graph.payload(release_gates=[]),
            self.graph.payload(work_items=[{
                "work_item_id": "item-1",
                "phase": "foundation",
                "title": "Verify baseline inputs",
                "owner_role": "planner",
                "dependencies": ["missing-item"],
                "input_digests": ["1" * 64],
                "outputs": ["baseline-proof"],
                "acceptance_checks": ["proof-is-verifiable"],
                "risk_level": "LOW",
                "human_gate_required": True,
            }]),
        ]
        for payload in malformed:
            with self.subTest(payload=payload):
                with self.assertRaises(Exception) as context:
                    self.graph.service.admit_plan(
                        "starcom-v3.2-baseline",
                        "missing-root",
                        payload,
                        b"bad-signature",
                        actor="planner",
                        occurred_at=T4,
                    )
                self.assertNotIsInstance(context.exception, AttributeError)

    def test_c5_binding_and_dag_fail_closed(self) -> None:
        for overrides in (
            {"planner_identity": "c4-architect"},
            {"planned_at_utc": T0},
            {"work_items": [{
                "work_item_id": "item-1",
                "phase": "foundation",
                "title": "Verify baseline inputs",
                "owner_role": "planner",
                "dependencies": ["missing-item"],
                "input_digests": ["1" * 64],
                "outputs": ["baseline-proof"],
                "acceptance_checks": ["proof-is-verifiable"],
                "risk_level": "LOW",
                "human_gate_required": True,
            }]},
            {"work_items": [{
                "work_item_id": "item-1",
                "phase": "foundation",
                "title": "Verify baseline inputs",
                "owner_role": "planner",
                "dependencies": ["item-1"],
                "input_digests": ["1" * 64],
                "outputs": ["baseline-proof"],
                "acceptance_checks": ["proof-is-verifiable"],
                "risk_level": "LOW",
                "human_gate_required": True,
            }]},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises((ValidationError, StateTransitionError)):
                    self.graph.service.admit_plan(
                        "starcom-v3.2-baseline",
                        "missing-root",
                        self.graph.payload(**overrides),
                        b"bad-signature",
                        actor="planner",
                        occurred_at=T4,
                    )

        cycle_items = [
            {
                "work_item_id": "item-1",
                "phase": "foundation",
                "title": "First",
                "owner_role": "planner",
                "dependencies": ["item-2"],
                "input_digests": ["1" * 64],
                "outputs": ["first-output"],
                "acceptance_checks": ["first-check"],
                "risk_level": "LOW",
                "human_gate_required": True,
            },
            {
                "work_item_id": "item-2",
                "phase": "foundation",
                "title": "Second",
                "owner_role": "planner",
                "dependencies": ["item-1"],
                "input_digests": ["2" * 64],
                "outputs": ["second-output"],
                "acceptance_checks": ["second-check"],
                "risk_level": "LOW",
                "human_gate_required": True,
            },
        ]
        with self.assertRaises(StateTransitionError):
            self.graph.service.admit_plan(
                "starcom-v3.2-baseline",
                "missing-root",
                self.graph.payload(work_items=cycle_items),
                b"bad-signature",
                actor="planner",
                occurred_at=T4,
            )

        self.graph.architecture.clean = False
        with self.assertRaises(IntegrityError):
            self.graph.service.snapshot("starcom-v3.2-baseline")

    def test_exact_admission_replay_and_conflict(self) -> None:
        payload = self.graph.payload()
        signature = self.graph.verifier.sign(PUBLIC_KEY, payload)
        with self.assertRaises(IntegrityError):
            self.graph.service.admit_plan(
                "starcom-v3.2-baseline",
                "c5-root",
                payload,
                signature,
                actor="plan-admitter",
                occurred_at=T4,
            )
        self.graph.accept_root()
        first = self.graph.service.admit_plan(
            "starcom-v3.2-baseline",
            "c5-root",
            payload,
            signature,
            actor="plan-admitter",
            occurred_at=T4,
        )
        self.assertEqual(first.execution_status, "NOT_STARTED")
        self.assertEqual(first.gate_effect, "C5_EXECUTION_PLAN_ADMITTED_NOT_STARTED")
        self.assertEqual(self.graph.service.get_plan("plan-1"), first)
        self.assertTrue(self.graph.service.verify_plan("plan-1").ok)
        replay = self.graph.service.admit_plan(
            "starcom-v3.2-baseline",
            "c5-root",
            payload,
            signature,
            actor="plan-admitter",
            occurred_at="2026-08-20T12:05:00.000000Z",
        )
        self.assertEqual(replay, first)
        self.assertEqual(
            len(self.graph.ledger.read_stream("continuity:c5:execution-plan:plan-1")),
            1,
        )
        with self.assertRaises(ConflictError):
            self.graph.service.admit_plan(
                "starcom-v3.2-baseline",
                "c5-root",
                self.graph.payload(plan_id="plan-2"),
                self.graph.verifier.sign(PUBLIC_KEY, self.graph.payload(plan_id="plan-2")),
                actor="plan-admitter",
                occurred_at=T4,
            )
        with self.assertRaises(IntegrityError):
            self.graph.service.admit_plan(
                "starcom-v3.2-baseline",
                "c5-root",
                payload + b" ",
                signature,
                actor="plan-admitter",
                occurred_at=T4,
            )

    def test_verifier_detects_c5_tampering(self) -> None:
        self.graph.accept_root()
        payload = self.graph.payload()
        signature = self.graph.verifier.sign(PUBLIC_KEY, payload)
        plan = self.graph.service.admit_plan(
            "starcom-v3.2-baseline",
            "c5-root",
            payload,
            signature,
            actor="plan-admitter",
            occurred_at=T4,
        )
        self.assertEqual(len(self.graph.service.get_work_items(plan.plan_id)), 1)
        self.assertEqual(len(self.graph.service.get_release_gates(plan.plan_id)), 1)
        with self.assertRaises(sqlite3.IntegrityError):
            self.graph.database.connection.execute(
                "UPDATE c5_execution_plans SET architecture_id = 'tampered' WHERE plan_id = ?",
                (plan.plan_id,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.graph.database.connection.execute(
                "UPDATE c5_execution_plan_release_gates SET material_json = '{}' WHERE plan_id = ?",
                (plan.plan_id,),
            )

        self.graph.database.connection.execute(
            "DROP TRIGGER c5_execution_plan_work_items_no_update"
        )
        self.graph.database.connection.execute(
            "UPDATE c5_execution_plan_work_items SET material_json = '{}' WHERE plan_id = ?",
            (plan.plan_id,),
        )
        verification = self.graph.service.verify_plan(plan.plan_id)
        self.assertFalse(verification.ok)
        self.assertTrue(any("PLAN_WORK_ITEMS" in defect for defect in verification.defects))

        self.graph.database.connection.execute(
            "DROP TRIGGER c5_execution_plans_no_update"
        )
        self.graph.database.connection.execute(
            "UPDATE c5_execution_plans SET payload_sha256 = ? WHERE plan_id = ?",
            ("f" * 64, plan.plan_id),
        )
        verification = self.graph.service.verify_plan(plan.plan_id)
        self.assertFalse(verification.ok)
        self.assertIn("PLAN_PAYLOAD_DIGEST_MISMATCH", verification.defects)

        self.graph.database.connection.execute("DROP TRIGGER ledger_events_no_update")
        self.graph.database.connection.execute(
            "UPDATE ledger_events SET kind = 'TAMPERED' WHERE event_id = ?",
            (plan.ledger_event_id,),
        )
        verification = self.graph.service.verify_plan(plan.plan_id)
        self.assertFalse(verification.ok)
        self.assertIn("PLAN_LEDGER_KIND_MISMATCH", verification.defects)

        self.graph.architecture.snapshot_value.latest_evidence_at = T4
        verification = self.graph.service.verify_plan(plan.plan_id)
        self.assertFalse(verification.ok)
        self.assertIn("PLAN_C4_SNAPSHOT_STALE", verification.defects)


class C5RuntimeWiringTests(unittest.TestCase):
    def test_runtime_exposes_one_shared_c5_graph_without_execution_surface(self) -> None:
        from starcom.cli import Runtime

        runtime = Runtime.open(":memory:")
        try:
            self.assertIs(runtime.execution_plan, runtime.c5_execution_plan)
            self.assertIs(runtime.execution_plan.database, runtime.database)
            self.assertIs(runtime.execution_plan.ledger, runtime.ledger)
            self.assertIs(runtime.execution_plan.continuity, runtime.continuity)
            self.assertIs(runtime.execution_plan.architecture, runtime.architecture)
            forbidden = {"start", "run", "execute", "schedule", "dispatch"}
            self.assertTrue(forbidden.isdisjoint(set(dir(runtime.execution_plan))))
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
