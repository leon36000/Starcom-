from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace

from starcom.canonical import canonical_json, sha256_digest
from starcom.continuity import ContinuityService
from starcom.db import Database
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
        self.database = None
        self.ledger = None
        self.continuity = None
        self.baseline = SimpleNamespace(
            baseline_id="baseline-1",
            architecture_id="starcom-v3.2-baseline",
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
        if baseline_id not in {self.baseline.baseline_id, self.baseline.architecture_id}:
            raise KeyError(baseline_id)
        return self.baseline

    def verify_baseline(self, baseline_id: str):
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


if __name__ == "__main__":
    unittest.main()
