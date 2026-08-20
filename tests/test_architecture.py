from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace

from starcom.architecture import C4ArchitectureService
from starcom.canonical import canonical_json, sha256_digest
from starcom.continuity import ContinuityService
from starcom.db import Database
from starcom.errors import ConflictError, IntegrityError, StateTransitionError, ValidationError
from starcom.ledger import EventLedger
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule, TrustPlane


T0 = "2026-08-20T12:00:00.000000Z"
T1 = "2026-08-20T12:01:00.000000Z"
T2 = "2026-08-20T12:02:00.000000Z"
T3 = "2026-08-20T12:03:00.000000Z"
PUBLIC_KEY = b"baseline-public-key"


class RecordingSignatureVerifier:
    def validate_public_key(self, public_key_pem: bytes) -> bool:
        return public_key_pem == PUBLIC_KEY

    @staticmethod
    def sign(public_key_pem: bytes, payload: bytes) -> bytes:
        return hashlib.sha256(public_key_pem + payload).digest()

    def verify(self, public_key_pem: bytes, payload: bytes, signature: bytes) -> bool:
        return signature == self.sign(public_key_pem, payload)


class FakeDecisions:
    def __init__(self) -> None:
        member = {
            "artifact_id": "candidate-1",
            "kind": "CANDIDATE",
            "material": {"candidate": "one"},
            "material_sha256": "a" * 64,
            "recorded_at": T1,
            "recorded_by": "c3-evidence-author",
            "ledger_hash": "b" * 64,
        }
        self.snapshot_value = SimpleNamespace(
            c3_run_id="c3-run-1",
            qualification_run_id="qualification-1",
            certificate_id="certificate-1",
            qualification_head_hash="c" * 64,
            candidate_set_digest=sha256_digest([member]),
            evaluation_set_digest=sha256_digest([]),
            latest_evidence_at=T1,
            candidates=(member,),
            evaluations=(),
        )
        self.record = SimpleNamespace(
            decision_id="decision-1",
            c3_run_id="c3-run-1",
            payload_sha256="d" * 64,
            verdict="C3_CANDIDATE_SELECTED",
            selected_candidate_artifact_id="candidate-1",
            qualification_head_hash="c" * 64,
            candidate_set_digest=self.snapshot_value.candidate_set_digest,
            evaluation_set_digest=self.snapshot_value.evaluation_set_digest,
            decision_maker_identity="c3-decision-maker",
            admitted_by="c3-decision-admitter",
        )

    def get_decision(self, decision_id: str):
        if decision_id != self.record.decision_id:
            raise KeyError(decision_id)
        return self.record

    def verify_decision(self, decision_id: str):
        return SimpleNamespace(decision_id=decision_id, defects=(), ok=True)

    def snapshot(self, c3_run_id: str):
        if c3_run_id != self.snapshot_value.c3_run_id:
            raise KeyError(c3_run_id)
        return self.snapshot_value


class FakeAdoption:
    def __init__(self) -> None:
        self.record = SimpleNamespace(
            adoption_id="adoption-1",
            c3_run_id="c3-run-1",
            c3_decision_id="decision-1",
            candidate_artifact_id="candidate-1",
            status="C3_ADOPTION_AUTHORIZED_NOT_EXECUTED",
            rollback_plan_sha256="e" * 64,
            authorized_by="adoption-authorizer",
        )

    def get_adoption(self, adoption_id: str):
        if adoption_id != self.record.adoption_id:
            raise KeyError(adoption_id)
        return self.record

    def verify_adoption(self, adoption_id: str):
        return SimpleNamespace(adoption_id=adoption_id, defects=(), ok=True)


class BaselineGraph:
    def __init__(self, root: Path) -> None:
        self.database = Database(root / "baseline.sqlite3")
        self.database.initialize()
        self.ledger = EventLedger(self.database)
        self.trust = TrustPlane(self.database, self.ledger)
        self.verifier = RecordingSignatureVerifier()
        self.continuity = ContinuityService(self.database, self.ledger, self.trust, self.verifier)
        self.decisions = FakeDecisions()
        self.adoption = FakeAdoption()
        self.database.connection.execute("CREATE TABLE c3_decisions (decision_id TEXT PRIMARY KEY, c3_run_id TEXT NOT NULL)")
        self.database.connection.execute("INSERT INTO c3_decisions VALUES ('decision-1', 'c3-run-1')")
        self.database.connection.execute("CREATE TABLE c3_adoptions (adoption_id TEXT PRIMARY KEY, c3_run_id TEXT NOT NULL)")
        self.database.connection.execute("INSERT INTO c3_adoptions VALUES ('adoption-1', 'c3-run-1')")
        self.service = C4ArchitectureService(self.database, self.ledger, self.trust, self.continuity, self.decisions, self.adoption)

    def close(self) -> None:
        self.database.close()

    def accept_root(self) -> None:
        self.trust.add_rule(PolicyRule("root-rule", PolicyEffect.ALLOW, "root-operator", "continuity.trust-root.accept", "continuity:trust-root:baseline-root"), actor="policy-owner", occurred_at=T0)
        decision = self.trust.authorize(AuthorizationRequest("root-operator", "continuity.trust-root.accept", "continuity:trust-root:baseline-root"), now=T1)
        self.continuity.accept_trust_root("baseline-root", PUBLIC_KEY, decision_id=decision.decision_id, actor="root-operator", occurred_at=T1)

    def payload(self, **overrides: object) -> bytes:
        snapshot = self.service.snapshot("c3-run-1")
        value: dict[str, object] = {
            "baseline_id": "baseline-1", "architecture_id": "starcom-v3.2-baseline", "architecture_version": "3.2.0",
            "c3_run_id": snapshot.c3_run_id, "qualification_run_id": snapshot.qualification_run_id, "certificate_id": snapshot.certificate_id,
            "c3_decision_id": snapshot.c3_decision_id, "c3_decision_verdict": snapshot.c3_decision_verdict, "decision_payload_sha256": snapshot.decision_payload_sha256,
            "selected_candidate_artifact_id": snapshot.selected_candidate_artifact_id, "qualification_head_hash": snapshot.qualification_head_hash,
            "candidate_set_digest": snapshot.candidate_set_digest, "evaluation_set_digest": snapshot.evaluation_set_digest, "c3_snapshot_digest": snapshot.snapshot_digest,
            "adoption_id": snapshot.adoption_id, "adoption_status": snapshot.adoption_status, "adoption_rollback_plan_sha256": snapshot.adoption_rollback_plan_sha256,
            "execution_id": snapshot.execution_id, "execution_status": snapshot.execution_status, "execution_receipt_sha256": snapshot.execution_receipt_sha256, "rollback_receipt_sha256": snapshot.rollback_receipt_sha256,
            "architecture_document_sha256": "1" * 64, "component_manifest_sha256": "2" * 64, "decision_log_sha256": "3" * 64, "threat_model_sha256": "4" * 64,
            "deployment_topology_sha256": "5" * 64, "data_flow_sha256": "6" * 64, "rollback_strategy_sha256": "7" * 64,
            "architect_identity": "independent-architect", "architect_environment": "isolated-architecture-worktree", "reviewer_identity": "independent-reviewer", "reviewer_environment": "isolated-review-worktree",
            "designed_at_utc": T2, "independence_basis": {"excluded_identities": list(snapshot.material_identities), "statement": "fresh isolated architecture and review authorities"},
            "external_runtime_integration_status": "NOT_PROVEN", "gate_effect": "C4_ARCHITECTURE_BASELINE_ADMITTED_NO_DEPLOYMENT",
        }
        value.update(overrides)
        return canonical_json(value).encode("utf-8")


class C4ArchitectureBaselineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.graph = BaselineGraph(Path(self.tempdir.name))

    def tearDown(self) -> None:
        self.graph.close()
        self.tempdir.cleanup()

    def test_snapshot_is_deterministic_and_binds_selected_adoption(self) -> None:
        first = self.graph.service.snapshot("c3-run-1")
        self.assertEqual(first, self.graph.service.snapshot("c3-run-1"))
        self.assertEqual(first.adoption_id, "adoption-1")
        self.assertIsNone(first.execution_id)
        self.assertEqual(first.external_runtime_integration_status, "NOT_PROVEN")

    def test_default_deny_root_and_exact_admission_are_enforced(self) -> None:
        payload = self.graph.payload()
        with self.assertRaises(IntegrityError):
            self.graph.service.admit_baseline("c3-run-1", "baseline-root", payload, self.graph.verifier.sign(PUBLIC_KEY, payload), actor="admitter", occurred_at=T3)
        self.graph.accept_root()
        signature = self.graph.verifier.sign(PUBLIC_KEY, payload)
        first = self.graph.service.admit_baseline("c3-run-1", "baseline-root", payload, signature, actor="admitter", occurred_at=T3)
        second = self.graph.service.admit_baseline("c3-run-1", "baseline-root", payload, signature, actor="admitter", occurred_at="2026-08-20T12:04:00.000000Z")
        self.assertEqual(first, second)
        self.assertEqual(first.gate_effect, "C4_ARCHITECTURE_BASELINE_ADMITTED_NO_DEPLOYMENT")
        self.assertTrue(self.graph.service.verify_baseline("baseline-1").ok)

    def test_payload_signature_and_contract_tampering_fail_closed(self) -> None:
        self.graph.accept_root()
        payload = self.graph.payload()
        with self.assertRaises(IntegrityError):
            self.graph.service.admit_baseline("c3-run-1", "baseline-root", payload + b" ", self.graph.verifier.sign(PUBLIC_KEY, payload), actor="admitter", occurred_at=T3)
        with self.assertRaises(ValidationError):
            self.graph.service.admit_baseline("c3-run-1", "baseline-root", self.graph.payload(gate_effect="WRONG"), b"x", actor="admitter", occurred_at=T3)
        with self.assertRaises(ValidationError):
            self.graph.service.admit_baseline("c3-run-1", "baseline-root", self.graph.payload(extra="unexpected"), b"x", actor="admitter", occurred_at=T3)

    def test_selected_c3_candidate_without_adoption_is_rejected(self) -> None:
        self.graph.database.connection.execute("DROP TABLE c3_adoptions")
        with self.assertRaises(StateTransitionError):
            self.graph.service.snapshot("c3-run-1")

    def test_immutable_rows_and_memberships_detect_tampering(self) -> None:
        self.graph.accept_root()
        payload = self.graph.payload()
        signature = self.graph.verifier.sign(PUBLIC_KEY, payload)
        baseline = self.graph.service.admit_baseline("c3-run-1", "baseline-root", payload, signature, actor="admitter", occurred_at=T3)
        with self.assertRaises(sqlite3.IntegrityError):
            self.graph.database.connection.execute("UPDATE c4_architecture_baselines SET architecture_id = 'tampered' WHERE baseline_id = ?", (baseline.baseline_id,))
        self.graph.database.connection.execute("DROP TRIGGER c4_architecture_baseline_members_no_update")
        self.graph.database.connection.execute("UPDATE c4_architecture_baseline_members SET material_json = '{}' WHERE baseline_id = ?", (baseline.baseline_id,))
        verification = self.graph.service.verify_baseline(baseline.baseline_id)
        self.assertFalse(verification.ok)
        self.assertTrue(any("BASELINE_MEMBER" in defect for defect in verification.defects))

    def test_independent_identities_and_chronology_are_required(self) -> None:
        self.graph.accept_root()
        identity_payload = self.graph.payload(reviewer_identity="c3-decision-maker")
        with self.assertRaises(StateTransitionError):
            self.graph.service.admit_baseline("c3-run-1", "baseline-root", identity_payload, self.graph.verifier.sign(PUBLIC_KEY, identity_payload), actor="admitter", occurred_at=T3)
        chronology_payload = self.graph.payload(designed_at_utc=T0)
        with self.assertRaises(StateTransitionError):
            self.graph.service.admit_baseline("c3-run-1", "baseline-root", chronology_payload, self.graph.verifier.sign(PUBLIC_KEY, chronology_payload), actor="admitter", occurred_at=T3)


if __name__ == "__main__":
    unittest.main()
