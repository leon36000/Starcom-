from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from types import SimpleNamespace

from starcom.canonical import canonical_json
from starcom.continuity import ContinuityService
from starcom.db import Database
from starcom.errors import ConflictError, IntegrityError, StateTransitionError, ValidationError
from starcom.ledger import EventLedger
from starcom.red_team import C6RedTeamService
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule, TrustPlane


T0 = "2026-08-20T12:00:00.000000Z"
T1 = "2026-08-20T12:01:00.000000Z"
T2 = "2026-08-20T12:02:00.000000Z"
T3 = "2026-08-20T12:03:00.000000Z"
T4 = "2026-08-20T12:04:00.000000Z"
T5 = "2026-08-20T12:05:00.000000Z"
T6 = "2026-08-20T12:06:00.000000Z"
PUBLIC_KEY = b"c6-red-team-public-key"


class RecordingSignatureVerifier:
    def validate_public_key(self, public_key_pem: bytes) -> bool:
        return public_key_pem == PUBLIC_KEY

    @staticmethod
    def sign(public_key_pem: bytes, payload: bytes) -> bytes:
        return hashlib.sha256(public_key_pem + payload).digest()

    def verify(self, public_key_pem: bytes, payload: bytes, signature: bytes) -> bool:
        return signature == self.sign(public_key_pem, payload)


class FakeExecutionPlan:
    def __init__(self, database: Database, ledger: EventLedger) -> None:
        self.database = database
        self.ledger = ledger
        self.clean = True
        c5_payload = canonical_json(
            {"plan_id": "plan-1", "architecture_id": "starcom-v3.2-baseline"}
        ).encode("utf-8")
        receipt = ledger.append(
            "continuity:c5:execution-plan:plan-1",
            "C5_EXECUTION_PLAN_ADMITTED",
            {
                "plan_id": "plan-1",
                "architecture_id": "starcom-v3.2-baseline",
                "payload_sha256": hashlib.sha256(c5_payload).hexdigest(),
            },
            actor="c5-admitter",
            event_id="c5-event-1",
            occurred_at=T4,
        )
        self.plan = SimpleNamespace(
            plan_id="plan-1",
            architecture_id="starcom-v3.2-baseline",
            plan_version="1.0.0",
            architecture_version="3.2.0",
            payload=c5_payload,
            payload_sha256=hashlib.sha256(c5_payload).hexdigest(),
            admitted_at=T4,
            admitted_by="c5-admitter",
            planner_identity="c5-planner",
            reviewer_identity="c5-reviewer",
            ledger_event_id=receipt.event_id,
            ledger_hash=receipt.record_hash,
            independence_basis={
                "excluded_identities": ["c3-actor", "c4-actor"],
                "statement": "C5 actors are independent from upstream material actors",
            },
        )
        self.work_items = (
            {
                "work_item_id": "item-1",
                "phase": "assessment",
                "title": "Freeze the C5 plan",
                "owner_role": "c5-owner",
                "dependencies": [],
            },
        )
        self.release_gates = (
            {
                "gate_id": "gate-1",
                "title": "C5 proof gate",
                "required_work_item_ids": ["item-1"],
            },
        )

    def get_plan(self, plan_id: str):
        if plan_id != self.plan.plan_id:
            raise KeyError(plan_id)
        return self.plan

    def verify_plan(self, plan_id: str):
        if not self.clean:
            return SimpleNamespace(plan_id=plan_id, defects=("PLAN_TAMPERED",), ok=False)
        return SimpleNamespace(plan_id=plan_id, defects=(), ok=True)

    def get_work_items(self, plan_id: str):
        self.get_plan(plan_id)
        return self.work_items

    def get_release_gates(self, plan_id: str):
        self.get_plan(plan_id)
        return self.release_gates

    def snapshot(self, plan_id: str):
        self.get_plan(plan_id)
        return SimpleNamespace(snapshot_digest="c5-upstream-snapshot")


class RedTeamGraph:
    def __init__(self, root: Path) -> None:
        self.database = Database(root / "red-team.sqlite3")
        self.database.initialize()
        self.ledger = EventLedger(self.database)
        self.trust = TrustPlane(self.database, self.ledger)
        self.verifier = RecordingSignatureVerifier()
        self.continuity = ContinuityService(
            self.database, self.ledger, self.trust, self.verifier
        )
        self.execution_plan = FakeExecutionPlan(self.database, self.ledger)
        self.service = C6RedTeamService(
            self.database,
            self.ledger,
            self.trust,
            self.continuity,
            self.execution_plan,
            signature_verifier=self.verifier,
        )

    def close(self) -> None:
        self.database.close()

    def accept_root(self) -> None:
        self.trust.add_rule(
            PolicyRule(
                "c6-root-rule",
                PolicyEffect.ALLOW,
                "c6-root-operator",
                "continuity.trust-root.accept",
                "continuity:trust-root:c6-root",
            ),
            actor="policy-owner",
            occurred_at=T0,
        )
        decision = self.trust.authorize(
            AuthorizationRequest(
                "c6-root-operator",
                "continuity.trust-root.accept",
                "continuity:trust-root:c6-root",
            ),
            now=T1,
        )
        self.continuity.accept_trust_root(
            "c6-root",
            PUBLIC_KEY,
            decision_id=decision.decision_id,
            actor="c6-root-operator",
            occurred_at=T1,
        )

    @staticmethod
    def attack(
        attack_case_id: str = "attack-1",
        *,
        outcome: str = "PASS",
        category: str = "INTEGRITY",
    ) -> dict[str, object]:
        return {
            "attack_case_id": attack_case_id,
            "category": category,
            "target": "c5-plan-authority",
            "method": "mutate signed C5 material",
            "invariant_expected": "C5 mutation must make C6 stale",
            "evidence_digest": "1" * 64,
            "outcome": outcome,
        }

    @staticmethod
    def finding(
        finding_id: str = "finding-1",
        *,
        attack_case_id: str = "attack-1",
        severity: str = "LOW",
        status: str = "OPEN",
        remediation_work_item_id: str | None = None,
    ) -> dict[str, object]:
        return {
            "finding_id": finding_id,
            "attack_case_id": attack_case_id,
            "severity": severity,
            "title": "Observed red-team result",
            "description_digest": "2" * 64,
            "evidence_digest": "3" * 64,
            "status": status,
            "remediation_work_item_id": remediation_work_item_id,
        }

    def payload(self, **overrides: object) -> bytes:
        snapshot = self.service.snapshot("plan-1")
        value: dict[str, object] = {
            "assessment_id": "assessment-1",
            "plan_id": "plan-1",
            "architecture_id": "starcom-v3.2-baseline",
            "plan_payload_sha256": snapshot.plan_payload_sha256,
            "c5_snapshot_digest": snapshot.snapshot_digest,
            "threat_model_digest": "4" * 64,
            "attack_cases": [self.attack()],
            "findings": [],
            "verdict": "C6_PASS_NO_BLOCKING_FINDINGS",
            "remediation_required": False,
            "release_recommendation": "PROCEED_TO_C7_FINAL_PACK",
            "assessor_identity": "independent-assessor",
            "assessor_environment": "c6-red-team-isolated",
            "adjudicator_identity": "independent-adjudicator",
            "adjudicator_environment": "c6-adjudication-isolated",
            "assessed_at_utc": T5,
            "independence_basis": {
                "excluded_identities": list(snapshot.material_identities),
                "statement": "C6 actors are independent from all C5 and C4 material actors",
            },
            "gate_effect": "C6_RED_TEAM_ASSESSMENT_ADMITTED_NO_RELEASE",
        }
        value.update(overrides)
        return canonical_json(value).encode("utf-8")


class C6RedTeamTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.graph = RedTeamGraph(Path(self.tempdir.name))

    def tearDown(self) -> None:
        self.graph.close()
        self.tempdir.cleanup()

    def test_public_contract_is_deterministic(self) -> None:
        first = self.graph.service.snapshot("plan-1")
        second = self.graph.service.snapshot("plan-1")
        self.assertEqual(first, second)
        preparation = self.graph.service.prepare("assessment-1", "plan-1")
        self.assertEqual(preparation.assessment_id, "assessment-1")
        self.assertEqual(preparation.plan_id, "plan-1")
        self.assertEqual(preparation.c5_snapshot_digest, first.snapshot_digest)
        self.assertEqual(preparation.gate_effect, "C6_RED_TEAM_ASSESSMENT_ADMITTED_NO_RELEASE")

    def test_strict_contract_rejects_malformed_payloads(self) -> None:
        malformed = [
            b'{"assessment_id":"a","assessment_id":"b"}',
            b"\xff",
            self.graph.payload(plan_payload_sha256="A" * 64),
            self.graph.payload(gate_effect="C6_RED_TEAM_ASSESSMENT_ADMITTED"),
            self.graph.payload(attack_cases=[]),
            self.graph.payload(
                attack_cases=[
                    {
                        "attack_case_id": "attack-1",
                        "category": "INTEGRITY",
                    }
                ]
            ),
            self.graph.payload(
                findings=[self.graph.finding(attack_case_id="missing-attack")]
            ),
            self.graph.payload(
                findings=[
                    self.graph.finding(
                        severity="CRITICAL",
                        remediation_work_item_id="missing-item",
                    )
                ]
            ),
            self.graph.payload(verdict="C6_FAIL_REMEDIATION_REQUIRED"),
            self.graph.payload(remediation_required=True),
            self.graph.payload(release_recommendation="PROCEED_TO_C7_FINAL_PACK"),
        ]
        for payload in malformed:
            with self.subTest(payload=payload):
                with self.assertRaises(
                    (ValidationError, StateTransitionError, IntegrityError)
                ):
                    self.graph.service.admit_assessment(
                        "plan-1",
                        "missing-root",
                        payload,
                        b"bad-signature",
                        actor="c6-admitter",
                        occurred_at=T6,
                    )
        count = self.graph.database.connection.execute(
            "SELECT COUNT(*) AS count FROM c6_red_team_assessments"
        ).fetchone()["count"]
        self.assertEqual(count, 0)

    def test_c5_binding_chronology_independence_and_verdict_fail_closed(self) -> None:
        self.graph.execution_plan.clean = False
        with self.assertRaises(IntegrityError):
            self.graph.service.snapshot("plan-1")
        self.graph.execution_plan.clean = True
        original_payload_sha256 = self.graph.execution_plan.plan.payload_sha256
        self.graph.execution_plan.plan.payload_sha256 = "f" * 64
        with self.assertRaises(IntegrityError):
            self.graph.service.snapshot("plan-1")
        self.graph.execution_plan.plan.payload_sha256 = original_payload_sha256
        original_ledger_hash = self.graph.execution_plan.plan.ledger_hash
        self.graph.execution_plan.plan.ledger_hash = "e" * 64
        with self.assertRaises(IntegrityError):
            self.graph.service.snapshot("plan-1")
        self.graph.execution_plan.plan.ledger_hash = original_ledger_hash
        for overrides in (
            {"assessor_identity": "c5-planner"},
            {"adjudicator_identity": "c5-reviewer"},
            {"assessed_at_utc": T3},
            {
                "attack_cases": [self.graph.attack(outcome="FAIL")],
                "verdict": "C6_PASS_NO_BLOCKING_FINDINGS",
            },
            {
                "findings": [self.graph.finding(severity="HIGH")],
                "verdict": "C6_PASS_NO_BLOCKING_FINDINGS",
            },
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises((ValidationError, StateTransitionError, IntegrityError)):
                    self.graph.service.admit_assessment(
                        "plan-1",
                        "missing-root",
                        self.graph.payload(**overrides),
                        b"bad-signature",
                        actor="c6-admitter",
                        occurred_at=T6,
                    )

    def test_fail_and_blocked_verdicts_are_derived_and_block_c7(self) -> None:
        self.graph.accept_root()
        failed_payload = self.graph.payload(
            attack_cases=[self.graph.attack(outcome="FAIL")],
            verdict="C6_FAIL_REMEDIATION_REQUIRED",
            remediation_required=True,
            release_recommendation="BLOCK_C7",
        )
        failed = self.graph.service.admit_assessment(
            "plan-1",
            "c6-root",
            failed_payload,
            self.graph.verifier.sign(PUBLIC_KEY, failed_payload),
            actor="c6-admitter",
            occurred_at=T6,
        )
        self.assertEqual(failed.verdict, "C6_FAIL_REMEDIATION_REQUIRED")
        self.assertEqual(failed.release_recommendation, "BLOCK_C7")
        self.assertTrue(self.graph.service.verify_assessment(failed.assessment_id).ok)

        blocked_tempdir = tempfile.TemporaryDirectory()
        blocked_graph = RedTeamGraph(Path(blocked_tempdir.name))
        try:
            blocked_graph.accept_root()
            blocked_payload = blocked_graph.payload(
                attack_cases=[blocked_graph.attack(outcome="BLOCKED")],
                verdict="C6_BLOCKED_INSUFFICIENT_EVIDENCE",
                remediation_required=False,
                release_recommendation="BLOCK_C7",
            )
            blocked = blocked_graph.service.admit_assessment(
                "plan-1",
                "c6-root",
                blocked_payload,
                blocked_graph.verifier.sign(PUBLIC_KEY, blocked_payload),
                actor="c6-admitter",
                occurred_at=T6,
            )
            self.assertEqual(blocked.verdict, "C6_BLOCKED_INSUFFICIENT_EVIDENCE")
            self.assertEqual(blocked.release_recommendation, "BLOCK_C7")
            self.assertTrue(blocked_graph.service.verify_assessment(blocked.assessment_id).ok)
        finally:
            blocked_graph.close()
            blocked_tempdir.cleanup()

    def test_exact_admission_replay_and_conflict(self) -> None:
        payload = self.graph.payload()
        signature = self.graph.verifier.sign(PUBLIC_KEY, payload)
        with self.assertRaises(IntegrityError):
            self.graph.service.admit_assessment(
                "plan-1",
                "c6-root",
                payload,
                signature,
                actor="c6-admitter",
                occurred_at=T6,
            )
        self.graph.accept_root()
        first = self.graph.service.admit_assessment(
            "plan-1",
            "c6-root",
            payload,
            signature,
            actor="c6-admitter",
            occurred_at=T6,
        )
        self.assertEqual(first.verdict, "C6_PASS_NO_BLOCKING_FINDINGS")
        self.assertEqual(first.release_recommendation, "PROCEED_TO_C7_FINAL_PACK")
        self.assertTrue(self.graph.service.verify_assessment(first.assessment_id).ok)
        replay = self.graph.service.admit_assessment(
            "plan-1",
            "c6-root",
            payload,
            signature,
            actor="c6-admitter",
            occurred_at="2026-08-20T12:07:00.000000Z",
        )
        self.assertEqual(replay, first)
        self.assertEqual(
            len(self.graph.ledger.read_stream("continuity:c6:red-team:assessment-1")),
            1,
        )
        conflict_payload = self.graph.payload(assessment_id="assessment-2")
        with self.assertRaises(ConflictError):
            self.graph.service.admit_assessment(
                "plan-1",
                "c6-root",
                conflict_payload,
                self.graph.verifier.sign(PUBLIC_KEY, conflict_payload),
                actor="c6-admitter",
                occurred_at=T6,
            )
        with self.assertRaises(IntegrityError):
            self.graph.service.admit_assessment(
                "plan-1",
                "c6-root",
                payload + b" ",
                signature,
                actor="c6-admitter",
                occurred_at=T6,
            )

    def test_verifier_detects_assessment_tampering_and_c5_staleness(self) -> None:
        self.graph.accept_root()
        payload = self.graph.payload()
        plan = self.graph.service.admit_assessment(
            "plan-1",
            "c6-root",
            payload,
            self.graph.verifier.sign(PUBLIC_KEY, payload),
            actor="c6-admitter",
            occurred_at=T6,
        )
        self.assertEqual(len(self.graph.service.get_attack_cases(plan.assessment_id)), 1)
        self.assertEqual(len(self.graph.service.get_findings(plan.assessment_id)), 0)
        with self.assertRaises(sqlite3.IntegrityError):
            self.graph.database.connection.execute(
                "UPDATE c6_red_team_assessments SET verdict = 'C6_FAIL_REMEDIATION_REQUIRED' WHERE assessment_id = ?",
                (plan.assessment_id,),
            )
        self.graph.database.connection.execute(
            "DROP TRIGGER c6_red_team_attack_cases_no_update"
        )
        self.graph.database.connection.execute(
            "UPDATE c6_red_team_attack_cases SET material_json = '{}' WHERE assessment_id = ?",
            (plan.assessment_id,),
        )
        verification = self.graph.service.verify_assessment(plan.assessment_id)
        self.assertFalse(verification.ok)
        self.assertTrue(any("ASSESSMENT_ATTACK_CASES" in defect for defect in verification.defects))

        self.graph.database.connection.execute("DROP TRIGGER c6_red_team_assessments_no_update")
        self.graph.database.connection.execute(
            "UPDATE c6_red_team_assessments SET payload_sha256 = ? WHERE assessment_id = ?",
            ("f" * 64, plan.assessment_id),
        )
        verification = self.graph.service.verify_assessment(plan.assessment_id)
        self.assertFalse(verification.ok)
        self.assertIn("ASSESSMENT_PAYLOAD_DIGEST_MISMATCH", verification.defects)

        self.graph.database.connection.execute("DROP TRIGGER ledger_events_no_update")
        self.graph.database.connection.execute(
            "UPDATE ledger_events SET kind = 'TAMPERED' WHERE event_id = ?",
            (plan.ledger_event_id,),
        )
        verification = self.graph.service.verify_assessment(plan.assessment_id)
        self.assertFalse(verification.ok)
        self.assertIn("ASSESSMENT_LEDGER_KIND_MISMATCH", verification.defects)

        self.graph.execution_plan.clean = False
        verification = self.graph.service.verify_assessment(plan.assessment_id)
        self.assertFalse(verification.ok)
        self.assertIn("ASSESSMENT_C5_SNAPSHOT_INVALID", verification.defects)


class C6RuntimeWiringTests(unittest.TestCase):
    def test_runtime_exposes_one_shared_c6_graph_without_operational_surface(self) -> None:
        from starcom.cli import Runtime

        runtime = Runtime.open(":memory:")
        try:
            self.assertIs(runtime.red_team, runtime.c6_red_team)
            self.assertIs(runtime.red_team.database, runtime.database)
            self.assertIs(runtime.red_team.ledger, runtime.ledger)
            self.assertIs(runtime.red_team.continuity, runtime.continuity)
            self.assertIs(runtime.red_team.execution_plan, runtime.execution_plan)
            forbidden = {
                "start",
                "run",
                "execute",
                "schedule",
                "dispatch",
                "repair",
                "release",
                "deploy",
                "promote",
                "publish",
            }
            self.assertTrue(forbidden.isdisjoint(set(dir(runtime.red_team))))
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
