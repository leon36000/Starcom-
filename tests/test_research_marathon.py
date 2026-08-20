from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

from starcom.canonical import canonical_json
from starcom.durable import DurableOutbox, EffectStatus
from starcom.errors import ConflictError, StateTransitionError, ValidationError
from starcom.research import ReceiptOutcome, ResearchCampaign
from starcom.research_marathon import (
    MarathonState,
    ResearchMarathonService,
)
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule
from test_final_pack import C7_PUBLIC_KEY, FinalPackGraph, T8
from test_execution_plan import RecordingSignatureVerifier


T9 = "2026-08-20T12:09:00.000000Z"
T10 = "2026-08-20T12:10:00.000000Z"
T11 = "2026-08-20T12:11:00.000000Z"
T12 = "2026-08-20T12:12:00.000000Z"
T13 = "2026-08-20T12:13:00.000000Z"
T14 = "2026-08-20T12:14:00.000000Z"
MARATHON_PUBLIC_KEY = b"12a-research-marathon-public-key"
MARATHON_ROOT = "marathon-root"


class MarathonSignatureVerifier(RecordingSignatureVerifier):
    def validate_public_key(self, public_key_pem: bytes) -> bool:
        return public_key_pem in {C7_PUBLIC_KEY, MARATHON_PUBLIC_KEY}


def make_profiles() -> list[dict[str, object]]:
    return [
        {
            "profile_id": f"profile-{index:03d}",
            "source_id": f"source-{index:03d}",
            "source_kind": "catalogue",
            "source_ref": f"opaque-source-{index:03d}",
            "request_template": {"query": "starcom", "profile": index},
            "request_policy_digest": hashlib.sha256(
                f"policy-{index:03d}".encode("utf-8")
            ).hexdigest(),
            "enabled": True,
        }
        for index in range(48)
    ]


def make_partitions() -> list[dict[str, object]]:
    partitions: list[dict[str, object]] = []
    for index in range(240):
        profile_index = index // 5
        partitions.append(
            {
                "partition_id": f"partition-{index:03d}",
                "profile_id": f"profile-{profile_index:03d}",
                "partition_key": f"page-{index % 5:02d}",
                "request": {"query": "starcom", "page": index},
            }
        )
    return partitions


class MarathonFixture:
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.graph = FinalPackGraph(Path(self.tempdir.name))
        self.graph.accept_root()
        c7_payload = self.graph.payload()
        self.pack = self.graph.service.admit_pack(
            "assessment-1",
            "c7-root",
            c7_payload,
            self.graph.verifier.sign(C7_PUBLIC_KEY, c7_payload),
            actor="c7-admitter",
            occurred_at=T8,
        )
        self.research = ResearchCampaign(self.graph.database, self.graph.ledger)
        self.research.create(
            campaign_id="campaign-1",
            name="12A empty campaign",
            actor="campaign-owner",
            occurred_at=T8,
        )
        self.outbox = DurableOutbox(self.graph.database, self.graph.ledger)
        self.marathon_verifier = MarathonSignatureVerifier()
        self.graph.continuity.signature_verifier = self.marathon_verifier
        self.accept_marathon_root()
        self.service = ResearchMarathonService(
            self.graph.database,
            self.graph.ledger,
            self.graph.trust,
            self.graph.continuity,
            self.graph.service,
            self.research,
            self.outbox,
            signature_verifier=self.marathon_verifier,
        )

    def tearDown(self) -> None:
        self.graph.close()
        self.tempdir.cleanup()

    def accept_marathon_root(self) -> None:
        self.graph.trust.add_rule(
            PolicyRule(
                "marathon-root-rule",
                PolicyEffect.ALLOW,
                "marathon-root-operator",
                "continuity.trust-root.accept",
                f"continuity:trust-root:{MARATHON_ROOT}",
            ),
            actor="policy-owner",
            occurred_at=T8,
        )
        decision = self.graph.trust.authorize(
            AuthorizationRequest(
                "marathon-root-operator",
                "continuity.trust-root.accept",
                f"continuity:trust-root:{MARATHON_ROOT}",
            ),
            now=T8,
        )
        self.graph.continuity.accept_trust_root(
            MARATHON_ROOT,
            MARATHON_PUBLIC_KEY,
            decision_id=decision.decision_id,
            actor="marathon-root-operator",
            occurred_at=T8,
        )

    def payload(self, **overrides: object) -> bytes:
        value: dict[str, object] = {
            "marathon_id": "marathon-1",
            "plan_version": "1.0.0",
            "c7_pack_id": self.pack.pack_id,
            "campaign_id": "campaign-1",
            "source_profiles": make_profiles(),
            "partitions": make_partitions(),
            "minimum_identity_target": 800,
            "max_parallelism": 8,
            "request_timeout_seconds": 30,
            "retry_policy": {
                "max_attempts": 3,
                "retry_delay_seconds": 5,
                "backoff_multiplier": 2,
            },
            "coordinator_identity": "coordinator-12a",
            "coordinator_environment": "self-hosted-isolated",
            "reviewer_identity": "reviewer-12a",
            "reviewer_environment": "independent-review-isolated",
            "planned_at_utc": T9,
            "independence_basis": {
                "excluded_identities": list(
                    self.graph.service.snapshot("assessment-1").material_identities
                ),
                "statement": "coordinator and reviewer are independent from C7 material actors",
            },
            "state": MarathonState.PLANNED_NOT_STARTED.value,
            "gate_effect": "12A_LIVE_RESEARCH_MARATHON_PLANNED_NO_NETWORK",
        }
        value.update(overrides)
        return canonical_json(value).encode("utf-8")

    def admit(self, payload: bytes | None = None):
        payload = payload or self.payload()
        return self.service.admit_plan(
            payload,
            self.marathon_verifier.sign(MARATHON_PUBLIC_KEY, payload),
            key_id=MARATHON_ROOT,
            actor="marathon-admitter",
            occurred_at=T9,
        )

    def allow_start(self, *, actor: str = "operator-12a", decision_time: str = T10):
        plan = self.service.get_plan("marathon-1")
        context = self.service.start_context(plan.marathon_id)
        self.graph.trust.issue_grant(
            grant_id=f"grant-{plan.marathon_id}",
            subject=actor,
            action="research.marathon.start",
            resource=f"research:marathon:{plan.marathon_id}",
            mission_id=None,
            expires_at="2026-08-20T13:00:00.000000Z",
            single_use=True,
            actor="grant-owner",
            occurred_at=T9,
        )
        return self.graph.trust.authorize(
            AuthorizationRequest(
                actor,
                "research.marathon.start",
                f"research:marathon:{plan.marathon_id}",
                context=context,
            ),
            now=decision_time,
        )


class ResearchMarathonContractTests(MarathonFixture, unittest.TestCase):
    def test_prepare_is_deterministic_and_admission_persists_closed_memberships(self) -> None:
        first = self.service.prepare(self.payload())
        second = self.service.prepare(self.payload())
        self.assertEqual(first, second)
        plan = self.admit()
        self.assertEqual(plan.state, MarathonState.PLANNED_NOT_STARTED)
        self.assertEqual(plan.profile_count, 48)
        self.assertEqual(plan.partition_count, 240)
        self.assertEqual(
            self.graph.database.connection.execute(
                "SELECT COUNT(*) AS count FROM research_marathon_profiles"
            ).fetchone()["count"],
            48,
        )
        self.assertEqual(
            self.graph.database.connection.execute(
                "SELECT COUNT(*) AS count FROM research_marathon_partitions"
            ).fetchone()["count"],
            240,
        )
        self.assertTrue(self.service.verify("marathon-1").ok)

    def test_closed_contract_rejects_short_duplicate_and_noncanonical_plans(self) -> None:
        with self.assertRaises(ValidationError):
            self.service.prepare(self.payload(source_profiles=make_profiles()[:47]))
        with self.assertRaises(ValidationError):
            self.service.prepare(self.payload(partitions=make_partitions()[:239]))
        duplicate_profiles = make_profiles()
        duplicate_profiles[-1] = dict(duplicate_profiles[-2])
        with self.assertRaises(ValidationError):
            self.service.prepare(self.payload(source_profiles=duplicate_profiles))
        with self.assertRaises(ValidationError):
            self.service.prepare(self.payload() + b" ")

    def test_admission_rejects_coordinator_or_reviewer_reuse_of_c7_actor(self) -> None:
        payload = self.payload(coordinator_identity="independent-packager")
        with self.assertRaises(StateTransitionError):
            self.admit(payload)


class ResearchMarathonStartTests(MarathonFixture, unittest.TestCase):
    def test_start_is_default_deny_and_atomically_enqueues_one_effect_per_partition(self) -> None:
        self.admit()
        denied = self.graph.trust.authorize(
            AuthorizationRequest(
                "operator-12a",
                "research.marathon.start",
                "research:marathon:marathon-1",
                context=self.service.start_context("marathon-1"),
            ),
            now=T10,
        )
        self.assertFalse(denied.allowed)
        with self.assertRaises(StateTransitionError):
            self.service.start(
                "marathon-1",
                decision_id=denied.decision_id,
                actor="operator-12a",
                occurred_at=T10,
            )
        decision = self.allow_start()
        started = self.service.start(
            "marathon-1",
            decision_id=decision.decision_id,
            actor="operator-12a",
            occurred_at=T11,
        )
        self.assertEqual(started.state, MarathonState.ACTIVE)
        count = self.graph.database.connection.execute(
            "SELECT COUNT(*) AS count FROM durable_effects"
        ).fetchone()["count"]
        self.assertEqual(count, 240)
        self.assertEqual(
            self.graph.database.connection.execute(
                "SELECT COUNT(DISTINCT topic) AS count FROM durable_effects"
            ).fetchone()["count"],
            1,
        )
        self.assertTrue(
            all(
                row["status"] == EffectStatus.PENDING.value
                for row in self.graph.database.connection.execute(
                    "SELECT status FROM durable_effects"
                ).fetchall()
            )
        )
        verification = self.service.verify("marathon-1")
        self.assertTrue(verification.ok, verification.defects)
        with self.assertRaises(ConflictError):
            self.service.start(
                "marathon-1",
                decision_id=decision.decision_id,
                actor="operator-12a",
                occurred_at=T12,
            )


class ResearchMarathonWorkerTests(MarathonFixture, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.admit()
        decision = self.allow_start()
        self.service.start(
            "marathon-1",
            decision_id=decision.decision_id,
            actor="operator-12a",
            occurred_at=T11,
        )

    def test_begin_persists_attempt_before_completion_and_rejects_missing_receipt(self) -> None:
        lease = self.service.claim(
            "marathon-1", worker_id="worker-a", now=T12, lease_seconds=180
        )[0]
        attempt = self.service.begin_partition_attempt(
            "marathon-1", lease, actor="worker-a", occurred_at=T13
        )
        events = self.graph.ledger.read_stream("research:campaign:campaign-1")
        kinds = [event.kind for event in events]
        self.assertEqual(kinds[-1], "RESEARCH_ATTEMPT_STARTED")
        self.assertTrue(attempt.request_key.startswith("marathon-1:partition-"))
        with self.assertRaises(StateTransitionError):
            self.service.complete_partition(
                "marathon-1",
                lease,
                actor="worker-a",
                occurred_at=T14,
            )

    def test_success_evidence_is_required_before_outbox_success(self) -> None:
        lease = self.service.claim(
            "marathon-1", worker_id="worker-a", now=T12, lease_seconds=180
        )[0]
        attempt = self.service.begin_partition_attempt(
            "marathon-1", lease, actor="worker-a", occurred_at=T13
        )
        snapshot = "a" * 64
        self.research.record_receipt(
            attempt.attempt_id,
            receipt_id="receipt-partition-000",
            outcome=ReceiptOutcome.SUCCESS,
            status_code=200,
            snapshot_digest=snapshot,
            metadata={"test_worker": True},
            actor="test-worker",
            occurred_at=T14,
        )
        self.research.record_observation(
            attempt.attempt_id,
            observation_id="observation-partition-000",
            snapshot_digest=snapshot,
            content_digest="b" * 64,
            data={"identities": ["identity-1"]},
            actor="test-worker",
            occurred_at=T14,
        )
        self.research.checkpoint_cursor(
            "campaign-1",
            wave=1,
            cursor_key="partition-000",
            value={"next": None},
            attempt_id=attempt.attempt_id,
            actor="test-worker",
            occurred_at=T14,
        )
        completion = self.service.complete_partition(
            "marathon-1", lease, actor="worker-a", occurred_at=T14
        )
        self.assertEqual(len(completion.result_digest), 64)
        record = self.outbox.get(lease.effect_id)
        self.assertEqual(record.status, EffectStatus.SUCCEEDED)
        self.assertEqual(self.service.progress("marathon-1").completed_count, 1)
        verification = self.service.verify("marathon-1")
        self.assertTrue(verification.ok, verification.defects)

    def test_close_pending_certification_refuses_partial_marathon(self) -> None:
        with self.assertRaises(StateTransitionError):
            self.service.close_pending_certification(
                "marathon-1", actor="operator-12a", occurred_at=T14
            )

    def test_expired_lease_recovery_changes_request_key_and_verifier_detects_tamper(self) -> None:
        first = self.service.claim(
            "marathon-1", worker_id="worker-a", now=T12, lease_seconds=1
        )[0]
        self.assertEqual(self.outbox.recover_expired(now=T13), 1)
        second = next(
            lease
            for lease in self.service.claim(
                "marathon-1", worker_id="worker-b", now=T13, limit=240
            )
            if lease.effect_id == first.effect_id
        )
        second_attempt = self.service.begin_partition_attempt(
            "marathon-1", second, actor="worker-b", occurred_at=T13
        )
        self.assertIn(":attempt:2", second_attempt.request_key)
        self.graph.database.connection.execute(
            "DROP TRIGGER research_marathon_profiles_no_update"
        )
        self.graph.database.connection.execute(
            "UPDATE research_marathon_profiles SET material_json = '{}' WHERE marathon_id = ? AND ordinal = 0",
            ("marathon-1",),
        )
        verification = self.service.verify("marathon-1")
        self.assertFalse(verification.ok)
        self.assertTrue(any("PROFILE" in defect for defect in verification.defects))


class ResearchMarathonRuntimeTests(unittest.TestCase):
    def test_runtime_exposes_the_shared_marathon_service(self) -> None:
        from starcom.cli import Runtime

        runtime = Runtime.open(":memory:")
        try:
            self.assertIs(runtime.research_marathon.database, runtime.database)
            self.assertIs(runtime.research_marathon.research, runtime.research)
            self.assertIs(runtime.research_marathon.outbox, runtime.outbox)
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
