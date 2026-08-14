from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import test_adoption_execution as execution_fixture

from starcom.adoption_execution import (
    C3AdoptionExecutionService,
    C3AdoptionExecutionStatus,
    C3AdoptionExecutionWorker,
)
from starcom.cli import Runtime
from starcom.durable import DurableOutbox, EffectStatus
from starcom.executor_registry import C3ExecutorRegistry, C3ExecutorState
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule


W0 = "2026-08-14T14:00:00.000000Z"
W1 = "2026-08-14T14:01:00.000000Z"
W2 = "2026-08-14T14:02:00.000000Z"
W3 = "2026-08-14T14:03:00.000000Z"
W4 = "2026-08-14T14:04:00.000000Z"
W5 = "2026-08-14T14:05:00.000000Z"
W6 = "2026-08-14T14:06:00.000000Z"
W7 = "2026-08-14T14:07:00.000000Z"
W8 = "2026-08-14T14:08:00.000000Z"
W9 = "2026-08-14T14:20:00.000000Z"
W10 = "2026-08-14T14:21:00.000000Z"
IMPLEMENTATION_VERSION = "1.0.0"
IMPLEMENTATION_DIGEST = "5" * 64
ARTIFACT_DIGEST = "6" * 64
REPORT_DIGEST = "7" * 64
TEST_SUITE_DIGEST = "8" * 64


class AttestedExecutor(execution_fixture.DeterministicExecutor):
    executor_id = "attested-fake-executor"
    implementation_version = IMPLEMENTATION_VERSION
    implementation_digest = IMPLEMENTATION_DIGEST


class WrongVersionExecutor(AttestedExecutor):
    implementation_version = "2.0.0"


class WrongDigestExecutor(AttestedExecutor):
    implementation_digest = "9" * 64


class CountingRegistry:
    def __init__(self, delegate: C3ExecutorRegistry) -> None:
        self.delegate = delegate
        self.attestation_calls = 0

    def attest(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        self.attestation_calls += 1
        return self.delegate.attest(*args, **kwargs)


class C3ExecutorWorkerAttestationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture = execution_fixture.C3AdoptionExecutionTests
        fixture.setUpClass()
        cls.execution_fixture = fixture
        cls.execution_base_db = fixture.execution_base_db
        cls.fixture_root = tempfile.TemporaryDirectory()
        cls.private_key = Path(cls.fixture_root.name) / "worker-qualifier-private.pem"
        cls.public_key = Path(cls.fixture_root.name) / "worker-qualifier-public.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(cls.private_key),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(cls.private_key),
                "-pubout",
                "-out",
                str(cls.public_key),
            ],
            check=True,
            capture_output=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_root.cleanup()
        cls.execution_fixture.tearDownClass()

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.db_path = self.root / "starcom.sqlite3"
        execution_fixture.copy_database(self.execution_base_db, self.db_path)
        self.runtime = Runtime.open(self.db_path)
        self.outbox = DurableOutbox(self.runtime.database, self.runtime.ledger)
        self.service = C3AdoptionExecutionService(
            self.runtime.database,
            self.runtime.ledger,
            self.runtime.trust,
            self.runtime.continuity,
            self.runtime.adoption,
            self.outbox,
        )
        self.registry = C3ExecutorRegistry(
            self.runtime.database,
            self.runtime.ledger,
            self.runtime.trust,
            self.runtime.continuity,
        )

    def tearDown(self) -> None:
        self.runtime.close()
        self.tempdir.cleanup()

    @staticmethod
    def descriptor() -> dict[str, object]:
        return {
            "executor_id": AttestedExecutor.executor_id,
            "implementation_name": "Attested deterministic fake executor",
            "implementation_version": IMPLEMENTATION_VERSION,
            "implementation_digest": IMPLEMENTATION_DIGEST,
            "artifact_digest": ARTIFACT_DIGEST,
            "entrypoint": "tests.test_executor_worker_attestation:AttestedExecutor",
            "supported_sandbox_profiles": ["starcom-c3-default-deny-v1"],
            "network_mode": "DENY",
            "capabilities": ["apply", "rollback"],
        }

    def authorize(
        self,
        preparation,
        *,
        subject: str,
        rule_id: str,
        now: str,
    ):
        self.runtime.trust.add_rule(
            PolicyRule(
                rule_id,
                PolicyEffect.ALLOW,
                subject,
                preparation.action,
                preparation.resource,
            ),
            actor="owner",
            occurred_at=W0,
        )
        decision = self.runtime.trust.authorize(
            AuthorizationRequest(
                subject=subject,
                action=preparation.action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=preparation.context,
            ),
            now=now,
        )
        self.assertTrue(decision.allowed)
        return decision

    def qualification_payload(self, descriptor_digest: str) -> bytes:
        value = {
            "qualification_id": "qualification-worker-executor",
            "executor_id": AttestedExecutor.executor_id,
            "descriptor_digest": descriptor_digest,
            "report_digest": REPORT_DIGEST,
            "test_suite_digest": TEST_SUITE_DIGEST,
            "reviewer_identity": "independent-worker-reviewer",
            "reviewer_environment": "isolated-worker-review-vm",
            "independence_basis": "separate process, key and workspace",
            "sandbox_profiles_tested": ["starcom-c3-default-deny-v1"],
            "network_mode_tested": "DENY",
            "verdict": "QUALIFIED",
            "qualified_at": W3,
            "gate_effect": "QUALIFIED_DISABLED_NO_ENABLEMENT",
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )

    def sign(self, payload: bytes) -> bytes:
        payload_path = self.root / "worker-qualification.json"
        signature_path = self.root / "worker-qualification.sig"
        payload_path.write_bytes(payload)
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(self.private_key),
                "-rawin",
                "-in",
                str(payload_path),
                "-out",
                str(signature_path),
            ],
            check=True,
            capture_output=True,
        )
        return signature_path.read_bytes()

    def register_executor(self, state: C3ExecutorState) -> None:
        descriptor = self.descriptor()
        registration = self.registry.prepare_registration(descriptor)
        registration_decision = self.authorize(
            registration,
            subject="registry-operator",
            rule_id="allow-worker-register",
            now=W1,
        )
        self.registry.register(
            descriptor,
            authorization_decision_id=registration_decision.decision_id,
            actor="registry-operator",
            occurred_at=W1,
        )
        if state is C3ExecutorState.REGISTERED_DISABLED:
            return

        public_key = self.public_key.read_bytes()
        root_preparation = self.registry.prepare_qualifier_root(
            "worker-qualifier-key",
            public_key,
        )
        root_decision = self.authorize(
            root_preparation,
            subject="root-owner",
            rule_id="allow-worker-root",
            now=W2,
        )
        self.registry.accept_qualifier_root(
            "worker-qualifier-key",
            public_key,
            authorization_decision_id=root_decision.decision_id,
            actor="root-owner",
            occurred_at=W2,
        )

        registered = self.registry.get_descriptor(AttestedExecutor.executor_id)
        payload = self.qualification_payload(registered.descriptor_digest)
        signature = self.sign(payload)
        qualification = self.registry.prepare_qualification(
            AttestedExecutor.executor_id,
            "worker-qualifier-key",
            payload,
            signature,
        )
        qualification_decision = self.authorize(
            qualification,
            subject="qualification-admitter",
            rule_id="allow-worker-qualification",
            now=W3,
        )
        self.registry.qualify(
            AttestedExecutor.executor_id,
            "worker-qualifier-key",
            payload,
            signature,
            authorization_decision_id=qualification_decision.decision_id,
            actor="qualification-admitter",
            occurred_at=W3,
        )
        if state is C3ExecutorState.QUALIFIED_DISABLED:
            return

        enable = self.registry.prepare_enable(AttestedExecutor.executor_id)
        enable_decision = self.authorize(
            enable,
            subject="executor-enabler",
            rule_id="allow-worker-enable",
            now=W4,
        )
        self.registry.enable(
            AttestedExecutor.executor_id,
            authorization_decision_id=enable_decision.decision_id,
            actor="executor-enabler",
            occurred_at=W4,
        )
        if state is C3ExecutorState.ENABLED:
            return

        self.revoke_executor(
            reason="pre-request revocation fixture",
            rule_id="allow-worker-revoke-pre-request",
            decision_time=W5,
            occurred_at=W5,
        )

    def revoke_executor(
        self,
        *,
        reason: str,
        rule_id: str,
        decision_time: str,
        occurred_at: str,
    ) -> None:
        preparation = self.registry.prepare_revoke(
            AttestedExecutor.executor_id,
            reason=reason,
        )
        decision = self.authorize(
            preparation,
            subject="security-owner",
            rule_id=rule_id,
            now=decision_time,
        )
        self.registry.revoke(
            AttestedExecutor.executor_id,
            reason=reason,
            authorization_decision_id=decision.decision_id,
            actor="security-owner",
            occurred_at=occurred_at,
        )

    def request(
        self,
        *,
        execution_id: str,
        executor_id: str = AttestedExecutor.executor_id,
        plan: dict[str, object] | None = None,
    ):
        execution_plan = plan or execution_fixture.C3AdoptionExecutionTests.execution_plan()
        preparation = self.service.prepare(
            execution_id,
            adoption_id="adoption-cli",
            executor_id=executor_id,
            execution_plan=execution_plan,
        )
        decision = self.authorize(
            preparation,
            subject="execution-operator",
            rule_id=f"allow-{execution_id}",
            now=W5,
        )
        return self.service.request_execution(
            execution_id,
            adoption_id="adoption-cli",
            executor_id=executor_id,
            execution_plan=execution_plan,
            authorization_decision_id=decision.decision_id,
            actor="execution-operator",
            occurred_at=W6,
        )

    def process(
        self,
        requested,
        executor,
        *,
        registry=None,
        worker_id: str = "worker-attested",
        now: str = W8,
    ):
        worker = C3AdoptionExecutionWorker(
            self.service,
            self.outbox,
            registry or self.registry,
            executor,
        )
        return worker.process_next(worker_id=worker_id, now=now, lease_seconds=30)

    def assert_no_effect_failure(self, completed, executor) -> None:
        self.assertIsNotNone(completed)
        assert completed is not None
        self.assertEqual(
            completed.status,
            C3AdoptionExecutionStatus.FAILED_NO_EFFECT,
        )
        self.assertFalse(completed.effect_started)
        self.assertEqual(executor.validate_calls, 0)
        self.assertEqual(executor.execute_calls, 0)
        self.assertEqual(executor.rollback_calls, 0)
        self.assertEqual(executor.actual_effect_count, 0)
        self.assertEqual(
            self.outbox.get(completed.outbox_effect_id).status,
            EffectStatus.SUCCEEDED,
        )

    def test_missing_executor_registration_fails_before_effect(self) -> None:
        requested = self.request(execution_id="worker-missing")
        executor = AttestedExecutor("success")
        self.assert_no_effect_failure(self.process(requested, executor), executor)

    def test_registered_disabled_executor_fails_before_effect(self) -> None:
        self.register_executor(C3ExecutorState.REGISTERED_DISABLED)
        requested = self.request(execution_id="worker-registered")
        executor = AttestedExecutor("success")
        self.assert_no_effect_failure(self.process(requested, executor), executor)

    def test_qualified_disabled_executor_fails_before_effect(self) -> None:
        self.register_executor(C3ExecutorState.QUALIFIED_DISABLED)
        requested = self.request(execution_id="worker-qualified")
        executor = AttestedExecutor("success")
        self.assert_no_effect_failure(self.process(requested, executor), executor)

    def test_enabled_executor_can_execute(self) -> None:
        self.register_executor(C3ExecutorState.ENABLED)
        requested = self.request(execution_id="worker-enabled")
        executor = AttestedExecutor("success")

        completed = self.process(requested, executor)

        self.assertIsNotNone(completed)
        assert completed is not None
        self.assertEqual(completed.status, C3AdoptionExecutionStatus.SUCCEEDED)
        self.assertEqual(executor.actual_effect_count, 1)
        self.assertGreaterEqual(executor.validate_calls, 1)
        self.assertTrue(self.service.verify_execution(requested.execution_id).ok)

    def test_revoked_after_admission_blocks_effect(self) -> None:
        self.register_executor(C3ExecutorState.ENABLED)
        requested = self.request(execution_id="worker-revoked-after-admission")
        self.revoke_executor(
            reason="revoked after execution admission",
            rule_id="allow-worker-revoke-after-admission",
            decision_time=W7,
            occurred_at=W7,
        )
        executor = AttestedExecutor("success")
        self.assert_no_effect_failure(self.process(requested, executor), executor)

    def test_wrong_implementation_version_fails_before_effect(self) -> None:
        self.register_executor(C3ExecutorState.ENABLED)
        requested = self.request(execution_id="worker-wrong-version")
        executor = WrongVersionExecutor("success")
        self.assert_no_effect_failure(self.process(requested, executor), executor)

    def test_wrong_implementation_digest_fails_before_effect(self) -> None:
        self.register_executor(C3ExecutorState.ENABLED)
        requested = self.request(execution_id="worker-wrong-digest")
        executor = WrongDigestExecutor("success")
        self.assert_no_effect_failure(self.process(requested, executor), executor)

    def test_unsupported_sandbox_fails_before_effect(self) -> None:
        self.register_executor(C3ExecutorState.ENABLED)
        plan = dict(execution_fixture.C3AdoptionExecutionTests.execution_plan())
        plan["sandbox_profile"] = "unqualified-sandbox"
        requested = self.request(
            execution_id="worker-wrong-sandbox",
            plan=plan,
        )
        executor = AttestedExecutor("success")
        self.assert_no_effect_failure(self.process(requested, executor), executor)

    def test_network_request_under_deny_mode_fails_before_effect(self) -> None:
        self.register_executor(C3ExecutorState.ENABLED)
        plan = dict(execution_fixture.C3AdoptionExecutionTests.execution_plan())
        plan["requires_network"] = True
        plan["network_allowlist"] = ["api.example.invalid"]
        requested = self.request(
            execution_id="worker-network-denied",
            plan=plan,
        )
        executor = AttestedExecutor("success")
        self.assert_no_effect_failure(self.process(requested, executor), executor)

    def test_dirty_registry_fails_before_effect(self) -> None:
        self.register_executor(C3ExecutorState.ENABLED)
        requested = self.request(execution_id="worker-dirty-registry")
        self.runtime.database.connection.execute(
            "DROP TRIGGER c3_executor_descriptors_no_update"
        )
        self.runtime.database.connection.execute(
            """
            UPDATE c3_executor_descriptors SET implementation_digest = ?
            WHERE executor_id = ?
            """,
            ("0" * 64, AttestedExecutor.executor_id),
        )
        executor = AttestedExecutor("success")
        self.assert_no_effect_failure(self.process(requested, executor), executor)

    def test_crash_recovery_re_attests_and_preserves_single_effect(self) -> None:
        self.register_executor(C3ExecutorState.ENABLED)
        requested = self.request(execution_id="worker-crash-retry")
        executor = AttestedExecutor("crash-once")
        counting_registry = CountingRegistry(self.registry)
        worker = C3AdoptionExecutionWorker(
            self.service,
            self.outbox,
            counting_registry,
            executor,
        )

        with self.assertRaises(KeyboardInterrupt):
            worker.process_next(worker_id="worker-crashed", now=W8, lease_seconds=30)
        self.assertEqual(counting_registry.attestation_calls, 1)
        self.assertEqual(executor.actual_effect_count, 1)
        self.assertEqual(self.outbox.recover_expired(now=W9), 1)

        completed = worker.process_next(
            worker_id="worker-retry",
            now=W9,
            lease_seconds=30,
        )

        self.assertIsNotNone(completed)
        assert completed is not None
        self.assertEqual(completed.status, C3AdoptionExecutionStatus.SUCCEEDED)
        self.assertEqual(counting_registry.attestation_calls, 2)
        self.assertEqual(executor.actual_effect_count, 1)
        self.assertGreaterEqual(executor.execute_calls, 2)

    def test_post_crash_revocation_triggers_compensating_rollback(self) -> None:
        self.register_executor(C3ExecutorState.ENABLED)
        requested = self.request(execution_id="worker-crash-revoked")
        executor = AttestedExecutor("crash-once")
        worker = C3AdoptionExecutionWorker(
            self.service,
            self.outbox,
            self.registry,
            executor,
        )

        with self.assertRaises(KeyboardInterrupt):
            worker.process_next(worker_id="worker-crashed", now=W8, lease_seconds=30)
        self.assertEqual(executor.actual_effect_count, 1)
        self.revoke_executor(
            reason="revoked after uncertain post-effect crash",
            rule_id="allow-worker-revoke-after-crash",
            decision_time=W9,
            occurred_at=W9,
        )
        self.assertEqual(self.outbox.recover_expired(now=W10), 1)

        completed = worker.process_next(
            worker_id="worker-recovery-after-revoke",
            now=W10,
            lease_seconds=30,
        )

        self.assertIsNotNone(completed)
        assert completed is not None
        self.assertEqual(
            completed.status,
            C3AdoptionExecutionStatus.FAILED_ROLLED_BACK,
        )
        self.assertTrue(completed.effect_started)
        self.assertEqual(executor.actual_effect_count, 1)
        self.assertEqual(executor.actual_rollback_count, 1)
        self.assertTrue(self.service.verify_execution(requested.execution_id).ok)


if __name__ == "__main__":
    unittest.main()
