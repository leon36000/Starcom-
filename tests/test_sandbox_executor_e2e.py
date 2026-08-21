from __future__ import annotations

import hashlib
import json
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
from starcom.canonical import canonical_json, sha256_digest
from starcom.cli import Runtime
from starcom.durable import DurableOutbox, EffectStatus
from starcom.executor_registry import C3ExecutorRegistry, C3ExecutorState
from starcom.sandbox_executor import SandboxComponentExecutor
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule


T0 = "2026-08-14T16:00:00.000000Z"
T1 = "2026-08-14T16:01:00.000000Z"
T2 = "2026-08-14T16:02:00.000000Z"
T3 = "2026-08-14T16:03:00.000000Z"
T4 = "2026-08-14T16:04:00.000000Z"
T5 = "2026-08-14T16:05:00.000000Z"
T6 = "2026-08-14T16:06:00.000000Z"
T7 = "2026-08-14T16:07:00.000000Z"
REPORT_DIGEST = "3" * 64
TEST_SUITE_DIGEST = "4" * 64


class RegisteredSandboxExecutorE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture = execution_fixture.C3AdoptionExecutionTests
        fixture.setUpClass()
        cls.execution_fixture = fixture
        cls.execution_base_db = fixture.execution_base_db
        cls.fixture_root = tempfile.TemporaryDirectory()
        cls.private_key = Path(cls.fixture_root.name) / "qualifier-private.pem"
        cls.public_key = Path(cls.fixture_root.name) / "qualifier-public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(cls.private_key)],
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
        self.source = self.root / "component-source"
        self.sandbox = self.root / "sandbox"
        self.source.mkdir()
        self.component_content = b"sandbox-component-v1\n"
        (self.source / "component.py").write_bytes(self.component_content)
        manifest = {
            "component": "sandbox-demo",
            "version": "1.0.0",
            "files": [
                {
                    "path": "component.py",
                    "digest": hashlib.sha256(self.component_content).hexdigest(),
                    "size": len(self.component_content),
                }
            ],
        }
        (self.source / "component_manifest.json").write_text(
            canonical_json(manifest), encoding="utf-8"
        )
        self.executor = SandboxComponentExecutor(
            self.sandbox,
            source_root=self.source,
        )

    def tearDown(self) -> None:
        self.runtime.close()
        self.tempdir.cleanup()

    @staticmethod
    def _profile() -> str:
        return "starcom-local-component-v1"

    def authorize(self, preparation, *, subject: str, rule_id: str, now: str):  # type: ignore[no-untyped-def]
        self.runtime.trust.add_rule(
            PolicyRule(
                rule_id,
                PolicyEffect.ALLOW,
                subject,
                preparation.action,
                preparation.resource,
            ),
            actor="owner",
            occurred_at=T0,
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
        self.assertTrue(decision.allowed, decision)
        return decision

    def qualification_payload(self, descriptor_digest: str) -> bytes:
        return canonical_json(
            {
                "qualification_id": "qualification-sandbox-component",
                "executor_id": self.executor.executor_id,
                "descriptor_digest": descriptor_digest,
                "report_digest": REPORT_DIGEST,
                "test_suite_digest": TEST_SUITE_DIGEST,
                "reviewer_identity": "independent-sandbox-reviewer",
                "reviewer_environment": "isolated-sandbox-review-vm",
                "independence_basis": "separate process, key and workspace",
                "sandbox_profiles_tested": [self._profile()],
                "network_mode_tested": "DENY",
                "verdict": "QUALIFIED",
                "qualified_at": T3,
                "gate_effect": "QUALIFIED_DISABLED_NO_ENABLEMENT",
            }
        ).encode("utf-8")

    def sign(self, payload: bytes) -> bytes:
        payload_path = self.root / "qualification.json"
        signature_path = self.root / "qualification.sig"
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

    def establish_registry(self, state: C3ExecutorState) -> None:
        descriptor = self.executor.descriptor()
        registration = self.registry.prepare_registration(descriptor)
        registration_decision = self.authorize(
            registration,
            subject="registry-operator",
            rule_id="allow-sandbox-register",
            now=T1,
        )
        self.registry.register(
            descriptor,
            authorization_decision_id=registration_decision.decision_id,
            actor="registry-operator",
            occurred_at=T1,
        )
        if state is C3ExecutorState.REGISTERED_DISABLED:
            return

        public_key = self.public_key.read_bytes()
        root_preparation = self.registry.prepare_qualifier_root(
            "sandbox-qualifier-key", public_key
        )
        root_decision = self.authorize(
            root_preparation,
            subject="root-owner",
            rule_id="allow-sandbox-root",
            now=T2,
        )
        self.registry.accept_qualifier_root(
            "sandbox-qualifier-key",
            public_key,
            authorization_decision_id=root_decision.decision_id,
            actor="root-owner",
            occurred_at=T2,
        )
        registered = self.registry.get_descriptor(self.executor.executor_id)
        payload = self.qualification_payload(registered.descriptor_digest)
        signature = self.sign(payload)
        qualification = self.registry.prepare_qualification(
            self.executor.executor_id,
            "sandbox-qualifier-key",
            payload,
            signature,
        )
        qualification_decision = self.authorize(
            qualification,
            subject="qualification-admitter",
            rule_id="allow-sandbox-qualification",
            now=T3,
        )
        self.registry.qualify(
            self.executor.executor_id,
            "sandbox-qualifier-key",
            payload,
            signature,
            authorization_decision_id=qualification_decision.decision_id,
            actor="qualification-admitter",
            occurred_at=T3,
        )
        if state is C3ExecutorState.QUALIFIED_DISABLED:
            return

        enable = self.registry.prepare_enable(self.executor.executor_id)
        enable_decision = self.authorize(
            enable,
            subject="executor-enabler",
            rule_id="allow-sandbox-enable",
            now=T4,
        )
        self.registry.enable(
            self.executor.executor_id,
            authorization_decision_id=enable_decision.decision_id,
            actor="executor-enabler",
            occurred_at=T4,
        )
        if state is C3ExecutorState.ENABLED:
            return

        revoke = self.registry.prepare_revoke(
            self.executor.executor_id,
            reason="sandbox executor revoked before worker claim",
        )
        revoke_decision = self.authorize(
            revoke,
            subject="security-owner",
            rule_id="allow-sandbox-revoke",
            now=T5,
        )
        self.registry.revoke(
            self.executor.executor_id,
            reason="sandbox executor revoked before worker claim",
            authorization_decision_id=revoke_decision.decision_id,
            actor="security-owner",
            occurred_at=T5,
        )

    def plan(self, *, source_digest: str | None = None) -> dict[str, object]:
        return {
            "component_ref": self.source.as_uri(),
            "source_digest": source_digest or self.executor.source_digest,
            "target_environment": "sandbox:e2e",
            "sandbox_profile": self._profile(),
            "preconditions": ["enabled registry attestation", "closed local manifest"],
            "postconditions": ["current pointer matches release", "ledger verifies"],
            "requires_network": False,
            "network_allowlist": [],
            "requires_separate_rollback_authorization": False,
        }

    def request(self, execution_id: str, plan: dict[str, object] | None = None):  # type: ignore[no-untyped-def]
        execution_plan = plan or self.plan()
        preparation = self.service.prepare(
            execution_id,
            adoption_id="adoption-cli",
            executor_id=self.executor.executor_id,
            execution_plan=execution_plan,
        )
        decision = self.authorize(
            preparation,
            subject="execution-operator",
            rule_id=f"allow-sandbox-execution-{execution_id}",
            now=T6,
        )
        return self.service.request_execution(
            execution_id,
            adoption_id="adoption-cli",
            executor_id=self.executor.executor_id,
            execution_plan=execution_plan,
            authorization_decision_id=decision.decision_id,
            actor="execution-operator",
            occurred_at=T6,
        )

    def process(self, requested, executor=None):  # type: ignore[no-untyped-def]
        worker = C3AdoptionExecutionWorker(
            self.service,
            self.outbox,
            self.registry,
            executor or self.executor,
        )
        return worker.process_next(worker_id="sandbox-worker", now=T7, lease_seconds=30)

    def assert_no_effect(self, completed) -> None:  # type: ignore[no-untyped-def]
        self.assertIsNotNone(completed)
        assert completed is not None
        self.assertEqual(completed.status, C3AdoptionExecutionStatus.FAILED_NO_EFFECT)
        self.assertFalse(completed.effect_started)
        self.assertFalse((self.sandbox / "current.json").exists())
        releases = self.sandbox / "releases"
        self.assertFalse(releases.exists() and any(releases.iterdir()))
        self.assertTrue(self.service.verify_execution(completed.execution_id).ok)
        self.assertEqual(
            self.outbox.get(completed.outbox_effect_id).status,
            EffectStatus.SUCCEEDED,
        )

    def test_enabled_registered_executor_installs_through_worker_without_external_proof(self) -> None:
        self.establish_registry(C3ExecutorState.ENABLED)
        requested = self.request("sandbox-e2e-success")

        completed = self.process(requested)

        self.assertIsNotNone(completed)
        assert completed is not None
        self.assertEqual(completed.status, C3AdoptionExecutionStatus.SUCCEEDED)
        self.assertTrue(self.registry.verify(self.executor.executor_id).ok)
        self.assertTrue(self.service.verify_execution(requested.execution_id).ok)
        self.assertEqual(
            self.outbox.get(requested.outbox_effect_id).status,
            EffectStatus.SUCCEEDED,
        )
        pointer = json.loads((self.sandbox / "current.json").read_text(encoding="utf-8"))
        installed = self.sandbox / "releases" / pointer["release_digest"] / "component.py"
        self.assertEqual(installed.read_bytes(), self.component_content)
        self.assertEqual(
            self.runtime.external_evidence.snapshot(as_of=T7),
            {
                "LIVE_CENSUS_CERTIFICATION": "NOT_PROVEN",
                "EXTERNAL_RUNTIME_INTEGRATION": "NOT_PROVEN",
                "COMPONENT_ADOPTION": "NOT_PROVEN",
                "REAL_DEPLOYMENT": "NOT_PROVEN",
            },
        )
        self.assertEqual(
            self.runtime.database.connection.execute(
                "SELECT COUNT(*) FROM external_evidence_records"
            ).fetchone()[0],
            0,
        )

    def test_registered_only_executor_has_no_effect(self) -> None:
        self.establish_registry(C3ExecutorState.REGISTERED_DISABLED)
        requested = self.request("sandbox-e2e-registered-only")

        self.assert_no_effect(self.process(requested))

    def test_revoked_executor_has_no_effect(self) -> None:
        self.establish_registry(C3ExecutorState.REVOKED)
        requested = self.request("sandbox-e2e-revoked")

        self.assert_no_effect(self.process(requested))

    def test_wrong_source_digest_has_no_effect(self) -> None:
        self.establish_registry(C3ExecutorState.ENABLED)
        requested = self.request("sandbox-e2e-wrong-digest", self.plan(source_digest="0" * 64))

        self.assert_no_effect(self.process(requested))

    def test_wrong_implementation_version_has_no_effect(self) -> None:
        self.establish_registry(C3ExecutorState.ENABLED)
        requested = self.request("sandbox-e2e-wrong-version")
        wrong_version = SandboxComponentExecutor(self.sandbox, source_root=self.source)
        wrong_version.implementation_version = "9.9.9"

        self.assert_no_effect(self.process(requested, wrong_version))


if __name__ == "__main__":
    unittest.main()
