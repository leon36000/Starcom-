from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

import test_executor_worker_attestation as worker_fixture

from starcom.adoption_execution import C3AdoptionExecutionStatus
from starcom.canonical import canonical_json
from starcom.external_evidence import EXTERNAL_EVIDENCE_KINDS
from starcom.executor_registry import C3ExecutorState
from starcom.sandbox_executor import SandboxComponentExecutor


class RegisteredSandboxExecutorE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        worker_fixture.C3ExecutorWorkerAttestationTests.setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        worker_fixture.C3ExecutorWorkerAttestationTests.tearDownClass()

    def setUp(self) -> None:
        base = worker_fixture.C3ExecutorWorkerAttestationTests
        fixture_type = type(
            "SandboxWorkerFixture",
            (base,),
            {
                "registry_executor_id": SandboxComponentExecutor.executor_id,
                "registry_implementation_version": SandboxComponentExecutor.implementation_version,
                "registry_implementation_digest": SandboxComponentExecutor.implementation_digest,
                "registry_artifact_digest": SandboxComponentExecutor.implementation_digest,
                "registry_entrypoint": "starcom.sandbox_executor:SandboxComponentExecutor",
                "registry_profile": "starcom-local-component-v1",
            },
        )
        self.fixture = fixture_type("runTest")
        self.fixture.setUp()
        root = self.fixture.root
        self.source = root / "component-source"
        self.sandbox = root / "sandbox"
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
        self.fixture.tearDown()

    def plan(self, *, source_digest: str | None = None) -> dict[str, object]:
        return {
            "component_ref": self.source.as_uri(),
            "source_digest": source_digest or self.executor.source_digest,
            "target_environment": "sandbox:e2e",
            "sandbox_profile": "starcom-local-component-v1",
            "preconditions": ["enabled registry attestation", "closed local manifest"],
            "postconditions": ["current pointer matches release", "ledger verifies"],
            "requires_network": False,
            "network_allowlist": [],
            "requires_separate_rollback_authorization": False,
        }

    def assert_no_effect(self, completed) -> None:  # type: ignore[no-untyped-def]
        self.assertIsNotNone(completed)
        assert completed is not None
        self.assertEqual(completed.status, C3AdoptionExecutionStatus.FAILED_NO_EFFECT)
        self.assertFalse(completed.effect_started)
        self.assertFalse((self.sandbox / "current.json").exists())
        releases = self.sandbox / "releases"
        self.assertFalse(releases.exists() and any(releases.iterdir()))
        self.assertTrue(self.fixture.service.verify_execution(completed.execution_id).ok)

    def test_enabled_registered_executor_installs_through_worker_without_external_proof(self) -> None:
        self.fixture.register_executor(C3ExecutorState.ENABLED)
        requested = self.fixture.request(
            execution_id="sandbox-e2e-success",
            executor_id=self.executor.executor_id,
            plan=self.plan(),
        )
        completed = self.fixture.process(requested, self.executor)

        self.assertIsNotNone(completed)
        assert completed is not None
        self.assertEqual(completed.status, C3AdoptionExecutionStatus.SUCCEEDED)
        self.assertTrue(self.fixture.registry.verify(self.executor.executor_id).ok)
        self.assertTrue(self.fixture.service.verify_execution(requested.execution_id).ok)
        pointer = json.loads((self.sandbox / "current.json").read_text(encoding="utf-8"))
        installed = self.sandbox / "releases" / pointer["release_digest"] / "component.py"
        self.assertEqual(installed.read_bytes(), self.component_content)
        self.assertEqual(
            self.fixture.runtime.external_evidence.snapshot(
                as_of="2026-08-14T14:07:00.000000Z"
            ),
            {kind: "NOT_PROVEN" for kind in EXTERNAL_EVIDENCE_KINDS},
        )
        self.assertEqual(
            self.fixture.runtime.database.connection.execute(
                "SELECT COUNT(*) FROM external_evidence_records"
            ).fetchone()[0],
            0,
        )

    def test_registered_only_executor_has_no_effect(self) -> None:
        self.fixture.register_executor(C3ExecutorState.REGISTERED_DISABLED)
        request = self.fixture.request(
            execution_id="sandbox-e2e-registered",
            executor_id=self.executor.executor_id,
            plan=self.plan(),
        )
        self.assert_no_effect(self.fixture.process(request, self.executor))

    def test_revoked_executor_has_no_effect(self) -> None:
        self.fixture.register_executor(C3ExecutorState.REVOKED)
        request = self.fixture.request(
            execution_id="sandbox-e2e-revoked",
            executor_id=self.executor.executor_id,
            plan=self.plan(),
        )
        self.assert_no_effect(self.fixture.process(request, self.executor))

    def test_wrong_source_digest_has_no_effect(self) -> None:
        self.fixture.register_executor(C3ExecutorState.ENABLED)
        request = self.fixture.request(
            execution_id="sandbox-e2e-digest",
            executor_id=self.executor.executor_id,
            plan=self.plan(source_digest="0" * 64),
        )
        self.assert_no_effect(self.fixture.process(request, self.executor))

    def test_wrong_implementation_version_has_no_effect(self) -> None:
        self.fixture.register_executor(C3ExecutorState.ENABLED)
        wrong_version = SandboxComponentExecutor(self.sandbox, source_root=self.source)
        wrong_version.implementation_version = "9.9.9"
        request = self.fixture.request(
            execution_id="sandbox-e2e-version",
            executor_id=self.executor.executor_id,
            plan=self.plan(),
        )
        self.assert_no_effect(self.fixture.process(request, wrong_version))


if __name__ == "__main__":
    unittest.main()
