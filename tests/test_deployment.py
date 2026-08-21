from __future__ import annotations

import inspect
from pathlib import Path
import subprocess
import tempfile
import unittest

from starcom.cli import Runtime
from starcom.deployment import (
    DeploymentAssignmentStatus,
    DeploymentBundleStatus,
    DeploymentFabricService,
    DeploymentNodeStatus,
    DeploymentPlatform,
)
from starcom.errors import (
    AuthorizationError,
    ConflictError,
    IntegrityError,
    ValidationError,
)
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule


T0 = "2026-08-21T12:00:00.000000Z"
T1 = "2026-08-21T12:00:01.000000Z"
T2 = "2026-08-21T12:00:02.000000Z"
T3 = "2026-08-21T12:00:03.000000Z"
PACKAGE_DIGEST = "a" * 64
ATTESTATION_DIGEST = "b" * 64


class DeploymentTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.runtime = Runtime.open(self.root / "deployment.sqlite3")
        self.service = DeploymentFabricService(
            self.runtime.database,
            self.runtime.ledger,
            self.runtime.trust,
            self.runtime.continuity,
        )
        self.private_key = self.root / "node-private.pem"
        self.public_key = self.root / "node-public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.private_key)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(self.private_key), "-pubout", "-out", str(self.public_key)],
            check=True,
            capture_output=True,
        )
        self.runtime.trust.add_rule(
            PolicyRule(
                rule_id="deployment-allow-all",
                effect=PolicyEffect.ALLOW,
                subject="operator-a",
                action="deployment.*",
                resource="deployment:*",
            ),
            actor="policy-admin",
            occurred_at=T0,
        )

    def tearDown(self) -> None:
        self.runtime.close()
        self.tempdir.cleanup()

    @staticmethod
    def bundle_values(bundle_id: str = "bundle-1", **overrides: object) -> dict[str, object]:
        values: dict[str, object] = {
            "bundle_id": bundle_id,
            "version": "1.2.3",
            "platform": DeploymentPlatform.LINUX_SERVER,
            "package_digest": PACKAGE_DIGEST,
            "sbom": {"format": "cyclonedx", "components": ["starcom-core"]},
            "configuration": {"profile": "offline-safe", "log_level": "INFO"},
            "provenance": {"builder": "starcom-ci", "source_digest": "c" * 64},
            "artifacts": [
                {
                    "artifact_id": "app",
                    "digest": "d" * 64,
                    "media_type": "application/octet-stream",
                    "size_bytes": 4096,
                }
            ],
            "minimum_resources": {
                "cpu_cores": 2,
                "memory_mb": 4096,
                "storage_mb": 10000,
            },
            "gpu_required": {
                "required": True,
                "model": "test-gpu",
                "memory_mb": 4096,
            },
            "offline_capability": True,
            "safety_profile": {
                "profile_id": "starcom-safe-v1",
                "network_mode": "NONE",
                "allow_privileged": False,
            },
        }
        values.update(overrides)
        return values

    def bundle(self, bundle_id: str = "bundle-1", **overrides: object):
        return self.service.prepare_bundle(**self.bundle_values(bundle_id, **overrides))

    def node(self, node_id: str = "node-1", **overrides: object):
        values: dict[str, object] = {
            "node_id": node_id,
            "platform": DeploymentPlatform.LINUX_SERVER,
            "public_key_pem": self.public_key.read_bytes(),
            "capabilities": {
                "cpu_cores": 8,
                "memory_mb": 16384,
                "storage_mb": 100000,
                "gpu": {
                    "available": True,
                    "model": "test-gpu",
                    "memory_mb": 8192,
                },
            },
            "offline_mode": True,
            "attestation_digest": ATTESTATION_DIGEST,
            "labels": ["production", "trusted"],
        }
        values.update(overrides)
        return self.service.prepare_node(**values)

    def decision(self, preparation, *, subject: str = "operator-a", context=None):
        return self.runtime.trust.authorize(
            AuthorizationRequest(
                subject=subject,
                action=preparation.action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=(
                    dict(preparation.context)
                    if context is None
                    else dict(context)
                ),
            ),
            now=T1,
        )

    def seal(self, bundle_id: str = "bundle-1"):
        preparation = self.bundle(bundle_id)
        decision = self.decision(preparation)
        record = self.service.seal_bundle(
            preparation,
            authorization_decision_id=decision.decision_id,
            actor="operator-a",
            occurred_at=T1,
        )
        return preparation, decision, record

    def enroll(self, node_id: str = "node-1"):
        preparation = self.node(node_id)
        decision = self.decision(preparation)
        record = self.service.enroll_node(
            preparation,
            authorization_decision_id=decision.decision_id,
            actor="operator-a",
            occurred_at=T2,
        )
        return preparation, decision, record

    def assignment(self, assignment_id: str = "assignment-1"):
        bundle_preparation, _, _ = self.seal()
        node_preparation, _, _ = self.enroll()
        preparation = self.service.prepare_assignment(
            assignment_id,
            bundle_preparation.bundle_id,
            node_preparation.node_id,
        )
        decision = self.decision(preparation)
        record = self.service.authorize_assignment(
            preparation,
            authorization_decision_id=decision.decision_id,
            actor="operator-a",
            occurred_at=T3,
        )
        return preparation, decision, record


class DeploymentContractTests(DeploymentTestBase):
    def test_six_platforms_are_closed_and_bundle_is_sealed_without_effect(self) -> None:
        self.assertEqual(
            {item.value for item in DeploymentPlatform},
            {
                "LINUX_SERVER",
                "WINDOWS_DESKTOP",
                "MACOS_DESKTOP",
                "ANDROID_MOBILE",
                "IOS_MOBILE",
                "EDGE_NODE",
            },
        )
        for index, platform in enumerate(DeploymentPlatform, start=1):
            preparation = self.bundle(f"bundle-platform-{index}", platform=platform)
            decision = self.decision(preparation)
            record = self.service.seal_bundle(
                preparation,
                authorization_decision_id=decision.decision_id,
                actor="operator-a",
                occurred_at=f"2026-08-21T12:01:0{index}.000000Z",
            )
            self.assertEqual(record.platform, platform)
            self.assertEqual(record.status, DeploymentBundleStatus.SEALED_NOT_DEPLOYED)
            self.assertTrue(self.service.verify_bundle(record.bundle_id).ok)

    def test_prepare_is_deterministic_and_side_effect_free(self) -> None:
        first = self.bundle()
        second = self.bundle()
        self.assertEqual(first, second)
        self.assertEqual(
            self.runtime.database.connection.execute(
                "SELECT COUNT(*) FROM deployment_bundles"
            ).fetchone()[0],
            0,
        )

    def test_default_deny_blocks_all_three_mutations(self) -> None:
        bundle = self.bundle("bundle-denied")
        denied_bundle = self.decision(bundle, subject="untrusted")
        with self.assertRaises(AuthorizationError):
            self.service.seal_bundle(
                bundle,
                authorization_decision_id=denied_bundle.decision_id,
                actor="untrusted",
            )
        node = self.node("node-denied")
        denied_node = self.decision(node, subject="untrusted")
        with self.assertRaises(AuthorizationError):
            self.service.enroll_node(
                node,
                authorization_decision_id=denied_node.decision_id,
                actor="untrusted",
            )
        self.assertEqual(
            self.runtime.database.connection.execute(
                "SELECT COUNT(*) FROM deployment_bundles"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.runtime.database.connection.execute(
                "SELECT COUNT(*) FROM deployment_nodes"
            ).fetchone()[0],
            0,
        )

    def test_node_enrollment_stores_key_fingerprint_and_offline_state(self) -> None:
        preparation, _, record = self.enroll()
        self.assertEqual(record.status, DeploymentNodeStatus.ENROLLED_OFFLINE)
        self.assertEqual(record.public_key_pem, self.public_key.read_bytes())
        self.assertEqual(record.public_key_fingerprint_sha256, preparation.public_key_fingerprint_sha256)
        self.assertTrue(self.service.verify_node(record.node_id).ok)

    def test_assignment_requires_exact_compatible_bundle_and_node(self) -> None:
        preparation, _, record = self.assignment()
        self.assertEqual(record.status, DeploymentAssignmentStatus.AUTHORIZED_NOT_EXECUTED)
        self.assertEqual(record.bundle_id, "bundle-1")
        self.assertEqual(record.node_id, "node-1")
        self.assertTrue(self.service.verify_assignment(preparation.assignment_id).ok)

    def test_exact_replay_is_idempotent_and_decision_reuse_conflicts(self) -> None:
        preparation = self.bundle("bundle-replay")
        decision = self.decision(preparation)
        first = self.service.seal_bundle(
            preparation,
            authorization_decision_id=decision.decision_id,
            actor="operator-a",
            occurred_at=T1,
        )
        replay = self.service.seal_bundle(
            preparation,
            authorization_decision_id=decision.decision_id,
            actor="operator-a",
            occurred_at=T2,
        )
        self.assertEqual(first, replay)
        with self.assertRaises(ConflictError):
            self.service.seal_bundle(
                self.bundle("bundle-replay-conflict", package_digest="e" * 64),
                authorization_decision_id=decision.decision_id,
                actor="operator-a",
            )

    def test_platform_resource_gpu_and_offline_incompatibilities_fail_closed(self) -> None:
        self.seal()
        self.enroll()
        with self.assertRaises(ValidationError):
            self.service.prepare_assignment("bad/platform", "bundle-1", "node-1")
        incompatible_bundle = self.bundle(
            "bundle-windows",
            platform=DeploymentPlatform.WINDOWS_DESKTOP,
        )
        decision = self.decision(incompatible_bundle)
        self.service.seal_bundle(
            incompatible_bundle,
            authorization_decision_id=decision.decision_id,
            actor="operator-a",
            occurred_at=T1,
        )
        with self.assertRaises(IntegrityError):
            self.service.prepare_assignment("assignment-platform", "bundle-windows", "node-1")

        low_private = self.root / "node-low-private.pem"
        low_public = self.root / "node-low-public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(low_private)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(low_private), "-pubout", "-out", str(low_public)],
            check=True,
            capture_output=True,
        )
        low_node = self.node(
            "node-low",
            public_key_pem=low_public.read_bytes(),
            capabilities={
                "cpu_cores": 1,
                "memory_mb": 1024,
                "storage_mb": 100,
                "gpu": {"available": False, "model": None, "memory_mb": 0},
            },
            offline_mode=False,
        )
        low_decision = self.decision(low_node)
        self.service.enroll_node(
            low_node,
            authorization_decision_id=low_decision.decision_id,
            actor="operator-a",
            occurred_at=T2,
        )
        with self.assertRaises(IntegrityError):
            self.service.authorize_assignment(
                self.service.prepare_assignment("assignment-low", "bundle-1", "node-low"),
                authorization_decision_id=self.decision(
                    self.service.prepare_assignment("assignment-low", "bundle-1", "node-low")
                ).decision_id,
                actor="operator-a",
            )

    def test_closed_fields_and_invalid_key_fail_before_persistence(self) -> None:
        with self.assertRaises(ValidationError):
            self.bundle(artifacts=[{"artifact_id": "app", "digest": "d" * 64}])
        with self.assertRaises(ValidationError):
            self.bundle(
                safety_profile={
                    "profile_id": "starcom-safe-v1",
                    "network_mode": "NONE",
                    "allow_privileged": False,
                    "unexpected": True,
                }
            )
        with self.assertRaises(ValidationError):
            self.node("node-invalid-key", public_key_pem=b"not-ed25519")
        self.assertEqual(
            self.runtime.database.connection.execute(
                "SELECT COUNT(*) FROM deployment_nodes"
            ).fetchone()[0],
            0,
        )


class DeploymentIntegrityTests(DeploymentTestBase):
    def test_bundle_node_and_assignment_tampering_is_detected(self) -> None:
        self.assignment()
        connection = self.runtime.database.connection
        connection.execute("DROP TRIGGER deployment_bundles_no_update")
        connection.execute(
            "UPDATE deployment_bundles SET package_digest = ? WHERE bundle_id = ?",
            ("f" * 64, "bundle-1"),
        )
        self.assertFalse(self.service.verify_bundle("bundle-1").ok)
        self.assertIn(
            "BUNDLE_PACKAGE_DIGEST_MISMATCH",
            self.service.verify_bundle("bundle-1").defects,
        )
        self.assertFalse(self.service.verify_assignment("assignment-1").ok)

    def test_decision_context_actor_and_ledger_tampering_fail_closed(self) -> None:
        preparation = self.bundle("bundle-context")
        wrong_context = dict(preparation.context)
        wrong_context["manifest_digest"] = "0" * 64
        wrong = self.decision(preparation, context=wrong_context)
        with self.assertRaises(AuthorizationError):
            self.service.seal_bundle(
                preparation,
                authorization_decision_id=wrong.decision_id,
                actor="operator-a",
            )
        preparation, _, _ = self.seal("bundle-ledger")
        row = self.runtime.database.connection.execute(
            "SELECT ledger_event_id FROM deployment_bundles WHERE bundle_id = ?",
            (preparation.bundle_id,),
        ).fetchone()
        self.runtime.database.connection.execute("DROP TRIGGER ledger_events_no_update")
        self.runtime.database.connection.execute(
            "UPDATE ledger_events SET actor = ? WHERE event_id = ?",
            ("tampered", str(row["ledger_event_id"])),
        )
        self.assertFalse(self.service.verify_bundle(preparation.bundle_id).ok)

    def test_service_has_no_deployment_or_remote_execution_surface(self) -> None:
        forbidden = {
            "deploy",
            "install",
            "push",
            "connect",
            "execute",
            "run",
            "download",
        }
        self.assertTrue(forbidden.isdisjoint(dir(self.service)))
        source = inspect.getsource(DeploymentFabricService).lower()
        for token in (
            "urllib",
            "requests",
            "http",
            "socket",
            "websocket",
            "subprocess",
            "deploy(",
            "install(",
            "push(",
            "connect(",
        ):
            self.assertNotIn(token, source)


class DeploymentRuntimeTests(unittest.TestCase):
    def test_runtime_exposes_one_shared_deployment_service(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = Runtime.open(Path(directory) / "runtime.sqlite3")
            try:
                self.assertIsInstance(runtime.deployment, DeploymentFabricService)
                self.assertIs(runtime.deployment.database, runtime.database)
                self.assertIs(runtime.deployment.ledger, runtime.ledger)
                self.assertIs(runtime.deployment.trust, runtime.trust)
                self.assertIs(runtime.deployment.continuity, runtime.continuity)
            finally:
                runtime.close()


if __name__ == "__main__":
    unittest.main()
