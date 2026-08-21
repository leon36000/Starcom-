from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from starcom.canonical import canonical_json, sha256_digest
from starcom.errors import StateTransitionError, ValidationError
from starcom.sandbox_executor import SandboxComponentExecutor


class SandboxExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(self.tempdir)
        self.source = self.root / "source"
        self.sandbox = self.root / "sandbox"
        self.source.mkdir()
        self.write_source("1.0.0", {"component.py": b"component-v1\n", "README.txt": b"one\n"})
        self.executor = SandboxComponentExecutor(self.sandbox, source_root=self.source)

    def write_source(self, version: str, files: dict[str, bytes]) -> str:
        for relative, content in files.items():
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        entries = [
            {"path": relative, "digest": hashlib.sha256(content).hexdigest(), "size": len(content)}
            for relative, content in sorted(files.items())
        ]
        manifest = {"component": "demo-component", "version": version, "files": entries}
        self.source.joinpath("component_manifest.json").write_text(
            canonical_json(manifest), encoding="utf-8"
        )
        return sha256_digest(manifest)

    def request(self, execution_id: str, key: str, source_digest: str, *, target: str = "sandbox:demo"):
        return SimpleNamespace(
            execution_id=execution_id,
            executor_id=self.executor.executor_id,
            idempotency_key=key,
            execution_plan={
                "component_ref": self.source.as_uri(),
                "source_digest": source_digest,
                "target_environment": target,
                "sandbox_profile": "starcom-local-component-v1",
                "preconditions": ["sandbox-empty-or-current"],
                "postconditions": ["current-pointer-matches-release"],
                "requires_network": False,
                "network_allowlist": [],
                "requires_separate_rollback_authorization": False,
            },
        )

    def test_manifest_descriptor_and_real_install_are_deterministic(self) -> None:
        digest = self.executor.validate_manifest()
        self.assertEqual(digest, self.executor.source_digest)
        self.assertEqual(self.executor.implementation_version, "1.0.0")
        self.assertEqual(self.executor.descriptor()["network_mode"], "DENY")
        request = self.request("exec-1", "request-1", digest)
        self.executor.validate(request)
        with patch("socket.socket") as socket, patch("subprocess.run") as run:
            result = self.executor.execute(request)
        socket.assert_not_called()
        run.assert_not_called()
        self.assertTrue(result.succeeded)
        self.assertTrue(result.effect_started)
        self.assertTrue(result.post_state_digest)
        current = json.loads(self.sandbox.joinpath("current.json").read_text())
        self.assertEqual(current["component"], "demo-component")
        self.assertTrue(self.sandbox.joinpath("releases", current["release_digest"], "component.py").exists())

    def test_exact_replay_does_not_copy_again(self) -> None:
        request = self.request("exec-1", "request-1", self.executor.source_digest)
        first = self.executor.execute(request)
        release = self.sandbox / "releases" / str(first.receipt["release_digest"])
        marker = release / "marker"
        marker.write_text("preserve", encoding="utf-8")
        replay = self.executor.execute(request)
        self.assertEqual(replay, first)
        self.assertTrue(marker.exists())

    def test_second_release_and_pointer_rollback_are_idempotent(self) -> None:
        first_request = self.request("exec-1", "request-1", self.executor.source_digest)
        first = self.executor.execute(first_request)
        first_digest = first.receipt["release_digest"]
        second_digest = self.write_source("2.0.0", {"component.py": b"component-v2\n", "README.txt": b"two\n"})
        second_request = self.request("exec-2", "request-2", second_digest)
        second = self.executor.execute(second_request)
        self.assertNotEqual(second.receipt["release_digest"], first_digest)
        rollback = self.executor.rollback(second_request, second, "test rollback")
        self.assertTrue(rollback.succeeded)
        current = json.loads(self.sandbox.joinpath("current.json").read_text())
        self.assertEqual(current["release_digest"], first_digest)
        self.assertEqual(self.executor.rollback(second_request, second, "test rollback"), rollback)
        self.assertTrue((self.sandbox / "releases" / str(second.receipt["release_digest"])).exists())

    def test_rejects_symlink_traversal_digest_network_and_bad_target(self) -> None:
        outside = self.root / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        (self.source / "link.txt").symlink_to(outside)
        with self.assertRaises(ValidationError):
            self.executor.validate_manifest()
        (self.source / "link.txt").unlink()
        request = self.request("exec-1", "request-1", "0" * 64)
        with self.assertRaises(ValidationError):
            self.executor.validate(request)
        request = self.request("exec-1", "request-1", self.executor.source_digest)
        request.execution_plan["requires_network"] = True
        with self.assertRaises(ValidationError):
            self.executor.validate(request)
        request.execution_plan["requires_network"] = False
        request.execution_plan["target_environment"] = "sandbox:../escape"
        with self.assertRaises(ValidationError):
            self.executor.validate(request)


if __name__ == "__main__":
    unittest.main()
