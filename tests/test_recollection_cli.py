from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ARCHIVE_SHA256 = "5609915904205503ebcdcc548d9b8171fd6d9ba9bf9d1bb9f1ebb036bf8fae7f"


class C2RecollectionCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.db_path = self.root / "starcom.sqlite3"
        self.repo_root = Path(__file__).resolve().parents[1]
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = str(self.repo_root / "src")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "starcom", "--db", str(self.db_path), *args],
            cwd=self.repo_root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )

    def success(self, result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def error(self, result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        return json.loads(result.stderr)

    def create_campaign(self) -> None:
        result = self.run_cli(
            "research",
            "create",
            "--campaign-id",
            "c2-campaign",
            "--name",
            "Task 5 C2 live recollection",
            "--actor",
            "owner",
        )
        self.success(result)

    def authorize(self, *, action: str, resource: str, rule_id: str) -> str:
        self.success(
            self.run_cli(
                "trust",
                "add-rule",
                "--rule-id",
                rule_id,
                "--effect",
                "ALLOW",
                "--subject",
                "owner",
                "--action",
                action,
                "--resource",
                resource,
                "--actor",
                "owner",
            )
        )
        decision = self.success(
            self.run_cli(
                "trust",
                "authorize",
                "--subject",
                "owner",
                "--action",
                action,
                "--resource",
                resource,
            )
        )
        return str(decision["result"]["decision_id"])  # type: ignore[index]

    def create_signed_review(self) -> tuple[Path, Path, Path]:
        payload_path = self.root / "INDEPENDENT-DISPOSITION.json"
        signature_path = self.root / "INDEPENDENT-DISPOSITION.sig"
        private_key = self.root / "reviewer-private.pem"
        public_key = self.root / "reviewer-public.pem"
        payload = {
            "review_id": "review-c2-cli",
            "reviewer_identity": "independent-c2-cli-fixture",
            "review_environment": "isolated-c2-cli-fixture",
            "reviewed_archive_sha256": ARCHIVE_SHA256,
            "reviewed_at_utc": "2026-08-14T04:01:00.000000Z",
            "independence_basis": "ephemeral CLI fixture",
            "independent_identity_status": "SATISFIED",
            "commands_and_exit_codes": [{"command": "verify", "exit_code": 0}],
            "receipt_snapshot_observation_result": "PASS",
            "wave_order_result": "CONFIRMS_W3_TO_W2",
            "attempt_boundary_result": "POSSIBLE_UNQUANTIFIED_CONFIRMED",
            "disposition": "RECOLLECT_REQUIRED",
            "evidence_paths_and_hashes": [{"path": "review.json", "sha256": "a" * 64}],
            "reasoning": "The isolated fixture confirms recollection is required.",
            "gate_effect": "NO_GATE_CHANGE",
        }
        payload_path.write_bytes(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(private_key),
                "-rawin",
                "-in",
                str(payload_path),
                "-out",
                str(signature_path),
            ],
            check=True,
            capture_output=True,
        )
        self.assertEqual(
            hashlib.sha256(payload_path.read_bytes()).hexdigest(),
            hashlib.sha256(payload_path.read_bytes()).hexdigest(),
        )
        return payload_path, signature_path, public_key

    def publish_c1(self) -> None:
        self.success(
            self.run_cli(
                "continuity",
                "create-incident",
                "--incident-id",
                "task5",
                "--reviewed-archive-sha256",
                ARCHIVE_SHA256,
                "--actor",
                "owner",
            )
        )
        payload_path, signature_path, public_key = self.create_signed_review()
        root_decision = self.authorize(
            action="continuity.trust-root.accept",
            resource="continuity:trust-root:reviewer-c2-cli",
            rule_id="allow-c2-cli-root",
        )
        self.success(
            self.run_cli(
                "continuity",
                "accept-trust-root",
                "--key-id",
                "reviewer-c2-cli",
                "--public-key-file",
                str(public_key),
                "--decision-id",
                root_decision,
                "--actor",
                "owner",
            )
        )
        self.success(
            self.run_cli(
                "continuity",
                "admit-review",
                "--incident-id",
                "task5",
                "--key-id",
                "reviewer-c2-cli",
                "--payload-file",
                str(payload_path),
                "--signature-file",
                str(signature_path),
                "--actor",
                "owner",
            )
        )
        recovery_decision = self.authorize(
            action="continuity.recovery.publish",
            resource="continuity:incident:task5",
            rule_id="allow-c2-cli-recovery",
        )
        published = self.success(
            self.run_cli(
                "continuity",
                "publish-recovery",
                "--incident-id",
                "task5",
                "--review-id",
                "review-c2-cli",
                "--publication-id",
                "publication-c2-cli",
                "--idempotency-key",
                "publish-c2-cli-recovery",
                "--decision-id",
                recovery_decision,
                "--actor",
                "owner",
            )
        )
        self.assertEqual(
            published["result"]["status"],  # type: ignore[index]
            "RECOVERY_PUBLISHED_RECOLLECT_REQUIRED",
        )

    def start(self, target: int = 800) -> subprocess.CompletedProcess[str]:
        return self.run_cli(
            "recollection",
            "start",
            "--recollection-id",
            "recollection-c2-cli",
            "--incident-id",
            "task5",
            "--campaign-id",
            "c2-campaign",
            "--minimum-identity-target",
            str(target),
            "--actor",
            "owner",
        )

    def test_start_is_blocked_before_c1_publication(self) -> None:
        self.success(
            self.run_cli(
                "continuity",
                "create-incident",
                "--incident-id",
                "task5",
                "--reviewed-archive-sha256",
                ARCHIVE_SHA256,
                "--actor",
                "owner",
            )
        )
        self.create_campaign()

        result = self.start()

        self.assertEqual(result.returncode, 2)
        error = self.error(result)
        self.assertEqual(error["error"], "STATE_TRANSITION_ERROR")
        self.assertEqual(error["message"], "C1 recovery must be published before C2 recollection")

    def test_published_c1_can_start_get_and_verify_c2(self) -> None:
        self.publish_c1()
        self.create_campaign()

        started = self.success(self.start())
        self.assertEqual(started["result"]["minimum_identity_target"], 800)  # type: ignore[index]
        self.assertEqual(started["result"]["campaign_id"], "c2-campaign")  # type: ignore[index]

        loaded = self.success(
            self.run_cli("recollection", "get", "--recollection-id", "recollection-c2-cli")
        )
        self.assertEqual(loaded["result"]["incident_id"], "task5")  # type: ignore[index]

        verified = self.success(
            self.run_cli("recollection", "verify", "--recollection-id", "recollection-c2-cli")
        )
        self.assertTrue(verified["result"]["ok"])  # type: ignore[index]

    def test_target_below_800_is_rejected_without_binding(self) -> None:
        self.publish_c1()
        self.create_campaign()

        rejected = self.start(799)

        self.assertEqual(rejected.returncode, 2)
        error = self.error(rejected)
        self.assertEqual(error["error"], "VALIDATION_ERROR")
        self.assertEqual(error["message"], "minimum_identity_target must be >= 800")
        missing = self.run_cli("recollection", "get", "--recollection-id", "recollection-c2-cli")
        self.assertEqual(missing.returncode, 2)
        self.assertEqual(self.error(missing)["error"], "NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
