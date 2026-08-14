from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest


ARCHIVE_SHA256 = "5609915904205503ebcdcc548d9b8171fd6d9ba9bf9d1bb9f1ebb036bf8fae7f"
SNAPSHOT_DIGEST = hashlib.sha256(b"census-cli-snapshot").hexdigest()
CONTENT_DIGEST = hashlib.sha256(b"census-cli-identity-profile").hexdigest()


class C2CensusCliTests(unittest.TestCase):
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
        self.assertTrue(result.stdout.strip(), result.stderr)
        return json.loads(result.stdout)

    def error(self, result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertTrue(result.stderr.strip(), result.stdout)
        return json.loads(result.stderr)

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
            "review_id": "review-census-cli",
            "reviewer_identity": "independent-census-cli-fixture",
            "review_environment": "isolated-census-cli-fixture",
            "reviewed_archive_sha256": ARCHIVE_SHA256,
            "reviewed_at_utc": "2026-08-14T05:00:00.000000Z",
            "independence_basis": "ephemeral explicit CLI fixture",
            "independent_identity_status": "SATISFIED",
            "commands_and_exit_codes": [{"command": "verify", "exit_code": 0}],
            "receipt_snapshot_observation_result": "PASS",
            "wave_order_result": "CONFIRMS_W3_TO_W2",
            "attempt_boundary_result": "POSSIBLE_UNQUANTIFIED_CONFIRMED",
            "disposition": "RECOLLECT_REQUIRED",
            "evidence_paths_and_hashes": [
                {"path": "review.json", "sha256": "a" * 64}
            ],
            "reasoning": "The explicit CLI fixture confirms recollection is required.",
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
        return payload_path, signature_path, public_key

    def build_explicit_c1_to_c2_chain(self) -> None:
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
            resource="continuity:trust-root:reviewer-census-cli",
            rule_id="allow-census-cli-root",
        )
        self.success(
            self.run_cli(
                "continuity",
                "accept-trust-root",
                "--key-id",
                "reviewer-census-cli",
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
                "reviewer-census-cli",
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
            rule_id="allow-census-cli-recovery",
        )
        self.success(
            self.run_cli(
                "continuity",
                "publish-recovery",
                "--incident-id",
                "task5",
                "--review-id",
                "review-census-cli",
                "--publication-id",
                "publication-census-cli",
                "--idempotency-key",
                "publish-census-cli-recovery",
                "--decision-id",
                recovery_decision,
                "--actor",
                "owner",
            )
        )
        self.success(
            self.run_cli(
                "research",
                "create",
                "--campaign-id",
                "c2-campaign",
                "--name",
                "Task 5 C2 explicit census",
                "--actor",
                "owner",
            )
        )
        self.success(
            self.run_cli(
                "recollection",
                "start",
                "--recollection-id",
                "c2-run",
                "--incident-id",
                "task5",
                "--campaign-id",
                "c2-campaign",
                "--minimum-identity-target",
                "800",
                "--actor",
                "owner",
            )
        )

    def build_explicit_success_evidence(self) -> None:
        self.success(
            self.run_cli(
                "research",
                "begin-attempt",
                "--campaign-id",
                "c2-campaign",
                "--attempt-id",
                "attempt-census-cli",
                "--wave",
                "1",
                "--request-key",
                "request-census-cli",
                "--source-id",
                "github",
                "--request-json",
                '{"url":"https://example.invalid/identity"}',
                "--actor",
                "researcher",
            )
        )
        self.success(
            self.run_cli(
                "research",
                "receipt",
                "--attempt-id",
                "attempt-census-cli",
                "--receipt-id",
                "receipt-census-cli",
                "--outcome",
                "SUCCESS",
                "--status-code",
                "200",
                "--snapshot-digest",
                SNAPSHOT_DIGEST,
                "--metadata-json",
                '{"fixture":true}',
                "--actor",
                "researcher",
            )
        )
        self.success(
            self.run_cli(
                "research",
                "observation",
                "--attempt-id",
                "attempt-census-cli",
                "--observation-id",
                "observation-census-cli",
                "--snapshot-digest",
                SNAPSHOT_DIGEST,
                "--content-digest",
                CONTENT_DIGEST,
                "--data-json",
                '{"identity":"identity-1","fixture":true}',
                "--actor",
                "researcher",
            )
        )
        self.success(
            self.run_cli(
                "research",
                "cursor",
                "--campaign-id",
                "c2-campaign",
                "--cursor-id",
                "cursor-census-cli",
                "--wave",
                "1",
                "--cursor-key",
                "page",
                "--value-json",
                '{"next":null}',
                "--attempt-id",
                "attempt-census-cli",
                "--actor",
                "researcher",
            )
        )

    def register(self, *, source_id: str = "github", identity_id: str = "identity-record-1"):
        return self.run_cli(
            "census",
            "register",
            "--recollection-id",
            "c2-run",
            "--identity-id",
            identity_id,
            "--identity-key",
            "identity-1",
            "--source-id",
            source_id,
            "--attempt-id",
            "attempt-census-cli",
            "--observation-id",
            "observation-census-cli",
            "--actor",
            "researcher",
        )

    def test_explicit_evidence_can_register_get_verify_and_assess_below_target(self) -> None:
        self.build_explicit_c1_to_c2_chain()
        self.build_explicit_success_evidence()

        registered = self.success(self.register())
        self.assertEqual(registered["result"]["evidence_digest"], CONTENT_DIGEST)  # type: ignore[index]

        loaded = self.success(
            self.run_cli("census", "get", "--identity-id", "identity-record-1")
        )
        self.assertEqual(loaded["result"]["recollection_id"], "c2-run")  # type: ignore[index]

        verified = self.success(
            self.run_cli("census", "verify", "--recollection-id", "c2-run")
        )
        self.assertTrue(verified["result"]["ok"])  # type: ignore[index]
        self.assertEqual(verified["result"]["identity_count"], 1)  # type: ignore[index]

        assessed = self.success(
            self.run_cli("census", "assess", "--recollection-id", "c2-run")
        )
        result = assessed["result"]  # type: ignore[index]
        self.assertEqual(result["identity_count"], 1)  # type: ignore[index]
        self.assertEqual(result["required_target"], 800)  # type: ignore[index]
        self.assertEqual(result["defects"], [])  # type: ignore[index]
        self.assertFalse(result["eligible_for_independent_certification"])  # type: ignore[index]
        self.assertNotIn("certificate_id", result)

    def test_mismatched_source_is_rejected_without_creating_identity(self) -> None:
        self.build_explicit_c1_to_c2_chain()
        self.build_explicit_success_evidence()

        rejected = self.register(source_id="gitlab", identity_id="identity-mismatch")

        self.assertEqual(rejected.returncode, 2)
        error = self.error(rejected)
        self.assertEqual(error["error"], "INVALID_STATE_TRANSITION")
        self.assertEqual(error["message"], "identity source does not match attempt")
        missing = self.run_cli("census", "get", "--identity-id", "identity-mismatch")
        self.assertEqual(missing.returncode, 2)
        self.assertEqual(self.error(missing)["error"], "NOT_FOUND")

    def test_register_never_creates_upstream_evidence_implicitly(self) -> None:
        rejected = self.run_cli(
            "census",
            "register",
            "--recollection-id",
            "missing-c2",
            "--identity-id",
            "identity-no-upstream",
            "--identity-key",
            "identity-no-upstream",
            "--source-id",
            "github",
            "--attempt-id",
            "missing-attempt",
            "--observation-id",
            "missing-observation",
            "--actor",
            "researcher",
        )

        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(self.error(rejected)["error"], "NOT_FOUND")
        with sqlite3.connect(self.db_path) as connection:
            for table in (
                "continuity_incidents",
                "research_campaigns",
                "c2_recollections",
                "research_attempts",
                "research_observations",
                "c2_census_identities",
            ):
                count = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                self.assertEqual(count, 0, table)


if __name__ == "__main__":
    unittest.main()
