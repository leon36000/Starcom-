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


class ContinuityCliContractTests(unittest.TestCase):
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
            [
                sys.executable,
                "-m",
                "starcom",
                "--db",
                str(self.db_path),
                *args,
            ],
            cwd=self.repo_root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )

    def payload(self, result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        self.assertTrue(result.stdout.strip(), result.stderr)
        return json.loads(result.stdout)

    def error_payload(self, result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        self.assertTrue(result.stderr.strip(), result.stdout)
        return json.loads(result.stderr)

    def authorize(self, *, action: str, resource: str, rule_id: str) -> str:
        rule = self.run_cli(
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
        self.assertEqual(rule.returncode, 0, rule.stderr)
        decision = self.run_cli(
            "trust",
            "authorize",
            "--subject",
            "owner",
            "--action",
            action,
            "--resource",
            resource,
        )
        self.assertEqual(decision.returncode, 0, decision.stderr)
        return str(self.payload(decision)["result"]["decision_id"])  # type: ignore[index]

    def make_ed25519_material(self, payload: bytes) -> tuple[Path, Path]:
        private_key = self.root / "reviewer-private.pem"
        public_key = self.root / "reviewer-public.pem"
        payload_path = self.root / "INDEPENDENT-DISPOSITION.json"
        signature_path = self.root / "INDEPENDENT-DISPOSITION.sig"
        payload_path.write_bytes(payload)
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
        return public_key, signature_path

    @staticmethod
    def review_payload() -> bytes:
        value = {
            "review_id": "review-cli",
            "reviewer_identity": "independent-cli-reviewer",
            "review_environment": "isolated-cli-fixture",
            "reviewed_archive_sha256": ARCHIVE_SHA256,
            "reviewed_at_utc": "2026-08-13T12:01:00.000000Z",
            "independence_basis": "ephemeral process fixture",
            "independent_identity_status": "SATISFIED",
            "commands_and_exit_codes": [{"command": "verify", "exit_code": 0}],
            "receipt_snapshot_observation_result": "PASS",
            "wave_order_result": "CONFIRMS_W3_TO_W2",
            "attempt_boundary_result": "POSSIBLE_UNQUANTIFIED_CONFIRMED",
            "disposition": "RECOLLECT_REQUIRED",
            "evidence_paths_and_hashes": [{"path": "review.json", "sha256": "a" * 64}],
            "reasoning": "The isolated fixture confirms the required recovery disposition.",
            "gate_effect": "NO_GATE_CHANGE",
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def test_exact_byte_artifacts_drive_explicit_c1_cli_flow(self) -> None:
        created = self.run_cli(
            "continuity",
            "create-incident",
            "--incident-id",
            "task5-cli",
            "--reviewed-archive-sha256",
            ARCHIVE_SHA256,
            "--actor",
            "owner",
        )
        self.assertEqual(created.returncode, 0, created.stderr)
        self.assertEqual(self.payload(created)["result"]["status"], "RECOVERY_REQUIRED")  # type: ignore[index]

        loaded = self.run_cli("continuity", "get-incident", "--incident-id", "task5-cli")
        self.assertEqual(loaded.returncode, 0, loaded.stderr)
        self.assertEqual(self.payload(loaded)["result"]["disposition"], "RECOLLECT_REQUIRED")  # type: ignore[index]

        review_payload = self.review_payload()
        public_key, signature_path = self.make_ed25519_material(review_payload)
        payload_path = self.root / "INDEPENDENT-DISPOSITION.json"

        root_decision_id = self.authorize(
            action="continuity.trust-root.accept",
            resource="continuity:trust-root:reviewer-cli",
            rule_id="allow-cli-root",
        )
        accepted = self.run_cli(
            "continuity",
            "accept-trust-root",
            "--key-id",
            "reviewer-cli",
            "--public-key-file",
            str(public_key),
            "--decision-id",
            root_decision_id,
            "--actor",
            "owner",
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(
            self.payload(accepted)["result"]["fingerprint_sha256"],  # type: ignore[index]
            hashlib.sha256(public_key.read_bytes()).hexdigest(),
        )

        tampered_path = self.root / "tampered-disposition.json"
        tampered_path.write_bytes(review_payload + b" ")
        rejected = self.run_cli(
            "continuity",
            "admit-review",
            "--incident-id",
            "task5-cli",
            "--key-id",
            "reviewer-cli",
            "--payload-file",
            str(tampered_path),
            "--signature-file",
            str(signature_path),
            "--actor",
            "owner",
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(self.error_payload(rejected)["error"], "INTEGRITY_ERROR")

        admitted = self.run_cli(
            "continuity",
            "admit-review",
            "--incident-id",
            "task5-cli",
            "--key-id",
            "reviewer-cli",
            "--payload-file",
            str(payload_path),
            "--signature-file",
            str(signature_path),
            "--actor",
            "owner",
        )
        self.assertEqual(admitted.returncode, 0, admitted.stderr)
        admitted_payload = self.payload(admitted)["result"]  # type: ignore[index]
        self.assertEqual(admitted_payload["review_id"], "review-cli")  # type: ignore[index]
        self.assertEqual(
            admitted_payload["payload_sha256"],  # type: ignore[index]
            hashlib.sha256(payload_path.read_bytes()).hexdigest(),
        )

        verified = self.run_cli("continuity", "verify", "--incident-id", "task5-cli")
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertTrue(self.payload(verified)["result"]["ok"])  # type: ignore[index]

        publication_decision_id = self.authorize(
            action="continuity.recovery.publish",
            resource="continuity:incident:task5-cli",
            rule_id="allow-cli-recovery",
        )
        published = self.run_cli(
            "continuity",
            "publish-recovery",
            "--incident-id",
            "task5-cli",
            "--review-id",
            "review-cli",
            "--publication-id",
            "publication-cli",
            "--idempotency-key",
            "recover-task5-cli",
            "--decision-id",
            publication_decision_id,
            "--actor",
            "owner",
        )
        self.assertEqual(published.returncode, 0, published.stderr)
        self.assertEqual(
            self.payload(published)["result"]["status"],  # type: ignore[index]
            "RECOVERY_PUBLISHED_RECOLLECT_REQUIRED",
        )

        final_verify = self.run_cli("continuity", "verify", "--incident-id", "task5-cli")
        self.assertEqual(final_verify.returncode, 0, final_verify.stderr)
        self.assertTrue(self.payload(final_verify)["result"]["ok"])  # type: ignore[index]
        final_incident = self.run_cli("continuity", "get-incident", "--incident-id", "task5-cli")
        self.assertEqual(final_incident.returncode, 0, final_incident.stderr)
        final_state = self.payload(final_incident)["result"]  # type: ignore[index]
        self.assertEqual(final_state["status"], "RECOVERY_PUBLISHED_RECOLLECT_REQUIRED")  # type: ignore[index]
        self.assertEqual(final_state["disposition"], "RECOLLECT_REQUIRED")  # type: ignore[index]

    def test_missing_artifact_file_is_machine_readable_validation_error(self) -> None:
        missing = self.run_cli(
            "continuity",
            "accept-trust-root",
            "--key-id",
            "reviewer-cli",
            "--public-key-file",
            str(self.root / "missing.pem"),
            "--decision-id",
            "decision-does-not-matter",
            "--actor",
            "owner",
        )
        self.assertEqual(missing.returncode, 2)
        error = self.error_payload(missing)
        self.assertEqual(error["error"], "VALIDATION_ERROR")
        self.assertNotIn("Traceback", missing.stderr)


if __name__ == "__main__":
    unittest.main()
