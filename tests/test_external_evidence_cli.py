from __future__ import annotations

import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest


T0 = "2026-08-21T14:00:00.000000Z"
T1 = "2026-08-21T14:00:01.000000Z"
T2 = "2026-08-21T14:00:02.000000Z"


class ExternalEvidenceCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.env = os.environ.copy()
        cls.env["PYTHONPATH"] = str(cls.repo_root / "src")

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.db = self.root / "starcom.sqlite3"
        self.private_key = self.root / "private.pem"
        self.public_key = self.root / "public.pem"
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

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "starcom.external_evidence_cli", "--db", str(self.db), *args],
            cwd=self.repo_root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )

    def run_core_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "starcom", "--db", str(self.db), *args],
            cwd=self.repo_root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )

    @staticmethod
    def stdout(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        return json.loads(result.stdout)

    @staticmethod
    def stderr(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        return json.loads(result.stderr)

    def accept_root(self) -> None:
        self.assertEqual(
            self.run_core_cli(
                "trust", "add-rule", "--rule-id", "external-cli-rule", "--effect", "ALLOW",
                "--subject", "root-operator", "--action", "continuity.trust-root.accept",
                "--resource", "continuity:trust-root:external-cli", "--actor", "policy-owner",
                "--occurred-at", T0,
            ).returncode,
            0,
        )
        authorization = self.stdout(self.run_core_cli(
            "trust", "authorize", "--subject", "root-operator",
            "--action", "continuity.trust-root.accept",
            "--resource", "continuity:trust-root:external-cli", "--at", T1,
        ))["result"]
        result = self.run_core_cli(
            "continuity", "accept-trust-root", "--key-id", "external-cli",
            "--public-key-file", str(self.public_key), "--decision-id", authorization["decision_id"],
            "--actor", "root-operator", "--occurred-at", T1,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def write_signed_payload(self) -> tuple[Path, Path]:
        payload = {
            "evidence_id": "cli-evidence",
            "kind": "LIVE_CENSUS_CERTIFICATION",
            "subject_id": "cli-subject",
            "operator_identity": "operator-a",
            "reviewer_identity": "reviewer-b",
            "reviewer_environment": "offline-cli",
            "captured_at_utc": T1,
            "valid_until_utc": "2026-08-21T15:00:00.000000Z",
            "claims": {
                "identity_count": 800,
                "independent_certification": True,
                "census_digest": "a" * 64,
                "certificate_digest": "b" * 64,
            },
            "evidence_items": [{
                "item_id": "cli-item",
                "kind": "certificate",
                "digest": "c" * 64,
                "media_type": "application/json",
            }],
            "independence_basis": {
                "excluded_identities": ["operator-a"],
                "statement": "independent offline review",
            },
            "result": "PROVEN",
            "gate_effect": "EXTERNAL_EVIDENCE_ADMITTED_NO_RELEASE",
        }
        payload_path = self.root / "evidence.json"
        signature_path = self.root / "evidence.sig"
        payload_path.write_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(self.private_key), "-rawin",
             "-in", str(payload_path), "-out", str(signature_path)],
            check=True,
            capture_output=True,
        )
        return payload_path, signature_path

    def test_snapshot_is_empty_and_cli_has_no_operational_commands(self) -> None:
        snapshot = self.run_cli("snapshot", "--as-of", T2)
        self.assertEqual(snapshot.returncode, 0, snapshot.stderr)
        self.assertEqual(set(self.stdout(snapshot)["result"]), {
            "LIVE_CENSUS_CERTIFICATION", "EXTERNAL_RUNTIME_INTEGRATION",
            "COMPONENT_ADOPTION", "REAL_DEPLOYMENT",
        })
        help_result = subprocess.run(
            [sys.executable, "-m", "starcom.external_evidence_cli", "--help"],
            cwd=self.repo_root, env=self.env, text=True, capture_output=True, check=False,
        )
        self.assertNotIn("release", help_result.stdout.lower())
        self.assertNotIn("deploy", help_result.stdout.lower())

    def test_admit_get_verify_and_snapshot_preserve_exact_bytes(self) -> None:
        self.accept_root()
        payload, signature = self.write_signed_payload()
        admitted = self.run_cli(
            "admit", "--evidence-id", "cli-evidence", "--key-id", "external-cli",
            "--payload-file", str(payload), "--signature-file", str(signature),
            "--actor", "cli-admitter", "--occurred-at", T2,
        )
        self.assertEqual(admitted.returncode, 0, admitted.stderr)
        got = self.run_cli("get", "--evidence-id", "cli-evidence")
        self.assertEqual(got.returncode, 0, got.stderr)
        verified = self.run_cli("verify", "--evidence-id", "cli-evidence")
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertTrue(self.stdout(verified)["result"]["ok"])
        snapshot = self.run_cli("snapshot", "--as-of", T2)
        self.assertEqual(self.stdout(snapshot)["result"]["LIVE_CENSUS_CERTIFICATION"], "PROVEN")

    def test_whitespace_mutation_and_missing_file_are_structured_errors(self) -> None:
        self.accept_root()
        payload, signature = self.write_signed_payload()
        mutated = self.root / "mutated.json"
        mutated.write_bytes(payload.read_bytes() + b" ")
        rejected = self.run_cli(
            "admit", "--evidence-id", "cli-evidence", "--key-id", "external-cli",
            "--payload-file", str(mutated), "--signature-file", str(signature),
            "--actor", "cli-admitter", "--occurred-at", T2,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(self.stderr(rejected)["error"], "INTEGRITY_ERROR")
        missing = self.run_cli(
            "admit", "--evidence-id", "cli-evidence", "--key-id", "external-cli",
            "--payload-file", str(self.root / "missing.json"), "--signature-file", str(signature),
            "--actor", "cli-admitter", "--occurred-at", T2,
        )
        self.assertEqual(missing.returncode, 2)
        self.assertEqual(self.stderr(missing)["error"], "VALIDATION_ERROR")
        self.assertNotIn("Traceback", missing.stderr)


if __name__ == "__main__":
    unittest.main()
