from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CliContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "starcom.sqlite3"
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

    def test_init_emits_json_and_creates_persistent_database(self) -> None:
        result = self.run_cli("init")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = self.payload(result)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["result"]["initialized"])  # type: ignore[index]
        self.assertEqual(payload["result"]["database"], str(self.db_path.resolve()))  # type: ignore[index]
        self.assertTrue(self.db_path.is_file())

        doctor = self.run_cli("doctor")
        self.assertEqual(doctor.returncode, 0, doctor.stderr)
        doctor_payload = self.payload(doctor)
        self.assertFalse(doctor_payload["result"]["product_complete"])  # type: ignore[index]
        self.assertTrue(doctor_payload["result"]["ledger"]["ok"])  # type: ignore[index]

    def test_mission_commands_persist_across_processes_and_errors_are_structured(self) -> None:
        created = self.run_cli(
            "mission",
            "create",
            "--mission-id",
            "mission-cli",
            "--title",
            "CLI mission",
            "--objective",
            "Prove persistence",
            "--owner",
            "owner",
        )
        self.assertEqual(created.returncode, 0, created.stderr)
        self.assertEqual(self.payload(created)["result"]["state"], "CREATED")  # type: ignore[index]

        loaded = self.run_cli("mission", "get", "--mission-id", "mission-cli")
        self.assertEqual(loaded.returncode, 0, loaded.stderr)
        self.assertEqual(self.payload(loaded)["result"]["mission_id"], "mission-cli")  # type: ignore[index]

        duplicate = self.run_cli(
            "mission",
            "create",
            "--mission-id",
            "mission-cli",
            "--title",
            "CLI mission",
            "--objective",
            "Prove persistence",
            "--owner",
            "owner",
        )
        self.assertEqual(duplicate.returncode, 2)
        error = self.error_payload(duplicate)
        self.assertEqual(error["error"], "CONFLICT")
        self.assertNotIn("Traceback", duplicate.stderr)

    def test_invalid_json_and_missing_entity_return_machine_readable_errors(self) -> None:
        self.assertEqual(self.run_cli("research", "create", "--campaign-id", "c1", "--name", "C1", "--actor", "owner").returncode, 0)
        invalid = self.run_cli(
            "research",
            "begin-attempt",
            "--campaign-id",
            "c1",
            "--wave",
            "1",
            "--request-key",
            "request-1",
            "--source-id",
            "source-1",
            "--request-json",
            "{not-json}",
            "--actor",
            "agent:researcher",
        )
        self.assertEqual(invalid.returncode, 2)
        self.assertEqual(self.error_payload(invalid)["error"], "VALIDATION_ERROR")

        missing = self.run_cli("research", "verify", "--campaign-id", "missing")
        self.assertEqual(missing.returncode, 2)
        self.assertEqual(self.error_payload(missing)["error"], "NOT_FOUND")

    def test_trust_and_proof_commands_are_exposed_as_json_contracts(self) -> None:
        add_rule = self.run_cli(
            "trust",
            "add-rule",
            "--rule-id",
            "allow-operator",
            "--effect",
            "ALLOW",
            "--subject",
            "agent:operator",
            "--action",
            "mission:*",
            "--resource",
            "mission:*",
            "--actor",
            "owner",
        )
        self.assertEqual(add_rule.returncode, 0, add_rule.stderr)
        self.assertEqual(self.payload(add_rule)["result"]["rule_id"], "allow-operator")  # type: ignore[index]

        decision = self.run_cli(
            "trust",
            "authorize",
            "--subject",
            "agent:operator",
            "--action",
            "mission:run",
            "--resource",
            "mission:mission-cli",
            "--mission-id",
            "mission-cli",
        )
        self.assertEqual(decision.returncode, 0, decision.stderr)
        self.assertTrue(self.payload(decision)["result"]["allowed"])  # type: ignore[index]

        claim = self.run_cli(
            "proof",
            "create-claim",
            "--claim-id",
            "claim-cli",
            "--subject-type",
            "mission",
            "--subject-id",
            "mission-cli",
            "--statement",
            "Acceptance criteria passed",
            "--author",
            "agent:builder",
            "--policy-version",
            "policy-v1",
        )
        self.assertEqual(claim.returncode, 0, claim.stderr)
        self.assertEqual(self.payload(claim)["result"]["status"], "DRAFT")  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
