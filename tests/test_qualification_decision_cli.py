from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

import test_qualification_cli as qualification_cli_fixture


C0 = "2026-08-14T12:00:00.000000Z"
C1 = "2026-08-14T12:01:00.000000Z"
C2 = "2026-08-14T12:02:00.000000Z"
C3 = "2026-08-14T12:03:00.000000Z"
C4 = "2026-08-14T12:04:00.000000Z"
C5 = "2026-08-14T12:05:00.000000Z"
C6 = "2026-08-14T12:06:00.000000Z"


class C3DecisionCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture = qualification_cli_fixture.QualificationAndC3CliTests
        fixture.setUpClass()
        cls.certified_c2_fixture = fixture
        cls.repo_root = fixture.repo_root
        cls.base_db_path = fixture.base_db_path
        cls.base_root = fixture.base_root
        cls.decision_private = cls.base_root / "c3-decision-private.pem"
        cls.decision_public = cls.base_root / "c3-decision-public.pem"
        fixture._generate_keypair(
            cls.decision_private,
            cls.decision_public,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.certified_c2_fixture.tearDownClass()

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.db_path = self.root / "starcom.sqlite3"
        shutil.copy2(self.base_db_path, self.db_path)
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

    @staticmethod
    def decode_stdout(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        if not result.stdout.strip():
            raise AssertionError(result.stderr)
        return json.loads(result.stdout)

    @staticmethod
    def decode_stderr(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        if not result.stderr.strip():
            raise AssertionError(result.stdout)
        return json.loads(result.stderr)

    def success(self, result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        self.assertEqual(result.returncode, 0, result.stderr)
        return self.decode_stdout(result)

    def sign(self, payload_path: Path, signature_path: Path) -> None:
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(self.decision_private),
                "-rawin",
                "-in",
                str(payload_path),
                "-out",
                str(signature_path),
            ],
            check=True,
            capture_output=True,
        )

    def prepare_c3_decision_material(self) -> tuple[Path, Path, dict[str, object]]:
        self.success(
            self.run_cli(
                "qualification",
                "create-run",
                "--qualification-run-id",
                "decision-run",
                "--name",
                "Explicit C3 decision qualification",
                "--actor",
                "lab-owner",
                "--occurred-at",
                C0,
            )
        )
        self.success(
            self.run_cli(
                "c3",
                "start",
                "--c3-run-id",
                "c3-decision-run",
                "--qualification-run-id",
                "decision-run",
                "--certificate-id",
                "certificate-qualification-cli",
                "--actor",
                "c3-owner",
                "--occurred-at",
                C1,
            )
        )
        self.success(
            self.run_cli(
                "qualification",
                "record-artifact",
                "--qualification-run-id",
                "decision-run",
                "--artifact-id",
                "candidate-a",
                "--kind",
                "CANDIDATE",
                "--material-json",
                '{"component_id":"candidate-a","version":"1.0.0"}',
                "--actor",
                "candidate-author",
                "--occurred-at",
                C2,
            )
        )
        self.success(
            self.run_cli(
                "qualification",
                "record-artifact",
                "--qualification-run-id",
                "decision-run",
                "--artifact-id",
                "evaluation-a",
                "--kind",
                "EVALUATION",
                "--material-json",
                '{"candidate_artifact_id":"candidate-a","score":93}',
                "--actor",
                "evaluator",
                "--occurred-at",
                C3,
            )
        )
        self.success(
            self.run_cli(
                "trust",
                "add-rule",
                "--rule-id",
                "allow-c3-decision-cli-root",
                "--effect",
                "ALLOW",
                "--subject",
                "owner",
                "--action",
                "continuity.trust-root.accept",
                "--resource",
                "continuity:trust-root:c3-decision-cli",
                "--actor",
                "owner",
                "--occurred-at",
                C0,
            )
        )
        authorization = self.success(
            self.run_cli(
                "trust",
                "authorize",
                "--subject",
                "owner",
                "--action",
                "continuity.trust-root.accept",
                "--resource",
                "continuity:trust-root:c3-decision-cli",
                "--at",
                C1,
            )
        )["result"]  # type: ignore[index]
        self.success(
            self.run_cli(
                "continuity",
                "accept-trust-root",
                "--key-id",
                "c3-decision-cli",
                "--public-key-file",
                str(self.decision_public),
                "--decision-id",
                str(authorization["decision_id"]),  # type: ignore[index]
                "--actor",
                "owner",
                "--occurred-at",
                C1,
            )
        )

        snapshot = self.success(
            self.run_cli(
                "c3-decision",
                "snapshot",
                "--c3-run-id",
                "c3-decision-run",
            )
        )["result"]  # type: ignore[index]
        self.assertEqual(snapshot["candidate_artifact_ids"], ["candidate-a"])  # type: ignore[index]
        self.assertEqual(snapshot["evaluation_artifact_ids"], ["evaluation-a"])  # type: ignore[index]
        with sqlite3.connect(self.db_path) as connection:
            count = connection.execute("SELECT COUNT(*) FROM c3_decisions").fetchone()[0]
        self.assertEqual(count, 0)

        payload = {
            "decision_id": "decision-cli",
            "c3_run_id": snapshot["c3_run_id"],
            "qualification_run_id": snapshot["qualification_run_id"],
            "certificate_id": snapshot["certificate_id"],
            "qualification_head_hash": snapshot["qualification_head_hash"],
            "candidate_count": snapshot["candidate_count"],
            "evaluation_count": snapshot["evaluation_count"],
            "candidate_set_digest": snapshot["candidate_set_digest"],
            "evaluation_set_digest": snapshot["evaluation_set_digest"],
            "verdict": "C3_CANDIDATE_SELECTED",
            "selected_candidate_artifact_id": "candidate-a",
            "decision_maker_identity": "independent-c3-decision-maker",
            "decision_maker_environment": "isolated-c3-decision-cli-fixture",
            "decided_at_utc": C4,
            "independence_basis": "separate key, identity, process, and evidence review",
            "independent_identity_status": "SATISFIED",
            "qualification_verification_result": "PASS",
            "gate_effect": "NO_ADOPTION_EXECUTED",
        }
        payload_path = self.root / "C3-DECISION.json"
        signature_path = self.root / "C3-DECISION.sig"
        payload_path.write_bytes(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        self.sign(payload_path, signature_path)
        return payload_path, signature_path, snapshot

    def admit(self, payload_path: Path, signature_path: Path) -> subprocess.CompletedProcess[str]:
        return self.run_cli(
            "c3-decision",
            "admit",
            "--c3-run-id",
            "c3-decision-run",
            "--key-id",
            "c3-decision-cli",
            "--payload-file",
            str(payload_path),
            "--signature-file",
            str(signature_path),
            "--actor",
            "decision-admission-agent",
            "--occurred-at",
            C5,
        )

    def test_snapshot_admit_get_and_verify_preserve_exact_bytes(self) -> None:
        payload_path, signature_path, snapshot = self.prepare_c3_decision_material()

        admitted = self.success(self.admit(payload_path, signature_path))["result"]  # type: ignore[index]

        self.assertEqual(admitted["decision_id"], "decision-cli")  # type: ignore[index]
        self.assertEqual(admitted["c3_run_id"], snapshot["c3_run_id"])  # type: ignore[index]
        self.assertEqual(admitted["verdict"], "C3_CANDIDATE_SELECTED")  # type: ignore[index]
        with sqlite3.connect(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT payload, signature FROM c3_decisions WHERE decision_id = ?",
                ("decision-cli",),
            ).fetchone()
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(bytes(row["payload"]), payload_path.read_bytes())
        self.assertEqual(bytes(row["signature"]), signature_path.read_bytes())

        loaded = self.success(
            self.run_cli(
                "c3-decision",
                "get",
                "--decision-id",
                "decision-cli",
            )
        )["result"]  # type: ignore[index]
        self.assertEqual(loaded["selected_candidate_artifact_id"], "candidate-a")  # type: ignore[index]
        verification = self.success(
            self.run_cli(
                "c3-decision",
                "verify",
                "--decision-id",
                "decision-cli",
            )
        )["result"]  # type: ignore[index]
        self.assertTrue(verification["ok"])  # type: ignore[index]

    def test_modified_payload_and_missing_files_fail_without_decision(self) -> None:
        payload_path, signature_path, _ = self.prepare_c3_decision_material()
        tampered_path = self.root / "C3-DECISION-tampered.json"
        tampered_path.write_bytes(payload_path.read_bytes() + b" ")

        rejected = self.admit(tampered_path, signature_path)

        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(self.decode_stderr(rejected)["error"], "INTEGRITY_ERROR")
        missing = self.run_cli(
            "c3-decision",
            "admit",
            "--c3-run-id",
            "c3-decision-run",
            "--key-id",
            "c3-decision-cli",
            "--payload-file",
            str(self.root / "missing.json"),
            "--signature-file",
            str(signature_path),
            "--actor",
            "decision-admission-agent",
            "--occurred-at",
            C5,
        )
        self.assertEqual(missing.returncode, 2)
        error = self.decode_stderr(missing)
        self.assertEqual(error["error"], "VALIDATION_ERROR")
        self.assertEqual(error["message"], "payload_file could not be read")
        self.assertNotIn("Traceback", missing.stderr)
        with sqlite3.connect(self.db_path) as connection:
            count = connection.execute("SELECT COUNT(*) FROM c3_decisions").fetchone()[0]
        self.assertEqual(count, 0)

    def test_later_evidence_makes_verify_exit_three(self) -> None:
        payload_path, signature_path, _ = self.prepare_c3_decision_material()
        self.success(self.admit(payload_path, signature_path))
        self.success(
            self.run_cli(
                "qualification",
                "record-artifact",
                "--qualification-run-id",
                "decision-run",
                "--artifact-id",
                "evaluation-later",
                "--kind",
                "EVALUATION",
                "--material-json",
                '{"candidate_artifact_id":"candidate-a","score":94}',
                "--actor",
                "later-evaluator",
                "--occurred-at",
                C6,
            )
        )

        verification = self.run_cli(
            "c3-decision",
            "verify",
            "--decision-id",
            "decision-cli",
        )

        self.assertEqual(verification.returncode, 3)
        payload = self.decode_stdout(verification)["result"]  # type: ignore[index]
        self.assertFalse(payload["ok"])  # type: ignore[index]
        self.assertIn("C3_DECISION_SNAPSHOT_STALE", payload["defects"])  # type: ignore[index]

    def test_no_adoption_subcommand_exists(self) -> None:
        rejected = self.run_cli("c3-decision", "adopt")

        self.assertEqual(rejected.returncode, 2)
        error = self.decode_stderr(rejected)
        self.assertEqual(error["error"], "VALIDATION_ERROR")
        self.assertIn("invalid choice", str(error["details"]))
        self.assertIn("snapshot", str(error["details"]))
        self.assertIn("admit", str(error["details"]))
        self.assertIn("get", str(error["details"]))
        self.assertIn("verify", str(error["details"]))
        self.assertNotIn("adopt,", str(error["details"]))


if __name__ == "__main__":
    unittest.main()
