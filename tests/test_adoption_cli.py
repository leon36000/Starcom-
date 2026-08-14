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

import test_qualification_decision_cli as decision_cli_fixture


A6 = "2026-08-14T12:06:00.000000Z"
A7 = "2026-08-14T12:07:00.000000Z"
A8 = "2026-08-14T12:08:00.000000Z"


class C3AdoptionCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture = decision_cli_fixture.C3DecisionCliTests
        fixture.setUpClass()
        cls.decision_fixture = fixture
        cls.repo_root = fixture.repo_root
        cls.base_db_path = fixture.base_db_path
        cls.decision_private = fixture.decision_private
        cls.decision_public = fixture.decision_public

    @classmethod
    def tearDownClass(cls) -> None:
        cls.decision_fixture.tearDownClass()

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

    def decision_helper(self) -> decision_cli_fixture.C3DecisionCliTests:
        helper = decision_cli_fixture.C3DecisionCliTests(
            methodName="test_snapshot_admit_get_and_verify_preserve_exact_bytes"
        )
        helper.root = self.root
        helper.db_path = self.db_path
        helper.repo_root = self.repo_root
        helper.env = self.env
        helper.decision_private = self.decision_private
        helper.decision_public = self.decision_public
        return helper

    def establish_signed_selected_decision(self) -> None:
        helper = self.decision_helper()
        payload_path, signature_path, _ = helper.prepare_c3_decision_material()
        admitted = helper.success(helper.admit(payload_path, signature_path))["result"]  # type: ignore[index]
        self.assertEqual(admitted["decision_id"], "decision-cli")  # type: ignore[index]
        self.assertEqual(admitted["verdict"], "C3_CANDIDATE_SELECTED")  # type: ignore[index]

    @staticmethod
    def rollback_plan() -> dict[str, object]:
        return {
            "strategy": "restore the pre-adoption component registry snapshot",
            "steps": [
                "stop the separately authorized execution",
                "restore the previous component registry snapshot",
            ],
            "verification_steps": [
                "verify the previous registry digest",
                "verify STARCOM ledger continuity",
            ],
            "abort_conditions": [
                "rollback digest mismatch",
                "ledger verification failure",
            ],
            "requires_separate_execution_authorization": True,
        }

    def rollback_json(self, plan: dict[str, object] | None = None) -> str:
        return json.dumps(
            plan or self.rollback_plan(),
            sort_keys=True,
            separators=(",", ":"),
        )

    def prepare(self, plan: dict[str, object] | None = None) -> subprocess.CompletedProcess[str]:
        return self.run_cli(
            "adoption",
            "prepare",
            "--c3-run-id",
            "c3-decision-run",
            "--rollback-plan-json",
            self.rollback_json(plan),
        )

    def table_count(self, table: str) -> int:
        with sqlite3.connect(self.db_path) as connection:
            exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                (table,),
            ).fetchone()
            if exists is None:
                return 0
            return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    def add_exact_allow_rule(self, preparation: dict[str, object]) -> None:
        self.success(
            self.run_cli(
                "trust",
                "add-rule",
                "--rule-id",
                "allow-c3-adoption-cli",
                "--effect",
                "ALLOW",
                "--subject",
                "adoption-operator",
                "--action",
                str(preparation["action"]),
                "--resource",
                str(preparation["resource"]),
                "--actor",
                "owner",
                "--occurred-at",
                A6,
            )
        )

    def authorize_request(
        self,
        preparation: dict[str, object],
        *,
        context: dict[str, object] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self.run_cli(
            "trust",
            "authorize",
            "--subject",
            "adoption-operator",
            "--action",
            str(preparation["action"]),
            "--resource",
            str(preparation["resource"]),
            "--mission-id",
            str(preparation["mission_id"]),
            "--context-json",
            json.dumps(
                context or preparation["context"],  # type: ignore[arg-type]
                sort_keys=True,
                separators=(",", ":"),
            ),
            "--at",
            A7,
        )

    def authorize_adoption(
        self,
        decision_id: str,
        *,
        plan: dict[str, object] | None = None,
        actor: str = "adoption-operator",
    ) -> subprocess.CompletedProcess[str]:
        return self.run_cli(
            "adoption",
            "authorize",
            "--adoption-id",
            "adoption-cli",
            "--c3-run-id",
            "c3-decision-run",
            "--authorization-decision-id",
            decision_id,
            "--rollback-plan-json",
            self.rollback_json(plan),
            "--actor",
            actor,
            "--occurred-at",
            A8,
        )

    def test_prepare_is_deterministic_and_has_no_trust_or_adoption_side_effect(self) -> None:
        self.establish_signed_selected_decision()
        trust_before = self.table_count("trust_decisions")
        consumption_before = self.table_count("continuity_authorization_consumptions")

        first = self.success(self.prepare())["result"]  # type: ignore[index]
        second = self.success(self.prepare())["result"]  # type: ignore[index]

        self.assertEqual(first, second)
        self.assertEqual(first["c3_run_id"], "c3-decision-run")  # type: ignore[index]
        self.assertEqual(first["c3_decision_id"], "decision-cli")  # type: ignore[index]
        self.assertEqual(first["candidate_artifact_id"], "candidate-a")  # type: ignore[index]
        self.assertEqual(first["action"], "c3.adoption.authorize")  # type: ignore[index]
        self.assertEqual(
            first["resource"],  # type: ignore[index]
            "continuity:c3:c3-decision-run:adoption:candidate-a",
        )
        self.assertEqual(first["mission_id"], "c3-decision-run")  # type: ignore[index]
        self.assertEqual(
            first["context"]["authorization_mode"],  # type: ignore[index]
            "AUTHORIZE_ONLY_NOT_EXECUTE",
        )
        self.assertEqual(first["rollback_plan"], self.rollback_plan())  # type: ignore[index]
        self.assertEqual(self.table_count("trust_decisions"), trust_before)
        self.assertEqual(
            self.table_count("continuity_authorization_consumptions"),
            consumption_before,
        )
        self.assertEqual(self.table_count("c3_adoptions"), 0)

    def test_default_deny_then_explicit_trust_decision_authorizes_gets_and_verifies(self) -> None:
        self.establish_signed_selected_decision()
        preparation = self.success(self.prepare())["result"]  # type: ignore[index]

        denied = self.authorize_request(preparation)

        self.assertEqual(denied.returncode, 4)
        self.assertFalse(self.decode_stdout(denied)["result"]["allowed"])  # type: ignore[index]
        self.assertEqual(self.table_count("c3_adoptions"), 0)

        self.add_exact_allow_rule(preparation)
        authorization = self.success(self.authorize_request(preparation))["result"]  # type: ignore[index]
        self.assertTrue(authorization["allowed"])  # type: ignore[index]
        authorized = self.success(
            self.authorize_adoption(str(authorization["decision_id"]))  # type: ignore[index]
        )["result"]  # type: ignore[index]

        self.assertEqual(authorized["adoption_id"], "adoption-cli")  # type: ignore[index]
        self.assertEqual(
            authorized["status"],  # type: ignore[index]
            "C3_ADOPTION_AUTHORIZED_NOT_EXECUTED",
        )
        self.assertEqual(authorized["candidate_artifact_id"], "candidate-a")  # type: ignore[index]
        loaded = self.success(
            self.run_cli("adoption", "get", "--adoption-id", "adoption-cli")
        )["result"]  # type: ignore[index]
        self.assertEqual(loaded, authorized)
        verification = self.success(
            self.run_cli("adoption", "verify", "--adoption-id", "adoption-cli")
        )["result"]  # type: ignore[index]
        self.assertTrue(verification["ok"])  # type: ignore[index]
        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute(
                """
                SELECT operation_kind, operation_id FROM continuity_authorization_consumptions
                WHERE decision_id = ?
                """,
                (str(authorization["decision_id"]),),  # type: ignore[index]
            ).fetchone()
        self.assertEqual(row, ("C3_ADOPTION_AUTHORIZED", "adoption-cli"))

    def test_wrong_context_actor_or_rollback_is_rejected_without_adoption(self) -> None:
        self.establish_signed_selected_decision()
        preparation = self.success(self.prepare())["result"]  # type: ignore[index]
        self.add_exact_allow_rule(preparation)
        wrong_context = dict(preparation["context"])  # type: ignore[arg-type]
        wrong_context["rollback_plan_sha256"] = "0" * 64
        authorization = self.success(
            self.authorize_request(preparation, context=wrong_context)
        )["result"]  # type: ignore[index]

        wrong_context_result = self.authorize_adoption(
            str(authorization["decision_id"])  # type: ignore[index]
        )

        self.assertEqual(wrong_context_result.returncode, 2)
        self.assertEqual(
            self.decode_stderr(wrong_context_result)["error"],
            "AUTHORIZATION_ERROR",
        )
        self.assertEqual(self.table_count("c3_adoptions"), 0)
        self.assertEqual(self.table_count("continuity_authorization_consumptions"), 0)

        exact_authorization = self.success(self.authorize_request(preparation))["result"]  # type: ignore[index]
        wrong_actor = self.authorize_adoption(
            str(exact_authorization["decision_id"]),  # type: ignore[index]
            actor="another-operator",
        )
        self.assertEqual(wrong_actor.returncode, 2)
        self.assertEqual(self.decode_stderr(wrong_actor)["error"], "AUTHORIZATION_ERROR")
        self.assertEqual(self.table_count("c3_adoptions"), 0)

        invalid_plan = {
            "strategy": "rollback",
            "steps": ["restore"],
            "verification_steps": ["verify"],
            "abort_conditions": ["mismatch"],
            "requires_separate_execution_authorization": False,
        }
        invalid_rollback = self.run_cli(
            "adoption",
            "prepare",
            "--c3-run-id",
            "c3-decision-run",
            "--rollback-plan-json",
            self.rollback_json(invalid_plan),
        )
        self.assertEqual(invalid_rollback.returncode, 2)
        self.assertEqual(
            self.decode_stderr(invalid_rollback)["error"],
            "VALIDATION_ERROR",
        )
        self.assertEqual(self.table_count("c3_adoptions"), 0)

    def test_no_execution_subcommand_is_exposed(self) -> None:
        for command in ("execute", "install", "enable", "deploy", "run"):
            with self.subTest(command=command):
                rejected = self.run_cli("adoption", command)
                self.assertEqual(rejected.returncode, 2)
                error = self.decode_stderr(rejected)
                self.assertEqual(error["error"], "VALIDATION_ERROR")
                self.assertIn("invalid choice", str(error["details"]))
                self.assertNotIn(f"'{command}'", str(error["details"]).split("choose from", 1)[-1])


if __name__ == "__main__":
    unittest.main()
