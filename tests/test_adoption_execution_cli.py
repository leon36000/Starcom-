from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

import test_adoption_execution as execution_fixture


X0 = "2026-08-14T14:00:00.000000Z"
X1 = "2026-08-14T14:01:00.000000Z"
X2 = "2026-08-14T14:02:00.000000Z"


class C3AdoptionExecutionCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture = execution_fixture.C3AdoptionExecutionTests
        fixture.setUpClass()
        cls.execution_fixture = fixture
        cls.repo_root = fixture.repo_root
        cls.execution_base_db = fixture.execution_base_db

    @classmethod
    def tearDownClass(cls) -> None:
        cls.execution_fixture.tearDownClass()

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.db_path = self.root / "starcom.sqlite3"
        execution_fixture.copy_database(self.execution_base_db, self.db_path)
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

    @staticmethod
    def plan() -> dict[str, object]:
        return {
            "component_ref": "candidate-a@sha256:immutable",
            "source_digest": "a" * 64,
            "target_environment": "isolated-c3-sandbox",
            "sandbox_profile": "starcom-c3-default-deny-v1",
            "preconditions": [
                "signed decision remains clean",
                "adoption authorization remains clean",
            ],
            "postconditions": [
                "component registry digest matches expected state",
                "STARCOM ledgers verify",
            ],
            "requires_network": False,
            "network_allowlist": [],
            "requires_separate_rollback_authorization": False,
        }

    def plan_json(self, plan: dict[str, object] | None = None) -> str:
        return json.dumps(
            plan or self.plan(),
            sort_keys=True,
            separators=(",", ":"),
        )

    def prepare(self, plan: dict[str, object] | None = None) -> subprocess.CompletedProcess[str]:
        return self.run_cli(
            "adoption-execution",
            "prepare",
            "--execution-id",
            "execution-cli",
            "--adoption-id",
            "adoption-cli",
            "--executor-id",
            "disabled",
            "--execution-plan-json",
            self.plan_json(plan),
        )

    def request(
        self,
        decision_id: str,
        plan: dict[str, object] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self.run_cli(
            "adoption-execution",
            "request",
            "--execution-id",
            "execution-cli",
            "--adoption-id",
            "adoption-cli",
            "--executor-id",
            "disabled",
            "--execution-plan-json",
            self.plan_json(plan),
            "--authorization-decision-id",
            decision_id,
            "--actor",
            "execution-operator",
            "--occurred-at",
            X2,
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

    def add_allow_rule(self, preparation: dict[str, object]) -> None:
        self.success(
            self.run_cli(
                "trust",
                "add-rule",
                "--rule-id",
                "allow-c3-execution-cli",
                "--effect",
                "ALLOW",
                "--subject",
                "execution-operator",
                "--action",
                str(preparation["action"]),
                "--resource",
                str(preparation["resource"]),
                "--actor",
                "owner",
                "--occurred-at",
                X0,
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
            "execution-operator",
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
            X1,
        )

    def test_prepare_is_deterministic_and_side_effect_free(self) -> None:
        decisions_before = self.table_count("trust_decisions")
        consumptions_before = self.table_count("continuity_authorization_consumptions")
        effects_before = self.table_count("durable_effects")

        first = self.success(self.prepare())["result"]  # type: ignore[index]
        second = self.success(self.prepare())["result"]  # type: ignore[index]

        self.assertEqual(first, second)
        self.assertEqual(first["execution_id"], "execution-cli")  # type: ignore[index]
        self.assertEqual(first["adoption_id"], "adoption-cli")  # type: ignore[index]
        self.assertEqual(first["executor_id"], "disabled")  # type: ignore[index]
        self.assertEqual(first["action"], "c3.adoption.execute")  # type: ignore[index]
        self.assertEqual(
            first["resource"],  # type: ignore[index]
            "continuity:c3:c3-decision-run:adoption:adoption-cli:execution:candidate-a",
        )
        self.assertEqual(first["mission_id"], "c3-decision-run")  # type: ignore[index]
        self.assertEqual(
            first["context"]["execution_mode"],  # type: ignore[index]
            "DURABLE_OUTBOX_SEPARATE_WORKER",
        )
        self.assertEqual(
            first["outbox_effect_id"],  # type: ignore[index]
            "c3-adoption-execution:execution-cli",
        )
        self.assertEqual(self.table_count("trust_decisions"), decisions_before)
        self.assertEqual(
            self.table_count("continuity_authorization_consumptions"),
            consumptions_before,
        )
        self.assertEqual(self.table_count("durable_effects"), effects_before)
        self.assertEqual(self.table_count("c3_adoption_execution_requests"), 0)

    def test_default_deny_then_exact_decision_requests_gets_and_verifies(self) -> None:
        preparation = self.success(self.prepare())["result"]  # type: ignore[index]
        denied = self.authorize_request(preparation)

        self.assertEqual(denied.returncode, 4)
        self.assertFalse(self.decode_stdout(denied)["result"]["allowed"])  # type: ignore[index]
        self.assertEqual(self.table_count("c3_adoption_execution_requests"), 0)

        self.add_allow_rule(preparation)
        authorization = self.success(self.authorize_request(preparation))["result"]  # type: ignore[index]
        self.assertTrue(authorization["allowed"])  # type: ignore[index]
        requested = self.success(
            self.request(str(authorization["decision_id"]))  # type: ignore[index]
        )["result"]  # type: ignore[index]

        self.assertEqual(
            requested["status"],  # type: ignore[index]
            "C3_ADOPTION_EXECUTION_REQUESTED_NOT_EXECUTED",
        )
        replay = self.success(
            self.request(str(authorization["decision_id"]))  # type: ignore[index]
        )["result"]  # type: ignore[index]
        self.assertEqual(replay, requested)
        loaded = self.success(
            self.run_cli(
                "adoption-execution",
                "get",
                "--execution-id",
                "execution-cli",
            )
        )["result"]  # type: ignore[index]
        self.assertEqual(loaded, requested)
        verification = self.success(
            self.run_cli(
                "adoption-execution",
                "verify",
                "--execution-id",
                "execution-cli",
            )
        )["result"]  # type: ignore[index]
        self.assertTrue(verification["ok"])  # type: ignore[index]
        with sqlite3.connect(self.db_path) as connection:
            consumption = connection.execute(
                """
                SELECT operation_kind, operation_id
                FROM continuity_authorization_consumptions
                WHERE decision_id = ?
                """,
                (str(authorization["decision_id"]),),  # type: ignore[index]
            ).fetchone()
            effect = connection.execute(
                """
                SELECT topic, status FROM durable_effects WHERE effect_id = ?
                """,
                ("c3-adoption-execution:execution-cli",),
            ).fetchone()
        self.assertEqual(
            consumption,
            ("C3_ADOPTION_EXECUTION_REQUESTED", "execution-cli"),
        )
        self.assertEqual(effect, ("c3.adoption.execute", "PENDING"))

    def test_wrong_context_changed_or_invalid_plan_is_rejected_without_request(self) -> None:
        preparation = self.success(self.prepare())["result"]  # type: ignore[index]
        self.add_allow_rule(preparation)
        consumption_before = self.table_count("continuity_authorization_consumptions")
        wrong_context = dict(preparation["context"])  # type: ignore[arg-type]
        wrong_context["execution_plan_sha256"] = "0" * 64
        wrong_authorization = self.success(
            self.authorize_request(preparation, context=wrong_context)
        )["result"]  # type: ignore[index]

        wrong_context_result = self.request(
            str(wrong_authorization["decision_id"])  # type: ignore[index]
        )

        self.assertEqual(wrong_context_result.returncode, 2)
        self.assertEqual(
            self.decode_stderr(wrong_context_result)["error"],
            "AUTHORIZATION_DENIED",
        )
        self.assertEqual(self.table_count("c3_adoption_execution_requests"), 0)
        self.assertEqual(self.table_count("durable_effects"), 0)
        self.assertEqual(
            self.table_count("continuity_authorization_consumptions"),
            consumption_before,
        )

        exact_authorization = self.success(self.authorize_request(preparation))["result"]  # type: ignore[index]
        changed = dict(self.plan())
        changed["target_environment"] = "different-sandbox"
        changed_result = self.request(
            str(exact_authorization["decision_id"]),  # type: ignore[index]
            changed,
        )
        self.assertEqual(changed_result.returncode, 2)
        self.assertEqual(
            self.decode_stderr(changed_result)["error"],
            "AUTHORIZATION_DENIED",
        )
        self.assertEqual(self.table_count("c3_adoption_execution_requests"), 0)
        self.assertEqual(
            self.table_count("continuity_authorization_consumptions"),
            consumption_before,
        )

        invalid = dict(self.plan())
        invalid["network_allowlist"] = ["api.example.invalid"]
        invalid_result = self.prepare(invalid)
        self.assertEqual(invalid_result.returncode, 2)
        self.assertEqual(
            self.decode_stderr(invalid_result)["error"],
            "VALIDATION_ERROR",
        )
        self.assertEqual(self.table_count("c3_adoption_execution_requests"), 0)

    def test_no_worker_or_execution_subcommand_is_exposed(self) -> None:
        forbidden = ("process", "worker", "execute", "run", "install", "deploy")
        for command in forbidden:
            with self.subTest(command=command):
                result = self.run_cli("adoption-execution", command)
                self.assertEqual(result.returncode, 2)
                error = self.decode_stderr(result)
                self.assertEqual(error["error"], "VALIDATION_ERROR")
                choices = str(error["details"]).split("choose from", 1)[-1]
                self.assertNotIn(f"'{command}'", choices)


if __name__ == "__main__":
    unittest.main()
