from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest


T0 = "2026-08-14T17:00:00.000000Z"
T1 = "2026-08-14T17:01:00.000000Z"
T2 = "2026-08-14T17:02:00.000000Z"
T3 = "2026-08-14T17:03:00.000000Z"
T4 = "2026-08-14T17:04:00.000000Z"
T5 = "2026-08-14T17:05:00.000000Z"
T6 = "2026-08-14T17:06:00.000000Z"
T7 = "2026-08-14T17:07:00.000000Z"
T8 = "2026-08-14T17:08:00.000000Z"
T9 = "2026-08-14T17:09:00.000000Z"
T10 = "2026-08-14T17:10:00.000000Z"
T11 = "2026-08-14T17:11:00.000000Z"
T12 = "2026-08-14T17:12:00.000000Z"
IMPLEMENTATION_DIGEST = "1" * 64
ARTIFACT_DIGEST = "2" * 64
REPORT_DIGEST = "3" * 64
TEST_SUITE_DIGEST = "4" * 64


class C3ExecutorRegistryCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.db_path = self.root / "starcom.sqlite3"
        self.repo_root = Path(__file__).resolve().parents[1]
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = str(self.repo_root / "src")
        self.private_key = self.root / "qualifier-private.pem"
        self.public_key = self.root / "qualifier-public.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(self.private_key),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(self.private_key),
                "-pubout",
                "-out",
                str(self.public_key),
            ],
            check=True,
            capture_output=True,
        )

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

    def table_count(self, table: str) -> int:
        if not self.db_path.exists():
            return 0
        with sqlite3.connect(self.db_path) as connection:
            exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                (table,),
            ).fetchone()
            if exists is None:
                return 0
            return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    @staticmethod
    def descriptor() -> dict[str, object]:
        return {
            "executor_id": "cli-fake-executor",
            "implementation_name": "CLI deterministic fake executor",
            "implementation_version": "1.0.0",
            "implementation_digest": IMPLEMENTATION_DIGEST,
            "artifact_digest": ARTIFACT_DIGEST,
            "entrypoint": "tests.cli_fake:Executor",
            "supported_sandbox_profiles": ["starcom-c3-default-deny-v1"],
            "network_mode": "DENY",
            "capabilities": ["apply", "rollback"],
        }

    def descriptor_json(self, descriptor: dict[str, object] | None = None) -> str:
        return json.dumps(
            descriptor or self.descriptor(),
            sort_keys=True,
            separators=(",", ":"),
        )

    def prepare_register(self) -> subprocess.CompletedProcess[str]:
        return self.run_cli(
            "executor-registry",
            "prepare-register",
            "--descriptor-json",
            self.descriptor_json(),
        )

    def authorize_preparation(
        self,
        preparation: dict[str, object],
        *,
        subject: str,
        rule_id: str,
        occurred_at: str,
        decided_at: str,
        context: dict[str, object] | None = None,
    ) -> dict[str, object]:
        self.success(
            self.run_cli(
                "trust",
                "add-rule",
                "--rule-id",
                rule_id,
                "--effect",
                "ALLOW",
                "--subject",
                subject,
                "--action",
                str(preparation["action"]),
                "--resource",
                str(preparation["resource"]),
                "--actor",
                "owner",
                "--occurred-at",
                occurred_at,
            )
        )
        return self.success(
            self.run_cli(
                "trust",
                "authorize",
                "--subject",
                subject,
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
                decided_at,
            )
        )["result"]  # type: ignore[index]

    def register_executor(self) -> dict[str, object]:
        preparation = self.success(self.prepare_register())["result"]  # type: ignore[index]
        decision = self.authorize_preparation(
            preparation,  # type: ignore[arg-type]
            subject="registry-operator",
            rule_id="allow-cli-register",
            occurred_at=T0,
            decided_at=T1,
        )
        return self.success(
            self.run_cli(
                "executor-registry",
                "register",
                "--descriptor-json",
                self.descriptor_json(),
                "--authorization-decision-id",
                str(decision["decision_id"]),
                "--actor",
                "registry-operator",
                "--occurred-at",
                T2,
            )
        )["result"]  # type: ignore[index]

    def accept_qualifier_root(self) -> dict[str, object]:
        preparation = self.success(
            self.run_cli(
                "executor-registry",
                "prepare-qualifier-root",
                "--key-id",
                "cli-qualifier-key",
                "--public-key-file",
                str(self.public_key),
            )
        )["result"]  # type: ignore[index]
        decision = self.authorize_preparation(
            preparation,  # type: ignore[arg-type]
            subject="root-owner",
            rule_id="allow-cli-qualifier-root",
            occurred_at=T2,
            decided_at=T3,
        )
        return self.success(
            self.run_cli(
                "executor-registry",
                "accept-qualifier-root",
                "--key-id",
                "cli-qualifier-key",
                "--public-key-file",
                str(self.public_key),
                "--authorization-decision-id",
                str(decision["decision_id"]),
                "--actor",
                "root-owner",
                "--occurred-at",
                T4,
            )
        )["result"]  # type: ignore[index]

    def qualification_payload(self, descriptor_digest: str) -> bytes:
        value = {
            "qualification_id": "cli-qualification",
            "executor_id": "cli-fake-executor",
            "descriptor_digest": descriptor_digest,
            "report_digest": REPORT_DIGEST,
            "test_suite_digest": TEST_SUITE_DIGEST,
            "reviewer_identity": "independent-cli-reviewer",
            "reviewer_environment": "isolated-cli-review-vm",
            "independence_basis": "separate process, key and workspace",
            "sandbox_profiles_tested": ["starcom-c3-default-deny-v1"],
            "network_mode_tested": "DENY",
            "verdict": "QUALIFIED",
            "qualified_at": T5,
            "gate_effect": "QUALIFIED_DISABLED_NO_ENABLEMENT",
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def write_signed_payload(self, descriptor_digest: str) -> tuple[Path, Path]:
        payload_path = self.root / "qualification.json"
        signature_path = self.root / "qualification.sig"
        payload_path.write_bytes(self.qualification_payload(descriptor_digest))
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(self.private_key),
                "-rawin",
                "-in",
                str(payload_path),
                "-out",
                str(signature_path),
            ],
            check=True,
            capture_output=True,
        )
        return payload_path, signature_path

    def qualify_executor(self, descriptor_digest: str) -> dict[str, object]:
        payload_path, signature_path = self.write_signed_payload(descriptor_digest)
        preparation = self.success(
            self.run_cli(
                "executor-registry",
                "prepare-qualify",
                "--executor-id",
                "cli-fake-executor",
                "--key-id",
                "cli-qualifier-key",
                "--payload-file",
                str(payload_path),
                "--signature-file",
                str(signature_path),
            )
        )["result"]  # type: ignore[index]
        decision = self.authorize_preparation(
            preparation,  # type: ignore[arg-type]
            subject="qualification-admitter",
            rule_id="allow-cli-qualification",
            occurred_at=T5,
            decided_at=T6,
        )
        result = self.success(
            self.run_cli(
                "executor-registry",
                "qualify",
                "--executor-id",
                "cli-fake-executor",
                "--key-id",
                "cli-qualifier-key",
                "--payload-file",
                str(payload_path),
                "--signature-file",
                str(signature_path),
                "--authorization-decision-id",
                str(decision["decision_id"]),
                "--actor",
                "qualification-admitter",
                "--occurred-at",
                T7,
            )
        )["result"]  # type: ignore[index]
        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute(
                "SELECT payload, signature FROM c3_executor_qualifications WHERE executor_id = ?",
                ("cli-fake-executor",),
            ).fetchone()
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(bytes(row[0]), payload_path.read_bytes())
        self.assertEqual(bytes(row[1]), signature_path.read_bytes())
        return result  # type: ignore[return-value]

    def enable_executor(self) -> dict[str, object]:
        preparation = self.success(
            self.run_cli(
                "executor-registry",
                "prepare-enable",
                "--executor-id",
                "cli-fake-executor",
            )
        )["result"]  # type: ignore[index]
        decision = self.authorize_preparation(
            preparation,  # type: ignore[arg-type]
            subject="executor-enabler",
            rule_id="allow-cli-enable",
            occurred_at=T7,
            decided_at=T8,
        )
        return self.success(
            self.run_cli(
                "executor-registry",
                "enable",
                "--executor-id",
                "cli-fake-executor",
                "--authorization-decision-id",
                str(decision["decision_id"]),
                "--actor",
                "executor-enabler",
                "--occurred-at",
                T9,
            )
        )["result"]  # type: ignore[index]

    def establish_enabled_executor(self) -> dict[str, object]:
        descriptor = self.register_executor()
        self.accept_qualifier_root()
        self.qualify_executor(str(descriptor["descriptor_digest"]))
        return self.enable_executor()

    def test_prepare_registration_is_deterministic_and_side_effect_free(self) -> None:
        decisions_before = self.table_count("trust_decisions")
        consumptions_before = self.table_count("continuity_authorization_consumptions")

        first = self.success(self.prepare_register())["result"]  # type: ignore[index]
        second = self.success(self.prepare_register())["result"]  # type: ignore[index]

        self.assertEqual(first, second)
        self.assertEqual(first["operation"], "REGISTER")  # type: ignore[index]
        self.assertEqual(first["action"], "c3.executor.register")  # type: ignore[index]
        self.assertEqual(first["executor_id"], "cli-fake-executor")  # type: ignore[index]
        self.assertEqual(self.table_count("trust_decisions"), decisions_before)
        self.assertEqual(
            self.table_count("continuity_authorization_consumptions"),
            consumptions_before,
        )
        self.assertEqual(self.table_count("c3_executor_descriptors"), 0)
        self.assertEqual(self.table_count("c3_executor_transitions"), 0)

    def test_default_deny_then_explicit_registration_stays_disabled(self) -> None:
        preparation = self.success(self.prepare_register())["result"]  # type: ignore[index]
        denied = self.run_cli(
            "trust",
            "authorize",
            "--subject",
            "registry-operator",
            "--action",
            str(preparation["action"]),  # type: ignore[index]
            "--resource",
            str(preparation["resource"]),  # type: ignore[index]
            "--mission-id",
            str(preparation["mission_id"]),  # type: ignore[index]
            "--context-json",
            json.dumps(
                preparation["context"],  # type: ignore[arg-type,index]
                sort_keys=True,
                separators=(",", ":"),
            ),
            "--at",
            T1,
        )
        self.assertEqual(denied.returncode, 4)
        denied_id = str(self.decode_stdout(denied)["result"]["decision_id"])  # type: ignore[index]
        rejected = self.run_cli(
            "executor-registry",
            "register",
            "--descriptor-json",
            self.descriptor_json(),
            "--authorization-decision-id",
            denied_id,
            "--actor",
            "registry-operator",
            "--occurred-at",
            T2,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(self.decode_stderr(rejected)["error"], "AUTHORIZATION_DENIED")
        self.assertEqual(self.table_count("c3_executor_descriptors"), 0)

        descriptor = self.register_executor()
        loaded = self.success(
            self.run_cli(
                "executor-registry",
                "get",
                "--executor-id",
                "cli-fake-executor",
            )
        )["result"]  # type: ignore[index]
        self.assertEqual(loaded["descriptor"], descriptor)  # type: ignore[index]
        self.assertEqual(
            loaded["current"]["state"],  # type: ignore[index]
            "C3_EXECUTOR_REGISTERED_DISABLED",
        )
        verification = self.success(
            self.run_cli(
                "executor-registry",
                "verify",
                "--executor-id",
                "cli-fake-executor",
            )
        )["result"]  # type: ignore[index]
        self.assertTrue(verification["ok"])  # type: ignore[index]
        attestation = self.run_cli(
            "executor-registry",
            "attest",
            "--executor-id",
            "cli-fake-executor",
            "--implementation-version",
            "1.0.0",
            "--implementation-digest",
            IMPLEMENTATION_DIGEST,
            "--sandbox-profile",
            "starcom-c3-default-deny-v1",
        )
        self.assertEqual(attestation.returncode, 2)
        self.assertEqual(
            self.decode_stderr(attestation)["error"],
            "INVALID_STATE_TRANSITION",
        )

    def test_exact_byte_files_and_key_substitution_are_fail_closed(self) -> None:
        missing_key = self.run_cli(
            "executor-registry",
            "prepare-qualifier-root",
            "--key-id",
            "missing-key",
            "--public-key-file",
            str(self.root / "missing.pem"),
        )
        self.assertEqual(missing_key.returncode, 2)
        self.assertEqual(self.decode_stderr(missing_key)["error"], "VALIDATION_ERROR")
        self.assertEqual(
            self.decode_stderr(missing_key)["message"],
            "public_key_file could not be read",
        )
        missing_payload = self.run_cli(
            "executor-registry",
            "prepare-qualify",
            "--executor-id",
            "missing-executor",
            "--key-id",
            "missing-key",
            "--payload-file",
            str(self.root / "missing.json"),
            "--signature-file",
            str(self.public_key),
        )
        self.assertEqual(missing_payload.returncode, 2)
        self.assertEqual(
            self.decode_stderr(missing_payload)["message"],
            "payload_file could not be read",
        )
        missing_signature = self.run_cli(
            "executor-registry",
            "prepare-qualify",
            "--executor-id",
            "missing-executor",
            "--key-id",
            "missing-key",
            "--payload-file",
            str(self.public_key),
            "--signature-file",
            str(self.root / "missing.sig"),
        )
        self.assertEqual(missing_signature.returncode, 2)
        self.assertEqual(
            self.decode_stderr(missing_signature)["message"],
            "signature_file could not be read",
        )

        root = self.accept_qualifier_root()
        substitute_private = self.root / "substitute-private.pem"
        substitute_public = self.root / "substitute-public.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(substitute_private),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(substitute_private),
                "-pubout",
                "-out",
                str(substitute_public),
            ],
            check=True,
            capture_output=True,
        )
        substituted = self.run_cli(
            "executor-registry",
            "accept-qualifier-root",
            "--key-id",
            "cli-qualifier-key",
            "--public-key-file",
            str(substitute_public),
            "--authorization-decision-id",
            str(root["authorization_decision_id"]),
            "--actor",
            "root-owner",
            "--occurred-at",
            T5,
        )
        self.assertEqual(substituted.returncode, 2)
        self.assertEqual(self.decode_stderr(substituted)["error"], "CONFLICT")
        self.assertEqual(self.table_count("c3_executor_qualifier_roots"), 1)

    def test_exact_signed_qualification_remains_disabled_then_enable_attests(self) -> None:
        descriptor = self.register_executor()
        self.accept_qualifier_root()
        qualification = self.qualify_executor(str(descriptor["descriptor_digest"]))
        self.assertEqual(qualification["qualification_id"], "cli-qualification")
        loaded = self.success(
            self.run_cli(
                "executor-registry",
                "get",
                "--executor-id",
                "cli-fake-executor",
            )
        )["result"]  # type: ignore[index]
        self.assertEqual(
            loaded["current"]["state"],  # type: ignore[index]
            "C3_EXECUTOR_QUALIFIED_DISABLED",
        )
        disabled_attestation = self.run_cli(
            "executor-registry",
            "attest",
            "--executor-id",
            "cli-fake-executor",
            "--implementation-version",
            "1.0.0",
            "--implementation-digest",
            IMPLEMENTATION_DIGEST,
            "--sandbox-profile",
            "starcom-c3-default-deny-v1",
        )
        self.assertEqual(disabled_attestation.returncode, 2)

        current = self.enable_executor()
        self.assertEqual(current["state"], "C3_EXECUTOR_ENABLED")
        attestation = self.success(
            self.run_cli(
                "executor-registry",
                "attest",
                "--executor-id",
                "cli-fake-executor",
                "--implementation-version",
                "1.0.0",
                "--implementation-digest",
                IMPLEMENTATION_DIGEST,
                "--sandbox-profile",
                "starcom-c3-default-deny-v1",
            )
        )["result"]  # type: ignore[index]
        self.assertEqual(attestation["state"], "C3_EXECUTOR_ENABLED")  # type: ignore[index]
        self.assertEqual(len(str(attestation["registry_head_hash"])), 64)  # type: ignore[index]

    def test_whitespace_modified_payload_with_original_signature_is_rejected(self) -> None:
        descriptor = self.register_executor()
        self.accept_qualifier_root()
        payload_path, signature_path = self.write_signed_payload(
            str(descriptor["descriptor_digest"])
        )
        tampered_path = self.root / "qualification-tampered.json"
        tampered_path.write_bytes(payload_path.read_bytes() + b" ")

        rejected = self.run_cli(
            "executor-registry",
            "prepare-qualify",
            "--executor-id",
            "cli-fake-executor",
            "--key-id",
            "cli-qualifier-key",
            "--payload-file",
            str(tampered_path),
            "--signature-file",
            str(signature_path),
        )

        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(self.decode_stderr(rejected)["error"], "INTEGRITY_ERROR")
        self.assertEqual(self.table_count("c3_executor_qualifications"), 0)
        exact = self.success(
            self.run_cli(
                "executor-registry",
                "prepare-qualify",
                "--executor-id",
                "cli-fake-executor",
                "--key-id",
                "cli-qualifier-key",
                "--payload-file",
                str(payload_path),
                "--signature-file",
                str(signature_path),
            )
        )["result"]  # type: ignore[index]
        self.assertEqual(exact["operation"], "QUALIFY")  # type: ignore[index]

    def test_revoke_is_separate_terminal_idempotent_and_blocks_attestation(self) -> None:
        self.establish_enabled_executor()
        preparation = self.success(
            self.run_cli(
                "executor-registry",
                "prepare-revoke",
                "--executor-id",
                "cli-fake-executor",
                "--reason",
                "CLI terminal revocation fixture",
            )
        )["result"]  # type: ignore[index]
        decision = self.authorize_preparation(
            preparation,  # type: ignore[arg-type]
            subject="security-owner",
            rule_id="allow-cli-revoke",
            occurred_at=T9,
            decided_at=T10,
        )
        command = (
            "executor-registry",
            "revoke",
            "--executor-id",
            "cli-fake-executor",
            "--reason",
            "CLI terminal revocation fixture",
            "--authorization-decision-id",
            str(decision["decision_id"]),
            "--actor",
            "security-owner",
            "--occurred-at",
            T11,
        )
        first = self.success(self.run_cli(*command))["result"]  # type: ignore[index]
        replay = self.success(self.run_cli(*command[:-1], T12))["result"]  # type: ignore[index]
        self.assertEqual(first, replay)
        self.assertEqual(first["state"], "C3_EXECUTOR_REVOKED")  # type: ignore[index]
        attestation = self.run_cli(
            "executor-registry",
            "attest",
            "--executor-id",
            "cli-fake-executor",
            "--implementation-version",
            "1.0.0",
            "--implementation-digest",
            IMPLEMENTATION_DIGEST,
            "--sandbox-profile",
            "starcom-c3-default-deny-v1",
        )
        self.assertEqual(attestation.returncode, 2)
        enable = self.run_cli(
            "executor-registry",
            "prepare-enable",
            "--executor-id",
            "cli-fake-executor",
        )
        self.assertEqual(enable.returncode, 2)
        verification = self.success(
            self.run_cli(
                "executor-registry",
                "verify",
                "--executor-id",
                "cli-fake-executor",
            )
        )["result"]  # type: ignore[index]
        self.assertTrue(verification["ok"])  # type: ignore[index]

    def test_wrong_context_actor_and_cross_operation_reuse_write_nothing(self) -> None:
        preparation = self.success(self.prepare_register())["result"]  # type: ignore[index]
        self.success(
            self.run_cli(
                "trust",
                "add-rule",
                "--rule-id",
                "allow-cli-register",
                "--effect",
                "ALLOW",
                "--subject",
                "registry-operator",
                "--action",
                str(preparation["action"]),  # type: ignore[index]
                "--resource",
                str(preparation["resource"]),  # type: ignore[index]
                "--actor",
                "owner",
                "--occurred-at",
                T0,
            )
        )
        wrong_context = dict(preparation["context"])  # type: ignore[arg-type,index]
        wrong_context["descriptor_digest"] = "0" * 64
        wrong_decision = self.success(
            self.run_cli(
                "trust",
                "authorize",
                "--subject",
                "registry-operator",
                "--action",
                str(preparation["action"]),  # type: ignore[index]
                "--resource",
                str(preparation["resource"]),  # type: ignore[index]
                "--mission-id",
                str(preparation["mission_id"]),  # type: ignore[index]
                "--context-json",
                json.dumps(wrong_context, sort_keys=True, separators=(",", ":")),
                "--at",
                T1,
            )
        )["result"]  # type: ignore[index]
        wrong_context_result = self.run_cli(
            "executor-registry",
            "register",
            "--descriptor-json",
            self.descriptor_json(),
            "--authorization-decision-id",
            str(wrong_decision["decision_id"]),
            "--actor",
            "registry-operator",
            "--occurred-at",
            T2,
        )
        self.assertEqual(wrong_context_result.returncode, 2)
        self.assertEqual(self.table_count("c3_executor_descriptors"), 0)

        exact_decision = self.success(
            self.run_cli(
                "trust",
                "authorize",
                "--subject",
                "registry-operator",
                "--action",
                str(preparation["action"]),  # type: ignore[index]
                "--resource",
                str(preparation["resource"]),  # type: ignore[index]
                "--mission-id",
                str(preparation["mission_id"]),  # type: ignore[index]
                "--context-json",
                json.dumps(
                    preparation["context"],  # type: ignore[arg-type,index]
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                "--at",
                T1,
            )
        )["result"]  # type: ignore[index]
        wrong_actor = self.run_cli(
            "executor-registry",
            "register",
            "--descriptor-json",
            self.descriptor_json(),
            "--authorization-decision-id",
            str(exact_decision["decision_id"]),
            "--actor",
            "different-operator",
            "--occurred-at",
            T2,
        )
        self.assertEqual(wrong_actor.returncode, 2)
        self.assertEqual(self.table_count("c3_executor_descriptors"), 0)

        registered = self.success(
            self.run_cli(
                "executor-registry",
                "register",
                "--descriptor-json",
                self.descriptor_json(),
                "--authorization-decision-id",
                str(exact_decision["decision_id"]),
                "--actor",
                "registry-operator",
                "--occurred-at",
                T2,
            )
        )["result"]  # type: ignore[index]
        self.assertEqual(registered["executor_id"], "cli-fake-executor")  # type: ignore[index]
        reused = self.run_cli(
            "executor-registry",
            "accept-qualifier-root",
            "--key-id",
            "cli-qualifier-key",
            "--public-key-file",
            str(self.public_key),
            "--authorization-decision-id",
            str(exact_decision["decision_id"]),
            "--actor",
            "registry-operator",
            "--occurred-at",
            T3,
        )
        self.assertEqual(reused.returncode, 2)
        self.assertEqual(self.table_count("c3_executor_qualifier_roots"), 0)

    def test_no_worker_or_execution_subcommand_is_exposed(self) -> None:
        forbidden = ("worker", "process", "execute", "run", "install", "deploy")
        for command in forbidden:
            with self.subTest(command=command):
                result = self.run_cli("executor-registry", command)
                self.assertEqual(result.returncode, 2)
                error = self.decode_stderr(result)
                self.assertEqual(error["error"], "VALIDATION_ERROR")
                choices = str(error["details"]).split("choose from", 1)[-1]
                self.assertNotIn(f"'{command}'", choices)


if __name__ == "__main__":
    unittest.main()
