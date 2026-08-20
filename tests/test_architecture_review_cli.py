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

import test_adoption_execution as execution_fixture

from starcom.adoption_execution import C3AdoptionExecutionWorker
from starcom.cli import Runtime
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule


C0 = "2026-08-14T14:00:00.000000Z"
C1 = "2026-08-14T14:01:00.000000Z"
C2 = "2026-08-14T14:02:00.000000Z"
C3 = "2026-08-14T14:03:00.000000Z"
C4 = "2026-08-14T14:04:00.000000Z"
C5 = "2026-08-14T14:05:00.000000Z"
C6 = "2026-08-14T14:06:00.000000Z"
C7 = "2026-08-14T14:07:00.000000Z"
C8 = "2026-08-14T14:08:00.000000Z"
C9 = "2026-08-14T14:09:00.000000Z"
C10 = "2026-08-14T14:10:00.000000Z"
C11 = "2026-08-14T14:11:00.000000Z"
C12 = "2026-08-14T14:12:00.000000Z"


class ArchitectureReviewCliMixin:
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
    def stdout_payload(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        if not result.stdout.strip():
            raise AssertionError(result.stderr)
        return json.loads(result.stdout)

    @staticmethod
    def stderr_payload(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        if not result.stderr.strip():
            raise AssertionError(result.stdout)
        return json.loads(result.stderr)

    def success(self, result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        self.assertEqual(result.returncode, 0, result.stderr)
        return self.stdout_payload(result)

    def generate_keys(self) -> None:
        self.private_key = self.root / "reviewer-private.pem"
        self.public_key = self.root / "reviewer-public.pem"
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

    def sign(self, payload_path: Path, signature_path: Path) -> None:
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(self.private_key),
                "-in",
                str(payload_path),
                "-out",
                str(signature_path),
            ],
            check=True,
            capture_output=True,
        )


class ArchitectureReviewCliSurfaceTests(
    ArchitectureReviewCliMixin,
    unittest.TestCase,
):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.db_path = self.root / "starcom.sqlite3"
        self.repo_root = Path(__file__).resolve().parents[1]
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = str(self.repo_root / "src")
        self.generate_keys()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_architecture_review_command_surface_is_non_publishing(self) -> None:
        help_result = self.run_cli("architecture-review", "--help")
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        for command in (
            "prepare-reviewer-root",
            "accept-reviewer-root",
            "admit",
            "get",
            "verify-root",
            "verify",
        ):
            self.assertIn(command, help_result.stdout)

        for forbidden in ("publish", "deploy", "execute", "install", "run"):
            with self.subTest(forbidden=forbidden):
                rejected = self.run_cli("architecture-review", forbidden)
                self.assertEqual(rejected.returncode, 2)
                error = self.stderr_payload(rejected)
                self.assertEqual(error["error"], "VALIDATION_ERROR")
                self.assertNotIn(
                    f"'{forbidden}'",
                    str(error.get("details", {})).split("choose from", 1)[-1],
                )

    def test_prepare_and_accept_root_keep_default_deny_and_return_clean_verify(self) -> None:
        prepared = self.success(
            self.run_cli(
                "architecture-review",
                "prepare-reviewer-root",
                "--key-id",
                "review-key",
                "--reviewer-identity",
                "independent-cli-reviewer",
                "--public-key-file",
                str(self.public_key),
            )
        )["result"]
        self.assertEqual(prepared["action"], "c4.architecture-reviewer.accept")  # type: ignore[index]
        self.assertEqual(  # type: ignore[index]
            prepared["fingerprint_sha256"],
            hashlib.sha256(self.public_key.read_bytes()).hexdigest(),
        )

        denied = self.run_cli(
            "trust",
            "authorize",
            "--subject",
            "root-owner",
            "--action",
            str(prepared["action"]),  # type: ignore[index]
            "--resource",
            str(prepared["resource"]),  # type: ignore[index]
            "--mission-id",
            str(prepared["mission_id"]),  # type: ignore[index]
            "--context-json",
            json.dumps(prepared["context"], sort_keys=True, separators=(",", ":")),  # type: ignore[index]
            "--at",
            C1,
        )
        self.assertEqual(denied.returncode, 4)
        denied_decision = self.stdout_payload(denied)["result"]
        self.assertFalse(denied_decision["allowed"])  # type: ignore[index]

        rejected = self.run_cli(
            "architecture-review",
            "accept-reviewer-root",
            "--key-id",
            "review-key",
            "--reviewer-identity",
            "independent-cli-reviewer",
            "--public-key-file",
            str(self.public_key),
            "--authorization-decision-id",
            str(denied_decision["decision_id"]),  # type: ignore[index]
            "--actor",
            "root-owner",
            "--occurred-at",
            C2,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(self.stderr_payload(rejected)["error"], "AUTHORIZATION_DENIED")

        self.success(
            self.run_cli(
                "trust",
                "add-rule",
                "--rule-id",
                "allow-cli-review-root",
                "--effect",
                "ALLOW",
                "--subject",
                "root-owner",
                "--action",
                str(prepared["action"]),  # type: ignore[index]
                "--resource",
                str(prepared["resource"]),  # type: ignore[index]
                "--conditions-json",
                json.dumps(prepared["context"], sort_keys=True, separators=(",", ":")),  # type: ignore[index]
                "--actor",
                "policy-owner",
                "--occurred-at",
                C2,
            )
        )
        allowed = self.success(
            self.run_cli(
                "trust",
                "authorize",
                "--subject",
                "root-owner",
                "--action",
                str(prepared["action"]),  # type: ignore[index]
                "--resource",
                str(prepared["resource"]),  # type: ignore[index]
                "--mission-id",
                str(prepared["mission_id"]),  # type: ignore[index]
                "--context-json",
                json.dumps(prepared["context"], sort_keys=True, separators=(",", ":")),  # type: ignore[index]
                "--at",
                C3,
            )
        )["result"]
        accepted = self.success(
            self.run_cli(
                "architecture-review",
                "accept-reviewer-root",
                "--key-id",
                "review-key",
                "--reviewer-identity",
                "independent-cli-reviewer",
                "--public-key-file",
                str(self.public_key),
                "--authorization-decision-id",
                str(allowed["decision_id"]),  # type: ignore[index]
                "--actor",
                "root-owner",
                "--occurred-at",
                C4,
            )
        )["result"]
        self.assertEqual(accepted["fingerprint_sha256"], prepared["fingerprint_sha256"])  # type: ignore[index]
        self.assertNotIn("public_key_pem", accepted)

        verified = self.success(
            self.run_cli(
                "architecture-review",
                "verify-root",
                "--key-id",
                "review-key",
            )
        )["result"]
        self.assertTrue(verified["ok"])  # type: ignore[index]

        with sqlite3.connect(self.db_path) as connection:
            connection.execute("DROP TRIGGER c4_architecture_reviewer_roots_no_update")
            connection.execute(
                "UPDATE c4_architecture_reviewer_roots SET reviewer_identity = ? WHERE key_id = ?",
                ("tampered-reviewer", "review-key"),
            )

        dirty = self.run_cli(
            "architecture-review",
            "verify-root",
            "--key-id",
            "review-key",
        )
        self.assertEqual(dirty.returncode, 3)
        dirty_result = self.stdout_payload(dirty)
        self.assertFalse(dirty_result["result"]["ok"])  # type: ignore[index]
        self.assertNotIn("Traceback", dirty.stderr)

    def test_missing_key_payload_or_signature_is_structured_without_traceback(self) -> None:
        missing_key = self.run_cli(
            "architecture-review",
            "prepare-reviewer-root",
            "--key-id",
            "missing-key",
            "--reviewer-identity",
            "reviewer",
            "--public-key-file",
            str(self.root / "missing.pem"),
        )
        self.assertEqual(missing_key.returncode, 2)
        self.assertEqual(self.stderr_payload(missing_key)["error"], "VALIDATION_ERROR")
        self.assertNotIn("Traceback", missing_key.stderr)

        missing_review_file = self.run_cli(
            "architecture-review",
            "admit",
            "--candidate-id",
            "candidate",
            "--key-id",
            "review-key",
            "--payload-file",
            str(self.root / "missing.json"),
            "--signature-file",
            str(self.root / "missing.sig"),
            "--actor",
            "admitter",
        )
        self.assertEqual(missing_review_file.returncode, 2)
        self.assertEqual(
            self.stderr_payload(missing_review_file)["error"],
            "VALIDATION_ERROR",
        )
        self.assertNotIn("Traceback", missing_review_file.stderr)


class ArchitectureReviewCliEndToEndTests(
    ArchitectureReviewCliMixin,
    unittest.TestCase,
):
    @classmethod
    def setUpClass(cls) -> None:
        execution_fixture.C3AdoptionExecutionTests.setUpClass()
        cls.execution_fixture = execution_fixture.C3AdoptionExecutionTests
        cls.repo_root = cls.execution_fixture.repo_root

    @classmethod
    def tearDownClass(cls) -> None:
        cls.execution_fixture.tearDownClass()

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.db_path = self.root / "starcom.sqlite3"
        with sqlite3.connect(self.execution_fixture.execution_base_db) as source:
            with sqlite3.connect(self.db_path) as destination:
                source.backup(destination)
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = str(self.repo_root / "src")
        self.generate_keys()
        self.runtime = Runtime.open(str(self.db_path))
        self.candidate, self.input_set = self._build_c4_candidate()
        self.runtime.close()
        self.runtime = None

    def tearDown(self) -> None:
        if self.runtime is not None:
            self.runtime.close()
        self.tempdir.cleanup()

    def authorize(self, preparation, *, actor: str, rule_id: str, now: str):  # type: ignore[no-untyped-def]
        self.runtime.trust.add_rule(  # type: ignore[union-attr]
            PolicyRule(
                rule_id,
                PolicyEffect.ALLOW,
                actor,
                preparation.action,
                preparation.resource,
            ),
            actor="fixture-policy-owner",
            occurred_at=C0,
        )
        decision = self.runtime.trust.authorize(  # type: ignore[union-attr]
            AuthorizationRequest(
                subject=actor,
                action=preparation.action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=preparation.context,
            ),
            now=now,
        )
        self.assertTrue(decision.allowed, decision)
        return decision

    @staticmethod
    def manifest(record) -> dict[str, object]:  # type: ignore[no-untyped-def]
        port_ids = [
            "port-action",
            "port-artifact",
            "port-monitor",
            "port-research",
        ]
        capability_ids = [
            "cap-action",
            "cap-artifact",
            "cap-monitor",
            "cap-research",
        ]
        return {
            "architecture_id": "starcom-v3.2-target",
            "architecture_version": "3.2",
            "title": "STARCOM v3.2 Universal Computer Mission Fabric",
            "authority_adrs": [
                {
                    "adr_id": "adr-authority-boundaries",
                    "title": "Sovereign authority ownership",
                    "decision": "Mission Kernel owns the four sovereign mission ports",
                    "rationale": "One explicit owner prevents framework authority drift",
                    "authority_owner": "MISSION_KERNEL",
                    "affected_port_ids": port_ids,
                    "evidence_execution_ids": [record.execution_id],
                }
            ],
            "ports": [
                {
                    "port_id": "port-action",
                    "capability_id": "cap-action",
                    "owner_authority": "MISSION_KERNEL",
                    "contract_digest": "a" * 64,
                    "test_ids": ["test-action"],
                    "proof_ids": ["proof-action"],
                },
                {
                    "port_id": "port-artifact",
                    "capability_id": "cap-artifact",
                    "owner_authority": "MISSION_KERNEL",
                    "contract_digest": "b" * 64,
                    "test_ids": ["test-artifact"],
                    "proof_ids": ["proof-artifact"],
                },
                {
                    "port_id": "port-monitor",
                    "capability_id": "cap-monitor",
                    "owner_authority": "MISSION_KERNEL",
                    "contract_digest": "c" * 64,
                    "test_ids": ["test-monitor"],
                    "proof_ids": ["proof-monitor"],
                },
                {
                    "port_id": "port-research",
                    "capability_id": "cap-research",
                    "owner_authority": "MISSION_KERNEL",
                    "contract_digest": "d" * 64,
                    "test_ids": ["test-research"],
                    "proof_ids": ["proof-research"],
                },
            ],
            "mission_fabric": {
                "RESEARCH": ["port-research"],
                "ARTIFACT": ["port-artifact"],
                "ACTION": ["port-action"],
                "MONITOR": ["port-monitor"],
            },
            "component_bindings": [
                {
                    "binding_id": "binding-success",
                    "execution_id": record.execution_id,
                    "candidate_artifact_id": record.candidate_artifact_id,
                    "candidate_material_sha256": record.candidate_material_sha256,
                    "port_ids": port_ids,
                    "capability_ids": capability_ids,
                }
            ],
            "vertical_benchmark": {
                "benchmark_id": "benchmark-research-artifact-action-monitor",
                "stage_order": ["RESEARCH", "ARTIFACT", "ACTION", "MONITOR"],
                "stage_test_ids": {
                    "RESEARCH": ["test-research"],
                    "ARTIFACT": ["test-artifact"],
                    "ACTION": ["test-action"],
                    "MONITOR": ["test-monitor"],
                },
                "stage_proof_ids": {
                    "RESEARCH": ["proof-research"],
                    "ARTIFACT": ["proof-artifact"],
                    "ACTION": ["proof-action"],
                    "MONITOR": ["proof-monitor"],
                },
                "end_to_end_test_id": "test-e2e-mission-fabric",
                "end_to_end_proof_id": "proof-e2e-mission-fabric",
            },
            "non_functional_requirements": [
                {
                    "requirement_id": "nfr-default-deny",
                    "category": "SECURITY",
                    "statement": "Every external effect remains default-deny",
                    "verification_method": "TrustPlane mutation suite",
                    "test_ids": ["test-action"],
                    "proof_ids": ["proof-action"],
                }
            ],
            "gate_effect": "C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED",
        }

    def _build_c4_candidate(self):  # type: ignore[no-untyped-def]
        plan = self.execution_fixture.execution_plan()
        preparation = self.runtime.adoption_execution.prepare(  # type: ignore[union-attr]
            "execution-c4-cli",
            adoption_id="adoption-cli",
            executor_id=execution_fixture.DeterministicExecutor.executor_id,
            execution_plan=plan,
        )
        decision = self.authorize(
            preparation,
            actor="execution-operator",
            rule_id="allow-c4-execution",
            now=C1,
        )
        self.runtime.adoption_execution.request_execution(  # type: ignore[union-attr]
            "execution-c4-cli",
            adoption_id="adoption-cli",
            executor_id=execution_fixture.DeterministicExecutor.executor_id,
            execution_plan=plan,
            authorization_decision_id=decision.decision_id,
            actor="execution-operator",
            occurred_at=C2,
        )
        worker = C3AdoptionExecutionWorker(
            self.runtime.adoption_execution,  # type: ignore[union-attr]
            self.runtime.outbox,  # type: ignore[union-attr]
            execution_fixture.DeterministicEnabledRegistry(),
            execution_fixture.DeterministicExecutor("success"),
        )
        worker.process_next(worker_id="worker-c4-cli", now=C3, lease_seconds=30)
        record = self.runtime.adoption_execution.get_execution("execution-c4-cli")  # type: ignore[union-attr]

        input_preparation = self.runtime.architecture_input.prepare_freeze(  # type: ignore[union-attr]
            "input-set-c4-cli", (record.execution_id,)
        )
        input_decision = self.authorize(
            input_preparation,
            actor="c4-input-owner",
            rule_id="allow-c4-input-cli",
            now=C4,
        )
        input_set = self.runtime.architecture_input.freeze(  # type: ignore[union-attr]
            "input-set-c4-cli",
            (record.execution_id,),
            authorization_decision_id=input_decision.decision_id,
            actor="c4-input-owner",
            occurred_at=C5,
        )

        manifest = self.manifest(record)
        candidate_preparation = self.runtime.architecture_candidate.prepare_create(  # type: ignore[union-attr]
            "candidate-c4-cli",
            input_set_id=input_set.input_set_id,
            manifest=manifest,
        )
        candidate_decision = self.authorize(
            candidate_preparation,
            actor="c4-architect",
            rule_id="allow-c4-candidate-cli",
            now=C6,
        )
        candidate = self.runtime.architecture_candidate.create_candidate(  # type: ignore[union-attr]
            "candidate-c4-cli",
            input_set_id=input_set.input_set_id,
            manifest=manifest,
            authorization_decision_id=candidate_decision.decision_id,
            actor="c4-architect",
            occurred_at=C7,
        )
        return candidate, input_set

    def prepare_and_accept_root(self) -> dict[str, object]:
        prepared = self.success(
            self.run_cli(
                "architecture-review",
                "prepare-reviewer-root",
                "--key-id",
                "review-key-cli",
                "--reviewer-identity",
                "independent-cli-reviewer",
                "--public-key-file",
                str(self.public_key),
            )
        )["result"]
        context_json = json.dumps(
            prepared["context"], sort_keys=True, separators=(",", ":")  # type: ignore[index]
        )
        self.success(
            self.run_cli(
                "trust",
                "add-rule",
                "--rule-id",
                "allow-c4-review-root-cli",
                "--effect",
                "ALLOW",
                "--subject",
                "root-owner",
                "--action",
                str(prepared["action"]),  # type: ignore[index]
                "--resource",
                str(prepared["resource"]),  # type: ignore[index]
                "--conditions-json",
                context_json,
                "--actor",
                "policy-owner",
                "--occurred-at",
                C8,
            )
        )
        decision = self.success(
            self.run_cli(
                "trust",
                "authorize",
                "--subject",
                "root-owner",
                "--action",
                str(prepared["action"]),  # type: ignore[index]
                "--resource",
                str(prepared["resource"]),  # type: ignore[index]
                "--mission-id",
                str(prepared["mission_id"]),  # type: ignore[index]
                "--context-json",
                context_json,
                "--at",
                C9,
            )
        )["result"]
        accepted = self.success(
            self.run_cli(
                "architecture-review",
                "accept-reviewer-root",
                "--key-id",
                "review-key-cli",
                "--reviewer-identity",
                "independent-cli-reviewer",
                "--public-key-file",
                str(self.public_key),
                "--authorization-decision-id",
                str(decision["decision_id"]),  # type: ignore[index]
                "--actor",
                "root-owner",
                "--occurred-at",
                C10,
            )
        )["result"]
        self.assertNotIn("public_key_pem", accepted)
        return accepted  # type: ignore[return-value]

    def review_payload(self) -> bytes:
        value = {
            "review_id": "review-cli",
            "candidate_id": self.candidate.candidate_id,
            "architecture_id": self.candidate.architecture_id,
            "input_set_id": self.input_set.input_set_id,
            "manifest_sha256": self.candidate.manifest_sha256,
            "input_set_digest": self.input_set.input_set_digest,
            "reviewer_identity": "independent-cli-reviewer",
            "reviewer_environment": {
                "description": "isolated CLI review worktree",
                "environment_type": "ISOLATED_WORKTREE",
            },
            "independence_basis": {
                "excluded_identities": [
                    "c4-architect",
                    "c4-input-owner",
                    "execution-operator",
                ],
                "statement": "reviewer is independent of static provenance identities",
            },
            "reviewed_at_utc": C11,
            "structural_verification_result": "PASS",
            "security_verification_result": "PASS",
            "evidence_binding_result": "PASS",
            "verdict": "C4_ARCHITECTURE_ACCEPTED",
            "findings": [],
            "gate_effect": "NO_PUBLICATION_NO_DEPLOYMENT",
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )

    def test_exact_byte_admission_get_and_verify_with_whitespace_mutation_rejected(self) -> None:
        self.prepare_and_accept_root()
        payload_path = self.root / "review.json"
        signature_path = self.root / "review.sig"
        payload = self.review_payload()
        payload_path.write_bytes(payload)
        self.sign(payload_path, signature_path)

        tampered_path = self.root / "review-whitespace.json"
        tampered_path.write_bytes(payload + b" ")
        rejected = self.run_cli(
            "architecture-review",
            "admit",
            "--candidate-id",
            self.candidate.candidate_id,
            "--key-id",
            "review-key-cli",
            "--payload-file",
            str(tampered_path),
            "--signature-file",
            str(signature_path),
            "--actor",
            "c4-review-admitter",
            "--occurred-at",
            C12,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(self.stderr_payload(rejected)["error"], "INTEGRITY_ERROR")

        admitted = self.success(
            self.run_cli(
                "architecture-review",
                "admit",
                "--candidate-id",
                self.candidate.candidate_id,
                "--key-id",
                "review-key-cli",
                "--payload-file",
                str(payload_path),
                "--signature-file",
                str(signature_path),
                "--actor",
                "c4-review-admitter",
                "--occurred-at",
                C12,
            )
        )["result"]
        self.assertEqual(admitted["review_id"], "review-cli")  # type: ignore[index]
        self.assertEqual(  # type: ignore[index]
            admitted["payload_sha256"],
            hashlib.sha256(payload).hexdigest(),
        )
        self.assertNotIn("payload", admitted)
        self.assertNotIn("signature", admitted)

        loaded = self.success(
            self.run_cli("architecture-review", "get", "--review-id", "review-cli")
        )["result"]
        self.assertEqual(loaded, admitted)
        verified = self.success(
            self.run_cli("architecture-review", "verify", "--review-id", "review-cli")
        )["result"]
        self.assertTrue(verified["ok"])  # type: ignore[index]

    def test_dirty_review_verification_returns_exit_three_and_no_traceback(self) -> None:
        self.prepare_and_accept_root()
        payload_path = self.root / "review.json"
        signature_path = self.root / "review.sig"
        payload_path.write_bytes(self.review_payload())
        self.sign(payload_path, signature_path)
        self.success(
            self.run_cli(
                "architecture-review",
                "admit",
                "--candidate-id",
                self.candidate.candidate_id,
                "--key-id",
                "review-key-cli",
                "--payload-file",
                str(payload_path),
                "--signature-file",
                str(signature_path),
                "--actor",
                "c4-review-admitter",
                "--occurred-at",
                C12,
            )
        )
        with sqlite3.connect(self.db_path) as connection:
            connection.execute("DROP TRIGGER c4_architecture_reviews_no_update")
            connection.execute(
                "UPDATE c4_architecture_reviews SET verdict = ? WHERE review_id = ?",
                ("C4_ARCHITECTURE_REWORK_REQUIRED", "review-cli"),
            )

        dirty = self.run_cli("architecture-review", "verify", "--review-id", "review-cli")
        self.assertEqual(dirty.returncode, 3)
        result = self.stdout_payload(dirty)
        self.assertFalse(result["result"]["ok"])  # type: ignore[index]
        self.assertNotIn("Traceback", dirty.stderr)


if __name__ == "__main__":
    unittest.main()
