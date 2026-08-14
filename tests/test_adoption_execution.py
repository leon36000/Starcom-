from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

import test_adoption_cli as adoption_cli_fixture

from starcom.adoption_execution import (
    C3AdoptionExecutionService,
    C3AdoptionExecutionStatus,
    C3AdoptionExecutionWorker,
    C3ExecutorResult,
    C3RollbackResult,
    DisabledC3AdoptionExecutor,
)
from starcom.cli import Runtime
from starcom.durable import DurableOutbox, EffectStatus
from starcom.errors import AuthorizationError, ConflictError, IntegrityError
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule


E0 = "2026-08-14T13:10:00.000000Z"
E1 = "2026-08-14T13:11:00.000000Z"
E2 = "2026-08-14T13:12:00.000000Z"
E3 = "2026-08-14T13:13:00.000000Z"
E4 = "2026-08-14T13:20:00.000000Z"
PRE_STATE = "1" * 64
POST_STATE = "2" * 64
RESTORED_STATE = "3" * 64


def copy_database(source: Path, destination: Path) -> None:
    with sqlite3.connect(source) as source_connection:
        with sqlite3.connect(destination) as destination_connection:
            source_connection.backup(destination_connection)


class DeterministicExecutor:
    executor_id = "deterministic-test-executor"

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.validate_calls = 0
        self.execute_calls = 0
        self.rollback_calls = 0
        self.actual_effect_count = 0
        self.actual_rollback_count = 0
        self._execution_results: dict[str, C3ExecutorResult] = {}
        self._rollback_results: dict[str, C3RollbackResult] = {}
        self._crashed: set[str] = set()

    def validate(self, request) -> None:  # type: ignore[no-untyped-def]
        self.validate_calls += 1
        if request.executor_id != self.executor_id:
            raise RuntimeError("executor identity mismatch")

    def execute(self, request) -> C3ExecutorResult:  # type: ignore[no-untyped-def]
        self.execute_calls += 1
        key = request.idempotency_key
        if key in self._execution_results:
            return self._execution_results[key]
        if self.mode == "no-effect-failure":
            result = C3ExecutorResult(
                succeeded=False,
                effect_started=False,
                pre_state_digest=PRE_STATE,
                post_state_digest=None,
                receipt={"mode": self.mode, "idempotency_key": key},
                error="validation rejected before effect",
            )
            self._execution_results[key] = result
            return result

        self.actual_effect_count += 1
        if self.mode in {"post-effect-failure", "rollback-failure"}:
            result = C3ExecutorResult(
                succeeded=False,
                effect_started=True,
                pre_state_digest=PRE_STATE,
                post_state_digest=POST_STATE,
                receipt={"mode": self.mode, "idempotency_key": key},
                error="effect failed after partial change",
            )
            self._execution_results[key] = result
            return result

        result = C3ExecutorResult(
            succeeded=True,
            effect_started=True,
            pre_state_digest=PRE_STATE,
            post_state_digest=POST_STATE,
            receipt={"mode": self.mode, "idempotency_key": key},
        )
        self._execution_results[key] = result
        if self.mode == "crash-once" and key not in self._crashed:
            self._crashed.add(key)
            raise KeyboardInterrupt("simulated hard crash after idempotent effect")
        return result

    def rollback(self, request, execution_result, reason: str) -> C3RollbackResult:  # type: ignore[no-untyped-def]
        self.rollback_calls += 1
        key = request.idempotency_key
        if key in self._rollback_results:
            return self._rollback_results[key]
        self.actual_rollback_count += 1
        succeeded = self.mode != "rollback-failure"
        result = C3RollbackResult(
            succeeded=succeeded,
            restored_state_digest=RESTORED_STATE if succeeded else None,
            receipt={
                "mode": self.mode,
                "idempotency_key": key,
                "reason": reason,
                "had_execution_result": execution_result is not None,
            },
            error=None if succeeded else "rollback failed",
        )
        self._rollback_results[key] = result
        return result


class C3AdoptionExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture = adoption_cli_fixture.C3AdoptionCliTests
        fixture.setUpClass()
        cls.upstream_fixture = fixture
        cls.repo_root = fixture.repo_root
        cls.fixture_root = tempfile.TemporaryDirectory()
        cls.execution_base_db = Path(cls.fixture_root.name) / "execution-base.sqlite3"
        copy_database(fixture.base_db_path, cls.execution_base_db)

        helper = adoption_cli_fixture.C3AdoptionCliTests(
            methodName=(
                "test_default_deny_then_explicit_trust_decision_authorizes_gets_and_verifies"
            )
        )
        helper.root = Path(cls.fixture_root.name)
        helper.db_path = cls.execution_base_db
        helper.repo_root = cls.repo_root
        helper.env = os.environ.copy()
        helper.env["PYTHONPATH"] = str(cls.repo_root / "src")
        helper.decision_private = fixture.decision_private
        helper.decision_public = fixture.decision_public
        helper.establish_signed_selected_decision()
        preparation = helper.success(helper.prepare())["result"]  # type: ignore[index]
        helper.add_exact_allow_rule(preparation)  # type: ignore[arg-type]
        authorization = helper.success(helper.authorize_request(preparation))["result"]  # type: ignore[index]
        helper.success(
            helper.authorize_adoption(str(authorization["decision_id"]))  # type: ignore[index]
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_root.cleanup()
        cls.upstream_fixture.tearDownClass()

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "starcom.sqlite3"
        copy_database(self.execution_base_db, self.db_path)
        self.runtime = Runtime.open(self.db_path)
        self.outbox = DurableOutbox(self.runtime.database, self.runtime.ledger)
        self.service = C3AdoptionExecutionService(
            self.runtime.database,
            self.runtime.ledger,
            self.runtime.trust,
            self.runtime.continuity,
            self.runtime.adoption,
            self.outbox,
        )

    def tearDown(self) -> None:
        self.runtime.close()
        self.tempdir.cleanup()

    @staticmethod
    def execution_plan() -> dict[str, object]:
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

    def prepare(self, *, execution_id: str = "execution-1", plan=None):  # type: ignore[no-untyped-def]
        return self.service.prepare(
            execution_id,
            adoption_id="adoption-cli",
            executor_id=DeterministicExecutor.executor_id,
            execution_plan=plan or self.execution_plan(),
        )

    def authorize(self, preparation, *, exact: bool = True, actor: str = "execution-operator"):  # type: ignore[no-untyped-def]
        self.runtime.trust.add_rule(
            PolicyRule(
                f"allow-{preparation.execution_id}",
                PolicyEffect.ALLOW,
                "execution-operator",
                preparation.action,
                preparation.resource,
            ),
            actor="owner",
            occurred_at=E0,
        )
        context = dict(preparation.context)
        if not exact:
            context["execution_plan_sha256"] = "0" * 64
        return self.runtime.trust.authorize(
            AuthorizationRequest(
                subject=actor,
                action=preparation.action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=context,
            ),
            now=E1,
        )

    def request(self, preparation, decision_id: str, *, actor: str = "execution-operator"):  # type: ignore[no-untyped-def]
        return self.service.request_execution(
            preparation.execution_id,
            adoption_id=preparation.adoption_id,
            executor_id=preparation.executor_id,
            execution_plan=preparation.execution_plan,
            authorization_decision_id=decision_id,
            actor=actor,
            occurred_at=E2,
        )

    def table_count(self, table: str) -> int:
        row = self.runtime.database.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        if row is None:
            return 0
        return int(
            self.runtime.database.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
        )

    def admitted(self, *, execution_id: str = "execution-1"):
        preparation = self.prepare(execution_id=execution_id)
        decision = self.authorize(preparation)
        self.assertTrue(decision.allowed)
        return self.request(preparation, decision.decision_id)

    def test_prepare_is_deterministic_and_has_no_side_effect(self) -> None:
        decisions_before = self.table_count("trust_decisions")
        consumptions_before = self.table_count("continuity_authorization_consumptions")

        first = self.prepare()
        second = self.prepare()

        self.assertEqual(first, second)
        self.assertEqual(first.action, "c3.adoption.execute")
        self.assertEqual(
            first.resource,
            "continuity:c3:c3-decision-run:adoption:adoption-cli:execution:candidate-a",
        )
        self.assertEqual(first.context["execution_mode"], "DURABLE_OUTBOX_SEPARATE_WORKER")
        self.assertEqual(first.outbox_effect_id, "c3-adoption-execution:execution-1")
        self.assertEqual(self.table_count("trust_decisions"), decisions_before)
        self.assertEqual(
            self.table_count("continuity_authorization_consumptions"),
            consumptions_before,
        )
        self.assertEqual(self.table_count("c3_adoption_execution_requests"), 0)
        with self.assertRaises(Exception):
            self.outbox.get(first.outbox_effect_id)

    def test_default_deny_and_atomic_admission_enqueue_without_executor_call(self) -> None:
        preparation = self.prepare()
        denied = self.runtime.trust.authorize(
            AuthorizationRequest(
                subject="execution-operator",
                action=preparation.action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=preparation.context,
            ),
            now=E1,
        )
        self.assertFalse(denied.allowed)
        with self.assertRaises(AuthorizationError):
            self.request(preparation, denied.decision_id)
        self.assertEqual(self.table_count("c3_adoption_execution_requests"), 0)

        decision = self.authorize(preparation)
        record = self.request(preparation, decision.decision_id)

        self.assertEqual(
            record.status,
            C3AdoptionExecutionStatus.REQUESTED_NOT_EXECUTED,
        )
        effect = self.outbox.get(preparation.outbox_effect_id)
        self.assertEqual(effect.status, EffectStatus.PENDING)
        self.assertEqual(effect.topic, "c3.adoption.execute")
        self.assertEqual(effect.payload["execution_id"], preparation.execution_id)
        self.assertTrue(self.service.verify_execution(record.execution_id).ok)

    def test_exact_replay_is_idempotent_and_material_conflicts_fail(self) -> None:
        preparation = self.prepare()
        decision = self.authorize(preparation)
        first = self.request(preparation, decision.decision_id)
        replay = self.request(preparation, decision.decision_id)
        self.assertEqual(first, replay)
        ledger_count = int(
            self.runtime.database.connection.execute(
                "SELECT COUNT(*) FROM ledger_events WHERE stream_id = ?",
                (
                    "continuity:c3:c3-decision-run:adoption:adoption-cli:"
                    "execution:execution-1",
                ),
            ).fetchone()[0]
        )
        self.assertEqual(ledger_count, 1)
        changed_plan = dict(self.execution_plan())
        changed_plan["target_environment"] = "different-sandbox"
        with self.assertRaises(ConflictError):
            self.service.request_execution(
                "execution-1",
                adoption_id="adoption-cli",
                executor_id=DeterministicExecutor.executor_id,
                execution_plan=changed_plan,
                authorization_decision_id=decision.decision_id,
                actor="execution-operator",
                occurred_at=E2,
            )

    def test_worker_success_is_terminal_and_adapter_idempotent(self) -> None:
        requested = self.admitted()
        executor = DeterministicExecutor("success")
        worker = C3AdoptionExecutionWorker(self.service, self.outbox, executor)

        completed = worker.process_next(worker_id="worker-1", now=E3, lease_seconds=30)

        self.assertIsNotNone(completed)
        assert completed is not None
        self.assertEqual(completed.status, C3AdoptionExecutionStatus.SUCCEEDED)
        self.assertEqual(executor.actual_effect_count, 1)
        self.assertEqual(executor.rollback_calls, 0)
        self.assertEqual(worker.process_next(worker_id="worker-1", now=E4), None)
        self.assertEqual(executor.actual_effect_count, 1)
        self.assertTrue(self.service.verify_execution(requested.execution_id).ok)
        self.assertEqual(self.outbox.get(requested.outbox_effect_id).status, EffectStatus.SUCCEEDED)

    def test_worker_failure_before_effect_never_rolls_back(self) -> None:
        requested = self.admitted()
        executor = DeterministicExecutor("no-effect-failure")
        worker = C3AdoptionExecutionWorker(self.service, self.outbox, executor)

        completed = worker.process_next(worker_id="worker-1", now=E3)

        assert completed is not None
        self.assertEqual(completed.status, C3AdoptionExecutionStatus.FAILED_NO_EFFECT)
        self.assertFalse(completed.effect_started)
        self.assertEqual(executor.actual_effect_count, 0)
        self.assertEqual(executor.rollback_calls, 0)
        self.assertTrue(self.service.verify_execution(requested.execution_id).ok)

    def test_post_effect_failure_requires_successful_rollback(self) -> None:
        requested = self.admitted()
        executor = DeterministicExecutor("post-effect-failure")
        worker = C3AdoptionExecutionWorker(self.service, self.outbox, executor)

        completed = worker.process_next(worker_id="worker-1", now=E3)

        assert completed is not None
        self.assertEqual(
            completed.status,
            C3AdoptionExecutionStatus.FAILED_ROLLED_BACK,
        )
        self.assertTrue(completed.effect_started)
        self.assertEqual(executor.actual_effect_count, 1)
        self.assertEqual(executor.actual_rollback_count, 1)
        self.assertIsNotNone(completed.rollback_receipt_sha256)
        self.assertTrue(self.service.verify_execution(requested.execution_id).ok)

    def test_failed_rollback_is_explicit_and_never_false_success(self) -> None:
        requested = self.admitted()
        executor = DeterministicExecutor("rollback-failure")
        worker = C3AdoptionExecutionWorker(self.service, self.outbox, executor)

        completed = worker.process_next(worker_id="worker-1", now=E3)

        assert completed is not None
        self.assertEqual(
            completed.status,
            C3AdoptionExecutionStatus.ROLLBACK_FAILED,
        )
        self.assertNotEqual(completed.status, C3AdoptionExecutionStatus.SUCCEEDED)
        self.assertEqual(executor.actual_effect_count, 1)
        self.assertEqual(executor.actual_rollback_count, 1)
        self.assertTrue(self.service.verify_execution(requested.execution_id).ok)

    def test_hard_crash_recovery_reuses_adapter_idempotency_key(self) -> None:
        requested = self.admitted()
        executor = DeterministicExecutor("crash-once")
        worker = C3AdoptionExecutionWorker(self.service, self.outbox, executor)

        with self.assertRaises(KeyboardInterrupt):
            worker.process_next(worker_id="worker-crashed", now=E3, lease_seconds=30)
        self.assertEqual(executor.actual_effect_count, 1)
        self.assertEqual(
            self.outbox.get(requested.outbox_effect_id).status,
            EffectStatus.LEASED,
        )

        recovered = self.outbox.recover_expired(now=E4)
        self.assertEqual(recovered, 1)
        completed = worker.process_next(worker_id="worker-retry", now=E4, lease_seconds=30)

        assert completed is not None
        self.assertEqual(completed.status, C3AdoptionExecutionStatus.SUCCEEDED)
        self.assertEqual(executor.actual_effect_count, 1)
        self.assertGreaterEqual(executor.execute_calls, 2)
        self.assertTrue(self.service.verify_execution(requested.execution_id).ok)

    def test_disabled_executor_fails_before_effect(self) -> None:
        preparation = self.service.prepare(
            "execution-disabled",
            adoption_id="adoption-cli",
            executor_id=DisabledC3AdoptionExecutor.executor_id,
            execution_plan=self.execution_plan(),
        )
        decision = self.authorize(preparation)
        requested = self.request(preparation, decision.decision_id)
        worker = C3AdoptionExecutionWorker(self.service, self.outbox)

        completed = worker.process_next(worker_id="worker-disabled", now=E3)

        assert completed is not None
        self.assertEqual(completed.status, C3AdoptionExecutionStatus.FAILED_NO_EFFECT)
        self.assertFalse(completed.effect_started)
        self.assertTrue(self.service.verify_execution(requested.execution_id).ok)

    def test_verifier_detects_transition_receipt_digest_tampering(self) -> None:
        requested = self.admitted()
        worker = C3AdoptionExecutionWorker(
            self.service,
            self.outbox,
            DeterministicExecutor("success"),
        )
        completed = worker.process_next(worker_id="worker-1", now=E3)
        assert completed is not None
        self.runtime.database.connection.execute(
            "DROP TRIGGER c3_adoption_execution_transitions_no_update"
        )
        self.runtime.database.connection.execute(
            """
            UPDATE c3_adoption_execution_transitions
            SET execution_receipt_sha256 = ?
            WHERE execution_id = ? AND status = ?
            """,
            (
                "0" * 64,
                requested.execution_id,
                C3AdoptionExecutionStatus.SUCCEEDED.value,
            ),
        )

        verification = self.service.verify_execution(requested.execution_id)

        self.assertFalse(verification.ok)
        self.assertIn(
            "C3_EXECUTION_RECEIPT_SHA256_MISMATCH:3",
            verification.defects,
        )


if __name__ == "__main__":
    unittest.main()
