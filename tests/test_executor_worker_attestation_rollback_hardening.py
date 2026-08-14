from __future__ import annotations

import unittest

import test_executor_worker_attestation as attestation_fixture

from starcom.adoption_execution import (
    C3AdoptionExecutionStatus,
    C3AdoptionExecutionWorker,
)
from starcom.executor_registry import C3ExecutorState


class C3ExecutorWorkerRollbackAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture = attestation_fixture.C3ExecutorWorkerAttestationTests
        fixture.setUpClass()
        cls.fixture_class = fixture

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_class.tearDownClass()

    def setUp(self) -> None:
        self.helper = self.fixture_class(
            methodName="test_enabled_executor_can_execute"
        )
        self.helper.setUp()

    def tearDown(self) -> None:
        self.helper.tearDown()

    def crash_after_effect(self, execution_id: str):  # type: ignore[no-untyped-def]
        self.helper.register_executor(C3ExecutorState.ENABLED)
        requested = self.helper.request(execution_id=execution_id)
        trusted_executor = attestation_fixture.AttestedExecutor("crash-once")
        worker = C3AdoptionExecutionWorker(
            self.helper.service,
            self.helper.outbox,
            self.helper.registry,
            trusted_executor,
        )
        with self.assertRaises(KeyboardInterrupt):
            worker.process_next(
                worker_id="worker-before-crash",
                now=attestation_fixture.W8,
                lease_seconds=30,
            )
        self.assertEqual(trusted_executor.actual_effect_count, 1)
        self.assertEqual(
            self.helper.outbox.recover_expired(now=attestation_fixture.W9),
            1,
        )
        return requested, trusted_executor

    def test_wrong_version_cannot_receive_compensating_rollback(self) -> None:
        requested, _ = self.crash_after_effect("worker-crash-wrong-version")
        wrong_executor = attestation_fixture.WrongVersionExecutor("success")
        worker = C3AdoptionExecutionWorker(
            self.helper.service,
            self.helper.outbox,
            self.helper.registry,
            wrong_executor,
        )

        completed = worker.process_next(
            worker_id="worker-wrong-version-recovery",
            now=attestation_fixture.W9,
            lease_seconds=30,
        )

        self.assertIsNotNone(completed)
        assert completed is not None
        self.assertEqual(
            completed.status,
            C3AdoptionExecutionStatus.ROLLBACK_FAILED,
        )
        self.assertTrue(completed.effect_started)
        self.assertEqual(wrong_executor.validate_calls, 0)
        self.assertEqual(wrong_executor.execute_calls, 0)
        self.assertEqual(wrong_executor.rollback_calls, 0)
        self.assertEqual(wrong_executor.actual_effect_count, 0)
        self.assertEqual(wrong_executor.actual_rollback_count, 0)
        self.assertTrue(
            self.helper.service.verify_execution(requested.execution_id).ok
        )

    def test_dirty_registry_cannot_authorize_compensating_rollback(self) -> None:
        requested, trusted_executor = self.crash_after_effect(
            "worker-crash-dirty-registry"
        )
        self.helper.runtime.database.connection.execute(
            "DROP TRIGGER c3_executor_descriptors_no_update"
        )
        self.helper.runtime.database.connection.execute(
            """
            UPDATE c3_executor_descriptors SET implementation_digest = ?
            WHERE executor_id = ?
            """,
            ("0" * 64, attestation_fixture.AttestedExecutor.executor_id),
        )
        worker = C3AdoptionExecutionWorker(
            self.helper.service,
            self.helper.outbox,
            self.helper.registry,
            trusted_executor,
        )

        completed = worker.process_next(
            worker_id="worker-dirty-registry-recovery",
            now=attestation_fixture.W9,
            lease_seconds=30,
        )

        self.assertIsNotNone(completed)
        assert completed is not None
        self.assertEqual(
            completed.status,
            C3AdoptionExecutionStatus.ROLLBACK_FAILED,
        )
        self.assertTrue(completed.effect_started)
        self.assertEqual(trusted_executor.actual_effect_count, 1)
        self.assertEqual(trusted_executor.rollback_calls, 0)
        self.assertEqual(trusted_executor.actual_rollback_count, 0)
        self.assertTrue(
            self.helper.service.verify_execution(requested.execution_id).ok
        )


if __name__ == "__main__":
    unittest.main()
