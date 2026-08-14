from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

import test_adoption_execution as execution_fixture

from starcom.adoption_execution import (
    C3AdoptionExecutionService,
    C3AdoptionExecutionStatus,
    C3AdoptionExecutionWorker,
)
from starcom.cli import Runtime
from starcom.durable import DurableOutbox, EffectStatus


E3 = "2026-08-14T13:13:00.000000Z"


class WrongExecutor(execution_fixture.DeterministicExecutor):
    executor_id = "wrong-executor"


class C3AdoptionExecutionHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture = execution_fixture.C3AdoptionExecutionTests
        fixture.setUpClass()
        cls.execution_fixture = fixture
        cls.execution_base_db = fixture.execution_base_db

    @classmethod
    def tearDownClass(cls) -> None:
        cls.execution_fixture.tearDownClass()

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "starcom.sqlite3"
        execution_fixture.copy_database(
            self.execution_base_db,
            self.db_path,
        )
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
        self.registry = execution_fixture.DeterministicEnabledRegistry()
        self.helper = execution_fixture.C3AdoptionExecutionTests(
            methodName="test_prepare_is_deterministic_and_has_no_side_effect"
        )
        self.helper.runtime = self.runtime
        self.helper.outbox = self.outbox
        self.helper.service = self.service

    def tearDown(self) -> None:
        self.runtime.close()
        self.tempdir.cleanup()

    def admitted(self, execution_id: str = "execution-hardening"):
        return self.helper.admitted(execution_id=execution_id)

    def test_executor_identity_mismatch_is_terminal_no_effect(self) -> None:
        requested = self.admitted()
        executor = WrongExecutor("success")
        worker = C3AdoptionExecutionWorker(
            self.service, self.outbox, self.registry, executor
        )

        completed = worker.process_next(worker_id="worker-wrong", now=E3)

        self.assertIsNotNone(completed)
        assert completed is not None
        self.assertEqual(
            completed.status,
            C3AdoptionExecutionStatus.FAILED_NO_EFFECT,
        )
        self.assertFalse(completed.effect_started)
        self.assertEqual(executor.validate_calls, 0)
        self.assertEqual(executor.execute_calls, 0)
        self.assertEqual(executor.actual_effect_count, 0)
        self.assertEqual(
            self.outbox.get(requested.outbox_effect_id).status,
            EffectStatus.SUCCEEDED,
        )
        self.assertTrue(self.service.verify_execution(requested.execution_id).ok)

    def test_dirty_request_before_effect_is_terminal_no_effect(self) -> None:
        requested = self.admitted()
        self.runtime.database.connection.execute(
            "DROP TRIGGER c3_adoption_execution_requests_no_update"
        )
        self.runtime.database.connection.execute(
            """
            UPDATE c3_adoption_execution_requests
            SET execution_plan_sha256 = ? WHERE execution_id = ?
            """,
            ("0" * 64, requested.execution_id),
        )
        executor = execution_fixture.DeterministicExecutor("success")
        worker = C3AdoptionExecutionWorker(
            self.service, self.outbox, self.registry, executor
        )

        completed = worker.process_next(worker_id="worker-dirty", now=E3)

        self.assertIsNotNone(completed)
        assert completed is not None
        self.assertEqual(
            completed.status,
            C3AdoptionExecutionStatus.FAILED_NO_EFFECT,
        )
        self.assertFalse(completed.effect_started)
        self.assertEqual(executor.validate_calls, 0)
        self.assertEqual(executor.execute_calls, 0)
        self.assertEqual(executor.actual_effect_count, 0)
        self.assertEqual(
            self.outbox.get(requested.outbox_effect_id).status,
            EffectStatus.SUCCEEDED,
        )

    def test_verifier_detects_request_plan_digest_tampering(self) -> None:
        requested = self.admitted()
        self.runtime.database.connection.execute(
            "DROP TRIGGER c3_adoption_execution_requests_no_update"
        )
        self.runtime.database.connection.execute(
            """
            UPDATE c3_adoption_execution_requests
            SET execution_plan_sha256 = ? WHERE execution_id = ?
            """,
            ("0" * 64, requested.execution_id),
        )

        verification = self.service.verify_execution(requested.execution_id)

        self.assertFalse(verification.ok)
        self.assertIn("C3_EXECUTION_PLAN_SHA256_MISMATCH", verification.defects)

    def test_verifier_detects_authorization_consumption_tampering(self) -> None:
        requested = self.admitted()
        self.runtime.database.connection.execute(
            "DROP TRIGGER continuity_authorization_consumptions_no_update"
        )
        self.runtime.database.connection.execute(
            """
            UPDATE continuity_authorization_consumptions
            SET operation_id = ? WHERE decision_id = ?
            """,
            ("different-execution", requested.authorization_decision_id),
        )

        verification = self.service.verify_execution(requested.execution_id)

        self.assertFalse(verification.ok)
        self.assertIn(
            "C3_EXECUTION_AUTHORIZATION_CONSUMPTION_MISMATCH",
            verification.defects,
        )

    def test_verifier_detects_outbox_payload_tampering(self) -> None:
        requested = self.admitted()
        self.runtime.database.connection.execute(
            """
            UPDATE durable_effects SET payload_json = ? WHERE effect_id = ?
            """,
            (
                json.dumps(
                    {"execution_id": "different-execution"},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                requested.outbox_effect_id,
            ),
        )

        verification = self.service.verify_execution(requested.execution_id)

        self.assertFalse(verification.ok)
        self.assertIn("C3_EXECUTION_OUTBOX_PAYLOAD_MISMATCH", verification.defects)

    def test_verifier_detects_transition_ledger_payload_tampering(self) -> None:
        requested = self.admitted()
        transition = self.runtime.database.connection.execute(
            """
            SELECT ledger_event_id FROM c3_adoption_execution_transitions
            WHERE execution_id = ? AND sequence = 1
            """,
            (requested.execution_id,),
        ).fetchone()
        self.assertIsNotNone(transition)
        assert transition is not None
        self.runtime.database.connection.execute("DROP TRIGGER ledger_events_no_update")
        self.runtime.database.connection.execute(
            "UPDATE ledger_events SET payload_json = ? WHERE event_id = ?",
            (
                json.dumps(
                    {"execution_id": "different-execution"},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                str(transition["ledger_event_id"]),
            ),
        )

        verification = self.service.verify_execution(requested.execution_id)

        self.assertFalse(verification.ok)
        self.assertTrue(
            any(
                defect.startswith("C3_EXECUTION_LEDGER_CHAIN:")
                for defect in verification.defects
            ),
            verification.defects,
        )


if __name__ == "__main__":
    unittest.main()
