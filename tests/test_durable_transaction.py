from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from starcom.db import Database
from starcom.durable import DurableOutbox
from starcom.errors import ConflictError, NotFoundError
from starcom.ledger import EventLedger


T0 = "2026-08-14T13:00:00.000000Z"


class DurableOutboxTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.database = Database(Path(self.tempdir.name) / "durable-transaction.sqlite3")
        self.database.initialize()
        self.ledger = EventLedger(self.database)
        self.outbox = DurableOutbox(self.database, self.ledger)

    def tearDown(self) -> None:
        self.database.close()
        self.tempdir.cleanup()

    def test_enqueue_in_transaction_rolls_back_with_caller(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "abort caller transaction"):
            with self.database.transaction() as connection:
                self.outbox.enqueue_in_transaction(
                    connection,
                    effect_id="effect-transaction-rollback",
                    topic="c3.adoption.execute",
                    payload={"execution_id": "execution-rollback"},
                    max_attempts=3,
                    available_at=T0,
                    actor="execution-authority",
                )
                raise RuntimeError("abort caller transaction")

        with self.assertRaises(NotFoundError):
            self.outbox.get("effect-transaction-rollback")
        ledger_count = int(
            self.database.connection.execute(
                "SELECT COUNT(*) FROM ledger_events WHERE stream_id = ?",
                ("durable:effect:effect-transaction-rollback",),
            ).fetchone()[0]
        )
        self.assertEqual(ledger_count, 0)

    def test_wrapper_and_transactional_enqueue_share_idempotency_and_conflicts(self) -> None:
        arguments = {
            "effect_id": "effect-transaction-idempotent",
            "topic": "c3.adoption.execute",
            "payload": {"execution_id": "execution-idempotent", "attempt": 1},
            "max_attempts": 3,
            "available_at": T0,
            "actor": "execution-authority",
        }
        with self.database.transaction() as connection:
            first = self.outbox.enqueue_in_transaction(connection, **arguments)
            replay = self.outbox.enqueue_in_transaction(connection, **arguments)

        wrapper_replay = self.outbox.enqueue(**arguments)

        self.assertEqual(first, replay)
        self.assertEqual(first, wrapper_replay)
        ledger_count = int(
            self.database.connection.execute(
                "SELECT COUNT(*) FROM ledger_events WHERE stream_id = ?",
                ("durable:effect:effect-transaction-idempotent",),
            ).fetchone()[0]
        )
        self.assertEqual(ledger_count, 1)
        with self.database.transaction() as connection:
            with self.assertRaises(ConflictError):
                self.outbox.enqueue_in_transaction(
                    connection,
                    **{
                        **arguments,
                        "payload": {
                            "execution_id": "execution-idempotent",
                            "attempt": 2,
                        },
                    },
                )


if __name__ == "__main__":
    unittest.main()
