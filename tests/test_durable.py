from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from starcom.db import Database
from starcom.durable import DurableOutbox, EffectStatus
from starcom.errors import ConflictError, StateTransitionError
from starcom.ledger import EventLedger


T0 = "2026-08-13T12:00:00.000000Z"
T5 = "2026-08-13T12:00:05.000000Z"
T10 = "2026-08-13T12:00:10.000000Z"
T20 = "2026-08-13T12:00:20.000000Z"


class DurableOutboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tempdir.name) / "durable.sqlite3")
        self.db.initialize()
        self.ledger = EventLedger(self.db)
        self.outbox = DurableOutbox(self.db, self.ledger)

    def tearDown(self) -> None:
        self.db.close()
        self.tempdir.cleanup()

    def enqueue(self, effect_id: str = "effect-1", max_attempts: int = 3):
        return self.outbox.enqueue(
            effect_id=effect_id,
            topic="artifact.publish",
            payload={"artifact_id": "artifact-1"},
            max_attempts=max_attempts,
            actor="mission-kernel",
            occurred_at=T0,
        )

    def test_enqueue_is_idempotent_for_same_payload(self) -> None:
        first = self.enqueue()
        count = len(self.ledger.read_stream("durable:effect:effect-1"))
        second = self.enqueue()
        self.assertEqual(first, second)
        self.assertEqual(first.status, EffectStatus.PENDING)
        self.assertEqual(first.effect_id, first.idempotency_key)
        self.assertEqual(len(self.ledger.read_stream("durable:effect:effect-1")), count)

    def test_enqueue_rejects_same_effect_id_with_different_payload(self) -> None:
        self.enqueue()
        with self.assertRaisesRegex(ConflictError, "idempotency"):
            self.outbox.enqueue(
                effect_id="effect-1",
                topic="artifact.publish",
                payload={"artifact_id": "different"},
                max_attempts=3,
                actor="mission-kernel",
                occurred_at=T0,
            )

    def test_claim_is_exclusive_and_increments_attempt_count(self) -> None:
        self.enqueue()
        first = self.outbox.claim("worker-a", now=T0, lease_seconds=10, limit=1)
        second = self.outbox.claim("worker-b", now=T0, lease_seconds=10, limit=1)
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertEqual(first[0].worker_id, "worker-a")
        self.assertEqual(first[0].attempt_count, 1)
        self.assertEqual(first[0].lease_expires_at, T10)

    def test_success_requires_current_lease(self) -> None:
        self.enqueue()
        lease = self.outbox.claim("worker-a", now=T0, lease_seconds=10)[0]
        record = self.outbox.succeed(
            "effect-1",
            worker_id="worker-a",
            lease_token=lease.lease_token,
            result_digest="c" * 64,
            occurred_at=T5,
        )
        self.assertEqual(record.status, EffectStatus.SUCCEEDED)
        self.assertEqual(record.result_digest, "c" * 64)
        self.assertTrue(self.ledger.verify("durable:effect:effect-1").ok)

    def test_retryable_failure_reschedules_effect(self) -> None:
        self.enqueue()
        lease = self.outbox.claim("worker-a", now=T0, lease_seconds=10)[0]
        record = self.outbox.fail(
            "effect-1",
            worker_id="worker-a",
            lease_token=lease.lease_token,
            error="temporary outage",
            retry_delay_seconds=10,
            occurred_at=T5,
        )
        self.assertEqual(record.status, EffectStatus.PENDING)
        self.assertEqual(record.attempt_count, 1)
        self.assertEqual(record.available_at, "2026-08-13T12:00:15.000000Z")
        self.assertEqual(self.outbox.claim("worker-b", now=T10, lease_seconds=10), [])
        self.assertEqual(len(self.outbox.claim("worker-b", now=T20, lease_seconds=10)), 1)

    def test_retry_exhaustion_is_terminal(self) -> None:
        self.enqueue(max_attempts=1)
        lease = self.outbox.claim("worker-a", now=T0, lease_seconds=10)[0]
        record = self.outbox.fail(
            "effect-1",
            worker_id="worker-a",
            lease_token=lease.lease_token,
            error="permanent failure",
            retry_delay_seconds=10,
            occurred_at=T5,
        )
        self.assertEqual(record.status, EffectStatus.TERMINAL_FAILED)
        self.assertEqual(self.outbox.claim("worker-b", now=T20, lease_seconds=10), [])

    def test_expired_lease_is_recovered_and_can_be_claimed_again(self) -> None:
        self.enqueue()
        first = self.outbox.claim("worker-a", now=T0, lease_seconds=10)[0]
        self.assertEqual(self.outbox.recover_expired(now=T5), 0)
        self.assertEqual(self.outbox.recover_expired(now=T10), 1)
        record = self.outbox.get("effect-1")
        self.assertEqual(record.status, EffectStatus.PENDING)
        second = self.outbox.claim("worker-b", now=T10, lease_seconds=10)[0]
        self.assertNotEqual(first.lease_token, second.lease_token)
        self.assertEqual(second.attempt_count, 2)

    def test_stale_worker_or_expired_lease_cannot_complete(self) -> None:
        self.enqueue()
        lease = self.outbox.claim("worker-a", now=T0, lease_seconds=10)[0]
        with self.assertRaisesRegex(StateTransitionError, "lease"):
            self.outbox.succeed(
                "effect-1",
                worker_id="worker-b",
                lease_token=lease.lease_token,
                result_digest="c" * 64,
                occurred_at=T5,
            )
        with self.assertRaisesRegex(StateTransitionError, "expired"):
            self.outbox.succeed(
                "effect-1",
                worker_id="worker-a",
                lease_token=lease.lease_token,
                result_digest="c" * 64,
                occurred_at=T20,
            )


if __name__ == "__main__":
    unittest.main()
