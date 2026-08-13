from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from starcom.db import Database
from starcom.errors import ConflictError
from starcom.ledger import EventLedger, GENESIS_HASH


class LedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "starcom.sqlite3"
        self.db = Database(self.db_path)
        self.db.initialize()
        self.ledger = EventLedger(self.db)

    def tearDown(self) -> None:
        self.db.close()
        self.tempdir.cleanup()

    def test_first_append_creates_genesis_link_and_receipt(self) -> None:
        receipt = self.ledger.append(
            "mission:one",
            "MISSION_CREATED",
            {"name": "One"},
            actor="owner",
            event_id="11111111-1111-4111-8111-111111111111",
            occurred_at="2026-08-13T12:00:00.000000Z",
        )
        self.assertEqual(receipt.sequence, 1)
        self.assertEqual(receipt.prev_hash, GENESIS_HASH)
        self.assertEqual(len(receipt.record_hash), 64)
        self.assertEqual(self.ledger.head("mission:one"), receipt.record_hash)

    def test_chained_appends_are_read_in_sequence(self) -> None:
        first = self.ledger.append("s", "A", {"n": 1}, actor="a")
        second = self.ledger.append("s", "B", {"n": 2}, actor="b", expected_head=first.record_hash)
        events = self.ledger.read_stream("s")
        self.assertEqual([event.sequence for event in events], [1, 2])
        self.assertEqual(events[1].prev_hash, first.record_hash)
        self.assertEqual(events[1].record_hash, second.record_hash)
        self.assertEqual(events[1].payload, {"n": 2})

    def test_expected_head_conflict_is_fail_closed(self) -> None:
        self.ledger.append("s", "A", {}, actor="a")
        with self.assertRaisesRegex(ConflictError, "stream head"):
            self.ledger.append("s", "B", {}, actor="a", expected_head=GENESIS_HASH)
        self.assertEqual(len(self.ledger.read_stream("s")), 1)

    def test_duplicate_event_id_is_rejected(self) -> None:
        event_id = "22222222-2222-4222-8222-222222222222"
        self.ledger.append("s1", "A", {}, actor="a", event_id=event_id)
        with self.assertRaisesRegex(ConflictError, "event_id"):
            self.ledger.append("s2", "B", {}, actor="a", event_id=event_id)

    def test_database_blocks_normal_event_updates_and_deletes(self) -> None:
        receipt = self.ledger.append("s", "A", {"n": 1}, actor="a")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "UPDATE ledger_events SET payload_json = ? WHERE event_id = ?",
                (json.dumps({"n": 9}), receipt.event_id),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.connection.execute(
                "DELETE FROM ledger_events WHERE event_id = ?",
                (receipt.event_id,),
            )

    def test_verifier_detects_payload_tampering(self) -> None:
        receipt = self.ledger.append("s", "A", {"n": 1}, actor="a")
        self.db.connection.execute("DROP TRIGGER ledger_events_no_update")
        self.db.connection.execute(
            "UPDATE ledger_events SET payload_json = ? WHERE event_id = ?",
            ('{"n":9}', receipt.event_id),
        )
        verification = self.ledger.verify("s")
        self.assertFalse(verification.ok)
        self.assertEqual(verification.checked_events, 1)
        self.assertIn("RECORD_HASH_MISMATCH", [d.code for d in verification.defects])

    def test_verifier_detects_sequence_and_previous_hash_tampering(self) -> None:
        self.ledger.append("s", "A", {}, actor="a")
        second = self.ledger.append("s", "B", {}, actor="a")
        self.db.connection.execute("DROP TRIGGER ledger_events_no_update")
        self.db.connection.execute(
            "UPDATE ledger_events SET prev_hash = ? WHERE event_id = ?",
            (GENESIS_HASH, second.event_id),
        )
        verification = self.ledger.verify("s")
        codes = [defect.code for defect in verification.defects]
        self.assertIn("PREVIOUS_HASH_MISMATCH", codes)
        self.assertIn("RECORD_HASH_MISMATCH", codes)

    def test_verifier_accepts_multiple_valid_streams(self) -> None:
        self.ledger.append("a", "A", {}, actor="x")
        self.ledger.append("a", "B", {}, actor="x")
        self.ledger.append("b", "A", {}, actor="y")
        verification = self.ledger.verify()
        self.assertTrue(verification.ok, verification.defects)
        self.assertEqual(verification.checked_events, 3)
        self.assertEqual(verification.checked_streams, 2)


if __name__ == "__main__":
    unittest.main()
