from __future__ import annotations

import json
import unittest

from starcom.canonical import sha256_digest
from starcom.recollection import (
    CampaignPlanItem,
    RecollectionLedger,
    RecollectionNotFound,
)
from starcom.recollection_executor import (
    AttemptContext,
    BoundedRecollectionExecutor,
    ReceiptOutcome,
)


T0 = "2026-08-13T22:00:00.000000Z"
T1 = "2026-08-13T22:00:01.000000Z"
T2 = "2026-08-13T22:00:02.000000Z"
T3 = "2026-08-13T22:00:03.000000Z"


def item(item_id: str = "item") -> CampaignPlanItem:
    return CampaignPlanItem(item_id, 1, "github", f"partition-{item_id}", {"query": item_id})


def rehash_events(ledger: RecollectionLedger, campaign_id: str) -> None:
    previous = "0" * 64
    rows = ledger.connection.execute(
        "SELECT * FROM recollection_events WHERE campaign_id=? ORDER BY sequence",
        (campaign_id,),
    ).fetchall()
    for row in rows:
        payload = json.loads(row["payload_json"])
        event_hash = sha256_digest(
            {
                "campaign_id": campaign_id,
                "sequence": row["sequence"],
                "event_type": row["event_type"],
                "payload": payload,
                "previous_hash": previous,
                "recorded_at": row["recorded_at"],
            }
        )
        ledger.connection.execute(
            "UPDATE recollection_events SET previous_hash=?,event_hash=? "
            "WHERE campaign_id=? AND sequence=?",
            (previous, event_hash, campaign_id, row["sequence"]),
        )
        previous = event_hash


class CountingAdapter:
    def __init__(self) -> None:
        self.calls = 0

    def execute(self, context: AttemptContext) -> ReceiptOutcome:
        self.calls += 1
        return ReceiptOutcome({"status": 200})


class RecollectionTemporalIntegrityTests(unittest.TestCase):
    def test_campaign_timestamp_requires_strict_rfc3339_utc(self) -> None:
        ledger = RecollectionLedger(":memory:")
        try:
            for invalid in (
                "2026-08-13Z",
                "2026-99-99T22:00:00Z",
                "2026-08-13T22:00:00.1234567Z",
                "2026-08-13T22:00:00+00:00",
            ):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    ledger.create_sealed_campaign("campaign", [item()], created_at=invalid)
        finally:
            ledger.close()

    def test_prepare_before_campaign_creation_rolls_back_completely(self) -> None:
        ledger = RecollectionLedger(":memory:")
        try:
            ledger.create_sealed_campaign("campaign", [item()], created_at=T1)
            with self.assertRaises(ValueError):
                ledger.prepare_attempt("campaign", "item", "attempt", prepared_at=T0)
            with self.assertRaises(RecollectionNotFound):
                ledger.get_attempt("attempt")
            self.assertEqual(1, ledger.event_count("campaign"))
        finally:
            ledger.close()

    def test_terminal_before_prepare_rolls_back_and_leaves_attempt_open(self) -> None:
        ledger = RecollectionLedger(":memory:")
        try:
            ledger.create_sealed_campaign("campaign", [item()], created_at=T0)
            ledger.prepare_attempt("campaign", "item", "attempt", prepared_at=T2)
            with self.assertRaises(ValueError):
                ledger.record_receipt("attempt", {"status": 200}, terminal_at=T1)
            stored = ledger.get_attempt("attempt")
            self.assertEqual("PRE_REQUEST_RECORDED", stored.state)
            self.assertIsNone(stored.terminal_kind)
            self.assertEqual(2, ledger.event_count("campaign"))
        finally:
            ledger.close()

    def test_retry_timestamp_cannot_regress_behind_prior_terminal(self) -> None:
        ledger = RecollectionLedger(":memory:")
        try:
            ledger.create_sealed_campaign("campaign", [item()], created_at=T0)
            ledger.prepare_attempt("campaign", "item", "attempt-1", prepared_at=T1)
            ledger.record_no_receipt_failure("attempt-1", "TIMEOUT", terminal_at=T3)
            with self.assertRaises(ValueError):
                ledger.prepare_attempt("campaign", "item", "attempt-2", prepared_at=T2)
            with self.assertRaises(RecollectionNotFound):
                ledger.get_attempt("attempt-2")
            self.assertEqual(3, ledger.event_count("campaign"))
        finally:
            ledger.close()

    def test_finalization_cannot_precede_last_terminal_event(self) -> None:
        ledger = RecollectionLedger(":memory:")
        try:
            ledger.create_sealed_campaign("campaign", [item()], created_at=T0)
            ledger.prepare_attempt("campaign", "item", "attempt", prepared_at=T1)
            ledger.record_receipt("attempt", {"status": 200}, terminal_at=T3)
            with self.assertRaises(ValueError):
                ledger.finalize_campaign("campaign", finalized_at=T2)
            self.assertEqual("RUNNING", ledger.get_campaign("campaign").status)
            self.assertEqual(3, ledger.event_count("campaign"))
        finally:
            ledger.close()

    def test_verifier_detects_temporal_regression_after_full_rehash(self) -> None:
        ledger = RecollectionLedger(":memory:")
        try:
            ledger.create_sealed_campaign("campaign", [item()], created_at=T0)
            ledger.prepare_attempt("campaign", "item", "attempt", prepared_at=T2)
            ledger.record_receipt("attempt", {"status": 200}, terminal_at=T3)
            ledger.connection.execute(
                "UPDATE recollection_attempts SET terminal_at=? WHERE attempt_id=?",
                (T1, "attempt"),
            )
            ledger.connection.execute(
                "UPDATE recollection_events SET recorded_at=? "
                "WHERE campaign_id=? AND sequence=3",
                (T1, "campaign"),
            )
            rehash_events(ledger, "campaign")
            defects = ledger.verify_campaign("campaign").defects
            self.assertIn("EVENT_TIMESTAMP_REGRESSION:3", defects)
            self.assertIn("ATTEMPT_TERMINAL_BEFORE_PREPARE:attempt", defects)
        finally:
            ledger.close()

    def test_verifier_cross_checks_row_and_event_timestamps(self) -> None:
        ledger = RecollectionLedger(":memory:")
        try:
            ledger.create_sealed_campaign("campaign", [item()], created_at=T0)
            ledger.prepare_attempt("campaign", "item", "attempt", prepared_at=T1)
            ledger.record_receipt("attempt", {"status": 200}, terminal_at=T2)
            ledger.connection.execute(
                "UPDATE recollection_attempts SET terminal_at=? WHERE attempt_id=?",
                (T3, "attempt"),
            )
            defects = ledger.verify_campaign("campaign").defects
            self.assertIn("ATTEMPT_TERMINAL_EVENT_TIME_MISMATCH:attempt", defects)
        finally:
            ledger.close()

    def test_equal_timestamps_are_allowed_and_verifiable(self) -> None:
        ledger = RecollectionLedger(":memory:")
        try:
            ledger.create_sealed_campaign("campaign", [item()], created_at=T0)
            ledger.prepare_attempt("campaign", "item", "attempt", prepared_at=T0)
            ledger.record_receipt("attempt", {"status": 200}, terminal_at=T0)
            ledger.finalize_campaign("campaign", finalized_at=T0)
            self.assertTrue(ledger.verify_campaign("campaign").ok)
        finally:
            ledger.close()

    def test_executor_rejects_terminal_before_prepare_without_side_effect(self) -> None:
        ledger = RecollectionLedger(":memory:")
        try:
            ledger.create_sealed_campaign("campaign", [item()], created_at=T0)
            adapter = CountingAdapter()
            with self.assertRaises(ValueError):
                BoundedRecollectionExecutor(ledger).execute(
                    "campaign", "item", "attempt", adapter,
                    prepared_at=T2, terminal_at=T1,
                )
            self.assertEqual(0, adapter.calls)
            with self.assertRaises(RecollectionNotFound):
                ledger.get_attempt("attempt")
        finally:
            ledger.close()

    def test_executor_rejects_noncanonical_fraction_before_side_effect(self) -> None:
        ledger = RecollectionLedger(":memory:")
        try:
            ledger.create_sealed_campaign("campaign", [item()], created_at=T0)
            adapter = CountingAdapter()
            with self.assertRaises(ValueError):
                BoundedRecollectionExecutor(ledger).execute(
                    "campaign", "item", "attempt", adapter,
                    prepared_at=T1,
                    terminal_at="2026-08-13T22:00:02.1234567Z",
                )
            self.assertEqual(0, adapter.calls)
            with self.assertRaises(RecollectionNotFound):
                ledger.get_attempt("attempt")
        finally:
            ledger.close()


if __name__ == "__main__":
    unittest.main()
