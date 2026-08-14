from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from starcom.db import Database
from starcom.errors import ConflictError, NotFoundError, StateTransitionError
from starcom.ledger import EventLedger
from starcom.research import ReceiptOutcome, ResearchCampaign


T0 = "2026-08-13T12:00:00.000000Z"
T1 = "2026-08-13T12:01:00.000000Z"
T2 = "2026-08-13T12:02:00.000000Z"
T3 = "2026-08-13T12:03:00.000000Z"
SNAPSHOT_A = "a" * 64
SNAPSHOT_B = "b" * 64
CONTENT = "c" * 64


class ResearchCampaignTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tempdir.name) / "research.sqlite3")
        self.db.initialize()
        self.ledger = EventLedger(self.db)
        self.research = ResearchCampaign(self.db, self.ledger)
        self.research.create(
            campaign_id="campaign-1",
            name="C2 certified recollection",
            actor="owner",
            occurred_at=T0,
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tempdir.cleanup()

    def begin(
        self,
        *,
        wave: int = 1,
        request_key: str = "request-1",
        request: dict[str, object] | None = None,
        occurred_at: str = T1,
    ):
        return self.research.begin_attempt(
            "campaign-1",
            wave=wave,
            request_key=request_key,
            source_id="github:repositories",
            request=request or {"query": "agent runtime"},
            actor="agent:researcher",
            occurred_at=occurred_at,
        )

    def complete_success(
        self,
        attempt_id: str,
        *,
        wave: int,
        snapshot: str = SNAPSHOT_A,
        cursor_key: str = "page",
    ) -> None:
        self.research.record_receipt(
            attempt_id,
            receipt_id=f"receipt-{attempt_id}",
            outcome=ReceiptOutcome.SUCCESS,
            status_code=200,
            snapshot_digest=snapshot,
            metadata={"content_type": "application/json"},
            actor="agent:researcher",
            occurred_at=T2,
        )
        self.research.record_observation(
            attempt_id,
            observation_id=f"observation-{attempt_id}",
            snapshot_digest=snapshot,
            content_digest=CONTENT,
            data={"items": ["one"]},
            actor="agent:researcher",
            occurred_at=T2,
        )
        self.research.checkpoint_cursor(
            "campaign-1",
            wave=wave,
            cursor_key=cursor_key,
            value={"next": None},
            attempt_id=attempt_id,
            actor="agent:researcher",
            occurred_at=T3,
        )

    def test_normal_w1_to_w2_flow_verifies(self) -> None:
        first = self.begin(wave=1, request_key="w1", occurred_at=T1)
        self.complete_success(first.attempt_id, wave=1, cursor_key="w1-page")
        second = self.begin(wave=2, request_key="w2", occurred_at=T2)
        self.complete_success(second.attempt_id, wave=2, snapshot=SNAPSHOT_B, cursor_key="w2-page")
        verification = self.research.verify("campaign-1")
        self.assertTrue(verification.ok, verification.defects)
        self.assertEqual(verification.wave_sequence, (1, 2))
        self.assertEqual(verification.attempt_count, 2)
        self.assertEqual(verification.receipt_count, 2)
        self.assertTrue(self.ledger.verify("research:campaign:campaign-1").ok)

    def test_wave_regression_is_rejected_before_attempt_creation(self) -> None:
        self.begin(wave=3, request_key="w3")
        count = self.research.verify("campaign-1").attempt_count
        with self.assertRaisesRegex(StateTransitionError, "wave regression"):
            self.begin(wave=2, request_key="late-w2")
        self.assertEqual(self.research.verify("campaign-1").attempt_count, count)

    def test_receipt_without_preexisting_attempt_is_rejected(self) -> None:
        with self.assertRaisesRegex(NotFoundError, "attempt"):
            self.research.record_receipt(
                "missing-attempt",
                receipt_id="receipt-missing",
                outcome=ReceiptOutcome.NO_RESPONSE,
                status_code=None,
                snapshot_digest=None,
                metadata={},
                actor="agent:researcher",
                occurred_at=T2,
            )

    def test_duplicate_request_key_is_idempotent_only_for_same_request(self) -> None:
        first = self.begin(request_key="same")
        event_count = len(self.ledger.read_stream("research:campaign:campaign-1"))
        second = self.begin(request_key="same")
        self.assertEqual(first, second)
        self.assertEqual(len(self.ledger.read_stream("research:campaign:campaign-1")), event_count)
        with self.assertRaisesRegex(ConflictError, "request key"):
            self.begin(request_key="same", request={"query": "different"})

    def test_verifier_fails_closed_when_attempt_has_no_receipt(self) -> None:
        attempt = self.begin()
        verification = self.research.verify("campaign-1")
        self.assertFalse(verification.ok)
        self.assertIn(
            f"ATTEMPT_RECEIPT_MISSING:{attempt.attempt_id}",
            verification.defects,
        )

    def test_success_receipt_requires_snapshot_and_linked_observation_and_cursor(self) -> None:
        attempt = self.begin()
        with self.assertRaisesRegex(StateTransitionError, "snapshot"):
            self.research.record_receipt(
                attempt.attempt_id,
                receipt_id="receipt-no-snapshot",
                outcome=ReceiptOutcome.SUCCESS,
                status_code=200,
                snapshot_digest=None,
                metadata={},
                actor="agent:researcher",
                occurred_at=T2,
            )
        self.research.record_receipt(
            attempt.attempt_id,
            receipt_id="receipt-1",
            outcome=ReceiptOutcome.SUCCESS,
            status_code=200,
            snapshot_digest=SNAPSHOT_A,
            metadata={},
            actor="agent:researcher",
            occurred_at=T2,
        )
        incomplete = self.research.verify("campaign-1")
        self.assertIn(
            f"SUCCESS_OBSERVATION_MISSING:{attempt.attempt_id}",
            incomplete.defects,
        )
        self.assertIn(
            f"SUCCESS_CURSOR_MISSING:{attempt.attempt_id}",
            incomplete.defects,
        )
        with self.assertRaisesRegex(StateTransitionError, "snapshot"):
            self.research.record_observation(
                attempt.attempt_id,
                observation_id="observation-wrong",
                snapshot_digest=SNAPSHOT_B,
                content_digest=CONTENT,
                data={},
                actor="agent:researcher",
                occurred_at=T2,
            )
        with self.assertRaisesRegex(StateTransitionError, "wave"):
            self.research.checkpoint_cursor(
                "campaign-1",
                wave=2,
                cursor_key="wrong-wave",
                value={},
                attempt_id=attempt.attempt_id,
                actor="agent:researcher",
                occurred_at=T3,
            )

    def test_terminal_policy_block_needs_receipt_but_no_snapshot_artifacts(self) -> None:
        attempt = self.begin()
        self.research.record_receipt(
            attempt.attempt_id,
            receipt_id="policy-block",
            outcome=ReceiptOutcome.POLICY_BLOCK,
            status_code=None,
            snapshot_digest=None,
            metadata={"policy": "robots"},
            actor="agent:researcher",
            occurred_at=T2,
        )
        verification = self.research.verify("campaign-1")
        self.assertTrue(verification.ok, verification.defects)

    def test_verifier_rejects_observation_on_non_success_attempt(self) -> None:
        attempt = self.begin()
        self.research.record_receipt(
            attempt.attempt_id,
            receipt_id="policy-block-forged-observation",
            outcome=ReceiptOutcome.POLICY_BLOCK,
            status_code=403,
            snapshot_digest=None,
            metadata={"policy": "robots"},
            actor="agent:researcher",
            occurred_at=T2,
        )
        observation_id = "observation-forged-after-policy-block"
        data = {"items": ["must-not-count"]}
        payload = {
            "observation_id": observation_id,
            "attempt_id": attempt.attempt_id,
            "snapshot_digest": SNAPSHOT_A,
            "content_digest": CONTENT,
            "data": data,
        }
        event = self.ledger.append(
            "research:campaign:campaign-1",
            "RESEARCH_OBSERVATION_RECORDED",
            payload,
            actor="fixture-forger",
            occurred_at=T3,
        )
        with self.db.transaction() as connection:
            connection.execute(
                """
                INSERT INTO research_observations (
                    observation_id, attempt_id, snapshot_digest, content_digest,
                    data_json, observed_at, ledger_event_id, ledger_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation_id,
                    attempt.attempt_id,
                    SNAPSHOT_A,
                    CONTENT,
                    json.dumps(data, sort_keys=True, separators=(",", ":")),
                    T3,
                    event.event_id,
                    event.record_hash,
                ),
            )

        verification = self.research.verify("campaign-1")

        self.assertFalse(verification.ok)
        self.assertIn(
            f"NON_SUCCESS_OBSERVATION_PRESENT:{observation_id}",
            verification.defects,
        )

    def test_verifier_reports_malformed_attempt_request_json(self) -> None:
        attempt = self.begin()
        self.complete_success(attempt.attempt_id, wave=1)
        self.db.connection.execute(
            "UPDATE research_attempts SET request_json = ? WHERE attempt_id = ?",
            ("{", attempt.attempt_id),
        )

        verification = self.research.verify("campaign-1")

        self.assertFalse(verification.ok)
        self.assertIn(
            f"ATTEMPT_REQUEST_JSON_INVALID:{attempt.attempt_id}",
            verification.defects,
        )

    def test_verifier_reports_malformed_cursor_value_json(self) -> None:
        attempt = self.begin()
        self.complete_success(attempt.attempt_id, wave=1)
        cursor = self.db.connection.execute(
            "SELECT cursor_id FROM research_cursors WHERE attempt_id = ?",
            (attempt.attempt_id,),
        ).fetchone()
        assert cursor is not None
        cursor_id = str(cursor["cursor_id"])
        self.db.connection.execute("DROP TRIGGER research_cursors_no_update")
        self.db.connection.execute(
            "UPDATE research_cursors SET value_json = ? WHERE cursor_id = ?",
            ("{", cursor_id),
        )

        verification = self.research.verify("campaign-1")

        self.assertFalse(verification.ok)
        self.assertIn(
            f"CURSOR_VALUE_JSON_INVALID:{cursor_id}",
            verification.defects,
        )

    def test_verifier_detects_attempt_request_key_tampering_against_ledger(self) -> None:
        attempt = self.begin(request_key="original-key")
        self.complete_success(attempt.attempt_id, wave=1)
        self.db.connection.execute(
            "UPDATE research_attempts SET request_key = ? WHERE attempt_id = ?",
            ("tampered-key", attempt.attempt_id),
        )

        verification = self.research.verify("campaign-1")

        self.assertFalse(verification.ok)
        self.assertIn(
            f"ATTEMPT_LEDGER_PAYLOAD_MISMATCH:{attempt.attempt_id}",
            verification.defects,
        )

    def test_verifier_detects_observation_data_tampering_against_ledger(self) -> None:
        attempt = self.begin()
        self.complete_success(attempt.attempt_id, wave=1)
        observation = self.db.connection.execute(
            "SELECT observation_id FROM research_observations WHERE attempt_id = ?",
            (attempt.attempt_id,),
        ).fetchone()
        assert observation is not None
        observation_id = str(observation["observation_id"])
        self.db.connection.execute("DROP TRIGGER research_observations_no_update")
        self.db.connection.execute(
            "UPDATE research_observations SET data_json = ? WHERE observation_id = ?",
            ('{"items":["tampered"]}', observation_id),
        )

        verification = self.research.verify("campaign-1")

        self.assertFalse(verification.ok)
        self.assertIn(
            f"OBSERVATION_LEDGER_PAYLOAD_MISMATCH:{observation_id}",
            verification.defects,
        )

    def test_verifier_detects_attempt_timestamp_tampering_against_ledger(self) -> None:
        attempt = self.begin()
        self.complete_success(attempt.attempt_id, wave=1)
        self.db.connection.execute(
            "UPDATE research_attempts SET started_at = ? WHERE attempt_id = ?",
            (T3, attempt.attempt_id),
        )

        verification = self.research.verify("campaign-1")

        self.assertFalse(verification.ok)
        self.assertIn(
            f"ATTEMPT_LEDGER_TIME_MISMATCH:{attempt.attempt_id}",
            verification.defects,
        )


if __name__ == "__main__":
    unittest.main()
