from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

import starcom.continuity_types as continuity_types
from starcom.continuity import ContinuityService
from starcom.db import Database
from starcom.ledger import EventLedger
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule, TrustPlane


T0 = "2026-08-14T06:00:00.000000Z"
T1 = "2026-08-14T06:01:00.000000Z"
T2 = "2026-08-14T06:02:00.000000Z"
PUBLIC_KEY = b"standalone-trust-root-key"


class DigestVerifier:
    def validate_public_key(self, public_key_pem: bytes) -> bool:
        return public_key_pem == PUBLIC_KEY

    def verify(self, public_key_pem: bytes, payload: bytes, signature: bytes) -> bool:
        return signature == hashlib.sha256(public_key_pem + payload).digest()


class StandaloneTrustRootVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tempdir.name) / "trust-root.sqlite3")
        self.db.initialize()
        self.ledger = EventLedger(self.db)
        self.trust = TrustPlane(self.db, self.ledger)
        self.service = ContinuityService(
            self.db,
            self.ledger,
            self.trust,
            DigestVerifier(),
        )
        self.trust.add_rule(
            PolicyRule(
                "allow-certifier-root",
                PolicyEffect.ALLOW,
                "owner",
                "continuity.trust-root.accept",
                "continuity:trust-root:certifier-1",
            ),
            actor="owner",
            occurred_at=T0,
        )
        decision = self.trust.authorize(
            AuthorizationRequest(
                subject="owner",
                action="continuity.trust-root.accept",
                resource="continuity:trust-root:certifier-1",
            ),
            now=T1,
        )
        self.decision_id = decision.decision_id
        self.service.accept_trust_root(
            "certifier-1",
            PUBLIC_KEY,
            decision_id=decision.decision_id,
            actor="owner",
            occurred_at=T1,
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tempdir.cleanup()

    def root_row(self):
        row = self.db.connection.execute(
            "SELECT * FROM continuity_trust_roots WHERE key_id = ?",
            ("certifier-1",),
        ).fetchone()
        self.assertIsNotNone(row)
        assert row is not None
        return row

    def root_payload(self) -> dict[str, str]:
        row = self.root_row()
        return {
            "key_id": "certifier-1",
            "fingerprint_sha256": str(row["fingerprint_sha256"]),
            "decision_id": str(row["decision_id"]),
        }

    def repoint_root(self, event_id: str, record_hash: str) -> None:
        self.db.connection.execute("DROP TRIGGER continuity_trust_roots_no_update")
        self.db.connection.execute(
            """
            UPDATE continuity_trust_roots
            SET ledger_event_id = ?, ledger_hash = ?
            WHERE key_id = ?
            """,
            (event_id, record_hash, "certifier-1"),
        )

    def assert_defect(self, expected: str) -> None:
        verification = self.service.verify_trust_root("certifier-1")
        self.assertFalse(verification.ok)
        self.assertIn(expected, verification.defects)

    def test_clean_root_verifies_without_incident_or_review(self) -> None:
        verification = self.service.verify_trust_root("certifier-1")

        self.assertTrue(verification.ok, verification.defects)
        self.assertEqual(verification.key_id, "certifier-1")
        self.assertIsInstance(verification, continuity_types.TrustRootVerification)

    def test_missing_root_returns_fail_closed_verification(self) -> None:
        verification = self.service.verify_trust_root("missing-certifier")

        self.assertFalse(verification.ok)
        self.assertEqual(verification.key_id, "missing-certifier")
        self.assertEqual(
            verification.defects,
            ("TRUST_ROOT_NOT_FOUND:missing-certifier",),
        )

    def test_fingerprint_tampering_is_detected(self) -> None:
        self.db.connection.execute("DROP TRIGGER continuity_trust_roots_no_update")
        self.db.connection.execute(
            "UPDATE continuity_trust_roots SET fingerprint_sha256 = ? WHERE key_id = ?",
            ("0" * 64, "certifier-1"),
        )

        self.assert_defect("TRUST_ROOT_FINGERPRINT_MISMATCH:certifier-1")

    def test_decision_tampering_is_detected(self) -> None:
        self.db.connection.execute("DROP TRIGGER trust_decisions_no_update")
        self.db.connection.execute(
            "UPDATE trust_decisions SET request_json = ? WHERE decision_id = ?",
            ("{}", self.decision_id),
        )

        self.assert_defect("TRUST_ROOT_DECISION_INVALID:certifier-1")

    def test_authorization_consumption_tampering_is_detected(self) -> None:
        self.db.connection.execute(
            "DROP TRIGGER continuity_authorization_consumptions_no_update"
        )
        self.db.connection.execute(
            """
            UPDATE continuity_authorization_consumptions
            SET operation_id = ?
            WHERE decision_id = ?
            """,
            ("other-root", self.decision_id),
        )

        self.assert_defect(
            "TRUST_ROOT_AUTHORIZATION_CONSUMPTION_MISMATCH:certifier-1"
        )

    def test_ledger_kind_repointing_is_detected(self) -> None:
        forged = self.ledger.append(
            "continuity:trust-root:certifier-1",
            "CONTINUITY_TRUST_ROOT_REBOUND",
            self.root_payload(),
            actor="owner",
            occurred_at=T1,
        )
        self.repoint_root(forged.event_id, forged.record_hash)

        self.assert_defect("TRUST_ROOT:certifier-1_LEDGER_KIND_MISMATCH")

    def test_ledger_payload_repointing_is_detected(self) -> None:
        payload = self.root_payload()
        payload["fingerprint_sha256"] = "f" * 64
        forged = self.ledger.append(
            "continuity:trust-root:certifier-1",
            "CONTINUITY_TRUST_ROOT_ACCEPTED",
            payload,
            actor="owner",
            occurred_at=T1,
        )
        self.repoint_root(forged.event_id, forged.record_hash)

        self.assert_defect("TRUST_ROOT:certifier-1_LEDGER_PAYLOAD_MISMATCH")

    def test_ledger_stream_repointing_is_detected(self) -> None:
        forged = self.ledger.append(
            "continuity:trust-root:shadow-certifier",
            "CONTINUITY_TRUST_ROOT_ACCEPTED",
            self.root_payload(),
            actor="owner",
            occurred_at=T1,
        )
        self.repoint_root(forged.event_id, forged.record_hash)

        self.assert_defect("TRUST_ROOT:certifier-1_LEDGER_STREAM_MISMATCH")

    def test_ledger_actor_repointing_is_detected(self) -> None:
        forged = self.ledger.append(
            "continuity:trust-root:certifier-1",
            "CONTINUITY_TRUST_ROOT_ACCEPTED",
            self.root_payload(),
            actor="intruder",
            occurred_at=T1,
        )
        self.repoint_root(forged.event_id, forged.record_hash)

        self.assert_defect("TRUST_ROOT:certifier-1_LEDGER_ACTOR_MISMATCH")

    def test_ledger_timestamp_repointing_is_detected(self) -> None:
        forged = self.ledger.append(
            "continuity:trust-root:certifier-1",
            "CONTINUITY_TRUST_ROOT_ACCEPTED",
            self.root_payload(),
            actor="owner",
            occurred_at=T2,
        )
        self.repoint_root(forged.event_id, forged.record_hash)

        self.assert_defect("TRUST_ROOT:certifier-1_LEDGER_TIMESTAMP_MISMATCH")

    def test_stored_ledger_hash_tampering_is_detected(self) -> None:
        self.db.connection.execute("DROP TRIGGER continuity_trust_roots_no_update")
        self.db.connection.execute(
            "UPDATE continuity_trust_roots SET ledger_hash = ? WHERE key_id = ?",
            ("0" * 64, "certifier-1"),
        )

        self.assert_defect("TRUST_ROOT:certifier-1_LEDGER_HASH_MISMATCH")

    def test_trust_root_ledger_chain_tampering_is_detected(self) -> None:
        second = self.ledger.append(
            "continuity:trust-root:certifier-1",
            "TRUST_ROOT_AUDIT_MARKER",
            {"key_id": "certifier-1"},
            actor="auditor",
            occurred_at=T2,
        )
        self.db.connection.execute("DROP TRIGGER ledger_events_no_update")
        self.db.connection.execute(
            "UPDATE ledger_events SET prev_hash = ? WHERE event_id = ?",
            ("0" * 64, second.event_id),
        )

        self.assert_defect("TRUST_ROOT_LEDGER_CHAIN_INVALID:certifier-1")


if __name__ == "__main__":
    unittest.main()
