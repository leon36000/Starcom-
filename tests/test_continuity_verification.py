from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from starcom.continuity import ContinuityService
from starcom.db import Database
from starcom.ledger import EventLedger
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule, TrustPlane


T0 = "2026-08-13T12:00:00.000000Z"
T1 = "2026-08-13T12:01:00.000000Z"
T2 = "2026-08-13T12:02:00.000000Z"
ARCHIVE_SHA256 = "5609915904205503ebcdcc548d9b8171fd6d9ba9bf9d1bb9f1ebb036bf8fae7f"
PUBLIC_KEY = b"test-public-key"


class DigestVerifier:
    def validate_public_key(self, public_key_pem: bytes) -> bool:
        return public_key_pem == PUBLIC_KEY

    def verify(self, public_key_pem: bytes, payload: bytes, signature: bytes) -> bool:
        return signature == hashlib.sha256(public_key_pem + payload).digest()


class ContinuityAuthorizationVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tempdir.name) / "continuity-verification.sqlite3")
        self.db.initialize()
        self.ledger = EventLedger(self.db)
        self.trust = TrustPlane(self.db, self.ledger)
        self.service = ContinuityService(self.db, self.ledger, self.trust, DigestVerifier())
        self.service.create_incident(
            "task5", reviewed_archive_sha256=ARCHIVE_SHA256, actor="owner", occurred_at=T0
        )
        self.trust.add_rule(
            PolicyRule(
                "allow-root",
                PolicyEffect.ALLOW,
                "owner",
                "continuity.trust-root.accept",
                "continuity:trust-root:reviewer-1",
            ),
            actor="owner",
            occurred_at=T0,
        )
        decision = self.trust.authorize(
            AuthorizationRequest(
                subject="owner",
                action="continuity.trust-root.accept",
                resource="continuity:trust-root:reviewer-1",
            ),
            now=T1,
        )
        self.root_decision_id = decision.decision_id
        self.service.accept_trust_root(
            "reviewer-1",
            PUBLIC_KEY,
            decision_id=decision.decision_id,
            actor="owner",
            occurred_at=T1,
        )
        payload = json.dumps(
            {
                "review_id": "review-1",
                "reviewer_identity": "independent-agent-1",
                "review_environment": "isolated-worker-1",
                "reviewed_archive_sha256": ARCHIVE_SHA256,
                "reviewed_at_utc": T1,
                "independence_basis": "fresh process and isolated extraction",
                "independent_identity_status": "SATISFIED",
                "commands_and_exit_codes": [{"command": "verify", "exit_code": 0}],
                "receipt_snapshot_observation_result": "PASS",
                "wave_order_result": "CONFIRMS_W3_TO_W2",
                "attempt_boundary_result": "POSSIBLE_UNQUANTIFIED_CONFIRMED",
                "disposition": "RECOLLECT_REQUIRED",
                "evidence_paths_and_hashes": [
                    {"path": "review.json", "sha256": "a" * 64}
                ],
                "reasoning": "The evidence confirms the nonconforming wave order.",
                "gate_effect": "NO_GATE_CHANGE",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.service.admit_review(
            "task5",
            "reviewer-1",
            payload,
            hashlib.sha256(PUBLIC_KEY + payload).digest(),
            actor="owner",
            occurred_at=T2,
        )

    def tearDown(self) -> None:
        self.db.close()
        self.tempdir.cleanup()

    def _root_row(self):
        root = self.db.connection.execute(
            "SELECT * FROM continuity_trust_roots WHERE key_id = ?",
            ("reviewer-1",),
        ).fetchone()
        self.assertIsNotNone(root)
        assert root is not None
        return root

    def _root_payload(self, root) -> dict[str, str]:
        return {
            "key_id": "reviewer-1",
            "fingerprint_sha256": str(root["fingerprint_sha256"]),
            "decision_id": str(root["decision_id"]),
        }

    def _repoint_root(self, event_id: str, record_hash: str) -> None:
        self.db.connection.execute("DROP TRIGGER continuity_trust_roots_no_update")
        self.db.connection.execute(
            """
            UPDATE continuity_trust_roots
            SET ledger_event_id = ?, ledger_hash = ?
            WHERE key_id = ?
            """,
            (event_id, record_hash, "reviewer-1"),
        )

    def test_verifier_detects_trust_root_decision_tampering(self) -> None:
        self.db.connection.execute("DROP TRIGGER trust_decisions_no_update")
        self.db.connection.execute(
            "UPDATE trust_decisions SET request_json = ? WHERE decision_id = ?",
            ("{}", self.root_decision_id),
        )

        verification = self.service.verify_incident("task5")

        self.assertFalse(verification.ok)
        self.assertIn("TRUST_ROOT_DECISION_INVALID:reviewer-1", verification.defects)

    def test_verifier_detects_trust_root_consumption_tampering(self) -> None:
        self.db.connection.execute(
            "DROP TRIGGER continuity_authorization_consumptions_no_update"
        )
        self.db.connection.execute(
            """
            UPDATE continuity_authorization_consumptions
            SET operation_id = ?
            WHERE decision_id = ?
            """,
            ("other-root", self.root_decision_id),
        )

        verification = self.service.verify_incident("task5")

        self.assertFalse(verification.ok)
        self.assertIn(
            "TRUST_ROOT_AUTHORIZATION_CONSUMPTION_MISMATCH:reviewer-1",
            verification.defects,
        )

    def test_verifier_detects_trust_root_ledger_event_binding_tampering(self) -> None:
        root = self._root_row()
        forged = self.ledger.append(
            "continuity:trust-root:reviewer-1",
            "CONTINUITY_TRUST_ROOT_REBOUND",
            self._root_payload(root),
            actor="owner",
            occurred_at=T2,
        )
        self._repoint_root(forged.event_id, forged.record_hash)

        verification = self.service.verify_incident("task5")

        self.assertFalse(verification.ok)
        self.assertIn(
            "TRUST_ROOT:reviewer-1_LEDGER_KIND_MISMATCH",
            verification.defects,
        )

    def test_verifier_detects_trust_root_cross_stream_repointing(self) -> None:
        root = self._root_row()
        forged = self.ledger.append(
            "continuity:trust-root:shadow-reviewer-1",
            "CONTINUITY_TRUST_ROOT_ACCEPTED",
            self._root_payload(root),
            actor="owner",
            occurred_at=T1,
        )
        self._repoint_root(forged.event_id, forged.record_hash)

        verification = self.service.verify_incident("task5")

        self.assertFalse(verification.ok)
        self.assertIn(
            "TRUST_ROOT:reviewer-1_LEDGER_STREAM_MISMATCH",
            verification.defects,
        )

    def test_verifier_detects_trust_root_ledger_actor_repointing(self) -> None:
        root = self._root_row()
        forged = self.ledger.append(
            "continuity:trust-root:reviewer-1",
            "CONTINUITY_TRUST_ROOT_ACCEPTED",
            self._root_payload(root),
            actor="intruder",
            occurred_at=T2,
        )
        self._repoint_root(forged.event_id, forged.record_hash)

        verification = self.service.verify_incident("task5")

        self.assertFalse(verification.ok)
        self.assertIn(
            "TRUST_ROOT:reviewer-1_LEDGER_ACTOR_MISMATCH",
            verification.defects,
        )

    def test_verifier_detects_trust_root_ledger_timestamp_repointing(self) -> None:
        root = self._root_row()
        forged = self.ledger.append(
            "continuity:trust-root:reviewer-1",
            "CONTINUITY_TRUST_ROOT_ACCEPTED",
            self._root_payload(root),
            actor="owner",
            occurred_at=T2,
        )
        self._repoint_root(forged.event_id, forged.record_hash)

        verification = self.service.verify_incident("task5")

        self.assertFalse(verification.ok)
        self.assertIn(
            "TRUST_ROOT:reviewer-1_LEDGER_TIMESTAMP_MISMATCH",
            verification.defects,
        )


if __name__ == "__main__":
    unittest.main()
