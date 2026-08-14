from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from starcom.db import Database
from starcom.ledger import EventLedger
from starcom.trust import (
    AuthorizationDecision,
    AuthorizationRequest,
    PolicyEffect,
    PolicyRule,
    TrustPlane,
)


NOW = "2026-08-13T12:00:00.000000Z"
LATER = "2026-08-13T13:00:00.000000Z"
EARLIER = "2026-08-13T11:00:00.000000Z"


class TrustPlaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tempdir.name) / "trust.sqlite3")
        self.db.initialize()
        self.ledger = EventLedger(self.db)
        self.trust = TrustPlane(self.db, self.ledger)

    def tearDown(self) -> None:
        self.db.close()
        self.tempdir.cleanup()

    def request(self, **overrides: object) -> AuthorizationRequest:
        values: dict[str, object] = {
            "subject": "agent:researcher",
            "action": "mission:run",
            "resource": "project:starcom",
            "mission_id": "mission-1",
            "context": {"environment": "test"},
        }
        values.update(overrides)
        return AuthorizationRequest(**values)  # type: ignore[arg-type]

    def _decision_payload(self, decision: AuthorizationDecision) -> object:
        row = self.db.connection.execute(
            "SELECT payload_json FROM ledger_events WHERE event_id = ?",
            (decision.ledger_event_id,),
        ).fetchone()
        self.assertIsNotNone(row)
        assert row is not None
        return json.loads(str(row["payload_json"]))

    def _repoint_decision(
        self,
        decision: AuthorizationDecision,
        *,
        stream_id: str,
        kind: str,
        actor: str,
        occurred_at: str,
    ) -> None:
        forged = self.ledger.append(
            stream_id,
            kind,
            self._decision_payload(decision),
            actor=actor,
            occurred_at=occurred_at,
        )
        self.db.connection.execute("DROP TRIGGER trust_decisions_no_update")
        self.db.connection.execute(
            """
            UPDATE trust_decisions
            SET ledger_event_id = ?, ledger_hash = ?
            WHERE decision_id = ?
            """,
            (forged.event_id, forged.record_hash, decision.decision_id),
        )

    def test_default_is_deny_and_decision_is_ledgered(self) -> None:
        decision = self.trust.authorize(self.request(), now=NOW)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "DEFAULT_DENY")
        self.assertEqual(len(decision.request_digest), 64)
        self.assertEqual(len(decision.ledger_hash), 64)
        self.assertTrue(self.ledger.verify().ok)

    def test_wildcard_allow_rule_authorizes(self) -> None:
        self.trust.add_rule(
            PolicyRule(
                rule_id="allow-research",
                effect=PolicyEffect.ALLOW,
                subject="agent:*",
                action="mission:*",
                resource="project:*",
            ),
            actor="owner",
            occurred_at=NOW,
        )
        decision = self.trust.authorize(self.request(), now=NOW)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "POLICY_ALLOW")
        self.assertEqual(decision.matched_rule_ids, ("allow-research",))

    def test_explicit_deny_overrides_allow_regardless_of_priority(self) -> None:
        self.trust.add_rule(
            PolicyRule("allow-all", PolicyEffect.ALLOW, "*", "*", "*", priority=100),
            actor="owner",
            occurred_at=NOW,
        )
        self.trust.add_rule(
            PolicyRule(
                "deny-production",
                PolicyEffect.DENY,
                "agent:researcher",
                "mission:run",
                "project:starcom",
                conditions={"environment": "production"},
                priority=1,
            ),
            actor="owner",
            occurred_at=NOW,
        )
        decision = self.trust.authorize(
            self.request(context={"environment": "production"}),
            now=NOW,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "EXPLICIT_DENY")
        self.assertEqual(decision.matched_rule_ids, ("allow-all", "deny-production"))

    def test_rule_conditions_must_all_match(self) -> None:
        self.trust.add_rule(
            PolicyRule(
                "allow-test",
                PolicyEffect.ALLOW,
                "agent:researcher",
                "mission:run",
                "project:starcom",
                conditions={"environment": "test", "risk": "low"},
            ),
            actor="owner",
            occurred_at=NOW,
        )
        denied = self.trust.authorize(self.request(context={"environment": "test"}), now=NOW)
        allowed = self.trust.authorize(
            self.request(context={"environment": "test", "risk": "low"}),
            now=NOW,
        )
        self.assertFalse(denied.allowed)
        self.assertTrue(allowed.allowed)

    def test_expired_grant_does_not_authorize(self) -> None:
        self.trust.issue_grant(
            grant_id="expired",
            subject="agent:researcher",
            action="mission:run",
            resource="project:starcom",
            mission_id="mission-1",
            expires_at=EARLIER,
            single_use=False,
            actor="owner",
            occurred_at=EARLIER,
        )
        decision = self.trust.authorize(self.request(), now=NOW)
        self.assertFalse(decision.allowed)
        self.assertIsNone(decision.grant_id)

    def test_grant_is_scoped_to_mission(self) -> None:
        self.trust.issue_grant(
            grant_id="mission-one",
            subject="agent:researcher",
            action="mission:run",
            resource="project:starcom",
            mission_id="mission-1",
            expires_at=LATER,
            single_use=False,
            actor="owner",
            occurred_at=NOW,
        )
        wrong = self.trust.authorize(self.request(mission_id="mission-2"), now=NOW)
        right = self.trust.authorize(self.request(), now=NOW)
        self.assertFalse(wrong.allowed)
        self.assertTrue(right.allowed)
        self.assertEqual(right.reason, "GRANT_ALLOW")
        self.assertEqual(right.grant_id, "mission-one")

    def test_single_use_grant_is_consumed_atomically(self) -> None:
        self.trust.issue_grant(
            grant_id="once",
            subject="agent:researcher",
            action="mission:run",
            resource="project:starcom",
            mission_id="mission-1",
            expires_at=LATER,
            single_use=True,
            actor="owner",
            occurred_at=NOW,
        )
        first = self.trust.authorize(self.request(), now=NOW)
        second = self.trust.authorize(self.request(), now=NOW)
        self.assertTrue(first.allowed)
        self.assertEqual(first.grant_id, "once")
        self.assertFalse(second.allowed)
        self.assertEqual(second.reason, "DEFAULT_DENY")

    def test_non_consuming_authorization_keeps_single_use_grant_available(self) -> None:
        self.trust.issue_grant(
            grant_id="preview",
            subject="agent:researcher",
            action="mission:run",
            resource="project:starcom",
            mission_id="mission-1",
            expires_at=LATER,
            single_use=True,
            actor="owner",
            occurred_at=NOW,
        )
        preview = self.trust.authorize(self.request(), now=NOW, consume=False)
        consumed = self.trust.authorize(self.request(), now=NOW, consume=True)
        after = self.trust.authorize(self.request(), now=NOW, consume=True)
        self.assertTrue(preview.allowed)
        self.assertTrue(consumed.allowed)
        self.assertFalse(after.allowed)

    def test_verifier_reports_malformed_decision_request_json(self) -> None:
        decision = self.trust.authorize(self.request(), now=NOW)
        self.db.connection.execute("DROP TRIGGER trust_decisions_no_update")
        self.db.connection.execute(
            "UPDATE trust_decisions SET request_json = ? WHERE decision_id = ?",
            ("{", decision.decision_id),
        )

        verification = self.trust.verify_decision(decision.decision_id)

        self.assertFalse(verification.ok)
        self.assertIn("DECISION_REQUEST_JSON_INVALID", verification.defects)

    def test_verifier_reports_malformed_matched_rule_ids_json(self) -> None:
        decision = self.trust.authorize(self.request(), now=NOW)
        self.db.connection.execute("DROP TRIGGER trust_decisions_no_update")
        self.db.connection.execute(
            "UPDATE trust_decisions SET matched_rule_ids_json = ? WHERE decision_id = ?",
            ("{", decision.decision_id),
        )

        verification = self.trust.verify_decision(decision.decision_id)

        self.assertFalse(verification.ok)
        self.assertIn(
            "DECISION_MATCHED_RULE_IDS_JSON_INVALID",
            verification.defects,
        )

    def test_verifier_rejects_wrong_decision_ledger_kind(self) -> None:
        decision = self.trust.authorize(self.request(), now=NOW)
        self._repoint_decision(
            decision,
            stream_id="trust:decisions:agent:researcher",
            kind="AUTHORIZATION_REBOUND",
            actor="trust-plane",
            occurred_at=NOW,
        )

        verification = self.trust.verify_decision(decision.decision_id)

        self.assertFalse(verification.ok)
        self.assertIn("DECISION_LEDGER_KIND_MISMATCH", verification.defects)

    def test_verifier_rejects_cross_stream_decision_repointing(self) -> None:
        decision = self.trust.authorize(self.request(), now=NOW)
        self._repoint_decision(
            decision,
            stream_id="trust:decisions:shadow",
            kind="AUTHORIZATION_DECIDED",
            actor="trust-plane",
            occurred_at=NOW,
        )

        verification = self.trust.verify_decision(decision.decision_id)

        self.assertFalse(verification.ok)
        self.assertIn("DECISION_LEDGER_STREAM_MISMATCH", verification.defects)

    def test_verifier_rejects_wrong_decision_ledger_actor(self) -> None:
        decision = self.trust.authorize(self.request(), now=NOW)
        self._repoint_decision(
            decision,
            stream_id="trust:decisions:agent:researcher",
            kind="AUTHORIZATION_DECIDED",
            actor="intruder",
            occurred_at=NOW,
        )

        verification = self.trust.verify_decision(decision.decision_id)

        self.assertFalse(verification.ok)
        self.assertIn("DECISION_LEDGER_ACTOR_MISMATCH", verification.defects)

    def test_verifier_rejects_wrong_decision_ledger_timestamp(self) -> None:
        decision = self.trust.authorize(self.request(), now=NOW)
        self._repoint_decision(
            decision,
            stream_id="trust:decisions:agent:researcher",
            kind="AUTHORIZATION_DECIDED",
            actor="trust-plane",
            occurred_at=LATER,
        )

        verification = self.trust.verify_decision(decision.decision_id)

        self.assertFalse(verification.ok)
        self.assertIn("DECISION_LEDGER_TIMESTAMP_MISMATCH", verification.defects)


if __name__ == "__main__":
    unittest.main()
