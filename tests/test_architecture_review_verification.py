from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from starcom.architecture_review import (
    C4ArchitectureReviewService,
    C4ArchitectureReviewVerification,
    C4ArchitectureReviewerRootVerification,
)
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule
from test_architecture_review import CanonicalGraph, PUBLIC_KEY, RecordingSignatureVerifier, T0, T1


class C4ArchitectureReviewerRootVerificationTests(unittest.TestCase):
    key_id = "review-key"
    reviewer_identity = "independent-c4-reviewer"
    accepting_actor = "c4-root-owner"

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.graph = CanonicalGraph(Path(self.tempdir.name))
        self.verifier = RecordingSignatureVerifier()

    def tearDown(self) -> None:
        self.graph.close()
        self.tempdir.cleanup()

    def service(self) -> C4ArchitectureReviewService:
        return C4ArchitectureReviewService(
            self.graph.database,
            self.graph.ledger,
            self.graph.trust,
            self.graph.continuity,
            self.graph.inputs,
            self.graph.candidates,
            signature_verifier=self.verifier,
        )

    def accept_root(self):  # type: ignore[no-untyped-def]
        context = {
            "algorithm": "Ed25519",
            "fingerprint_sha256": hashlib.sha256(PUBLIC_KEY).hexdigest(),
            "purpose": "C4_ARCHITECTURE_REVIEW",
            "reviewer_identity": self.reviewer_identity,
        }
        request = AuthorizationRequest(
            subject=self.accepting_actor,
            action="c4.architecture-reviewer.accept",
            resource=f"continuity:c4:architecture-reviewer:{self.key_id}",
            mission_id=f"c4-architecture-reviewer:{self.key_id}",
            context=context,
        )
        self.graph.trust.add_rule(
            PolicyRule(
                rule_id="allow-c4-reviewer-root",
                effect=PolicyEffect.ALLOW,
                subject=request.subject,
                action=request.action,
                resource=request.resource,
                conditions=context,
                priority=100,
            ),
            actor="test-policy-owner",
            occurred_at=T0,
        )
        decision = self.graph.trust.authorize(request, now=T0, consume=False)
        self.assertTrue(decision.allowed)
        return self.service().accept_reviewer_root(
            self.key_id,
            self.reviewer_identity,
            PUBLIC_KEY,
            authorization_decision_id=decision.decision_id,
            actor=self.accepting_actor,
            occurred_at=T1,
        )

    def assert_trigger_blocks(self, sql: str, parameters: tuple[object, ...]) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self.graph.database.connection.execute(sql, parameters)

    def drop_trigger_and_execute(
        self, trigger: str, sql: str, parameters: tuple[object, ...]
    ) -> None:
        self.graph.database.connection.execute(f"DROP TRIGGER {trigger}")
        self.graph.database.connection.execute(sql, parameters)

    def assert_detects(self, defect_prefix: str) -> None:
        result = self.service().verify_reviewer_root(self.key_id)
        self.assertFalse(result.ok)
        self.assertTrue(
            any(defect.startswith(defect_prefix) for defect in result.defects),
            result.defects,
        )

    def update_root(
        self,
        assignment: str,
        parameters: tuple[object, ...],
        *,
        ignore_checks: bool = False,
    ) -> None:
        self.graph.database.connection.execute(
            "DROP TRIGGER c4_architecture_reviewer_roots_no_update"
        )
        if ignore_checks:
            self.graph.database.connection.execute(
                "PRAGMA ignore_check_constraints = ON"
            )
        try:
            self.graph.database.connection.execute(
                f"UPDATE c4_architecture_reviewer_roots SET {assignment} WHERE key_id = ?",
                parameters + (self.key_id,),
            )
        finally:
            if ignore_checks:
                self.graph.database.connection.execute(
                    "PRAGMA ignore_check_constraints = OFF"
                )

    def update_consumption(
        self,
        decision_id: str,
        assignment: str,
        parameters: tuple[object, ...],
    ) -> None:
        self.graph.database.connection.execute(
            "DROP TRIGGER continuity_authorization_consumptions_no_update"
        )
        self.graph.database.connection.execute(
            "UPDATE continuity_authorization_consumptions "
            f"SET {assignment} WHERE decision_id = ?",
            parameters + (decision_id,),
        )

    def update_event(
        self,
        event_id: str,
        assignment: str,
        parameters: tuple[object, ...],
    ) -> None:
        self.graph.database.connection.execute("DROP TRIGGER ledger_events_no_update")
        self.graph.database.connection.execute(
            f"UPDATE ledger_events SET {assignment} WHERE event_id = ?",
            parameters + (event_id,),
        )

    def additional_root_decision(self):  # type: ignore[no-untyped-def]
        context = {
            "algorithm": "Ed25519",
            "fingerprint_sha256": hashlib.sha256(PUBLIC_KEY).hexdigest(),
            "purpose": "C4_ARCHITECTURE_REVIEW",
            "reviewer_identity": self.reviewer_identity,
        }
        return self.graph.trust.authorize(
            AuthorizationRequest(
                subject=self.accepting_actor,
                action="c4.architecture-reviewer.accept",
                resource=f"continuity:c4:architecture-reviewer:{self.key_id}",
                mission_id=f"c4-architecture-reviewer:{self.key_id}",
                context=context,
            ),
            now=T0,
            consume=False,
        )

    def test_verify_reviewer_root_accepts_clean_authorized_root(self) -> None:
        self.accept_root()
        result = self.service().verify_reviewer_root(self.key_id)
        self.assertTrue(result.ok, result.defects)

    def test_verify_reviewer_root_detects_tampered_algorithm(self) -> None:
        self.accept_root()
        self.update_root("algorithm = ?", ("RSA",), ignore_checks=True)
        self.assert_detects("REVIEWER_ROOT_ALGORITHM_MISMATCH")

    def test_verify_reviewer_root_detects_tampered_purpose(self) -> None:
        self.accept_root()
        self.update_root(
            "purpose = ?",
            ("C4_ARCHITECTURE_CANDIDATE",),
            ignore_checks=True,
        )
        self.assert_detects("REVIEWER_ROOT_PURPOSE_MISMATCH")

    def test_verify_reviewer_root_detects_tampered_stored_fingerprint(self) -> None:
        self.accept_root()
        self.update_root("fingerprint_sha256 = ?", ("f" * 64,))
        self.assert_detects("REVIEWER_ROOT_FINGERPRINT_MISMATCH")

    def test_verify_reviewer_root_detects_tampered_authorization_decision_id(self) -> None:
        root = self.accept_root()
        replacement = self.additional_root_decision()
        self.assertTrue(replacement.allowed)
        self.assertNotEqual(replacement.decision_id, root.authorization_decision_id)
        self.update_root(
            "authorization_decision_id = ?",
            (replacement.decision_id,),
        )
        self.assert_detects("REVIEWER_ROOT_AUTHORIZATION_CONSUMPTION_MISSING")

    def test_verify_reviewer_root_detects_tampered_accepting_actor(self) -> None:
        self.accept_root()
        self.update_root("accepted_by = ?", ("tampered-root-owner",))
        self.assert_detects("REVIEWER_ROOT_ACCEPTANCE_ACTOR_MISMATCH")

    def test_verify_reviewer_root_detects_tampered_acceptance_time(self) -> None:
        self.accept_root()
        self.update_root("accepted_at = ?", ("2026-08-16T11:59:59.000000Z",))
        self.assert_detects("REVIEWER_ROOT_ACCEPTANCE_PREDATES_DECISION")

    def test_verify_reviewer_root_reports_malformed_acceptance_timestamp(self) -> None:
        self.accept_root()
        self.update_root("accepted_at = ?", ("not-a-timestamp",))
        self.assert_detects("REVIEWER_ROOT_ACCEPTANCE_CHRONOLOGY_INVALID")

    def test_verify_reviewer_root_reports_non_blob_public_key_without_raising(self) -> None:
        self.accept_root()
        self.update_root("public_key_pem = ?", ("not-a-blob",))
        self.assert_detects("REVIEWER_ROOT_PUBLIC_KEY_INVALID")

    def test_verify_reviewer_root_reports_malformed_decision_json_without_raising(self) -> None:
        root = self.accept_root()
        self.graph.database.connection.execute("DROP TRIGGER trust_decisions_no_update")
        self.graph.database.connection.execute(
            "UPDATE trust_decisions SET request_json = ? WHERE decision_id = ?",
            ("{not-json", root.authorization_decision_id),
        )
        self.assert_detects("REVIEWER_ROOT_DECISION_INVALID")

    def test_verify_reviewer_root_detects_tampered_reviewer_identity(self) -> None:
        self.accept_root()
        self.assert_trigger_blocks(
            "UPDATE c4_architecture_reviewer_roots SET reviewer_identity = ? WHERE key_id = ?",
            ("tampered-reviewer", self.key_id),
        )
        self.drop_trigger_and_execute(
            "c4_architecture_reviewer_roots_no_update",
            "UPDATE c4_architecture_reviewer_roots SET reviewer_identity = ? WHERE key_id = ?",
            ("tampered-reviewer", self.key_id),
        )
        self.assert_detects("REVIEWER_ROOT_IDENTITY_MISMATCH")

    def test_verify_reviewer_root_detects_tampered_public_key_fingerprint(self) -> None:
        self.accept_root()
        self.assert_trigger_blocks(
            "UPDATE c4_architecture_reviewer_roots SET public_key_pem = ? WHERE key_id = ?",
            (b"tampered-ed25519-public-key", self.key_id),
        )
        self.drop_trigger_and_execute(
            "c4_architecture_reviewer_roots_no_update",
            "UPDATE c4_architecture_reviewer_roots SET public_key_pem = ? WHERE key_id = ?",
            (b"tampered-ed25519-public-key", self.key_id),
        )
        self.assert_detects("REVIEWER_ROOT_FINGERPRINT_MISMATCH")

    def test_verify_reviewer_root_detects_tampered_authorization_subject(self) -> None:
        root = self.accept_root()
        row = self.graph.database.connection.execute(
            "SELECT request_json FROM trust_decisions WHERE decision_id = ?",
            (root.authorization_decision_id,),
        ).fetchone()
        assert row is not None
        request = json.loads(str(row["request_json"]))
        request["subject"] = "other-root-owner"
        self.assert_trigger_blocks(
            "UPDATE trust_decisions SET request_json = ? WHERE decision_id = ?",
            (json.dumps(request, sort_keys=True), root.authorization_decision_id),
        )
        self.drop_trigger_and_execute(
            "trust_decisions_no_update",
            "UPDATE trust_decisions SET request_json = ? WHERE decision_id = ?",
            (json.dumps(request, sort_keys=True), root.authorization_decision_id),
        )
        self.assert_detects("REVIEWER_ROOT_DECISION_INVALID")

    def test_verify_reviewer_root_detects_tampered_authorization_consumption(self) -> None:
        root = self.accept_root()
        self.assert_trigger_blocks(
            "UPDATE continuity_authorization_consumptions "
            "SET operation_kind = ? WHERE decision_id = ?",
            ("OTHER_OPERATION", root.authorization_decision_id),
        )
        self.drop_trigger_and_execute(
            "continuity_authorization_consumptions_no_update",
            "UPDATE continuity_authorization_consumptions "
            "SET operation_kind = ?, operation_id = ? WHERE decision_id = ?",
            ("OTHER_OPERATION", "other-key", root.authorization_decision_id),
        )
        self.assert_detects("REVIEWER_ROOT_AUTHORIZATION_CONSUMPTION_MISMATCH")

    def test_verify_reviewer_root_detects_consumption_kind_tamper(self) -> None:
        root = self.accept_root()
        self.update_consumption(
            root.authorization_decision_id,
            "operation_kind = ?",
            ("OTHER_OPERATION",),
        )
        self.assert_detects(
            "REVIEWER_ROOT_AUTHORIZATION_CONSUMPTION_KIND_MISMATCH"
        )

    def test_verify_reviewer_root_detects_consumption_id_tamper(self) -> None:
        root = self.accept_root()
        self.update_consumption(
            root.authorization_decision_id,
            "operation_id = ?",
            ("other-key",),
        )
        self.assert_detects(
            "REVIEWER_ROOT_AUTHORIZATION_CONSUMPTION_ID_MISMATCH"
        )

    def test_verify_reviewer_root_detects_consumption_actor_tamper(self) -> None:
        root = self.accept_root()
        self.update_consumption(
            root.authorization_decision_id,
            "consumed_by = ?",
            ("other-root-owner",),
        )
        self.assert_detects(
            "REVIEWER_ROOT_AUTHORIZATION_CONSUMPTION_ACTOR_MISMATCH"
        )

    def test_verify_reviewer_root_detects_consumption_time_tamper(self) -> None:
        root = self.accept_root()
        self.update_consumption(
            root.authorization_decision_id,
            "consumed_at = ?",
            ("2026-08-16T12:02:00.000000Z",),
        )
        self.assert_detects(
            "REVIEWER_ROOT_AUTHORIZATION_CONSUMPTION_TIME_MISMATCH"
        )

    def test_verify_reviewer_root_detects_tampered_acceptance_actor_and_chronology(self) -> None:
        self.accept_root()
        self.assert_trigger_blocks(
            "UPDATE c4_architecture_reviewer_roots SET accepted_by = ? WHERE key_id = ?",
            ("tampered-owner", self.key_id),
        )
        self.drop_trigger_and_execute(
            "c4_architecture_reviewer_roots_no_update",
            "UPDATE c4_architecture_reviewer_roots "
            "SET accepted_by = ?, accepted_at = ? WHERE key_id = ?",
            ("tampered-owner", "2026-08-16T11:59:59.000000Z", self.key_id),
        )
        self.assert_detects("REVIEWER_ROOT_ACCEPTANCE_")

    def test_verify_reviewer_root_detects_tampered_ledger_event_payload_and_hash(self) -> None:
        root = self.accept_root()
        self.assert_trigger_blocks(
            "UPDATE ledger_events SET kind = ? WHERE event_id = ?",
            ("TAMPERED", root.ledger_event_id),
        )
        self.drop_trigger_and_execute(
            "ledger_events_no_update",
            "UPDATE ledger_events SET kind = ?, payload_json = ?, record_hash = ? WHERE event_id = ?",
            ("TAMPERED", '{"tampered":true}', "f" * 64, root.ledger_event_id),
        )
        self.assert_detects("REVIEWER_ROOT_LEDGER_")

    def test_verify_reviewer_root_detects_ledger_stream_tamper(self) -> None:
        root = self.accept_root()
        self.update_event(
            root.ledger_event_id,
            "stream_id = ?",
            ("tampered:c4:reviewer-root",),
        )
        self.assert_detects("REVIEWER_ROOT_LEDGER_STREAM_MISMATCH")

    def test_verify_reviewer_root_detects_ledger_kind_tamper(self) -> None:
        root = self.accept_root()
        self.update_event(root.ledger_event_id, "kind = ?", ("TAMPERED",))
        self.assert_detects("REVIEWER_ROOT_LEDGER_KIND_MISMATCH")

    def test_verify_reviewer_root_detects_ledger_actor_tamper(self) -> None:
        root = self.accept_root()
        self.update_event(
            root.ledger_event_id,
            "actor = ?",
            ("tampered-root-owner",),
        )
        self.assert_detects("REVIEWER_ROOT_LEDGER_ACTOR_MISMATCH")

    def test_verify_reviewer_root_detects_ledger_time_tamper(self) -> None:
        root = self.accept_root()
        self.update_event(
            root.ledger_event_id,
            "occurred_at = ?",
            ("2026-08-16T12:02:00.000000Z",),
        )
        self.assert_detects("REVIEWER_ROOT_LEDGER_TIME_MISMATCH")

    def test_verify_reviewer_root_detects_ledger_payload_tamper(self) -> None:
        root = self.accept_root()
        self.update_event(
            root.ledger_event_id,
            "payload_json = ?",
            ('{"tampered":true}',),
        )
        self.assert_detects("REVIEWER_ROOT_LEDGER_PAYLOAD_MISMATCH")

    def test_verify_reviewer_root_detects_ledger_hash_tamper(self) -> None:
        root = self.accept_root()
        self.update_event(root.ledger_event_id, "record_hash = ?", ("f" * 64,))
        self.assert_detects("REVIEWER_ROOT_LEDGER_HASH_MISMATCH")

    def test_verify_reviewer_root_reports_malformed_ledger_payload_without_raising(self) -> None:
        root = self.accept_root()
        self.update_event(root.ledger_event_id, "payload_json = ?", ("{not-json",))
        self.assert_detects("REVIEWER_ROOT_LEDGER_PAYLOAD_INVALID")

    def test_verify_reviewer_root_detects_broken_ledger_previous_hash_chain(self) -> None:
        root = self.accept_root()
        self.assert_trigger_blocks(
            "UPDATE ledger_events SET prev_hash = ? WHERE event_id = ?",
            ("f" * 64, root.ledger_event_id),
        )
        self.drop_trigger_and_execute(
            "ledger_events_no_update",
            "UPDATE ledger_events SET prev_hash = ? WHERE event_id = ?",
            ("f" * 64, root.ledger_event_id),
        )
        self.assert_detects("REVIEWER_ROOT_LEDGER_CHAIN_INVALID")

    def test_verify_reviewer_root_rejects_direct_root_deletion_before_mutation(self) -> None:
        self.accept_root()
        self.assert_trigger_blocks(
            "DELETE FROM c4_architecture_reviewer_roots WHERE key_id = ?", (self.key_id,)
        )
        self.graph.database.connection.execute(
            "DROP TRIGGER c4_architecture_reviewer_roots_no_delete"
        )
        self.graph.database.connection.execute(
            "DELETE FROM c4_architecture_reviewer_roots WHERE key_id = ?", (self.key_id,)
        )
        self.assert_detects("REVIEWER_ROOT_NOT_FOUND")


class C4ArchitectureReviewVerificationTests(unittest.TestCase):
    def test_root_verification_not_implemented_defect_cannot_report_ok(self) -> None:
        result = C4ArchitectureReviewerRootVerification("review-key", ("NOT_IMPLEMENTED",))
        self.assertFalse(result.ok)
        self.assertEqual(result.defects, ("NOT_IMPLEMENTED",))

    def test_review_verification_not_implemented_defect_cannot_report_ok(self) -> None:
        result = C4ArchitectureReviewVerification("review-1", ("NOT_IMPLEMENTED",))
        self.assertFalse(result.ok)
        self.assertEqual(result.defects, ("NOT_IMPLEMENTED",))

    def test_verification_contract_is_frozen(self) -> None:
        result = C4ArchitectureReviewVerification("review-1", ("NOT_IMPLEMENTED",))
        with self.assertRaises(FrozenInstanceError):
            result.review_id = "tampered"  # type: ignore[misc]
