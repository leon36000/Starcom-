from __future__ import annotations

import unittest

import test_architecture_review as review_fixture

from starcom.architecture_candidate import C4ArchitectureCandidateVerification
from starcom.architecture_publication import (
    C4ArchitecturePublicationService,
    C4ArchitecturePublicationStatus,
)
from starcom.errors import (
    AuthorizationError,
    ConflictError,
    StateTransitionError,
)
from starcom.cli import Runtime
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule


T2 = "2026-08-16T12:02:00.000000Z"
T3 = "2026-08-16T12:03:00.000000Z"
T4 = "2026-08-16T12:04:00.000000Z"
T5 = "2026-08-16T12:05:00.000000Z"


class C4ArchitecturePublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.review_case = review_fixture.C4ArchitectureReviewTests("runTest")
        self.review_case.setUp()
        self.graph = self.review_case.graph
        self.review_service, _, _, _, self.review = (
            self.review_case.admitted_fixture_review()
        )
        self.manifest = {
            "architecture_id": self.review.architecture_id,
            "architecture_version": "3.2",
            "gate_effect": "C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED",
        }
        self.graph.candidates.get_manifest = (  # type: ignore[method-assign]
            lambda candidate_id: dict(self.manifest)
        )
        self.service = C4ArchitecturePublicationService(
            self.graph.database,
            self.graph.ledger,
            self.graph.trust,
            self.graph.continuity,
            self.graph.inputs,
            self.graph.candidates,
            self.review_service,
        )

    def tearDown(self) -> None:
        self.review_case.tearDown()

    def prepare(self, publication_id: str = "publication-001"):
        return self.service.prepare(
            publication_id,
            self.review.candidate_id,
            self.review.review_id,
        )

    def authorize(self, preparation, *, actor: str = "c4-publication-owner"):
        request = AuthorizationRequest(
            subject=actor,
            action=preparation.action,
            resource=preparation.resource,
            mission_id=preparation.mission_id,
            context=preparation.context,
        )
        self.graph.trust.add_rule(
            PolicyRule(
                rule_id="allow-c4-publication",
                effect=PolicyEffect.ALLOW,
                subject=actor,
                action=preparation.action,
                resource=preparation.resource,
                conditions=dict(preparation.context),
            ),
            actor="publication-policy-owner",
            occurred_at=T2,
        )
        decision = self.graph.trust.authorize(request, now=T3, consume=False)
        self.assertTrue(decision.allowed, decision)
        return decision

    def publish(self, *, actor: str = "c4-publication-owner", occurred_at: str = T4):
        preparation = self.prepare()
        decision = self.authorize(preparation, actor=actor)
        return self.service.publish(
            preparation.publication_id,
            preparation.candidate_id,
            preparation.review_id,
            decision.decision_id,
            actor=actor,
            occurred_at=occurred_at,
        )

    def test_prepare_is_deterministic_and_side_effect_free(self) -> None:
        before = self.graph.database.connection.total_changes
        first = self.prepare()
        second = self.prepare()
        self.assertEqual(first, second)
        self.assertEqual(before, self.graph.database.connection.total_changes)
        self.assertEqual(first.action, "c4.architecture.publish")
        self.assertEqual(
            first.resource,
            "continuity:c4:architecture-publication:publication-001",
        )
        self.assertEqual(first.mission_id, "c4-architecture:architecture-c4")
        self.assertEqual(
            first.context,
            {
                "publication_id": "publication-001",
                "candidate_id": "candidate-c4",
                "architecture_id": "architecture-c4",
                "input_set_id": "input-set-c4",
                "manifest_sha256": "a" * 64,
                "input_set_digest": "b" * 64,
                "review_id": "review-001",
                "reviewer_identity": "independent-c4-reviewer",
                "review_payload_sha256": self.review.payload_sha256,
                "review_signature_sha256": self.review.signature_sha256,
                "review_verdict": "C4_ARCHITECTURE_ACCEPTED",
                "publication_mode": "PUBLISH_ARCHITECTURE_NOT_DEPLOY",
                "status": "C4_ARCHITECTURE_PUBLISHED_NOT_DEPLOYED",
            },
        )

    def test_default_deny_blocks_publication(self) -> None:
        preparation = self.prepare()
        denied = self.graph.trust.authorize(
            AuthorizationRequest(
                subject="c4-publication-owner",
                action=preparation.action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=preparation.context,
            ),
            now=T3,
            consume=False,
        )
        self.assertFalse(denied.allowed)
        with self.assertRaises(AuthorizationError):
            self.service.publish(
                preparation.publication_id,
                preparation.candidate_id,
                preparation.review_id,
                denied.decision_id,
                actor="c4-publication-owner",
                occurred_at=T4,
            )

    def test_wrong_authorization_request_is_rejected(self) -> None:
        preparation = self.prepare()
        actor = "c4-publication-owner"
        wrong_action = "c4.architecture.publish.other"
        self.graph.trust.add_rule(
            PolicyRule(
                rule_id="allow-wrong-c4-publication",
                effect=PolicyEffect.ALLOW,
                subject=actor,
                action=wrong_action,
                resource=preparation.resource,
                conditions=dict(preparation.context),
            ),
            actor="publication-policy-owner",
            occurred_at=T2,
        )
        decision = self.graph.trust.authorize(
            AuthorizationRequest(
                subject=actor,
                action=wrong_action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=preparation.context,
            ),
            now=T3,
            consume=False,
        )
        self.assertTrue(decision.allowed)
        with self.assertRaises(AuthorizationError):
            self.service.publish(
                preparation.publication_id,
                preparation.candidate_id,
                preparation.review_id,
                decision.decision_id,
                actor=actor,
                occurred_at=T4,
            )

    def test_authorization_must_be_post_review(self) -> None:
        preparation = self.prepare()
        actor = "c4-publication-owner"
        request = AuthorizationRequest(
            subject=actor,
            action=preparation.action,
            resource=preparation.resource,
            mission_id=preparation.mission_id,
            context=preparation.context,
        )
        self.graph.trust.add_rule(
            PolicyRule(
                rule_id="allow-early-c4-publication",
                effect=PolicyEffect.ALLOW,
                subject=actor,
                action=preparation.action,
                resource=preparation.resource,
                conditions=dict(preparation.context),
            ),
            actor="publication-policy-owner",
            occurred_at=T2,
        )
        decision = self.graph.trust.authorize(request, now=T2, consume=False)
        self.assertTrue(decision.allowed)
        with self.assertRaises(StateTransitionError):
            self.service.publish(
                preparation.publication_id,
                preparation.candidate_id,
                preparation.review_id,
                decision.decision_id,
                actor=actor,
                occurred_at=T4,
            )

    def test_explicit_publication_is_atomic_and_verifies_cleanly(self) -> None:
        candidate_before = self.graph.candidates.get_candidate("candidate-c4")
        publication = self.publish()
        self.assertEqual(
            publication.status,
            C4ArchitecturePublicationStatus.PUBLISHED_NOT_DEPLOYED,
        )
        self.assertEqual(publication.verdict, "C4_ARCHITECTURE_ACCEPTED")
        self.assertEqual(
            self.service.get_manifest(publication.publication_id), self.manifest
        )
        self.assertEqual(
            self.service.get_publication(publication.publication_id), publication
        )
        self.assertTrue(self.service.verify_publication(publication.publication_id).ok)
        self.assertEqual(
            self.graph.candidates.get_candidate("candidate-c4"), candidate_before
        )
        consumption = self.graph.database.connection.execute(
            "SELECT * FROM continuity_authorization_consumptions WHERE decision_id = ?",
            (publication.authorization_decision_id,),
        ).fetchone()
        self.assertIsNotNone(consumption)
        assert consumption is not None
        self.assertEqual(
            consumption["operation_kind"],
            "C4_ARCHITECTURE_PUBLISHED_NOT_DEPLOYED",
        )
        self.assertEqual(consumption["operation_id"], publication.publication_id)
        events = self.graph.ledger.read_stream(
            self.service._stream(publication.publication_id)
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].kind, "C4_ARCHITECTURE_PUBLISHED_NOT_DEPLOYED")

    def test_replay_is_idempotent_and_material_reuse_conflicts(self) -> None:
        first = self.publish()
        preparation = self.prepare()
        replay = self.service.publish(
            preparation.publication_id,
            preparation.candidate_id,
            preparation.review_id,
            first.authorization_decision_id,
            actor=first.published_by,
            occurred_at=T5,
        )
        self.assertEqual(replay, first)
        self.assertEqual(
            len(self.graph.ledger.read_stream(self.service._stream(first.publication_id))),
            1,
        )
        with self.assertRaises(ConflictError):
            self.service.publish(
                preparation.publication_id,
                preparation.candidate_id,
                preparation.review_id,
                first.authorization_decision_id,
                actor="different-publication-owner",
                occurred_at=T4,
            )

    def test_schema_rows_are_immutable(self) -> None:
        for operation in ("update", "delete"):
            trigger = self.graph.database.connection.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type = 'trigger' AND name = ?
                """,
                (f"c4_architecture_publications_no_{operation}",),
            ).fetchone()
            self.assertIsNotNone(trigger)

    def test_runtime_exposes_one_canonical_publication_graph(self) -> None:
        runtime_path = self.review_case.graph.database.path + ".runtime"
        runtime = Runtime.open(runtime_path)
        self.addCleanup(runtime.close)
        self.assertIs(runtime.architecture_publication.database, runtime.database)
        self.assertIs(runtime.architecture_publication.ledger, runtime.ledger)
        self.assertIs(runtime.architecture_publication.trust, runtime.trust)
        self.assertIs(runtime.architecture_publication.continuity, runtime.continuity)
        self.assertIs(runtime.architecture_publication.inputs, runtime.architecture_input)
        self.assertIs(runtime.architecture_publication.candidates, runtime.architecture_candidate)
        self.assertIs(runtime.architecture_publication.reviews, runtime.architecture_review)

    def test_verifier_detects_publication_row_tampering(self) -> None:
        publication = self.publish()
        self.graph.database.connection.execute(
            "DROP TRIGGER c4_architecture_publications_no_update"
        )
        self.graph.database.connection.execute(
            "UPDATE c4_architecture_publications SET published_by = ? WHERE publication_id = ?",
            ("tampered-publisher", publication.publication_id),
        )
        verification = self.service.verify_publication(publication.publication_id)
        self.assertFalse(verification.ok)
        self.assertIn("PUBLICATION_DECISION_REQUEST_MISMATCH", verification.defects)

    def test_verifier_detects_invalid_publication_chronology(self) -> None:
        publication = self.publish()
        connection = self.graph.database.connection
        connection.execute("DROP TRIGGER c4_architecture_publications_no_update")
        connection.execute(
            "UPDATE c4_architecture_publications SET published_at = ? WHERE publication_id = ?",
            ("not-a-timestamp", publication.publication_id),
        )
        verification = self.service.verify_publication(publication.publication_id)
        self.assertFalse(verification.ok)
        self.assertIn("PUBLICATION_CHRONOLOGY_INVALID", verification.defects)

    def test_verifier_detects_manifest_decision_consumption_and_event_tampering(self) -> None:
        publication = self.publish()
        connection = self.graph.database.connection
        connection.execute("DROP TRIGGER c4_architecture_publications_no_update")
        connection.execute(
            "UPDATE c4_architecture_publications SET manifest_json = ? WHERE publication_id = ?",
            ("{}", publication.publication_id),
        )
        verification = self.service.verify_publication(publication.publication_id)
        self.assertFalse(verification.ok)
        self.assertIn("PUBLICATION_MANIFEST_MISMATCH", verification.defects)

        connection.execute("DROP TRIGGER continuity_authorization_consumptions_no_update")
        connection.execute(
            "UPDATE continuity_authorization_consumptions SET operation_id = ? WHERE decision_id = ?",
            ("tampered-operation", publication.authorization_decision_id),
        )
        verification = self.service.verify_publication(publication.publication_id)
        self.assertIn("PUBLICATION_AUTHORIZATION_CONSUMPTION_MISMATCH", verification.defects)

        connection.execute("DROP TRIGGER ledger_events_no_update")
        connection.execute(
            "UPDATE ledger_events SET actor = ? WHERE event_id = ?",
            ("tampered-ledger-actor", publication.ledger_event_id),
        )
        verification = self.service.verify_publication(publication.publication_id)
        self.assertIn("PUBLICATION_LEDGER_ACTOR_MISMATCH", verification.defects)

    def test_verifier_fails_closed_when_candidate_or_review_is_dirty(self) -> None:
        publication = self.publish()
        connection = self.graph.database.connection
        connection.execute("DROP TRIGGER c4_architecture_candidates_no_update")
        connection.execute(
            "UPDATE c4_architecture_candidates SET manifest_json = ? WHERE candidate_id = ?",
            ("{}", publication.candidate_id),
        )
        self.graph.candidates.verify_candidate = (  # type: ignore[method-assign]
            lambda candidate_id: C4ArchitectureCandidateVerification(
                candidate_id, ("C4_CANDIDATE_MANIFEST_NOT_CANONICAL",)
            )
        )
        verification = self.service.verify_publication(publication.publication_id)
        self.assertFalse(verification.ok)
        self.assertIn("PUBLICATION_C4_GRAPH_INVALID", verification.defects)


if __name__ == "__main__":
    unittest.main()
