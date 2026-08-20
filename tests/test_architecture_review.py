from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sqlite3
import tempfile
import unittest

from starcom.adoption import C3AdoptionService
from starcom.adoption_execution import C3AdoptionExecutionService
from starcom.architecture_candidate import (
    C4ArchitectureCandidate,
    C4ArchitectureCandidateService,
    C4ArchitectureCandidateStatus,
    C4ArchitectureCandidateVerification,
)
from starcom.architecture_input import (
    C4ArchitectureInputService,
    C4ArchitectureInputSet,
    C4ArchitectureInputVerification,
)
from starcom.architecture_review import C4ArchitectureReviewService
from starcom.census import C2CensusService
from starcom.certification import C2CertificationService
from starcom.continuity import ContinuityService
from starcom.continuity_crypto import OpenSSLEd25519Verifier
from starcom.db import Database
from starcom.durable import DurableOutbox
from starcom.errors import (
    AuthorizationError,
    ConflictError,
    IntegrityError,
    StateTransitionError,
    ValidationError,
)
from starcom.ledger import EventLedger
from starcom.qualification import QualificationLab
from starcom.qualification_decision import C3DecisionService
from starcom.qualification_gate import C3QualificationGate
from starcom.recollection import C2RecollectionService
from starcom.research import ResearchCampaign
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule, TrustPlane


T0 = "2026-08-16T12:00:00.000000Z"
T1 = "2026-08-16T12:01:00.000000Z"
T2 = "2026-08-16T12:02:00.000000Z"
PUBLIC_KEY = b"deterministic-ed25519-public-key"


class RecordingSignatureVerifier:
    def __init__(self) -> None:
        self.calls: list[tuple[str, bytes]] = []

    def validate_public_key(self, public_key_pem: bytes) -> bool:
        self.calls.append(("validate_public_key", public_key_pem))
        return public_key_pem == PUBLIC_KEY

    @staticmethod
    def sign(public_key_pem: bytes, payload: bytes) -> bytes:
        return hashlib.sha256(public_key_pem + payload).digest()

    def verify(self, public_key_pem: bytes, payload: bytes, signature: bytes) -> bool:
        self.calls.append(("verify", payload))
        return signature == self.sign(public_key_pem, payload)


class NoncanonicalExecutionSource:
    pass


class NoncanonicalExecutionSubclass(C3AdoptionExecutionService):
    """A structurally compatible but noncanonical execution authority."""


class CanonicalGraph:
    def __init__(self, root: Path) -> None:
        self.database = Database(root / "review.sqlite3")
        self.database.initialize()
        self.ledger = EventLedger(self.database)
        self.trust = TrustPlane(self.database, self.ledger)
        self.continuity = ContinuityService(self.database, self.ledger, self.trust)
        self.research = ResearchCampaign(self.database, self.ledger)
        self.recollection = C2RecollectionService(
            self.database, self.ledger, self.continuity, self.research
        )
        self.census = C2CensusService(
            self.database, self.ledger, self.recollection, self.research
        )
        self.certification = C2CertificationService(
            self.database, self.ledger, self.continuity, self.recollection, self.census
        )
        self.qualification = QualificationLab(self.database, self.ledger)
        self.c3 = C3QualificationGate(
            self.database, self.ledger, self.certification, self.qualification
        )
        self.decisions = C3DecisionService(
            self.database,
            self.ledger,
            self.continuity,
            self.certification,
            self.c3,
            self.qualification,
        )
        self.adoption = C3AdoptionService(
            self.database,
            self.ledger,
            self.trust,
            self.continuity,
            self.decisions,
            self.qualification,
        )
        self.outbox = DurableOutbox(self.database, self.ledger)
        self.executions = C3AdoptionExecutionService(
            self.database,
            self.ledger,
            self.trust,
            self.continuity,
            self.adoption,
            self.outbox,
        )
        self.inputs = C4ArchitectureInputService(
            self.database,
            self.ledger,
            self.trust,
            self.continuity,
            self.executions,
        )
        self.candidates = C4ArchitectureCandidateService(
            self.database,
            self.ledger,
            self.trust,
            self.continuity,
            self.inputs,
        )

    def close(self) -> None:
        self.database.close()


class C4ArchitectureReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.graph = CanonicalGraph(Path(self.tempdir.name))
        self.verifier = RecordingSignatureVerifier()

    def tearDown(self) -> None:
        self.graph.close()
        self.tempdir.cleanup()

    def service(self, **overrides):  # type: ignore[no-untyped-def]
        values = {
            "database": self.graph.database,
            "ledger": self.graph.ledger,
            "trust": self.graph.trust,
            "continuity": self.graph.continuity,
            "inputs": self.graph.inputs,
            "candidates": self.graph.candidates,
            "signature_verifier": self.verifier,
        }
        values.update(overrides)
        return C4ArchitectureReviewService(**values)

    def assert_constructor_rejects(self, mutate) -> None:  # type: ignore[no-untyped-def]
        mutate()
        with self.assertRaises(ValidationError):
            self.service()

    def review_fixture(self):  # type: ignore[no-untyped-def]
        service = self.service()
        root = self.accept()

        def authorize(subject: str, action: str, resource: str, rule_id: str):
            request = AuthorizationRequest(
                subject=subject,
                action=action,
                resource=resource,
                mission_id=f"fixture:{resource}",
                context={},
            )
            self.graph.trust.add_rule(
                PolicyRule(
                    rule_id=rule_id,
                    effect=PolicyEffect.ALLOW,
                    subject=subject,
                    action=action,
                    resource=resource,
                ),
                actor="fixture-policy-owner",
                occurred_at=T0,
            )
            decision = self.graph.trust.authorize(request, now=T0, consume=False)
            self.assertTrue(decision.allowed)
            return decision

        input_decision = authorize(
            "c4-input-owner",
            "fixture.input.freeze",
            "fixture:input-set-c4",
            "fixture-input-authorize",
        )
        candidate_decision = authorize(
            "c4-architect",
            "fixture.candidate.create",
            "fixture:candidate-c4",
            "fixture-candidate-authorize",
        )
        self.graph.database.connection.execute(
            """
            INSERT INTO c4_architecture_input_sets (
                input_set_id, member_count, success_count,
                negative_evidence_count, input_set_digest,
                author_identities_json, authorization_decision_id,
                frozen_at, frozen_by, ledger_event_id, ledger_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "input-set-c4",
                1,
                1,
                0,
                "b" * 64,
                '["c3-author"]',
                input_decision.decision_id,
                T0,
                "c4-input-owner",
                "fixture-input-ledger-event",
                "1" * 64,
            ),
        )
        self.graph.database.connection.execute(
            """
            INSERT INTO c4_architecture_candidates (
                candidate_id, architecture_id, architecture_version,
                input_set_id, input_set_digest, manifest_json,
                manifest_sha256, adr_count, port_count, binding_count,
                nfr_count, stage_order_json, status,
                authorization_decision_id, created_at, created_by,
                ledger_event_id, ledger_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "candidate-c4",
                "architecture-c4",
                "3.2",
                "input-set-c4",
                "b" * 64,
                "{}",
                "a" * 64,
                1,
                1,
                1,
                1,
                '["RESEARCH","ARTIFACT","ACTION","MONITOR"]',
                C4ArchitectureCandidateStatus.NOT_REVIEWED.value,
                candidate_decision.decision_id,
                T1,
                "c4-architect",
                "fixture-candidate-ledger-event",
                "2" * 64,
            ),
        )
        candidate = C4ArchitectureCandidate(
            candidate_id="candidate-c4",
            architecture_id="architecture-c4",
            architecture_version="3.2",
            input_set_id="input-set-c4",
            input_set_digest="b" * 64,
            manifest_sha256="a" * 64,
            status=C4ArchitectureCandidateStatus.NOT_REVIEWED,
            authorization_decision_id=candidate_decision.decision_id,
            created_at=T1,
            created_by="c4-architect",
            ledger_event_id="fixture-candidate-ledger-event",
            ledger_hash="2" * 64,
        )
        input_set = C4ArchitectureInputSet(
            input_set_id="input-set-c4",
            member_count=1,
            success_count=1,
            negative_evidence_count=0,
            input_set_digest="b" * 64,
            author_identities=("c3-author",),
            authorization_decision_id=input_decision.decision_id,
            frozen_at=T0,
            frozen_by="c4-input-owner",
            ledger_event_id="fixture-input-ledger-event",
            ledger_hash="1" * 64,
        )
        member = {"requested_by": "c3-author", "execution_id": "execution-c4"}
        self.graph.candidates.get_candidate = lambda candidate_id: candidate  # type: ignore[method-assign]
        self.graph.candidates.verify_candidate = (  # type: ignore[method-assign]
            lambda candidate_id: C4ArchitectureCandidateVerification(
                candidate_id, ()
            )
        )
        self.graph.inputs.get_input_set = lambda input_set_id: input_set  # type: ignore[method-assign]
        self.graph.inputs.get_members = lambda input_set_id: (member,)  # type: ignore[method-assign]
        self.graph.inputs.verify_input_set = (  # type: ignore[method-assign]
            lambda input_set_id: C4ArchitectureInputVerification(input_set_id, ())
        )
        return service, root

    @staticmethod
    def root_context(
        *,
        reviewer_identity: str = "independent-c4-reviewer",
        public_key_pem: bytes = PUBLIC_KEY,
        algorithm: str = "Ed25519",
        purpose: str = "C4_ARCHITECTURE_REVIEW",
        fingerprint_sha256: str | None = None,
    ) -> dict[str, str]:
        return {
            "algorithm": algorithm,
            "fingerprint_sha256": fingerprint_sha256
            or hashlib.sha256(public_key_pem).hexdigest(),
            "purpose": purpose,
            "reviewer_identity": reviewer_identity,
        }

    def root_request(
        self,
        *,
        subject: str = "c4-root-owner",
        action: str = "c4.architecture-reviewer.accept",
        resource: str = "continuity:c4:architecture-reviewer:review-key",
        mission_id: str = "c4-architecture-reviewer:review-key",
        context: dict[str, str] | None = None,
    ) -> AuthorizationRequest:
        return AuthorizationRequest(
            subject=subject,
            action=action,
            resource=resource,
            mission_id=mission_id,
            context=context or self.root_context(),
        )

    def authorize_root(
        self,
        *,
        request: AuthorizationRequest | None = None,
        allow: bool = True,
        now: str = T0,
    ):
        request = request or self.root_request()
        if allow:
            rule_id = f"allow-root-{self.graph.database.connection.total_changes}"
            self.graph.trust.add_rule(
                PolicyRule(
                    rule_id=rule_id,
                    effect=PolicyEffect.ALLOW,
                    subject=request.subject,
                    action=request.action,
                    resource=request.resource,
                    conditions=dict(request.context),
                    priority=100,
                ),
                actor="test-policy-owner",
                occurred_at=T0,
            )
        return self.graph.trust.authorize(request, now=now, consume=False)

    def accept(self, *, decision=None, decision_now: str = T0, **overrides):  # type: ignore[no-untyped-def]
        values = {
            "key_id": "review-key",
            "reviewer_identity": "independent-c4-reviewer",
            "public_key_pem": PUBLIC_KEY,
            "actor": "c4-root-owner",
            "occurred_at": T1,
        }
        values.update(overrides)
        if decision is None:
            request = self.root_request(
                subject=values["actor"],
                resource=f"continuity:c4:architecture-reviewer:{values['key_id']}",
                mission_id=f"c4-architecture-reviewer:{values['key_id']}",
                context=self.root_context(
                    reviewer_identity=values["reviewer_identity"],
                    public_key_pem=values["public_key_pem"],
                ),
            )
            decision = self.authorize_root(request=request, now=decision_now)
        return self.service().accept_reviewer_root(
            values["key_id"],
            values["reviewer_identity"],
            values["public_key_pem"],
            authorization_decision_id=decision.decision_id,
            actor=values["actor"],
            occurred_at=values["occurred_at"],
        )

    def test_constructor_rejects_noncanonical_execution_evidence_source(self) -> None:
        self.graph.inputs.executions = NoncanonicalExecutionSource()
        with self.assertRaises(ValidationError):
            self.service()

    def test_constructor_rejects_mismatched_database_graph(self) -> None:
        other = Database(Path(self.tempdir.name) / "other.sqlite3")
        other.initialize()
        self.addCleanup(other.close)
        self.graph.ledger.database = other
        self.assert_constructor_rejects(lambda: None)

    def test_constructor_rejects_mismatched_service_graph(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.candidates, "inputs", object())
        )

    def test_constructor_rejects_mismatched_execution_evidence_database(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.executions, "database", object())
        )

    def test_constructor_rejects_mismatched_execution_adoption_graph(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.executions, "adoption", object())
        )

    def test_constructor_rejects_mismatched_execution_decision_graph(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.adoption, "decisions", object())
        )

    def test_constructor_rejects_mismatched_qualification_database(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.qualification, "database", object())
        )

    def test_constructor_rejects_mismatched_qualification_ledger(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.qualification, "ledger", object())
        )

    def test_constructor_rejects_mismatched_c3_gate_graph(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.decisions, "c3", object())
        )

    def test_constructor_rejects_mismatched_certification_census_recollection_graph(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.certification.census, "recollection", object())
        )

    def test_constructor_rejects_mismatched_research_graph(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.census, "research", object())
        )

    def test_constructor_rejects_mismatched_outbox_graph(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.outbox, "ledger", object())
        )

    def test_constructor_rejects_execution_service_subclass(self) -> None:
        self.graph.inputs.executions = NoncanonicalExecutionSubclass(
            self.graph.database,
            self.graph.ledger,
            self.graph.trust,
            self.graph.continuity,
            self.graph.adoption,
            self.graph.outbox,
        )
        with self.assertRaises(ValidationError):
            self.service()

    def test_constructor_rejects_mismatched_execution_ledger(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.executions, "ledger", object())
        )

    def test_constructor_rejects_mismatched_execution_trust(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.executions, "trust", object())
        )

    def test_constructor_rejects_mismatched_execution_continuity(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.executions, "continuity", object())
        )

    def test_constructor_rejects_mismatched_adoption_database(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.adoption, "database", object())
        )

    def test_constructor_rejects_mismatched_adoption_ledger(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.adoption, "ledger", object())
        )

    def test_constructor_rejects_mismatched_adoption_trust(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.adoption, "trust", object())
        )

    def test_constructor_rejects_mismatched_adoption_continuity(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.adoption, "continuity", object())
        )

    def test_constructor_rejects_mismatched_adoption_qualification(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.adoption, "qualification", object())
        )

    def test_constructor_rejects_mismatched_decision_database(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.decisions, "database", object())
        )

    def test_constructor_rejects_mismatched_decision_ledger(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.decisions, "ledger", object())
        )

    def test_constructor_rejects_mismatched_decision_continuity(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.decisions, "continuity", object())
        )

    def test_constructor_rejects_mismatched_decision_qualification(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.decisions, "qualification", object())
        )

    def test_constructor_rejects_mismatched_decision_certification(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.decisions, "certification", object())
        )

    def test_constructor_rejects_mismatched_c3_database(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.c3, "database", object())
        )

    def test_constructor_rejects_mismatched_c3_ledger(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.c3, "ledger", object())
        )

    def test_constructor_rejects_mismatched_c3_qualification(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.c3, "qualification", object())
        )

    def test_constructor_rejects_mismatched_c3_certification(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.c3, "certification", object())
        )

    def test_constructor_rejects_mismatched_certification_ledger(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.certification, "ledger", object())
        )

    def test_constructor_rejects_mismatched_certification_continuity(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.certification, "continuity", object())
        )

    def test_constructor_rejects_mismatched_certification_recollection(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.certification, "recollection", object())
        )

    def test_constructor_rejects_mismatched_recollection_database(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.recollection, "database", object())
        )

    def test_constructor_rejects_mismatched_recollection_ledger(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.recollection, "ledger", object())
        )

    def test_constructor_rejects_mismatched_recollection_continuity(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.recollection, "continuity", object())
        )

    def test_constructor_rejects_mismatched_census_database(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.census, "database", object())
        )

    def test_constructor_rejects_mismatched_census_ledger(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.census, "ledger", object())
        )

    def test_constructor_rejects_mismatched_research_database(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.research, "database", object())
        )

    def test_constructor_rejects_mismatched_research_ledger(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.research, "ledger", object())
        )

    def test_constructor_rejects_mismatched_outbox_database(self) -> None:
        self.assert_constructor_rejects(
            lambda: setattr(self.graph.outbox, "database", object())
        )

    def test_prepare_reviewer_root_is_deterministic_and_side_effect_free(self) -> None:
        service = self.service()
        before = self.graph.database.connection.total_changes
        first = service.prepare_reviewer_root("review-key", "independent-c4-reviewer", PUBLIC_KEY)
        second = service.prepare_reviewer_root("review-key", "independent-c4-reviewer", PUBLIC_KEY)
        self.assertEqual(first, second)
        self.assertEqual(before, self.graph.database.connection.total_changes)

    def test_prepare_reviewer_root_uses_exact_action_resource_context_and_identity_binding(self) -> None:
        preparation = self.service().prepare_reviewer_root(
            "review-key", "independent-c4-reviewer", PUBLIC_KEY
        )
        self.assertEqual(preparation.action, "c4.architecture-reviewer.accept")
        self.assertNotEqual(preparation.action, "c4.architecture-review.trust-root.accept")
        self.assertEqual(preparation.resource, "continuity:c4:architecture-reviewer:review-key")
        self.assertNotEqual(
            preparation.resource,
            "continuity:c4:architecture-review:trust-root:review-key",
        )
        self.assertEqual(preparation.mission_id, "c4-architecture-reviewer:review-key")
        self.assertEqual(
            preparation.context,
            {
                "algorithm": "Ed25519",
                "fingerprint_sha256": hashlib.sha256(PUBLIC_KEY).hexdigest(),
                "purpose": "C4_ARCHITECTURE_REVIEW",
                "reviewer_identity": "independent-c4-reviewer",
            },
        )

    def test_default_deny_blocks_reviewer_root_acceptance(self) -> None:
        denied = self.authorize_root(allow=False)
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.reason, "DEFAULT_DENY")
        with self.assertRaises(AuthorizationError):
            self.accept(decision=denied)

    def test_root_acceptance_rejects_reviewer_self_authorization(self) -> None:
        with self.assertRaises(StateTransitionError) as captured:
            self.accept(
                reviewer_identity="independent-c4-reviewer",
                actor="independent-c4-reviewer",
            )
        self.assertNotIn("not implemented", str(captured.exception).lower())

    def test_root_acceptance_rejects_decision_subject_not_accepting_actor(self) -> None:
        request = self.root_request(subject="different-root-owner")
        decision = self.authorize_root(request=request)
        self.assertTrue(decision.allowed)
        with self.assertRaises(AuthorizationError):
            self.accept(decision=decision, actor="c4-root-owner")

    def test_root_acceptance_rejects_wrong_action_resource_purpose_algorithm_fingerprint_or_identity(self) -> None:
        cases = (
            self.root_request(action="c4.architecture-review.trust-root.accept"),
            self.root_request(
                resource="continuity:c4:architecture-review:trust-root:review-key"
            ),
            self.root_request(
                context=self.root_context(purpose="C4_ARCHITECTURE_CANDIDATE")
            ),
            self.root_request(context=self.root_context(algorithm="RSA")),
            self.root_request(
                context=self.root_context(fingerprint_sha256="0" * 64)
            ),
            self.root_request(
                context=self.root_context(reviewer_identity="somebody-else")
            ),
        )
        for request in cases:
            with self.subTest(request=request):
                decision = self.authorize_root(request=request)
                self.assertTrue(decision.allowed)
                with self.assertRaises(AuthorizationError):
                    self.accept(decision=decision)

    def test_root_acceptance_rejects_non_ed25519_key(self) -> None:
        with self.assertRaises(ValidationError):
            self.accept(public_key_pem=b"not-an-ed25519-key")

    def test_root_acceptance_requires_authorization_chronology(self) -> None:
        with self.assertRaises(ValidationError):
            self.accept(decision_now=T1, occurred_at=T0)

    def test_review_schema_is_created_with_immutable_review_and_finding_rows(self) -> None:
        self.service()
        for table in (
            "c4_architecture_reviews",
            "c4_architecture_review_findings",
        ):
            with self.subTest(table=table):
                row = self.graph.database.connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                    (table,),
                ).fetchone()
                self.assertIsNotNone(row)
                for operation in ("update", "delete"):
                    trigger = self.graph.database.connection.execute(
                        "SELECT 1 FROM sqlite_master "
                        "WHERE type = 'trigger' AND name = ?",
                        (f"{table}_no_{operation}",),
                    ).fetchone()
                    self.assertIsNotNone(trigger)

    def test_admit_review_persists_exact_signed_material_and_ledger_event(self) -> None:
        service, root = self.review_fixture()
        value = self.valid_review_payload()
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        signature = self.verifier.sign(PUBLIC_KEY, payload)

        review = service.admit_review(
            "candidate-c4",
            root.key_id,
            payload,
            signature,
            actor="c4-review-admitter",
            occurred_at=T2,
        )

        self.assertEqual(review.payload, payload)
        self.assertEqual(review.signature, signature)
        self.assertEqual(review.review_id, "review-001")
        self.assertEqual(service.get_review_for_candidate("candidate-c4"), review)
        self.assertEqual(service.get_findings(review.review_id), ())
        event = self.graph.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (review.ledger_event_id,),
        ).fetchone()
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["kind"], "C4_ARCHITECTURE_REVIEW_ADMITTED")
        self.assertEqual(event["stream_id"], service._review_stream("candidate-c4"))
        self.assertEqual(event["actor"], "c4-review-admitter")

    def admitted_fixture_review(self, **overrides):  # type: ignore[no-untyped-def]
        service, root = self.review_fixture()
        value = self.valid_review_payload(**overrides)
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        review = service.admit_review(
            "candidate-c4",
            root.key_id,
            payload,
            self.verifier.sign(PUBLIC_KEY, payload),
            actor="c4-review-admitter",
            occurred_at=T2,
        )
        return service, root, value, payload, review

    def test_admit_review_exact_replay_returns_original_without_duplicate_event(self) -> None:
        service, root, _, payload, first = self.admitted_fixture_review()
        replay = service.admit_review(
            "candidate-c4",
            root.key_id,
            payload,
            self.verifier.sign(PUBLIC_KEY, payload),
            actor="c4-review-admitter",
            occurred_at="2026-08-16T12:03:00.000000Z",
        )
        self.assertEqual(replay, first)
        self.assertEqual(
            self.graph.database.connection.execute(
                "SELECT COUNT(*) FROM c4_architecture_reviews"
            ).fetchone()[0],
            1,
        )
        self.assertEqual(
            len(self.graph.ledger.read_stream(service._review_stream("candidate-c4"))),
            1,
        )

    def test_admit_review_replay_ignores_new_call_admission_timestamp(self) -> None:
        service, root, _, payload, first = self.admitted_fixture_review()
        replay = service.admit_review(
            "candidate-c4",
            root.key_id,
            payload,
            self.verifier.sign(PUBLIC_KEY, payload),
            actor="c4-review-admitter",
            occurred_at=T1,
        )
        self.assertEqual(replay, first)

    @unittest.skipUnless(shutil.which("openssl"), "openssl executable is required")
    def test_default_openssl_ed25519_verifier_checks_exact_signed_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_key = root / "reviewer-private.pem"
            public_key = root / "reviewer-public.pem"
            payload = root / "review.json"
            signature = root / "review.sig"
            payload.write_bytes(b"{\"exact\":true}")
            subprocess.run(
                [
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "ED25519",
                    "-out",
                    str(private_key),
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "openssl",
                    "pkey",
                    "-in",
                    str(private_key),
                    "-pubout",
                    "-out",
                    str(public_key),
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-inkey",
                    str(private_key),
                    "-in",
                    str(payload),
                    "-out",
                    str(signature),
                ],
                check=True,
                capture_output=True,
            )
            verifier = OpenSSLEd25519Verifier()
            public_key_bytes = public_key.read_bytes()
            payload_bytes = payload.read_bytes()
            signature_bytes = signature.read_bytes()
            self.assertTrue(verifier.validate_public_key(public_key_bytes))
            self.assertTrue(
                verifier.verify(public_key_bytes, payload_bytes, signature_bytes)
            )
            self.assertFalse(
                verifier.verify(public_key_bytes, payload_bytes + b"!", signature_bytes)
            )

    def test_admit_review_rejects_conflicting_reuse(self) -> None:
        service, root, value, payload, _ = self.admitted_fixture_review()
        changed = dict(value)
        changed["review_id"] = "review-002"
        changed_payload = json.dumps(
            changed, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        with self.assertRaises(ConflictError):
            service.admit_review(
                "candidate-c4",
                root.key_id,
                changed_payload,
                self.verifier.sign(PUBLIC_KEY, changed_payload),
                actor="c4-review-admitter",
                occurred_at=T2,
            )
        with self.assertRaises(ConflictError):
            service.admit_review(
                "candidate-c4",
                root.key_id,
                payload,
                self.verifier.sign(PUBLIC_KEY, payload),
                actor="different-admitter",
                occurred_at=T2,
            )

    def test_review_and_finding_rows_are_immutable(self) -> None:
        finding = {
            "finding_id": "finding-001",
            "code": "EVIDENCE_MISSING",
            "severity": "HIGH",
            "evidence_sha256": "c" * 64,
            "description": "required independent evidence is missing",
        }
        service, _, _, _, review = self.admitted_fixture_review(
            verdict="C4_ARCHITECTURE_REWORK_REQUIRED",
            security_verification_result="FAIL",
            findings=[finding],
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.graph.database.connection.execute(
                "UPDATE c4_architecture_reviews SET reviewer_identity = ? WHERE review_id = ?",
                ("tampered", review.review_id),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.graph.database.connection.execute(
                "DELETE FROM c4_architecture_reviews WHERE review_id = ?",
                (review.review_id,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.graph.database.connection.execute(
                "UPDATE c4_architecture_review_findings SET severity = ? WHERE review_id = ?",
                ("LOW", review.review_id),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.graph.database.connection.execute(
                "DELETE FROM c4_architecture_review_findings WHERE review_id = ?",
                (review.review_id,),
            )
        self.assertEqual(len(service.get_findings(review.review_id)), 1)

    def test_admit_review_binds_every_signed_candidate_and_input_field(self) -> None:
        cases = (
            ("candidate_id", "different-candidate"),
            ("architecture_id", "different-architecture"),
            ("input_set_id", "different-input"),
            ("manifest_sha256", "c" * 64),
            ("input_set_digest", "d" * 64),
        )
        service, root = self.review_fixture()
        for field, value in cases:
            with self.subTest(field=field):
                review = self.valid_review_payload(**{field: value})
                payload = json.dumps(
                    review, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
                with self.assertRaises(IntegrityError):
                    service.admit_review(
                        "candidate-c4",
                        root.key_id,
                        payload,
                        self.verifier.sign(PUBLIC_KEY, payload),
                        actor="c4-review-admitter",
                        occurred_at=T2,
                    )
                self.assertEqual(
                    self.graph.database.connection.execute(
                        "SELECT COUNT(*) FROM c4_architecture_reviews"
                    ).fetchone()[0],
                    0,
                )

    def test_admit_review_requires_clean_candidate_and_input_verifiers(self) -> None:
        service, root = self.review_fixture()
        self.graph.candidates.verify_candidate = (  # type: ignore[method-assign]
            lambda candidate_id: C4ArchitectureCandidateVerification(
                candidate_id, ("C4_CANDIDATE_TAMPERED",)
            )
        )
        payload = json.dumps(
            self.valid_review_payload(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        with self.assertRaises(IntegrityError):
            service.admit_review(
                "candidate-c4",
                root.key_id,
                payload,
                self.verifier.sign(PUBLIC_KEY, payload),
                actor="c4-review-admitter",
                occurred_at=T2,
            )
        self.assertEqual(
            self.graph.database.connection.execute(
                "SELECT COUNT(*) FROM ledger_events "
                "WHERE kind = 'C4_ARCHITECTURE_REVIEW_ADMITTED'"
            ).fetchone()[0],
            0,
        )

    def test_admit_review_enforces_static_independence_and_actor_separation(self) -> None:
        cases = (
            self.valid_review_payload(
                reviewer_identity="c4-architect",
            ),
            self.valid_review_payload(
                reviewer_identity="c4-input-owner",
            ),
            self.valid_review_payload(
                reviewer_identity="c3-author",
            ),
            self.valid_review_payload(
                independence_basis={
                    "excluded_identities": ["c4-architect", "c4-input-owner"],
                    "statement": "incomplete provenance",
                }
            ),
        )
        service, root = self.review_fixture()
        for value in cases:
            with self.subTest(value=value):
                payload = json.dumps(
                    value, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
                error = StateTransitionError
                with self.assertRaises(error):
                    service.admit_review(
                        "candidate-c4",
                        root.key_id,
                        payload,
                        self.verifier.sign(PUBLIC_KEY, payload),
                        actor="c4-review-admitter",
                        occurred_at=T2,
                    )

        payload = json.dumps(
            self.valid_review_payload(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        with self.assertRaises(StateTransitionError):
            service.admit_review(
                "candidate-c4",
                root.key_id,
                payload,
                self.verifier.sign(PUBLIC_KEY, payload),
                actor="independent-c4-reviewer",
                occurred_at=T2,
            )

    def test_admit_review_enforces_review_and_admission_chronology(self) -> None:
        cases = (
            (self.valid_review_payload(reviewed_at_utc=T1), T2),
            (self.valid_review_payload(reviewed_at_utc=T0), T2),
            (self.valid_review_payload(), T1),
        )
        service, root = self.review_fixture()
        for value, occurred_at in cases:
            with self.subTest(value=value, occurred_at=occurred_at):
                payload = json.dumps(
                    value, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
                with self.assertRaises(StateTransitionError):
                    service.admit_review(
                        "candidate-c4",
                        root.key_id,
                        payload,
                        self.verifier.sign(PUBLIC_KEY, payload),
                        actor="c4-review-admitter",
                        occurred_at=occurred_at,
                    )

    def test_verify_review_accepts_clean_immutable_record(self) -> None:
        service, _, _, _, review = self.admitted_fixture_review()
        verification = service.verify_review(review.review_id)
        self.assertTrue(verification.ok, verification.defects)

    def test_verify_review_detects_payload_and_signature_byte_tampering(self) -> None:
        service, _, _, _, review = self.admitted_fixture_review()
        self.graph.database.connection.execute(
            "DROP TRIGGER c4_architecture_reviews_no_update"
        )
        self.graph.database.connection.execute(
            "UPDATE c4_architecture_reviews SET payload = ? WHERE review_id = ?",
            (b"tampered-payload", review.review_id),
        )
        verification = service.verify_review(review.review_id)
        self.assertFalse(verification.ok)
        self.assertIn("REVIEW_PAYLOAD_DIGEST_MISMATCH", verification.defects)
        self.assertIn("REVIEW_SIGNATURE_INVALID", verification.defects)

        self.graph.database.connection.execute(
            "UPDATE c4_architecture_reviews SET payload = ?, signature = ? "
            "WHERE review_id = ?",
            (review.payload, b"tampered-signature", review.review_id),
        )
        verification = service.verify_review(review.review_id)
        self.assertFalse(verification.ok)
        self.assertIn("REVIEW_SIGNATURE_DIGEST_MISMATCH", verification.defects)
        self.assertIn("REVIEW_SIGNATURE_INVALID", verification.defects)

    def test_verify_review_detects_stored_field_and_finding_tampering(self) -> None:
        finding = {
            "finding_id": "finding-001",
            "code": "EVIDENCE_MISSING",
            "severity": "HIGH",
            "evidence_sha256": "c" * 64,
            "description": "required independent evidence is missing",
        }
        service, _, _, _, review = self.admitted_fixture_review(
            verdict="C4_ARCHITECTURE_REWORK_REQUIRED",
            security_verification_result="FAIL",
            findings=[finding],
        )
        self.graph.database.connection.execute(
            "DROP TRIGGER c4_architecture_reviews_no_update"
        )
        self.graph.database.connection.execute(
            "UPDATE c4_architecture_reviews SET reviewer_identity = ? WHERE review_id = ?",
            ("tampered-reviewer", review.review_id),
        )
        verification = service.verify_review(review.review_id)
        self.assertFalse(verification.ok)
        self.assertIn("REVIEW_STORED_FIELD_MISMATCH:reviewer_identity", verification.defects)

        self.graph.database.connection.execute(
            "DROP TRIGGER c4_architecture_review_findings_no_update"
        )
        self.graph.database.connection.execute(
            "UPDATE c4_architecture_review_findings SET description = ? WHERE review_id = ?",
            ("tampered-finding", review.review_id),
        )
        verification = service.verify_review(review.review_id)
        self.assertFalse(verification.ok)
        self.assertIn("REVIEW_FINDINGS_MISMATCH", verification.defects)

    def test_verify_review_detects_ledger_event_and_chain_tampering(self) -> None:
        service, _, _, _, review = self.admitted_fixture_review()
        self.graph.database.connection.execute("DROP TRIGGER ledger_events_no_update")
        self.graph.database.connection.execute(
            "UPDATE ledger_events SET actor = ? WHERE event_id = ?",
            ("intruder", review.ledger_event_id),
        )
        verification = service.verify_review(review.review_id)
        self.assertFalse(verification.ok)
        self.assertIn("REVIEW_LEDGER_ACTOR_MISMATCH", verification.defects)
        self.assertIn("REVIEW_LEDGER_CHAIN_INVALID", verification.defects)

    def test_verify_review_missing_record_is_not_ok(self) -> None:
        service = self.service()
        verification = service.verify_review("missing-review")
        self.assertFalse(verification.ok)
        self.assertEqual(verification.defects, ("REVIEW_NOT_FOUND",))

    def test_root_acceptance_is_exact_replay_idempotent_and_conflicting_reuse_fails(self) -> None:
        decision = self.authorize_root()
        first = self.accept(decision=decision)
        self.assertEqual(first, self.accept(decision=decision))
        with self.assertRaises(ConflictError):
            self.accept(decision=decision, reviewer_identity="different-reviewer")

    def test_root_exact_replay_ignores_changed_caller_occurred_at(self) -> None:
        decision = self.authorize_root()
        first = self.accept(decision=decision, occurred_at=T1)
        replay = self.accept(decision=decision, occurred_at=T2)
        self.assertEqual(first, replay)
        self.assertEqual(replay.accepted_at, T1)

    def test_root_reuse_with_same_decision_and_different_key_conflicts(self) -> None:
        decision = self.authorize_root()
        self.accept(decision=decision)
        with self.assertRaises(ConflictError):
            self.accept(decision=decision, key_id="different-review-key")

    def test_root_reuse_with_same_key_and_different_actor_conflicts(self) -> None:
        decision = self.authorize_root()
        self.accept(decision=decision)
        with self.assertRaises(ConflictError):
            self.accept(decision=decision, actor="different-root-owner")

    def test_root_reuse_with_same_key_and_different_decision_conflicts(self) -> None:
        first_decision = self.authorize_root()
        self.accept(decision=first_decision)
        second_decision = self.graph.trust.authorize(
            self.root_request(),
            now=T0,
            consume=False,
        )
        self.assertTrue(second_decision.allowed)
        with self.assertRaises(ConflictError):
            self.accept(decision=second_decision)

    def assert_signature_boundary(self, payload: bytes, signature: bytes, error) -> None:  # type: ignore[no-untyped-def]
        self.accept()
        with self.assertRaises(error):
            self.service().admit_review(
                "candidate-c4",
                "review-key",
                payload,
                signature,
                actor="c4-review-admitter",
                occurred_at=T1,
            )

    @staticmethod
    def valid_review_payload(**overrides) -> dict[str, object]:  # type: ignore[no-untyped-def]
        value: dict[str, object] = {
            "review_id": "review-001",
            "candidate_id": "candidate-c4",
            "architecture_id": "architecture-c4",
            "input_set_id": "input-set-c4",
            "manifest_sha256": "a" * 64,
            "input_set_digest": "b" * 64,
            "reviewer_identity": "independent-c4-reviewer",
            "reviewer_environment": {
                "description": "isolated independent review worktree",
                "environment_type": "ISOLATED_WORKTREE",
            },
            "independence_basis": {
                "excluded_identities": [
                    "c3-author",
                    "c4-architect",
                    "c4-input-owner",
                ],
                "statement": "reviewer is independent of static provenance identities",
            },
            "reviewed_at_utc": T2,
            "structural_verification_result": "PASS",
            "security_verification_result": "PASS",
            "evidence_binding_result": "PASS",
            "verdict": "C4_ARCHITECTURE_ACCEPTED",
            "findings": [],
            "gate_effect": "NO_PUBLICATION_NO_DEPLOYMENT",
        }
        value.update(overrides)
        return value

    def assert_signed_payload_validation_error(self, value: object) -> None:
        if not getattr(self, "_payload_validation_root_accepted", False):
            self.accept()
            self._payload_validation_root_accepted = True
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        with self.assertRaises(ValidationError):
            self.service().admit_review(
                "candidate-c4",
                "review-key",
                payload,
                self.verifier.sign(PUBLIC_KEY, payload),
                actor="c4-review-admitter",
                occurred_at=T1,
            )
        self.assertEqual(self.verifier.calls[-1], ("verify", payload))

    def test_invalid_utf8_bad_signature_fails_integrity_before_parser_semantics(self) -> None:
        self.assert_signature_boundary(b"\xff", b"bad", IntegrityError)
        self.assertEqual(self.verifier.calls[-1], ("verify", b"\xff"))

    def test_malformed_json_bad_signature_fails_integrity_before_parser_semantics(self) -> None:
        payload = b'{"review_id":'
        self.assert_signature_boundary(payload, b"bad", IntegrityError)
        self.assertEqual(self.verifier.calls[-1], ("verify", payload))

    def test_validly_signed_invalid_utf8_reaches_validation_only_after_verifier_call(self) -> None:
        payload = b"\xff"
        self.assert_signature_boundary(
            payload, self.verifier.sign(PUBLIC_KEY, payload), ValidationError
        )
        self.assertEqual(self.verifier.calls[-1], ("verify", payload))

    def test_validly_signed_top_level_duplicate_key_json_rejected_after_verifier_call(self) -> None:
        payload = b'{"review_id":"one","review_id":"two"}'
        self.assert_signature_boundary(
            payload, self.verifier.sign(PUBLIC_KEY, payload), ValidationError
        )
        self.assertEqual(self.verifier.calls[-1], ("verify", payload))

    def test_validly_signed_nested_duplicate_key_json_rejected_after_verifier_call(self) -> None:
        payload = b'{"reviewer_environment":{"description":"one","description":"two"}}'
        self.assert_signature_boundary(
            payload, self.verifier.sign(PUBLIC_KEY, payload), ValidationError
        )
        self.assertEqual(self.verifier.calls[-1], ("verify", payload))

    def test_signed_payload_rejects_non_object_top_level(self) -> None:
        self.assert_signed_payload_validation_error([])

    def test_signed_payload_requires_exact_top_level_keys(self) -> None:
        missing = self.valid_review_payload()
        missing.pop("review_id")
        unexpected = self.valid_review_payload(unexpected_field="forbidden")
        for value in (missing, unexpected):
            with self.subTest(value=value):
                self.assert_signed_payload_validation_error(value)

    def test_signed_payload_rejects_invalid_sha256_digests(self) -> None:
        cases = (
            self.valid_review_payload(manifest_sha256="A" * 64),
            self.valid_review_payload(manifest_sha256="a" * 63),
            self.valid_review_payload(manifest_sha256="g" * 64),
            self.valid_review_payload(input_set_digest="B" * 64),
            self.valid_review_payload(input_set_digest="b" * 65),
            self.valid_review_payload(input_set_digest="z" * 64),
        )
        for value in cases:
            with self.subTest(value=value):
                self.assert_signed_payload_validation_error(value)

    def test_signed_payload_requires_canonical_utc_review_timestamp(self) -> None:
        for timestamp in (
            "2026-08-16T12:02:00Z",
            "2026-08-16T12:02:00.000000+00:00",
            "2026-08-16T12:02:00.000000-04:00",
            "not-a-timestamp",
        ):
            with self.subTest(timestamp=timestamp):
                self.assert_signed_payload_validation_error(
                    self.valid_review_payload(reviewed_at_utc=timestamp)
                )

    def test_signed_payload_rejects_invalid_verification_results(self) -> None:
        for field in (
            "structural_verification_result",
            "security_verification_result",
            "evidence_binding_result",
        ):
            with self.subTest(field=field):
                self.assert_signed_payload_validation_error(
                    self.valid_review_payload(**{field: "INCONCLUSIVE"})
                )

    def test_signed_payload_rejects_non_string_enum_fields(self) -> None:
        cases = (
            self.valid_review_payload(structural_verification_result=[]),
            self.valid_review_payload(security_verification_result={}),
            self.valid_review_payload(evidence_binding_result=["PASS"]),
            self.valid_review_payload(verdict={"value": "C4_ARCHITECTURE_ACCEPTED"}),
        )
        for value in cases:
            with self.subTest(value=value):
                self.assert_signed_payload_validation_error(value)

    def test_signed_payload_rejects_invalid_verdict(self) -> None:
        self.assert_signed_payload_validation_error(
            self.valid_review_payload(verdict="C4_ARCHITECTURE_MAYBE")
        )

    def test_signed_payload_requires_no_publication_no_deployment_gate(self) -> None:
        self.assert_signed_payload_validation_error(
            self.valid_review_payload(gate_effect="PUBLISH_AND_DEPLOY")
        )

    def test_review_signature_verification_uses_the_verified_root_snapshot(self) -> None:
        root = self.accept()
        service = self.service()
        self.graph.database.connection.execute(
            "DROP TRIGGER c4_architecture_reviewer_roots_no_update"
        )
        attacker_key = b"attacker-ed25519-public-key"
        original_get = service.get_reviewer_root
        mutated = False

        def mutate_then_get(key_id: str):  # type: ignore[no-untyped-def]
            nonlocal mutated
            if not mutated:
                self.graph.database.connection.execute(
                    "UPDATE c4_architecture_reviewer_roots SET public_key_pem = ? WHERE key_id = ?",
                    (attacker_key, root.key_id),
                )
                mutated = True
            return original_get(key_id)

        service.get_reviewer_root = mutate_then_get  # type: ignore[method-assign]
        payload = b"{}"
        with self.assertRaises(IntegrityError):
            service.admit_review(
                "candidate-c4",
                root.key_id,
                payload,
                self.verifier.sign(attacker_key, payload),
                actor="c4-review-admitter",
                occurred_at=T2,
            )
        self.assertTrue(mutated)

    def test_validly_signed_nonstandard_json_constant_is_rejected(self) -> None:
        payload = b'{"security_verification_result":NaN}'
        self.assert_signature_boundary(
            payload,
            self.verifier.sign(PUBLIC_KEY, payload),
            ValidationError,
        )
        self.assertEqual(self.verifier.calls[-1], ("verify", payload))

    def test_signed_payload_requires_closed_reviewer_environment(self) -> None:
        cases = (
            "ISOLATED_WORKTREE",
            {"description": "isolated"},
            {
                "description": "isolated",
                "environment_type": "ISOLATED_WORKTREE",
                "unexpected": "forbidden",
            },
            {
                "description": "isolated",
                "environment_type": "NETWORKED_SHARED",
            },
        )
        for environment in cases:
            with self.subTest(environment=environment):
                self.assert_signed_payload_validation_error(
                    self.valid_review_payload(reviewer_environment=environment)
                )

    def test_signed_payload_requires_sorted_independent_identities_and_statement(self) -> None:
        cases = (
            ["c4-architect"],
            {"excluded_identities": ["c4-architect"]},
            {
                "excluded_identities": ["z-author", "a-author"],
                "statement": "independent",
            },
            {
                "excluded_identities": ["a-author", "a-author"],
                "statement": "independent",
            },
            {
                "excluded_identities": ["c4-architect"],
                "statement": "",
            },
        )
        for independence in cases:
            with self.subTest(independence=independence):
                self.assert_signed_payload_validation_error(
                    self.valid_review_payload(independence_basis=independence)
                )

    def test_signed_payload_requires_verdict_result_and_findings_consistency(self) -> None:
        accepted_with_failure = self.valid_review_payload(
            security_verification_result="FAIL"
        )
        accepted_with_finding = self.valid_review_payload(
            findings=[
                {
                    "finding_id": "finding-001",
                    "code": "EVIDENCE_MISSING",
                    "severity": "HIGH",
                    "evidence_sha256": "c" * 64,
                    "description": "required independent evidence is missing",
                }
            ]
        )
        rejected_without_failure = self.valid_review_payload(
            verdict="C4_ARCHITECTURE_REJECTED",
            findings=[
                {
                    "finding_id": "finding-001",
                    "code": "EVIDENCE_MISSING",
                    "severity": "HIGH",
                    "evidence_sha256": "c" * 64,
                    "description": "required independent evidence is missing",
                }
            ],
        )
        rejected_without_finding = self.valid_review_payload(
            verdict="C4_ARCHITECTURE_REJECTED",
            security_verification_result="FAIL",
        )
        for value in (
            accepted_with_failure,
            accepted_with_finding,
            rejected_without_failure,
            rejected_without_finding,
        ):
            with self.subTest(value=value):
                self.assert_signed_payload_validation_error(value)

    def test_signed_payload_rejects_unclassified_or_unsorted_findings(self) -> None:
        base = self.valid_review_payload(
            verdict="C4_ARCHITECTURE_REWORK_REQUIRED",
            security_verification_result="FAIL",
        )
        cases = (
            "finding",
            [{"finding_id": "finding-001"}],
            [
                {
                    "finding_id": "finding-001",
                    "code": "CALLER_DEFINED_CODE",
                    "severity": "HIGH",
                    "evidence_sha256": "c" * 64,
                    "description": "missing",
                }
            ],
            [
                {
                    "finding_id": "finding-002",
                    "code": "EVIDENCE_MISSING",
                    "severity": "HIGH",
                    "evidence_sha256": "c" * 64,
                    "description": "missing",
                },
                {
                    "finding_id": "finding-001",
                    "code": "EVIDENCE_MISSING",
                    "severity": "HIGH",
                    "evidence_sha256": "c" * 64,
                    "description": "missing",
                },
            ],
        )
        for findings in cases:
            with self.subTest(findings=findings):
                self.assert_signed_payload_validation_error(
                    self.valid_review_payload(**dict(base, findings=findings))
                )
