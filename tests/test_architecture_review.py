from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from starcom.adoption import C3AdoptionService
from starcom.adoption_execution import C3AdoptionExecutionService
from starcom.architecture_candidate import C4ArchitectureCandidateService
from starcom.architecture_input import C4ArchitectureInputService
from starcom.architecture_review import C4ArchitectureReviewService
from starcom.census import C2CensusService
from starcom.certification import C2CertificationService
from starcom.continuity import ContinuityService
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
            "reviewer_environment": {},
            "independence_basis": {},
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
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.assert_signature_boundary(
            payload,
            self.verifier.sign(PUBLIC_KEY, payload),
            ValidationError,
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

    def test_signed_payload_rejects_invalid_verdict(self) -> None:
        self.assert_signed_payload_validation_error(
            self.valid_review_payload(verdict="C4_ARCHITECTURE_MAYBE")
        )

    def test_signed_payload_requires_no_publication_no_deployment_gate(self) -> None:
        self.assert_signed_payload_validation_error(
            self.valid_review_payload(gate_effect="PUBLISH_AND_DEPLOY")
        )
