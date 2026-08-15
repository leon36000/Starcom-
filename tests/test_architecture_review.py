from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from starcom.architecture_candidate import (
    C4ArchitectureCandidate,
    C4ArchitectureCandidateStatus,
    C4ArchitectureCandidateVerification,
)
from starcom.architecture_input import (
    C4ArchitectureInputSet,
    C4ArchitectureInputVerification,
)
from starcom.architecture_review import (
    C4ArchitectureFindingCode,
    C4ArchitectureFindingSeverity,
    C4ArchitectureReviewService,
    C4ArchitectureReviewVerdict,
)
from starcom.canonical import sha256_digest
from starcom.continuity import ContinuityService
from starcom.db import Database
from starcom.errors import (
    AuthorizationError,
    ConflictError,
    IntegrityError,
    StateTransitionError,
    ValidationError,
)
from starcom.ledger import EventLedger
from starcom.trust import (
    AuthorizationRequest,
    PolicyEffect,
    PolicyRule,
    TrustPlane,
)


R0 = "2026-08-14T19:00:00.000000Z"
R1 = "2026-08-14T19:01:00.000000Z"
R2 = "2026-08-14T19:02:00.000000Z"
R3 = "2026-08-14T19:03:00.000000Z"
R4 = "2026-08-14T19:04:00.000000Z"


class FakeReviewInputService:
    def __init__(self) -> None:
        self.members = (
            {
                "execution_id": "execution-success",
                "adoption_id": "adoption-success",
                "c3_run_id": "c3-success",
                "c3_decision_id": "decision-success",
                "candidate_artifact_id": "candidate-artifact-success",
                "candidate_material_sha256": "1" * 64,
                "decision_payload_sha256": "2" * 64,
                "qualification_head_hash": "3" * 64,
                "executor_id": "executor-success",
                "execution_plan_sha256": "4" * 64,
                "authorization_decision_id": "authorization-success",
                "status": "C3_ADOPTION_EXECUTION_SUCCEEDED",
                "execution_receipt_sha256": "5" * 64,
                "rollback_receipt_sha256": None,
                "effect_started": True,
                "error": None,
                "requested_at": R0,
                "requested_by": "c3-author",
                "transition_sequence": 3,
                "terminal_result_digest": "6" * 64,
            },
        )
        self.record = C4ArchitectureInputSet(
            input_set_id="input-set-review",
            member_count=1,
            success_count=1,
            negative_evidence_count=0,
            input_set_digest=sha256_digest(list(self.members)),
            author_identities=("c3-author",),
            authorization_decision_id="input-authorization",
            frozen_at=R0,
            frozen_by="input-freezer",
            ledger_event_id="input-event",
            ledger_hash="7" * 64,
        )
        self.defects: tuple[str, ...] = ()

    def get_input_set(self, input_set_id: str) -> C4ArchitectureInputSet:
        if input_set_id != self.record.input_set_id:
            raise AssertionError("unexpected input_set_id")
        return self.record

    def get_members(self, input_set_id: str):  # type: ignore[no-untyped-def]
        self.get_input_set(input_set_id)
        return self.members

    def verify_input_set(
        self,
        input_set_id: str,
    ) -> C4ArchitectureInputVerification:
        self.get_input_set(input_set_id)
        return C4ArchitectureInputVerification(input_set_id, self.defects)


class FakeReviewCandidateService:
    def __init__(self, inputs: FakeReviewInputService) -> None:
        self.inputs = inputs
        self.manifest = self._manifest()
        self.record = C4ArchitectureCandidate(
            candidate_id="candidate-c4-review",
            architecture_id="starcom-v3.2-target",
            architecture_version="3.2",
            input_set_id=inputs.record.input_set_id,
            input_set_digest=inputs.record.input_set_digest,
            manifest_sha256=sha256_digest(self.manifest),
            status=C4ArchitectureCandidateStatus.NOT_REVIEWED,
            authorization_decision_id="candidate-authorization",
            created_at=R1,
            created_by="candidate-author",
            ledger_event_id="candidate-event",
            ledger_hash="8" * 64,
        )
        self.defects: tuple[str, ...] = ()

    @staticmethod
    def _manifest() -> dict[str, object]:
        ports = [
            {
                "port_id": "port-action",
                "capability_id": "cap-action",
                "owner_authority": "MISSION_KERNEL",
                "contract_digest": "a" * 64,
                "test_ids": ["test-action"],
                "proof_ids": ["proof-action"],
            },
            {
                "port_id": "port-artifact",
                "capability_id": "cap-artifact",
                "owner_authority": "MISSION_KERNEL",
                "contract_digest": "b" * 64,
                "test_ids": ["test-artifact"],
                "proof_ids": ["proof-artifact"],
            },
            {
                "port_id": "port-monitor",
                "capability_id": "cap-monitor",
                "owner_authority": "MISSION_KERNEL",
                "contract_digest": "c" * 64,
                "test_ids": ["test-monitor"],
                "proof_ids": ["proof-monitor"],
            },
            {
                "port_id": "port-research",
                "capability_id": "cap-research",
                "owner_authority": "MISSION_KERNEL",
                "contract_digest": "d" * 64,
                "test_ids": ["test-research"],
                "proof_ids": ["proof-research"],
            },
        ]
        return {
            "architecture_id": "starcom-v3.2-target",
            "architecture_version": "3.2",
            "title": "STARCOM v3.2 architecture review fixture",
            "authority_adrs": [
                {
                    "adr_id": "adr-authority-boundaries",
                    "title": "Authority boundaries",
                    "decision": "Mission Kernel owns mission ports",
                    "rationale": "Explicit authority prevents drift",
                    "authority_owner": "MISSION_KERNEL",
                    "affected_port_ids": [
                        "port-action",
                        "port-artifact",
                        "port-monitor",
                        "port-research",
                    ],
                    "evidence_execution_ids": ["execution-success"],
                }
            ],
            "ports": ports,
            "mission_fabric": {
                "RESEARCH": ["port-research"],
                "ARTIFACT": ["port-artifact"],
                "ACTION": ["port-action"],
                "MONITOR": ["port-monitor"],
            },
            "component_bindings": [
                {
                    "binding_id": "binding-success",
                    "execution_id": "execution-success",
                    "candidate_artifact_id": "candidate-artifact-success",
                    "candidate_material_sha256": "1" * 64,
                    "port_ids": [
                        "port-action",
                        "port-artifact",
                        "port-monitor",
                        "port-research",
                    ],
                    "capability_ids": [
                        "cap-action",
                        "cap-artifact",
                        "cap-monitor",
                        "cap-research",
                    ],
                }
            ],
            "vertical_benchmark": {
                "benchmark_id": "benchmark-mission-fabric",
                "stage_order": ["RESEARCH", "ARTIFACT", "ACTION", "MONITOR"],
                "stage_test_ids": {
                    "RESEARCH": ["test-research"],
                    "ARTIFACT": ["test-artifact"],
                    "ACTION": ["test-action"],
                    "MONITOR": ["test-monitor"],
                },
                "stage_proof_ids": {
                    "RESEARCH": ["proof-research"],
                    "ARTIFACT": ["proof-artifact"],
                    "ACTION": ["proof-action"],
                    "MONITOR": ["proof-monitor"],
                },
                "end_to_end_test_id": "test-e2e-mission-fabric",
                "end_to_end_proof_id": "proof-e2e-mission-fabric",
            },
            "non_functional_requirements": [
                {
                    "requirement_id": "nfr-default-deny",
                    "category": "SECURITY",
                    "statement": "All external effects remain default-deny",
                    "verification_method": "TrustPlane mutation suite",
                    "test_ids": ["test-action"],
                    "proof_ids": ["proof-action"],
                }
            ],
            "gate_effect": "C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED",
        }

    def get_candidate(self, candidate_id: str) -> C4ArchitectureCandidate:
        if candidate_id != self.record.candidate_id:
            raise AssertionError("unexpected candidate_id")
        return self.record

    def get_manifest(self, candidate_id: str):  # type: ignore[no-untyped-def]
        self.get_candidate(candidate_id)
        return self.manifest

    def verify_candidate(
        self,
        candidate_id: str,
    ) -> C4ArchitectureCandidateVerification:
        self.get_candidate(candidate_id)
        return C4ArchitectureCandidateVerification(candidate_id, self.defects)


class C4ArchitectureReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.database = Database(self.root / "review.sqlite3")
        self.database.initialize()
        self.ledger = EventLedger(self.database)
        self.trust = TrustPlane(self.database, self.ledger)
        self.continuity = ContinuityService(
            self.database,
            self.ledger,
            self.trust,
        )
        self.inputs = FakeReviewInputService()
        self.candidates = FakeReviewCandidateService(self.inputs)
        self.reviews = C4ArchitectureReviewService(
            self.database,
            self.ledger,
            self.trust,
            self.continuity,
            self.inputs,  # type: ignore[arg-type]
            self.candidates,  # type: ignore[arg-type]
        )
        self.private_key = self.root / "reviewer-private.pem"
        self.public_key = self.root / "reviewer-public.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(self.private_key),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(self.private_key),
                "-pubout",
                "-out",
                str(self.public_key),
            ],
            check=True,
            capture_output=True,
        )

    def tearDown(self) -> None:
        self.database.close()
        self.tempdir.cleanup()

    def table_count(self, table: str) -> int:
        exists = self.database.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        if exists is None:
            return 0
        return int(
            self.database.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
        )

    def authorize_root(
        self,
        preparation,
        *,
        actor: str = "root-owner",
        rule_id: str = "allow-c4-reviewer-root",
    ):
        self.trust.add_rule(
            PolicyRule(
                rule_id,
                PolicyEffect.ALLOW,
                actor,
                preparation.action,
                preparation.resource,
            ),
            actor="owner",
            occurred_at=R0,
        )
        decision = self.trust.authorize(
            AuthorizationRequest(
                subject=actor,
                action=preparation.action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=preparation.context,
            ),
            now=R1,
        )
        self.assertTrue(decision.allowed)
        return decision

    def accept_root(
        self,
        *,
        key_id: str = "reviewer-key",
        actor: str = "root-owner",
        public_key: bytes | None = None,
    ):
        key_bytes = public_key or self.public_key.read_bytes()
        preparation = self.reviews.prepare_reviewer_root(key_id, key_bytes)
        decision = self.authorize_root(
            preparation,
            actor=actor,
            rule_id=f"allow-{key_id}",
        )
        return self.reviews.accept_reviewer_root(
            key_id,
            key_bytes,
            authorization_decision_id=decision.decision_id,
            actor=actor,
            occurred_at=R2,
        )

    def payload_value(
        self,
        *,
        review_id: str = "review-c4",
        reviewer_identity: str = "independent-reviewer",
        reviewed_at: str = R3,
        structural: str = "PASS",
        security: str = "PASS",
        evidence: str = "PASS",
        findings: list[dict[str, object]] | None = None,
        verdict: C4ArchitectureReviewVerdict = C4ArchitectureReviewVerdict.ACCEPTED,
    ) -> dict[str, object]:
        candidate = self.candidates.record
        return {
            "review_id": review_id,
            "candidate_id": candidate.candidate_id,
            "architecture_id": candidate.architecture_id,
            "architecture_version": candidate.architecture_version,
            "input_set_id": candidate.input_set_id,
            "input_set_digest": candidate.input_set_digest,
            "manifest_sha256": candidate.manifest_sha256,
            "reviewer_identity": reviewer_identity,
            "reviewer_environment": "isolated-c4-review-vm",
            "reviewed_at": reviewed_at,
            "independence_basis": "separate process, key and clean workspace",
            "structural_verification_result": structural,
            "security_verification_result": security,
            "evidence_binding_result": evidence,
            "findings": findings or [],
            "verdict": verdict.value,
            "gate_effect": "NO_PUBLICATION_NO_DEPLOYMENT",
        }

    @staticmethod
    def encoded(value: dict[str, object]) -> bytes:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def sign(self, payload: bytes, *, private_key: Path | None = None) -> bytes:
        payload_path = self.root / f"payload-{hashlib.sha256(payload).hexdigest()}.json"
        signature_path = self.root / f"signature-{hashlib.sha256(payload).hexdigest()}.sig"
        payload_path.write_bytes(payload)
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(private_key or self.private_key),
                "-rawin",
                "-in",
                str(payload_path),
                "-out",
                str(signature_path),
            ],
            check=True,
            capture_output=True,
        )
        return signature_path.read_bytes()

    def admit(
        self,
        value: dict[str, object] | None = None,
        *,
        key_id: str = "reviewer-key",
        actor: str = "review-admitter",
        occurred_at: str = R4,
        payload: bytes | None = None,
        signature: bytes | None = None,
    ):
        actual_payload = payload or self.encoded(value or self.payload_value())
        actual_signature = signature or self.sign(actual_payload)
        return self.reviews.admit_review(
            self.candidates.record.candidate_id,
            key_id,
            actual_payload,
            actual_signature,
            actor=actor,
            occurred_at=occurred_at,
        )

    @staticmethod
    def finding(
        finding_id: str,
        *,
        code: C4ArchitectureFindingCode,
        severity: C4ArchitectureFindingSeverity,
        affected_ids: list[str] | None = None,
        evidence_refs: list[str] | None = None,
    ) -> dict[str, object]:
        return {
            "finding_id": finding_id,
            "code": code.value,
            "severity": severity.value,
            "title": f"Finding {finding_id}",
            "description": "Deterministic architecture review finding",
            "affected_ids": affected_ids or ["port-action"],
            "evidence_refs": evidence_refs or ["proof-action"],
            "recommendation": "Address the finding before the next gate",
        }

    def test_reviewer_root_prepare_is_deterministic_and_side_effect_free(self) -> None:
        key_bytes = self.public_key.read_bytes()
        decisions_before = self.table_count("trust_decisions")
        consumptions_before = self.table_count(
            "continuity_authorization_consumptions"
        )

        first = self.reviews.prepare_reviewer_root("reviewer-key", key_bytes)
        second = self.reviews.prepare_reviewer_root("reviewer-key", key_bytes)

        self.assertEqual(first, second)
        self.assertEqual(first.action, "c4.architecture-reviewer.accept")
        self.assertEqual(
            first.resource,
            "continuity:c4:architecture-reviewer:reviewer-key",
        )
        self.assertEqual(first.mission_id, "c4-architecture-reviewer:reviewer-key")
        self.assertEqual(
            first.public_key_fingerprint_sha256,
            hashlib.sha256(key_bytes).hexdigest(),
        )
        self.assertEqual(self.table_count("trust_decisions"), decisions_before)
        self.assertEqual(
            self.table_count("continuity_authorization_consumptions"),
            consumptions_before,
        )
        self.assertEqual(self.table_count("c4_architecture_reviewer_roots"), 0)

    def test_reviewer_root_default_deny_accept_replay_and_verify(self) -> None:
        key_bytes = self.public_key.read_bytes()
        preparation = self.reviews.prepare_reviewer_root("reviewer-key", key_bytes)
        denied = self.trust.authorize(
            AuthorizationRequest(
                subject="root-owner",
                action=preparation.action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=preparation.context,
            ),
            now=R1,
        )
        self.assertFalse(denied.allowed)
        with self.assertRaises(AuthorizationError):
            self.reviews.accept_reviewer_root(
                "reviewer-key",
                key_bytes,
                authorization_decision_id=denied.decision_id,
                actor="root-owner",
                occurred_at=R2,
            )

        decision = self.authorize_root(preparation)
        first = self.reviews.accept_reviewer_root(
            "reviewer-key",
            key_bytes,
            authorization_decision_id=decision.decision_id,
            actor="root-owner",
            occurred_at=R2,
        )
        replay = self.reviews.accept_reviewer_root(
            "reviewer-key",
            key_bytes,
            authorization_decision_id=decision.decision_id,
            actor="root-owner",
            occurred_at=R4,
        )

        self.assertEqual(first, replay)
        verification = self.reviews.verify_reviewer_root("reviewer-key")
        self.assertTrue(verification.ok, verification.defects)

    def test_exact_accepted_review_is_admitted_replayed_and_verified(self) -> None:
        self.accept_root()
        low_finding = self.finding(
            "finding-documentation",
            code=C4ArchitectureFindingCode.DOCUMENTATION_IMPROVEMENT,
            severity=C4ArchitectureFindingSeverity.LOW,
        )
        value = self.payload_value(findings=[low_finding])
        payload = self.encoded(value)
        signature = self.sign(payload)

        first = self.admit(value, payload=payload, signature=signature)
        replay = self.admit(
            value,
            payload=payload,
            signature=signature,
            occurred_at="2026-08-14T19:05:00.000000Z",
        )

        self.assertEqual(first, replay)
        self.assertEqual(first.verdict, C4ArchitectureReviewVerdict.ACCEPTED)
        self.assertEqual(first.finding_count, 1)
        stored = self.database.connection.execute(
            "SELECT payload, signature FROM c4_architecture_reviews WHERE review_id = ?",
            (first.review_id,),
        ).fetchone()
        self.assertIsNotNone(stored)
        assert stored is not None
        self.assertEqual(bytes(stored["payload"]), payload)
        self.assertEqual(bytes(stored["signature"]), signature)
        self.assertEqual(self.reviews.get_findings(first.review_id), (low_finding,))
        verification = self.reviews.verify_review(first.review_id)
        self.assertTrue(verification.ok, verification.defects)

    def test_exact_rejected_review_is_valid(self) -> None:
        self.accept_root()
        finding = self.finding(
            "finding-critical-security",
            code=C4ArchitectureFindingCode.SECURITY_CONTROL_GAP,
            severity=C4ArchitectureFindingSeverity.CRITICAL,
        )
        value = self.payload_value(
            security="FAIL",
            findings=[finding],
            verdict=C4ArchitectureReviewVerdict.REJECTED,
        )

        record = self.admit(value)

        self.assertEqual(record.verdict, C4ArchitectureReviewVerdict.REJECTED)
        self.assertTrue(self.reviews.verify_review(record.review_id).ok)

    def test_exact_rework_review_is_valid(self) -> None:
        self.accept_root()
        finding = self.finding(
            "finding-port-rework",
            code=C4ArchitectureFindingCode.PORT_OWNERSHIP_GAP,
            severity=C4ArchitectureFindingSeverity.HIGH,
        )
        value = self.payload_value(
            structural="FAIL",
            findings=[finding],
            verdict=C4ArchitectureReviewVerdict.REWORK_REQUIRED,
        )

        record = self.admit(value)

        self.assertEqual(
            record.verdict,
            C4ArchitectureReviewVerdict.REWORK_REQUIRED,
        )
        self.assertTrue(self.reviews.verify_review(record.review_id).ok)

    def test_review_rejects_unaccepted_wrong_key_and_modified_exact_bytes(self) -> None:
        value = self.payload_value()
        payload = self.encoded(value)
        signature = self.sign(payload)
        with self.assertRaises((IntegrityError, StateTransitionError)):
            self.admit(value, payload=payload, signature=signature)

        self.accept_root()
        second_private = self.root / "second-private.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(second_private),
            ],
            check=True,
            capture_output=True,
        )
        wrong_signature = self.sign(payload, private_key=second_private)
        with self.assertRaises(IntegrityError):
            self.admit(value, payload=payload, signature=wrong_signature)
        with self.assertRaises(IntegrityError):
            self.admit(
                value,
                payload=payload + b" ",
                signature=signature,
            )

    def test_review_rejects_schema_finding_binding_and_verdict_inconsistencies(self) -> None:
        self.accept_root()
        missing = self.payload_value()
        del missing["gate_effect"]
        missing_payload = self.encoded(missing)
        with self.assertRaises(ValidationError):
            self.admit(
                missing,
                payload=missing_payload,
                signature=self.sign(missing_payload),
            )

        extra = self.payload_value()
        extra["unexpected"] = "fail closed"
        extra_payload = self.encoded(extra)
        with self.assertRaises(ValidationError):
            self.admit(
                extra,
                payload=extra_payload,
                signature=self.sign(extra_payload),
            )

        raw = self.encoded(self.payload_value()).decode("utf-8").replace(
            '"review_id":"review-c4"',
            '"review_id":"review-c4","review_id":"duplicate"',
            1,
        ).encode("utf-8")
        with self.assertRaises(ValidationError):
            self.admit(payload=raw, signature=self.sign(raw))

        unknown_evidence = self.finding(
            "finding-unknown-evidence",
            code=C4ArchitectureFindingCode.EVIDENCE_BINDING_GAP,
            severity=C4ArchitectureFindingSeverity.HIGH,
            evidence_refs=["not-in-candidate-or-input"],
        )
        value = self.payload_value(
            evidence="FAIL",
            findings=[unknown_evidence],
            verdict=C4ArchitectureReviewVerdict.REWORK_REQUIRED,
        )
        with self.assertRaises(StateTransitionError):
            self.admit(value)

        inconsistent = self.payload_value(
            structural="FAIL",
            verdict=C4ArchitectureReviewVerdict.ACCEPTED,
        )
        with self.assertRaises(StateTransitionError):
            self.admit(inconsistent)

    def test_reviewer_independence_and_chronology_are_enforced(self) -> None:
        self.accept_root()
        for identity in (
            "candidate-author",
            "input-freezer",
            "c3-author",
            "root-owner",
            "review-admitter",
        ):
            with self.subTest(identity=identity):
                value = self.payload_value(
                    review_id=f"review-{identity}",
                    reviewer_identity=identity,
                )
                with self.assertRaisesRegex(
                    StateTransitionError,
                    "reviewer identity is not independent",
                ):
                    self.admit(value)

        early = self.payload_value(
            review_id="review-too-early",
            reviewed_at=R0,
        )
        with self.assertRaisesRegex(
            StateTransitionError,
            "review timestamp predates C4 material",
        ):
            self.admit(early)

        value = self.payload_value(review_id="review-admission-too-early")
        with self.assertRaisesRegex(
            StateTransitionError,
            "review admission predates",
        ):
            self.admit(value, occurred_at=R2)

    def test_second_review_for_candidate_conflicts(self) -> None:
        self.accept_root()
        self.admit(self.payload_value(review_id="review-first"))
        second = self.payload_value(review_id="review-second")

        with self.assertRaises(ConflictError):
            self.admit(second)


if __name__ == "__main__":
    unittest.main()
