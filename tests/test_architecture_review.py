from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import test_architecture_candidate as candidate_fixture
import test_architecture_input as input_fixture

from starcom.architecture_candidate import C4ArchitectureCandidateService
from starcom.architecture_input import C4ArchitectureInputService
from starcom.architecture_review import (
    C4ArchitectureFindingCode,
    C4ArchitectureFindingSeverity,
    C4ArchitectureReviewService,
    C4ArchitectureReviewVerdict,
    C4ArchitectureVerificationResult,
)
from starcom.continuity import ContinuityService
from starcom.db import Database
from starcom.errors import AuthorizationError, ConflictError, IntegrityError
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
R5 = "2026-08-14T19:05:00.000000Z"
R6 = "2026-08-14T19:06:00.000000Z"
R7 = "2026-08-14T19:07:00.000000Z"
R8 = "2026-08-14T19:08:00.000000Z"
R9 = "2026-08-14T19:09:00.000000Z"


class C4ArchitectureReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.database = Database(self.root / "c4-review.sqlite3")
        self.database.initialize()
        self.ledger = EventLedger(self.database)
        self.trust = TrustPlane(self.database, self.ledger)
        self.continuity = ContinuityService(
            self.database,
            self.ledger,
            self.trust,
        )
        self.executions = input_fixture.FakeExecutionEvidenceSource()
        self.inputs = C4ArchitectureInputService(
            self.database,
            self.ledger,
            self.trust,
            self.continuity,
            self.executions,
        )
        self._create_input_set()
        self.candidates = C4ArchitectureCandidateService(
            self.database,
            self.ledger,
            self.trust,
            self.continuity,
            self.inputs,
        )
        self.manifest = self._valid_manifest()
        self._create_candidate()
        self.reviews = C4ArchitectureReviewService(
            self.database,
            self.ledger,
            self.trust,
            self.continuity,
            self.inputs,
            self.candidates,
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

    def _create_input_set(self) -> None:
        execution_ids = ("execution-no-effect", "execution-success")
        preparation = self.inputs.prepare_freeze("input-set-c4", execution_ids)
        self.trust.add_rule(
            PolicyRule(
                "allow-review-fixture-input",
                PolicyEffect.ALLOW,
                "c4-input-owner",
                preparation.action,
                preparation.resource,
            ),
            actor="owner",
            occurred_at=R0,
        )
        decision = self.trust.authorize(
            AuthorizationRequest(
                subject="c4-input-owner",
                action=preparation.action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=preparation.context,
            ),
            now=R1,
        )
        self.assertTrue(decision.allowed)
        self.input_set = self.inputs.freeze(
            "input-set-c4",
            execution_ids,
            authorization_decision_id=decision.decision_id,
            actor="c4-input-owner",
            occurred_at=R2,
        )
        self.assertTrue(self.inputs.verify_input_set("input-set-c4").ok)

    def _valid_manifest(self) -> dict[str, object]:
        helper = candidate_fixture.C4ArchitectureCandidateTests(
            methodName="test_prepare_candidate_is_deterministic_and_side_effect_free"
        )
        helper.inputs = candidate_fixture.FakeC4InputService()
        return helper.valid_manifest()

    def _create_candidate(self) -> None:
        preparation = self.candidates.prepare_create(
            "candidate-c4",
            input_set_id="input-set-c4",
            manifest=self.manifest,
        )
        self.trust.add_rule(
            PolicyRule(
                "allow-review-fixture-candidate",
                PolicyEffect.ALLOW,
                "c4-architect",
                preparation.action,
                preparation.resource,
            ),
            actor="owner",
            occurred_at=R0,
        )
        decision = self.trust.authorize(
            AuthorizationRequest(
                subject="c4-architect",
                action=preparation.action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=preparation.context,
            ),
            now=R3,
        )
        self.assertTrue(decision.allowed)
        self.candidate = self.candidates.create_candidate(
            "candidate-c4",
            input_set_id="input-set-c4",
            manifest=self.manifest,
            authorization_decision_id=decision.decision_id,
            actor="c4-architect",
            occurred_at=R4,
        )
        self.assertTrue(self.candidates.verify_candidate("candidate-c4").ok)

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

    def accept_root(self) -> None:
        public_key = self.public_key.read_bytes()
        preparation = self.reviews.prepare_reviewer_root(
            "architecture-reviewer-key",
            public_key,
        )
        self.trust.add_rule(
            PolicyRule(
                "allow-c4-reviewer-root",
                PolicyEffect.ALLOW,
                "review-root-owner",
                preparation.action,
                preparation.resource,
            ),
            actor="owner",
            occurred_at=R0,
        )
        decision = self.trust.authorize(
            AuthorizationRequest(
                subject="review-root-owner",
                action=preparation.action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=preparation.context,
            ),
            now=R5,
        )
        self.assertTrue(decision.allowed)
        self.root_record = self.reviews.accept_reviewer_root(
            "architecture-reviewer-key",
            public_key,
            authorization_decision_id=decision.decision_id,
            actor="review-root-owner",
            occurred_at=R6,
        )
        self.assertTrue(
            self.reviews.verify_reviewer_root("architecture-reviewer-key").ok
        )

    @staticmethod
    def finding(
        *,
        finding_id: str,
        severity: C4ArchitectureFindingSeverity,
        code: C4ArchitectureFindingCode,
        message: str,
        evidence_refs: tuple[str, ...],
    ) -> dict[str, object]:
        return {
            "finding_id": finding_id,
            "severity": severity.value,
            "code": code.value,
            "message": message,
            "evidence_refs": list(evidence_refs),
        }

    def payload(
        self,
        *,
        review_id: str = "review-c4",
        reviewer_identity: str = "independent-architecture-reviewer",
        reviewed_at_utc: str = R7,
        structural: C4ArchitectureVerificationResult = (
            C4ArchitectureVerificationResult.PASS
        ),
        security: C4ArchitectureVerificationResult = (
            C4ArchitectureVerificationResult.PASS
        ),
        evidence: C4ArchitectureVerificationResult = (
            C4ArchitectureVerificationResult.PASS
        ),
        verdict: C4ArchitectureReviewVerdict = (
            C4ArchitectureReviewVerdict.ACCEPTED
        ),
        findings: list[dict[str, object]] | None = None,
        reviewer_environment: str = "isolated-c4-review-vm",
    ) -> bytes:
        value = {
            "review_id": review_id,
            "candidate_id": self.candidate.candidate_id,
            "architecture_id": self.candidate.architecture_id,
            "architecture_version": self.candidate.architecture_version,
            "input_set_id": self.candidate.input_set_id,
            "manifest_sha256": self.candidate.manifest_sha256,
            "input_set_digest": self.candidate.input_set_digest,
            "reviewer_identity": reviewer_identity,
            "reviewer_environment": reviewer_environment,
            "independence_basis": "separate key, process, identity and workspace",
            "reviewed_at_utc": reviewed_at_utc,
            "structural_verification_result": structural.value,
            "security_verification_result": security.value,
            "evidence_binding_result": evidence.value,
            "verdict": verdict.value,
            "findings": findings or [],
            "gate_effect": "NO_PUBLICATION_NO_DEPLOYMENT",
        }
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def sign(self, payload: bytes) -> bytes:
        payload_path = self.root / "review-payload.json"
        signature_path = self.root / "review-payload.sig"
        payload_path.write_bytes(payload)
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(self.private_key),
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
        payload: bytes,
        *,
        signature: bytes | None = None,
        actor: str = "review-admitter",
        occurred_at: str = R8,
    ):
        return self.reviews.admit_review(
            "candidate-c4",
            "architecture-reviewer-key",
            payload,
            signature or self.sign(payload),
            actor=actor,
            occurred_at=occurred_at,
        )

    def test_reviewer_root_preparation_is_deterministic_and_side_effect_free(self) -> None:
        public_key = self.public_key.read_bytes()
        decisions_before = self.table_count("trust_decisions")
        consumptions_before = self.table_count(
            "continuity_authorization_consumptions"
        )

        first = self.reviews.prepare_reviewer_root("reviewer-key", public_key)
        second = self.reviews.prepare_reviewer_root("reviewer-key", public_key)

        self.assertEqual(first, second)
        self.assertEqual(first.algorithm, "Ed25519")
        self.assertEqual(first.purpose, "C4_ARCHITECTURE_REVIEW")
        self.assertEqual(first.action, "c4.architecture-reviewer.accept")
        self.assertEqual(
            first.resource,
            "continuity:c4:architecture-reviewer:reviewer-key",
        )
        self.assertEqual(
            first.mission_id,
            "c4-architecture-reviewer:reviewer-key",
        )
        self.assertEqual(self.table_count("trust_decisions"), decisions_before)
        self.assertEqual(
            self.table_count("continuity_authorization_consumptions"),
            consumptions_before,
        )
        self.assertEqual(self.table_count("c4_architecture_reviewer_roots"), 0)

    def test_default_deny_then_exact_reviewer_root_is_verified_and_idempotent(self) -> None:
        public_key = self.public_key.read_bytes()
        preparation = self.reviews.prepare_reviewer_root(
            "architecture-reviewer-key",
            public_key,
        )
        denied = self.trust.authorize(
            AuthorizationRequest(
                subject="review-root-owner",
                action=preparation.action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=preparation.context,
            ),
            now=R5,
        )
        self.assertFalse(denied.allowed)
        with self.assertRaises(AuthorizationError):
            self.reviews.accept_reviewer_root(
                "architecture-reviewer-key",
                public_key,
                authorization_decision_id=denied.decision_id,
                actor="review-root-owner",
                occurred_at=R6,
            )

        self.accept_root()
        replay = self.reviews.accept_reviewer_root(
            "architecture-reviewer-key",
            public_key,
            authorization_decision_id=self.root_record.authorization_decision_id,
            actor="review-root-owner",
            occurred_at=R9,
        )

        self.assertEqual(replay, self.root_record)
        verification = self.reviews.verify_reviewer_root(
            "architecture-reviewer-key"
        )
        self.assertTrue(verification.ok, verification.defects)

    def test_exact_signed_accepted_review_is_admitted_verified_and_idempotent(self) -> None:
        self.accept_root()
        payload = self.payload()
        signature = self.sign(payload)

        first = self.admit(payload, signature=signature)
        replay = self.admit(payload, signature=signature, occurred_at=R9)

        self.assertEqual(first, replay)
        self.assertEqual(first.verdict, C4ArchitectureReviewVerdict.ACCEPTED)
        self.assertEqual(first.finding_count, 0)
        self.assertEqual(self.reviews.get_findings(first.review_id), ())
        stored = self.database.connection.execute(
            "SELECT payload, signature FROM c4_architecture_reviews WHERE review_id = ?",
            (first.review_id,),
        ).fetchone()
        self.assertIsNotNone(stored)
        assert stored is not None
        self.assertEqual(bytes(stored["payload"]), payload)
        self.assertEqual(bytes(stored["signature"]), signature)
        verification = self.reviews.verify_review(first.review_id)
        self.assertTrue(verification.ok, verification.defects)

    def test_exact_signed_rework_review_is_valid(self) -> None:
        self.accept_root()
        findings = [
            self.finding(
                finding_id="finding-medium",
                severity=C4ArchitectureFindingSeverity.MEDIUM,
                code=C4ArchitectureFindingCode.PORT_CONTRACT_GAP,
                message="Port contract needs one additional recovery invariant",
                evidence_refs=("port-action", "proof-action"),
            )
        ]
        payload = self.payload(
            verdict=C4ArchitectureReviewVerdict.REWORK_REQUIRED,
            findings=findings,
        )

        record = self.admit(payload)

        self.assertEqual(
            record.verdict,
            C4ArchitectureReviewVerdict.REWORK_REQUIRED,
        )
        self.assertEqual(record.finding_count, 1)
        frozen = self.reviews.get_findings(record.review_id)
        self.assertEqual(frozen[0].severity, C4ArchitectureFindingSeverity.MEDIUM)
        self.assertTrue(self.reviews.verify_review(record.review_id).ok)

    def test_exact_signed_rejected_review_is_valid(self) -> None:
        self.accept_root()
        findings = [
            self.finding(
                finding_id="finding-high",
                severity=C4ArchitectureFindingSeverity.HIGH,
                code=C4ArchitectureFindingCode.SECURITY_BOUNDARY_GAP,
                message="Action port lacks an independently verified isolation boundary",
                evidence_refs=("port-action", "test-action"),
            )
        ]
        payload = self.payload(
            security=C4ArchitectureVerificationResult.FAIL,
            verdict=C4ArchitectureReviewVerdict.REJECTED,
            findings=findings,
        )

        record = self.admit(payload)

        self.assertEqual(record.verdict, C4ArchitectureReviewVerdict.REJECTED)
        self.assertEqual(record.security_verification_result.value, "FAIL")
        self.assertTrue(self.reviews.verify_review(record.review_id).ok)

    def test_whitespace_modified_payload_with_original_signature_is_rejected(self) -> None:
        self.accept_root()
        payload = self.payload()
        signature = self.sign(payload)

        with self.assertRaises(IntegrityError):
            self.admit(payload + b" ", signature=signature)

    def test_second_review_or_material_conflict_is_rejected(self) -> None:
        self.accept_root()
        first_payload = self.payload()
        first_signature = self.sign(first_payload)
        self.admit(first_payload, signature=first_signature)

        changed_same_id = self.payload(
            reviewer_environment="different-review-environment"
        )
        with self.assertRaises(ConflictError):
            self.admit(changed_same_id)

        second_payload = self.payload(
            review_id="review-c4-second",
            verdict=C4ArchitectureReviewVerdict.REWORK_REQUIRED,
            findings=[
                self.finding(
                    finding_id="finding-medium",
                    severity=C4ArchitectureFindingSeverity.MEDIUM,
                    code=C4ArchitectureFindingCode.MISSION_FABRIC_GAP,
                    message="Monitor stage needs revised proof ownership",
                    evidence_refs=("MONITOR", "proof-monitor"),
                )
            ],
        )
        with self.assertRaises(ConflictError):
            self.admit(second_payload)


if __name__ == "__main__":
    unittest.main()
