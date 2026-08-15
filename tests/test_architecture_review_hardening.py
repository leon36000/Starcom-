from __future__ import annotations

import json
import unittest

import test_architecture_review as review_fixture

from starcom.architecture_candidate import C4ArchitectureCandidateVerification
from starcom.architecture_review import (
    C4ArchitectureFindingCode,
    C4ArchitectureFindingSeverity,
    C4ArchitectureReviewVerdict,
    C4ArchitectureVerificationResult,
)
from starcom.errors import IntegrityError, StateTransitionError, ValidationError


class C4ArchitectureReviewHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = review_fixture.C4ArchitectureReviewTests(
            methodName="test_exact_signed_accepted_review_is_admitted_verified_and_idempotent"
        )
        self.helper.setUp()
        self.reviews = self.helper.reviews
        self.database = self.helper.database

    def tearDown(self) -> None:
        self.helper.tearDown()

    @staticmethod
    def compact(value: object) -> bytes:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def signed_admission(self, payload: bytes) -> None:
        self.reviews.admit_review(
            "candidate-c4",
            "architecture-reviewer-key",
            payload,
            self.helper.sign(payload),
            actor="review-admitter",
            occurred_at=review_fixture.R8,
        )

    def test_duplicate_missing_extra_fields_and_invalid_utf8_fail_closed(self) -> None:
        self.helper.accept_root()
        valid = self.helper.payload()
        value = json.loads(valid.decode("utf-8"))

        missing_value = dict(value)
        del missing_value["gate_effect"]
        with self.assertRaises(ValidationError):
            self.signed_admission(self.compact(missing_value))

        extra_value = dict(value)
        extra_value["unexpected"] = "must fail closed"
        with self.assertRaises(ValidationError):
            self.signed_admission(self.compact(extra_value))

        duplicate = valid.decode("utf-8").replace(
            '"review_id":"review-c4"',
            '"review_id":"review-c4","review_id":"review-duplicate"',
            1,
        ).encode("utf-8")
        with self.assertRaises(ValidationError):
            self.signed_admission(duplicate)

        invalid_utf8 = b"\xff\xfe\xfd"
        with self.assertRaises(ValidationError):
            self.signed_admission(invalid_utf8)

        self.assertEqual(self.helper.table_count("c4_architecture_reviews"), 0)

    def test_verdict_result_and_finding_invariants_fail_closed(self) -> None:
        self.helper.accept_root()
        medium = [
            self.helper.finding(
                finding_id="finding-medium",
                severity=C4ArchitectureFindingSeverity.MEDIUM,
                code=C4ArchitectureFindingCode.PORT_CONTRACT_GAP,
                message="Port contract needs rework",
                evidence_refs=("port-action",),
            )
        ]
        cases = (
            self.helper.payload(
                verdict=C4ArchitectureReviewVerdict.ACCEPTED,
                findings=medium,
            ),
            self.helper.payload(
                verdict=C4ArchitectureReviewVerdict.REWORK_REQUIRED,
                findings=[],
            ),
            self.helper.payload(
                verdict=C4ArchitectureReviewVerdict.REJECTED,
                findings=[],
            ),
            self.helper.payload(
                structural=C4ArchitectureVerificationResult.FAIL,
                verdict=C4ArchitectureReviewVerdict.ACCEPTED,
            ),
        )
        for index, payload in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(ValidationError):
                    self.signed_admission(payload)
        self.assertEqual(self.helper.table_count("c4_architecture_reviews"), 0)

    def test_reviewer_must_be_independent_from_every_disallowed_identity(self) -> None:
        self.helper.accept_root()
        disallowed = (
            "c4-architect",
            "c4-input-owner",
            "author-negative",
            "author-success",
            "review-root-owner",
            "review-admitter",
        )
        for index, identity in enumerate(disallowed):
            with self.subTest(identity=identity):
                payload = self.helper.payload(
                    review_id=f"review-dependent-{index}",
                    reviewer_identity=identity,
                )
                with self.assertRaisesRegex(
                    StateTransitionError,
                    "reviewer identity is not independent",
                ):
                    self.signed_admission(payload)
        self.assertEqual(self.helper.table_count("c4_architecture_reviews"), 0)

    def test_review_timestamp_must_follow_root_input_and_candidate(self) -> None:
        self.helper.accept_root()
        for index, reviewed_at in enumerate(
            (review_fixture.R1, review_fixture.R5)
        ):
            with self.subTest(reviewed_at=reviewed_at):
                payload = self.helper.payload(
                    review_id=f"review-early-{index}",
                    reviewed_at_utc=reviewed_at,
                )
                with self.assertRaisesRegex(
                    StateTransitionError,
                    "review timestamp predates",
                ):
                    self.signed_admission(payload)
        self.assertEqual(self.helper.table_count("c4_architecture_reviews"), 0)

    def test_transaction_rechecks_candidate_input_and_root(self) -> None:
        self.helper.accept_root()
        payload = self.helper.payload()
        original = self.helper.candidates.verify_candidate
        calls = 0

        def dirty_on_second(candidate_id: str) -> C4ArchitectureCandidateVerification:
            nonlocal calls
            calls += 1
            if calls >= 2:
                return C4ArchitectureCandidateVerification(
                    candidate_id=candidate_id,
                    defects=("C4_CANDIDATE_LEDGER_CHAIN:HASH_MISMATCH",),
                )
            return original(candidate_id)

        self.helper.candidates.verify_candidate = dirty_on_second  # type: ignore[method-assign]

        with self.assertRaisesRegex(
            IntegrityError,
            "C4 architecture candidate verification failed",
        ):
            self.signed_admission(payload)
        self.assertGreaterEqual(calls, 2)
        self.assertEqual(self.helper.table_count("c4_architecture_reviews"), 0)

    def test_verifier_detects_reviewer_root_fingerprint_tampering(self) -> None:
        self.helper.accept_root()
        record = self.helper.admit(self.helper.payload())
        self.database.connection.execute(
            "DROP TRIGGER c4_architecture_reviewer_roots_no_update"
        )
        self.database.connection.execute(
            """
            UPDATE c4_architecture_reviewer_roots
            SET public_key_fingerprint_sha256 = ? WHERE key_id = ?
            """,
            ("0" * 64, "architecture-reviewer-key"),
        )

        root_verification = self.reviews.verify_reviewer_root(
            "architecture-reviewer-key"
        )
        review_verification = self.reviews.verify_review(record.review_id)

        self.assertFalse(root_verification.ok)
        self.assertIn(
            "C4_REVIEWER_ROOT_FINGERPRINT_MISMATCH",
            root_verification.defects,
        )
        self.assertFalse(review_verification.ok)
        self.assertIn(
            "C4_REVIEW_ROOT:C4_REVIEWER_ROOT_FINGERPRINT_MISMATCH",
            review_verification.defects,
        )

    def test_verifier_detects_payload_signature_and_finding_tampering(self) -> None:
        self.helper.accept_root()
        payload = self.helper.payload(
            verdict=C4ArchitectureReviewVerdict.REWORK_REQUIRED,
            findings=[
                self.helper.finding(
                    finding_id="finding-medium",
                    severity=C4ArchitectureFindingSeverity.MEDIUM,
                    code=C4ArchitectureFindingCode.MISSION_FABRIC_GAP,
                    message="Monitor proof ownership needs rework",
                    evidence_refs=("MONITOR", "proof-monitor"),
                )
            ],
        )
        record = self.helper.admit(payload)
        self.database.connection.execute(
            "DROP TRIGGER c4_architecture_reviews_no_update"
        )
        self.database.connection.execute(
            "DROP TRIGGER c4_architecture_review_findings_no_update"
        )
        self.database.connection.execute(
            """
            UPDATE c4_architecture_reviews SET payload = ?
            WHERE review_id = ?
            """,
            (payload + b" ", record.review_id),
        )
        self.database.connection.execute(
            """
            UPDATE c4_architecture_review_findings SET finding_sha256 = ?
            WHERE review_id = ? AND ordinal = 0
            """,
            ("0" * 64, record.review_id),
        )

        verification = self.reviews.verify_review(record.review_id)

        self.assertFalse(verification.ok)
        self.assertIn("C4_REVIEW_PAYLOAD_SHA256_MISMATCH", verification.defects)
        self.assertIn("C4_REVIEW_SIGNATURE_INVALID", verification.defects)
        self.assertIn(
            "C4_REVIEW_FINDING_SHA256_MISMATCH:0",
            verification.defects,
        )

    def test_verifier_detects_consumption_and_review_ledger_tampering(self) -> None:
        self.helper.accept_root()
        record = self.helper.admit(self.helper.payload())
        root = self.reviews.get_reviewer_root("architecture-reviewer-key")
        self.database.connection.execute(
            "DROP TRIGGER continuity_authorization_consumptions_no_update"
        )
        self.database.connection.execute(
            """
            UPDATE continuity_authorization_consumptions SET operation_id = ?
            WHERE decision_id = ?
            """,
            ("different-reviewer-key", root.authorization_decision_id),
        )
        self.database.connection.execute("DROP TRIGGER ledger_events_no_update")
        self.database.connection.execute(
            "UPDATE ledger_events SET actor = ? WHERE event_id = ?",
            ("intruder", record.ledger_event_id),
        )

        verification = self.reviews.verify_review(record.review_id)

        self.assertFalse(verification.ok)
        self.assertIn(
            "C4_REVIEW_ROOT:C4_REVIEWER_ROOT_AUTHORIZATION_CONSUMPTION_MISMATCH",
            verification.defects,
        )
        self.assertIn("C4_REVIEW_LEDGER_ACTOR_MISMATCH", verification.defects)
        self.assertTrue(
            any(
                defect.startswith("C4_REVIEW_LEDGER_CHAIN:")
                for defect in verification.defects
            ),
            verification.defects,
        )


if __name__ == "__main__":
    unittest.main()
