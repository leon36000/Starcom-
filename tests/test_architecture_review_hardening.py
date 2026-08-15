from __future__ import annotations

import json
import unittest

import test_architecture_review as review_fixture

from starcom.architecture_review import (
    C4ArchitectureFindingCode,
    C4ArchitectureFindingSeverity,
)


class C4ArchitectureReviewHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = review_fixture.C4ArchitectureReviewTests(
            methodName="test_exact_accepted_review_is_admitted_replayed_and_verified"
        )
        self.helper.setUp()
        self.database = self.helper.database
        self.reviews = self.helper.reviews

    def tearDown(self) -> None:
        self.helper.tearDown()

    def admitted(self, *, with_finding: bool = False):
        self.helper.accept_root()
        findings = []
        if with_finding:
            findings = [
                self.helper.finding(
                    "finding-documentation",
                    code=C4ArchitectureFindingCode.DOCUMENTATION_IMPROVEMENT,
                    severity=C4ArchitectureFindingSeverity.LOW,
                )
            ]
        value = self.helper.payload_value(findings=findings)
        return self.helper.admit(value)

    def test_reviewer_root_verifier_detects_fingerprint_tampering(self) -> None:
        self.helper.accept_root()
        self.database.connection.execute(
            "DROP TRIGGER c4_architecture_reviewer_roots_no_update"
        )
        self.database.connection.execute(
            """
            UPDATE c4_architecture_reviewer_roots
            SET public_key_fingerprint_sha256 = ? WHERE key_id = ?
            """,
            ("0" * 64, "reviewer-key"),
        )

        verification = self.reviews.verify_reviewer_root("reviewer-key")

        self.assertFalse(verification.ok)
        self.assertIn(
            "C4_REVIEWER_ROOT_FINGERPRINT_MISMATCH",
            verification.defects,
        )

    def test_review_verifier_detects_exact_payload_and_signature_tampering(self) -> None:
        review = self.admitted()
        self.database.connection.execute(
            "DROP TRIGGER c4_architecture_reviews_no_update"
        )
        row = self.database.connection.execute(
            "SELECT payload FROM c4_architecture_reviews WHERE review_id = ?",
            (review.review_id,),
        ).fetchone()
        self.assertIsNotNone(row)
        assert row is not None
        self.database.connection.execute(
            "UPDATE c4_architecture_reviews SET payload = ? WHERE review_id = ?",
            (bytes(row["payload"]) + b" ", review.review_id),
        )

        verification = self.reviews.verify_review(review.review_id)

        self.assertFalse(verification.ok)
        self.assertIn("C4_REVIEW_PAYLOAD_SHA256_MISMATCH", verification.defects)
        self.assertIn("C4_REVIEW_SIGNATURE_INVALID", verification.defects)

    def test_review_verifier_detects_finding_digest_tampering(self) -> None:
        review = self.admitted(with_finding=True)
        self.database.connection.execute(
            "DROP TRIGGER c4_architecture_review_findings_no_update"
        )
        self.database.connection.execute(
            """
            UPDATE c4_architecture_review_findings SET finding_sha256 = ?
            WHERE review_id = ? AND ordinal = 0
            """,
            ("0" * 64, review.review_id),
        )

        verification = self.reviews.verify_review(review.review_id)

        self.assertFalse(verification.ok)
        self.assertIn("C4_REVIEW_FINDING_SHA256_MISMATCH:0", verification.defects)

    def test_review_verifier_detects_candidate_and_input_becoming_dirty(self) -> None:
        review = self.admitted()
        self.helper.candidates.defects = (
            "C4_CANDIDATE_LEDGER_CHAIN:HASH_MISMATCH",
        )
        self.helper.inputs.defects = (
            "C4_INPUT_MEMBER_STALE:execution-success",
        )

        verification = self.reviews.verify_review(review.review_id)

        self.assertFalse(verification.ok)
        self.assertIn(
            "C4_REVIEW_CANDIDATE:C4_CANDIDATE_LEDGER_CHAIN:HASH_MISMATCH",
            verification.defects,
        )
        self.assertIn(
            "C4_REVIEW_INPUT:C4_INPUT_MEMBER_STALE:execution-success",
            verification.defects,
        )

    def test_reviewer_root_verifier_detects_consumption_and_event_tampering(self) -> None:
        root = self.helper.accept_root()
        self.database.connection.execute(
            "DROP TRIGGER continuity_authorization_consumptions_no_update"
        )
        self.database.connection.execute(
            """
            UPDATE continuity_authorization_consumptions SET operation_id = ?
            WHERE decision_id = ?
            """,
            ("different-key", root.authorization_decision_id),
        )
        self.database.connection.execute("DROP TRIGGER ledger_events_no_update")
        self.database.connection.execute(
            "UPDATE ledger_events SET actor = ? WHERE event_id = ?",
            ("intruder", root.ledger_event_id),
        )

        verification = self.reviews.verify_reviewer_root(root.key_id)

        self.assertFalse(verification.ok)
        self.assertIn(
            "C4_REVIEWER_ROOT_AUTHORIZATION_CONSUMPTION_MISMATCH",
            verification.defects,
        )
        self.assertIn("C4_REVIEWER_ROOT_LEDGER_ACTOR_MISMATCH", verification.defects)
        self.assertTrue(
            any(
                defect.startswith("C4_REVIEWER_ROOT_LEDGER_CHAIN:")
                for defect in verification.defects
            ),
            verification.defects,
        )

    def test_review_verifier_detects_row_binding_tampering(self) -> None:
        review = self.admitted()
        self.database.connection.execute(
            "DROP TRIGGER c4_architecture_reviews_no_update"
        )
        self.database.connection.execute(
            """
            UPDATE c4_architecture_reviews SET input_set_digest = ?
            WHERE review_id = ?
            """,
            ("0" * 64, review.review_id),
        )

        verification = self.reviews.verify_review(review.review_id)

        self.assertFalse(verification.ok)
        self.assertIn("C4_REVIEW_PAYLOAD_RECORD_MISMATCH", verification.defects)
        self.assertIn("C4_REVIEW_INPUT_SET_DIGEST_MISMATCH", verification.defects)

    def test_review_verifier_detects_review_ledger_tampering(self) -> None:
        review = self.admitted()
        self.database.connection.execute("DROP TRIGGER ledger_events_no_update")
        self.database.connection.execute(
            """
            UPDATE ledger_events SET actor = ?, payload_json = ?
            WHERE event_id = ?
            """,
            (
                "intruder",
                json.dumps(
                    {"review_id": "different-review"},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                review.ledger_event_id,
            ),
        )

        verification = self.reviews.verify_review(review.review_id)

        self.assertFalse(verification.ok)
        self.assertIn("C4_REVIEW_LEDGER_ACTOR_MISMATCH", verification.defects)
        self.assertIn("C4_REVIEW_LEDGER_PAYLOAD_MISMATCH", verification.defects)
        self.assertTrue(
            any(
                defect.startswith("C4_REVIEW_LEDGER_CHAIN:")
                for defect in verification.defects
            ),
            verification.defects,
        )


if __name__ == "__main__":
    unittest.main()
