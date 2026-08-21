from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest

from starcom.canonical import canonical_json
from starcom.continuity import ContinuityService
from starcom.db import Database
from starcom.errors import ConflictError, IntegrityError, StateTransitionError, ValidationError
from starcom.ledger import EventLedger
from starcom.release_candidate import ReleaseCandidateService
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule, TrustPlane


T0 = "2026-08-21T13:00:00.000000Z"
T1 = "2026-08-21T13:00:01.000000Z"
T2 = "2026-08-21T13:00:02.000000Z"
T3 = "2026-08-21T13:00:03.000000Z"
PUBLIC_KEY = b"block19-rc-public-key"


class RecordingSignatureVerifier:
    def validate_public_key(self, public_key_pem: bytes) -> bool:
        return public_key_pem == PUBLIC_KEY

    def sign(self, payload: bytes) -> bytes:
        return hashlib.sha256(PUBLIC_KEY + payload).digest()

    def verify(self, public_key_pem: bytes, payload: bytes, signature: bytes) -> bool:
        return public_key_pem == PUBLIC_KEY and signature == self.sign(payload)


class ReleaseCandidateGraph:
    def __init__(self, root: Path) -> None:
        self.database = Database(str(root / "release-candidate.sqlite3"))
        self.database.initialize()
        self.ledger = EventLedger(self.database)
        self.trust = TrustPlane(self.database, self.ledger)
        self.verifier = RecordingSignatureVerifier()
        self.continuity = ContinuityService(
            self.database,
            self.ledger,
            self.trust,
            self.verifier,
        )
        self.service = ReleaseCandidateService(
            self.database,
            self.ledger,
            self.trust,
            self.continuity,
            signature_verifier=self.verifier,
        )

    def close(self) -> None:
        self.database.close()

    def accept_root(self) -> None:
        self.trust.add_rule(
            PolicyRule(
                "rc-root-rule",
                PolicyEffect.ALLOW,
                "rc-root-operator",
                "continuity.trust-root.accept",
                "continuity:trust-root:rc-root",
            ),
            actor="policy-owner",
            occurred_at=T0,
        )
        decision = self.trust.authorize(
            AuthorizationRequest(
                "rc-root-operator",
                "continuity.trust-root.accept",
                "continuity:trust-root:rc-root",
            ),
            now=T1,
        )
        self.continuity.accept_trust_root(
            "rc-root",
            PUBLIC_KEY,
            decision_id=decision.decision_id,
            actor="rc-root-operator",
            occurred_at=T1,
        )

    @staticmethod
    def payload(**overrides: object) -> bytes:
        evidence = [
            {
                "evidence_id": evidence_id,
                "artifact_id": f"artifact-{evidence_id.lower()}",
                "digest": "abcdef012"[index] * 64,
                "status": "PROVEN",
            }
            for index, evidence_id in enumerate(
                (
                    "12A-LIVE",
                    "12B-BLUEPRINT",
                    "12C-SIMULATION",
                    "13-ARTIFACTS",
                    "14-SOFTWARE-STUDIO",
                    "15-ASSISTANT",
                    "16-CREATIVE",
                    "17-COCKPIT",
                    "18-DEPLOYMENT",
                )
            )
        ]
        value: dict[str, object] = {
            "assessment_id": "rc-1",
            "assessment_version": "19.0.0",
            "evidence_manifest": evidence,
            "benchmarks": [
                {
                    "benchmark_id": "benchmark-latency",
                    "domain": "integration",
                    "metric": "latency",
                    "unit": "ms",
                    "threshold": 250,
                    "observed": 120,
                    "direction": "MAXIMUM",
                    "pass": True,
                    "evidence_digest": "d" * 64,
                },
                {
                    "benchmark_id": "benchmark-throughput",
                    "domain": "integration",
                    "metric": "throughput",
                    "unit": "events/s",
                    "threshold": 100,
                    "observed": 150,
                    "direction": "MINIMUM",
                    "pass": True,
                    "evidence_digest": "e" * 64,
                },
            ],
            "red_team_cases": [
                {
                    "case_id": "red-team-boundary",
                    "category": "authorization-boundary",
                    "severity": "HIGH",
                    "outcome": "PASS",
                    "evidence_digest": "f" * 64,
                }
            ],
            "release_gates": [
                {
                    "gate_id": "gate-internal-proof",
                    "status": "PASS",
                    "evidence_digest": "0" * 64,
                }
            ],
            "live_census_certification_status": "NOT_PROVEN",
            "external_runtime_integration_status": "NOT_PROVEN",
            "component_adoption_status": "NOT_PROVEN",
            "real_deployment_status": "NOT_PROVEN",
            "assessor_identity": "rc-assessor",
            "assessor_environment": "rc-assessment-isolated",
            "reviewer_identity": "rc-reviewer",
            "reviewer_environment": "rc-review-isolated",
            "assessed_at_utc": T1,
            "reviewed_at_utc": T2,
            "independence_basis": {
                "excluded_identities": ["upstream-builder", "upstream-reviewer"],
                "statement": "Block 19 assessment actors are independent from upstream material actors",
            },
        }
        value.update(overrides)
        return canonical_json(value).encode("utf-8")


class ReleaseCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.graph = ReleaseCandidateGraph(Path(self.tempdir.name))

    def tearDown(self) -> None:
        self.graph.close()
        self.tempdir.cleanup()

    def admit(self, payload: bytes | None = None, **kwargs: object):
        payload = payload or self.graph.payload()
        return self.graph.service.admit_assessment(
            "rc-1",
            "rc-root",
            payload,
            self.graph.verifier.sign(payload),
            actor="rc-admitter",
            occurred_at=T3,
            **kwargs,
        )

    def test_prepare_snapshot_and_runtime_contract(self) -> None:
        preparation = self.graph.service.prepare("rc-1", "19.0.0")
        self.assertEqual(preparation.assessment_id, "rc-1")
        self.assertEqual(preparation.assessment_version, "19.0.0")
        self.assertEqual(preparation.gate_effect, "BLOCK19_RC_ASSESSMENT_ADMITTED_NOT_RELEASED")
        self.assertEqual(preparation.action, "block19.rc-assessment.admit")
        self.graph.accept_root()
        record = self.admit()
        snapshot = self.graph.service.snapshot("rc-1")
        self.assertEqual(snapshot.verdict, "RC_BLOCKED_EXTERNAL_EVIDENCE")
        self.assertEqual(record.release_status, "NOT_RELEASED")
        self.assertEqual(record.gate_effect, "BLOCK19_RC_ASSESSMENT_ADMITTED_NOT_RELEASED")
        self.assertEqual(len(self.graph.service.get_evidence_manifest("rc-1")), 9)
        self.assertEqual(len(self.graph.service.get_benchmarks("rc-1")), 2)
        self.assertEqual(len(self.graph.service.get_red_team_cases("rc-1")), 1)
        self.assertEqual(len(self.graph.service.get_release_gates("rc-1")), 1)

    def test_strict_payload_rejects_duplicates_unknown_derived_fields_and_bad_digests(self) -> None:
        self.graph.accept_root()
        valid = self.graph.payload()
        malformed = [
            b'{"assessment_id":"a","assessment_id":"b"}',
            b"\xff",
            self.graph.payload(verdict="RC_READY_FOR_INDEPENDENT_RELEASE_REVIEW"),
            self.graph.payload(release_status="RELEASED"),
            self.graph.payload(
                evidence_manifest=[
                    *(__import__("json").loads(valid)["evidence_manifest"][:-1]),
                    __import__("json").loads(valid)["evidence_manifest"][-1],
                    __import__("json").loads(valid)["evidence_manifest"][-1],
                ]
            ),
            self.graph.payload(benchmarks=[{"benchmark_id": "bad"}]),
            self.graph.payload(
                evidence_manifest=[
                    {
                        **item,
                        "digest": "A" * 64,
                    }
                    for item in __import__("json").loads(valid)["evidence_manifest"]
                ]
            ),
        ]
        for payload in malformed:
            with self.subTest(payload=payload):
                with self.assertRaises((ValidationError, StateTransitionError, IntegrityError)):
                    self.graph.service.admit_assessment(
                        "rc-1",
                        "rc-root",
                        payload,
                        self.graph.verifier.sign(payload),
                        actor="rc-admitter",
                        occurred_at=T3,
                    )
        count = self.graph.database.connection.execute(
            "SELECT COUNT(*) AS count FROM block19_rc_assessments"
        ).fetchone()["count"]
        self.assertEqual(count, 0)

    def test_numeric_benchmark_consistency_and_chronology_are_fail_closed(self) -> None:
        self.graph.accept_root()
        payload = self.graph.payload(
            benchmarks=[
                {
                    "benchmark_id": "benchmark-latency",
                    "domain": "integration",
                    "metric": "latency",
                    "unit": "ms",
                    "threshold": 250,
                    "observed": 120,
                    "direction": "MAXIMUM",
                    "pass": False,
                    "evidence_digest": "d" * 64,
                }
            ]
        )
        with self.assertRaises(ValidationError):
            self.admit(payload)
        with self.assertRaises(StateTransitionError):
            self.admit(self.graph.payload(assessor_identity="rc-reviewer"))
        with self.assertRaises(StateTransitionError):
            self.admit(self.graph.payload(assessed_at_utc=T2, reviewed_at_utc="2026-08-21T13:00:04.000000Z"))

    def test_internal_failure_is_derived_and_external_proof_is_not_forged(self) -> None:
        self.graph.accept_root()
        import json

        value = json.loads(self.graph.payload())
        value["evidence_manifest"][4]["status"] = "NOT_PROVEN"
        record = self.admit(canonical_json(value).encode("utf-8"))
        self.assertEqual(record.verdict, "RC_BLOCKED_VERIFICATION_FAILURE")
        self.assertEqual(self.graph.service.snapshot("rc-1").release_status, "NOT_RELEASED")

    def test_failed_benchmark_red_team_and_gate_are_internal_failures(self) -> None:
        self.graph.accept_root()
        value = __import__("json").loads(self.graph.payload())
        value["benchmarks"][0]["observed"] = 300
        value["benchmarks"][0]["pass"] = False
        value["red_team_cases"][0]["outcome"] = "BLOCKED"
        value["release_gates"][0]["status"] = "FAIL"
        record = self.admit(canonical_json(value).encode("utf-8"))
        self.assertEqual(record.verdict, "RC_BLOCKED_VERIFICATION_FAILURE")

    def test_ready_for_independent_review_requires_all_external_statuses(self) -> None:
        self.graph.accept_root()
        value = __import__("json").loads(self.graph.payload())
        for field in (
            "live_census_certification_status",
            "external_runtime_integration_status",
            "component_adoption_status",
            "real_deployment_status",
        ):
            value[field] = "PROVEN"
        record = self.admit(canonical_json(value).encode("utf-8"))
        self.assertEqual(record.verdict, "RC_READY_FOR_INDEPENDENT_RELEASE_REVIEW")
        self.assertEqual(record.release_status, "NOT_RELEASED")
        self.assertEqual(record.gate_effect, "BLOCK19_RC_ASSESSMENT_ADMITTED_NOT_RELEASED")

    def test_exact_replay_version_conflict_and_signature_root(self) -> None:
        with self.assertRaises(IntegrityError):
            self.admit()
        self.graph.accept_root()
        payload = self.graph.payload()
        first = self.admit(payload)
        replay = self.graph.service.admit_assessment(
            "rc-1",
            "rc-root",
            payload,
            self.graph.verifier.sign(payload),
            actor="rc-admitter",
            occurred_at="2026-08-21T13:00:09.000000Z",
        )
        self.assertEqual(replay, first)
        self.assertEqual(
            len(self.graph.ledger.read_stream("continuity:block19:release-candidate:rc-1")),
            1,
        )
        conflict = self.graph.payload(assessment_id="rc-2")
        with self.assertRaises(ConflictError):
            self.graph.service.admit_assessment(
                "rc-2",
                "rc-root",
                conflict,
                self.graph.verifier.sign(conflict),
                actor="rc-admitter",
                occurred_at=T3,
            )

    def test_verifier_detects_membership_payload_and_ledger_tampering(self) -> None:
        self.graph.accept_root()
        record = self.admit()
        self.assertTrue(self.graph.service.verify_assessment(record.assessment_id).ok)
        with self.assertRaises(sqlite3.IntegrityError):
            self.graph.database.connection.execute(
                "UPDATE block19_rc_assessments SET release_status = 'RELEASED' WHERE assessment_id = ?",
                (record.assessment_id,),
            )
        self.graph.database.connection.execute("DROP TRIGGER block19_rc_evidence_no_update")
        self.graph.database.connection.execute(
            "UPDATE block19_rc_evidence SET material_json = '{}' WHERE assessment_id = ? AND ordinal = 0",
            (record.assessment_id,),
        )
        verification = self.graph.service.verify_assessment(record.assessment_id)
        self.assertFalse(verification.ok)
        self.assertTrue(any("EVIDENCE" in defect for defect in verification.defects))
        self.graph.database.connection.execute("DROP TRIGGER block19_rc_assessments_no_update")
        self.graph.database.connection.execute(
            "UPDATE block19_rc_assessments SET payload_sha256 = ? WHERE assessment_id = ?",
            ("f" * 64, record.assessment_id),
        )
        self.assertIn(
            "ASSESSMENT_PAYLOAD_DIGEST_MISMATCH",
            self.graph.service.verify_assessment(record.assessment_id).defects,
        )


class ReleaseCandidateRuntimeTests(unittest.TestCase):
    def test_runtime_exposes_one_shared_non_operational_authority(self) -> None:
        from starcom.cli import Runtime

        runtime = Runtime.open(":memory:")
        try:
            self.assertIs(runtime.release_candidate, runtime.rc_assessment)
            self.assertIs(runtime.release_candidate.database, runtime.database)
            forbidden = {"release", "publish", "deploy", "execute", "promote"}
            self.assertTrue(forbidden.isdisjoint(set(dir(runtime.release_candidate))))
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
