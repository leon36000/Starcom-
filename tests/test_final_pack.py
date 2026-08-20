from __future__ import annotations

from pathlib import Path
import sqlite3
import tempfile
import unittest

from starcom.canonical import canonical_json
from starcom.continuity import ContinuityService
from starcom.errors import ConflictError, IntegrityError, StateTransitionError, ValidationError
from starcom.final_pack import C7FinalPackService
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule
from test_execution_plan import RecordingSignatureVerifier
from test_red_team import C6_PUBLIC_KEY, RedTeamGraph, T6


T7 = "2026-08-20T12:07:00.000000Z"
T8 = "2026-08-20T12:08:00.000000Z"
C7_PUBLIC_KEY = b"c7-final-pack-public-key"


class C7RecordingSignatureVerifier(RecordingSignatureVerifier):
    def validate_public_key(self, public_key_pem: bytes) -> bool:
        return public_key_pem == C7_PUBLIC_KEY


class FinalPackGraph:
    def __init__(self, root: Path) -> None:
        self.base = RedTeamGraph(root)
        self.database = self.base.database
        self.ledger = self.base.ledger
        self.trust = self.base.trust
        self.architecture = self.base.architecture
        self.execution_plan = self.base.execution_plan
        self.red_team = self.base.service
        self.verifier = C7RecordingSignatureVerifier()
        self.continuity = ContinuityService(
            self.database, self.ledger, self.trust, self.verifier
        )
        self.base.accept_root()
        c6_payload = self.base.payload()
        self.red_team.admit_assessment(
            "plan-1",
            "c6-root",
            c6_payload,
            self.base.verifier.sign(C6_PUBLIC_KEY, c6_payload),
            actor="c6-admitter",
            occurred_at=T6,
        )
        self.service = C7FinalPackService(
            self.database,
            self.ledger,
            self.trust,
            self.continuity,
            self.architecture,
            self.execution_plan,
            self.red_team,
            signature_verifier=self.verifier,
        )

    def close(self) -> None:
        self.base.close()

    def accept_root(self) -> None:
        self.trust.add_rule(
            PolicyRule(
                "c7-root-rule",
                PolicyEffect.ALLOW,
                "c7-root-operator",
                "continuity.trust-root.accept",
                "continuity:trust-root:c7-root",
            ),
            actor="policy-owner",
            occurred_at="2026-08-20T12:00:00.000000Z",
        )
        decision = self.trust.authorize(
            AuthorizationRequest(
                "c7-root-operator",
                "continuity.trust-root.accept",
                "continuity:trust-root:c7-root",
            ),
            now="2026-08-20T12:01:00.000000Z",
        )
        self.continuity.accept_trust_root(
            "c7-root",
            C7_PUBLIC_KEY,
            decision_id=decision.decision_id,
            actor="c7-root-operator",
            occurred_at="2026-08-20T12:01:00.000000Z",
        )

    def payload(self, **overrides: object) -> bytes:
        snapshot = self.service.snapshot("assessment-1")
        manifest = [
            {
                "artifact_id": "artifact-architecture",
                "artifact_kind": "C4_ARCHITECTURE_BASELINE",
                "source_phase": "C4",
                "digest": snapshot.architecture_payload_sha256,
                "media_type": "application/json",
                "required": True,
            },
            {
                "artifact_id": "artifact-assessment",
                "artifact_kind": "C6_RED_TEAM_ASSESSMENT",
                "source_phase": "C6",
                "digest": snapshot.assessment_payload_sha256,
                "media_type": "application/json",
                "required": True,
            },
            {
                "artifact_id": "artifact-plan",
                "artifact_kind": "C5_EXECUTION_PLAN",
                "source_phase": "C5",
                "digest": snapshot.plan_payload_sha256,
                "media_type": "application/json",
                "required": True,
            },
            {
                "artifact_id": "artifact-provenance",
                "artifact_kind": "PROVENANCE",
                "source_phase": "C7",
                "digest": snapshot.provenance_digest,
                "media_type": "application/json",
                "required": True,
            },
            {
                "artifact_id": "artifact-reproducibility",
                "artifact_kind": "REPRODUCIBILITY",
                "source_phase": "C7",
                "digest": "4" * 64,
                "media_type": "text/plain",
                "required": True,
            },
            {
                "artifact_id": "artifact-rollback",
                "artifact_kind": "ROLLBACK_EVIDENCE",
                "source_phase": "C7",
                "digest": "5" * 64,
                "media_type": "text/plain",
                "required": True,
            },
            {
                "artifact_id": "artifact-sbom",
                "artifact_kind": "SBOM",
                "source_phase": "C7",
                "digest": "3" * 64,
                "media_type": "application/json",
                "required": True,
            },
            {
                "artifact_id": "artifact-security",
                "artifact_kind": "SECURITY_REPORT",
                "source_phase": "C7",
                "digest": "2" * 64,
                "media_type": "text/plain",
                "required": True,
            },
            {
                "artifact_id": "artifact-tests",
                "artifact_kind": "TEST_REPORT",
                "source_phase": "C7",
                "digest": "1" * 64,
                "media_type": "text/plain",
                "required": True,
            },
        ]
        value: dict[str, object] = {
            "pack_id": "pack-1",
            "pack_version": "1.0.0",
            "baseline_id": snapshot.baseline_id,
            "architecture_id": snapshot.architecture_id,
            "architecture_version": snapshot.architecture_version,
            "architecture_payload_sha256": snapshot.architecture_payload_sha256,
            "c4_snapshot_digest": snapshot.c4_snapshot_digest,
            "plan_id": snapshot.plan_id,
            "plan_version": snapshot.plan_version,
            "plan_payload_sha256": snapshot.plan_payload_sha256,
            "c5_snapshot_digest": snapshot.c5_snapshot_digest,
            "assessment_id": snapshot.assessment_id,
            "assessment_payload_sha256": snapshot.assessment_payload_sha256,
            "c6_snapshot_digest": snapshot.c6_snapshot_digest,
            "c3_snapshot_digest": snapshot.c3_snapshot_digest,
            "chain_snapshot_digest": snapshot.chain_snapshot_digest,
            "evidence_manifest": manifest,
            "sbom_digest": "3" * 64,
            "test_report_digest": "1" * 64,
            "security_report_digest": "2" * 64,
            "provenance_digest": snapshot.provenance_digest,
            "reproducibility_digest": "4" * 64,
            "rollback_evidence_digest": "5" * 64,
            "packager_identity": "independent-packager",
            "packager_environment": "c7-packaging-isolated",
            "verifier_identity": "independent-pack-verifier",
            "verifier_environment": "c7-verification-isolated",
            "packaged_at_utc": T7,
            "independence_basis": {
                "excluded_identities": list(snapshot.material_identities),
                "statement": "C7 actors are independent from all C4, C5, and C6 material actors",
            },
            "release_status": "NOT_RELEASED",
            "external_runtime_integration_status": "NOT_PROVEN",
            "live_census_certification_status": "NOT_PROVEN",
            "gate_effect": "C7_FINAL_PACK_ADMITTED_NOT_RELEASED",
        }
        value.update(overrides)
        return canonical_json(value).encode("utf-8")


class C7FinalPackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.graph = FinalPackGraph(Path(self.tempdir.name))

    def tearDown(self) -> None:
        self.graph.close()
        self.tempdir.cleanup()

    def test_public_contract_is_deterministic(self) -> None:
        first = self.graph.service.snapshot("assessment-1")
        self.assertEqual(first, self.graph.service.snapshot("assessment-1"))
        preparation = self.graph.service.prepare("pack-1", "assessment-1")
        self.assertEqual(preparation.pack_id, "pack-1")
        self.assertEqual(preparation.assessment_id, "assessment-1")
        self.assertEqual(preparation.chain_snapshot_digest, first.chain_snapshot_digest)
        self.assertEqual(preparation.gate_effect, "C7_FINAL_PACK_ADMITTED_NOT_RELEASED")

    def test_strict_contract_rejects_malformed_payloads(self) -> None:
        valid = self.graph.payload()
        malformed = [
            b'{"pack_id":"a","pack_id":"b"}',
            b"\xff",
            self.graph.payload(release_status="RELEASED"),
            self.graph.payload(gate_effect="C7_FINAL_PACK_ADMITTED"),
            self.graph.payload(evidence_manifest=[]),
            self.graph.payload(
                evidence_manifest=[
                    {
                        "artifact_id": "artifact-architecture",
                        "artifact_kind": "C4_ARCHITECTURE_BASELINE",
                    }
                ]
            ),
            self.graph.payload(architecture_payload_sha256="A" * 64),
            valid + b" ",
        ]
        for payload in malformed:
            with self.subTest(payload=payload):
                with self.assertRaises((ValidationError, StateTransitionError, IntegrityError)):
                    self.graph.service.admit_pack(
                        "assessment-1",
                        "missing-root",
                        payload,
                        b"bad-signature",
                        actor="c7-admitter",
                        occurred_at=T8,
                    )
        count = self.graph.database.connection.execute(
            "SELECT COUNT(*) AS count FROM c7_final_packs"
        ).fetchone()["count"]
        self.assertEqual(count, 0)

    def test_upstream_dirty_and_nonpass_material_blocks_snapshot(self) -> None:
        self.graph.architecture.clean = False
        with self.assertRaises(IntegrityError):
            self.graph.service.snapshot("assessment-1")

    def test_independence_and_chronology_are_fail_closed(self) -> None:
        self.graph.accept_root()
        with self.assertRaises(StateTransitionError):
            self.graph.service.admit_pack(
                "assessment-1",
                "c7-root",
                self.graph.payload(packager_identity="planner"),
                self.graph.verifier.sign(C7_PUBLIC_KEY, self.graph.payload(packager_identity="planner")),
                actor="c7-admitter",
                occurred_at=T8,
            )
        with self.assertRaises(StateTransitionError):
            self.graph.service.admit_pack(
                "assessment-1",
                "c7-root",
                self.graph.payload(verifier_identity="independent-packager"),
                self.graph.verifier.sign(C7_PUBLIC_KEY, self.graph.payload(verifier_identity="independent-packager")),
                actor="c7-admitter",
                occurred_at=T8,
            )
        with self.assertRaises(StateTransitionError):
            self.graph.service.admit_pack(
                "assessment-1",
                "c7-root",
                self.graph.payload(packaged_at_utc=T6),
                self.graph.verifier.sign(C7_PUBLIC_KEY, self.graph.payload(packaged_at_utc=T6)),
                actor="c7-admitter",
                occurred_at=T8,
            )

    def test_exact_admission_replay_conflict_and_manifest_reads(self) -> None:
        payload = self.graph.payload()
        signature = self.graph.verifier.sign(C7_PUBLIC_KEY, payload)
        with self.assertRaises(IntegrityError):
            self.graph.service.admit_pack(
                "assessment-1",
                "c7-root",
                payload,
                signature,
                actor="c7-admitter",
                occurred_at=T8,
            )
        self.graph.accept_root()
        first = self.graph.service.admit_pack(
            "assessment-1",
            "c7-root",
            payload,
            signature,
            actor="c7-admitter",
            occurred_at=T8,
        )
        self.assertEqual(first.release_status, "NOT_RELEASED")
        self.assertTrue(self.graph.service.verify_pack(first.pack_id).ok)
        self.assertEqual(len(self.graph.service.get_manifest(first.pack_id)), 9)
        replay = self.graph.service.admit_pack(
            "assessment-1",
            "c7-root",
            payload,
            signature,
            actor="c7-admitter",
            occurred_at="2026-08-20T12:09:00.000000Z",
        )
        self.assertEqual(replay, first)
        self.assertEqual(
            len(self.graph.ledger.read_stream("continuity:c7:final-pack:pack-1")),
            1,
        )
        conflict_payload = self.graph.payload(pack_id="pack-2")
        with self.assertRaises(ConflictError):
            self.graph.service.admit_pack(
                "assessment-1",
                "c7-root",
                conflict_payload,
                self.graph.verifier.sign(C7_PUBLIC_KEY, conflict_payload),
                actor="c7-admitter",
                occurred_at=T8,
            )

    def test_independent_verifier_detects_pack_manifest_and_ledger_tampering(self) -> None:
        self.graph.accept_root()
        payload = self.graph.payload()
        pack = self.graph.service.admit_pack(
            "assessment-1",
            "c7-root",
            payload,
            self.graph.verifier.sign(C7_PUBLIC_KEY, payload),
            actor="c7-admitter",
            occurred_at=T8,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.graph.database.connection.execute(
                "UPDATE c7_final_packs SET release_status = 'RELEASED' WHERE pack_id = ?",
                (pack.pack_id,),
            )
        self.graph.database.connection.execute(
            "DROP TRIGGER c7_final_pack_manifest_no_update"
        )
        self.graph.database.connection.execute(
            "UPDATE c7_final_pack_manifest SET material_json = '{}' WHERE pack_id = ? AND ordinal = 0",
            (pack.pack_id,),
        )
        verification = self.graph.service.verify_pack(pack.pack_id)
        self.assertFalse(verification.ok)
        self.assertTrue(any("PACK_MANIFEST" in defect for defect in verification.defects))

        self.graph.database.connection.execute("DROP TRIGGER c7_final_packs_no_update")
        self.graph.database.connection.execute(
            "UPDATE c7_final_packs SET payload_sha256 = ? WHERE pack_id = ?",
            ("f" * 64, pack.pack_id),
        )
        verification = self.graph.service.verify_pack(pack.pack_id)
        self.assertFalse(verification.ok)
        self.assertIn("PACK_PAYLOAD_DIGEST_MISMATCH", verification.defects)

        self.graph.database.connection.execute("DROP TRIGGER ledger_events_no_update")
        self.graph.database.connection.execute(
            "UPDATE ledger_events SET kind = 'TAMPERED' WHERE event_id = ?",
            (pack.ledger_event_id,),
        )
        verification = self.graph.service.verify_pack(pack.pack_id)
        self.assertFalse(verification.ok)
        self.assertIn("PACK_LEDGER_KIND_MISMATCH", verification.defects)


class C7RuntimeWiringTests(unittest.TestCase):
    def test_runtime_exposes_one_shared_c7_graph_without_release_surface(self) -> None:
        from starcom.cli import Runtime

        runtime = Runtime.open(":memory:")
        try:
            self.assertIs(runtime.final_pack, runtime.c7_final_pack)
            self.assertIs(runtime.final_pack.database, runtime.database)
            self.assertIs(runtime.final_pack.ledger, runtime.ledger)
            forbidden = {
                "release",
                "publish",
                "deploy",
                "execute",
                "promote",
                "adopt",
            }
            self.assertTrue(forbidden.isdisjoint(set(dir(runtime.final_pack))))
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
