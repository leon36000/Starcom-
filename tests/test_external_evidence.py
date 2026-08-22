from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

from starcom.canonical import canonical_json
from starcom.continuity import ContinuityService
from starcom.db import Database
from starcom.errors import ConflictError, IntegrityError, StateTransitionError, ValidationError
from starcom.external_evidence import (
    EXTERNAL_EVIDENCE_KINDS,
    ExternalEvidenceService,
)
from starcom.ledger import EventLedger
from starcom.program import ProgramTruth, StarcomProgram
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule, TrustPlane


T0 = "2026-08-21T13:00:00.000000Z"
T1 = "2026-08-21T13:00:01.000000Z"
T2 = "2026-08-21T13:00:02.000000Z"
T3 = "2026-08-21T13:00:03.000000Z"
PUBLIC_KEY = b"external-evidence-public-key"


class RecordingSignatureVerifier:
    def validate_public_key(self, public_key_pem: bytes) -> bool:
        return public_key_pem == PUBLIC_KEY

    def sign(self, payload: bytes) -> bytes:
        return hashlib.sha256(PUBLIC_KEY + payload).digest()

    def verify(self, public_key_pem: bytes, payload: bytes, signature: bytes) -> bool:
        return public_key_pem == PUBLIC_KEY and signature == self.sign(payload)


class ExternalEvidenceGraph:
    def __init__(self, root: Path) -> None:
        self.database = Database(root / "external-evidence.sqlite3")
        self.database.initialize()
        self.ledger = EventLedger(self.database)
        self.trust = TrustPlane(self.database, self.ledger)
        self.verifier = RecordingSignatureVerifier()
        self.continuity = ContinuityService(
            self.database, self.ledger, self.trust, self.verifier
        )
        self.service = ExternalEvidenceService(
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
                "external-root-rule",
                PolicyEffect.ALLOW,
                "external-root-operator",
                "continuity.trust-root.accept",
                "continuity:trust-root:external-root",
            ),
            actor="policy-owner",
            occurred_at=T0,
        )
        decision = self.trust.authorize(
            AuthorizationRequest(
                "external-root-operator",
                "continuity.trust-root.accept",
                "continuity:trust-root:external-root",
            ),
            now=T1,
        )
        self.continuity.accept_trust_root(
            "external-root",
            PUBLIC_KEY,
            decision_id=decision.decision_id,
            actor="external-root-operator",
            occurred_at=T1,
        )

    @staticmethod
    def payload(
        kind: str = "LIVE_CENSUS_CERTIFICATION",
        *,
        evidence_id: str = "evidence-1",
        valid_until: str = "2026-08-21T14:00:00.000000Z",
        census_count: int = 800,
    ) -> bytes:
        claims: dict[str, object]
        if kind == "LIVE_CENSUS_CERTIFICATION":
            claims = {
                "identity_count": census_count,
                "independent_certification": True,
                "census_digest": "a" * 64,
                "certificate_digest": "b" * 64,
            }
        elif kind == "EXTERNAL_RUNTIME_INTEGRATION":
            claims = {
                "runtime": "starcom-runtime",
                "version": "1.0.0",
                "handshake": "PASS",
                "health": "PASS",
                "durable_roundtrip": "PASS",
            }
        elif kind == "COMPONENT_ADOPTION":
            claims = {
                "component": "component-a",
                "version": "1.0.0",
                "installation": "PASS",
                "enablement": "PASS",
                "rollback": "PASS",
            }
        else:
            claims = {
                "deployment": "deployment-a",
                "node": "node-a",
                "bundle": "bundle-a",
                "health": "PASS",
                "rollback": "PASS",
            }
        return canonical_json(
            {
                "evidence_id": evidence_id,
                "kind": kind,
                "subject_id": f"subject-{evidence_id}",
                "operator_identity": "operator-a",
                "reviewer_identity": "reviewer-b",
                "reviewer_environment": "offline-review",
                "captured_at_utc": T1,
                "valid_until_utc": valid_until,
                "claims": claims,
                "evidence_items": [
                    {
                        "item_id": f"item-{evidence_id}",
                        "kind": "signed-artifact",
                        "digest": "c" * 64,
                        "media_type": "application/json",
                    }
                ],
                "independence_basis": {
                    "excluded_identities": ["operator-a"],
                    "statement": "independent reviewer and environment",
                },
                "result": "PROVEN",
                "gate_effect": "EXTERNAL_EVIDENCE_ADMITTED_NO_RELEASE",
            }
        ).encode("utf-8")


class ExternalEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = self.enterContext(tempfile.TemporaryDirectory())
        self.graph = ExternalEvidenceGraph(Path(self.tempdir))
        self.addCleanup(self.graph.close)
        self.graph.accept_root()

    def admit(self, payload: bytes, *, evidence_id: str = "evidence-1", actor: str = "admitter"):
        return self.graph.service.admit_evidence(
            evidence_id,
            "external-root",
            payload,
            self.graph.verifier.sign(payload),
            actor=actor,
            occurred_at=T2,
        )

    def test_all_four_closed_categories_admit_and_snapshot(self) -> None:
        for index, kind in enumerate(EXTERNAL_EVIDENCE_KINDS):
            payload = self.graph.payload(kind, evidence_id=f"evidence-{index}")
            record = self.admit(payload, evidence_id=f"evidence-{index}")
            self.assertEqual(record.kind, kind)
            self.assertTrue(
                self.graph.service.verify_evidence(record.evidence_id, as_of=T3).ok
            )

        snapshot = self.graph.service.snapshot(as_of=T3)
        self.assertEqual(
            snapshot,
            {kind: "PROVEN" for kind in EXTERNAL_EVIDENCE_KINDS},
        )

    def test_program_composes_one_external_evidence_authority(self) -> None:
        path = Path(self.tempdir) / "program.sqlite3"
        program = StarcomProgram.open(path)
        self.addCleanup(program.close)

        self.assertIs(program.external_evidence.database, program.database)
        self.assertIs(program.external_evidence.ledger, program.ledger)
        self.assertIs(program.external_evidence.continuity, program.continuity)
        self.assertEqual(program.authority("19.external_evidence"), program.external_evidence)
        self.assertEqual(program.verify().truth, ProgramTruth())
        self.assertTrue(program.verify().ok, program.verify().defects)

    def test_exact_replay_is_idempotent_and_actor_conflict_is_closed(self) -> None:
        payload = self.graph.payload()
        first = self.admit(payload)
        event_count = self.graph.database.connection.execute(
            "SELECT COUNT(*) FROM ledger_events WHERE stream_id = ?",
            (first.stream_id,),
        ).fetchone()[0]
        replay = self.admit(payload)
        self.assertEqual(replay, first)
        self.assertEqual(
            self.graph.database.connection.execute(
                "SELECT COUNT(*) FROM ledger_events WHERE stream_id = ?",
                (first.stream_id,),
            ).fetchone()[0],
            event_count,
        )
        with self.assertRaises(ConflictError):
            self.admit(payload, actor="different-admitter")

    def test_whitespace_mutation_and_unknown_key_fail_closed(self) -> None:
        payload = self.graph.payload()
        mutated_payload = payload + b" "
        mutated_signature = self.graph.verifier.sign(payload)
        with self.assertRaises(IntegrityError):
            self.graph.service.admit_evidence(
                "evidence-1",
                "external-root",
                mutated_payload,
                mutated_signature,
                actor="admitter",
                occurred_at=T2,
            )
        value = payload.decode("utf-8")[:-1] + ',"unexpected":true}'
        unknown_payload = value.encode("utf-8")
        unknown_signature = self.graph.verifier.sign(unknown_payload)
        with self.assertRaises(ValidationError):
            self.graph.service.admit_evidence(
                "evidence-2",
                "external-root",
                unknown_payload,
                unknown_signature,
                actor="admitter",
                occurred_at=T2,
            )

    def test_category_claims_expiration_and_identity_are_strict(self) -> None:
        low_census_payload = self.graph.payload(census_count=799)
        with self.assertRaises(ValidationError):
            self.admit(low_census_payload)
        expired_payload = self.graph.payload(
            evidence_id="expired",
            valid_until="2026-08-21T13:00:01.000000Z",
        )
        with self.assertRaises(StateTransitionError):
            self.admit(expired_payload, evidence_id="expired")
        value = self.graph.payload(kind="COMPONENT_ADOPTION").decode("utf-8")
        value = value.replace('"reviewer_identity":"reviewer-b"', '"reviewer_identity":"operator-a"')
        identity_payload = value.encode("utf-8")
        with self.assertRaises(ValidationError):
            self.admit(identity_payload)

    def test_snapshot_excludes_expired_and_missing_categories(self) -> None:
        self.admit(self.graph.payload())
        snapshot = self.graph.service.snapshot(as_of="2026-08-21T15:00:00.000000Z")
        self.assertEqual(snapshot["LIVE_CENSUS_CERTIFICATION"], "NOT_PROVEN")
        self.assertEqual(snapshot["REAL_DEPLOYMENT"], "NOT_PROVEN")

    def test_verifier_detects_stored_payload_tampering_and_key_substitution(self) -> None:
        record = self.admit(self.graph.payload())
        self.graph.database.connection.execute("DROP TRIGGER external_evidence_records_no_update")
        self.graph.database.connection.execute(
            "UPDATE external_evidence_records SET payload = ? WHERE evidence_id = ?",
            (b"tampered", record.evidence_id),
        )
        verification = self.graph.service.verify_evidence(record.evidence_id)
        self.assertFalse(verification.ok)
        self.assertTrue(any("PAYLOAD" in defect for defect in verification.defects))
        other_payload = self.graph.payload(evidence_id="other-key")
        with self.assertRaises(IntegrityError):
            self.graph.service.admit_evidence(
                "other-key",
                "missing-key",
                other_payload,
                b"bad",
                actor="admitter",
                occurred_at=T2,
            )

    def test_public_surface_does_not_authorize_effects(self) -> None:
        names = dir(self.graph.service)
        self.assertTrue({"run", "execute", "deploy", "release", "publish", "promote"}.isdisjoint(names))


if __name__ == "__main__":
    unittest.main()
