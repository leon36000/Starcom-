from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from starcom.adoption_execution import C3AdoptionExecutionStatus
from starcom.architecture_candidate import (
    C4ArchitectureCandidateService,
    C4ArchitectureCandidateStatus,
)
from starcom.architecture_input import (
    C4ArchitectureInputSet,
    C4ArchitectureInputVerification,
)
from starcom.canonical import sha256_digest
from starcom.continuity import ContinuityService
from starcom.db import Database
from starcom.errors import (
    AuthorizationError,
    ConflictError,
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

import test_architecture_input as input_fixture


C0 = "2026-08-14T18:00:00.000000Z"
C1 = "2026-08-14T18:01:00.000000Z"
C2 = "2026-08-14T18:02:00.000000Z"
C3 = "2026-08-14T18:03:00.000000Z"
_STAGE_ORDER = ("RESEARCH", "ARTIFACT", "ACTION", "MONITOR")


def _member(record) -> dict[str, object]:  # type: ignore[no-untyped-def]
    return {
        "execution_id": record.execution_id,
        "adoption_id": record.adoption_id,
        "c3_run_id": record.c3_run_id,
        "c3_decision_id": record.c3_decision_id,
        "candidate_artifact_id": record.candidate_artifact_id,
        "candidate_material_sha256": record.candidate_material_sha256,
        "decision_payload_sha256": record.decision_payload_sha256,
        "qualification_head_hash": record.qualification_head_hash,
        "executor_id": record.executor_id,
        "execution_plan_sha256": record.execution_plan_sha256,
        "authorization_decision_id": record.authorization_decision_id,
        "status": record.status.value,
        "execution_receipt_sha256": record.execution_receipt_sha256,
        "rollback_receipt_sha256": record.rollback_receipt_sha256,
        "effect_started": record.effect_started,
        "error": record.error,
        "requested_at": record.requested_at,
        "requested_by": record.requested_by,
        "transition_sequence": record.transition_sequence,
        "terminal_result_digest": input_fixture.FakeExecutionEvidenceSource.terminal_result_digest(
            record
        ),
    }


class FakeC4InputService:
    def __init__(self) -> None:
        source = input_fixture.FakeExecutionEvidenceSource()
        self.members = (
            _member(source.records["execution-no-effect"]),
            _member(source.records["execution-success"]),
        )
        self.record = C4ArchitectureInputSet(
            input_set_id="input-set-c4",
            member_count=2,
            success_count=1,
            negative_evidence_count=1,
            input_set_digest=sha256_digest(list(self.members)),
            author_identities=("author-negative", "author-success"),
            authorization_decision_id="input-authorization",
            frozen_at=C0,
            frozen_by="c4-input-owner",
            ledger_event_id="input-ledger-event",
            ledger_hash="f" * 64,
        )
        self.defects: tuple[str, ...] = ()

    def get_input_set(self, input_set_id: str) -> C4ArchitectureInputSet:
        if input_set_id != self.record.input_set_id:
            raise AssertionError("unexpected input set id")
        return self.record

    def get_members(self, input_set_id: str):  # type: ignore[no-untyped-def]
        self.get_input_set(input_set_id)
        return self.members

    def verify_input_set(
        self,
        input_set_id: str,
    ) -> C4ArchitectureInputVerification:
        self.get_input_set(input_set_id)
        return C4ArchitectureInputVerification(
            input_set_id=input_set_id,
            defects=self.defects,
        )


class C4ArchitectureCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.database = Database(Path(self.tempdir.name) / "c4-candidate.sqlite3")
        self.database.initialize()
        self.ledger = EventLedger(self.database)
        self.trust = TrustPlane(self.database, self.ledger)
        self.continuity = ContinuityService(
            self.database,
            self.ledger,
            self.trust,
        )
        self.inputs = FakeC4InputService()
        self.candidates = C4ArchitectureCandidateService(
            self.database,
            self.ledger,
            self.trust,
            self.continuity,
            self.inputs,  # type: ignore[arg-type]
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

    def valid_manifest(self) -> dict[str, object]:
        success = next(
            member
            for member in self.inputs.members
            if member["status"] == C3AdoptionExecutionStatus.SUCCEEDED.value
        )
        port_ids = (
            "port-action",
            "port-artifact",
            "port-monitor",
            "port-research",
        )
        capability_ids = (
            "cap-action",
            "cap-artifact",
            "cap-monitor",
            "cap-research",
        )
        return {
            "architecture_id": "starcom-v3.2-target",
            "architecture_version": "3.2",
            "title": "STARCOM v3.2 Universal Computer Mission Fabric",
            "authority_adrs": [
                {
                    "adr_id": "adr-authority-boundaries",
                    "title": "Sovereign authority ownership",
                    "decision": "Mission Kernel owns the four sovereign mission ports",
                    "rationale": "One explicit owner prevents framework authority drift",
                    "authority_owner": "MISSION_KERNEL",
                    "affected_port_ids": list(port_ids),
                    "evidence_execution_ids": [
                        "execution-no-effect",
                        "execution-success",
                    ],
                }
            ],
            "ports": [
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
            ],
            "mission_fabric": {
                "RESEARCH": ["port-research"],
                "ARTIFACT": ["port-artifact"],
                "ACTION": ["port-action"],
                "MONITOR": ["port-monitor"],
            },
            "component_bindings": [
                {
                    "binding_id": "binding-success",
                    "execution_id": success["execution_id"],
                    "candidate_artifact_id": success["candidate_artifact_id"],
                    "candidate_material_sha256": success[
                        "candidate_material_sha256"
                    ],
                    "port_ids": list(port_ids),
                    "capability_ids": list(capability_ids),
                }
            ],
            "vertical_benchmark": {
                "benchmark_id": "benchmark-research-artifact-action-monitor",
                "stage_order": list(_STAGE_ORDER),
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
                    "statement": "Every external effect remains default-deny",
                    "verification_method": "TrustPlane mutation suite",
                    "test_ids": ["test-action"],
                    "proof_ids": ["proof-action"],
                }
            ],
            "gate_effect": "C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED",
        }

    def authorize(
        self,
        preparation,
        *,
        actor: str = "c4-architect",
        rule_id: str = "allow-c4-candidate",
        now: str = C1,
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
            occurred_at=C0,
        )
        decision = self.trust.authorize(
            AuthorizationRequest(
                subject=actor,
                action=preparation.action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=preparation.context,
            ),
            now=now,
        )
        self.assertTrue(decision.allowed)
        return decision

    def create(
        self,
        candidate_id: str = "candidate-c4",
        manifest: dict[str, object] | None = None,
        *,
        actor: str = "c4-architect",
    ):
        material = manifest or self.valid_manifest()
        preparation = self.candidates.prepare_create(
            candidate_id,
            input_set_id="input-set-c4",
            manifest=material,
        )
        decision = self.authorize(
            preparation,
            actor=actor,
            rule_id=f"allow-{candidate_id}",
        )
        return self.candidates.create_candidate(
            candidate_id,
            input_set_id="input-set-c4",
            manifest=material,
            authorization_decision_id=decision.decision_id,
            actor=actor,
            occurred_at=C2,
        )

    def test_prepare_candidate_is_deterministic_and_side_effect_free(self) -> None:
        manifest = self.valid_manifest()
        decisions_before = self.table_count("trust_decisions")
        consumptions_before = self.table_count(
            "continuity_authorization_consumptions"
        )

        first = self.candidates.prepare_create(
            "candidate-c4",
            input_set_id="input-set-c4",
            manifest=manifest,
        )
        second = self.candidates.prepare_create(
            "candidate-c4",
            input_set_id="input-set-c4",
            manifest=manifest,
        )

        self.assertEqual(first, second)
        self.assertEqual(first.architecture_id, "starcom-v3.2-target")
        self.assertEqual(first.architecture_version, "3.2")
        self.assertEqual(first.input_set_digest, self.inputs.record.input_set_digest)
        self.assertEqual(first.adr_count, 1)
        self.assertEqual(first.port_count, 4)
        self.assertEqual(first.binding_count, 1)
        self.assertEqual(first.nfr_count, 1)
        self.assertEqual(first.stage_order, _STAGE_ORDER)
        self.assertEqual(first.status, C4ArchitectureCandidateStatus.NOT_REVIEWED)
        self.assertEqual(first.action, "c4.architecture-candidate.create")
        self.assertEqual(
            first.resource,
            "continuity:c4:architecture-candidate:candidate-c4",
        )
        self.assertEqual(
            first.mission_id,
            "c4-architecture:starcom-v3.2-target",
        )
        self.assertEqual(self.table_count("trust_decisions"), decisions_before)
        self.assertEqual(
            self.table_count("continuity_authorization_consumptions"),
            consumptions_before,
        )
        self.assertEqual(self.table_count("c4_architecture_candidates"), 0)

    def test_default_deny_then_valid_candidate_is_verified_and_idempotent(self) -> None:
        manifest = self.valid_manifest()
        preparation = self.candidates.prepare_create(
            "candidate-c4",
            input_set_id="input-set-c4",
            manifest=manifest,
        )
        denied = self.trust.authorize(
            AuthorizationRequest(
                subject="c4-architect",
                action=preparation.action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=preparation.context,
            ),
            now=C1,
        )
        self.assertFalse(denied.allowed)
        with self.assertRaises(AuthorizationError):
            self.candidates.create_candidate(
                "candidate-c4",
                input_set_id="input-set-c4",
                manifest=manifest,
                authorization_decision_id=denied.decision_id,
                actor="c4-architect",
                occurred_at=C2,
            )

        decision = self.authorize(preparation)
        first = self.candidates.create_candidate(
            "candidate-c4",
            input_set_id="input-set-c4",
            manifest=manifest,
            authorization_decision_id=decision.decision_id,
            actor="c4-architect",
            occurred_at=C2,
        )
        replay = self.candidates.create_candidate(
            "candidate-c4",
            input_set_id="input-set-c4",
            manifest=manifest,
            authorization_decision_id=decision.decision_id,
            actor="c4-architect",
            occurred_at=C3,
        )

        self.assertEqual(first, replay)
        self.assertEqual(first.status, C4ArchitectureCandidateStatus.NOT_REVIEWED)
        self.assertEqual(self.candidates.get_manifest(first.candidate_id), manifest)
        verification = self.candidates.verify_candidate(first.candidate_id)
        self.assertTrue(verification.ok, verification.defects)

    def test_manifest_rejects_missing_owner_or_orphan_port(self) -> None:
        missing_owner = self.valid_manifest()
        missing_owner["ports"][0]["owner_authority"] = "OTHER_AUTHORITY"  # type: ignore[index]
        with self.assertRaises(StateTransitionError):
            self.candidates.prepare_create(
                "candidate-missing-owner",
                input_set_id="input-set-c4",
                manifest=missing_owner,
            )

        orphan = self.valid_manifest()
        orphan["authority_adrs"][0]["affected_port_ids"] = [  # type: ignore[index]
            "port-artifact",
            "port-monitor",
            "port-research",
        ]
        with self.assertRaises(StateTransitionError):
            self.candidates.prepare_create(
                "candidate-orphan-port",
                input_set_id="input-set-c4",
                manifest=orphan,
            )

    def test_manifest_rejects_missing_test_proof_mapping_or_mission_stage(self) -> None:
        no_test = self.valid_manifest()
        no_test["ports"][0]["test_ids"] = []  # type: ignore[index]
        with self.assertRaises(ValidationError):
            self.candidates.prepare_create(
                "candidate-no-test",
                input_set_id="input-set-c4",
                manifest=no_test,
            )

        no_stage = self.valid_manifest()
        del no_stage["mission_fabric"]["MONITOR"]  # type: ignore[index]
        with self.assertRaises(ValidationError):
            self.candidates.prepare_create(
                "candidate-no-stage",
                input_set_id="input-set-c4",
                manifest=no_stage,
            )

    def test_manifest_rejects_failed_execution_binding_and_missing_success_binding(self) -> None:
        negative = next(
            member
            for member in self.inputs.members
            if member["status"]
            == C3AdoptionExecutionStatus.FAILED_NO_EFFECT.value
        )
        failed_binding = self.valid_manifest()
        failed_binding["component_bindings"][0]["execution_id"] = negative[  # type: ignore[index]
            "execution_id"
        ]
        failed_binding["component_bindings"][0][  # type: ignore[index]
            "candidate_artifact_id"
        ] = negative["candidate_artifact_id"]
        failed_binding["component_bindings"][0][  # type: ignore[index]
            "candidate_material_sha256"
        ] = negative["candidate_material_sha256"]
        with self.assertRaises(StateTransitionError):
            self.candidates.prepare_create(
                "candidate-failed-binding",
                input_set_id="input-set-c4",
                manifest=failed_binding,
            )

        missing = self.valid_manifest()
        missing["component_bindings"] = []
        with self.assertRaises(StateTransitionError):
            self.candidates.prepare_create(
                "candidate-missing-success",
                input_set_id="input-set-c4",
                manifest=missing,
            )

    def test_manifest_rejects_incomplete_vertical_benchmark(self) -> None:
        incomplete = self.valid_manifest()
        incomplete["vertical_benchmark"]["stage_test_ids"]["ACTION"] = [  # type: ignore[index]
            "test-not-owned-by-action-port"
        ]
        with self.assertRaises(StateTransitionError):
            self.candidates.prepare_create(
                "candidate-incomplete-benchmark",
                input_set_id="input-set-c4",
                manifest=incomplete,
            )

    def test_conflicting_candidate_or_architecture_reuse_is_rejected(self) -> None:
        self.create()
        changed = self.valid_manifest()
        changed["title"] = "Different immutable title"
        changed_preparation = self.candidates.prepare_create(
            "candidate-c4",
            input_set_id="input-set-c4",
            manifest=changed,
        )
        changed_decision = self.authorize(
            changed_preparation,
            rule_id="allow-candidate-changed",
            now=C2,
        )
        with self.assertRaises(ConflictError):
            self.candidates.create_candidate(
                "candidate-c4",
                input_set_id="input-set-c4",
                manifest=changed,
                authorization_decision_id=changed_decision.decision_id,
                actor="c4-architect",
                occurred_at=C3,
            )

        second_preparation = self.candidates.prepare_create(
            "candidate-c4-second",
            input_set_id="input-set-c4",
            manifest=self.valid_manifest(),
        )
        second_decision = self.authorize(
            second_preparation,
            rule_id="allow-candidate-second",
            now=C2,
        )
        with self.assertRaises(ConflictError):
            self.candidates.create_candidate(
                "candidate-c4-second",
                input_set_id="input-set-c4",
                manifest=self.valid_manifest(),
                authorization_decision_id=second_decision.decision_id,
                actor="c4-architect",
                occurred_at=C3,
            )

    def test_candidate_verifier_detects_manifest_consumption_and_ledger_tampering(self) -> None:
        record = self.create()
        self.database.connection.execute(
            "DROP TRIGGER c4_architecture_candidates_no_update"
        )
        self.database.connection.execute(
            """
            UPDATE c4_architecture_candidates SET manifest_sha256 = ?
            WHERE candidate_id = ?
            """,
            ("0" * 64, record.candidate_id),
        )
        self.database.connection.execute(
            "DROP TRIGGER continuity_authorization_consumptions_no_update"
        )
        self.database.connection.execute(
            """
            UPDATE continuity_authorization_consumptions SET operation_id = ?
            WHERE decision_id = ?
            """,
            ("different-candidate", record.authorization_decision_id),
        )
        self.database.connection.execute("DROP TRIGGER ledger_events_no_update")
        self.database.connection.execute(
            "UPDATE ledger_events SET actor = ? WHERE event_id = ?",
            ("intruder", record.ledger_event_id),
        )

        verification = self.candidates.verify_candidate(record.candidate_id)

        self.assertFalse(verification.ok)
        self.assertIn(
            "C4_CANDIDATE_MANIFEST_SHA256_MISMATCH",
            verification.defects,
        )
        self.assertIn(
            "C4_CANDIDATE_AUTHORIZATION_CONSUMPTION_MISMATCH",
            verification.defects,
        )
        self.assertIn("C4_CANDIDATE_LEDGER_ACTOR_MISMATCH", verification.defects)
        self.assertTrue(
            any(
                defect.startswith("C4_CANDIDATE_LEDGER_CHAIN:")
                for defect in verification.defects
            ),
            verification.defects,
        )


if __name__ == "__main__":
    unittest.main()
