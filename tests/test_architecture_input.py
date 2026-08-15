from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from starcom.adoption_execution import (
    C3AdoptionExecutionRecord,
    C3AdoptionExecutionService,
    C3AdoptionExecutionStatus,
    C3AdoptionExecutionVerification,
)
from starcom.architecture_input import C4ArchitectureInputService
from starcom.continuity import ContinuityService
from starcom.db import Database
from starcom.errors import (
    AuthorizationError,
    ConflictError,
    IntegrityError,
    NotFoundError,
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


I0 = "2026-08-14T17:00:00.000000Z"
I1 = "2026-08-14T17:01:00.000000Z"
I2 = "2026-08-14T17:02:00.000000Z"
I3 = "2026-08-14T17:03:00.000000Z"


def _record(
    execution_id: str,
    *,
    status: C3AdoptionExecutionStatus,
    requested_by: str,
    marker: str,
) -> C3AdoptionExecutionRecord:
    terminal = status.terminal
    execution_receipt = (
        {"execution_id": execution_id, "status": status.value}
        if terminal
        else None
    )
    execution_receipt_sha256 = marker * 64 if terminal else None
    rollback = status in {
        C3AdoptionExecutionStatus.FAILED_ROLLED_BACK,
        C3AdoptionExecutionStatus.ROLLBACK_FAILED,
    }
    return C3AdoptionExecutionRecord(
        execution_id=execution_id,
        adoption_id=f"adoption-{execution_id}",
        c3_run_id=f"c3-{execution_id}",
        c3_decision_id=f"decision-{execution_id}",
        candidate_artifact_id=f"candidate-{execution_id}",
        candidate_material_sha256=marker * 64,
        decision_payload_sha256=(chr(ord(marker) + 1)) * 64,
        qualification_head_hash=(chr(ord(marker) + 2)) * 64,
        rollback_plan_sha256=(chr(ord(marker) + 3)) * 64,
        executor_id=f"executor-{execution_id}",
        execution_plan={"component_ref": execution_id},
        execution_plan_sha256=(chr(ord(marker) + 4)) * 64,
        authorization_decision_id=f"authorization-{execution_id}",
        outbox_effect_id=f"effect-{execution_id}",
        idempotency_key=f"idempotency-{execution_id}",
        status=status,
        requested_at=I0,
        requested_by=requested_by,
        transition_sequence=3 if terminal else 2,
        execution_receipt=execution_receipt,
        execution_receipt_sha256=execution_receipt_sha256,
        rollback_receipt=(
            {"execution_id": execution_id, "restored": status is C3AdoptionExecutionStatus.FAILED_ROLLED_BACK}
            if rollback
            else None
        ),
        rollback_receipt_sha256=(chr(ord(marker) + 5)) * 64 if rollback else None,
        effect_started=status
        in {
            C3AdoptionExecutionStatus.SUCCEEDED,
            C3AdoptionExecutionStatus.FAILED_ROLLED_BACK,
            C3AdoptionExecutionStatus.ROLLBACK_FAILED,
        },
        error=(
            None
            if status is C3AdoptionExecutionStatus.SUCCEEDED
            else "deterministic fixture failure"
        ),
    )


class FakeExecutionEvidenceSource:
    def __init__(self) -> None:
        self.records = {
            "execution-success": _record(
                "execution-success",
                status=C3AdoptionExecutionStatus.SUCCEEDED,
                requested_by="author-success",
                marker="1",
            ),
            "execution-no-effect": _record(
                "execution-no-effect",
                status=C3AdoptionExecutionStatus.FAILED_NO_EFFECT,
                requested_by="author-negative",
                marker="2",
            ),
            "execution-rolled-back": _record(
                "execution-rolled-back",
                status=C3AdoptionExecutionStatus.FAILED_ROLLED_BACK,
                requested_by="author-negative",
                marker="3",
            ),
            "execution-rollback-failed": _record(
                "execution-rollback-failed",
                status=C3AdoptionExecutionStatus.ROLLBACK_FAILED,
                requested_by="author-unsafe",
                marker="4",
            ),
            "execution-running": _record(
                "execution-running",
                status=C3AdoptionExecutionStatus.RUNNING,
                requested_by="author-running",
                marker="5",
            ),
        }
        self.defects: dict[str, tuple[str, ...]] = {}

    def get_execution(self, execution_id: str) -> C3AdoptionExecutionRecord:
        try:
            return self.records[execution_id]
        except KeyError as exc:
            raise NotFoundError(
                "C3 adoption execution does not exist",
                {"execution_id": execution_id},
            ) from exc

    def verify_execution(
        self,
        execution_id: str,
    ) -> C3AdoptionExecutionVerification:
        self.get_execution(execution_id)
        return C3AdoptionExecutionVerification(
            execution_id=execution_id,
            defects=self.defects.get(execution_id, ()),
        )

    @staticmethod
    def terminal_result_digest(record: C3AdoptionExecutionRecord) -> str:
        return C3AdoptionExecutionService.terminal_result_digest(record)


class C4ArchitectureInputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.database = Database(Path(self.tempdir.name) / "c4-input.sqlite3")
        self.database.initialize()
        self.ledger = EventLedger(self.database)
        self.trust = TrustPlane(self.database, self.ledger)
        self.continuity = ContinuityService(
            self.database,
            self.ledger,
            self.trust,
        )
        self.executions = FakeExecutionEvidenceSource()
        self.inputs = C4ArchitectureInputService(
            self.database,
            self.ledger,
            self.trust,
            self.continuity,
            self.executions,
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

    def authorize(
        self,
        preparation,
        *,
        actor: str = "c4-input-owner",
        rule_id: str = "allow-c4-input",
        now: str = I1,
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
            occurred_at=I0,
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

    def freeze(
        self,
        input_set_id: str = "input-set-a",
        execution_ids: tuple[str, ...] = ("execution-success",),
        *,
        actor: str = "c4-input-owner",
    ):
        preparation = self.inputs.prepare_freeze(input_set_id, execution_ids)
        decision = self.authorize(
            preparation,
            actor=actor,
            rule_id=f"allow-{input_set_id}",
        )
        return self.inputs.freeze(
            input_set_id,
            execution_ids,
            authorization_decision_id=decision.decision_id,
            actor=actor,
            occurred_at=I2,
        )

    def test_prepare_freeze_is_deterministic_and_side_effect_free(self) -> None:
        execution_ids = ("execution-no-effect", "execution-success")
        decisions_before = self.table_count("trust_decisions")
        consumptions_before = self.table_count(
            "continuity_authorization_consumptions"
        )

        first = self.inputs.prepare_freeze("input-set-a", execution_ids)
        second = self.inputs.prepare_freeze("input-set-a", execution_ids)

        self.assertEqual(first, second)
        self.assertEqual(first.execution_ids, execution_ids)
        self.assertEqual(first.member_count, 2)
        self.assertEqual(first.success_count, 1)
        self.assertEqual(first.negative_evidence_count, 1)
        self.assertEqual(
            first.author_identities,
            ("author-negative", "author-success"),
        )
        self.assertEqual(first.action, "c4.architecture-input.freeze")
        self.assertEqual(
            first.resource,
            "continuity:c4:architecture-input:input-set-a",
        )
        self.assertEqual(first.mission_id, "c4-architecture:input-set-a")
        self.assertEqual(self.table_count("trust_decisions"), decisions_before)
        self.assertEqual(
            self.table_count("continuity_authorization_consumptions"),
            consumptions_before,
        )
        self.assertEqual(self.table_count("c4_architecture_input_sets"), 0)

    def test_default_deny_then_exact_freeze_is_verified_and_idempotent(self) -> None:
        execution_ids = ("execution-success",)
        preparation = self.inputs.prepare_freeze("input-set-a", execution_ids)
        denied = self.trust.authorize(
            AuthorizationRequest(
                subject="c4-input-owner",
                action=preparation.action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=preparation.context,
            ),
            now=I1,
        )
        self.assertFalse(denied.allowed)
        with self.assertRaises(AuthorizationError):
            self.inputs.freeze(
                "input-set-a",
                execution_ids,
                authorization_decision_id=denied.decision_id,
                actor="c4-input-owner",
                occurred_at=I2,
            )

        decision = self.authorize(preparation)
        first = self.inputs.freeze(
            "input-set-a",
            execution_ids,
            authorization_decision_id=decision.decision_id,
            actor="c4-input-owner",
            occurred_at=I2,
        )
        replay = self.inputs.freeze(
            "input-set-a",
            execution_ids,
            authorization_decision_id=decision.decision_id,
            actor="c4-input-owner",
            occurred_at=I3,
        )

        self.assertEqual(first, replay)
        self.assertEqual(first.member_count, 1)
        self.assertEqual(first.success_count, 1)
        self.assertEqual(len(self.inputs.get_members("input-set-a")), 1)
        verification = self.inputs.verify_input_set("input-set-a")
        self.assertTrue(verification.ok, verification.defects)

    def test_freeze_accepts_success_plus_clean_negative_evidence(self) -> None:
        record = self.freeze(
            execution_ids=(
                "execution-no-effect",
                "execution-rolled-back",
                "execution-success",
            )
        )

        self.assertEqual(record.member_count, 3)
        self.assertEqual(record.success_count, 1)
        self.assertEqual(record.negative_evidence_count, 2)
        self.assertEqual(
            record.author_identities,
            ("author-negative", "author-success"),
        )
        self.assertTrue(self.inputs.verify_input_set(record.input_set_id).ok)

    def test_freeze_rejects_unsorted_duplicate_nonterminal_dirty_and_rollback_failed_inputs(self) -> None:
        with self.assertRaises(ValidationError):
            self.inputs.prepare_freeze(
                "input-unsorted",
                ("execution-success", "execution-no-effect"),
            )
        with self.assertRaises(ValidationError):
            self.inputs.prepare_freeze(
                "input-duplicate",
                ("execution-success", "execution-success"),
            )
        with self.assertRaises(StateTransitionError):
            self.inputs.prepare_freeze(
                "input-running",
                ("execution-running", "execution-success"),
            )
        self.executions.defects["execution-success"] = (
            "C3_EXECUTION_LEDGER_CHAIN:HASH_MISMATCH",
        )
        with self.assertRaises(IntegrityError):
            self.inputs.prepare_freeze(
                "input-dirty",
                ("execution-success",),
            )
        self.executions.defects.clear()
        with self.assertRaises(StateTransitionError):
            self.inputs.prepare_freeze(
                "input-unsafe",
                ("execution-rollback-failed", "execution-success"),
            )

    def test_freeze_requires_at_least_one_success(self) -> None:
        with self.assertRaisesRegex(
            StateTransitionError,
            "at least one successful C3 execution",
        ):
            self.inputs.prepare_freeze(
                "input-no-success",
                ("execution-no-effect", "execution-rolled-back"),
            )

    def test_conflicting_input_replay_is_rejected(self) -> None:
        self.freeze()
        changed_ids = ("execution-no-effect", "execution-success")
        changed_preparation = self.inputs.prepare_freeze(
            "input-set-a",
            changed_ids,
        )
        changed_decision = self.authorize(
            changed_preparation,
            rule_id="allow-input-set-a-changed",
            now=I2,
        )

        with self.assertRaises(ConflictError):
            self.inputs.freeze(
                "input-set-a",
                changed_ids,
                authorization_decision_id=changed_decision.decision_id,
                actor="c4-input-owner",
                occurred_at=I3,
            )

    def test_input_verifier_detects_member_digest_tampering(self) -> None:
        record = self.freeze()
        self.database.connection.execute(
            "DROP TRIGGER c4_architecture_input_members_no_update"
        )
        self.database.connection.execute(
            """
            UPDATE c4_architecture_input_members SET member_sha256 = ?
            WHERE input_set_id = ? AND ordinal = 0
            """,
            ("0" * 64, record.input_set_id),
        )

        verification = self.inputs.verify_input_set(record.input_set_id)

        self.assertFalse(verification.ok)
        self.assertIn("C4_INPUT_MEMBER_SHA256_MISMATCH:0", verification.defects)

    def test_input_verifier_detects_consumption_and_ledger_tampering(self) -> None:
        record = self.freeze()
        self.database.connection.execute(
            "DROP TRIGGER continuity_authorization_consumptions_no_update"
        )
        self.database.connection.execute(
            """
            UPDATE continuity_authorization_consumptions SET operation_id = ?
            WHERE decision_id = ?
            """,
            ("different-input", record.authorization_decision_id),
        )
        self.database.connection.execute("DROP TRIGGER ledger_events_no_update")
        self.database.connection.execute(
            "UPDATE ledger_events SET actor = ? WHERE event_id = ?",
            ("intruder", record.ledger_event_id),
        )

        verification = self.inputs.verify_input_set(record.input_set_id)

        self.assertFalse(verification.ok)
        self.assertIn(
            "C4_INPUT_AUTHORIZATION_CONSUMPTION_MISMATCH",
            verification.defects,
        )
        self.assertIn("C4_INPUT_LEDGER_ACTOR_MISMATCH", verification.defects)
        self.assertTrue(
            any(
                defect.startswith("C4_INPUT_LEDGER_CHAIN:")
                for defect in verification.defects
            ),
            verification.defects,
        )


if __name__ == "__main__":
    unittest.main()
