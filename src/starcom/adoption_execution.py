from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Protocol

from .adoption import C3AdoptionService
from .continuity import ContinuityService
from .db import Database
from .durable import DurableOutbox
from .errors import NotFoundError, StateTransitionError
from .ledger import EventLedger
from .trust import TrustPlane


class C3AdoptionExecutionStatus(str, Enum):
    REQUESTED_NOT_EXECUTED = "C3_ADOPTION_EXECUTION_REQUESTED_NOT_EXECUTED"
    RUNNING = "C3_ADOPTION_EXECUTION_RUNNING"
    SUCCEEDED = "C3_ADOPTION_EXECUTION_SUCCEEDED"
    FAILED_NO_EFFECT = "C3_ADOPTION_EXECUTION_FAILED_NO_EFFECT"
    FAILED_ROLLED_BACK = "C3_ADOPTION_EXECUTION_FAILED_ROLLED_BACK"
    ROLLBACK_FAILED = "C3_ADOPTION_EXECUTION_ROLLBACK_FAILED"


@dataclass(frozen=True)
class C3AdoptionExecutionPreparation:
    execution_id: str
    adoption_id: str
    c3_run_id: str
    c3_decision_id: str
    candidate_artifact_id: str
    candidate_material_sha256: str
    decision_payload_sha256: str
    qualification_head_hash: str
    rollback_plan_sha256: str
    executor_id: str
    execution_plan: Mapping[str, Any]
    execution_plan_json: str
    execution_plan_sha256: str
    outbox_effect_id: str
    idempotency_key: str
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]


@dataclass(frozen=True)
class C3AdoptionExecutionRecord:
    execution_id: str
    adoption_id: str
    c3_run_id: str
    c3_decision_id: str
    candidate_artifact_id: str
    candidate_material_sha256: str
    decision_payload_sha256: str
    qualification_head_hash: str
    rollback_plan_sha256: str
    executor_id: str
    execution_plan: Mapping[str, Any]
    execution_plan_sha256: str
    authorization_decision_id: str
    outbox_effect_id: str
    idempotency_key: str
    status: C3AdoptionExecutionStatus
    requested_at: str
    requested_by: str
    transition_sequence: int
    execution_receipt: Mapping[str, Any] | None
    execution_receipt_sha256: str | None
    rollback_receipt: Mapping[str, Any] | None
    rollback_receipt_sha256: str | None
    effect_started: bool
    error: str | None


@dataclass(frozen=True)
class C3ExecutorResult:
    succeeded: bool
    effect_started: bool
    pre_state_digest: str
    post_state_digest: str | None
    receipt: Mapping[str, Any]
    error: str | None = None


@dataclass(frozen=True)
class C3RollbackResult:
    succeeded: bool
    restored_state_digest: str | None
    receipt: Mapping[str, Any]
    error: str | None = None


@dataclass(frozen=True)
class C3AdoptionExecutionVerification:
    execution_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C3AdoptionExecutor(Protocol):
    executor_id: str

    def validate(self, request: C3AdoptionExecutionRecord) -> None: ...

    def execute(self, request: C3AdoptionExecutionRecord) -> C3ExecutorResult: ...

    def rollback(
        self,
        request: C3AdoptionExecutionRecord,
        execution_result: C3ExecutorResult | None,
        reason: str,
    ) -> C3RollbackResult: ...


class DisabledC3AdoptionExecutor:
    executor_id = "disabled"

    def validate(self, request: C3AdoptionExecutionRecord) -> None:
        raise StateTransitionError("C3 adoption execution is disabled")

    def execute(self, request: C3AdoptionExecutionRecord) -> C3ExecutorResult:
        raise StateTransitionError("C3 adoption execution is disabled")

    def rollback(
        self,
        request: C3AdoptionExecutionRecord,
        execution_result: C3ExecutorResult | None,
        reason: str,
    ) -> C3RollbackResult:
        return C3RollbackResult(
            succeeded=False,
            restored_state_digest=None,
            receipt={"executor_id": self.executor_id, "reason": reason},
            error="C3 adoption execution is disabled",
        )


class C3AdoptionExecutionService:
    """RED seam for separately authorized durable adoption execution."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        trust: TrustPlane,
        continuity: ContinuityService,
        adoption: C3AdoptionService,
        outbox: DurableOutbox,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self.continuity = continuity
        self.adoption = adoption
        self.outbox = outbox

    def prepare(
        self,
        execution_id: str,
        *,
        adoption_id: str,
        executor_id: str,
        execution_plan: Mapping[str, Any],
    ) -> C3AdoptionExecutionPreparation:
        raise StateTransitionError("C3 adoption execution is not implemented")

    def request_execution(self, *args: Any, **kwargs: Any) -> C3AdoptionExecutionRecord:
        raise StateTransitionError("C3 adoption execution is not implemented")

    def get_execution(self, execution_id: str) -> C3AdoptionExecutionRecord:
        raise NotFoundError(
            "C3 adoption execution does not exist",
            {"execution_id": execution_id},
        )

    def verify_execution(self, execution_id: str) -> C3AdoptionExecutionVerification:
        return C3AdoptionExecutionVerification(
            execution_id=execution_id,
            defects=("C3_ADOPTION_EXECUTION_NOT_IMPLEMENTED",),
        )


class C3AdoptionExecutionWorker:
    """RED seam for durable execution processing."""

    def __init__(
        self,
        service: C3AdoptionExecutionService,
        outbox: DurableOutbox,
        executor: C3AdoptionExecutor | None = None,
    ) -> None:
        self.service = service
        self.outbox = outbox
        self.executor = executor or DisabledC3AdoptionExecutor()

    def process_next(self, *args: Any, **kwargs: Any) -> C3AdoptionExecutionRecord | None:
        raise StateTransitionError("C3 adoption execution worker is not implemented")
