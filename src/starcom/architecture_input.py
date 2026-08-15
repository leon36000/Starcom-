from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence

from .adoption_execution import (
    C3AdoptionExecutionRecord,
    C3AdoptionExecutionVerification,
)
from .continuity import ContinuityService
from .db import Database
from .errors import NotFoundError, StateTransitionError
from .ledger import EventLedger
from .trust import TrustPlane


class C4ExecutionEvidenceSource(Protocol):
    def get_execution(self, execution_id: str) -> C3AdoptionExecutionRecord: ...

    def verify_execution(
        self,
        execution_id: str,
    ) -> C3AdoptionExecutionVerification: ...

    @staticmethod
    def terminal_result_digest(record: C3AdoptionExecutionRecord) -> str: ...


@dataclass(frozen=True)
class C4ArchitectureInputPreparation:
    input_set_id: str
    execution_ids: tuple[str, ...]
    member_count: int
    success_count: int
    negative_evidence_count: int
    input_set_digest: str
    author_identities: tuple[str, ...]
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]


@dataclass(frozen=True)
class C4ArchitectureInputSet:
    input_set_id: str
    member_count: int
    success_count: int
    negative_evidence_count: int
    input_set_digest: str
    author_identities: tuple[str, ...]
    authorization_decision_id: str
    frozen_at: str
    frozen_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C4ArchitectureInputVerification:
    input_set_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C4ArchitectureInputService:
    """RED seam for immutable C4 architecture input sets."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        trust: TrustPlane,
        continuity: ContinuityService,
        executions: C4ExecutionEvidenceSource,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self.continuity = continuity
        self.executions = executions

    def prepare_freeze(
        self,
        input_set_id: str,
        execution_ids: Sequence[str],
    ) -> C4ArchitectureInputPreparation:
        raise StateTransitionError("C4 architecture foundation is not implemented")

    def freeze(
        self,
        input_set_id: str,
        execution_ids: Sequence[str],
        *,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> C4ArchitectureInputSet:
        raise StateTransitionError("C4 architecture foundation is not implemented")

    def get_input_set(self, input_set_id: str) -> C4ArchitectureInputSet:
        raise NotFoundError(
            "C4 architecture input set does not exist",
            {"input_set_id": input_set_id},
        )

    def get_members(
        self,
        input_set_id: str,
    ) -> tuple[Mapping[str, Any], ...]:
        raise NotFoundError(
            "C4 architecture input set does not exist",
            {"input_set_id": input_set_id},
        )

    def verify_input_set(
        self,
        input_set_id: str,
    ) -> C4ArchitectureInputVerification:
        return C4ArchitectureInputVerification(
            input_set_id=input_set_id,
            defects=("C4_ARCHITECTURE_FOUNDATION_NOT_IMPLEMENTED",),
        )
