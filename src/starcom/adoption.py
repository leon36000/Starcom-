from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from .continuity import ContinuityService
from .db import Database
from .errors import NotFoundError, StateTransitionError
from .ledger import EventLedger
from .qualification import QualificationLab
from .qualification_decision import C3DecisionService
from .trust import TrustPlane


class C3AdoptionStatus(str, Enum):
    AUTHORIZED_NOT_EXECUTED = "C3_ADOPTION_AUTHORIZED_NOT_EXECUTED"


@dataclass(frozen=True)
class C3AdoptionPreparation:
    c3_run_id: str
    c3_decision_id: str
    candidate_artifact_id: str
    candidate_material_sha256: str
    decision_payload_sha256: str
    qualification_head_hash: str
    rollback_plan: Mapping[str, Any]
    rollback_plan_json: str
    rollback_plan_sha256: str
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]


@dataclass(frozen=True)
class C3AdoptionRecord:
    adoption_id: str
    c3_run_id: str
    c3_decision_id: str
    candidate_artifact_id: str
    candidate_material_sha256: str
    decision_payload_sha256: str
    qualification_head_hash: str
    authorization_decision_id: str
    rollback_plan: Mapping[str, Any]
    rollback_plan_sha256: str
    status: C3AdoptionStatus
    authorized_at: str
    authorized_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C3AdoptionVerification:
    adoption_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C3AdoptionService:
    """RED seam for explicit C3 adoption authorization without execution."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        trust: TrustPlane,
        continuity: ContinuityService,
        decisions: C3DecisionService,
        qualification: QualificationLab,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self.continuity = continuity
        self.decisions = decisions
        self.qualification = qualification

    def prepare(
        self,
        c3_run_id: str,
        rollback_plan: Mapping[str, Any],
    ) -> C3AdoptionPreparation:
        raise StateTransitionError("C3 adoption authorization is not implemented")

    def authorize_adoption(
        self,
        adoption_id: str,
        *,
        c3_run_id: str,
        authorization_decision_id: str,
        rollback_plan: Mapping[str, Any],
        actor: str,
        occurred_at: str | None = None,
    ) -> C3AdoptionRecord:
        raise StateTransitionError("C3 adoption authorization is not implemented")

    def get_adoption(self, adoption_id: str) -> C3AdoptionRecord:
        raise NotFoundError(
            "C3 adoption authorization does not exist",
            {"adoption_id": adoption_id},
        )

    def verify_adoption(self, adoption_id: str) -> C3AdoptionVerification:
        return C3AdoptionVerification(
            adoption_id=adoption_id,
            defects=("C3_ADOPTION_AUTHORITY_NOT_IMPLEMENTED",),
        )
