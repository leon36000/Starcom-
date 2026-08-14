from __future__ import annotations

from dataclasses import dataclass

from .continuity import ContinuityService
from .db import Database
from .errors import NotFoundError, StateTransitionError
from .ledger import EventLedger
from .research import ResearchCampaign


@dataclass(frozen=True)
class C2RecollectionRecord:
    recollection_id: str
    incident_id: str
    campaign_id: str
    minimum_identity_target: int
    started_at: str
    started_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C2RecollectionVerification:
    recollection_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C2RecollectionService:
    """RED contract seam for the C1-gated Task 5 recollection coordinator."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        continuity: ContinuityService,
        research: ResearchCampaign,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.continuity = continuity
        self.research = research

    def start(
        self,
        recollection_id: str,
        *,
        incident_id: str,
        campaign_id: str,
        minimum_identity_target: int,
        actor: str,
        occurred_at: str | None = None,
    ) -> C2RecollectionRecord:
        raise StateTransitionError("C2 recollection gate is not implemented")

    def get(self, recollection_id: str) -> C2RecollectionRecord:
        raise NotFoundError("C2 recollection does not exist", {"recollection_id": recollection_id})

    def verify(self, recollection_id: str) -> C2RecollectionVerification:
        return C2RecollectionVerification(
            recollection_id=recollection_id,
            defects=("C2_RECOLLECTION_GATE_NOT_IMPLEMENTED",),
        )
