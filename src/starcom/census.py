from __future__ import annotations

from dataclasses import dataclass

from .db import Database
from .errors import NotFoundError, StateTransitionError
from .ledger import EventLedger
from .recollection import C2RecollectionService
from .research import ResearchCampaign


@dataclass(frozen=True)
class C2CensusIdentity:
    identity_id: str
    recollection_id: str
    campaign_id: str
    identity_key: str
    source_id: str
    attempt_id: str
    observation_id: str
    evidence_digest: str
    recorded_at: str
    recorded_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C2CensusVerification:
    recollection_id: str
    identity_count: int
    required_target: int
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


@dataclass(frozen=True)
class C2CensusAssessment:
    recollection_id: str
    identity_count: int
    required_target: int
    eligible_for_independent_certification: bool
    defects: tuple[str, ...]


class C2CensusService:
    """RED seam for evidence-bound C2 census identity accounting."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        recollection: C2RecollectionService,
        research: ResearchCampaign,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.recollection = recollection
        self.research = research

    def register_identity(self, *args, **kwargs) -> C2CensusIdentity:  # type: ignore[no-untyped-def]
        raise StateTransitionError("C2 census identity registry is not implemented")

    def get_identity(self, identity_id: str) -> C2CensusIdentity:
        raise NotFoundError("C2 census identity does not exist", {"identity_id": identity_id})

    def verify(self, recollection_id: str) -> C2CensusVerification:
        return C2CensusVerification(
            recollection_id=recollection_id,
            identity_count=0,
            required_target=800,
            defects=("C2_CENSUS_IDENTITY_REGISTRY_NOT_IMPLEMENTED",),
        )

    def assess(self, recollection_id: str) -> C2CensusAssessment:
        verification = self.verify(recollection_id)
        return C2CensusAssessment(
            recollection_id=recollection_id,
            identity_count=verification.identity_count,
            required_target=verification.required_target,
            eligible_for_independent_certification=False,
            defects=verification.defects,
        )
