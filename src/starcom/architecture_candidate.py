from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from .architecture_input import C4ArchitectureInputService
from .continuity import ContinuityService
from .db import Database
from .errors import NotFoundError, StateTransitionError
from .ledger import EventLedger
from .trust import TrustPlane


class C4ArchitectureCandidateStatus(str, Enum):
    NOT_REVIEWED = "C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED"


@dataclass(frozen=True)
class C4ArchitectureCandidatePreparation:
    candidate_id: str
    architecture_id: str
    architecture_version: str
    input_set_id: str
    input_set_digest: str
    manifest_sha256: str
    adr_count: int
    port_count: int
    binding_count: int
    nfr_count: int
    stage_order: tuple[str, ...]
    status: C4ArchitectureCandidateStatus
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]


@dataclass(frozen=True)
class C4ArchitectureCandidate:
    candidate_id: str
    architecture_id: str
    architecture_version: str
    input_set_id: str
    input_set_digest: str
    manifest_sha256: str
    status: C4ArchitectureCandidateStatus
    authorization_decision_id: str
    created_at: str
    created_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C4ArchitectureCandidateVerification:
    candidate_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C4ArchitectureCandidateService:
    """RED seam for immutable unreviewed STARCOM v3.2 candidates."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        trust: TrustPlane,
        continuity: ContinuityService,
        inputs: C4ArchitectureInputService,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self.continuity = continuity
        self.inputs = inputs

    def prepare_create(
        self,
        candidate_id: str,
        *,
        input_set_id: str,
        manifest: Mapping[str, Any],
    ) -> C4ArchitectureCandidatePreparation:
        raise StateTransitionError("C4 architecture foundation is not implemented")

    def create_candidate(
        self,
        candidate_id: str,
        *,
        input_set_id: str,
        manifest: Mapping[str, Any],
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> C4ArchitectureCandidate:
        raise StateTransitionError("C4 architecture foundation is not implemented")

    def get_candidate(self, candidate_id: str) -> C4ArchitectureCandidate:
        raise NotFoundError(
            "C4 architecture candidate does not exist",
            {"candidate_id": candidate_id},
        )

    def get_manifest(self, candidate_id: str) -> Mapping[str, Any]:
        raise NotFoundError(
            "C4 architecture candidate does not exist",
            {"candidate_id": candidate_id},
        )

    def verify_candidate(
        self,
        candidate_id: str,
    ) -> C4ArchitectureCandidateVerification:
        return C4ArchitectureCandidateVerification(
            candidate_id=candidate_id,
            defects=("C4_ARCHITECTURE_FOUNDATION_NOT_IMPLEMENTED",),
        )
