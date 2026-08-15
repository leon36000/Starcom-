from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from .architecture_candidate import C4ArchitectureCandidateService
from .architecture_input import C4ArchitectureInputService
from .continuity import ContinuityService
from .db import Database
from .errors import NotFoundError, StateTransitionError
from .ledger import EventLedger
from .trust import TrustPlane


class C4ArchitectureReviewVerdict(str, Enum):
    ACCEPTED = "C4_ARCHITECTURE_ACCEPTED"
    REJECTED = "C4_ARCHITECTURE_REJECTED"
    REWORK_REQUIRED = "C4_ARCHITECTURE_REWORK_REQUIRED"


class C4ArchitectureVerificationResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"


class C4ArchitectureFindingSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class C4ArchitectureFindingCode(str, Enum):
    AUTHORITY_ADR_GAP = "AUTHORITY_ADR_GAP"
    PORT_OWNERSHIP_GAP = "PORT_OWNERSHIP_GAP"
    PORT_CONTRACT_GAP = "PORT_CONTRACT_GAP"
    MISSION_FABRIC_GAP = "MISSION_FABRIC_GAP"
    COMPONENT_BINDING_GAP = "COMPONENT_BINDING_GAP"
    VERTICAL_BENCHMARK_GAP = "VERTICAL_BENCHMARK_GAP"
    NON_FUNCTIONAL_REQUIREMENT_GAP = "NON_FUNCTIONAL_REQUIREMENT_GAP"
    SECURITY_BOUNDARY_GAP = "SECURITY_BOUNDARY_GAP"
    EVIDENCE_BINDING_GAP = "EVIDENCE_BINDING_GAP"


@dataclass(frozen=True)
class C4ArchitectureReviewerRootPreparation:
    key_id: str
    public_key_fingerprint_sha256: str
    algorithm: str
    purpose: str
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]


@dataclass(frozen=True)
class C4ArchitectureReviewerRoot:
    key_id: str
    public_key_fingerprint_sha256: str
    accepted_at: str
    accepted_by: str
    authorization_decision_id: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C4ArchitectureReviewerRootVerification:
    key_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


@dataclass(frozen=True)
class C4ArchitectureReviewFinding:
    finding_id: str
    severity: C4ArchitectureFindingSeverity
    code: C4ArchitectureFindingCode
    message: str
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class C4ArchitectureReviewRecord:
    review_id: str
    candidate_id: str
    architecture_id: str
    architecture_version: str
    input_set_id: str
    manifest_sha256: str
    input_set_digest: str
    key_id: str
    payload_sha256: str
    signature_sha256: str
    reviewer_identity: str
    reviewer_environment: str
    independence_basis: str
    reviewed_at_utc: str
    structural_verification_result: C4ArchitectureVerificationResult
    security_verification_result: C4ArchitectureVerificationResult
    evidence_binding_result: C4ArchitectureVerificationResult
    verdict: C4ArchitectureReviewVerdict
    finding_count: int
    finding_set_digest: str
    gate_effect: str
    admitted_at: str
    admitted_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C4ArchitectureReviewVerification:
    review_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C4ArchitectureReviewService:
    """RED seam for exact-byte independent C4 architecture review."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        trust: TrustPlane,
        continuity: ContinuityService,
        inputs: C4ArchitectureInputService,
        candidates: C4ArchitectureCandidateService,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self.continuity = continuity
        self.inputs = inputs
        self.candidates = candidates

    def prepare_reviewer_root(
        self,
        key_id: str,
        public_key: bytes,
    ) -> C4ArchitectureReviewerRootPreparation:
        raise StateTransitionError(
            "C4 architecture review authority is not implemented"
        )

    def accept_reviewer_root(
        self,
        key_id: str,
        public_key: bytes,
        *,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> C4ArchitectureReviewerRoot:
        raise StateTransitionError(
            "C4 architecture review authority is not implemented"
        )

    def get_reviewer_root(self, key_id: str) -> C4ArchitectureReviewerRoot:
        raise NotFoundError(
            "C4 architecture reviewer root does not exist",
            {"key_id": key_id},
        )

    def verify_reviewer_root(
        self,
        key_id: str,
    ) -> C4ArchitectureReviewerRootVerification:
        return C4ArchitectureReviewerRootVerification(
            key_id=key_id,
            defects=("C4_ARCHITECTURE_REVIEW_AUTHORITY_NOT_IMPLEMENTED",),
        )

    def admit_review(
        self,
        candidate_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        *,
        actor: str,
        occurred_at: str | None = None,
    ) -> C4ArchitectureReviewRecord:
        raise StateTransitionError(
            "C4 architecture review authority is not implemented"
        )

    def get_review(self, review_id: str) -> C4ArchitectureReviewRecord:
        raise NotFoundError(
            "C4 architecture review does not exist",
            {"review_id": review_id},
        )

    def get_findings(
        self,
        review_id: str,
    ) -> tuple[C4ArchitectureReviewFinding, ...]:
        raise NotFoundError(
            "C4 architecture review does not exist",
            {"review_id": review_id},
        )

    def verify_review(
        self,
        review_id: str,
    ) -> C4ArchitectureReviewVerification:
        return C4ArchitectureReviewVerification(
            review_id=review_id,
            defects=("C4_ARCHITECTURE_REVIEW_AUTHORITY_NOT_IMPLEMENTED",),
        )
