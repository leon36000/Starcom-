from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import sqlite3
from typing import Any, Mapping

from .certification import C2CertificationService
from .continuity import ContinuityService
from .db import Database
from .errors import NotFoundError, StateTransitionError
from .ledger import EventLedger
from .qualification import QualificationLab
from .qualification_gate import C3QualificationGate


class C3DecisionVerdict(str, Enum):
    CANDIDATE_SELECTED = "C3_CANDIDATE_SELECTED"
    NO_SELECTION = "C3_NO_SELECTION"


@dataclass(frozen=True)
class C3DecisionSnapshot:
    c3_run_id: str
    qualification_run_id: str
    certificate_id: str
    qualification_head_hash: str
    candidate_count: int
    evaluation_count: int
    candidate_set_digest: str
    evaluation_set_digest: str
    latest_evidence_at: str | None
    candidates: tuple[Mapping[str, Any], ...]
    evaluations: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class C3DecisionRecord:
    decision_id: str
    c3_run_id: str
    qualification_run_id: str
    certificate_id: str
    key_id: str
    payload_sha256: str
    signature_sha256: str
    decision_maker_identity: str
    decision_maker_environment: str
    verdict: C3DecisionVerdict
    selected_candidate_artifact_id: str | None
    qualification_head_hash: str
    candidate_count: int
    evaluation_count: int
    candidate_set_digest: str
    evaluation_set_digest: str
    decided_at_utc: str
    independence_basis: str
    admitted_at: str
    admitted_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C3DecisionVerification:
    decision_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C3DecisionService:
    """RED seam for the sovereign exact-byte C3 decision authority."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        continuity: ContinuityService,
        certification: C2CertificationService,
        c3: C3QualificationGate,
        qualification: QualificationLab,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.continuity = continuity
        self.certification = certification
        self.c3 = c3
        self.qualification = qualification

    def _snapshot_from_connection(
        self,
        connection: sqlite3.Connection,
        c3_run_id: str,
    ) -> C3DecisionSnapshot:
        raise StateTransitionError("C3 decision authority is not implemented")

    def snapshot(self, c3_run_id: str) -> C3DecisionSnapshot:
        raise StateTransitionError("C3 decision authority is not implemented")

    def admit_decision(
        self,
        c3_run_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        *,
        actor: str,
        occurred_at: str | None = None,
    ) -> C3DecisionRecord:
        raise StateTransitionError("C3 decision authority is not implemented")

    def get_decision(self, decision_id: str) -> C3DecisionRecord:
        raise NotFoundError(
            "C3 decision does not exist",
            {"decision_id": decision_id},
        )

    def verify_decision(self, decision_id: str) -> C3DecisionVerification:
        return C3DecisionVerification(
            decision_id=decision_id,
            defects=("C3_DECISION_AUTHORITY_NOT_IMPLEMENTED",),
        )
