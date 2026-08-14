from __future__ import annotations

from dataclasses import dataclass

from .certification import C2CertificationService
from .db import Database
from .errors import NotFoundError, StateTransitionError
from .ledger import EventLedger
from .qualification import QualificationLab


@dataclass(frozen=True)
class C3QualificationBinding:
    c3_run_id: str
    qualification_run_id: str
    certificate_id: str
    recollection_id: str
    incident_id: str
    campaign_id: str
    identity_count: int
    required_target: int
    identity_set_digest: str
    started_at: str
    started_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C3QualificationVerification:
    c3_run_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C3QualificationGate:
    """RED seam for certification-gated C3 qualification startup."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        certification: C2CertificationService,
        qualification: QualificationLab,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.certification = certification
        self.qualification = qualification

    def start(
        self,
        c3_run_id: str,
        *,
        qualification_run_id: str,
        certificate_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> C3QualificationBinding:
        raise StateTransitionError("C3 qualification gate is not implemented")

    def get(self, c3_run_id: str) -> C3QualificationBinding:
        raise NotFoundError(
            "C3 qualification binding does not exist",
            {"c3_run_id": c3_run_id},
        )

    def verify(self, c3_run_id: str) -> C3QualificationVerification:
        return C3QualificationVerification(
            c3_run_id=c3_run_id,
            defects=("C3_QUALIFICATION_GATE_NOT_IMPLEMENTED",),
        )
