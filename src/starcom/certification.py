from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .census import C2CensusService
from .continuity import ContinuityService
from .db import Database
from .errors import NotFoundError, StateTransitionError
from .ledger import EventLedger
from .recollection import C2RecollectionService


@dataclass(frozen=True)
class C2CertificationSnapshot:
    recollection_id: str
    incident_id: str
    campaign_id: str
    identity_count: int
    required_target: int
    identity_set_digest: str
    latest_identity_at: str | None
    members: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class C2CertificationRecord:
    certificate_id: str
    recollection_id: str
    incident_id: str
    campaign_id: str
    key_id: str
    payload_sha256: str
    signature_sha256: str
    certifier_identity: str
    identity_count: int
    required_target: int
    identity_set_digest: str
    certified_at_utc: str
    admitted_at: str
    admitted_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C2CertificationVerification:
    certificate_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C2CertificationService:
    """RED seam for exact-byte independently signed C2 census certification."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        continuity: ContinuityService,
        recollection: C2RecollectionService,
        census: C2CensusService,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.continuity = continuity
        self.recollection = recollection
        self.census = census

    def snapshot(self, recollection_id: str) -> C2CertificationSnapshot:
        raise StateTransitionError("C2 certification protocol is not implemented")

    def admit_certification(
        self,
        recollection_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        *,
        actor: str,
        occurred_at: str | None = None,
    ) -> C2CertificationRecord:
        raise StateTransitionError("C2 certification protocol is not implemented")

    def get_certificate(self, certificate_id: str) -> C2CertificationRecord:
        raise NotFoundError(
            "C2 certification does not exist",
            {"certificate_id": certificate_id},
        )

    def verify_certificate(self, certificate_id: str) -> C2CertificationVerification:
        return C2CertificationVerification(
            certificate_id=certificate_id,
            defects=("C2_CERTIFICATION_PROTOCOL_NOT_IMPLEMENTED",),
        )
