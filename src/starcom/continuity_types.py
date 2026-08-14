from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class IncidentStatus(str, Enum):
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    RECOVERY_PUBLISHED_RECOLLECT_REQUIRED = "RECOVERY_PUBLISHED_RECOLLECT_REQUIRED"


class SignatureVerifier(Protocol):
    def validate_public_key(self, public_key_pem: bytes) -> bool: ...

    def verify(self, public_key_pem: bytes, payload: bytes, signature: bytes) -> bool: ...


@dataclass(frozen=True)
class IncidentRecord:
    incident_id: str
    reviewed_archive_sha256: str
    status: IncidentStatus
    disposition: str
    created_at: str
    created_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class TrustRootReceipt:
    key_id: str
    fingerprint_sha256: str
    accepted_at: str
    accepted_by: str
    decision_id: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class TrustRootVerification:
    key_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


@dataclass(frozen=True)
class ReviewAdmission:
    review_id: str
    incident_id: str
    key_id: str
    payload_sha256: str
    signature_sha256: str
    disposition: str
    reviewer_identity: str
    admitted_at: str
    admitted_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class RecoveryPublication:
    publication_id: str
    incident_id: str
    review_id: str
    idempotency_key: str
    decision_id: str
    status: IncidentStatus
    published_at: str
    published_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class ContinuityVerification:
    incident_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects
