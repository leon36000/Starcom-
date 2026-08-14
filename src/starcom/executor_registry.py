from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from .continuity import ContinuityService
from .db import Database
from .errors import NotFoundError, StateTransitionError
from .ledger import EventLedger
from .trust import TrustPlane


class C3ExecutorNetworkMode(str, Enum):
    DENY = "DENY"
    ALLOWLIST_ONLY = "ALLOWLIST_ONLY"


class C3ExecutorState(str, Enum):
    REGISTERED_DISABLED = "C3_EXECUTOR_REGISTERED_DISABLED"
    QUALIFIED_DISABLED = "C3_EXECUTOR_QUALIFIED_DISABLED"
    ENABLED = "C3_EXECUTOR_ENABLED"
    REVOKED = "C3_EXECUTOR_REVOKED"


@dataclass(frozen=True)
class C3ExecutorDescriptor:
    executor_id: str
    implementation_name: str
    implementation_version: str
    implementation_digest: str
    artifact_digest: str
    entrypoint: str
    supported_sandbox_profiles: tuple[str, ...]
    network_mode: C3ExecutorNetworkMode
    capabilities: tuple[str, ...]
    descriptor_digest: str
    registered_at: str
    registered_by: str
    authorization_decision_id: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C3ExecutorQualifierRoot:
    key_id: str
    public_key_fingerprint_sha256: str
    accepted_at: str
    accepted_by: str
    authorization_decision_id: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C3ExecutorQualification:
    qualification_id: str
    executor_id: str
    key_id: str
    payload_sha256: str
    signature_sha256: str
    reviewer_identity: str
    reviewer_environment: str
    qualified_at: str
    admitted_at: str
    admitted_by: str
    authorization_decision_id: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C3ExecutorCurrent:
    executor_id: str
    state: C3ExecutorState
    transition_sequence: int
    transitioned_at: str
    transitioned_by: str
    authorization_decision_id: str


@dataclass(frozen=True)
class C3ExecutorPreparation:
    operation: str
    executor_id: str
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]


@dataclass(frozen=True)
class C3ExecutorRegistryVerification:
    executor_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


@dataclass(frozen=True)
class C3ExecutorAttestation:
    executor_id: str
    state: C3ExecutorState
    implementation_version: str
    implementation_digest: str
    sandbox_profile: str
    network_mode: C3ExecutorNetworkMode
    registry_head_hash: str


class C3ExecutorRegistry:
    """RED seam for the signed, enabled and revocable C3 executor authority."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        trust: TrustPlane,
        continuity: ContinuityService,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self.continuity = continuity

    def prepare_registration(
        self,
        descriptor: Mapping[str, Any],
    ) -> C3ExecutorPreparation:
        raise StateTransitionError("C3 executor registry v4 is not implemented")

    def register(
        self,
        descriptor: Mapping[str, Any],
        *,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> C3ExecutorDescriptor:
        raise StateTransitionError("C3 executor registry v4 is not implemented")

    def prepare_qualifier_root(
        self,
        key_id: str,
        public_key: bytes,
    ) -> C3ExecutorPreparation:
        raise StateTransitionError("C3 executor registry v4 is not implemented")

    def accept_qualifier_root(
        self,
        key_id: str,
        public_key: bytes,
        *,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> C3ExecutorQualifierRoot:
        raise StateTransitionError("C3 executor registry v4 is not implemented")

    def prepare_qualification(
        self,
        executor_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
    ) -> C3ExecutorPreparation:
        raise StateTransitionError("C3 executor registry v4 is not implemented")

    def qualify(
        self,
        executor_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        *,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> C3ExecutorQualification:
        raise StateTransitionError("C3 executor registry v4 is not implemented")

    def prepare_enable(self, executor_id: str) -> C3ExecutorPreparation:
        raise StateTransitionError("C3 executor registry v4 is not implemented")

    def enable(
        self,
        executor_id: str,
        *,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> C3ExecutorCurrent:
        raise StateTransitionError("C3 executor registry v4 is not implemented")

    def prepare_revoke(
        self,
        executor_id: str,
        *,
        reason: str,
    ) -> C3ExecutorPreparation:
        raise StateTransitionError("C3 executor registry v4 is not implemented")

    def revoke(
        self,
        executor_id: str,
        *,
        reason: str,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> C3ExecutorCurrent:
        raise StateTransitionError("C3 executor registry v4 is not implemented")

    def get_descriptor(self, executor_id: str) -> C3ExecutorDescriptor:
        raise NotFoundError("C3 executor does not exist", {"executor_id": executor_id})

    def get_qualifier_root(self, key_id: str) -> C3ExecutorQualifierRoot:
        raise NotFoundError("C3 qualifier root does not exist", {"key_id": key_id})

    def get_qualification(self, executor_id: str) -> C3ExecutorQualification:
        raise NotFoundError("C3 executor qualification does not exist", {"executor_id": executor_id})

    def get_current(self, executor_id: str) -> C3ExecutorCurrent:
        raise NotFoundError("C3 executor does not exist", {"executor_id": executor_id})

    def verify(self, executor_id: str) -> C3ExecutorRegistryVerification:
        return C3ExecutorRegistryVerification(
            executor_id=executor_id,
            defects=("C3_EXECUTOR_REGISTRY_V4_NOT_IMPLEMENTED",),
        )

    def attest(
        self,
        executor_id: str,
        *,
        implementation_version: str,
        implementation_digest: str,
        sandbox_profile: str,
        requires_network: bool,
    ) -> C3ExecutorAttestation:
        raise StateTransitionError("C3 executor registry v4 is not implemented")
