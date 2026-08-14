from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from .db import Database
from .errors import NotFoundError, StateTransitionError
from .ledger import EventLedger


class QualificationArtifactKind(str, Enum):
    CANDIDATE = "CANDIDATE"
    EVALUATION = "EVALUATION"
    DECISION = "DECISION"
    ADOPTION = "ADOPTION"


@dataclass(frozen=True)
class QualificationRun:
    qualification_run_id: str
    name: str
    created_at: str
    created_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class QualificationArtifact:
    artifact_id: str
    qualification_run_id: str
    kind: QualificationArtifactKind
    material: Mapping[str, Any]
    material_sha256: str
    recorded_at: str
    recorded_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class QualificationVerification:
    qualification_run_id: str
    artifact_counts: Mapping[str, int]
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class QualificationLab:
    """RED seam for a generic append-only qualification laboratory."""

    def __init__(self, database: Database, ledger: EventLedger) -> None:
        self.database = database
        self.ledger = ledger

    def create_run(
        self,
        qualification_run_id: str,
        *,
        name: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> QualificationRun:
        raise StateTransitionError("qualification laboratory is not implemented")

    def get_run(self, qualification_run_id: str) -> QualificationRun:
        raise NotFoundError(
            "qualification run does not exist",
            {"qualification_run_id": qualification_run_id},
        )

    def record_artifact(
        self,
        qualification_run_id: str,
        *,
        artifact_id: str,
        kind: QualificationArtifactKind,
        material: Mapping[str, Any],
        actor: str,
        occurred_at: str | None = None,
    ) -> QualificationArtifact:
        raise StateTransitionError("qualification laboratory is not implemented")

    def get_artifact(self, artifact_id: str) -> QualificationArtifact:
        raise NotFoundError(
            "qualification artifact does not exist",
            {"artifact_id": artifact_id},
        )

    def verify(self, qualification_run_id: str) -> QualificationVerification:
        return QualificationVerification(
            qualification_run_id=qualification_run_id,
            artifact_counts={item.value: 0 for item in QualificationArtifactKind},
            defects=("QUALIFICATION_LAB_NOT_IMPLEMENTED",),
        )
