from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import platform
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from . import __version__
from .adoption import C3AdoptionService
from .adoption_execution import C3AdoptionExecutionService
from .architecture_candidate import C4ArchitectureCandidateService
from .architecture_input import C4ArchitectureInputService
from .architecture_publication import C4ArchitecturePublicationService
from .architecture_review import C4ArchitectureReviewService
from .architecture import C4ArchitectureService
from .canonical import canonical_json
from .census import C2CensusService
from .certification import C2CertificationService
from .continuity import ContinuityService
from .cockpit import CockpitService
from .creative import CreativeJobService
from .db import Database
from .deployment import DeploymentFabricService
from .durable import DurableOutbox
from .errors import StarcomError, ValidationError
from .execution_plan import C5ExecutionPlanService
from .executor_registry import C3ExecutorRegistry
from .final_pack import C7FinalPackService
from .ledger import EventLedger
from .mission import MissionKernel, MissionState
from .proof import ProofEngine, VerificationVerdict
from .qualification import QualificationArtifactKind, QualificationLab
from .qualification_decision import C3DecisionService
from .qualification_gate import C3QualificationGate
from .recollection import C2RecollectionService
from .red_team import C6RedTeamService
from .release_candidate import ReleaseCandidateService
from .research import ReceiptOutcome, ResearchCampaign
from .research_marathon import ResearchMarathonService
from .trust import (
    AuthorizationRequest,
    PolicyEffect,
    PolicyRule,
    TrustPlane,
)


Handler = Callable[["Runtime", argparse.Namespace], tuple[Any, int]]


class JsonArgumentParser(argparse.ArgumentParser):
    """Argument parser that maps contract failures to STARCOM JSON errors."""

    def error(self, message: str) -> None:
        raise ValidationError("invalid command arguments", {"reason": message})


@dataclass
class Runtime:
    database: Database
    ledger: EventLedger
    trust: TrustPlane
    proof: ProofEngine
    missions: MissionKernel
    research: ResearchCampaign
    continuity: ContinuityService
    recollection: C2RecollectionService
    census: C2CensusService
    certification: C2CertificationService
    qualification: QualificationLab
    c3: C3QualificationGate
    c3_decision: C3DecisionService
    adoption: C3AdoptionService
    outbox: DurableOutbox
    adoption_execution: C3AdoptionExecutionService
    executor_registry: C3ExecutorRegistry
    architecture_input: C4ArchitectureInputService
    architecture_candidate: C4ArchitectureCandidateService
    architecture_review: C4ArchitectureReviewService
    architecture_publication: C4ArchitecturePublicationService
    architecture: C4ArchitectureService
    execution_plan: C5ExecutionPlanService
    red_team: C6RedTeamService
    final_pack: C7FinalPackService
    research_marathon: ResearchMarathonService
    creative_jobs: CreativeJobService
    cockpit: CockpitService
    deployment: DeploymentFabricService
    release_candidate: ReleaseCandidateService

    @property
    def architecture_baseline(self) -> C4ArchitectureService:
        return self.architecture

    @property
    def c5_execution_plan(self) -> C5ExecutionPlanService:
        return self.execution_plan

    @property
    def c6_red_team(self) -> C6RedTeamService:
        return self.red_team

    @property
    def c7_final_pack(self) -> C7FinalPackService:
        return self.final_pack

    @property
    def creative(self) -> CreativeJobService:
        return self.creative_jobs

    @property
    def rc_assessment(self) -> ReleaseCandidateService:
        return self.release_candidate

    @classmethod
    def open(cls, path: str) -> "Runtime":
        database = Database(path)
        try:
            database.initialize()
            ledger = EventLedger(database)
            trust = TrustPlane(database, ledger)
            proof = ProofEngine(database, ledger)
            missions = MissionKernel(database, ledger, trust, proof)
            research = ResearchCampaign(database, ledger)
            continuity = ContinuityService(database, ledger, trust)
            recollection = C2RecollectionService(database, ledger, continuity, research)
            census = C2CensusService(database, ledger, recollection, research)
            certification = C2CertificationService(
                database,
                ledger,
                continuity,
                recollection,
                census,
            )
            qualification = QualificationLab(database, ledger)
            c3 = C3QualificationGate(
                database,
                ledger,
                certification,
                qualification,
            )
            c3_decision = C3DecisionService(
                database,
                ledger,
                continuity,
                certification,
                c3,
                qualification,
            )
            adoption = C3AdoptionService(
                database,
                ledger,
                trust,
                continuity,
                c3_decision,
                qualification,
            )
            outbox = DurableOutbox(database, ledger)
            adoption_execution = C3AdoptionExecutionService(
                database,
                ledger,
                trust,
                continuity,
                adoption,
                outbox,
            )
            executor_registry = C3ExecutorRegistry(
                database,
                ledger,
                trust,
                continuity,
            )
            architecture_input = C4ArchitectureInputService(
                database,
                ledger,
                trust,
                continuity,
                adoption_execution,
            )
            architecture_candidate = C4ArchitectureCandidateService(
                database,
                ledger,
                trust,
                continuity,
                architecture_input,
            )
            architecture_review = C4ArchitectureReviewService(
                database,
                ledger,
                trust,
                continuity,
                architecture_input,
                architecture_candidate,
            )
            architecture_publication = C4ArchitecturePublicationService(
                database,
                ledger,
                trust,
                continuity,
                architecture_input,
                architecture_candidate,
                architecture_review,
            )
            architecture = C4ArchitectureService(
                database,
                ledger,
                trust,
                continuity,
                c3_decision,
                adoption,
                adoption_execution,
            )
            execution_plan = C5ExecutionPlanService(
                database,
                ledger,
                trust,
                continuity,
                architecture,
            )
            red_team = C6RedTeamService(
                database,
                ledger,
                trust,
                continuity,
                execution_plan,
            )
            final_pack = C7FinalPackService(
                database,
                ledger,
                trust,
                continuity,
                architecture,
                execution_plan,
                red_team,
            )
            research_marathon = ResearchMarathonService(
                database,
                ledger,
                trust,
                continuity,
                final_pack,
                research,
                outbox,
            )
            creative_jobs = CreativeJobService(
                database,
                ledger,
                trust,
                outbox,
            )
            cockpit = CockpitService(database, ledger, trust)
            deployment = DeploymentFabricService(
                database,
                ledger,
                trust,
                continuity,
            )
            release_candidate = ReleaseCandidateService(
                database,
                ledger,
                trust,
                continuity,
            )
            return cls(
                database,
                ledger,
                trust,
                proof,
                missions,
                research,
                continuity,
                recollection,
                census,
                certification,
                qualification,
                c3,
                c3_decision,
                adoption,
                outbox,
                adoption_execution,
                executor_registry,
                architecture_input,
                architecture_candidate,
                architecture_review,
                architecture_publication,
                architecture,
                execution_plan,
                red_team,
                final_pack,
                research_marathon,
                creative_jobs,
                cockpit,
                deployment,
                release_candidate,
            )
        except BaseException:
            database.close()
            raise

    def close(self) -> None:
        self.database.close()


def _database_path(raw: str) -> str:
    if raw == ":memory:":
        return raw
    return str(Path(raw).expanduser().resolve())


def _json_value(raw: str, field_name: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValidationError(
            f"{field_name} must contain valid JSON",
            {"line": exc.lineno, "column": exc.colno},
        ) from exc


def _json_object(raw: str, field_name: str) -> Mapping[str, Any]:
    value = _json_value(raw, field_name)
    if not isinstance(value, dict):
        raise ValidationError(f"{field_name} must contain a JSON object")
    return value


def _read_file_bytes(raw: str, field_name: str) -> bytes:
    path = Path(raw).expanduser()
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ValidationError(
            f"{field_name} could not be read",
            {"path": str(path), "type": type(exc).__name__},
        ) from exc


def _verification_payload(value: Any) -> dict[str, Any]:
    payload = asdict(value)
    payload["ok"] = bool(value.ok)
    return payload


def _emit_success(result: Any) -> None:
    print(canonical_json({"ok": True, "result": result}))


def _emit_error(error: StarcomError) -> None:
    print(canonical_json(error.to_dict()), file=sys.stderr)


def _init(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return {
        "database": _database_path(args.db),
        "initialized": True,
        "version": __version__,
    }, 0


def _doctor(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    verification = runtime.ledger.verify()
    result = {
        "component": "starcom-core",
        "version": __version__,
        "python": platform.python_version(),
        "database": _database_path(args.db),
        "product_complete": False,
        "external_runtime_integrated": False,
        "component_adoption": False,
        "live_800_plus_census_certified": False,
        "task5_disposition": "RECOLLECT_REQUIRED",
        "ledger": _verification_payload(verification),
    }
    return result, 0 if verification.ok else 3


def _ledger_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    verification = runtime.ledger.verify(args.stream_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _mission_create(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.missions.create(
        mission_id=args.mission_id,
        title=args.title,
        objective=args.objective,
        owner=args.owner,
        occurred_at=args.occurred_at,
    ), 0


def _mission_get(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.missions.get(args.mission_id), 0


def _mission_transition(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.missions.transition(
        args.mission_id,
        MissionState(args.to),
        actor=args.actor,
        idempotency_key=args.idempotency_key,
        reason=args.reason,
        authorization_decision_id=args.authorization_decision_id,
        certificate_id=args.certificate_id,
        occurred_at=args.occurred_at,
    ), 0


def _research_create(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.research.create(
        campaign_id=args.campaign_id,
        name=args.name,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _research_begin_attempt(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.research.begin_attempt(
        args.campaign_id,
        attempt_id=args.attempt_id,
        wave=args.wave,
        request_key=args.request_key,
        source_id=args.source_id,
        request=_json_object(args.request_json, "request_json"),
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _research_receipt(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.research.record_receipt(
        args.attempt_id,
        receipt_id=args.receipt_id,
        outcome=ReceiptOutcome(args.outcome),
        status_code=args.status_code,
        snapshot_digest=args.snapshot_digest,
        metadata=_json_object(args.metadata_json, "metadata_json"),
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _research_observation(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.research.record_observation(
        args.attempt_id,
        observation_id=args.observation_id,
        snapshot_digest=args.snapshot_digest,
        content_digest=args.content_digest,
        data=_json_object(args.data_json, "data_json"),
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _research_cursor(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.research.checkpoint_cursor(
        args.campaign_id,
        cursor_id=args.cursor_id,
        wave=args.wave,
        cursor_key=args.cursor_key,
        value=_json_value(args.value_json, "value_json"),
        attempt_id=args.attempt_id,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _research_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    verification = runtime.research.verify(args.campaign_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _continuity_create_incident(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.continuity.create_incident(
        args.incident_id,
        reviewed_archive_sha256=args.reviewed_archive_sha256,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _continuity_get_incident(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.continuity.get_incident(args.incident_id), 0


def _continuity_accept_trust_root(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    public_key = _read_file_bytes(args.public_key_file, "public_key_file")
    return runtime.continuity.accept_trust_root(
        args.key_id,
        public_key,
        decision_id=args.decision_id,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _continuity_admit_review(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    payload = _read_file_bytes(args.payload_file, "payload_file")
    signature = _read_file_bytes(args.signature_file, "signature_file")
    return runtime.continuity.admit_review(
        args.incident_id,
        args.key_id,
        payload,
        signature,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _continuity_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    verification = runtime.continuity.verify_incident(args.incident_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _continuity_publish_recovery(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.continuity.publish_recovery(
        args.incident_id,
        args.review_id,
        publication_id=args.publication_id,
        idempotency_key=args.idempotency_key,
        decision_id=args.decision_id,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _recollection_start(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.recollection.start(
        args.recollection_id,
        incident_id=args.incident_id,
        campaign_id=args.campaign_id,
        minimum_identity_target=args.minimum_identity_target,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _recollection_get(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.recollection.get(args.recollection_id), 0


def _recollection_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    verification = runtime.recollection.verify(args.recollection_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _census_register(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.census.register_identity(
        args.recollection_id,
        identity_id=args.identity_id,
        identity_key=args.identity_key,
        source_id=args.source_id,
        attempt_id=args.attempt_id,
        observation_id=args.observation_id,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _census_get(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.census.get_identity(args.identity_id), 0


def _census_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    verification = runtime.census.verify(args.recollection_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _census_assess(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    assessment = runtime.census.assess(args.recollection_id)
    return assessment, 0 if not assessment.defects else 3


def _certification_snapshot(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    snapshot = runtime.certification.snapshot(args.recollection_id)
    return {
        "recollection_id": snapshot.recollection_id,
        "incident_id": snapshot.incident_id,
        "campaign_id": snapshot.campaign_id,
        "identity_count": snapshot.identity_count,
        "required_target": snapshot.required_target,
        "identity_set_digest": snapshot.identity_set_digest,
        "latest_identity_at": snapshot.latest_identity_at,
    }, 0


def _certification_admit(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    payload = _read_file_bytes(args.payload_file, "payload_file")
    signature = _read_file_bytes(args.signature_file, "signature_file")
    return runtime.certification.admit_certification(
        args.recollection_id,
        args.key_id,
        payload,
        signature,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _certification_get(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.certification.get_certificate(args.certificate_id), 0


def _certification_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    verification = runtime.certification.verify_certificate(args.certificate_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _qualification_create_run(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.qualification.create_run(
        args.qualification_run_id,
        name=args.name,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _qualification_get_run(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.qualification.get_run(args.qualification_run_id), 0


def _qualification_record_artifact(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.qualification.record_artifact(
        args.qualification_run_id,
        artifact_id=args.artifact_id,
        kind=QualificationArtifactKind(args.kind),
        material=_json_object(args.material_json, "material_json"),
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _qualification_get_artifact(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.qualification.get_artifact(args.artifact_id), 0


def _qualification_verify(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    verification = runtime.qualification.verify(args.qualification_run_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _c3_start(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.c3.start(
        args.c3_run_id,
        qualification_run_id=args.qualification_run_id,
        certificate_id=args.certificate_id,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _c3_get(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.c3.get(args.c3_run_id), 0


def _c3_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    verification = runtime.c3.verify(args.c3_run_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _c3_decision_snapshot(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    snapshot = runtime.c3_decision.snapshot(args.c3_run_id)
    return {
        "c3_run_id": snapshot.c3_run_id,
        "qualification_run_id": snapshot.qualification_run_id,
        "certificate_id": snapshot.certificate_id,
        "qualification_head_hash": snapshot.qualification_head_hash,
        "candidate_count": snapshot.candidate_count,
        "evaluation_count": snapshot.evaluation_count,
        "candidate_set_digest": snapshot.candidate_set_digest,
        "evaluation_set_digest": snapshot.evaluation_set_digest,
        "latest_evidence_at": snapshot.latest_evidence_at,
        "candidate_artifact_ids": [
            str(member["artifact_id"]) for member in snapshot.candidates
        ],
        "evaluation_artifact_ids": [
            str(member["artifact_id"]) for member in snapshot.evaluations
        ],
    }, 0


def _c3_decision_admit(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    payload = _read_file_bytes(args.payload_file, "payload_file")
    signature = _read_file_bytes(args.signature_file, "signature_file")
    return runtime.c3_decision.admit_decision(
        args.c3_run_id,
        args.key_id,
        payload,
        signature,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _c3_decision_get(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.c3_decision.get_decision(args.decision_id), 0


def _c3_decision_verify(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    verification = runtime.c3_decision.verify_decision(args.decision_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _architecture_reviewer_root_result(value: Any) -> dict[str, Any]:
    result = asdict(value)
    result.pop("public_key_pem", None)
    return result


def _architecture_review_result(
    runtime: Runtime,
    review: Any,
) -> dict[str, Any]:
    result = asdict(review)
    result.pop("payload", None)
    result.pop("signature", None)
    result["verdict"] = review.verdict.value
    result["findings"] = [
        asdict(finding)
        for finding in runtime.architecture_review.get_findings(review.review_id)
    ]
    return result


def _architecture_review_prepare_root(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    public_key = _read_file_bytes(args.public_key_file, "public_key_file")
    return runtime.architecture_review.prepare_reviewer_root(
        args.key_id,
        args.reviewer_identity,
        public_key,
    ), 0


def _architecture_review_accept_root(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    public_key = _read_file_bytes(args.public_key_file, "public_key_file")
    root = runtime.architecture_review.accept_reviewer_root(
        args.key_id,
        args.reviewer_identity,
        public_key,
        authorization_decision_id=args.authorization_decision_id,
        actor=args.actor,
        occurred_at=args.occurred_at,
    )
    return _architecture_reviewer_root_result(root), 0


def _architecture_review_admit(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    payload = _read_file_bytes(args.payload_file, "payload_file")
    signature = _read_file_bytes(args.signature_file, "signature_file")
    review = runtime.architecture_review.admit_review(
        args.candidate_id,
        args.key_id,
        payload,
        signature,
        actor=args.actor,
        occurred_at=args.occurred_at,
    )
    return _architecture_review_result(runtime, review), 0


def _architecture_review_get(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    review = runtime.architecture_review.get_review(args.review_id)
    return _architecture_review_result(runtime, review), 0


def _architecture_review_verify_root(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    verification = runtime.architecture_review.verify_reviewer_root(args.key_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _architecture_review_verify(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    verification = runtime.architecture_review.verify_review(args.review_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _adoption_prepare(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.adoption.prepare(
        args.c3_run_id,
        _json_object(args.rollback_plan_json, "rollback_plan_json"),
    ), 0


def _adoption_authorize(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.adoption.authorize_adoption(
        args.adoption_id,
        c3_run_id=args.c3_run_id,
        authorization_decision_id=args.authorization_decision_id,
        rollback_plan=_json_object(args.rollback_plan_json, "rollback_plan_json"),
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _adoption_get(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.adoption.get_adoption(args.adoption_id), 0


def _adoption_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    verification = runtime.adoption.verify_adoption(args.adoption_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _adoption_execution_prepare(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.adoption_execution.prepare(
        args.execution_id,
        adoption_id=args.adoption_id,
        executor_id=args.executor_id,
        execution_plan=_json_object(
            args.execution_plan_json,
            "execution_plan_json",
        ),
    ), 0


def _adoption_execution_request(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.adoption_execution.request_execution(
        args.execution_id,
        adoption_id=args.adoption_id,
        executor_id=args.executor_id,
        execution_plan=_json_object(
            args.execution_plan_json,
            "execution_plan_json",
        ),
        authorization_decision_id=args.authorization_decision_id,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _adoption_execution_get(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.adoption_execution.get_execution(args.execution_id), 0


def _adoption_execution_verify(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    verification = runtime.adoption_execution.verify_execution(args.execution_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _executor_registry_prepare_register(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.executor_registry.prepare_registration(
        _json_object(args.descriptor_json, "descriptor_json")
    ), 0


def _executor_registry_register(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.executor_registry.register(
        _json_object(args.descriptor_json, "descriptor_json"),
        authorization_decision_id=args.authorization_decision_id,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _executor_registry_prepare_qualifier_root(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    public_key = _read_file_bytes(args.public_key_file, "public_key_file")
    return runtime.executor_registry.prepare_qualifier_root(
        args.key_id,
        public_key,
    ), 0


def _executor_registry_accept_qualifier_root(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    public_key = _read_file_bytes(args.public_key_file, "public_key_file")
    return runtime.executor_registry.accept_qualifier_root(
        args.key_id,
        public_key,
        authorization_decision_id=args.authorization_decision_id,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _executor_registry_prepare_qualify(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    payload = _read_file_bytes(args.payload_file, "payload_file")
    signature = _read_file_bytes(args.signature_file, "signature_file")
    return runtime.executor_registry.prepare_qualification(
        args.executor_id,
        args.key_id,
        payload,
        signature,
    ), 0


def _executor_registry_qualify(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    payload = _read_file_bytes(args.payload_file, "payload_file")
    signature = _read_file_bytes(args.signature_file, "signature_file")
    return runtime.executor_registry.qualify(
        args.executor_id,
        args.key_id,
        payload,
        signature,
        authorization_decision_id=args.authorization_decision_id,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _executor_registry_prepare_enable(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.executor_registry.prepare_enable(args.executor_id), 0


def _executor_registry_enable(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.executor_registry.enable(
        args.executor_id,
        authorization_decision_id=args.authorization_decision_id,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _executor_registry_prepare_revoke(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.executor_registry.prepare_revoke(
        args.executor_id,
        reason=args.reason,
    ), 0


def _executor_registry_revoke(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.executor_registry.revoke(
        args.executor_id,
        reason=args.reason,
        authorization_decision_id=args.authorization_decision_id,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _executor_registry_get(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return {
        "descriptor": runtime.executor_registry.get_descriptor(args.executor_id),
        "current": runtime.executor_registry.get_current(args.executor_id),
    }, 0


def _executor_registry_verify(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    verification = runtime.executor_registry.verify(args.executor_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _executor_registry_attest(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.executor_registry.attest(
        args.executor_id,
        implementation_version=args.implementation_version,
        implementation_digest=args.implementation_digest,
        sandbox_profile=args.sandbox_profile,
        requires_network=args.requires_network,
    ), 0


def _trust_add_rule(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    rule = PolicyRule(
        rule_id=args.rule_id,
        effect=PolicyEffect(args.effect),
        subject=args.subject,
        action=args.action,
        resource=args.resource,
        conditions=_json_object(args.conditions_json, "conditions_json"),
        priority=args.priority,
    )
    runtime.trust.add_rule(rule, actor=args.actor, occurred_at=args.occurred_at)
    return rule, 0


def _trust_issue_grant(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    runtime.trust.issue_grant(
        grant_id=args.grant_id,
        subject=args.subject,
        action=args.action,
        resource=args.resource,
        mission_id=args.mission_id,
        expires_at=args.expires_at,
        single_use=args.single_use,
        actor=args.actor,
        occurred_at=args.occurred_at,
    )
    return {
        "grant_id": args.grant_id,
        "mission_id": args.mission_id,
        "single_use": args.single_use,
    }, 0


def _trust_authorize(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    request = AuthorizationRequest(
        subject=args.subject,
        action=args.action,
        resource=args.resource,
        mission_id=args.mission_id,
        context=_json_object(args.context_json, "context_json"),
    )
    decision = runtime.trust.authorize(
        request,
        now=args.at,
        consume=not args.no_consume,
    )
    return decision, 0 if decision.allowed else 4


def _trust_verify_decision(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    verification = runtime.trust.verify_decision(args.decision_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _proof_create_claim(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.proof.create_claim(
        claim_id=args.claim_id,
        subject_type=args.subject_type,
        subject_id=args.subject_id,
        statement=args.statement,
        author=args.author,
        policy_version=args.policy_version,
        occurred_at=args.occurred_at,
    ), 0


def _proof_get_claim(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.proof.get_claim(args.claim_id), 0


def _proof_attach_evidence(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.proof.attach_evidence(
        args.claim_id,
        evidence_id=args.evidence_id,
        kind=args.kind,
        uri=args.uri,
        digest=args.digest,
        metadata=_json_object(args.metadata_json, "metadata_json"),
        attached_by=args.attached_by,
        occurred_at=args.occurred_at,
    ), 0


def _proof_verify_claim(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.proof.verify_claim(
        args.claim_id,
        verifier=args.verifier,
        verdict=VerificationVerdict(args.verdict),
        notes=args.notes,
        occurred_at=args.occurred_at,
    ), 0


def _proof_certify_claim(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    return runtime.proof.certify_claim(
        args.claim_id,
        certifier=args.certifier,
        occurred_at=args.occurred_at,
    ), 0


def _proof_verify_certificate(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    verification = runtime.proof.verify_certificate(args.certificate_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _set_handler(parser: argparse.ArgumentParser, handler: Handler) -> None:
    parser.set_defaults(handler=handler)


def _add_occurred_at(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--occurred-at")


def build_parser() -> argparse.ArgumentParser:
    parser = JsonArgumentParser(
        prog="starcom",
        description="STARCOM proof-gated mission core",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "--db",
        default=os.environ.get("STARCOM_DB", "starcom.sqlite3"),
        help="SQLite database path (default: STARCOM_DB or ./starcom.sqlite3)",
    )
    top = parser.add_subparsers(dest="command")

    init_parser = top.add_parser("init", help="initialize the local STARCOM database")
    _set_handler(init_parser, _init)

    doctor = top.add_parser("doctor", help="report the local R0.1 runtime state")
    _set_handler(doctor, _doctor)

    ledger = top.add_parser("ledger", help="verify immutable ledger chains")
    ledger_commands = ledger.add_subparsers(dest="ledger_command", required=True)
    ledger_verify = ledger_commands.add_parser("verify")
    ledger_verify.add_argument("--stream-id")
    _set_handler(ledger_verify, _ledger_verify)

    mission = top.add_parser("mission", help="manage proof-gated missions")
    mission_commands = mission.add_subparsers(dest="mission_command", required=True)
    mission_create = mission_commands.add_parser("create")
    mission_create.add_argument("--mission-id")
    mission_create.add_argument("--title", required=True)
    mission_create.add_argument("--objective", required=True)
    mission_create.add_argument("--owner", required=True)
    _add_occurred_at(mission_create)
    _set_handler(mission_create, _mission_create)

    mission_get = mission_commands.add_parser("get")
    mission_get.add_argument("--mission-id", required=True)
    _set_handler(mission_get, _mission_get)

    mission_transition = mission_commands.add_parser("transition")
    mission_transition.add_argument("--mission-id", required=True)
    mission_transition.add_argument("--to", required=True, choices=[state.value for state in MissionState])
    mission_transition.add_argument("--actor", required=True)
    mission_transition.add_argument("--idempotency-key", required=True)
    mission_transition.add_argument("--reason", default="")
    mission_transition.add_argument("--authorization-decision-id")
    mission_transition.add_argument("--certificate-id")
    _add_occurred_at(mission_transition)
    _set_handler(mission_transition, _mission_transition)

    research = top.add_parser("research", help="manage pre-request research evidence")
    research_commands = research.add_subparsers(dest="research_command", required=True)
    research_create = research_commands.add_parser("create")
    research_create.add_argument("--campaign-id")
    research_create.add_argument("--name", required=True)
    research_create.add_argument("--actor", required=True)
    _add_occurred_at(research_create)
    _set_handler(research_create, _research_create)

    begin_attempt = research_commands.add_parser("begin-attempt")
    begin_attempt.add_argument("--campaign-id", required=True)
    begin_attempt.add_argument("--attempt-id")
    begin_attempt.add_argument("--wave", type=int, required=True)
    begin_attempt.add_argument("--request-key", required=True)
    begin_attempt.add_argument("--source-id", required=True)
    begin_attempt.add_argument("--request-json", required=True)
    begin_attempt.add_argument("--actor", required=True)
    _add_occurred_at(begin_attempt)
    _set_handler(begin_attempt, _research_begin_attempt)

    receipt = research_commands.add_parser("receipt")
    receipt.add_argument("--attempt-id", required=True)
    receipt.add_argument("--receipt-id")
    receipt.add_argument("--outcome", required=True, choices=[item.value for item in ReceiptOutcome])
    receipt.add_argument("--status-code", type=int)
    receipt.add_argument("--snapshot-digest")
    receipt.add_argument("--metadata-json", default="{}")
    receipt.add_argument("--actor", required=True)
    _add_occurred_at(receipt)
    _set_handler(receipt, _research_receipt)

    observation = research_commands.add_parser("observation")
    observation.add_argument("--attempt-id", required=True)
    observation.add_argument("--observation-id")
    observation.add_argument("--snapshot-digest", required=True)
    observation.add_argument("--content-digest", required=True)
    observation.add_argument("--data-json", default="{}")
    observation.add_argument("--actor", required=True)
    _add_occurred_at(observation)
    _set_handler(observation, _research_observation)

    cursor = research_commands.add_parser("cursor")
    cursor.add_argument("--campaign-id", required=True)
    cursor.add_argument("--cursor-id")
    cursor.add_argument("--wave", type=int, required=True)
    cursor.add_argument("--cursor-key", required=True)
    cursor.add_argument("--value-json", required=True)
    cursor.add_argument("--attempt-id", required=True)
    cursor.add_argument("--actor", required=True)
    _add_occurred_at(cursor)
    _set_handler(cursor, _research_cursor)

    research_verify = research_commands.add_parser("verify")
    research_verify.add_argument("--campaign-id", required=True)
    _set_handler(research_verify, _research_verify)

    continuity = top.add_parser(
        "continuity",
        help="manage proof-gated C1 review admission and recovery publication",
    )
    continuity_commands = continuity.add_subparsers(dest="continuity_command", required=True)

    create_incident = continuity_commands.add_parser("create-incident")
    create_incident.add_argument("--incident-id", required=True)
    create_incident.add_argument("--reviewed-archive-sha256", required=True)
    create_incident.add_argument("--actor", required=True)
    _add_occurred_at(create_incident)
    _set_handler(create_incident, _continuity_create_incident)

    get_incident = continuity_commands.add_parser("get-incident")
    get_incident.add_argument("--incident-id", required=True)
    _set_handler(get_incident, _continuity_get_incident)

    accept_trust_root = continuity_commands.add_parser("accept-trust-root")
    accept_trust_root.add_argument("--key-id", required=True)
    accept_trust_root.add_argument("--public-key-file", required=True)
    accept_trust_root.add_argument("--decision-id", required=True)
    accept_trust_root.add_argument("--actor", required=True)
    _add_occurred_at(accept_trust_root)
    _set_handler(accept_trust_root, _continuity_accept_trust_root)

    admit_review = continuity_commands.add_parser("admit-review")
    admit_review.add_argument("--incident-id", required=True)
    admit_review.add_argument("--key-id", required=True)
    admit_review.add_argument("--payload-file", required=True)
    admit_review.add_argument("--signature-file", required=True)
    admit_review.add_argument("--actor", required=True)
    _add_occurred_at(admit_review)
    _set_handler(admit_review, _continuity_admit_review)

    continuity_verify = continuity_commands.add_parser("verify")
    continuity_verify.add_argument("--incident-id", required=True)
    _set_handler(continuity_verify, _continuity_verify)

    publish_recovery = continuity_commands.add_parser("publish-recovery")
    publish_recovery.add_argument("--incident-id", required=True)
    publish_recovery.add_argument("--review-id", required=True)
    publish_recovery.add_argument("--publication-id", required=True)
    publish_recovery.add_argument("--idempotency-key", required=True)
    publish_recovery.add_argument("--decision-id", required=True)
    publish_recovery.add_argument("--actor", required=True)
    _add_occurred_at(publish_recovery)
    _set_handler(publish_recovery, _continuity_publish_recovery)

    recollection = top.add_parser(
        "recollection",
        help="manage the C1-gated Task 5 C2 recollection binding",
    )
    recollection_commands = recollection.add_subparsers(
        dest="recollection_command", required=True
    )

    recollection_start = recollection_commands.add_parser("start")
    recollection_start.add_argument("--recollection-id", required=True)
    recollection_start.add_argument("--incident-id", required=True)
    recollection_start.add_argument("--campaign-id", required=True)
    recollection_start.add_argument("--minimum-identity-target", type=int, required=True)
    recollection_start.add_argument("--actor", required=True)
    _add_occurred_at(recollection_start)
    _set_handler(recollection_start, _recollection_start)

    recollection_get = recollection_commands.add_parser("get")
    recollection_get.add_argument("--recollection-id", required=True)
    _set_handler(recollection_get, _recollection_get)

    recollection_verify = recollection_commands.add_parser("verify")
    recollection_verify.add_argument("--recollection-id", required=True)
    _set_handler(recollection_verify, _recollection_verify)

    census = top.add_parser(
        "census",
        help="manage evidence-bound Task 5 C2 census identities and assessment",
    )
    census_commands = census.add_subparsers(dest="census_command", required=True)

    census_register = census_commands.add_parser("register")
    census_register.add_argument("--recollection-id", required=True)
    census_register.add_argument("--identity-id", required=True)
    census_register.add_argument("--identity-key", required=True)
    census_register.add_argument("--source-id", required=True)
    census_register.add_argument("--attempt-id", required=True)
    census_register.add_argument("--observation-id", required=True)
    census_register.add_argument("--actor", required=True)
    _add_occurred_at(census_register)
    _set_handler(census_register, _census_register)

    census_get = census_commands.add_parser("get")
    census_get.add_argument("--identity-id", required=True)
    _set_handler(census_get, _census_get)

    census_verify = census_commands.add_parser("verify")
    census_verify.add_argument("--recollection-id", required=True)
    _set_handler(census_verify, _census_verify)

    census_assess = census_commands.add_parser("assess")
    census_assess.add_argument("--recollection-id", required=True)
    _set_handler(census_assess, _census_assess)

    certification = top.add_parser(
        "certification",
        help="manage exact-byte independently signed Task 5 C2 certifications",
    )
    certification_commands = certification.add_subparsers(
        dest="certification_command", required=True
    )

    certification_snapshot = certification_commands.add_parser("snapshot")
    certification_snapshot.add_argument("--recollection-id", required=True)
    _set_handler(certification_snapshot, _certification_snapshot)

    certification_admit = certification_commands.add_parser("admit")
    certification_admit.add_argument("--recollection-id", required=True)
    certification_admit.add_argument("--key-id", required=True)
    certification_admit.add_argument("--payload-file", required=True)
    certification_admit.add_argument("--signature-file", required=True)
    certification_admit.add_argument("--actor", required=True)
    _add_occurred_at(certification_admit)
    _set_handler(certification_admit, _certification_admit)

    certification_get = certification_commands.add_parser("get")
    certification_get.add_argument("--certificate-id", required=True)
    _set_handler(certification_get, _certification_get)

    certification_verify = certification_commands.add_parser("verify")
    certification_verify.add_argument("--certificate-id", required=True)
    _set_handler(certification_verify, _certification_verify)

    qualification = top.add_parser(
        "qualification",
        help="manage generic append-only component qualification evidence",
    )
    qualification_commands = qualification.add_subparsers(
        dest="qualification_command", required=True
    )

    qualification_create_run = qualification_commands.add_parser("create-run")
    qualification_create_run.add_argument("--qualification-run-id", required=True)
    qualification_create_run.add_argument("--name", required=True)
    qualification_create_run.add_argument("--actor", required=True)
    _add_occurred_at(qualification_create_run)
    _set_handler(qualification_create_run, _qualification_create_run)

    qualification_get_run = qualification_commands.add_parser("get-run")
    qualification_get_run.add_argument("--qualification-run-id", required=True)
    _set_handler(qualification_get_run, _qualification_get_run)

    qualification_record_artifact = qualification_commands.add_parser(
        "record-artifact"
    )
    qualification_record_artifact.add_argument(
        "--qualification-run-id", required=True
    )
    qualification_record_artifact.add_argument("--artifact-id", required=True)
    qualification_record_artifact.add_argument(
        "--kind",
        required=True,
        choices=[item.value for item in QualificationArtifactKind],
    )
    qualification_record_artifact.add_argument("--material-json", required=True)
    qualification_record_artifact.add_argument("--actor", required=True)
    _add_occurred_at(qualification_record_artifact)
    _set_handler(qualification_record_artifact, _qualification_record_artifact)

    qualification_get_artifact = qualification_commands.add_parser("get-artifact")
    qualification_get_artifact.add_argument("--artifact-id", required=True)
    _set_handler(qualification_get_artifact, _qualification_get_artifact)

    qualification_verify = qualification_commands.add_parser("verify")
    qualification_verify.add_argument("--qualification-run-id", required=True)
    _set_handler(qualification_verify, _qualification_verify)

    c3 = top.add_parser(
        "c3",
        help="manage the exact-C2-certificate-gated C3 qualification binding",
    )
    c3_commands = c3.add_subparsers(dest="c3_command", required=True)

    c3_start = c3_commands.add_parser("start")
    c3_start.add_argument("--c3-run-id", required=True)
    c3_start.add_argument("--qualification-run-id", required=True)
    c3_start.add_argument("--certificate-id", required=True)
    c3_start.add_argument("--actor", required=True)
    _add_occurred_at(c3_start)
    _set_handler(c3_start, _c3_start)

    c3_get = c3_commands.add_parser("get")
    c3_get.add_argument("--c3-run-id", required=True)
    _set_handler(c3_get, _c3_get)

    c3_verify = c3_commands.add_parser("verify")
    c3_verify.add_argument("--c3-run-id", required=True)
    _set_handler(c3_verify, _c3_verify)

    c3_decision = top.add_parser(
        "c3-decision",
        help="manage exact-byte independently signed C3 qualification decisions",
    )
    c3_decision_commands = c3_decision.add_subparsers(
        dest="c3_decision_command", required=True
    )

    c3_decision_snapshot = c3_decision_commands.add_parser("snapshot")
    c3_decision_snapshot.add_argument("--c3-run-id", required=True)
    _set_handler(c3_decision_snapshot, _c3_decision_snapshot)

    c3_decision_admit = c3_decision_commands.add_parser("admit")
    c3_decision_admit.add_argument("--c3-run-id", required=True)
    c3_decision_admit.add_argument("--key-id", required=True)
    c3_decision_admit.add_argument("--payload-file", required=True)
    c3_decision_admit.add_argument("--signature-file", required=True)
    c3_decision_admit.add_argument("--actor", required=True)
    _add_occurred_at(c3_decision_admit)
    _set_handler(c3_decision_admit, _c3_decision_admit)

    c3_decision_get = c3_decision_commands.add_parser("get")
    c3_decision_get.add_argument("--decision-id", required=True)
    _set_handler(c3_decision_get, _c3_decision_get)

    c3_decision_verify = c3_decision_commands.add_parser("verify")
    c3_decision_verify.add_argument("--decision-id", required=True)
    _set_handler(c3_decision_verify, _c3_decision_verify)

    architecture_review = top.add_parser(
        "architecture-review",
        help="operate the exact-byte non-publishing C4 architecture review",
    )
    architecture_review_commands = architecture_review.add_subparsers(
        dest="architecture_review_command",
        required=True,
    )

    architecture_review_prepare_root = architecture_review_commands.add_parser(
        "prepare-reviewer-root"
    )
    architecture_review_prepare_root.add_argument("--key-id", required=True)
    architecture_review_prepare_root.add_argument(
        "--reviewer-identity", required=True
    )
    architecture_review_prepare_root.add_argument(
        "--public-key-file", required=True
    )
    _set_handler(
        architecture_review_prepare_root,
        _architecture_review_prepare_root,
    )

    architecture_review_accept_root = architecture_review_commands.add_parser(
        "accept-reviewer-root"
    )
    architecture_review_accept_root.add_argument("--key-id", required=True)
    architecture_review_accept_root.add_argument(
        "--reviewer-identity", required=True
    )
    architecture_review_accept_root.add_argument(
        "--public-key-file", required=True
    )
    architecture_review_accept_root.add_argument(
        "--authorization-decision-id", required=True
    )
    architecture_review_accept_root.add_argument("--actor", required=True)
    _add_occurred_at(architecture_review_accept_root)
    _set_handler(
        architecture_review_accept_root,
        _architecture_review_accept_root,
    )

    architecture_review_admit = architecture_review_commands.add_parser("admit")
    architecture_review_admit.add_argument("--candidate-id", required=True)
    architecture_review_admit.add_argument("--key-id", required=True)
    architecture_review_admit.add_argument("--payload-file", required=True)
    architecture_review_admit.add_argument("--signature-file", required=True)
    architecture_review_admit.add_argument("--actor", required=True)
    _add_occurred_at(architecture_review_admit)
    _set_handler(architecture_review_admit, _architecture_review_admit)

    architecture_review_get = architecture_review_commands.add_parser("get")
    architecture_review_get.add_argument("--review-id", required=True)
    _set_handler(architecture_review_get, _architecture_review_get)

    architecture_review_verify_root = architecture_review_commands.add_parser(
        "verify-root"
    )
    architecture_review_verify_root.add_argument("--key-id", required=True)
    _set_handler(
        architecture_review_verify_root,
        _architecture_review_verify_root,
    )

    architecture_review_verify = architecture_review_commands.add_parser("verify")
    architecture_review_verify.add_argument("--review-id", required=True)
    _set_handler(architecture_review_verify, _architecture_review_verify)

    adoption = top.add_parser(
        "adoption",
        help="authorize one selected C3 candidate without executing adoption",
    )
    adoption_commands = adoption.add_subparsers(
        dest="adoption_command", required=True
    )

    adoption_prepare = adoption_commands.add_parser("prepare")
    adoption_prepare.add_argument("--c3-run-id", required=True)
    adoption_prepare.add_argument("--rollback-plan-json", required=True)
    _set_handler(adoption_prepare, _adoption_prepare)

    adoption_authorize = adoption_commands.add_parser("authorize")
    adoption_authorize.add_argument("--adoption-id", required=True)
    adoption_authorize.add_argument("--c3-run-id", required=True)
    adoption_authorize.add_argument(
        "--authorization-decision-id", required=True
    )
    adoption_authorize.add_argument("--rollback-plan-json", required=True)
    adoption_authorize.add_argument("--actor", required=True)
    _add_occurred_at(adoption_authorize)
    _set_handler(adoption_authorize, _adoption_authorize)

    adoption_get = adoption_commands.add_parser("get")
    adoption_get.add_argument("--adoption-id", required=True)
    _set_handler(adoption_get, _adoption_get)

    adoption_verify = adoption_commands.add_parser("verify")
    adoption_verify.add_argument("--adoption-id", required=True)
    _set_handler(adoption_verify, _adoption_verify)

    adoption_execution = top.add_parser(
        "adoption-execution",
        help="admit durable C3 execution requests without running a worker",
    )
    adoption_execution_commands = adoption_execution.add_subparsers(
        dest="adoption_execution_command",
        required=True,
    )

    execution_prepare = adoption_execution_commands.add_parser("prepare")
    execution_prepare.add_argument("--execution-id", required=True)
    execution_prepare.add_argument("--adoption-id", required=True)
    execution_prepare.add_argument("--executor-id", required=True)
    execution_prepare.add_argument("--execution-plan-json", required=True)
    _set_handler(execution_prepare, _adoption_execution_prepare)

    execution_request = adoption_execution_commands.add_parser("request")
    execution_request.add_argument("--execution-id", required=True)
    execution_request.add_argument("--adoption-id", required=True)
    execution_request.add_argument("--executor-id", required=True)
    execution_request.add_argument("--execution-plan-json", required=True)
    execution_request.add_argument(
        "--authorization-decision-id",
        required=True,
    )
    execution_request.add_argument("--actor", required=True)
    _add_occurred_at(execution_request)
    _set_handler(execution_request, _adoption_execution_request)

    execution_get = adoption_execution_commands.add_parser("get")
    execution_get.add_argument("--execution-id", required=True)
    _set_handler(execution_get, _adoption_execution_get)

    execution_verify = adoption_execution_commands.add_parser("verify")
    execution_verify.add_argument("--execution-id", required=True)
    _set_handler(execution_verify, _adoption_execution_verify)

    executor_registry = top.add_parser(
        "executor-registry",
        help="manage exact, qualified, enabled and revocable C3 executors",
    )
    executor_registry_commands = executor_registry.add_subparsers(
        dest="executor_registry_command",
        required=True,
    )

    registry_prepare_register = executor_registry_commands.add_parser(
        "prepare-register"
    )
    registry_prepare_register.add_argument("--descriptor-json", required=True)
    _set_handler(
        registry_prepare_register,
        _executor_registry_prepare_register,
    )

    registry_register = executor_registry_commands.add_parser("register")
    registry_register.add_argument("--descriptor-json", required=True)
    registry_register.add_argument(
        "--authorization-decision-id",
        required=True,
    )
    registry_register.add_argument("--actor", required=True)
    _add_occurred_at(registry_register)
    _set_handler(registry_register, _executor_registry_register)

    registry_prepare_root = executor_registry_commands.add_parser(
        "prepare-qualifier-root"
    )
    registry_prepare_root.add_argument("--key-id", required=True)
    registry_prepare_root.add_argument("--public-key-file", required=True)
    _set_handler(
        registry_prepare_root,
        _executor_registry_prepare_qualifier_root,
    )

    registry_accept_root = executor_registry_commands.add_parser(
        "accept-qualifier-root"
    )
    registry_accept_root.add_argument("--key-id", required=True)
    registry_accept_root.add_argument("--public-key-file", required=True)
    registry_accept_root.add_argument(
        "--authorization-decision-id",
        required=True,
    )
    registry_accept_root.add_argument("--actor", required=True)
    _add_occurred_at(registry_accept_root)
    _set_handler(
        registry_accept_root,
        _executor_registry_accept_qualifier_root,
    )

    registry_prepare_qualify = executor_registry_commands.add_parser(
        "prepare-qualify"
    )
    registry_prepare_qualify.add_argument("--executor-id", required=True)
    registry_prepare_qualify.add_argument("--key-id", required=True)
    registry_prepare_qualify.add_argument("--payload-file", required=True)
    registry_prepare_qualify.add_argument("--signature-file", required=True)
    _set_handler(
        registry_prepare_qualify,
        _executor_registry_prepare_qualify,
    )

    registry_qualify = executor_registry_commands.add_parser("qualify")
    registry_qualify.add_argument("--executor-id", required=True)
    registry_qualify.add_argument("--key-id", required=True)
    registry_qualify.add_argument("--payload-file", required=True)
    registry_qualify.add_argument("--signature-file", required=True)
    registry_qualify.add_argument(
        "--authorization-decision-id",
        required=True,
    )
    registry_qualify.add_argument("--actor", required=True)
    _add_occurred_at(registry_qualify)
    _set_handler(registry_qualify, _executor_registry_qualify)

    registry_prepare_enable = executor_registry_commands.add_parser(
        "prepare-enable"
    )
    registry_prepare_enable.add_argument("--executor-id", required=True)
    _set_handler(
        registry_prepare_enable,
        _executor_registry_prepare_enable,
    )

    registry_enable = executor_registry_commands.add_parser("enable")
    registry_enable.add_argument("--executor-id", required=True)
    registry_enable.add_argument(
        "--authorization-decision-id",
        required=True,
    )
    registry_enable.add_argument("--actor", required=True)
    _add_occurred_at(registry_enable)
    _set_handler(registry_enable, _executor_registry_enable)

    registry_prepare_revoke = executor_registry_commands.add_parser(
        "prepare-revoke"
    )
    registry_prepare_revoke.add_argument("--executor-id", required=True)
    registry_prepare_revoke.add_argument("--reason", required=True)
    _set_handler(
        registry_prepare_revoke,
        _executor_registry_prepare_revoke,
    )

    registry_revoke = executor_registry_commands.add_parser("revoke")
    registry_revoke.add_argument("--executor-id", required=True)
    registry_revoke.add_argument("--reason", required=True)
    registry_revoke.add_argument(
        "--authorization-decision-id",
        required=True,
    )
    registry_revoke.add_argument("--actor", required=True)
    _add_occurred_at(registry_revoke)
    _set_handler(registry_revoke, _executor_registry_revoke)

    registry_get = executor_registry_commands.add_parser("get")
    registry_get.add_argument("--executor-id", required=True)
    _set_handler(registry_get, _executor_registry_get)

    registry_verify = executor_registry_commands.add_parser("verify")
    registry_verify.add_argument("--executor-id", required=True)
    _set_handler(registry_verify, _executor_registry_verify)

    registry_attest = executor_registry_commands.add_parser("attest")
    registry_attest.add_argument("--executor-id", required=True)
    registry_attest.add_argument("--implementation-version", required=True)
    registry_attest.add_argument("--implementation-digest", required=True)
    registry_attest.add_argument("--sandbox-profile", required=True)
    registry_attest.add_argument(
        "--requires-network",
        action="store_true",
    )
    _set_handler(registry_attest, _executor_registry_attest)

    trust = top.add_parser("trust", help="manage default-deny policy and decisions")
    trust_commands = trust.add_subparsers(dest="trust_command", required=True)
    add_rule = trust_commands.add_parser("add-rule")
    add_rule.add_argument("--rule-id", required=True)
    add_rule.add_argument("--effect", required=True, choices=[item.value for item in PolicyEffect])
    add_rule.add_argument("--subject", required=True)
    add_rule.add_argument("--action", required=True)
    add_rule.add_argument("--resource", required=True)
    add_rule.add_argument("--conditions-json", default="{}")
    add_rule.add_argument("--priority", type=int, default=0)
    add_rule.add_argument("--actor", required=True)
    _add_occurred_at(add_rule)
    _set_handler(add_rule, _trust_add_rule)

    issue_grant = trust_commands.add_parser("issue-grant")
    issue_grant.add_argument("--grant-id", required=True)
    issue_grant.add_argument("--subject", required=True)
    issue_grant.add_argument("--action", required=True)
    issue_grant.add_argument("--resource", required=True)
    issue_grant.add_argument("--mission-id")
    issue_grant.add_argument("--expires-at", required=True)
    issue_grant.add_argument("--single-use", action="store_true")
    issue_grant.add_argument("--actor", required=True)
    _add_occurred_at(issue_grant)
    _set_handler(issue_grant, _trust_issue_grant)

    authorize = trust_commands.add_parser("authorize")
    authorize.add_argument("--subject", required=True)
    authorize.add_argument("--action", required=True)
    authorize.add_argument("--resource", required=True)
    authorize.add_argument("--mission-id")
    authorize.add_argument("--context-json", default="{}")
    authorize.add_argument("--at")
    authorize.add_argument("--no-consume", action="store_true")
    _set_handler(authorize, _trust_authorize)

    verify_decision = trust_commands.add_parser("verify-decision")
    verify_decision.add_argument("--decision-id", required=True)
    _set_handler(verify_decision, _trust_verify_decision)

    proof = top.add_parser("proof", help="manage claims, evidence, and certificates")
    proof_commands = proof.add_subparsers(dest="proof_command", required=True)
    create_claim = proof_commands.add_parser("create-claim")
    create_claim.add_argument("--claim-id")
    create_claim.add_argument("--subject-type", required=True)
    create_claim.add_argument("--subject-id", required=True)
    create_claim.add_argument("--statement", required=True)
    create_claim.add_argument("--author", required=True)
    create_claim.add_argument("--policy-version", required=True)
    _add_occurred_at(create_claim)
    _set_handler(create_claim, _proof_create_claim)

    get_claim = proof_commands.add_parser("get-claim")
    get_claim.add_argument("--claim-id", required=True)
    _set_handler(get_claim, _proof_get_claim)

    attach_evidence = proof_commands.add_parser("attach-evidence")
    attach_evidence.add_argument("--claim-id", required=True)
    attach_evidence.add_argument("--evidence-id")
    attach_evidence.add_argument("--kind", required=True)
    attach_evidence.add_argument("--uri", required=True)
    attach_evidence.add_argument("--digest", required=True)
    attach_evidence.add_argument("--metadata-json", default="{}")
    attach_evidence.add_argument("--attached-by", required=True)
    _add_occurred_at(attach_evidence)
    _set_handler(attach_evidence, _proof_attach_evidence)

    verify_claim = proof_commands.add_parser("verify-claim")
    verify_claim.add_argument("--claim-id", required=True)
    verify_claim.add_argument("--verifier", required=True)
    verify_claim.add_argument("--verdict", required=True, choices=[item.value for item in VerificationVerdict])
    verify_claim.add_argument("--notes", required=True)
    _add_occurred_at(verify_claim)
    _set_handler(verify_claim, _proof_verify_claim)

    certify_claim = proof_commands.add_parser("certify-claim")
    certify_claim.add_argument("--claim-id", required=True)
    certify_claim.add_argument("--certifier", required=True)
    _add_occurred_at(certify_claim)
    _set_handler(certify_claim, _proof_certify_claim)

    verify_certificate = proof_commands.add_parser("verify-certificate")
    verify_certificate.add_argument("--certificate-id", required=True)
    _set_handler(verify_certificate, _proof_verify_certificate)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    runtime: Runtime | None = None
    try:
        args = parser.parse_args(argv)
        if not hasattr(args, "handler"):
            parser.print_help()
            return 0
        args.db = _database_path(args.db)
        runtime = Runtime.open(args.db)
        result, exit_code = args.handler(runtime, args)
        _emit_success(result)
        return exit_code
    except StarcomError as exc:
        _emit_error(exc)
        return 2
    except Exception as exc:  # no tracebacks across the machine-readable CLI boundary
        if os.environ.get("STARCOM_DEBUG") == "1":
            raise
        _emit_error(
            StarcomError(
                "INTERNAL_ERROR",
                "unexpected internal failure",
                {"type": type(exc).__name__},
            )
        )
        return 1
    finally:
        if runtime is not None:
            runtime.close()
