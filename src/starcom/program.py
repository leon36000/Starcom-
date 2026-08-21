from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .adoption import C3AdoptionService
from .adoption_execution import C3AdoptionExecutionService
from .architecture import C4ArchitectureService
from .architecture_candidate import C4ArchitectureCandidateService
from .architecture_input import C4ArchitectureInputService
from .architecture_publication import C4ArchitecturePublicationService
from .architecture_review import C4ArchitectureReviewService
from .census import C2CensusService
from .certification import C2CertificationService
from .continuity import ContinuityService
from .continuity_types import SignatureVerifier
from .cockpit import CockpitService
from .creative import CreativeJobService
from .db import Database
from .deployment import DeploymentFabricService
from .durable import DurableOutbox
from .errors import NotFoundError, ValidationError
from .execution_plan import C5ExecutionPlanService
from .executor_registry import C3ExecutorRegistry
from .final_pack import C7FinalPackService
from .ledger import EventLedger
from .mission import MissionKernel
from .proof import ProofEngine
from .qualification import QualificationLab
from .qualification_decision import C3DecisionService
from .qualification_gate import C3QualificationGate
from .recollection import C2RecollectionService
from .red_team import C6RedTeamService
from .release_candidate import ReleaseCandidateService
from .research import ResearchCampaign
from .research_marathon import ResearchMarathonService
from .trust import TrustPlane


@dataclass(frozen=True)
class AuthorityDescriptor:
    name: str
    module: str
    class_name: str
    attribute: str
    dependencies: tuple[str, ...]


@dataclass(frozen=True)
class ProgramTruth:
    project_state: str = "RC_BLOCKED_EXTERNAL_EVIDENCE"
    release_status: str = "NOT_RELEASED"
    live_census_certification_status: str = "NOT_PROVEN"
    external_runtime_integration_status: str = "NOT_PROVEN"
    component_adoption_status: str = "NOT_PROVEN"
    real_deployment_status: str = "NOT_PROVEN"


@dataclass(frozen=True)
class ProgramVerification:
    defects: tuple[str, ...]
    foreign_keys_ok: bool
    schema_ok: bool
    catalog_ok: bool
    dependencies_ok: bool
    ledger_ok: bool
    surfaces_ok: bool
    canonical_truth_ok: bool
    checked_tables: tuple[str, ...]
    checked_streams: int
    truth: ProgramTruth

    @property
    def ok(self) -> bool:
        return not self.defects


_AUTHORITY_DESCRIPTORS = tuple(
    sorted(
        (
            AuthorityDescriptor(
                "core.proof", "starcom.proof", "ProofEngine", "proof", ("database", "ledger")
            ),
            AuthorityDescriptor(
                "core.missions",
                "starcom.mission",
                "MissionKernel",
                "missions",
                ("database", "ledger", "trust", "proof"),
            ),
            AuthorityDescriptor(
                "core.research",
                "starcom.research",
                "ResearchCampaign",
                "research",
                ("database", "ledger"),
            ),
            AuthorityDescriptor(
                "c1.continuity",
                "starcom.continuity",
                "ContinuityService",
                "continuity",
                ("database", "ledger", "trust"),
            ),
            AuthorityDescriptor(
                "c2.recollection",
                "starcom.recollection",
                "C2RecollectionService",
                "recollection",
                ("database", "ledger", "continuity", "research"),
            ),
            AuthorityDescriptor(
                "c2.census",
                "starcom.census",
                "C2CensusService",
                "census",
                ("database", "ledger", "recollection", "research"),
            ),
            AuthorityDescriptor(
                "c2.certification",
                "starcom.certification",
                "C2CertificationService",
                "certification",
                ("database", "ledger", "continuity", "recollection", "census"),
            ),
            AuthorityDescriptor(
                "c3.qualification",
                "starcom.qualification",
                "QualificationLab",
                "qualification",
                ("database", "ledger"),
            ),
            AuthorityDescriptor(
                "c3.gate",
                "starcom.qualification_gate",
                "C3QualificationGate",
                "c3",
                ("database", "ledger", "certification", "qualification"),
            ),
            AuthorityDescriptor(
                "c3.decision",
                "starcom.qualification_decision",
                "C3DecisionService",
                "c3_decision",
                ("database", "ledger", "continuity", "certification", "c3", "qualification"),
            ),
            AuthorityDescriptor(
                "c3.adoption",
                "starcom.adoption",
                "C3AdoptionService",
                "adoption",
                ("database", "ledger", "trust", "continuity", "c3_decision", "qualification"),
            ),
            AuthorityDescriptor(
                "c3.execution",
                "starcom.adoption_execution",
                "C3AdoptionExecutionService",
                "adoption_execution",
                ("database", "ledger", "trust", "continuity", "adoption", "outbox"),
            ),
            AuthorityDescriptor(
                "c3.executor_registry",
                "starcom.executor_registry",
                "C3ExecutorRegistry",
                "executor_registry",
                ("database", "ledger", "trust", "continuity"),
            ),
            AuthorityDescriptor(
                "c4.input",
                "starcom.architecture_input",
                "C4ArchitectureInputService",
                "architecture_input",
                ("database", "ledger", "trust", "continuity", "adoption_execution"),
            ),
            AuthorityDescriptor(
                "c4.candidate",
                "starcom.architecture_candidate",
                "C4ArchitectureCandidateService",
                "architecture_candidate",
                ("database", "ledger", "trust", "continuity", "architecture_input"),
            ),
            AuthorityDescriptor(
                "c4.review",
                "starcom.architecture_review",
                "C4ArchitectureReviewService",
                "architecture_review",
                (
                    "database",
                    "ledger",
                    "trust",
                    "continuity",
                    "architecture_input",
                    "architecture_candidate",
                ),
            ),
            AuthorityDescriptor(
                "c4.publication",
                "starcom.architecture_publication",
                "C4ArchitecturePublicationService",
                "architecture_publication",
                (
                    "database",
                    "ledger",
                    "trust",
                    "continuity",
                    "architecture_input",
                    "architecture_candidate",
                    "architecture_review",
                ),
            ),
            AuthorityDescriptor(
                "c4.architecture",
                "starcom.architecture",
                "C4ArchitectureService",
                "architecture",
                (
                    "database",
                    "ledger",
                    "trust",
                    "continuity",
                    "c3_decision",
                    "adoption",
                    "adoption_execution",
                ),
            ),
            AuthorityDescriptor(
                "c5.execution_plan",
                "starcom.execution_plan",
                "C5ExecutionPlanService",
                "execution_plan",
                ("database", "ledger", "trust", "continuity", "architecture"),
            ),
            AuthorityDescriptor(
                "c6.red_team",
                "starcom.red_team",
                "C6RedTeamService",
                "red_team",
                ("database", "ledger", "trust", "continuity", "execution_plan"),
            ),
            AuthorityDescriptor(
                "c7.final_pack",
                "starcom.final_pack",
                "C7FinalPackService",
                "final_pack",
                ("database", "ledger", "trust", "continuity", "architecture", "execution_plan", "red_team"),
            ),
            AuthorityDescriptor(
                "12a.research_marathon",
                "starcom.research_marathon",
                "ResearchMarathonService",
                "research_marathon",
                ("database", "ledger", "trust", "continuity", "final_pack", "research", "outbox"),
            ),
            AuthorityDescriptor(
                "16.creative_jobs",
                "starcom.creative",
                "CreativeJobService",
                "creative_jobs",
                ("database", "ledger", "trust", "outbox"),
            ),
            AuthorityDescriptor(
                "17.cockpit",
                "starcom.cockpit",
                "CockpitService",
                "cockpit",
                ("database", "ledger", "trust"),
            ),
            AuthorityDescriptor(
                "18.deployment",
                "starcom.deployment",
                "DeploymentFabricService",
                "deployment",
                ("database", "ledger", "trust", "continuity"),
            ),
            AuthorityDescriptor(
                "19.release_candidate",
                "starcom.release_candidate",
                "ReleaseCandidateService",
                "release_candidate",
                ("database", "ledger", "trust", "continuity"),
            ),
        ),
        key=lambda descriptor: descriptor.name,
    )
)
_AUTHORITY_BY_NAME = {descriptor.name: descriptor for descriptor in _AUTHORITY_DESCRIPTORS}
_ATTRIBUTE_TO_NAME = {
    descriptor.attribute: descriptor.name for descriptor in _AUTHORITY_DESCRIPTORS
}
_SHARED_COMPONENT_FIELDS = ("database", "ledger", "trust", "continuity", "outbox")
_FORBIDDEN_ROOT_SURFACE = frozenset({"run", "execute", "deploy", "release", "publish", "promote"})
_EXPECTED_TRUTH = ProgramTruth()
_EXPECTED_SCHEMA_TABLES = frozenset(
    {
        "block19_rc_assessments",
        "block19_rc_benchmarks",
        "block19_rc_evidence",
        "block19_rc_gates",
        "block19_rc_red_team_cases",
        "c2_census_identities",
        "c2_certification_members",
        "c2_certifications",
        "c2_recollections",
        "c3_adoption_execution_requests",
        "c3_adoption_execution_transitions",
        "c3_adoptions",
        "c3_decision_evidence",
        "c3_decisions",
        "c3_executor_descriptors",
        "c3_executor_qualifications",
        "c3_executor_qualifier_roots",
        "c3_executor_transitions",
        "c3_qualification_bindings",
        "c4_architecture_baseline_members",
        "c4_architecture_baselines",
        "c4_architecture_candidates",
        "c4_architecture_input_members",
        "c4_architecture_input_sets",
        "c4_architecture_publications",
        "c4_architecture_review_findings",
        "c4_architecture_reviewer_roots",
        "c4_architecture_reviews",
        "c5_execution_plan_release_gates",
        "c5_execution_plan_work_items",
        "c5_execution_plans",
        "c6_red_team_assessments",
        "c6_red_team_attack_cases",
        "c6_red_team_findings",
        "c7_final_pack_manifest",
        "c7_final_packs",
        "cockpit_command_transitions",
        "cockpit_commands",
        "cockpit_sessions",
        "cockpit_snapshots",
        "continuity_authorization_consumptions",
        "continuity_incidents",
        "continuity_recovery_publications",
        "continuity_reviews",
        "continuity_trust_roots",
        "creative_job_inputs",
        "creative_job_transitions",
        "creative_jobs",
        "deployment_assignments",
        "deployment_bundles",
        "deployment_nodes",
        "durable_effects",
        "ledger_events",
        "mission_transitions",
        "missions",
        "proof_certificates",
        "proof_claims",
        "proof_evidence",
        "proof_verifications",
        "qualification_artifacts",
        "qualification_runs",
        "research_attempts",
        "research_campaigns",
        "research_cursors",
        "research_marathon_completions",
        "research_marathon_partition_attempts",
        "research_marathon_partitions",
        "research_marathon_profiles",
        "research_marathon_transitions",
        "research_marathons",
        "research_observations",
        "research_receipts",
        "schema_meta",
        "trust_decisions",
        "trust_grants",
        "trust_policy_rules",
    }
)


@dataclass
class StarcomProgram:
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
    _components: Mapping[str, object] = field(init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        components: dict[str, object] = {
            "database": self.database,
            "ledger": self.ledger,
            "trust": self.trust,
            "continuity": self.continuity,
            "outbox": self.outbox,
        }
        for descriptor in _AUTHORITY_DESCRIPTORS:
            authority = getattr(self, descriptor.attribute)
            components[descriptor.name] = authority
            components[descriptor.attribute] = authority
        self._components = MappingProxyType(components)

    @property
    def catalog(self) -> tuple[AuthorityDescriptor, ...]:
        return _AUTHORITY_DESCRIPTORS

    @property
    def components(self) -> Mapping[str, object]:
        return self._components

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
    def open(
        cls,
        path: str | Path,
        signature_verifier: SignatureVerifier | None = None,
    ) -> StarcomProgram:
        database = Database(path)
        try:
            database.initialize()
            ledger = EventLedger(database)
            trust = TrustPlane(database, ledger)
            components: dict[str, object] = {
                "database": database,
                "ledger": ledger,
                "trust": trust,
            }

            def dependencies(authority: str, names: tuple[str, ...]) -> tuple[object, ...]:
                return cls._resolve_dependencies(authority, names, components)

            proof = ProofEngine(*dependencies("core.proof", ("database", "ledger")))
            components["proof"] = proof
            missions = MissionKernel(
                *dependencies("core.missions", ("database", "ledger", "trust", "proof"))
            )
            components["missions"] = missions
            research = ResearchCampaign(*dependencies("core.research", ("database", "ledger")))
            components["research"] = research
            continuity = ContinuityService(
                *dependencies("c1.continuity", ("database", "ledger", "trust")),
                signature_verifier,
            )
            components["continuity"] = continuity
            recollection = C2RecollectionService(
                *dependencies("c2.recollection", ("database", "ledger", "continuity", "research"))
            )
            components["recollection"] = recollection
            census = C2CensusService(
                *dependencies("c2.census", ("database", "ledger", "recollection", "research"))
            )
            components["census"] = census
            certification = C2CertificationService(
                *dependencies(
                    "c2.certification",
                    ("database", "ledger", "continuity", "recollection", "census"),
                )
            )
            components["certification"] = certification
            qualification = QualificationLab(*dependencies("c3.qualification", ("database", "ledger")))
            components["qualification"] = qualification
            c3 = C3QualificationGate(
                *dependencies("c3.gate", ("database", "ledger", "certification", "qualification"))
            )
            components["c3"] = c3
            c3_decision = C3DecisionService(
                *dependencies(
                    "c3.decision",
                    ("database", "ledger", "continuity", "certification", "c3", "qualification"),
                )
            )
            components["c3_decision"] = c3_decision
            adoption = C3AdoptionService(
                *dependencies(
                    "c3.adoption",
                    ("database", "ledger", "trust", "continuity", "c3_decision", "qualification"),
                )
            )
            components["adoption"] = adoption
            outbox = DurableOutbox(*dependencies("core.outbox", ("database", "ledger")))
            components["outbox"] = outbox
            adoption_execution = C3AdoptionExecutionService(
                *dependencies(
                    "c3.execution",
                    ("database", "ledger", "trust", "continuity", "adoption", "outbox"),
                )
            )
            components["adoption_execution"] = adoption_execution
            executor_registry = C3ExecutorRegistry(
                *dependencies("c3.executor_registry", ("database", "ledger", "trust", "continuity"))
            )
            components["executor_registry"] = executor_registry
            architecture_input = C4ArchitectureInputService(
                *dependencies(
                    "c4.input",
                    ("database", "ledger", "trust", "continuity", "adoption_execution"),
                )
            )
            components["architecture_input"] = architecture_input
            architecture_candidate = C4ArchitectureCandidateService(
                *dependencies(
                    "c4.candidate",
                    ("database", "ledger", "trust", "continuity", "architecture_input"),
                )
            )
            components["architecture_candidate"] = architecture_candidate
            architecture_review = C4ArchitectureReviewService(
                *dependencies(
                    "c4.review",
                    (
                        "database",
                        "ledger",
                        "trust",
                        "continuity",
                        "architecture_input",
                        "architecture_candidate",
                    ),
                ),
                signature_verifier=signature_verifier,
            )
            components["architecture_review"] = architecture_review
            architecture_publication = C4ArchitecturePublicationService(
                *dependencies(
                    "c4.publication",
                    (
                        "database",
                        "ledger",
                        "trust",
                        "continuity",
                        "architecture_input",
                        "architecture_candidate",
                        "architecture_review",
                    ),
                )
            )
            components["architecture_publication"] = architecture_publication
            architecture = C4ArchitectureService(
                *dependencies(
                    "c4.architecture",
                    (
                        "database",
                        "ledger",
                        "trust",
                        "continuity",
                        "c3_decision",
                        "adoption",
                        "adoption_execution",
                    ),
                ),
                signature_verifier=signature_verifier,
            )
            components["architecture"] = architecture
            execution_plan = C5ExecutionPlanService(
                *dependencies(
                    "c5.execution_plan",
                    ("database", "ledger", "trust", "continuity", "architecture"),
                ),
                signature_verifier=signature_verifier,
            )
            components["execution_plan"] = execution_plan
            red_team = C6RedTeamService(
                *dependencies(
                    "c6.red_team",
                    ("database", "ledger", "trust", "continuity", "execution_plan"),
                ),
                signature_verifier=signature_verifier,
            )
            components["red_team"] = red_team
            final_pack = C7FinalPackService(
                *dependencies(
                    "c7.final_pack",
                    ("database", "ledger", "trust", "continuity", "architecture", "execution_plan", "red_team"),
                ),
                signature_verifier=signature_verifier,
            )
            components["final_pack"] = final_pack
            research_marathon = ResearchMarathonService(
                *dependencies(
                    "12a.research_marathon",
                    ("database", "ledger", "trust", "continuity", "final_pack", "research", "outbox"),
                ),
                signature_verifier=signature_verifier,
            )
            components["research_marathon"] = research_marathon
            creative_jobs = CreativeJobService(
                *dependencies("16.creative_jobs", ("database", "ledger", "trust", "outbox"))
            )
            components["creative_jobs"] = creative_jobs
            cockpit = CockpitService(*dependencies("17.cockpit", ("database", "ledger", "trust")))
            components["cockpit"] = cockpit
            deployment = DeploymentFabricService(
                *dependencies("18.deployment", ("database", "ledger", "trust", "continuity"))
            )
            components["deployment"] = deployment
            release_candidate = ReleaseCandidateService(
                *dependencies("19.release_candidate", ("database", "ledger", "trust", "continuity")),
                signature_verifier=signature_verifier,
            )
            components["release_candidate"] = release_candidate
            return cls(
                database=database,
                ledger=ledger,
                trust=trust,
                proof=proof,
                missions=missions,
                research=research,
                continuity=continuity,
                recollection=recollection,
                census=census,
                certification=certification,
                qualification=qualification,
                c3=c3,
                c3_decision=c3_decision,
                adoption=adoption,
                outbox=outbox,
                adoption_execution=adoption_execution,
                executor_registry=executor_registry,
                architecture_input=architecture_input,
                architecture_candidate=architecture_candidate,
                architecture_review=architecture_review,
                architecture_publication=architecture_publication,
                architecture=architecture,
                execution_plan=execution_plan,
                red_team=red_team,
                final_pack=final_pack,
                research_marathon=research_marathon,
                creative_jobs=creative_jobs,
                cockpit=cockpit,
                deployment=deployment,
                release_candidate=release_candidate,
            )
        except BaseException:
            database.close()
            raise

    @staticmethod
    def _resolve_dependencies(
        authority: str,
        dependency_names: tuple[str, ...],
        components: Mapping[str, object],
    ) -> tuple[object, ...]:
        if len(dependency_names) != len(set(dependency_names)):
            duplicates = sorted(
                name
                for name in set(dependency_names)
                if dependency_names.count(name) > 1
            )
            raise ValidationError(
                "authority dependency names must be unique",
                {"authority": authority, "duplicate_dependencies": duplicates},
            )
        missing = sorted(set(dependency_names) - set(components))
        if missing:
            raise ValidationError(
                "mandatory authority dependency is unknown",
                {"authority": authority, "missing_dependencies": missing},
            )
        return tuple(components[name] for name in dependency_names)

    def authority(self, name: str) -> object:
        if name in _AUTHORITY_BY_NAME:
            attribute = _AUTHORITY_BY_NAME[name].attribute
        elif name in _ATTRIBUTE_TO_NAME:
            attribute = name
        elif name in {"database", "ledger", "trust", "continuity", "outbox"}:
            return getattr(self, name)
        else:
            raise NotFoundError("unknown STARCOM program authority", {"name": name})
        return getattr(self, attribute)

    def verify(self) -> ProgramVerification:
        foreign_key_defects: list[str] = []
        schema_defects: list[str] = []
        catalog_defects: list[str] = []
        dependency_defects: list[str] = []
        ledger_defects: list[str] = []
        surface_defects: list[str] = []
        truth = ProgramTruth()

        foreign_keys_enabled = bool(
            self.database.connection.execute("PRAGMA foreign_keys").fetchone()[0]
        )
        if not foreign_keys_enabled:
            foreign_key_defects.append("FOREIGN_KEYS_DISABLED")
        for row in self.database.connection.execute("PRAGMA foreign_key_check").fetchall():
            foreign_key_defects.append(
                "FOREIGN_KEY_VIOLATION:{table}:{rowid}:{parent}".format(
                    table=row["table"], rowid=row["rowid"], parent=row["parent"]
                )
            )

        table_rows = self.database.connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        checked_tables = tuple(sorted(str(row["name"]) for row in table_rows))
        actual_tables = set(checked_tables)
        for table in sorted(_EXPECTED_SCHEMA_TABLES - actual_tables):
            schema_defects.append(f"SCHEMA_TABLE_MISSING:{table}")
        for table in sorted(actual_tables - _EXPECTED_SCHEMA_TABLES):
            schema_defects.append(f"SCHEMA_TABLE_UNEXPECTED:{table}")

        catalog_names = tuple(descriptor.name for descriptor in self.catalog)
        if catalog_names != tuple(sorted(catalog_names)):
            catalog_defects.append("CATALOG_NOT_SORTED")
        if len(catalog_names) != len(set(catalog_names)):
            catalog_defects.append("CATALOG_DUPLICATE_AUTHORITY")
        if set(catalog_names) != set(_AUTHORITY_BY_NAME):
            catalog_defects.append("CATALOG_INCOMPLETE")
        for descriptor in self.catalog:
            authority = getattr(self, descriptor.attribute, None)
            if authority is None:
                catalog_defects.append(f"CATALOG_AUTHORITY_MISSING:{descriptor.name}")
                continue
            if (
                type(authority).__module__ != descriptor.module
                or type(authority).__name__ != descriptor.class_name
            ):
                catalog_defects.append(f"CATALOG_IMPLEMENTATION_MISMATCH:{descriptor.name}")
            if descriptor.attribute not in self._components:
                catalog_defects.append(f"CATALOG_ATTRIBUTE_MISSING:{descriptor.name}")
            if len(descriptor.dependencies) != len(set(descriptor.dependencies)):
                catalog_defects.append(f"CATALOG_DEPENDENCY_DUPLICATE:{descriptor.name}")
            for dependency in descriptor.dependencies:
                if dependency not in self._components:
                    dependency_defects.append(
                        f"DEPENDENCY_UNKNOWN:{descriptor.name}:{dependency}"
                    )
            for field_name in _SHARED_COMPONENT_FIELDS:
                if hasattr(authority, field_name) and getattr(authority, field_name) is not getattr(
                    self, field_name
                ):
                    dependency_defects.append(
                        f"SHARED_INSTANCE_MISMATCH:{descriptor.name}:{field_name}"
                    )

        ledger_verification = self.ledger.verify()
        for defect in ledger_verification.defects:
            code = getattr(defect, "code", str(defect))
            ledger_defects.append(f"LEDGER_INVALID:{code}")

        for forbidden in sorted(_FORBIDDEN_ROOT_SURFACE.intersection(dir(self))):
            surface_defects.append(f"FORBIDDEN_ROOT_SURFACE:{forbidden}")
        canonical_truth_ok = truth == _EXPECTED_TRUTH
        if not canonical_truth_ok:
            surface_defects.append("CANONICAL_TRUTH_MISMATCH")

        defects = tuple(
            sorted(
                {
                    *foreign_key_defects,
                    *schema_defects,
                    *catalog_defects,
                    *dependency_defects,
                    *ledger_defects,
                    *surface_defects,
                }
            )
        )
        return ProgramVerification(
            defects=defects,
            foreign_keys_ok=not foreign_key_defects,
            schema_ok=not schema_defects,
            catalog_ok=not catalog_defects,
            dependencies_ok=not dependency_defects,
            ledger_ok=not ledger_defects,
            surfaces_ok=not surface_defects,
            canonical_truth_ok=canonical_truth_ok,
            checked_tables=checked_tables,
            checked_streams=ledger_verification.checked_streams,
            truth=truth,
        )

    def close(self) -> None:
        if not self._closed:
            self.database.close()
            self._closed = True


__all__ = [
    "AuthorityDescriptor",
    "ProgramTruth",
    "ProgramVerification",
    "StarcomProgram",
]
