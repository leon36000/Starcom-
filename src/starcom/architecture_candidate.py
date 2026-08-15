from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import json
import re
import sqlite3
from typing import Any, Mapping

from .adoption_execution import C3AdoptionExecutionStatus
from .architecture_input import C4ArchitectureInputService
from .canonical import canonical_json, sha256_digest, utc_now
from .continuity import ContinuityService
from .db import Database
from .errors import (
    AuthorizationError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    StateTransitionError,
    ValidationError,
)
from .ledger import EventLedger
from .trust import AuthorizationDecision, TrustPlane


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_STAGE_ORDER = ("RESEARCH", "ARTIFACT", "ACTION", "MONITOR")
_CANDIDATE_EVENT_KIND = "C4_ARCHITECTURE_CANDIDATE_CREATED"
_CANDIDATE_GATE_EFFECT = "C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED"
_TOP_FIELDS = frozenset(
    {
        "architecture_id",
        "architecture_version",
        "title",
        "authority_adrs",
        "ports",
        "mission_fabric",
        "component_bindings",
        "vertical_benchmark",
        "non_functional_requirements",
        "gate_effect",
    }
)
_ADR_FIELDS = frozenset(
    {
        "adr_id",
        "title",
        "decision",
        "rationale",
        "authority_owner",
        "affected_port_ids",
        "evidence_execution_ids",
    }
)
_PORT_FIELDS = frozenset(
    {
        "port_id",
        "capability_id",
        "owner_authority",
        "contract_digest",
        "test_ids",
        "proof_ids",
    }
)
_BINDING_FIELDS = frozenset(
    {
        "binding_id",
        "execution_id",
        "candidate_artifact_id",
        "candidate_material_sha256",
        "port_ids",
        "capability_ids",
    }
)
_BENCHMARK_FIELDS = frozenset(
    {
        "benchmark_id",
        "stage_order",
        "stage_test_ids",
        "stage_proof_ids",
        "end_to_end_test_id",
        "end_to_end_proof_id",
    }
)
_NFR_FIELDS = frozenset(
    {
        "requirement_id",
        "category",
        "statement",
        "verification_method",
        "test_ids",
        "proof_ids",
    }
)


class C4ArchitectureCandidateStatus(str, Enum):
    NOT_REVIEWED = _CANDIDATE_GATE_EFFECT


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
    """Create immutable, explicitly authorized, unreviewed STARCOM v3.2 candidates."""

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
        self._initialize_schema()

    @staticmethod
    def _required_text(value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{field} must be a non-empty string")
        return value

    @staticmethod
    def _timestamp(value: object, field: str = "timestamp") -> str:
        if not isinstance(value, str):
            raise ValidationError(f"{field} must be RFC 3339")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError(f"{field} must be RFC 3339") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValidationError(f"{field} must be timezone-aware")
        return value

    @staticmethod
    def _as_datetime(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    @staticmethod
    def _digest(value: object, field: str) -> str:
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
        return value

    @classmethod
    def _closed_object(
        cls,
        value: object,
        fields: frozenset[str],
        field: str,
    ) -> dict[str, object]:
        if not isinstance(value, Mapping):
            raise ValidationError(f"{field} must be a JSON object")
        observed = frozenset(value)
        if observed != fields:
            raise ValidationError(
                f"{field} fields do not match the required contract",
                {
                    "missing": sorted(fields - observed),
                    "unexpected": sorted(observed - fields),
                },
            )
        return dict(value)

    @classmethod
    def _sorted_strings(
        cls,
        value: object,
        field: str,
        *,
        allow_empty: bool = False,
    ) -> tuple[str, ...]:
        if not isinstance(value, list) or (not allow_empty and not value):
            qualifier = "" if allow_empty else "non-empty "
            raise ValidationError(f"{field} must be a {qualifier}list")
        normalized = tuple(cls._required_text(item, field) for item in value)
        if tuple(sorted(normalized)) != normalized:
            raise ValidationError(f"{field} must be sorted")
        if len(set(normalized)) != len(normalized):
            raise ValidationError(f"{field} must be duplicate-free")
        return normalized

    @classmethod
    def _sorted_objects(
        cls,
        value: object,
        field: str,
        *,
        identity_field: str,
        allow_empty: bool = False,
    ) -> list[dict[str, object]]:
        if not isinstance(value, list) or (not allow_empty and not value):
            qualifier = "" if allow_empty else "non-empty "
            raise ValidationError(f"{field} must be a {qualifier}list")
        objects: list[dict[str, object]] = []
        identities: list[str] = []
        for item in value:
            if not isinstance(item, Mapping):
                raise ValidationError(f"{field} entries must be JSON objects")
            copied = dict(item)
            identities.append(
                cls._required_text(copied.get(identity_field), identity_field)
            )
            objects.append(copied)
        if identities != sorted(identities):
            raise ValidationError(f"{field} must be sorted by {identity_field}")
        if len(set(identities)) != len(identities):
            raise ValidationError(f"{field} {identity_field} values must be unique")
        return objects

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c4_architecture_candidates (
                    candidate_id TEXT PRIMARY KEY,
                    architecture_id TEXT NOT NULL UNIQUE,
                    architecture_version TEXT NOT NULL
                        CHECK (architecture_version = '3.2'),
                    input_set_id TEXT NOT NULL,
                    input_set_digest TEXT NOT NULL
                        CHECK (length(input_set_digest) = 64),
                    manifest_json TEXT NOT NULL,
                    manifest_sha256 TEXT NOT NULL
                        CHECK (length(manifest_sha256) = 64),
                    adr_count INTEGER NOT NULL CHECK (adr_count >= 1),
                    port_count INTEGER NOT NULL CHECK (port_count >= 1),
                    binding_count INTEGER NOT NULL CHECK (binding_count >= 1),
                    nfr_count INTEGER NOT NULL CHECK (nfr_count >= 1),
                    stage_order_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status = 'C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED'
                    ),
                    authorization_decision_id TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (authorization_decision_id)
                        REFERENCES trust_decisions(decision_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS
                    c4_architecture_candidates_no_update
                BEFORE UPDATE ON c4_architecture_candidates
                BEGIN SELECT RAISE(
                    ABORT, 'c4 architecture candidate rows are immutable'
                ); END
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS
                    c4_architecture_candidates_no_delete
                BEFORE DELETE ON c4_architecture_candidates
                BEGIN SELECT RAISE(
                    ABORT, 'c4 architecture candidate rows are immutable'
                ); END
                """
            )

    @staticmethod
    def _stream(candidate_id: str) -> str:
        return f"continuity:c4:architecture-candidate:{candidate_id}"

    def _normalize_adrs(
        self,
        value: object,
        *,
        input_execution_ids: set[str],
    ) -> list[dict[str, object]]:
        objects = self._sorted_objects(
            value,
            "authority_adrs",
            identity_field="adr_id",
        )
        normalized: list[dict[str, object]] = []
        for item in objects:
            item = self._closed_object(item, _ADR_FIELDS, "authority ADR")
            evidence_ids = self._sorted_strings(
                item["evidence_execution_ids"],
                "evidence_execution_ids",
            )
            unknown = sorted(set(evidence_ids) - input_execution_ids)
            if unknown:
                raise StateTransitionError(
                    "authority ADR references execution outside the frozen input set",
                    {"execution_ids": unknown},
                )
            normalized.append(
                {
                    "adr_id": self._required_text(item["adr_id"], "adr_id"),
                    "title": self._required_text(item["title"], "title"),
                    "decision": self._required_text(
                        item["decision"], "decision"
                    ),
                    "rationale": self._required_text(
                        item["rationale"], "rationale"
                    ),
                    "authority_owner": self._required_text(
                        item["authority_owner"], "authority_owner"
                    ),
                    "affected_port_ids": list(
                        self._sorted_strings(
                            item["affected_port_ids"],
                            "affected_port_ids",
                        )
                    ),
                    "evidence_execution_ids": list(evidence_ids),
                }
            )
        return normalized

    def _normalize_ports(
        self,
        value: object,
    ) -> list[dict[str, object]]:
        objects = self._sorted_objects(value, "ports", identity_field="port_id")
        normalized: list[dict[str, object]] = []
        capability_ids: set[str] = set()
        for item in objects:
            item = self._closed_object(item, _PORT_FIELDS, "port")
            capability_id = self._required_text(
                item["capability_id"], "capability_id"
            )
            if capability_id in capability_ids:
                raise ValidationError("capability_id values must be unique")
            capability_ids.add(capability_id)
            normalized.append(
                {
                    "port_id": self._required_text(item["port_id"], "port_id"),
                    "capability_id": capability_id,
                    "owner_authority": self._required_text(
                        item["owner_authority"], "owner_authority"
                    ),
                    "contract_digest": self._digest(
                        item["contract_digest"], "contract_digest"
                    ),
                    "test_ids": list(
                        self._sorted_strings(item["test_ids"], "test_ids")
                    ),
                    "proof_ids": list(
                        self._sorted_strings(item["proof_ids"], "proof_ids")
                    ),
                }
            )
        return normalized

    def _validate_ownership(
        self,
        adrs: list[dict[str, object]],
        ports: list[dict[str, object]],
    ) -> None:
        port_ids = {str(port["port_id"]) for port in ports}
        for adr in adrs:
            unknown = sorted(
                set(str(item) for item in adr["affected_port_ids"]) - port_ids
            )
            if unknown:
                raise StateTransitionError(
                    "authority ADR references unknown port",
                    {"port_ids": unknown},
                )
        for port in ports:
            port_id = str(port["port_id"])
            owner = str(port["owner_authority"])
            matching = any(
                str(adr["authority_owner"]) == owner
                and port_id in adr["affected_port_ids"]
                for adr in adrs
            )
            if not matching:
                raise StateTransitionError(
                    "port owner lacks matching authority ADR",
                    {"port_id": port_id, "owner_authority": owner},
                )

    def _normalize_mission_fabric(
        self,
        value: object,
        *,
        port_ids: set[str],
    ) -> dict[str, object]:
        fabric = self._closed_object(
            value,
            frozenset(_STAGE_ORDER),
            "mission_fabric",
        )
        normalized: dict[str, object] = {}
        referenced: set[str] = set()
        for stage in _STAGE_ORDER:
            stage_ports = self._sorted_strings(
                fabric[stage],
                f"mission_fabric.{stage}",
            )
            unknown = sorted(set(stage_ports) - port_ids)
            if unknown:
                raise StateTransitionError(
                    "mission fabric references unknown port",
                    {"stage": stage, "port_ids": unknown},
                )
            referenced.update(stage_ports)
            normalized[stage] = list(stage_ports)
        missing = sorted(port_ids - referenced)
        if missing:
            raise StateTransitionError(
                "architecture port is orphaned from the mission fabric",
                {"port_ids": missing},
            )
        return normalized

    def _normalize_bindings(
        self,
        value: object,
        *,
        input_members: tuple[Mapping[str, Any], ...],
        ports_by_id: dict[str, dict[str, object]],
    ) -> list[dict[str, object]]:
        objects = self._sorted_objects(
            value,
            "component_bindings",
            identity_field="binding_id",
            allow_empty=True,
        )
        members_by_execution = {
            str(member["execution_id"]): member
            for member in input_members
        }
        successful_ids = {
            execution_id
            for execution_id, member in members_by_execution.items()
            if member.get("status")
            == C3AdoptionExecutionStatus.SUCCEEDED.value
        }
        normalized: list[dict[str, object]] = []
        bound_execution_ids: list[str] = []
        for item in objects:
            item = self._closed_object(
                item,
                _BINDING_FIELDS,
                "component binding",
            )
            execution_id = self._required_text(
                item["execution_id"], "execution_id"
            )
            member = members_by_execution.get(execution_id)
            if member is None:
                raise StateTransitionError(
                    "component binding references execution outside the frozen input set",
                    {"execution_id": execution_id},
                )
            if member.get("status") != C3AdoptionExecutionStatus.SUCCEEDED.value:
                raise StateTransitionError(
                    "component binding requires a successful frozen execution",
                    {"execution_id": execution_id},
                )
            candidate_id = self._required_text(
                item["candidate_artifact_id"],
                "candidate_artifact_id",
            )
            candidate_digest = self._digest(
                item["candidate_material_sha256"],
                "candidate_material_sha256",
            )
            if (
                candidate_id != member.get("candidate_artifact_id")
                or candidate_digest != member.get("candidate_material_sha256")
            ):
                raise StateTransitionError(
                    "component binding candidate does not match frozen execution",
                    {"execution_id": execution_id},
                )
            port_ids = self._sorted_strings(item["port_ids"], "port_ids")
            unknown_ports = sorted(set(port_ids) - set(ports_by_id))
            if unknown_ports:
                raise StateTransitionError(
                    "component binding references unknown port",
                    {"port_ids": unknown_ports},
                )
            expected_capabilities = tuple(
                sorted(
                    {
                        str(ports_by_id[port_id]["capability_id"])
                        for port_id in port_ids
                    }
                )
            )
            capability_ids = self._sorted_strings(
                item["capability_ids"],
                "capability_ids",
            )
            if capability_ids != expected_capabilities:
                raise StateTransitionError(
                    "component binding capability set does not match its ports",
                    {
                        "binding_id": item["binding_id"],
                        "expected": list(expected_capabilities),
                        "observed": list(capability_ids),
                    },
                )
            bound_execution_ids.append(execution_id)
            normalized.append(
                {
                    "binding_id": self._required_text(
                        item["binding_id"], "binding_id"
                    ),
                    "execution_id": execution_id,
                    "candidate_artifact_id": candidate_id,
                    "candidate_material_sha256": candidate_digest,
                    "port_ids": list(port_ids),
                    "capability_ids": list(capability_ids),
                }
            )
        if len(bound_execution_ids) != len(set(bound_execution_ids)):
            raise StateTransitionError(
                "successful execution may appear in only one component binding"
            )
        if set(bound_execution_ids) != successful_ids:
            raise StateTransitionError(
                "every successful execution requires exactly one component binding",
                {
                    "expected": sorted(successful_ids),
                    "observed": sorted(bound_execution_ids),
                },
            )
        return normalized

    def _normalize_benchmark(
        self,
        value: object,
        *,
        mission_fabric: Mapping[str, object],
        ports_by_id: dict[str, dict[str, object]],
    ) -> dict[str, object]:
        benchmark = self._closed_object(
            value,
            _BENCHMARK_FIELDS,
            "vertical_benchmark",
        )
        raw_stage_order = benchmark["stage_order"]
        if (
            not isinstance(raw_stage_order, list)
            or not all(isinstance(item, str) for item in raw_stage_order)
        ):
            raise ValidationError(
                "vertical benchmark stage_order must be a list of strings"
            )
        stage_order = tuple(raw_stage_order)
        if stage_order != _STAGE_ORDER:
            raise ValidationError(
                "vertical benchmark stage_order must be "
                "RESEARCH, ARTIFACT, ACTION, MONITOR"
            )
        stage_tests = self._closed_object(
            benchmark["stage_test_ids"],
            frozenset(_STAGE_ORDER),
            "vertical_benchmark.stage_test_ids",
        )
        stage_proofs = self._closed_object(
            benchmark["stage_proof_ids"],
            frozenset(_STAGE_ORDER),
            "vertical_benchmark.stage_proof_ids",
        )
        normalized_tests: dict[str, object] = {}
        normalized_proofs: dict[str, object] = {}
        for stage in _STAGE_ORDER:
            observed_tests = self._sorted_strings(
                stage_tests[stage],
                f"vertical_benchmark.stage_test_ids.{stage}",
            )
            observed_proofs = self._sorted_strings(
                stage_proofs[stage],
                f"vertical_benchmark.stage_proof_ids.{stage}",
            )
            stage_port_ids = tuple(
                str(item) for item in mission_fabric[stage]
            )
            exposed_tests = {
                str(test_id)
                for port_id in stage_port_ids
                for test_id in ports_by_id[port_id]["test_ids"]
            }
            exposed_proofs = {
                str(proof_id)
                for port_id in stage_port_ids
                for proof_id in ports_by_id[port_id]["proof_ids"]
            }
            if not set(observed_tests).issubset(exposed_tests):
                raise StateTransitionError(
                    "vertical benchmark stage tests are not exposed by mission ports",
                    {"stage": stage},
                )
            if not set(observed_proofs).issubset(exposed_proofs):
                raise StateTransitionError(
                    "vertical benchmark stage proofs are not exposed by mission ports",
                    {"stage": stage},
                )
            normalized_tests[stage] = list(observed_tests)
            normalized_proofs[stage] = list(observed_proofs)
        return {
            "benchmark_id": self._required_text(
                benchmark["benchmark_id"], "benchmark_id"
            ),
            "stage_order": list(stage_order),
            "stage_test_ids": normalized_tests,
            "stage_proof_ids": normalized_proofs,
            "end_to_end_test_id": self._required_text(
                benchmark["end_to_end_test_id"],
                "end_to_end_test_id",
            ),
            "end_to_end_proof_id": self._required_text(
                benchmark["end_to_end_proof_id"],
                "end_to_end_proof_id",
            ),
        }

    def _normalize_nfrs(self, value: object) -> list[dict[str, object]]:
        objects = self._sorted_objects(
            value,
            "non_functional_requirements",
            identity_field="requirement_id",
        )
        normalized: list[dict[str, object]] = []
        for item in objects:
            item = self._closed_object(
                item,
                _NFR_FIELDS,
                "non-functional requirement",
            )
            normalized.append(
                {
                    "requirement_id": self._required_text(
                        item["requirement_id"], "requirement_id"
                    ),
                    "category": self._required_text(
                        item["category"], "category"
                    ),
                    "statement": self._required_text(
                        item["statement"], "statement"
                    ),
                    "verification_method": self._required_text(
                        item["verification_method"],
                        "verification_method",
                    ),
                    "test_ids": list(
                        self._sorted_strings(item["test_ids"], "test_ids")
                    ),
                    "proof_ids": list(
                        self._sorted_strings(item["proof_ids"], "proof_ids")
                    ),
                }
            )
        return normalized

    def _normalize_manifest(
        self,
        manifest: Mapping[str, Any],
        *,
        input_members: tuple[Mapping[str, Any], ...],
    ) -> tuple[dict[str, object], str, str]:
        top = self._closed_object(manifest, _TOP_FIELDS, "architecture manifest")
        architecture_id = self._required_text(
            top["architecture_id"], "architecture_id"
        )
        version = self._required_text(
            top["architecture_version"], "architecture_version"
        )
        if version != "3.2":
            raise ValidationError("architecture_version must equal 3.2")
        if top["gate_effect"] != _CANDIDATE_GATE_EFFECT:
            raise ValidationError(
                "gate_effect must equal C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED"
            )
        input_execution_ids = {
            str(member["execution_id"])
            for member in input_members
        }
        adrs = self._normalize_adrs(
            top["authority_adrs"],
            input_execution_ids=input_execution_ids,
        )
        ports = self._normalize_ports(top["ports"])
        self._validate_ownership(adrs, ports)
        ports_by_id = {str(port["port_id"]): port for port in ports}
        mission_fabric = self._normalize_mission_fabric(
            top["mission_fabric"],
            port_ids=set(ports_by_id),
        )
        bindings = self._normalize_bindings(
            top["component_bindings"],
            input_members=input_members,
            ports_by_id=ports_by_id,
        )
        benchmark = self._normalize_benchmark(
            top["vertical_benchmark"],
            mission_fabric=mission_fabric,
            ports_by_id=ports_by_id,
        )
        nfrs = self._normalize_nfrs(top["non_functional_requirements"])
        normalized: dict[str, object] = {
            "architecture_id": architecture_id,
            "architecture_version": version,
            "title": self._required_text(top["title"], "title"),
            "authority_adrs": adrs,
            "ports": ports,
            "mission_fabric": mission_fabric,
            "component_bindings": bindings,
            "vertical_benchmark": benchmark,
            "non_functional_requirements": nfrs,
            "gate_effect": _CANDIDATE_GATE_EFFECT,
        }
        serialized = canonical_json(normalized)
        return normalized, serialized, sha256_digest(normalized)

    def _clean_input(
        self,
        input_set_id: str,
    ) -> tuple[object, tuple[Mapping[str, Any], ...]]:
        input_set = self.inputs.get_input_set(input_set_id)
        verification = self.inputs.verify_input_set(input_set_id)
        if not verification.ok:
            raise IntegrityError(
                "C4 architecture input set failed verification",
                {
                    "input_set_id": input_set_id,
                    "defects": list(verification.defects),
                },
            )
        members = self.inputs.get_members(input_set_id)
        return input_set, members

    @staticmethod
    def _context(
        preparation_fields: Mapping[str, object],
    ) -> dict[str, object]:
        return {
            **dict(preparation_fields),
            "gate_effect": _CANDIDATE_GATE_EFFECT,
        }

    def prepare_create(
        self,
        candidate_id: str,
        *,
        input_set_id: str,
        manifest: Mapping[str, Any],
    ) -> C4ArchitectureCandidatePreparation:
        candidate_id = self._required_text(candidate_id, "candidate_id")
        input_set_id = self._required_text(input_set_id, "input_set_id")
        input_set, members = self._clean_input(input_set_id)
        normalized, _, manifest_sha256 = self._normalize_manifest(
            manifest,
            input_members=members,
        )
        architecture_id = str(normalized["architecture_id"])
        fields = {
            "candidate_id": candidate_id,
            "architecture_id": architecture_id,
            "architecture_version": "3.2",
            "input_set_id": input_set_id,
            "input_set_digest": input_set.input_set_digest,
            "manifest_sha256": manifest_sha256,
            "adr_count": len(normalized["authority_adrs"]),
            "port_count": len(normalized["ports"]),
            "binding_count": len(normalized["component_bindings"]),
            "nfr_count": len(normalized["non_functional_requirements"]),
            "stage_order": list(_STAGE_ORDER),
            "status": _CANDIDATE_GATE_EFFECT,
        }
        return C4ArchitectureCandidatePreparation(
            candidate_id=candidate_id,
            architecture_id=architecture_id,
            architecture_version="3.2",
            input_set_id=input_set_id,
            input_set_digest=input_set.input_set_digest,
            manifest_sha256=manifest_sha256,
            adr_count=len(normalized["authority_adrs"]),
            port_count=len(normalized["ports"]),
            binding_count=len(normalized["component_bindings"]),
            nfr_count=len(normalized["non_functional_requirements"]),
            stage_order=_STAGE_ORDER,
            status=C4ArchitectureCandidateStatus.NOT_REVIEWED,
            action="c4.architecture-candidate.create",
            resource=self._stream(candidate_id),
            mission_id=f"c4-architecture:{architecture_id}",
            context=self._context(fields),
        )

    def _assert_authorization(
        self,
        decision_id: str,
        *,
        preparation: C4ArchitectureCandidatePreparation,
        actor: str,
    ) -> AuthorizationDecision:
        decision_id = self._required_text(decision_id, "authorization_decision_id")
        verification = self.trust.verify_decision(decision_id)
        if not verification.ok:
            raise AuthorizationError(
                "C4 candidate authorization decision failed verification",
                {
                    "decision_id": decision_id,
                    "defects": list(verification.defects),
                },
            )
        try:
            decision = self.trust.get_decision(decision_id)
        except NotFoundError as exc:
            raise AuthorizationError(
                "C4 candidate authorization decision does not exist"
            ) from exc
        observed = (
            decision.request.subject,
            decision.request.action,
            decision.request.resource,
            decision.request.mission_id,
            dict(decision.request.context),
        )
        expected = (
            actor,
            preparation.action,
            preparation.resource,
            preparation.mission_id,
            dict(preparation.context),
        )
        if not decision.allowed or observed != expected:
            raise AuthorizationError(
                "authorization decision does not exactly match C4 candidate creation",
                {
                    "decision_id": decision_id,
                    "allowed": decision.allowed,
                    "expected": list(expected),
                    "observed": list(observed),
                },
            )
        return decision

    @staticmethod
    def _from_row(row: sqlite3.Row) -> C4ArchitectureCandidate:
        return C4ArchitectureCandidate(
            candidate_id=str(row["candidate_id"]),
            architecture_id=str(row["architecture_id"]),
            architecture_version=str(row["architecture_version"]),
            input_set_id=str(row["input_set_id"]),
            input_set_digest=str(row["input_set_digest"]),
            manifest_sha256=str(row["manifest_sha256"]),
            status=C4ArchitectureCandidateStatus(str(row["status"])),
            authorization_decision_id=str(row["authorization_decision_id"]),
            created_at=str(row["created_at"]),
            created_by=str(row["created_by"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def get_candidate(self, candidate_id: str) -> C4ArchitectureCandidate:
        candidate_id = self._required_text(candidate_id, "candidate_id")
        row = self.database.connection.execute(
            """
            SELECT * FROM c4_architecture_candidates
            WHERE candidate_id = ?
            """,
            (candidate_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C4 architecture candidate does not exist",
                {"candidate_id": candidate_id},
            )
        try:
            return self._from_row(row)
        except ValueError as exc:
            raise IntegrityError("stored C4 candidate status is invalid") from exc

    def get_manifest(self, candidate_id: str) -> Mapping[str, Any]:
        self.get_candidate(candidate_id)
        row = self.database.connection.execute(
            """
            SELECT manifest_json FROM c4_architecture_candidates
            WHERE candidate_id = ?
            """,
            (candidate_id,),
        ).fetchone()
        try:
            manifest = json.loads(str(row["manifest_json"]))
        except (json.JSONDecodeError, TypeError) as exc:
            raise IntegrityError("stored C4 candidate manifest is invalid") from exc
        if not isinstance(manifest, dict):
            raise IntegrityError("stored C4 candidate manifest must be an object")
        return manifest

    @staticmethod
    def _ledger_payload(
        candidate: C4ArchitectureCandidate,
        *,
        adr_count: int,
        port_count: int,
        binding_count: int,
        nfr_count: int,
    ) -> dict[str, object]:
        return {
            "candidate_id": candidate.candidate_id,
            "architecture_id": candidate.architecture_id,
            "architecture_version": candidate.architecture_version,
            "input_set_id": candidate.input_set_id,
            "input_set_digest": candidate.input_set_digest,
            "manifest_sha256": candidate.manifest_sha256,
            "adr_count": adr_count,
            "port_count": port_count,
            "binding_count": binding_count,
            "nfr_count": nfr_count,
            "stage_order": list(_STAGE_ORDER),
            "status": candidate.status.value,
            "authorization_decision_id": candidate.authorization_decision_id,
            "gate_effect": _CANDIDATE_GATE_EFFECT,
        }

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
        candidate_id = self._required_text(candidate_id, "candidate_id")
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now())
        preparation = self.prepare_create(
            candidate_id,
            input_set_id=input_set_id,
            manifest=manifest,
        )
        decision = self._assert_authorization(
            authorization_decision_id,
            preparation=preparation,
            actor=actor,
        )
        if self._as_datetime(occurred_at) < self._as_datetime(decision.decided_at):
            raise StateTransitionError(
                "C4 candidate creation predates TrustPlane authorization"
            )
        _, manifest_json, _ = self._normalize_manifest(
            manifest,
            input_members=self.inputs.get_members(input_set_id),
        )

        existing = self.database.connection.execute(
            """
            SELECT * FROM c4_architecture_candidates
            WHERE candidate_id = ? OR architecture_id = ?
            """,
            (candidate_id, preparation.architecture_id),
        ).fetchone()
        if existing is not None:
            if str(existing["candidate_id"]) != candidate_id:
                raise ConflictError(
                    "architecture_id already has an immutable C4 candidate",
                    {"architecture_id": preparation.architecture_id},
                )
            record = self._from_row(existing)
            exact = (
                record.architecture_id == preparation.architecture_id
                and record.input_set_id == input_set_id
                and record.input_set_digest == preparation.input_set_digest
                and record.manifest_sha256 == preparation.manifest_sha256
                and str(existing["manifest_json"]) == manifest_json
                and record.authorization_decision_id
                == authorization_decision_id
                and record.created_by == actor
            )
            if not exact:
                raise ConflictError(
                    "candidate_id was reused with different C4 architecture material",
                    {"candidate_id": candidate_id},
                )
            verification = self.verify_candidate(candidate_id)
            if not verification.ok:
                raise IntegrityError(
                    "existing C4 architecture candidate failed verification",
                    {
                        "candidate_id": candidate_id,
                        "defects": list(verification.defects),
                    },
                )
            return record

        provisional = C4ArchitectureCandidate(
            candidate_id=candidate_id,
            architecture_id=preparation.architecture_id,
            architecture_version="3.2",
            input_set_id=input_set_id,
            input_set_digest=preparation.input_set_digest,
            manifest_sha256=preparation.manifest_sha256,
            status=C4ArchitectureCandidateStatus.NOT_REVIEWED,
            authorization_decision_id=authorization_decision_id,
            created_at=occurred_at,
            created_by=actor,
            ledger_event_id="pending",
            ledger_hash="pending",
        )
        payload = self._ledger_payload(
            provisional,
            adr_count=preparation.adr_count,
            port_count=preparation.port_count,
            binding_count=preparation.binding_count,
            nfr_count=preparation.nfr_count,
        )
        try:
            with self.database.transaction() as connection:
                race = connection.execute(
                    """
                    SELECT candidate_id FROM c4_architecture_candidates
                    WHERE candidate_id = ? OR architecture_id = ?
                       OR authorization_decision_id = ?
                    """,
                    (
                        candidate_id,
                        preparation.architecture_id,
                        authorization_decision_id,
                    ),
                ).fetchone()
                if race is not None:
                    raise ConflictError(
                        "C4 architecture candidate appeared during creation"
                    )
                input_verification = self.inputs.verify_input_set(input_set_id)
                if not input_verification.ok:
                    raise IntegrityError(
                        "C4 architecture input set failed verification",
                        {
                            "input_set_id": input_set_id,
                            "defects": list(input_verification.defects),
                        },
                    )
                current = self.prepare_create(
                    candidate_id,
                    input_set_id=input_set_id,
                    manifest=manifest,
                )
                if current != preparation:
                    raise ConflictError(
                        "C4 architecture material changed during candidate creation"
                    )
                current_decision = self._assert_authorization(
                    authorization_decision_id,
                    preparation=current,
                    actor=actor,
                )
                if self._as_datetime(occurred_at) < self._as_datetime(
                    current_decision.decided_at
                ):
                    raise StateTransitionError(
                        "C4 candidate creation predates TrustPlane authorization"
                    )
                self.continuity._consume_authorization(
                    connection,
                    decision_id=authorization_decision_id,
                    operation_kind=_CANDIDATE_EVENT_KIND,
                    operation_id=candidate_id,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    self._stream(candidate_id),
                    _CANDIDATE_EVENT_KIND,
                    payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO c4_architecture_candidates (
                        candidate_id, architecture_id, architecture_version,
                        input_set_id, input_set_digest, manifest_json,
                        manifest_sha256, adr_count, port_count, binding_count,
                        nfr_count, stage_order_json, status,
                        authorization_decision_id, created_at, created_by,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, '3.2', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        candidate_id,
                        preparation.architecture_id,
                        input_set_id,
                        preparation.input_set_digest,
                        manifest_json,
                        preparation.manifest_sha256,
                        preparation.adr_count,
                        preparation.port_count,
                        preparation.binding_count,
                        preparation.nfr_count,
                        canonical_json(list(_STAGE_ORDER)),
                        C4ArchitectureCandidateStatus.NOT_REVIEWED.value,
                        authorization_decision_id,
                        occurred_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "C4 architecture candidate conflicts with immutable state",
                {"candidate_id": candidate_id},
            ) from exc
        return self.get_candidate(candidate_id)

    def verify_candidate(
        self,
        candidate_id: str,
    ) -> C4ArchitectureCandidateVerification:
        candidate_id = self._required_text(candidate_id, "candidate_id")
        row = self.database.connection.execute(
            """
            SELECT * FROM c4_architecture_candidates
            WHERE candidate_id = ?
            """,
            (candidate_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C4 architecture candidate does not exist",
                {"candidate_id": candidate_id},
            )
        defects: list[str] = []
        try:
            record = self._from_row(row)
        except (IntegrityError, ValueError):
            return C4ArchitectureCandidateVerification(
                candidate_id=candidate_id,
                defects=("C4_CANDIDATE_ROW_INVALID",),
            )
        input_verification = self.inputs.verify_input_set(record.input_set_id)
        defects.extend(
            f"C4_CANDIDATE_INPUT:{defect}"
            for defect in input_verification.defects
        )
        try:
            input_set, members = self._clean_input(record.input_set_id)
        except (IntegrityError, NotFoundError):
            defects.append("C4_CANDIDATE_INPUT_INVALID")
            input_set = None
            members = ()
        try:
            manifest = json.loads(str(row["manifest_json"]))
        except (json.JSONDecodeError, TypeError):
            defects.append("C4_CANDIDATE_MANIFEST_INVALID")
            manifest = None
        preparation: C4ArchitectureCandidatePreparation | None = None
        if isinstance(manifest, dict) and input_set is not None:
            try:
                normalized, manifest_json, manifest_sha256 = self._normalize_manifest(
                    manifest,
                    input_members=members,
                )
            except (
                StateTransitionError,
                ValidationError,
            ):
                defects.append("C4_CANDIDATE_MANIFEST_SEMANTICS_INVALID")
            else:
                if manifest_json != str(row["manifest_json"]):
                    defects.append("C4_CANDIDATE_MANIFEST_NOT_CANONICAL")
                if manifest_sha256 != record.manifest_sha256:
                    defects.append("C4_CANDIDATE_MANIFEST_SHA256_MISMATCH")
                if str(normalized["architecture_id"]) != record.architecture_id:
                    defects.append("C4_CANDIDATE_ARCHITECTURE_ID_MISMATCH")
                if record.input_set_digest != input_set.input_set_digest:
                    defects.append("C4_CANDIDATE_INPUT_SET_DIGEST_MISMATCH")
                if int(row["adr_count"]) != len(normalized["authority_adrs"]):
                    defects.append("C4_CANDIDATE_ADR_COUNT_MISMATCH")
                if int(row["port_count"]) != len(normalized["ports"]):
                    defects.append("C4_CANDIDATE_PORT_COUNT_MISMATCH")
                if int(row["binding_count"]) != len(
                    normalized["component_bindings"]
                ):
                    defects.append("C4_CANDIDATE_BINDING_COUNT_MISMATCH")
                if int(row["nfr_count"]) != len(
                    normalized["non_functional_requirements"]
                ):
                    defects.append("C4_CANDIDATE_NFR_COUNT_MISMATCH")
                if str(row["stage_order_json"]) != canonical_json(
                    list(_STAGE_ORDER)
                ):
                    defects.append("C4_CANDIDATE_STAGE_ORDER_MISMATCH")
                preparation = C4ArchitectureCandidatePreparation(
                    candidate_id=record.candidate_id,
                    architecture_id=record.architecture_id,
                    architecture_version=record.architecture_version,
                    input_set_id=record.input_set_id,
                    input_set_digest=record.input_set_digest,
                    manifest_sha256=record.manifest_sha256,
                    adr_count=int(row["adr_count"]),
                    port_count=int(row["port_count"]),
                    binding_count=int(row["binding_count"]),
                    nfr_count=int(row["nfr_count"]),
                    stage_order=_STAGE_ORDER,
                    status=C4ArchitectureCandidateStatus.NOT_REVIEWED,
                    action="c4.architecture-candidate.create",
                    resource=self._stream(record.candidate_id),
                    mission_id=f"c4-architecture:{record.architecture_id}",
                    context=self._context(
                        {
                            "candidate_id": record.candidate_id,
                            "architecture_id": record.architecture_id,
                            "architecture_version": record.architecture_version,
                            "input_set_id": record.input_set_id,
                            "input_set_digest": record.input_set_digest,
                            "manifest_sha256": record.manifest_sha256,
                            "adr_count": int(row["adr_count"]),
                            "port_count": int(row["port_count"]),
                            "binding_count": int(row["binding_count"]),
                            "nfr_count": int(row["nfr_count"]),
                            "stage_order": list(_STAGE_ORDER),
                            "status": record.status.value,
                        }
                    ),
                )
        if record.architecture_version != "3.2":
            defects.append("C4_CANDIDATE_ARCHITECTURE_VERSION_MISMATCH")
        if record.status is not C4ArchitectureCandidateStatus.NOT_REVIEWED:
            defects.append("C4_CANDIDATE_STATUS_MISMATCH")

        decision_verification = self.trust.verify_decision(
            record.authorization_decision_id
        )
        defects.extend(
            f"C4_CANDIDATE_AUTHORIZATION:{defect}"
            for defect in decision_verification.defects
        )
        try:
            decision = self.trust.get_decision(record.authorization_decision_id)
        except NotFoundError:
            defects.append("C4_CANDIDATE_AUTHORIZATION_MISSING")
            decision = None
        if decision is not None and preparation is not None:
            observed = (
                decision.request.subject,
                decision.request.action,
                decision.request.resource,
                decision.request.mission_id,
                dict(decision.request.context),
            )
            expected = (
                record.created_by,
                preparation.action,
                preparation.resource,
                preparation.mission_id,
                dict(preparation.context),
            )
            if not decision.allowed or observed != expected:
                defects.append(
                    "C4_CANDIDATE_AUTHORIZATION_REQUEST_MISMATCH"
                )
            if self._as_datetime(record.created_at) < self._as_datetime(
                decision.decided_at
            ):
                defects.append(
                    "C4_CANDIDATE_CREATED_AT_PREDATES_AUTHORIZATION"
                )

        consumption = self.database.connection.execute(
            """
            SELECT * FROM continuity_authorization_consumptions
            WHERE decision_id = ?
            """,
            (record.authorization_decision_id,),
        ).fetchone()
        if consumption is None:
            defects.append(
                "C4_CANDIDATE_AUTHORIZATION_CONSUMPTION_MISSING"
            )
        elif (
            str(consumption["operation_kind"]),
            str(consumption["operation_id"]),
            str(consumption["consumed_at"]),
            str(consumption["consumed_by"]),
        ) != (
            _CANDIDATE_EVENT_KIND,
            record.candidate_id,
            record.created_at,
            record.created_by,
        ):
            defects.append(
                "C4_CANDIDATE_AUTHORIZATION_CONSUMPTION_MISMATCH"
            )

        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (record.ledger_event_id,),
        ).fetchone()
        if event is None:
            defects.append("C4_CANDIDATE_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != self._stream(record.candidate_id):
                defects.append("C4_CANDIDATE_LEDGER_STREAM_MISMATCH")
            if str(event["kind"]) != _CANDIDATE_EVENT_KIND:
                defects.append("C4_CANDIDATE_LEDGER_KIND_MISMATCH")
            if str(event["actor"]) != record.created_by:
                defects.append("C4_CANDIDATE_LEDGER_ACTOR_MISMATCH")
            if str(event["occurred_at"]) != record.created_at:
                defects.append("C4_CANDIDATE_LEDGER_TIMESTAMP_MISMATCH")
            if str(event["record_hash"]) != record.ledger_hash:
                defects.append("C4_CANDIDATE_LEDGER_HASH_MISMATCH")
            try:
                payload = json.loads(str(event["payload_json"]))
            except (json.JSONDecodeError, TypeError):
                defects.append("C4_CANDIDATE_LEDGER_PAYLOAD_INVALID")
            else:
                if preparation is None:
                    defects.append("C4_CANDIDATE_LEDGER_PAYLOAD_UNVERIFIABLE")
                else:
                    expected_payload = self._ledger_payload(
                        record,
                        adr_count=preparation.adr_count,
                        port_count=preparation.port_count,
                        binding_count=preparation.binding_count,
                        nfr_count=preparation.nfr_count,
                    )
                    if payload != expected_payload:
                        defects.append("C4_CANDIDATE_LEDGER_PAYLOAD_MISMATCH")
        chain = self.ledger.verify(self._stream(record.candidate_id))
        defects.extend(
            f"C4_CANDIDATE_LEDGER_CHAIN:{defect.code}"
            for defect in chain.defects
        )
        return C4ArchitectureCandidateVerification(
            candidate_id=candidate_id,
            defects=tuple(dict.fromkeys(defects)),
        )
