from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re
import sqlite3
from typing import Any, Mapping

from .canonical import canonical_json, sha256_digest, utc_now
from .continuity_crypto import OpenSSLEd25519Verifier
from .errors import ConflictError, IntegrityError, NotFoundError, StateTransitionError, ValidationError


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
_MAX_SIGNATURE_BYTES = 1024
_VERSION = "1.0.0"
_ARCHITECTURE_VERSION = "3.2.0"
_EXECUTION_STATUS = "NOT_STARTED"
_GATE_EFFECT = "C5_EXECUTION_PLAN_ADMITTED_NOT_STARTED"
_EVENT_KIND = "C5_EXECUTION_PLAN_ADMITTED"
_ACTION = "c5.execution.plan.admit"
_RISK_LEVELS = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
_REQUIRED_FIELDS = frozenset(
    {
        "plan_id",
        "plan_version",
        "architecture_id",
        "architecture_version",
        "architecture_payload_sha256",
        "c3_snapshot_digest",
        "work_items",
        "execution_policy",
        "release_gates",
        "risk_register_digest",
        "resource_model_digest",
        "verification_strategy_digest",
        "planner_identity",
        "planner_environment",
        "reviewer_identity",
        "reviewer_environment",
        "planned_at_utc",
        "independence_basis",
        "execution_status",
        "gate_effect",
    }
)
_WORK_ITEM_FIELDS = frozenset(
    {
        "work_item_id",
        "phase",
        "title",
        "owner_role",
        "dependencies",
        "input_digests",
        "outputs",
        "acceptance_checks",
        "risk_level",
        "human_gate_required",
    }
)
_POLICY_FIELDS = frozenset(
    {
        "max_parallelism",
        "fail_closed",
        "require_proof",
        "stop_on_verification_failure",
        "human_gate_actions",
    }
)
_GATE_FIELDS = frozenset(
    {
        "gate_id",
        "title",
        "required_work_item_ids",
        "proof_digests",
        "human_gate_required",
    }
)


@dataclass(frozen=True)
class C5ExecutionPlanSnapshot:
    c4_baseline_id: str
    architecture_id: str
    architecture_version: str
    architecture_payload_sha256: str
    c3_snapshot_digest: str
    c4_admitted_at: str
    latest_evidence_at: str
    material_identities: tuple[str, ...]
    snapshot_digest: str

    @property
    def c4_snapshot_digest(self) -> str:
        return self.snapshot_digest


@dataclass(frozen=True)
class C5ExecutionPlanPreparation:
    plan_id: str
    plan_version: str
    architecture_id: str
    architecture_version: str
    c4_snapshot_digest: str
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]
    execution_status: str
    gate_effect: str


@dataclass(frozen=True)
class C5ExecutionPlan:
    plan_id: str
    plan_version: str
    architecture_id: str
    architecture_version: str
    architecture_payload_sha256: str
    c3_snapshot_digest: str
    c4_snapshot_digest: str
    c4_baseline_id: str
    work_items_digest: str
    release_gates_digest: str
    risk_register_digest: str
    resource_model_digest: str
    verification_strategy_digest: str
    planner_identity: str
    planner_environment: str
    reviewer_identity: str
    reviewer_environment: str
    planned_at_utc: str
    independence_basis: Mapping[str, Any]
    execution_status: str
    gate_effect: str
    execution_policy: Mapping[str, Any]
    key_id: str
    payload: bytes
    payload_sha256: str
    signature: bytes
    signature_sha256: str
    admitted_at: str
    admitted_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C5ExecutionPlanVerification:
    plan_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C5ExecutionPlanService:
    """Exact-byte C5 plan authority; admission never performs or promotes work."""

    def __init__(
        self,
        database: Any,
        ledger: Any,
        *dependencies: Any,
        signature_verifier: Any | None = None,
        **named: Any,
    ) -> None:
        self.database = database
        self.ledger = ledger
        values = [*dependencies, *named.values()]
        self.trust = self._find(
            values,
            lambda value: hasattr(value, "authorize") and hasattr(value, "verify_decision"),
        )
        self.continuity = self._find(values, lambda value: hasattr(value, "verify_trust_root"))
        self.architecture = self._find(
            values,
            lambda value: hasattr(value, "get_baseline")
            and hasattr(value, "verify_baseline")
            and hasattr(value, "snapshot"),
        )
        if self.continuity is None or self.architecture is None:
            raise ValidationError(
                "C5 execution plan requires Continuity and C4 architecture authorities"
            )
        self.signature_verifier = signature_verifier or getattr(
            self.continuity,
            "signature_verifier",
            OpenSSLEd25519Verifier(),
        )
        self._initialize_schema()

    @staticmethod
    def _find(values: list[Any], predicate: Any) -> Any | None:
        return next(
            (value for value in values if value is not None and predicate(value)),
            None,
        )

    @staticmethod
    def _text(value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{field} must be a non-empty string")
        return value

    @classmethod
    def _digest(cls, value: object, field: str) -> str:
        value = cls._text(value, field)
        if not _SHA256.fullmatch(value):
            raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
        return value

    @classmethod
    def _timestamp(cls, value: object, field: str) -> str:
        value = cls._text(value, field)
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError(f"{field} must be RFC 3339") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValidationError(f"{field} must be timezone-aware")
        return value

    @staticmethod
    def _dt(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    @classmethod
    def _sorted_strings(
        cls,
        value: object,
        field: str,
        *,
        allow_empty: bool,
        digest: bool = False,
    ) -> list[str]:
        if not isinstance(value, list):
            raise ValidationError(f"{field} must be a list")
        if not allow_empty and not value:
            raise ValidationError(f"{field} must not be empty")
        result = [cls._text(item, f"{field}[]") for item in value]
        if digest:
            for item in result:
                cls._digest(item, f"{field}[]")
        if result != sorted(result) or len(set(result)) != len(result):
            raise ValidationError(f"{field} must be sorted and unique")
        return result

    @classmethod
    def _parse_payload(cls, payload: bytes) -> dict[str, object]:
        if not isinstance(payload, bytes) or not payload or len(payload) > _MAX_PAYLOAD_BYTES:
            raise ValidationError("payload must be non-empty bytes within the size limit")

        def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate key: {key}")
                result[key] = value
            return result

        try:
            value = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=no_duplicates,
                parse_constant=lambda _: (_ for _ in ()).throw(
                    ValueError("invalid JSON constant")
                ),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValidationError("C5 execution plan payload must be strict UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise ValidationError("C5 execution plan payload must be a JSON object")
        fields = frozenset(value)
        if fields != _REQUIRED_FIELDS:
            raise ValidationError(
                "C5 execution plan payload fields do not match the contract",
                {"missing": sorted(_REQUIRED_FIELDS - fields), "unexpected": sorted(fields - _REQUIRED_FIELDS)},
            )

        for field in (
            "plan_id",
            "architecture_id",
            "architecture_version",
            "planner_identity",
            "planner_environment",
            "reviewer_identity",
            "reviewer_environment",
            "gate_effect",
        ):
            value[field] = cls._text(value[field], field)
        if value["plan_version"] != _VERSION:
            raise ValidationError(f"plan_version must equal {_VERSION}")
        if value["architecture_version"] != _ARCHITECTURE_VERSION:
            raise ValidationError(
                f"architecture_version must equal {_ARCHITECTURE_VERSION}"
            )
        for field in (
            "architecture_payload_sha256",
            "c3_snapshot_digest",
            "risk_register_digest",
            "resource_model_digest",
            "verification_strategy_digest",
        ):
            value[field] = cls._digest(value[field], field)
        value["planned_at_utc"] = cls._timestamp(value["planned_at_utc"], "planned_at_utc")
        if value["execution_status"] != _EXECUTION_STATUS:
            raise ValidationError(
                f"execution_status must equal {_EXECUTION_STATUS}"
            )
        if value["gate_effect"] != _GATE_EFFECT:
            raise ValidationError(f"gate_effect must equal {_GATE_EFFECT}")

        work_items = value["work_items"]
        if not isinstance(work_items, list) or not work_items:
            raise ValidationError("work_items must be a non-empty list")
        normalized_items: list[dict[str, object]] = []
        seen_item_ids: set[str] = set()
        for ordinal, raw_item in enumerate(work_items):
            if not isinstance(raw_item, dict) or frozenset(raw_item) != _WORK_ITEM_FIELDS:
                raise ValidationError(f"work_items[{ordinal}] fields do not match the contract")
            item = dict(raw_item)
            item["work_item_id"] = cls._text(item["work_item_id"], f"work_items[{ordinal}].work_item_id")
            if item["work_item_id"] in seen_item_ids:
                raise ValidationError("work_item_id values must be unique")
            seen_item_ids.add(str(item["work_item_id"]))
            for field in ("phase", "title", "owner_role"):
                item[field] = cls._text(item[field], f"work_items[{ordinal}].{field}")
            item["dependencies"] = cls._sorted_strings(
                item["dependencies"], f"work_items[{ordinal}].dependencies", allow_empty=True
            )
            item["input_digests"] = cls._sorted_strings(
                item["input_digests"], f"work_items[{ordinal}].input_digests",
                allow_empty=True, digest=True
            )
            item["outputs"] = cls._sorted_strings(
                item["outputs"], f"work_items[{ordinal}].outputs", allow_empty=False
            )
            item["acceptance_checks"] = cls._sorted_strings(
                item["acceptance_checks"], f"work_items[{ordinal}].acceptance_checks",
                allow_empty=False
            )
            item["risk_level"] = cls._text(item["risk_level"], f"work_items[{ordinal}].risk_level")
            if item["risk_level"] not in _RISK_LEVELS:
                raise ValidationError("work item risk_level is outside the closed contract")
            if not isinstance(item["human_gate_required"], bool):
                raise ValidationError("work item human_gate_required must be boolean")
            normalized_items.append(item)
        if [str(item["work_item_id"]) for item in normalized_items] != sorted(seen_item_ids):
            raise ValidationError("work_items must be sorted by work_item_id")
        item_ids = {str(item["work_item_id"]) for item in normalized_items}
        for item in normalized_items:
            dependencies = [str(dep) for dep in item["dependencies"]]
            if str(item["work_item_id"]) in dependencies:
                raise ValidationError("work item cannot depend on itself")
            if any(dep not in item_ids for dep in dependencies):
                raise ValidationError("work item dependency does not exist")
        cls._assert_acyclic(normalized_items)
        value["work_items"] = normalized_items

        policy = value["execution_policy"]
        if not isinstance(policy, dict) or frozenset(policy) != _POLICY_FIELDS:
            raise ValidationError("execution_policy fields do not match the contract")
        policy = dict(policy)
        if (
            not isinstance(policy["max_parallelism"], int)
            or isinstance(policy["max_parallelism"], bool)
            or policy["max_parallelism"] <= 0
        ):
            raise ValidationError("execution_policy.max_parallelism must be a positive integer")
        for field in ("fail_closed", "require_proof", "stop_on_verification_failure"):
            if policy[field] is not True:
                raise ValidationError(f"execution_policy.{field} must be true")
        policy["human_gate_actions"] = cls._sorted_strings(
            policy["human_gate_actions"], "execution_policy.human_gate_actions", allow_empty=True
        )
        value["execution_policy"] = policy

        gates = value["release_gates"]
        if not isinstance(gates, list) or not gates:
            raise ValidationError("release_gates must be a non-empty list")
        normalized_gates: list[dict[str, object]] = []
        seen_gate_ids: set[str] = set()
        for ordinal, raw_gate in enumerate(gates):
            if not isinstance(raw_gate, dict) or frozenset(raw_gate) != _GATE_FIELDS:
                raise ValidationError(f"release_gates[{ordinal}] fields do not match the contract")
            gate = dict(raw_gate)
            gate["gate_id"] = cls._text(gate["gate_id"], f"release_gates[{ordinal}].gate_id")
            if gate["gate_id"] in seen_gate_ids:
                raise ValidationError("gate_id values must be unique")
            seen_gate_ids.add(str(gate["gate_id"]))
            gate["title"] = cls._text(gate["title"], f"release_gates[{ordinal}].title")
            gate["required_work_item_ids"] = cls._sorted_strings(
                gate["required_work_item_ids"],
                f"release_gates[{ordinal}].required_work_item_ids",
                allow_empty=False,
            )
            if any(item_id not in item_ids for item_id in gate["required_work_item_ids"]):
                raise ValidationError("release gate references an unknown work item")
            gate["proof_digests"] = cls._sorted_strings(
                gate["proof_digests"],
                f"release_gates[{ordinal}].proof_digests",
                allow_empty=False,
                digest=True,
            )
            if not isinstance(gate["human_gate_required"], bool):
                raise ValidationError("release gate human_gate_required must be boolean")
            normalized_gates.append(gate)
        if [str(gate["gate_id"]) for gate in normalized_gates] != sorted(seen_gate_ids):
            raise ValidationError("release_gates must be sorted by gate_id")
        value["release_gates"] = normalized_gates

        independence = value["independence_basis"]
        if not isinstance(independence, dict) or frozenset(independence) != frozenset(
            {"excluded_identities", "statement"}
        ):
            raise ValidationError("independence_basis fields do not match the contract")
        independence = dict(independence)
        independence["excluded_identities"] = cls._sorted_strings(
            independence["excluded_identities"],
            "independence_basis.excluded_identities",
            allow_empty=True,
        )
        independence["statement"] = cls._text(
            independence["statement"], "independence_basis.statement"
        )
        value["independence_basis"] = independence
        return value

    @staticmethod
    def _assert_acyclic(work_items: list[Mapping[str, object]]) -> None:
        identifiers = {str(item["work_item_id"]) for item in work_items}
        indegree = {identifier: 0 for identifier in identifiers}
        outgoing = {identifier: [] for identifier in identifiers}
        for item in work_items:
            identifier = str(item["work_item_id"])
            for dependency in item["dependencies"]:
                dependency = str(dependency)
                outgoing[dependency].append(identifier)
                indegree[identifier] += 1
        ready = sorted(identifier for identifier, degree in indegree.items() if degree == 0)
        visited = 0
        while ready:
            current = ready.pop(0)
            visited += 1
            for dependent in sorted(outgoing[current]):
                indegree[dependent] -= 1
                if indegree[dependent] == 0:
                    ready.append(dependent)
                    ready.sort()
        if visited != len(identifiers):
            raise StateTransitionError("work item dependency graph must be acyclic")

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c5_execution_plans (
                    plan_id TEXT PRIMARY KEY,
                    plan_version TEXT NOT NULL CHECK (plan_version = '1.0.0'),
                    architecture_id TEXT NOT NULL UNIQUE,
                    architecture_version TEXT NOT NULL CHECK (architecture_version = '3.2.0'),
                    c4_baseline_id TEXT NOT NULL,
                    c4_snapshot_digest TEXT NOT NULL CHECK (length(c4_snapshot_digest) = 64),
                    architecture_payload_sha256 TEXT NOT NULL CHECK (length(architecture_payload_sha256) = 64),
                    c3_snapshot_digest TEXT NOT NULL CHECK (length(c3_snapshot_digest) = 64),
                    work_items_digest TEXT NOT NULL CHECK (length(work_items_digest) = 64),
                    release_gates_digest TEXT NOT NULL CHECK (length(release_gates_digest) = 64),
                    risk_register_digest TEXT NOT NULL CHECK (length(risk_register_digest) = 64),
                    resource_model_digest TEXT NOT NULL CHECK (length(resource_model_digest) = 64),
                    verification_strategy_digest TEXT NOT NULL CHECK (length(verification_strategy_digest) = 64),
                    execution_policy_json TEXT NOT NULL,
                    planner_identity TEXT NOT NULL,
                    planner_environment TEXT NOT NULL,
                    reviewer_identity TEXT NOT NULL,
                    reviewer_environment TEXT NOT NULL,
                    planned_at_utc TEXT NOT NULL,
                    independence_basis_json TEXT NOT NULL,
                    execution_status TEXT NOT NULL CHECK (execution_status = 'NOT_STARTED'),
                    gate_effect TEXT NOT NULL CHECK (gate_effect = 'C5_EXECUTION_PLAN_ADMITTED_NOT_STARTED'),
                    key_id TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    payload_sha256 TEXT NOT NULL UNIQUE CHECK (length(payload_sha256) = 64),
                    signature BLOB NOT NULL,
                    signature_sha256 TEXT NOT NULL CHECK (length(signature_sha256) = 64),
                    admitted_at TEXT NOT NULL,
                    admitted_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (key_id) REFERENCES continuity_trust_roots(key_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c5_execution_plan_work_items (
                    plan_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                    work_item_id TEXT NOT NULL,
                    material_json TEXT NOT NULL,
                    material_sha256 TEXT NOT NULL CHECK (length(material_sha256) = 64),
                    recorded_at TEXT NOT NULL,
                    recorded_by TEXT NOT NULL,
                    member_ledger_hash TEXT NOT NULL CHECK (length(member_ledger_hash) = 64),
                    PRIMARY KEY (plan_id, ordinal),
                    UNIQUE (plan_id, work_item_id),
                    FOREIGN KEY (plan_id) REFERENCES c5_execution_plans(plan_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c5_execution_plan_release_gates (
                    plan_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                    gate_id TEXT NOT NULL,
                    material_json TEXT NOT NULL,
                    material_sha256 TEXT NOT NULL CHECK (length(material_sha256) = 64),
                    recorded_at TEXT NOT NULL,
                    recorded_by TEXT NOT NULL,
                    member_ledger_hash TEXT NOT NULL CHECK (length(member_ledger_hash) = 64),
                    PRIMARY KEY (plan_id, ordinal),
                    UNIQUE (plan_id, gate_id),
                    FOREIGN KEY (plan_id) REFERENCES c5_execution_plans(plan_id)
                )
                """
            )
            for table in (
                "c5_execution_plans",
                "c5_execution_plan_work_items",
                "c5_execution_plan_release_gates",
            ):
                connection.execute(
                    f"CREATE TRIGGER IF NOT EXISTS {table}_no_update "
                    f"BEFORE UPDATE ON {table} BEGIN "
                    f"SELECT RAISE(ABORT, '{table} rows are immutable'); END"
                )
                connection.execute(
                    f"CREATE TRIGGER IF NOT EXISTS {table}_no_delete "
                    f"BEFORE DELETE ON {table} BEGIN "
                    f"SELECT RAISE(ABORT, '{table} rows are immutable'); END"
                )

    def _architecture_baseline(self, identifier: str) -> Any:
        try:
            return self.architecture.get_baseline(identifier)
        except (NotFoundError, KeyError):
            row = self.database.connection.execute(
                "SELECT baseline_id FROM c4_architecture_baselines "
                "WHERE architecture_id = ? ORDER BY baseline_id LIMIT 1",
                (identifier,),
            ).fetchone()
            if row is None:
                raise NotFoundError(
                    "C4 architecture baseline does not exist",
                    {"architecture_id": identifier},
                )
            return self.architecture.get_baseline(str(row["baseline_id"]))

    @staticmethod
    def _value(source: object, field: str, default: object = None) -> object:
        if isinstance(source, Mapping):
            return source.get(field, default)
        return getattr(source, field, default)

    def _clean_c4(self, baseline_id: str) -> None:
        result = self.architecture.verify_baseline(baseline_id)
        if not getattr(result, "ok", False):
            raise IntegrityError(
                "C4 architecture baseline verification failed",
                {"baseline_id": baseline_id, "defects": list(getattr(result, "defects", ()))},
            )

    def _build_snapshot(self, architecture_id: str) -> C5ExecutionPlanSnapshot:
        baseline = self._architecture_baseline(architecture_id)
        baseline_id = self._text(self._value(baseline, "baseline_id"), "c4_baseline_id")
        self._clean_c4(baseline_id)
        c3_run_id = self._value(baseline, "c3_run_id")
        try:
            current = self.architecture.snapshot(str(c3_run_id or baseline_id))
        except (NotFoundError, KeyError):
            current = self.architecture.snapshot(baseline_id)
        actual_architecture_id = self._text(
            self._value(baseline, "architecture_id"), "architecture_id"
        )
        version = self._text(
            self._value(baseline, "architecture_version"), "architecture_version"
        )
        if version != _ARCHITECTURE_VERSION:
            raise IntegrityError("C4 architecture version is outside the C5 contract")
        payload_digest = self._digest(
            self._value(baseline, "payload_sha256"), "architecture_payload_sha256"
        )
        c3_digest = self._digest(
            self._value(baseline, "c3_snapshot_digest")
            or self._value(current, "c3_snapshot_digest"),
            "c3_snapshot_digest",
        )
        if self._value(current, "c3_snapshot_digest") not in {None, c3_digest}:
            raise IntegrityError("C4 baseline C3 snapshot digest is inconsistent")
        admitted_at = self._timestamp(
            self._value(baseline, "admitted_at"), "c4_admitted_at"
        )
        timestamps = [admitted_at]
        for field in (
            "latest_evidence_at",
            "decision_decided_at",
            "adoption_authorized_at",
            "execution_requested_at",
        ):
            value = self._value(current, field)
            if value:
                timestamps.append(self._timestamp(value, field))
        latest_evidence_at = max(timestamps, key=self._dt)
        identities: set[str] = set()
        source_identities = self._value(current, "material_identities", ())
        if not isinstance(source_identities, (list, tuple, set)):
            raise IntegrityError("C4 material identities are invalid")
        for identity in source_identities:
            identities.add(self._text(identity, "material_identity").strip())
        for field in (
            "architect_identity",
            "reviewer_identity",
            "admitted_by",
        ):
            value = self._value(baseline, field)
            if value:
                identities.add(self._text(value, field).strip())
        material = {
            "c4_baseline_id": baseline_id,
            "architecture_id": actual_architecture_id,
            "architecture_version": version,
            "architecture_payload_sha256": payload_digest,
            "c3_snapshot_digest": c3_digest,
            "c4_admitted_at": admitted_at,
            "latest_evidence_at": latest_evidence_at,
            "material_identities": sorted(identities),
        }
        return C5ExecutionPlanSnapshot(
            baseline_id,
            actual_architecture_id,
            version,
            payload_digest,
            c3_digest,
            admitted_at,
            latest_evidence_at,
            tuple(sorted(identities)),
            sha256_digest(material),
        )

    def snapshot(self, architecture_id: str) -> C5ExecutionPlanSnapshot:
        return self._build_snapshot(self._text(architecture_id, "architecture_id"))

    def prepare(
        self,
        plan_id: str,
        architecture_id: str,
        payload: Mapping[str, Any] | None = None,
    ) -> C5ExecutionPlanPreparation:
        plan_id = self._text(plan_id, "plan_id")
        architecture_id = self._text(architecture_id, "architecture_id")
        snapshot = self.snapshot(architecture_id)
        if payload is not None:
            supplied_architecture_id = self._text(
                payload.get("architecture_id"), "payload.architecture_id"
            )
            if supplied_architecture_id != snapshot.architecture_id:
                raise StateTransitionError("C5 preparation targets another C4 architecture")
        resource = f"continuity:c5:execution-plan:{plan_id}"
        context = {
            "plan_id": plan_id,
            "plan_version": _VERSION,
            "architecture_id": snapshot.architecture_id,
            "architecture_version": snapshot.architecture_version,
            "architecture_payload_sha256": snapshot.architecture_payload_sha256,
            "c3_snapshot_digest": snapshot.c3_snapshot_digest,
            "c4_snapshot_digest": snapshot.snapshot_digest,
            "execution_status": _EXECUTION_STATUS,
            "gate_effect": _GATE_EFFECT,
        }
        return C5ExecutionPlanPreparation(
            plan_id,
            _VERSION,
            snapshot.architecture_id,
            snapshot.architecture_version,
            snapshot.snapshot_digest,
            _ACTION,
            resource,
            f"c5-execution-plan:{snapshot.architecture_id}",
            context,
            _EXECUTION_STATUS,
            _GATE_EFFECT,
        )

    prepare_plan = prepare

    @staticmethod
    def _bounded_payload(value: object) -> bytes:
        if not isinstance(value, bytes) or not value or len(value) > _MAX_PAYLOAD_BYTES:
            raise ValidationError("payload must be non-empty bytes within the size limit")
        return value

    @staticmethod
    def _bounded_signature(value: object) -> bytes:
        if not isinstance(value, bytes) or not value or len(value) > _MAX_SIGNATURE_BYTES:
            raise ValidationError("signature must be non-empty bytes within the size limit")
        return value

    @staticmethod
    def _snapshot_fields(snapshot: C5ExecutionPlanSnapshot) -> dict[str, object]:
        return {
            "architecture_id": snapshot.architecture_id,
            "architecture_version": snapshot.architecture_version,
            "architecture_payload_sha256": snapshot.architecture_payload_sha256,
            "c3_snapshot_digest": snapshot.c3_snapshot_digest,
        }

    @classmethod
    def _assert_payload_snapshot(
        cls,
        value: Mapping[str, object],
        snapshot: C5ExecutionPlanSnapshot,
    ) -> None:
        expected = cls._snapshot_fields(snapshot)
        mismatches = {
            field: {"expected": expected_value, "observed": value.get(field)}
            for field, expected_value in expected.items()
            if value.get(field) != expected_value
        }
        if mismatches:
            raise StateTransitionError(
                "signed C5 execution plan does not match the current C4 snapshot",
                {"mismatches": mismatches},
            )
        planner = str(value["planner_identity"]).strip()
        reviewer = str(value["reviewer_identity"]).strip()
        if planner == reviewer or planner in snapshot.material_identities or reviewer in snapshot.material_identities:
            raise StateTransitionError(
                "C5 planner and reviewer identities are not independent",
                {"material_identities": list(snapshot.material_identities)},
            )
        independence = value["independence_basis"]
        if not isinstance(independence, dict):
            raise StateTransitionError("C5 independence basis is invalid")
        if independence["excluded_identities"] != list(snapshot.material_identities):
            raise StateTransitionError(
                "C5 independence exclusion set does not match C4 provenance",
                {"material_identities": list(snapshot.material_identities)},
            )
        planned_at = cls._dt(str(value["planned_at_utc"]))
        if planned_at <= cls._dt(snapshot.latest_evidence_at):
            raise StateTransitionError(
                "C5 execution plan chronology must follow the C4 evidence snapshot"
            )

    @classmethod
    def _derived_digests(cls, value: Mapping[str, object]) -> tuple[str, str]:
        return (
            sha256_digest(value["work_items"]),
            sha256_digest(value["release_gates"]),
        )

    @classmethod
    def _blob(cls, row: sqlite3.Row, field: str) -> bytes:
        value = row[field]
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise IntegrityError(f"stored C5 execution plan {field} is not binary")
        return bytes(value)

    @classmethod
    def _record(cls, row: sqlite3.Row) -> C5ExecutionPlan:
        try:
            independence = json.loads(str(row["independence_basis_json"]))
            execution_policy = json.loads(str(row["execution_policy_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrityError("stored C5 execution plan JSON is invalid") from exc
        if not isinstance(independence, dict) or not isinstance(execution_policy, dict):
            raise IntegrityError("stored C5 execution plan JSON is invalid")
        get = lambda field: row[field]
        return C5ExecutionPlan(
            cls._text(get("plan_id"), "plan_id"),
            cls._text(get("plan_version"), "plan_version"),
            cls._text(get("architecture_id"), "architecture_id"),
            cls._text(get("architecture_version"), "architecture_version"),
            cls._digest(get("architecture_payload_sha256"), "architecture_payload_sha256"),
            cls._digest(get("c3_snapshot_digest"), "c3_snapshot_digest"),
            cls._digest(get("c4_snapshot_digest"), "c4_snapshot_digest"),
            cls._text(get("c4_baseline_id"), "c4_baseline_id"),
            cls._digest(get("work_items_digest"), "work_items_digest"),
            cls._digest(get("release_gates_digest"), "release_gates_digest"),
            cls._digest(get("risk_register_digest"), "risk_register_digest"),
            cls._digest(get("resource_model_digest"), "resource_model_digest"),
            cls._digest(get("verification_strategy_digest"), "verification_strategy_digest"),
            cls._text(get("planner_identity"), "planner_identity"),
            cls._text(get("planner_environment"), "planner_environment"),
            cls._text(get("reviewer_identity"), "reviewer_identity"),
            cls._text(get("reviewer_environment"), "reviewer_environment"),
            cls._timestamp(get("planned_at_utc"), "planned_at_utc"),
            independence,
            cls._text(get("execution_status"), "execution_status"),
            cls._text(get("gate_effect"), "gate_effect"),
            execution_policy,
            cls._text(get("key_id"), "key_id"),
            cls._blob(row, "payload"),
            cls._digest(get("payload_sha256"), "payload_sha256"),
            cls._blob(row, "signature"),
            cls._digest(get("signature_sha256"), "signature_sha256"),
            cls._timestamp(get("admitted_at"), "admitted_at"),
            cls._text(get("admitted_by"), "admitted_by"),
            cls._text(get("ledger_event_id"), "ledger_event_id"),
            cls._digest(get("ledger_hash"), "ledger_hash"),
        )

    def _row_for(self, plan_id: str, architecture_id: str) -> sqlite3.Row | None:
        return self.database.connection.execute(
            "SELECT * FROM c5_execution_plans "
            "WHERE plan_id = ? OR architecture_id = ? ORDER BY plan_id LIMIT 1",
            (plan_id, architecture_id),
        ).fetchone()

    def get_plan(self, plan_id: str) -> C5ExecutionPlan:
        plan_id = self._text(plan_id, "plan_id")
        row = self.database.connection.execute(
            "SELECT * FROM c5_execution_plans WHERE plan_id = ?", (plan_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("C5 execution plan does not exist", {"plan_id": plan_id})
        return self._record(row)

    get = get_plan
    get_execution_plan = get_plan

    @staticmethod
    def _event_payload(record: C5ExecutionPlan) -> dict[str, object]:
        return {
            "plan_id": record.plan_id,
            "architecture_id": record.architecture_id,
            "architecture_version": record.architecture_version,
            "c4_snapshot_digest": record.c4_snapshot_digest,
            "architecture_payload_sha256": record.architecture_payload_sha256,
            "c3_snapshot_digest": record.c3_snapshot_digest,
            "work_items_digest": record.work_items_digest,
            "release_gates_digest": record.release_gates_digest,
            "key_id": record.key_id,
            "payload_sha256": record.payload_sha256,
            "signature_sha256": record.signature_sha256,
            "execution_status": record.execution_status,
            "gate_effect": record.gate_effect,
        }

    @staticmethod
    def _replay_matches(
        row: sqlite3.Row,
        plan_id: str,
        architecture_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        actor: str,
    ) -> bool:
        return (
            str(row["plan_id"]) == plan_id
            and str(row["architecture_id"]) == architecture_id
            and str(row["key_id"]) == key_id
            and bytes(row["payload"]) == payload
            and bytes(row["signature"]) == signature
            and str(row["admitted_by"]) == actor
        )

    def _assert_signature(self, key_id: str, payload: bytes, signature: bytes) -> None:
        root = self.continuity.verify_trust_root(key_id)
        if not getattr(root, "ok", False):
            raise IntegrityError(
                "C5 execution plan trust root verification failed",
                {"key_id": key_id, "defects": list(getattr(root, "defects", ()))},
            )
        row = self.database.connection.execute(
            "SELECT public_key_pem FROM continuity_trust_roots WHERE key_id = ?",
            (key_id,),
        ).fetchone()
        if row is None or not self.signature_verifier.verify(
            bytes(row["public_key_pem"]), payload, signature
        ):
            raise IntegrityError("C5 execution plan signature is invalid")

    def _provisional(
        self,
        value: Mapping[str, object],
        snapshot: C5ExecutionPlanSnapshot,
        key_id: str,
        payload: bytes,
        signature: bytes,
        admitted_at: str,
        actor: str,
    ) -> C5ExecutionPlan:
        work_items_digest, release_gates_digest = self._derived_digests(value)
        independence = value["independence_basis"]
        policy = value["execution_policy"]
        assert isinstance(independence, dict)
        assert isinstance(policy, dict)
        return C5ExecutionPlan(
            str(value["plan_id"]),
            str(value["plan_version"]),
            str(value["architecture_id"]),
            str(value["architecture_version"]),
            str(value["architecture_payload_sha256"]),
            str(value["c3_snapshot_digest"]),
            snapshot.snapshot_digest,
            snapshot.c4_baseline_id,
            work_items_digest,
            release_gates_digest,
            str(value["risk_register_digest"]),
            str(value["resource_model_digest"]),
            str(value["verification_strategy_digest"]),
            str(value["planner_identity"]),
            str(value["planner_environment"]),
            str(value["reviewer_identity"]),
            str(value["reviewer_environment"]),
            str(value["planned_at_utc"]),
            dict(independence),
            str(value["execution_status"]),
            str(value["gate_effect"]),
            dict(policy),
            key_id,
            payload,
            hashlib.sha256(payload).hexdigest(),
            signature,
            hashlib.sha256(signature).hexdigest(),
            admitted_at,
            actor,
            "pending",
            "pending",
        )

    def admit_plan(
        self,
        architecture_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        *,
        actor: str,
        occurred_at: str | None = None,
    ) -> C5ExecutionPlan:
        architecture_id = self._text(architecture_id, "architecture_id")
        key_id = self._text(key_id, "key_id")
        actor = self._text(actor, "actor")
        payload = self._bounded_payload(payload)
        signature = self._bounded_signature(signature)
        admitted_at = self._timestamp(occurred_at or utc_now(), "admitted_at")
        value = self._parse_payload(payload)
        if value["architecture_id"] != architecture_id:
            raise StateTransitionError("signed C5 execution plan targets another architecture")
        snapshot = self.snapshot(architecture_id)
        self._assert_payload_snapshot(value, snapshot)
        self._assert_signature(key_id, payload, signature)
        if self._dt(admitted_at) < self._dt(str(value["planned_at_utc"])):
            raise StateTransitionError("C5 plan admission predates its signed planning timestamp")
        plan_id = str(value["plan_id"])
        existing = self._row_for(plan_id, architecture_id)
        if existing is not None:
            if not self._replay_matches(existing, plan_id, architecture_id, key_id, payload, signature, actor):
                raise ConflictError(
                    "C5 execution plan identifier or architecture already binds different material",
                    {"plan_id": plan_id, "architecture_id": architecture_id},
                )
            record = self._record(existing)
            verification = self.verify_plan(plan_id)
            if not verification.ok:
                raise IntegrityError(
                    "existing C5 execution plan failed verification",
                    {"plan_id": plan_id, "defects": list(verification.defects)},
                )
            return record
        provisional = self._provisional(
            value, snapshot, key_id, payload, signature, admitted_at, actor
        )
        event_payload = self._event_payload(provisional)
        columns = (
            "plan_id", "plan_version", "architecture_id", "architecture_version",
            "c4_baseline_id", "c4_snapshot_digest", "architecture_payload_sha256",
            "c3_snapshot_digest", "work_items_digest", "release_gates_digest",
            "risk_register_digest", "resource_model_digest", "verification_strategy_digest",
            "execution_policy_json", "planner_identity", "planner_environment",
            "reviewer_identity", "reviewer_environment", "planned_at_utc",
            "independence_basis_json", "execution_status", "gate_effect", "key_id",
            "payload", "payload_sha256", "signature", "signature_sha256", "admitted_at",
            "admitted_by", "ledger_event_id", "ledger_hash",
        )
        try:
            with self.database.transaction() as connection:
                current = self._build_snapshot(architecture_id)
                if current != snapshot:
                    raise ConflictError(
                        "C4 snapshot changed during C5 execution plan admission",
                        {"architecture_id": architecture_id},
                    )
                self._assert_payload_snapshot(value, current)
                self._assert_signature(key_id, payload, signature)
                race = connection.execute(
                    "SELECT plan_id FROM c5_execution_plans "
                    "WHERE plan_id = ? OR architecture_id = ?",
                    (plan_id, architecture_id),
                ).fetchone()
                if race is not None:
                    raise ConflictError("C5 execution plan appeared during admission")
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"continuity:c5:execution-plan:{plan_id}",
                    _EVENT_KIND,
                    event_payload,
                    actor=actor,
                    occurred_at=admitted_at,
                )
                values: list[object] = []
                for field in columns:
                    if field == "execution_policy_json":
                        values.append(canonical_json(dict(provisional.execution_policy)))
                    elif field == "independence_basis_json":
                        values.append(canonical_json(dict(provisional.independence_basis)))
                    elif field == "payload":
                        values.append(sqlite3.Binary(provisional.payload))
                    elif field == "signature":
                        values.append(sqlite3.Binary(provisional.signature))
                    elif field == "ledger_event_id":
                        values.append(receipt.event_id)
                    elif field == "ledger_hash":
                        values.append(receipt.record_hash)
                    else:
                        values.append(getattr(provisional, field))
                placeholders = ",".join("?" for _ in columns)
                connection.execute(
                    f"INSERT INTO c5_execution_plans ({','.join(columns)}) "
                    f"VALUES ({placeholders})",
                    tuple(values),
                )
                for ordinal, item in enumerate(value["work_items"]):
                    material = dict(item)
                    connection.execute(
                        "INSERT INTO c5_execution_plan_work_items "
                        "(plan_id, ordinal, work_item_id, material_json, material_sha256, "
                        "recorded_at, recorded_by, member_ledger_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            plan_id,
                            ordinal,
                            material["work_item_id"],
                            canonical_json(material),
                            sha256_digest(material),
                            admitted_at,
                            actor,
                            receipt.record_hash,
                        ),
                    )
                for ordinal, gate in enumerate(value["release_gates"]):
                    material = dict(gate)
                    connection.execute(
                        "INSERT INTO c5_execution_plan_release_gates "
                        "(plan_id, ordinal, gate_id, material_json, material_sha256, "
                        "recorded_at, recorded_by, member_ledger_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            plan_id,
                            ordinal,
                            material["gate_id"],
                            canonical_json(material),
                            sha256_digest(material),
                            admitted_at,
                            actor,
                            receipt.record_hash,
                        ),
                    )
        except sqlite3.IntegrityError as exc:
            race = self._row_for(plan_id, architecture_id)
            if race is not None and self._replay_matches(
                race, plan_id, architecture_id, key_id, payload, signature, actor
            ):
                return self._record(race)
            raise ConflictError(
                "C5 execution plan violates an immutable constraint",
                {"plan_id": plan_id, "architecture_id": architecture_id},
            ) from exc
        return self.get_plan(plan_id)

    admit_execution_plan = admit_plan
    admit = admit_plan
    prepare_execution_plan = prepare

    @staticmethod
    def _members(
        database: Any,
        table: str,
        plan_id: str,
    ) -> tuple[Mapping[str, object], ...]:
        rows = database.connection.execute(
            f"SELECT material_json FROM {table} WHERE plan_id = ? ORDER BY ordinal",
            (plan_id,),
        ).fetchall()
        values: list[Mapping[str, object]] = []
        for row in rows:
            try:
                material = json.loads(str(row["material_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise IntegrityError("stored C5 execution plan member is invalid") from exc
            if not isinstance(material, dict):
                raise IntegrityError("stored C5 execution plan member is invalid")
            values.append(material)
        return tuple(values)

    def get_work_items(self, plan_id: str) -> tuple[Mapping[str, object], ...]:
        self.get_plan(plan_id)
        return self._members(self.database, "c5_execution_plan_work_items", plan_id)

    def get_release_gates(self, plan_id: str) -> tuple[Mapping[str, object], ...]:
        self.get_plan(plan_id)
        return self._members(
            self.database,
            "c5_execution_plan_release_gates",
            plan_id,
        )

    def _verify_memberships(
        self,
        record: C5ExecutionPlan,
        expected: list[Mapping[str, object]],
        table: str,
        identifier_field: str,
        defect_prefix: str,
        defects: list[str],
    ) -> None:
        rows = self.database.connection.execute(
            f"SELECT * FROM {table} WHERE plan_id = ? ORDER BY ordinal",
            (record.plan_id,),
        ).fetchall()
        if len(rows) != len(expected):
            defects.append(f"{defect_prefix}_COUNT_MISMATCH")
        actual: list[Mapping[str, object]] = []
        for ordinal, row in enumerate(rows):
            if int(row["ordinal"]) != ordinal:
                defects.append(f"{defect_prefix}_ORDINAL_MISMATCH:{ordinal}")
            try:
                material = json.loads(str(row["material_json"]))
            except (TypeError, json.JSONDecodeError):
                defects.append(f"{defect_prefix}_MATERIAL_INVALID:{ordinal}")
                continue
            if not isinstance(material, dict):
                defects.append(f"{defect_prefix}_MATERIAL_INVALID:{ordinal}")
                continue
            actual.append(material)
            if str(row[identifier_field]) != str(material.get(identifier_field)):
                defects.append(f"{defect_prefix}_BINDING_MISMATCH:{ordinal}")
            if (
                str(row["material_json"]) != canonical_json(material)
                or str(row["material_sha256"]) != sha256_digest(material)
            ):
                defects.append(f"{defect_prefix}_DIGEST_MISMATCH:{ordinal}")
            if (
                str(row["recorded_at"]) != record.admitted_at
                or str(row["recorded_by"]) != record.admitted_by
                or str(row["member_ledger_hash"]) != record.ledger_hash
            ):
                defects.append(f"{defect_prefix}_PROVENANCE_MISMATCH:{ordinal}")
        if actual != [dict(item) for item in expected]:
            defects.append(f"{defect_prefix}_MATERIAL_NOT_CURRENT")

    def verify_plan(self, plan_id: str) -> C5ExecutionPlanVerification:
        plan_id = self._text(plan_id, "plan_id")
        row = self.database.connection.execute(
            "SELECT * FROM c5_execution_plans WHERE plan_id = ?", (plan_id,)
        ).fetchone()
        if row is None:
            return C5ExecutionPlanVerification(plan_id, ("PLAN_NOT_FOUND",))
        defects: list[str] = []
        try:
            record = self._record(row)
        except (IntegrityError, KeyError, TypeError, ValueError, ValidationError):
            return C5ExecutionPlanVerification(plan_id, ("PLAN_ROW_INVALID",))
        if hashlib.sha256(record.payload).hexdigest() != record.payload_sha256:
            defects.append("PLAN_PAYLOAD_DIGEST_MISMATCH")
        if hashlib.sha256(record.signature).hexdigest() != record.signature_sha256:
            defects.append("PLAN_SIGNATURE_DIGEST_MISMATCH")
        parsed: dict[str, object] | None = None
        try:
            parsed = self._parse_payload(record.payload)
        except (IntegrityError, StateTransitionError, TypeError, ValueError, ValidationError):
            defects.append("PLAN_PAYLOAD_INVALID")
        try:
            self._assert_signature(record.key_id, record.payload, record.signature)
        except (IntegrityError, NotFoundError, OSError, TypeError, ValueError, sqlite3.Error):
            defects.append("PLAN_SIGNATURE_INVALID")
        current: C5ExecutionPlanSnapshot | None = None
        try:
            current = self._build_snapshot(record.architecture_id)
        except (
            IntegrityError,
            NotFoundError,
            StateTransitionError,
            TypeError,
            ValueError,
            ValidationError,
            sqlite3.Error,
        ):
            defects.append("PLAN_C4_SNAPSHOT_INVALID")
        if current is not None:
            if current.snapshot_digest != record.c4_snapshot_digest:
                defects.append("PLAN_C4_SNAPSHOT_STALE")
            if current.c4_baseline_id != record.c4_baseline_id:
                defects.append("PLAN_C4_BASELINE_MISMATCH")
            if parsed is not None:
                try:
                    self._assert_payload_snapshot(parsed, current)
                except (IntegrityError, StateTransitionError, ValidationError, TypeError, ValueError):
                    defects.append("PLAN_PAYLOAD_C4_MISMATCH")
        if parsed is not None:
            work_digest, gate_digest = self._derived_digests(parsed)
            expected: dict[str, object] = {
                "plan_id": record.plan_id,
                "plan_version": record.plan_version,
                "architecture_id": record.architecture_id,
                "architecture_version": record.architecture_version,
                "architecture_payload_sha256": record.architecture_payload_sha256,
                "c3_snapshot_digest": record.c3_snapshot_digest,
                "risk_register_digest": record.risk_register_digest,
                "resource_model_digest": record.resource_model_digest,
                "verification_strategy_digest": record.verification_strategy_digest,
                "planner_identity": record.planner_identity,
                "planner_environment": record.planner_environment,
                "reviewer_identity": record.reviewer_identity,
                "reviewer_environment": record.reviewer_environment,
                "planned_at_utc": record.planned_at_utc,
                "independence_basis": dict(record.independence_basis),
                "execution_status": record.execution_status,
                "gate_effect": record.gate_effect,
            }
            if any(parsed.get(field) != observed for field, observed in expected.items()):
                defects.append("PLAN_PAYLOAD_RECORD_MISMATCH")
            if parsed.get("execution_policy") != dict(record.execution_policy):
                defects.append("PLAN_POLICY_MISMATCH")
            if work_digest != record.work_items_digest:
                defects.append("PLAN_WORK_ITEMS_DIGEST_MISMATCH")
            if gate_digest != record.release_gates_digest:
                defects.append("PLAN_RELEASE_GATES_DIGEST_MISMATCH")
            self._verify_memberships(
                record,
                parsed["work_items"],
                "c5_execution_plan_work_items",
                "work_item_id",
                "PLAN_WORK_ITEMS",
                defects,
            )
            self._verify_memberships(
                record,
                parsed["release_gates"],
                "c5_execution_plan_release_gates",
                "gate_id",
                "PLAN_RELEASE_GATES",
                defects,
            )
        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?", (record.ledger_event_id,)
        ).fetchone()
        expected_event = self._event_payload(record)
        if event is None:
            defects.append("PLAN_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != f"continuity:c5:execution-plan:{record.plan_id}":
                defects.append("PLAN_LEDGER_STREAM_MISMATCH")
            if str(event["kind"]) != _EVENT_KIND:
                defects.append("PLAN_LEDGER_KIND_MISMATCH")
            if str(event["actor"]) != record.admitted_by:
                defects.append("PLAN_LEDGER_ACTOR_MISMATCH")
            if str(event["occurred_at"]) != record.admitted_at:
                defects.append("PLAN_LEDGER_TIMESTAMP_MISMATCH")
            if str(event["record_hash"]) != record.ledger_hash:
                defects.append("PLAN_LEDGER_HASH_MISMATCH")
            try:
                if json.loads(str(event["payload_json"])) != expected_event:
                    defects.append("PLAN_LEDGER_PAYLOAD_MISMATCH")
            except (TypeError, json.JSONDecodeError):
                defects.append("PLAN_LEDGER_PAYLOAD_INVALID")
        try:
            chain = self.ledger.verify(f"continuity:c5:execution-plan:{record.plan_id}")
            defects.extend(
                f"PLAN_LEDGER_CHAIN:{getattr(defect, 'code', 'INVALID')}"
                for defect in getattr(chain, "defects", ())
            )
        except (IntegrityError, TypeError, ValueError, sqlite3.Error):
            defects.append("PLAN_LEDGER_CHAIN_INVALID")
        return C5ExecutionPlanVerification(plan_id, tuple(dict.fromkeys(defects)))

    verify_execution_plan = verify_plan
    verify = verify_plan
