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
_VERSION = "3.2.0"
_RUNTIME_STATUS = "NOT_PROVEN"
_GATE_EFFECT = "C4_ARCHITECTURE_BASELINE_ADMITTED_NO_DEPLOYMENT"
_EVENT_KIND = "C4_ARCHITECTURE_BASELINE_ADMITTED"
_ACTION = "c4.architecture.baseline.admit"
_DECISION_VERDICTS = frozenset({"C3_CANDIDATE_SELECTED", "C3_NO_SELECTION"})
_EXECUTION_STATUSES = frozenset(
    {
        "C3_ADOPTION_EXECUTION_REQUESTED_NOT_EXECUTED",
        "C3_ADOPTION_EXECUTION_RUNNING",
        "C3_ADOPTION_EXECUTION_SUCCEEDED",
        "C3_ADOPTION_EXECUTION_FAILED_NO_EFFECT",
        "C3_ADOPTION_EXECUTION_FAILED_ROLLED_BACK",
        "C3_ADOPTION_EXECUTION_ROLLBACK_FAILED",
    }
)
_INDEPENDENCE_FIELDS = frozenset({"excluded_identities", "statement"})
_DOCUMENT_FIELDS = (
    "architecture_document_sha256",
    "component_manifest_sha256",
    "decision_log_sha256",
    "threat_model_sha256",
    "deployment_topology_sha256",
    "data_flow_sha256",
    "rollback_strategy_sha256",
)
_REQUIRED_FIELDS = frozenset(
    {
        "architecture_id", "architecture_version", "c3_run_id", "qualification_run_id",
        "certificate_id", "c3_decision_id", "c3_decision_verdict", "decision_payload_sha256",
        "selected_candidate_artifact_id", "qualification_head_hash", "candidate_set_digest",
        "evaluation_set_digest", "c3_snapshot_digest", "adoption_id", "adoption_status",
        "adoption_rollback_plan_sha256", "execution_id", "execution_status",
        "execution_receipt_sha256", "rollback_receipt_sha256", *_DOCUMENT_FIELDS,
        "architect_identity", "architect_environment", "reviewer_identity",
        "reviewer_environment", "designed_at_utc", "independence_basis",
        "external_runtime_integration_status", "gate_effect",
    }
)
_OPTIONAL_FIELDS = frozenset({"baseline_id"})


@dataclass(frozen=True)
class C4ArchitectureSnapshot:
    c3_run_id: str
    qualification_run_id: str
    certificate_id: str
    c3_decision_id: str
    c3_decision_verdict: str
    decision_payload_sha256: str
    selected_candidate_artifact_id: str | None
    qualification_head_hash: str
    candidate_set_digest: str
    evaluation_set_digest: str
    latest_evidence_at: str | None
    decision_decided_at: str | None
    adoption_id: str | None
    adoption_status: str | None
    adoption_rollback_plan_sha256: str | None
    adoption_authorized_at: str | None
    execution_id: str | None
    execution_status: str | None
    execution_receipt_sha256: str | None
    rollback_receipt_sha256: str | None
    execution_requested_at: str | None
    external_runtime_integration_status: str
    members: tuple[Mapping[str, Any], ...]
    material_identities: tuple[str, ...]
    snapshot_digest: str


@dataclass(frozen=True)
class C4ArchitectureBaselinePreparation:
    baseline_id: str
    architecture_id: str
    architecture_version: str
    c3_run_id: str
    c3_snapshot_digest: str
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]


@dataclass(frozen=True)
class C4ArchitectureBaseline:
    baseline_id: str
    architecture_id: str
    architecture_version: str
    c3_run_id: str
    qualification_run_id: str
    certificate_id: str
    c3_decision_id: str
    c3_snapshot_digest: str
    decision_payload_sha256: str
    selected_candidate_artifact_id: str | None
    qualification_head_hash: str
    candidate_set_digest: str
    evaluation_set_digest: str
    adoption_id: str | None
    adoption_status: str | None
    adoption_rollback_plan_sha256: str | None
    execution_id: str | None
    execution_status: str | None
    execution_receipt_sha256: str | None
    rollback_receipt_sha256: str | None
    architecture_document_sha256: str
    component_manifest_sha256: str
    decision_log_sha256: str
    threat_model_sha256: str
    deployment_topology_sha256: str
    data_flow_sha256: str
    rollback_strategy_sha256: str
    architect_identity: str
    architect_environment: str
    reviewer_identity: str
    reviewer_environment: str
    designed_at_utc: str
    independence_basis: Mapping[str, Any]
    external_runtime_integration_status: str
    gate_effect: str
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
class C4ArchitectureBaselineVerification:
    baseline_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C4ArchitectureService:
    """Exact-byte C4 baseline authority; it never deploys or promotes product state."""

    def __init__(self, database: Any, ledger: Any, *dependencies: Any,
                 signature_verifier: Any | None = None, **named: Any) -> None:
        self.database = database
        self.ledger = ledger
        deps = [*dependencies, *named.values()]
        self.trust = self._find(deps, lambda x: hasattr(x, "authorize") and hasattr(x, "verify_decision"))
        self.continuity = self._find(deps, lambda x: hasattr(x, "verify_trust_root"))
        self.decisions = self._find(deps, lambda x: hasattr(x, "snapshot") and hasattr(x, "verify_decision"))
        self.adoption = self._find(deps, lambda x: hasattr(x, "get_adoption") and hasattr(x, "verify_adoption"))
        self.executions = self._find(deps, lambda x: hasattr(x, "get_execution") and hasattr(x, "verify_execution"))
        if self.continuity is None or self.decisions is None:
            raise ValidationError("C4 architecture baseline requires continuity and C3 decision authorities")
        self.signature_verifier = signature_verifier or getattr(
            self.continuity, "signature_verifier", OpenSSLEd25519Verifier()
        )
        self._initialize_schema()

    @staticmethod
    def _find(values: list[Any], predicate: Any) -> Any | None:
        return next((value for value in values if value is not None and predicate(value)), None)

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
    def _optional_text(cls, value: object, field: str) -> str | None:
        return None if value is None else cls._text(value, field)

    @classmethod
    def _optional_digest(cls, value: object, field: str) -> str | None:
        return None if value is None else cls._digest(value, field)

    @staticmethod
    def _value(obj: object, field: str, default: object = None) -> object:
        return obj.get(field, default) if isinstance(obj, Mapping) else getattr(obj, field, default)

    @staticmethod
    def _stream(baseline_id: str) -> str:
        return f"continuity:c4:architecture-baseline:{baseline_id}"

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
                payload.decode("utf-8"), object_pairs_hook=no_duplicates,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON constant")),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValidationError("C4 architecture baseline payload must be strict UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise ValidationError("C4 architecture baseline payload must be a JSON object")
        fields = frozenset(value)
        allowed = _REQUIRED_FIELDS | _OPTIONAL_FIELDS
        if not (_REQUIRED_FIELDS <= fields <= allowed):
            raise ValidationError(
                "C4 architecture baseline payload fields do not match the contract",
                {"missing": sorted(_REQUIRED_FIELDS - fields), "unexpected": sorted(fields - allowed)},
            )
        for field in (
            "architecture_id", "architecture_version", "c3_run_id", "qualification_run_id",
            "certificate_id", "c3_decision_id", "decision_payload_sha256", "qualification_head_hash",
            "candidate_set_digest", "evaluation_set_digest", "c3_snapshot_digest", *_DOCUMENT_FIELDS,
            "architect_identity", "architect_environment", "reviewer_identity", "reviewer_environment",
            "external_runtime_integration_status", "gate_effect",
        ):
            value[field] = cls._text(value[field], field)
        if value["architecture_version"] != _VERSION:
            raise ValidationError(f"architecture_version must equal {_VERSION}")
        for field in ("decision_payload_sha256", "qualification_head_hash", "candidate_set_digest", "evaluation_set_digest", "c3_snapshot_digest", *_DOCUMENT_FIELDS):
            cls._digest(value[field], field)
        value["c3_decision_verdict"] = cls._text(value["c3_decision_verdict"], "c3_decision_verdict")
        if value["c3_decision_verdict"] not in _DECISION_VERDICTS:
            raise ValidationError("c3_decision_verdict is outside the closed contract")
        value["selected_candidate_artifact_id"] = cls._optional_text(value["selected_candidate_artifact_id"], "selected_candidate_artifact_id")
        for field in ("adoption_id", "execution_id"):
            value[field] = cls._optional_text(value[field], field)
        value["adoption_status"] = cls._optional_text(value["adoption_status"], "adoption_status")
        if value["adoption_status"] not in {None, "C3_ADOPTION_AUTHORIZED_NOT_EXECUTED"}:
            raise ValidationError("adoption_status is outside the closed contract")
        value["adoption_rollback_plan_sha256"] = cls._optional_digest(value["adoption_rollback_plan_sha256"], "adoption_rollback_plan_sha256")
        value["execution_status"] = cls._optional_text(value["execution_status"], "execution_status")
        if value["execution_status"] not in {None, *_EXECUTION_STATUSES}:
            raise ValidationError("execution_status is outside the closed contract")
        value["execution_receipt_sha256"] = cls._optional_digest(value["execution_receipt_sha256"], "execution_receipt_sha256")
        value["rollback_receipt_sha256"] = cls._optional_digest(value["rollback_receipt_sha256"], "rollback_receipt_sha256")
        value["designed_at_utc"] = cls._timestamp(value["designed_at_utc"], "designed_at_utc")
        independence = value["independence_basis"]
        if not isinstance(independence, dict) or frozenset(independence) != _INDEPENDENCE_FIELDS:
            raise ValidationError("independence_basis fields do not match the contract")
        excluded = independence["excluded_identities"]
        if not isinstance(excluded, list) or any(not isinstance(item, str) or not item.strip() for item in excluded) or excluded != sorted(excluded) or len(set(excluded)) != len(excluded):
            raise ValidationError("independence_basis.excluded_identities must be sorted and unique")
        independence["statement"] = cls._text(independence["statement"], "independence_basis.statement")
        if value["external_runtime_integration_status"] != _RUNTIME_STATUS:
            raise ValidationError("external_runtime_integration_status must remain NOT_PROVEN")
        if value["gate_effect"] != _GATE_EFFECT:
            raise ValidationError(f"gate_effect must equal {_GATE_EFFECT}")
        if "baseline_id" in value:
            value["baseline_id"] = cls._text(value["baseline_id"], "baseline_id")
        return value

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c4_architecture_baselines (
                    baseline_id TEXT PRIMARY KEY, architecture_id TEXT NOT NULL,
                    architecture_version TEXT NOT NULL CHECK (architecture_version = '3.2.0'),
                    c3_run_id TEXT NOT NULL UNIQUE, qualification_run_id TEXT NOT NULL,
                    certificate_id TEXT NOT NULL, c3_decision_id TEXT NOT NULL UNIQUE,
                    c3_snapshot_digest TEXT NOT NULL CHECK (length(c3_snapshot_digest) = 64),
                    decision_payload_sha256 TEXT NOT NULL CHECK (length(decision_payload_sha256) = 64),
                    selected_candidate_artifact_id TEXT, qualification_head_hash TEXT NOT NULL CHECK (length(qualification_head_hash) = 64),
                    candidate_set_digest TEXT NOT NULL CHECK (length(candidate_set_digest) = 64),
                    evaluation_set_digest TEXT NOT NULL CHECK (length(evaluation_set_digest) = 64),
                    adoption_id TEXT, adoption_status TEXT,
                    adoption_rollback_plan_sha256 TEXT CHECK (adoption_rollback_plan_sha256 IS NULL OR length(adoption_rollback_plan_sha256) = 64),
                    execution_id TEXT, execution_status TEXT,
                    execution_receipt_sha256 TEXT CHECK (execution_receipt_sha256 IS NULL OR length(execution_receipt_sha256) = 64),
                    rollback_receipt_sha256 TEXT CHECK (rollback_receipt_sha256 IS NULL OR length(rollback_receipt_sha256) = 64),
                    architecture_document_sha256 TEXT NOT NULL CHECK (length(architecture_document_sha256) = 64),
                    component_manifest_sha256 TEXT NOT NULL CHECK (length(component_manifest_sha256) = 64),
                    decision_log_sha256 TEXT NOT NULL CHECK (length(decision_log_sha256) = 64),
                    threat_model_sha256 TEXT NOT NULL CHECK (length(threat_model_sha256) = 64),
                    deployment_topology_sha256 TEXT NOT NULL CHECK (length(deployment_topology_sha256) = 64),
                    data_flow_sha256 TEXT NOT NULL CHECK (length(data_flow_sha256) = 64),
                    rollback_strategy_sha256 TEXT NOT NULL CHECK (length(rollback_strategy_sha256) = 64),
                    architect_identity TEXT NOT NULL, architect_environment TEXT NOT NULL,
                    reviewer_identity TEXT NOT NULL, reviewer_environment TEXT NOT NULL,
                    designed_at_utc TEXT NOT NULL, independence_basis_json TEXT NOT NULL,
                    external_runtime_integration_status TEXT NOT NULL CHECK (external_runtime_integration_status = 'NOT_PROVEN'),
                    gate_effect TEXT NOT NULL CHECK (gate_effect = 'C4_ARCHITECTURE_BASELINE_ADMITTED_NO_DEPLOYMENT'),
                    key_id TEXT NOT NULL, payload BLOB NOT NULL,
                    payload_sha256 TEXT NOT NULL UNIQUE CHECK (length(payload_sha256) = 64),
                    signature BLOB NOT NULL, signature_sha256 TEXT NOT NULL CHECK (length(signature_sha256) = 64),
                    admitted_at TEXT NOT NULL, admitted_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE, ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (key_id) REFERENCES continuity_trust_roots(key_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c4_architecture_baseline_members (
                    baseline_id TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                    member_kind TEXT NOT NULL CHECK (member_kind IN ('CANDIDATE', 'EVALUATION')),
                    artifact_id TEXT NOT NULL, material_json TEXT NOT NULL,
                    material_sha256 TEXT NOT NULL CHECK (length(material_sha256) = 64),
                    recorded_at TEXT NOT NULL, recorded_by TEXT NOT NULL,
                    member_ledger_hash TEXT NOT NULL CHECK (length(member_ledger_hash) = 64),
                    PRIMARY KEY (baseline_id, ordinal), UNIQUE (baseline_id, member_kind, artifact_id),
                    FOREIGN KEY (baseline_id) REFERENCES c4_architecture_baselines(baseline_id)
                )
                """
            )
            for table in ("c4_architecture_baselines", "c4_architecture_baseline_members"):
                connection.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_no_update BEFORE UPDATE ON {table} BEGIN SELECT RAISE(ABORT, '{table} rows are immutable'); END")
                connection.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_no_delete BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT, '{table} rows are immutable'); END")

    def _decision_for_run(self, c3_run_id: str) -> Any:
        row = self.database.connection.execute("SELECT decision_id FROM c3_decisions WHERE c3_run_id = ?", (c3_run_id,)).fetchone()
        if row is not None:
            try:
                return self.decisions.get_decision(str(row["decision_id"]))
            except AttributeError:
                pass
        for name in ("get_decision_for_run", "get_for_run"):
            method = getattr(self.decisions, name, None)
            if method:
                return method(c3_run_id)
        raise NotFoundError("C3 signed decision does not exist for the run", {"c3_run_id": c3_run_id})

    def _verify_decision(self, decision_id: str) -> None:
        result = self.decisions.verify_decision(decision_id)
        if not getattr(result, "ok", False):
            raise IntegrityError("C3 signed decision verification failed", {"decision_id": decision_id, "defects": list(getattr(result, "defects", ()))})

    def _adoption_for_run(self, c3_run_id: str) -> Any | None:
        try:
            row = self.database.connection.execute("SELECT adoption_id FROM c3_adoptions WHERE c3_run_id = ?", (c3_run_id,)).fetchone()
        except sqlite3.OperationalError:
            row = None
        if row is not None and self.adoption is not None:
            return self.adoption.get_adoption(str(row["adoption_id"]))
        method = getattr(self.adoption, "get_adoption_for_run", None)
        if method:
            try:
                return method(c3_run_id)
            except NotFoundError:
                return None
        return None

    def _execution_for_adoption(self, adoption_id: str) -> Any | None:
        try:
            row = self.database.connection.execute("SELECT execution_id FROM c3_adoption_execution_requests WHERE adoption_id = ?", (adoption_id,)).fetchone()
        except sqlite3.OperationalError:
            row = None
        if row is not None and self.executions is not None:
            return self.executions.get_execution(str(row["execution_id"]))
        method = getattr(self.executions, "get_execution_for_adoption", None)
        if method:
            try:
                return method(adoption_id)
            except NotFoundError:
                return None
        return None

    @staticmethod
    def _verify_source(source: Any, method_name: str, identifier: str, label: str) -> None:
        if source is None:
            raise IntegrityError(f"{label} authority is unavailable")
        result = getattr(source, method_name)(identifier)
        if not getattr(result, "ok", False):
            raise IntegrityError(f"{label} verification failed", {"identifier": identifier, "defects": list(getattr(result, "defects", ()))})

    def _members(self, source_snapshot: Any) -> tuple[Mapping[str, Any], ...]:
        result: list[Mapping[str, Any]] = []
        for kind, entries in (("CANDIDATE", getattr(source_snapshot, "candidates", ())), ("EVALUATION", getattr(source_snapshot, "evaluations", ()) )):
            for entry in entries:
                member = dict(entry)
                member["kind"] = kind
                for field in ("artifact_id", "recorded_at", "recorded_by", "ledger_hash", "material_sha256"):
                    self._text(member.get(field), field)
                self._digest(member["ledger_hash"], "ledger_hash")
                self._digest(member["material_sha256"], "material_sha256")
                result.append(member)
        return tuple(result)

    def _binding_actor(self, c3_run_id: str) -> str | None:
        try:
            row = self.database.connection.execute("SELECT started_by FROM c3_qualification_bindings WHERE c3_run_id = ?", (c3_run_id,)).fetchone()
        except sqlite3.OperationalError:
            row = None
        return str(row["started_by"]) if row else None

    def _build_snapshot(self, c3_run_id: str) -> C4ArchitectureSnapshot:
        decision = self._decision_for_run(c3_run_id)
        decision_id = self._text(self._value(decision, "decision_id"), "decision_id")
        self._verify_decision(decision_id)
        source = self.decisions.snapshot(c3_run_id)
        members = self._members(source)
        if self._value(decision, "c3_run_id") != c3_run_id:
            raise IntegrityError("C3 decision is bound to another run")
        qual_id = self._text(getattr(source, "qualification_run_id", None), "qualification_run_id")
        cert_id = self._text(getattr(source, "certificate_id", None), "certificate_id")
        verdict_raw = self._value(decision, "verdict")
        verdict = self._text(getattr(verdict_raw, "value", verdict_raw), "c3_decision_verdict")
        if verdict not in _DECISION_VERDICTS:
            raise IntegrityError("C3 decision verdict is outside the closed contract")
        selected = self._optional_text(self._value(decision, "selected_candidate_artifact_id"), "selected_candidate_artifact_id")
        candidate_ids = {str(member["artifact_id"]) for member in members if member["kind"] == "CANDIDATE"}
        if verdict == "C3_CANDIDATE_SELECTED" and (selected is None or selected not in candidate_ids):
            raise IntegrityError("selected C3 candidate is absent from the verified snapshot")
        if verdict == "C3_NO_SELECTION" and selected is not None:
            raise IntegrityError("C3_NO_SELECTION cannot carry a selected candidate")
        decision_digest = self._digest(self._value(decision, "payload_sha256"), "decision_payload_sha256")
        qual_head = self._digest(getattr(source, "qualification_head_hash", None), "qualification_head_hash")
        candidate_digest = self._digest(getattr(source, "candidate_set_digest", None), "candidate_set_digest")
        evaluation_digest = self._digest(getattr(source, "evaluation_set_digest", None), "evaluation_set_digest")
        for field, expected in (("qualification_head_hash", qual_head), ("candidate_set_digest", candidate_digest), ("evaluation_set_digest", evaluation_digest)):
            observed = self._value(decision, field)
            if observed is not None and str(observed) != expected:
                raise IntegrityError(f"C3 decision {field} does not match its snapshot")
        adoption = self._adoption_for_run(c3_run_id)
        if verdict == "C3_CANDIDATE_SELECTED" and adoption is None:
            raise StateTransitionError("a selected C3 candidate requires a clean adoption authorization")
        decision_time = self._value(decision, "decided_at_utc")
        decision_time = self._timestamp(decision_time, "decided_at_utc") if decision_time else None
        adoption_id = adoption_status = adoption_rollback = adoption_time = None
        execution_id = execution_status = execution_receipt = rollback_receipt = execution_time = None
        actors: set[str] = set()
        for field in ("decision_maker_identity", "admitted_by"):
            identity = self._optional_text(self._value(decision, field), field)
            if identity:
                actors.add(identity.strip())
        if (binding_actor := self._binding_actor(c3_run_id)):
            actors.add(binding_actor.strip())
        actors.update(str(member["recorded_by"]).strip() for member in members)
        if adoption is not None:
            adoption_id = self._text(self._value(adoption, "adoption_id"), "adoption_id")
            self._verify_source(self.adoption, "verify_adoption", adoption_id, "C3 adoption")
            candidate_member = next(member for member in members if member["kind"] == "CANDIDATE" and member["artifact_id"] == selected)
            adoption_material = self._value(adoption, "candidate_material_sha256")
            if adoption_material is None:
                adoption_material = self._value(adoption, "candidate_material_digest")
            if (
                self._value(adoption, "c3_run_id") != c3_run_id
                or self._value(adoption, "candidate_artifact_id") != selected
                or self._value(adoption, "c3_decision_id") != decision_id
                or (adoption_material is not None and adoption_material != candidate_member["material_sha256"])
                or self._value(adoption, "decision_payload_sha256") not in {None, decision_digest}
                or self._value(adoption, "qualification_head_hash") not in {None, qual_head}
            ):
                raise IntegrityError("C3 adoption does not match the selected decision")
            adoption_status_raw = self._value(adoption, "status")
            adoption_status = self._text(getattr(adoption_status_raw, "value", adoption_status_raw), "adoption_status")
            if adoption_status != "C3_ADOPTION_AUTHORIZED_NOT_EXECUTED":
                raise IntegrityError("C3 adoption status is outside the admitted baseline contract")
            adoption_rollback = self._digest(self._value(adoption, "rollback_plan_sha256"), "adoption_rollback_plan_sha256")
            raw_adoption_time = self._value(adoption, "authorized_at")
            adoption_time = self._timestamp(raw_adoption_time, "adoption_authorized_at") if raw_adoption_time else None
            identity = self._optional_text(self._value(adoption, "authorized_by"), "authorized_by")
            if identity:
                actors.add(identity.strip())
            execution = self._execution_for_adoption(adoption_id)
            if execution is not None:
                execution_id = self._text(self._value(execution, "execution_id"), "execution_id")
                self._verify_source(self.executions, "verify_execution", execution_id, "C3 adoption execution")
                for field, expected in (("adoption_id", adoption_id), ("c3_run_id", c3_run_id), ("c3_decision_id", decision_id), ("candidate_artifact_id", selected)):
                    if self._value(execution, field) != expected:
                        raise IntegrityError(f"C3 execution {field} does not match the snapshot")
                if (
                    self._value(execution, "candidate_material_sha256") not in {None, candidate_member["material_sha256"]}
                    or self._value(execution, "decision_payload_sha256") not in {None, decision_digest}
                    or self._value(execution, "qualification_head_hash") not in {None, qual_head}
                    or self._value(execution, "rollback_plan_sha256") not in {None, adoption_rollback}
                ):
                    raise IntegrityError("C3 execution material does not match the snapshot")
                status_raw = self._value(execution, "status")
                execution_status = self._text(getattr(status_raw, "value", status_raw), "execution_status")
                if execution_status not in _EXECUTION_STATUSES:
                    raise IntegrityError("C3 execution status is outside the closed contract")
                execution_receipt = self._optional_digest(self._value(execution, "execution_receipt_sha256"), "execution_receipt_sha256")
                rollback_receipt = self._optional_digest(self._value(execution, "rollback_receipt_sha256"), "rollback_receipt_sha256")
                raw_execution_time = self._value(execution, "requested_at")
                execution_time = self._timestamp(raw_execution_time, "execution_requested_at") if raw_execution_time else None
                identity = self._optional_text(self._value(execution, "requested_by"), "requested_by")
                if identity:
                    actors.add(identity.strip())
        latest = getattr(source, "latest_evidence_at", None)
        latest = self._timestamp(latest, "latest_evidence_at") if latest else None
        material = {
            "c3_run_id": c3_run_id, "qualification_run_id": qual_id, "certificate_id": cert_id,
            "c3_decision_id": decision_id, "c3_decision_verdict": verdict,
            "decision_payload_sha256": decision_digest, "selected_candidate_artifact_id": selected,
            "qualification_head_hash": qual_head, "candidate_set_digest": candidate_digest,
            "evaluation_set_digest": evaluation_digest, "latest_evidence_at": latest, "decision_decided_at": decision_time,
            "adoption": {"adoption_id": adoption_id, "status": adoption_status, "rollback_plan_sha256": adoption_rollback, "authorized_at": adoption_time},
            "execution": {"execution_id": execution_id, "status": execution_status, "execution_receipt_sha256": execution_receipt, "rollback_receipt_sha256": rollback_receipt, "requested_at": execution_time},
            "external_runtime_integration_status": _RUNTIME_STATUS,
            "members": [dict(member) for member in members], "material_identities": sorted(actors),
        }
        return C4ArchitectureSnapshot(
            c3_run_id, qual_id, cert_id, decision_id, verdict, decision_digest, selected,
            qual_head, candidate_digest, evaluation_digest, latest, decision_time, adoption_id, adoption_status,
            adoption_rollback, adoption_time, execution_id, execution_status, execution_receipt, rollback_receipt,
            execution_time, _RUNTIME_STATUS, members, tuple(sorted(actors)), sha256_digest(material)
        )

    def snapshot(self, c3_run_id: str) -> C4ArchitectureSnapshot:
        return self._build_snapshot(self._text(c3_run_id, "c3_run_id"))

    def prepare(self, baseline_id: str, c3_run_id: str, payload: Mapping[str, Any] | None = None) -> C4ArchitectureBaselinePreparation:
        baseline_id = self._text(baseline_id, "baseline_id")
        c3_run_id = self._text(c3_run_id, "c3_run_id")
        snapshot = self.snapshot(c3_run_id)
        architecture_id = self._text(payload.get("architecture_id", baseline_id), "architecture_id") if payload else baseline_id
        resource = f"continuity:c4:architecture-baseline:{baseline_id}"
        context = {"baseline_id": baseline_id, "architecture_id": architecture_id, "c3_run_id": c3_run_id, "c3_snapshot_digest": snapshot.snapshot_digest, "gate_effect": _GATE_EFFECT}
        return C4ArchitectureBaselinePreparation(baseline_id, architecture_id, _VERSION, c3_run_id, snapshot.snapshot_digest, _ACTION, resource, f"c4-architecture:{c3_run_id}", context)

    prepare_baseline = prepare

    @staticmethod
    def _snapshot_fields(snapshot: C4ArchitectureSnapshot) -> dict[str, object]:
        return {
            "c3_run_id": snapshot.c3_run_id, "qualification_run_id": snapshot.qualification_run_id,
            "certificate_id": snapshot.certificate_id, "c3_decision_id": snapshot.c3_decision_id,
            "c3_decision_verdict": snapshot.c3_decision_verdict, "decision_payload_sha256": snapshot.decision_payload_sha256,
            "selected_candidate_artifact_id": snapshot.selected_candidate_artifact_id, "qualification_head_hash": snapshot.qualification_head_hash,
            "candidate_set_digest": snapshot.candidate_set_digest, "evaluation_set_digest": snapshot.evaluation_set_digest,
            "c3_snapshot_digest": snapshot.snapshot_digest, "adoption_id": snapshot.adoption_id,
            "adoption_status": snapshot.adoption_status, "adoption_rollback_plan_sha256": snapshot.adoption_rollback_plan_sha256,
            "execution_id": snapshot.execution_id, "execution_status": snapshot.execution_status,
            "execution_receipt_sha256": snapshot.execution_receipt_sha256, "rollback_receipt_sha256": snapshot.rollback_receipt_sha256,
            "external_runtime_integration_status": _RUNTIME_STATUS,
        }

    @classmethod
    def _assert_payload_snapshot(cls, value: Mapping[str, object], snapshot: C4ArchitectureSnapshot) -> None:
        expected = cls._snapshot_fields(snapshot)
        mismatches = {key: {"expected": expected_value, "observed": value.get(key)} for key, expected_value in expected.items() if value.get(key) != expected_value}
        if mismatches:
            raise StateTransitionError("signed C4 architecture baseline does not match the current C3 snapshot", {"mismatches": mismatches})
        actors = list(snapshot.material_identities)
        architect, reviewer = str(value["architect_identity"]).strip(), str(value["reviewer_identity"]).strip()
        if architect == reviewer or architect in actors or reviewer in actors:
            raise StateTransitionError("C4 architect and reviewer identities are not independent", {"material_identities": actors})
        independence = value["independence_basis"]
        if not isinstance(independence, dict) or independence["excluded_identities"] != actors:
            raise StateTransitionError("signed independence exclusion set does not match C3 provenance")
        designed_at = cls._dt(str(value["designed_at_utc"]))
        for timestamp in (
            snapshot.latest_evidence_at,
            snapshot.decision_decided_at,
            snapshot.adoption_authorized_at,
            snapshot.execution_requested_at,
        ):
            if timestamp and designed_at < cls._dt(timestamp):
                raise StateTransitionError("C4 architecture baseline predates included C3 evidence")

    @classmethod
    def _blob(cls, row: sqlite3.Row, field: str) -> bytes:
        value = row[field]
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise IntegrityError(f"stored C4 architecture baseline {field} is not binary")
        return bytes(value)

    @classmethod
    def _record(cls, row: sqlite3.Row) -> C4ArchitectureBaseline:
        try:
            independence = json.loads(str(row["independence_basis_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrityError("stored C4 architecture baseline independence is invalid") from exc
        if not isinstance(independence, dict):
            raise IntegrityError("stored C4 architecture baseline independence is invalid")
        get = lambda field: row[field]
        return C4ArchitectureBaseline(
            cls._text(get("baseline_id"), "baseline_id"), cls._text(get("architecture_id"), "architecture_id"), cls._text(get("architecture_version"), "architecture_version"),
            cls._text(get("c3_run_id"), "c3_run_id"), cls._text(get("qualification_run_id"), "qualification_run_id"), cls._text(get("certificate_id"), "certificate_id"), cls._text(get("c3_decision_id"), "c3_decision_id"),
            cls._digest(get("c3_snapshot_digest"), "c3_snapshot_digest"), cls._digest(get("decision_payload_sha256"), "decision_payload_sha256"), cls._optional_text(get("selected_candidate_artifact_id"), "selected_candidate_artifact_id"),
            cls._digest(get("qualification_head_hash"), "qualification_head_hash"), cls._digest(get("candidate_set_digest"), "candidate_set_digest"), cls._digest(get("evaluation_set_digest"), "evaluation_set_digest"),
            cls._optional_text(get("adoption_id"), "adoption_id"), cls._optional_text(get("adoption_status"), "adoption_status"), cls._optional_digest(get("adoption_rollback_plan_sha256"), "adoption_rollback_plan_sha256"),
            cls._optional_text(get("execution_id"), "execution_id"), cls._optional_text(get("execution_status"), "execution_status"), cls._optional_digest(get("execution_receipt_sha256"), "execution_receipt_sha256"), cls._optional_digest(get("rollback_receipt_sha256"), "rollback_receipt_sha256"),
            *[cls._digest(get(field), field) for field in _DOCUMENT_FIELDS],
            cls._text(get("architect_identity"), "architect_identity"), cls._text(get("architect_environment"), "architect_environment"), cls._text(get("reviewer_identity"), "reviewer_identity"), cls._text(get("reviewer_environment"), "reviewer_environment"),
            cls._timestamp(get("designed_at_utc"), "designed_at_utc"), independence, cls._text(get("external_runtime_integration_status"), "external_runtime_integration_status"), cls._text(get("gate_effect"), "gate_effect"),
            cls._text(get("key_id"), "key_id"), cls._blob(row, "payload"), cls._digest(get("payload_sha256"), "payload_sha256"), cls._blob(row, "signature"), cls._digest(get("signature_sha256"), "signature_sha256"),
            cls._timestamp(get("admitted_at"), "admitted_at"), cls._text(get("admitted_by"), "admitted_by"), cls._text(get("ledger_event_id"), "ledger_event_id"), cls._digest(get("ledger_hash"), "ledger_hash"),
        )

    def _row_for(self, baseline_id: str, c3_run_id: str) -> sqlite3.Row | None:
        return self.database.connection.execute("SELECT * FROM c4_architecture_baselines WHERE baseline_id = ? OR c3_run_id = ? ORDER BY baseline_id LIMIT 1", (baseline_id, c3_run_id)).fetchone()

    def get_baseline(self, baseline_id: str) -> C4ArchitectureBaseline:
        baseline_id = self._text(baseline_id, "baseline_id")
        row = self.database.connection.execute("SELECT * FROM c4_architecture_baselines WHERE baseline_id = ?", (baseline_id,)).fetchone()
        if row is None:
            raise NotFoundError("C4 architecture baseline does not exist", {"baseline_id": baseline_id})
        return self._record(row)

    get = get_baseline

    def get_payload(self, baseline_id: str) -> bytes:
        return self.get_baseline(baseline_id).payload

    def get_members(self, baseline_id: str) -> tuple[Mapping[str, Any], ...]:
        baseline = self.get_baseline(baseline_id)
        rows = self.database.connection.execute("SELECT material_json FROM c4_architecture_baseline_members WHERE baseline_id = ? ORDER BY ordinal", (baseline.baseline_id,)).fetchall()
        result: list[Mapping[str, Any]] = []
        for row in rows:
            try:
                value = json.loads(str(row["material_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise IntegrityError("stored C4 architecture baseline member is invalid") from exc
            if not isinstance(value, dict):
                raise IntegrityError("stored C4 architecture baseline member is invalid")
            result.append(value)
        return tuple(result)

    @staticmethod
    def _event_payload(record: C4ArchitectureBaseline) -> dict[str, object]:
        return {"baseline_id": record.baseline_id, "architecture_id": record.architecture_id, "architecture_version": record.architecture_version, "c3_run_id": record.c3_run_id, "c3_snapshot_digest": record.c3_snapshot_digest, "key_id": record.key_id, "payload_sha256": record.payload_sha256, "signature_sha256": record.signature_sha256, "architect_identity": record.architect_identity, "reviewer_identity": record.reviewer_identity, "external_runtime_integration_status": record.external_runtime_integration_status, "gate_effect": record.gate_effect}

    @staticmethod
    def _replay_matches(row: sqlite3.Row, baseline_id: str, c3_run_id: str, key_id: str, payload: bytes, signature: bytes, actor: str) -> bool:
        return str(row["baseline_id"]) == baseline_id and str(row["c3_run_id"]) == c3_run_id and str(row["key_id"]) == key_id and bytes(row["payload"]) == payload and bytes(row["signature"]) == signature and str(row["admitted_by"]) == actor

    def _assert_signature(self, key_id: str, payload: bytes, signature: bytes) -> None:
        root = self.continuity.verify_trust_root(key_id)
        if not getattr(root, "ok", False):
            raise IntegrityError("C4 architecture trust root verification failed", {"key_id": key_id, "defects": list(getattr(root, "defects", ()))})
        row = self.database.connection.execute("SELECT public_key_pem FROM continuity_trust_roots WHERE key_id = ?", (key_id,)).fetchone()
        if row is None or not self.signature_verifier.verify(bytes(row["public_key_pem"]), payload, signature):
            raise IntegrityError("C4 architecture baseline signature is invalid")

    def _provisional(self, value: Mapping[str, object], baseline_id: str, key_id: str, payload: bytes, signature: bytes, occurred_at: str, actor: str) -> C4ArchitectureBaseline:
        independence = value["independence_basis"]
        assert isinstance(independence, dict)
        fields = {field: value[field] for field in _DOCUMENT_FIELDS}
        return C4ArchitectureBaseline(
            baseline_id, str(value["architecture_id"]), str(value["architecture_version"]), str(value["c3_run_id"]), str(value["qualification_run_id"]), str(value["certificate_id"]), str(value["c3_decision_id"]), str(value["c3_snapshot_digest"]), str(value["decision_payload_sha256"]), value["selected_candidate_artifact_id"], str(value["qualification_head_hash"]), str(value["candidate_set_digest"]), str(value["evaluation_set_digest"]), value["adoption_id"], value["adoption_status"], value["adoption_rollback_plan_sha256"], value["execution_id"], value["execution_status"], value["execution_receipt_sha256"], value["rollback_receipt_sha256"], *[str(fields[field]) for field in _DOCUMENT_FIELDS], str(value["architect_identity"]), str(value["architect_environment"]), str(value["reviewer_identity"]), str(value["reviewer_environment"]), str(value["designed_at_utc"]), dict(independence), str(value["external_runtime_integration_status"]), str(value["gate_effect"]), key_id, payload, hashlib.sha256(payload).hexdigest(), signature, hashlib.sha256(signature).hexdigest(), occurred_at, actor, "pending", "pending"
        )

    def admit_baseline(self, c3_run_id: str, key_id: str, payload: bytes, signature: bytes, *, actor: str, occurred_at: str | None = None) -> C4ArchitectureBaseline:
        c3_run_id, key_id, actor = self._text(c3_run_id, "c3_run_id"), self._text(key_id, "key_id"), self._text(actor, "actor")
        signature = self._bounded_signature(signature)
        payload = self._bounded_payload(payload)
        admitted_at = self._timestamp(occurred_at or utc_now(), "admitted_at")
        value = self._parse_payload(payload)
        if value["c3_run_id"] != c3_run_id:
            raise StateTransitionError("signed C4 architecture baseline targets another C3 run")
        baseline_id = str(value.get("baseline_id") or value["architecture_id"])
        snapshot = self.snapshot(c3_run_id)
        self._assert_signature(key_id, payload, signature)
        self._assert_payload_snapshot(value, snapshot)
        if self._dt(admitted_at) < self._dt(str(value["designed_at_utc"])):
            raise StateTransitionError("baseline admission predates its signed design timestamp")
        existing = self._row_for(baseline_id, c3_run_id)
        if existing is not None:
            if not self._replay_matches(existing, baseline_id, c3_run_id, key_id, payload, signature, actor):
                raise ConflictError("C4 architecture baseline identifier or C3 run already binds different material", {"baseline_id": baseline_id, "c3_run_id": c3_run_id})
            record = self._record(existing)
            verification = self.verify_baseline(baseline_id)
            if not verification.ok:
                raise IntegrityError("existing C4 architecture baseline failed verification", {"baseline_id": baseline_id, "defects": list(verification.defects)})
            return record
        provisional = self._provisional(value, baseline_id, key_id, payload, signature, admitted_at, actor)
        event_payload = self._event_payload(provisional)
        columns = ("baseline_id", "architecture_id", "architecture_version", "c3_run_id", "qualification_run_id", "certificate_id", "c3_decision_id", "c3_snapshot_digest", "decision_payload_sha256", "selected_candidate_artifact_id", "qualification_head_hash", "candidate_set_digest", "evaluation_set_digest", "adoption_id", "adoption_status", "adoption_rollback_plan_sha256", "execution_id", "execution_status", "execution_receipt_sha256", "rollback_receipt_sha256", *_DOCUMENT_FIELDS, "architect_identity", "architect_environment", "reviewer_identity", "reviewer_environment", "designed_at_utc", "independence_basis_json", "external_runtime_integration_status", "gate_effect", "key_id", "payload", "payload_sha256", "signature", "signature_sha256", "admitted_at", "admitted_by", "ledger_event_id", "ledger_hash")
        try:
            with self.database.transaction() as connection:
                current = self._build_snapshot(c3_run_id)
                if current != snapshot:
                    raise ConflictError("C3 snapshot changed during C4 architecture admission", {"c3_run_id": c3_run_id})
                self._assert_signature(key_id, payload, signature)
                self._assert_payload_snapshot(value, current)
                race = connection.execute("SELECT baseline_id FROM c4_architecture_baselines WHERE baseline_id = ? OR c3_run_id = ?", (baseline_id, c3_run_id)).fetchone()
                if race is not None:
                    raise ConflictError("C4 architecture baseline appeared during admission")
                receipt = self.ledger.append_in_transaction(connection, self._stream(baseline_id), _EVENT_KIND, event_payload, actor=actor, occurred_at=admitted_at)
                insert_values: list[object] = []
                for field in columns:
                    if field == "independence_basis_json":
                        insert_values.append(canonical_json(dict(provisional.independence_basis)))
                    elif field == "payload":
                        insert_values.append(sqlite3.Binary(provisional.payload))
                    elif field == "signature":
                        insert_values.append(sqlite3.Binary(provisional.signature))
                    elif field == "ledger_event_id":
                        insert_values.append(receipt.event_id)
                    elif field == "ledger_hash":
                        insert_values.append(receipt.record_hash)
                    else:
                        insert_values.append(getattr(provisional, field))
                placeholders = ",".join("?" for _ in columns)
                connection.execute(f"INSERT INTO c4_architecture_baselines ({','.join(columns)}) VALUES ({placeholders})", tuple(insert_values))
                for ordinal, member in enumerate(current.members):
                    material = dict(member)
                    connection.execute("INSERT INTO c4_architecture_baseline_members (baseline_id,ordinal,member_kind,artifact_id,material_json,material_sha256,recorded_at,recorded_by,member_ledger_hash) VALUES (?,?,?,?,?,?,?,?,?)", (baseline_id, ordinal, material["kind"], material["artifact_id"], canonical_json(material), sha256_digest(material), material["recorded_at"], material["recorded_by"], material["ledger_hash"]))
        except sqlite3.IntegrityError as exc:
            race = self._row_for(baseline_id, c3_run_id)
            if race is not None and self._replay_matches(race, baseline_id, c3_run_id, key_id, payload, signature, actor):
                return self._record(race)
            raise ConflictError("C4 architecture baseline violates an immutable constraint", {"baseline_id": baseline_id}) from exc
        return self.get_baseline(baseline_id)

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

    admit = admit_baseline

    def _verify_memberships(self, baseline_id: str, expected: tuple[Mapping[str, Any], ...], defects: list[str]) -> None:
        rows = self.database.connection.execute("SELECT * FROM c4_architecture_baseline_members WHERE baseline_id = ? ORDER BY ordinal", (baseline_id,)).fetchall()
        if len(rows) != len(expected):
            defects.append("BASELINE_MEMBER_COUNT_MISMATCH")
        actual: list[Mapping[str, Any]] = []
        for ordinal, row in enumerate(rows):
            if int(row["ordinal"]) != ordinal:
                defects.append(f"BASELINE_MEMBER_ORDINAL_MISMATCH:{ordinal}")
            try:
                material = json.loads(str(row["material_json"]))
            except (TypeError, json.JSONDecodeError):
                defects.append(f"BASELINE_MEMBER_MATERIAL_INVALID:{ordinal}")
                continue
            if not isinstance(material, dict):
                defects.append(f"BASELINE_MEMBER_MATERIAL_INVALID:{ordinal}")
                continue
            actual.append(material)
            if str(row["member_kind"]) != str(material.get("kind")) or str(row["artifact_id"]) != str(material.get("artifact_id")):
                defects.append(f"BASELINE_MEMBER_BINDING_MISMATCH:{ordinal}")
            if str(row["material_json"]) != canonical_json(material) or str(row["material_sha256"]) != sha256_digest(material):
                defects.append(f"BASELINE_MEMBER_DIGEST_MISMATCH:{ordinal}")
            if str(row["recorded_at"]) != str(material.get("recorded_at")) or str(row["recorded_by"]) != str(material.get("recorded_by")) or str(row["member_ledger_hash"]) != str(material.get("ledger_hash")):
                defects.append(f"BASELINE_MEMBER_PROVENANCE_MISMATCH:{ordinal}")
        if actual != [dict(member) for member in expected]:
            defects.append("BASELINE_MEMBER_MATERIAL_NOT_CURRENT")

    def verify_baseline(self, baseline_id: str) -> C4ArchitectureBaselineVerification:
        baseline_id = self._text(baseline_id, "baseline_id")
        row = self.database.connection.execute("SELECT * FROM c4_architecture_baselines WHERE baseline_id = ?", (baseline_id,)).fetchone()
        if row is None:
            return C4ArchitectureBaselineVerification(baseline_id, ("BASELINE_NOT_FOUND",))
        try:
            record = self._record(row)
        except (IntegrityError, KeyError, TypeError, ValueError, ValidationError):
            return C4ArchitectureBaselineVerification(baseline_id, ("BASELINE_ROW_INVALID",))
        defects: list[str] = []
        if hashlib.sha256(record.payload).hexdigest() != record.payload_sha256:
            defects.append("BASELINE_PAYLOAD_DIGEST_MISMATCH")
        if hashlib.sha256(record.signature).hexdigest() != record.signature_sha256:
            defects.append("BASELINE_SIGNATURE_DIGEST_MISMATCH")
        try:
            parsed = self._parse_payload(record.payload)
        except (ValidationError, TypeError, ValueError):
            parsed = None
            defects.append("BASELINE_PAYLOAD_INVALID")
        try:
            self._assert_signature(record.key_id, record.payload, record.signature)
        except (IntegrityError, NotFoundError, OSError, TypeError, ValueError, sqlite3.Error):
            defects.append("BASELINE_SIGNATURE_INVALID")
        current: C4ArchitectureSnapshot | None = None
        try:
            current = self._build_snapshot(record.c3_run_id)
        except (IntegrityError, NotFoundError, StateTransitionError, TypeError, ValueError, sqlite3.Error):
            defects.append("BASELINE_C3_SNAPSHOT_INVALID")
        if current is not None:
            if current.snapshot_digest != record.c3_snapshot_digest:
                defects.append("BASELINE_C3_SNAPSHOT_STALE")
            try:
                if parsed is not None:
                    self._assert_payload_snapshot(parsed, current)
            except (IntegrityError, StateTransitionError, ValidationError):
                defects.append("BASELINE_PAYLOAD_SNAPSHOT_MISMATCH")
            self._verify_memberships(record.baseline_id, current.members, defects)
        if parsed is not None:
            expected = {"architecture_id": record.architecture_id, "architecture_version": record.architecture_version, "c3_run_id": record.c3_run_id, "qualification_run_id": record.qualification_run_id, "certificate_id": record.certificate_id, "c3_decision_id": record.c3_decision_id, "c3_snapshot_digest": record.c3_snapshot_digest, "decision_payload_sha256": record.decision_payload_sha256, "selected_candidate_artifact_id": record.selected_candidate_artifact_id, "qualification_head_hash": record.qualification_head_hash, "candidate_set_digest": record.candidate_set_digest, "evaluation_set_digest": record.evaluation_set_digest, "adoption_id": record.adoption_id, "adoption_status": record.adoption_status, "adoption_rollback_plan_sha256": record.adoption_rollback_plan_sha256, "execution_id": record.execution_id, "execution_status": record.execution_status, "execution_receipt_sha256": record.execution_receipt_sha256, "rollback_receipt_sha256": record.rollback_receipt_sha256, **{field: getattr(record, field) for field in _DOCUMENT_FIELDS}, "architect_identity": record.architect_identity, "architect_environment": record.architect_environment, "reviewer_identity": record.reviewer_identity, "reviewer_environment": record.reviewer_environment, "designed_at_utc": record.designed_at_utc, "independence_basis": dict(record.independence_basis), "external_runtime_integration_status": record.external_runtime_integration_status, "gate_effect": record.gate_effect}
            if any(parsed.get(field) != observed for field, observed in expected.items()):
                defects.append("BASELINE_PAYLOAD_RECORD_MISMATCH")
            if parsed.get("baseline_id", record.baseline_id) != record.baseline_id:
                defects.append("BASELINE_PAYLOAD_ID_MISMATCH")
        event = self.database.connection.execute("SELECT * FROM ledger_events WHERE event_id = ?", (record.ledger_event_id,)).fetchone()
        expected_event = self._event_payload(record)
        if event is None:
            defects.append("BASELINE_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != self._stream(record.baseline_id): defects.append("BASELINE_LEDGER_STREAM_MISMATCH")
            if str(event["kind"]) != _EVENT_KIND: defects.append("BASELINE_LEDGER_KIND_MISMATCH")
            if str(event["actor"]) != record.admitted_by: defects.append("BASELINE_LEDGER_ACTOR_MISMATCH")
            if str(event["occurred_at"]) != record.admitted_at: defects.append("BASELINE_LEDGER_TIMESTAMP_MISMATCH")
            if str(event["record_hash"]) != record.ledger_hash: defects.append("BASELINE_LEDGER_HASH_MISMATCH")
            try:
                if json.loads(str(event["payload_json"])) != expected_event: defects.append("BASELINE_LEDGER_PAYLOAD_MISMATCH")
            except (TypeError, json.JSONDecodeError): defects.append("BASELINE_LEDGER_PAYLOAD_INVALID")
        try:
            chain = self.ledger.verify(self._stream(record.baseline_id))
            defects.extend(f"BASELINE_LEDGER_CHAIN:{defect.code}" for defect in getattr(chain, "defects", ()))
        except (IntegrityError, TypeError, ValueError, sqlite3.Error):
            defects.append("BASELINE_LEDGER_CHAIN_INVALID")
        return C4ArchitectureBaselineVerification(baseline_id, tuple(dict.fromkeys(defects)))

    verify = verify_baseline


C4Architecture = C4ArchitectureBaseline
C4ArchitectureVerification = C4ArchitectureBaselineVerification
