from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import sqlite3
from typing import Any, Mapping

from .canonical import canonical_json, sha256_digest, utc_now
from .continuity_crypto import OpenSSLEd25519Verifier
from .errors import ConflictError, IntegrityError, NotFoundError, StateTransitionError, ValidationError
from .execution_plan import C5ExecutionPlanService


_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
_MAX_SIGNATURE_BYTES = 1024
_GATE_EFFECT = "C6_RED_TEAM_ASSESSMENT_ADMITTED_NO_RELEASE"
_EVENT_KIND = "C6_RED_TEAM_ASSESSMENT_ADMITTED"
_ACTION = "c6.red-team.assessment.admit"
_VERDICTS = frozenset(
    {
        "C6_PASS_NO_BLOCKING_FINDINGS",
        "C6_FAIL_REMEDIATION_REQUIRED",
        "C6_BLOCKED_INSUFFICIENT_EVIDENCE",
    }
)
_RELEASE_RECOMMENDATIONS = frozenset({"PROCEED_TO_C7_FINAL_PACK", "BLOCK_C7"})
_ATTACK_CATEGORIES = frozenset(
    {"AUTHORITY", "INTEGRITY", "PROVENANCE", "DEPENDENCY", "BOUNDARY", "RECOVERY"}
)
_ATTACK_OUTCOMES = frozenset({"PASS", "FAIL", "BLOCKED"})
_SEVERITIES = frozenset({"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"})
_FINDING_STATUSES = frozenset({"OPEN", "REMEDIATED", "ACCEPTED_RISK"})
_REQUIRED_FIELDS = frozenset(
    {
        "assessment_id",
        "plan_id",
        "architecture_id",
        "plan_payload_sha256",
        "c5_snapshot_digest",
        "threat_model_digest",
        "attack_cases",
        "findings",
        "verdict",
        "remediation_required",
        "release_recommendation",
        "assessor_identity",
        "assessor_environment",
        "adjudicator_identity",
        "adjudicator_environment",
        "assessed_at_utc",
        "independence_basis",
        "gate_effect",
    }
)
_ATTACK_FIELDS = frozenset(
    {
        "attack_case_id",
        "category",
        "target",
        "method",
        "invariant_expected",
        "evidence_digest",
        "outcome",
    }
)
_FINDING_FIELDS = frozenset(
    {
        "finding_id",
        "attack_case_id",
        "severity",
        "title",
        "description_digest",
        "evidence_digest",
        "status",
        "remediation_work_item_id",
    }
)

_TEXT = C5ExecutionPlanService._text
_DIGEST = C5ExecutionPlanService._digest
_TIMESTAMP = C5ExecutionPlanService._timestamp
_DT = C5ExecutionPlanService._dt
_SORTED_STRINGS = C5ExecutionPlanService._sorted_strings


@dataclass(frozen=True)
class C6RedTeamSnapshot:
    plan_id: str
    architecture_id: str
    plan_version: str
    architecture_version: str
    plan_payload_sha256: str
    work_items_count: int
    work_items_digest: str
    release_gates_count: int
    release_gates_digest: str
    c5_provenance_event_id: str
    c5_provenance_head_hash: str
    latest_evidence_at: str
    material_identities: tuple[str, ...]
    snapshot_digest: str


@dataclass(frozen=True)
class C6RedTeamPreparation:
    assessment_id: str
    plan_id: str
    architecture_id: str
    c5_snapshot_digest: str
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]
    gate_effect: str


@dataclass(frozen=True)
class C6RedTeamAssessment:
    assessment_id: str
    plan_id: str
    architecture_id: str
    plan_payload_sha256: str
    c5_snapshot_digest: str
    work_items_count: int
    work_items_digest: str
    release_gates_count: int
    release_gates_digest: str
    c5_provenance_event_id: str
    c5_provenance_head_hash: str
    latest_evidence_at: str
    threat_model_digest: str
    verdict: str
    remediation_required: bool
    release_recommendation: str
    assessor_identity: str
    assessor_environment: str
    adjudicator_identity: str
    adjudicator_environment: str
    assessed_at_utc: str
    independence_basis: Mapping[str, Any]
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
class C6RedTeamAssessmentVerification:
    assessment_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C6RedTeamService:
    """Exact-byte C6 red-team authority; assessment never repairs or releases."""

    _text = staticmethod(_TEXT)
    _digest = staticmethod(_DIGEST)
    _timestamp = staticmethod(_TIMESTAMP)
    _dt = staticmethod(_DT)
    _sorted_strings = staticmethod(_SORTED_STRINGS)

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
        self.execution_plan = self._find(
            values,
            lambda value: all(
                hasattr(value, name)
                for name in (
                    "get_plan",
                    "verify_plan",
                    "get_work_items",
                    "get_release_gates",
                    "snapshot",
                )
            ),
        )
        if self.continuity is None or self.execution_plan is None:
            raise ValidationError(
                "C6 red-team assessment requires Continuity and C5 execution-plan authorities"
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
            raise ValidationError("C6 red-team payload must be strict UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise ValidationError("C6 red-team payload must be a JSON object")
        fields = frozenset(value)
        if fields != _REQUIRED_FIELDS:
            raise ValidationError(
                "C6 red-team payload fields do not match the contract",
                {
                    "missing": sorted(_REQUIRED_FIELDS - fields),
                    "unexpected": sorted(fields - _REQUIRED_FIELDS),
                },
            )

        for field in (
            "assessment_id",
            "plan_id",
            "architecture_id",
            "assessor_identity",
            "assessor_environment",
            "adjudicator_identity",
            "adjudicator_environment",
            "gate_effect",
        ):
            value[field] = cls._text(value[field], field)
        for field in ("plan_payload_sha256", "c5_snapshot_digest", "threat_model_digest"):
            value[field] = cls._digest(value[field], field)
        value["assessed_at_utc"] = cls._timestamp(value["assessed_at_utc"], "assessed_at_utc")
        verdict = cls._text(value["verdict"], "verdict")
        if verdict not in _VERDICTS:
            raise ValidationError("verdict is outside the closed C6 contract")
        value["verdict"] = verdict
        if not isinstance(value["remediation_required"], bool):
            raise ValidationError("remediation_required must be boolean")
        recommendation = cls._text(
            value["release_recommendation"], "release_recommendation"
        )
        if recommendation not in _RELEASE_RECOMMENDATIONS:
            raise ValidationError("release_recommendation is outside the closed C6 contract")
        value["release_recommendation"] = recommendation
        if value["gate_effect"] != _GATE_EFFECT:
            raise ValidationError(f"gate_effect must equal {_GATE_EFFECT}")

        raw_attacks = value["attack_cases"]
        if not isinstance(raw_attacks, list) or not raw_attacks:
            raise ValidationError("attack_cases must be a non-empty list")
        attacks: list[dict[str, object]] = []
        attack_ids: set[str] = set()
        for ordinal, raw_attack in enumerate(raw_attacks):
            if not isinstance(raw_attack, dict) or frozenset(raw_attack) != _ATTACK_FIELDS:
                raise ValidationError(
                    f"attack_cases[{ordinal}] fields do not match the contract"
                )
            attack = dict(raw_attack)
            attack_id = cls._text(
                attack["attack_case_id"], f"attack_cases[{ordinal}].attack_case_id"
            )
            if attack_id in attack_ids:
                raise ValidationError("attack_case_id values must be unique")
            attack_ids.add(attack_id)
            attack["attack_case_id"] = attack_id
            for field in ("target", "method", "invariant_expected"):
                attack[field] = cls._text(attack[field], f"attack_cases[{ordinal}].{field}")
            category = cls._text(attack["category"], f"attack_cases[{ordinal}].category")
            if category not in _ATTACK_CATEGORIES:
                raise ValidationError("attack category is outside the closed contract")
            attack["category"] = category
            attack["evidence_digest"] = cls._digest(
                attack["evidence_digest"], f"attack_cases[{ordinal}].evidence_digest"
            )
            outcome = cls._text(attack["outcome"], f"attack_cases[{ordinal}].outcome")
            if outcome not in _ATTACK_OUTCOMES:
                raise ValidationError("attack outcome is outside the closed contract")
            attack["outcome"] = outcome
            attacks.append(attack)
        if [str(item["attack_case_id"]) for item in attacks] != sorted(attack_ids):
            raise ValidationError("attack_cases must be sorted by attack_case_id")
        value["attack_cases"] = attacks

        raw_findings = value["findings"]
        if not isinstance(raw_findings, list):
            raise ValidationError("findings must be a list")
        findings: list[dict[str, object]] = []
        finding_ids: set[str] = set()
        for ordinal, raw_finding in enumerate(raw_findings):
            if not isinstance(raw_finding, dict) or frozenset(raw_finding) != _FINDING_FIELDS:
                raise ValidationError(
                    f"findings[{ordinal}] fields do not match the contract"
                )
            finding = dict(raw_finding)
            finding_id = cls._text(
                finding["finding_id"], f"findings[{ordinal}].finding_id"
            )
            if finding_id in finding_ids:
                raise ValidationError("finding_id values must be unique")
            finding_ids.add(finding_id)
            finding["finding_id"] = finding_id
            finding["attack_case_id"] = cls._text(
                finding["attack_case_id"], f"findings[{ordinal}].attack_case_id"
            )
            if finding["attack_case_id"] not in attack_ids:
                raise ValidationError("finding references an unknown attack case")
            severity = cls._text(finding["severity"], f"findings[{ordinal}].severity")
            if severity not in _SEVERITIES:
                raise ValidationError("finding severity is outside the closed contract")
            finding["severity"] = severity
            finding["title"] = cls._text(finding["title"], f"findings[{ordinal}].title")
            for field in ("description_digest", "evidence_digest"):
                finding[field] = cls._digest(
                    finding[field], f"findings[{ordinal}].{field}"
                )
            status = cls._text(finding["status"], f"findings[{ordinal}].status")
            if status not in _FINDING_STATUSES:
                raise ValidationError("finding status is outside the closed contract")
            finding["status"] = status
            remediation_id = finding["remediation_work_item_id"]
            if remediation_id is not None:
                finding["remediation_work_item_id"] = cls._text(
                    remediation_id, f"findings[{ordinal}].remediation_work_item_id"
                )
            findings.append(finding)
        if [str(item["finding_id"]) for item in findings] != sorted(finding_ids):
            raise ValidationError("findings must be sorted by finding_id")
        value["findings"] = findings

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
        cls._assert_derived_verdict(value)
        return value

    @staticmethod
    def _assert_derived_verdict(value: Mapping[str, object]) -> None:
        attacks = value["attack_cases"]
        findings = value["findings"]
        assert isinstance(attacks, list)
        assert isinstance(findings, list)
        has_failed_attack = any(item["outcome"] == "FAIL" for item in attacks)
        has_blocked_attack = any(item["outcome"] == "BLOCKED" for item in attacks)
        has_blocking_finding = any(
            item["severity"] in {"HIGH", "CRITICAL"} and item["status"] == "OPEN"
            for item in findings
        )
        if has_failed_attack or has_blocking_finding:
            expected_verdict = "C6_FAIL_REMEDIATION_REQUIRED"
        elif has_blocked_attack:
            expected_verdict = "C6_BLOCKED_INSUFFICIENT_EVIDENCE"
        else:
            expected_verdict = "C6_PASS_NO_BLOCKING_FINDINGS"
        if value["verdict"] != expected_verdict:
            raise StateTransitionError(
                "C6 verdict does not match attack outcomes and blocking findings",
                {"expected_verdict": expected_verdict},
            )
        expected_remediation = expected_verdict == "C6_FAIL_REMEDIATION_REQUIRED"
        if value["remediation_required"] is not expected_remediation:
            raise StateTransitionError("C6 remediation_required does not match the derived verdict")
        expected_recommendation = (
            "PROCEED_TO_C7_FINAL_PACK"
            if expected_verdict == "C6_PASS_NO_BLOCKING_FINDINGS"
            else "BLOCK_C7"
        )
        if value["release_recommendation"] != expected_recommendation:
            raise StateTransitionError(
                "C6 release recommendation does not match the derived verdict",
                {"expected_recommendation": expected_recommendation},
            )

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c6_red_team_assessments (
                    assessment_id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL UNIQUE,
                    architecture_id TEXT NOT NULL,
                    plan_payload_sha256 TEXT NOT NULL CHECK (length(plan_payload_sha256) = 64),
                    c5_snapshot_digest TEXT NOT NULL CHECK (length(c5_snapshot_digest) = 64),
                    work_items_count INTEGER NOT NULL CHECK (work_items_count > 0),
                    work_items_digest TEXT NOT NULL CHECK (length(work_items_digest) = 64),
                    release_gates_count INTEGER NOT NULL CHECK (release_gates_count > 0),
                    release_gates_digest TEXT NOT NULL CHECK (length(release_gates_digest) = 64),
                    c5_provenance_event_id TEXT NOT NULL UNIQUE,
                    c5_provenance_head_hash TEXT NOT NULL CHECK (length(c5_provenance_head_hash) = 64),
                    latest_evidence_at TEXT NOT NULL,
                    threat_model_digest TEXT NOT NULL CHECK (length(threat_model_digest) = 64),
                    verdict TEXT NOT NULL CHECK (verdict IN (
                        'C6_PASS_NO_BLOCKING_FINDINGS',
                        'C6_FAIL_REMEDIATION_REQUIRED',
                        'C6_BLOCKED_INSUFFICIENT_EVIDENCE'
                    )),
                    remediation_required INTEGER NOT NULL CHECK (remediation_required IN (0, 1)),
                    release_recommendation TEXT NOT NULL CHECK (
                        release_recommendation IN ('PROCEED_TO_C7_FINAL_PACK', 'BLOCK_C7')
                    ),
                    assessor_identity TEXT NOT NULL,
                    assessor_environment TEXT NOT NULL,
                    adjudicator_identity TEXT NOT NULL,
                    adjudicator_environment TEXT NOT NULL,
                    assessed_at_utc TEXT NOT NULL,
                    independence_basis_json TEXT NOT NULL,
                    gate_effect TEXT NOT NULL CHECK (
                        gate_effect = 'C6_RED_TEAM_ASSESSMENT_ADMITTED_NO_RELEASE'
                    ),
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
                CREATE TABLE IF NOT EXISTS c6_red_team_attack_cases (
                    assessment_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                    attack_case_id TEXT NOT NULL,
                    material_json TEXT NOT NULL,
                    material_sha256 TEXT NOT NULL CHECK (length(material_sha256) = 64),
                    recorded_at TEXT NOT NULL,
                    recorded_by TEXT NOT NULL,
                    member_ledger_hash TEXT NOT NULL CHECK (length(member_ledger_hash) = 64),
                    PRIMARY KEY (assessment_id, ordinal),
                    UNIQUE (assessment_id, attack_case_id),
                    FOREIGN KEY (assessment_id) REFERENCES c6_red_team_assessments(assessment_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c6_red_team_findings (
                    assessment_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                    finding_id TEXT NOT NULL,
                    material_json TEXT NOT NULL,
                    material_sha256 TEXT NOT NULL CHECK (length(material_sha256) = 64),
                    recorded_at TEXT NOT NULL,
                    recorded_by TEXT NOT NULL,
                    member_ledger_hash TEXT NOT NULL CHECK (length(member_ledger_hash) = 64),
                    PRIMARY KEY (assessment_id, ordinal),
                    UNIQUE (assessment_id, finding_id),
                    FOREIGN KEY (assessment_id) REFERENCES c6_red_team_assessments(assessment_id)
                )
                """
            )
            for table in (
                "c6_red_team_assessments",
                "c6_red_team_attack_cases",
                "c6_red_team_findings",
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

    @staticmethod
    def _value(source: object, field: str, default: object = None) -> object:
        if isinstance(source, Mapping):
            return source.get(field, default)
        return getattr(source, field, default)

    def _c5_plan(self, plan_id: str) -> Any:
        try:
            return self.execution_plan.get_plan(plan_id)
        except (NotFoundError, KeyError) as exc:
            raise NotFoundError("C5 execution plan does not exist", {"plan_id": plan_id}) from exc

    def _clean_c5(self, plan_id: str) -> Any:
        plan = self._c5_plan(plan_id)
        result = self.execution_plan.verify_plan(plan_id)
        if not getattr(result, "ok", False):
            raise IntegrityError(
                "C5 execution plan verification failed",
                {"plan_id": plan_id, "defects": list(getattr(result, "defects", ()))},
            )
        return plan

    @classmethod
    def _member_material(
        cls,
        values: object,
        *,
        identifier_field: str,
        field: str,
    ) -> tuple[dict[str, object], ...]:
        if not isinstance(values, (list, tuple)) or not values:
            raise IntegrityError(f"C5 {field} are missing or empty")
        material = []
        identifiers: list[str] = []
        for ordinal, value in enumerate(values):
            if not isinstance(value, Mapping):
                raise IntegrityError(f"C5 {field}[{ordinal}] is not an object")
            item = dict(value)
            identifier = cls._text(item.get(identifier_field), f"{field}[{ordinal}].{identifier_field}")
            identifiers.append(identifier)
            material.append(item)
        if identifiers != sorted(identifiers) or len(set(identifiers)) != len(identifiers):
            raise IntegrityError(f"C5 {field} must be sorted and unique")
        return tuple(material)

    def _c5_provenance(self, plan: Any) -> None:
        event_id = self._text(self._value(plan, "ledger_event_id"), "c5_provenance_event_id")
        event_hash = self._digest(
            self._value(plan, "ledger_hash"), "c5_provenance_head_hash"
        )
        plan_id = self._text(self._value(plan, "plan_id"), "plan_id")
        admitted_at = self._timestamp(self._value(plan, "admitted_at"), "c5_admitted_at")
        admitted_by = self._text(self._value(plan, "admitted_by"), "c5_admitted_by")
        row = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        if row is None:
            raise IntegrityError("C5 provenance ledger event is missing")
        if (
            str(row["stream_id"]) != f"continuity:c5:execution-plan:{plan_id}"
            or str(row["kind"]) != "C5_EXECUTION_PLAN_ADMITTED"
            or str(row["actor"]) != admitted_by
            or str(row["occurred_at"]) != admitted_at
            or str(row["record_hash"]) != event_hash
        ):
            raise IntegrityError("C5 provenance ledger event is inconsistent")
        try:
            event_payload = json.loads(str(row["payload_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrityError("C5 provenance ledger payload is invalid") from exc
        if not isinstance(event_payload, dict):
            raise IntegrityError("C5 provenance ledger payload is invalid")
        plan_payload = self._value(plan, "payload")
        if not isinstance(plan_payload, bytes) or event_payload.get("plan_id") != plan_id:
            raise IntegrityError("C5 provenance ledger payload is inconsistent")
        if event_payload.get("payload_sha256") != hashlib.sha256(plan_payload).hexdigest():
            raise IntegrityError("C5 provenance ledger payload digest is inconsistent")
        try:
            chain = self.ledger.verify(f"continuity:c5:execution-plan:{plan_id}")
        except (IntegrityError, TypeError, ValueError, sqlite3.Error) as exc:
            raise IntegrityError("C5 provenance ledger chain is invalid") from exc
        if not getattr(chain, "ok", False):
            raise IntegrityError("C5 provenance ledger chain is invalid")

    def _build_snapshot(self, plan_id: str) -> C6RedTeamSnapshot:
        plan = self._clean_c5(plan_id)
        actual_plan_id = self._text(self._value(plan, "plan_id"), "plan_id")
        if actual_plan_id != plan_id:
            raise IntegrityError("C5 plan identifier is inconsistent")
        architecture_id = self._text(
            self._value(plan, "architecture_id"), "architecture_id"
        )
        plan_version = self._text(self._value(plan, "plan_version"), "plan_version")
        architecture_version = self._text(
            self._value(plan, "architecture_version"), "architecture_version"
        )
        payload = self._value(plan, "payload")
        if not isinstance(payload, bytes) or not payload:
            raise IntegrityError("C5 plan payload is missing")
        payload_digest = hashlib.sha256(payload).hexdigest()
        stored_payload_digest = self._digest(
            self._value(plan, "payload_sha256"), "plan_payload_sha256"
        )
        if payload_digest != stored_payload_digest:
            raise IntegrityError("C5 plan payload digest is inconsistent")
        work_items = self._member_material(
            self.execution_plan.get_work_items(plan_id),
            identifier_field="work_item_id",
            field="work items",
        )
        release_gates = self._member_material(
            self.execution_plan.get_release_gates(plan_id),
            identifier_field="gate_id",
            field="release gates",
        )
        self._c5_provenance(plan)
        admitted_at = self._timestamp(self._value(plan, "admitted_at"), "latest_evidence_at")
        latest_evidence_at = admitted_at
        for table in ("c5_execution_plan_work_items", "c5_execution_plan_release_gates"):
            try:
                rows = self.database.connection.execute(
                    f"SELECT recorded_at FROM {table} WHERE plan_id = ?",
                    (plan_id,),
                ).fetchall()
            except sqlite3.Error:
                rows = []
            for row in rows:
                timestamp = self._timestamp(row["recorded_at"], f"{table}.recorded_at")
                if self._dt(timestamp) > self._dt(latest_evidence_at):
                    latest_evidence_at = timestamp
        independence = self._value(plan, "independence_basis", {})
        if not isinstance(independence, Mapping):
            raise IntegrityError("C5 independence basis is invalid")
        excluded = independence.get("excluded_identities", [])
        if not isinstance(excluded, (list, tuple, set)):
            raise IntegrityError("C5 excluded identities are invalid")
        identities = {self._text(item, "c5_material_identity") for item in excluded}
        for field in ("planner_identity", "reviewer_identity", "admitted_by"):
            identities.add(self._text(self._value(plan, field), f"c5.{field}"))
        material_identities = tuple(sorted(identities))
        work_items_digest = sha256_digest([dict(item) for item in work_items])
        release_gates_digest = sha256_digest([dict(item) for item in release_gates])
        provenance_event_id = self._text(
            self._value(plan, "ledger_event_id"), "c5_provenance_event_id"
        )
        provenance_head_hash = self._digest(
            self._value(plan, "ledger_hash"), "c5_provenance_head_hash"
        )
        material = {
            "plan_id": actual_plan_id,
            "architecture_id": architecture_id,
            "plan_version": plan_version,
            "architecture_version": architecture_version,
            "plan_payload_sha256": stored_payload_digest,
            "work_items_count": len(work_items),
            "work_items_digest": work_items_digest,
            "release_gates_count": len(release_gates),
            "release_gates_digest": release_gates_digest,
            "c5_provenance_event_id": provenance_event_id,
            "c5_provenance_head_hash": provenance_head_hash,
            "latest_evidence_at": latest_evidence_at,
            "material_identities": list(material_identities),
        }
        return C6RedTeamSnapshot(
            actual_plan_id,
            architecture_id,
            plan_version,
            architecture_version,
            stored_payload_digest,
            len(work_items),
            work_items_digest,
            len(release_gates),
            release_gates_digest,
            provenance_event_id,
            provenance_head_hash,
            latest_evidence_at,
            material_identities,
            sha256_digest(material),
        )

    def snapshot(self, plan_id: str) -> C6RedTeamSnapshot:
        return self._build_snapshot(self._text(plan_id, "plan_id"))

    def prepare(
        self,
        assessment_id: str,
        plan_id: str,
        payload: Mapping[str, Any] | None = None,
    ) -> C6RedTeamPreparation:
        assessment_id = self._text(assessment_id, "assessment_id")
        plan_id = self._text(plan_id, "plan_id")
        snapshot = self.snapshot(plan_id)
        if payload is not None:
            if self._text(payload.get("plan_id"), "payload.plan_id") != plan_id:
                raise StateTransitionError("C6 preparation targets another C5 plan")
            if self._text(payload.get("architecture_id"), "payload.architecture_id") != snapshot.architecture_id:
                raise StateTransitionError("C6 preparation targets another architecture")
        resource = f"continuity:c6:red-team:{assessment_id}"
        context = {
            "assessment_id": assessment_id,
            "plan_id": snapshot.plan_id,
            "architecture_id": snapshot.architecture_id,
            "plan_payload_sha256": snapshot.plan_payload_sha256,
            "c5_snapshot_digest": snapshot.snapshot_digest,
            "gate_effect": _GATE_EFFECT,
        }
        return C6RedTeamPreparation(
            assessment_id,
            plan_id,
            snapshot.architecture_id,
            snapshot.snapshot_digest,
            _ACTION,
            resource,
            "continuity",
            context,
            _GATE_EFFECT,
        )

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
    def _blob(row: sqlite3.Row, field: str) -> bytes:
        value = row[field]
        if not isinstance(value, bytes) or not value:
            raise IntegrityError(f"stored {field} is invalid")
        return bytes(value)

    @classmethod
    def _record(cls, row: sqlite3.Row) -> C6RedTeamAssessment:
        def get(field: str) -> Any:
            return row[field]

        try:
            independence = json.loads(str(get("independence_basis_json")))
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrityError("stored C6 independence basis is invalid") from exc
        if not isinstance(independence, dict):
            raise IntegrityError("stored C6 independence basis is invalid")
        return C6RedTeamAssessment(
            cls._text(get("assessment_id"), "assessment_id"),
            cls._text(get("plan_id"), "plan_id"),
            cls._text(get("architecture_id"), "architecture_id"),
            cls._digest(get("plan_payload_sha256"), "plan_payload_sha256"),
            cls._digest(get("c5_snapshot_digest"), "c5_snapshot_digest"),
            int(get("work_items_count")),
            cls._digest(get("work_items_digest"), "work_items_digest"),
            int(get("release_gates_count")),
            cls._digest(get("release_gates_digest"), "release_gates_digest"),
            cls._text(get("c5_provenance_event_id"), "c5_provenance_event_id"),
            cls._digest(get("c5_provenance_head_hash"), "c5_provenance_head_hash"),
            cls._timestamp(get("latest_evidence_at"), "latest_evidence_at"),
            cls._digest(get("threat_model_digest"), "threat_model_digest"),
            cls._text(get("verdict"), "verdict"),
            bool(int(get("remediation_required"))),
            cls._text(get("release_recommendation"), "release_recommendation"),
            cls._text(get("assessor_identity"), "assessor_identity"),
            cls._text(get("assessor_environment"), "assessor_environment"),
            cls._text(get("adjudicator_identity"), "adjudicator_identity"),
            cls._text(get("adjudicator_environment"), "adjudicator_environment"),
            cls._timestamp(get("assessed_at_utc"), "assessed_at_utc"),
            independence,
            cls._text(get("gate_effect"), "gate_effect"),
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

    def _row_for(self, assessment_id: str, plan_id: str) -> sqlite3.Row | None:
        return self.database.connection.execute(
            "SELECT * FROM c6_red_team_assessments "
            "WHERE assessment_id = ? OR plan_id = ? ORDER BY assessment_id LIMIT 1",
            (assessment_id, plan_id),
        ).fetchone()

    def get_assessment(self, assessment_id: str) -> C6RedTeamAssessment:
        assessment_id = self._text(assessment_id, "assessment_id")
        row = self.database.connection.execute(
            "SELECT * FROM c6_red_team_assessments WHERE assessment_id = ?",
            (assessment_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C6 red-team assessment does not exist", {"assessment_id": assessment_id}
            )
        return self._record(row)

    get = get_assessment
    get_red_team_assessment = get_assessment

    @staticmethod
    def _event_payload(record: C6RedTeamAssessment) -> dict[str, object]:
        return {
            "assessment_id": record.assessment_id,
            "plan_id": record.plan_id,
            "architecture_id": record.architecture_id,
            "plan_payload_sha256": record.plan_payload_sha256,
            "c5_snapshot_digest": record.c5_snapshot_digest,
            "work_items_count": record.work_items_count,
            "work_items_digest": record.work_items_digest,
            "release_gates_count": record.release_gates_count,
            "release_gates_digest": record.release_gates_digest,
            "c5_provenance_event_id": record.c5_provenance_event_id,
            "c5_provenance_head_hash": record.c5_provenance_head_hash,
            "latest_evidence_at": record.latest_evidence_at,
            "threat_model_digest": record.threat_model_digest,
            "verdict": record.verdict,
            "remediation_required": record.remediation_required,
            "release_recommendation": record.release_recommendation,
            "assessor_identity": record.assessor_identity,
            "adjudicator_identity": record.adjudicator_identity,
            "assessed_at_utc": record.assessed_at_utc,
            "independence_basis": dict(record.independence_basis),
            "key_id": record.key_id,
            "payload_sha256": record.payload_sha256,
            "signature_sha256": record.signature_sha256,
            "gate_effect": record.gate_effect,
        }

    @staticmethod
    def _replay_matches(
        row: sqlite3.Row,
        assessment_id: str,
        plan_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        actor: str,
    ) -> bool:
        return (
            str(row["assessment_id"]) == assessment_id
            and str(row["plan_id"]) == plan_id
            and str(row["key_id"]) == key_id
            and bytes(row["payload"]) == payload
            and bytes(row["signature"]) == signature
            and str(row["admitted_by"]) == actor
        )

    def _assert_signature(self, key_id: str, payload: bytes, signature: bytes) -> None:
        root = self.continuity.verify_trust_root(key_id)
        if not getattr(root, "ok", False):
            raise IntegrityError(
                "C6 red-team trust root verification failed",
                {"key_id": key_id, "defects": list(getattr(root, "defects", ()))},
            )
        row = self.database.connection.execute(
            "SELECT public_key_pem FROM continuity_trust_roots WHERE key_id = ?",
            (key_id,),
        ).fetchone()
        if row is None or not self.signature_verifier.verify(
            bytes(row["public_key_pem"]), payload, signature
        ):
            raise IntegrityError("C6 red-team signature is invalid")

    def _assert_payload_binding(
        self,
        value: Mapping[str, object],
        snapshot: C6RedTeamSnapshot,
        *,
        admitted_at: str | None = None,
    ) -> None:
        if value.get("plan_id") != snapshot.plan_id:
            raise StateTransitionError("signed C6 assessment targets another C5 plan")
        if value.get("architecture_id") != snapshot.architecture_id:
            raise StateTransitionError("signed C6 assessment targets another architecture")
        if value.get("plan_payload_sha256") != snapshot.plan_payload_sha256:
            raise IntegrityError("signed C6 assessment binds a stale C5 payload")
        if value.get("c5_snapshot_digest") != snapshot.snapshot_digest:
            raise IntegrityError("signed C6 assessment binds a stale C5 snapshot")
        if value.get("assessor_identity") == value.get("adjudicator_identity"):
            raise StateTransitionError("C6 assessor and adjudicator must be distinct")
        independence = value.get("independence_basis")
        if not isinstance(independence, Mapping):
            raise ValidationError("C6 independence basis is invalid")
        excluded = independence.get("excluded_identities")
        if list(excluded or ()) != list(snapshot.material_identities):
            raise StateTransitionError("C6 independence exclusions do not match C5 material")
        if any(
            identity in snapshot.material_identities
            for identity in (value.get("assessor_identity"), value.get("adjudicator_identity"))
        ):
            raise StateTransitionError("C6 assessor or adjudicator reuses an upstream material identity")
        if self._dt(str(value["assessed_at_utc"])) <= self._dt(snapshot.latest_evidence_at):
            raise StateTransitionError("C6 assessment predates the latest C5 evidence")
        if admitted_at is not None and self._dt(admitted_at) < self._dt(str(value["assessed_at_utc"])):
            raise StateTransitionError("C6 admission predates the signed assessment")
        work_items = self._member_material(
            self.execution_plan.get_work_items(snapshot.plan_id),
            identifier_field="work_item_id",
            field="work items",
        )
        work_item_ids = {str(item["work_item_id"]) for item in work_items}
        for finding in value["findings"]:
            remediation_id = finding["remediation_work_item_id"]
            if remediation_id is not None and remediation_id not in work_item_ids:
                raise StateTransitionError("C6 finding remediation work item does not exist")
        self._assert_derived_verdict(value)

    def _provisional(
        self,
        value: Mapping[str, object],
        snapshot: C6RedTeamSnapshot,
        key_id: str,
        payload: bytes,
        signature: bytes,
        admitted_at: str,
        actor: str,
    ) -> C6RedTeamAssessment:
        independence = value["independence_basis"]
        assert isinstance(independence, Mapping)
        return C6RedTeamAssessment(
            str(value["assessment_id"]),
            snapshot.plan_id,
            snapshot.architecture_id,
            snapshot.plan_payload_sha256,
            snapshot.snapshot_digest,
            snapshot.work_items_count,
            snapshot.work_items_digest,
            snapshot.release_gates_count,
            snapshot.release_gates_digest,
            snapshot.c5_provenance_event_id,
            snapshot.c5_provenance_head_hash,
            snapshot.latest_evidence_at,
            str(value["threat_model_digest"]),
            str(value["verdict"]),
            bool(value["remediation_required"]),
            str(value["release_recommendation"]),
            str(value["assessor_identity"]),
            str(value["assessor_environment"]),
            str(value["adjudicator_identity"]),
            str(value["adjudicator_environment"]),
            str(value["assessed_at_utc"]),
            dict(independence),
            str(value["gate_effect"]),
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

    def admit_assessment(
        self,
        plan_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        *,
        actor: str,
        occurred_at: str | None = None,
    ) -> C6RedTeamAssessment:
        plan_id = self._text(plan_id, "plan_id")
        key_id = self._text(key_id, "key_id")
        actor = self._text(actor, "actor")
        payload = self._bounded_payload(payload)
        signature = self._bounded_signature(signature)
        admitted_at = self._timestamp(occurred_at or utc_now(), "admitted_at")
        value = self._parse_payload(payload)
        if value["plan_id"] != plan_id:
            raise StateTransitionError("signed C6 assessment targets another C5 plan")
        snapshot = self.snapshot(plan_id)
        self._assert_payload_binding(value, snapshot, admitted_at=admitted_at)
        self._assert_signature(key_id, payload, signature)
        assessment_id = str(value["assessment_id"])
        existing = self._row_for(assessment_id, plan_id)
        if existing is not None:
            if not self._replay_matches(
                existing, assessment_id, plan_id, key_id, payload, signature, actor
            ):
                raise ConflictError(
                    "C6 assessment identifier or C5 plan already binds different material",
                    {"assessment_id": assessment_id, "plan_id": plan_id},
                )
            record = self._record(existing)
            verification = self.verify_assessment(assessment_id)
            if not verification.ok:
                raise IntegrityError(
                    "existing C6 red-team assessment failed verification",
                    {"assessment_id": assessment_id, "defects": list(verification.defects)},
                )
            return record
        provisional = self._provisional(
            value, snapshot, key_id, payload, signature, admitted_at, actor
        )
        event_payload = self._event_payload(provisional)
        columns = (
            "assessment_id",
            "plan_id",
            "architecture_id",
            "plan_payload_sha256",
            "c5_snapshot_digest",
            "work_items_count",
            "work_items_digest",
            "release_gates_count",
            "release_gates_digest",
            "c5_provenance_event_id",
            "c5_provenance_head_hash",
            "latest_evidence_at",
            "threat_model_digest",
            "verdict",
            "remediation_required",
            "release_recommendation",
            "assessor_identity",
            "assessor_environment",
            "adjudicator_identity",
            "adjudicator_environment",
            "assessed_at_utc",
            "independence_basis_json",
            "gate_effect",
            "key_id",
            "payload",
            "payload_sha256",
            "signature",
            "signature_sha256",
            "admitted_at",
            "admitted_by",
            "ledger_event_id",
            "ledger_hash",
        )
        try:
            with self.database.transaction() as connection:
                current = self._build_snapshot(plan_id)
                if current != snapshot:
                    raise ConflictError("C5 snapshot changed during C6 assessment admission")
                self._assert_payload_binding(value, current, admitted_at=admitted_at)
                self._assert_signature(key_id, payload, signature)
                race = connection.execute(
                    "SELECT assessment_id FROM c6_red_team_assessments "
                    "WHERE assessment_id = ? OR plan_id = ? OR payload_sha256 = ?",
                    (assessment_id, plan_id, provisional.payload_sha256),
                ).fetchone()
                if race is not None:
                    raise ConflictError("C6 assessment appeared during admission")
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"continuity:c6:red-team:{assessment_id}",
                    _EVENT_KIND,
                    event_payload,
                    actor=actor,
                    occurred_at=admitted_at,
                )
                values: list[object] = []
                for field in columns:
                    if field == "independence_basis_json":
                        values.append(canonical_json(dict(provisional.independence_basis)))
                    elif field == "remediation_required":
                        values.append(int(provisional.remediation_required))
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
                    f"INSERT INTO c6_red_team_assessments ({','.join(columns)}) "
                    f"VALUES ({placeholders})",
                    tuple(values),
                )
                for ordinal, attack in enumerate(value["attack_cases"]):
                    material = dict(attack)
                    connection.execute(
                        "INSERT INTO c6_red_team_attack_cases "
                        "(assessment_id,ordinal,attack_case_id,material_json,material_sha256,"
                        "recorded_at,recorded_by,member_ledger_hash) VALUES (?,?,?,?,?,?,?,?)",
                        (
                            assessment_id,
                            ordinal,
                            material["attack_case_id"],
                            canonical_json(material),
                            sha256_digest(material),
                            admitted_at,
                            actor,
                            receipt.record_hash,
                        ),
                    )
                for ordinal, finding in enumerate(value["findings"]):
                    material = dict(finding)
                    connection.execute(
                        "INSERT INTO c6_red_team_findings "
                        "(assessment_id,ordinal,finding_id,material_json,material_sha256,"
                        "recorded_at,recorded_by,member_ledger_hash) VALUES (?,?,?,?,?,?,?,?)",
                        (
                            assessment_id,
                            ordinal,
                            material["finding_id"],
                            canonical_json(material),
                            sha256_digest(material),
                            admitted_at,
                            actor,
                            receipt.record_hash,
                        ),
                    )
        except sqlite3.IntegrityError as exc:
            race = self._row_for(assessment_id, plan_id)
            if race is not None and self._replay_matches(
                race, assessment_id, plan_id, key_id, payload, signature, actor
            ):
                return self._record(race)
            raise ConflictError(
                "C6 red-team assessment violates an immutable constraint",
                {"assessment_id": assessment_id, "plan_id": plan_id},
            ) from exc
        return self.get_assessment(assessment_id)

    admit = admit_assessment
    admit_red_team_assessment = admit_assessment

    @classmethod
    def _read_members(
        cls,
        database: Any,
        assessment_id: str,
        table: str,
    ) -> tuple[Mapping[str, object], ...]:
        rows = database.connection.execute(
            f"SELECT material_json FROM {table} WHERE assessment_id = ? ORDER BY ordinal",
            (assessment_id,),
        ).fetchall()
        members: list[Mapping[str, object]] = []
        for row in rows:
            try:
                material = json.loads(str(row["material_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise IntegrityError("stored C6 member material is invalid") from exc
            if not isinstance(material, dict):
                raise IntegrityError("stored C6 member material is invalid")
            members.append(material)
        return tuple(members)

    def get_attack_cases(self, assessment_id: str) -> tuple[Mapping[str, object], ...]:
        assessment_id = self._text(assessment_id, "assessment_id")
        self.get_assessment(assessment_id)
        return self._read_members(
            self.database, assessment_id, "c6_red_team_attack_cases"
        )

    def get_findings(self, assessment_id: str) -> tuple[Mapping[str, object], ...]:
        assessment_id = self._text(assessment_id, "assessment_id")
        self.get_assessment(assessment_id)
        return self._read_members(
            self.database, assessment_id, "c6_red_team_findings"
        )

    def _verify_memberships(
        self,
        record: C6RedTeamAssessment,
        expected: list[Mapping[str, object]],
        table: str,
        identifier_field: str,
        prefix: str,
        defects: list[str],
    ) -> None:
        rows = self.database.connection.execute(
            f"SELECT * FROM {table} WHERE assessment_id = ? ORDER BY ordinal",
            (record.assessment_id,),
        ).fetchall()
        if len(rows) != len(expected):
            defects.append(f"{prefix}_COUNT_MISMATCH")
        actual: list[Mapping[str, object]] = []
        for ordinal, row in enumerate(rows):
            if int(row["ordinal"]) != ordinal:
                defects.append(f"{prefix}_ORDINAL_MISMATCH:{ordinal}")
            try:
                material = json.loads(str(row["material_json"]))
            except (TypeError, json.JSONDecodeError):
                defects.append(f"{prefix}_MATERIAL_INVALID:{ordinal}")
                continue
            if not isinstance(material, dict):
                defects.append(f"{prefix}_MATERIAL_INVALID:{ordinal}")
                continue
            actual.append(material)
            if str(row[identifier_field]) != str(material.get(identifier_field)):
                defects.append(f"{prefix}_BINDING_MISMATCH:{ordinal}")
            if (
                str(row["material_json"]) != canonical_json(material)
                or str(row["material_sha256"]) != sha256_digest(material)
            ):
                defects.append(f"{prefix}_DIGEST_MISMATCH:{ordinal}")
            if (
                str(row["recorded_at"]) != record.admitted_at
                or str(row["recorded_by"]) != record.admitted_by
                or str(row["member_ledger_hash"]) != record.ledger_hash
            ):
                defects.append(f"{prefix}_PROVENANCE_MISMATCH:{ordinal}")
        if actual != [dict(item) for item in expected]:
            defects.append(f"{prefix}_MATERIAL_NOT_CURRENT")

    def verify_assessment(self, assessment_id: str) -> C6RedTeamAssessmentVerification:
        assessment_id = self._text(assessment_id, "assessment_id")
        row = self.database.connection.execute(
            "SELECT * FROM c6_red_team_assessments WHERE assessment_id = ?",
            (assessment_id,),
        ).fetchone()
        if row is None:
            return C6RedTeamAssessmentVerification(assessment_id, ("ASSESSMENT_NOT_FOUND",))
        try:
            record = self._record(row)
        except (IntegrityError, KeyError, TypeError, ValueError, ValidationError):
            return C6RedTeamAssessmentVerification(assessment_id, ("ASSESSMENT_ROW_INVALID",))
        defects: list[str] = []
        if hashlib.sha256(record.payload).hexdigest() != record.payload_sha256:
            defects.append("ASSESSMENT_PAYLOAD_DIGEST_MISMATCH")
        if hashlib.sha256(record.signature).hexdigest() != record.signature_sha256:
            defects.append("ASSESSMENT_SIGNATURE_DIGEST_MISMATCH")
        parsed: dict[str, object] | None = None
        try:
            parsed = self._parse_payload(record.payload)
        except (IntegrityError, StateTransitionError, TypeError, ValueError, ValidationError):
            defects.append("ASSESSMENT_PAYLOAD_INVALID")
        try:
            self._assert_signature(record.key_id, record.payload, record.signature)
        except (IntegrityError, NotFoundError, OSError, TypeError, ValueError, sqlite3.Error):
            defects.append("ASSESSMENT_SIGNATURE_INVALID")
        current: C6RedTeamSnapshot | None = None
        try:
            current = self._build_snapshot(record.plan_id)
        except (
            IntegrityError,
            NotFoundError,
            StateTransitionError,
            TypeError,
            ValueError,
            ValidationError,
            sqlite3.Error,
        ):
            defects.append("ASSESSMENT_C5_SNAPSHOT_INVALID")
        if current is not None:
            if current.snapshot_digest != record.c5_snapshot_digest:
                defects.append("ASSESSMENT_C5_SNAPSHOT_STALE")
            snapshot_fields = {
                "plan_id": current.plan_id,
                "architecture_id": current.architecture_id,
                "plan_version": current.plan_version,
                "architecture_version": current.architecture_version,
                "plan_payload_sha256": current.plan_payload_sha256,
                "work_items_count": current.work_items_count,
                "work_items_digest": current.work_items_digest,
                "release_gates_count": current.release_gates_count,
                "release_gates_digest": current.release_gates_digest,
                "c5_provenance_event_id": current.c5_provenance_event_id,
                "c5_provenance_head_hash": current.c5_provenance_head_hash,
                "latest_evidence_at": current.latest_evidence_at,
                "c5_snapshot_digest": current.snapshot_digest,
            }
            record_snapshot_fields = {
                "plan_id": record.plan_id,
                "architecture_id": record.architecture_id,
                "plan_payload_sha256": record.plan_payload_sha256,
                "work_items_count": record.work_items_count,
                "work_items_digest": record.work_items_digest,
                "release_gates_count": record.release_gates_count,
                "release_gates_digest": record.release_gates_digest,
                "c5_provenance_event_id": record.c5_provenance_event_id,
                "c5_provenance_head_hash": record.c5_provenance_head_hash,
                "latest_evidence_at": record.latest_evidence_at,
                "c5_snapshot_digest": record.c5_snapshot_digest,
            }
            if any(
                record_snapshot_fields.get(field) != observed
                for field, observed in snapshot_fields.items()
                if field in record_snapshot_fields
            ):
                defects.append("ASSESSMENT_C5_BINDING_MISMATCH")
        if parsed is not None:
            if parsed.get("assessment_id") != record.assessment_id:
                defects.append("ASSESSMENT_PAYLOAD_RECORD_MISMATCH")
            expected_record = {
                "plan_id": record.plan_id,
                "architecture_id": record.architecture_id,
                "plan_payload_sha256": record.plan_payload_sha256,
                "c5_snapshot_digest": record.c5_snapshot_digest,
                "threat_model_digest": record.threat_model_digest,
                "verdict": record.verdict,
                "remediation_required": record.remediation_required,
                "release_recommendation": record.release_recommendation,
                "assessor_identity": record.assessor_identity,
                "assessor_environment": record.assessor_environment,
                "adjudicator_identity": record.adjudicator_identity,
                "adjudicator_environment": record.adjudicator_environment,
                "assessed_at_utc": record.assessed_at_utc,
                "independence_basis": dict(record.independence_basis),
                "gate_effect": record.gate_effect,
            }
            if any(parsed.get(field) != observed for field, observed in expected_record.items()):
                defects.append("ASSESSMENT_PAYLOAD_RECORD_MISMATCH")
            if current is not None:
                try:
                    self._assert_payload_binding(parsed, current, admitted_at=record.admitted_at)
                except (IntegrityError, StateTransitionError, ValidationError, TypeError, ValueError):
                    defects.append("ASSESSMENT_PAYLOAD_C5_MISMATCH")
                self._verify_memberships(
                    record,
                    parsed["attack_cases"],
                    "c6_red_team_attack_cases",
                    "attack_case_id",
                    "ASSESSMENT_ATTACK_CASES",
                    defects,
                )
                self._verify_memberships(
                    record,
                    parsed["findings"],
                    "c6_red_team_findings",
                    "finding_id",
                    "ASSESSMENT_FINDINGS",
                    defects,
                )
            work_items_digest = current.work_items_digest if current is not None else record.work_items_digest
            release_gates_digest = current.release_gates_digest if current is not None else record.release_gates_digest
            if work_items_digest != record.work_items_digest:
                defects.append("ASSESSMENT_WORK_ITEMS_DIGEST_MISMATCH")
            if release_gates_digest != record.release_gates_digest:
                defects.append("ASSESSMENT_RELEASE_GATES_DIGEST_MISMATCH")
        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?", (record.ledger_event_id,)
        ).fetchone()
        expected_event = self._event_payload(record)
        if event is None:
            defects.append("ASSESSMENT_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != f"continuity:c6:red-team:{record.assessment_id}":
                defects.append("ASSESSMENT_LEDGER_STREAM_MISMATCH")
            if str(event["kind"]) != _EVENT_KIND:
                defects.append("ASSESSMENT_LEDGER_KIND_MISMATCH")
            if str(event["actor"]) != record.admitted_by:
                defects.append("ASSESSMENT_LEDGER_ACTOR_MISMATCH")
            if str(event["occurred_at"]) != record.admitted_at:
                defects.append("ASSESSMENT_LEDGER_TIMESTAMP_MISMATCH")
            if str(event["record_hash"]) != record.ledger_hash:
                defects.append("ASSESSMENT_LEDGER_HASH_MISMATCH")
            try:
                if json.loads(str(event["payload_json"])) != expected_event:
                    defects.append("ASSESSMENT_LEDGER_PAYLOAD_MISMATCH")
            except (TypeError, json.JSONDecodeError):
                defects.append("ASSESSMENT_LEDGER_PAYLOAD_INVALID")
        try:
            chain = self.ledger.verify(f"continuity:c6:red-team:{record.assessment_id}")
            defects.extend(
                f"ASSESSMENT_LEDGER_CHAIN:{getattr(defect, 'code', 'INVALID')}"
                for defect in getattr(chain, "defects", ())
            )
        except (IntegrityError, TypeError, ValueError, sqlite3.Error):
            defects.append("ASSESSMENT_LEDGER_CHAIN_INVALID")
        return C6RedTeamAssessmentVerification(assessment_id, tuple(dict.fromkeys(defects)))

    verify = verify_assessment
    verify_red_team_assessment = verify_assessment
