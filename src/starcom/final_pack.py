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
from .red_team import C6RedTeamService


_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
_MAX_SIGNATURE_BYTES = 1024
_PACK_VERSION = "1.0.0"
_RELEASE_STATUS = "NOT_RELEASED"
_RUNTIME_STATUS = "NOT_PROVEN"
_CENSUS_STATUS = "NOT_PROVEN"
_GATE_EFFECT = "C7_FINAL_PACK_ADMITTED_NOT_RELEASED"
_EVENT_KIND = "C7_FINAL_PACK_ADMITTED"
_ACTION = "c7.final-pack.admit"
_ARTIFACT_KINDS = frozenset(
    {
        "C4_ARCHITECTURE_BASELINE",
        "C5_EXECUTION_PLAN",
        "C6_RED_TEAM_ASSESSMENT",
        "TEST_REPORT",
        "SECURITY_REPORT",
        "SBOM",
        "PROVENANCE",
        "REPRODUCIBILITY",
        "ROLLBACK_EVIDENCE",
    }
)
_ARTIFACT_PHASES = {
    "C4_ARCHITECTURE_BASELINE": "C4",
    "C5_EXECUTION_PLAN": "C5",
    "C6_RED_TEAM_ASSESSMENT": "C6",
    "TEST_REPORT": "C7",
    "SECURITY_REPORT": "C7",
    "SBOM": "C7",
    "PROVENANCE": "C7",
    "REPRODUCIBILITY": "C7",
    "ROLLBACK_EVIDENCE": "C7",
}
_MANIFEST_DIGEST_FIELDS = {
    "C4_ARCHITECTURE_BASELINE": "architecture_payload_sha256",
    "C5_EXECUTION_PLAN": "plan_payload_sha256",
    "C6_RED_TEAM_ASSESSMENT": "assessment_payload_sha256",
    "TEST_REPORT": "test_report_digest",
    "SECURITY_REPORT": "security_report_digest",
    "SBOM": "sbom_digest",
    "PROVENANCE": "provenance_digest",
    "REPRODUCIBILITY": "reproducibility_digest",
    "ROLLBACK_EVIDENCE": "rollback_evidence_digest",
}
_REQUIRED_FIELDS = frozenset(
    {
        "pack_id",
        "pack_version",
        "baseline_id",
        "architecture_id",
        "architecture_version",
        "architecture_payload_sha256",
        "c4_snapshot_digest",
        "plan_id",
        "plan_version",
        "plan_payload_sha256",
        "c5_snapshot_digest",
        "assessment_id",
        "assessment_payload_sha256",
        "c6_snapshot_digest",
        "c3_snapshot_digest",
        "chain_snapshot_digest",
        "evidence_manifest",
        "sbom_digest",
        "test_report_digest",
        "security_report_digest",
        "provenance_digest",
        "reproducibility_digest",
        "rollback_evidence_digest",
        "packager_identity",
        "packager_environment",
        "verifier_identity",
        "verifier_environment",
        "packaged_at_utc",
        "independence_basis",
        "release_status",
        "external_runtime_integration_status",
        "live_census_certification_status",
        "gate_effect",
    }
)
_MANIFEST_FIELDS = frozenset(
    {
        "artifact_id",
        "artifact_kind",
        "source_phase",
        "digest",
        "media_type",
        "required",
    }
)

_FIND = C6RedTeamService._find
_TEXT = C5ExecutionPlanService._text
_DIGEST = C5ExecutionPlanService._digest
_TIMESTAMP = C5ExecutionPlanService._timestamp
_DT = C5ExecutionPlanService._dt
_SORTED_STRINGS = C5ExecutionPlanService._sorted_strings
_VALUE = C6RedTeamService._value
_BOUNDED_PAYLOAD = C6RedTeamService._bounded_payload
_BOUNDED_SIGNATURE = C6RedTeamService._bounded_signature
_BLOB = C6RedTeamService._blob


@dataclass(frozen=True)
class C7FinalPackSnapshot:
    baseline_id: str
    architecture_id: str
    architecture_version: str
    architecture_payload_sha256: str
    c4_snapshot_digest: str
    plan_id: str
    plan_version: str
    plan_payload_sha256: str
    c5_snapshot_digest: str
    assessment_id: str
    assessment_payload_sha256: str
    c6_snapshot_digest: str
    c3_snapshot_digest: str
    chain_snapshot_digest: str
    provenance_digest: str
    latest_evidence_at: str
    material_identities: tuple[str, ...]


@dataclass(frozen=True)
class C7FinalPackPreparation:
    pack_id: str
    assessment_id: str
    architecture_id: str
    chain_snapshot_digest: str
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]
    gate_effect: str


@dataclass(frozen=True)
class C7FinalPack:
    pack_id: str
    pack_version: str
    baseline_id: str
    architecture_id: str
    architecture_version: str
    architecture_payload_sha256: str
    c4_snapshot_digest: str
    plan_id: str
    plan_version: str
    plan_payload_sha256: str
    c5_snapshot_digest: str
    assessment_id: str
    assessment_payload_sha256: str
    c6_snapshot_digest: str
    c3_snapshot_digest: str
    chain_snapshot_digest: str
    evidence_manifest_digest: str
    sbom_digest: str
    test_report_digest: str
    security_report_digest: str
    provenance_digest: str
    reproducibility_digest: str
    rollback_evidence_digest: str
    packager_identity: str
    packager_environment: str
    verifier_identity: str
    verifier_environment: str
    packaged_at_utc: str
    independence_basis: Mapping[str, Any]
    release_status: str
    external_runtime_integration_status: str
    live_census_certification_status: str
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
class C7FinalPackVerification:
    pack_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C7FinalPackService:
    """Exact-byte C7 final pack authority; admission never releases or publishes."""

    _find = staticmethod(_FIND)
    _text = staticmethod(_TEXT)
    _digest = staticmethod(_DIGEST)
    _timestamp = staticmethod(_TIMESTAMP)
    _dt = staticmethod(_DT)
    _sorted_strings = staticmethod(_SORTED_STRINGS)
    _value = staticmethod(_VALUE)
    _bounded_payload = staticmethod(_BOUNDED_PAYLOAD)
    _bounded_signature = staticmethod(_BOUNDED_SIGNATURE)
    _blob = staticmethod(_BLOB)

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
            lambda value: all(
                hasattr(value, name)
                for name in ("get_baseline", "verify_baseline", "snapshot")
            ),
        )
        self.execution_plan = self._find(
            values,
            lambda value: all(
                hasattr(value, name)
                for name in ("get_plan", "verify_plan", "snapshot")
            ),
        )
        self.red_team = self._find(
            values,
            lambda value: all(
                hasattr(value, name)
                for name in ("get_assessment", "verify_assessment", "snapshot")
            ),
        )
        if any(
            dependency is None
            for dependency in (
                self.trust,
                self.continuity,
                self.architecture,
                self.execution_plan,
                self.red_team,
            )
        ):
            raise ValidationError(
                "C7 final pack requires trust, continuity, C4, C5, and C6 authorities"
            )
        self.signature_verifier = signature_verifier or getattr(
            self.continuity,
            "signature_verifier",
            OpenSSLEd25519Verifier(),
        )
        self._initialize_schema()

    @classmethod
    def _parse_payload(cls, payload: bytes) -> dict[str, object]:
        payload = cls._bounded_payload(payload)

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
            raise ValidationError("C7 final pack payload must be strict UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise ValidationError("C7 final pack payload must be a JSON object")
        fields = frozenset(value)
        if fields != _REQUIRED_FIELDS:
            raise ValidationError(
                "C7 final pack payload fields do not match the contract",
                {
                    "missing": sorted(_REQUIRED_FIELDS - fields),
                    "unexpected": sorted(fields - _REQUIRED_FIELDS),
                },
            )

        for field in (
            "pack_id",
            "pack_version",
            "baseline_id",
            "architecture_id",
            "architecture_version",
            "plan_id",
            "plan_version",
            "assessment_id",
            "packager_identity",
            "packager_environment",
            "verifier_identity",
            "verifier_environment",
            "release_status",
            "external_runtime_integration_status",
            "live_census_certification_status",
            "gate_effect",
        ):
            value[field] = cls._text(value[field], field)
        if value["pack_version"] != _PACK_VERSION:
            raise ValidationError(f"pack_version must equal {_PACK_VERSION}")
        if value["release_status"] != _RELEASE_STATUS:
            raise ValidationError("release_status must remain NOT_RELEASED")
        if value["external_runtime_integration_status"] != _RUNTIME_STATUS:
            raise ValidationError("external_runtime_integration_status must remain NOT_PROVEN")
        if value["live_census_certification_status"] != _CENSUS_STATUS:
            raise ValidationError("live_census_certification_status must remain NOT_PROVEN")
        if value["gate_effect"] != _GATE_EFFECT:
            raise ValidationError("gate_effect must equal C7_FINAL_PACK_ADMITTED_NOT_RELEASED")
        for field in (
            "architecture_payload_sha256",
            "c4_snapshot_digest",
            "plan_payload_sha256",
            "c5_snapshot_digest",
            "assessment_payload_sha256",
            "c6_snapshot_digest",
            "c3_snapshot_digest",
            "chain_snapshot_digest",
            "sbom_digest",
            "test_report_digest",
            "security_report_digest",
            "provenance_digest",
            "reproducibility_digest",
            "rollback_evidence_digest",
        ):
            value[field] = cls._digest(value[field], field)
        value["packaged_at_utc"] = cls._timestamp(value["packaged_at_utc"], "packaged_at_utc")
        value["evidence_manifest"] = cls._parse_manifest(value["evidence_manifest"], value)
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

    @classmethod
    def _parse_manifest(
        cls,
        manifest: object,
        payload: Mapping[str, object],
    ) -> list[dict[str, object]]:
        if not isinstance(manifest, list) or not manifest:
            raise ValidationError("evidence_manifest must be a non-empty list")
        normalized: list[dict[str, object]] = []
        identifiers: list[str] = []
        kinds: list[str] = []
        for ordinal, entry in enumerate(manifest):
            if not isinstance(entry, dict) or frozenset(entry) != _MANIFEST_FIELDS:
                raise ValidationError(
                    f"evidence_manifest[{ordinal}] fields do not match the contract"
                )
            item = dict(entry)
            artifact_id = cls._text(item["artifact_id"], f"evidence_manifest[{ordinal}].artifact_id")
            kind = cls._text(item["artifact_kind"], f"evidence_manifest[{ordinal}].artifact_kind")
            source_phase = cls._text(
                item["source_phase"], f"evidence_manifest[{ordinal}].source_phase"
            )
            digest = cls._digest(item["digest"], f"evidence_manifest[{ordinal}].digest")
            media_type = cls._text(item["media_type"], f"evidence_manifest[{ordinal}].media_type")
            required = item["required"]
            if not isinstance(required, bool):
                raise ValidationError(f"evidence_manifest[{ordinal}].required must be boolean")
            if kind not in _ARTIFACT_KINDS:
                raise ValidationError("evidence_manifest artifact kind is outside the contract")
            if source_phase != _ARTIFACT_PHASES[kind]:
                raise ValidationError("evidence_manifest source phase does not match artifact kind")
            if digest != payload[_MANIFEST_DIGEST_FIELDS[kind]]:
                raise IntegrityError("evidence_manifest digest does not match its top-level digest")
            identifiers.append(artifact_id)
            kinds.append(kind)
            normalized.append(
                {
                    "artifact_id": artifact_id,
                    "artifact_kind": kind,
                    "source_phase": source_phase,
                    "digest": digest,
                    "media_type": media_type,
                    "required": required,
                }
            )
        if identifiers != sorted(identifiers) or len(set(identifiers)) != len(identifiers):
            raise ValidationError("evidence_manifest artifact IDs must be sorted and unique")
        if set(kinds) != _ARTIFACT_KINDS or len(kinds) != len(_ARTIFACT_KINDS):
            raise ValidationError("evidence_manifest must contain every mandatory artifact kind once")
        if not all(bool(item["required"]) for item in normalized):
            raise ValidationError("every mandatory evidence artifact must be required")
        return normalized

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c7_final_packs (
                    pack_id TEXT PRIMARY KEY,
                    pack_version TEXT NOT NULL CHECK (pack_version = '1.0.0'),
                    baseline_id TEXT NOT NULL,
                    architecture_id TEXT NOT NULL,
                    architecture_version TEXT NOT NULL,
                    architecture_payload_sha256 TEXT NOT NULL CHECK (length(architecture_payload_sha256) = 64),
                    c4_snapshot_digest TEXT NOT NULL CHECK (length(c4_snapshot_digest) = 64),
                    plan_id TEXT NOT NULL,
                    plan_version TEXT NOT NULL,
                    plan_payload_sha256 TEXT NOT NULL CHECK (length(plan_payload_sha256) = 64),
                    c5_snapshot_digest TEXT NOT NULL CHECK (length(c5_snapshot_digest) = 64),
                    assessment_id TEXT NOT NULL UNIQUE,
                    assessment_payload_sha256 TEXT NOT NULL CHECK (length(assessment_payload_sha256) = 64),
                    c6_snapshot_digest TEXT NOT NULL CHECK (length(c6_snapshot_digest) = 64),
                    c3_snapshot_digest TEXT NOT NULL CHECK (length(c3_snapshot_digest) = 64),
                    chain_snapshot_digest TEXT NOT NULL CHECK (length(chain_snapshot_digest) = 64),
                    evidence_manifest_digest TEXT NOT NULL CHECK (length(evidence_manifest_digest) = 64),
                    sbom_digest TEXT NOT NULL CHECK (length(sbom_digest) = 64),
                    test_report_digest TEXT NOT NULL CHECK (length(test_report_digest) = 64),
                    security_report_digest TEXT NOT NULL CHECK (length(security_report_digest) = 64),
                    provenance_digest TEXT NOT NULL CHECK (length(provenance_digest) = 64),
                    reproducibility_digest TEXT NOT NULL CHECK (length(reproducibility_digest) = 64),
                    rollback_evidence_digest TEXT NOT NULL CHECK (length(rollback_evidence_digest) = 64),
                    packager_identity TEXT NOT NULL,
                    packager_environment TEXT NOT NULL,
                    verifier_identity TEXT NOT NULL,
                    verifier_environment TEXT NOT NULL,
                    packaged_at_utc TEXT NOT NULL,
                    independence_basis_json TEXT NOT NULL,
                    release_status TEXT NOT NULL CHECK (release_status = 'NOT_RELEASED'),
                    external_runtime_integration_status TEXT NOT NULL CHECK (external_runtime_integration_status = 'NOT_PROVEN'),
                    live_census_certification_status TEXT NOT NULL CHECK (live_census_certification_status = 'NOT_PROVEN'),
                    gate_effect TEXT NOT NULL CHECK (gate_effect = 'C7_FINAL_PACK_ADMITTED_NOT_RELEASED'),
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
                CREATE TABLE IF NOT EXISTS c7_final_pack_manifest (
                    pack_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                    artifact_id TEXT NOT NULL,
                    artifact_kind TEXT NOT NULL,
                    material_json TEXT NOT NULL,
                    material_sha256 TEXT NOT NULL CHECK (length(material_sha256) = 64),
                    recorded_at TEXT NOT NULL,
                    recorded_by TEXT NOT NULL,
                    member_ledger_hash TEXT NOT NULL CHECK (length(member_ledger_hash) = 64),
                    PRIMARY KEY (pack_id, ordinal),
                    UNIQUE (pack_id, artifact_id),
                    UNIQUE (pack_id, artifact_kind),
                    FOREIGN KEY (pack_id) REFERENCES c7_final_packs(pack_id)
                )
                """
            )
            for table in ("c7_final_packs", "c7_final_pack_manifest"):
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

    def _clean(self, authority: Any, method: str, identifier: str, label: str) -> Any:
        result = getattr(authority, method)(identifier)
        if not getattr(result, "ok", False):
            raise IntegrityError(
                f"{label} verification failed",
                {"identifier": identifier, "defects": list(getattr(result, "defects", ()))},
            )
        return result

    def _c6_assessment(self, assessment_id: str) -> Any:
        try:
            return self.red_team.get_assessment(assessment_id)
        except (NotFoundError, KeyError) as exc:
            raise NotFoundError(
                "C6 red-team assessment does not exist", {"assessment_id": assessment_id}
            ) from exc

    def _snapshot_material(self, assessment_id: str) -> tuple[Any, Any, Any, Any, Any, Any]:
        assessment = self._c6_assessment(assessment_id)
        self._clean(self.red_team, "verify_assessment", assessment_id, "C6 red-team assessment")
        if assessment.verdict != "C6_PASS_NO_BLOCKING_FINDINGS":
            raise IntegrityError("C6 assessment is not a PASS")
        if assessment.release_recommendation != "PROCEED_TO_C7_FINAL_PACK":
            raise IntegrityError("C6 assessment does not permit the C7 final pack")
        if assessment.gate_effect != "C6_RED_TEAM_ASSESSMENT_ADMITTED_NO_RELEASE":
            raise IntegrityError("C6 assessment gate effect is invalid")

        plan = self.execution_plan.get_plan(assessment.plan_id)
        self._clean(self.execution_plan, "verify_plan", assessment.plan_id, "C5 execution plan")
        c5_snapshot = self.red_team.snapshot(assessment.plan_id)
        if assessment.c5_snapshot_digest != c5_snapshot.snapshot_digest:
            raise IntegrityError("C6 assessment is stale against the C5 snapshot")
        if assessment.plan_payload_sha256 != c5_snapshot.plan_payload_sha256:
            raise IntegrityError("C6 assessment is stale against the C5 payload")

        baseline_id = self._text(self._value(plan, "c4_baseline_id"), "baseline_id")
        baseline = self.architecture.get_baseline(baseline_id)
        self._clean(self.architecture, "verify_baseline", baseline_id, "C4 architecture baseline")
        c3_run_id = self._text(self._value(baseline, "c3_run_id"), "c3_run_id")
        c4_snapshot = self.architecture.snapshot(c3_run_id)
        architecture_id = self._text(self._value(baseline, "architecture_id"), "architecture_id")
        architecture_version = self._text(
            self._value(baseline, "architecture_version"), "architecture_version"
        )
        architecture_payload_sha256 = self._digest(
            self._value(baseline, "payload_sha256"), "architecture_payload_sha256"
        )
        c4_snapshot_digest = self._digest(
            self._value(plan, "c4_snapshot_digest"), "c4_snapshot_digest"
        )
        c4_authority_snapshot = self.execution_plan.snapshot(architecture_id)
        if c4_snapshot_digest != self._digest(
            self._value(c4_authority_snapshot, "snapshot_digest"),
            "c4_authority_snapshot_digest",
        ):
            raise IntegrityError("C5 plan C4 snapshot binding is stale")
        c3_snapshot_digest = self._digest(
            self._value(c4_snapshot, "c3_snapshot_digest")
            or self._value(plan, "c3_snapshot_digest"),
            "c3_snapshot_digest",
        )
        if self._text(self._value(plan, "architecture_id"), "plan.architecture_id") != architecture_id:
            raise IntegrityError("C5 plan architecture binding is inconsistent")
        if self._text(self._value(plan, "architecture_version"), "plan.architecture_version") != architecture_version:
            raise IntegrityError("C5 plan architecture version binding is inconsistent")
        if self._digest(self._value(plan, "architecture_payload_sha256"), "plan.architecture_payload_sha256") != architecture_payload_sha256:
            raise IntegrityError("C5 plan architecture payload binding is inconsistent")
        if self._digest(self._value(plan, "c3_snapshot_digest"), "plan.c3_snapshot_digest") != c3_snapshot_digest:
            raise IntegrityError("C5 plan C3 snapshot binding is stale")

        plan_id = self._text(self._value(plan, "plan_id"), "plan_id")
        plan_version = self._text(self._value(plan, "plan_version"), "plan_version")
        plan_payload_sha256 = self._digest(self._value(plan, "payload_sha256"), "plan_payload_sha256")
        assessment_payload_sha256 = self._digest(
            self._value(assessment, "payload_sha256"), "assessment_payload_sha256"
        )
        c6_snapshot_digest = sha256_digest(
            {
                "assessment_id": assessment_id,
                "plan_id": plan_id,
                "architecture_id": architecture_id,
                "plan_payload_sha256": plan_payload_sha256,
                "c5_snapshot_digest": c5_snapshot.snapshot_digest,
                "assessment_payload_sha256": assessment_payload_sha256,
                "threat_model_digest": assessment.threat_model_digest,
                "verdict": assessment.verdict,
                "remediation_required": assessment.remediation_required,
                "release_recommendation": assessment.release_recommendation,
                "assessed_at_utc": assessment.assessed_at_utc,
                "admitted_at": assessment.admitted_at,
                "admitted_by": assessment.admitted_by,
                "ledger_event_id": assessment.ledger_event_id,
                "ledger_hash": assessment.ledger_hash,
            }
        )
        provenance_digest = sha256_digest(
            {
                "c4_payload_sha256": architecture_payload_sha256,
                "c4_snapshot_digest": c4_snapshot_digest,
                "c5_provenance_event_id": self._text(
                    self._value(plan, "ledger_event_id"), "c5_provenance_event_id"
                ),
                "c5_provenance_head_hash": self._digest(
                    self._value(plan, "ledger_hash"), "c5_provenance_head_hash"
                ),
                "c6_provenance_event_id": self._text(
                    self._value(assessment, "ledger_event_id"), "c6_provenance_event_id"
                ),
                "c6_provenance_head_hash": self._digest(
                    self._value(assessment, "ledger_hash"), "c6_provenance_head_hash"
                ),
            }
        )
        c4_identities = self._value(c4_snapshot, "material_identities", ())
        c5_identities = c5_snapshot.material_identities
        if not isinstance(c4_identities, (list, tuple, set)):
            raise IntegrityError("C4 material identities are invalid")
        identities = {
            self._text(identity, "c4_material_identity") for identity in c4_identities
        }
        identities.update(
            self._text(identity, "c5_material_identity") for identity in c5_identities
        )
        independence = self._value(assessment, "independence_basis", {})
        if not isinstance(independence, Mapping):
            raise IntegrityError("C6 independence basis is invalid")
        identities.update(
            self._sorted_strings(
                independence.get("excluded_identities"),
                "c6.excluded_identities",
                allow_empty=True,
            )
        )
        for field in ("assessor_identity", "adjudicator_identity", "admitted_by"):
            identities.add(self._text(self._value(assessment, field), f"c6.{field}"))
        material_identities = tuple(sorted(identities))
        timestamps = [
            self._timestamp(
                self._value(c4_snapshot, "latest_evidence_at"), "c4.latest_evidence_at"
            ),
            self._timestamp(c5_snapshot.latest_evidence_at, "c5.latest_evidence_at"),
            self._timestamp(assessment.assessed_at_utc, "c6.assessed_at_utc"),
            self._timestamp(assessment.admitted_at, "c6.admitted_at"),
        ]
        latest_evidence_at = max(timestamps, key=self._dt)
        chain_snapshot_digest = sha256_digest(
            {
                "baseline_id": baseline_id,
                "architecture_id": architecture_id,
                "architecture_version": architecture_version,
                "architecture_payload_sha256": architecture_payload_sha256,
                "c4_snapshot_digest": c4_snapshot_digest,
                "plan_id": plan_id,
                "plan_version": plan_version,
                "plan_payload_sha256": plan_payload_sha256,
                "c5_snapshot_digest": self._c5_snapshot_digest(c5_snapshot),
                "assessment_id": assessment_id,
                "assessment_payload_sha256": assessment_payload_sha256,
                "c6_snapshot_digest": c6_snapshot_digest,
                "c3_snapshot_digest": c3_snapshot_digest,
                "provenance_digest": provenance_digest,
                "latest_evidence_at": latest_evidence_at,
                "material_identities": list(material_identities),
            }
        )
        snapshot = C7FinalPackSnapshot(
            baseline_id,
            architecture_id,
            architecture_version,
            architecture_payload_sha256,
            c4_snapshot_digest,
            plan_id,
            plan_version,
            plan_payload_sha256,
            self._c5_snapshot_digest(c5_snapshot),
            assessment_id,
            assessment_payload_sha256,
            c6_snapshot_digest,
            c3_snapshot_digest,
            chain_snapshot_digest,
            provenance_digest,
            latest_evidence_at,
            material_identities,
        )
        return baseline, plan, assessment, c4_snapshot, c5_snapshot, snapshot

    def snapshot(self, assessment_id: str) -> C7FinalPackSnapshot:
        assessment_id = self._text(assessment_id, "assessment_id")
        return self._snapshot_material(assessment_id)[-1]

    def prepare(
        self,
        pack_id: str,
        assessment_id: str,
        payload: Mapping[str, Any] | None = None,
    ) -> C7FinalPackPreparation:
        pack_id = self._text(pack_id, "pack_id")
        assessment_id = self._text(assessment_id, "assessment_id")
        snapshot = self.snapshot(assessment_id)
        if payload is not None:
            if self._text(payload.get("pack_id"), "payload.pack_id") != pack_id:
                raise StateTransitionError("C7 preparation targets another pack")
            if self._text(payload.get("assessment_id"), "payload.assessment_id") != assessment_id:
                raise StateTransitionError("C7 preparation targets another C6 assessment")
        resource = f"continuity:c7:final-pack:{pack_id}"
        context = {
            "pack_id": pack_id,
            "assessment_id": snapshot.assessment_id,
            "architecture_id": snapshot.architecture_id,
            "plan_id": snapshot.plan_id,
            "c5_snapshot_digest": snapshot.c5_snapshot_digest,
            "c6_snapshot_digest": snapshot.c6_snapshot_digest,
            "chain_snapshot_digest": snapshot.chain_snapshot_digest,
            "release_status": _RELEASE_STATUS,
            "gate_effect": _GATE_EFFECT,
        }
        return C7FinalPackPreparation(
            pack_id,
            assessment_id,
            snapshot.architecture_id,
            snapshot.chain_snapshot_digest,
            _ACTION,
            resource,
            "continuity",
            context,
            _GATE_EFFECT,
        )

    @staticmethod
    def _c5_snapshot_digest(snapshot: Any) -> str:
        return str(snapshot.snapshot_digest)

    @staticmethod
    def _identity_related(candidate: str, upstream: str) -> bool:
        candidate_tokens = set(candidate.lower().replace("_", "-").split("-"))
        upstream_tokens = set(upstream.lower().replace("_", "-").split("-"))
        role_tokens = {
            "adjudicator",
            "admitter",
            "architect",
            "assessor",
            "author",
            "decision",
            "evidence",
            "maker",
            "planner",
            "reviewer",
        }
        return (
            candidate == upstream
            or candidate in upstream
            or upstream in candidate
            or bool(candidate_tokens & upstream_tokens & role_tokens)
        )

    @classmethod
    def _assert_payload_binding(
        cls,
        value: Mapping[str, object],
        snapshot: C7FinalPackSnapshot,
        *,
        admitted_at: str | None = None,
    ) -> None:
        fields = (
            "baseline_id",
            "architecture_id",
            "architecture_version",
            "architecture_payload_sha256",
            "c4_snapshot_digest",
            "plan_id",
            "plan_version",
            "plan_payload_sha256",
            "c5_snapshot_digest",
            "assessment_id",
            "assessment_payload_sha256",
            "c6_snapshot_digest",
            "c3_snapshot_digest",
            "chain_snapshot_digest",
            "provenance_digest",
        )
        expected = {field: getattr(snapshot, field) for field in fields}
        for field, observed in expected.items():
            if value.get(field) != observed:
                raise IntegrityError(
                    "signed C7 pack is stale or bound to another upstream authority",
                    {"field": field, "expected": observed, "actual": value.get(field)},
                )
        packaged_at = cls._timestamp(value.get("packaged_at_utc"), "packaged_at_utc")
        if cls._dt(packaged_at) <= cls._dt(snapshot.latest_evidence_at):
            raise StateTransitionError("C7 packaging must occur after all upstream evidence")
        if admitted_at is not None and cls._dt(admitted_at) < cls._dt(packaged_at):
            raise StateTransitionError("C7 admission predates signed packaging")
        if value.get("release_status") != _RELEASE_STATUS:
            raise StateTransitionError("C7 final pack must remain NOT_RELEASED")
        if value.get("external_runtime_integration_status") != _RUNTIME_STATUS:
            raise StateTransitionError("C7 runtime integration must remain NOT_PROVEN")
        if value.get("live_census_certification_status") != _CENSUS_STATUS:
            raise StateTransitionError("C7 live census certification must remain NOT_PROVEN")
        if value.get("gate_effect") != _GATE_EFFECT:
            raise StateTransitionError("C7 gate effect is invalid")
        packager = cls._text(value.get("packager_identity"), "packager_identity")
        verifier = cls._text(value.get("verifier_identity"), "verifier_identity")
        if packager == verifier:
            raise StateTransitionError("C7 packager and verifier must be distinct")
        if any(
            cls._identity_related(candidate, upstream)
            for candidate in (packager, verifier)
            for upstream in snapshot.material_identities
        ):
            raise StateTransitionError("C7 packager and verifier must be independent")
        independence = value.get("independence_basis")
        if not isinstance(independence, Mapping):
            raise ValidationError("C7 independence basis is invalid")
        excluded = list(independence.get("excluded_identities", ()))
        if excluded != list(snapshot.material_identities):
            raise StateTransitionError("C7 independence exclusions do not match upstream material")

    @staticmethod
    def _stream(pack_id: str) -> str:
        return f"continuity:c7:final-pack:{pack_id}"

    @staticmethod
    def _event_payload(record: C7FinalPack) -> dict[str, object]:
        return {
            "pack_id": record.pack_id,
            "assessment_id": record.assessment_id,
            "baseline_id": record.baseline_id,
            "architecture_id": record.architecture_id,
            "plan_id": record.plan_id,
            "architecture_payload_sha256": record.architecture_payload_sha256,
            "plan_payload_sha256": record.plan_payload_sha256,
            "assessment_payload_sha256": record.assessment_payload_sha256,
            "c4_snapshot_digest": record.c4_snapshot_digest,
            "c5_snapshot_digest": record.c5_snapshot_digest,
            "c6_snapshot_digest": record.c6_snapshot_digest,
            "chain_snapshot_digest": record.chain_snapshot_digest,
            "evidence_manifest_digest": record.evidence_manifest_digest,
            "key_id": record.key_id,
            "payload_sha256": record.payload_sha256,
            "signature_sha256": record.signature_sha256,
            "release_status": record.release_status,
            "gate_effect": record.gate_effect,
        }

    @staticmethod
    def _replay_matches(
        row: sqlite3.Row,
        pack_id: str,
        assessment_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        actor: str,
    ) -> bool:
        return (
            str(row["pack_id"]) == pack_id
            and str(row["assessment_id"]) == assessment_id
            and str(row["key_id"]) == key_id
            and bytes(row["payload"]) == payload
            and bytes(row["signature"]) == signature
            and str(row["admitted_by"]) == actor
        )

    def _assert_signature(self, key_id: str, payload: bytes, signature: bytes) -> None:
        root = self.continuity.verify_trust_root(key_id)
        if not getattr(root, "ok", False):
            raise IntegrityError(
                "C7 final pack trust root verification failed",
                {"key_id": key_id, "defects": list(getattr(root, "defects", ()))},
            )
        row = self.database.connection.execute(
            "SELECT public_key_pem FROM continuity_trust_roots WHERE key_id = ?",
            (key_id,),
        ).fetchone()
        if row is None or not self.signature_verifier.verify(
            bytes(row["public_key_pem"]), payload, signature
        ):
            raise IntegrityError("C7 final pack signature is invalid")

    @classmethod
    def _record(cls, row: sqlite3.Row) -> C7FinalPack:
        try:
            independence = json.loads(str(row["independence_basis_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrityError("stored C7 independence basis is invalid") from exc
        if not isinstance(independence, dict):
            raise IntegrityError("stored C7 independence basis is invalid")

        def get(field: str) -> Any:
            return row[field]

        return C7FinalPack(
            cls._text(get("pack_id"), "pack_id"),
            cls._text(get("pack_version"), "pack_version"),
            cls._text(get("baseline_id"), "baseline_id"),
            cls._text(get("architecture_id"), "architecture_id"),
            cls._text(get("architecture_version"), "architecture_version"),
            cls._digest(get("architecture_payload_sha256"), "architecture_payload_sha256"),
            cls._digest(get("c4_snapshot_digest"), "c4_snapshot_digest"),
            cls._text(get("plan_id"), "plan_id"),
            cls._text(get("plan_version"), "plan_version"),
            cls._digest(get("plan_payload_sha256"), "plan_payload_sha256"),
            cls._digest(get("c5_snapshot_digest"), "c5_snapshot_digest"),
            cls._text(get("assessment_id"), "assessment_id"),
            cls._digest(get("assessment_payload_sha256"), "assessment_payload_sha256"),
            cls._digest(get("c6_snapshot_digest"), "c6_snapshot_digest"),
            cls._digest(get("c3_snapshot_digest"), "c3_snapshot_digest"),
            cls._digest(get("chain_snapshot_digest"), "chain_snapshot_digest"),
            cls._digest(get("evidence_manifest_digest"), "evidence_manifest_digest"),
            cls._digest(get("sbom_digest"), "sbom_digest"),
            cls._digest(get("test_report_digest"), "test_report_digest"),
            cls._digest(get("security_report_digest"), "security_report_digest"),
            cls._digest(get("provenance_digest"), "provenance_digest"),
            cls._digest(get("reproducibility_digest"), "reproducibility_digest"),
            cls._digest(get("rollback_evidence_digest"), "rollback_evidence_digest"),
            cls._text(get("packager_identity"), "packager_identity"),
            cls._text(get("packager_environment"), "packager_environment"),
            cls._text(get("verifier_identity"), "verifier_identity"),
            cls._text(get("verifier_environment"), "verifier_environment"),
            cls._timestamp(get("packaged_at_utc"), "packaged_at_utc"),
            independence,
            cls._text(get("release_status"), "release_status"),
            cls._text(
                get("external_runtime_integration_status"),
                "external_runtime_integration_status",
            ),
            cls._text(
                get("live_census_certification_status"),
                "live_census_certification_status",
            ),
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

    def _row_for(self, pack_id: str, assessment_id: str) -> sqlite3.Row | None:
        return self.database.connection.execute(
            "SELECT * FROM c7_final_packs "
            "WHERE pack_id = ? OR assessment_id = ? ORDER BY pack_id LIMIT 1",
            (pack_id, assessment_id),
        ).fetchone()

    def get_pack(self, pack_id: str) -> C7FinalPack:
        pack_id = self._text(pack_id, "pack_id")
        row = self.database.connection.execute(
            "SELECT * FROM c7_final_packs WHERE pack_id = ?", (pack_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("C7 final pack does not exist", {"pack_id": pack_id})
        return self._record(row)

    get = get_pack
    get_final_pack = get_pack

    @classmethod
    def _read_manifest(
        cls,
        database: Any,
        pack_id: str,
    ) -> tuple[Mapping[str, object], ...]:
        rows = database.connection.execute(
            "SELECT material_json FROM c7_final_pack_manifest WHERE pack_id = ? ORDER BY ordinal",
            (pack_id,),
        ).fetchall()
        values: list[Mapping[str, object]] = []
        for row in rows:
            try:
                material = json.loads(str(row["material_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise IntegrityError("stored C7 manifest material is invalid") from exc
            if not isinstance(material, dict):
                raise IntegrityError("stored C7 manifest material is invalid")
            values.append(material)
        return tuple(values)

    def get_manifest(self, pack_id: str) -> tuple[Mapping[str, object], ...]:
        pack_id = self._text(pack_id, "pack_id")
        self.get_pack(pack_id)
        return self._read_manifest(self.database, pack_id)

    def _provisional(
        self,
        value: Mapping[str, object],
        key_id: str,
        payload: bytes,
        signature: bytes,
        admitted_at: str,
        actor: str,
    ) -> C7FinalPack:
        independence = value["independence_basis"]
        assert isinstance(independence, dict)
        manifest = value["evidence_manifest"]
        assert isinstance(manifest, list)
        return C7FinalPack(
            str(value["pack_id"]),
            str(value["pack_version"]),
            str(value["baseline_id"]),
            str(value["architecture_id"]),
            str(value["architecture_version"]),
            str(value["architecture_payload_sha256"]),
            str(value["c4_snapshot_digest"]),
            str(value["plan_id"]),
            str(value["plan_version"]),
            str(value["plan_payload_sha256"]),
            str(value["c5_snapshot_digest"]),
            str(value["assessment_id"]),
            str(value["assessment_payload_sha256"]),
            str(value["c6_snapshot_digest"]),
            str(value["c3_snapshot_digest"]),
            str(value["chain_snapshot_digest"]),
            sha256_digest(manifest),
            str(value["sbom_digest"]),
            str(value["test_report_digest"]),
            str(value["security_report_digest"]),
            str(value["provenance_digest"]),
            str(value["reproducibility_digest"]),
            str(value["rollback_evidence_digest"]),
            str(value["packager_identity"]),
            str(value["packager_environment"]),
            str(value["verifier_identity"]),
            str(value["verifier_environment"]),
            str(value["packaged_at_utc"]),
            dict(independence),
            str(value["release_status"]),
            str(value["external_runtime_integration_status"]),
            str(value["live_census_certification_status"]),
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

    def admit_pack(
        self,
        assessment_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        *,
        actor: str,
        occurred_at: str | None = None,
    ) -> C7FinalPack:
        assessment_id = self._text(assessment_id, "assessment_id")
        key_id = self._text(key_id, "key_id")
        actor = self._text(actor, "actor")
        payload = self._bounded_payload(payload)
        signature = self._bounded_signature(signature)
        admitted_at = self._timestamp(occurred_at or utc_now(), "admitted_at")
        value = self._parse_payload(payload)
        if value["assessment_id"] != assessment_id:
            raise StateTransitionError("signed C7 final pack targets another C6 assessment")
        snapshot = self.snapshot(assessment_id)
        self._assert_payload_binding(value, snapshot, admitted_at=admitted_at)
        self._assert_signature(key_id, payload, signature)
        pack_id = str(value["pack_id"])
        existing = self._row_for(pack_id, assessment_id)
        if existing is not None:
            if self._replay_matches(
                existing, pack_id, assessment_id, key_id, payload, signature, actor
            ):
                record = self._record(existing)
                verification = self.verify_pack(pack_id)
                if not verification.ok:
                    raise IntegrityError(
                        "existing C7 final pack failed verification",
                        {"pack_id": pack_id, "defects": list(verification.defects)},
                    )
                return record
            raise ConflictError(
                "C7 pack identifier or C6 assessment already binds different material",
                {"pack_id": pack_id, "assessment_id": assessment_id},
            )
        provisional = self._provisional(value, key_id, payload, signature, admitted_at, actor)
        event_payload = self._event_payload(provisional)
        columns = (
            "pack_id",
            "pack_version",
            "baseline_id",
            "architecture_id",
            "architecture_version",
            "architecture_payload_sha256",
            "c4_snapshot_digest",
            "plan_id",
            "plan_version",
            "plan_payload_sha256",
            "c5_snapshot_digest",
            "assessment_id",
            "assessment_payload_sha256",
            "c6_snapshot_digest",
            "c3_snapshot_digest",
            "chain_snapshot_digest",
            "evidence_manifest_digest",
            "sbom_digest",
            "test_report_digest",
            "security_report_digest",
            "provenance_digest",
            "reproducibility_digest",
            "rollback_evidence_digest",
            "packager_identity",
            "packager_environment",
            "verifier_identity",
            "verifier_environment",
            "packaged_at_utc",
            "independence_basis_json",
            "release_status",
            "external_runtime_integration_status",
            "live_census_certification_status",
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
                current = self.snapshot(assessment_id)
                if current != snapshot:
                    raise ConflictError("C4/C5/C6 snapshot changed during C7 admission")
                self._assert_payload_binding(value, current, admitted_at=admitted_at)
                self._assert_signature(key_id, payload, signature)
                race = connection.execute(
                    "SELECT pack_id FROM c7_final_packs "
                    "WHERE pack_id = ? OR assessment_id = ? OR payload_sha256 = ?",
                    (pack_id, assessment_id, provisional.payload_sha256),
                ).fetchone()
                if race is not None:
                    raise ConflictError("C7 final pack appeared during admission")
                receipt = self.ledger.append_in_transaction(
                    connection,
                    self._stream(pack_id),
                    _EVENT_KIND,
                    event_payload,
                    actor=actor,
                    occurred_at=admitted_at,
                )
                values: list[object] = []
                for field in columns:
                    if field == "independence_basis_json":
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
                    f"INSERT INTO c7_final_packs ({','.join(columns)}) VALUES ({placeholders})",
                    tuple(values),
                )
                for ordinal, material in enumerate(value["evidence_manifest"]):
                    assert isinstance(material, dict)
                    connection.execute(
                        "INSERT INTO c7_final_pack_manifest "
                        "(pack_id,ordinal,artifact_id,artifact_kind,material_json,material_sha256,"
                        "recorded_at,recorded_by,member_ledger_hash) VALUES (?,?,?,?,?,?,?,?,?)",
                        (
                            pack_id,
                            ordinal,
                            material["artifact_id"],
                            material["artifact_kind"],
                            canonical_json(material),
                            sha256_digest(material),
                            admitted_at,
                            actor,
                            receipt.record_hash,
                        ),
                    )
        except sqlite3.IntegrityError as exc:
            race = self._row_for(pack_id, assessment_id)
            if race is not None and self._replay_matches(
                race, pack_id, assessment_id, key_id, payload, signature, actor
            ):
                return self._record(race)
            raise ConflictError(
                "C7 final pack violates an immutable constraint",
                {"pack_id": pack_id, "assessment_id": assessment_id},
            ) from exc
        return self.get_pack(pack_id)

    admit = admit_pack
    admit_final_pack = admit_pack

    @classmethod
    def _verify_manifest(
        cls,
        database: Any,
        record: C7FinalPack,
        expected: list[Mapping[str, object]],
        defects: list[str],
    ) -> None:
        rows = database.connection.execute(
            "SELECT * FROM c7_final_pack_manifest WHERE pack_id = ? ORDER BY ordinal",
            (record.pack_id,),
        ).fetchall()
        actual: list[Mapping[str, object]] = []
        for ordinal, row in enumerate(rows):
            if int(row["ordinal"]) != ordinal:
                defects.append(f"PACK_MANIFEST_ORDINAL_MISMATCH:{ordinal}")
            try:
                material = json.loads(str(row["material_json"]))
            except (TypeError, json.JSONDecodeError):
                defects.append(f"PACK_MANIFEST_MATERIAL_INVALID:{ordinal}")
                continue
            if not isinstance(material, dict):
                defects.append(f"PACK_MANIFEST_MATERIAL_INVALID:{ordinal}")
                continue
            actual.append(material)
            if str(row["artifact_id"]) != str(material.get("artifact_id")):
                defects.append(f"PACK_MANIFEST_ID_MISMATCH:{ordinal}")
            if str(row["artifact_kind"]) != str(material.get("artifact_kind")):
                defects.append(f"PACK_MANIFEST_KIND_MISMATCH:{ordinal}")
            if (
                str(row["material_json"]) != canonical_json(material)
                or str(row["material_sha256"]) != sha256_digest(material)
            ):
                defects.append(f"PACK_MANIFEST_DIGEST_MISMATCH:{ordinal}")
            if (
                str(row["recorded_at"]) != record.admitted_at
                or str(row["recorded_by"]) != record.admitted_by
                or str(row["member_ledger_hash"]) != record.ledger_hash
            ):
                defects.append(f"PACK_MANIFEST_PROVENANCE_MISMATCH:{ordinal}")
        if actual != [dict(item) for item in expected]:
            defects.append("PACK_MANIFEST_MATERIAL_NOT_CURRENT")
        if len(actual) != len(expected):
            defects.append("PACK_MANIFEST_COUNT_MISMATCH")

    def verify_pack(self, pack_id: str) -> C7FinalPackVerification:
        pack_id = self._text(pack_id, "pack_id")
        row = self.database.connection.execute(
            "SELECT * FROM c7_final_packs WHERE pack_id = ?", (pack_id,)
        ).fetchone()
        if row is None:
            return C7FinalPackVerification(pack_id, ("PACK_NOT_FOUND",))
        defects: list[str] = []
        try:
            record = self._record(row)
        except (IntegrityError, KeyError, TypeError, ValueError, ValidationError):
            return C7FinalPackVerification(pack_id, ("PACK_ROW_INVALID",))
        if hashlib.sha256(record.payload).hexdigest() != record.payload_sha256:
            defects.append("PACK_PAYLOAD_DIGEST_MISMATCH")
        if hashlib.sha256(record.signature).hexdigest() != record.signature_sha256:
            defects.append("PACK_SIGNATURE_DIGEST_MISMATCH")
        parsed: dict[str, object] | None = None
        try:
            parsed = self._parse_payload(record.payload)
        except (IntegrityError, StateTransitionError, TypeError, ValueError, ValidationError):
            defects.append("PACK_PAYLOAD_INVALID")
        try:
            self._assert_signature(record.key_id, record.payload, record.signature)
        except (IntegrityError, NotFoundError, OSError, TypeError, ValueError, sqlite3.Error):
            defects.append("PACK_SIGNATURE_INVALID")
        current: C7FinalPackSnapshot | None = None
        try:
            current = self.snapshot(record.assessment_id)
        except (
            IntegrityError,
            NotFoundError,
            StateTransitionError,
            TypeError,
            ValueError,
            ValidationError,
            sqlite3.Error,
        ):
            defects.append("PACK_UPSTREAM_SNAPSHOT_INVALID")
        if current is not None:
            for field in (
                "baseline_id",
                "architecture_id",
                "architecture_version",
                "architecture_payload_sha256",
                "c4_snapshot_digest",
                "plan_id",
                "plan_version",
                "plan_payload_sha256",
                "c5_snapshot_digest",
                "assessment_id",
                "assessment_payload_sha256",
                "c6_snapshot_digest",
                "c3_snapshot_digest",
                "chain_snapshot_digest",
                "provenance_digest",
            ):
                if getattr(record, field) != getattr(current, field):
                    defects.append(f"PACK_{field.upper()}_STALE")
            if parsed is not None:
                try:
                    self._assert_payload_binding(parsed, current, admitted_at=record.admitted_at)
                except (IntegrityError, StateTransitionError, ValidationError, TypeError, ValueError):
                    defects.append("PACK_PAYLOAD_UPSTREAM_MISMATCH")
        if parsed is not None:
            expected_record = {
                "pack_id": record.pack_id,
                "pack_version": record.pack_version,
                "baseline_id": record.baseline_id,
                "architecture_id": record.architecture_id,
                "architecture_version": record.architecture_version,
                "architecture_payload_sha256": record.architecture_payload_sha256,
                "c4_snapshot_digest": record.c4_snapshot_digest,
                "plan_id": record.plan_id,
                "plan_version": record.plan_version,
                "plan_payload_sha256": record.plan_payload_sha256,
                "c5_snapshot_digest": record.c5_snapshot_digest,
                "assessment_id": record.assessment_id,
                "assessment_payload_sha256": record.assessment_payload_sha256,
                "c6_snapshot_digest": record.c6_snapshot_digest,
                "c3_snapshot_digest": record.c3_snapshot_digest,
                "chain_snapshot_digest": record.chain_snapshot_digest,
                "sbom_digest": record.sbom_digest,
                "test_report_digest": record.test_report_digest,
                "security_report_digest": record.security_report_digest,
                "provenance_digest": record.provenance_digest,
                "reproducibility_digest": record.reproducibility_digest,
                "rollback_evidence_digest": record.rollback_evidence_digest,
                "packager_identity": record.packager_identity,
                "packager_environment": record.packager_environment,
                "verifier_identity": record.verifier_identity,
                "verifier_environment": record.verifier_environment,
                "packaged_at_utc": record.packaged_at_utc,
                "independence_basis": dict(record.independence_basis),
                "release_status": record.release_status,
                "external_runtime_integration_status": record.external_runtime_integration_status,
                "live_census_certification_status": record.live_census_certification_status,
                "gate_effect": record.gate_effect,
            }
            if parsed.get("assessment_id") != record.assessment_id:
                defects.append("PACK_PAYLOAD_RECORD_MISMATCH")
            if any(parsed.get(field) != observed for field, observed in expected_record.items()):
                defects.append("PACK_PAYLOAD_RECORD_MISMATCH")
            manifest = parsed["evidence_manifest"]
            if isinstance(manifest, list):
                if sha256_digest(manifest) != record.evidence_manifest_digest:
                    defects.append("PACK_MANIFEST_DIGEST_MISMATCH")
                self._verify_manifest(self.database, record, manifest, defects)
        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?", (record.ledger_event_id,)
        ).fetchone()
        expected_event = self._event_payload(record)
        if event is None:
            defects.append("PACK_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != self._stream(record.pack_id):
                defects.append("PACK_LEDGER_STREAM_MISMATCH")
            if str(event["kind"]) != _EVENT_KIND:
                defects.append("PACK_LEDGER_KIND_MISMATCH")
            if str(event["actor"]) != record.admitted_by:
                defects.append("PACK_LEDGER_ACTOR_MISMATCH")
            if str(event["occurred_at"]) != record.admitted_at:
                defects.append("PACK_LEDGER_TIMESTAMP_MISMATCH")
            if str(event["record_hash"]) != record.ledger_hash:
                defects.append("PACK_LEDGER_HASH_MISMATCH")
            try:
                if json.loads(str(event["payload_json"])) != expected_event:
                    defects.append("PACK_LEDGER_PAYLOAD_MISMATCH")
            except (TypeError, json.JSONDecodeError):
                defects.append("PACK_LEDGER_PAYLOAD_INVALID")
        try:
            chain = self.ledger.verify(self._stream(record.pack_id))
            defects.extend(
                f"PACK_LEDGER_CHAIN:{getattr(defect, 'code', 'INVALID')}"
                for defect in getattr(chain, "defects", ())
            )
        except (IntegrityError, TypeError, ValueError, sqlite3.Error):
            defects.append("PACK_LEDGER_CHAIN_INVALID")
        return C7FinalPackVerification(pack_id, tuple(dict.fromkeys(defects)))

    verify = verify_pack
    verify_final_pack = verify_pack
C7FinalEvidencePack = C7FinalPack
C7FinalEvidencePackVerification = C7FinalPackVerification
