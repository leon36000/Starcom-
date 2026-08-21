from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import math
import sqlite3
from typing import Any, Mapping

from .canonical import canonical_json, parse_strict_json_object, sha256_digest, utc_now
from .continuity_crypto import OpenSSLEd25519Verifier
from .errors import ConflictError, IntegrityError, NotFoundError, StateTransitionError, ValidationError


_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
_MAX_SIGNATURE_BYTES = 1024
_REQUIRED_EVIDENCE_IDS = (
    "12A-LIVE",
    "12B-BLUEPRINT",
    "12C-SIMULATION",
    "13-ARTIFACTS",
    "14-SOFTWARE-STUDIO",
    "15-ASSISTANT",
    "16-CREATIVE",
    "17-COCKPIT",
    "18-DEPLOYMENT",
)
_EXTERNAL_FIELDS = (
    "live_census_certification_status",
    "external_runtime_integration_status",
    "component_adoption_status",
    "real_deployment_status",
)
_EXTERNAL_STATUSES = frozenset({"PROVEN", "NOT_PROVEN"})
_OUTCOMES = frozenset({"PASS", "FAIL", "BLOCKED"})
_DIRECTIONS = frozenset({"MINIMUM", "MAXIMUM"})
_VERDICT_VERIFICATION_FAILURE = "RC_BLOCKED_VERIFICATION_FAILURE"
_VERDICT_EXTERNAL_EVIDENCE = "RC_BLOCKED_EXTERNAL_EVIDENCE"
_VERDICT_READY = "RC_READY_FOR_INDEPENDENT_RELEASE_REVIEW"
_RELEASE_STATUS = "NOT_RELEASED"
_GATE_EFFECT = "BLOCK19_RC_ASSESSMENT_ADMITTED_NOT_RELEASED"
_ACTION = "block19.rc-assessment.admit"
_EVENT_KIND = "BLOCK19_RC_ASSESSMENT_ADMITTED"
_REQUIRED_FIELDS = frozenset(
    {
        "assessment_id",
        "assessment_version",
        "evidence_manifest",
        "benchmarks",
        "red_team_cases",
        "release_gates",
        *_EXTERNAL_FIELDS,
        "assessor_identity",
        "assessor_environment",
        "reviewer_identity",
        "reviewer_environment",
        "assessed_at_utc",
        "reviewed_at_utc",
        "independence_basis",
    }
)
_EVIDENCE_FIELDS = frozenset({"evidence_id", "artifact_id", "digest", "status"})
_BENCHMARK_FIELDS = frozenset(
    {
        "benchmark_id",
        "domain",
        "metric",
        "unit",
        "threshold",
        "observed",
        "direction",
        "pass",
        "evidence_digest",
    }
)
_RED_TEAM_FIELDS = frozenset(
    {"case_id", "category", "severity", "outcome", "evidence_digest"}
)
_GATE_FIELDS = frozenset({"gate_id", "status", "evidence_digest"})
_MEMBERSHIP_SPECS = (
    ("block19_rc_evidence", "evidence_id", "evidence_manifest"),
    ("block19_rc_benchmarks", "benchmark_id", "benchmarks"),
    ("block19_rc_red_team_cases", "case_id", "red_team_cases"),
    ("block19_rc_gates", "gate_id", "release_gates"),
)


@dataclass(frozen=True)
class ReleaseCandidatePreparation:
    assessment_id: str
    assessment_version: str
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]
    gate_effect: str


@dataclass(frozen=True)
class ReleaseCandidateSnapshot:
    assessment_id: str
    assessment_version: str
    payload_sha256: str
    evidence_manifest_digest: str
    benchmarks_digest: str
    red_team_digest: str
    release_gates_digest: str
    external_statuses_digest: str
    live_census_certification_status: str
    external_runtime_integration_status: str
    component_adoption_status: str
    real_deployment_status: str
    assessed_at_utc: str
    reviewed_at_utc: str
    latest_evidence_at: str
    material_identities: tuple[str, ...]
    verdict: str
    release_status: str
    gate_effect: str

    @property
    def external_statuses(self) -> Mapping[str, str]:
        return {
            "live_census_certification_status": self.live_census_certification_status,
            "external_runtime_integration_status": self.external_runtime_integration_status,
            "component_adoption_status": self.component_adoption_status,
            "real_deployment_status": self.real_deployment_status,
        }


@dataclass(frozen=True)
class ReleaseCandidateAssessment:
    assessment_id: str
    assessment_version: str
    evidence_manifest_digest: str
    benchmarks_digest: str
    red_team_digest: str
    release_gates_digest: str
    external_statuses_digest: str
    live_census_certification_status: str
    external_runtime_integration_status: str
    component_adoption_status: str
    real_deployment_status: str
    assessor_identity: str
    assessor_environment: str
    reviewer_identity: str
    reviewer_environment: str
    assessed_at_utc: str
    reviewed_at_utc: str
    independence_basis: Mapping[str, Any]
    verdict: str
    release_status: str
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

    @property
    def external_statuses(self) -> Mapping[str, str]:
        return {
            "live_census_certification_status": self.live_census_certification_status,
            "external_runtime_integration_status": self.external_runtime_integration_status,
            "component_adoption_status": self.component_adoption_status,
            "real_deployment_status": self.real_deployment_status,
        }

    @property
    def readiness(self) -> str:
        return self.verdict


@dataclass(frozen=True)
class ReleaseCandidateVerification:
    assessment_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class ReleaseCandidateService:
    """Exact-byte Block 19 authority; readiness never changes release state."""

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
        self.continuity = self._find(values, lambda value: hasattr(value, "verify_trust_root"))
        if self.continuity is None:
            raise ValidationError("Block 19 RC assessment requires Continuity authority")
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
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
        return value

    @staticmethod
    def _timestamp(value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{field} must be an RFC 3339 timestamp")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError(f"{field} must be an RFC 3339 timestamp") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValidationError(f"{field} must be timezone-aware")
        return value

    @staticmethod
    def _dt(value: str) -> datetime:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValidationError("timestamp must be timezone-aware")
        return parsed

    @classmethod
    def _sorted_strings(
        cls,
        value: object,
        field: str,
        *,
        allow_empty: bool = False,
    ) -> list[str]:
        if not isinstance(value, list) or (not allow_empty and not value):
            raise ValidationError(f"{field} must be a non-empty list of strings")
        result = [cls._text(item, f"{field}[{index}]") for index, item in enumerate(value)]
        if result != sorted(result) or len(set(result)) != len(result):
            raise ValidationError(f"{field} must be sorted and unique")
        return result

    @staticmethod
    def _number(value: object, field: str) -> int | float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValidationError(f"{field} must be numeric")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValidationError(f"{field} must be finite")
        return value

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
    def _parse_payload(cls, payload: bytes) -> dict[str, object]:
        value = parse_strict_json_object(
            payload,
            max_bytes=_MAX_PAYLOAD_BYTES,
            label="Block 19 RC assessment",
        )
        fields = frozenset(value)
        if fields != _REQUIRED_FIELDS:
            raise ValidationError(
                "Block 19 RC assessment payload fields do not match the contract",
                {
                    "missing": sorted(_REQUIRED_FIELDS - fields),
                    "unexpected": sorted(fields - _REQUIRED_FIELDS),
                },
            )

        for field in (
            "assessment_id",
            "assessment_version",
            "assessor_identity",
            "assessor_environment",
            "reviewer_identity",
            "reviewer_environment",
        ):
            value[field] = cls._text(value[field], field)
        if value["assessor_identity"] == value["reviewer_identity"]:
            raise StateTransitionError("RC assessor and reviewer must be distinct")
        value["assessed_at_utc"] = cls._timestamp(value["assessed_at_utc"], "assessed_at_utc")
        value["reviewed_at_utc"] = cls._timestamp(value["reviewed_at_utc"], "reviewed_at_utc")
        if cls._dt(str(value["reviewed_at_utc"])) < cls._dt(str(value["assessed_at_utc"])):
            raise StateTransitionError("RC review cannot predate the assessment")

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

        for field in _EXTERNAL_FIELDS:
            status = cls._text(value[field], field)
            if status not in _EXTERNAL_STATUSES:
                raise ValidationError(f"{field} is outside the closed status set")
            value[field] = status
        value["evidence_manifest"] = cls._parse_evidence_manifest(value["evidence_manifest"])
        value["benchmarks"] = cls._parse_benchmarks(value["benchmarks"])
        value["red_team_cases"] = cls._parse_red_team_cases(value["red_team_cases"])
        value["release_gates"] = cls._parse_gates(value["release_gates"])
        return value

    @classmethod
    def _parse_ordered_members(
        cls,
        raw: object,
        label: str,
        fields: frozenset[str],
        identifier_field: str,
        normalizer: Any,
    ) -> list[dict[str, object]]:
        if not isinstance(raw, list) or not raw:
            raise ValidationError(f"{label} must be a non-empty list")
        normalized: list[dict[str, object]] = []
        identifiers: list[str] = []
        for ordinal, entry in enumerate(raw):
            if not isinstance(entry, dict) or frozenset(entry) != fields:
                raise ValidationError(f"{label}[{ordinal}] fields do not match the contract")
            item = normalizer(dict(entry), f"{label}[{ordinal}]")
            identifiers.append(str(item[identifier_field]))
            normalized.append(item)
        if identifiers != sorted(identifiers) or len(set(identifiers)) != len(identifiers):
            raise ValidationError(f"{label} IDs must be sorted and unique")
        return normalized

    @classmethod
    def _normalize_evidence(
        cls, item: dict[str, object], prefix: str
    ) -> dict[str, object]:
        evidence_id = cls._text(item["evidence_id"], f"{prefix}.evidence_id")
        artifact_id = cls._text(item["artifact_id"], f"{prefix}.artifact_id")
        digest = cls._digest(item["digest"], f"{prefix}.digest")
        status = cls._text(item["status"], f"{prefix}.status")
        if status not in _EXTERNAL_STATUSES:
            raise ValidationError("evidence manifest status is outside the closed status set")
        return {
            "evidence_id": evidence_id,
            "artifact_id": artifact_id,
            "digest": digest,
            "status": status,
        }

    @classmethod
    def _normalize_benchmark(
        cls, item: dict[str, object], prefix: str
    ) -> dict[str, object]:
        benchmark_id = cls._text(item["benchmark_id"], f"{prefix}.benchmark_id")
        domain = cls._text(item["domain"], f"{prefix}.domain")
        metric = cls._text(item["metric"], f"{prefix}.metric")
        unit = cls._text(item["unit"], f"{prefix}.unit")
        threshold = cls._number(item["threshold"], f"{prefix}.threshold")
        observed = cls._number(item["observed"], f"{prefix}.observed")
        direction = cls._text(item["direction"], f"{prefix}.direction")
        if direction not in _DIRECTIONS:
            raise ValidationError("benchmark direction is outside the closed set")
        passed = item["pass"]
        if not isinstance(passed, bool):
            raise ValidationError(f"{prefix}.pass must be boolean")
        expected = observed >= threshold if direction == "MINIMUM" else observed <= threshold
        if passed != expected:
            raise ValidationError("benchmark pass is inconsistent with its numeric direction")
        evidence_digest = cls._digest(item["evidence_digest"], f"{prefix}.evidence_digest")
        return {
            "benchmark_id": benchmark_id,
            "domain": domain,
            "metric": metric,
            "unit": unit,
            "threshold": threshold,
            "observed": observed,
            "direction": direction,
            "pass": passed,
            "evidence_digest": evidence_digest,
        }

    @classmethod
    def _normalize_red_team(
        cls, item: dict[str, object], prefix: str
    ) -> dict[str, object]:
        case_id = cls._text(item["case_id"], f"{prefix}.case_id")
        category = cls._text(item["category"], f"{prefix}.category")
        severity = cls._text(item["severity"], f"{prefix}.severity")
        outcome = cls._text(item["outcome"], f"{prefix}.outcome")
        if outcome not in _OUTCOMES:
            raise ValidationError("red-team outcome is outside the closed set")
        evidence_digest = cls._digest(item["evidence_digest"], f"{prefix}.evidence_digest")
        return {
            "case_id": case_id,
            "category": category,
            "severity": severity,
            "outcome": outcome,
            "evidence_digest": evidence_digest,
        }

    @classmethod
    def _normalize_gate(cls, item: dict[str, object], prefix: str) -> dict[str, object]:
        gate_id = cls._text(item["gate_id"], f"{prefix}.gate_id")
        status = cls._text(item["status"], f"{prefix}.status")
        if status not in _OUTCOMES:
            raise ValidationError("release gate status is outside the closed set")
        evidence_digest = cls._digest(item["evidence_digest"], f"{prefix}.evidence_digest")
        return {"gate_id": gate_id, "status": status, "evidence_digest": evidence_digest}

    @classmethod
    def _parse_evidence_manifest(cls, raw: object) -> list[dict[str, object]]:
        normalized = cls._parse_ordered_members(
            raw, "evidence_manifest", _EVIDENCE_FIELDS, "evidence_id", cls._normalize_evidence
        )
        if tuple(item["evidence_id"] for item in normalized) != _REQUIRED_EVIDENCE_IDS:
            raise ValidationError("evidence manifest must contain exactly blocks 12A through 18")
        return normalized

    @classmethod
    def _parse_benchmarks(cls, raw: object) -> list[dict[str, object]]:
        return cls._parse_ordered_members(
            raw, "benchmarks", _BENCHMARK_FIELDS, "benchmark_id", cls._normalize_benchmark
        )

    @classmethod
    def _parse_red_team_cases(cls, raw: object) -> list[dict[str, object]]:
        return cls._parse_ordered_members(
            raw, "red_team_cases", _RED_TEAM_FIELDS, "case_id", cls._normalize_red_team
        )

    @classmethod
    def _parse_gates(cls, raw: object) -> list[dict[str, object]]:
        return cls._parse_ordered_members(
            raw, "release_gates", _GATE_FIELDS, "gate_id", cls._normalize_gate
        )

    @staticmethod
    def _external_material(value: Mapping[str, object]) -> dict[str, object]:
        return {field: value[field] for field in _EXTERNAL_FIELDS}

    @classmethod
    def _derive(cls, value: Mapping[str, object]) -> tuple[str, str, str]:
        evidence = value["evidence_manifest"]
        benchmarks = value["benchmarks"]
        red_team = value["red_team_cases"]
        gates = value["release_gates"]
        assert isinstance(evidence, list)
        assert isinstance(benchmarks, list)
        assert isinstance(red_team, list)
        assert isinstance(gates, list)
        internal_failure = (
            any(item["status"] != "PROVEN" for item in evidence)
            or any(not item["pass"] for item in benchmarks)
            or any(item["outcome"] != "PASS" for item in red_team)
            or any(item["status"] != "PASS" for item in gates)
        )
        if internal_failure:
            verdict = _VERDICT_VERIFICATION_FAILURE
        elif any(value[field] != "PROVEN" for field in _EXTERNAL_FIELDS):
            verdict = _VERDICT_EXTERNAL_EVIDENCE
        else:
            verdict = _VERDICT_READY
        return verdict, _RELEASE_STATUS, _GATE_EFFECT

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS block19_rc_assessments (
                    assessment_id TEXT PRIMARY KEY,
                    assessment_version TEXT NOT NULL UNIQUE,
                    evidence_manifest_digest TEXT NOT NULL CHECK (length(evidence_manifest_digest) = 64),
                    benchmarks_digest TEXT NOT NULL CHECK (length(benchmarks_digest) = 64),
                    red_team_digest TEXT NOT NULL CHECK (length(red_team_digest) = 64),
                    release_gates_digest TEXT NOT NULL CHECK (length(release_gates_digest) = 64),
                    external_statuses_digest TEXT NOT NULL CHECK (length(external_statuses_digest) = 64),
                    live_census_certification_status TEXT NOT NULL CHECK (live_census_certification_status IN ('PROVEN', 'NOT_PROVEN')),
                    external_runtime_integration_status TEXT NOT NULL CHECK (external_runtime_integration_status IN ('PROVEN', 'NOT_PROVEN')),
                    component_adoption_status TEXT NOT NULL CHECK (component_adoption_status IN ('PROVEN', 'NOT_PROVEN')),
                    real_deployment_status TEXT NOT NULL CHECK (real_deployment_status IN ('PROVEN', 'NOT_PROVEN')),
                    assessor_identity TEXT NOT NULL,
                    assessor_environment TEXT NOT NULL,
                    reviewer_identity TEXT NOT NULL,
                    reviewer_environment TEXT NOT NULL,
                    assessed_at_utc TEXT NOT NULL,
                    reviewed_at_utc TEXT NOT NULL,
                    independence_basis_json TEXT NOT NULL,
                    verdict TEXT NOT NULL CHECK (verdict IN ('RC_BLOCKED_VERIFICATION_FAILURE', 'RC_BLOCKED_EXTERNAL_EVIDENCE', 'RC_READY_FOR_INDEPENDENT_RELEASE_REVIEW')),
                    release_status TEXT NOT NULL CHECK (release_status = 'NOT_RELEASED'),
                    gate_effect TEXT NOT NULL CHECK (gate_effect = 'BLOCK19_RC_ASSESSMENT_ADMITTED_NOT_RELEASED'),
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
            for table, identifier, _ in _MEMBERSHIP_SPECS:
                artifact_column = ", artifact_id TEXT NOT NULL" if table == "block19_rc_evidence" else ""
                connection.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {table} (
                        assessment_id TEXT NOT NULL,
                        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                        {identifier} TEXT NOT NULL{artifact_column},
                        material_json TEXT NOT NULL,
                        material_sha256 TEXT NOT NULL CHECK (length(material_sha256) = 64),
                        recorded_at TEXT NOT NULL,
                        recorded_by TEXT NOT NULL,
                        member_ledger_hash TEXT NOT NULL CHECK (length(member_ledger_hash) = 64),
                        PRIMARY KEY (assessment_id, ordinal),
                        UNIQUE (assessment_id, {identifier}),
                        FOREIGN KEY (assessment_id) REFERENCES block19_rc_assessments(assessment_id)
                    )
                    """
                )
            for table in (
                "block19_rc_assessments",
                "block19_rc_evidence",
                "block19_rc_benchmarks",
                "block19_rc_red_team_cases",
                "block19_rc_gates",
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

    @classmethod
    def _record(cls, row: sqlite3.Row) -> ReleaseCandidateAssessment:
        try:
            independence = json.loads(str(row["independence_basis_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrityError("stored Block 19 independence basis is invalid") from exc
        if not isinstance(independence, dict):
            raise IntegrityError("stored Block 19 independence basis is invalid")
        return ReleaseCandidateAssessment(
            cls._text(row["assessment_id"], "assessment_id"),
            cls._text(row["assessment_version"], "assessment_version"),
            cls._digest(row["evidence_manifest_digest"], "evidence_manifest_digest"),
            cls._digest(row["benchmarks_digest"], "benchmarks_digest"),
            cls._digest(row["red_team_digest"], "red_team_digest"),
            cls._digest(row["release_gates_digest"], "release_gates_digest"),
            cls._digest(row["external_statuses_digest"], "external_statuses_digest"),
            cls._text(row["live_census_certification_status"], "live_census_certification_status"),
            cls._text(row["external_runtime_integration_status"], "external_runtime_integration_status"),
            cls._text(row["component_adoption_status"], "component_adoption_status"),
            cls._text(row["real_deployment_status"], "real_deployment_status"),
            cls._text(row["assessor_identity"], "assessor_identity"),
            cls._text(row["assessor_environment"], "assessor_environment"),
            cls._text(row["reviewer_identity"], "reviewer_identity"),
            cls._text(row["reviewer_environment"], "reviewer_environment"),
            cls._timestamp(row["assessed_at_utc"], "assessed_at_utc"),
            cls._timestamp(row["reviewed_at_utc"], "reviewed_at_utc"),
            independence,
            cls._text(row["verdict"], "verdict"),
            cls._text(row["release_status"], "release_status"),
            cls._text(row["gate_effect"], "gate_effect"),
            cls._text(row["key_id"], "key_id"),
            cls._blob(row, "payload"),
            cls._digest(row["payload_sha256"], "payload_sha256"),
            cls._blob(row, "signature"),
            cls._digest(row["signature_sha256"], "signature_sha256"),
            cls._timestamp(row["admitted_at"], "admitted_at"),
            cls._text(row["admitted_by"], "admitted_by"),
            cls._text(row["ledger_event_id"], "ledger_event_id"),
            cls._digest(row["ledger_hash"], "ledger_hash"),
        )

    @staticmethod
    def _stream(assessment_id: str) -> str:
        return f"continuity:block19:release-candidate:{assessment_id}"

    @staticmethod
    def _event_payload(record: ReleaseCandidateAssessment) -> dict[str, object]:
        return {
            "assessment_id": record.assessment_id,
            "assessment_version": record.assessment_version,
            "evidence_manifest_digest": record.evidence_manifest_digest,
            "benchmarks_digest": record.benchmarks_digest,
            "red_team_digest": record.red_team_digest,
            "release_gates_digest": record.release_gates_digest,
            "external_statuses_digest": record.external_statuses_digest,
            "live_census_certification_status": record.live_census_certification_status,
            "external_runtime_integration_status": record.external_runtime_integration_status,
            "component_adoption_status": record.component_adoption_status,
            "real_deployment_status": record.real_deployment_status,
            "assessor_identity": record.assessor_identity,
            "reviewer_identity": record.reviewer_identity,
            "assessed_at_utc": record.assessed_at_utc,
            "reviewed_at_utc": record.reviewed_at_utc,
            "independence_basis": dict(record.independence_basis),
            "verdict": record.verdict,
            "release_status": record.release_status,
            "gate_effect": record.gate_effect,
            "key_id": record.key_id,
            "payload_sha256": record.payload_sha256,
            "signature_sha256": record.signature_sha256,
        }

    def _assert_signature(self, key_id: str, payload: bytes, signature: bytes) -> None:
        trust_root = self.continuity.verify_trust_root(key_id)
        if not getattr(trust_root, "ok", False):
            raise IntegrityError(
                "Block 19 RC trust root verification failed",
                {"key_id": key_id, "defects": list(getattr(trust_root, "defects", ()))},
            )
        row = self.database.connection.execute(
            "SELECT public_key_pem FROM continuity_trust_roots WHERE key_id = ?",
            (key_id,),
        ).fetchone()
        if row is None or not self.signature_verifier.verify(
            bytes(row["public_key_pem"]), payload, signature
        ):
            raise IntegrityError("Block 19 RC signature is invalid")

    @classmethod
    def _assert_payload_binding(
        cls,
        value: Mapping[str, object],
        assessment_id: str,
        admitted_at: str,
        actor: str | None = None,
    ) -> None:
        if value["assessment_id"] != assessment_id:
            raise StateTransitionError("signed Block 19 RC assessment targets another identifier")
        if cls._dt(str(value["reviewed_at_utc"])) > cls._dt(admitted_at):
            raise StateTransitionError("RC admission predates the signed review")
        if value["assessor_identity"] == value["reviewer_identity"]:
            raise StateTransitionError("RC assessor and reviewer must be distinct")
        if actor is not None and actor in {
            value["assessor_identity"],
            value["reviewer_identity"],
        }:
            raise StateTransitionError("RC admission actor must be independent from assessor and reviewer")
        cls._derive(value)

    @staticmethod
    def _replay_matches(
        row: sqlite3.Row,
        assessment_id: str,
        assessment_version: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        actor: str,
    ) -> bool:
        return (
            str(row["assessment_id"]) == assessment_id
            and str(row["assessment_version"]) == assessment_version
            and str(row["key_id"]) == key_id
            and bytes(row["payload"]) == payload
            and bytes(row["signature"]) == signature
            and str(row["admitted_by"]) == actor
        )

    def prepare(
        self,
        assessment_id: str,
        assessment_version: str,
        payload: Mapping[str, object] | None = None,
    ) -> ReleaseCandidatePreparation:
        assessment_id = self._text(assessment_id, "assessment_id")
        assessment_version = self._text(assessment_version, "assessment_version")
        if payload is not None:
            if payload.get("assessment_id") != assessment_id:
                raise StateTransitionError("RC preparation targets another assessment")
            if payload.get("assessment_version") != assessment_version:
                raise StateTransitionError("RC preparation targets another version")
        resource = f"continuity:block19:release-candidate:{assessment_id}"
        context = {
            "assessment_id": assessment_id,
            "assessment_version": assessment_version,
            "gate_effect": _GATE_EFFECT,
        }
        return ReleaseCandidatePreparation(
            assessment_id,
            assessment_version,
            _ACTION,
            resource,
            "continuity",
            context,
            _GATE_EFFECT,
        )

    def get_assessment(self, assessment_id: str) -> ReleaseCandidateAssessment:
        assessment_id = self._text(assessment_id, "assessment_id")
        row = self.database.connection.execute(
            "SELECT * FROM block19_rc_assessments WHERE assessment_id = ?",
            (assessment_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "Block 19 RC assessment does not exist",
                {"assessment_id": assessment_id},
            )
        return self._record(row)

    get = get_assessment
    get_release_candidate = get_assessment

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
        values: list[Mapping[str, object]] = []
        for row in rows:
            try:
                material = json.loads(str(row["material_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise IntegrityError("stored Block 19 membership material is invalid") from exc
            if not isinstance(material, dict):
                raise IntegrityError("stored Block 19 membership material is invalid")
            values.append(material)
        return tuple(values)

    def get_evidence_manifest(self, assessment_id: str) -> tuple[Mapping[str, object], ...]:
        self.get_assessment(assessment_id)
        return self._read_members(self.database, assessment_id, "block19_rc_evidence")

    def get_benchmarks(self, assessment_id: str) -> tuple[Mapping[str, object], ...]:
        self.get_assessment(assessment_id)
        return self._read_members(self.database, assessment_id, "block19_rc_benchmarks")

    def get_red_team_cases(self, assessment_id: str) -> tuple[Mapping[str, object], ...]:
        self.get_assessment(assessment_id)
        return self._read_members(self.database, assessment_id, "block19_rc_red_team_cases")

    def get_release_gates(self, assessment_id: str) -> tuple[Mapping[str, object], ...]:
        self.get_assessment(assessment_id)
        return self._read_members(self.database, assessment_id, "block19_rc_gates")

    get_evidence = get_evidence_manifest
    get_red_team = get_red_team_cases
    get_gates = get_release_gates

    def _snapshot_for_record(
        self,
        record: ReleaseCandidateAssessment,
    ) -> ReleaseCandidateSnapshot:
        value = self._parse_payload(record.payload)
        verdict, release_status, gate_effect = self._derive(value)
        expected = {
            "assessment_id": str(value["assessment_id"]),
            "assessment_version": str(value["assessment_version"]),
            "evidence_manifest_digest": sha256_digest(value["evidence_manifest"]),
            "benchmarks_digest": sha256_digest(value["benchmarks"]),
            "red_team_digest": sha256_digest(value["red_team_cases"]),
            "release_gates_digest": sha256_digest(value["release_gates"]),
            "external_statuses_digest": sha256_digest(self._external_material(value)),
        }
        for field, observed in expected.items():
            if getattr(record, field) != observed:
                raise IntegrityError(f"stored Block 19 {field} does not match signed payload")
        for field in _EXTERNAL_FIELDS:
            if getattr(record, field) != value[field]:
                raise IntegrityError(f"stored Block 19 {field} does not match signed payload")
        if record.verdict != verdict:
            raise IntegrityError("stored Block 19 verdict is not derived from the signed payload")
        if record.release_status != release_status or record.gate_effect != gate_effect:
            raise IntegrityError("stored Block 19 release boundary is invalid")
        material_identities = tuple(
            sorted(
                {
                    str(value["assessor_identity"]),
                    str(value["reviewer_identity"]),
                    record.admitted_by,
                }
            )
        )
        return ReleaseCandidateSnapshot(
            record.assessment_id,
            record.assessment_version,
            record.payload_sha256,
            record.evidence_manifest_digest,
            record.benchmarks_digest,
            record.red_team_digest,
            record.release_gates_digest,
            record.external_statuses_digest,
            record.live_census_certification_status,
            record.external_runtime_integration_status,
            record.component_adoption_status,
            record.real_deployment_status,
            record.assessed_at_utc,
            record.reviewed_at_utc,
            record.reviewed_at_utc,
            material_identities,
            record.verdict,
            record.release_status,
            record.gate_effect,
        )

    def snapshot(self, assessment_id: str) -> ReleaseCandidateSnapshot:
        return self._snapshot_for_record(self.get_assessment(assessment_id))

    def _provisional(
        self,
        value: Mapping[str, object],
        key_id: str,
        payload: bytes,
        signature: bytes,
        admitted_at: str,
        actor: str,
    ) -> ReleaseCandidateAssessment:
        evidence = value["evidence_manifest"]
        benchmarks = value["benchmarks"]
        red_team = value["red_team_cases"]
        gates = value["release_gates"]
        assert isinstance(evidence, list)
        assert isinstance(benchmarks, list)
        assert isinstance(red_team, list)
        assert isinstance(gates, list)
        verdict, release_status, gate_effect = self._derive(value)
        return ReleaseCandidateAssessment(
            str(value["assessment_id"]),
            str(value["assessment_version"]),
            sha256_digest(evidence),
            sha256_digest(benchmarks),
            sha256_digest(red_team),
            sha256_digest(gates),
            sha256_digest(self._external_material(value)),
            str(value["live_census_certification_status"]),
            str(value["external_runtime_integration_status"]),
            str(value["component_adoption_status"]),
            str(value["real_deployment_status"]),
            str(value["assessor_identity"]),
            str(value["assessor_environment"]),
            str(value["reviewer_identity"]),
            str(value["reviewer_environment"]),
            str(value["assessed_at_utc"]),
            str(value["reviewed_at_utc"]),
            dict(value["independence_basis"]),
            verdict,
            release_status,
            gate_effect,
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
        assessment_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        *,
        actor: str,
        occurred_at: str | None = None,
    ) -> ReleaseCandidateAssessment:
        assessment_id = self._text(assessment_id, "assessment_id")
        key_id = self._text(key_id, "key_id")
        actor = self._text(actor, "actor")
        payload = self._bounded_payload(payload)
        signature = self._bounded_signature(signature)
        admitted_at = self._timestamp(occurred_at or utc_now(), "admitted_at")
        value = self._parse_payload(payload)
        self._assert_payload_binding(value, assessment_id, admitted_at, actor)
        assessment_version = str(value["assessment_version"])
        self._assert_signature(key_id, payload, signature)
        existing = self.database.connection.execute(
            "SELECT * FROM block19_rc_assessments "
            "WHERE assessment_id = ? OR assessment_version = ? OR payload_sha256 = ? "
            "ORDER BY assessment_id LIMIT 1",
            (assessment_id, assessment_version, hashlib.sha256(payload).hexdigest()),
        ).fetchone()
        if existing is not None:
            if self._replay_matches(
                existing,
                assessment_id,
                assessment_version,
                key_id,
                payload,
                signature,
                actor,
            ):
                record = self._record(existing)
                if not self.verify_assessment(assessment_id).ok:
                    raise IntegrityError("existing Block 19 RC assessment failed verification")
                return record
            raise ConflictError(
                "Block 19 RC assessment identifier or version already binds different material",
                {"assessment_id": assessment_id, "assessment_version": assessment_version},
            )

        provisional = self._provisional(value, key_id, payload, signature, admitted_at, actor)
        event_payload = self._event_payload(provisional)
        columns = (
            "assessment_id",
            "assessment_version",
            "evidence_manifest_digest",
            "benchmarks_digest",
            "red_team_digest",
            "release_gates_digest",
            "external_statuses_digest",
            "live_census_certification_status",
            "external_runtime_integration_status",
            "component_adoption_status",
            "real_deployment_status",
            "assessor_identity",
            "assessor_environment",
            "reviewer_identity",
            "reviewer_environment",
            "assessed_at_utc",
            "reviewed_at_utc",
            "independence_basis_json",
            "verdict",
            "release_status",
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
                race = connection.execute(
                    "SELECT assessment_id FROM block19_rc_assessments "
                    "WHERE assessment_id = ? OR assessment_version = ? OR payload_sha256 = ?",
                    (assessment_id, assessment_version, provisional.payload_sha256),
                ).fetchone()
                if race is not None:
                    raise ConflictError("Block 19 RC assessment appeared during admission")
                self._assert_signature(key_id, payload, signature)
                receipt = self.ledger.append_in_transaction(
                    connection,
                    self._stream(assessment_id),
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
                    f"INSERT INTO block19_rc_assessments ({','.join(columns)}) VALUES ({placeholders})",
                    tuple(values),
                )
                for table, identifier, collection in _MEMBERSHIP_SPECS:
                    members = value[collection]
                    assert isinstance(members, list)
                    for ordinal, material in enumerate(members):
                        assert isinstance(material, dict)
                        if table == "block19_rc_evidence":
                            identifier_columns = f"{identifier},artifact_id"
                            identifier_values: tuple[object, ...] = (
                                material[identifier],
                                material["artifact_id"],
                            )
                        else:
                            identifier_columns = identifier
                            identifier_values = (material[identifier],)
                        material_json = canonical_json(material)
                        connection.execute(
                            f"INSERT INTO {table} "
                            f"(assessment_id,ordinal,{identifier_columns},material_json,material_sha256,"
                            "recorded_at,recorded_by,member_ledger_hash) "
                            f"VALUES ({','.join('?' for _ in range(7 + len(identifier_values)))})",
                            (
                                assessment_id,
                                ordinal,
                                *identifier_values,
                                material_json,
                                sha256_digest(material),
                                admitted_at,
                                actor,
                                receipt.record_hash,
                            ),
                        )
        except sqlite3.IntegrityError as exc:
            race = self.database.connection.execute(
                "SELECT * FROM block19_rc_assessments "
                "WHERE assessment_id = ? OR assessment_version = ? OR payload_sha256 = ? "
                "ORDER BY assessment_id LIMIT 1",
                (assessment_id, assessment_version, provisional.payload_sha256),
            ).fetchone()
            if race is not None and self._replay_matches(
                race,
                assessment_id,
                assessment_version,
                key_id,
                payload,
                signature,
                actor,
            ):
                return self._record(race)
            raise ConflictError(
                "Block 19 RC assessment violates an immutable constraint",
                {"assessment_id": assessment_id, "assessment_version": assessment_version},
            ) from exc
        return self.get_assessment(assessment_id)

    admit = admit_assessment
    admit_rc_assessment = admit_assessment

    @classmethod
    def _verify_membership(
        cls,
        database: Any,
        record: ReleaseCandidateAssessment,
        expected: list[Mapping[str, object]],
        table: str,
        identifier_field: str,
        prefix: str,
        defects: list[str],
    ) -> None:
        rows = database.connection.execute(
            f"SELECT * FROM {table} WHERE assessment_id = ? ORDER BY ordinal",
            (record.assessment_id,),
        ).fetchall()
        actual: list[Mapping[str, object]] = []
        if len(rows) != len(expected):
            defects.append(f"{prefix}_COUNT_MISMATCH")
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
                defects.append(f"{prefix}_ID_MISMATCH:{ordinal}")
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

    def verify_assessment(self, assessment_id: str) -> ReleaseCandidateVerification:
        assessment_id = self._text(assessment_id, "assessment_id")
        row = self.database.connection.execute(
            "SELECT * FROM block19_rc_assessments WHERE assessment_id = ?",
            (assessment_id,),
        ).fetchone()
        if row is None:
            return ReleaseCandidateVerification(assessment_id, ("ASSESSMENT_NOT_FOUND",))
        try:
            record = self._record(row)
        except (IntegrityError, KeyError, TypeError, ValueError, ValidationError):
            return ReleaseCandidateVerification(assessment_id, ("ASSESSMENT_ROW_INVALID",))
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
        if parsed is not None:
            try:
                self._assert_payload_binding(parsed, record.assessment_id, record.admitted_at, record.admitted_by)
            except (IntegrityError, StateTransitionError, ValidationError, TypeError, ValueError):
                defects.append("ASSESSMENT_CHRONOLOGY_OR_INDEPENDENCE_INVALID")
            verdict, release_status, gate_effect = self._derive(parsed)
            expected_digest_fields = {
                "evidence_manifest_digest": sha256_digest(parsed["evidence_manifest"]),
                "benchmarks_digest": sha256_digest(parsed["benchmarks"]),
                "red_team_digest": sha256_digest(parsed["red_team_cases"]),
                "release_gates_digest": sha256_digest(parsed["release_gates"]),
                "external_statuses_digest": sha256_digest(self._external_material(parsed)),
            }
            for field, expected in expected_digest_fields.items():
                if getattr(record, field) != expected:
                    defects.append(f"ASSESSMENT_{field.upper()}_MISMATCH")
            for field in (
                "assessment_id",
                "assessment_version",
                "assessor_identity",
                "assessor_environment",
                "reviewer_identity",
                "reviewer_environment",
                "assessed_at_utc",
                "reviewed_at_utc",
            ):
                if getattr(record, field) != parsed[field]:
                    defects.append(f"ASSESSMENT_{field.upper()}_MISMATCH")
            if dict(record.independence_basis) != parsed["independence_basis"]:
                defects.append("ASSESSMENT_INDEPENDENCE_BASIS_MISMATCH")
            for field in _EXTERNAL_FIELDS:
                if getattr(record, field) != parsed[field]:
                    defects.append(f"ASSESSMENT_{field.upper()}_MISMATCH")
            if record.verdict != verdict:
                defects.append("ASSESSMENT_VERDICT_DERIVATION_MISMATCH")
            if record.release_status != release_status:
                defects.append("ASSESSMENT_RELEASE_STATUS_MISMATCH")
            if record.gate_effect != gate_effect:
                defects.append("ASSESSMENT_GATE_EFFECT_MISMATCH")
            for expected, table, identifier, prefix in (
                (parsed["evidence_manifest"], "block19_rc_evidence", "evidence_id", "ASSESSMENT_EVIDENCE"),
                (parsed["benchmarks"], "block19_rc_benchmarks", "benchmark_id", "ASSESSMENT_BENCHMARK"),
                (parsed["red_team_cases"], "block19_rc_red_team_cases", "case_id", "ASSESSMENT_RED_TEAM"),
                (parsed["release_gates"], "block19_rc_gates", "gate_id", "ASSESSMENT_GATE"),
            ):
                assert isinstance(expected, list)
                self._verify_membership(
                    self.database,
                    record,
                    expected,
                    table,
                    identifier,
                    prefix,
                    defects,
                )
        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (record.ledger_event_id,),
        ).fetchone()
        expected_event = self._event_payload(record)
        if event is None:
            defects.append("ASSESSMENT_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != self._stream(record.assessment_id):
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
            chain = self.ledger.verify(self._stream(record.assessment_id))
            defects.extend(
                f"ASSESSMENT_LEDGER_CHAIN:{getattr(defect, 'code', 'INVALID')}"
                for defect in getattr(chain, "defects", ())
            )
        except (IntegrityError, TypeError, ValueError, sqlite3.Error):
            defects.append("ASSESSMENT_LEDGER_CHAIN_INVALID")
        return ReleaseCandidateVerification(assessment_id, tuple(dict.fromkeys(defects)))

    verify = verify_assessment
    verify_rc_assessment = verify_assessment


ReleaseCandidate = ReleaseCandidateAssessment
ReleaseCandidateVerificationResult = ReleaseCandidateVerification
