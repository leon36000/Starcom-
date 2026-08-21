from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
import re
import sqlite3
from typing import Any, Mapping

from .canonical import canonical_json, sha256_digest, utc_now
from .continuity import ContinuityService
from .db import Database
from .errors import (
    AuthorizationError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    ValidationError,
)
from .ledger import EventLedger
from .trust import AuthorizationDecision, AuthorizationRequest, TrustPlane


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,190}$")
_MEDIA_TYPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*/[A-Za-z0-9][A-Za-z0-9.+-]*$")
_MAX_JSON_BYTES = 512 * 1024
_MAX_PUBLIC_KEY_BYTES = 8 * 1024
_MAX_LABELS = 64

_BUNDLE_ACTION = "deployment.bundle.seal"
_NODE_ACTION = "deployment.node.enroll"
_ASSIGNMENT_ACTION = "deployment.assignment.authorize"
_BUNDLE_STATUS = "DEPLOYMENT_BUNDLE_SEALED_NOT_DEPLOYED"
_NODE_STATUS = "NODE_ENROLLED_OFFLINE"
_ASSIGNMENT_STATUS = "DEPLOYMENT_AUTHORIZED_NOT_EXECUTED"

_BUNDLE_OPERATION = "DEPLOYMENT_BUNDLE_SEAL"
_NODE_OPERATION = "DEPLOYMENT_NODE_ENROLL"
_ASSIGNMENT_OPERATION = "DEPLOYMENT_ASSIGNMENT_AUTHORIZE"

_BUNDLE_FIELDS = frozenset(
    {
        "bundle_id",
        "version",
        "platform",
        "package_digest",
        "sbom",
        "configuration",
        "provenance",
        "artifacts",
        "minimum_resources",
        "gpu_required",
        "offline_capability",
        "safety_profile",
    }
)
_RESOURCE_FIELDS = frozenset({"cpu_cores", "memory_mb", "storage_mb"})
_GPU_REQUIREMENT_FIELDS = frozenset({"required", "model", "memory_mb"})
_GPU_CAPABILITY_FIELDS = frozenset({"available", "model", "memory_mb"})
_SAFETY_FIELDS = frozenset({"profile_id", "network_mode", "allow_privileged"})
_ARTIFACT_FIELDS = frozenset({"artifact_id", "digest", "media_type", "size_bytes"})
_NODE_CAPABILITY_FIELDS = frozenset({"cpu_cores", "memory_mb", "storage_mb", "gpu"})


class DeploymentPlatform(str, Enum):
    LINUX_SERVER = "LINUX_SERVER"
    WINDOWS_DESKTOP = "WINDOWS_DESKTOP"
    MACOS_DESKTOP = "MACOS_DESKTOP"
    ANDROID_MOBILE = "ANDROID_MOBILE"
    IOS_MOBILE = "IOS_MOBILE"
    EDGE_NODE = "EDGE_NODE"


class DeploymentBundleStatus(str, Enum):
    SEALED_NOT_DEPLOYED = _BUNDLE_STATUS


class DeploymentNodeStatus(str, Enum):
    ENROLLED_OFFLINE = _NODE_STATUS


class DeploymentAssignmentStatus(str, Enum):
    AUTHORIZED_NOT_EXECUTED = _ASSIGNMENT_STATUS


@dataclass(frozen=True)
class DeploymentArtifact:
    artifact_id: str
    digest: str
    media_type: str
    size_bytes: int

    def as_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "digest": self.digest,
            "media_type": self.media_type,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class DeploymentBundlePreparation:
    bundle_id: str
    version: str
    platform: DeploymentPlatform
    package_digest: str
    sbom: Mapping[str, Any]
    configuration: Mapping[str, Any]
    provenance: Mapping[str, Any]
    artifacts: tuple[DeploymentArtifact, ...]
    minimum_resources: Mapping[str, int]
    gpu_required: Mapping[str, Any]
    offline_capability: bool
    safety_profile: Mapping[str, Any]
    manifest_digest: str
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]


@dataclass(frozen=True)
class DeploymentBundleRecord:
    bundle_id: str
    version: str
    platform: DeploymentPlatform
    package_digest: str
    sbom: Mapping[str, Any]
    configuration: Mapping[str, Any]
    provenance: Mapping[str, Any]
    artifacts: tuple[DeploymentArtifact, ...]
    minimum_resources: Mapping[str, int]
    gpu_required: Mapping[str, Any]
    offline_capability: bool
    safety_profile: Mapping[str, Any]
    manifest_digest: str
    status: DeploymentBundleStatus
    sealed_at: str
    sealed_by: str
    authorization_decision_id: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class DeploymentNodePreparation:
    node_id: str
    platform: DeploymentPlatform
    public_key_pem: bytes
    public_key_fingerprint_sha256: str
    capabilities: Mapping[str, Any]
    offline_mode: bool
    attestation_digest: str
    labels: tuple[str, ...]
    node_digest: str
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]


@dataclass(frozen=True)
class DeploymentNodeRecord:
    node_id: str
    platform: DeploymentPlatform
    public_key_pem: bytes
    public_key_fingerprint_sha256: str
    capabilities: Mapping[str, Any]
    offline_mode: bool
    attestation_digest: str
    labels: tuple[str, ...]
    node_digest: str
    status: DeploymentNodeStatus
    enrolled_at: str
    enrolled_by: str
    authorization_decision_id: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class DeploymentAssignmentPreparation:
    assignment_id: str
    bundle_id: str
    node_id: str
    bundle_manifest_digest: str
    node_public_key_fingerprint_sha256: str
    compatibility_digest: str
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]


@dataclass(frozen=True)
class DeploymentAssignmentRecord:
    assignment_id: str
    bundle_id: str
    node_id: str
    bundle_manifest_digest: str
    node_public_key_fingerprint_sha256: str
    compatibility_digest: str
    status: DeploymentAssignmentStatus
    authorized_at: str
    authorized_by: str
    authorization_decision_id: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class DeploymentVerification:
    entity_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


def _required_text(value: object, field: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be a non-empty string")
    if len(value) > maximum:
        raise ValidationError(f"{field} is too long")
    return value


def _required_id(value: object, field: str) -> str:
    result = _required_text(value, field, maximum=191)
    if _ID.fullmatch(result) is None:
        raise ValidationError(f"{field} has an invalid identifier")
    return result


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _positive_int(value: object, field: str, *, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValidationError(f"{field} must be an integer >= {minimum}")
    return value


def _strict_bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationError(f"{field} must be boolean")
    return value


def _object(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{field} must be an object")
    result = dict(value)
    try:
        encoded = canonical_json(result).encode("utf-8")
    except ValidationError:
        raise
    if len(encoded) > _MAX_JSON_BYTES:
        raise ValidationError(f"{field} exceeds the size limit")
    return result


def _closed_object(value: object, field: str, fields: frozenset[str]) -> dict[str, Any]:
    result = _object(value, field)
    observed = frozenset(result)
    if observed != fields:
        raise ValidationError(
            f"{field} fields do not match the closed contract",
            {
                "missing": sorted(fields - observed),
                "unexpected": sorted(observed - fields),
            },
        )
    return result


def _platform(value: object) -> DeploymentPlatform:
    try:
        return value if isinstance(value, DeploymentPlatform) else DeploymentPlatform(str(value))
    except ValueError as exc:
        raise ValidationError("platform is not a supported deployment platform") from exc


def _sorted_labels(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > _MAX_LABELS:
        raise ValidationError("labels must be a bounded list")
    result = tuple(_required_text(item, "label", maximum=64) for item in value)
    if tuple(sorted(result)) != result or len(set(result)) != len(result):
        raise ValidationError("labels must be sorted and duplicate-free")
    return result


def _artifacts(value: object) -> tuple[DeploymentArtifact, ...]:
    if not isinstance(value, list) or not value:
        raise ValidationError("artifacts must be a non-empty list")
    result: list[DeploymentArtifact] = []
    for item in value:
        material = _closed_object(item, "artifact", _ARTIFACT_FIELDS)
        result.append(
            DeploymentArtifact(
                artifact_id=_required_id(material["artifact_id"], "artifact_id"),
                digest=_digest(material["digest"], "artifact digest"),
                media_type=_media_type(material["media_type"]),
                size_bytes=_positive_int(material["size_bytes"], "artifact size_bytes"),
            )
        )
    if tuple(item.artifact_id for item in result) != tuple(
        sorted(item.artifact_id for item in result)
    ) or len({item.artifact_id for item in result}) != len(result):
        raise ValidationError("artifacts must be sorted by unique artifact_id")
    return tuple(result)


def _media_type(value: object, field: str = "media_type") -> str:
    result = _required_text(value, field, maximum=128)
    if _MEDIA_TYPE.fullmatch(result) is None:
        raise ValidationError(f"{field} must be a valid media type")
    return result


def _resources(value: object, field: str) -> dict[str, int]:
    result = _closed_object(value, field, _RESOURCE_FIELDS)
    return {
        "cpu_cores": _positive_int(result["cpu_cores"], f"{field}.cpu_cores"),
        "memory_mb": _positive_int(result["memory_mb"], f"{field}.memory_mb"),
        "storage_mb": _positive_int(result["storage_mb"], f"{field}.storage_mb"),
    }


def _gpu_requirement(value: object) -> dict[str, Any]:
    result = _closed_object(value, "gpu_required", _GPU_REQUIREMENT_FIELDS)
    required = _strict_bool(result["required"], "gpu_required.required")
    model = result["model"]
    if model is not None:
        model = _required_text(model, "gpu_required.model", maximum=128)
    memory_mb = result["memory_mb"]
    if required:
        memory_mb = _positive_int(memory_mb, "gpu_required.memory_mb")
    elif memory_mb != 0 or model is not None:
        raise ValidationError("optional GPU requirements must have null model and zero memory")
    return {"required": required, "model": model, "memory_mb": memory_mb}


def _gpu_capability(value: object) -> dict[str, Any]:
    result = _closed_object(value, "capabilities.gpu", _GPU_CAPABILITY_FIELDS)
    available = _strict_bool(result["available"], "capabilities.gpu.available")
    model = result["model"]
    if model is not None:
        model = _required_text(model, "capabilities.gpu.model", maximum=128)
    memory_mb = result["memory_mb"]
    if available:
        memory_mb = _positive_int(memory_mb, "capabilities.gpu.memory_mb")
    elif memory_mb != 0 or model is not None:
        raise ValidationError("unavailable GPU capability must have null model and zero memory")
    return {"available": available, "model": model, "memory_mb": memory_mb}


def _capabilities(value: object) -> dict[str, Any]:
    result = _closed_object(value, "capabilities", _NODE_CAPABILITY_FIELDS)
    return {
        "cpu_cores": _positive_int(result["cpu_cores"], "capabilities.cpu_cores"),
        "memory_mb": _positive_int(result["memory_mb"], "capabilities.memory_mb"),
        "storage_mb": _positive_int(result["storage_mb"], "capabilities.storage_mb"),
        "gpu": _gpu_capability(result["gpu"]),
    }


def _safety_profile(value: object) -> dict[str, Any]:
    result = _closed_object(value, "safety_profile", _SAFETY_FIELDS)
    profile_id = _required_id(result["profile_id"], "safety_profile.profile_id")
    network_mode = _required_text(result["network_mode"], "safety_profile.network_mode")
    if network_mode not in {"NONE", "LOCAL_ONLY"}:
        raise ValidationError("safety_profile.network_mode is not supported")
    return {
        "profile_id": profile_id,
        "network_mode": network_mode,
        "allow_privileged": _strict_bool(
            result["allow_privileged"], "safety_profile.allow_privileged"
        ),
    }


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


def _decode_object(value: str, field: str) -> dict[str, Any]:
    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"stored {field} is not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise IntegrityError(f"stored {field} is not an object")
    return decoded


class DeploymentFabricService:
    """Seal bundles, enroll offline nodes, and authorize compatible assignments."""

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
        self.signature_verifier = continuity.signature_verifier
        self._initialize_schema()

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS deployment_bundles (
                    bundle_id TEXT PRIMARY KEY,
                    version TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    package_digest TEXT NOT NULL CHECK (length(package_digest) = 64),
                    sbom_json TEXT NOT NULL,
                    configuration_json TEXT NOT NULL,
                    provenance_json TEXT NOT NULL,
                    artifacts_json TEXT NOT NULL,
                    minimum_resources_json TEXT NOT NULL,
                    gpu_required_json TEXT NOT NULL,
                    offline_capability INTEGER NOT NULL CHECK (offline_capability IN (0, 1)),
                    safety_profile_json TEXT NOT NULL,
                    manifest_digest TEXT NOT NULL UNIQUE CHECK (length(manifest_digest) = 64),
                    status TEXT NOT NULL CHECK (status = 'DEPLOYMENT_BUNDLE_SEALED_NOT_DEPLOYED'),
                    sealed_at TEXT NOT NULL,
                    sealed_by TEXT NOT NULL,
                    authorization_decision_id TEXT NOT NULL UNIQUE,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (authorization_decision_id) REFERENCES trust_decisions(decision_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS deployment_nodes (
                    node_id TEXT PRIMARY KEY,
                    platform TEXT NOT NULL,
                    public_key_pem BLOB NOT NULL,
                    public_key_fingerprint_sha256 TEXT NOT NULL UNIQUE CHECK (length(public_key_fingerprint_sha256) = 64),
                    capabilities_json TEXT NOT NULL,
                    offline_mode INTEGER NOT NULL CHECK (offline_mode IN (0, 1)),
                    attestation_digest TEXT NOT NULL CHECK (length(attestation_digest) = 64),
                    labels_json TEXT NOT NULL,
                    node_digest TEXT NOT NULL UNIQUE CHECK (length(node_digest) = 64),
                    status TEXT NOT NULL CHECK (status = 'NODE_ENROLLED_OFFLINE'),
                    enrolled_at TEXT NOT NULL,
                    enrolled_by TEXT NOT NULL,
                    authorization_decision_id TEXT NOT NULL UNIQUE,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (authorization_decision_id) REFERENCES trust_decisions(decision_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS deployment_assignments (
                    assignment_id TEXT PRIMARY KEY,
                    bundle_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    bundle_manifest_digest TEXT NOT NULL CHECK (length(bundle_manifest_digest) = 64),
                    node_public_key_fingerprint_sha256 TEXT NOT NULL CHECK (length(node_public_key_fingerprint_sha256) = 64),
                    compatibility_digest TEXT NOT NULL CHECK (length(compatibility_digest) = 64),
                    status TEXT NOT NULL CHECK (status = 'DEPLOYMENT_AUTHORIZED_NOT_EXECUTED'),
                    authorized_at TEXT NOT NULL,
                    authorized_by TEXT NOT NULL,
                    authorization_decision_id TEXT NOT NULL UNIQUE,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (bundle_id) REFERENCES deployment_bundles(bundle_id),
                    FOREIGN KEY (node_id) REFERENCES deployment_nodes(node_id),
                    FOREIGN KEY (authorization_decision_id) REFERENCES trust_decisions(decision_id)
                )
                """
            )
            for table in (
                "deployment_bundles",
                "deployment_nodes",
                "deployment_assignments",
            ):
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {table}_no_update
                    BEFORE UPDATE ON {table}
                    BEGIN SELECT RAISE(ABORT, '{table} rows are immutable'); END
                    """
                )
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {table}_no_delete
                    BEFORE DELETE ON {table}
                    BEGIN SELECT RAISE(ABORT, '{table} rows are immutable'); END
                    """
                )

    @staticmethod
    def _bundle_stream(bundle_id: str) -> str:
        return f"deployment:bundle:{bundle_id}"

    @staticmethod
    def _node_stream(node_id: str) -> str:
        return f"deployment:node:{node_id}"

    @staticmethod
    def _assignment_stream(assignment_id: str) -> str:
        return f"deployment:assignment:{assignment_id}"

    @staticmethod
    def _bundle_resource(bundle_id: str) -> str:
        return f"deployment:bundle:{bundle_id}"

    @staticmethod
    def _node_resource(node_id: str) -> str:
        return f"deployment:node:{node_id}"

    @staticmethod
    def _assignment_resource(assignment_id: str) -> str:
        return f"deployment:assignment:{assignment_id}"

    @staticmethod
    def _bundle_material(preparation: DeploymentBundlePreparation) -> dict[str, Any]:
        return {
            "bundle_id": preparation.bundle_id,
            "version": preparation.version,
            "platform": preparation.platform.value,
            "package_digest": preparation.package_digest,
            "sbom": dict(preparation.sbom),
            "configuration": dict(preparation.configuration),
            "provenance": dict(preparation.provenance),
            "artifacts": [item.as_dict() for item in preparation.artifacts],
            "minimum_resources": dict(preparation.minimum_resources),
            "gpu_required": dict(preparation.gpu_required),
            "offline_capability": preparation.offline_capability,
            "safety_profile": dict(preparation.safety_profile),
        }

    @staticmethod
    def _node_material(preparation: DeploymentNodePreparation) -> dict[str, Any]:
        return {
            "node_id": preparation.node_id,
            "platform": preparation.platform.value,
            "public_key_fingerprint_sha256": preparation.public_key_fingerprint_sha256,
            "capabilities": dict(preparation.capabilities),
            "offline_mode": preparation.offline_mode,
            "attestation_digest": preparation.attestation_digest,
            "labels": list(preparation.labels),
        }

    @staticmethod
    def _assignment_material(preparation: DeploymentAssignmentPreparation) -> dict[str, Any]:
        return {
            "assignment_id": preparation.assignment_id,
            "bundle_id": preparation.bundle_id,
            "node_id": preparation.node_id,
            "bundle_manifest_digest": preparation.bundle_manifest_digest,
            "node_public_key_fingerprint_sha256": preparation.node_public_key_fingerprint_sha256,
            "compatibility_digest": preparation.compatibility_digest,
        }

    @staticmethod
    def _compatibility_material(
        bundle: DeploymentBundleRecord,
        node: DeploymentNodeRecord,
    ) -> dict[str, Any]:
        return {
            "bundle_manifest_digest": bundle.manifest_digest,
            "bundle_platform": bundle.platform.value,
            "minimum_resources": dict(bundle.minimum_resources),
            "gpu_required": dict(bundle.gpu_required),
            "offline_capability": bundle.offline_capability,
            "node_digest": node.node_digest,
            "node_platform": node.platform.value,
            "capabilities": dict(node.capabilities),
            "offline_mode": node.offline_mode,
        }

    @classmethod
    def _compatibility_digest(
        cls,
        bundle: DeploymentBundleRecord,
        node: DeploymentNodeRecord,
    ) -> str:
        return sha256_digest(cls._compatibility_material(bundle, node))

    @staticmethod
    def _compatibility_defects(
        bundle: DeploymentBundleRecord,
        node: DeploymentNodeRecord,
    ) -> tuple[str, ...]:
        defects: list[str] = []
        if bundle.platform is not node.platform:
            defects.append("ASSIGNMENT_PLATFORM_MISMATCH")
        for field in ("cpu_cores", "memory_mb", "storage_mb"):
            if int(node.capabilities[field]) < int(bundle.minimum_resources[field]):
                defects.append(f"ASSIGNMENT_{field.upper()}_INSUFFICIENT")
        requirement = bundle.gpu_required
        gpu = node.capabilities["gpu"]
        if bool(requirement["required"]):
            if not bool(gpu["available"]):
                defects.append("ASSIGNMENT_GPU_MISSING")
            elif requirement["model"] is not None and gpu["model"] != requirement["model"]:
                defects.append("ASSIGNMENT_GPU_MODEL_MISMATCH")
            if int(gpu["memory_mb"]) < int(requirement["memory_mb"]):
                defects.append("ASSIGNMENT_GPU_MEMORY_INSUFFICIENT")
        if bundle.offline_capability and not node.offline_mode:
            defects.append("ASSIGNMENT_OFFLINE_CAPABILITY_MISSING")
        return tuple(defects)

    def _expected_request(
        self,
        preparation: DeploymentBundlePreparation | DeploymentNodePreparation | DeploymentAssignmentPreparation,
        actor: str,
    ) -> AuthorizationRequest:
        return AuthorizationRequest(
            subject=actor,
            action=preparation.action,
            resource=preparation.resource,
            mission_id=preparation.mission_id,
            context=dict(preparation.context),
        )

    def _verified_decision(
        self,
        preparation: DeploymentBundlePreparation | DeploymentNodePreparation | DeploymentAssignmentPreparation,
        decision_id: str,
        actor: str,
    ) -> AuthorizationDecision:
        decision_id = _required_text(decision_id, "authorization_decision_id")
        actor = _required_id(actor, "actor")
        try:
            decision = self.trust.get_decision(decision_id)
        except NotFoundError as exc:
            raise AuthorizationError("authorization decision does not exist") from exc
        verification = self.trust.verify_decision(decision_id)
        if not verification.ok:
            raise IntegrityError(
                "authorization decision is not independently verifiable",
                {"decision_id": decision_id, "defects": list(verification.defects)},
            )
        if not decision.allowed:
            raise AuthorizationError(
                "deployment operation is denied by TrustPlane",
                {"decision_id": decision_id, "reason": decision.reason},
            )
        if decision.request != self._expected_request(preparation, actor):
            raise AuthorizationError(
                "authorization decision does not match the exact deployment context",
                {"decision_id": decision_id},
            )
        return decision

    @staticmethod
    def _existing_consumption(
        connection: sqlite3.Connection,
        decision_id: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM continuity_authorization_consumptions WHERE decision_id = ?",
            (decision_id,),
        ).fetchone()

    @staticmethod
    def _ensure_unused_or_same(
        connection: sqlite3.Connection,
        *,
        decision_id: str,
        operation_kind: str,
        operation_id: str,
    ) -> None:
        row = DeploymentFabricService._existing_consumption(connection, decision_id)
        if row is None:
            return
        observed = (str(row["operation_kind"]), str(row["operation_id"]))
        expected = (operation_kind, operation_id)
        if observed != expected:
            raise ConflictError(
                "authorization decision was already consumed by another deployment operation",
                {"decision_id": decision_id, "observed": list(observed)},
            )
        raise IntegrityError(
            "authorization consumption exists without its immutable deployment record",
            {"decision_id": decision_id, "operation_id": operation_id},
        )

    @staticmethod
    def _bundle_manifest(preparation: DeploymentBundlePreparation) -> dict[str, Any]:
        return DeploymentFabricService._bundle_material(preparation)

    def prepare_bundle(
        self,
        *,
        bundle_id: str,
        version: str,
        platform: DeploymentPlatform | str,
        package_digest: str,
        sbom: Mapping[str, Any],
        configuration: Mapping[str, Any],
        provenance: Mapping[str, Any],
        artifacts: list[Mapping[str, Any]],
        minimum_resources: Mapping[str, Any],
        gpu_required: Mapping[str, Any],
        offline_capability: bool,
        safety_profile: Mapping[str, Any],
    ) -> DeploymentBundlePreparation:
        bundle_id = _required_id(bundle_id, "bundle_id")
        version = _required_text(version, "version", maximum=128)
        selected_platform = _platform(platform)
        package_digest = _digest(package_digest, "package_digest")
        selected_sbom = _object(sbom, "sbom")
        selected_configuration = _object(configuration, "configuration")
        selected_provenance = _object(provenance, "provenance")
        selected_artifacts = _artifacts(artifacts)
        selected_resources = _resources(minimum_resources, "minimum_resources")
        selected_gpu = _gpu_requirement(gpu_required)
        offline_capability = _strict_bool(offline_capability, "offline_capability")
        selected_safety = _safety_profile(safety_profile)
        material = {
            "bundle_id": bundle_id,
            "version": version,
            "platform": selected_platform.value,
            "package_digest": package_digest,
            "sbom": selected_sbom,
            "configuration": selected_configuration,
            "provenance": selected_provenance,
            "artifacts": [item.as_dict() for item in selected_artifacts],
            "minimum_resources": selected_resources,
            "gpu_required": selected_gpu,
            "offline_capability": offline_capability,
            "safety_profile": selected_safety,
        }
        manifest_digest = sha256_digest(material)
        context = {
            "bundle_id": bundle_id,
            "manifest_digest": manifest_digest,
            "package_digest": package_digest,
            "platform": selected_platform.value,
        }
        return DeploymentBundlePreparation(
            bundle_id=bundle_id,
            version=version,
            platform=selected_platform,
            package_digest=package_digest,
            sbom=selected_sbom,
            configuration=selected_configuration,
            provenance=selected_provenance,
            artifacts=selected_artifacts,
            minimum_resources=selected_resources,
            gpu_required=selected_gpu,
            offline_capability=offline_capability,
            safety_profile=selected_safety,
            manifest_digest=manifest_digest,
            action=_BUNDLE_ACTION,
            resource=self._bundle_resource(bundle_id),
            mission_id=f"deployment-bundle:{bundle_id}",
            context=context,
        )

    def _canonical_bundle(self, preparation: DeploymentBundlePreparation) -> DeploymentBundlePreparation:
        if not isinstance(preparation, DeploymentBundlePreparation):
            raise ValidationError("preparation must be a DeploymentBundlePreparation")
        try:
            canonical = self.prepare_bundle(
                bundle_id=preparation.bundle_id,
                version=preparation.version,
                platform=preparation.platform,
                package_digest=preparation.package_digest,
                sbom=preparation.sbom,
                configuration=preparation.configuration,
                provenance=preparation.provenance,
                artifacts=[item.as_dict() for item in preparation.artifacts],
                minimum_resources=preparation.minimum_resources,
                gpu_required=preparation.gpu_required,
                offline_capability=preparation.offline_capability,
                safety_profile=preparation.safety_profile,
            )
        except (TypeError, ValidationError) as exc:
            raise IntegrityError("bundle preparation is invalid") from exc
        if canonical != preparation:
            raise IntegrityError("bundle preparation is not canonical")
        return canonical

    def _row_to_bundle(self, row: sqlite3.Row) -> DeploymentBundleRecord:
        try:
            artifacts_value = json.loads(str(row["artifacts_json"]))
            artifacts = _artifacts(artifacts_value)
            platform = _platform(str(row["platform"]))
            sbom = _object(json.loads(str(row["sbom_json"])), "sbom")
            configuration = _object(json.loads(str(row["configuration_json"])), "configuration")
            provenance = _object(json.loads(str(row["provenance_json"])), "provenance")
            resources = _resources(json.loads(str(row["minimum_resources_json"])), "minimum_resources")
            gpu = _gpu_requirement(json.loads(str(row["gpu_required_json"])))
            safety = _safety_profile(json.loads(str(row["safety_profile_json"])))
            status = DeploymentBundleStatus(str(row["status"]))
        except (TypeError, ValueError, json.JSONDecodeError, ValidationError) as exc:
            raise IntegrityError("stored deployment bundle is malformed") from exc
        return DeploymentBundleRecord(
            bundle_id=str(row["bundle_id"]),
            version=str(row["version"]),
            platform=platform,
            package_digest=str(row["package_digest"]),
            sbom=sbom,
            configuration=configuration,
            provenance=provenance,
            artifacts=artifacts,
            minimum_resources=resources,
            gpu_required=gpu,
            offline_capability=bool(row["offline_capability"]),
            safety_profile=safety,
            manifest_digest=str(row["manifest_digest"]),
            status=status,
            sealed_at=str(row["sealed_at"]),
            sealed_by=str(row["sealed_by"]),
            authorization_decision_id=str(row["authorization_decision_id"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    @staticmethod
    def _record_bundle_material(record: DeploymentBundleRecord) -> dict[str, Any]:
        return {
            "bundle_id": record.bundle_id,
            "version": record.version,
            "platform": record.platform.value,
            "package_digest": record.package_digest,
            "sbom": dict(record.sbom),
            "configuration": dict(record.configuration),
            "provenance": dict(record.provenance),
            "artifacts": [item.as_dict() for item in record.artifacts],
            "minimum_resources": dict(record.minimum_resources),
            "gpu_required": dict(record.gpu_required),
            "offline_capability": record.offline_capability,
            "safety_profile": dict(record.safety_profile),
        }

    def seal_bundle(
        self,
        preparation: DeploymentBundlePreparation,
        *,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> DeploymentBundleRecord:
        preparation = self._canonical_bundle(preparation)
        actor = _required_id(actor, "actor")
        authorization_decision_id = _required_text(
            authorization_decision_id, "authorization_decision_id"
        )
        if self.database.connection.execute(
            "SELECT 1 FROM deployment_bundles WHERE bundle_id = ?",
            (preparation.bundle_id,),
        ).fetchone() is None:
            self._ensure_unused_or_same(
                self.database.connection,
                decision_id=authorization_decision_id,
                operation_kind=_BUNDLE_OPERATION,
                operation_id=preparation.bundle_id,
            )
        self._verified_decision(preparation, authorization_decision_id, actor)
        occurred_at = _timestamp(occurred_at or utc_now(), "occurred_at")
        material = self._bundle_material(preparation)
        with self.database.transaction() as connection:
            existing_row = connection.execute(
                "SELECT * FROM deployment_bundles WHERE bundle_id = ?",
                (preparation.bundle_id,),
            ).fetchone()
            if existing_row is not None:
                existing = self._row_to_bundle(existing_row)
                if (
                    self._record_bundle_material(existing) != material
                    or existing.authorization_decision_id != authorization_decision_id
                    or existing.sealed_by != actor
                ):
                    raise ConflictError(
                        "bundle replay changed immutable material",
                        {"bundle_id": preparation.bundle_id},
                    )
                verification = self.verify_bundle(preparation.bundle_id)
                if not verification.ok:
                    raise IntegrityError(
                        "bundle replay found corrupted immutable state",
                        {"bundle_id": preparation.bundle_id, "defects": list(verification.defects)},
                    )
                return existing
            self._ensure_unused_or_same(
                connection,
                decision_id=authorization_decision_id,
                operation_kind=_BUNDLE_OPERATION,
                operation_id=preparation.bundle_id,
            )
            payload = {
                "bundle_id": preparation.bundle_id,
                "manifest": material,
                "manifest_digest": preparation.manifest_digest,
                "status": _BUNDLE_STATUS,
                "authorization_decision_id": authorization_decision_id,
            }
            self.continuity._consume_authorization(
                connection,
                decision_id=authorization_decision_id,
                operation_kind=_BUNDLE_OPERATION,
                operation_id=preparation.bundle_id,
                actor=actor,
                occurred_at=occurred_at,
            )
            receipt = self.ledger.append_in_transaction(
                connection,
                self._bundle_stream(preparation.bundle_id),
                _BUNDLE_STATUS,
                payload,
                actor=actor,
                occurred_at=occurred_at,
            )
            try:
                connection.execute(
                    """
                    INSERT INTO deployment_bundles (
                        bundle_id, version, platform, package_digest,
                        sbom_json, configuration_json, provenance_json,
                        artifacts_json, minimum_resources_json, gpu_required_json,
                        offline_capability, safety_profile_json, manifest_digest,
                        status, sealed_at, sealed_by, authorization_decision_id,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        preparation.bundle_id,
                        preparation.version,
                        preparation.platform.value,
                        preparation.package_digest,
                        canonical_json(preparation.sbom),
                        canonical_json(preparation.configuration),
                        canonical_json(preparation.provenance),
                        canonical_json([item.as_dict() for item in preparation.artifacts]),
                        canonical_json(preparation.minimum_resources),
                        canonical_json(preparation.gpu_required),
                        int(preparation.offline_capability),
                        canonical_json(preparation.safety_profile),
                        preparation.manifest_digest,
                        _BUNDLE_STATUS,
                        occurred_at,
                        actor,
                        authorization_decision_id,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("bundle already exists", {"bundle_id": preparation.bundle_id}) from exc
        return self.get_bundle(preparation.bundle_id)

    def get_bundle(self, bundle_id: str) -> DeploymentBundleRecord:
        bundle_id = _required_id(bundle_id, "bundle_id")
        row = self.database.connection.execute(
            "SELECT * FROM deployment_bundles WHERE bundle_id = ?", (bundle_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("deployment bundle does not exist", {"bundle_id": bundle_id})
        return self._row_to_bundle(row)

    def _bundle_verification_defects(self, record: DeploymentBundleRecord) -> list[str]:
        defects: list[str] = []
        material = self._record_bundle_material(record)
        recomputed = sha256_digest(material)
        if recomputed != record.manifest_digest:
            defects.append("BUNDLE_MANIFEST_DIGEST_MISMATCH")
        if record.package_digest != material["package_digest"]:
            defects.append("BUNDLE_PACKAGE_DIGEST_MISMATCH")
        if record.status is not DeploymentBundleStatus.SEALED_NOT_DEPLOYED:
            defects.append("BUNDLE_STATUS_INVALID")
        try:
            preparation = self.prepare_bundle(**material)
        except (TypeError, ValidationError):
            preparation = None
            defects.append("BUNDLE_FIELDS_INVALID")
        if preparation is not None and preparation.manifest_digest != record.manifest_digest:
            defects.append("BUNDLE_CANONICAL_MATERIAL_MISMATCH")
        decision_verification = self.trust.verify_decision(record.authorization_decision_id)
        defects.extend(f"BUNDLE_DECISION:{item}" for item in decision_verification.defects)
        try:
            decision = self.trust.get_decision(record.authorization_decision_id)
        except NotFoundError:
            decision = None
            defects.append("BUNDLE_DECISION_MISSING")
        if decision is not None and preparation is not None:
            if not decision.allowed or decision.request != self._expected_request(preparation, record.sealed_by):
                defects.append("BUNDLE_DECISION_REQUEST_MISMATCH")
        consumption = self.database.connection.execute(
            "SELECT * FROM continuity_authorization_consumptions WHERE decision_id = ?",
            (record.authorization_decision_id,),
        ).fetchone()
        if consumption is None:
            defects.append("BUNDLE_CONSUMPTION_MISSING")
        elif (
            str(consumption["operation_kind"]),
            str(consumption["operation_id"]),
            str(consumption["consumed_at"]),
            str(consumption["consumed_by"]),
        ) != (
            _BUNDLE_OPERATION,
            record.bundle_id,
            record.sealed_at,
            record.sealed_by,
        ):
            defects.append("BUNDLE_CONSUMPTION_MISMATCH")
        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?", (record.ledger_event_id,)
        ).fetchone()
        if event is None:
            defects.append("BUNDLE_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != self._bundle_stream(record.bundle_id):
                defects.append("BUNDLE_LEDGER_STREAM_MISMATCH")
            if str(event["kind"]) != _BUNDLE_STATUS:
                defects.append("BUNDLE_LEDGER_KIND_MISMATCH")
            if str(event["actor"]) != record.sealed_by:
                defects.append("BUNDLE_LEDGER_ACTOR_MISMATCH")
            if str(event["occurred_at"]) != record.sealed_at:
                defects.append("BUNDLE_LEDGER_TIME_MISMATCH")
            if str(event["record_hash"]) != record.ledger_hash:
                defects.append("BUNDLE_LEDGER_HASH_MISMATCH")
            try:
                event_payload = json.loads(str(event["payload_json"]))
            except json.JSONDecodeError:
                defects.append("BUNDLE_LEDGER_PAYLOAD_INVALID")
            else:
                expected_payload = {
                    "bundle_id": record.bundle_id,
                    "manifest": material,
                    "manifest_digest": record.manifest_digest,
                    "status": _BUNDLE_STATUS,
                    "authorization_decision_id": record.authorization_decision_id,
                }
                if event_payload != expected_payload:
                    defects.append("BUNDLE_LEDGER_PAYLOAD_MISMATCH")
                manifest_payload = event_payload.get("manifest")
                if isinstance(manifest_payload, dict) and manifest_payload.get(
                    "package_digest"
                ) != record.package_digest:
                    defects.append("BUNDLE_PACKAGE_DIGEST_MISMATCH")
        defects.extend(
            f"BUNDLE_LEDGER_CHAIN:{item.code}"
            for item in self.ledger.verify(self._bundle_stream(record.bundle_id)).defects
        )
        return defects

    def verify_bundle(self, bundle_id: str) -> DeploymentVerification:
        try:
            record = self.get_bundle(bundle_id)
        except NotFoundError:
            return DeploymentVerification(str(bundle_id), ("BUNDLE_NOT_FOUND",))
        try:
            defects = self._bundle_verification_defects(record)
        except (IntegrityError, ValidationError, TypeError, ValueError, json.JSONDecodeError):
            defects = ["BUNDLE_FIELDS_INVALID"]
        return DeploymentVerification(record.bundle_id, tuple(dict.fromkeys(defects)))

    def prepare_node(
        self,
        *,
        node_id: str,
        platform: DeploymentPlatform | str,
        public_key_pem: bytes,
        capabilities: Mapping[str, Any],
        offline_mode: bool,
        attestation_digest: str,
        labels: list[str],
    ) -> DeploymentNodePreparation:
        node_id = _required_id(node_id, "node_id")
        selected_platform = _platform(platform)
        if not isinstance(public_key_pem, bytes) or not public_key_pem or len(public_key_pem) > _MAX_PUBLIC_KEY_BYTES:
            raise ValidationError("public_key_pem must be bounded non-empty bytes")
        if not self.signature_verifier.validate_public_key(public_key_pem):
            raise ValidationError("public_key_pem must be a valid Ed25519 public key")
        fingerprint = hashlib.sha256(public_key_pem).hexdigest()
        selected_capabilities = _capabilities(capabilities)
        offline_mode = _strict_bool(offline_mode, "offline_mode")
        attestation_digest = _digest(attestation_digest, "attestation_digest")
        selected_labels = _sorted_labels(labels)
        material = {
            "node_id": node_id,
            "platform": selected_platform.value,
            "public_key_fingerprint_sha256": fingerprint,
            "capabilities": selected_capabilities,
            "offline_mode": offline_mode,
            "attestation_digest": attestation_digest,
            "labels": list(selected_labels),
        }
        node_digest = sha256_digest(material)
        context = {
            "node_id": node_id,
            "node_digest": node_digest,
            "public_key_fingerprint_sha256": fingerprint,
            "platform": selected_platform.value,
            "attestation_digest": attestation_digest,
        }
        return DeploymentNodePreparation(
            node_id=node_id,
            platform=selected_platform,
            public_key_pem=public_key_pem,
            public_key_fingerprint_sha256=fingerprint,
            capabilities=selected_capabilities,
            offline_mode=offline_mode,
            attestation_digest=attestation_digest,
            labels=selected_labels,
            node_digest=node_digest,
            action=_NODE_ACTION,
            resource=self._node_resource(node_id),
            mission_id=f"deployment-node:{node_id}",
            context=context,
        )

    def _canonical_node(self, preparation: DeploymentNodePreparation) -> DeploymentNodePreparation:
        if not isinstance(preparation, DeploymentNodePreparation):
            raise ValidationError("preparation must be a DeploymentNodePreparation")
        try:
            canonical = self.prepare_node(
                node_id=preparation.node_id,
                platform=preparation.platform,
                public_key_pem=preparation.public_key_pem,
                capabilities=preparation.capabilities,
                offline_mode=preparation.offline_mode,
                attestation_digest=preparation.attestation_digest,
                labels=list(preparation.labels),
            )
        except (TypeError, ValidationError) as exc:
            raise IntegrityError("node preparation is invalid") from exc
        if canonical != preparation:
            raise IntegrityError("node preparation is not canonical")
        return canonical

    def _row_to_node(self, row: sqlite3.Row) -> DeploymentNodeRecord:
        try:
            platform = _platform(str(row["platform"]))
            capabilities = _capabilities(json.loads(str(row["capabilities_json"])))
            labels = _sorted_labels(json.loads(str(row["labels_json"])))
            status = DeploymentNodeStatus(str(row["status"]))
        except (TypeError, ValueError, json.JSONDecodeError, ValidationError) as exc:
            raise IntegrityError("stored deployment node is malformed") from exc
        return DeploymentNodeRecord(
            node_id=str(row["node_id"]),
            platform=platform,
            public_key_pem=bytes(row["public_key_pem"]),
            public_key_fingerprint_sha256=str(row["public_key_fingerprint_sha256"]),
            capabilities=capabilities,
            offline_mode=bool(row["offline_mode"]),
            attestation_digest=str(row["attestation_digest"]),
            labels=labels,
            node_digest=str(row["node_digest"]),
            status=status,
            enrolled_at=str(row["enrolled_at"]),
            enrolled_by=str(row["enrolled_by"]),
            authorization_decision_id=str(row["authorization_decision_id"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    @staticmethod
    def _record_node_material(record: DeploymentNodeRecord) -> dict[str, Any]:
        return {
            "node_id": record.node_id,
            "platform": record.platform.value,
            "public_key_fingerprint_sha256": record.public_key_fingerprint_sha256,
            "capabilities": dict(record.capabilities),
            "offline_mode": record.offline_mode,
            "attestation_digest": record.attestation_digest,
            "labels": list(record.labels),
        }

    def enroll_node(
        self,
        preparation: DeploymentNodePreparation,
        *,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> DeploymentNodeRecord:
        preparation = self._canonical_node(preparation)
        actor = _required_id(actor, "actor")
        authorization_decision_id = _required_text(
            authorization_decision_id, "authorization_decision_id"
        )
        if self.database.connection.execute(
            "SELECT 1 FROM deployment_nodes WHERE node_id = ?",
            (preparation.node_id,),
        ).fetchone() is None:
            self._ensure_unused_or_same(
                self.database.connection,
                decision_id=authorization_decision_id,
                operation_kind=_NODE_OPERATION,
                operation_id=preparation.node_id,
            )
        self._verified_decision(preparation, authorization_decision_id, actor)
        occurred_at = _timestamp(occurred_at or utc_now(), "occurred_at")
        material = self._node_material(preparation)
        with self.database.transaction() as connection:
            existing_row = connection.execute(
                "SELECT * FROM deployment_nodes WHERE node_id = ?", (preparation.node_id,)
            ).fetchone()
            if existing_row is not None:
                existing = self._row_to_node(existing_row)
                if (
                    self._record_node_material(existing) != material
                    or existing.public_key_pem != preparation.public_key_pem
                    or existing.authorization_decision_id != authorization_decision_id
                    or existing.enrolled_by != actor
                ):
                    raise ConflictError(
                        "node replay changed immutable material",
                        {"node_id": preparation.node_id},
                    )
                verification = self.verify_node(preparation.node_id)
                if not verification.ok:
                    raise IntegrityError(
                        "node replay found corrupted immutable state",
                        {"node_id": preparation.node_id, "defects": list(verification.defects)},
                    )
                return existing
            self._ensure_unused_or_same(
                connection,
                decision_id=authorization_decision_id,
                operation_kind=_NODE_OPERATION,
                operation_id=preparation.node_id,
            )
            payload = {
                "node_id": preparation.node_id,
                "platform": preparation.platform.value,
                "public_key_fingerprint_sha256": preparation.public_key_fingerprint_sha256,
                "capabilities": dict(preparation.capabilities),
                "offline_mode": preparation.offline_mode,
                "attestation_digest": preparation.attestation_digest,
                "labels": list(preparation.labels),
                "node_digest": preparation.node_digest,
                "status": _NODE_STATUS,
                "authorization_decision_id": authorization_decision_id,
            }
            self.continuity._consume_authorization(
                connection,
                decision_id=authorization_decision_id,
                operation_kind=_NODE_OPERATION,
                operation_id=preparation.node_id,
                actor=actor,
                occurred_at=occurred_at,
            )
            receipt = self.ledger.append_in_transaction(
                connection,
                self._node_stream(preparation.node_id),
                _NODE_STATUS,
                payload,
                actor=actor,
                occurred_at=occurred_at,
            )
            try:
                connection.execute(
                    """
                    INSERT INTO deployment_nodes (
                        node_id, platform, public_key_pem,
                        public_key_fingerprint_sha256, capabilities_json,
                        offline_mode, attestation_digest, labels_json, node_digest,
                        status, enrolled_at, enrolled_by,
                        authorization_decision_id, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        preparation.node_id,
                        preparation.platform.value,
                        preparation.public_key_pem,
                        preparation.public_key_fingerprint_sha256,
                        canonical_json(preparation.capabilities),
                        int(preparation.offline_mode),
                        preparation.attestation_digest,
                        canonical_json(list(preparation.labels)),
                        preparation.node_digest,
                        _NODE_STATUS,
                        occurred_at,
                        actor,
                        authorization_decision_id,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("node already exists", {"node_id": preparation.node_id}) from exc
        return self.get_node(preparation.node_id)

    def get_node(self, node_id: str) -> DeploymentNodeRecord:
        node_id = _required_id(node_id, "node_id")
        row = self.database.connection.execute(
            "SELECT * FROM deployment_nodes WHERE node_id = ?", (node_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("deployment node does not exist", {"node_id": node_id})
        return self._row_to_node(row)

    def _node_verification_defects(self, record: DeploymentNodeRecord) -> list[str]:
        defects: list[str] = []
        material = self._record_node_material(record)
        if sha256_digest(material) != record.node_digest:
            defects.append("NODE_DIGEST_MISMATCH")
        if hashlib.sha256(record.public_key_pem).hexdigest() != record.public_key_fingerprint_sha256:
            defects.append("NODE_PUBLIC_KEY_FINGERPRINT_MISMATCH")
        if not self.signature_verifier.validate_public_key(record.public_key_pem):
            defects.append("NODE_PUBLIC_KEY_INVALID")
        if record.status is not DeploymentNodeStatus.ENROLLED_OFFLINE:
            defects.append("NODE_STATUS_INVALID")
        preparation: DeploymentNodePreparation | None
        try:
            preparation = self.prepare_node(
                node_id=record.node_id,
                platform=record.platform,
                public_key_pem=record.public_key_pem,
                capabilities=record.capabilities,
                offline_mode=record.offline_mode,
                attestation_digest=record.attestation_digest,
                labels=list(record.labels),
            )
        except (TypeError, ValidationError):
            preparation = None
            defects.append("NODE_FIELDS_INVALID")
        if preparation is not None and preparation.node_digest != record.node_digest:
            defects.append("NODE_CANONICAL_MATERIAL_MISMATCH")
        decision_verification = self.trust.verify_decision(record.authorization_decision_id)
        defects.extend(f"NODE_DECISION:{item}" for item in decision_verification.defects)
        try:
            decision = self.trust.get_decision(record.authorization_decision_id)
        except NotFoundError:
            decision = None
            defects.append("NODE_DECISION_MISSING")
        if decision is not None and preparation is not None:
            if not decision.allowed or decision.request != self._expected_request(preparation, record.enrolled_by):
                defects.append("NODE_DECISION_REQUEST_MISMATCH")
        consumption = self.database.connection.execute(
            "SELECT * FROM continuity_authorization_consumptions WHERE decision_id = ?",
            (record.authorization_decision_id,),
        ).fetchone()
        if consumption is None:
            defects.append("NODE_CONSUMPTION_MISSING")
        elif (
            str(consumption["operation_kind"]),
            str(consumption["operation_id"]),
            str(consumption["consumed_at"]),
            str(consumption["consumed_by"]),
        ) != (
            _NODE_OPERATION,
            record.node_id,
            record.enrolled_at,
            record.enrolled_by,
        ):
            defects.append("NODE_CONSUMPTION_MISMATCH")
        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?", (record.ledger_event_id,)
        ).fetchone()
        if event is None:
            defects.append("NODE_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != self._node_stream(record.node_id):
                defects.append("NODE_LEDGER_STREAM_MISMATCH")
            if str(event["kind"]) != _NODE_STATUS:
                defects.append("NODE_LEDGER_KIND_MISMATCH")
            if str(event["actor"]) != record.enrolled_by:
                defects.append("NODE_LEDGER_ACTOR_MISMATCH")
            if str(event["occurred_at"]) != record.enrolled_at:
                defects.append("NODE_LEDGER_TIME_MISMATCH")
            if str(event["record_hash"]) != record.ledger_hash:
                defects.append("NODE_LEDGER_HASH_MISMATCH")
            try:
                event_payload = json.loads(str(event["payload_json"]))
            except json.JSONDecodeError:
                defects.append("NODE_LEDGER_PAYLOAD_INVALID")
            else:
                expected_payload = {
                    "node_id": record.node_id,
                    "platform": record.platform.value,
                    "public_key_fingerprint_sha256": record.public_key_fingerprint_sha256,
                    "capabilities": dict(record.capabilities),
                    "offline_mode": record.offline_mode,
                    "attestation_digest": record.attestation_digest,
                    "labels": list(record.labels),
                    "node_digest": record.node_digest,
                    "status": _NODE_STATUS,
                    "authorization_decision_id": record.authorization_decision_id,
                }
                if event_payload != expected_payload:
                    defects.append("NODE_LEDGER_PAYLOAD_MISMATCH")
                if event_payload.get("public_key_fingerprint_sha256") != (
                    record.public_key_fingerprint_sha256
                ):
                    defects.append("NODE_PUBLIC_KEY_FINGERPRINT_MISMATCH")
        defects.extend(
            f"NODE_LEDGER_CHAIN:{item.code}"
            for item in self.ledger.verify(self._node_stream(record.node_id)).defects
        )
        return defects

    def verify_node(self, node_id: str) -> DeploymentVerification:
        try:
            record = self.get_node(node_id)
        except NotFoundError:
            return DeploymentVerification(str(node_id), ("NODE_NOT_FOUND",))
        try:
            defects = self._node_verification_defects(record)
        except (IntegrityError, ValidationError, TypeError, ValueError, json.JSONDecodeError):
            defects = ["NODE_FIELDS_INVALID"]
        return DeploymentVerification(record.node_id, tuple(dict.fromkeys(defects)))

    def prepare_assignment(
        self,
        assignment_id: str,
        bundle_id: str,
        node_id: str,
    ) -> DeploymentAssignmentPreparation:
        assignment_id = _required_id(assignment_id, "assignment_id")
        bundle = self.get_bundle(bundle_id)
        node = self.get_node(node_id)
        bundle_verification = self.verify_bundle(bundle.bundle_id)
        if not bundle_verification.ok:
            raise IntegrityError(
                "bundle verification failed before assignment",
                {"bundle_id": bundle.bundle_id, "defects": list(bundle_verification.defects)},
            )
        node_verification = self.verify_node(node.node_id)
        if not node_verification.ok:
            raise IntegrityError(
                "node verification failed before assignment",
                {"node_id": node.node_id, "defects": list(node_verification.defects)},
            )
        compatibility_defects = self._compatibility_defects(bundle, node)
        if compatibility_defects:
            raise IntegrityError(
                "bundle and node are incompatible",
                {"assignment_id": assignment_id, "defects": list(compatibility_defects)},
            )
        compatibility_digest = self._compatibility_digest(bundle, node)
        context = {
            "assignment_id": assignment_id,
            "bundle_id": bundle.bundle_id,
            "bundle_manifest_digest": bundle.manifest_digest,
            "node_id": node.node_id,
            "node_public_key_fingerprint_sha256": node.public_key_fingerprint_sha256,
            "compatibility_digest": compatibility_digest,
        }
        return DeploymentAssignmentPreparation(
            assignment_id=assignment_id,
            bundle_id=bundle.bundle_id,
            node_id=node.node_id,
            bundle_manifest_digest=bundle.manifest_digest,
            node_public_key_fingerprint_sha256=node.public_key_fingerprint_sha256,
            compatibility_digest=compatibility_digest,
            action=_ASSIGNMENT_ACTION,
            resource=self._assignment_resource(assignment_id),
            mission_id=f"deployment-assignment:{assignment_id}",
            context=context,
        )

    def _canonical_assignment(
        self,
        preparation: DeploymentAssignmentPreparation,
    ) -> DeploymentAssignmentPreparation:
        if not isinstance(preparation, DeploymentAssignmentPreparation):
            raise ValidationError("preparation must be a DeploymentAssignmentPreparation")
        try:
            canonical = self.prepare_assignment(
                preparation.assignment_id,
                preparation.bundle_id,
                preparation.node_id,
            )
        except (TypeError, ValidationError, NotFoundError, IntegrityError) as exc:
            raise IntegrityError("assignment preparation is invalid") from exc
        if canonical != preparation:
            raise IntegrityError("assignment preparation is not canonical")
        return canonical

    def _row_to_assignment(self, row: sqlite3.Row) -> DeploymentAssignmentRecord:
        try:
            status = DeploymentAssignmentStatus(str(row["status"]))
        except ValueError as exc:
            raise IntegrityError("stored deployment assignment has an invalid status") from exc
        return DeploymentAssignmentRecord(
            assignment_id=str(row["assignment_id"]),
            bundle_id=str(row["bundle_id"]),
            node_id=str(row["node_id"]),
            bundle_manifest_digest=str(row["bundle_manifest_digest"]),
            node_public_key_fingerprint_sha256=str(row["node_public_key_fingerprint_sha256"]),
            compatibility_digest=str(row["compatibility_digest"]),
            status=status,
            authorized_at=str(row["authorized_at"]),
            authorized_by=str(row["authorized_by"]),
            authorization_decision_id=str(row["authorization_decision_id"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def authorize_assignment(
        self,
        preparation: DeploymentAssignmentPreparation,
        *,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> DeploymentAssignmentRecord:
        preparation = self._canonical_assignment(preparation)
        actor = _required_id(actor, "actor")
        authorization_decision_id = _required_text(
            authorization_decision_id, "authorization_decision_id"
        )
        if self.database.connection.execute(
            "SELECT 1 FROM deployment_assignments WHERE assignment_id = ?",
            (preparation.assignment_id,),
        ).fetchone() is None:
            self._ensure_unused_or_same(
                self.database.connection,
                decision_id=authorization_decision_id,
                operation_kind=_ASSIGNMENT_OPERATION,
                operation_id=preparation.assignment_id,
            )
        self._verified_decision(preparation, authorization_decision_id, actor)
        occurred_at = _timestamp(occurred_at or utc_now(), "occurred_at")
        material = self._assignment_material(preparation)
        with self.database.transaction() as connection:
            existing_row = connection.execute(
                "SELECT * FROM deployment_assignments WHERE assignment_id = ?",
                (preparation.assignment_id,),
            ).fetchone()
            if existing_row is not None:
                existing = self._row_to_assignment(existing_row)
                if (
                    {
                        "assignment_id": existing.assignment_id,
                        "bundle_id": existing.bundle_id,
                        "node_id": existing.node_id,
                        "bundle_manifest_digest": existing.bundle_manifest_digest,
                        "node_public_key_fingerprint_sha256": existing.node_public_key_fingerprint_sha256,
                        "compatibility_digest": existing.compatibility_digest,
                    }
                    != material
                    or existing.authorization_decision_id != authorization_decision_id
                    or existing.authorized_by != actor
                ):
                    raise ConflictError(
                        "assignment replay changed immutable material",
                        {"assignment_id": preparation.assignment_id},
                    )
                verification = self.verify_assignment(preparation.assignment_id)
                if not verification.ok:
                    raise IntegrityError(
                        "assignment replay found corrupted immutable state",
                        {
                            "assignment_id": preparation.assignment_id,
                            "defects": list(verification.defects),
                        },
                    )
                return existing
            self._ensure_unused_or_same(
                connection,
                decision_id=authorization_decision_id,
                operation_kind=_ASSIGNMENT_OPERATION,
                operation_id=preparation.assignment_id,
            )
            payload = {
                **material,
                "status": _ASSIGNMENT_STATUS,
                "authorization_decision_id": authorization_decision_id,
            }
            self.continuity._consume_authorization(
                connection,
                decision_id=authorization_decision_id,
                operation_kind=_ASSIGNMENT_OPERATION,
                operation_id=preparation.assignment_id,
                actor=actor,
                occurred_at=occurred_at,
            )
            receipt = self.ledger.append_in_transaction(
                connection,
                self._assignment_stream(preparation.assignment_id),
                _ASSIGNMENT_STATUS,
                payload,
                actor=actor,
                occurred_at=occurred_at,
            )
            try:
                connection.execute(
                    """
                    INSERT INTO deployment_assignments (
                        assignment_id, bundle_id, node_id,
                        bundle_manifest_digest, node_public_key_fingerprint_sha256,
                        compatibility_digest, status, authorized_at, authorized_by,
                        authorization_decision_id, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        preparation.assignment_id,
                        preparation.bundle_id,
                        preparation.node_id,
                        preparation.bundle_manifest_digest,
                        preparation.node_public_key_fingerprint_sha256,
                        preparation.compatibility_digest,
                        _ASSIGNMENT_STATUS,
                        occurred_at,
                        actor,
                        authorization_decision_id,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError(
                    "assignment already exists",
                    {"assignment_id": preparation.assignment_id},
                ) from exc
        return self.get_assignment(preparation.assignment_id)

    def get_assignment(self, assignment_id: str) -> DeploymentAssignmentRecord:
        assignment_id = _required_id(assignment_id, "assignment_id")
        row = self.database.connection.execute(
            "SELECT * FROM deployment_assignments WHERE assignment_id = ?",
            (assignment_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "deployment assignment does not exist",
                {"assignment_id": assignment_id},
            )
        return self._row_to_assignment(row)

    def _assignment_verification_defects(self, record: DeploymentAssignmentRecord) -> list[str]:
        defects: list[str] = []
        try:
            bundle = self.get_bundle(record.bundle_id)
        except NotFoundError:
            bundle = None
            defects.append("ASSIGNMENT_BUNDLE_MISSING")
        try:
            node = self.get_node(record.node_id)
        except NotFoundError:
            node = None
            defects.append("ASSIGNMENT_NODE_MISSING")
        if bundle is not None:
            bundle_verification = self.verify_bundle(bundle.bundle_id)
            defects.extend(f"ASSIGNMENT_BUNDLE:{item}" for item in bundle_verification.defects)
            if record.bundle_manifest_digest != bundle.manifest_digest:
                defects.append("ASSIGNMENT_BUNDLE_DIGEST_MISMATCH")
        if node is not None:
            node_verification = self.verify_node(node.node_id)
            defects.extend(f"ASSIGNMENT_NODE:{item}" for item in node_verification.defects)
            if record.node_public_key_fingerprint_sha256 != node.public_key_fingerprint_sha256:
                defects.append("ASSIGNMENT_NODE_FINGERPRINT_MISMATCH")
        if bundle is not None and node is not None:
            defects.extend(self._compatibility_defects(bundle, node))
            recomputed_compatibility = self._compatibility_digest(bundle, node)
            if recomputed_compatibility != record.compatibility_digest:
                defects.append("ASSIGNMENT_COMPATIBILITY_DIGEST_MISMATCH")
            if bundle.platform is not node.platform:
                defects.append("ASSIGNMENT_PLATFORM_MISMATCH")
        if record.status is not DeploymentAssignmentStatus.AUTHORIZED_NOT_EXECUTED:
            defects.append("ASSIGNMENT_STATUS_INVALID")
        context = {
            "assignment_id": record.assignment_id,
            "bundle_id": record.bundle_id,
            "bundle_manifest_digest": record.bundle_manifest_digest,
            "node_id": record.node_id,
            "node_public_key_fingerprint_sha256": record.node_public_key_fingerprint_sha256,
            "compatibility_digest": record.compatibility_digest,
        }
        expected_request = AuthorizationRequest(
            subject=record.authorized_by,
            action=_ASSIGNMENT_ACTION,
            resource=self._assignment_resource(record.assignment_id),
            mission_id=f"deployment-assignment:{record.assignment_id}",
            context=context,
        )
        decision_verification = self.trust.verify_decision(record.authorization_decision_id)
        defects.extend(f"ASSIGNMENT_DECISION:{item}" for item in decision_verification.defects)
        try:
            decision = self.trust.get_decision(record.authorization_decision_id)
        except NotFoundError:
            decision = None
            defects.append("ASSIGNMENT_DECISION_MISSING")
        if decision is not None and (not decision.allowed or decision.request != expected_request):
            defects.append("ASSIGNMENT_DECISION_REQUEST_MISMATCH")
        consumption = self.database.connection.execute(
            "SELECT * FROM continuity_authorization_consumptions WHERE decision_id = ?",
            (record.authorization_decision_id,),
        ).fetchone()
        if consumption is None:
            defects.append("ASSIGNMENT_CONSUMPTION_MISSING")
        elif (
            str(consumption["operation_kind"]),
            str(consumption["operation_id"]),
            str(consumption["consumed_at"]),
            str(consumption["consumed_by"]),
        ) != (
            _ASSIGNMENT_OPERATION,
            record.assignment_id,
            record.authorized_at,
            record.authorized_by,
        ):
            defects.append("ASSIGNMENT_CONSUMPTION_MISMATCH")
        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?", (record.ledger_event_id,)
        ).fetchone()
        if event is None:
            defects.append("ASSIGNMENT_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != self._assignment_stream(record.assignment_id):
                defects.append("ASSIGNMENT_LEDGER_STREAM_MISMATCH")
            if str(event["kind"]) != _ASSIGNMENT_STATUS:
                defects.append("ASSIGNMENT_LEDGER_KIND_MISMATCH")
            if str(event["actor"]) != record.authorized_by:
                defects.append("ASSIGNMENT_LEDGER_ACTOR_MISMATCH")
            if str(event["occurred_at"]) != record.authorized_at:
                defects.append("ASSIGNMENT_LEDGER_TIME_MISMATCH")
            if str(event["record_hash"]) != record.ledger_hash:
                defects.append("ASSIGNMENT_LEDGER_HASH_MISMATCH")
            try:
                event_payload = json.loads(str(event["payload_json"]))
            except json.JSONDecodeError:
                defects.append("ASSIGNMENT_LEDGER_PAYLOAD_INVALID")
            else:
                expected_payload = {
                    "assignment_id": record.assignment_id,
                    "bundle_id": record.bundle_id,
                    "node_id": record.node_id,
                    "bundle_manifest_digest": record.bundle_manifest_digest,
                    "node_public_key_fingerprint_sha256": record.node_public_key_fingerprint_sha256,
                    "compatibility_digest": record.compatibility_digest,
                    "status": _ASSIGNMENT_STATUS,
                    "authorization_decision_id": record.authorization_decision_id,
                }
                if event_payload != expected_payload:
                    defects.append("ASSIGNMENT_LEDGER_PAYLOAD_MISMATCH")
        defects.extend(
            f"ASSIGNMENT_LEDGER_CHAIN:{item.code}"
            for item in self.ledger.verify(self._assignment_stream(record.assignment_id)).defects
        )
        return defects

    def verify_assignment(self, assignment_id: str) -> DeploymentVerification:
        try:
            record = self.get_assignment(assignment_id)
        except NotFoundError:
            return DeploymentVerification(str(assignment_id), ("ASSIGNMENT_NOT_FOUND",))
        try:
            defects = self._assignment_verification_defects(record)
        except (IntegrityError, ValidationError, TypeError, ValueError, json.JSONDecodeError):
            defects = ["ASSIGNMENT_FIELDS_INVALID"]
        return DeploymentVerification(record.assignment_id, tuple(dict.fromkeys(defects)))
