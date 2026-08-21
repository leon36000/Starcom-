from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import re
import sqlite3
from collections.abc import Mapping, Sequence
from typing import Any

from .canonical import canonical_json, sha256_digest, utc_now
from .db import Database
from .durable import DurableOutbox, EffectStatus
from .errors import (
    AuthorizationError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    ValidationError,
)
from .ledger import EventLedger
from .trust import AuthorizationDecision, AuthorizationRequest, TrustPlane


_ACTION = "creative.job.request"
_TOPIC = "creative.job.request"
_MISSION_PREFIX = "creative-job:"
_STATUS = "CREATIVE_JOB_REQUESTED_NOT_EXECUTED"
_MAX_PROMPT_BYTES = 4 * 1024 * 1024
_MAX_JSON_BYTES = 512 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,190}$")
_MEDIA_TYPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*/[A-Za-z0-9][A-Za-z0-9.+-]*$")
_SAFETY_KEYS = frozenset(
    {"profile_id", "mode", "allow_sensitive", "max_output_bytes"}
)
_SEED_KEYS = frozenset({"seed", "options"})
_NETWORK_KEYS = frozenset({"mode", "egress_allowed"})
_INPUT_KEYS = frozenset({"artifact_id", "digest", "media_type"})
_SAFETY_MODES = frozenset({"STRICT", "STANDARD"})
_NETWORK_MODES = frozenset({"NONE", "LOCAL_ONLY", "EXTERNAL"})
_OUTPUT_PREFIXES = {
    "IMAGE": ("image/",),
    "TEXT_TO_SPEECH": ("audio/",),
    "SPEECH_TO_TEXT": ("application/json", "text/plain"),
    "AUDIO": ("audio/",),
    "VIDEO": ("video/",),
}


class CreativeJobType(str, Enum):
    IMAGE = "IMAGE"
    TEXT_TO_SPEECH = "TEXT_TO_SPEECH"
    SPEECH_TO_TEXT = "SPEECH_TO_TEXT"
    AUDIO = "AUDIO"
    VIDEO = "VIDEO"


class CreativeJobStatus(str, Enum):
    REQUESTED_NOT_EXECUTED = _STATUS


@dataclass(frozen=True)
class CreativeInputArtifact:
    artifact_id: str
    digest: str
    media_type: str

    def as_dict(self) -> dict[str, str]:
        return {
            "artifact_id": self.artifact_id,
            "digest": self.digest,
            "media_type": self.media_type,
        }


@dataclass(frozen=True)
class CreativeJobPreparation:
    job_id: str
    job_type: CreativeJobType
    owner: str
    prompt_bytes: bytes
    prompt_digest: str
    prompt_size_bytes: int
    model_id: str
    executor_id: str
    executor_descriptor_digest: str
    input_artifacts: tuple[CreativeInputArtifact, ...]
    output_media_type: str
    safety_profile: Mapping[str, Any]
    safety_policy_digest: str
    seed_configuration: Mapping[str, Any]
    network_requirements: Mapping[str, Any]
    idempotency_key: str
    effect_id: str
    request_digest: str
    action: str
    resource: str
    mission_id: str
    authorization_context: Mapping[str, Any]


@dataclass(frozen=True)
class CreativeJobRecord:
    job_id: str
    job_type: CreativeJobType
    owner: str
    prompt_bytes: bytes
    prompt_digest: str
    prompt_size_bytes: int
    model_id: str
    executor_id: str
    executor_descriptor_digest: str
    input_artifacts: tuple[CreativeInputArtifact, ...]
    output_media_type: str
    safety_profile: Mapping[str, Any]
    safety_policy_digest: str
    seed_configuration: Mapping[str, Any]
    network_requirements: Mapping[str, Any]
    idempotency_key: str
    effect_id: str
    request_digest: str
    authorization_decision_id: str
    operator_identity: str
    status: CreativeJobStatus
    created_at: str
    updated_at: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class CreativeJobVerification:
    job_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


def _required_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field_name} must be a non-empty string")
    if len(value) > 256:
        raise ValidationError(f"{field_name} is too long")
    return value


def _required_id(value: object, field_name: str) -> str:
    result = _required_text(value, field_name)
    if not _ID_RE.fullmatch(result):
        raise ValidationError(f"{field_name} has an invalid identifier")
    return result


def _digest(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValidationError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _media_type(value: object, field_name: str) -> str:
    result = _required_text(value, field_name)
    if not _MEDIA_TYPE_RE.fullmatch(result):
        raise ValidationError(f"{field_name} must be a valid closed media type")
    return result


def _closed_object(
    value: object,
    *,
    field_name: str,
    keys: frozenset[str],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{field_name} must be an object")
    result = dict(value)
    if set(result) != set(keys):
        raise ValidationError(f"{field_name} has an unexpected or missing field")
    try:
        encoded = canonical_json(result).encode("utf-8")
    except (TypeError, ValueError, ValidationError) as exc:
        raise ValidationError(f"{field_name} must contain canonical JSON values") from exc
    if len(encoded) > _MAX_JSON_BYTES:
        raise ValidationError(f"{field_name} is too large")
    return result


def _validate_safety_profile(value: object) -> dict[str, Any]:
    result = _closed_object(value, field_name="safety_profile", keys=_SAFETY_KEYS)
    result["profile_id"] = _required_id(result["profile_id"], "safety_profile.profile_id")
    mode = result["mode"]
    if not isinstance(mode, str) or mode not in _SAFETY_MODES:
        raise ValidationError("safety_profile.mode is not a supported mode")
    if type(result["allow_sensitive"]) is not bool:
        raise ValidationError("safety_profile.allow_sensitive must be boolean")
    max_output = result["max_output_bytes"]
    if type(max_output) is not int or max_output < 1 or max_output > 2**63 - 1:
        raise ValidationError("safety_profile.max_output_bytes must be a positive integer")
    return result


def _validate_seed_configuration(value: object) -> dict[str, Any]:
    result = _closed_object(value, field_name="seed_configuration", keys=_SEED_KEYS)
    seed = result["seed"]
    if seed is not None and (type(seed) is not int or seed < 0):
        raise ValidationError("seed_configuration.seed must be a non-negative integer or null")
    if not isinstance(result["options"], Mapping):
        raise ValidationError("seed_configuration.options must be an object")
    canonical_json(dict(result["options"]))
    return result


def _validate_network_requirements(value: object) -> dict[str, Any]:
    result = _closed_object(
        value,
        field_name="network_requirements",
        keys=_NETWORK_KEYS,
    )
    mode = result["mode"]
    if not isinstance(mode, str) or mode not in _NETWORK_MODES:
        raise ValidationError("network_requirements.mode is not supported")
    if type(result["egress_allowed"]) is not bool:
        raise ValidationError("network_requirements.egress_allowed must be boolean")
    if mode in {"NONE", "LOCAL_ONLY"} and result["egress_allowed"]:
        raise ValidationError("non-external network modes cannot allow egress")
    if mode == "EXTERNAL" and not result["egress_allowed"]:
        raise ValidationError("EXTERNAL network mode requires egress_allowed")
    return result


def _validate_inputs(value: object) -> tuple[CreativeInputArtifact, ...]:
    if value is None or isinstance(value, (str, bytes, bytearray)):
        raise ValidationError("input_artifacts must be a sequence of closed references")
    if not isinstance(value, Sequence):
        raise ValidationError("input_artifacts must be a sequence of closed references")
    result: list[CreativeInputArtifact] = []
    for index, item in enumerate(value):
        if isinstance(item, CreativeInputArtifact):
            artifact = item
        else:
            if not isinstance(item, Mapping):
                raise ValidationError(f"input_artifacts[{index}] must be an object")
            raw = dict(item)
            if set(raw) != set(_INPUT_KEYS):
                raise ValidationError(
                    f"input_artifacts[{index}] has an unexpected or missing field"
                )
            artifact = CreativeInputArtifact(
                artifact_id=_required_id(raw["artifact_id"], "input artifact_id"),
                digest=_digest(raw["digest"], "input digest"),
                media_type=_media_type(raw["media_type"], "input media_type"),
            )
        artifact_id = _required_id(artifact.artifact_id, "input artifact_id")
        artifact_digest = _digest(artifact.digest, "input digest")
        artifact_media_type = _media_type(artifact.media_type, "input media_type")
        result.append(
            CreativeInputArtifact(artifact_id, artifact_digest, artifact_media_type)
        )
    if tuple(item.artifact_id for item in result) != tuple(
        sorted(item.artifact_id for item in result)
    ):
        raise ValidationError("input_artifacts must be sorted by artifact_id")
    if len({item.artifact_id for item in result}) != len(result):
        raise ValidationError("input_artifacts must have unique artifact_id values")
    return tuple(result)


def _decode_canonical_object(raw: object, field_name: str) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw or len(raw.encode("utf-8")) > _MAX_JSON_BYTES:
        raise ValueError(f"{field_name} is not a bounded JSON string")

    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key {key}")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=no_duplicates)
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise ValueError(f"{field_name} is not canonical JSON")
    return value


class CreativeJobService:
    """Durable request authority whose terminal truth is not executed."""

    database: Database
    ledger: EventLedger
    trust: TrustPlane
    outbox: DurableOutbox

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        trust: TrustPlane,
        outbox: DurableOutbox,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self.outbox = outbox
        self._initialize_schema()

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS creative_jobs (
                    job_id TEXT PRIMARY KEY,
                    job_type TEXT NOT NULL CHECK (
                        job_type IN ('IMAGE','TEXT_TO_SPEECH','SPEECH_TO_TEXT','AUDIO','VIDEO')
                    ),
                    owner TEXT NOT NULL,
                    prompt_bytes BLOB NOT NULL,
                    prompt_digest TEXT NOT NULL CHECK (length(prompt_digest) = 64),
                    prompt_size_bytes INTEGER NOT NULL CHECK (prompt_size_bytes >= 1),
                    model_id TEXT NOT NULL,
                    executor_id TEXT NOT NULL,
                    executor_descriptor_digest TEXT NOT NULL
                        CHECK (length(executor_descriptor_digest) = 64),
                    output_media_type TEXT NOT NULL,
                    safety_profile_json TEXT NOT NULL,
                    safety_policy_digest TEXT NOT NULL CHECK (length(safety_policy_digest) = 64),
                    seed_configuration_json TEXT NOT NULL,
                    network_requirements_json TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    effect_id TEXT NOT NULL UNIQUE,
                    request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
                    authorization_decision_id TEXT NOT NULL UNIQUE,
                    operator_identity TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status = 'CREATIVE_JOB_REQUESTED_NOT_EXECUTED'
                    ),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS creative_job_inputs (
                    job_id TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    digest TEXT NOT NULL CHECK (length(digest) = 64),
                    media_type TEXT NOT NULL,
                    PRIMARY KEY (job_id, artifact_id),
                    FOREIGN KEY (job_id) REFERENCES creative_jobs(job_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS creative_job_transitions (
                    transition_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL CHECK (sequence >= 1),
                    from_status TEXT,
                    to_status TEXT NOT NULL CHECK (
                        to_status = 'CREATIVE_JOB_REQUESTED_NOT_EXECUTED'
                    ),
                    actor TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    UNIQUE (job_id, sequence),
                    FOREIGN KEY (job_id) REFERENCES creative_jobs(job_id)
                )
                """
            )
            for table, label in (
                ("creative_jobs", "creative jobs"),
                ("creative_job_inputs", "creative job inputs"),
                ("creative_job_transitions", "creative job transitions"),
            ):
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {table}_no_update
                    BEFORE UPDATE ON {table}
                    BEGIN SELECT RAISE(ABORT, '{label} are immutable'); END
                    """
                )
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {table}_no_delete
                    BEFORE DELETE ON {table}
                    BEGIN SELECT RAISE(ABORT, '{label} are immutable'); END
                    """
                )

    @staticmethod
    def _job_type(value: object) -> CreativeJobType:
        try:
            return value if isinstance(value, CreativeJobType) else CreativeJobType(str(value))
        except ValueError as exc:
            raise ValidationError("job_type is not supported") from exc

    @staticmethod
    def _output_media_type(job_type: CreativeJobType, value: object) -> str:
        result = _media_type(value, "output_media_type")
        if not any(
            result == prefix or result.startswith(prefix)
            for prefix in _OUTPUT_PREFIXES[job_type.value]
        ):
            raise ValidationError("output_media_type is incompatible with job_type")
        return result

    @classmethod
    def _material_from_preparation(
        cls,
        preparation: CreativeJobPreparation,
    ) -> dict[str, Any]:
        return {
            "job_id": preparation.job_id,
            "job_type": preparation.job_type.value,
            "owner": preparation.owner,
            "prompt_digest": preparation.prompt_digest,
            "prompt_size_bytes": preparation.prompt_size_bytes,
            "model_id": preparation.model_id,
            "executor_id": preparation.executor_id,
            "executor_descriptor_digest": preparation.executor_descriptor_digest,
            "input_artifacts": [
                artifact.as_dict() for artifact in preparation.input_artifacts
            ],
            "output_media_type": preparation.output_media_type,
            "safety_profile": dict(preparation.safety_profile),
            "safety_policy_digest": preparation.safety_policy_digest,
            "seed_configuration": dict(preparation.seed_configuration),
            "network_requirements": dict(preparation.network_requirements),
            "idempotency_key": preparation.idempotency_key,
            "effect_id": preparation.effect_id,
        }

    @classmethod
    def _authorization_context(
        cls,
        preparation: CreativeJobPreparation,
    ) -> dict[str, Any]:
        return cls._material_from_preparation(preparation) | {
            "request_digest": preparation.request_digest,
        }

    @classmethod
    def _outbox_payload(cls, preparation: CreativeJobPreparation) -> dict[str, Any]:
        return {
            "job_id": preparation.job_id,
            "job_type": preparation.job_type.value,
            "owner": preparation.owner,
            "prompt_digest": preparation.prompt_digest,
            "prompt_size_bytes": preparation.prompt_size_bytes,
            "model_id": preparation.model_id,
            "executor_id": preparation.executor_id,
            "executor_descriptor_digest": preparation.executor_descriptor_digest,
            "input_artifacts": [
                artifact.as_dict() for artifact in preparation.input_artifacts
            ],
            "output_media_type": preparation.output_media_type,
            "safety_profile": dict(preparation.safety_profile),
            "safety_policy_digest": preparation.safety_policy_digest,
            "seed_configuration": dict(preparation.seed_configuration),
            "network_requirements": dict(preparation.network_requirements),
            "idempotency_key": preparation.idempotency_key,
            "effect_id": preparation.effect_id,
            "request_digest": preparation.request_digest,
            "status": CreativeJobStatus.REQUESTED_NOT_EXECUTED.value,
        }

    def prepare(
        self,
        *,
        job_id: str,
        job_type: CreativeJobType | str,
        owner: str,
        prompt: bytes,
        model_id: str,
        executor_id: str,
        executor_descriptor_digest: str,
        input_artifacts: Sequence[Mapping[str, object] | CreativeInputArtifact],
        output_media_type: str,
        safety_profile: Mapping[str, object],
        safety_policy_digest: str,
        seed_configuration: Mapping[str, object],
        network_requirements: Mapping[str, object],
        idempotency_key: str,
    ) -> CreativeJobPreparation:
        job_id = _required_id(job_id, "job_id")
        selected_type = self._job_type(job_type)
        owner = _required_id(owner, "owner")
        if not isinstance(prompt, bytes) or not prompt:
            raise ValidationError("prompt must be non-empty exact UTF-8 bytes")
        if len(prompt) > _MAX_PROMPT_BYTES:
            raise ValidationError("prompt is too large")
        try:
            prompt.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValidationError("prompt must be valid UTF-8 bytes") from exc
        model_id = _required_id(model_id, "model_id")
        executor_id = _required_id(executor_id, "executor_id")
        executor_descriptor_digest = _digest(
            executor_descriptor_digest,
            "executor_descriptor_digest",
        )
        selected_inputs = _validate_inputs(input_artifacts)
        output_media_type = self._output_media_type(selected_type, output_media_type)
        selected_safety = _validate_safety_profile(safety_profile)
        safety_policy_digest = _digest(safety_policy_digest, "safety_policy_digest")
        selected_seed = _validate_seed_configuration(seed_configuration)
        selected_network = _validate_network_requirements(network_requirements)
        idempotency_key = _required_text(idempotency_key, "idempotency_key")
        effect_id = f"creative:job:{job_id}"
        prompt_digest = sha256_digest(prompt)
        material = {
            "job_id": job_id,
            "job_type": selected_type.value,
            "owner": owner,
            "prompt_digest": prompt_digest,
            "prompt_size_bytes": len(prompt),
            "model_id": model_id,
            "executor_id": executor_id,
            "executor_descriptor_digest": executor_descriptor_digest,
            "input_artifacts": [artifact.as_dict() for artifact in selected_inputs],
            "output_media_type": output_media_type,
            "safety_profile": selected_safety,
            "safety_policy_digest": safety_policy_digest,
            "seed_configuration": selected_seed,
            "network_requirements": selected_network,
            "idempotency_key": idempotency_key,
            "effect_id": effect_id,
        }
        request_digest = sha256_digest(material)
        preparation = CreativeJobPreparation(
            job_id=job_id,
            job_type=selected_type,
            owner=owner,
            prompt_bytes=prompt,
            prompt_digest=prompt_digest,
            prompt_size_bytes=len(prompt),
            model_id=model_id,
            executor_id=executor_id,
            executor_descriptor_digest=executor_descriptor_digest,
            input_artifacts=selected_inputs,
            output_media_type=output_media_type,
            safety_profile=selected_safety,
            safety_policy_digest=safety_policy_digest,
            seed_configuration=selected_seed,
            network_requirements=selected_network,
            idempotency_key=idempotency_key,
            effect_id=effect_id,
            request_digest=request_digest,
            action=_ACTION,
            resource=f"creative:job:{job_id}",
            mission_id=f"{_MISSION_PREFIX}{job_id}",
            authorization_context={},
        )
        return CreativeJobPreparation(
            **{
                **preparation.__dict__,
                "authorization_context": self._authorization_context(preparation),
            }
        )

    def _canonical_preparation(
        self,
        preparation: CreativeJobPreparation,
    ) -> CreativeJobPreparation:
        if not isinstance(preparation, CreativeJobPreparation):
            raise ValidationError("preparation must be a CreativeJobPreparation")
        try:
            canonical = self.prepare(
                job_id=preparation.job_id,
                job_type=preparation.job_type,
                owner=preparation.owner,
                prompt=preparation.prompt_bytes,
                model_id=preparation.model_id,
                executor_id=preparation.executor_id,
                executor_descriptor_digest=preparation.executor_descriptor_digest,
                input_artifacts=preparation.input_artifacts,
                output_media_type=preparation.output_media_type,
                safety_profile=preparation.safety_profile,
                safety_policy_digest=preparation.safety_policy_digest,
                seed_configuration=preparation.seed_configuration,
                network_requirements=preparation.network_requirements,
                idempotency_key=preparation.idempotency_key,
            )
        except (TypeError, ValidationError) as exc:
            raise IntegrityError("creative job preparation is invalid") from exc
        if canonical != preparation:
            raise IntegrityError("creative job preparation is not canonical")
        return canonical

    def _verified_decision(
        self,
        preparation: CreativeJobPreparation,
        decision_id: str,
        actor: str,
    ) -> AuthorizationDecision:
        decision_id = _required_text(decision_id, "authorization_decision_id")
        actor = _required_id(actor, "actor")
        decision = self.trust.get_decision(decision_id)
        verification = self.trust.verify_decision(decision_id)
        if not verification.ok:
            raise IntegrityError(
                "authorization decision is not independently verifiable",
                {"decision_id": decision_id, "defects": list(verification.defects)},
            )
        if not decision.allowed:
            raise AuthorizationError(
                "creative job request is denied by TrustPlane",
                {"decision_id": decision_id, "reason": decision.reason},
            )
        expected = AuthorizationRequest(
            subject=actor,
            action=preparation.action,
            resource=preparation.resource,
            mission_id=preparation.mission_id,
            context=dict(preparation.authorization_context),
        )
        if decision.request != expected:
            raise AuthorizationError(
                "authorization decision does not match the creative job context",
                {"decision_id": decision_id},
            )
        return decision

    @staticmethod
    def _record_material(record: CreativeJobRecord) -> dict[str, Any]:
        return {
            "job_id": record.job_id,
            "job_type": record.job_type.value,
            "owner": record.owner,
            "prompt_digest": record.prompt_digest,
            "prompt_size_bytes": record.prompt_size_bytes,
            "model_id": record.model_id,
            "executor_id": record.executor_id,
            "executor_descriptor_digest": record.executor_descriptor_digest,
            "input_artifacts": [artifact.as_dict() for artifact in record.input_artifacts],
            "output_media_type": record.output_media_type,
            "safety_profile": dict(record.safety_profile),
            "safety_policy_digest": record.safety_policy_digest,
            "seed_configuration": dict(record.seed_configuration),
            "network_requirements": dict(record.network_requirements),
            "idempotency_key": record.idempotency_key,
            "effect_id": record.effect_id,
        }

    @staticmethod
    def _row_to_record(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> CreativeJobRecord:
        inputs = connection.execute(
            """
            SELECT artifact_id, digest, media_type
            FROM creative_job_inputs WHERE job_id = ? ORDER BY artifact_id
            """,
            (str(row["job_id"]),),
        ).fetchall()
        return CreativeJobRecord(
            job_id=str(row["job_id"]),
            job_type=CreativeJobType(str(row["job_type"])),
            owner=str(row["owner"]),
            prompt_bytes=bytes(row["prompt_bytes"]),
            prompt_digest=str(row["prompt_digest"]),
            prompt_size_bytes=int(row["prompt_size_bytes"]),
            model_id=str(row["model_id"]),
            executor_id=str(row["executor_id"]),
            executor_descriptor_digest=str(row["executor_descriptor_digest"]),
            input_artifacts=tuple(
                CreativeInputArtifact(
                    str(item["artifact_id"]),
                    str(item["digest"]),
                    str(item["media_type"]),
                )
                for item in inputs
            ),
            output_media_type=str(row["output_media_type"]),
            safety_profile=_decode_canonical_object(
                str(row["safety_profile_json"]), "safety_profile"
            ),
            safety_policy_digest=str(row["safety_policy_digest"]),
            seed_configuration=_decode_canonical_object(
                str(row["seed_configuration_json"]), "seed_configuration"
            ),
            network_requirements=_decode_canonical_object(
                str(row["network_requirements_json"]), "network_requirements"
            ),
            idempotency_key=str(row["idempotency_key"]),
            effect_id=str(row["effect_id"]),
            request_digest=str(row["request_digest"]),
            authorization_decision_id=str(row["authorization_decision_id"]),
            operator_identity=str(row["operator_identity"]),
            status=CreativeJobStatus(str(row["status"])),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def get(self, job_id: str) -> CreativeJobRecord:
        job_id = _required_id(job_id, "job_id")
        row = self.database.connection.execute(
            "SELECT * FROM creative_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("creative job does not exist", {"job_id": job_id})
        return self._row_to_record(self.database.connection, row)

    def request(
        self,
        preparation: CreativeJobPreparation,
        *,
        authorization_decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> CreativeJobRecord:
        preparation = self._canonical_preparation(preparation)
        actor = _required_id(actor, "actor")
        authorization_decision_id = _required_text(
            authorization_decision_id,
            "authorization_decision_id",
        )
        used_decision = self.database.connection.execute(
            """
            SELECT job_id FROM creative_jobs
            WHERE authorization_decision_id = ?
            """,
            (authorization_decision_id,),
        ).fetchone()
        if used_decision is not None and str(used_decision["job_id"]) != preparation.job_id:
            raise ConflictError(
                "authorization decision was already consumed by another creative job",
                {"job_id": str(used_decision["job_id"])},
            )
        decision = self._verified_decision(
            preparation,
            authorization_decision_id,
            actor,
        )
        occurred_at = occurred_at or utc_now()
        occurred_at = _required_text(occurred_at, "occurred_at")

        try:
            with self.database.transaction() as connection:
                existing = connection.execute(
                    "SELECT * FROM creative_jobs WHERE job_id = ?",
                    (preparation.job_id,),
                ).fetchone()
                if existing is not None:
                    current = self._row_to_record(connection, existing)
                    if (
                        self._record_material(current)
                        != self._material_from_preparation(preparation)
                        or current.prompt_bytes != preparation.prompt_bytes
                        or current.authorization_decision_id != authorization_decision_id
                        or current.operator_identity != actor
                    ):
                        raise ConflictError(
                            "creative job replay changed immutable material",
                            {"job_id": preparation.job_id},
                        )
                    replay_verification = self.verify(preparation.job_id)
                    if not replay_verification.ok:
                        raise IntegrityError(
                            "creative job replay found corrupted immutable state",
                            {
                                "job_id": preparation.job_id,
                                "defects": list(replay_verification.defects),
                            },
                        )
                    return current

                competitor = connection.execute(
                    """
                    SELECT job_id FROM creative_jobs
                    WHERE idempotency_key = ?
                       OR effect_id = ?
                       OR authorization_decision_id = ?
                    """,
                    (
                        preparation.idempotency_key,
                        preparation.effect_id,
                        authorization_decision_id,
                    ),
                ).fetchone()
                if competitor is not None:
                    raise ConflictError(
                        "creative job idempotency or decision material was already used",
                        {"job_id": str(competitor["job_id"])},
                    )

                # Re-read and revalidate the decision while the admission transaction owns the database lock.
                decision = self._verified_decision(
                    preparation,
                    authorization_decision_id,
                    actor,
                )
                event_payload = {
                    "job": self._material_from_preparation(preparation),
                    "request_digest": preparation.request_digest,
                    "authorization_decision_id": decision.decision_id,
                    "operator_identity": actor,
                    "status": CreativeJobStatus.REQUESTED_NOT_EXECUTED.value,
                }
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"creative:job:{preparation.job_id}",
                    "CREATIVE_JOB_REQUESTED",
                    event_payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO creative_jobs (
                        job_id, job_type, owner, prompt_bytes, prompt_digest,
                        prompt_size_bytes, model_id, executor_id,
                        executor_descriptor_digest, output_media_type,
                        safety_profile_json, safety_policy_digest,
                        seed_configuration_json, network_requirements_json,
                        idempotency_key, effect_id, request_digest,
                        authorization_decision_id, operator_identity, status,
                        created_at, updated_at, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        preparation.job_id,
                        preparation.job_type.value,
                        preparation.owner,
                        preparation.prompt_bytes,
                        preparation.prompt_digest,
                        preparation.prompt_size_bytes,
                        preparation.model_id,
                        preparation.executor_id,
                        preparation.executor_descriptor_digest,
                        preparation.output_media_type,
                        canonical_json(dict(preparation.safety_profile)),
                        preparation.safety_policy_digest,
                        canonical_json(dict(preparation.seed_configuration)),
                        canonical_json(dict(preparation.network_requirements)),
                        preparation.idempotency_key,
                        preparation.effect_id,
                        preparation.request_digest,
                        decision.decision_id,
                        actor,
                        CreativeJobStatus.REQUESTED_NOT_EXECUTED.value,
                        occurred_at,
                        occurred_at,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
                for artifact in preparation.input_artifacts:
                    connection.execute(
                        """
                        INSERT INTO creative_job_inputs (
                            job_id, artifact_id, digest, media_type
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (
                            preparation.job_id,
                            artifact.artifact_id,
                            artifact.digest,
                            artifact.media_type,
                        ),
                    )
                connection.execute(
                    """
                    INSERT INTO creative_job_transitions (
                        job_id, sequence, from_status, to_status, actor,
                        occurred_at, ledger_event_id, ledger_hash
                    ) VALUES (?, 1, NULL, ?, ?, ?, ?, ?)
                    """,
                    (
                        preparation.job_id,
                        CreativeJobStatus.REQUESTED_NOT_EXECUTED.value,
                        actor,
                        occurred_at,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
                self.outbox.enqueue_in_transaction(
                    connection,
                    effect_id=preparation.effect_id,
                    topic=_TOPIC,
                    payload=self._outbox_payload(preparation),
                    max_attempts=3,
                    available_at=occurred_at,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                row = connection.execute(
                    "SELECT * FROM creative_jobs WHERE job_id = ?",
                    (preparation.job_id,),
                ).fetchone()
                assert row is not None
                return self._row_to_record(connection, row)
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "creative job admission conflicted with immutable state",
                {"job_id": preparation.job_id},
            ) from exc

    @staticmethod
    def _append_unique(defects: list[str], *values: str) -> None:
        for value in values:
            if value not in defects:
                defects.append(value)

    def verify(self, job_id: str) -> CreativeJobVerification:
        job_id = _required_id(job_id, "job_id")
        defects: list[str] = []
        connection = self.database.connection
        row = connection.execute(
            "SELECT * FROM creative_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        if row is None:
            return CreativeJobVerification(job_id, ("JOB_NOT_FOUND",))

        preparation: CreativeJobPreparation | None = None
        prompt_bytes = row["prompt_bytes"]
        if not isinstance(prompt_bytes, bytes):
            self._append_unique(defects, "PROMPT_BYTES_INVALID")
            prompt_bytes = b""
        else:
            try:
                prompt_bytes.decode("utf-8")
            except UnicodeDecodeError:
                self._append_unique(defects, "PROMPT_UTF8_INVALID")
        if isinstance(prompt_bytes, bytes) and sha256_digest(prompt_bytes) != str(
            row["prompt_digest"]
        ):
            self._append_unique(defects, "PROMPT_DIGEST_MISMATCH")
        try:
            prompt_size_bytes = int(row["prompt_size_bytes"])
        except (TypeError, ValueError):
            prompt_size_bytes = None
            self._append_unique(defects, "PROMPT_SIZE_INVALID")
        if (
            isinstance(prompt_bytes, bytes)
            and prompt_size_bytes is not None
            and len(prompt_bytes) != prompt_size_bytes
        ):
            self._append_unique(defects, "PROMPT_SIZE_MISMATCH")
        if str(row["status"]) != CreativeJobStatus.REQUESTED_NOT_EXECUTED.value:
            self._append_unique(defects, "STATUS_INVALID")
        if str(row["updated_at"]) != str(row["created_at"]):
            self._append_unique(defects, "UPDATED_TIMESTAMP_MISMATCH")

        try:
            stored_inputs = connection.execute(
                """
                SELECT artifact_id, digest, media_type
                FROM creative_job_inputs WHERE job_id = ? ORDER BY artifact_id
                """,
                (job_id,),
            ).fetchall()
            input_values = [
                {
                    "artifact_id": str(item["artifact_id"]),
                    "digest": str(item["digest"]),
                    "media_type": str(item["media_type"]),
                }
                for item in stored_inputs
            ]
            preparation = self.prepare(
                job_id=job_id,
                job_type=str(row["job_type"]),
                owner=str(row["owner"]),
                prompt=prompt_bytes,
                model_id=str(row["model_id"]),
                executor_id=str(row["executor_id"]),
                executor_descriptor_digest=str(row["executor_descriptor_digest"]),
                input_artifacts=input_values,
                output_media_type=str(row["output_media_type"]),
                safety_profile=_decode_canonical_object(
                    str(row["safety_profile_json"]), "safety_profile"
                ),
                safety_policy_digest=str(row["safety_policy_digest"]),
                seed_configuration=_decode_canonical_object(
                    str(row["seed_configuration_json"]), "seed_configuration"
                ),
                network_requirements=_decode_canonical_object(
                    str(row["network_requirements_json"]), "network_requirements"
                ),
                idempotency_key=str(row["idempotency_key"]),
            )
        except (TypeError, ValueError, KeyError, ValidationError, sqlite3.Error):
            self._append_unique(defects, "PLAN_FIELDS_INVALID")

        if preparation is not None:
            if str(row["request_digest"]) != preparation.request_digest:
                self._append_unique(defects, "REQUEST_DIGEST_MISMATCH")
            if str(row["effect_id"]) != preparation.effect_id:
                self._append_unique(defects, "EFFECT_ID_MISMATCH")

        input_rows = connection.execute(
            "SELECT artifact_id FROM creative_job_inputs WHERE job_id = ?",
            (job_id,),
        ).fetchall()
        input_ids = [str(item["artifact_id"]) for item in input_rows]
        if input_ids != sorted(input_ids) or len(input_ids) != len(set(input_ids)):
            self._append_unique(defects, "INPUT_MEMBERSHIP_ORDER_INVALID")

        transitions = connection.execute(
            "SELECT * FROM creative_job_transitions WHERE job_id = ? ORDER BY sequence",
            (job_id,),
        ).fetchall()
        if len(transitions) != 1:
            self._append_unique(defects, "TRANSITION_COUNT_INVALID")
        else:
            transition = transitions[0]
            if int(transition["sequence"]) != 1:
                self._append_unique(defects, "TRANSITION_SEQUENCE_INVALID")
            if transition["from_status"] is not None:
                self._append_unique(defects, "TRANSITION_FROM_STATUS_INVALID")
            if str(transition["to_status"]) != _STATUS:
                self._append_unique(defects, "TRANSITION_TO_STATUS_INVALID")
            if str(transition["ledger_event_id"]) != str(row["ledger_event_id"]):
                self._append_unique(defects, "TRANSITION_LEDGER_EVENT_MISMATCH")
            if str(transition["ledger_hash"]) != str(row["ledger_hash"]):
                self._append_unique(defects, "TRANSITION_LEDGER_HASH_MISMATCH")
            if str(transition["actor"]) != str(row["operator_identity"]):
                self._append_unique(defects, "TRANSITION_ACTOR_MISMATCH")
            if str(transition["occurred_at"]) != str(row["created_at"]):
                self._append_unique(defects, "TRANSITION_TIMESTAMP_MISMATCH")

        decision: AuthorizationDecision | None = None
        if preparation is not None:
            decision_id = str(row["authorization_decision_id"])
            try:
                decision = self.trust.get_decision(decision_id)
                decision_verification = self.trust.verify_decision(decision_id)
                if not decision_verification.ok:
                    self._append_unique(defects, "AUTHORIZATION_DECISION_INVALID")
                expected_request = AuthorizationRequest(
                    subject=str(row["operator_identity"]),
                    action=preparation.action,
                    resource=preparation.resource,
                    mission_id=preparation.mission_id,
                    context=dict(preparation.authorization_context),
                )
                if not decision.allowed:
                    self._append_unique(defects, "AUTHORIZATION_NOT_ALLOWED")
                if decision.request != expected_request:
                    self._append_unique(defects, "AUTHORIZATION_CONTEXT_MISMATCH")
                used_count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM creative_jobs WHERE authorization_decision_id = ?",
                        (decision_id,),
                    ).fetchone()[0]
                )
                if used_count != 1:
                    self._append_unique(defects, "AUTHORIZATION_SINGLE_USE_INVALID")
            except Exception:
                self._append_unique(defects, "AUTHORIZATION_DECISION_MISSING")

        ledger_row = connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (str(row["ledger_event_id"]),),
        ).fetchone()
        if ledger_row is None:
            self._append_unique(defects, "JOB_LEDGER_EVENT_MISSING")
        else:
            if str(ledger_row["record_hash"]) != str(row["ledger_hash"]):
                self._append_unique(defects, "JOB_LEDGER_HASH_MISMATCH")
            if str(ledger_row["stream_id"]) != f"creative:job:{job_id}":
                self._append_unique(defects, "JOB_LEDGER_STREAM_MISMATCH")
            if str(ledger_row["kind"]) != "CREATIVE_JOB_REQUESTED":
                self._append_unique(defects, "JOB_LEDGER_KIND_MISMATCH")
            if str(ledger_row["actor"]) != str(row["operator_identity"]):
                self._append_unique(defects, "JOB_LEDGER_ACTOR_MISMATCH")
            if str(ledger_row["occurred_at"]) != str(row["created_at"]):
                self._append_unique(defects, "JOB_LEDGER_TIMESTAMP_MISMATCH")
            if preparation is not None and decision is not None:
                try:
                    payload = json.loads(str(ledger_row["payload_json"]))
                    expected_payload = {
                        "job": self._material_from_preparation(preparation),
                        "request_digest": preparation.request_digest,
                        "authorization_decision_id": decision.decision_id,
                        "operator_identity": str(row["operator_identity"]),
                        "status": _STATUS,
                    }
                    if payload != expected_payload:
                        self._append_unique(defects, "JOB_LEDGER_PAYLOAD_MISMATCH")
                except (TypeError, ValueError, json.JSONDecodeError):
                    self._append_unique(defects, "JOB_LEDGER_PAYLOAD_INVALID")
            if not self.ledger.verify(str(ledger_row["stream_id"])).ok:
                self._append_unique(defects, "JOB_LEDGER_CHAIN_INVALID")

        try:
            effect = self.outbox.get(str(row["effect_id"]))
        except Exception:
            effect = None
            self._append_unique(defects, "OUTBOX_EFFECT_MISSING")
        if effect is not None and preparation is not None:
            expected_payload = self._outbox_payload(preparation)
            if effect.topic != _TOPIC:
                self._append_unique(defects, "OUTBOX_TOPIC_MISMATCH")
            if dict(effect.payload) != expected_payload:
                self._append_unique(defects, "OUTBOX_PAYLOAD_MISMATCH")
            expected_effect_digest = sha256_digest(
                {
                    "effect_id": preparation.effect_id,
                    "topic": _TOPIC,
                    "payload": expected_payload,
                    "max_attempts": 3,
                }
            )
            if effect.request_digest != expected_effect_digest:
                self._append_unique(defects, "OUTBOX_REQUEST_DIGEST_MISMATCH")
            if effect.status is not EffectStatus.PENDING:
                self._append_unique(defects, "OUTBOX_EFFECT_NOT_PENDING")
            effect_ledger = connection.execute(
                "SELECT * FROM ledger_events WHERE event_id = ?",
                (effect.ledger_event_id,),
            ).fetchone()
            if effect_ledger is None:
                self._append_unique(defects, "OUTBOX_LEDGER_EVENT_MISSING")
            else:
                if str(effect_ledger["record_hash"]) != effect.ledger_hash:
                    self._append_unique(defects, "OUTBOX_LEDGER_HASH_MISMATCH")
                if str(effect_ledger["occurred_at"]) != effect.created_at:
                    self._append_unique(defects, "OUTBOX_LEDGER_TIMESTAMP_MISMATCH")
                if str(effect_ledger["stream_id"]) != f"durable:effect:{effect.effect_id}":
                    self._append_unique(defects, "OUTBOX_LEDGER_STREAM_MISMATCH")
                if str(effect_ledger["kind"]) != "EFFECT_ENQUEUED":
                    self._append_unique(defects, "OUTBOX_LEDGER_KIND_MISMATCH")
                if str(effect_ledger["actor"]) != str(row["operator_identity"]):
                    self._append_unique(defects, "OUTBOX_LEDGER_ACTOR_MISMATCH")
                try:
                    payload = json.loads(str(effect_ledger["payload_json"]))
                    expected = {
                        "effect_id": preparation.effect_id,
                        "topic": _TOPIC,
                        "payload": expected_payload,
                        "max_attempts": 3,
                        "available_at": str(effect.available_at),
                    }
                    if payload != expected:
                        self._append_unique(defects, "OUTBOX_LEDGER_PAYLOAD_MISMATCH")
                except (TypeError, ValueError, json.JSONDecodeError):
                    self._append_unique(defects, "OUTBOX_LEDGER_PAYLOAD_INVALID")
                if not self.ledger.verify(str(effect_ledger["stream_id"])).ok:
                    self._append_unique(defects, "OUTBOX_LEDGER_CHAIN_INVALID")

        return CreativeJobVerification(job_id, tuple(defects))


CreativeJob = CreativeJobRecord
CreativeJobVerificationResult = CreativeJobVerification
