from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import math
import re
import sqlite3
from typing import Any

from .canonical import canonical_json, parse_strict_json_object, sha256_digest, utc_now
from .continuity_types import SignatureVerifier
from .db import Database
from .durable import DurableOutbox, EffectLease, EffectRecord, EffectStatus
from .errors import ConflictError, IntegrityError, NotFoundError, StateTransitionError, ValidationError
from .final_pack import C7FinalPackService
from .ledger import EventLedger
from .research import ReceiptOutcome, ResearchCampaign
from .trust import AuthorizationDecision, AuthorizationRequest, TrustPlane


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_PLAN_BYTES = 4 * 1024 * 1024
_MAX_SIGNATURE_BYTES = 1024
_PLAN_VERSION = "1.0.0"
_GATE_EFFECT = "12A_LIVE_RESEARCH_MARATHON_PLANNED_NO_NETWORK"
_START_ACTION = "research.marathon.start"
_TOPIC_PREFIX = "research.marathon.partition:"
_TOP_LEVEL_KEYS = frozenset(
    {
        "marathon_id",
        "plan_version",
        "c7_pack_id",
        "campaign_id",
        "source_profiles",
        "partitions",
        "minimum_identity_target",
        "max_parallelism",
        "request_timeout_seconds",
        "retry_policy",
        "coordinator_identity",
        "coordinator_environment",
        "reviewer_identity",
        "reviewer_environment",
        "planned_at_utc",
        "independence_basis",
        "state",
        "gate_effect",
    }
)
_PROFILE_KEYS = frozenset(
    {
        "profile_id",
        "source_id",
        "source_kind",
        "source_ref",
        "request_template",
        "request_policy_digest",
        "enabled",
    }
)
_PARTITION_KEYS = frozenset({"partition_id", "profile_id", "partition_key", "request"})
_RETRY_KEYS = frozenset({"max_attempts", "retry_delay_seconds", "backoff_multiplier"})
_INDEPENDENCE_KEYS = frozenset({"excluded_identities", "statement"})


class MarathonState(str, Enum):
    PLANNED_NOT_STARTED = "PLANNED_NOT_STARTED"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    COMPLETE_PENDING_CERTIFICATION = "COMPLETE_PENDING_CERTIFICATION"


ResearchMarathonState = MarathonState


@dataclass(frozen=True)
class ResearchMarathonProfile:
    profile_id: str
    source_id: str
    source_kind: str
    source_ref: str
    request_template: Mapping[str, Any]
    request_policy_digest: str
    enabled: bool

    @property
    def material(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "source_id": self.source_id,
            "source_kind": self.source_kind,
            "source_ref": self.source_ref,
            "request_template": dict(self.request_template),
            "request_policy_digest": self.request_policy_digest,
            "enabled": self.enabled,
        }


@dataclass(frozen=True)
class ResearchMarathonPartition:
    partition_id: str
    profile_id: str
    partition_key: str
    request: Mapping[str, Any]

    @property
    def material(self) -> dict[str, Any]:
        return {
            "partition_id": self.partition_id,
            "profile_id": self.profile_id,
            "partition_key": self.partition_key,
            "request": dict(self.request),
        }


@dataclass(frozen=True)
class ResearchMarathonPreparation:
    marathon_id: str
    plan_version: str
    c7_pack_id: str
    campaign_id: str
    profile_count: int
    partition_count: int
    minimum_identity_target: int
    max_parallelism: int
    payload_sha256: str
    signature_sha256: str | None
    key_id: str | None
    state: MarathonState
    gate_effect: str


@dataclass(frozen=True)
class ResearchMarathonPlan:
    marathon_id: str
    plan_version: str
    c7_pack_id: str
    campaign_id: str
    profiles: tuple[ResearchMarathonProfile, ...]
    partitions: tuple[ResearchMarathonPartition, ...]
    minimum_identity_target: int
    max_parallelism: int
    request_timeout_seconds: int
    retry_policy: Mapping[str, Any]
    coordinator_identity: str
    coordinator_environment: str
    reviewer_identity: str
    reviewer_environment: str
    planned_at_utc: str
    independence_basis: Mapping[str, Any]
    state: MarathonState
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
    def profile_count(self) -> int:
        return len(self.profiles)

    @property
    def partition_count(self) -> int:
        return len(self.partitions)


@dataclass(frozen=True)
class ResearchMarathonStartPreparation:
    marathon_id: str
    action: str
    resource: str
    context: Mapping[str, Any]
    state: MarathonState


@dataclass(frozen=True)
class ResearchMarathonTransition:
    marathon_id: str
    sequence: int
    state: MarathonState
    transition_kind: str
    decision_id: str | None
    actor: str
    occurred_at: str
    payload: Mapping[str, Any]
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class ResearchMarathonPartitionAttempt:
    marathon_id: str
    partition_id: str
    effect_id: str
    attempt_number: int
    attempt_id: str
    request_key: str
    worker_id: str
    source_id: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class ResearchMarathonCompletion:
    marathon_id: str
    partition_id: str
    effect_id: str
    result_digest: str
    attempt_ids: tuple[str, ...]
    evidence: Mapping[str, Any]
    actor: str
    occurred_at: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class ResearchMarathonProgress:
    marathon_id: str
    state: MarathonState
    profile_count: int
    partition_count: int
    completed_count: int
    attempt_count: int
    pending_count: int
    leased_count: int
    succeeded_count: int
    terminal_failed_count: int


@dataclass(frozen=True)
class ResearchMarathonVerification:
    marathon_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


@dataclass(frozen=True)
class _ParsedPlan:
    marathon_id: str
    plan_version: str
    c7_pack_id: str
    campaign_id: str
    profiles: tuple[ResearchMarathonProfile, ...]
    partitions: tuple[ResearchMarathonPartition, ...]
    minimum_identity_target: int
    max_parallelism: int
    request_timeout_seconds: int
    retry_policy: Mapping[str, Any]
    coordinator_identity: str
    coordinator_environment: str
    reviewer_identity: str
    reviewer_environment: str
    planned_at_utc: str
    independence_basis: Mapping[str, Any]
    state: MarathonState
    gate_effect: str


class ResearchMarathonService:
    """Durable 12A coordinator; it schedules evidence work but never performs source I/O."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        trust: TrustPlane,
        continuity: Any,
        final_pack: C7FinalPackService,
        research: ResearchCampaign,
        outbox: DurableOutbox,
        *,
        signature_verifier: SignatureVerifier | None = None,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self.continuity = continuity
        self.final_pack = final_pack
        self.research = research
        self.outbox = outbox
        self.signature_verifier = signature_verifier or continuity.signature_verifier
        self._initialize_schema()

    @staticmethod
    def _required_text(value: str, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{field} must be a non-empty string")
        return value

    @staticmethod
    def _timestamp(value: str, field: str = "timestamp") -> str:
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
    def _digest(value: str, field: str) -> str:
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            raise ValidationError(f"{field} must be a lowercase SHA-256 hex digest")
        return value

    @staticmethod
    def _object(value: object, field: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValidationError(f"{field} must be an object")
        return dict(value)

    @staticmethod
    def _list(value: object, field: str) -> list[Any]:
        if not isinstance(value, list):
            raise ValidationError(f"{field} must be an array")
        return list(value)

    @staticmethod
    def _closed(value: Mapping[str, Any], expected: frozenset[str], field: str) -> None:
        actual = set(value)
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        if missing or unknown:
            raise ValidationError(
                f"{field} has an invalid closed schema",
                {"missing": missing, "unknown": unknown},
            )

    @staticmethod
    def _integer(
        value: object, field: str, *, minimum: int, maximum: int | None = None
    ) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise ValidationError(f"{field} must be an integer >= {minimum}")
        if maximum is not None and value > maximum:
            raise ValidationError(f"{field} must be an integer <= {maximum}")
        return value

    @classmethod
    def _profile(cls, value: object, ordinal: int) -> ResearchMarathonProfile:
        material = cls._object(value, f"source_profiles[{ordinal}]")
        cls._closed(material, _PROFILE_KEYS, f"source_profiles[{ordinal}]")
        profile_id = cls._required_text(material["profile_id"], "profile_id")
        source_id = cls._required_text(material["source_id"], "source_id")
        source_kind = cls._required_text(material["source_kind"], "source_kind")
        source_ref = cls._required_text(material["source_ref"], "source_ref")
        request_template = cls._object(
            material["request_template"], f"source_profiles[{ordinal}].request_template"
        )
        request_policy_digest = cls._digest(
            material["request_policy_digest"], "request_policy_digest"
        )
        enabled = material["enabled"]
        if not isinstance(enabled, bool):
            raise ValidationError("enabled must be boolean")
        return ResearchMarathonProfile(
            profile_id,
            source_id,
            source_kind,
            source_ref,
            request_template,
            request_policy_digest,
            enabled,
        )

    @classmethod
    def _partition(cls, value: object, ordinal: int) -> ResearchMarathonPartition:
        material = cls._object(value, f"partitions[{ordinal}]")
        cls._closed(material, _PARTITION_KEYS, f"partitions[{ordinal}]")
        return ResearchMarathonPartition(
            cls._required_text(material["partition_id"], "partition_id"),
            cls._required_text(material["profile_id"], "profile_id"),
            cls._required_text(material["partition_key"], "partition_key"),
            cls._object(material["request"], f"partitions[{ordinal}].request"),
        )

    @classmethod
    def _parse_payload(cls, payload: bytes) -> _ParsedPlan:
        value = parse_strict_json_object(
            payload,
            max_bytes=_MAX_PLAN_BYTES,
            label="research marathon plan",
        )
        if canonical_json(value).encode("utf-8") != payload:
            raise ValidationError("research marathon plan must use canonical exact bytes")
        cls._closed(value, _TOP_LEVEL_KEYS, "research marathon plan")
        marathon_id = cls._required_text(value["marathon_id"], "marathon_id")
        plan_version = cls._required_text(value["plan_version"], "plan_version")
        if plan_version != _PLAN_VERSION:
            raise ValidationError("plan_version must be 1.0.0")
        c7_pack_id = cls._required_text(value["c7_pack_id"], "c7_pack_id")
        campaign_id = cls._required_text(value["campaign_id"], "campaign_id")
        raw_profiles = cls._list(value["source_profiles"], "source_profiles")
        if len(raw_profiles) < 48:
            raise ValidationError("at least 48 source profiles are required")
        profiles = tuple(
            cls._profile(item, ordinal) for ordinal, item in enumerate(raw_profiles)
        )
        profile_ids = [profile.profile_id for profile in profiles]
        source_ids = [profile.source_id for profile in profiles]
        if profile_ids != sorted(profile_ids) or len(set(profile_ids)) != len(profile_ids):
            raise ValidationError("profile IDs must be sorted and unique")
        if source_ids != sorted(source_ids) or len(set(source_ids)) != len(source_ids):
            raise ValidationError("source IDs must be sorted and unique")
        raw_partitions = cls._list(value["partitions"], "partitions")
        if len(raw_partitions) < 240:
            raise ValidationError("at least 240 partitions are required")
        partitions = tuple(
            cls._partition(item, ordinal) for ordinal, item in enumerate(raw_partitions)
        )
        partition_ids = [partition.partition_id for partition in partitions]
        if partition_ids != sorted(partition_ids) or len(set(partition_ids)) != len(partition_ids):
            raise ValidationError("partition IDs must be sorted and unique")
        profile_id_set = set(profile_ids)
        partition_keys: set[tuple[str, str]] = set()
        for partition in partitions:
            if partition.profile_id not in profile_id_set:
                raise ValidationError("partition references an unknown profile")
            key = (partition.profile_id, partition.partition_key)
            if key in partition_keys:
                raise ValidationError("partition keys must be unique per profile")
            partition_keys.add(key)
        minimum_identity_target = cls._integer(
            value["minimum_identity_target"],
            "minimum_identity_target",
            minimum=800,
            maximum=10_000_000,
        )
        max_parallelism = cls._integer(
            value["max_parallelism"], "max_parallelism", minimum=1, maximum=100_000
        )
        request_timeout_seconds = cls._integer(
            value["request_timeout_seconds"],
            "request_timeout_seconds",
            minimum=1,
            maximum=86_400,
        )
        retry_policy = cls._object(value["retry_policy"], "retry_policy")
        cls._closed(retry_policy, _RETRY_KEYS, "retry_policy")
        backoff_multiplier = retry_policy["backoff_multiplier"]
        if (
            isinstance(backoff_multiplier, bool)
            or not isinstance(backoff_multiplier, (int, float))
            or not math.isfinite(float(backoff_multiplier))
            or float(backoff_multiplier) < 1
            or float(backoff_multiplier) > 10
        ):
            raise ValidationError("retry_policy.backoff_multiplier must be between 1 and 10")
        retry_policy = {
            "max_attempts": cls._integer(
                retry_policy["max_attempts"],
                "retry_policy.max_attempts",
                minimum=1,
                maximum=100,
            ),
            "retry_delay_seconds": cls._integer(
                retry_policy["retry_delay_seconds"],
                "retry_policy.retry_delay_seconds",
                minimum=0,
                maximum=86_400,
            ),
            "backoff_multiplier": backoff_multiplier,
        }
        coordinator_identity = cls._required_text(
            value["coordinator_identity"], "coordinator_identity"
        )
        coordinator_environment = cls._required_text(
            value["coordinator_environment"], "coordinator_environment"
        )
        reviewer_identity = cls._required_text(
            value["reviewer_identity"], "reviewer_identity"
        )
        reviewer_environment = cls._required_text(
            value["reviewer_environment"], "reviewer_environment"
        )
        if coordinator_identity == reviewer_identity:
            raise ValidationError("coordinator and reviewer identities must be distinct")
        if coordinator_environment == reviewer_environment:
            raise ValidationError("coordinator and reviewer environments must be distinct")
        planned_at_utc = cls._timestamp(value["planned_at_utc"], "planned_at_utc")
        independence = cls._object(value["independence_basis"], "independence_basis")
        cls._closed(independence, _INDEPENDENCE_KEYS, "independence_basis")
        excluded = cls._list(independence["excluded_identities"], "excluded_identities")
        if any(not isinstance(item, str) or not item.strip() for item in excluded):
            raise ValidationError("excluded_identities must contain non-empty strings")
        if excluded != sorted(set(excluded)):
            raise ValidationError("excluded_identities must be sorted and unique")
        statement = cls._required_text(
            independence["statement"], "independence_basis.statement"
        )
        independence = {"excluded_identities": excluded, "statement": statement}
        if coordinator_identity in excluded or reviewer_identity in excluded:
            raise StateTransitionError(
                "marathon identities are not independent from C7 material"
            )
        if value["state"] != "PLANNED_NOT_STARTED":
            raise ValidationError("plan state must be PLANNED_NOT_STARTED")
        if value["gate_effect"] != _GATE_EFFECT:
            raise ValidationError("plan gate_effect is invalid")
        return _ParsedPlan(
            marathon_id,
            plan_version,
            c7_pack_id,
            campaign_id,
            profiles,
            partitions,
            minimum_identity_target,
            max_parallelism,
            request_timeout_seconds,
            retry_policy,
            coordinator_identity,
            coordinator_environment,
            reviewer_identity,
            reviewer_environment,
            planned_at_utc,
            independence,
            MarathonState.PLANNED_NOT_STARTED,
            _GATE_EFFECT,
        )

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS research_marathons (
                    marathon_id TEXT PRIMARY KEY,
                    plan_version TEXT NOT NULL,
                    c7_pack_id TEXT NOT NULL UNIQUE,
                    campaign_id TEXT NOT NULL UNIQUE,
                    minimum_identity_target INTEGER NOT NULL CHECK (minimum_identity_target >= 800),
                    max_parallelism INTEGER NOT NULL CHECK (max_parallelism >= 1),
                    request_timeout_seconds INTEGER NOT NULL CHECK (request_timeout_seconds >= 1),
                    retry_policy_json TEXT NOT NULL,
                    coordinator_identity TEXT NOT NULL,
                    coordinator_environment TEXT NOT NULL,
                    reviewer_identity TEXT NOT NULL,
                    reviewer_environment TEXT NOT NULL,
                    planned_at_utc TEXT NOT NULL,
                    independence_basis_json TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state = 'PLANNED_NOT_STARTED'),
                    gate_effect TEXT NOT NULL CHECK (
                        gate_effect = '12A_LIVE_RESEARCH_MARATHON_PLANNED_NO_NETWORK'
                    ),
                    key_id TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
                    signature BLOB NOT NULL,
                    signature_sha256 TEXT NOT NULL CHECK (length(signature_sha256) = 64),
                    admitted_at TEXT NOT NULL,
                    admitted_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS research_marathon_profiles (
                    marathon_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                    profile_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    material_json TEXT NOT NULL,
                    material_sha256 TEXT NOT NULL CHECK (length(material_sha256) = 64),
                    recorded_at TEXT NOT NULL,
                    recorded_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    PRIMARY KEY (marathon_id, ordinal),
                    UNIQUE (marathon_id, profile_id),
                    FOREIGN KEY (marathon_id) REFERENCES research_marathons(marathon_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS research_marathon_partitions (
                    marathon_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                    partition_id TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    material_json TEXT NOT NULL,
                    material_sha256 TEXT NOT NULL CHECK (length(material_sha256) = 64),
                    recorded_at TEXT NOT NULL,
                    recorded_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    PRIMARY KEY (marathon_id, ordinal),
                    UNIQUE (marathon_id, partition_id),
                    FOREIGN KEY (marathon_id) REFERENCES research_marathons(marathon_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS research_marathon_transitions (
                    marathon_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL CHECK (sequence >= 1),
                    state TEXT NOT NULL,
                    transition_kind TEXT NOT NULL,
                    decision_id TEXT UNIQUE,
                    actor TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    PRIMARY KEY (marathon_id, sequence),
                    FOREIGN KEY (marathon_id) REFERENCES research_marathons(marathon_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS research_marathon_partition_attempts (
                    marathon_id TEXT NOT NULL,
                    partition_id TEXT NOT NULL,
                    effect_id TEXT NOT NULL,
                    attempt_number INTEGER NOT NULL CHECK (attempt_number >= 1),
                    attempt_id TEXT NOT NULL UNIQUE,
                    request_key TEXT NOT NULL UNIQUE,
                    worker_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    PRIMARY KEY (marathon_id, partition_id, attempt_number),
                    FOREIGN KEY (marathon_id) REFERENCES research_marathons(marathon_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS research_marathon_completions (
                    marathon_id TEXT NOT NULL,
                    partition_id TEXT NOT NULL,
                    effect_id TEXT NOT NULL UNIQUE,
                    result_digest TEXT NOT NULL CHECK (length(result_digest) = 64),
                    attempt_ids_json TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    PRIMARY KEY (marathon_id, partition_id),
                    FOREIGN KEY (marathon_id) REFERENCES research_marathons(marathon_id)
                )
                """
            )
            for table in (
                "research_marathons",
                "research_marathon_profiles",
                "research_marathon_partitions",
                "research_marathon_transitions",
                "research_marathon_partition_attempts",
                "research_marathon_completions",
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
    def _stream(marathon_id: str) -> str:
        return f"research:marathon:{marathon_id}"

    @staticmethod
    def _partition_stream(marathon_id: str, partition_id: str) -> str:
        return f"research:marathon:{marathon_id}:partition:{partition_id}"

    @staticmethod
    def _topic(marathon_id: str) -> str:
        return f"{_TOPIC_PREFIX}{marathon_id}"

    @staticmethod
    def _effect_id(marathon_id: str, partition_id: str) -> str:
        return f"research:marathon:{marathon_id}:partition:{partition_id}"

    @staticmethod
    def _profile_from_row(row: sqlite3.Row) -> ResearchMarathonProfile:
        material = json.loads(str(row["material_json"]))
        if not isinstance(material, dict):
            raise IntegrityError("stored marathon profile material is invalid")
        return ResearchMarathonProfile(
            str(material["profile_id"]),
            str(material["source_id"]),
            str(material["source_kind"]),
            str(material["source_ref"]),
            dict(material["request_template"]),
            str(material["request_policy_digest"]),
            bool(material["enabled"]),
        )

    @staticmethod
    def _partition_from_row(row: sqlite3.Row) -> ResearchMarathonPartition:
        material = json.loads(str(row["material_json"]))
        if not isinstance(material, dict):
            raise IntegrityError("stored marathon partition material is invalid")
        return ResearchMarathonPartition(
            str(material["partition_id"]),
            str(material["profile_id"]),
            str(material["partition_key"]),
            dict(material["request"]),
        )

    def _current_state_in_transaction(
        self, connection: sqlite3.Connection, marathon_id: str
    ) -> MarathonState:
        row = connection.execute(
            "SELECT state FROM research_marathon_transitions "
            "WHERE marathon_id = ? ORDER BY sequence DESC LIMIT 1",
            (marathon_id,),
        ).fetchone()
        if row is None:
            raise IntegrityError("marathon has no state transition")
        try:
            return MarathonState(str(row["state"]))
        except ValueError as exc:
            raise IntegrityError("marathon state is invalid") from exc

    def current_state(self, marathon_id: str) -> MarathonState:
        marathon_id = self._required_text(marathon_id, "marathon_id")
        try:
            with self.database.transaction() as connection:
                return self._current_state_in_transaction(connection, marathon_id)
        except sqlite3.IntegrityError as exc:
            raise IntegrityError("marathon state is invalid") from exc

    def prepare(
        self,
        payload: bytes,
        signature: bytes | None = None,
        *,
        key_id: str | None = None,
    ) -> ResearchMarathonPreparation:
        parsed = self._parse_payload(payload)
        signature_sha256 = None
        if signature is not None:
            if not isinstance(signature, bytes) or not 0 < len(signature) <= _MAX_SIGNATURE_BYTES:
                raise ValidationError("signature must be non-empty bytes within the size limit")
            signature_sha256 = hashlib.sha256(signature).hexdigest()
        return ResearchMarathonPreparation(
            parsed.marathon_id,
            parsed.plan_version,
            parsed.c7_pack_id,
            parsed.campaign_id,
            len(parsed.profiles),
            len(parsed.partitions),
            parsed.minimum_identity_target,
            parsed.max_parallelism,
            sha256_digest(payload),
            signature_sha256,
            key_id,
            parsed.state,
            parsed.gate_effect,
        )

    plan = prepare

    def _verify_plan_signature(
        self,
        key_id: str,
        payload: bytes,
        signature: bytes,
        *,
        as_of: str | None = None,
    ) -> None:
        key_id = self._required_text(key_id, "key_id")
        root_verification = self.continuity.verify_trust_root(key_id)
        if not root_verification.ok:
            raise IntegrityError(
                "marathon signing trust root is not valid",
                {"defects": root_verification.defects},
            )
        root = self.database.connection.execute(
            "SELECT public_key_pem FROM continuity_trust_roots WHERE key_id = ?",
            (key_id,),
        ).fetchone()
        if root is None or not self.signature_verifier.verify(
            bytes(root["public_key_pem"]), payload, signature
        ):
            raise IntegrityError("marathon plan signature is invalid", {"key_id": key_id})
        if as_of is not None:
            accepted_row = self.database.connection.execute(
                "SELECT accepted_at FROM continuity_trust_roots WHERE key_id = ?",
                (key_id,),
            ).fetchone()
            if accepted_row is not None and self._parse_utc(str(accepted_row["accepted_at"])) > self._parse_utc(
                as_of
            ):
                raise StateTransitionError("marathon trust root was accepted after admission")

    def _assert_admission_prerequisites(
        self, connection: sqlite3.Connection, parsed: _ParsedPlan
    ) -> None:
        pack = self.final_pack.get_pack(parsed.c7_pack_id)
        c7_verification = self.final_pack.verify_pack(parsed.c7_pack_id)
        if not c7_verification.ok:
            raise IntegrityError(
                "C7 final pack is not clean", {"defects": c7_verification.defects}
            )
        if (
            pack.release_status != "NOT_RELEASED"
            or pack.external_runtime_integration_status != "NOT_PROVEN"
            or pack.live_census_certification_status != "NOT_PROVEN"
            or pack.gate_effect != "C7_FINAL_PACK_ADMITTED_NOT_RELEASED"
        ):
            raise StateTransitionError("C7 final pack is not the required unreleased gate")
        if self._parse_utc(pack.admitted_at) > self._parse_utc(parsed.planned_at_utc):
            raise StateTransitionError("plan planning time must follow C7 admission")
        c7_actors = {
            pack.packager_identity,
            pack.verifier_identity,
            pack.admitted_by,
        }
        if (
            parsed.coordinator_identity in c7_actors
            or parsed.reviewer_identity in c7_actors
        ):
            raise StateTransitionError(
                "marathon coordinator and reviewer must be independent from C7 actors"
            )
        campaign = self.research.get_campaign(parsed.campaign_id)
        if self._parse_utc(campaign.created_at) > self._parse_utc(parsed.planned_at_utc):
            raise StateTransitionError("plan planning time must follow campaign creation")
        if campaign.max_wave != 0:
            raise StateTransitionError("research campaign must be empty before marathon start")
        counts = connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM research_attempts WHERE campaign_id = ?) AS attempts,
                (SELECT COUNT(*) FROM research_receipts r JOIN research_attempts a ON a.attempt_id = r.attempt_id WHERE a.campaign_id = ?) AS receipts,
                (SELECT COUNT(*) FROM research_observations o JOIN research_attempts a ON a.attempt_id = o.attempt_id WHERE a.campaign_id = ?) AS observations,
                (SELECT COUNT(*) FROM research_cursors WHERE campaign_id = ?) AS cursors
            """,
            (
                parsed.campaign_id,
                parsed.campaign_id,
                parsed.campaign_id,
                parsed.campaign_id,
            ),
        ).fetchone()
        if counts is None or any(
            int(counts[field]) != 0
            for field in ("attempts", "receipts", "observations", "cursors")
        ):
            raise StateTransitionError("research campaign must have no existing evidence")

    def admit_plan(
        self,
        payload: bytes,
        signature: bytes,
        *,
        key_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> ResearchMarathonPlan:
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now(), "occurred_at")
        if not isinstance(signature, bytes) or not 0 < len(signature) <= _MAX_SIGNATURE_BYTES:
            raise ValidationError("signature must be non-empty bytes within the size limit")
        parsed = self._parse_payload(payload)
        if self._parse_utc(parsed.planned_at_utc) > self._parse_utc(occurred_at):
            raise StateTransitionError("plan admission cannot predate the signed planning time")
        payload_sha256 = sha256_digest(payload)
        signature_sha256 = hashlib.sha256(signature).hexdigest()
        self._verify_plan_signature(key_id, payload, signature, as_of=occurred_at)
        existing = self.database.connection.execute(
            "SELECT payload, signature, key_id FROM research_marathons WHERE marathon_id = ?",
            (parsed.marathon_id,),
        ).fetchone()
        if existing is not None:
            if (
                bytes(existing["payload"]) == payload
                and bytes(existing["signature"]) == signature
                and str(existing["key_id"]) == key_id
            ):
                return self.get_plan(parsed.marathon_id)
            raise ConflictError("marathon identifier already binds different plan material")

        with self.database.transaction() as connection:
            self._assert_admission_prerequisites(connection, parsed)
            existing = connection.execute(
                "SELECT marathon_id FROM research_marathons "
                "WHERE marathon_id = ? OR c7_pack_id = ? OR campaign_id = ?",
                (parsed.marathon_id, parsed.c7_pack_id, parsed.campaign_id),
            ).fetchone()
            if existing is not None:
                raise ConflictError("C7 pack or campaign is already bound to a marathon")
            admission = self.ledger.append_in_transaction(
                connection,
                self._stream(parsed.marathon_id),
                "12A_RESEARCH_MARATHON_PLAN_ADMITTED",
                {
                    "marathon_id": parsed.marathon_id,
                    "plan_version": parsed.plan_version,
                    "c7_pack_id": parsed.c7_pack_id,
                    "campaign_id": parsed.campaign_id,
                    "payload_sha256": payload_sha256,
                    "signature_sha256": signature_sha256,
                    "profile_count": len(parsed.profiles),
                    "partition_count": len(parsed.partitions),
                    "minimum_identity_target": parsed.minimum_identity_target,
                    "state": parsed.state.value,
                    "gate_effect": parsed.gate_effect,
                },
                actor=actor,
                occurred_at=occurred_at,
            )
            connection.execute(
                """
                INSERT INTO research_marathons (
                    marathon_id, plan_version, c7_pack_id, campaign_id,
                    minimum_identity_target, max_parallelism, request_timeout_seconds,
                    retry_policy_json, coordinator_identity, coordinator_environment,
                    reviewer_identity, reviewer_environment, planned_at_utc,
                    independence_basis_json, state, gate_effect, key_id, payload,
                    payload_sha256, signature, signature_sha256, admitted_at, admitted_by,
                    ledger_event_id, ledger_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    parsed.marathon_id,
                    parsed.plan_version,
                    parsed.c7_pack_id,
                    parsed.campaign_id,
                    parsed.minimum_identity_target,
                    parsed.max_parallelism,
                    parsed.request_timeout_seconds,
                    canonical_json(parsed.retry_policy),
                    parsed.coordinator_identity,
                    parsed.coordinator_environment,
                    parsed.reviewer_identity,
                    parsed.reviewer_environment,
                    parsed.planned_at_utc,
                    canonical_json(parsed.independence_basis),
                    parsed.state.value,
                    parsed.gate_effect,
                    key_id,
                    sqlite3.Binary(payload),
                    payload_sha256,
                    sqlite3.Binary(signature),
                    signature_sha256,
                    occurred_at,
                    actor,
                    admission.event_id,
                    admission.record_hash,
                ),
            )
            self._append_transition_in_transaction(
                connection,
                parsed.marathon_id,
                state=MarathonState.PLANNED_NOT_STARTED,
                transition_kind="PLAN_ADMITTED",
                decision_id=None,
                actor=actor,
                occurred_at=occurred_at,
                payload={"payload_sha256": payload_sha256, "gate_effect": parsed.gate_effect},
            )
            for ordinal, profile in enumerate(parsed.profiles):
                material = profile.material
                member = self.ledger.append_in_transaction(
                    connection,
                    self._stream(parsed.marathon_id),
                    "12A_RESEARCH_MARATHON_PROFILE_MEMBER_RECORDED",
                    {
                        "marathon_id": parsed.marathon_id,
                        "ordinal": ordinal,
                        "profile_id": profile.profile_id,
                        "material_sha256": sha256_digest(material),
                    },
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO research_marathon_profiles (
                        marathon_id, ordinal, profile_id, source_id, material_json,
                        material_sha256, recorded_at, recorded_by, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        parsed.marathon_id,
                        ordinal,
                        profile.profile_id,
                        profile.source_id,
                        canonical_json(material),
                        sha256_digest(material),
                        occurred_at,
                        actor,
                        member.event_id,
                        member.record_hash,
                    ),
                )
            for ordinal, partition in enumerate(parsed.partitions):
                material = partition.material
                member = self.ledger.append_in_transaction(
                    connection,
                    self._stream(parsed.marathon_id),
                    "12A_RESEARCH_MARATHON_PARTITION_MEMBER_RECORDED",
                    {
                        "marathon_id": parsed.marathon_id,
                        "ordinal": ordinal,
                        "partition_id": partition.partition_id,
                        "profile_id": partition.profile_id,
                        "material_sha256": sha256_digest(material),
                    },
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO research_marathon_partitions (
                        marathon_id, ordinal, partition_id, profile_id, material_json,
                        material_sha256, recorded_at, recorded_by, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        parsed.marathon_id,
                        ordinal,
                        partition.partition_id,
                        partition.profile_id,
                        canonical_json(material),
                        sha256_digest(material),
                        occurred_at,
                        actor,
                        member.event_id,
                        member.record_hash,
                    ),
                )
        return self.get_plan(parsed.marathon_id)

    admit = admit_plan
    admission = admit_plan

    def _row_to_plan(self, row: sqlite3.Row) -> ResearchMarathonPlan:
        marathon_id = str(row["marathon_id"])
        profiles = tuple(
            self._profile_from_row(profile_row)
            for profile_row in self.database.connection.execute(
                "SELECT * FROM research_marathon_profiles "
                "WHERE marathon_id = ? ORDER BY ordinal",
                (marathon_id,),
            ).fetchall()
        )
        partitions = tuple(
            self._partition_from_row(partition_row)
            for partition_row in self.database.connection.execute(
                "SELECT * FROM research_marathon_partitions "
                "WHERE marathon_id = ? ORDER BY ordinal",
                (marathon_id,),
            ).fetchall()
        )
        state = self.current_state(marathon_id)
        return ResearchMarathonPlan(
            marathon_id,
            str(row["plan_version"]),
            str(row["c7_pack_id"]),
            str(row["campaign_id"]),
            profiles,
            partitions,
            int(row["minimum_identity_target"]),
            int(row["max_parallelism"]),
            int(row["request_timeout_seconds"]),
            dict(json.loads(str(row["retry_policy_json"]))),
            str(row["coordinator_identity"]),
            str(row["coordinator_environment"]),
            str(row["reviewer_identity"]),
            str(row["reviewer_environment"]),
            str(row["planned_at_utc"]),
            dict(json.loads(str(row["independence_basis_json"]))),
            state,
            str(row["gate_effect"]),
            str(row["key_id"]),
            bytes(row["payload"]),
            str(row["payload_sha256"]),
            bytes(row["signature"]),
            str(row["signature_sha256"]),
            str(row["admitted_at"]),
            str(row["admitted_by"]),
            str(row["ledger_event_id"]),
            str(row["ledger_hash"]),
        )

    def get_plan(self, marathon_id: str) -> ResearchMarathonPlan:
        marathon_id = self._required_text(marathon_id, "marathon_id")
        row = self.database.connection.execute(
            "SELECT * FROM research_marathons WHERE marathon_id = ?", (marathon_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "research marathon does not exist", {"marathon_id": marathon_id}
            )
        return self._row_to_plan(row)

    get = get_plan

    def get_profile(self, marathon_id: str, profile_id: str) -> ResearchMarathonProfile:
        row = self.database.connection.execute(
            "SELECT * FROM research_marathon_profiles "
            "WHERE marathon_id = ? AND profile_id = ?",
            (marathon_id, profile_id),
        ).fetchone()
        if row is None:
            raise NotFoundError("research marathon profile does not exist")
        return self._profile_from_row(row)

    def get_partition(
        self, marathon_id: str, partition_id: str
    ) -> ResearchMarathonPartition:
        row = self.database.connection.execute(
            "SELECT * FROM research_marathon_partitions "
            "WHERE marathon_id = ? AND partition_id = ?",
            (marathon_id, partition_id),
        ).fetchone()
        if row is None:
            raise NotFoundError("research marathon partition does not exist")
        return self._partition_from_row(row)

    def start_context(self, marathon_id: str) -> dict[str, Any]:
        plan = self.get_plan(marathon_id)
        return {
            "c7_pack_id": plan.c7_pack_id,
            "campaign_id": plan.campaign_id,
            "plan_payload_sha256": plan.payload_sha256,
            "source_profile_count": plan.profile_count,
            "partition_count": plan.partition_count,
            "minimum_identity_target": plan.minimum_identity_target,
            "max_parallelism": plan.max_parallelism,
        }

    def prepare_start(self, marathon_id: str) -> ResearchMarathonStartPreparation:
        plan = self.get_plan(marathon_id)
        return ResearchMarathonStartPreparation(
            plan.marathon_id,
            _START_ACTION,
            f"research:marathon:{plan.marathon_id}",
            self.start_context(plan.marathon_id),
            plan.state,
        )

    def _assert_start_decision(
        self, decision_id: str, actor: str, plan: ResearchMarathonPlan
    ) -> AuthorizationDecision:
        decision_id = self._required_text(decision_id, "decision_id")
        actor = self._required_text(actor, "actor")
        verification = self.trust.verify_decision(decision_id)
        if not verification.ok:
            raise IntegrityError(
                "start authorization decision is invalid",
                {"defects": verification.defects},
            )
        decision = self.trust.get_decision(decision_id)
        expected_request = AuthorizationRequest(
            actor,
            _START_ACTION,
            f"research:marathon:{plan.marathon_id}",
            context=self.start_context(plan.marathon_id),
        )
        if not decision.allowed or decision.request != expected_request:
            raise StateTransitionError(
                "start authorization decision does not exactly bind this plan"
            )
        return decision

    def _append_transition_in_transaction(
        self,
        connection: sqlite3.Connection,
        marathon_id: str,
        *,
        state: MarathonState,
        transition_kind: str,
        decision_id: str | None,
        actor: str,
        occurred_at: str,
        payload: Mapping[str, Any],
    ) -> ResearchMarathonTransition:
        previous = connection.execute(
            "SELECT sequence FROM research_marathon_transitions "
            "WHERE marathon_id = ? ORDER BY sequence DESC LIMIT 1",
            (marathon_id,),
        ).fetchone()
        sequence = int(previous["sequence"]) + 1 if previous is not None else 1
        receipt = self.ledger.append_in_transaction(
            connection,
            self._stream(marathon_id),
            "12A_RESEARCH_MARATHON_STATE_TRANSITION",
            {
                "marathon_id": marathon_id,
                "sequence": sequence,
                "state": state.value,
                "transition_kind": transition_kind,
                "decision_id": decision_id,
                "payload": dict(payload),
            },
            actor=actor,
            occurred_at=occurred_at,
        )
        connection.execute(
            """
            INSERT INTO research_marathon_transitions (
                marathon_id, sequence, state, transition_kind, decision_id,
                actor, occurred_at, payload_json, ledger_event_id, ledger_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                marathon_id,
                sequence,
                state.value,
                transition_kind,
                decision_id,
                actor,
                occurred_at,
                canonical_json(dict(payload)),
                receipt.event_id,
                receipt.record_hash,
            ),
        )
        return ResearchMarathonTransition(
            marathon_id,
            sequence,
            state,
            transition_kind,
            decision_id,
            actor,
            occurred_at,
            dict(payload),
            receipt.event_id,
            receipt.record_hash,
        )

    def start(
        self,
        marathon_id: str,
        *,
        decision_id: str | None = None,
        authorization_decision_id: str | None = None,
        actor: str,
        occurred_at: str | None = None,
    ) -> ResearchMarathonPlan:
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now(), "occurred_at")
        if decision_id is not None and authorization_decision_id is not None:
            if decision_id != authorization_decision_id:
                raise ConflictError("conflicting authorization decision identifiers")
        decision_id = decision_id or authorization_decision_id
        if decision_id is None:
            raise ValidationError("decision_id is required")
        plan = self.get_plan(marathon_id)
        decision = self._assert_start_decision(decision_id, actor, plan)
        start_context = self.start_context(marathon_id)
        with self.database.transaction() as connection:
            current = self._current_state_in_transaction(connection, marathon_id)
            if current is not MarathonState.PLANNED_NOT_STARTED:
                raise ConflictError("marathon start is only valid once from PLANNED_NOT_STARTED")
            consumed = connection.execute(
                "SELECT sequence FROM research_marathon_transitions "
                "WHERE marathon_id = ? AND decision_id = ?",
                (marathon_id, decision.decision_id),
            ).fetchone()
            if consumed is not None:
                raise ConflictError("start authorization decision was already consumed")
            stored_plan = connection.execute(
                "SELECT * FROM research_marathons WHERE marathon_id = ?",
                (marathon_id,),
            ).fetchone()
            if stored_plan is None:
                raise NotFoundError("research marathon does not exist")
            preexisting_effect = connection.execute(
                "SELECT effect_id FROM durable_effects WHERE topic = ? LIMIT 1",
                (self._topic(marathon_id),),
            ).fetchone()
            if preexisting_effect is not None:
                raise ConflictError("marathon outbox effects already exist before start")
            parsed = self._parse_payload(bytes(stored_plan["payload"]))
            self._assert_admission_prerequisites(connection, parsed)
            self._append_transition_in_transaction(
                connection,
                marathon_id,
                state=MarathonState.ACTIVE,
                transition_kind="START_AUTHORIZED",
                decision_id=decision.decision_id,
                actor=actor,
                occurred_at=occurred_at,
                payload={
                    "action": _START_ACTION,
                    "resource": f"research:marathon:{marathon_id}",
                    "context": start_context,
                },
            )
            profiles = {
                profile.profile_id: profile
                for profile in (
                    self._profile_from_row(row)
                    for row in connection.execute(
                        "SELECT * FROM research_marathon_profiles "
                        "WHERE marathon_id = ? ORDER BY ordinal",
                        (marathon_id,),
                    ).fetchall()
                )
            }
            partitions = connection.execute(
                "SELECT * FROM research_marathon_partitions "
                "WHERE marathon_id = ? ORDER BY ordinal",
                (marathon_id,),
            ).fetchall()
            for row in partitions:
                partition = self._partition_from_row(row)
                profile = profiles.get(partition.profile_id)
                if profile is None:
                    raise IntegrityError(
                        "partition references an unavailable profile",
                        {"partition_id": partition.partition_id},
                    )
                effect_id = self._effect_id(marathon_id, partition.partition_id)
                self.outbox.enqueue_in_transaction(
                    connection,
                    effect_id=effect_id,
                    topic=self._topic(marathon_id),
                    payload={
                        "marathon_id": marathon_id,
                        "partition_id": partition.partition_id,
                        "profile_id": profile.profile_id,
                        "source_id": profile.source_id,
                        "request": dict(partition.request),
                        "partition_material_sha256": str(row["material_sha256"]),
                        "plan_payload_sha256": str(stored_plan["payload_sha256"]),
                        "max_attempts": int(parsed.retry_policy["max_attempts"]),
                        "request_timeout_seconds": parsed.request_timeout_seconds,
                    },
                    max_attempts=int(parsed.retry_policy["max_attempts"]),
                    available_at=occurred_at,
                    actor=actor,
                    occurred_at=occurred_at,
                )
        return self.get_plan(marathon_id)

    def _assert_state_decision(
        self,
        *,
        decision_id: str,
        actor: str,
        plan: ResearchMarathonPlan,
        action: str,
    ) -> AuthorizationDecision:
        decision_id = self._required_text(decision_id, "decision_id")
        actor = self._required_text(actor, "actor")
        verification = self.trust.verify_decision(decision_id)
        if not verification.ok:
            raise IntegrityError(
                "marathon state authorization decision is invalid",
                {"defects": verification.defects},
            )
        decision = self.trust.get_decision(decision_id)
        expected = AuthorizationRequest(
            actor,
            action,
            f"research:marathon:{plan.marathon_id}",
            context=self.start_context(plan.marathon_id),
        )
        if not decision.allowed or decision.request != expected:
            raise StateTransitionError(
                "marathon state authorization does not exactly bind this plan"
            )
        return decision

    def pause(
        self,
        marathon_id: str,
        *,
        decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> ResearchMarathonPlan:
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now(), "occurred_at")
        plan = self.get_plan(marathon_id)
        decision = self._assert_state_decision(
            decision_id=decision_id,
            actor=actor,
            plan=plan,
            action="research.marathon.pause",
        )
        if plan.state is not MarathonState.ACTIVE:
            raise StateTransitionError("pause requires an ACTIVE marathon")
        with self.database.transaction() as connection:
            if self._current_state_in_transaction(connection, marathon_id) is not MarathonState.ACTIVE:
                raise StateTransitionError("pause requires an ACTIVE marathon")
            self._append_transition_in_transaction(
                connection,
                marathon_id,
                state=MarathonState.PAUSED,
                transition_kind="PAUSE_AUTHORIZED",
                decision_id=decision.decision_id,
                actor=actor,
                occurred_at=occurred_at,
                payload={"action": "research.marathon.pause"},
            )
        return self.get_plan(marathon_id)

    def resume(
        self,
        marathon_id: str,
        *,
        decision_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> ResearchMarathonPlan:
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now(), "occurred_at")
        plan = self.get_plan(marathon_id)
        decision = self._assert_state_decision(
            decision_id=decision_id,
            actor=actor,
            plan=plan,
            action="research.marathon.resume",
        )
        if plan.state is not MarathonState.PAUSED:
            raise StateTransitionError("resume requires a PAUSED marathon")
        with self.database.transaction() as connection:
            if self._current_state_in_transaction(connection, marathon_id) is not MarathonState.PAUSED:
                raise StateTransitionError("resume requires a PAUSED marathon")
            self._append_transition_in_transaction(
                connection,
                marathon_id,
                state=MarathonState.ACTIVE,
                transition_kind="RESUME_AUTHORIZED",
                decision_id=decision.decision_id,
                actor=actor,
                occurred_at=occurred_at,
                payload={"action": "research.marathon.resume"},
            )
        return self.get_plan(marathon_id)

    @staticmethod
    def _parse_utc(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError("timestamp must be RFC 3339") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValidationError("timestamp must be timezone-aware")
        return parsed.astimezone(timezone.utc)

    def _validate_lease(
        self, marathon_id: str, lease: EffectLease, occurred_at: str
    ) -> EffectRecord:
        expected_effect = self._effect_id(marathon_id, str(lease.payload.get("partition_id", "")))
        if lease.effect_id != expected_effect or lease.topic != self._topic(marathon_id):
            raise IntegrityError("lease is not bound to this marathon partition")
        record = self.outbox.get(lease.effect_id)
        if (
            record.status is not EffectStatus.LEASED
            or record.lease_owner != lease.worker_id
            or record.lease_token != lease.lease_token
        ):
            raise StateTransitionError("lease owner or token does not match")
        if record.lease_expires_at is None or self._parse_utc(occurred_at) >= self._parse_utc(
            record.lease_expires_at
        ):
            raise StateTransitionError("lease has expired")
        if record.attempt_count != lease.attempt_count:
            raise ConflictError("lease attempt number is stale")
        return record

    def claim(
        self,
        marathon_id: str,
        *,
        worker_id: str,
        now: str | None = None,
        lease_seconds: int = 60,
        limit: int = 1,
    ) -> list[EffectLease]:
        marathon_id = self._required_text(marathon_id, "marathon_id")
        if self.current_state(marathon_id) is not MarathonState.ACTIVE:
            raise StateTransitionError("partition claims require an ACTIVE marathon")
        leases = self.outbox.claim(
            worker_id,
            now=now,
            lease_seconds=lease_seconds,
            limit=limit,
            topic=self._topic(marathon_id),
        )
        for lease in leases:
            if lease.payload.get("marathon_id") != marathon_id:
                raise IntegrityError("outbox lease payload is bound to another marathon")
        return leases

    def fail_partition(
        self,
        marathon_id: str,
        lease: EffectLease,
        *,
        error: str,
        actor: str,
        retry_delay_seconds: int | None = None,
        occurred_at: str | None = None,
    ) -> EffectRecord:
        actor = self._required_text(actor, "actor")
        error = self._required_text(error, "error")
        occurred_at = self._timestamp(occurred_at or utc_now(), "occurred_at")
        plan = self.get_plan(marathon_id)
        if plan.state is not MarathonState.ACTIVE:
            raise StateTransitionError("partition failure requires an ACTIVE marathon")
        if actor != lease.worker_id:
            raise StateTransitionError("actor must match the active lease worker")
        self._validate_lease(marathon_id, lease, occurred_at)
        delay = (
            int(plan.retry_policy["retry_delay_seconds"])
            if retry_delay_seconds is None
            else retry_delay_seconds
        )
        return self.outbox.fail(
            lease.effect_id,
            worker_id=lease.worker_id,
            lease_token=lease.lease_token,
            error=error,
            retry_delay_seconds=delay,
            occurred_at=occurred_at,
        )

    def begin_partition_attempt(
        self,
        marathon_id: str,
        lease: EffectLease,
        *,
        actor: str,
        occurred_at: str | None = None,
    ) -> ResearchMarathonPartitionAttempt:
        marathon_id = self._required_text(marathon_id, "marathon_id")
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now(), "occurred_at")
        if self.current_state(marathon_id) is not MarathonState.ACTIVE:
            raise StateTransitionError("partition attempts require an ACTIVE marathon")
        record = self._validate_lease(marathon_id, lease, occurred_at)
        if actor != lease.worker_id:
            raise StateTransitionError("actor must match the active lease worker")
        partition_id = lease.payload.get("partition_id")
        if not isinstance(partition_id, str) or not partition_id.strip():
            raise IntegrityError("lease partition_id is invalid")
        partition = self.get_partition(marathon_id, partition_id)
        profile = self.get_profile(marathon_id, partition.profile_id)
        plan = self.get_plan(marathon_id)
        if (
            lease.payload.get("profile_id") != profile.profile_id
            or lease.payload.get("source_id") != profile.source_id
            or lease.payload.get("request") != dict(partition.request)
            or lease.payload.get("plan_payload_sha256") != plan.payload_sha256
            or lease.payload.get("partition_material_sha256")
            != sha256_digest(partition.material)
        ):
            raise IntegrityError("lease payload does not match immutable partition material")
        existing = self.database.connection.execute(
            "SELECT * FROM research_marathon_partition_attempts "
            "WHERE marathon_id = ? AND partition_id = ? AND attempt_number = ?",
            (marathon_id, partition_id, lease.attempt_count),
        ).fetchone()
        request_key = f"{marathon_id}:{partition_id}:attempt:{lease.attempt_count}"
        if existing is not None:
            if (
                str(existing["effect_id"]) != record.effect_id
                or str(existing["request_key"]) != request_key
                or str(existing["worker_id"]) != actor
            ):
                raise ConflictError("partition attempt idempotency material conflicts")
            return self._attempt_from_row(existing)

        # This call is deliberately the first worker-side operation that can
        # create research evidence; no transport seam exists in this service.
        attempt = self.research.begin_attempt(
            plan.campaign_id,
            wave=1,
            request_key=request_key,
            source_id=profile.source_id,
            request=partition.request,
            actor=actor,
            occurred_at=occurred_at,
        )
        with self.database.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM research_marathon_partition_attempts "
                "WHERE marathon_id = ? AND partition_id = ? AND attempt_number = ?",
                (marathon_id, partition_id, lease.attempt_count),
            ).fetchone()
            if existing is not None:
                return self._attempt_from_row(existing)
            receipt = self.ledger.append_in_transaction(
                connection,
                self._partition_stream(marathon_id, partition_id),
                "12A_RESEARCH_MARATHON_PARTITION_ATTEMPT_BOUND",
                {
                    "marathon_id": marathon_id,
                    "partition_id": partition_id,
                    "effect_id": record.effect_id,
                    "attempt_number": lease.attempt_count,
                    "attempt_id": attempt.attempt_id,
                    "request_key": request_key,
                    "worker_id": actor,
                    "source_id": profile.source_id,
                },
                actor=actor,
                occurred_at=occurred_at,
            )
            connection.execute(
                """
                INSERT INTO research_marathon_partition_attempts (
                    marathon_id, partition_id, effect_id, attempt_number, attempt_id,
                    request_key, worker_id, source_id, ledger_event_id, ledger_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    marathon_id,
                    partition_id,
                    record.effect_id,
                    lease.attempt_count,
                    attempt.attempt_id,
                    request_key,
                    actor,
                    profile.source_id,
                    receipt.event_id,
                    receipt.record_hash,
                ),
            )
            row = connection.execute(
                "SELECT * FROM research_marathon_partition_attempts "
                "WHERE marathon_id = ? AND partition_id = ? AND attempt_number = ?",
                (marathon_id, partition_id, lease.attempt_count),
            ).fetchone()
            assert row is not None
            return self._attempt_from_row(row)

    begin_attempt = begin_partition_attempt

    @staticmethod
    def _attempt_from_row(row: sqlite3.Row) -> ResearchMarathonPartitionAttempt:
        return ResearchMarathonPartitionAttempt(
            str(row["marathon_id"]),
            str(row["partition_id"]),
            str(row["effect_id"]),
            int(row["attempt_number"]),
            str(row["attempt_id"]),
            str(row["request_key"]),
            str(row["worker_id"]),
            str(row["source_id"]),
            str(row["ledger_event_id"]),
            str(row["ledger_hash"]),
        )

    @staticmethod
    def _json_object(value: object, field: str) -> dict[str, Any]:
        try:
            decoded = json.loads(str(value))
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrityError(f"{field} is not valid JSON") from exc
        if not isinstance(decoded, dict):
            raise IntegrityError(f"{field} must be a JSON object")
        return decoded

    def _assert_research_event(
        self,
        connection: sqlite3.Connection,
        *,
        event_id: str,
        ledger_hash: str,
        stream_id: str,
        kind: str,
        occurred_at: str,
        payload: Mapping[str, Any],
    ) -> None:
        event = connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        if event is None:
            raise IntegrityError("research evidence ledger event is missing")
        try:
            observed_payload = json.loads(str(event["payload_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrityError("research evidence ledger payload is invalid") from exc
        if (
            str(event["stream_id"]) != stream_id
            or str(event["kind"]) != kind
            or str(event["record_hash"]) != ledger_hash
            or str(event["occurred_at"]) != occurred_at
            or observed_payload != dict(payload)
        ):
            raise IntegrityError("research evidence ledger link is invalid")

    def _partition_evidence(
        self,
        connection: sqlite3.Connection,
        *,
        marathon_id: str,
        partition_id: str,
        plan: ResearchMarathonPlan,
        mappings: list[sqlite3.Row],
    ) -> dict[str, Any]:
        partition = self.get_partition(marathon_id, partition_id)
        attempts: list[dict[str, Any]] = []
        successful = 0
        for mapping in mappings:
            attempt_id = str(mapping["attempt_id"])
            attempt_row = connection.execute(
                "SELECT * FROM research_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if attempt_row is None or str(attempt_row["campaign_id"]) != plan.campaign_id:
                raise IntegrityError("partition mapping references an invalid research attempt")
            request = self._json_object(
                attempt_row["request_json"], "research_attempt.request_json"
            )
            self._assert_research_event(
                connection,
                event_id=str(attempt_row["ledger_event_id"]),
                ledger_hash=str(attempt_row["ledger_hash"]),
                stream_id=f"research:campaign:{plan.campaign_id}",
                kind="RESEARCH_ATTEMPT_STARTED",
                occurred_at=str(attempt_row["started_at"]),
                payload={
                    "attempt_id": attempt_id,
                    "campaign_id": plan.campaign_id,
                    "wave": int(attempt_row["wave"]),
                    "request_key": str(attempt_row["request_key"]),
                    "source_id": str(attempt_row["source_id"]),
                    "request": request,
                    "request_digest": str(attempt_row["request_digest"]),
                    "pre_request_persisted": True,
                },
            )
            receipt = connection.execute(
                "SELECT * FROM research_receipts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if receipt is None:
                raise StateTransitionError(
                    "partition completion requires a receipt for every attempt"
                )
            observations = connection.execute(
                "SELECT * FROM research_observations WHERE attempt_id = ? ORDER BY observation_id",
                (attempt_id,),
            ).fetchall()
            cursors = connection.execute(
                "SELECT * FROM research_cursors WHERE attempt_id = ? ORDER BY cursor_id",
                (attempt_id,),
            ).fetchall()
            observation_material: list[dict[str, Any]] = []
            for observation in observations:
                observation_material.append(
                    {
                        "observation_id": str(observation["observation_id"]),
                        "snapshot_digest": str(observation["snapshot_digest"]),
                        "content_digest": str(observation["content_digest"]),
                        "data": self._json_object(
                            observation["data_json"], "observation.data_json"
                        ),
                        "observed_at": str(observation["observed_at"]),
                        "ledger_event_id": str(observation["ledger_event_id"]),
                        "ledger_hash": str(observation["ledger_hash"]),
                    }
                )
            cursor_material: list[dict[str, Any]] = []
            for cursor in cursors:
                try:
                    cursor_value = json.loads(str(cursor["value_json"]))
                except (TypeError, json.JSONDecodeError) as exc:
                    raise IntegrityError("cursor value is not valid JSON") from exc
                cursor_material.append(
                    {
                        "cursor_id": str(cursor["cursor_id"]),
                        "wave": int(cursor["wave"]),
                        "cursor_key": str(cursor["cursor_key"]),
                        "value": cursor_value,
                        "value_digest": str(cursor["value_digest"]),
                        "attempt_id": attempt_id,
                        "checkpoint_at": str(cursor["checkpoint_at"]),
                        "ledger_event_id": str(cursor["ledger_event_id"]),
                        "ledger_hash": str(cursor["ledger_hash"]),
                    }
                )
            outcome = str(receipt["outcome"])
            snapshot_digest = (
                str(receipt["snapshot_digest"])
                if receipt["snapshot_digest"] is not None
                else None
            )
            if outcome == ReceiptOutcome.SUCCESS.value:
                successful += 1
                if snapshot_digest is None:
                    raise StateTransitionError("successful receipt requires a snapshot digest")
                if not any(
                    item["snapshot_digest"] == snapshot_digest
                    for item in observation_material
                ):
                    raise StateTransitionError(
                        "successful receipt requires a matching observation"
                    )
                if not cursor_material:
                    raise StateTransitionError(
                        "successful receipt requires a linked cursor checkpoint"
                    )
            metadata = self._json_object(receipt["metadata_json"], "receipt.metadata_json")
            self._assert_research_event(
                connection,
                event_id=str(receipt["ledger_event_id"]),
                ledger_hash=str(receipt["ledger_hash"]),
                stream_id=f"research:campaign:{plan.campaign_id}",
                kind="RESEARCH_RECEIPT_RECORDED",
                occurred_at=str(receipt["received_at"]),
                payload={
                    "receipt_id": str(receipt["receipt_id"]),
                    "attempt_id": attempt_id,
                    "outcome": outcome,
                    "status_code": (
                        int(receipt["status_code"])
                        if receipt["status_code"] is not None
                        else None
                    ),
                    "snapshot_digest": snapshot_digest,
                    "metadata": metadata,
                },
            )
            for observation in observations:
                observation_data = self._json_object(
                    observation["data_json"], "research_observation.data_json"
                )
                self._assert_research_event(
                    connection,
                    event_id=str(observation["ledger_event_id"]),
                    ledger_hash=str(observation["ledger_hash"]),
                    stream_id=f"research:campaign:{plan.campaign_id}",
                    kind="RESEARCH_OBSERVATION_RECORDED",
                    occurred_at=str(observation["observed_at"]),
                    payload={
                        "observation_id": str(observation["observation_id"]),
                        "attempt_id": attempt_id,
                        "snapshot_digest": str(observation["snapshot_digest"]),
                        "content_digest": str(observation["content_digest"]),
                        "data": observation_data,
                    },
                )
            for cursor in cursors:
                try:
                    cursor_value = json.loads(str(cursor["value_json"]))
                except (TypeError, json.JSONDecodeError) as exc:
                    raise IntegrityError("cursor value is not valid JSON") from exc
                self._assert_research_event(
                    connection,
                    event_id=str(cursor["ledger_event_id"]),
                    ledger_hash=str(cursor["ledger_hash"]),
                    stream_id=f"research:campaign:{plan.campaign_id}",
                    kind="RESEARCH_CURSOR_CHECKPOINTED",
                    occurred_at=str(cursor["checkpoint_at"]),
                    payload={
                        "cursor_id": str(cursor["cursor_id"]),
                        "campaign_id": plan.campaign_id,
                        "wave": int(cursor["wave"]),
                        "cursor_key": str(cursor["cursor_key"]),
                        "value": cursor_value,
                        "value_digest": str(cursor["value_digest"]),
                        "attempt_id": attempt_id,
                    },
                )
            attempts.append(
                {
                    "attempt_id": attempt_id,
                    "attempt_number": int(mapping["attempt_number"]),
                    "effect_id": str(mapping["effect_id"]),
                    "request_key": str(attempt_row["request_key"]),
                    "source_id": str(attempt_row["source_id"]),
                    "worker_id": str(mapping["worker_id"]),
                    "mapping_ledger_event_id": str(mapping["ledger_event_id"]),
                    "mapping_ledger_hash": str(mapping["ledger_hash"]),
                    "request_digest": str(attempt_row["request_digest"]),
                    "status": str(attempt_row["status"]),
                    "receipt": {
                        "receipt_id": str(receipt["receipt_id"]),
                        "outcome": outcome,
                        "status_code": (
                            int(receipt["status_code"])
                            if receipt["status_code"] is not None
                            else None
                        ),
                        "snapshot_digest": snapshot_digest,
                        "metadata": metadata,
                        "received_at": str(receipt["received_at"]),
                        "ledger_event_id": str(receipt["ledger_event_id"]),
                        "ledger_hash": str(receipt["ledger_hash"]),
                    },
                    "observations": observation_material,
                    "cursors": cursor_material,
                }
            )
        if successful < 1:
            raise StateTransitionError("partition completion requires at least one SUCCESS receipt")
        return {
            "marathon_id": marathon_id,
            "partition_id": partition_id,
            "effect_id": self._effect_id(marathon_id, partition_id),
            "partition_material_sha256": sha256_digest(partition.material),
            "plan_payload_sha256": plan.payload_sha256,
            "attempts": attempts,
        }

    def _completion_from_row(self, row: sqlite3.Row) -> ResearchMarathonCompletion:
        try:
            attempt_ids = json.loads(str(row["attempt_ids_json"]))
            evidence = json.loads(str(row["evidence_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrityError("stored partition completion evidence is invalid") from exc
        if not isinstance(attempt_ids, list) or not isinstance(evidence, dict):
            raise IntegrityError("stored partition completion evidence is invalid")
        return ResearchMarathonCompletion(
            str(row["marathon_id"]),
            str(row["partition_id"]),
            str(row["effect_id"]),
            str(row["result_digest"]),
            tuple(str(item) for item in attempt_ids),
            evidence,
            str(row["actor"]),
            str(row["occurred_at"]),
            str(row["ledger_event_id"]),
            str(row["ledger_hash"]),
        )

    def _plan_from_parsed_row(
        self, row: sqlite3.Row, parsed: _ParsedPlan, state: MarathonState
    ) -> ResearchMarathonPlan:
        return ResearchMarathonPlan(
            str(row["marathon_id"]),
            parsed.plan_version,
            parsed.c7_pack_id,
            parsed.campaign_id,
            parsed.profiles,
            parsed.partitions,
            parsed.minimum_identity_target,
            parsed.max_parallelism,
            parsed.request_timeout_seconds,
            parsed.retry_policy,
            parsed.coordinator_identity,
            parsed.coordinator_environment,
            parsed.reviewer_identity,
            parsed.reviewer_environment,
            parsed.planned_at_utc,
            parsed.independence_basis,
            state,
            parsed.gate_effect,
            str(row["key_id"]),
            bytes(row["payload"]),
            str(row["payload_sha256"]),
            bytes(row["signature"]),
            str(row["signature_sha256"]),
            str(row["admitted_at"]),
            str(row["admitted_by"]),
            str(row["ledger_event_id"]),
            str(row["ledger_hash"]),
        )

    def complete_partition(
        self,
        marathon_id: str,
        lease: EffectLease,
        *,
        actor: str,
        attempt_id: str | None = None,
        occurred_at: str | None = None,
    ) -> ResearchMarathonCompletion:
        marathon_id = self._required_text(marathon_id, "marathon_id")
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now(), "occurred_at")
        partition_id = lease.payload.get("partition_id")
        if not isinstance(partition_id, str) or not partition_id.strip():
            raise IntegrityError("lease partition_id is invalid")
        existing = self.database.connection.execute(
            "SELECT * FROM research_marathon_completions "
            "WHERE marathon_id = ? AND partition_id = ?",
            (marathon_id, partition_id),
        ).fetchone()
        if existing is not None:
            if str(existing["effect_id"]) != lease.effect_id:
                raise ConflictError("completion effect does not match the supplied lease")
            return self._completion_from_row(existing)
        plan = self.get_plan(marathon_id)
        if plan.state is not MarathonState.ACTIVE:
            raise StateTransitionError("partition completion requires an ACTIVE marathon")
        self._validate_lease(marathon_id, lease, occurred_at)
        if actor != lease.worker_id:
            raise StateTransitionError("actor must match the active lease worker")
        mappings = self.database.connection.execute(
            "SELECT * FROM research_marathon_partition_attempts "
            "WHERE marathon_id = ? AND partition_id = ? ORDER BY attempt_number",
            (marathon_id, partition_id),
        ).fetchall()
        if not mappings:
            raise StateTransitionError("partition has no pre-request attempt")
        if attempt_id is not None and attempt_id not in {
            str(mapping["attempt_id"]) for mapping in mappings
        }:
            raise ConflictError("completion attempt does not belong to this partition")
        evidence = self._partition_evidence(
            self.database.connection,
            marathon_id=marathon_id,
            partition_id=partition_id,
            plan=plan,
            mappings=mappings,
        )
        result_digest = sha256_digest(evidence)
        attempt_ids = tuple(str(mapping["attempt_id"]) for mapping in mappings)
        with self.database.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM research_marathon_completions "
                "WHERE marathon_id = ? AND partition_id = ?",
                (marathon_id, partition_id),
            ).fetchone()
            if existing is not None:
                return self._completion_from_row(existing)
            completion_event = self.ledger.append_in_transaction(
                connection,
                self._partition_stream(marathon_id, partition_id),
                "12A_RESEARCH_MARATHON_PARTITION_COMPLETED",
                {
                    "marathon_id": marathon_id,
                    "partition_id": partition_id,
                    "effect_id": lease.effect_id,
                    "result_digest": result_digest,
                    "attempt_ids": list(attempt_ids),
                },
                actor=actor,
                occurred_at=occurred_at,
            )
            connection.execute(
                """
                INSERT INTO research_marathon_completions (
                    marathon_id, partition_id, effect_id, result_digest,
                    attempt_ids_json, evidence_json, actor, occurred_at,
                    ledger_event_id, ledger_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    marathon_id,
                    partition_id,
                    lease.effect_id,
                    result_digest,
                    canonical_json(list(attempt_ids)),
                    canonical_json(evidence),
                    actor,
                    occurred_at,
                    completion_event.event_id,
                    completion_event.record_hash,
                ),
            )
            self.outbox.succeed_in_transaction(
                connection,
                effect_id=lease.effect_id,
                worker_id=lease.worker_id,
                lease_token=lease.lease_token,
                result_digest=result_digest,
                occurred_at=occurred_at,
            )
            row = connection.execute(
                "SELECT * FROM research_marathon_completions "
                "WHERE marathon_id = ? AND partition_id = ?",
                (marathon_id, partition_id),
            ).fetchone()
            assert row is not None
            return self._completion_from_row(row)

    complete = complete_partition

    def progress(self, marathon_id: str) -> ResearchMarathonProgress:
        plan = self.get_plan(marathon_id)
        effect_counts = self.database.connection.execute(
            "SELECT status, COUNT(*) AS count FROM durable_effects "
            "WHERE topic = ? GROUP BY status",
            (self._topic(marathon_id),),
        ).fetchall()
        counts = {str(row["status"]): int(row["count"]) for row in effect_counts}
        completed = self.database.connection.execute(
            "SELECT COUNT(*) AS count FROM research_marathon_completions "
            "WHERE marathon_id = ?",
            (marathon_id,),
        ).fetchone()
        attempts = self.database.connection.execute(
            "SELECT COUNT(*) AS count FROM research_marathon_partition_attempts "
            "WHERE marathon_id = ?",
            (marathon_id,),
        ).fetchone()
        return ResearchMarathonProgress(
            marathon_id,
            plan.state,
            plan.profile_count,
            plan.partition_count,
            int(completed["count"]) if completed is not None else 0,
            int(attempts["count"]) if attempts is not None else 0,
            counts.get(EffectStatus.PENDING.value, 0),
            counts.get(EffectStatus.LEASED.value, 0),
            counts.get(EffectStatus.SUCCEEDED.value, 0),
            counts.get(EffectStatus.TERMINAL_FAILED.value, 0),
        )

    def close_pending_certification(
        self,
        marathon_id: str,
        *,
        actor: str,
        occurred_at: str | None = None,
    ) -> ResearchMarathonPlan:
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now(), "occurred_at")
        plan = self.get_plan(marathon_id)
        if plan.state not in {MarathonState.ACTIVE, MarathonState.PAUSED}:
            if plan.state is MarathonState.COMPLETE_PENDING_CERTIFICATION:
                return plan
            raise StateTransitionError("marathon cannot close from its current state")
        progress = self.progress(marathon_id)
        if (
            progress.completed_count != progress.partition_count
            or progress.succeeded_count != progress.partition_count
            or progress.pending_count
            or progress.leased_count
            or progress.terminal_failed_count
        ):
            raise StateTransitionError("all partition effects must be proven successful before close")
        campaign_verification = self.research.verify(plan.campaign_id)
        if not campaign_verification.ok:
            raise StateTransitionError(
                "research campaign evidence is not clean",
                {"defects": campaign_verification.defects},
            )
        with self.database.transaction() as connection:
            current = self._current_state_in_transaction(connection, marathon_id)
            if current not in {MarathonState.ACTIVE, MarathonState.PAUSED}:
                raise StateTransitionError("marathon cannot close from its current state")
            self._append_transition_in_transaction(
                connection,
                marathon_id,
                state=MarathonState.COMPLETE_PENDING_CERTIFICATION,
                transition_kind="CLOSE_PENDING_CERTIFICATION",
                decision_id=None,
                actor=actor,
                occurred_at=occurred_at,
                payload={
                    "completed_count": progress.completed_count,
                    "partition_count": progress.partition_count,
                    "census_certification": "NOT_PERFORMED",
                },
            )
        return self.get_plan(marathon_id)

    close = close_pending_certification

    def _verify_member_row(
        self,
        row: sqlite3.Row,
        *,
        expected: Mapping[str, Any],
        marathon_id: str,
        kind: str,
        ordinal: int,
        defects: list[str],
    ) -> None:
        material_json = str(row["material_json"])
        expected_json = canonical_json(dict(expected))
        if material_json != expected_json:
            defects.append(f"{kind}_MATERIAL_MISMATCH:{ordinal}")
        material_digest = hashlib.sha256(material_json.encode("utf-8")).hexdigest()
        if material_digest != str(row["material_sha256"]):
            defects.append(f"{kind}_DIGEST_MISMATCH:{ordinal}")
        if str(row["profile_id"]) != str(expected["profile_id"]):
            defects.append(f"{kind}_PROFILE_ID_MISMATCH:{ordinal}")
        if kind == "PROFILE" and str(row["profile_id"]) != str(expected["profile_id"]):
            defects.append(f"{kind}_ID_MISMATCH:{ordinal}")
        if kind == "PROFILE" and str(row["source_id"]) != str(expected["source_id"]):
            defects.append(f"{kind}_SOURCE_ID_MISMATCH:{ordinal}")
        if kind == "PARTITION" and str(row["partition_id"]) != str(
            expected["partition_id"]
        ):
            defects.append(f"{kind}_ID_MISMATCH:{ordinal}")
        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (str(row["ledger_event_id"]),),
        ).fetchone()
        if event is None:
            defects.append(f"{kind}_LEDGER_EVENT_MISSING:{ordinal}")
            return
        if (
            str(event["stream_id"]) != self._stream(marathon_id)
            or str(event["kind"]) != (
                "12A_RESEARCH_MARATHON_PROFILE_MEMBER_RECORDED"
                if kind == "PROFILE"
                else "12A_RESEARCH_MARATHON_PARTITION_MEMBER_RECORDED"
            )
            or str(event["record_hash"]) != str(row["ledger_hash"])
            or str(event["actor"]) != str(row["recorded_by"])
            or str(event["occurred_at"]) != str(row["recorded_at"])
        ):
            defects.append(f"{kind}_LEDGER_LINK_INVALID:{ordinal}")
        else:
            try:
                event_payload = json.loads(str(event["payload_json"]))
            except (TypeError, json.JSONDecodeError):
                defects.append(f"{kind}_LEDGER_PAYLOAD_INVALID:{ordinal}")
            else:
                expected_payload = {
                    "marathon_id": marathon_id,
                    "ordinal": ordinal,
                    "material_sha256": str(row["material_sha256"]),
                }
                if kind == "PROFILE":
                    expected_payload["profile_id"] = str(row["profile_id"])
                else:
                    expected_payload["partition_id"] = str(row["partition_id"])
                    expected_payload["profile_id"] = str(row["profile_id"])
                if event_payload != expected_payload:
                    defects.append(f"{kind}_LEDGER_PAYLOAD_MISMATCH:{ordinal}")

    def _verify_effects(
        self,
        plan: ResearchMarathonPlan,
        defects: list[str],
    ) -> None:
        rows = self.database.connection.execute(
            "SELECT * FROM durable_effects WHERE topic = ? ORDER BY effect_id",
            (self._topic(plan.marathon_id),),
        ).fetchall()
        if plan.state is MarathonState.PLANNED_NOT_STARTED:
            if rows:
                defects.append("OUTBOX_EFFECTS_EXIST_BEFORE_START")
            return
        expected = {
            partition.partition_id: partition for partition in plan.partitions
        }
        if len(rows) != len(expected):
            defects.append("OUTBOX_EFFECT_COUNT_MISMATCH")
        profiles = {profile.profile_id: profile for profile in plan.profiles}
        observed: set[str] = set()
        for row in rows:
            effect_id = str(row["effect_id"])
            payload = self._json_object(row["payload_json"], "outbox.payload_json")
            partition_id = payload.get("partition_id")
            if not isinstance(partition_id, str) or partition_id not in expected:
                defects.append(f"OUTBOX_PARTITION_UNKNOWN:{effect_id}")
                continue
            if partition_id in observed:
                defects.append(f"OUTBOX_PARTITION_DUPLICATE:{partition_id}")
            observed.add(partition_id)
            partition = expected[partition_id]
            profile = profiles.get(partition.profile_id)
            if profile is None:
                defects.append(f"OUTBOX_PROFILE_UNKNOWN:{partition_id}")
                continue
            expected_payload = {
                "marathon_id": plan.marathon_id,
                "partition_id": partition.partition_id,
                "profile_id": profile.profile_id,
                "source_id": profile.source_id,
                "request": dict(partition.request),
                "partition_material_sha256": sha256_digest(partition.material),
                "plan_payload_sha256": plan.payload_sha256,
                "max_attempts": int(plan.retry_policy["max_attempts"]),
                "request_timeout_seconds": plan.request_timeout_seconds,
            }
            if (
                effect_id != self._effect_id(plan.marathon_id, partition_id)
                or str(row["topic"]) != self._topic(plan.marathon_id)
                or payload != expected_payload
            ):
                defects.append(f"OUTBOX_PAYLOAD_MISMATCH:{partition_id}")
            expected_request_digest = sha256_digest(
                {
                    "effect_id": effect_id,
                    "topic": self._topic(plan.marathon_id),
                    "payload": expected_payload,
                    "max_attempts": int(plan.retry_policy["max_attempts"]),
                }
            )
            if str(row["request_digest"]) != expected_request_digest:
                defects.append(f"OUTBOX_REQUEST_DIGEST_MISMATCH:{partition_id}")
            completion = self.database.connection.execute(
                "SELECT result_digest FROM research_marathon_completions "
                "WHERE marathon_id = ? AND partition_id = ?",
                (plan.marathon_id, partition_id),
            ).fetchone()
            if completion is None and str(row["status"]) == EffectStatus.SUCCEEDED.value:
                defects.append(f"OUTBOX_SUCCEEDED_WITHOUT_PROOF:{partition_id}")
            if completion is not None and (
                str(row["status"]) != EffectStatus.SUCCEEDED.value
                or str(row["result_digest"]) != str(completion["result_digest"])
            ):
                defects.append(f"OUTBOX_COMPLETION_LINK_INVALID:{partition_id}")
        for partition_id in expected:
            if partition_id not in observed and plan.state is not MarathonState.PLANNED_NOT_STARTED:
                defects.append(f"OUTBOX_PARTITION_MISSING:{partition_id}")

    def _verify_attempts_and_completions(
        self, plan: ResearchMarathonPlan, defects: list[str]
    ) -> None:
        mappings = self.database.connection.execute(
            "SELECT * FROM research_marathon_partition_attempts "
            "WHERE marathon_id = ? ORDER BY partition_id, attempt_number",
            (plan.marathon_id,),
        ).fetchall()
        partitions = {partition.partition_id: partition for partition in plan.partitions}
        profiles = {profile.profile_id: profile for profile in plan.profiles}
        for mapping in mappings:
            attempt_id = str(mapping["attempt_id"])
            partition_id = str(mapping["partition_id"])
            partition = partitions.get(partition_id)
            profile = profiles.get(partition.profile_id) if partition is not None else None
            if (
                partition is None
                or profile is None
                or str(mapping["effect_id"]) != self._effect_id(plan.marathon_id, partition_id)
                or str(mapping["request_key"])
                != f"{plan.marathon_id}:{partition_id}:attempt:{int(mapping['attempt_number'])}"
                or str(mapping["source_id"]) != profile.source_id
            ):
                defects.append(f"ATTEMPT_BINDING_INVALID:{attempt_id}")
            attempt = self.database.connection.execute(
                "SELECT * FROM research_attempts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if attempt is None:
                defects.append(f"ATTEMPT_MISSING:{attempt_id}")
                continue
            try:
                request = self._json_object(attempt["request_json"], "research.request_json")
            except IntegrityError:
                defects.append(f"ATTEMPT_REQUEST_INVALID:{attempt_id}")
                continue
            expected_digest = sha256_digest(
                {
                    "campaign_id": plan.campaign_id,
                    "wave": int(attempt["wave"]),
                    "source_id": str(attempt["source_id"]),
                    "request": request,
                }
            )
            if str(attempt["request_digest"]) != expected_digest:
                defects.append(f"ATTEMPT_REQUEST_DIGEST_MISMATCH:{attempt_id}")
            if (
                str(attempt["campaign_id"]) != plan.campaign_id
                or str(attempt["request_key"]) != str(mapping["request_key"])
                or str(attempt["source_id"]) != str(mapping["source_id"])
            ):
                defects.append(f"ATTEMPT_MAPPING_MISMATCH:{attempt_id}")
            event = self.database.connection.execute(
                "SELECT * FROM ledger_events WHERE event_id = ?",
                (str(attempt["ledger_event_id"]),),
            ).fetchone()
            if event is None or str(event["record_hash"]) != str(attempt["ledger_hash"]):
                defects.append(f"ATTEMPT_LEDGER_LINK_INVALID:{attempt_id}")
            mapping_event = self.database.connection.execute(
                "SELECT * FROM ledger_events WHERE event_id = ?",
                (str(mapping["ledger_event_id"]),),
            ).fetchone()
            if mapping_event is None:
                defects.append(f"ATTEMPT_MAPPING_LEDGER_MISSING:{attempt_id}")
            else:
                expected_mapping_payload = {
                    "marathon_id": plan.marathon_id,
                    "partition_id": partition_id,
                    "effect_id": str(mapping["effect_id"]),
                    "attempt_number": int(mapping["attempt_number"]),
                    "attempt_id": attempt_id,
                    "request_key": str(mapping["request_key"]),
                    "worker_id": str(mapping["worker_id"]),
                    "source_id": str(mapping["source_id"]),
                }
                try:
                    observed_mapping_payload = json.loads(
                        str(mapping_event["payload_json"])
                    )
                except (TypeError, json.JSONDecodeError):
                    defects.append(f"ATTEMPT_MAPPING_LEDGER_PAYLOAD_INVALID:{attempt_id}")
                else:
                    if observed_mapping_payload != expected_mapping_payload:
                        defects.append(f"ATTEMPT_MAPPING_LEDGER_PAYLOAD_MISMATCH:{attempt_id}")
                if (
                    str(mapping_event["stream_id"])
                    != self._partition_stream(plan.marathon_id, partition_id)
                    or str(mapping_event["kind"])
                    != "12A_RESEARCH_MARATHON_PARTITION_ATTEMPT_BOUND"
                    or str(mapping_event["record_hash"]) != str(mapping["ledger_hash"])
                    or str(mapping_event["actor"]) != str(mapping["worker_id"])
                ):
                    defects.append(f"ATTEMPT_MAPPING_LEDGER_LINK_INVALID:{attempt_id}")
        completions = self.database.connection.execute(
            "SELECT * FROM research_marathon_completions "
            "WHERE marathon_id = ? ORDER BY partition_id",
            (plan.marathon_id,),
        ).fetchall()
        for completion in completions:
            partition_id = str(completion["partition_id"])
            mappings_for_partition = [
                row
                for row in mappings
                if str(row["partition_id"]) == partition_id
            ]
            if not mappings_for_partition:
                defects.append(f"COMPLETION_ATTEMPTS_MISSING:{partition_id}")
                continue
            try:
                evidence = self._partition_evidence(
                    self.database.connection,
                    marathon_id=plan.marathon_id,
                    partition_id=partition_id,
                    plan=plan,
                    mappings=mappings_for_partition,
                )
                if sha256_digest(evidence) != str(completion["result_digest"]):
                    defects.append(f"COMPLETION_DIGEST_MISMATCH:{partition_id}")
            except (IntegrityError, StateTransitionError, ValidationError) as exc:
                defects.append(f"COMPLETION_EVIDENCE_INVALID:{partition_id}:{exc}")
            event = self.database.connection.execute(
                "SELECT * FROM ledger_events WHERE event_id = ?",
                (str(completion["ledger_event_id"]),),
            ).fetchone()
            if event is None:
                defects.append(f"COMPLETION_LEDGER_LINK_INVALID:{partition_id}")
            else:
                try:
                    stored_attempt_ids = json.loads(str(completion["attempt_ids_json"]))
                    observed_completion_payload = json.loads(
                        str(event["payload_json"])
                    )
                except (TypeError, json.JSONDecodeError):
                    defects.append(f"COMPLETION_LEDGER_PAYLOAD_INVALID:{partition_id}")
                else:
                    expected_completion_payload = {
                        "marathon_id": plan.marathon_id,
                        "partition_id": partition_id,
                        "effect_id": str(completion["effect_id"]),
                        "result_digest": str(completion["result_digest"]),
                        "attempt_ids": stored_attempt_ids,
                    }
                    if observed_completion_payload != expected_completion_payload:
                        defects.append(f"COMPLETION_LEDGER_PAYLOAD_MISMATCH:{partition_id}")
                if (
                    str(event["stream_id"])
                    != self._partition_stream(plan.marathon_id, partition_id)
                    or str(event["kind"])
                    != "12A_RESEARCH_MARATHON_PARTITION_COMPLETED"
                    or str(event["record_hash"]) != str(completion["ledger_hash"])
                    or str(event["actor"]) != str(completion["actor"])
                    or str(event["occurred_at"]) != str(completion["occurred_at"])
                    or str(completion["effect_id"])
                    != self._effect_id(plan.marathon_id, partition_id)
                ):
                    defects.append(f"COMPLETION_LEDGER_LINK_INVALID:{partition_id}")

    def verify(self, marathon_id: str) -> ResearchMarathonVerification:
        marathon_id = self._required_text(marathon_id, "marathon_id")
        row = self.database.connection.execute(
            "SELECT * FROM research_marathons WHERE marathon_id = ?", (marathon_id,)
        ).fetchone()
        if row is None:
            return ResearchMarathonVerification(marathon_id, ("MARATHON_NOT_FOUND",))
        defects: list[str] = []
        try:
            stored_payload = bytes(row["payload"])
        except (TypeError, ValueError):
            stored_payload = b""
            defects.append("PLAN_PAYLOAD_TYPE_INVALID")
        try:
            stored_signature = bytes(row["signature"])
        except (TypeError, ValueError):
            stored_signature = b""
            defects.append("PLAN_SIGNATURE_TYPE_INVALID")
        try:
            parsed = self._parse_payload(stored_payload)
        except (IntegrityError, TypeError, ValueError, ValidationError, KeyError):
            parsed = None
            defects.append("PLAN_PAYLOAD_INVALID")
        if hashlib.sha256(stored_payload).hexdigest() != str(row["payload_sha256"]):
            defects.append("PLAN_PAYLOAD_DIGEST_MISMATCH")
        if hashlib.sha256(stored_signature).hexdigest() != str(row["signature_sha256"]):
            defects.append("PLAN_SIGNATURE_DIGEST_MISMATCH")
        try:
            root = self.continuity.verify_trust_root(str(row["key_id"]))
            if not root.ok:
                defects.extend(f"PLAN_TRUST_ROOT:{defect}" for defect in root.defects)
            root_row = self.database.connection.execute(
                "SELECT public_key_pem FROM continuity_trust_roots WHERE key_id = ?",
                (str(row["key_id"]),),
            ).fetchone()
            if root_row is None or not self.signature_verifier.verify(
                bytes(root_row["public_key_pem"]), stored_payload, stored_signature
            ):
                defects.append("PLAN_SIGNATURE_INVALID")
        except (IntegrityError, NotFoundError, TypeError, ValueError, sqlite3.Error):
            defects.append("PLAN_SIGNATURE_INVALID")
        try:
            c7_pack = self.final_pack.get_pack(str(row["c7_pack_id"]))
            c7_verification = self.final_pack.verify_pack(str(row["c7_pack_id"]))
            if not c7_verification.ok:
                defects.extend(f"C7:{defect}" for defect in c7_verification.defects)
            if (
                c7_pack.release_status != "NOT_RELEASED"
                or c7_pack.external_runtime_integration_status != "NOT_PROVEN"
                or c7_pack.live_census_certification_status != "NOT_PROVEN"
                or c7_pack.gate_effect != "C7_FINAL_PACK_ADMITTED_NOT_RELEASED"
            ):
                defects.append("C7_GATE_STATUS_INVALID")
        except (IntegrityError, NotFoundError, StateTransitionError, TypeError, ValueError):
            defects.append("C7_VERIFICATION_FAILED")
        admission_event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (str(row["ledger_event_id"]),),
        ).fetchone()
        if admission_event is None:
            defects.append("PLAN_LEDGER_EVENT_MISSING")
        else:
            try:
                admission_payload = json.loads(str(admission_event["payload_json"]))
            except (TypeError, json.JSONDecodeError):
                defects.append("PLAN_LEDGER_PAYLOAD_INVALID")
            else:
                expected_admission = {
                    "marathon_id": str(row["marathon_id"]),
                    "plan_version": str(row["plan_version"]),
                    "c7_pack_id": str(row["c7_pack_id"]),
                    "campaign_id": str(row["campaign_id"]),
                    "payload_sha256": str(row["payload_sha256"]),
                    "signature_sha256": str(row["signature_sha256"]),
                    "profile_count": self.database.connection.execute(
                        "SELECT COUNT(*) AS count FROM research_marathon_profiles "
                        "WHERE marathon_id = ?",
                        (marathon_id,),
                    ).fetchone()["count"],
                    "partition_count": self.database.connection.execute(
                        "SELECT COUNT(*) AS count FROM research_marathon_partitions "
                        "WHERE marathon_id = ?",
                        (marathon_id,),
                    ).fetchone()["count"],
                    "minimum_identity_target": int(row["minimum_identity_target"]),
                    "state": MarathonState.PLANNED_NOT_STARTED.value,
                    "gate_effect": str(row["gate_effect"]),
                }
                if admission_payload != expected_admission:
                    defects.append("PLAN_LEDGER_PAYLOAD_MISMATCH")
            if (
                str(admission_event["stream_id"]) != self._stream(marathon_id)
                or str(admission_event["kind"]) != "12A_RESEARCH_MARATHON_PLAN_ADMITTED"
                or str(admission_event["record_hash"]) != str(row["ledger_hash"])
                or str(admission_event["actor"]) != str(row["admitted_by"])
                or str(admission_event["occurred_at"]) != str(row["admitted_at"])
            ):
                defects.append("PLAN_LEDGER_LINK_INVALID")
        profile_rows: list[sqlite3.Row] = []
        partition_rows: list[sqlite3.Row] = []
        if parsed is not None:
            scalar_fields = (
                ("marathon_id", parsed.marathon_id),
                ("plan_version", parsed.plan_version),
                ("c7_pack_id", parsed.c7_pack_id),
                ("campaign_id", parsed.campaign_id),
                ("minimum_identity_target", parsed.minimum_identity_target),
                ("max_parallelism", parsed.max_parallelism),
                ("request_timeout_seconds", parsed.request_timeout_seconds),
                ("coordinator_identity", parsed.coordinator_identity),
                ("coordinator_environment", parsed.coordinator_environment),
                ("reviewer_identity", parsed.reviewer_identity),
                ("reviewer_environment", parsed.reviewer_environment),
                ("planned_at_utc", parsed.planned_at_utc),
                ("state", MarathonState.PLANNED_NOT_STARTED.value),
                ("gate_effect", parsed.gate_effect),
            )
            for field, expected_value in scalar_fields:
                if row[field] != expected_value:
                    defects.append(f"PLAN_{field.upper()}_MISMATCH")
            try:
                if json.loads(str(row["retry_policy_json"])) != dict(parsed.retry_policy):
                    defects.append("PLAN_RETRY_POLICY_MISMATCH")
                if json.loads(str(row["independence_basis_json"])) != dict(
                    parsed.independence_basis
                ):
                    defects.append("PLAN_INDEPENDENCE_BASIS_MISMATCH")
            except (TypeError, json.JSONDecodeError):
                defects.append("PLAN_STORED_JSON_INVALID")
            profile_rows = self.database.connection.execute(
                "SELECT * FROM research_marathon_profiles "
                "WHERE marathon_id = ? ORDER BY ordinal",
                (marathon_id,),
            ).fetchall()
            partition_rows = self.database.connection.execute(
                "SELECT * FROM research_marathon_partitions "
                "WHERE marathon_id = ? ORDER BY ordinal",
                (marathon_id,),
            ).fetchall()
            if len(profile_rows) != len(parsed.profiles):
                defects.append("PROFILE_COUNT_MISMATCH")
            if len(partition_rows) != len(parsed.partitions):
                defects.append("PARTITION_COUNT_MISMATCH")
            for ordinal, (member, expected) in enumerate(
                zip(profile_rows, parsed.profiles, strict=False)
            ):
                self._verify_member_row(
                    member,
                    expected=expected.material,
                    marathon_id=marathon_id,
                    kind="PROFILE",
                    ordinal=ordinal,
                    defects=defects,
                )
            for ordinal, (member, expected) in enumerate(
                zip(partition_rows, parsed.partitions, strict=False)
            ):
                self._verify_member_row(
                    member,
                    expected=expected.material,
                    marathon_id=marathon_id,
                    kind="PARTITION",
                    ordinal=ordinal,
                    defects=defects,
                )
            try:
                plan = self.get_plan(marathon_id)
                self._verify_effects(plan, defects)
                self._verify_attempts_and_completions(plan, defects)
            except (
                IntegrityError,
                NotFoundError,
                TypeError,
                ValueError,
                KeyError,
                sqlite3.Error,
            ):
                defects.append("MARATHON_RECORDS_INVALID")
                try:
                    state_row = self.database.connection.execute(
                        "SELECT state FROM research_marathon_transitions "
                        "WHERE marathon_id = ? ORDER BY sequence DESC LIMIT 1",
                        (marathon_id,),
                    ).fetchone()
                    state = (
                        MarathonState(str(state_row["state"]))
                        if state_row is not None
                        else MarathonState.PLANNED_NOT_STARTED
                    )
                    fallback_plan = self._plan_from_parsed_row(row, parsed, state)
                    self._verify_effects(fallback_plan, defects)
                    self._verify_attempts_and_completions(fallback_plan, defects)
                except (IntegrityError, NotFoundError, TypeError, ValueError, sqlite3.Error):
                    defects.append("MARATHON_RECORDS_UNRECONSTRUCTABLE")
        transition_rows = self.database.connection.execute(
            "SELECT * FROM research_marathon_transitions "
            "WHERE marathon_id = ? ORDER BY sequence",
            (marathon_id,),
        ).fetchall()
        if not transition_rows:
            defects.append("TRANSITIONS_MISSING")
        else:
            if str(transition_rows[0]["state"]) != MarathonState.PLANNED_NOT_STARTED.value:
                defects.append("TRANSITION_INITIAL_STATE_INVALID")
            prior_state: MarathonState | None = None
            for expected_sequence, transition in enumerate(transition_rows, start=1):
                if int(transition["sequence"]) != expected_sequence:
                    defects.append("TRANSITION_SEQUENCE_INVALID")
                try:
                    state = MarathonState(str(transition["state"]))
                except ValueError:
                    defects.append(f"TRANSITION_STATE_INVALID:{expected_sequence}")
                    continue
                if prior_state is not None:
                    valid_next = {
                        MarathonState.PLANNED_NOT_STARTED: {MarathonState.ACTIVE},
                        MarathonState.ACTIVE: {
                            MarathonState.ACTIVE,
                            MarathonState.PAUSED,
                            MarathonState.COMPLETE_PENDING_CERTIFICATION,
                        },
                        MarathonState.PAUSED: {
                            MarathonState.ACTIVE,
                            MarathonState.COMPLETE_PENDING_CERTIFICATION,
                        },
                        MarathonState.COMPLETE_PENDING_CERTIFICATION: set(),
                    }
                    if state not in valid_next[prior_state]:
                        defects.append(f"TRANSITION_STATE_REGRESSION:{expected_sequence}")
                prior_state = state
                event = self.database.connection.execute(
                    "SELECT * FROM ledger_events WHERE event_id = ?",
                    (str(transition["ledger_event_id"]),),
                ).fetchone()
                if event is None or str(event["record_hash"]) != str(transition["ledger_hash"]):
                    defects.append(f"TRANSITION_LEDGER_LINK_INVALID:{expected_sequence}")
                elif (
                    str(event["actor"]) != str(transition["actor"])
                    or str(event["occurred_at"]) != str(transition["occurred_at"])
                ):
                    defects.append(
                        f"TRANSITION_LEDGER_PROVENANCE_INVALID:{expected_sequence}"
                    )
                else:
                    try:
                        event_payload = json.loads(str(event["payload_json"]))
                        transition_payload = json.loads(str(transition["payload_json"]))
                    except (TypeError, json.JSONDecodeError):
                        defects.append(f"TRANSITION_PAYLOAD_INVALID:{expected_sequence}")
                    else:
                        expected_event_payload = {
                            "marathon_id": marathon_id,
                            "sequence": expected_sequence,
                            "state": state.value,
                            "transition_kind": str(transition["transition_kind"]),
                            "decision_id": (
                                str(transition["decision_id"])
                                if transition["decision_id"] is not None
                                else None
                            ),
                            "payload": transition_payload,
                        }
                        if event_payload != expected_event_payload:
                            defects.append(
                                f"TRANSITION_LEDGER_PAYLOAD_MISMATCH:{expected_sequence}"
                            )
                decision_id = transition["decision_id"]
                if decision_id is not None:
                    decision_verification = self.trust.verify_decision(str(decision_id))
                    if not decision_verification.ok:
                        defects.extend(
                            f"TRANSITION_DECISION:{expected_sequence}:{defect}"
                            for defect in decision_verification.defects
                        )
                    else:
                        try:
                            decision = self.trust.get_decision(str(decision_id))
                            transition_payload = json.loads(
                                str(transition["payload_json"])
                            )
                            if not isinstance(transition_payload, dict):
                                raise ValueError("transition payload must be an object")
                            action = transition_payload.get("action")
                            expected_context = {
                                "c7_pack_id": (
                                    parsed.c7_pack_id
                                    if parsed is not None
                                    else str(row["c7_pack_id"])
                                ),
                                "campaign_id": (
                                    parsed.campaign_id
                                    if parsed is not None
                                    else str(row["campaign_id"])
                                ),
                                "plan_payload_sha256": str(row["payload_sha256"]),
                                "source_profile_count": (
                                    len(parsed.profiles)
                                    if parsed is not None
                                    else len(profile_rows)
                                ),
                                "partition_count": (
                                    len(parsed.partitions)
                                    if parsed is not None
                                    else len(partition_rows)
                                ),
                                "minimum_identity_target": int(
                                    row["minimum_identity_target"]
                                ),
                                "max_parallelism": int(row["max_parallelism"]),
                            }
                            expected_request = AuthorizationRequest(
                                str(transition["actor"]),
                                str(action),
                                f"research:marathon:{marathon_id}",
                                context=expected_context,
                            )
                            if not decision.allowed or decision.request != expected_request:
                                defects.append(
                                    f"TRANSITION_DECISION_BINDING_INVALID:{expected_sequence}"
                                )
                        except (
                            IntegrityError,
                            NotFoundError,
                            TypeError,
                            ValueError,
                            json.JSONDecodeError,
                        ):
                            defects.append(
                                f"TRANSITION_DECISION_BINDING_INVALID:{expected_sequence}"
                            )
        try:
            chain = self.ledger.verify(self._stream(marathon_id))
            defects.extend(
                f"MARATHON_LEDGER_CHAIN:{getattr(defect, 'code', 'INVALID')}"
                for defect in chain.defects
            )
        except (IntegrityError, TypeError, ValueError, sqlite3.Error):
            defects.append("MARATHON_LEDGER_CHAIN_INVALID")
        return ResearchMarathonVerification(marathon_id, tuple(dict.fromkeys(defects)))
