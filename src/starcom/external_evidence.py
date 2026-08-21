from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import sqlite3
from typing import Any, Mapping

from .canonical import parse_strict_json_object, sha256_digest, utc_now
from .continuity_crypto import OpenSSLEd25519Verifier
from .errors import ConflictError, IntegrityError, NotFoundError, StateTransitionError, ValidationError


EXTERNAL_EVIDENCE_KINDS = (
    "LIVE_CENSUS_CERTIFICATION",
    "EXTERNAL_RUNTIME_INTEGRATION",
    "COMPONENT_ADOPTION",
    "REAL_DEPLOYMENT",
)
_KIND_SET = frozenset(EXTERNAL_EVIDENCE_KINDS)
_RESULT = "PROVEN"
_GATE_EFFECT = "EXTERNAL_EVIDENCE_ADMITTED_NO_RELEASE"
_EVENT_KIND = "EXTERNAL_EVIDENCE_ADMITTED"
_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
_MAX_SIGNATURE_BYTES = 1024
_SHA256_LENGTH = 64
_PAYLOAD_FIELDS = frozenset(
    {
        "evidence_id",
        "kind",
        "subject_id",
        "operator_identity",
        "reviewer_identity",
        "reviewer_environment",
        "captured_at_utc",
        "valid_until_utc",
        "claims",
        "evidence_items",
        "independence_basis",
        "result",
        "gate_effect",
    }
)
_CLAIM_FIELDS = {
    "LIVE_CENSUS_CERTIFICATION": frozenset(
        {"identity_count", "independent_certification", "census_digest", "certificate_digest"}
    ),
    "EXTERNAL_RUNTIME_INTEGRATION": frozenset(
        {"runtime", "version", "handshake", "health", "durable_roundtrip"}
    ),
    "COMPONENT_ADOPTION": frozenset(
        {"component", "version", "installation", "enablement", "rollback"}
    ),
    "REAL_DEPLOYMENT": frozenset(
        {"deployment", "node", "bundle", "health", "rollback"}
    ),
}
_ITEM_FIELDS = frozenset({"item_id", "kind", "digest", "media_type"})
_INDEPENDENCE_FIELDS = frozenset({"excluded_identities", "statement"})


@dataclass(frozen=True)
class ExternalEvidencePreparation:
    evidence_id: str
    kind: str
    subject_id: str
    gate_effect: str = _GATE_EFFECT


@dataclass(frozen=True)
class ExternalEvidenceRecord:
    evidence_id: str
    kind: str
    subject_id: str
    operator_identity: str
    reviewer_identity: str
    reviewer_environment: str
    captured_at_utc: str
    valid_until_utc: str
    claims: Mapping[str, object]
    evidence_items: tuple[Mapping[str, object], ...]
    independence_basis: Mapping[str, object]
    result: str
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
    def stream_id(self) -> str:
        return f"continuity:external-evidence:{self.evidence_id}"


@dataclass(frozen=True)
class ExternalEvidenceVerification:
    evidence_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class ExternalEvidenceService:
    """Immutable exact-byte authority for local external-evidence receipts."""

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
        self.continuity = next(
            (value for value in values if hasattr(value, "verify_trust_root")), None
        )
        if self.continuity is None:
            raise ValidationError("external evidence requires Continuity authority")
        self.signature_verifier = signature_verifier or getattr(
            self.continuity, "signature_verifier", OpenSSLEd25519Verifier()
        )
        self._initialize_schema()

    @staticmethod
    def _text(value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{field} must be a non-empty string")
        return value

    @classmethod
    def _digest(cls, value: object, field: str) -> str:
        value = cls._text(value, field)
        if len(value) != _SHA256_LENGTH or any(char not in "0123456789abcdef" for char in value):
            raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
        return value

    @classmethod
    def _bounded_bytes(cls, value: object, field: str, maximum: int) -> bytes:
        if not isinstance(value, bytes) or not value or len(value) > maximum:
            raise ValidationError(f"{field} must be non-empty bytes within the size limit")
        return value

    @staticmethod
    def _timestamp(value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{field} must be RFC 3339")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError(f"{field} must be RFC 3339") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValidationError(f"{field} must be timezone-aware")
        return value

    @classmethod
    def _sorted_strings(cls, value: object, field: str) -> list[str]:
        if not isinstance(value, list):
            raise ValidationError(f"{field} must be a sorted unique list")
        result = [cls._text(item, f"{field}[{index}]") for index, item in enumerate(value)]
        if result != sorted(result) or len(result) != len(set(result)):
            raise ValidationError(f"{field} must be sorted and unique")
        return result

    @classmethod
    def _parse_claims(cls, kind: str, value: object) -> dict[str, object]:
        if not isinstance(value, dict):
            raise ValidationError("claims must be an object")
        if frozenset(value) != _CLAIM_FIELDS[kind]:
            raise ValidationError("claims fields do not match the evidence category")
        result = dict(value)
        if kind == "LIVE_CENSUS_CERTIFICATION":
            count = result["identity_count"]
            if isinstance(count, bool) or not isinstance(count, int) or count < 800:
                raise ValidationError("census evidence requires at least 800 identities")
            if result["independent_certification"] is not True:
                raise ValidationError("census evidence requires independent certification")
            cls._digest(result["census_digest"], "claims.census_digest")
            cls._digest(result["certificate_digest"], "claims.certificate_digest")
        elif kind == "EXTERNAL_RUNTIME_INTEGRATION":
            for field in ("runtime", "version"):
                cls._text(result[field], f"claims.{field}")
            for field in ("handshake", "health", "durable_roundtrip"):
                if result[field] != "PASS":
                    raise ValidationError(f"claims.{field} must be PASS")
        elif kind == "COMPONENT_ADOPTION":
            for field in ("component", "version"):
                cls._text(result[field], f"claims.{field}")
            for field in ("installation", "enablement", "rollback"):
                if result[field] != "PASS":
                    raise ValidationError(f"claims.{field} must be PASS")
        else:
            for field in ("deployment", "node", "bundle"):
                cls._text(result[field], f"claims.{field}")
            for field in ("health", "rollback"):
                if result[field] != "PASS":
                    raise ValidationError(f"claims.{field} must be PASS")
        return result

    @classmethod
    def _parse_payload(cls, payload: bytes) -> dict[str, object]:
        value = parse_strict_json_object(
            payload, max_bytes=_MAX_PAYLOAD_BYTES, label="external evidence"
        )
        fields = frozenset(value)
        if fields != _PAYLOAD_FIELDS:
            raise ValidationError(
                "external evidence payload fields do not match the contract",
                {"missing": sorted(_PAYLOAD_FIELDS - fields), "unexpected": sorted(fields - _PAYLOAD_FIELDS)},
            )
        kind = cls._text(value["kind"], "kind")
        if kind not in _KIND_SET:
            raise ValidationError("kind is not a supported external evidence category")
        cls._text(value["evidence_id"], "evidence_id")
        cls._text(value["subject_id"], "subject_id")
        operator = cls._text(value["operator_identity"], "operator_identity")
        reviewer = cls._text(value["reviewer_identity"], "reviewer_identity")
        if operator == reviewer:
            raise ValidationError("operator and reviewer identities must be distinct")
        cls._text(value["reviewer_environment"], "reviewer_environment")
        captured = cls._timestamp(value["captured_at_utc"], "captured_at_utc")
        valid_until = cls._timestamp(value["valid_until_utc"], "valid_until_utc")
        if cls._dt(captured) > cls._dt(valid_until):
            raise ValidationError("captured_at_utc must not be after valid_until_utc")
        cls._parse_claims(kind, value["claims"])
        items = value["evidence_items"]
        if not isinstance(items, list) or not items:
            raise ValidationError("evidence_items must be a non-empty list")
        item_ids: list[str] = []
        for index, item in enumerate(items):
            if not isinstance(item, dict) or frozenset(item) != _ITEM_FIELDS:
                raise ValidationError(f"evidence_items[{index}] fields are invalid")
            item_ids.append(cls._text(item["item_id"], f"evidence_items[{index}].item_id"))
            cls._text(item["kind"], f"evidence_items[{index}].kind")
            cls._digest(item["digest"], f"evidence_items[{index}].digest")
            cls._text(item["media_type"], f"evidence_items[{index}].media_type")
        if item_ids != sorted(item_ids) or len(item_ids) != len(set(item_ids)):
            raise ValidationError("evidence_items must be sorted and unique")
        independence = value["independence_basis"]
        if not isinstance(independence, dict) or frozenset(independence) != _INDEPENDENCE_FIELDS:
            raise ValidationError("independence_basis fields are invalid")
        cls._sorted_strings(independence["excluded_identities"], "excluded_identities")
        cls._text(independence["statement"], "independence_basis.statement")
        if value["result"] != _RESULT or value["gate_effect"] != _GATE_EFFECT:
            raise ValidationError("external evidence result or gate effect is invalid")
        return value

    @staticmethod
    def _dt(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS external_evidence_records (
                    evidence_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL CHECK (kind IN (
                        'LIVE_CENSUS_CERTIFICATION',
                        'EXTERNAL_RUNTIME_INTEGRATION',
                        'COMPONENT_ADOPTION',
                        'REAL_DEPLOYMENT'
                    )),
                    subject_id TEXT NOT NULL,
                    operator_identity TEXT NOT NULL,
                    reviewer_identity TEXT NOT NULL,
                    reviewer_environment TEXT NOT NULL,
                    captured_at_utc TEXT NOT NULL,
                    valid_until_utc TEXT NOT NULL,
                    claims_json TEXT NOT NULL,
                    independence_basis_json TEXT NOT NULL,
                    result TEXT NOT NULL CHECK (result = 'PROVEN'),
                    gate_effect TEXT NOT NULL CHECK (gate_effect = 'EXTERNAL_EVIDENCE_ADMITTED_NO_RELEASE'),
                    key_id TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    payload_sha256 TEXT NOT NULL UNIQUE CHECK (length(payload_sha256) = 64),
                    signature BLOB NOT NULL,
                    signature_sha256 TEXT NOT NULL CHECK (length(signature_sha256) = 64),
                    admitted_at TEXT NOT NULL,
                    admitted_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    UNIQUE (kind, subject_id),
                    FOREIGN KEY (key_id) REFERENCES continuity_trust_roots(key_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS external_evidence_items (
                    evidence_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                    item_id TEXT NOT NULL,
                    item_kind TEXT NOT NULL,
                    digest TEXT NOT NULL CHECK (length(digest) = 64),
                    media_type TEXT NOT NULL,
                    material_json TEXT NOT NULL,
                    material_sha256 TEXT NOT NULL CHECK (length(material_sha256) = 64),
                    member_ledger_hash TEXT NOT NULL CHECK (length(member_ledger_hash) = 64),
                    PRIMARY KEY (evidence_id, ordinal),
                    UNIQUE (evidence_id, item_id),
                    FOREIGN KEY (evidence_id) REFERENCES external_evidence_records(evidence_id)
                )
                """
            )
            for table in ("external_evidence_records", "external_evidence_items"):
                connection.execute(
                    f"CREATE TRIGGER IF NOT EXISTS {table}_no_update BEFORE UPDATE ON {table} BEGIN "
                    f"SELECT RAISE(ABORT, '{table} rows are immutable'); END"
                )
                connection.execute(
                    f"CREATE TRIGGER IF NOT EXISTS {table}_no_delete BEFORE DELETE ON {table} BEGIN "
                    f"SELECT RAISE(ABORT, '{table} rows are immutable'); END"
                )

    @staticmethod
    def _stream(evidence_id: str) -> str:
        return f"continuity:external-evidence:{evidence_id}"

    def _assert_signature(self, key_id: str, payload: bytes, signature: bytes) -> None:
        root = self.continuity.verify_trust_root(key_id)
        if not getattr(root, "ok", False):
            raise IntegrityError(
                "external evidence trust root verification failed",
                {"key_id": key_id, "defects": list(getattr(root, "defects", ()))},
            )
        row = self.database.connection.execute(
            "SELECT public_key_pem FROM continuity_trust_roots WHERE key_id = ?", (key_id,)
        ).fetchone()
        if row is None or not self.signature_verifier.verify(
            bytes(row["public_key_pem"]), payload, signature
        ):
            raise IntegrityError("external evidence signature is invalid")

    @staticmethod
    def _record(row: sqlite3.Row) -> ExternalEvidenceRecord:
        try:
            claims = json.loads(str(row["claims_json"]))
            independence = json.loads(str(row["independence_basis_json"]))
        except json.JSONDecodeError as exc:
            raise IntegrityError("stored external evidence JSON is invalid") from exc
        if not isinstance(claims, dict) or not isinstance(independence, dict):
            raise IntegrityError("stored external evidence JSON shape is invalid")
        return ExternalEvidenceRecord(
            str(row["evidence_id"]), str(row["kind"]), str(row["subject_id"]),
            str(row["operator_identity"]), str(row["reviewer_identity"]),
            str(row["reviewer_environment"]), str(row["captured_at_utc"]),
            str(row["valid_until_utc"]), claims, (), independence,
            str(row["result"]), str(row["gate_effect"]), str(row["key_id"]),
            bytes(row["payload"]), str(row["payload_sha256"]), bytes(row["signature"]),
            str(row["signature_sha256"]), str(row["admitted_at"]), str(row["admitted_by"]),
            str(row["ledger_event_id"]), str(row["ledger_hash"]),
        )

    def get_evidence(self, evidence_id: str) -> ExternalEvidenceRecord:
        row = self.database.connection.execute(
            "SELECT * FROM external_evidence_records WHERE evidence_id = ?", (evidence_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("external evidence does not exist", {"evidence_id": evidence_id})
        record = self._record(row)
        items = self.database.connection.execute(
            "SELECT item_id, item_kind, digest, media_type FROM external_evidence_items "
            "WHERE evidence_id = ? ORDER BY ordinal", (evidence_id,)
        ).fetchall()
        return ExternalEvidenceRecord(
            **{**record.__dict__, "evidence_items": tuple(
                {"item_id": str(row["item_id"]), "kind": str(row["item_kind"]),
                 "digest": str(row["digest"]), "media_type": str(row["media_type"])}
                for row in items
            )}
        )

    def list_evidence(self) -> tuple[ExternalEvidenceRecord, ...]:
        rows = self.database.connection.execute(
            "SELECT evidence_id FROM external_evidence_records ORDER BY evidence_id"
        ).fetchall()
        return tuple(self.get_evidence(str(row["evidence_id"])) for row in rows)

    def prepare_evidence(self, evidence_id: str, kind: str, subject_id: str) -> ExternalEvidencePreparation:
        evidence_id = self._text(evidence_id, "evidence_id")
        kind = self._text(kind, "kind")
        if kind not in _KIND_SET:
            raise ValidationError("kind is not a supported external evidence category")
        return ExternalEvidencePreparation(evidence_id, kind, self._text(subject_id, "subject_id"))

    def admit_evidence(
        self,
        evidence_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        *,
        actor: str,
        occurred_at: str | None = None,
    ) -> ExternalEvidenceRecord:
        evidence_id = self._text(evidence_id, "evidence_id")
        key_id = self._text(key_id, "key_id")
        actor = self._text(actor, "actor")
        payload = self._bounded_bytes(payload, "payload", _MAX_PAYLOAD_BYTES)
        signature = self._bounded_bytes(signature, "signature", _MAX_SIGNATURE_BYTES)
        value = self._parse_payload(payload)
        if value["evidence_id"] != evidence_id:
            raise StateTransitionError("external evidence targets another identifier")
        admitted_at = self._timestamp(occurred_at or utc_now(), "occurred_at")
        if self._dt(str(value["valid_until_utc"])) < self._dt(admitted_at):
            raise StateTransitionError("external evidence is expired at admission")
        self._assert_signature(key_id, payload, signature)
        existing = self.database.connection.execute(
            "SELECT * FROM external_evidence_records WHERE evidence_id = ?", (evidence_id,)
        ).fetchone()
        if existing is not None:
            if (
                str(existing["key_id"]) == key_id
                and bytes(existing["payload"]) == payload
                and bytes(existing["signature"]) == signature
                and str(existing["admitted_by"]) == actor
            ):
                return self.get_evidence(evidence_id)
            raise ConflictError("external evidence identifier already binds different material")
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        signature_sha256 = hashlib.sha256(signature).hexdigest()
        items = value["evidence_items"]
        assert isinstance(items, list)
        with self.database.transaction() as connection:
            try:
                receipt = self.ledger.append_in_transaction(
                    connection,
                    self._stream(evidence_id),
                    _EVENT_KIND,
                    {
                        "evidence_id": evidence_id,
                        "kind": value["kind"],
                        "subject_id": value["subject_id"],
                        "payload_sha256": payload_sha256,
                        "signature_sha256": signature_sha256,
                        "key_id": key_id,
                        "result": _RESULT,
                        "gate_effect": _GATE_EFFECT,
                    },
                    actor=actor,
                    occurred_at=admitted_at,
                )
                connection.execute(
                    """
                    INSERT INTO external_evidence_records (
                        evidence_id, kind, subject_id, operator_identity, reviewer_identity,
                        reviewer_environment, captured_at_utc, valid_until_utc, claims_json,
                        independence_basis_json, result, gate_effect, key_id, payload,
                        payload_sha256, signature, signature_sha256, admitted_at, admitted_by,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence_id, value["kind"], value["subject_id"], value["operator_identity"],
                        value["reviewer_identity"], value["reviewer_environment"],
                        value["captured_at_utc"], value["valid_until_utc"],
                        json.dumps(value["claims"], sort_keys=True, separators=(",", ":")),
                        json.dumps(value["independence_basis"], sort_keys=True, separators=(",", ":")),
                        _RESULT, _GATE_EFFECT, key_id, sqlite3.Binary(payload), payload_sha256,
                        sqlite3.Binary(signature), signature_sha256, admitted_at, actor,
                        receipt.event_id, receipt.record_hash,
                    ),
                )
                for ordinal, item in enumerate(items):
                    assert isinstance(item, dict)
                    material = json.dumps(item, sort_keys=True, separators=(",", ":"))
                    connection.execute(
                        """
                        INSERT INTO external_evidence_items (
                            evidence_id, ordinal, item_id, item_kind, digest, media_type,
                            material_json, material_sha256, member_ledger_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            evidence_id, ordinal, item["item_id"], item["kind"], item["digest"],
                            item["media_type"], material, sha256_digest(item), receipt.record_hash,
                        ),
                    )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("external evidence violates a uniqueness constraint") from exc
        return self.get_evidence(evidence_id)

    @staticmethod
    def _event_payload(record: ExternalEvidenceRecord) -> dict[str, object]:
        return {
            "evidence_id": record.evidence_id,
            "kind": record.kind,
            "subject_id": record.subject_id,
            "payload_sha256": record.payload_sha256,
            "signature_sha256": record.signature_sha256,
            "key_id": record.key_id,
            "result": record.result,
            "gate_effect": record.gate_effect,
        }

    def verify_evidence(
        self, evidence_id: str, *, as_of: str | None = None
    ) -> ExternalEvidenceVerification:
        defects: list[str] = []
        observed_at = self._timestamp(as_of or utc_now(), "as_of")
        row = self.database.connection.execute(
            "SELECT * FROM external_evidence_records WHERE evidence_id = ?", (evidence_id,)
        ).fetchone()
        if row is None:
            return ExternalEvidenceVerification(evidence_id, ("EVIDENCE_NOT_FOUND",))
        try:
            record = self.get_evidence(evidence_id)
            value = self._parse_payload(record.payload)
        except (ValidationError, IntegrityError) as exc:
            return ExternalEvidenceVerification(evidence_id, (f"PAYLOAD_INVALID:{type(exc).__name__}",))
        if value["evidence_id"] != record.evidence_id:
            defects.append("PAYLOAD_EVIDENCE_ID_MISMATCH")
        bindings = {
            "kind": record.kind,
            "subject_id": record.subject_id,
            "operator_identity": record.operator_identity,
            "reviewer_identity": record.reviewer_identity,
            "reviewer_environment": record.reviewer_environment,
            "captured_at_utc": record.captured_at_utc,
            "valid_until_utc": record.valid_until_utc,
            "claims": dict(record.claims),
            "independence_basis": dict(record.independence_basis),
            "result": record.result,
            "gate_effect": record.gate_effect,
        }
        for field, expected in bindings.items():
            if value.get(field) != expected:
                defects.append(f"PAYLOAD_BINDING_MISMATCH:{field}")
        if hashlib.sha256(record.payload).hexdigest() != record.payload_sha256:
            defects.append("PAYLOAD_DIGEST_MISMATCH")
        if hashlib.sha256(record.signature).hexdigest() != record.signature_sha256:
            defects.append("SIGNATURE_DIGEST_MISMATCH")
        try:
            self._assert_signature(record.key_id, record.payload, record.signature)
        except IntegrityError:
            defects.append("SIGNATURE_INVALID")
        if self._dt(record.valid_until_utc) < self._dt(observed_at):
            defects.append("EVIDENCE_EXPIRED")
        if record.operator_identity == record.reviewer_identity:
            defects.append("IDENTITIES_NOT_INDEPENDENT")
        expected_items = value["evidence_items"]
        if tuple(expected_items) != record.evidence_items:
            defects.append("ITEM_MEMBERSHIP_MISMATCH")
        for ordinal, item in enumerate(record.evidence_items):
            stored = self.database.connection.execute(
                "SELECT material_json, material_sha256, member_ledger_hash FROM external_evidence_items "
                "WHERE evidence_id = ? AND ordinal = ?", (evidence_id, ordinal)
            ).fetchone()
            if stored is None:
                defects.append(f"ITEM_MISSING:{ordinal}")
                continue
            if sha256_digest(item) != str(stored["material_sha256"]):
                defects.append(f"ITEM_DIGEST_MISMATCH:{ordinal}")
            if str(stored["member_ledger_hash"]) != record.ledger_hash:
                defects.append(f"ITEM_LEDGER_HASH_MISMATCH:{ordinal}")
        stream = self._stream(evidence_id)
        events = self.ledger.read_stream(stream)
        if len(events) != 1:
            defects.append("LEDGER_EVENT_COUNT_MISMATCH")
        else:
            event = events[0]
            if event.kind != _EVENT_KIND or event.actor != record.admitted_by:
                defects.append("LEDGER_EVENT_PROVENANCE_MISMATCH")
            if event.payload != self._event_payload(record):
                defects.append("LEDGER_EVENT_PAYLOAD_MISMATCH")
            if event.record_hash != record.ledger_hash or event.event_id != record.ledger_event_id:
                defects.append("LEDGER_RECEIPT_MISMATCH")
        chain = self.ledger.verify(stream)
        if not chain.ok:
            defects.extend(f"LEDGER_INVALID:{defect.code}" for defect in chain.defects)
        return ExternalEvidenceVerification(evidence_id, tuple(sorted(set(defects))))

    def snapshot(self, *, as_of: str | None = None) -> dict[str, str]:
        observed_at = self._timestamp(as_of or utc_now(), "as_of")
        result = {kind: "NOT_PROVEN" for kind in EXTERNAL_EVIDENCE_KINDS}
        rows = self.database.connection.execute(
            "SELECT evidence_id, kind, valid_until_utc FROM external_evidence_records "
            "ORDER BY kind, captured_at_utc DESC, evidence_id"
        ).fetchall()
        for row in rows:
            kind = str(row["kind"])
            evidence_id = str(row["evidence_id"])
            if result[kind] == "PROVEN" or self._dt(str(row["valid_until_utc"])) < self._dt(observed_at):
                continue
            if self.verify_evidence(evidence_id, as_of=observed_at).ok:
                result[kind] = "PROVEN"
        return result


__all__ = [
    "EXTERNAL_EVIDENCE_KINDS",
    "ExternalEvidencePreparation",
    "ExternalEvidenceRecord",
    "ExternalEvidenceService",
    "ExternalEvidenceVerification",
]
