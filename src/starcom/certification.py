from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re
import sqlite3
from typing import Any, Mapping

from .canonical import canonical_json, sha256_digest, utc_now
from .census import C2CensusService
from .continuity import ContinuityService
from .db import Database
from .errors import (
    ConflictError,
    IntegrityError,
    NotFoundError,
    StateTransitionError,
    ValidationError,
)
from .ledger import EventLedger
from .recollection import C2RecollectionService


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
_MAX_SIGNATURE_BYTES = 1024
_REQUIRED_PAYLOAD_FIELDS = frozenset(
    {
        "certificate_id",
        "recollection_id",
        "incident_id",
        "campaign_id",
        "identity_count",
        "required_target",
        "identity_set_digest",
        "certifier_identity",
        "certifier_environment",
        "certified_at_utc",
        "independence_basis",
        "independent_identity_status",
        "census_verification_result",
        "verdict",
        "gate_effect",
    }
)


@dataclass(frozen=True)
class C2CertificationSnapshot:
    recollection_id: str
    incident_id: str
    campaign_id: str
    identity_count: int
    required_target: int
    identity_set_digest: str
    latest_identity_at: str | None
    members: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class C2CertificationRecord:
    certificate_id: str
    recollection_id: str
    incident_id: str
    campaign_id: str
    key_id: str
    payload_sha256: str
    signature_sha256: str
    certifier_identity: str
    identity_count: int
    required_target: int
    identity_set_digest: str
    certified_at_utc: str
    admitted_at: str
    admitted_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C2CertificationVerification:
    certificate_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C2CertificationService:
    """Admit exact-byte independent signatures over immutable C2 census snapshots."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        continuity: ContinuityService,
        recollection: C2RecollectionService,
        census: C2CensusService,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.continuity = continuity
        self.recollection = recollection
        self.census = census
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
    def _bounded_bytes(value: bytes, field: str, maximum: int) -> bytes:
        if not isinstance(value, bytes) or not value or len(value) > maximum:
            raise ValidationError(
                f"{field} must be non-empty bytes within the size limit",
                {"maximum_bytes": maximum},
            )
        return value

    @staticmethod
    def _digest(value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c2_certifications (
                    certificate_id TEXT PRIMARY KEY,
                    recollection_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
                    signature BLOB NOT NULL,
                    signature_sha256 TEXT NOT NULL CHECK (length(signature_sha256) = 64),
                    certifier_identity TEXT NOT NULL,
                    certifier_environment TEXT NOT NULL,
                    identity_count INTEGER NOT NULL CHECK (identity_count >= 0),
                    required_target INTEGER NOT NULL CHECK (required_target >= 800),
                    identity_set_digest TEXT NOT NULL CHECK (length(identity_set_digest) = 64),
                    certified_at_utc TEXT NOT NULL,
                    independence_basis TEXT NOT NULL,
                    independent_identity_status TEXT NOT NULL
                        CHECK (independent_identity_status = 'SATISFIED'),
                    census_verification_result TEXT NOT NULL
                        CHECK (census_verification_result = 'PASS'),
                    verdict TEXT NOT NULL CHECK (verdict = 'C2_CENSUS_CERTIFIED'),
                    gate_effect TEXT NOT NULL CHECK (gate_effect = 'NO_CANONICAL_PROMOTION'),
                    admitted_at TEXT NOT NULL,
                    admitted_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (recollection_id)
                        REFERENCES c2_recollections(recollection_id),
                    FOREIGN KEY (key_id) REFERENCES continuity_trust_roots(key_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c2_certification_members (
                    certificate_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                    identity_id TEXT NOT NULL,
                    identity_key TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    attempt_id TEXT NOT NULL,
                    observation_id TEXT NOT NULL,
                    evidence_digest TEXT NOT NULL CHECK (length(evidence_digest) = 64),
                    recorded_at TEXT NOT NULL,
                    recorded_by TEXT NOT NULL,
                    identity_ledger_hash TEXT NOT NULL
                        CHECK (length(identity_ledger_hash) = 64),
                    material_json TEXT NOT NULL,
                    material_sha256 TEXT NOT NULL CHECK (length(material_sha256) = 64),
                    PRIMARY KEY (certificate_id, ordinal),
                    UNIQUE (certificate_id, identity_id),
                    FOREIGN KEY (certificate_id)
                        REFERENCES c2_certifications(certificate_id),
                    FOREIGN KEY (identity_id)
                        REFERENCES c2_census_identities(identity_id)
                )
                """
            )
            for table in ("c2_certifications", "c2_certification_members"):
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {table}_no_update
                    BEFORE UPDATE ON {table}
                    BEGIN SELECT RAISE(ABORT, '{table} records are immutable'); END
                    """
                )
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {table}_no_delete
                    BEFORE DELETE ON {table}
                    BEGIN SELECT RAISE(ABORT, '{table} records are immutable'); END
                    """
                )

    @staticmethod
    def _member_material(row: sqlite3.Row) -> dict[str, object]:
        return {
            "identity_id": str(row["identity_id"]),
            "identity_key": str(row["identity_key"]),
            "source_id": str(row["source_id"]),
            "attempt_id": str(row["attempt_id"]),
            "observation_id": str(row["observation_id"]),
            "evidence_digest": str(row["evidence_digest"]),
            "recorded_at": str(row["recorded_at"]),
            "recorded_by": str(row["recorded_by"]),
            "ledger_hash": str(row["ledger_hash"]),
        }

    def _snapshot_from_connection(
        self,
        connection: sqlite3.Connection,
        recollection_id: str,
    ) -> C2CertificationSnapshot:
        recollection_row = connection.execute(
            "SELECT * FROM c2_recollections WHERE recollection_id = ?",
            (recollection_id,),
        ).fetchone()
        if recollection_row is None:
            raise NotFoundError(
                "C2 recollection does not exist",
                {"recollection_id": recollection_id},
            )
        rows = connection.execute(
            """
            SELECT * FROM c2_census_identities
            WHERE recollection_id = ?
            ORDER BY identity_key, identity_id
            """,
            (recollection_id,),
        ).fetchall()
        members = tuple(self._member_material(row) for row in rows)
        latest_identity_at = max(
            (str(row["recorded_at"]) for row in rows),
            default=None,
        )
        return C2CertificationSnapshot(
            recollection_id=recollection_id,
            incident_id=str(recollection_row["incident_id"]),
            campaign_id=str(recollection_row["campaign_id"]),
            identity_count=len(members),
            required_target=int(recollection_row["minimum_identity_target"]),
            identity_set_digest=sha256_digest(list(members)),
            latest_identity_at=latest_identity_at,
            members=members,
        )

    def snapshot(self, recollection_id: str) -> C2CertificationSnapshot:
        recollection_id = self._required_text(recollection_id, "recollection_id")
        verification = self.census.verify(recollection_id)
        if not verification.ok:
            raise IntegrityError(
                "C2 census verification failed",
                {
                    "recollection_id": recollection_id,
                    "defects": list(verification.defects),
                },
            )
        return self._snapshot_from_connection(
            self.database.connection,
            recollection_id,
        )

    @staticmethod
    def _decode_payload(payload: bytes) -> dict[str, object]:
        def object_without_duplicates(
            pairs: list[tuple[str, object]],
        ) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate key: {key}")
                result[key] = value
            return result

        try:
            decoded = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=object_without_duplicates,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValidationError("C2 certification payload must be valid UTF-8 JSON") from exc
        if not isinstance(decoded, dict):
            raise ValidationError("C2 certification payload must be a JSON object")
        observed = frozenset(decoded)
        if observed != _REQUIRED_PAYLOAD_FIELDS:
            raise ValidationError(
                "C2 certification payload fields do not match the required contract",
                {
                    "missing": sorted(_REQUIRED_PAYLOAD_FIELDS - observed),
                    "unexpected": sorted(observed - _REQUIRED_PAYLOAD_FIELDS),
                },
            )
        return decoded

    def _parse_payload(self, payload: bytes) -> dict[str, object]:
        value = self._decode_payload(payload)
        for field in (
            "certificate_id",
            "recollection_id",
            "incident_id",
            "campaign_id",
            "identity_set_digest",
            "certifier_identity",
            "certifier_environment",
            "certified_at_utc",
            "independence_basis",
            "independent_identity_status",
            "census_verification_result",
            "verdict",
            "gate_effect",
        ):
            value[field] = self._required_text(value[field], field)
        for field in ("identity_count", "required_target"):
            field_value = value[field]
            if type(field_value) is not int or field_value < 0:
                raise ValidationError(f"{field} must be an integer >= 0")
        if int(value["required_target"]) < 800:
            raise ValidationError("required_target must be >= 800")
        if not _SHA256.fullmatch(str(value["identity_set_digest"])):
            raise ValidationError("identity_set_digest must be a lowercase SHA-256 digest")
        value["certified_at_utc"] = self._timestamp(
            value["certified_at_utc"],
            "certified_at_utc",
        )
        expected_constants = {
            "independent_identity_status": "SATISFIED",
            "census_verification_result": "PASS",
            "verdict": "C2_CENSUS_CERTIFIED",
            "gate_effect": "NO_CANONICAL_PROMOTION",
        }
        for field, expected in expected_constants.items():
            if value[field] != expected:
                raise ValidationError(f"{field} must equal {expected}")
        return value

    @staticmethod
    def _record_from_row(row: sqlite3.Row) -> C2CertificationRecord:
        return C2CertificationRecord(
            certificate_id=str(row["certificate_id"]),
            recollection_id=str(row["recollection_id"]),
            incident_id=str(row["incident_id"]),
            campaign_id=str(row["campaign_id"]),
            key_id=str(row["key_id"]),
            payload_sha256=str(row["payload_sha256"]),
            signature_sha256=str(row["signature_sha256"]),
            certifier_identity=str(row["certifier_identity"]),
            identity_count=int(row["identity_count"]),
            required_target=int(row["required_target"]),
            identity_set_digest=str(row["identity_set_digest"]),
            certified_at_utc=str(row["certified_at_utc"]),
            admitted_at=str(row["admitted_at"]),
            admitted_by=str(row["admitted_by"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def get_certificate(self, certificate_id: str) -> C2CertificationRecord:
        certificate_id = self._required_text(certificate_id, "certificate_id")
        row = self.database.connection.execute(
            "SELECT * FROM c2_certifications WHERE certificate_id = ?",
            (certificate_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C2 certification does not exist",
                {"certificate_id": certificate_id},
            )
        return self._record_from_row(row)

    def _assert_trust_root(self, key_id: str) -> bytes:
        verification = self.continuity.verify_trust_root(key_id)
        if not verification.ok:
            raise IntegrityError(
                "certifier trust root verification failed",
                {"key_id": key_id, "defects": list(verification.defects)},
            )
        row = self.database.connection.execute(
            "SELECT public_key_pem FROM continuity_trust_roots WHERE key_id = ?",
            (key_id,),
        ).fetchone()
        if row is None:
            raise IntegrityError("certifier trust root verification failed", {"key_id": key_id})
        return bytes(row["public_key_pem"])

    @staticmethod
    def _assert_payload_matches_snapshot(
        value: Mapping[str, object],
        snapshot: C2CertificationSnapshot,
    ) -> None:
        expected = {
            "recollection_id": snapshot.recollection_id,
            "incident_id": snapshot.incident_id,
            "campaign_id": snapshot.campaign_id,
            "identity_count": snapshot.identity_count,
            "required_target": snapshot.required_target,
            "identity_set_digest": snapshot.identity_set_digest,
        }
        mismatches = {
            field: {"expected": expected_value, "observed": value[field]}
            for field, expected_value in expected.items()
            if value[field] != expected_value
        }
        if mismatches:
            raise StateTransitionError(
                "signed C2 certification does not match the current census snapshot",
                {"mismatches": mismatches},
            )

    def _assert_independent(
        self,
        certifier_identity: str,
        snapshot: C2CertificationSnapshot,
    ) -> None:
        recollection = self.recollection.get(snapshot.recollection_id)
        disallowed = {recollection.started_by.strip()}
        disallowed.update(
            str(member["recorded_by"]).strip() for member in snapshot.members
        )
        if certifier_identity.strip() in disallowed:
            raise StateTransitionError(
                "certifier identity is not independent",
                {
                    "certifier_identity": certifier_identity,
                    "disallowed_identities": sorted(disallowed),
                },
            )

    @staticmethod
    def _ledger_payload(record: C2CertificationRecord) -> dict[str, object]:
        return {
            "certificate_id": record.certificate_id,
            "recollection_id": record.recollection_id,
            "key_id": record.key_id,
            "payload_sha256": record.payload_sha256,
            "signature_sha256": record.signature_sha256,
            "identity_count": record.identity_count,
            "required_target": record.required_target,
            "identity_set_digest": record.identity_set_digest,
            "verdict": "C2_CENSUS_CERTIFIED",
        }

    def admit_certification(
        self,
        recollection_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        *,
        actor: str,
        occurred_at: str | None = None,
    ) -> C2CertificationRecord:
        recollection_id = self._required_text(recollection_id, "recollection_id")
        key_id = self._required_text(key_id, "key_id")
        actor = self._required_text(actor, "actor")
        payload = self._bounded_bytes(payload, "payload", _MAX_PAYLOAD_BYTES)
        signature = self._bounded_bytes(signature, "signature", _MAX_SIGNATURE_BYTES)
        occurred_at = self._timestamp(occurred_at or utc_now())
        value = self._parse_payload(payload)
        if value["recollection_id"] != recollection_id:
            raise StateTransitionError(
                "signed C2 certification targets another recollection"
            )
        certificate_id = str(value["certificate_id"])
        payload_sha256 = self._digest(payload)
        signature_sha256 = self._digest(signature)

        existing = self.database.connection.execute(
            "SELECT * FROM c2_certifications WHERE certificate_id = ?",
            (certificate_id,),
        ).fetchone()
        if existing is not None:
            exact = (
                str(existing["recollection_id"]) == recollection_id
                and str(existing["key_id"]) == key_id
                and bytes(existing["payload"]) == payload
                and bytes(existing["signature"]) == signature
                and str(existing["payload_sha256"]) == payload_sha256
                and str(existing["signature_sha256"]) == signature_sha256
            )
            if not exact:
                raise ConflictError(
                    "certificate_id was reused with different certification material",
                    {"certificate_id": certificate_id},
                )
            verification = self.verify_certificate(certificate_id)
            if not verification.ok:
                raise IntegrityError(
                    "existing C2 certification failed verification",
                    {
                        "certificate_id": certificate_id,
                        "defects": list(verification.defects),
                    },
                )
            return self._record_from_row(existing)

        public_key = self._assert_trust_root(key_id)
        if not self.continuity.signature_verifier.verify(public_key, payload, signature):
            raise IntegrityError("C2 certification signature is invalid")

        snapshot = self.snapshot(recollection_id)
        if snapshot.identity_count < snapshot.required_target:
            raise StateTransitionError(
                "C2 census is not eligible for independent certification",
                {
                    "identity_count": snapshot.identity_count,
                    "required_target": snapshot.required_target,
                },
            )
        self._assert_payload_matches_snapshot(value, snapshot)
        certifier_identity = str(value["certifier_identity"])
        self._assert_independent(certifier_identity, snapshot)
        certified_at_utc = str(value["certified_at_utc"])
        if (
            snapshot.latest_identity_at is not None
            and self._as_datetime(certified_at_utc)
            < self._as_datetime(snapshot.latest_identity_at)
        ):
            raise StateTransitionError(
                "certification predates the latest certified census identity"
            )

        try:
            with self.database.transaction() as connection:
                race = connection.execute(
                    "SELECT * FROM c2_certifications WHERE certificate_id = ?",
                    (certificate_id,),
                ).fetchone()
                if race is not None:
                    raise ConflictError(
                        "C2 certification appeared during admission",
                        {"certificate_id": certificate_id},
                    )
                current_public_key = self._assert_trust_root(key_id)
                if not self.continuity.signature_verifier.verify(
                    current_public_key,
                    payload,
                    signature,
                ):
                    raise IntegrityError("C2 certification signature is invalid")
                current_census_verification = self.census.verify(recollection_id)
                if not current_census_verification.ok:
                    raise IntegrityError(
                        "C2 census verification failed",
                        {
                            "recollection_id": recollection_id,
                            "defects": list(current_census_verification.defects),
                        },
                    )
                current_snapshot = self._snapshot_from_connection(
                    connection,
                    recollection_id,
                )
                if current_snapshot != snapshot:
                    raise ConflictError(
                        "C2 census changed during certification admission",
                        {"recollection_id": recollection_id},
                    )
                provisional = C2CertificationRecord(
                    certificate_id=certificate_id,
                    recollection_id=recollection_id,
                    incident_id=snapshot.incident_id,
                    campaign_id=snapshot.campaign_id,
                    key_id=key_id,
                    payload_sha256=payload_sha256,
                    signature_sha256=signature_sha256,
                    certifier_identity=certifier_identity,
                    identity_count=snapshot.identity_count,
                    required_target=snapshot.required_target,
                    identity_set_digest=snapshot.identity_set_digest,
                    certified_at_utc=certified_at_utc,
                    admitted_at=occurred_at,
                    admitted_by=actor,
                    ledger_event_id="pending",
                    ledger_hash="pending",
                )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"continuity:c2:{recollection_id}:certification",
                    "C2_CENSUS_CERTIFICATION_ADMITTED",
                    self._ledger_payload(provisional),
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO c2_certifications (
                        certificate_id, recollection_id, incident_id, campaign_id,
                        key_id, payload, payload_sha256, signature, signature_sha256,
                        certifier_identity, certifier_environment, identity_count,
                        required_target, identity_set_digest, certified_at_utc,
                        independence_basis, independent_identity_status,
                        census_verification_result, verdict, gate_effect,
                        admitted_at, admitted_by, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        certificate_id,
                        recollection_id,
                        snapshot.incident_id,
                        snapshot.campaign_id,
                        key_id,
                        payload,
                        payload_sha256,
                        signature,
                        signature_sha256,
                        certifier_identity,
                        str(value["certifier_environment"]),
                        snapshot.identity_count,
                        snapshot.required_target,
                        snapshot.identity_set_digest,
                        certified_at_utc,
                        str(value["independence_basis"]),
                        str(value["independent_identity_status"]),
                        str(value["census_verification_result"]),
                        str(value["verdict"]),
                        str(value["gate_effect"]),
                        occurred_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
                for ordinal, member in enumerate(snapshot.members):
                    material_json = canonical_json(dict(member))
                    connection.execute(
                        """
                        INSERT INTO c2_certification_members (
                            certificate_id, ordinal, identity_id, identity_key,
                            source_id, attempt_id, observation_id, evidence_digest,
                            recorded_at, recorded_by, identity_ledger_hash,
                            material_json, material_sha256
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            certificate_id,
                            ordinal,
                            str(member["identity_id"]),
                            str(member["identity_key"]),
                            str(member["source_id"]),
                            str(member["attempt_id"]),
                            str(member["observation_id"]),
                            str(member["evidence_digest"]),
                            str(member["recorded_at"]),
                            str(member["recorded_by"]),
                            str(member["ledger_hash"]),
                            material_json,
                            sha256_digest(dict(member)),
                        ),
                    )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "C2 certification or membership already exists",
                {"certificate_id": certificate_id},
            ) from exc
        return self.get_certificate(certificate_id)

    @staticmethod
    def _member_from_snapshot_row(row: sqlite3.Row) -> dict[str, object]:
        return {
            "identity_id": str(row["identity_id"]),
            "identity_key": str(row["identity_key"]),
            "source_id": str(row["source_id"]),
            "attempt_id": str(row["attempt_id"]),
            "observation_id": str(row["observation_id"]),
            "evidence_digest": str(row["evidence_digest"]),
            "recorded_at": str(row["recorded_at"]),
            "recorded_by": str(row["recorded_by"]),
            "ledger_hash": str(row["identity_ledger_hash"]),
        }

    def verify_certificate(self, certificate_id: str) -> C2CertificationVerification:
        certificate_id = self._required_text(certificate_id, "certificate_id")
        row = self.database.connection.execute(
            "SELECT * FROM c2_certifications WHERE certificate_id = ?",
            (certificate_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C2 certification does not exist",
                {"certificate_id": certificate_id},
            )
        record = self._record_from_row(row)
        defects: list[str] = []
        payload = bytes(row["payload"])
        signature = bytes(row["signature"])
        if self._digest(payload) != record.payload_sha256:
            defects.append("C2_CERT_PAYLOAD_DIGEST_MISMATCH")
        if self._digest(signature) != record.signature_sha256:
            defects.append("C2_CERT_SIGNATURE_DIGEST_MISMATCH")

        parsed: dict[str, object] | None = None
        try:
            parsed = self._parse_payload(payload)
        except ValidationError:
            defects.append("C2_CERT_PAYLOAD_INVALID")

        root_verification = self.continuity.verify_trust_root(record.key_id)
        defects.extend(
            f"C2_CERT_TRUST_ROOT:{defect}"
            for defect in root_verification.defects
        )
        root = self.database.connection.execute(
            "SELECT public_key_pem FROM continuity_trust_roots WHERE key_id = ?",
            (record.key_id,),
        ).fetchone()
        if root is None:
            defects.append("C2_CERT_TRUST_ROOT_MISSING")
        elif not self.continuity.signature_verifier.verify(
            bytes(root["public_key_pem"]),
            payload,
            signature,
        ):
            defects.append("C2_CERT_SIGNATURE_INVALID")

        recollection = None
        try:
            recollection = self.recollection.get(record.recollection_id)
        except NotFoundError:
            defects.append("C2_CERT_RECOLLECTION_MISSING")
        else:
            recollection_verification = self.recollection.verify(record.recollection_id)
            defects.extend(
                f"C2_CERT_RECOLLECTION:{defect}"
                for defect in recollection_verification.defects
            )
            if recollection.incident_id != record.incident_id:
                defects.append("C2_CERT_INCIDENT_MISMATCH")
            if recollection.campaign_id != record.campaign_id:
                defects.append("C2_CERT_CAMPAIGN_MISMATCH")
            if recollection.minimum_identity_target != record.required_target:
                defects.append("C2_CERT_REQUIRED_TARGET_MISMATCH")

        try:
            census_verification = self.census.verify(record.recollection_id)
        except NotFoundError:
            defects.append("C2_CERT_CENSUS_MISSING")
        else:
            defects.extend(
                f"C2_CERT_CENSUS:{defect}"
                for defect in census_verification.defects
            )

        member_rows = self.database.connection.execute(
            """
            SELECT * FROM c2_certification_members
            WHERE certificate_id = ? ORDER BY ordinal
            """,
            (certificate_id,),
        ).fetchall()
        if len(member_rows) != record.identity_count:
            defects.append("C2_CERT_MEMBER_COUNT_MISMATCH")
        materials: list[dict[str, object]] = []
        represented_actors: set[str] = set()
        for expected_ordinal, member_row in enumerate(member_rows):
            ordinal = int(member_row["ordinal"])
            if ordinal != expected_ordinal:
                defects.append(
                    f"C2_CERT_MEMBER_ORDINAL_MISMATCH:{expected_ordinal}"
                )
            material = self._member_from_snapshot_row(member_row)
            materials.append(material)
            represented_actors.add(str(material["recorded_by"]))
            expected_json = canonical_json(material)
            expected_digest = sha256_digest(material)
            if (
                str(member_row["material_json"]) != expected_json
                or str(member_row["material_sha256"]) != expected_digest
            ):
                defects.append(f"C2_CERT_MEMBER_MATERIAL_MISMATCH:{ordinal}")
            identity = self.database.connection.execute(
                "SELECT * FROM c2_census_identities WHERE identity_id = ?",
                (str(member_row["identity_id"]),),
            ).fetchone()
            if identity is None:
                defects.append(f"C2_CERT_MEMBER_IDENTITY_MISSING:{ordinal}")
            else:
                current_material = self._member_material(identity)
                if current_material != material:
                    defects.append(f"C2_CERT_MEMBER_MATERIAL_MISMATCH:{ordinal}")

        computed_set_digest = sha256_digest(materials)
        if computed_set_digest != record.identity_set_digest:
            defects.append("C2_CERT_IDENTITY_SET_DIGEST_MISMATCH")
        if record.identity_count < record.required_target:
            defects.append("C2_CERT_THRESHOLD_NOT_MET")

        normalized_actors = {actor.strip() for actor in represented_actors}
        if recollection is not None:
            normalized_actors.add(recollection.started_by.strip())
        if record.certifier_identity.strip() in normalized_actors:
            defects.append("C2_CERT_INDEPENDENCE_VIOLATION")

        if parsed is not None:
            expected_payload_fields: dict[str, object] = {
                "certificate_id": record.certificate_id,
                "recollection_id": record.recollection_id,
                "incident_id": record.incident_id,
                "campaign_id": record.campaign_id,
                "identity_count": record.identity_count,
                "required_target": record.required_target,
                "identity_set_digest": record.identity_set_digest,
                "certifier_identity": record.certifier_identity,
                "certifier_environment": str(row["certifier_environment"]),
                "certified_at_utc": record.certified_at_utc,
                "independence_basis": str(row["independence_basis"]),
                "independent_identity_status": "SATISFIED",
                "census_verification_result": "PASS",
                "verdict": "C2_CENSUS_CERTIFIED",
                "gate_effect": "NO_CANONICAL_PROMOTION",
            }
            if parsed != expected_payload_fields:
                defects.append("C2_CERT_PAYLOAD_FIELDS_MISMATCH")

        if member_rows:
            latest_identity_at = max(
                str(member_row["recorded_at"])
                for member_row in member_rows
            )
            if self._as_datetime(record.certified_at_utc) < self._as_datetime(
                latest_identity_at
            ):
                defects.append("C2_CERT_CERTIFIED_BEFORE_MEMBERS")

        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (record.ledger_event_id,),
        ).fetchone()
        expected_stream = f"continuity:c2:{record.recollection_id}:certification"
        expected_event_payload = self._ledger_payload(record)
        if event is None:
            defects.append("C2_CERT_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != expected_stream:
                defects.append("C2_CERT_LEDGER_STREAM_MISMATCH")
            if str(event["kind"]) != "C2_CENSUS_CERTIFICATION_ADMITTED":
                defects.append("C2_CERT_LEDGER_KIND_MISMATCH")
            if str(event["actor"]) != record.admitted_by:
                defects.append("C2_CERT_LEDGER_ACTOR_MISMATCH")
            if str(event["occurred_at"]) != record.admitted_at:
                defects.append("C2_CERT_LEDGER_TIMESTAMP_MISMATCH")
            if str(event["record_hash"]) != record.ledger_hash:
                defects.append("C2_CERT_LEDGER_HASH_MISMATCH")
            try:
                event_payload = json.loads(str(event["payload_json"]))
            except (json.JSONDecodeError, TypeError):
                defects.append("C2_CERT_LEDGER_PAYLOAD_INVALID")
            else:
                if event_payload != expected_event_payload:
                    defects.append("C2_CERT_LEDGER_PAYLOAD_MISMATCH")

        chain = self.ledger.verify(expected_stream)
        defects.extend(
            f"C2_CERT_LEDGER_CHAIN:{defect.code}"
            for defect in chain.defects
        )
        return C2CertificationVerification(
            certificate_id=certificate_id,
            defects=tuple(dict.fromkeys(defects)),
        )
