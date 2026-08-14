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
from .certification import C2CertificationService
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
from .qualification import QualificationArtifactKind, QualificationLab
from .qualification_gate import C3QualificationGate


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
_MAX_SIGNATURE_BYTES = 1024
_REQUIRED_PAYLOAD_FIELDS = frozenset(
    {
        "decision_id",
        "c3_run_id",
        "qualification_run_id",
        "certificate_id",
        "qualification_head_hash",
        "candidate_count",
        "evaluation_count",
        "candidate_set_digest",
        "evaluation_set_digest",
        "verdict",
        "selected_candidate_artifact_id",
        "decision_maker_identity",
        "decision_maker_environment",
        "decided_at_utc",
        "independence_basis",
        "independent_identity_status",
        "qualification_verification_result",
        "gate_effect",
    }
)


class C3DecisionVerdict(str, Enum):
    CANDIDATE_SELECTED = "C3_CANDIDATE_SELECTED"
    NO_SELECTION = "C3_NO_SELECTION"


@dataclass(frozen=True)
class C3DecisionSnapshot:
    c3_run_id: str
    qualification_run_id: str
    certificate_id: str
    qualification_head_hash: str
    candidate_count: int
    evaluation_count: int
    candidate_set_digest: str
    evaluation_set_digest: str
    latest_evidence_at: str | None
    candidates: tuple[Mapping[str, Any], ...]
    evaluations: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class C3DecisionRecord:
    decision_id: str
    c3_run_id: str
    qualification_run_id: str
    certificate_id: str
    key_id: str
    payload_sha256: str
    signature_sha256: str
    decision_maker_identity: str
    decision_maker_environment: str
    verdict: C3DecisionVerdict
    selected_candidate_artifact_id: str | None
    qualification_head_hash: str
    candidate_count: int
    evaluation_count: int
    candidate_set_digest: str
    evaluation_set_digest: str
    decided_at_utc: str
    independence_basis: str
    admitted_at: str
    admitted_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C3DecisionVerification:
    decision_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C3DecisionService:
    """Admit exact-byte independent decisions over immutable C3 evidence snapshots."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        continuity: ContinuityService,
        certification: C2CertificationService,
        c3: C3QualificationGate,
        qualification: QualificationLab,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.continuity = continuity
        self.certification = certification
        self.c3 = c3
        self.qualification = qualification
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
                CREATE TABLE IF NOT EXISTS c3_decisions (
                    decision_id TEXT PRIMARY KEY,
                    c3_run_id TEXT NOT NULL UNIQUE,
                    qualification_run_id TEXT NOT NULL,
                    certificate_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
                    signature BLOB NOT NULL,
                    signature_sha256 TEXT NOT NULL CHECK (length(signature_sha256) = 64),
                    decision_maker_identity TEXT NOT NULL,
                    decision_maker_environment TEXT NOT NULL,
                    verdict TEXT NOT NULL CHECK (
                        verdict IN ('C3_CANDIDATE_SELECTED','C3_NO_SELECTION')
                    ),
                    selected_candidate_artifact_id TEXT,
                    qualification_head_hash TEXT NOT NULL
                        CHECK (length(qualification_head_hash) = 64),
                    candidate_count INTEGER NOT NULL CHECK (candidate_count >= 1),
                    evaluation_count INTEGER NOT NULL CHECK (evaluation_count >= 1),
                    candidate_set_digest TEXT NOT NULL
                        CHECK (length(candidate_set_digest) = 64),
                    evaluation_set_digest TEXT NOT NULL
                        CHECK (length(evaluation_set_digest) = 64),
                    decided_at_utc TEXT NOT NULL,
                    independence_basis TEXT NOT NULL,
                    independent_identity_status TEXT NOT NULL
                        CHECK (independent_identity_status = 'SATISFIED'),
                    qualification_verification_result TEXT NOT NULL
                        CHECK (qualification_verification_result = 'PASS'),
                    gate_effect TEXT NOT NULL
                        CHECK (gate_effect = 'NO_ADOPTION_EXECUTED'),
                    admitted_at TEXT NOT NULL,
                    admitted_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    CHECK (
                        (verdict = 'C3_CANDIDATE_SELECTED'
                            AND selected_candidate_artifact_id IS NOT NULL
                            AND length(selected_candidate_artifact_id) > 0)
                        OR
                        (verdict = 'C3_NO_SELECTION'
                            AND selected_candidate_artifact_id IS NULL)
                    ),
                    FOREIGN KEY (c3_run_id)
                        REFERENCES c3_qualification_bindings(c3_run_id),
                    FOREIGN KEY (qualification_run_id)
                        REFERENCES qualification_runs(qualification_run_id),
                    FOREIGN KEY (certificate_id)
                        REFERENCES c2_certifications(certificate_id),
                    FOREIGN KEY (key_id) REFERENCES continuity_trust_roots(key_id),
                    FOREIGN KEY (selected_candidate_artifact_id)
                        REFERENCES qualification_artifacts(artifact_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c3_decision_evidence (
                    decision_id TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK (kind IN ('CANDIDATE','EVALUATION')),
                    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                    artifact_id TEXT NOT NULL,
                    material_json TEXT NOT NULL,
                    material_sha256 TEXT NOT NULL CHECK (length(material_sha256) = 64),
                    recorded_at TEXT NOT NULL,
                    recorded_by TEXT NOT NULL,
                    artifact_ledger_event_id TEXT NOT NULL,
                    artifact_ledger_hash TEXT NOT NULL
                        CHECK (length(artifact_ledger_hash) = 64),
                    PRIMARY KEY (decision_id, kind, ordinal),
                    UNIQUE (decision_id, artifact_id),
                    FOREIGN KEY (decision_id) REFERENCES c3_decisions(decision_id),
                    FOREIGN KEY (artifact_id)
                        REFERENCES qualification_artifacts(artifact_id)
                )
                """
            )
            for table in ("c3_decisions", "c3_decision_evidence"):
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
    def _member_from_artifact_row(row: sqlite3.Row) -> dict[str, object]:
        try:
            material = json.loads(str(row["material_json"]))
        except (json.JSONDecodeError, TypeError) as exc:
            raise IntegrityError(
                "qualification artifact material is invalid",
                {"artifact_id": str(row["artifact_id"])},
            ) from exc
        if not isinstance(material, dict):
            raise IntegrityError(
                "qualification artifact material is invalid",
                {"artifact_id": str(row["artifact_id"])},
            )
        return {
            "artifact_id": str(row["artifact_id"]),
            "kind": str(row["kind"]),
            "material": material,
            "material_sha256": str(row["material_sha256"]),
            "recorded_at": str(row["recorded_at"]),
            "recorded_by": str(row["recorded_by"]),
            "ledger_event_id": str(row["ledger_event_id"]),
            "ledger_hash": str(row["ledger_hash"]),
        }

    def _snapshot_from_connection(
        self,
        connection: sqlite3.Connection,
        c3_run_id: str,
    ) -> C3DecisionSnapshot:
        binding = connection.execute(
            "SELECT * FROM c3_qualification_bindings WHERE c3_run_id = ?",
            (c3_run_id,),
        ).fetchone()
        if binding is None:
            raise NotFoundError(
                "C3 qualification binding does not exist",
                {"c3_run_id": c3_run_id},
            )
        qualification_run_id = str(binding["qualification_run_id"])
        rows = connection.execute(
            """
            SELECT * FROM qualification_artifacts
            WHERE qualification_run_id = ? AND kind IN ('CANDIDATE','EVALUATION')
            ORDER BY kind, artifact_id
            """,
            (qualification_run_id,),
        ).fetchall()
        candidates = tuple(
            self._member_from_artifact_row(row)
            for row in rows
            if str(row["kind"]) == QualificationArtifactKind.CANDIDATE.value
        )
        evaluations = tuple(
            self._member_from_artifact_row(row)
            for row in rows
            if str(row["kind"]) == QualificationArtifactKind.EVALUATION.value
        )
        head = connection.execute(
            """
            SELECT record_hash FROM ledger_events
            WHERE stream_id = ? ORDER BY sequence DESC LIMIT 1
            """,
            (f"qualification:run:{qualification_run_id}",),
        ).fetchone()
        if head is None:
            raise IntegrityError(
                "qualification ledger head is missing",
                {"qualification_run_id": qualification_run_id},
            )
        evidence = (*candidates, *evaluations)
        latest_evidence_at = None
        if evidence:
            latest_evidence_at = max(
                (str(member["recorded_at"]) for member in evidence),
                key=self._as_datetime,
            )
        return C3DecisionSnapshot(
            c3_run_id=c3_run_id,
            qualification_run_id=qualification_run_id,
            certificate_id=str(binding["certificate_id"]),
            qualification_head_hash=str(head["record_hash"]),
            candidate_count=len(candidates),
            evaluation_count=len(evaluations),
            candidate_set_digest=sha256_digest(list(candidates)),
            evaluation_set_digest=sha256_digest(list(evaluations)),
            latest_evidence_at=latest_evidence_at,
            candidates=candidates,
            evaluations=evaluations,
        )

    def snapshot(self, c3_run_id: str) -> C3DecisionSnapshot:
        c3_run_id = self._required_text(c3_run_id, "c3_run_id")
        verification = self.c3.verify(c3_run_id)
        if not verification.ok:
            raise IntegrityError(
                "C3 qualification verification failed",
                {"c3_run_id": c3_run_id, "defects": list(verification.defects)},
            )
        return self._snapshot_from_connection(self.database.connection, c3_run_id)

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
            raise ValidationError("C3 decision payload must be valid UTF-8 JSON") from exc
        if not isinstance(decoded, dict):
            raise ValidationError("C3 decision payload must be a JSON object")
        observed = frozenset(decoded)
        if observed != _REQUIRED_PAYLOAD_FIELDS:
            raise ValidationError(
                "C3 decision payload fields do not match the required contract",
                {
                    "missing": sorted(_REQUIRED_PAYLOAD_FIELDS - observed),
                    "unexpected": sorted(observed - _REQUIRED_PAYLOAD_FIELDS),
                },
            )
        return decoded

    def _parse_payload(self, payload: bytes) -> dict[str, object]:
        value = self._decode_payload(payload)
        for field in (
            "decision_id",
            "c3_run_id",
            "qualification_run_id",
            "certificate_id",
            "qualification_head_hash",
            "candidate_set_digest",
            "evaluation_set_digest",
            "verdict",
            "decision_maker_identity",
            "decision_maker_environment",
            "decided_at_utc",
            "independence_basis",
            "independent_identity_status",
            "qualification_verification_result",
            "gate_effect",
        ):
            value[field] = self._required_text(value[field], field)
        for field in ("candidate_count", "evaluation_count"):
            field_value = value[field]
            if type(field_value) is not int or field_value < 0:
                raise ValidationError(f"{field} must be an integer >= 0")
        for field in (
            "qualification_head_hash",
            "candidate_set_digest",
            "evaluation_set_digest",
        ):
            if not _SHA256.fullmatch(str(value[field])):
                raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
        value["decided_at_utc"] = self._timestamp(
            value["decided_at_utc"],
            "decided_at_utc",
        )
        try:
            verdict = C3DecisionVerdict(str(value["verdict"]))
        except ValueError as exc:
            raise ValidationError("unknown C3 decision verdict") from exc
        selected = value["selected_candidate_artifact_id"]
        if verdict is C3DecisionVerdict.CANDIDATE_SELECTED:
            value["selected_candidate_artifact_id"] = self._required_text(
                selected,
                "selected_candidate_artifact_id",
            )
        elif selected is not None:
            raise ValidationError(
                "selected_candidate_artifact_id must be null for C3_NO_SELECTION"
            )
        expected_constants = {
            "independent_identity_status": "SATISFIED",
            "qualification_verification_result": "PASS",
            "gate_effect": "NO_ADOPTION_EXECUTED",
        }
        for field, expected in expected_constants.items():
            if value[field] != expected:
                raise ValidationError(f"{field} must equal {expected}")
        return value

    @staticmethod
    def _record_from_row(row: sqlite3.Row) -> C3DecisionRecord:
        return C3DecisionRecord(
            decision_id=str(row["decision_id"]),
            c3_run_id=str(row["c3_run_id"]),
            qualification_run_id=str(row["qualification_run_id"]),
            certificate_id=str(row["certificate_id"]),
            key_id=str(row["key_id"]),
            payload_sha256=str(row["payload_sha256"]),
            signature_sha256=str(row["signature_sha256"]),
            decision_maker_identity=str(row["decision_maker_identity"]),
            decision_maker_environment=str(row["decision_maker_environment"]),
            verdict=C3DecisionVerdict(str(row["verdict"])),
            selected_candidate_artifact_id=(
                str(row["selected_candidate_artifact_id"])
                if row["selected_candidate_artifact_id"] is not None
                else None
            ),
            qualification_head_hash=str(row["qualification_head_hash"]),
            candidate_count=int(row["candidate_count"]),
            evaluation_count=int(row["evaluation_count"]),
            candidate_set_digest=str(row["candidate_set_digest"]),
            evaluation_set_digest=str(row["evaluation_set_digest"]),
            decided_at_utc=str(row["decided_at_utc"]),
            independence_basis=str(row["independence_basis"]),
            admitted_at=str(row["admitted_at"]),
            admitted_by=str(row["admitted_by"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def get_decision(self, decision_id: str) -> C3DecisionRecord:
        decision_id = self._required_text(decision_id, "decision_id")
        row = self.database.connection.execute(
            "SELECT * FROM c3_decisions WHERE decision_id = ?",
            (decision_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C3 decision does not exist",
                {"decision_id": decision_id},
            )
        return self._record_from_row(row)

    def _assert_trust_root(self, key_id: str) -> bytes:
        verification = self.continuity.verify_trust_root(key_id)
        if not verification.ok:
            raise IntegrityError(
                "C3 decision trust root verification failed",
                {"key_id": key_id, "defects": list(verification.defects)},
            )
        row = self.database.connection.execute(
            "SELECT public_key_pem FROM continuity_trust_roots WHERE key_id = ?",
            (key_id,),
        ).fetchone()
        if row is None:
            raise IntegrityError(
                "C3 decision trust root verification failed",
                {"key_id": key_id},
            )
        return bytes(row["public_key_pem"])

    @staticmethod
    def _assert_payload_matches_snapshot(
        value: Mapping[str, object],
        snapshot: C3DecisionSnapshot,
    ) -> None:
        expected = {
            "c3_run_id": snapshot.c3_run_id,
            "qualification_run_id": snapshot.qualification_run_id,
            "certificate_id": snapshot.certificate_id,
            "qualification_head_hash": snapshot.qualification_head_hash,
            "candidate_count": snapshot.candidate_count,
            "evaluation_count": snapshot.evaluation_count,
            "candidate_set_digest": snapshot.candidate_set_digest,
            "evaluation_set_digest": snapshot.evaluation_set_digest,
        }
        mismatches = {
            field: {"expected": expected_value, "observed": value[field]}
            for field, expected_value in expected.items()
            if value[field] != expected_value
        }
        if mismatches:
            raise StateTransitionError(
                "signed C3 decision does not match the current qualification snapshot",
                {"mismatches": mismatches},
            )

    def _assert_evidence_selection_and_time(
        self,
        value: Mapping[str, object],
        snapshot: C3DecisionSnapshot,
    ) -> None:
        if snapshot.candidate_count < 1 or snapshot.evaluation_count < 1:
            raise StateTransitionError(
                "C3 decision requires candidate and evaluation evidence",
                {
                    "candidate_count": snapshot.candidate_count,
                    "evaluation_count": snapshot.evaluation_count,
                },
            )
        verdict = C3DecisionVerdict(str(value["verdict"]))
        selected = value["selected_candidate_artifact_id"]
        candidate_ids = {
            str(member["artifact_id"])
            for member in snapshot.candidates
        }
        if (
            verdict is C3DecisionVerdict.CANDIDATE_SELECTED
            and str(selected) not in candidate_ids
        ):
            raise StateTransitionError(
                "selected candidate is not present in the C3 decision snapshot",
                {"selected_candidate_artifact_id": selected},
            )
        if (
            snapshot.latest_evidence_at is not None
            and self._as_datetime(str(value["decided_at_utc"]))
            < self._as_datetime(snapshot.latest_evidence_at)
        ):
            raise StateTransitionError(
                "decision predates the latest qualification evidence"
            )

    def _assert_independent(
        self,
        decision_maker_identity: str,
        snapshot: C3DecisionSnapshot,
    ) -> None:
        binding = self.c3.get(snapshot.c3_run_id)
        run = self.qualification.get_run(snapshot.qualification_run_id)
        certificate = self.certification.get_certificate(snapshot.certificate_id)
        disallowed = {
            binding.started_by.strip(),
            run.created_by.strip(),
            certificate.certifier_identity.strip(),
        }
        disallowed.update(
            str(member["recorded_by"]).strip()
            for member in (*snapshot.candidates, *snapshot.evaluations)
        )
        if decision_maker_identity.strip() in disallowed:
            raise StateTransitionError(
                "decision maker is not independent",
                {
                    "decision_maker_identity": decision_maker_identity,
                    "disallowed_identities": sorted(disallowed),
                },
            )

    @staticmethod
    def _ledger_payload(record: C3DecisionRecord) -> dict[str, object]:
        return {
            "decision_id": record.decision_id,
            "c3_run_id": record.c3_run_id,
            "key_id": record.key_id,
            "payload_sha256": record.payload_sha256,
            "signature_sha256": record.signature_sha256,
            "verdict": record.verdict.value,
            "selected_candidate_artifact_id": record.selected_candidate_artifact_id,
            "qualification_head_hash": record.qualification_head_hash,
            "candidate_count": record.candidate_count,
            "evaluation_count": record.evaluation_count,
            "candidate_set_digest": record.candidate_set_digest,
            "evaluation_set_digest": record.evaluation_set_digest,
            "gate_effect": "NO_ADOPTION_EXECUTED",
        }

    def admit_decision(
        self,
        c3_run_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
        *,
        actor: str,
        occurred_at: str | None = None,
    ) -> C3DecisionRecord:
        c3_run_id = self._required_text(c3_run_id, "c3_run_id")
        key_id = self._required_text(key_id, "key_id")
        actor = self._required_text(actor, "actor")
        payload = self._bounded_bytes(payload, "payload", _MAX_PAYLOAD_BYTES)
        signature = self._bounded_bytes(signature, "signature", _MAX_SIGNATURE_BYTES)
        occurred_at = self._timestamp(occurred_at or utc_now())
        value = self._parse_payload(payload)
        if value["c3_run_id"] != c3_run_id:
            raise StateTransitionError("signed C3 decision targets another C3 run")
        decision_id = str(value["decision_id"])
        payload_sha256 = self._digest(payload)
        signature_sha256 = self._digest(signature)

        existing = self.database.connection.execute(
            "SELECT * FROM c3_decisions WHERE decision_id = ?",
            (decision_id,),
        ).fetchone()
        if existing is not None:
            exact = (
                str(existing["c3_run_id"]) == c3_run_id
                and str(existing["key_id"]) == key_id
                and bytes(existing["payload"]) == payload
                and bytes(existing["signature"]) == signature
                and str(existing["payload_sha256"]) == payload_sha256
                and str(existing["signature_sha256"]) == signature_sha256
            )
            if not exact:
                raise ConflictError(
                    "decision_id was reused with different C3 decision material",
                    {"decision_id": decision_id},
                )
            verification = self.verify_decision(decision_id)
            if not verification.ok:
                raise IntegrityError(
                    "existing C3 decision failed verification",
                    {"decision_id": decision_id, "defects": list(verification.defects)},
                )
            return self._record_from_row(existing)

        prior = self.database.connection.execute(
            "SELECT decision_id FROM c3_decisions WHERE c3_run_id = ?",
            (c3_run_id,),
        ).fetchone()
        if prior is not None:
            raise ConflictError(
                "C3 run already has a sovereign decision",
                {
                    "c3_run_id": c3_run_id,
                    "decision_id": str(prior["decision_id"]),
                },
            )

        public_key = self._assert_trust_root(key_id)
        if not self.continuity.signature_verifier.verify(public_key, payload, signature):
            raise IntegrityError("C3 decision signature is invalid")
        snapshot = self.snapshot(c3_run_id)
        self._assert_payload_matches_snapshot(value, snapshot)
        self._assert_evidence_selection_and_time(value, snapshot)
        decision_maker_identity = str(value["decision_maker_identity"])
        self._assert_independent(decision_maker_identity, snapshot)

        try:
            with self.database.transaction() as connection:
                race = connection.execute(
                    """
                    SELECT decision_id FROM c3_decisions
                    WHERE decision_id = ? OR c3_run_id = ?
                    """,
                    (decision_id, c3_run_id),
                ).fetchone()
                if race is not None:
                    raise ConflictError(
                        "C3 decision appeared during admission",
                        {"decision_id": str(race["decision_id"])},
                    )
                current_public_key = self._assert_trust_root(key_id)
                if not self.continuity.signature_verifier.verify(
                    current_public_key,
                    payload,
                    signature,
                ):
                    raise IntegrityError("C3 decision signature is invalid")
                current_c3 = self.c3.verify(c3_run_id)
                if not current_c3.ok:
                    raise IntegrityError(
                        "C3 qualification verification failed",
                        {"c3_run_id": c3_run_id, "defects": list(current_c3.defects)},
                    )
                current_snapshot = self._snapshot_from_connection(connection, c3_run_id)
                if current_snapshot != snapshot:
                    raise ConflictError(
                        "qualification evidence changed during C3 decision admission",
                        {"c3_run_id": c3_run_id},
                    )
                self._assert_payload_matches_snapshot(value, current_snapshot)
                self._assert_evidence_selection_and_time(value, current_snapshot)
                self._assert_independent(decision_maker_identity, current_snapshot)
                provisional = C3DecisionRecord(
                    decision_id=decision_id,
                    c3_run_id=c3_run_id,
                    qualification_run_id=current_snapshot.qualification_run_id,
                    certificate_id=current_snapshot.certificate_id,
                    key_id=key_id,
                    payload_sha256=payload_sha256,
                    signature_sha256=signature_sha256,
                    decision_maker_identity=decision_maker_identity,
                    decision_maker_environment=str(value["decision_maker_environment"]),
                    verdict=C3DecisionVerdict(str(value["verdict"])),
                    selected_candidate_artifact_id=(
                        str(value["selected_candidate_artifact_id"])
                        if value["selected_candidate_artifact_id"] is not None
                        else None
                    ),
                    qualification_head_hash=current_snapshot.qualification_head_hash,
                    candidate_count=current_snapshot.candidate_count,
                    evaluation_count=current_snapshot.evaluation_count,
                    candidate_set_digest=current_snapshot.candidate_set_digest,
                    evaluation_set_digest=current_snapshot.evaluation_set_digest,
                    decided_at_utc=str(value["decided_at_utc"]),
                    independence_basis=str(value["independence_basis"]),
                    admitted_at=occurred_at,
                    admitted_by=actor,
                    ledger_event_id="pending",
                    ledger_hash="pending",
                )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"continuity:c3:{c3_run_id}:decision",
                    "C3_DECISION_ADMITTED",
                    self._ledger_payload(provisional),
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO c3_decisions (
                        decision_id, c3_run_id, qualification_run_id, certificate_id,
                        key_id, payload, payload_sha256, signature, signature_sha256,
                        decision_maker_identity, decision_maker_environment, verdict,
                        selected_candidate_artifact_id, qualification_head_hash,
                        candidate_count, evaluation_count, candidate_set_digest,
                        evaluation_set_digest, decided_at_utc, independence_basis,
                        independent_identity_status, qualification_verification_result,
                        gate_effect, admitted_at, admitted_by, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              'SATISFIED', 'PASS', 'NO_ADOPTION_EXECUTED', ?, ?, ?, ?)
                    """,
                    (
                        decision_id,
                        c3_run_id,
                        current_snapshot.qualification_run_id,
                        current_snapshot.certificate_id,
                        key_id,
                        payload,
                        payload_sha256,
                        signature,
                        signature_sha256,
                        decision_maker_identity,
                        str(value["decision_maker_environment"]),
                        str(value["verdict"]),
                        value["selected_candidate_artifact_id"],
                        current_snapshot.qualification_head_hash,
                        current_snapshot.candidate_count,
                        current_snapshot.evaluation_count,
                        current_snapshot.candidate_set_digest,
                        current_snapshot.evaluation_set_digest,
                        str(value["decided_at_utc"]),
                        str(value["independence_basis"]),
                        occurred_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
                for kind, members in (
                    (QualificationArtifactKind.CANDIDATE.value, current_snapshot.candidates),
                    (QualificationArtifactKind.EVALUATION.value, current_snapshot.evaluations),
                ):
                    for ordinal, member in enumerate(members):
                        connection.execute(
                            """
                            INSERT INTO c3_decision_evidence (
                                decision_id, kind, ordinal, artifact_id, material_json,
                                material_sha256, recorded_at, recorded_by,
                                artifact_ledger_event_id, artifact_ledger_hash
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                decision_id,
                                kind,
                                ordinal,
                                str(member["artifact_id"]),
                                canonical_json(member["material"]),
                                str(member["material_sha256"]),
                                str(member["recorded_at"]),
                                str(member["recorded_by"]),
                                str(member["ledger_event_id"]),
                                str(member["ledger_hash"]),
                            ),
                        )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "C3 decision conflicts with existing immutable state",
                {"decision_id": decision_id, "c3_run_id": c3_run_id},
            ) from exc
        return self.get_decision(decision_id)

    @staticmethod
    def _payload_matches_record(
        value: Mapping[str, object],
        record: C3DecisionRecord,
    ) -> bool:
        expected = {
            "decision_id": record.decision_id,
            "c3_run_id": record.c3_run_id,
            "qualification_run_id": record.qualification_run_id,
            "certificate_id": record.certificate_id,
            "qualification_head_hash": record.qualification_head_hash,
            "candidate_count": record.candidate_count,
            "evaluation_count": record.evaluation_count,
            "candidate_set_digest": record.candidate_set_digest,
            "evaluation_set_digest": record.evaluation_set_digest,
            "verdict": record.verdict.value,
            "selected_candidate_artifact_id": record.selected_candidate_artifact_id,
            "decision_maker_identity": record.decision_maker_identity,
            "decision_maker_environment": record.decision_maker_environment,
            "decided_at_utc": record.decided_at_utc,
            "independence_basis": record.independence_basis,
            "independent_identity_status": "SATISFIED",
            "qualification_verification_result": "PASS",
            "gate_effect": "NO_ADOPTION_EXECUTED",
        }
        return all(value.get(field) == expected_value for field, expected_value in expected.items())

    @staticmethod
    def _member_from_frozen_row(row: sqlite3.Row) -> dict[str, object]:
        try:
            material = json.loads(str(row["material_json"]))
        except (json.JSONDecodeError, TypeError):
            material = None
        return {
            "artifact_id": str(row["artifact_id"]),
            "kind": str(row["kind"]),
            "material": material,
            "material_sha256": str(row["material_sha256"]),
            "recorded_at": str(row["recorded_at"]),
            "recorded_by": str(row["recorded_by"]),
            "ledger_event_id": str(row["artifact_ledger_event_id"]),
            "ledger_hash": str(row["artifact_ledger_hash"]),
        }

    def verify_decision(self, decision_id: str) -> C3DecisionVerification:
        decision_id = self._required_text(decision_id, "decision_id")
        row = self.database.connection.execute(
            "SELECT * FROM c3_decisions WHERE decision_id = ?",
            (decision_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C3 decision does not exist",
                {"decision_id": decision_id},
            )
        record = self._record_from_row(row)
        payload = bytes(row["payload"])
        signature = bytes(row["signature"])
        defects: list[str] = []

        if self._digest(payload) != record.payload_sha256:
            defects.append("C3_DECISION_PAYLOAD_SHA256_MISMATCH")
        if self._digest(signature) != record.signature_sha256:
            defects.append("C3_DECISION_SIGNATURE_SHA256_MISMATCH")
        parsed: dict[str, object] | None = None
        try:
            parsed = self._parse_payload(payload)
        except ValidationError:
            defects.append("C3_DECISION_PAYLOAD_INVALID")
        if parsed is not None and not self._payload_matches_record(parsed, record):
            defects.append("C3_DECISION_PAYLOAD_RECORD_MISMATCH")

        root_verification = self.continuity.verify_trust_root(record.key_id)
        defects.extend(
            f"C3_DECISION_TRUST_ROOT:{defect}"
            for defect in root_verification.defects
        )
        key_row = self.database.connection.execute(
            "SELECT public_key_pem FROM continuity_trust_roots WHERE key_id = ?",
            (record.key_id,),
        ).fetchone()
        if key_row is None:
            defects.append("C3_DECISION_TRUST_ROOT_MISSING")
        elif not self.continuity.signature_verifier.verify(
            bytes(key_row["public_key_pem"]),
            payload,
            signature,
        ):
            defects.append("C3_DECISION_SIGNATURE_INVALID")

        c3_verification = self.c3.verify(record.c3_run_id)
        defects.extend(
            f"C3_DECISION_C3:{defect}"
            for defect in c3_verification.defects
        )

        frozen_rows = self.database.connection.execute(
            """
            SELECT * FROM c3_decision_evidence
            WHERE decision_id = ?
            ORDER BY CASE kind WHEN 'CANDIDATE' THEN 0 ELSE 1 END, ordinal
            """,
            (decision_id,),
        ).fetchall()
        frozen_candidates: list[Mapping[str, Any]] = []
        frozen_evaluations: list[Mapping[str, Any]] = []
        expected_ordinals = {"CANDIDATE": 0, "EVALUATION": 0}
        for frozen in frozen_rows:
            kind = str(frozen["kind"])
            ordinal = int(frozen["ordinal"])
            label = f"{kind}:{ordinal}"
            if ordinal != expected_ordinals.get(kind, -1):
                defects.append(f"C3_DECISION_EVIDENCE_ORDINAL_MISMATCH:{label}")
            expected_ordinals[kind] = ordinal + 1
            member = self._member_from_frozen_row(frozen)
            material = member["material"]
            if not isinstance(material, dict):
                defects.append(f"C3_DECISION_EVIDENCE_MATERIAL_INVALID:{label}")
            elif sha256_digest(material) != str(member["material_sha256"]):
                defects.append(
                    f"C3_DECISION_EVIDENCE_MATERIAL_SHA256_MISMATCH:{label}"
                )
            artifact_row = self.database.connection.execute(
                "SELECT * FROM qualification_artifacts WHERE artifact_id = ?",
                (str(member["artifact_id"]),),
            ).fetchone()
            if artifact_row is None:
                defects.append(f"C3_DECISION_EVIDENCE_ARTIFACT_MISSING:{label}")
            else:
                try:
                    current_member = self._member_from_artifact_row(artifact_row)
                except IntegrityError:
                    defects.append(f"C3_DECISION_EVIDENCE_ARTIFACT_INVALID:{label}")
                else:
                    if current_member != member:
                        defects.append(f"C3_DECISION_EVIDENCE_ARTIFACT_MISMATCH:{label}")
                    if str(artifact_row["qualification_run_id"]) != record.qualification_run_id:
                        defects.append(f"C3_DECISION_EVIDENCE_RUN_MISMATCH:{label}")
            if kind == QualificationArtifactKind.CANDIDATE.value:
                frozen_candidates.append(member)
            elif kind == QualificationArtifactKind.EVALUATION.value:
                frozen_evaluations.append(member)
            else:
                defects.append(f"C3_DECISION_EVIDENCE_KIND_INVALID:{label}")

        candidate_digest = sha256_digest(list(frozen_candidates))
        evaluation_digest = sha256_digest(list(frozen_evaluations))
        if len(frozen_candidates) != record.candidate_count:
            defects.append("C3_DECISION_CANDIDATE_COUNT_MISMATCH")
        if len(frozen_evaluations) != record.evaluation_count:
            defects.append("C3_DECISION_EVALUATION_COUNT_MISMATCH")
        if candidate_digest != record.candidate_set_digest:
            defects.append("C3_DECISION_CANDIDATE_SET_DIGEST_MISMATCH")
        if evaluation_digest != record.evaluation_set_digest:
            defects.append("C3_DECISION_EVALUATION_SET_DIGEST_MISMATCH")

        latest_evidence_at = None
        frozen_all = (*frozen_candidates, *frozen_evaluations)
        if frozen_all:
            latest_evidence_at = max(
                (str(member["recorded_at"]) for member in frozen_all),
                key=self._as_datetime,
            )
        frozen_snapshot = C3DecisionSnapshot(
            c3_run_id=record.c3_run_id,
            qualification_run_id=record.qualification_run_id,
            certificate_id=record.certificate_id,
            qualification_head_hash=record.qualification_head_hash,
            candidate_count=len(frozen_candidates),
            evaluation_count=len(frozen_evaluations),
            candidate_set_digest=candidate_digest,
            evaluation_set_digest=evaluation_digest,
            latest_evidence_at=latest_evidence_at,
            candidates=tuple(frozen_candidates),
            evaluations=tuple(frozen_evaluations),
        )
        semantic_value: Mapping[str, object] = parsed or {
            "verdict": record.verdict.value,
            "selected_candidate_artifact_id": record.selected_candidate_artifact_id,
            "decided_at_utc": record.decided_at_utc,
        }
        try:
            self._assert_evidence_selection_and_time(semantic_value, frozen_snapshot)
        except StateTransitionError:
            defects.append("C3_DECISION_SEMANTICS_OR_CHRONOLOGY_INVALID")
        try:
            self._assert_independent(record.decision_maker_identity, frozen_snapshot)
        except StateTransitionError:
            defects.append("C3_DECISION_INDEPENDENCE_INVALID")

        if c3_verification.ok:
            try:
                current_snapshot = self._snapshot_from_connection(
                    self.database.connection,
                    record.c3_run_id,
                )
            except (IntegrityError, NotFoundError, ValidationError):
                defects.append("C3_DECISION_CURRENT_SNAPSHOT_INVALID")
            else:
                if current_snapshot != frozen_snapshot:
                    defects.append("C3_DECISION_SNAPSHOT_STALE")

        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (record.ledger_event_id,),
        ).fetchone()
        expected_stream = f"continuity:c3:{record.c3_run_id}:decision"
        expected_payload = self._ledger_payload(record)
        if event is None:
            defects.append("C3_DECISION_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != expected_stream:
                defects.append("C3_DECISION_LEDGER_STREAM_MISMATCH")
            if str(event["kind"]) != "C3_DECISION_ADMITTED":
                defects.append("C3_DECISION_LEDGER_KIND_MISMATCH")
            if str(event["actor"]) != record.admitted_by:
                defects.append("C3_DECISION_LEDGER_ACTOR_MISMATCH")
            if str(event["occurred_at"]) != record.admitted_at:
                defects.append("C3_DECISION_LEDGER_TIMESTAMP_MISMATCH")
            if str(event["record_hash"]) != record.ledger_hash:
                defects.append("C3_DECISION_LEDGER_HASH_MISMATCH")
            try:
                event_payload = json.loads(str(event["payload_json"]))
            except (json.JSONDecodeError, TypeError):
                defects.append("C3_DECISION_LEDGER_PAYLOAD_INVALID")
            else:
                if event_payload != expected_payload:
                    defects.append("C3_DECISION_LEDGER_PAYLOAD_MISMATCH")
        chain = self.ledger.verify(expected_stream)
        defects.extend(
            f"C3_DECISION_LEDGER_CHAIN:{defect.code}"
            for defect in chain.defects
        )

        return C3DecisionVerification(
            decision_id=decision_id,
            defects=tuple(dict.fromkeys(defects)),
        )
