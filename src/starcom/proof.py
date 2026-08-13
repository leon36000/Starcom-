from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import json
import re
import sqlite3
from typing import Any, Mapping
from uuid import uuid4

from .canonical import canonical_json, sha256_digest, utc_now
from .db import Database
from .errors import ConflictError, NotFoundError, StateTransitionError, ValidationError
from .ledger import EventLedger


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ClaimStatus(str, Enum):
    DRAFT = "DRAFT"
    EVIDENCE_ATTACHED = "EVIDENCE_ATTACHED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    CERTIFIED = "CERTIFIED"


class VerificationVerdict(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


@dataclass(frozen=True)
class Claim:
    claim_id: str
    subject_type: str
    subject_id: str
    statement: str
    author: str
    policy_version: str
    status: ClaimStatus
    created_at: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class EvidenceReference:
    evidence_id: str
    claim_id: str
    kind: str
    uri: str
    digest: str
    metadata: Mapping[str, Any]
    attached_by: str
    attached_at: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class ClaimVerification:
    verification_id: str
    claim_id: str
    verifier: str
    verdict: VerificationVerdict
    notes: str
    evidence_set_digest: str
    verified_at: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class ProofCertificate:
    certificate_id: str
    claim_id: str
    verification_id: str
    certifier: str
    policy_version: str
    certificate_digest: str
    issued_at: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class CertificateVerification:
    certificate_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class ProofEngine:
    def __init__(self, database: Database, ledger: EventLedger) -> None:
        self.database = database
        self.ledger = ledger
        self._initialize_schema()

    @staticmethod
    def _required_text(value: str, name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{name} must be a non-empty string")
        return value

    @staticmethod
    def _validate_time(value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError("timestamp must be RFC 3339") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValidationError("timestamp must be timezone-aware")
        return value

    @staticmethod
    def _validate_digest(value: str) -> str:
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            raise ValidationError("evidence digest must be a lowercase SHA-256 hex digest")
        return value

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS proof_claims (
                    claim_id TEXT PRIMARY KEY,
                    subject_type TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    statement TEXT NOT NULL,
                    author TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('DRAFT', 'EVIDENCE_ATTACHED', 'VERIFIED', 'REJECTED', 'CERTIFIED')
                    ),
                    created_at TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS proof_evidence (
                    evidence_id TEXT PRIMARY KEY,
                    claim_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    uri TEXT NOT NULL,
                    digest TEXT NOT NULL CHECK (length(digest) = 64),
                    metadata_json TEXT NOT NULL,
                    attached_by TEXT NOT NULL,
                    attached_at TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (claim_id) REFERENCES proof_claims(claim_id)
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS proof_evidence_claim_idx "
                "ON proof_evidence(claim_id, evidence_id)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS proof_verifications (
                    verification_id TEXT PRIMARY KEY,
                    claim_id TEXT NOT NULL UNIQUE,
                    verifier TEXT NOT NULL,
                    verdict TEXT NOT NULL CHECK (verdict IN ('APPROVED', 'REJECTED')),
                    notes TEXT NOT NULL,
                    evidence_set_digest TEXT NOT NULL CHECK (length(evidence_set_digest) = 64),
                    verified_at TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (claim_id) REFERENCES proof_claims(claim_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS proof_certificates (
                    certificate_id TEXT PRIMARY KEY,
                    claim_id TEXT NOT NULL UNIQUE,
                    verification_id TEXT NOT NULL UNIQUE,
                    certifier TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    certificate_digest TEXT NOT NULL CHECK (length(certificate_digest) = 64),
                    issued_at TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (claim_id) REFERENCES proof_claims(claim_id),
                    FOREIGN KEY (verification_id) REFERENCES proof_verifications(verification_id)
                )
                """
            )
            for table in ("proof_evidence", "proof_verifications", "proof_certificates"):
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

    def create_claim(
        self,
        *,
        claim_id: str | None = None,
        subject_type: str,
        subject_id: str,
        statement: str,
        author: str,
        policy_version: str,
        occurred_at: str | None = None,
    ) -> Claim:
        claim_id = self._required_text(claim_id or str(uuid4()), "claim_id")
        subject_type = self._required_text(subject_type, "subject_type")
        subject_id = self._required_text(subject_id, "subject_id")
        statement = self._required_text(statement, "statement")
        author = self._required_text(author, "author")
        policy_version = self._required_text(policy_version, "policy_version")
        occurred_at = self._validate_time(occurred_at or utc_now())
        payload = {
            "claim_id": claim_id,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "statement": statement,
            "author": author,
            "policy_version": policy_version,
        }
        try:
            with self.database.transaction() as connection:
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"proof:claim:{claim_id}",
                    "CLAIM_CREATED",
                    payload,
                    actor=author,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO proof_claims (
                        claim_id, subject_type, subject_id, statement, author,
                        policy_version, status, created_at, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_id,
                        subject_type,
                        subject_id,
                        statement,
                        author,
                        policy_version,
                        ClaimStatus.DRAFT.value,
                        occurred_at,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("claim already exists", {"claim_id": claim_id}) from exc
        return self.get_claim(claim_id)

    def get_claim(self, claim_id: str) -> Claim:
        row = self.database.connection.execute(
            "SELECT * FROM proof_claims WHERE claim_id = ?",
            (claim_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("claim does not exist", {"claim_id": claim_id})
        return Claim(
            claim_id=str(row["claim_id"]),
            subject_type=str(row["subject_type"]),
            subject_id=str(row["subject_id"]),
            statement=str(row["statement"]),
            author=str(row["author"]),
            policy_version=str(row["policy_version"]),
            status=ClaimStatus(str(row["status"])),
            created_at=str(row["created_at"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def attach_evidence(
        self,
        claim_id: str,
        *,
        evidence_id: str | None = None,
        kind: str,
        uri: str,
        digest: str,
        metadata: Mapping[str, Any],
        attached_by: str,
        occurred_at: str | None = None,
    ) -> EvidenceReference:
        claim_id = self._required_text(claim_id, "claim_id")
        evidence_id = self._required_text(evidence_id or str(uuid4()), "evidence_id")
        kind = self._required_text(kind, "kind")
        uri = self._required_text(uri, "uri")
        digest = self._validate_digest(digest)
        attached_by = self._required_text(attached_by, "attached_by")
        occurred_at = self._validate_time(occurred_at or utc_now())
        metadata_json = canonical_json(dict(metadata))

        try:
            with self.database.transaction() as connection:
                claim = connection.execute(
                    "SELECT * FROM proof_claims WHERE claim_id = ?",
                    (claim_id,),
                ).fetchone()
                if claim is None:
                    raise NotFoundError("claim does not exist", {"claim_id": claim_id})
                status = ClaimStatus(str(claim["status"]))
                if status not in (ClaimStatus.DRAFT, ClaimStatus.EVIDENCE_ATTACHED):
                    raise StateTransitionError(
                        "evidence cannot be attached after verification",
                        {"claim_id": claim_id, "status": status.value},
                    )
                payload = {
                    "claim_id": claim_id,
                    "evidence_id": evidence_id,
                    "kind": kind,
                    "uri": uri,
                    "digest": digest,
                    "metadata": dict(metadata),
                    "attached_by": attached_by,
                }
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"proof:claim:{claim_id}",
                    "EVIDENCE_ATTACHED",
                    payload,
                    actor=attached_by,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO proof_evidence (
                        evidence_id, claim_id, kind, uri, digest, metadata_json,
                        attached_by, attached_at, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence_id,
                        claim_id,
                        kind,
                        uri,
                        digest,
                        metadata_json,
                        attached_by,
                        occurred_at,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
                connection.execute(
                    "UPDATE proof_claims SET status = ? WHERE claim_id = ?",
                    (ClaimStatus.EVIDENCE_ATTACHED.value, claim_id),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("evidence already exists", {"evidence_id": evidence_id}) from exc
        return EvidenceReference(
            evidence_id=evidence_id,
            claim_id=claim_id,
            kind=kind,
            uri=uri,
            digest=digest,
            metadata=dict(metadata),
            attached_by=attached_by,
            attached_at=occurred_at,
            ledger_event_id=receipt.event_id,
            ledger_hash=receipt.record_hash,
        )

    @staticmethod
    def _evidence_material(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
        return [
            {
                "evidence_id": str(row["evidence_id"]),
                "kind": str(row["kind"]),
                "uri": str(row["uri"]),
                "digest": str(row["digest"]),
                "metadata": json.loads(str(row["metadata_json"])),
                "attached_by": str(row["attached_by"]),
                "attached_at": str(row["attached_at"]),
            }
            for row in rows
        ]

    def verify_claim(
        self,
        claim_id: str,
        *,
        verifier: str,
        verdict: VerificationVerdict,
        notes: str,
        occurred_at: str | None = None,
    ) -> ClaimVerification:
        claim_id = self._required_text(claim_id, "claim_id")
        verifier = self._required_text(verifier, "verifier")
        notes = self._required_text(notes, "notes")
        if not isinstance(verdict, VerificationVerdict):
            try:
                verdict = VerificationVerdict(str(verdict))
            except ValueError as exc:
                raise ValidationError("verdict must be APPROVED or REJECTED") from exc
        occurred_at = self._validate_time(occurred_at or utc_now())
        verification_id = str(uuid4())

        try:
            with self.database.transaction() as connection:
                claim = connection.execute(
                    "SELECT * FROM proof_claims WHERE claim_id = ?",
                    (claim_id,),
                ).fetchone()
                if claim is None:
                    raise NotFoundError("claim does not exist", {"claim_id": claim_id})
                if str(claim["author"]) == verifier:
                    raise StateTransitionError("claim author cannot act as verifier")
                status = ClaimStatus(str(claim["status"]))
                if status not in (ClaimStatus.DRAFT, ClaimStatus.EVIDENCE_ATTACHED):
                    raise StateTransitionError(
                        "claim has already been verified",
                        {"claim_id": claim_id, "status": status.value},
                    )
                rows = connection.execute(
                    "SELECT * FROM proof_evidence WHERE claim_id = ? ORDER BY evidence_id",
                    (claim_id,),
                ).fetchall()
                if verdict is VerificationVerdict.APPROVED and not rows:
                    raise StateTransitionError("approved verification requires evidence")
                evidence_set_digest = sha256_digest(self._evidence_material(list(rows)))
                payload = {
                    "verification_id": verification_id,
                    "claim_id": claim_id,
                    "verifier": verifier,
                    "verdict": verdict.value,
                    "notes": notes,
                    "evidence_set_digest": evidence_set_digest,
                }
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"proof:claim:{claim_id}",
                    "CLAIM_VERIFIED",
                    payload,
                    actor=verifier,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO proof_verifications (
                        verification_id, claim_id, verifier, verdict, notes,
                        evidence_set_digest, verified_at, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        verification_id,
                        claim_id,
                        verifier,
                        verdict.value,
                        notes,
                        evidence_set_digest,
                        occurred_at,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
                next_status = (
                    ClaimStatus.VERIFIED
                    if verdict is VerificationVerdict.APPROVED
                    else ClaimStatus.REJECTED
                )
                connection.execute(
                    "UPDATE proof_claims SET status = ? WHERE claim_id = ?",
                    (next_status.value, claim_id),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("claim already has a verification", {"claim_id": claim_id}) from exc
        return ClaimVerification(
            verification_id=verification_id,
            claim_id=claim_id,
            verifier=verifier,
            verdict=verdict,
            notes=notes,
            evidence_set_digest=evidence_set_digest,
            verified_at=occurred_at,
            ledger_event_id=receipt.event_id,
            ledger_hash=receipt.record_hash,
        )

    @staticmethod
    def _certificate_material(
        claim: sqlite3.Row,
        verification: sqlite3.Row,
        *,
        certificate_id: str,
        certifier: str,
        issued_at: str,
    ) -> dict[str, Any]:
        return {
            "certificate_id": certificate_id,
            "claim": {
                "claim_id": str(claim["claim_id"]),
                "subject_type": str(claim["subject_type"]),
                "subject_id": str(claim["subject_id"]),
                "statement": str(claim["statement"]),
                "author": str(claim["author"]),
                "policy_version": str(claim["policy_version"]),
            },
            "verification": {
                "verification_id": str(verification["verification_id"]),
                "verifier": str(verification["verifier"]),
                "verdict": str(verification["verdict"]),
                "evidence_set_digest": str(verification["evidence_set_digest"]),
                "verified_at": str(verification["verified_at"]),
            },
            "certifier": certifier,
            "issued_at": issued_at,
        }

    def certify_claim(
        self,
        claim_id: str,
        *,
        certifier: str,
        occurred_at: str | None = None,
    ) -> ProofCertificate:
        claim_id = self._required_text(claim_id, "claim_id")
        certifier = self._required_text(certifier, "certifier")
        occurred_at = self._validate_time(occurred_at or utc_now())

        with self.database.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM proof_certificates WHERE claim_id = ?",
                (claim_id,),
            ).fetchone()
            if existing is not None:
                if str(existing["certifier"]) != certifier:
                    raise ConflictError("claim is already certified by a different actor")
                return self._row_to_certificate(existing)

            claim = connection.execute(
                "SELECT * FROM proof_claims WHERE claim_id = ?",
                (claim_id,),
            ).fetchone()
            if claim is None:
                raise NotFoundError("claim does not exist", {"claim_id": claim_id})
            verification = connection.execute(
                "SELECT * FROM proof_verifications WHERE claim_id = ?",
                (claim_id,),
            ).fetchone()
            if (
                verification is None
                or str(verification["verdict"]) != VerificationVerdict.APPROVED.value
                or str(claim["status"]) != ClaimStatus.VERIFIED.value
            ):
                raise StateTransitionError("claim does not have an approved verification")
            if certifier in (str(claim["author"]), str(verification["verifier"])):
                raise StateTransitionError(
                    "certifier must be distinct from claim author and verifier"
                )
            certificate_id = str(uuid4())
            material = self._certificate_material(
                claim,
                verification,
                certificate_id=certificate_id,
                certifier=certifier,
                issued_at=occurred_at,
            )
            certificate_digest = sha256_digest(material)
            payload = {
                "certificate_id": certificate_id,
                "claim_id": claim_id,
                "verification_id": str(verification["verification_id"]),
                "certifier": certifier,
                "policy_version": str(claim["policy_version"]),
                "certificate_digest": certificate_digest,
            }
            receipt = self.ledger.append_in_transaction(
                connection,
                f"proof:claim:{claim_id}",
                "CLAIM_CERTIFIED",
                payload,
                actor=certifier,
                occurred_at=occurred_at,
            )
            connection.execute(
                """
                INSERT INTO proof_certificates (
                    certificate_id, claim_id, verification_id, certifier,
                    policy_version, certificate_digest, issued_at,
                    ledger_event_id, ledger_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    certificate_id,
                    claim_id,
                    str(verification["verification_id"]),
                    certifier,
                    str(claim["policy_version"]),
                    certificate_digest,
                    occurred_at,
                    receipt.event_id,
                    receipt.record_hash,
                ),
            )
            connection.execute(
                "UPDATE proof_claims SET status = ? WHERE claim_id = ?",
                (ClaimStatus.CERTIFIED.value, claim_id),
            )
            row = connection.execute(
                "SELECT * FROM proof_certificates WHERE certificate_id = ?",
                (certificate_id,),
            ).fetchone()
            assert row is not None
            return self._row_to_certificate(row)

    @staticmethod
    def _row_to_certificate(row: sqlite3.Row) -> ProofCertificate:
        return ProofCertificate(
            certificate_id=str(row["certificate_id"]),
            claim_id=str(row["claim_id"]),
            verification_id=str(row["verification_id"]),
            certifier=str(row["certifier"]),
            policy_version=str(row["policy_version"]),
            certificate_digest=str(row["certificate_digest"]),
            issued_at=str(row["issued_at"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def get_certificate(self, certificate_id: str) -> ProofCertificate:
        row = self.database.connection.execute(
            "SELECT * FROM proof_certificates WHERE certificate_id = ?",
            (certificate_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("certificate does not exist", {"certificate_id": certificate_id})
        return self._row_to_certificate(row)

    def get_certificate_for_claim(self, claim_id: str) -> ProofCertificate:
        row = self.database.connection.execute(
            "SELECT * FROM proof_certificates WHERE claim_id = ?",
            (claim_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("claim has no certificate", {"claim_id": claim_id})
        return self._row_to_certificate(row)

    def verify_certificate(self, certificate_id: str) -> CertificateVerification:
        defects: list[str] = []
        certificate = self.database.connection.execute(
            "SELECT * FROM proof_certificates WHERE certificate_id = ?",
            (certificate_id,),
        ).fetchone()
        if certificate is None:
            return CertificateVerification(certificate_id, ("CERTIFICATE_NOT_FOUND",))
        claim = self.database.connection.execute(
            "SELECT * FROM proof_claims WHERE claim_id = ?",
            (str(certificate["claim_id"]),),
        ).fetchone()
        verification = self.database.connection.execute(
            "SELECT * FROM proof_verifications WHERE verification_id = ?",
            (str(certificate["verification_id"]),),
        ).fetchone()
        if claim is None:
            defects.append("CLAIM_NOT_FOUND")
        if verification is None:
            defects.append("VERIFICATION_NOT_FOUND")
        if claim is None or verification is None:
            return CertificateVerification(certificate_id, tuple(defects))

        evidence_rows = self.database.connection.execute(
            "SELECT * FROM proof_evidence WHERE claim_id = ? ORDER BY evidence_id",
            (str(claim["claim_id"]),),
        ).fetchall()
        evidence_material: list[dict[str, Any]] = []
        evidence_metadata_valid = True
        for evidence in evidence_rows:
            evidence_id = str(evidence["evidence_id"])
            try:
                metadata = json.loads(str(evidence["metadata_json"]))
                if not isinstance(metadata, dict):
                    raise ValueError("metadata_json must decode to an object")
            except (json.JSONDecodeError, TypeError, ValueError):
                defects.append(f"EVIDENCE_METADATA_JSON_INVALID:{evidence_id}")
                evidence_metadata_valid = False
                continue
            evidence_material.append(
                {
                    "evidence_id": evidence_id,
                    "kind": str(evidence["kind"]),
                    "uri": str(evidence["uri"]),
                    "digest": str(evidence["digest"]),
                    "metadata": metadata,
                    "attached_by": str(evidence["attached_by"]),
                    "attached_at": str(evidence["attached_at"]),
                }
            )
        if evidence_metadata_valid:
            evidence_digest = sha256_digest(evidence_material)
            if evidence_digest != str(verification["evidence_set_digest"]):
                defects.append("EVIDENCE_SET_DIGEST_MISMATCH")
        if str(verification["verdict"]) != VerificationVerdict.APPROVED.value:
            defects.append("VERIFICATION_NOT_APPROVED")
        if str(claim["status"]) != ClaimStatus.CERTIFIED.value:
            defects.append("CLAIM_STATUS_NOT_CERTIFIED")
        if str(certificate["certifier"]) in (
            str(claim["author"]),
            str(verification["verifier"]),
        ):
            defects.append("ROLE_SEPARATION_VIOLATION")

        material = self._certificate_material(
            claim,
            verification,
            certificate_id=certificate_id,
            certifier=str(certificate["certifier"]),
            issued_at=str(certificate["issued_at"]),
        )
        expected_digest = sha256_digest(material)
        if expected_digest != str(certificate["certificate_digest"]):
            defects.append("CERTIFICATE_DIGEST_MISMATCH")

        ledger_row = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (str(certificate["ledger_event_id"]),),
        ).fetchone()
        if ledger_row is None:
            defects.append("CERTIFICATE_LEDGER_EVENT_MISSING")
        else:
            if str(ledger_row["record_hash"]) != str(certificate["ledger_hash"]):
                defects.append("CERTIFICATE_LEDGER_HASH_MISMATCH")
            try:
                payload = json.loads(str(ledger_row["payload_json"]))
            except json.JSONDecodeError:
                defects.append("CERTIFICATE_LEDGER_PAYLOAD_INVALID")
            else:
                if payload.get("certificate_digest") != str(certificate["certificate_digest"]):
                    defects.append("CERTIFICATE_LEDGER_PAYLOAD_MISMATCH")
        if not self.ledger.verify(f"proof:claim:{claim['claim_id']}").ok:
            defects.append("CLAIM_LEDGER_CHAIN_INVALID")
        return CertificateVerification(certificate_id, tuple(dict.fromkeys(defects)))
