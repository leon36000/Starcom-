from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import sqlite3

from .canonical import utc_now
from .certification import C2CertificationRecord, C2CertificationService
from .db import Database
from .errors import (
    ConflictError,
    IntegrityError,
    NotFoundError,
    StateTransitionError,
    ValidationError,
)
from .ledger import EventLedger
from .qualification import QualificationLab, QualificationRun


@dataclass(frozen=True)
class C3QualificationBinding:
    c3_run_id: str
    qualification_run_id: str
    certificate_id: str
    recollection_id: str
    incident_id: str
    campaign_id: str
    identity_count: int
    required_target: int
    identity_set_digest: str
    qualification_head_hash_at_bind: str
    started_at: str
    started_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C3QualificationVerification:
    c3_run_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C3QualificationGate:
    """Bind an empty qualification run to one exact verified C2 certificate."""

    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        certification: C2CertificationService,
        qualification: QualificationLab,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.certification = certification
        self.qualification = qualification
        self._initialize_schema()

    @staticmethod
    def _required_text(value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{field} must be a non-empty string")
        return value

    @staticmethod
    def _timestamp(value: object) -> str:
        if not isinstance(value, str):
            raise ValidationError("timestamp must be RFC 3339")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError("timestamp must be RFC 3339") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValidationError("timestamp must be timezone-aware")
        return value

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c3_qualification_bindings (
                    c3_run_id TEXT PRIMARY KEY,
                    qualification_run_id TEXT NOT NULL UNIQUE,
                    certificate_id TEXT NOT NULL UNIQUE,
                    recollection_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    identity_count INTEGER NOT NULL CHECK (identity_count >= 800),
                    required_target INTEGER NOT NULL CHECK (required_target >= 800),
                    identity_set_digest TEXT NOT NULL
                        CHECK (length(identity_set_digest) = 64),
                    qualification_head_hash_at_bind TEXT NOT NULL
                        CHECK (length(qualification_head_hash_at_bind) = 64),
                    started_at TEXT NOT NULL,
                    started_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (qualification_run_id)
                        REFERENCES qualification_runs(qualification_run_id),
                    FOREIGN KEY (certificate_id)
                        REFERENCES c2_certifications(certificate_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS c3_qualification_bindings_no_update
                BEFORE UPDATE ON c3_qualification_bindings
                BEGIN SELECT RAISE(ABORT, 'c3 qualification bindings are immutable'); END
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS c3_qualification_bindings_no_delete
                BEFORE DELETE ON c3_qualification_bindings
                BEGIN SELECT RAISE(ABORT, 'c3 qualification bindings are immutable'); END
                """
            )

    @staticmethod
    def _from_row(row: sqlite3.Row) -> C3QualificationBinding:
        return C3QualificationBinding(
            c3_run_id=str(row["c3_run_id"]),
            qualification_run_id=str(row["qualification_run_id"]),
            certificate_id=str(row["certificate_id"]),
            recollection_id=str(row["recollection_id"]),
            incident_id=str(row["incident_id"]),
            campaign_id=str(row["campaign_id"]),
            identity_count=int(row["identity_count"]),
            required_target=int(row["required_target"]),
            identity_set_digest=str(row["identity_set_digest"]),
            qualification_head_hash_at_bind=str(
                row["qualification_head_hash_at_bind"]
            ),
            started_at=str(row["started_at"]),
            started_by=str(row["started_by"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def get(self, c3_run_id: str) -> C3QualificationBinding:
        c3_run_id = self._required_text(c3_run_id, "c3_run_id")
        row = self.database.connection.execute(
            "SELECT * FROM c3_qualification_bindings WHERE c3_run_id = ?",
            (c3_run_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C3 qualification binding does not exist",
                {"c3_run_id": c3_run_id},
            )
        return self._from_row(row)

    def _clean_certificate(self, certificate_id: str) -> C2CertificationRecord:
        certificate = self.certification.get_certificate(certificate_id)
        verification = self.certification.verify_certificate(certificate_id)
        if not verification.ok:
            raise IntegrityError(
                "C2 certification verification failed",
                {
                    "certificate_id": certificate_id,
                    "defects": list(verification.defects),
                },
            )
        if (
            certificate.identity_count < certificate.required_target
            or certificate.required_target < 800
        ):
            raise StateTransitionError(
                "C2 certification does not satisfy the C3 qualification threshold",
                {
                    "identity_count": certificate.identity_count,
                    "required_target": certificate.required_target,
                },
            )
        return certificate

    def _clean_qualification_run(self, qualification_run_id: str) -> QualificationRun:
        run = self.qualification.get_run(qualification_run_id)
        verification = self.qualification.verify(qualification_run_id)
        if not verification.ok:
            raise IntegrityError(
                "qualification run verification failed",
                {
                    "qualification_run_id": qualification_run_id,
                    "defects": list(verification.defects),
                },
            )
        return run

    @staticmethod
    def _payload(binding: C3QualificationBinding) -> dict[str, object]:
        return {
            "c3_run_id": binding.c3_run_id,
            "qualification_run_id": binding.qualification_run_id,
            "certificate_id": binding.certificate_id,
            "recollection_id": binding.recollection_id,
            "incident_id": binding.incident_id,
            "campaign_id": binding.campaign_id,
            "identity_count": binding.identity_count,
            "required_target": binding.required_target,
            "identity_set_digest": binding.identity_set_digest,
            "qualification_head_hash_at_bind": (
                binding.qualification_head_hash_at_bind
            ),
            "pre_binding_artifact_count": 0,
        }

    def start(
        self,
        c3_run_id: str,
        *,
        qualification_run_id: str,
        certificate_id: str,
        actor: str,
        occurred_at: str | None = None,
    ) -> C3QualificationBinding:
        c3_run_id = self._required_text(c3_run_id, "c3_run_id")
        qualification_run_id = self._required_text(
            qualification_run_id,
            "qualification_run_id",
        )
        certificate_id = self._required_text(certificate_id, "certificate_id")
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now())

        certificate = self._clean_certificate(certificate_id)
        run = self._clean_qualification_run(qualification_run_id)

        existing = self.database.connection.execute(
            "SELECT * FROM c3_qualification_bindings WHERE c3_run_id = ?",
            (c3_run_id,),
        ).fetchone()
        if existing is not None:
            binding = self._from_row(existing)
            expected = (
                qualification_run_id,
                certificate_id,
                certificate.recollection_id,
                certificate.incident_id,
                certificate.campaign_id,
                certificate.identity_count,
                certificate.required_target,
                certificate.identity_set_digest,
                run.ledger_hash,
                actor,
            )
            observed = (
                binding.qualification_run_id,
                binding.certificate_id,
                binding.recollection_id,
                binding.incident_id,
                binding.campaign_id,
                binding.identity_count,
                binding.required_target,
                binding.identity_set_digest,
                binding.qualification_head_hash_at_bind,
                binding.started_by,
            )
            if observed != expected:
                raise ConflictError(
                    "c3_run_id was reused with different qualification binding material",
                    {"c3_run_id": c3_run_id},
                )
            verification = self.verify(c3_run_id)
            if not verification.ok:
                raise IntegrityError(
                    "existing C3 qualification binding failed verification",
                    {
                        "c3_run_id": c3_run_id,
                        "defects": list(verification.defects),
                    },
                )
            return binding

        reused = self.database.connection.execute(
            """
            SELECT c3_run_id FROM c3_qualification_bindings
            WHERE qualification_run_id = ? OR certificate_id = ?
            """,
            (qualification_run_id, certificate_id),
        ).fetchone()
        if reused is not None:
            raise ConflictError(
                "qualification run or certificate is already bound to another C3 run",
                {"existing_c3_run_id": str(reused["c3_run_id"])},
            )

        try:
            with self.database.transaction() as connection:
                certificate_verification = self.certification.verify_certificate(
                    certificate_id
                )
                if not certificate_verification.ok:
                    raise IntegrityError(
                        "C2 certification verification failed",
                        {
                            "certificate_id": certificate_id,
                            "defects": list(certificate_verification.defects),
                        },
                    )
                qualification_verification = self.qualification.verify(
                    qualification_run_id
                )
                if not qualification_verification.ok:
                    raise IntegrityError(
                        "qualification run verification failed",
                        {
                            "qualification_run_id": qualification_run_id,
                            "defects": list(qualification_verification.defects),
                        },
                    )
                certificate_row = connection.execute(
                    "SELECT * FROM c2_certifications WHERE certificate_id = ?",
                    (certificate_id,),
                ).fetchone()
                run_row = connection.execute(
                    "SELECT * FROM qualification_runs WHERE qualification_run_id = ?",
                    (qualification_run_id,),
                ).fetchone()
                if certificate_row is None:
                    raise NotFoundError(
                        "C2 certification does not exist",
                        {"certificate_id": certificate_id},
                    )
                if run_row is None:
                    raise NotFoundError(
                        "qualification run does not exist",
                        {"qualification_run_id": qualification_run_id},
                    )
                current_certificate = self.certification.get_certificate(certificate_id)
                if current_certificate != certificate:
                    raise ConflictError(
                        "C2 certification changed during C3 binding",
                        {"certificate_id": certificate_id},
                    )
                current_run = self.qualification.get_run(qualification_run_id)
                if current_run != run:
                    raise ConflictError(
                        "qualification run changed during C3 binding",
                        {"qualification_run_id": qualification_run_id},
                    )
                artifact_count = int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM qualification_artifacts
                        WHERE qualification_run_id = ?
                        """,
                        (qualification_run_id,),
                    ).fetchone()[0]
                )
                if artifact_count != 0:
                    raise StateTransitionError(
                        "qualification run must be empty at C3 binding",
                        {
                            "qualification_run_id": qualification_run_id,
                            "artifact_count": artifact_count,
                        },
                    )
                head = connection.execute(
                    """
                    SELECT record_hash FROM ledger_events
                    WHERE stream_id = ? ORDER BY sequence DESC LIMIT 1
                    """,
                    (f"qualification:run:{qualification_run_id}",),
                ).fetchone()
                if head is None or str(head["record_hash"]) != run.ledger_hash:
                    raise IntegrityError(
                        "qualification ledger head does not prove an empty bind boundary",
                        {"qualification_run_id": qualification_run_id},
                    )
                race = connection.execute(
                    """
                    SELECT c3_run_id FROM c3_qualification_bindings
                    WHERE c3_run_id = ? OR qualification_run_id = ? OR certificate_id = ?
                    """,
                    (c3_run_id, qualification_run_id, certificate_id),
                ).fetchone()
                if race is not None:
                    raise ConflictError(
                        "C3 qualification binding appeared during start",
                        {"existing_c3_run_id": str(race["c3_run_id"])},
                    )
                provisional = C3QualificationBinding(
                    c3_run_id=c3_run_id,
                    qualification_run_id=qualification_run_id,
                    certificate_id=certificate_id,
                    recollection_id=certificate.recollection_id,
                    incident_id=certificate.incident_id,
                    campaign_id=certificate.campaign_id,
                    identity_count=certificate.identity_count,
                    required_target=certificate.required_target,
                    identity_set_digest=certificate.identity_set_digest,
                    qualification_head_hash_at_bind=run.ledger_hash,
                    started_at=occurred_at,
                    started_by=actor,
                    ledger_event_id="pending",
                    ledger_hash="pending",
                )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"continuity:c3:{c3_run_id}",
                    "C3_QUALIFICATION_STARTED",
                    self._payload(provisional),
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO c3_qualification_bindings (
                        c3_run_id, qualification_run_id, certificate_id,
                        recollection_id, incident_id, campaign_id,
                        identity_count, required_target, identity_set_digest,
                        qualification_head_hash_at_bind, started_at, started_by,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        c3_run_id,
                        qualification_run_id,
                        certificate_id,
                        certificate.recollection_id,
                        certificate.incident_id,
                        certificate.campaign_id,
                        certificate.identity_count,
                        certificate.required_target,
                        certificate.identity_set_digest,
                        run.ledger_hash,
                        occurred_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "C3 qualification binding already exists",
                {
                    "c3_run_id": c3_run_id,
                    "qualification_run_id": qualification_run_id,
                    "certificate_id": certificate_id,
                },
            ) from exc
        return self.get(c3_run_id)

    def verify(self, c3_run_id: str) -> C3QualificationVerification:
        binding = self.get(c3_run_id)
        defects: list[str] = []

        certificate = None
        try:
            certificate = self.certification.get_certificate(binding.certificate_id)
        except NotFoundError:
            defects.append("C3_CERTIFICATE_MISSING")
        else:
            verification = self.certification.verify_certificate(binding.certificate_id)
            defects.extend(
                f"C3_CERTIFICATE:{defect}"
                for defect in verification.defects
            )
            expected_certificate = (
                certificate.recollection_id,
                certificate.incident_id,
                certificate.campaign_id,
                certificate.identity_count,
                certificate.required_target,
                certificate.identity_set_digest,
            )
            observed_certificate = (
                binding.recollection_id,
                binding.incident_id,
                binding.campaign_id,
                binding.identity_count,
                binding.required_target,
                binding.identity_set_digest,
            )
            if observed_certificate != expected_certificate:
                defects.append("C3_CERTIFICATE_BINDING_MISMATCH")

        run = None
        try:
            run = self.qualification.get_run(binding.qualification_run_id)
        except NotFoundError:
            defects.append("C3_QUALIFICATION_RUN_MISSING")
        else:
            verification = self.qualification.verify(binding.qualification_run_id)
            defects.extend(
                f"C3_QUALIFICATION:{defect}"
                for defect in verification.defects
            )
            if binding.qualification_head_hash_at_bind != run.ledger_hash:
                defects.append("C3_QUALIFICATION_HEAD_AT_BIND_MISMATCH")

        artifacts = self.database.connection.execute(
            """
            SELECT artifact_id, kind, recorded_at FROM qualification_artifacts
            WHERE qualification_run_id = ? ORDER BY artifact_id
            """,
            (binding.qualification_run_id,),
        ).fetchall()
        for artifact in artifacts:
            artifact_id = str(artifact["artifact_id"])
            artifact_kind = str(artifact["kind"])
            if artifact_kind == "DECISION":
                defects.append(
                    f"C3_UNGOVERNED_DECISION_ARTIFACT:{artifact_id}"
                )
            elif artifact_kind == "ADOPTION":
                defects.append(
                    f"C3_UNAUTHORIZED_ADOPTION_ARTIFACT:{artifact_id}"
                )
        try:
            binding_time = datetime.fromisoformat(
                binding.started_at.replace("Z", "+00:00")
            )
        except ValueError:
            defects.append("C3_STARTED_AT_INVALID")
            binding_time = None
        if binding_time is not None:
            for artifact in artifacts:
                try:
                    artifact_time = datetime.fromisoformat(
                        str(artifact["recorded_at"]).replace("Z", "+00:00")
                    )
                except ValueError:
                    defects.append(
                        f"C3_ARTIFACT_TIME_INVALID:{artifact['artifact_id']}"
                    )
                    continue
                if artifact_time < binding_time:
                    defects.append(
                        f"C3_PRE_BINDING_ARTIFACT:{artifact['artifact_id']}"
                    )

        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (binding.ledger_event_id,),
        ).fetchone()
        expected_stream = f"continuity:c3:{binding.c3_run_id}"
        expected_payload = self._payload(binding)
        if event is None:
            defects.append("C3_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != expected_stream:
                defects.append("C3_LEDGER_STREAM_MISMATCH")
            if str(event["kind"]) != "C3_QUALIFICATION_STARTED":
                defects.append("C3_LEDGER_KIND_MISMATCH")
            if str(event["actor"]) != binding.started_by:
                defects.append("C3_LEDGER_ACTOR_MISMATCH")
            if str(event["occurred_at"]) != binding.started_at:
                defects.append("C3_LEDGER_TIMESTAMP_MISMATCH")
            if str(event["record_hash"]) != binding.ledger_hash:
                defects.append("C3_LEDGER_HASH_MISMATCH")
            try:
                payload = json.loads(str(event["payload_json"]))
            except (json.JSONDecodeError, TypeError):
                defects.append("C3_LEDGER_PAYLOAD_INVALID")
            else:
                if payload != expected_payload:
                    defects.append("C3_LEDGER_PAYLOAD_MISMATCH")

        chain = self.ledger.verify(expected_stream)
        defects.extend(
            f"C3_LEDGER_CHAIN:{defect.code}"
            for defect in chain.defects
        )
        return C3QualificationVerification(
            c3_run_id=binding.c3_run_id,
            defects=tuple(dict.fromkeys(defects)),
        )
