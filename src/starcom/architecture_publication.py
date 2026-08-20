from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import json
import sqlite3
from typing import Any, Mapping

from .architecture_candidate import C4ArchitectureCandidateService
from .architecture_input import C4ArchitectureInputService
from .architecture_review import (
    C4ArchitectureReviewService,
    C4ArchitectureReviewVerdict,
)
from .canonical import canonical_json, sha256_digest, utc_now
from .continuity import ContinuityService
from .errors import (
    AuthorizationError,
    ConflictError,
    IntegrityError,
    NotFoundError,
    StateTransitionError,
    ValidationError,
)
from .ledger import EventLedger
from .trust import AuthorizationDecision, TrustPlane


_PUBLICATION_ACTION = "c4.architecture.publish"
_PUBLICATION_MODE = "PUBLISH_ARCHITECTURE_NOT_DEPLOY"
_PUBLICATION_STATUS = "C4_ARCHITECTURE_PUBLISHED_NOT_DEPLOYED"
_PUBLICATION_EVENT_KIND = "C4_ARCHITECTURE_PUBLISHED_NOT_DEPLOYED"
_PUBLICATION_OPERATION_KIND = _PUBLICATION_EVENT_KIND
_REVIEW_GATE_EFFECT = "NO_PUBLICATION_NO_DEPLOYMENT"
_CANDIDATE_STATUS = "C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED"


class C4ArchitecturePublicationStatus(str, Enum):
    PUBLISHED_NOT_DEPLOYED = _PUBLICATION_STATUS


@dataclass(frozen=True)
class C4ArchitecturePublicationPreparation:
    publication_id: str
    candidate_id: str
    architecture_id: str
    architecture_version: str
    input_set_id: str
    manifest_sha256: str
    input_set_digest: str
    review_id: str
    reviewer_identity: str
    review_payload_sha256: str
    review_signature_sha256: str
    review_verdict: str
    publication_mode: str
    status: C4ArchitecturePublicationStatus
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, object]


@dataclass(frozen=True)
class C4ArchitecturePublication:
    publication_id: str
    candidate_id: str
    architecture_id: str
    architecture_version: str
    input_set_id: str
    manifest_sha256: str
    input_set_digest: str
    review_id: str
    reviewer_identity: str
    review_payload_sha256: str
    review_signature_sha256: str
    verdict: C4ArchitectureReviewVerdict
    publication_mode: str
    status: C4ArchitecturePublicationStatus
    authorization_decision_id: str
    published_at: str
    published_by: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class C4ArchitecturePublicationVerification:
    publication_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class C4ArchitecturePublicationService:
    """Publish one accepted C4 manifest into the internal registry only."""

    def __init__(
        self,
        database,
        ledger: EventLedger,
        trust: TrustPlane,
        continuity: ContinuityService,
        inputs: C4ArchitectureInputService,
        candidates: C4ArchitectureCandidateService,
        reviews: C4ArchitectureReviewService,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self.continuity = continuity
        self.inputs = inputs
        self.candidates = candidates
        self.reviews = reviews
        self._assert_canonical_graph()
        self._initialize_schema()

    def _assert_canonical_graph(self) -> None:
        expected = (
            (self.ledger, "database", self.database),
            (self.trust, "database", self.database),
            (self.trust, "ledger", self.ledger),
            (self.continuity, "database", self.database),
            (self.continuity, "ledger", self.ledger),
            (self.continuity, "trust", self.trust),
            (self.inputs, "database", self.database),
            (self.inputs, "ledger", self.ledger),
            (self.inputs, "trust", self.trust),
            (self.inputs, "continuity", self.continuity),
            (self.candidates, "database", self.database),
            (self.candidates, "ledger", self.ledger),
            (self.candidates, "trust", self.trust),
            (self.candidates, "continuity", self.continuity),
            (self.candidates, "inputs", self.inputs),
            (self.reviews, "database", self.database),
            (self.reviews, "ledger", self.ledger),
            (self.reviews, "trust", self.trust),
            (self.reviews, "continuity", self.continuity),
            (self.reviews, "inputs", self.inputs),
            (self.reviews, "candidates", self.candidates),
        )
        if any(
            getattr(item, attribute, None) is not value
            for item, attribute, value in expected
        ):
            raise ValidationError(
                "C4 architecture publication dependencies must share one canonical graph"
            )

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

    @staticmethod
    def _as_datetime(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    @staticmethod
    def _digest(value: object, field: str) -> str:
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
        return value

    @staticmethod
    def _stream(publication_id: str) -> str:
        return f"continuity:c4:architecture-publication:{publication_id}"

    @staticmethod
    def _resource(publication_id: str) -> str:
        return f"continuity:c4:architecture-publication:{publication_id}"

    @staticmethod
    def _mission(architecture_id: str) -> str:
        return f"c4-architecture:{architecture_id}"

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS c4_architecture_publications (
                    publication_id TEXT PRIMARY KEY,
                    candidate_id TEXT NOT NULL UNIQUE,
                    architecture_id TEXT NOT NULL UNIQUE,
                    architecture_version TEXT NOT NULL
                        CHECK (architecture_version = '3.2'),
                    input_set_id TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    manifest_sha256 TEXT NOT NULL
                        CHECK (length(manifest_sha256) = 64),
                    input_set_digest TEXT NOT NULL
                        CHECK (length(input_set_digest) = 64),
                    review_id TEXT NOT NULL UNIQUE,
                    reviewer_identity TEXT NOT NULL,
                    review_payload_sha256 TEXT NOT NULL
                        CHECK (length(review_payload_sha256) = 64),
                    review_signature_sha256 TEXT NOT NULL
                        CHECK (length(review_signature_sha256) = 64),
                    verdict TEXT NOT NULL
                        CHECK (verdict = 'C4_ARCHITECTURE_ACCEPTED'),
                    publication_mode TEXT NOT NULL
                        CHECK (publication_mode = 'PUBLISH_ARCHITECTURE_NOT_DEPLOY'),
                    status TEXT NOT NULL
                        CHECK (status = 'C4_ARCHITECTURE_PUBLISHED_NOT_DEPLOYED'),
                    authorization_decision_id TEXT NOT NULL UNIQUE,
                    published_at TEXT NOT NULL,
                    published_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (candidate_id)
                        REFERENCES c4_architecture_candidates(candidate_id),
                    FOREIGN KEY (input_set_id)
                        REFERENCES c4_architecture_input_sets(input_set_id),
                    FOREIGN KEY (review_id)
                        REFERENCES c4_architecture_reviews(review_id),
                    FOREIGN KEY (authorization_decision_id)
                        REFERENCES continuity_authorization_consumptions(decision_id)
                )
                """
            )
            for operation in ("UPDATE", "DELETE"):
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS
                        c4_architecture_publications_no_{operation.lower()}
                    BEFORE {operation} ON c4_architecture_publications
                    BEGIN SELECT RAISE(
                        ABORT, 'c4 architecture publication rows are immutable'
                    ); END
                    """
                )

    def _verified_material(
        self,
        candidate_id: str,
        review_id: str,
    ) -> tuple[object, object, object, Mapping[str, Any], str]:
        candidate_id = self._required_text(candidate_id, "candidate_id")
        review_id = self._required_text(review_id, "review_id")
        try:
            candidate = self.candidates.get_candidate(candidate_id)
            candidate_verification = self.candidates.verify_candidate(candidate_id)
        except (NotFoundError, ValidationError, TypeError, ValueError) as exc:
            raise IntegrityError("C4 publication candidate could not be verified") from exc
        if not candidate_verification.ok:
            raise IntegrityError(
                "C4 publication candidate failed verification",
                {
                    "candidate_id": candidate_id,
                    "defects": list(candidate_verification.defects),
                },
            )
        try:
            input_set = self.inputs.get_input_set(candidate.input_set_id)
            input_verification = self.inputs.verify_input_set(candidate.input_set_id)
        except (NotFoundError, ValidationError, TypeError, ValueError) as exc:
            raise IntegrityError("C4 publication input set could not be verified") from exc
        if not input_verification.ok:
            raise IntegrityError(
                "C4 publication input set failed verification",
                {
                    "input_set_id": candidate.input_set_id,
                    "defects": list(input_verification.defects),
                },
            )
        try:
            review = self.reviews.get_review(review_id)
            review_verification = self.reviews.verify_review(review_id)
        except (NotFoundError, ValidationError, TypeError, ValueError) as exc:
            raise IntegrityError("C4 publication review could not be verified") from exc
        if not review_verification.ok:
            raise IntegrityError(
                "C4 publication review failed verification",
                {"review_id": review_id, "defects": list(review_verification.defects)},
            )
        if review.candidate_id != candidate.candidate_id:
            raise IntegrityError("C4 publication review candidate binding is invalid")
        if review.input_set_id != input_set.input_set_id:
            raise IntegrityError("C4 publication review input-set binding is invalid")
        if review.architecture_id != candidate.architecture_id:
            raise IntegrityError("C4 publication review architecture binding is invalid")
        if review.manifest_sha256 != candidate.manifest_sha256:
            raise IntegrityError("C4 publication review manifest binding is invalid")
        if review.input_set_digest != input_set.input_set_digest:
            raise IntegrityError("C4 publication review input-set digest is invalid")
        if review.verdict is not C4ArchitectureReviewVerdict.ACCEPTED:
            raise StateTransitionError(
                "only an accepted C4 architecture review can be published"
            )
        if review.gate_effect != _REVIEW_GATE_EFFECT:
            raise IntegrityError("C4 architecture review gate effect is invalid")
        status = getattr(candidate.status, "value", candidate.status)
        if status != _CANDIDATE_STATUS:
            raise StateTransitionError("C4 architecture candidate is not publishable")
        try:
            manifest = self.candidates.get_manifest(candidate_id)
        except (NotFoundError, IntegrityError, TypeError, ValueError) as exc:
            raise IntegrityError("C4 publication candidate manifest is unavailable") from exc
        if not isinstance(manifest, Mapping):
            raise IntegrityError("C4 publication candidate manifest is not an object")
        manifest_json = canonical_json(manifest)
        return candidate, input_set, review, dict(manifest), manifest_json

    def _context(
        self,
        preparation_fields: Mapping[str, object],
    ) -> dict[str, object]:
        return dict(preparation_fields)

    def prepare(
        self,
        publication_id: str,
        candidate_id: str,
        review_id: str,
    ) -> C4ArchitecturePublicationPreparation:
        publication_id = self._required_text(publication_id, "publication_id")
        candidate, input_set, review, _, _ = self._verified_material(
            candidate_id, review_id
        )
        fields = {
            "publication_id": publication_id,
            "candidate_id": candidate.candidate_id,
            "architecture_id": candidate.architecture_id,
            "input_set_id": input_set.input_set_id,
            "manifest_sha256": candidate.manifest_sha256,
            "input_set_digest": input_set.input_set_digest,
            "review_id": review.review_id,
            "reviewer_identity": review.reviewer_identity,
            "review_payload_sha256": review.payload_sha256,
            "review_signature_sha256": review.signature_sha256,
            "review_verdict": review.verdict.value,
            "publication_mode": _PUBLICATION_MODE,
            "status": _PUBLICATION_STATUS,
        }
        return C4ArchitecturePublicationPreparation(
            publication_id=publication_id,
            candidate_id=candidate.candidate_id,
            architecture_id=candidate.architecture_id,
            architecture_version=candidate.architecture_version,
            input_set_id=input_set.input_set_id,
            manifest_sha256=candidate.manifest_sha256,
            input_set_digest=input_set.input_set_digest,
            review_id=review.review_id,
            reviewer_identity=review.reviewer_identity,
            review_payload_sha256=review.payload_sha256,
            review_signature_sha256=review.signature_sha256,
            review_verdict=review.verdict.value,
            publication_mode=_PUBLICATION_MODE,
            status=C4ArchitecturePublicationStatus.PUBLISHED_NOT_DEPLOYED,
            action=_PUBLICATION_ACTION,
            resource=self._resource(publication_id),
            mission_id=self._mission(candidate.architecture_id),
            context=self._context(fields),
        )

    prepare_publish = prepare

    def _assert_authorization(
        self,
        decision_id: str,
        *,
        preparation: C4ArchitecturePublicationPreparation,
        actor: str,
    ) -> AuthorizationDecision:
        decision_id = self._required_text(decision_id, "authorization_decision_id")
        actor = self._required_text(actor, "actor")
        verification = self.trust.verify_decision(decision_id)
        if not verification.ok:
            raise AuthorizationError(
                "C4 publication authorization decision failed verification",
                {"decision_id": decision_id, "defects": list(verification.defects)},
            )
        try:
            decision = self.trust.get_decision(decision_id)
        except NotFoundError as exc:
            raise AuthorizationError(
                "C4 publication authorization decision does not exist"
            ) from exc
        observed = (
            decision.request.subject,
            decision.request.action,
            decision.request.resource,
            decision.request.mission_id,
            dict(decision.request.context),
        )
        expected = (
            actor,
            preparation.action,
            preparation.resource,
            preparation.mission_id,
            dict(preparation.context),
        )
        if not decision.allowed or observed != expected:
            raise AuthorizationError(
                "authorization decision does not exactly match C4 publication",
                {
                    "decision_id": decision_id,
                    "allowed": decision.allowed,
                    "expected": list(expected),
                    "observed": list(observed),
                },
            )
        return decision

    @staticmethod
    def _record_from_row(row: sqlite3.Row) -> C4ArchitecturePublication:
        try:
            verdict = C4ArchitectureReviewVerdict(str(row["verdict"]))
            status = C4ArchitecturePublicationStatus(str(row["status"]))
        except ValueError as exc:
            raise IntegrityError("stored C4 publication enum is invalid") from exc
        return C4ArchitecturePublication(
            publication_id=str(row["publication_id"]),
            candidate_id=str(row["candidate_id"]),
            architecture_id=str(row["architecture_id"]),
            architecture_version=str(row["architecture_version"]),
            input_set_id=str(row["input_set_id"]),
            manifest_sha256=str(row["manifest_sha256"]),
            input_set_digest=str(row["input_set_digest"]),
            review_id=str(row["review_id"]),
            reviewer_identity=str(row["reviewer_identity"]),
            review_payload_sha256=str(row["review_payload_sha256"]),
            review_signature_sha256=str(row["review_signature_sha256"]),
            verdict=verdict,
            publication_mode=str(row["publication_mode"]),
            status=status,
            authorization_decision_id=str(row["authorization_decision_id"]),
            published_at=str(row["published_at"]),
            published_by=str(row["published_by"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def _row_for_identity(
        self,
        publication_id: str,
        candidate_id: str,
        review_id: str,
    ) -> sqlite3.Row | None:
        return self.database.connection.execute(
            """
            SELECT * FROM c4_architecture_publications
            WHERE publication_id = ? OR candidate_id = ? OR review_id = ?
            ORDER BY publication_id
            LIMIT 1
            """,
            (publication_id, candidate_id, review_id),
        ).fetchone()

    def get_publication(self, publication_id: str) -> C4ArchitecturePublication:
        publication_id = self._required_text(publication_id, "publication_id")
        row = self.database.connection.execute(
            "SELECT * FROM c4_architecture_publications WHERE publication_id = ?",
            (publication_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C4 architecture publication does not exist",
                {"publication_id": publication_id},
            )
        try:
            return self._record_from_row(row)
        except (KeyError, TypeError, ValueError, IntegrityError) as exc:
            raise IntegrityError("stored C4 architecture publication is malformed") from exc

    def get_publication_for_candidate(
        self,
        candidate_id: str,
    ) -> C4ArchitecturePublication:
        candidate_id = self._required_text(candidate_id, "candidate_id")
        row = self.database.connection.execute(
            "SELECT * FROM c4_architecture_publications WHERE candidate_id = ?",
            (candidate_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C4 architecture publication for candidate does not exist",
                {"candidate_id": candidate_id},
            )
        return self._record_from_row(row)

    def get_manifest(self, publication_id: str) -> Mapping[str, Any]:
        self.get_publication(publication_id)
        row = self.database.connection.execute(
            "SELECT manifest_json FROM c4_architecture_publications WHERE publication_id = ?",
            (publication_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("C4 architecture publication does not exist")
        try:
            manifest = json.loads(str(row["manifest_json"]))
        except (json.JSONDecodeError, TypeError) as exc:
            raise IntegrityError("stored C4 publication manifest is invalid") from exc
        if not isinstance(manifest, dict):
            raise IntegrityError("stored C4 publication manifest must be an object")
        if canonical_json(manifest) != str(row["manifest_json"]):
            raise IntegrityError("stored C4 publication manifest is not canonical")
        return manifest

    @staticmethod
    def _event_payload(
        publication: C4ArchitecturePublication,
    ) -> dict[str, object]:
        return {
            "publication_id": publication.publication_id,
            "candidate_id": publication.candidate_id,
            "architecture_id": publication.architecture_id,
            "architecture_version": publication.architecture_version,
            "input_set_id": publication.input_set_id,
            "manifest_sha256": publication.manifest_sha256,
            "input_set_digest": publication.input_set_digest,
            "review_id": publication.review_id,
            "reviewer_identity": publication.reviewer_identity,
            "review_payload_sha256": publication.review_payload_sha256,
            "review_signature_sha256": publication.review_signature_sha256,
            "verdict": publication.verdict.value,
            "publication_mode": publication.publication_mode,
            "status": publication.status.value,
            "authorization_decision_id": publication.authorization_decision_id,
        }

    @staticmethod
    def _replay_matches(
        row: sqlite3.Row,
        preparation: C4ArchitecturePublicationPreparation,
        *,
        authorization_decision_id: str,
        actor: str,
    ) -> bool:
        expected = {
            "publication_id": preparation.publication_id,
            "candidate_id": preparation.candidate_id,
            "architecture_id": preparation.architecture_id,
            "architecture_version": preparation.architecture_version,
            "input_set_id": preparation.input_set_id,
            "manifest_sha256": preparation.manifest_sha256,
            "input_set_digest": preparation.input_set_digest,
            "review_id": preparation.review_id,
            "reviewer_identity": preparation.reviewer_identity,
            "review_payload_sha256": preparation.review_payload_sha256,
            "review_signature_sha256": preparation.review_signature_sha256,
            "verdict": preparation.review_verdict,
            "publication_mode": preparation.publication_mode,
            "status": preparation.status.value,
            "authorization_decision_id": authorization_decision_id,
            "published_by": actor,
        }
        return all(str(row[field]) == str(value) for field, value in expected.items())

    def publish(
        self,
        publication_id: str,
        candidate_id: str,
        review_id: str,
        authorization_decision_id: str,
        *,
        actor: str,
        occurred_at: str | None = None,
    ) -> C4ArchitecturePublication:
        publication_id = self._required_text(publication_id, "publication_id")
        actor = self._required_text(actor, "actor")
        occurred_at = self._timestamp(occurred_at or utc_now())
        preparation = self.prepare(publication_id, candidate_id, review_id)
        existing = self._row_for_identity(publication_id, candidate_id, review_id)
        if existing is not None:
            if self._replay_matches(
                existing,
                preparation,
                authorization_decision_id=authorization_decision_id,
                actor=actor,
            ):
                record = self._record_from_row(existing)
                verification = self.verify_publication(record.publication_id)
                if not verification.ok:
                    raise IntegrityError(
                        "existing C4 architecture publication failed verification",
                        {
                            "publication_id": record.publication_id,
                            "defects": list(verification.defects),
                        },
                    )
                return record
            raise ConflictError(
                "C4 architecture publication identifier or binding was reused with different material",
                {"publication_id": publication_id},
            )
        decision = self._assert_authorization(
            authorization_decision_id,
            preparation=preparation,
            actor=actor,
        )
        _, _, review, _, manifest_json = self._verified_material(
            preparation.candidate_id, preparation.review_id
        )
        if self._as_datetime(decision.decided_at) <= self._as_datetime(review.admitted_at):
            raise StateTransitionError(
                "C4 publication authorization must be decided after review admission"
            )
        if self._as_datetime(occurred_at) < self._as_datetime(decision.decided_at):
            raise StateTransitionError(
                "C4 publication predates its TrustPlane authorization"
            )
        provisional = C4ArchitecturePublication(
            publication_id=preparation.publication_id,
            candidate_id=preparation.candidate_id,
            architecture_id=preparation.architecture_id,
            architecture_version=preparation.architecture_version,
            input_set_id=preparation.input_set_id,
            manifest_sha256=preparation.manifest_sha256,
            input_set_digest=preparation.input_set_digest,
            review_id=preparation.review_id,
            reviewer_identity=preparation.reviewer_identity,
            review_payload_sha256=preparation.review_payload_sha256,
            review_signature_sha256=preparation.review_signature_sha256,
            verdict=C4ArchitectureReviewVerdict.ACCEPTED,
            publication_mode=_PUBLICATION_MODE,
            status=C4ArchitecturePublicationStatus.PUBLISHED_NOT_DEPLOYED,
            authorization_decision_id=authorization_decision_id,
            published_at=occurred_at,
            published_by=actor,
            ledger_event_id="pending",
            ledger_hash="pending",
        )
        event_payload = self._event_payload(provisional)
        try:
            with self.database.transaction() as connection:
                current = self.prepare(
                    preparation.publication_id,
                    preparation.candidate_id,
                    preparation.review_id,
                )
                if current != preparation:
                    raise ConflictError("C4 publication material changed during admission")
                current_decision = self._assert_authorization(
                    authorization_decision_id,
                    preparation=current,
                    actor=actor,
                )
                if self._as_datetime(current_decision.decided_at) <= self._as_datetime(
                    review.admitted_at
                ):
                    raise StateTransitionError(
                        "C4 publication authorization must be decided after review admission"
                    )
                if self._as_datetime(occurred_at) < self._as_datetime(
                    current_decision.decided_at
                ):
                    raise StateTransitionError(
                        "C4 publication predates its TrustPlane authorization"
                    )
                race = connection.execute(
                    """
                    SELECT * FROM c4_architecture_publications
                    WHERE publication_id = ? OR candidate_id = ? OR review_id = ?
                    LIMIT 1
                    """,
                    (
                        preparation.publication_id,
                        preparation.candidate_id,
                        preparation.review_id,
                    ),
                ).fetchone()
                if race is not None:
                    raise ConflictError("C4 architecture publication appeared during admission")
                self.continuity._consume_authorization(
                    connection,
                    decision_id=authorization_decision_id,
                    operation_kind=_PUBLICATION_OPERATION_KIND,
                    operation_id=preparation.publication_id,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                receipt = self.ledger.append_in_transaction(
                    connection,
                    self._stream(preparation.publication_id),
                    _PUBLICATION_EVENT_KIND,
                    event_payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO c4_architecture_publications (
                        publication_id, candidate_id, architecture_id,
                        architecture_version, input_set_id, manifest_json,
                        manifest_sha256, input_set_digest, review_id,
                        reviewer_identity, review_payload_sha256,
                        review_signature_sha256, verdict, publication_mode,
                        status, authorization_decision_id, published_at,
                        published_by, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        provisional.publication_id,
                        provisional.candidate_id,
                        provisional.architecture_id,
                        provisional.architecture_version,
                        provisional.input_set_id,
                        manifest_json,
                        provisional.manifest_sha256,
                        provisional.input_set_digest,
                        provisional.review_id,
                        provisional.reviewer_identity,
                        provisional.review_payload_sha256,
                        provisional.review_signature_sha256,
                        provisional.verdict.value,
                        provisional.publication_mode,
                        provisional.status.value,
                        provisional.authorization_decision_id,
                        provisional.published_at,
                        provisional.published_by,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except ConflictError:
            raise
        except sqlite3.IntegrityError as exc:
            race = self._row_for_identity(
                preparation.publication_id,
                preparation.candidate_id,
                preparation.review_id,
            )
            if race is not None and self._replay_matches(
                race,
                preparation,
                authorization_decision_id=authorization_decision_id,
                actor=actor,
            ):
                record = self._record_from_row(race)
                verification = self.verify_publication(record.publication_id)
                if verification.ok:
                    return record
            raise ConflictError(
                "C4 architecture publication violates an integrity constraint",
                {"publication_id": publication_id},
            ) from exc
        return self.get_publication(publication_id)

    def verify_publication(
        self,
        publication_id: str,
    ) -> C4ArchitecturePublicationVerification:
        publication_id = self._required_text(publication_id, "publication_id")
        row = self.database.connection.execute(
            "SELECT * FROM c4_architecture_publications WHERE publication_id = ?",
            (publication_id,),
        ).fetchone()
        if row is None:
            return C4ArchitecturePublicationVerification(
                publication_id, ("PUBLICATION_NOT_FOUND",)
            )
        defects: list[str] = []

        def add(code: str) -> None:
            if code not in defects:
                defects.append(code)

        try:
            record = self._record_from_row(row)
        except (IntegrityError, KeyError, TypeError, ValueError):
            return C4ArchitecturePublicationVerification(
                publication_id, ("PUBLICATION_ROW_INVALID",)
            )
        if record.publication_id != publication_id:
            add("PUBLICATION_ID_MISMATCH")
        if record.status is not C4ArchitecturePublicationStatus.PUBLISHED_NOT_DEPLOYED:
            add("PUBLICATION_STATUS_MISMATCH")
        if record.publication_mode != _PUBLICATION_MODE:
            add("PUBLICATION_MODE_MISMATCH")
        if record.verdict is not C4ArchitectureReviewVerdict.ACCEPTED:
            add("PUBLICATION_VERDICT_MISMATCH")
        try:
            candidate, input_set, review, manifest, manifest_json = self._verified_material(
                record.candidate_id, record.review_id
            )
        except (
            IntegrityError,
            NotFoundError,
            StateTransitionError,
            ValidationError,
            TypeError,
            ValueError,
        ):
            add("PUBLICATION_C4_GRAPH_INVALID")
            candidate = input_set = review = None
            manifest = None
            manifest_json = None
        if candidate is not None and input_set is not None and review is not None:
            if record.architecture_id != candidate.architecture_id:
                add("PUBLICATION_ARCHITECTURE_ID_MISMATCH")
            if record.architecture_version != candidate.architecture_version:
                add("PUBLICATION_ARCHITECTURE_VERSION_MISMATCH")
            if record.input_set_id != input_set.input_set_id:
                add("PUBLICATION_INPUT_SET_ID_MISMATCH")
            if record.manifest_sha256 != candidate.manifest_sha256:
                add("PUBLICATION_MANIFEST_DIGEST_MISMATCH")
            if record.input_set_digest != input_set.input_set_digest:
                add("PUBLICATION_INPUT_SET_DIGEST_MISMATCH")
            if record.review_id != review.review_id:
                add("PUBLICATION_REVIEW_ID_MISMATCH")
            if record.reviewer_identity != review.reviewer_identity:
                add("PUBLICATION_REVIEWER_IDENTITY_MISMATCH")
            if record.review_payload_sha256 != review.payload_sha256:
                add("PUBLICATION_REVIEW_PAYLOAD_DIGEST_MISMATCH")
            if record.review_signature_sha256 != review.signature_sha256:
                add("PUBLICATION_REVIEW_SIGNATURE_DIGEST_MISMATCH")
            if review.verdict is not C4ArchitectureReviewVerdict.ACCEPTED:
                add("PUBLICATION_REVIEW_NOT_ACCEPTED")
            if manifest_json != str(row["manifest_json"]):
                add("PUBLICATION_MANIFEST_MISMATCH")
            if str(row["manifest_sha256"]) != record.manifest_sha256:
                add("PUBLICATION_STORED_MANIFEST_DIGEST_MISMATCH")

        try:
            decision_verification = self.trust.verify_decision(
                record.authorization_decision_id
            )
        except (TypeError, ValueError, sqlite3.Error):
            decision_verification = None
            add("PUBLICATION_DECISION_INVALID")
        if decision_verification is not None and not decision_verification.ok:
            add("PUBLICATION_DECISION_INVALID")
        try:
            decision = self.trust.get_decision(record.authorization_decision_id)
        except (NotFoundError, TypeError, ValueError):
            decision = None
            add("PUBLICATION_DECISION_MISSING")
        if decision is not None and candidate is not None and review is not None:
            preparation = self.prepare(
                record.publication_id,
                record.candidate_id,
                record.review_id,
            )
            expected_request = (
                record.published_by,
                preparation.action,
                preparation.resource,
                preparation.mission_id,
                dict(preparation.context),
            )
            observed_request = (
                decision.request.subject,
                decision.request.action,
                decision.request.resource,
                decision.request.mission_id,
                dict(decision.request.context),
            )
            if not decision.allowed or observed_request != expected_request:
                add("PUBLICATION_DECISION_REQUEST_MISMATCH")
            try:
                decision_time = self._as_datetime(decision.decided_at)
                review_time = self._as_datetime(review.admitted_at)
                publication_time = self._as_datetime(record.published_at)
            except (TypeError, ValueError):
                add("PUBLICATION_CHRONOLOGY_INVALID")
            else:
                if decision_time <= review_time:
                    add("PUBLICATION_DECISION_NOT_POST_REVIEW")
                if publication_time < decision_time:
                    add("PUBLICATION_TIME_PREDATES_DECISION")

        consumption = self.database.connection.execute(
            """
            SELECT * FROM continuity_authorization_consumptions
            WHERE decision_id = ?
            """,
            (record.authorization_decision_id,),
        ).fetchone()
        if consumption is None:
            add("PUBLICATION_AUTHORIZATION_CONSUMPTION_MISSING")
        elif (
            str(consumption["operation_kind"]),
            str(consumption["operation_id"]),
            str(consumption["consumed_at"]),
            str(consumption["consumed_by"]),
        ) != (
            _PUBLICATION_OPERATION_KIND,
            record.publication_id,
            record.published_at,
            record.published_by,
        ):
            add("PUBLICATION_AUTHORIZATION_CONSUMPTION_MISMATCH")

        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (record.ledger_event_id,),
        ).fetchone()
        expected_payload = self._event_payload(record)
        if event is None:
            add("PUBLICATION_LEDGER_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != self._stream(record.publication_id):
                add("PUBLICATION_LEDGER_STREAM_MISMATCH")
            if str(event["kind"]) != _PUBLICATION_EVENT_KIND:
                add("PUBLICATION_LEDGER_KIND_MISMATCH")
            if str(event["actor"]) != record.published_by:
                add("PUBLICATION_LEDGER_ACTOR_MISMATCH")
            if str(event["occurred_at"]) != record.published_at:
                add("PUBLICATION_LEDGER_TIME_MISMATCH")
            if str(event["record_hash"]) != record.ledger_hash:
                add("PUBLICATION_LEDGER_HASH_MISMATCH")
            try:
                observed_payload = json.loads(str(event["payload_json"]))
            except (json.JSONDecodeError, TypeError, ValueError):
                add("PUBLICATION_LEDGER_PAYLOAD_INVALID")
            else:
                if observed_payload != expected_payload:
                    add("PUBLICATION_LEDGER_PAYLOAD_MISMATCH")
        try:
            chain = self.ledger.verify(self._stream(record.publication_id))
        except (json.JSONDecodeError, TypeError, ValueError, sqlite3.Error):
            chain = None
            add("PUBLICATION_LEDGER_CHAIN_INVALID")
        if chain is not None and not chain.ok:
            add("PUBLICATION_LEDGER_CHAIN_INVALID")
        return C4ArchitecturePublicationVerification(publication_id, tuple(defects))
