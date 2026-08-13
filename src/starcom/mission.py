from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import sqlite3
from uuid import uuid4

from .canonical import sha256_digest, utc_now
from .db import Database
from .errors import ConflictError, NotFoundError, StateTransitionError, ValidationError
from .ledger import EventLedger
from .proof import ProofEngine
from .trust import TrustPlane


class MissionState(str, Enum):
    CREATED = "CREATED"
    PLANNED = "PLANNED"
    AUTHORIZED = "AUTHORIZED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


TERMINAL_STATES = frozenset(
    {MissionState.SUCCEEDED, MissionState.FAILED, MissionState.CANCELLED}
)

ALLOWED_TRANSITIONS: dict[MissionState, frozenset[MissionState]] = {
    MissionState.CREATED: frozenset({MissionState.PLANNED, MissionState.CANCELLED}),
    MissionState.PLANNED: frozenset({MissionState.AUTHORIZED, MissionState.CANCELLED}),
    MissionState.AUTHORIZED: frozenset({MissionState.RUNNING, MissionState.CANCELLED}),
    MissionState.RUNNING: frozenset(
        {
            MissionState.PAUSED,
            MissionState.SUCCEEDED,
            MissionState.FAILED,
            MissionState.CANCELLED,
        }
    ),
    MissionState.PAUSED: frozenset(
        {MissionState.RUNNING, MissionState.FAILED, MissionState.CANCELLED}
    ),
    MissionState.SUCCEEDED: frozenset(),
    MissionState.FAILED: frozenset(),
    MissionState.CANCELLED: frozenset(),
}

AUTHORIZATION_ACTIONS = {
    MissionState.AUTHORIZED: "mission:authorize",
    MissionState.RUNNING: "mission:run",
}


@dataclass(frozen=True)
class Mission:
    mission_id: str
    title: str
    objective: str
    owner: str
    state: MissionState
    revision: int
    created_at: str
    updated_at: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class TransitionReceipt:
    transition_id: str
    mission_id: str
    from_state: MissionState
    to_state: MissionState
    actor: str
    reason: str
    idempotency_key: str
    request_digest: str
    authorization_decision_id: str | None
    certificate_id: str | None
    occurred_at: str
    ledger_event_id: str
    ledger_hash: str


class MissionKernel:
    def __init__(
        self,
        database: Database,
        ledger: EventLedger,
        trust: TrustPlane,
        proof: ProofEngine,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self.proof = proof
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

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS missions (
                    mission_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    objective TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (
                        state IN ('CREATED','PLANNED','AUTHORIZED','RUNNING','PAUSED','SUCCEEDED','FAILED','CANCELLED')
                    ),
                    revision INTEGER NOT NULL CHECK (revision >= 0),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS mission_transitions (
                    transition_id TEXT PRIMARY KEY,
                    mission_id TEXT NOT NULL,
                    from_state TEXT NOT NULL,
                    to_state TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
                    authorization_decision_id TEXT UNIQUE,
                    certificate_id TEXT UNIQUE,
                    occurred_at TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    UNIQUE (mission_id, idempotency_key),
                    FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS mission_transitions_no_update
                BEFORE UPDATE ON mission_transitions
                BEGIN SELECT RAISE(ABORT, 'mission transitions are immutable'); END
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS mission_transitions_no_delete
                BEFORE DELETE ON mission_transitions
                BEGIN SELECT RAISE(ABORT, 'mission transitions are immutable'); END
                """
            )

    def create(
        self,
        *,
        mission_id: str | None = None,
        title: str,
        objective: str,
        owner: str,
        occurred_at: str | None = None,
    ) -> Mission:
        mission_id = self._required_text(mission_id or str(uuid4()), "mission_id")
        title = self._required_text(title, "title")
        objective = self._required_text(objective, "objective")
        owner = self._required_text(owner, "owner")
        occurred_at = self._validate_time(occurred_at or utc_now())
        payload = {
            "mission_id": mission_id,
            "title": title,
            "objective": objective,
            "owner": owner,
            "state": MissionState.CREATED.value,
        }
        try:
            with self.database.transaction() as connection:
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"mission:{mission_id}",
                    "MISSION_CREATED",
                    payload,
                    actor=owner,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO missions (
                        mission_id, title, objective, owner, state, revision,
                        created_at, updated_at, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
                    """,
                    (
                        mission_id,
                        title,
                        objective,
                        owner,
                        MissionState.CREATED.value,
                        occurred_at,
                        occurred_at,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("mission already exists", {"mission_id": mission_id}) from exc
        return self.get(mission_id)

    def get(self, mission_id: str) -> Mission:
        row = self.database.connection.execute(
            "SELECT * FROM missions WHERE mission_id = ?",
            (mission_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("mission does not exist", {"mission_id": mission_id})
        return Mission(
            mission_id=str(row["mission_id"]),
            title=str(row["title"]),
            objective=str(row["objective"]),
            owner=str(row["owner"]),
            state=MissionState(str(row["state"])),
            revision=int(row["revision"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def _validate_authorization(
        self,
        decision_id: str | None,
        *,
        mission_id: str,
        actor: str,
        expected_action: str,
    ) -> None:
        if decision_id is None:
            raise StateTransitionError(
                "transition requires an authorization decision",
                {"mission_id": mission_id, "action": expected_action},
            )
        verification = self.trust.verify_decision(decision_id)
        if not verification.ok:
            raise StateTransitionError(
                "authorization decision failed integrity verification",
                {"decision_id": decision_id, "defects": list(verification.defects)},
            )
        decision = self.trust.get_decision(decision_id)
        request = decision.request
        if not decision.allowed:
            raise StateTransitionError("authorization decision is denied")
        expected_resource = f"mission:{mission_id}"
        if (
            request.subject != actor
            or request.action != expected_action
            or request.resource != expected_resource
            or request.mission_id != mission_id
        ):
            raise StateTransitionError(
                "authorization decision does not match transition",
                {
                    "decision_id": decision_id,
                    "expected_subject": actor,
                    "expected_action": expected_action,
                    "expected_resource": expected_resource,
                    "expected_mission_id": mission_id,
                },
            )

    def _validate_certificate(self, certificate_id: str | None, mission_id: str) -> None:
        if certificate_id is None:
            raise StateTransitionError("successful mission requires a proof certificate")
        verification = self.proof.verify_certificate(certificate_id)
        if not verification.ok:
            raise StateTransitionError(
                "proof certificate failed integrity verification",
                {"certificate_id": certificate_id, "defects": list(verification.defects)},
            )
        certificate = self.proof.get_certificate(certificate_id)
        claim = self.proof.get_claim(certificate.claim_id)
        if claim.subject_type != "mission" or claim.subject_id != mission_id:
            raise StateTransitionError("proof certificate belongs to a different mission")

    @staticmethod
    def _row_to_receipt(row: sqlite3.Row) -> TransitionReceipt:
        return TransitionReceipt(
            transition_id=str(row["transition_id"]),
            mission_id=str(row["mission_id"]),
            from_state=MissionState(str(row["from_state"])),
            to_state=MissionState(str(row["to_state"])),
            actor=str(row["actor"]),
            reason=str(row["reason"]),
            idempotency_key=str(row["idempotency_key"]),
            request_digest=str(row["request_digest"]),
            authorization_decision_id=(
                str(row["authorization_decision_id"])
                if row["authorization_decision_id"] is not None
                else None
            ),
            certificate_id=(
                str(row["certificate_id"]) if row["certificate_id"] is not None else None
            ),
            occurred_at=str(row["occurred_at"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def transition(
        self,
        mission_id: str,
        to_state: MissionState,
        *,
        actor: str,
        idempotency_key: str,
        reason: str = "",
        authorization_decision_id: str | None = None,
        certificate_id: str | None = None,
        occurred_at: str | None = None,
    ) -> TransitionReceipt:
        mission_id = self._required_text(mission_id, "mission_id")
        actor = self._required_text(actor, "actor")
        idempotency_key = self._required_text(idempotency_key, "idempotency_key")
        if not isinstance(reason, str):
            raise ValidationError("reason must be a string")
        if not isinstance(to_state, MissionState):
            try:
                to_state = MissionState(str(to_state))
            except ValueError as exc:
                raise ValidationError("unknown mission state") from exc
        occurred_at = self._validate_time(occurred_at or utc_now())
        request_material = {
            "mission_id": mission_id,
            "to_state": to_state.value,
            "actor": actor,
            "reason": reason,
            "authorization_decision_id": authorization_decision_id,
            "certificate_id": certificate_id,
        }
        request_digest = sha256_digest(request_material)

        with self.database.transaction() as connection:
            existing = connection.execute(
                """
                SELECT * FROM mission_transitions
                WHERE mission_id = ? AND idempotency_key = ?
                """,
                (mission_id, idempotency_key),
            ).fetchone()
            if existing is not None:
                if str(existing["request_digest"]) != request_digest:
                    raise ConflictError(
                        "idempotency key was used with a different transition payload",
                        {"mission_id": mission_id, "idempotency_key": idempotency_key},
                    )
                return self._row_to_receipt(existing)

            mission = connection.execute(
                "SELECT * FROM missions WHERE mission_id = ?",
                (mission_id,),
            ).fetchone()
            if mission is None:
                raise NotFoundError("mission does not exist", {"mission_id": mission_id})
            current_state = MissionState(str(mission["state"]))
            if current_state in TERMINAL_STATES:
                raise StateTransitionError(
                    "terminal mission state is immutable",
                    {"mission_id": mission_id, "state": current_state.value},
                )
            if to_state not in ALLOWED_TRANSITIONS[current_state]:
                raise StateTransitionError(
                    f"transition {current_state.value} -> {to_state.value} is not allowed",
                    {
                        "mission_id": mission_id,
                        "from_state": current_state.value,
                        "to_state": to_state.value,
                    },
                )
            if authorization_decision_id is not None:
                reused = connection.execute(
                    """
                    SELECT transition_id FROM mission_transitions
                    WHERE authorization_decision_id = ?
                    """,
                    (authorization_decision_id,),
                ).fetchone()
                if reused is not None:
                    raise ConflictError(
                        "authorization decision has already been consumed by a transition",
                        {"decision_id": authorization_decision_id},
                    )
            expected_action = AUTHORIZATION_ACTIONS.get(to_state)
            if expected_action is not None:
                self._validate_authorization(
                    authorization_decision_id,
                    mission_id=mission_id,
                    actor=actor,
                    expected_action=expected_action,
                )
            elif authorization_decision_id is not None:
                verification = self.trust.verify_decision(authorization_decision_id)
                if not verification.ok:
                    raise StateTransitionError(
                        "authorization decision failed integrity verification"
                    )
            if to_state is MissionState.SUCCEEDED:
                self._validate_certificate(certificate_id, mission_id)
            elif certificate_id is not None:
                raise StateTransitionError(
                    "proof certificate may only be attached to SUCCEEDED transition"
                )

            transition_id = str(uuid4())
            payload = {
                "transition_id": transition_id,
                "mission_id": mission_id,
                "from_state": current_state.value,
                "to_state": to_state.value,
                "actor": actor,
                "reason": reason,
                "idempotency_key": idempotency_key,
                "request_digest": request_digest,
                "authorization_decision_id": authorization_decision_id,
                "certificate_id": certificate_id,
            }
            receipt = self.ledger.append_in_transaction(
                connection,
                f"mission:{mission_id}",
                "MISSION_TRANSITIONED",
                payload,
                actor=actor,
                occurred_at=occurred_at,
            )
            try:
                connection.execute(
                    """
                    INSERT INTO mission_transitions (
                        transition_id, mission_id, from_state, to_state, actor,
                        reason, idempotency_key, request_digest,
                        authorization_decision_id, certificate_id, occurred_at,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        transition_id,
                        mission_id,
                        current_state.value,
                        to_state.value,
                        actor,
                        reason,
                        idempotency_key,
                        request_digest,
                        authorization_decision_id,
                        certificate_id,
                        occurred_at,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                if authorization_decision_id is not None:
                    raise ConflictError(
                        "authorization decision has already been consumed by a transition",
                        {"decision_id": authorization_decision_id},
                    ) from exc
                raise ConflictError("mission transition conflicts with existing state") from exc
            connection.execute(
                """
                UPDATE missions
                SET state = ?, revision = revision + 1, updated_at = ?,
                    ledger_event_id = ?, ledger_hash = ?
                WHERE mission_id = ?
                """,
                (
                    to_state.value,
                    occurred_at,
                    receipt.event_id,
                    receipt.record_hash,
                    mission_id,
                ),
            )
            row = connection.execute(
                "SELECT * FROM mission_transitions WHERE transition_id = ?",
                (transition_id,),
            ).fetchone()
            assert row is not None
            return self._row_to_receipt(row)
