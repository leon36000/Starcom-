from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from fnmatch import fnmatchcase
import json
import sqlite3
from typing import Any, Mapping
from uuid import uuid4

from .canonical import canonical_json, sha256_digest, utc_now
from .db import Database
from .errors import ConflictError, ValidationError
from .ledger import EventLedger


class PolicyEffect(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    effect: PolicyEffect
    subject: str
    action: str
    resource: str
    conditions: Mapping[str, Any] = field(default_factory=dict)
    priority: int = 0


@dataclass(frozen=True)
class AuthorizationRequest:
    subject: str
    action: str
    resource: str
    mission_id: str | None = None
    context: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AuthorizationDecision:
    decision_id: str
    allowed: bool
    reason: str
    request: AuthorizationRequest
    request_digest: str
    matched_rule_ids: tuple[str, ...]
    grant_id: str | None
    decided_at: str
    ledger_event_id: str
    ledger_hash: str


@dataclass(frozen=True)
class DecisionVerification:
    decision_id: str
    defects: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.defects


class TrustPlane:
    def __init__(self, database: Database, ledger: EventLedger) -> None:
        self.database = database
        self.ledger = ledger
        self._initialize_schema()

    @staticmethod
    def _required_text(value: str, field_name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{field_name} must be a non-empty string")
        return value

    @staticmethod
    def _parse_time(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError("timestamp must be RFC 3339") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValidationError("timestamp must be timezone-aware")
        return parsed

    def _initialize_schema(self) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS trust_policy_rules (
                    rule_id TEXT PRIMARY KEY,
                    effect TEXT NOT NULL CHECK (effect IN ('ALLOW', 'DENY')),
                    subject_pattern TEXT NOT NULL,
                    action_pattern TEXT NOT NULL,
                    resource_pattern TEXT NOT NULL,
                    conditions_json TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS trust_grants (
                    grant_id TEXT PRIMARY KEY,
                    subject_pattern TEXT NOT NULL,
                    action_pattern TEXT NOT NULL,
                    resource_pattern TEXT NOT NULL,
                    mission_id TEXT,
                    expires_at TEXT NOT NULL,
                    single_use INTEGER NOT NULL CHECK (single_use IN (0, 1)),
                    consumed_at TEXT,
                    consumed_by_decision TEXT,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS trust_decisions (
                    decision_id TEXT PRIMARY KEY,
                    request_json TEXT NOT NULL,
                    request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
                    allowed INTEGER NOT NULL CHECK (allowed IN (0, 1)),
                    reason TEXT NOT NULL,
                    matched_rule_ids_json TEXT NOT NULL,
                    grant_id TEXT,
                    decided_at TEXT NOT NULL,
                    ledger_event_id TEXT NOT NULL UNIQUE,
                    ledger_hash TEXT NOT NULL CHECK (length(ledger_hash) = 64),
                    FOREIGN KEY (grant_id) REFERENCES trust_grants(grant_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trust_policy_rules_no_update
                BEFORE UPDATE ON trust_policy_rules
                BEGIN SELECT RAISE(ABORT, 'policy rules are immutable'); END
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trust_policy_rules_no_delete
                BEFORE DELETE ON trust_policy_rules
                BEGIN SELECT RAISE(ABORT, 'policy rules are immutable'); END
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trust_decisions_no_update
                BEFORE UPDATE ON trust_decisions
                BEGIN SELECT RAISE(ABORT, 'authorization decisions are immutable'); END
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS trust_decisions_no_delete
                BEFORE DELETE ON trust_decisions
                BEGIN SELECT RAISE(ABORT, 'authorization decisions are immutable'); END
                """
            )

    def add_rule(
        self,
        rule: PolicyRule,
        *,
        actor: str,
        occurred_at: str | None = None,
    ) -> None:
        self._required_text(rule.rule_id, "rule_id")
        self._required_text(rule.subject, "subject")
        self._required_text(rule.action, "action")
        self._required_text(rule.resource, "resource")
        actor = self._required_text(actor, "actor")
        occurred_at = occurred_at or utc_now()
        self._parse_time(occurred_at)
        conditions_json = canonical_json(dict(rule.conditions))
        payload = {
            "rule_id": rule.rule_id,
            "effect": rule.effect.value,
            "subject": rule.subject,
            "action": rule.action,
            "resource": rule.resource,
            "conditions": dict(rule.conditions),
            "priority": rule.priority,
        }
        try:
            with self.database.transaction() as connection:
                receipt = self.ledger.append_in_transaction(
                    connection,
                    "trust:policy",
                    "POLICY_RULE_ADDED",
                    payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO trust_policy_rules (
                        rule_id, effect, subject_pattern, action_pattern,
                        resource_pattern, conditions_json, priority,
                        created_at, created_by, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        rule.rule_id,
                        rule.effect.value,
                        rule.subject,
                        rule.action,
                        rule.resource,
                        conditions_json,
                        int(rule.priority),
                        occurred_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("policy rule already exists", {"rule_id": rule.rule_id}) from exc

    def issue_grant(
        self,
        *,
        grant_id: str,
        subject: str,
        action: str,
        resource: str,
        mission_id: str | None,
        expires_at: str,
        single_use: bool,
        actor: str,
        occurred_at: str | None = None,
    ) -> None:
        grant_id = self._required_text(grant_id, "grant_id")
        subject = self._required_text(subject, "subject")
        action = self._required_text(action, "action")
        resource = self._required_text(resource, "resource")
        actor = self._required_text(actor, "actor")
        occurred_at = occurred_at or utc_now()
        self._parse_time(occurred_at)
        self._parse_time(expires_at)
        if mission_id is not None:
            self._required_text(mission_id, "mission_id")
        payload = {
            "grant_id": grant_id,
            "subject": subject,
            "action": action,
            "resource": resource,
            "mission_id": mission_id,
            "expires_at": expires_at,
            "single_use": bool(single_use),
        }
        try:
            with self.database.transaction() as connection:
                receipt = self.ledger.append_in_transaction(
                    connection,
                    f"trust:grant:{grant_id}",
                    "GRANT_ISSUED",
                    payload,
                    actor=actor,
                    occurred_at=occurred_at,
                )
                connection.execute(
                    """
                    INSERT INTO trust_grants (
                        grant_id, subject_pattern, action_pattern, resource_pattern,
                        mission_id, expires_at, single_use, consumed_at,
                        consumed_by_decision, created_at, created_by,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?)
                    """,
                    (
                        grant_id,
                        subject,
                        action,
                        resource,
                        mission_id,
                        expires_at,
                        int(single_use),
                        occurred_at,
                        actor,
                        receipt.event_id,
                        receipt.record_hash,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("grant already exists", {"grant_id": grant_id}) from exc

    @staticmethod
    def _rule_matches(row: sqlite3.Row, request: AuthorizationRequest) -> bool:
        if not fnmatchcase(request.subject, str(row["subject_pattern"])):
            return False
        if not fnmatchcase(request.action, str(row["action_pattern"])):
            return False
        if not fnmatchcase(request.resource, str(row["resource_pattern"])):
            return False
        conditions = json.loads(str(row["conditions_json"]))
        return all(request.context.get(key) == expected for key, expected in conditions.items())

    @staticmethod
    def _grant_matches(row: sqlite3.Row, request: AuthorizationRequest, now: datetime) -> bool:
        if not fnmatchcase(request.subject, str(row["subject_pattern"])):
            return False
        if not fnmatchcase(request.action, str(row["action_pattern"])):
            return False
        if not fnmatchcase(request.resource, str(row["resource_pattern"])):
            return False
        mission_id = row["mission_id"]
        if mission_id is not None and str(mission_id) != request.mission_id:
            return False
        if row["consumed_at"] is not None:
            return False
        expires_at = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
        return expires_at > now

    def authorize(
        self,
        request: AuthorizationRequest,
        *,
        now: str | None = None,
        consume: bool = True,
    ) -> AuthorizationDecision:
        self._required_text(request.subject, "subject")
        self._required_text(request.action, "action")
        self._required_text(request.resource, "resource")
        if request.mission_id is not None:
            self._required_text(request.mission_id, "mission_id")
        decided_at = now or utc_now()
        now_value = self._parse_time(decided_at)
        request_payload = {
            "subject": request.subject,
            "action": request.action,
            "resource": request.resource,
            "mission_id": request.mission_id,
            "context": dict(request.context),
        }
        request_json = canonical_json(request_payload)
        request_digest = sha256_digest(request_payload)
        decision_id = str(uuid4())

        with self.database.transaction() as connection:
            rule_rows = connection.execute(
                "SELECT * FROM trust_policy_rules ORDER BY priority DESC, rule_id"
            ).fetchall()
            matching = [row for row in rule_rows if self._rule_matches(row, request)]
            matching_ids = tuple(str(row["rule_id"]) for row in matching)
            deny_match = any(str(row["effect"]) == PolicyEffect.DENY.value for row in matching)
            allow_match = any(str(row["effect"]) == PolicyEffect.ALLOW.value for row in matching)
            grant_row: sqlite3.Row | None = None

            if deny_match:
                allowed = False
                reason = "EXPLICIT_DENY"
            elif allow_match:
                allowed = True
                reason = "POLICY_ALLOW"
            else:
                grant_rows = connection.execute(
                    "SELECT * FROM trust_grants ORDER BY expires_at, grant_id"
                ).fetchall()
                grant_row = next(
                    (row for row in grant_rows if self._grant_matches(row, request, now_value)),
                    None,
                )
                allowed = grant_row is not None
                reason = "GRANT_ALLOW" if allowed else "DEFAULT_DENY"

            grant_id = str(grant_row["grant_id"]) if grant_row is not None else None
            if allowed and grant_row is not None and bool(grant_row["single_use"]) and consume:
                updated = connection.execute(
                    """
                    UPDATE trust_grants
                    SET consumed_at = ?, consumed_by_decision = ?
                    WHERE grant_id = ? AND consumed_at IS NULL
                    """,
                    (decided_at, decision_id, grant_id),
                )
                if updated.rowcount != 1:
                    raise ConflictError("single-use grant was consumed concurrently", {"grant_id": grant_id})

            payload = {
                "decision_id": decision_id,
                "request": request_payload,
                "request_digest": request_digest,
                "allowed": allowed,
                "reason": reason,
                "matched_rule_ids": list(matching_ids),
                "grant_id": grant_id,
                "consume": bool(consume),
            }
            receipt = self.ledger.append_in_transaction(
                connection,
                f"trust:decisions:{request.subject}",
                "AUTHORIZATION_DECIDED",
                payload,
                actor="trust-plane",
                occurred_at=decided_at,
            )
            connection.execute(
                """
                INSERT INTO trust_decisions (
                    decision_id, request_json, request_digest, allowed, reason,
                    matched_rule_ids_json, grant_id, decided_at,
                    ledger_event_id, ledger_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision_id,
                    request_json,
                    request_digest,
                    int(allowed),
                    reason,
                    canonical_json(list(matching_ids)),
                    grant_id,
                    decided_at,
                    receipt.event_id,
                    receipt.record_hash,
                ),
            )

        return AuthorizationDecision(
            decision_id=decision_id,
            allowed=allowed,
            reason=reason,
            request=request,
            request_digest=request_digest,
            matched_rule_ids=matching_ids,
            grant_id=grant_id,
            decided_at=decided_at,
            ledger_event_id=receipt.event_id,
            ledger_hash=receipt.record_hash,
        )
    def get_decision(self, decision_id: str) -> AuthorizationDecision:
        row = self.database.connection.execute(
            "SELECT * FROM trust_decisions WHERE decision_id = ?",
            (decision_id,),
        ).fetchone()
        if row is None:
            from .errors import NotFoundError

            raise NotFoundError(
                "authorization decision does not exist",
                {"decision_id": decision_id},
            )
        request_payload = json.loads(str(row["request_json"]))
        request = AuthorizationRequest(
            subject=str(request_payload["subject"]),
            action=str(request_payload["action"]),
            resource=str(request_payload["resource"]),
            mission_id=(
                str(request_payload["mission_id"])
                if request_payload.get("mission_id") is not None
                else None
            ),
            context=dict(request_payload.get("context", {})),
        )
        return AuthorizationDecision(
            decision_id=str(row["decision_id"]),
            allowed=bool(row["allowed"]),
            reason=str(row["reason"]),
            request=request,
            request_digest=str(row["request_digest"]),
            matched_rule_ids=tuple(json.loads(str(row["matched_rule_ids_json"]))),
            grant_id=str(row["grant_id"]) if row["grant_id"] is not None else None,
            decided_at=str(row["decided_at"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def verify_decision(self, decision_id: str) -> DecisionVerification:
        defects: list[str] = []
        decision_row = self.database.connection.execute(
            "SELECT * FROM trust_decisions WHERE decision_id = ?",
            (decision_id,),
        ).fetchone()
        if decision_row is None:
            return DecisionVerification(decision_id, ("DECISION_NOT_FOUND",))

        request_payload: dict[str, Any] | None = None
        try:
            decoded_request = json.loads(str(decision_row["request_json"]))
            if not isinstance(decoded_request, dict):
                raise ValueError("request_json must decode to an object")
            subject = decoded_request["subject"]
            action = decoded_request["action"]
            resource = decoded_request["resource"]
            mission_id = decoded_request.get("mission_id")
            context = decoded_request.get("context", {})
            if not all(
                isinstance(value, str) and value.strip()
                for value in (subject, action, resource)
            ):
                raise ValueError("request fields must be non-empty strings")
            if mission_id is not None and not isinstance(mission_id, str):
                raise ValueError("mission_id must be a string or null")
            if not isinstance(context, dict):
                raise ValueError("context must be an object")
            request_payload = {
                "subject": subject,
                "action": action,
                "resource": resource,
                "mission_id": mission_id,
                "context": context,
            }
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            defects.append("DECISION_REQUEST_JSON_INVALID")

        matched_rule_ids: list[str] | None = None
        try:
            decoded_rules = json.loads(str(decision_row["matched_rule_ids_json"]))
            if not isinstance(decoded_rules, list) or not all(
                isinstance(rule_id, str) for rule_id in decoded_rules
            ):
                raise ValueError("matched rule ids must be a list of strings")
            matched_rule_ids = decoded_rules
        except (json.JSONDecodeError, TypeError, ValueError):
            defects.append("DECISION_MATCHED_RULE_IDS_JSON_INVALID")

        if (
            request_payload is not None
            and sha256_digest(request_payload) != str(decision_row["request_digest"])
        ):
            defects.append("REQUEST_DIGEST_MISMATCH")

        ledger_row = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (str(decision_row["ledger_event_id"]),),
        ).fetchone()
        if ledger_row is None:
            defects.append("DECISION_LEDGER_EVENT_MISSING")
        else:
            if str(ledger_row["record_hash"]) != str(decision_row["ledger_hash"]):
                defects.append("DECISION_LEDGER_HASH_MISMATCH")
            if str(ledger_row["kind"]) != "AUTHORIZATION_DECIDED":
                defects.append("DECISION_LEDGER_KIND_MISMATCH")
            if request_payload is not None:
                expected_stream_id = f"trust:decisions:{request_payload['subject']}"
                if str(ledger_row["stream_id"]) != expected_stream_id:
                    defects.append("DECISION_LEDGER_STREAM_MISMATCH")
            if str(ledger_row["actor"]) != "trust-plane":
                defects.append("DECISION_LEDGER_ACTOR_MISMATCH")
            if str(ledger_row["occurred_at"]) != str(decision_row["decided_at"]):
                defects.append("DECISION_LEDGER_TIMESTAMP_MISMATCH")
            try:
                payload = json.loads(str(ledger_row["payload_json"]))
                if not isinstance(payload, dict):
                    raise ValueError("ledger payload must decode to an object")
            except (json.JSONDecodeError, TypeError, ValueError):
                defects.append("DECISION_LEDGER_PAYLOAD_INVALID")
            else:
                if request_payload is not None and matched_rule_ids is not None:
                    expected = {
                        "decision_id": str(decision_row["decision_id"]),
                        "request": request_payload,
                        "request_digest": str(decision_row["request_digest"]),
                        "allowed": bool(decision_row["allowed"]),
                        "reason": str(decision_row["reason"]),
                        "matched_rule_ids": matched_rule_ids,
                        "grant_id": (
                            str(decision_row["grant_id"])
                            if decision_row["grant_id"] is not None
                            else None
                        ),
                    }
                    for key, value in expected.items():
                        if payload.get(key) != value:
                            defects.append(f"DECISION_LEDGER_{key.upper()}_MISMATCH")
            if not self.ledger.verify(str(ledger_row["stream_id"])).ok:
                defects.append("DECISION_LEDGER_CHAIN_INVALID")
        return DecisionVerification(decision_id, tuple(dict.fromkeys(defects)))

