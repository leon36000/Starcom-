from __future__ import annotations

from pathlib import Path


PATH = Path("src/starcom/executor_registry.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"registry authority hardening refused for {label}: "
            f"expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def main() -> int:
    source = PATH.read_text(encoding="utf-8")

    source = replace_once(
        source,
        '''    def _consumption(self, decision_id: str) -> sqlite3.Row | None:
        return self.database.connection.execute(
            "SELECT * FROM continuity_authorization_consumptions WHERE decision_id = ?",
            (decision_id,),
        ).fetchone()

    @staticmethod
    def _descriptor_from_row(row: sqlite3.Row) -> C3ExecutorDescriptor:
''',
        '''    def _consumption(self, decision_id: str) -> sqlite3.Row | None:
        return self.database.connection.execute(
            "SELECT * FROM continuity_authorization_consumptions WHERE decision_id = ?",
            (decision_id,),
        ).fetchone()

    @staticmethod
    def _request_tuple(decision: AuthorizationDecision) -> tuple[object, ...]:
        return (
            decision.request.subject,
            decision.request.action,
            decision.request.resource,
            decision.request.mission_id,
            dict(decision.request.context),
        )

    @staticmethod
    def _expected_request_tuple(
        preparation: C3ExecutorPreparation,
        actor: str,
    ) -> tuple[object, ...]:
        return (
            actor,
            preparation.action,
            preparation.resource,
            preparation.mission_id,
            dict(preparation.context),
        )

    def _qualifier_root_defects(self, key_id: str) -> tuple[str, ...]:
        defects: list[str] = []
        row = self.database.connection.execute(
            "SELECT * FROM c3_executor_qualifier_roots WHERE key_id = ?",
            (key_id,),
        ).fetchone()
        if row is None:
            return ("C3_EXECUTOR_QUALIFIER_ROOT_MISSING",)
        public_key = bytes(row["public_key"])
        fingerprint = self._fingerprint(public_key)
        if (
            fingerprint != str(row["public_key_fingerprint_sha256"])
            or not self.signature_verifier.validate_public_key(public_key)
        ):
            defects.append("C3_EXECUTOR_QUALIFIER_ROOT_INVALID")
        preparation: C3ExecutorPreparation | None = None
        try:
            preparation = self.prepare_qualifier_root(key_id, public_key)
        except ValidationError:
            defects.append("C3_EXECUTOR_QUALIFIER_ROOT_INVALID")
        decision_id = str(row["authorization_decision_id"])
        decision_verification = self.trust.verify_decision(decision_id)
        defects.extend(
            f"C3_EXECUTOR_QUALIFIER_ROOT_DECISION:{item}"
            for item in decision_verification.defects
        )
        decision: AuthorizationDecision | None = None
        try:
            decision = self.trust.get_decision(decision_id)
        except NotFoundError:
            defects.append("C3_EXECUTOR_QUALIFIER_ROOT_DECISION_MISSING")
        if decision is not None and preparation is not None:
            if (
                not decision.allowed
                or self._request_tuple(decision)
                != self._expected_request_tuple(
                    preparation,
                    str(row["accepted_by"]),
                )
            ):
                defects.append(
                    "C3_EXECUTOR_QUALIFIER_ROOT_DECISION_REQUEST_MISMATCH"
                )
            try:
                if self._as_datetime(str(row["accepted_at"])) < self._as_datetime(
                    decision.decided_at
                ):
                    defects.append(
                        "C3_EXECUTOR_QUALIFIER_ROOT_ACCEPTANCE_PREDATES_DECISION"
                    )
            except ValueError:
                defects.append("C3_EXECUTOR_QUALIFIER_ROOT_CHRONOLOGY_INVALID")
        consumption = self._consumption(decision_id)
        if consumption is None:
            defects.append("C3_EXECUTOR_QUALIFIER_ROOT_CONSUMPTION_MISSING")
        elif (
            str(consumption["operation_kind"]),
            str(consumption["operation_id"]),
            str(consumption["consumed_at"]),
            str(consumption["consumed_by"]),
        ) != (
            self._operation_kind("QUALIFIER_ROOT"),
            key_id,
            str(row["accepted_at"]),
            str(row["accepted_by"]),
        ):
            defects.append(
                "C3_EXECUTOR_QUALIFIER_ROOT_CONSUMPTION_MISMATCH"
            )
        event = self.database.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (str(row["ledger_event_id"]),),
        ).fetchone()
        expected_payload = {
            "key_id": key_id,
            "public_key_fingerprint_sha256": fingerprint,
            "algorithm": "Ed25519",
            "purpose": "C3_EXECUTOR_QUALIFICATION",
            "authorization_decision_id": decision_id,
        }
        stream_id = f"continuity:c3:executor-qualifier:{key_id}"
        if event is None:
            defects.append("C3_EXECUTOR_QUALIFIER_ROOT_EVENT_MISSING")
        else:
            if str(event["stream_id"]) != stream_id:
                defects.append(
                    "C3_EXECUTOR_QUALIFIER_ROOT_EVENT_STREAM_MISMATCH"
                )
            if str(event["kind"]) != "C3_EXECUTOR_QUALIFIER_ACCEPTED":
                defects.append(
                    "C3_EXECUTOR_QUALIFIER_ROOT_EVENT_KIND_MISMATCH"
                )
            if str(event["actor"]) != str(row["accepted_by"]):
                defects.append(
                    "C3_EXECUTOR_QUALIFIER_ROOT_EVENT_ACTOR_MISMATCH"
                )
            if str(event["occurred_at"]) != str(row["accepted_at"]):
                defects.append(
                    "C3_EXECUTOR_QUALIFIER_ROOT_EVENT_TIME_MISMATCH"
                )
            if str(event["record_hash"]) != str(row["ledger_hash"]):
                defects.append(
                    "C3_EXECUTOR_QUALIFIER_ROOT_EVENT_HASH_MISMATCH"
                )
            try:
                event_payload = json.loads(str(event["payload_json"]))
            except (json.JSONDecodeError, TypeError):
                defects.append(
                    "C3_EXECUTOR_QUALIFIER_ROOT_EVENT_PAYLOAD_INVALID"
                )
            else:
                if event_payload != expected_payload:
                    defects.append(
                        "C3_EXECUTOR_QUALIFIER_ROOT_EVENT_PAYLOAD_MISMATCH"
                    )
        defects.extend(
            f"C3_EXECUTOR_QUALIFIER_ROOT_LEDGER:{item.code}"
            for item in self.ledger.verify(stream_id).defects
        )
        return tuple(dict.fromkeys(defects))

    def _assert_clean_qualifier_root(self, key_id: str) -> None:
        defects = self._qualifier_root_defects(key_id)
        if defects:
            raise IntegrityError(
                "C3 executor qualifier root verification failed",
                {"key_id": key_id, "defects": list(defects)},
            )

    def _assert_clean_executor(self, executor_id: str) -> None:
        verification = self.verify(executor_id)
        if not verification.ok:
            raise IntegrityError(
                "C3 executor registry verification failed",
                {
                    "executor_id": executor_id,
                    "defects": list(verification.defects),
                },
            )

    def _transition_preparation(
        self,
        executor_id: str,
        operation: str,
        metadata: Mapping[str, Any],
        descriptor_row: sqlite3.Row,
    ) -> C3ExecutorPreparation:
        if operation == "REGISTER":
            descriptor_value = json.loads(str(descriptor_row["descriptor_json"]))
            if not isinstance(descriptor_value, dict):
                raise ValidationError("registered descriptor must be an object")
            return self.prepare_registration(descriptor_value)
        if operation == "QUALIFY":
            qualification = self.database.connection.execute(
                "SELECT * FROM c3_executor_qualifications WHERE executor_id = ?",
                (executor_id,),
            ).fetchone()
            if qualification is None:
                raise ValidationError("qualification row is missing")
            value = self._decode_exact_object(bytes(qualification["payload"]))
            return C3ExecutorPreparation(
                "QUALIFY",
                executor_id,
                "c3.executor.qualify",
                self._resource(executor_id, "qualify"),
                self._mission(executor_id),
                {
                    "qualification_id": value["qualification_id"],
                    "key_id": str(qualification["key_id"]),
                    "descriptor_digest": value["descriptor_digest"],
                    "payload_sha256": str(qualification["payload_sha256"]),
                    "signature_sha256": str(
                        qualification["signature_sha256"]
                    ),
                    "report_digest": value["report_digest"],
                    "test_suite_digest": value["test_suite_digest"],
                    "reviewer_identity": value["reviewer_identity"],
                    "gate_effect": value["gate_effect"],
                    "prior_state": C3ExecutorState.REGISTERED_DISABLED.value,
                    "requested_state": C3ExecutorState.QUALIFIED_DISABLED.value,
                },
            )
        if operation == "ENABLE":
            return C3ExecutorPreparation(
                "ENABLE",
                executor_id,
                "c3.executor.enable",
                self._resource(executor_id, "enable"),
                self._mission(executor_id),
                dict(metadata),
            )
        if operation == "REVOKE":
            return C3ExecutorPreparation(
                "REVOKE",
                executor_id,
                "c3.executor.revoke",
                self._resource(executor_id, "revoke"),
                self._mission(executor_id),
                dict(metadata),
            )
        raise ValidationError("unknown executor transition operation")

    @staticmethod
    def _descriptor_from_row(row: sqlite3.Row) -> C3ExecutorDescriptor:
''',
        "authority verification helpers",
    )

    source = replace_once(
        source,
        '''        if existing is not None:
            if (
                bytes(existing["public_key"]) != public_key
                or str(existing["authorization_decision_id"])
                != authorization_decision_id
                or str(existing["accepted_by"]) != actor
            ):
                raise ConflictError("qualifier key_id was reused with different material")
            return C3ExecutorQualifierRoot(
''',
        '''        if existing is not None:
            if (
                bytes(existing["public_key"]) != public_key
                or str(existing["authorization_decision_id"])
                != authorization_decision_id
                or str(existing["accepted_by"]) != actor
            ):
                raise ConflictError("qualifier key_id was reused with different material")
            self._assert_clean_qualifier_root(key_id)
            return C3ExecutorQualifierRoot(
''',
        "qualifier root replay verification",
    )

    source = replace_once(
        source,
        '''        descriptor = self.get_descriptor(executor_id)
        if require_registered_state and self.get_current(executor_id).state is not (
''',
        '''        descriptor = self.get_descriptor(executor_id)
        self._assert_clean_executor(executor_id)
        if require_registered_state and self.get_current(executor_id).state is not (
''',
        "qualification executor authority recheck",
    )
    source = replace_once(
        source,
        '''        if root is None:
            raise StateTransitionError("qualifier root is not accepted")
        public_key = bytes(root["public_key"])
''',
        '''        if root is None:
            raise StateTransitionError("qualifier root is not accepted")
        self._assert_clean_qualifier_root(key_id)
        public_key = bytes(root["public_key"])
''',
        "qualification root authority recheck",
    )

    source = replace_once(
        source,
        '''    def prepare_enable(self, executor_id: str) -> C3ExecutorPreparation:
        descriptor = self.get_descriptor(executor_id)
''',
        '''    def prepare_enable(self, executor_id: str) -> C3ExecutorPreparation:
        self._assert_clean_executor(executor_id)
        descriptor = self.get_descriptor(executor_id)
''',
        "enable preparation authority recheck",
    )
    source = replace_once(
        source,
        '''        if current.state is C3ExecutorState.ENABLED:
            if (
                current.authorization_decision_id == authorization_decision_id
                and current.transitioned_by == actor
            ):
                return current
''',
        '''        if current.state is C3ExecutorState.ENABLED:
            if (
                current.authorization_decision_id == authorization_decision_id
                and current.transitioned_by == actor
            ):
                self._assert_clean_executor(executor_id)
                return current
''',
        "enable replay authority recheck",
    )

    source = replace_once(
        source,
        '''        transitions = self.database.connection.execute(
            "SELECT * FROM c3_executor_transitions WHERE executor_id = ? ORDER BY sequence",
            (executor_id,),
        ).fetchall()
        expected_prior: C3ExecutorState | None = None
''',
        '''        transitions = self.database.connection.execute(
            "SELECT * FROM c3_executor_transitions WHERE executor_id = ? ORDER BY sequence",
            (executor_id,),
        ).fetchall()
        if not transitions:
            defects.append("C3_EXECUTOR_TRANSITION_MISSING")
        else:
            first = transitions[0]
            if (
                str(row["registered_at"]),
                str(row["registered_by"]),
                str(row["authorization_decision_id"]),
                str(row["ledger_event_id"]),
                str(row["ledger_hash"]),
            ) != (
                str(first["transitioned_at"]),
                str(first["transitioned_by"]),
                str(first["authorization_decision_id"]),
                str(first["ledger_event_id"]),
                str(first["ledger_hash"]),
            ):
                defects.append("C3_EXECUTOR_DESCRIPTOR_PROVENANCE_MISMATCH")
        expected_prior: C3ExecutorState | None = None
''',
        "descriptor provenance verification",
    )

    source = replace_once(
        source,
        '''            try:
                expected_operation_kind = self._operation_kind(operation)
            except KeyError:
                expected_operation_kind = ""
                defects.append(f"C3_EXECUTOR_OPERATION_INVALID:{sequence}")
            if consumption is None:
''',
        '''            try:
                expected_operation_kind = self._operation_kind(operation)
            except KeyError:
                expected_operation_kind = ""
                defects.append(f"C3_EXECUTOR_OPERATION_INVALID:{sequence}")
            try:
                preparation = self._transition_preparation(
                    executor_id,
                    operation,
                    metadata,
                    row,
                )
            except (KeyError, TypeError, ValidationError, ValueError):
                preparation = None
                defects.append(
                    f"C3_EXECUTOR_DECISION_CONTEXT_INVALID:{sequence}"
                )
            try:
                linked_decision = self.trust.get_decision(decision_id)
            except NotFoundError:
                linked_decision = None
                defects.append(f"C3_EXECUTOR_DECISION_MISSING:{sequence}")
            if linked_decision is not None and preparation is not None:
                if (
                    not linked_decision.allowed
                    or self._request_tuple(linked_decision)
                    != self._expected_request_tuple(
                        preparation,
                        str(transition["transitioned_by"]),
                    )
                ):
                    defects.append(
                        f"C3_EXECUTOR_DECISION_REQUEST_MISMATCH:{sequence}"
                    )
                try:
                    if self._as_datetime(
                        str(transition["transitioned_at"])
                    ) < self._as_datetime(linked_decision.decided_at):
                        defects.append(
                            f"C3_EXECUTOR_TRANSITION_PREDATES_DECISION:{sequence}"
                        )
                except ValueError:
                    defects.append(
                        f"C3_EXECUTOR_TRANSITION_CHRONOLOGY_INVALID:{sequence}"
                    )
            if consumption is None:
''',
        "transition decision semantic verification",
    )

    source = replace_once(
        source,
        '''        if qualification is not None:
            try:
                qualification_value = self._decode_exact_object(
''',
        '''        if qualification is not None:
            qualification_transition = next(
                (
                    transition
                    for transition in transitions
                    if str(transition["operation"]) == "QUALIFY"
                ),
                None,
            )
            if qualification_transition is None:
                defects.append("C3_EXECUTOR_QUALIFICATION_TRANSITION_MISSING")
            else:
                try:
                    qualification_metadata = json.loads(
                        str(qualification_transition["metadata_json"])
                    )
                except (json.JSONDecodeError, TypeError):
                    qualification_metadata = {}
                if (
                    str(qualification["admitted_at"]),
                    str(qualification["admitted_by"]),
                    str(qualification["authorization_decision_id"]),
                    str(qualification["ledger_event_id"]),
                    str(qualification["ledger_hash"]),
                    str(qualification["qualification_id"]),
                ) != (
                    str(qualification_transition["transitioned_at"]),
                    str(qualification_transition["transitioned_by"]),
                    str(qualification_transition["authorization_decision_id"]),
                    str(qualification_transition["ledger_event_id"]),
                    str(qualification_transition["ledger_hash"]),
                    str(qualification_metadata.get("qualification_id", "")),
                ):
                    defects.append(
                        "C3_EXECUTOR_QUALIFICATION_PROVENANCE_MISMATCH"
                    )
            try:
                qualification_value = self._decode_exact_object(
''',
        "qualification provenance verification",
    )

    source = replace_once(
        source,
        '''            root = self.database.connection.execute(
                "SELECT * FROM c3_executor_qualifier_roots WHERE key_id = ?",
                (str(qualification["key_id"]),),
            ).fetchone()
''',
        '''            key_id = str(qualification["key_id"])
            defects.extend(self._qualifier_root_defects(key_id))
            root = self.database.connection.execute(
                "SELECT * FROM c3_executor_qualifier_roots WHERE key_id = ?",
                (key_id,),
            ).fetchone()
''',
        "qualification root verification reuse",
    )

    PATH.write_text(source, encoding="utf-8")
    print("hardened executor registry authority rechecks and provenance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
