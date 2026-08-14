from __future__ import annotations

from pathlib import Path


PATH = Path("/tmp/starcom-c3-executor-registry-v4/executor_registry.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"registry v4 adaptation refused for {label}: expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def main() -> int:
    source = PATH.read_text(encoding="utf-8")

    source = replace_once(
        source,
        '''from .continuity import (
    ContinuityService,
    OpenSSLEd25519Verifier,
    SignatureVerifier,
)
''',
        '''from .continuity import ContinuityService
''',
        "single continuity authority import",
    )
    source = replace_once(
        source,
        '''    reviewer_identity: str
    qualified_at: str
''',
        '''    reviewer_identity: str
    reviewer_environment: str
    qualified_at: str
''',
        "qualification reviewer environment record",
    )
    source = replace_once(
        source,
        '''        trust: TrustPlane,
        signature_verifier: SignatureVerifier | None = None,
        continuity: ContinuityService | None = None,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self.signature_verifier = signature_verifier or OpenSSLEd25519Verifier()
        self.continuity = continuity or ContinuityService(database, ledger, trust)
''',
        '''        trust: TrustPlane,
        continuity: ContinuityService,
    ) -> None:
        self.database = database
        self.ledger = ledger
        self.trust = trust
        self.continuity = continuity
        self.signature_verifier = continuity.signature_verifier
''',
        "constructor continuity authority",
    )
    source = replace_once(
        source,
        '''                    reviewer_identity TEXT NOT NULL,
                    qualified_at TEXT NOT NULL,
''',
        '''                    reviewer_identity TEXT NOT NULL,
                    reviewer_environment TEXT NOT NULL,
                    qualified_at TEXT NOT NULL,
''',
        "qualification reviewer environment schema",
    )
    source = replace_once(
        source,
        '''    @staticmethod
    def _fingerprint(public_key: bytes) -> str:
        return hashlib.sha256(public_key).hexdigest()

    @staticmethod
    def _operation_kind(operation: str) -> str:
''',
        '''    @staticmethod
    def _fingerprint(public_key: bytes) -> str:
        return hashlib.sha256(public_key).hexdigest()

    @staticmethod
    def _decode_exact_object(payload: bytes) -> dict[str, Any]:
        def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate key: {key}")
                result[key] = value
            return result

        try:
            value = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=no_duplicates,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValidationError(
                "qualification payload must be valid UTF-8 JSON without duplicate keys"
            ) from exc
        if not isinstance(value, dict):
            raise ValidationError("qualification payload must be a JSON object")
        return value

    @staticmethod
    def _operation_kind(operation: str) -> str:
''',
        "duplicate-safe qualification parser",
    )
    source = replace_once(
        source,
        '''        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("qualification payload must be UTF-8 JSON") from exc
        if not isinstance(value, dict) or frozenset(value) != _QUALIFICATION_FIELDS:
''',
        '''        value = self._decode_exact_object(payload)
        if frozenset(value) != _QUALIFICATION_FIELDS:
''',
        "exact qualification decoding",
    )
    source = replace_once(
        source,
        '''        self._required_text(value["reviewer_environment"], "reviewer_environment")
''',
        '''        reviewer_environment = self._required_text(
            value["reviewer_environment"], "reviewer_environment"
        )
''',
        "qualification reviewer environment normalization",
    )
    source = replace_once(
        source,
        '''        value["reviewer_identity"] = reviewer
        value["qualified_at"] = qualified_at
''',
        '''        value["reviewer_identity"] = reviewer
        value["reviewer_environment"] = reviewer_environment
        value["qualified_at"] = qualified_at
''',
        "qualification normalized environment",
    )
    source = replace_once(
        source,
        '''            "reviewer_identity": value["reviewer_identity"],
            "descriptor_digest": descriptor.descriptor_digest,
''',
        '''            "reviewer_identity": value["reviewer_identity"],
            "reviewer_environment": value["reviewer_environment"],
            "descriptor_digest": descriptor.descriptor_digest,
''',
        "qualification transition reviewer environment",
    )
    source = replace_once(
        source,
        '''                        reviewer_identity, qualified_at, admitted_at,
                        admitted_by, authorization_decision_id,
                        ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
''',
        '''                        reviewer_identity, reviewer_environment,
                        qualified_at, admitted_at, admitted_by,
                        authorization_decision_id, ledger_event_id, ledger_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
''',
        "qualification insert columns",
    )
    source = replace_once(
        source,
        '''                        value["reviewer_identity"],
                        value["qualified_at"],
''',
        '''                        value["reviewer_identity"],
                        value["reviewer_environment"],
                        value["qualified_at"],
''',
        "qualification insert values",
    )
    source = replace_once(
        source,
        '''            str(row["reviewer_identity"]),
            str(row["qualified_at"]),
''',
        '''            str(row["reviewer_identity"]),
            str(row["reviewer_environment"]),
            str(row["qualified_at"]),
''',
        "qualification row environment",
    )
    source = replace_once(
        source,
        '''    def get_current(self, executor_id: str) -> C3ExecutorCurrent:
''',
        '''    def get_qualifier_root(self, key_id: str) -> C3ExecutorQualifierRoot:
        key_id = self._required_text(key_id, "key_id")
        row = self.database.connection.execute(
            "SELECT * FROM c3_executor_qualifier_roots WHERE key_id = ?",
            (key_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C3 qualifier root does not exist", {"key_id": key_id}
            )
        return C3ExecutorQualifierRoot(
            key_id=str(row["key_id"]),
            public_key_fingerprint_sha256=str(
                row["public_key_fingerprint_sha256"]
            ),
            accepted_at=str(row["accepted_at"]),
            accepted_by=str(row["accepted_by"]),
            authorization_decision_id=str(row["authorization_decision_id"]),
            ledger_event_id=str(row["ledger_event_id"]),
            ledger_hash=str(row["ledger_hash"]),
        )

    def get_qualification(self, executor_id: str) -> C3ExecutorQualification:
        executor_id = self._required_text(executor_id, "executor_id")
        row = self.database.connection.execute(
            "SELECT * FROM c3_executor_qualifications WHERE executor_id = ?",
            (executor_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(
                "C3 executor qualification does not exist",
                {"executor_id": executor_id},
            )
        return self._qualification_from_row(row)

    def get_current(self, executor_id: str) -> C3ExecutorCurrent:
''',
        "registry public getters",
    )
    source = source.replace(
        'defects.append("C3_EXECUTOR_DESCRIPTOR_DIGEST_MISMATCH")',
        'defects.append("C3_EXECUTOR_DESCRIPTOR_MISMATCH")',
    )
    if "C3_EXECUTOR_DESCRIPTOR_DIGEST_MISMATCH" in source:
        raise SystemExit("registry v4 adaptation left old descriptor defect code")

    source = replace_once(
        source,
        '''                if str(event["record_hash"]) != str(transition["ledger_hash"]):
                    defects.append(f"C3_EXECUTOR_LEDGER_HASH_MISMATCH:{sequence}")
''',
        '''                if str(event["record_hash"]) != str(transition["ledger_hash"]):
                    defects.append(f"C3_EXECUTOR_LEDGER_HASH_MISMATCH:{sequence}")
                try:
                    event_payload = json.loads(str(event["payload_json"]))
                    metadata_payload = json.loads(
                        str(transition["metadata_json"])
                    )
                except (json.JSONDecodeError, TypeError):
                    defects.append(
                        f"C3_EXECUTOR_LEDGER_PAYLOAD_INVALID:{sequence}"
                    )
                else:
                    if str(transition["operation"]) == "REGISTER":
                        expected_event_payload = metadata_payload
                    else:
                        expected_event_payload = {
                            "executor_id": executor_id,
                            "state": state.value,
                            "authorization_decision_id": decision_id,
                            **metadata_payload,
                        }
                    if event_payload != expected_event_payload:
                        defects.append(
                            f"C3_EXECUTOR_LEDGER_PAYLOAD_MISMATCH:{sequence}"
                        )
''',
        "transition event payload verification",
    )
    source = replace_once(
        source,
        '''        if qualification is not None:
            root = self.database.connection.execute(
''',
        '''        if qualification is not None:
            try:
                qualification_value = self._decode_exact_object(
                    bytes(qualification["payload"])
                )
            except ValidationError:
                qualification_value = {}
                defects.append("C3_EXECUTOR_QUALIFICATION_PAYLOAD_INVALID")
            if frozenset(qualification_value) != _QUALIFICATION_FIELDS:
                defects.append("C3_EXECUTOR_QUALIFICATION_PAYLOAD_SCHEMA_MISMATCH")
            else:
                if qualification_value.get("executor_id") != executor_id:
                    defects.append("C3_EXECUTOR_QUALIFICATION_EXECUTOR_MISMATCH")
                if qualification_value.get("descriptor_digest") != str(
                    row["descriptor_digest"]
                ):
                    defects.append("C3_EXECUTOR_QUALIFICATION_DESCRIPTOR_MISMATCH")
                if qualification_value.get("reviewer_identity") != str(
                    qualification["reviewer_identity"]
                ):
                    defects.append("C3_EXECUTOR_QUALIFICATION_REVIEWER_MISMATCH")
                if qualification_value.get("reviewer_environment") != str(
                    qualification["reviewer_environment"]
                ):
                    defects.append(
                        "C3_EXECUTOR_QUALIFICATION_ENVIRONMENT_MISMATCH"
                    )
                if qualification_value.get("qualified_at") != str(
                    qualification["qualified_at"]
                ):
                    defects.append("C3_EXECUTOR_QUALIFICATION_TIME_MISMATCH")
                if qualification_value.get("verdict") != "QUALIFIED":
                    defects.append("C3_EXECUTOR_QUALIFICATION_VERDICT_INVALID")
                if qualification_value.get("gate_effect") != (
                    "QUALIFIED_DISABLED_NO_ENABLEMENT"
                ):
                    defects.append("C3_EXECUTOR_QUALIFICATION_GATE_EFFECT_INVALID")
                if qualification_value.get("reviewer_identity") == str(
                    row["registered_by"]
                ):
                    defects.append("C3_EXECUTOR_QUALIFICATION_INDEPENDENCE_INVALID")
            root = self.database.connection.execute(
''',
        "stored qualification semantic verification",
    )
    source = replace_once(
        source,
        '''        return C3ExecutorRegistryVerification(
            executor_id, tuple(dict.fromkeys(defects))
        )
''',
        '''        return C3ExecutorRegistryVerification(
            executor_id, tuple(dict.fromkeys(defects))
        )
''',
        "single verification return",
    )

    PATH.write_text(source, encoding="utf-8")
    print("adapted prototype to exact C3 executor registry v4 contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
