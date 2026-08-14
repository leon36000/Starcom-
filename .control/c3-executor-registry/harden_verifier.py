from __future__ import annotations

from pathlib import Path


PATH = Path("/tmp/starcom-c3-executor-registry/executor_registry.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"registry hardening refused for {label}: expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def main() -> int:
    source = PATH.read_text(encoding="utf-8")
    source = replace_once(
        source,
        '''            consumption = self._consumption(decision_id)\n            if consumption is None:\n                defects.append(f"C3_EXECUTOR_CONSUMPTION_MISSING:{sequence}")\n            event = self.database.connection.execute(\n''',
        '''            consumption = self._consumption(decision_id)\n            operation = str(transition["operation"])\n            try:\n                metadata = json.loads(str(transition["metadata_json"]))\n                if not isinstance(metadata, dict):\n                    raise ValueError("transition metadata must be an object")\n            except (json.JSONDecodeError, TypeError, ValueError):\n                metadata = {}\n                defects.append(f"C3_EXECUTOR_TRANSITION_METADATA_INVALID:{sequence}")\n            expected_operation_id = (\n                str(metadata.get("qualification_id", ""))\n                if operation == "QUALIFY"\n                else executor_id\n            )\n            try:\n                expected_operation_kind = self._operation_kind(operation)\n            except KeyError:\n                expected_operation_kind = ""\n                defects.append(f"C3_EXECUTOR_OPERATION_INVALID:{sequence}")\n            if consumption is None:\n                defects.append(f"C3_EXECUTOR_CONSUMPTION_MISSING:{sequence}")\n            elif (\n                str(consumption["operation_kind"]),\n                str(consumption["operation_id"]),\n                str(consumption["consumed_at"]),\n                str(consumption["consumed_by"]),\n            ) != (\n                expected_operation_kind,\n                expected_operation_id,\n                str(transition["transitioned_at"]),\n                str(transition["transitioned_by"]),\n            ):\n                defects.append(f"C3_EXECUTOR_CONSUMPTION_MISMATCH:{sequence}")\n            event = self.database.connection.execute(\n''',
        "transition consumption verification",
    )
    source = replace_once(
        source,
        '''            else:\n                public_key = bytes(root["public_key"])\n                if (\n                    self._fingerprint(public_key)\n                    != str(root["public_key_fingerprint_sha256"])\n                    or not self.signature_verifier.validate_public_key(public_key)\n                ):\n                    defects.append("C3_EXECUTOR_QUALIFIER_ROOT_INVALID")\n                if not self.signature_verifier.verify(\n                    public_key,\n                    bytes(qualification["payload"]),\n                    bytes(qualification["signature"]),\n                ):\n                    defects.append("C3_EXECUTOR_QUALIFICATION_SIGNATURE_INVALID")\n''',
        '''            else:\n                public_key = bytes(root["public_key"])\n                key_id = str(root["key_id"])\n                if (\n                    self._fingerprint(public_key)\n                    != str(root["public_key_fingerprint_sha256"])\n                    or not self.signature_verifier.validate_public_key(public_key)\n                ):\n                    defects.append("C3_EXECUTOR_QUALIFIER_ROOT_INVALID")\n                root_decision_id = str(root["authorization_decision_id"])\n                root_decision_verification = self.trust.verify_decision(\n                    root_decision_id\n                )\n                defects.extend(\n                    f"C3_EXECUTOR_QUALIFIER_ROOT_DECISION:{item}"\n                    for item in root_decision_verification.defects\n                )\n                root_consumption = self._consumption(root_decision_id)\n                if root_consumption is None:\n                    defects.append(\n                        "C3_EXECUTOR_QUALIFIER_ROOT_CONSUMPTION_MISSING"\n                    )\n                elif (\n                    str(root_consumption["operation_kind"]),\n                    str(root_consumption["operation_id"]),\n                    str(root_consumption["consumed_at"]),\n                    str(root_consumption["consumed_by"]),\n                ) != (\n                    self._operation_kind("QUALIFIER_ROOT"),\n                    key_id,\n                    str(root["accepted_at"]),\n                    str(root["accepted_by"]),\n                ):\n                    defects.append(\n                        "C3_EXECUTOR_QUALIFIER_ROOT_CONSUMPTION_MISMATCH"\n                    )\n                root_event = self.database.connection.execute(\n                    "SELECT * FROM ledger_events WHERE event_id = ?",\n                    (str(root["ledger_event_id"]),),\n                ).fetchone()\n                if root_event is None:\n                    defects.append("C3_EXECUTOR_QUALIFIER_ROOT_EVENT_MISSING")\n                else:\n                    if str(root_event["stream_id"]) != (\n                        f"continuity:c3:executor-qualifier:{key_id}"\n                    ):\n                        defects.append(\n                            "C3_EXECUTOR_QUALIFIER_ROOT_EVENT_STREAM_MISMATCH"\n                        )\n                    if str(root_event["kind"]) != (\n                        "C3_EXECUTOR_QUALIFIER_ACCEPTED"\n                    ):\n                        defects.append(\n                            "C3_EXECUTOR_QUALIFIER_ROOT_EVENT_KIND_MISMATCH"\n                        )\n                    if str(root_event["actor"]) != str(root["accepted_by"]):\n                        defects.append(\n                            "C3_EXECUTOR_QUALIFIER_ROOT_EVENT_ACTOR_MISMATCH"\n                        )\n                    if str(root_event["occurred_at"]) != str(\n                        root["accepted_at"]\n                    ):\n                        defects.append(\n                            "C3_EXECUTOR_QUALIFIER_ROOT_EVENT_TIME_MISMATCH"\n                        )\n                    if str(root_event["record_hash"]) != str(\n                        root["ledger_hash"]\n                    ):\n                        defects.append(\n                            "C3_EXECUTOR_QUALIFIER_ROOT_EVENT_HASH_MISMATCH"\n                        )\n                defects.extend(\n                    f"C3_EXECUTOR_QUALIFIER_ROOT_LEDGER:{item.code}"\n                    for item in self.ledger.verify(\n                        f"continuity:c3:executor-qualifier:{key_id}"\n                    ).defects\n                )\n                if not self.signature_verifier.verify(\n                    public_key,\n                    bytes(qualification["payload"]),\n                    bytes(qualification["signature"]),\n                ):\n                    defects.append("C3_EXECUTOR_QUALIFICATION_SIGNATURE_INVALID")\n''',
        "qualifier root verification",
    )
    PATH.write_text(source, encoding="utf-8")
    print("hardened exact authorization consumptions and qualifier-root provenance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
