from __future__ import annotations

from pathlib import Path


PATH = Path("src/starcom/continuity.py")
OLD = '''                defects.extend(\n                    self._event_defects(\n                        event_id=str(root["ledger_event_id"]),\n                        expected_hash=str(root["ledger_hash"]),\n                        expected_kind="CONTINUITY_TRUST_ROOT_ACCEPTED",\n                        expected_payload=trust_root_payload,\n                        label=f"TRUST_ROOT:{key_id}",\n                    )\n                )\n\n                if not self.signature_verifier.verify(public_key, payload, signature):\n'''
NEW = '''                defects.extend(\n                    self._event_defects(\n                        event_id=str(root["ledger_event_id"]),\n                        expected_hash=str(root["ledger_hash"]),\n                        expected_kind="CONTINUITY_TRUST_ROOT_ACCEPTED",\n                        expected_payload=trust_root_payload,\n                        label=f"TRUST_ROOT:{key_id}",\n                    )\n                )\n                trust_root_event = self.database.connection.execute(\n                    "SELECT stream_id, actor, occurred_at FROM ledger_events WHERE event_id = ?",\n                    (str(root["ledger_event_id"]),),\n                ).fetchone()\n                if trust_root_event is not None:\n                    if str(trust_root_event["stream_id"]) != f"continuity:trust-root:{key_id}":\n                        defects.append(f"TRUST_ROOT:{key_id}_LEDGER_STREAM_MISMATCH")\n                    if str(trust_root_event["actor"]) != str(root["accepted_by"]):\n                        defects.append(f"TRUST_ROOT:{key_id}_LEDGER_ACTOR_MISMATCH")\n                    if str(trust_root_event["occurred_at"]) != str(root["accepted_at"]):\n                        defects.append(f"TRUST_ROOT:{key_id}_LEDGER_TIMESTAMP_MISMATCH")\n\n                if not self.signature_verifier.verify(public_key, payload, signature):\n'''


def main() -> int:
    source = PATH.read_text(encoding="utf-8")
    count = source.count(OLD)
    if count != 1:
        raise SystemExit(f"bounded patch refused: expected exactly one target block, found {count}")
    updated = source.replace(OLD, NEW, 1)
    if updated == source:
        raise SystemExit("bounded patch refused: source unchanged")
    PATH.write_text(updated, encoding="utf-8")
    print("patched exact C1 trust-root ledger provenance binding once")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
