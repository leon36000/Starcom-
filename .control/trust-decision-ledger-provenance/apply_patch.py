from __future__ import annotations

from pathlib import Path


PATH = Path("src/starcom/trust.py")
OLD = '''        ledger_row = self.database.connection.execute(\n            "SELECT * FROM ledger_events WHERE event_id = ?",\n            (str(decision_row["ledger_event_id"]),),\n        ).fetchone()\n        if ledger_row is None:\n            defects.append("DECISION_LEDGER_EVENT_MISSING")\n        else:\n            if str(ledger_row["record_hash"]) != str(decision_row["ledger_hash"]):\n                defects.append("DECISION_LEDGER_HASH_MISMATCH")\n            try:\n'''
NEW = '''        ledger_row = self.database.connection.execute(\n            "SELECT * FROM ledger_events WHERE event_id = ?",\n            (str(decision_row["ledger_event_id"]),),\n        ).fetchone()\n        if ledger_row is None:\n            defects.append("DECISION_LEDGER_EVENT_MISSING")\n        else:\n            if str(ledger_row["record_hash"]) != str(decision_row["ledger_hash"]):\n                defects.append("DECISION_LEDGER_HASH_MISMATCH")\n            if str(ledger_row["kind"]) != "AUTHORIZATION_DECIDED":\n                defects.append("DECISION_LEDGER_KIND_MISMATCH")\n            if request_payload is not None:\n                expected_stream_id = f"trust:decisions:{request_payload['subject']}"\n                if str(ledger_row["stream_id"]) != expected_stream_id:\n                    defects.append("DECISION_LEDGER_STREAM_MISMATCH")\n            if str(ledger_row["actor"]) != "trust-plane":\n                defects.append("DECISION_LEDGER_ACTOR_MISMATCH")\n            if str(ledger_row["occurred_at"]) != str(decision_row["decided_at"]):\n                defects.append("DECISION_LEDGER_TIMESTAMP_MISMATCH")\n            try:\n'''


def main() -> int:
    source = PATH.read_text(encoding="utf-8")
    count = source.count(OLD)
    if count != 1:
        raise SystemExit(f"bounded patch refused: expected one target, found {count}")
    updated = source.replace(OLD, NEW, 1)
    if updated == source:
        raise SystemExit("bounded patch refused: source unchanged")
    PATH.write_text(updated, encoding="utf-8")
    print("patched TrustPlane decision ledger provenance exactly once")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
