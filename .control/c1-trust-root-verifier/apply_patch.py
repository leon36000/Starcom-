from __future__ import annotations

from pathlib import Path


PATH = Path("src/starcom/continuity.py")
OLD = '''            else:\n                public_key = bytes(root["public_key_pem"])\n                if self._digest(public_key) != str(root["fingerprint_sha256"]):\n                    defects.append(f"TRUST_ROOT_FINGERPRINT_MISMATCH:{review['key_id']}")\n                if not self.signature_verifier.verify(public_key, payload, signature):\n                    defects.append(f"REVIEW_SIGNATURE_INVALID:{review_id}")\n'''
NEW = '''            else:\n                key_id = str(root["key_id"])\n                public_key = bytes(root["public_key_pem"])\n                if self._digest(public_key) != str(root["fingerprint_sha256"]):\n                    defects.append(f"TRUST_ROOT_FINGERPRINT_MISMATCH:{key_id}")\n\n                decision_id = str(root["decision_id"])\n                decision_verification = self.trust.verify_decision(decision_id)\n                if not decision_verification.ok:\n                    defects.append(f"TRUST_ROOT_DECISION_INVALID:{key_id}")\n                else:\n                    try:\n                        decision = self.trust.get_decision(decision_id)\n                    except NotFoundError:\n                        defects.append(f"TRUST_ROOT_DECISION_INVALID:{key_id}")\n                    else:\n                        expected_request = (\n                            str(root["accepted_by"]),\n                            "continuity.trust-root.accept",\n                            f"continuity:trust-root:{key_id}",\n                        )\n                        observed_request = (\n                            decision.request.subject,\n                            decision.request.action,\n                            decision.request.resource,\n                        )\n                        if not decision.allowed or observed_request != expected_request:\n                            defects.append(f"TRUST_ROOT_DECISION_INVALID:{key_id}")\n\n                consumption = self.database.connection.execute(\n                    "SELECT * FROM continuity_authorization_consumptions WHERE decision_id = ?",\n                    (decision_id,),\n                ).fetchone()\n                if consumption is None or (\n                    str(consumption["operation_kind"]) != "TRUST_ROOT_ACCEPTED"\n                    or str(consumption["operation_id"]) != key_id\n                    or str(consumption["consumed_by"]) != str(root["accepted_by"])\n                ):\n                    defects.append(\n                        f"TRUST_ROOT_AUTHORIZATION_CONSUMPTION_MISMATCH:{key_id}"\n                    )\n\n                trust_root_payload = {\n                    "key_id": key_id,\n                    "fingerprint_sha256": str(root["fingerprint_sha256"]),\n                    "decision_id": decision_id,\n                }\n                defects.extend(\n                    self._event_defects(\n                        event_id=str(root["ledger_event_id"]),\n                        expected_hash=str(root["ledger_hash"]),\n                        expected_kind="CONTINUITY_TRUST_ROOT_ACCEPTED",\n                        expected_payload=trust_root_payload,\n                        label=f"TRUST_ROOT:{key_id}",\n                    )\n                )\n\n                if not self.signature_verifier.verify(public_key, payload, signature):\n                    defects.append(f"REVIEW_SIGNATURE_INVALID:{review_id}")\n'''


def main() -> int:
    source = PATH.read_text(encoding="utf-8")
    count = source.count(OLD)
    if count != 1:
        raise SystemExit(f"bounded patch refused: expected exactly one target block, found {count}")
    updated = source.replace(OLD, NEW, 1)
    if updated == source:
        raise SystemExit("bounded patch refused: source was unchanged")
    PATH.write_text(updated, encoding="utf-8")
    print("patched src/starcom/continuity.py exactly once")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
