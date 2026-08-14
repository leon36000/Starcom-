from __future__ import annotations

from pathlib import Path


TYPES_PATH = Path("src/starcom/continuity_types.py")
SERVICE_PATH = Path("src/starcom/continuity.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"bounded trust-root patch refused for {label}: expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def patch_types() -> None:
    source = TYPES_PATH.read_text(encoding="utf-8")
    source = replace_once(
        source,
        '''@dataclass(frozen=True)\nclass ReviewAdmission:\n''',
        '''@dataclass(frozen=True)\nclass TrustRootVerification:\n    key_id: str\n    defects: tuple[str, ...]\n\n    @property\n    def ok(self) -> bool:\n        return not self.defects\n\n\n@dataclass(frozen=True)\nclass ReviewAdmission:\n''',
        "canonical TrustRootVerification type",
    )
    TYPES_PATH.write_text(source, encoding="utf-8")


def patch_service() -> None:
    source = SERVICE_PATH.read_text(encoding="utf-8")
    source = replace_once(
        source,
        '''    SignatureVerifier,\n    TrustRootReceipt,\n)\n''',
        '''    SignatureVerifier,\n    TrustRootReceipt,\n    TrustRootVerification,\n)\n''',
        "TrustRootVerification import",
    )

    method = '''    def verify_trust_root(self, key_id: str) -> TrustRootVerification:\n        key_id = self._required_text(key_id, "key_id")\n        root = self.database.connection.execute(\n            "SELECT * FROM continuity_trust_roots WHERE key_id = ?",\n            (key_id,),\n        ).fetchone()\n        if root is None:\n            return TrustRootVerification(\n                key_id=key_id,\n                defects=(f"TRUST_ROOT_NOT_FOUND:{key_id}",),\n            )\n\n        defects: list[str] = []\n        public_key = bytes(root["public_key_pem"])\n        if self._digest(public_key) != str(root["fingerprint_sha256"]):\n            defects.append(f"TRUST_ROOT_FINGERPRINT_MISMATCH:{key_id}")\n        if not self.signature_verifier.validate_public_key(public_key):\n            defects.append(f"TRUST_ROOT_PUBLIC_KEY_INVALID:{key_id}")\n\n        decision_id = str(root["decision_id"])\n        decision_verification = self.trust.verify_decision(decision_id)\n        if not decision_verification.ok:\n            defects.append(f"TRUST_ROOT_DECISION_INVALID:{key_id}")\n        else:\n            try:\n                decision = self.trust.get_decision(decision_id)\n            except NotFoundError:\n                defects.append(f"TRUST_ROOT_DECISION_INVALID:{key_id}")\n            else:\n                expected_request = (\n                    str(root["accepted_by"]),\n                    "continuity.trust-root.accept",\n                    f"continuity:trust-root:{key_id}",\n                )\n                observed_request = (\n                    decision.request.subject,\n                    decision.request.action,\n                    decision.request.resource,\n                )\n                if not decision.allowed or observed_request != expected_request:\n                    defects.append(f"TRUST_ROOT_DECISION_INVALID:{key_id}")\n\n        consumption = self.database.connection.execute(\n            "SELECT * FROM continuity_authorization_consumptions WHERE decision_id = ?",\n            (decision_id,),\n        ).fetchone()\n        if consumption is None or (\n            str(consumption["operation_kind"]) != "TRUST_ROOT_ACCEPTED"\n            or str(consumption["operation_id"]) != key_id\n            or str(consumption["consumed_by"]) != str(root["accepted_by"])\n            or str(consumption["consumed_at"]) != str(root["accepted_at"])\n        ):\n            defects.append(\n                f"TRUST_ROOT_AUTHORIZATION_CONSUMPTION_MISMATCH:{key_id}"\n            )\n\n        trust_root_payload = {\n            "key_id": key_id,\n            "fingerprint_sha256": str(root["fingerprint_sha256"]),\n            "decision_id": decision_id,\n        }\n        defects.extend(\n            self._event_defects(\n                event_id=str(root["ledger_event_id"]),\n                expected_hash=str(root["ledger_hash"]),\n                expected_kind="CONTINUITY_TRUST_ROOT_ACCEPTED",\n                expected_payload=trust_root_payload,\n                label=f"TRUST_ROOT:{key_id}",\n            )\n        )\n        trust_root_event = self.database.connection.execute(\n            "SELECT stream_id, actor, occurred_at FROM ledger_events WHERE event_id = ?",\n            (str(root["ledger_event_id"]),),\n        ).fetchone()\n        if trust_root_event is not None:\n            if str(trust_root_event["stream_id"]) != f"continuity:trust-root:{key_id}":\n                defects.append(f"TRUST_ROOT:{key_id}_LEDGER_STREAM_MISMATCH")\n            if str(trust_root_event["actor"]) != str(root["accepted_by"]):\n                defects.append(f"TRUST_ROOT:{key_id}_LEDGER_ACTOR_MISMATCH")\n            if str(trust_root_event["occurred_at"]) != str(root["accepted_at"]):\n                defects.append(f"TRUST_ROOT:{key_id}_LEDGER_TIMESTAMP_MISMATCH")\n\n        if not self.ledger.verify(f"continuity:trust-root:{key_id}").ok:\n            defects.append(f"TRUST_ROOT_LEDGER_CHAIN_INVALID:{key_id}")\n\n        return TrustRootVerification(\n            key_id=key_id,\n            defects=tuple(dict.fromkeys(defects)),\n        )\n\n'''
    source = replace_once(
        source,
        '''    def _parse_review(self, payload: bytes) -> dict[str, object]:\n''',
        method + '''    def _parse_review(self, payload: bytes) -> dict[str, object]:\n''',
        "standalone trust-root verifier method",
    )

    start_marker = '''            if root is None:\n                defects.append(f"REVIEW_TRUST_ROOT_MISSING:{review_id}")\n            else:\n                key_id = str(root["key_id"])\n                public_key = bytes(root["public_key_pem"])\n'''
    end_marker = '''                if not self.signature_verifier.verify(public_key, payload, signature):\n                    defects.append(f"REVIEW_SIGNATURE_INVALID:{review_id}")\n'''
    if source.count(start_marker) != 1 or source.count(end_marker) != 1:
        raise SystemExit("bounded trust-root refactor markers missing or duplicated")
    start = source.index(start_marker)
    end = source.index(end_marker, start) + len(end_marker)
    replacement = '''            if root is None:\n                defects.append(f"REVIEW_TRUST_ROOT_MISSING:{review_id}")\n            else:\n                key_id = str(root["key_id"])\n                public_key = bytes(root["public_key_pem"])\n                defects.extend(self.verify_trust_root(key_id).defects)\n                if not self.signature_verifier.verify(public_key, payload, signature):\n                    defects.append(f"REVIEW_SIGNATURE_INVALID:{review_id}")\n'''
    source = source[:start] + replacement + source[end:]

    source = replace_once(
        source,
        '''        for key_id in {\n            str(row["key_id"])\n            for row in review_rows\n        }:\n            if not self.ledger.verify(f"continuity:trust-root:{key_id}").ok:\n                defects.append(f"TRUST_ROOT_LEDGER_CHAIN_INVALID:{key_id}")\n''',
        "",
        "obsolete incident-local trust-root chain verification",
    )
    SERVICE_PATH.write_text(source, encoding="utf-8")


def main() -> int:
    patch_types()
    patch_service()
    print("extracted one standalone continuity trust-root verification authority")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
