from __future__ import annotations

from pathlib import Path


PATH = Path("tests/test_census.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"bounded census patch refused for {label}: expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def main() -> int:
    source = PATH.read_text(encoding="utf-8")

    source = replace_once(
        source,
        '''        return observation_id, digest\n\n    def register(\n''',
        '''        return observation_id, digest\n\n    def prepare_failed_evidence(self) -> tuple[str, str]:\n        attempt_id = "attempt-failed"\n        observation_id = "observation-failed"\n        source_id = "blocked-source"\n        content_digest = hashlib.sha256(b"failed-identity-evidence").hexdigest()\n        data = {"identity": "failed-identity", "fixture": True}\n        self.research.begin_attempt(\n            "c2-campaign",\n            attempt_id=attempt_id,\n            wave=1,\n            request_key="request-failed",\n            source_id=source_id,\n            request={"url": "https://example.invalid/blocked"},\n            actor="researcher",\n            occurred_at=T1,\n        )\n        self.research.record_receipt(\n            attempt_id,\n            receipt_id="receipt-failed",\n            outcome=ReceiptOutcome.POLICY_BLOCK,\n            status_code=403,\n            snapshot_digest=None,\n            metadata={"fixture": True},\n            actor="researcher",\n            occurred_at=T1,\n        )\n        payload = {\n            "observation_id": observation_id,\n            "attempt_id": attempt_id,\n            "snapshot_digest": SNAPSHOT,\n            "content_digest": content_digest,\n            "data": data,\n        }\n        event = self.ledger.append(\n            "research:campaign:c2-campaign",\n            "RESEARCH_OBSERVATION_RECORDED",\n            payload,\n            actor="fixture-forger",\n            occurred_at=T2,\n        )\n        with self.db.transaction() as connection:\n            connection.execute(\n                """\n                INSERT INTO research_observations (\n                    observation_id, attempt_id, snapshot_digest, content_digest,\n                    data_json, observed_at, ledger_event_id, ledger_hash\n                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)\n                """,\n                (\n                    observation_id,\n                    attempt_id,\n                    SNAPSHOT,\n                    content_digest,\n                    json.dumps(data, sort_keys=True, separators=(",", ":")),\n                    T2,\n                    event.event_id,\n                    event.record_hash,\n                ),\n            )\n        return attempt_id, observation_id\n\n    def register(\n''',
        "failed evidence helper",
    )

    source = replace_once(
        source,
        '''    def test_verifier_detects_repointed_identity_event(self) -> None:\n''',
        '''    def test_failed_attempt_evidence_is_rejected(self) -> None:\n        attempt_id, observation_id = self.prepare_failed_evidence()\n\n        with self.assertRaisesRegex(\n            StateTransitionError,\n            "identity evidence requires a successful attempt",\n        ):\n            self.census.register_identity(\n                "c2-run",\n                identity_id="identity-failed",\n                identity_key="failed-person",\n                source_id="blocked-source",\n                attempt_id=attempt_id,\n                observation_id=observation_id,\n                actor="researcher",\n                occurred_at=T3,\n            )\n\n    def test_verifier_detects_identity_evidence_digest_tampering(self) -> None:\n        self.prepare_success_attempt()\n        self.add_observation(1)\n        record = self.register(1)\n        self.db.connection.execute("DROP TRIGGER c2_census_identities_no_update")\n        self.db.connection.execute(\n            "UPDATE c2_census_identities SET evidence_digest = ? WHERE identity_id = ?",\n            ("0" * 64, record.identity_id),\n        )\n\n        verification = self.census.verify("c2-run")\n\n        self.assertFalse(verification.ok)\n        self.assertIn(\n            f"C2_IDENTITY_EVIDENCE_DIGEST_MISMATCH:{record.identity_id}",\n            verification.defects,\n        )\n        self.assertIn(\n            f"C2_IDENTITY_LEDGER_PAYLOAD_MISMATCH:{record.identity_id}",\n            verification.defects,\n        )\n\n    def test_verifier_detects_repointed_identity_event(self) -> None:\n''',
        "additional census falsification tests",
    )

    PATH.write_text(source, encoding="utf-8")
    print("added failed-evidence and evidence-digest falsification coverage")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
