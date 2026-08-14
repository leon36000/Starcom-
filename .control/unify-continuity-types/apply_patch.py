from __future__ import annotations

from pathlib import Path


PATH = Path("src/starcom/continuity.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"bounded patch refused for {label}: expected one target, found {count}")
    return source.replace(old, new, 1)


def main() -> int:
    source = PATH.read_text(encoding="utf-8")

    source = replace_once(
        source,
        '''from dataclasses import dataclass\nfrom datetime import datetime\nfrom enum import Enum\n''',
        '''from datetime import datetime\n''',
        "obsolete dataclass/enum imports",
    )
    source = replace_once(
        source,
        '''import tempfile\nfrom typing import Protocol\n\nfrom .canonical import canonical_json, sha256_digest, utc_now\n''',
        '''import tempfile\n\nfrom .canonical import canonical_json, sha256_digest, utc_now\nfrom .continuity_types import (\n    ContinuityVerification,\n    IncidentRecord,\n    IncidentStatus,\n    RecoveryPublication,\n    ReviewAdmission,\n    SignatureVerifier,\n    TrustRootReceipt,\n)\n''',
        "canonical continuity type imports",
    )
    source = replace_once(
        source,
        '''\n\nclass IncidentStatus(str, Enum):\n    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"\n    RECOVERY_PUBLISHED_RECOLLECT_REQUIRED = "RECOVERY_PUBLISHED_RECOLLECT_REQUIRED"\n\n\nclass SignatureVerifier(Protocol):\n    def validate_public_key(self, public_key_pem: bytes) -> bool: ...\n\n    def verify(self, public_key_pem: bytes, payload: bytes, signature: bytes) -> bool: ...\n\n\nclass OpenSSLEd25519Verifier:\n''',
        '''\n\nclass OpenSSLEd25519Verifier:\n''',
        "duplicate enum/protocol definitions",
    )
    source = replace_once(
        source,
        '''\n\n@dataclass(frozen=True)\nclass IncidentRecord:\n    incident_id: str\n    reviewed_archive_sha256: str\n    status: IncidentStatus\n    disposition: str\n    created_at: str\n    created_by: str\n    ledger_event_id: str\n    ledger_hash: str\n\n\n@dataclass(frozen=True)\nclass TrustRootReceipt:\n    key_id: str\n    fingerprint_sha256: str\n    accepted_at: str\n    accepted_by: str\n    decision_id: str\n    ledger_event_id: str\n    ledger_hash: str\n\n\n@dataclass(frozen=True)\nclass ReviewAdmission:\n    review_id: str\n    incident_id: str\n    key_id: str\n    payload_sha256: str\n    signature_sha256: str\n    disposition: str\n    reviewer_identity: str\n    admitted_at: str\n    admitted_by: str\n    ledger_event_id: str\n    ledger_hash: str\n\n\n@dataclass(frozen=True)\nclass RecoveryPublication:\n    publication_id: str\n    incident_id: str\n    review_id: str\n    idempotency_key: str\n    decision_id: str\n    status: IncidentStatus\n    published_at: str\n    published_by: str\n    ledger_event_id: str\n    ledger_hash: str\n\n\n@dataclass(frozen=True)\nclass ContinuityVerification:\n    incident_id: str\n    defects: tuple[str, ...]\n\n    @property\n    def ok(self) -> bool:\n        return not self.defects\n\n\nclass ContinuityService:\n''',
        '''\n\nclass ContinuityService:\n''',
        "duplicate dataclass definitions",
    )

    PATH.write_text(source, encoding="utf-8")
    print("continuity.py now imports and re-exports the single canonical continuity type authority")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
