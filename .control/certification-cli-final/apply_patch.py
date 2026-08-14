from __future__ import annotations

from pathlib import Path


PATH = Path("src/starcom/cli.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"bounded certification CLI patch refused for {label}: "
            f"expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def main() -> int:
    source = PATH.read_text(encoding="utf-8")

    source = replace_once(
        source,
        '''from .census import C2CensusService\nfrom .continuity import ContinuityService\n''',
        '''from .census import C2CensusService\nfrom .certification import C2CertificationService\nfrom .continuity import ContinuityService\n''',
        "certification import",
    )

    source = replace_once(
        source,
        '''    recollection: C2RecollectionService\n    census: C2CensusService\n''',
        '''    recollection: C2RecollectionService\n    census: C2CensusService\n    certification: C2CertificationService\n''',
        "runtime certification field",
    )

    source = replace_once(
        source,
        '''            recollection = C2RecollectionService(database, ledger, continuity, research)\n            census = C2CensusService(database, ledger, recollection, research)\n            return cls(\n                database,\n                ledger,\n                trust,\n                proof,\n                missions,\n                research,\n                continuity,\n                recollection,\n                census,\n            )\n''',
        '''            recollection = C2RecollectionService(database, ledger, continuity, research)\n            census = C2CensusService(database, ledger, recollection, research)\n            certification = C2CertificationService(\n                database,\n                ledger,\n                continuity,\n                recollection,\n                census,\n            )\n            return cls(\n                database,\n                ledger,\n                trust,\n                proof,\n                missions,\n                research,\n                continuity,\n                recollection,\n                census,\n                certification,\n            )\n''',
        "runtime certification initialization",
    )

    source = replace_once(
        source,
        '''def _census_assess(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    assessment = runtime.census.assess(args.recollection_id)\n    return assessment, 0 if not assessment.defects else 3\n\n\ndef _trust_add_rule(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n''',
        '''def _census_assess(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    assessment = runtime.census.assess(args.recollection_id)\n    return assessment, 0 if not assessment.defects else 3\n\n\ndef _certification_snapshot(\n    runtime: Runtime, args: argparse.Namespace\n) -> tuple[Any, int]:\n    snapshot = runtime.certification.snapshot(args.recollection_id)\n    return {\n        "recollection_id": snapshot.recollection_id,\n        "incident_id": snapshot.incident_id,\n        "campaign_id": snapshot.campaign_id,\n        "identity_count": snapshot.identity_count,\n        "required_target": snapshot.required_target,\n        "identity_set_digest": snapshot.identity_set_digest,\n        "latest_identity_at": snapshot.latest_identity_at,\n    }, 0\n\n\ndef _certification_admit(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    payload = _read_file_bytes(args.payload_file, "payload_file")\n    signature = _read_file_bytes(args.signature_file, "signature_file")\n    return runtime.certification.admit_certification(\n        args.recollection_id,\n        args.key_id,\n        payload,\n        signature,\n        actor=args.actor,\n        occurred_at=args.occurred_at,\n    ), 0\n\n\ndef _certification_get(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    return runtime.certification.get_certificate(args.certificate_id), 0\n\n\ndef _certification_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    verification = runtime.certification.verify_certificate(args.certificate_id)\n    return _verification_payload(verification), 0 if verification.ok else 3\n\n\ndef _trust_add_rule(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n''',
        "certification handlers",
    )

    source = replace_once(
        source,
        '''    census_assess = census_commands.add_parser("assess")\n    census_assess.add_argument("--recollection-id", required=True)\n    _set_handler(census_assess, _census_assess)\n\n    trust = top.add_parser("trust", help="manage default-deny policy and decisions")\n''',
        '''    census_assess = census_commands.add_parser("assess")\n    census_assess.add_argument("--recollection-id", required=True)\n    _set_handler(census_assess, _census_assess)\n\n    certification = top.add_parser(\n        "certification",\n        help="manage exact-byte independently signed Task 5 C2 certifications",\n    )\n    certification_commands = certification.add_subparsers(\n        dest="certification_command", required=True\n    )\n\n    certification_snapshot = certification_commands.add_parser("snapshot")\n    certification_snapshot.add_argument("--recollection-id", required=True)\n    _set_handler(certification_snapshot, _certification_snapshot)\n\n    certification_admit = certification_commands.add_parser("admit")\n    certification_admit.add_argument("--recollection-id", required=True)\n    certification_admit.add_argument("--key-id", required=True)\n    certification_admit.add_argument("--payload-file", required=True)\n    certification_admit.add_argument("--signature-file", required=True)\n    certification_admit.add_argument("--actor", required=True)\n    _add_occurred_at(certification_admit)\n    _set_handler(certification_admit, _certification_admit)\n\n    certification_get = certification_commands.add_parser("get")\n    certification_get.add_argument("--certificate-id", required=True)\n    _set_handler(certification_get, _certification_get)\n\n    certification_verify = certification_commands.add_parser("verify")\n    certification_verify.add_argument("--certificate-id", required=True)\n    _set_handler(certification_verify, _certification_verify)\n\n    trust = top.add_parser("trust", help="manage default-deny policy and decisions")\n''',
        "certification parser",
    )

    PATH.write_text(source, encoding="utf-8")
    print("patched src/starcom/cli.py with exact-byte C2 certification CLI")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
