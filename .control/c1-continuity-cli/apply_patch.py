from __future__ import annotations

from pathlib import Path


PATH = Path("src/starcom/cli.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"bounded patch refused for {label}: expected one target, found {count}")
    return source.replace(old, new, 1)


def main() -> int:
    source = PATH.read_text(encoding="utf-8")

    source = replace_once(
        source,
        '''from .canonical import canonical_json\nfrom .db import Database\n''',
        '''from .canonical import canonical_json\nfrom .continuity import ContinuityService\nfrom .db import Database\n''',
        "continuity import",
    )

    source = replace_once(
        source,
        '''    missions: MissionKernel\n    research: ResearchCampaign\n\n    @classmethod\n''',
        '''    missions: MissionKernel\n    research: ResearchCampaign\n    continuity: ContinuityService\n\n    @classmethod\n''',
        "runtime field",
    )

    source = replace_once(
        source,
        '''            missions = MissionKernel(database, ledger, trust, proof)\n            research = ResearchCampaign(database, ledger)\n            return cls(database, ledger, trust, proof, missions, research)\n''',
        '''            missions = MissionKernel(database, ledger, trust, proof)\n            research = ResearchCampaign(database, ledger)\n            continuity = ContinuityService(database, ledger, trust)\n            return cls(database, ledger, trust, proof, missions, research, continuity)\n''',
        "runtime initialization",
    )

    source = replace_once(
        source,
        '''def _json_object(raw: str, field_name: str) -> Mapping[str, Any]:\n    value = _json_value(raw, field_name)\n    if not isinstance(value, dict):\n        raise ValidationError(f"{field_name} must contain a JSON object")\n    return value\n\n\ndef _verification_payload(value: Any) -> dict[str, Any]:\n''',
        '''def _json_object(raw: str, field_name: str) -> Mapping[str, Any]:\n    value = _json_value(raw, field_name)\n    if not isinstance(value, dict):\n        raise ValidationError(f"{field_name} must contain a JSON object")\n    return value\n\n\ndef _read_file_bytes(raw: str, field_name: str) -> bytes:\n    path = Path(raw).expanduser()\n    try:\n        return path.read_bytes()\n    except OSError as exc:\n        raise ValidationError(\n            f"{field_name} could not be read",\n            {"path": str(path), "type": type(exc).__name__},\n        ) from exc\n\n\ndef _verification_payload(value: Any) -> dict[str, Any]:\n''',
        "exact-byte file reader",
    )

    source = replace_once(
        source,
        '''def _research_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    verification = runtime.research.verify(args.campaign_id)\n    return _verification_payload(verification), 0 if verification.ok else 3\n\n\ndef _trust_add_rule(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n''',
        '''def _research_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    verification = runtime.research.verify(args.campaign_id)\n    return _verification_payload(verification), 0 if verification.ok else 3\n\n\ndef _continuity_create_incident(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    return runtime.continuity.create_incident(\n        args.incident_id,\n        reviewed_archive_sha256=args.reviewed_archive_sha256,\n        actor=args.actor,\n        occurred_at=args.occurred_at,\n    ), 0\n\n\ndef _continuity_get_incident(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    return runtime.continuity.get_incident(args.incident_id), 0\n\n\ndef _continuity_accept_trust_root(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    public_key = _read_file_bytes(args.public_key_file, "public_key_file")\n    return runtime.continuity.accept_trust_root(\n        args.key_id,\n        public_key,\n        decision_id=args.decision_id,\n        actor=args.actor,\n        occurred_at=args.occurred_at,\n    ), 0\n\n\ndef _continuity_admit_review(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    payload = _read_file_bytes(args.payload_file, "payload_file")\n    signature = _read_file_bytes(args.signature_file, "signature_file")\n    return runtime.continuity.admit_review(\n        args.incident_id,\n        args.key_id,\n        payload,\n        signature,\n        actor=args.actor,\n        occurred_at=args.occurred_at,\n    ), 0\n\n\ndef _continuity_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    verification = runtime.continuity.verify_incident(args.incident_id)\n    return _verification_payload(verification), 0 if verification.ok else 3\n\n\ndef _continuity_publish_recovery(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    return runtime.continuity.publish_recovery(\n        args.incident_id,\n        args.review_id,\n        publication_id=args.publication_id,\n        idempotency_key=args.idempotency_key,\n        decision_id=args.decision_id,\n        actor=args.actor,\n        occurred_at=args.occurred_at,\n    ), 0\n\n\ndef _trust_add_rule(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n''',
        "continuity handlers",
    )

    source = replace_once(
        source,
        '''    research_verify = research_commands.add_parser("verify")\n    research_verify.add_argument("--campaign-id", required=True)\n    _set_handler(research_verify, _research_verify)\n\n    trust = top.add_parser("trust", help="manage default-deny policy and decisions")\n''',
        '''    research_verify = research_commands.add_parser("verify")\n    research_verify.add_argument("--campaign-id", required=True)\n    _set_handler(research_verify, _research_verify)\n\n    continuity = top.add_parser(\n        "continuity",\n        help="manage proof-gated C1 review admission and recovery publication",\n    )\n    continuity_commands = continuity.add_subparsers(dest="continuity_command", required=True)\n\n    create_incident = continuity_commands.add_parser("create-incident")\n    create_incident.add_argument("--incident-id", required=True)\n    create_incident.add_argument("--reviewed-archive-sha256", required=True)\n    create_incident.add_argument("--actor", required=True)\n    _add_occurred_at(create_incident)\n    _set_handler(create_incident, _continuity_create_incident)\n\n    get_incident = continuity_commands.add_parser("get-incident")\n    get_incident.add_argument("--incident-id", required=True)\n    _set_handler(get_incident, _continuity_get_incident)\n\n    accept_trust_root = continuity_commands.add_parser("accept-trust-root")\n    accept_trust_root.add_argument("--key-id", required=True)\n    accept_trust_root.add_argument("--public-key-file", required=True)\n    accept_trust_root.add_argument("--decision-id", required=True)\n    accept_trust_root.add_argument("--actor", required=True)\n    _add_occurred_at(accept_trust_root)\n    _set_handler(accept_trust_root, _continuity_accept_trust_root)\n\n    admit_review = continuity_commands.add_parser("admit-review")\n    admit_review.add_argument("--incident-id", required=True)\n    admit_review.add_argument("--key-id", required=True)\n    admit_review.add_argument("--payload-file", required=True)\n    admit_review.add_argument("--signature-file", required=True)\n    admit_review.add_argument("--actor", required=True)\n    _add_occurred_at(admit_review)\n    _set_handler(admit_review, _continuity_admit_review)\n\n    continuity_verify = continuity_commands.add_parser("verify")\n    continuity_verify.add_argument("--incident-id", required=True)\n    _set_handler(continuity_verify, _continuity_verify)\n\n    publish_recovery = continuity_commands.add_parser("publish-recovery")\n    publish_recovery.add_argument("--incident-id", required=True)\n    publish_recovery.add_argument("--review-id", required=True)\n    publish_recovery.add_argument("--publication-id", required=True)\n    publish_recovery.add_argument("--idempotency-key", required=True)\n    publish_recovery.add_argument("--decision-id", required=True)\n    publish_recovery.add_argument("--actor", required=True)\n    _add_occurred_at(publish_recovery)\n    _set_handler(publish_recovery, _continuity_publish_recovery)\n\n    trust = top.add_parser("trust", help="manage default-deny policy and decisions")\n''',
        "continuity parser",
    )

    PATH.write_text(source, encoding="utf-8")
    print("patched src/starcom/cli.py with exact-byte C1 continuity CLI")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
