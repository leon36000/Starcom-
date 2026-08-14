from __future__ import annotations

from pathlib import Path


PATH = Path("src/starcom/cli.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"bounded patch refused for {label}: expected 1 target, found {count}")
    return source.replace(old, new, 1)


def main() -> int:
    source = PATH.read_text(encoding="utf-8")

    source = replace_once(
        source,
        "from .proof import ProofEngine, VerificationVerdict\nfrom .research import ReceiptOutcome, ResearchCampaign\n",
        "from .proof import ProofEngine, VerificationVerdict\nfrom .recollection import C2RecollectionService\nfrom .research import ReceiptOutcome, ResearchCampaign\n",
        "recollection import",
    )

    source = replace_once(
        source,
        "    research: ResearchCampaign\n    continuity: ContinuityService\n",
        "    research: ResearchCampaign\n    continuity: ContinuityService\n    recollection: C2RecollectionService\n",
        "runtime field",
    )

    source = replace_once(
        source,
        "            research = ResearchCampaign(database, ledger)\n            continuity = ContinuityService(database, ledger, trust)\n            return cls(database, ledger, trust, proof, missions, research, continuity)\n",
        "            research = ResearchCampaign(database, ledger)\n            continuity = ContinuityService(database, ledger, trust)\n            recollection = C2RecollectionService(database, ledger, continuity, research)\n            return cls(\n                database, ledger, trust, proof, missions, research, continuity, recollection\n            )\n",
        "runtime initialization",
    )

    source = replace_once(
        source,
        '''def _continuity_publish_recovery(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    return runtime.continuity.publish_recovery(\n        args.incident_id,\n        args.review_id,\n        publication_id=args.publication_id,\n        idempotency_key=args.idempotency_key,\n        decision_id=args.decision_id,\n        actor=args.actor,\n        occurred_at=args.occurred_at,\n    ), 0\n\n\ndef _trust_add_rule(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n''',
        '''def _continuity_publish_recovery(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    return runtime.continuity.publish_recovery(\n        args.incident_id,\n        args.review_id,\n        publication_id=args.publication_id,\n        idempotency_key=args.idempotency_key,\n        decision_id=args.decision_id,\n        actor=args.actor,\n        occurred_at=args.occurred_at,\n    ), 0\n\n\ndef _recollection_start(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    return runtime.recollection.start(\n        args.recollection_id,\n        incident_id=args.incident_id,\n        campaign_id=args.campaign_id,\n        minimum_identity_target=args.minimum_identity_target,\n        actor=args.actor,\n        occurred_at=args.occurred_at,\n    ), 0\n\n\ndef _recollection_get(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    return runtime.recollection.get(args.recollection_id), 0\n\n\ndef _recollection_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    verification = runtime.recollection.verify(args.recollection_id)\n    return _verification_payload(verification), 0 if verification.ok else 3\n\n\ndef _trust_add_rule(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n''',
        "recollection handlers",
    )

    source = replace_once(
        source,
        '''    _add_occurred_at(publish_recovery)\n    _set_handler(publish_recovery, _continuity_publish_recovery)\n\n    trust = top.add_parser("trust", help="manage default-deny policy and decisions")\n''',
        '''    _add_occurred_at(publish_recovery)\n    _set_handler(publish_recovery, _continuity_publish_recovery)\n\n    recollection = top.add_parser(\n        "recollection",\n        help="manage the C1-gated Task 5 C2 recollection binding",\n    )\n    recollection_commands = recollection.add_subparsers(\n        dest="recollection_command", required=True\n    )\n\n    recollection_start = recollection_commands.add_parser("start")\n    recollection_start.add_argument("--recollection-id", required=True)\n    recollection_start.add_argument("--incident-id", required=True)\n    recollection_start.add_argument("--campaign-id", required=True)\n    recollection_start.add_argument("--minimum-identity-target", type=int, required=True)\n    recollection_start.add_argument("--actor", required=True)\n    _add_occurred_at(recollection_start)\n    _set_handler(recollection_start, _recollection_start)\n\n    recollection_get = recollection_commands.add_parser("get")\n    recollection_get.add_argument("--recollection-id", required=True)\n    _set_handler(recollection_get, _recollection_get)\n\n    recollection_verify = recollection_commands.add_parser("verify")\n    recollection_verify.add_argument("--recollection-id", required=True)\n    _set_handler(recollection_verify, _recollection_verify)\n\n    trust = top.add_parser("trust", help="manage default-deny policy and decisions")\n''',
        "recollection parser",
    )

    PATH.write_text(source, encoding="utf-8")
    print("patched src/starcom/cli.py with thin C2 recollection CLI")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
