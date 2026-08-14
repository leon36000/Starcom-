from __future__ import annotations

from pathlib import Path


PATH = Path("src/starcom/cli.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"bounded census CLI patch refused for {label}: expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def main() -> int:
    source = PATH.read_text(encoding="utf-8")

    source = replace_once(
        source,
        '''from .canonical import canonical_json\nfrom .continuity import ContinuityService\n''',
        '''from .canonical import canonical_json\nfrom .census import C2CensusService\nfrom .continuity import ContinuityService\n''',
        "census import",
    )

    source = replace_once(
        source,
        '''    continuity: ContinuityService\n    recollection: C2RecollectionService\n''',
        '''    continuity: ContinuityService\n    recollection: C2RecollectionService\n    census: C2CensusService\n''',
        "runtime census field",
    )

    source = replace_once(
        source,
        '''            continuity = ContinuityService(database, ledger, trust)\n            recollection = C2RecollectionService(database, ledger, continuity, research)\n            return cls(\n                database, ledger, trust, proof, missions, research, continuity, recollection\n            )\n''',
        '''            continuity = ContinuityService(database, ledger, trust)\n            recollection = C2RecollectionService(database, ledger, continuity, research)\n            census = C2CensusService(database, ledger, recollection, research)\n            return cls(\n                database,\n                ledger,\n                trust,\n                proof,\n                missions,\n                research,\n                continuity,\n                recollection,\n                census,\n            )\n''',
        "runtime census initialization",
    )

    source = replace_once(
        source,
        '''def _recollection_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    verification = runtime.recollection.verify(args.recollection_id)\n    return _verification_payload(verification), 0 if verification.ok else 3\n\n\ndef _trust_add_rule(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n''',
        '''def _recollection_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    verification = runtime.recollection.verify(args.recollection_id)\n    return _verification_payload(verification), 0 if verification.ok else 3\n\n\ndef _census_register(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    return runtime.census.register_identity(\n        args.recollection_id,\n        identity_id=args.identity_id,\n        identity_key=args.identity_key,\n        source_id=args.source_id,\n        attempt_id=args.attempt_id,\n        observation_id=args.observation_id,\n        actor=args.actor,\n        occurred_at=args.occurred_at,\n    ), 0\n\n\ndef _census_get(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    return runtime.census.get_identity(args.identity_id), 0\n\n\ndef _census_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    verification = runtime.census.verify(args.recollection_id)\n    return _verification_payload(verification), 0 if verification.ok else 3\n\n\ndef _census_assess(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    assessment = runtime.census.assess(args.recollection_id)\n    return assessment, 0 if not assessment.defects else 3\n\n\ndef _trust_add_rule(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n''',
        "census handlers",
    )

    source = replace_once(
        source,
        '''    recollection_verify = recollection_commands.add_parser("verify")\n    recollection_verify.add_argument("--recollection-id", required=True)\n    _set_handler(recollection_verify, _recollection_verify)\n\n    trust = top.add_parser("trust", help="manage default-deny policy and decisions")\n''',
        '''    recollection_verify = recollection_commands.add_parser("verify")\n    recollection_verify.add_argument("--recollection-id", required=True)\n    _set_handler(recollection_verify, _recollection_verify)\n\n    census = top.add_parser(\n        "census",\n        help="manage evidence-bound Task 5 C2 census identities and assessment",\n    )\n    census_commands = census.add_subparsers(dest="census_command", required=True)\n\n    census_register = census_commands.add_parser("register")\n    census_register.add_argument("--recollection-id", required=True)\n    census_register.add_argument("--identity-id", required=True)\n    census_register.add_argument("--identity-key", required=True)\n    census_register.add_argument("--source-id", required=True)\n    census_register.add_argument("--attempt-id", required=True)\n    census_register.add_argument("--observation-id", required=True)\n    census_register.add_argument("--actor", required=True)\n    _add_occurred_at(census_register)\n    _set_handler(census_register, _census_register)\n\n    census_get = census_commands.add_parser("get")\n    census_get.add_argument("--identity-id", required=True)\n    _set_handler(census_get, _census_get)\n\n    census_verify = census_commands.add_parser("verify")\n    census_verify.add_argument("--recollection-id", required=True)\n    _set_handler(census_verify, _census_verify)\n\n    census_assess = census_commands.add_parser("assess")\n    census_assess.add_argument("--recollection-id", required=True)\n    _set_handler(census_assess, _census_assess)\n\n    trust = top.add_parser("trust", help="manage default-deny policy and decisions")\n''',
        "census parser",
    )

    PATH.write_text(source, encoding="utf-8")
    print("patched src/starcom/cli.py with thin C2 census CLI")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
