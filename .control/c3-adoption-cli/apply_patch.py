from __future__ import annotations

from pathlib import Path


PATH = Path("src/starcom/cli.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"bounded patch refused for {label}: expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def main() -> int:
    source = PATH.read_text(encoding="utf-8")

    source = replace_once(
        source,
        "from . import __version__\nfrom .canonical import canonical_json\n",
        "from . import __version__\nfrom .adoption import C3AdoptionService\nfrom .canonical import canonical_json\n",
        "adoption import",
    )
    source = replace_once(
        source,
        "    c3: C3QualificationGate\n    c3_decision: C3DecisionService\n",
        "    c3: C3QualificationGate\n    c3_decision: C3DecisionService\n    adoption: C3AdoptionService\n",
        "runtime adoption field",
    )
    source = replace_once(
        source,
        '''            c3_decision = C3DecisionService(\n                database,\n                ledger,\n                continuity,\n                certification,\n                c3,\n                qualification,\n            )\n            return cls(\n''',
        '''            c3_decision = C3DecisionService(\n                database,\n                ledger,\n                continuity,\n                certification,\n                c3,\n                qualification,\n            )\n            adoption = C3AdoptionService(\n                database,\n                ledger,\n                trust,\n                continuity,\n                c3_decision,\n                qualification,\n            )\n            return cls(\n''',
        "runtime adoption initialization",
    )
    source = replace_once(
        source,
        '''                qualification,\n                c3,\n                c3_decision,\n            )\n''',
        '''                qualification,\n                c3,\n                c3_decision,\n                adoption,\n            )\n''',
        "runtime adoption constructor argument",
    )
    source = replace_once(
        source,
        '''def _c3_decision_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    verification = runtime.c3_decision.verify_decision(args.decision_id)\n    return _verification_payload(verification), 0 if verification.ok else 3\n\n\ndef _trust_add_rule(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n''',
        '''def _c3_decision_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    verification = runtime.c3_decision.verify_decision(args.decision_id)\n    return _verification_payload(verification), 0 if verification.ok else 3\n\n\ndef _adoption_prepare(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    return runtime.adoption.prepare(\n        args.c3_run_id,\n        _json_object(args.rollback_plan_json, "rollback_plan_json"),\n    ), 0\n\n\ndef _adoption_authorize(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    return runtime.adoption.authorize_adoption(\n        args.adoption_id,\n        c3_run_id=args.c3_run_id,\n        authorization_decision_id=args.authorization_decision_id,\n        rollback_plan=_json_object(args.rollback_plan_json, "rollback_plan_json"),\n        actor=args.actor,\n        occurred_at=args.occurred_at,\n    ), 0\n\n\ndef _adoption_get(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    return runtime.adoption.get_adoption(args.adoption_id), 0\n\n\ndef _adoption_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    verification = runtime.adoption.verify_adoption(args.adoption_id)\n    return _verification_payload(verification), 0 if verification.ok else 3\n\n\ndef _trust_add_rule(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n''',
        "adoption handlers",
    )
    source = replace_once(
        source,
        '''    c3_decision_verify = c3_decision_commands.add_parser("verify")\n    c3_decision_verify.add_argument("--decision-id", required=True)\n    _set_handler(c3_decision_verify, _c3_decision_verify)\n\n    trust = top.add_parser("trust", help="manage default-deny policy and decisions")\n''',
        '''    c3_decision_verify = c3_decision_commands.add_parser("verify")\n    c3_decision_verify.add_argument("--decision-id", required=True)\n    _set_handler(c3_decision_verify, _c3_decision_verify)\n\n    adoption = top.add_parser(\n        "adoption",\n        help="authorize one selected C3 candidate without executing adoption",\n    )\n    adoption_commands = adoption.add_subparsers(\n        dest="adoption_command", required=True\n    )\n\n    adoption_prepare = adoption_commands.add_parser("prepare")\n    adoption_prepare.add_argument("--c3-run-id", required=True)\n    adoption_prepare.add_argument("--rollback-plan-json", required=True)\n    _set_handler(adoption_prepare, _adoption_prepare)\n\n    adoption_authorize = adoption_commands.add_parser("authorize")\n    adoption_authorize.add_argument("--adoption-id", required=True)\n    adoption_authorize.add_argument("--c3-run-id", required=True)\n    adoption_authorize.add_argument(\n        "--authorization-decision-id", required=True\n    )\n    adoption_authorize.add_argument("--rollback-plan-json", required=True)\n    adoption_authorize.add_argument("--actor", required=True)\n    _add_occurred_at(adoption_authorize)\n    _set_handler(adoption_authorize, _adoption_authorize)\n\n    adoption_get = adoption_commands.add_parser("get")\n    adoption_get.add_argument("--adoption-id", required=True)\n    _set_handler(adoption_get, _adoption_get)\n\n    adoption_verify = adoption_commands.add_parser("verify")\n    adoption_verify.add_argument("--adoption-id", required=True)\n    _set_handler(adoption_verify, _adoption_verify)\n\n    trust = top.add_parser("trust", help="manage default-deny policy and decisions")\n''',
        "adoption parser",
    )

    PATH.write_text(source, encoding="utf-8")
    print("patched CLI with non-executing C3 adoption prepare/authorize/get/verify")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
