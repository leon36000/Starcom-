from __future__ import annotations

from pathlib import Path


PATH = Path("src/starcom/cli.py")


def require_once(source: str, needle: str, label: str) -> None:
    count = source.count(needle)
    if count != 1:
        raise SystemExit(
            f"bounded CLI patch refused for {label}: expected one target, found {count}"
        )


def main() -> int:
    source = PATH.read_text(encoding="utf-8")

    adoption_import = "from .adoption import C3AdoptionService\n"
    require_once(source, adoption_import, "adoption import")
    execution_import = (
        "from .adoption_execution import C3AdoptionExecutionService\n"
    )
    if execution_import not in source:
        source = source.replace(
            adoption_import,
            adoption_import + execution_import,
            1,
        )

    durable_import = "from .durable import DurableOutbox\n"
    if durable_import not in source:
        db_import = "from .db import Database\n"
        require_once(source, db_import, "database import")
        source = source.replace(db_import, db_import + durable_import, 1)

    runtime_field = "    adoption: C3AdoptionService\n"
    require_once(source, runtime_field, "runtime adoption field")
    if "    adoption_execution: C3AdoptionExecutionService\n" not in source:
        source = source.replace(
            runtime_field,
            runtime_field
            + "    outbox: DurableOutbox\n"
            + "    adoption_execution: C3AdoptionExecutionService\n",
            1,
        )

    creation_start = source.index("            adoption = C3AdoptionService(")
    return_start = source.index("            return cls(\n", creation_start)
    creation_block = source[creation_start:return_start]
    if creation_block.count("            adoption = C3AdoptionService(") != 1:
        raise SystemExit("bounded CLI patch refused: adoption creation is ambiguous")
    if "            adoption_execution = C3AdoptionExecutionService(" not in source:
        insertion = '''            outbox = DurableOutbox(database, ledger)
            adoption_execution = C3AdoptionExecutionService(
                database,
                ledger,
                trust,
                continuity,
                adoption,
                outbox,
            )
'''
        source = source[:return_start] + insertion + source[return_start:]

    constructor_tail = "                adoption,\n            )\n"
    require_once(source, constructor_tail, "Runtime constructor tail")
    source = source.replace(
        constructor_tail,
        "                adoption,\n"
        "                outbox,\n"
        "                adoption_execution,\n"
        "            )\n",
        1,
    )

    trust_handler = "\ndef _trust_add_rule("
    require_once(source, trust_handler, "trust handler boundary")
    handlers = '''

def _adoption_execution_prepare(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.adoption_execution.prepare(
        args.execution_id,
        adoption_id=args.adoption_id,
        executor_id=args.executor_id,
        execution_plan=_json_object(
            args.execution_plan_json, "execution_plan_json"
        ),
    ), 0


def _adoption_execution_request(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.adoption_execution.request_execution(
        args.execution_id,
        adoption_id=args.adoption_id,
        executor_id=args.executor_id,
        execution_plan=_json_object(
            args.execution_plan_json, "execution_plan_json"
        ),
        authorization_decision_id=args.authorization_decision_id,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _adoption_execution_get(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.adoption_execution.get_execution(args.execution_id), 0


def _adoption_execution_verify(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    verification = runtime.adoption_execution.verify_execution(args.execution_id)
    return _verification_payload(verification), 0 if verification.ok else 3
'''
    if "def _adoption_execution_prepare(" not in source:
        source = source.replace(trust_handler, handlers + trust_handler, 1)

    trust_parser = (
        '    trust = top.add_parser("trust", help="manage default-deny policy and decisions")\n'
    )
    require_once(source, trust_parser, "trust parser boundary")
    parser = '''    adoption_execution = top.add_parser(
        "adoption-execution",
        help="admit durable C3 execution requests without running a worker",
    )
    adoption_execution_commands = adoption_execution.add_subparsers(
        dest="adoption_execution_command", required=True
    )

    execution_prepare = adoption_execution_commands.add_parser("prepare")
    execution_prepare.add_argument("--execution-id", required=True)
    execution_prepare.add_argument("--adoption-id", required=True)
    execution_prepare.add_argument("--executor-id", required=True)
    execution_prepare.add_argument("--execution-plan-json", required=True)
    _set_handler(execution_prepare, _adoption_execution_prepare)

    execution_request = adoption_execution_commands.add_parser("request")
    execution_request.add_argument("--execution-id", required=True)
    execution_request.add_argument("--adoption-id", required=True)
    execution_request.add_argument("--executor-id", required=True)
    execution_request.add_argument("--execution-plan-json", required=True)
    execution_request.add_argument(
        "--authorization-decision-id", required=True
    )
    execution_request.add_argument("--actor", required=True)
    _add_occurred_at(execution_request)
    _set_handler(execution_request, _adoption_execution_request)

    execution_get = adoption_execution_commands.add_parser("get")
    execution_get.add_argument("--execution-id", required=True)
    _set_handler(execution_get, _adoption_execution_get)

    execution_verify = adoption_execution_commands.add_parser("verify")
    execution_verify.add_argument("--execution-id", required=True)
    _set_handler(execution_verify, _adoption_execution_verify)

'''
    if 'top.add_parser(\n        "adoption-execution"' not in source:
        source = source.replace(trust_parser, parser + trust_parser, 1)

    required = (
        "from .adoption_execution import C3AdoptionExecutionService",
        "    adoption_execution: C3AdoptionExecutionService",
        "def _adoption_execution_prepare(",
        "def _adoption_execution_request(",
        "def _adoption_execution_get(",
        "def _adoption_execution_verify(",
        '        "adoption-execution",',
    )
    missing = [item for item in required if item not in source]
    if missing:
        raise SystemExit(f"bounded CLI patch incomplete: {missing}")
    forbidden = (
        'adoption_execution_commands.add_parser("process")',
        'adoption_execution_commands.add_parser("worker")',
        'adoption_execution_commands.add_parser("execute")',
        "C3AdoptionExecutionWorker",
    )
    present = [item for item in forbidden if item in source]
    if present:
        raise SystemExit(f"bounded CLI patch exposed forbidden execution paths: {present}")

    PATH.write_text(source, encoding="utf-8")
    print("patched non-executing C3 execution prepare/request/get/verify CLI")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
