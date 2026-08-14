from __future__ import annotations

from pathlib import Path


PATH = Path("src/starcom/cli.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"bounded CLI patch refused for {label}: expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def main() -> int:
    source = PATH.read_text(encoding="utf-8")

    source = replace_once(
        source,
        "from .adoption import C3AdoptionService\n",
        "from .adoption import C3AdoptionService\n"
        "from .adoption_execution import C3AdoptionExecutionService\n",
        "execution service import",
    )
    source = replace_once(
        source,
        "from .db import Database\n",
        "from .db import Database\nfrom .durable import DurableOutbox\n",
        "durable outbox import",
    )
    source = replace_once(
        source,
        "    c3_decision: C3DecisionService\n    adoption: C3AdoptionService\n",
        "    c3_decision: C3DecisionService\n"
        "    adoption: C3AdoptionService\n"
        "    outbox: DurableOutbox\n"
        "    adoption_execution: C3AdoptionExecutionService\n",
        "Runtime execution fields",
    )
    source = replace_once(
        source,
        '''            adoption = C3AdoptionService(
                database,
                ledger,
                trust,
                continuity,
                c3_decision,
                qualification,
            )
            return cls(
''',
        '''            adoption = C3AdoptionService(
                database,
                ledger,
                trust,
                continuity,
                c3_decision,
                qualification,
            )
            outbox = DurableOutbox(database, ledger)
            adoption_execution = C3AdoptionExecutionService(
                database,
                ledger,
                trust,
                continuity,
                adoption,
                outbox,
            )
            return cls(
''',
        "Runtime execution initialization",
    )
    source = replace_once(
        source,
        '''                c3,
                c3_decision,
                adoption,
            )
''',
        '''                c3,
                c3_decision,
                adoption,
                outbox,
                adoption_execution,
            )
''',
        "Runtime execution constructor arguments",
    )
    source = replace_once(
        source,
        '''def _adoption_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    verification = runtime.adoption.verify_adoption(args.adoption_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _trust_add_rule(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
''',
        '''def _adoption_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
    verification = runtime.adoption.verify_adoption(args.adoption_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _adoption_execution_prepare(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.adoption_execution.prepare(
        args.execution_id,
        adoption_id=args.adoption_id,
        executor_id=args.executor_id,
        execution_plan=_json_object(
            args.execution_plan_json,
            "execution_plan_json",
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
            args.execution_plan_json,
            "execution_plan_json",
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


def _trust_add_rule(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
''',
        "execution CLI handlers",
    )
    source = replace_once(
        source,
        '''    adoption_verify = adoption_commands.add_parser("verify")
    adoption_verify.add_argument("--adoption-id", required=True)
    _set_handler(adoption_verify, _adoption_verify)

    trust = top.add_parser("trust", help="manage default-deny policy and decisions")
''',
        '''    adoption_verify = adoption_commands.add_parser("verify")
    adoption_verify.add_argument("--adoption-id", required=True)
    _set_handler(adoption_verify, _adoption_verify)

    adoption_execution = top.add_parser(
        "adoption-execution",
        help="admit durable C3 execution requests without running a worker",
    )
    adoption_execution_commands = adoption_execution.add_subparsers(
        dest="adoption_execution_command",
        required=True,
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
        "--authorization-decision-id",
        required=True,
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

    trust = top.add_parser("trust", help="manage default-deny policy and decisions")
''',
        "execution CLI parser",
    )

    forbidden = (
        "C3AdoptionExecutionWorker",
        'adoption_execution_commands.add_parser("process")',
        'adoption_execution_commands.add_parser("worker")',
        'adoption_execution_commands.add_parser("execute")',
        'adoption_execution_commands.add_parser("install")',
        'adoption_execution_commands.add_parser("deploy")',
    )
    present = [item for item in forbidden if item in source]
    if present:
        raise SystemExit(
            f"bounded CLI patch exposed forbidden execution paths: {present}"
        )
    if source.count("def _adoption_execution_") != 4:
        raise SystemExit("bounded CLI patch did not create exactly four handlers")
    if source.count('        "adoption-execution",\n') != 1:
        raise SystemExit("bounded CLI patch did not create one command surface")

    PATH.write_text(source, encoding="utf-8")
    print("patched non-executing C3 execution prepare/request/get/verify CLI")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
