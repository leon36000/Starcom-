from __future__ import annotations

from pathlib import Path


PATH = Path("src/starcom/cli.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"bounded registry CLI patch refused for {label}: "
            f"expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def main() -> int:
    source = PATH.read_text(encoding="utf-8")

    source = replace_once(
        source,
        "from .errors import StarcomError, ValidationError\n",
        "from .errors import StarcomError, ValidationError\n"
        "from .executor_registry import C3ExecutorRegistry\n",
        "executor registry import",
    )

    source = replace_once(
        source,
        "    adoption_execution: C3AdoptionExecutionService\n",
        "    adoption_execution: C3AdoptionExecutionService\n"
        "    executor_registry: C3ExecutorRegistry\n",
        "Runtime registry field",
    )

    source = replace_once(
        source,
        '''            adoption_execution = C3AdoptionExecutionService(
                database,
                ledger,
                trust,
                continuity,
                adoption,
                outbox,
            )
            return cls(
''',
        '''            adoption_execution = C3AdoptionExecutionService(
                database,
                ledger,
                trust,
                continuity,
                adoption,
                outbox,
            )
            executor_registry = C3ExecutorRegistry(
                database,
                ledger,
                trust,
                continuity.signature_verifier,
            )
            return cls(
''',
        "Runtime registry initialization",
    )

    source = replace_once(
        source,
        '''                outbox,
                adoption_execution,
            )
''',
        '''                outbox,
                adoption_execution,
                executor_registry,
            )
''',
        "Runtime registry constructor argument",
    )

    source = replace_once(
        source,
        '''def _adoption_execution_verify(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    verification = runtime.adoption_execution.verify_execution(args.execution_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _trust_add_rule(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
''',
        '''def _adoption_execution_verify(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    verification = runtime.adoption_execution.verify_execution(args.execution_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _executor_registry_prepare_register(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.executor_registry.prepare_registration(
        _json_object(args.descriptor_json, "descriptor_json")
    ), 0


def _executor_registry_register(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.executor_registry.register(
        _json_object(args.descriptor_json, "descriptor_json"),
        authorization_decision_id=args.authorization_decision_id,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _executor_registry_prepare_qualifier_root(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    public_key = _read_file_bytes(args.public_key_file, "public_key_file")
    return runtime.executor_registry.prepare_qualifier_root(
        args.key_id,
        public_key,
    ), 0


def _executor_registry_accept_qualifier_root(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    public_key = _read_file_bytes(args.public_key_file, "public_key_file")
    return runtime.executor_registry.accept_qualifier_root(
        args.key_id,
        public_key,
        authorization_decision_id=args.authorization_decision_id,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _executor_registry_prepare_qualify(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    payload = _read_file_bytes(args.payload_file, "payload_file")
    signature = _read_file_bytes(args.signature_file, "signature_file")
    return runtime.executor_registry.prepare_qualification(
        args.executor_id,
        args.key_id,
        payload,
        signature,
    ), 0


def _executor_registry_qualify(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    payload = _read_file_bytes(args.payload_file, "payload_file")
    signature = _read_file_bytes(args.signature_file, "signature_file")
    return runtime.executor_registry.qualify(
        args.executor_id,
        args.key_id,
        payload,
        signature,
        authorization_decision_id=args.authorization_decision_id,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _executor_registry_prepare_enable(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.executor_registry.prepare_enable(args.executor_id), 0


def _executor_registry_enable(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.executor_registry.enable(
        args.executor_id,
        authorization_decision_id=args.authorization_decision_id,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _executor_registry_prepare_revoke(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.executor_registry.prepare_revoke(
        args.executor_id,
        reason=args.reason,
    ), 0


def _executor_registry_revoke(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.executor_registry.revoke(
        args.executor_id,
        reason=args.reason,
        authorization_decision_id=args.authorization_decision_id,
        actor=args.actor,
        occurred_at=args.occurred_at,
    ), 0


def _executor_registry_get(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return {
        "descriptor": runtime.executor_registry.get_descriptor(args.executor_id),
        "current": runtime.executor_registry.get_current(args.executor_id),
    }, 0


def _executor_registry_verify(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    verification = runtime.executor_registry.verify(args.executor_id)
    return _verification_payload(verification), 0 if verification.ok else 3


def _executor_registry_attest(
    runtime: Runtime, args: argparse.Namespace
) -> tuple[Any, int]:
    return runtime.executor_registry.attest(
        args.executor_id,
        implementation_version=args.implementation_version,
        implementation_digest=args.implementation_digest,
        sandbox_profile=args.sandbox_profile,
        requires_network=args.requires_network,
    ), 0


def _trust_add_rule(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:
''',
        "executor registry handlers",
    )

    source = replace_once(
        source,
        '''    execution_verify = adoption_execution_commands.add_parser("verify")
    execution_verify.add_argument("--execution-id", required=True)
    _set_handler(execution_verify, _adoption_execution_verify)

    trust = top.add_parser("trust", help="manage default-deny policy and decisions")
''',
        '''    execution_verify = adoption_execution_commands.add_parser("verify")
    execution_verify.add_argument("--execution-id", required=True)
    _set_handler(execution_verify, _adoption_execution_verify)

    executor_registry = top.add_parser(
        "executor-registry",
        help="manage exact, qualified, enabled and revocable C3 executors",
    )
    executor_registry_commands = executor_registry.add_subparsers(
        dest="executor_registry_command",
        required=True,
    )

    registry_prepare_register = executor_registry_commands.add_parser(
        "prepare-register"
    )
    registry_prepare_register.add_argument("--descriptor-json", required=True)
    _set_handler(
        registry_prepare_register,
        _executor_registry_prepare_register,
    )

    registry_register = executor_registry_commands.add_parser("register")
    registry_register.add_argument("--descriptor-json", required=True)
    registry_register.add_argument(
        "--authorization-decision-id",
        required=True,
    )
    registry_register.add_argument("--actor", required=True)
    _add_occurred_at(registry_register)
    _set_handler(registry_register, _executor_registry_register)

    registry_prepare_root = executor_registry_commands.add_parser(
        "prepare-qualifier-root"
    )
    registry_prepare_root.add_argument("--key-id", required=True)
    registry_prepare_root.add_argument("--public-key-file", required=True)
    _set_handler(
        registry_prepare_root,
        _executor_registry_prepare_qualifier_root,
    )

    registry_accept_root = executor_registry_commands.add_parser(
        "accept-qualifier-root"
    )
    registry_accept_root.add_argument("--key-id", required=True)
    registry_accept_root.add_argument("--public-key-file", required=True)
    registry_accept_root.add_argument(
        "--authorization-decision-id",
        required=True,
    )
    registry_accept_root.add_argument("--actor", required=True)
    _add_occurred_at(registry_accept_root)
    _set_handler(
        registry_accept_root,
        _executor_registry_accept_qualifier_root,
    )

    registry_prepare_qualify = executor_registry_commands.add_parser(
        "prepare-qualify"
    )
    registry_prepare_qualify.add_argument("--executor-id", required=True)
    registry_prepare_qualify.add_argument("--key-id", required=True)
    registry_prepare_qualify.add_argument("--payload-file", required=True)
    registry_prepare_qualify.add_argument("--signature-file", required=True)
    _set_handler(
        registry_prepare_qualify,
        _executor_registry_prepare_qualify,
    )

    registry_qualify = executor_registry_commands.add_parser("qualify")
    registry_qualify.add_argument("--executor-id", required=True)
    registry_qualify.add_argument("--key-id", required=True)
    registry_qualify.add_argument("--payload-file", required=True)
    registry_qualify.add_argument("--signature-file", required=True)
    registry_qualify.add_argument(
        "--authorization-decision-id",
        required=True,
    )
    registry_qualify.add_argument("--actor", required=True)
    _add_occurred_at(registry_qualify)
    _set_handler(registry_qualify, _executor_registry_qualify)

    registry_prepare_enable = executor_registry_commands.add_parser(
        "prepare-enable"
    )
    registry_prepare_enable.add_argument("--executor-id", required=True)
    _set_handler(
        registry_prepare_enable,
        _executor_registry_prepare_enable,
    )

    registry_enable = executor_registry_commands.add_parser("enable")
    registry_enable.add_argument("--executor-id", required=True)
    registry_enable.add_argument(
        "--authorization-decision-id",
        required=True,
    )
    registry_enable.add_argument("--actor", required=True)
    _add_occurred_at(registry_enable)
    _set_handler(registry_enable, _executor_registry_enable)

    registry_prepare_revoke = executor_registry_commands.add_parser(
        "prepare-revoke"
    )
    registry_prepare_revoke.add_argument("--executor-id", required=True)
    registry_prepare_revoke.add_argument("--reason", required=True)
    _set_handler(
        registry_prepare_revoke,
        _executor_registry_prepare_revoke,
    )

    registry_revoke = executor_registry_commands.add_parser("revoke")
    registry_revoke.add_argument("--executor-id", required=True)
    registry_revoke.add_argument("--reason", required=True)
    registry_revoke.add_argument(
        "--authorization-decision-id",
        required=True,
    )
    registry_revoke.add_argument("--actor", required=True)
    _add_occurred_at(registry_revoke)
    _set_handler(registry_revoke, _executor_registry_revoke)

    registry_get = executor_registry_commands.add_parser("get")
    registry_get.add_argument("--executor-id", required=True)
    _set_handler(registry_get, _executor_registry_get)

    registry_verify = executor_registry_commands.add_parser("verify")
    registry_verify.add_argument("--executor-id", required=True)
    _set_handler(registry_verify, _executor_registry_verify)

    registry_attest = executor_registry_commands.add_parser("attest")
    registry_attest.add_argument("--executor-id", required=True)
    registry_attest.add_argument("--implementation-version", required=True)
    registry_attest.add_argument("--implementation-digest", required=True)
    registry_attest.add_argument("--sandbox-profile", required=True)
    registry_attest.add_argument(
        "--requires-network",
        action="store_true",
    )
    _set_handler(registry_attest, _executor_registry_attest)

    trust = top.add_parser("trust", help="manage default-deny policy and decisions")
''',
        "executor registry parser",
    )

    forbidden = (
        "C3AdoptionExecutionWorker",
        'executor_registry_commands.add_parser("worker")',
        'executor_registry_commands.add_parser("process")',
        'executor_registry_commands.add_parser("execute")',
        'executor_registry_commands.add_parser("run")',
        'executor_registry_commands.add_parser("install")',
        'executor_registry_commands.add_parser("deploy")',
    )
    present = [item for item in forbidden if item in source]
    if present:
        raise SystemExit(
            f"bounded registry CLI patch exposed forbidden execution paths: {present}"
        )
    if source.count("def _executor_registry_") != 13:
        raise SystemExit("bounded registry CLI patch did not create 13 handlers")
    if source.count('        "executor-registry",\n') != 1:
        raise SystemExit("bounded registry CLI patch did not create one command")

    PATH.write_text(source, encoding="utf-8")
    print("patched exact-byte, non-executing C3 executor registry CLI")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
