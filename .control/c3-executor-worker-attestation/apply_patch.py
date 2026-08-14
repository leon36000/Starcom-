from __future__ import annotations

from pathlib import Path


PRODUCTION = Path("src/starcom/adoption_execution.py")
EXECUTION_TESTS = Path("tests/test_adoption_execution.py")
HARDENING_TESTS = Path("tests/test_adoption_execution_hardening.py")
ATTESTATION_TESTS = Path("tests/test_executor_worker_attestation.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"worker attestation patch refused for {label}: expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def patch_production() -> None:
    source = PRODUCTION.read_text(encoding="utf-8")
    source = replace_once(
        source,
        "from .errors import (\n",
        "from .executor_registry import C3ExecutorRegistry\nfrom .errors import (\n",
        "executor registry import",
    )
    source = replace_once(
        source,
        '''class C3AdoptionExecutor(Protocol):\n    executor_id: str\n\n    def validate''',
        '''class C3AdoptionExecutor(Protocol):\n    executor_id: str\n    implementation_version: str\n    implementation_digest: str\n\n    def validate''',
        "executor runtime identity protocol",
    )
    source = replace_once(
        source,
        '''class DisabledC3AdoptionExecutor:\n    executor_id = "disabled"\n\n    def validate''',
        '''class DisabledC3AdoptionExecutor:\n    executor_id = "disabled"\n    implementation_version = "0.0.0-disabled"\n    implementation_digest = "0" * 64\n\n    def validate''',
        "disabled executor attestation fields",
    )
    source = replace_once(
        source,
        '''    def __init__(\n        self,\n        service: C3AdoptionExecutionService,\n        outbox: DurableOutbox,\n        executor: C3AdoptionExecutor | None = None,\n    ) -> None:\n        self.service = service\n        self.outbox = outbox\n        self.executor = executor or DisabledC3AdoptionExecutor()\n''',
        '''    def __init__(\n        self,\n        service: C3AdoptionExecutionService,\n        outbox: DurableOutbox,\n        registry: C3ExecutorRegistry,\n        executor: C3AdoptionExecutor | None = None,\n    ) -> None:\n        self.service = service\n        self.outbox = outbox\n        self.registry = registry\n        self.executor = executor or DisabledC3AdoptionExecutor()\n''',
        "worker constructor registry authority",
    )
    identity_block = '''        if request.executor_id != self.executor.executor_id:\n            return self._terminalize(\n                effect,\n                request,\n                worker_id=worker_id,\n                status=C3AdoptionExecutionStatus.FAILED_NO_EFFECT,\n                effect_started=False,\n                execution_receipt={\n                    "phase": "executor-selection",\n                    "expected_executor_id": request.executor_id,\n                    "observed_executor_id": self.executor.executor_id,\n                    "idempotency_key": request.idempotency_key,\n                },\n                rollback_receipt=None,\n                error="executor identity mismatch",\n                now=now,\n            )\n        request = self.service.append_transition(\n'''
    attested_block = '''        if request.executor_id != self.executor.executor_id:\n            return self._terminalize(\n                effect,\n                request,\n                worker_id=worker_id,\n                status=C3AdoptionExecutionStatus.FAILED_NO_EFFECT,\n                effect_started=False,\n                execution_receipt={\n                    "phase": "executor-selection",\n                    "expected_executor_id": request.executor_id,\n                    "observed_executor_id": self.executor.executor_id,\n                    "idempotency_key": request.idempotency_key,\n                },\n                rollback_receipt=None,\n                error="executor identity mismatch",\n                now=now,\n            )\n        sandbox_profile = str(request.execution_plan["sandbox_profile"])\n        requires_network = bool(request.execution_plan["requires_network"])\n        try:\n            self.registry.attest(\n                request.executor_id,\n                implementation_version=self.executor.implementation_version,\n                implementation_digest=self.executor.implementation_digest,\n                sandbox_profile=sandbox_profile,\n                requires_network=requires_network,\n            )\n        except (\n            IntegrityError,\n            NotFoundError,\n            StateTransitionError,\n            ValidationError,\n        ) as exc:\n            return self._terminalize(\n                effect,\n                request,\n                worker_id=worker_id,\n                status=C3AdoptionExecutionStatus.FAILED_NO_EFFECT,\n                effect_started=False,\n                execution_receipt={\n                    "phase": "executor-registry-attestation",\n                    "requested_executor_id": request.executor_id,\n                    "observed_executor_id": self.executor.executor_id,\n                    "implementation_version": self.executor.implementation_version,\n                    "implementation_digest": self.executor.implementation_digest,\n                    "sandbox_profile": sandbox_profile,\n                    "requires_network": requires_network,\n                    "idempotency_key": request.idempotency_key,\n                    "error_type": type(exc).__name__,\n                    "message": str(exc)[:4096],\n                },\n                rollback_receipt=None,\n                error=exc,\n                now=now,\n            )\n        request = self.service.append_transition(\n'''
    source = replace_once(
        source,
        identity_block,
        attested_block,
        "pre-effect registry attestation",
    )
    PRODUCTION.write_text(source, encoding="utf-8")


def patch_execution_tests() -> None:
    source = EXECUTION_TESTS.read_text(encoding="utf-8")
    source = replace_once(
        source,
        '''from starcom.errors import AuthorizationError, ConflictError, IntegrityError\n''',
        '''from starcom.errors import (\n    AuthorizationError,\n    ConflictError,\n    IntegrityError,\n    StateTransitionError,\n)\n''',
        "execution test StateTransitionError import",
    )
    source = replace_once(
        source,
        '''RESTORED_STATE = "3" * 64\n\n\nclass DeterministicExecutor:\n    executor_id = "deterministic-test-executor"\n''',
        '''RESTORED_STATE = "3" * 64\nIMPLEMENTATION_VERSION = "1.0.0"\nIMPLEMENTATION_DIGEST = "5" * 64\n\n\nclass DeterministicExecutor:\n    executor_id = "deterministic-test-executor"\n    implementation_version = IMPLEMENTATION_VERSION\n    implementation_digest = IMPLEMENTATION_DIGEST\n''',
        "deterministic executor attestation identity",
    )
    marker = "\n\nclass C3AdoptionExecutionTests(unittest.TestCase):\n"
    replace_once(source, marker, marker, "execution test class marker")
    fake_registry = '''\n\nclass TestExecutionRegistry:\n    def attest(\n        self,\n        executor_id: str,\n        *,\n        implementation_version: str,\n        implementation_digest: str,\n        sandbox_profile: str,\n        requires_network: bool,\n    ) -> object:\n        if executor_id != DeterministicExecutor.executor_id:\n            raise StateTransitionError("test executor is not enabled")\n        if implementation_version != IMPLEMENTATION_VERSION:\n            raise StateTransitionError("test executor version mismatch")\n        if implementation_digest != IMPLEMENTATION_DIGEST:\n            raise StateTransitionError("test executor digest mismatch")\n        if sandbox_profile != "starcom-c3-default-deny-v1":\n            raise StateTransitionError("test executor sandbox mismatch")\n        if requires_network:\n            raise StateTransitionError("test executor network denied")\n        return object()\n'''
    source = source.replace(marker, fake_registry + marker, 1)
    source = replace_once(
        source,
        '''        self.service = C3AdoptionExecutionService(\n            self.runtime.database,\n            self.runtime.ledger,\n            self.runtime.trust,\n            self.runtime.continuity,\n            self.runtime.adoption,\n            self.outbox,\n        )\n''',
        '''        self.service = C3AdoptionExecutionService(\n            self.runtime.database,\n            self.runtime.ledger,\n            self.runtime.trust,\n            self.runtime.continuity,\n            self.runtime.adoption,\n            self.outbox,\n        )\n        self.registry = TestExecutionRegistry()\n''',
        "execution test fake registry setup",
    )
    source = source.replace(
        "C3AdoptionExecutionWorker(self.service, self.outbox, executor)",
        "C3AdoptionExecutionWorker(\n            self.service, self.outbox, self.registry, executor\n        )",
    )
    source = source.replace(
        "C3AdoptionExecutionWorker(self.service, self.outbox)",
        "C3AdoptionExecutionWorker(self.service, self.outbox, self.registry)",
    )
    if "C3AdoptionExecutionWorker(self.service, self.outbox, executor)" in source:
        raise SystemExit("execution test worker call remained unpatched")
    if source.count("self.registry = TestExecutionRegistry()") != 1:
        raise SystemExit("execution test fake registry setup count mismatch")
    EXECUTION_TESTS.write_text(source, encoding="utf-8")


def patch_hardening_tests() -> None:
    source = HARDENING_TESTS.read_text(encoding="utf-8")
    source = replace_once(
        source,
        '''        self.service = C3AdoptionExecutionService(\n            self.runtime.database,\n            self.runtime.ledger,\n            self.runtime.trust,\n            self.runtime.continuity,\n            self.runtime.adoption,\n            self.outbox,\n        )\n''',
        '''        self.service = C3AdoptionExecutionService(\n            self.runtime.database,\n            self.runtime.ledger,\n            self.runtime.trust,\n            self.runtime.continuity,\n            self.runtime.adoption,\n            self.outbox,\n        )\n        self.registry = execution_fixture.TestExecutionRegistry()\n''',
        "hardening test fake registry setup",
    )
    source = source.replace(
        "C3AdoptionExecutionWorker(self.service, self.outbox, executor)",
        "C3AdoptionExecutionWorker(\n            self.service, self.outbox, self.registry, executor\n        )",
    )
    if source.count("self.registry = execution_fixture.TestExecutionRegistry()") != 1:
        raise SystemExit("hardening test fake registry setup count mismatch")
    HARDENING_TESTS.write_text(source, encoding="utf-8")


def patch_attestation_tests() -> None:
    source = ATTESTATION_TESTS.read_text(encoding="utf-8")
    source = replace_once(
        source,
        '''W6 = "2026-08-14T16:06:00.000000Z"\nIMPLEMENTATION_VERSION''',
        '''W6 = "2026-08-14T16:06:00.000000Z"\nW7 = "2026-08-14T16:07:00.000000Z"\nW8 = "2026-08-14T16:08:00.000000Z"\nIMPLEMENTATION_VERSION''',
        "attestation test post-admission times",
    )
    source = replace_once(
        source,
        '''            occurred_at=W5,\n        )\n        executor = AttestedExecutor("success")\n        self.assert_no_effect_failure(self.process(requested, executor), executor)\n\n    def test_wrong_implementation_version''',
        '''            occurred_at=W7,\n        )\n        executor = AttestedExecutor("success")\n        self.assert_no_effect_failure(self.process(requested, executor), executor)\n\n    def test_wrong_implementation_version''',
        "revocation after admission timestamp",
    )
    source = source.replace(
        'return worker.process_next(worker_id="worker-attested", now=W6)',
        'return worker.process_next(worker_id="worker-attested", now=W8)',
        1,
    )
    ATTESTATION_TESTS.write_text(source, encoding="utf-8")


def main() -> int:
    patch_production()
    patch_execution_tests()
    patch_hardening_tests()
    patch_attestation_tests()
    print("patched registry-attested C3 worker and adapted focused fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
