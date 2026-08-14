from __future__ import annotations

from pathlib import Path


PRODUCTION = Path("src/starcom/adoption_execution.py")
EXECUTION_TESTS = Path("tests/test_adoption_execution.py")
HARDENING_TESTS = Path("tests/test_adoption_execution_hardening.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"worker attestation patch refused for {label}: "
            f"expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def patch_production() -> None:
    source = PRODUCTION.read_text(encoding="utf-8")
    source = replace_once(
        source,
        "from .ledger import EventLedger\n",
        "from .executor_registry import C3ExecutorRegistry\n"
        "from .ledger import EventLedger\n",
        "executor registry import",
    )
    source = replace_once(
        source,
        '''class C3AdoptionExecutor(Protocol):
    executor_id: str

    def validate''',
        '''class C3AdoptionExecutor(Protocol):
    executor_id: str
    implementation_version: str
    implementation_digest: str

    def validate''',
        "executor runtime identity protocol",
    )
    source = replace_once(
        source,
        '''class DisabledC3AdoptionExecutor:
    executor_id = "disabled"

    def validate''',
        '''class DisabledC3AdoptionExecutor:
    executor_id = "disabled"
    implementation_version = "0.0.0-disabled"
    implementation_digest = "0" * 64

    def validate''',
        "disabled executor runtime identity",
    )
    source = replace_once(
        source,
        '''    def __init__(
        self,
        service: C3AdoptionExecutionService,
        outbox: DurableOutbox,
        executor: C3AdoptionExecutor | None = None,
    ) -> None:
        self.service = service
        self.outbox = outbox
        self.executor = executor or DisabledC3AdoptionExecutor()
''',
        '''    def __init__(
        self,
        service: C3AdoptionExecutionService,
        outbox: DurableOutbox,
        registry: C3ExecutorRegistry,
        executor: C3AdoptionExecutor | None = None,
    ) -> None:
        self.service = service
        self.outbox = outbox
        self.registry = registry
        self.executor = executor or DisabledC3AdoptionExecutor()
''',
        "worker registry dependency",
    )
    source = replace_once(
        source,
        '''    def _terminalize(
        self,
        lease: EffectLease,
''',
        '''    def _terminalize_gate_failure(
        self,
        lease: EffectLease,
        request: C3AdoptionExecutionRecord,
        *,
        worker_id: str,
        phase: str,
        receipt: Mapping[str, Any],
        error: object,
        rollback_uncertain_effect: bool,
        now: str,
    ) -> C3AdoptionExecutionRecord:
        if request.status is not C3AdoptionExecutionStatus.RUNNING:
            return self._terminalize(
                lease,
                request,
                worker_id=worker_id,
                status=C3AdoptionExecutionStatus.FAILED_NO_EFFECT,
                effect_started=False,
                execution_receipt=dict(receipt),
                rollback_receipt=None,
                error=error,
                now=now,
            )

        execution_receipt = {
            **dict(receipt),
            "phase": f"{phase}-recovered-running-uncertain",
            "prior_effect_state": "UNCERTAIN",
        }
        if not rollback_uncertain_effect:
            rollback_receipt = {
                "executor_id": request.executor_id,
                "idempotency_key": request.idempotency_key,
                "succeeded": False,
                "rollback_attempted": False,
                "reason": "correct rollback authority unavailable",
            }
            return self._terminalize(
                lease,
                request,
                worker_id=worker_id,
                status=C3AdoptionExecutionStatus.ROLLBACK_FAILED,
                effect_started=True,
                execution_receipt=execution_receipt,
                rollback_receipt=rollback_receipt,
                error=error,
                now=now,
            )

        try:
            rollback = self.executor.rollback(
                request,
                None,
                f"registry gate failed during recovered RUNNING state: {error}",
            )
        except Exception as rollback_error:
            rollback = C3RollbackResult(
                succeeded=False,
                restored_state_digest=None,
                receipt=self._exception_receipt(
                    request,
                    "registry-gate-rollback-exception",
                    rollback_error,
                ),
                error=str(rollback_error),
            )
        if rollback.restored_state_digest is not None:
            self.service._digest(
                rollback.restored_state_digest,
                "restored_state_digest",
            )
        rollback_receipt = {
            "executor_id": request.executor_id,
            "idempotency_key": request.idempotency_key,
            "succeeded": rollback.succeeded,
            "restored_state_digest": rollback.restored_state_digest,
            "adapter_receipt": dict(rollback.receipt),
        }
        return self._terminalize(
            lease,
            request,
            worker_id=worker_id,
            status=(
                C3AdoptionExecutionStatus.FAILED_ROLLED_BACK
                if rollback.succeeded
                else C3AdoptionExecutionStatus.ROLLBACK_FAILED
            ),
            effect_started=True,
            execution_receipt=execution_receipt,
            rollback_receipt=rollback_receipt,
            error=rollback.error or error,
            now=now,
        )

    def _terminalize(
        self,
        lease: EffectLease,
''',
        "recovered-running gate failure handler",
    )
    source = replace_once(
        source,
        '''        verification = self.service.verify_execution(execution_id)
        if not verification.ok:
            return self._terminalize(
                lease,
                request,
                worker_id=worker_id,
                status=C3AdoptionExecutionStatus.FAILED_NO_EFFECT,
                effect_started=False,
                execution_receipt={
                    "phase": "pre-effect-verification",
                    "defects": list(verification.defects),
                    "idempotency_key": request.idempotency_key,
                },
                rollback_receipt=None,
                error="pre-effect execution verification failed",
                now=now,
            )
        if request.executor_id != self.executor.executor_id:
            return self._terminalize(
                lease,
                request,
                worker_id=worker_id,
                status=C3AdoptionExecutionStatus.FAILED_NO_EFFECT,
                effect_started=False,
                execution_receipt={
                    "phase": "executor-selection",
                    "expected_executor_id": request.executor_id,
                    "observed_executor_id": self.executor.executor_id,
                    "idempotency_key": request.idempotency_key,
                },
                rollback_receipt=None,
                error="executor identity mismatch",
                now=now,
            )
        request = self.service.append_transition(
''',
        '''        verification = self.service.verify_execution(execution_id)
        if not verification.ok:
            return self._terminalize_gate_failure(
                lease,
                request,
                worker_id=worker_id,
                phase="pre-effect-verification",
                receipt={
                    "phase": "pre-effect-verification",
                    "defects": list(verification.defects),
                    "idempotency_key": request.idempotency_key,
                },
                error="pre-effect execution verification failed",
                rollback_uncertain_effect=False,
                now=now,
            )
        if request.executor_id != self.executor.executor_id:
            return self._terminalize_gate_failure(
                lease,
                request,
                worker_id=worker_id,
                phase="executor-selection",
                receipt={
                    "phase": "executor-selection",
                    "expected_executor_id": request.executor_id,
                    "observed_executor_id": self.executor.executor_id,
                    "idempotency_key": request.idempotency_key,
                },
                error="executor identity mismatch",
                rollback_uncertain_effect=False,
                now=now,
            )
        sandbox_profile = str(request.execution_plan["sandbox_profile"])
        requires_network = bool(request.execution_plan["requires_network"])
        try:
            self.registry.attest(
                request.executor_id,
                implementation_version=self.executor.implementation_version,
                implementation_digest=self.executor.implementation_digest,
                sandbox_profile=sandbox_profile,
                requires_network=requires_network,
            )
        except (
            IntegrityError,
            NotFoundError,
            StateTransitionError,
            ValidationError,
        ) as registry_error:
            return self._terminalize_gate_failure(
                lease,
                request,
                worker_id=worker_id,
                phase="executor-registry-attestation",
                receipt={
                    "phase": "executor-registry-attestation",
                    "requested_executor_id": request.executor_id,
                    "observed_executor_id": self.executor.executor_id,
                    "implementation_version": self.executor.implementation_version,
                    "implementation_digest": self.executor.implementation_digest,
                    "sandbox_profile": sandbox_profile,
                    "requires_network": requires_network,
                    "idempotency_key": request.idempotency_key,
                    "error_type": type(registry_error).__name__,
                    "message": str(registry_error)[:4096],
                },
                error=registry_error,
                rollback_uncertain_effect=True,
                now=now,
            )
        request = self.service.append_transition(
''',
        "pre-effect registry attestation gate",
    )

    if source.count("registry: C3ExecutorRegistry") != 1:
        raise SystemExit("worker attestation patch did not add one registry dependency")
    if source.count("self.registry.attest(") != 1:
        raise SystemExit("worker attestation patch did not add one fresh attestation")
    PRODUCTION.write_text(source, encoding="utf-8")


def patch_execution_tests() -> None:
    source = EXECUTION_TESTS.read_text(encoding="utf-8")
    source = replace_once(
        source,
        "from starcom.errors import AuthorizationError, ConflictError, IntegrityError\n",
        '''from starcom.errors import (
    AuthorizationError,
    ConflictError,
    IntegrityError,
    StateTransitionError,
)
''',
        "execution fixture StateTransitionError import",
    )
    source = replace_once(
        source,
        '''RESTORED_STATE = "3" * 64


def copy_database''',
        '''RESTORED_STATE = "3" * 64
IMPLEMENTATION_VERSION = "1.0.0"
IMPLEMENTATION_DIGEST = "5" * 64


def copy_database''',
        "execution fixture implementation identity constants",
    )
    source = replace_once(
        source,
        '''class DeterministicExecutor:
    executor_id = "deterministic-test-executor"

    def __init__''',
        '''class DeterministicExecutor:
    executor_id = "deterministic-test-executor"
    implementation_version = IMPLEMENTATION_VERSION
    implementation_digest = IMPLEMENTATION_DIGEST

    def __init__''',
        "deterministic executor runtime identity",
    )
    source = replace_once(
        source,
        '''

class C3AdoptionExecutionTests(unittest.TestCase):
''',
        '''

class DeterministicEnabledRegistry:
    def attest(
        self,
        executor_id: str,
        *,
        implementation_version: str,
        implementation_digest: str,
        sandbox_profile: str,
        requires_network: bool,
    ) -> object:
        if executor_id != DeterministicExecutor.executor_id:
            raise StateTransitionError("fixture executor is not enabled")
        if implementation_version != IMPLEMENTATION_VERSION:
            raise StateTransitionError("fixture executor version mismatch")
        if implementation_digest != IMPLEMENTATION_DIGEST:
            raise StateTransitionError("fixture executor digest mismatch")
        if sandbox_profile != "starcom-c3-default-deny-v1":
            raise StateTransitionError("fixture executor sandbox mismatch")
        if requires_network:
            raise StateTransitionError("fixture executor network denied")
        return object()


class C3AdoptionExecutionTests(unittest.TestCase):
''',
        "deterministic enabled registry fixture",
    )
    source = replace_once(
        source,
        '''        self.service = C3AdoptionExecutionService(
            self.runtime.database,
            self.runtime.ledger,
            self.runtime.trust,
            self.runtime.continuity,
            self.runtime.adoption,
            self.outbox,
        )
''',
        '''        self.service = C3AdoptionExecutionService(
            self.runtime.database,
            self.runtime.ledger,
            self.runtime.trust,
            self.runtime.continuity,
            self.runtime.adoption,
            self.outbox,
        )
        self.registry = DeterministicEnabledRegistry()
''',
        "execution fixture registry setup",
    )
    source = source.replace(
        "C3AdoptionExecutionWorker(self.service, self.outbox, executor)",
        "C3AdoptionExecutionWorker(\n"
        "            self.service, self.outbox, self.registry, executor\n"
        "        )",
    )
    source = source.replace(
        "C3AdoptionExecutionWorker(self.service, self.outbox)",
        "C3AdoptionExecutionWorker(self.service, self.outbox, self.registry)",
    )
    source = replace_once(
        source,
        '''        worker = C3AdoptionExecutionWorker(
            self.service,
            self.outbox,
            DeterministicExecutor("success"),
        )
''',
        '''        worker = C3AdoptionExecutionWorker(
            self.service,
            self.outbox,
            self.registry,
            DeterministicExecutor("success"),
        )
''',
        "multiline execution worker fixture",
    )
    if "C3AdoptionExecutionWorker(self.service, self.outbox, executor)" in source:
        raise SystemExit("execution fixture retained legacy worker constructor")
    EXECUTION_TESTS.write_text(source, encoding="utf-8")


def patch_hardening_tests() -> None:
    source = HARDENING_TESTS.read_text(encoding="utf-8")
    source = replace_once(
        source,
        '''        self.service = C3AdoptionExecutionService(
            self.runtime.database,
            self.runtime.ledger,
            self.runtime.trust,
            self.runtime.continuity,
            self.runtime.adoption,
            self.outbox,
        )
''',
        '''        self.service = C3AdoptionExecutionService(
            self.runtime.database,
            self.runtime.ledger,
            self.runtime.trust,
            self.runtime.continuity,
            self.runtime.adoption,
            self.outbox,
        )
        self.registry = execution_fixture.DeterministicEnabledRegistry()
''',
        "hardening fixture registry setup",
    )
    source = source.replace(
        "C3AdoptionExecutionWorker(self.service, self.outbox, executor)",
        "C3AdoptionExecutionWorker(\n"
        "            self.service, self.outbox, self.registry, executor\n"
        "        )",
    )
    if "C3AdoptionExecutionWorker(self.service, self.outbox, executor)" in source:
        raise SystemExit("hardening fixture retained legacy worker constructor")
    HARDENING_TESTS.write_text(source, encoding="utf-8")


def main() -> int:
    patch_production()
    patch_execution_tests()
    patch_hardening_tests()
    print("patched registry-attested C3 worker and bounded execution fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
