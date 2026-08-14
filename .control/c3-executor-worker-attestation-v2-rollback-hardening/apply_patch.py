from __future__ import annotations

from pathlib import Path


PATH = Path("src/starcom/adoption_execution.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"rollback authority hardening refused for {label}: "
            f"expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def main() -> int:
    source = PATH.read_text(encoding="utf-8")
    source = replace_once(
        source,
        '''    def _terminalize_gate_failure(
        self,
        lease: EffectLease,
''',
        '''    def _registry_allows_compensating_rollback(
        self,
        request: C3AdoptionExecutionRecord,
    ) -> bool:
        try:
            verification = self.registry.verify(request.executor_id)
            if not verification.ok:
                return False
            descriptor = self.registry.get_descriptor(request.executor_id)
        except (
            IntegrityError,
            NotFoundError,
            StateTransitionError,
            ValidationError,
        ):
            return False
        return (
            request.executor_id == self.executor.executor_id
            and descriptor.implementation_version
            == self.executor.implementation_version
            and descriptor.implementation_digest
            == self.executor.implementation_digest
        )

    def _terminalize_gate_failure(
        self,
        lease: EffectLease,
''',
        "trusted compensating rollback predicate",
    )
    source = replace_once(
        source,
        '''                error=registry_error,
                rollback_uncertain_effect=True,
                now=now,
            )
''',
        '''                error=registry_error,
                rollback_uncertain_effect=(
                    self._registry_allows_compensating_rollback(request)
                ),
                now=now,
            )
''',
        "registry failure rollback authority",
    )
    if source.count("def _registry_allows_compensating_rollback(") != 1:
        raise SystemExit("rollback authority helper count mismatch")
    if source.count("self._registry_allows_compensating_rollback(request)") != 1:
        raise SystemExit("rollback authority call count mismatch")
    PATH.write_text(source, encoding="utf-8")
    print("restricted compensating rollback to clean matching executor material")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
