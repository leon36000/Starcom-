from __future__ import annotations

from pathlib import Path


PATH = Path("/tmp/starcom-c3-execution/adoption_execution.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"execution hardening refused for {label}: expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def main() -> int:
    source = PATH.read_text(encoding="utf-8")
    source = replace_once(
        source,
        '''        if status is C3AdoptionExecutionStatus.RUNNING:\n            if current.status not in {\n                C3AdoptionExecutionStatus.REQUESTED_NOT_EXECUTED,\n                C3AdoptionExecutionStatus.RUNNING,\n            }:\n                raise StateTransitionError("illegal C3 execution transition")\n        elif current.status is not C3AdoptionExecutionStatus.RUNNING:\n            raise StateTransitionError("terminal execution requires RUNNING")\n''',
        '''        if status is C3AdoptionExecutionStatus.RUNNING:\n            if current.status not in {\n                C3AdoptionExecutionStatus.REQUESTED_NOT_EXECUTED,\n                C3AdoptionExecutionStatus.RUNNING,\n            }:\n                raise StateTransitionError("illegal C3 execution transition")\n        elif status is C3AdoptionExecutionStatus.FAILED_NO_EFFECT:\n            if current.status not in {\n                C3AdoptionExecutionStatus.REQUESTED_NOT_EXECUTED,\n                C3AdoptionExecutionStatus.RUNNING,\n            }:\n                raise StateTransitionError("illegal no-effect failure transition")\n        elif current.status is not C3AdoptionExecutionStatus.RUNNING:\n            raise StateTransitionError("terminal execution requires RUNNING")\n''',
        "direct no-effect failure transition",
    )
    source = replace_once(
        source,
        '''                if status is C3AdoptionExecutionStatus.RUNNING:\n                    if prior not in {\n                        C3AdoptionExecutionStatus.REQUESTED_NOT_EXECUTED,\n                        C3AdoptionExecutionStatus.RUNNING,\n                    }:\n                        defects.append(f"C3_EXECUTION_RUNNING_PREDECESSOR_INVALID:{sequence}")\n                elif prior is not C3AdoptionExecutionStatus.RUNNING:\n                    defects.append(f"C3_EXECUTION_TERMINAL_PREDECESSOR_INVALID:{sequence}")\n''',
        '''                if status is C3AdoptionExecutionStatus.RUNNING:\n                    if prior not in {\n                        C3AdoptionExecutionStatus.REQUESTED_NOT_EXECUTED,\n                        C3AdoptionExecutionStatus.RUNNING,\n                    }:\n                        defects.append(f"C3_EXECUTION_RUNNING_PREDECESSOR_INVALID:{sequence}")\n                elif status is C3AdoptionExecutionStatus.FAILED_NO_EFFECT:\n                    if prior not in {\n                        C3AdoptionExecutionStatus.REQUESTED_NOT_EXECUTED,\n                        C3AdoptionExecutionStatus.RUNNING,\n                    }:\n                        defects.append(f"C3_EXECUTION_NO_EFFECT_PREDECESSOR_INVALID:{sequence}")\n                elif prior is not C3AdoptionExecutionStatus.RUNNING:\n                    defects.append(f"C3_EXECUTION_TERMINAL_PREDECESSOR_INVALID:{sequence}")\n''',
        "verifier no-effect predecessor",
    )
    PATH.write_text(source, encoding="utf-8")
    print("hardened pre-effect failures to terminal FAILED_NO_EFFECT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
