from __future__ import annotations

from pathlib import Path


PATH = Path("/tmp/starcom-c2-gate/apply_patch.py")


def replace_exact(source: str, old: str, new: str, *, expected: int, label: str) -> str:
    count = source.count(old)
    if count != expected:
        raise SystemExit(
            f"control normalization refused for {label}: expected {expected}, found {count}"
        )
    return source.replace(old, new)


def main() -> int:
    source = PATH.read_text(encoding="utf-8")
    source = replace_exact(
        source,
        "from .continuity import ContinuityService\\nfrom .continuity_types import IncidentStatus",
        "from .continuity import ContinuityService, IncidentStatus",
        expected=1,
        label="IncidentStatus import",
    )
    source = replace_exact(
        source,
        "incident.status is not IncidentStatus.RECOVERY_PUBLISHED_RECOLLECT_REQUIRED",
        "incident.status != IncidentStatus.RECOVERY_PUBLISHED_RECOLLECT_REQUIRED",
        expected=2,
        label="IncidentStatus comparison",
    )
    PATH.write_text(source, encoding="utf-8")
    print("normalized bounded C2 patch to ContinuityService IncidentStatus authority")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
