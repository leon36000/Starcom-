from __future__ import annotations

from pathlib import Path


PATH = Path("/tmp/starcom-c3-adoption-cli/apply_patch.py")
OLD = "'''def _c3_decision_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\\n"
NEW = "'''def _c3_decision_verify(\\n    runtime: Runtime, args: argparse.Namespace\\n) -> tuple[Any, int]:\\n"


def main() -> int:
    source = PATH.read_text(encoding="utf-8")
    count = source.count(OLD)
    if count != 2:
        raise SystemExit(
            f"patch normalization refused: expected two handler anchors, found {count}"
        )
    PATH.write_text(source.replace(OLD, NEW), encoding="utf-8")
    print("normalized exactly two multiline C3 decision handler anchors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
