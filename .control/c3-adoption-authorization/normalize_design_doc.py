from __future__ import annotations

from pathlib import Path


PATH = Path("docs/superpowers/specs/2026-08-14-c3-adoption-authorization-design.md")
EXPECTED = {
    3: "**Date:** 2026-08-14  ",
    4: "**Issue:** #42  ",
}


def main() -> int:
    lines = PATH.read_text(encoding="utf-8").splitlines()
    if len(lines) < max(EXPECTED):
        raise SystemExit("design normalization refused: document is unexpectedly short")
    for line_number, expected in EXPECTED.items():
        observed = lines[line_number - 1]
        if observed != expected:
            raise SystemExit(
                "design normalization refused: "
                f"line {line_number} expected {expected!r}, found {observed!r}"
            )
        lines[line_number - 1] = expected.rstrip()
    PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("normalized exactly two trailing-whitespace metadata lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
