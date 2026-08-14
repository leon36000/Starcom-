from __future__ import annotations

from pathlib import Path


PATH = Path("src/starcom/research.py")


def main() -> int:
    source = PATH.read_text(encoding="utf-8")
    old = '''            for observation in observations:\n                observation_id = str(observation["observation_id"])\n                observation_data: dict[str, Any] | None = None\n'''
    new = '''            for observation in observations:\n                observation_id = str(observation["observation_id"])\n                if outcome is not None and outcome is not ReceiptOutcome.SUCCESS:\n                    defects.append(f"NON_SUCCESS_OBSERVATION_PRESENT:{observation_id}")\n                observation_data: dict[str, Any] | None = None\n'''
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            "bounded research verifier patch refused: "
            f"expected one observation-loop target, found {count}"
        )
    PATH.write_text(source.replace(old, new, 1), encoding="utf-8")
    print("research verifier now rejects observations on non-success attempts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
