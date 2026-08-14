from __future__ import annotations

from pathlib import Path


PATH = Path("/tmp/starcom-c3-execution-v4/adoption_execution.py")


def main() -> int:
    source = PATH.read_text(encoding="utf-8")
    method_start = source.index("    def request_execution(\n")
    auth_start = source.index(
        "        decision = self._assert_authorization(\n",
        method_start,
    )
    existing_start = source.index(
        "        existing = self.database.connection.execute(\n",
        auth_start,
    )
    competitor_start = source.index(
        "        competitor = self.database.connection.execute(\n",
        existing_start,
    )
    auth_block = source[auth_start:existing_start]
    existing_block = source[existing_start:competitor_start]
    if auth_block.count("self._assert_authorization(") != 1:
        raise SystemExit(
            "execution conflict hardening refused: authorization block changed"
        )
    if existing_block.count("if existing is not None:") != 1:
        raise SystemExit(
            "execution conflict hardening refused: existing-material block changed"
        )
    if "return self.get_execution(preparation.execution_id)" not in existing_block:
        raise SystemExit(
            "execution conflict hardening refused: idempotent replay return missing"
        )
    hardened = (
        source[:auth_start]
        + existing_block
        + auth_block
        + source[competitor_start:]
    )
    if hardened.count(
        "execution_id was reused with different execution material"
    ) != 1:
        raise SystemExit(
            "execution conflict hardening refused: conflict authority count mismatch"
        )
    PATH.write_text(hardened, encoding="utf-8")
    print("moved execution identity conflict detection before authorization replay")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
