from __future__ import annotations

from pathlib import Path


PATH = Path("tests/test_adoption.py")
OLD = '''        self.database.connection.execute(
            """
            UPDATE continuity_authorization_consumptions SET operation_id = ?
'''
NEW = '''        self.database.connection.execute(
            "DROP TRIGGER continuity_authorization_consumptions_no_update"
        )
        self.database.connection.execute(
            """
            UPDATE continuity_authorization_consumptions SET operation_id = ?
'''


def main() -> int:
    source = PATH.read_text(encoding="utf-8")
    count = source.count(OLD)
    if count != 1:
        raise SystemExit(
            f"fixture patch refused: expected one consumption tamper target, found {count}"
        )
    PATH.write_text(source.replace(OLD, NEW, 1), encoding="utf-8")
    print("patched tamper fixture without weakening immutable production triggers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
