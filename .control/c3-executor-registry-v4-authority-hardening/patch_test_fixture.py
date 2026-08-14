from __future__ import annotations

from pathlib import Path


PATH = Path("tests/test_executor_registry_hardening.py")
OLD = '''        self.assertIn(
            "C3_EXECUTOR_CONSUMPTION_MISMATCH:1",
            registration_verification.defects,
        )

        self.helper.accept_root()
'''
NEW = '''        self.assertIn(
            "C3_EXECUTOR_CONSUMPTION_MISMATCH:1",
            registration_verification.defects,
        )
        self.database.connection.execute(
            """
            UPDATE continuity_authorization_consumptions SET operation_id = ?
            WHERE decision_id = ?
            """,
            ("fake-executor", descriptor.authorization_decision_id),
        )

        self.helper.accept_root()
'''


def main() -> int:
    source = PATH.read_text(encoding="utf-8")
    count = source.count(OLD)
    if count != 1:
        raise SystemExit(
            f"fixture isolation refused: expected one target, found {count}"
        )
    PATH.write_text(source.replace(OLD, NEW, 1), encoding="utf-8")
    print("isolated registration and qualifier-root consumption attacks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
