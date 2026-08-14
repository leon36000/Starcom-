from __future__ import annotations

from pathlib import Path


EXECUTION_PATH = Path("tests/test_adoption_execution.py")
DURABLE_PATH = Path("tests/test_durable_transaction.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"execution test patch refused for {label}: expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def patch_execution_tests() -> None:
    source = EXECUTION_PATH.read_text(encoding="utf-8")
    source = replace_once(
        source,
        "EffectStatus.IN_PROGRESS",
        "EffectStatus.LEASED",
        "real durable leased status",
    )
    source = replace_once(
        source,
        '''        recovered = self.outbox.recover_expired(now=E4, actor="lease-reaper")
        self.assertEqual([item.effect_id for item in recovered], [requested.outbox_effect_id])
''',
        '''        recovered = self.outbox.recover_expired(now=E4)
        self.assertEqual(recovered, 1)
''',
        "real durable lease recovery result",
    )
    EXECUTION_PATH.write_text(source, encoding="utf-8")


def patch_durable_tests() -> None:
    source = DURABLE_PATH.read_text(encoding="utf-8")
    source = replace_once(
        source,
        '''        self.assertEqual(
            self.ledger.read("durable:effect:effect-transaction-rollback"),
            (),
        )
''',
        '''        ledger_count = int(
            self.database.connection.execute(
                "SELECT COUNT(*) FROM ledger_events WHERE stream_id = ?",
                ("durable:effect:effect-transaction-rollback",),
            ).fetchone()[0]
        )
        self.assertEqual(ledger_count, 0)
''',
        "rolled-back ledger event count",
    )
    source = replace_once(
        source,
        '''        self.assertEqual(
            len(self.ledger.read("durable:effect:effect-transaction-idempotent")),
            1,
        )
''',
        '''        ledger_count = int(
            self.database.connection.execute(
                "SELECT COUNT(*) FROM ledger_events WHERE stream_id = ?",
                ("durable:effect:effect-transaction-idempotent",),
            ).fetchone()[0]
        )
        self.assertEqual(ledger_count, 1)
''',
        "idempotent ledger event count",
    )
    DURABLE_PATH.write_text(source, encoding="utf-8")


def main() -> int:
    patch_execution_tests()
    patch_durable_tests()
    print("aligned C3 execution tests with authoritative durable and ledger APIs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
