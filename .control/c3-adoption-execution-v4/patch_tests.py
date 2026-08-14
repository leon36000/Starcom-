from __future__ import annotations

from pathlib import Path


PATH = Path("tests/test_adoption_execution.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"execution test patch refused for {label}: expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def main() -> int:
    source = PATH.read_text(encoding="utf-8")
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
    PATH.write_text(source, encoding="utf-8")
    print("aligned C3 execution tests with the authoritative durable outbox API")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
