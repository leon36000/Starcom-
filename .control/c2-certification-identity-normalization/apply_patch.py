from __future__ import annotations

import argparse
from pathlib import Path


TEST_PATH = Path("tests/test_certification.py")
SERVICE_PATH = Path("src/starcom/certification.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"bounded certification normalization refused for {label}: "
            f"expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def patch_test() -> None:
    source = TEST_PATH.read_text(encoding="utf-8")
    source = replace_once(
        source,
        '            certifier_identity="collector",\n',
        '            certifier_identity=" collector ",\n',
        "whitespace-equivalent certifier attack",
    )
    TEST_PATH.write_text(source, encoding="utf-8")
    print("test now treats whitespace-padded collector identity as non-independent")


def patch_production() -> None:
    source = SERVICE_PATH.read_text(encoding="utf-8")
    source = replace_once(
        source,
        '''        disallowed = {recollection.started_by}\n        disallowed.update(str(member["recorded_by"]) for member in snapshot.members)\n        if certifier_identity in disallowed:\n''',
        '''        disallowed = {recollection.started_by.strip()}\n        disallowed.update(\n            str(member["recorded_by"]).strip() for member in snapshot.members\n        )\n        if certifier_identity.strip() in disallowed:\n''',
        "admission identity normalization",
    )
    source = replace_once(
        source,
        '''        if recollection is not None:\n            represented_actors.add(recollection.started_by)\n        if record.certifier_identity in represented_actors:\n            defects.append("C2_CERT_INDEPENDENCE_VIOLATION")\n''',
        '''        normalized_actors = {actor.strip() for actor in represented_actors}\n        if recollection is not None:\n            normalized_actors.add(recollection.started_by.strip())\n        if record.certifier_identity.strip() in normalized_actors:\n            defects.append("C2_CERT_INDEPENDENCE_VIOLATION")\n''',
        "verification identity normalization",
    )
    SERVICE_PATH.write_text(source, encoding="utf-8")
    print("certifier independence comparisons now normalize surrounding whitespace")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("test", "production"))
    args = parser.parse_args()
    if args.mode == "test":
        patch_test()
    else:
        patch_production()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
