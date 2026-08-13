from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from collections.abc import Iterable, Mapping, Sequence


_INCLUDED_ROOT_FILES = {".gitignore", "AGENTS.md", "README.md", "pyproject.toml"}
_INCLUDED_DIRECTORIES = (".github", "docs/status", "docs/superpowers", "scripts", "src", "tests")
_EXCLUDED_PARTS = {
    ".git",
    ".worktrees",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "build",
    "dist",
    ".tmp",
    "tmp",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ManifestVerification:
    checked: int
    missing: tuple[str, ...]
    mismatched: tuple[str, ...]
    unlisted: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not (self.missing or self.mismatched or self.unlisted)


def _included(relative: Path) -> bool:
    value = relative.as_posix()
    if value in _INCLUDED_ROOT_FILES:
        return True
    return any(value == prefix or value.startswith(f"{prefix}/") for prefix in _INCLUDED_DIRECTORIES)


def iter_manifest_files(root: str | Path) -> Iterable[Path]:
    root_path = Path(root).resolve()
    for path in sorted(root_path.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root_path)
        if any(part in _EXCLUDED_PARTS for part in relative.parts):
            continue
        if relative.as_posix() == "MANIFEST.sha256":
            continue
        if _included(relative):
            yield path


def _digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def build_manifest(root: str | Path) -> dict[str, str]:
    root_path = Path(root).resolve()
    return {
        path.relative_to(root_path).as_posix(): _digest(path)
        for path in iter_manifest_files(root_path)
    }


def render_manifest(entries: Mapping[str, str]) -> str:
    return "".join(f"{digest}  {path}\n" for path, digest in sorted(entries.items()))


def parse_manifest(path: str | Path) -> dict[str, str]:
    manifest_path = Path(path)
    entries: dict[str, str] = {}
    for line_number, raw in enumerate(manifest_path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        if "  " not in raw:
            raise ValueError(f"invalid manifest line {line_number}")
        digest, relative = raw.split("  ", 1)
        if not _SHA256.fullmatch(digest) or not relative or relative.startswith("/"):
            raise ValueError(f"invalid manifest line {line_number}")
        if relative in entries:
            raise ValueError(f"duplicate manifest path {relative}")
        entries[relative] = digest
    return entries


def verify_manifest(root: str | Path, manifest_path: str | Path) -> ManifestVerification:
    current = build_manifest(root)
    expected = parse_manifest(manifest_path)
    missing = tuple(sorted(set(expected) - set(current)))
    unlisted = tuple(sorted(set(current) - set(expected)))
    mismatched = tuple(
        sorted(path for path in set(current) & set(expected) if current[path] != expected[path])
    )
    return ManifestVerification(
        checked=len(set(current) & set(expected)),
        missing=missing,
        mismatched=mismatched,
        unlisted=unlisted,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build or verify STARCOM source manifest")
    parser.add_argument("--root", default=".")
    parser.add_argument("--manifest", default="MANIFEST.sha256")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.root).resolve()
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path
    if args.write:
        manifest_path.write_text(render_manifest(build_manifest(root)), encoding="utf-8")
        print(f"manifest_written path={manifest_path} entries={len(build_manifest(root))}")
        return 0
    verification = verify_manifest(root, manifest_path)
    payload = asdict(verification) | {"ok": verification.ok}
    if args.json:
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    else:
        print(json.dumps(payload, sort_keys=True))
    return 0 if verification.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
