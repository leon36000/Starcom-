from __future__ import annotations

from pathlib import Path, PurePosixPath
from collections.abc import Iterable, Sequence
from urllib.parse import unquote

from scripts.build_manifest import ManifestVerification, build_manifest


_HEX = frozenset("0123456789abcdef")
_ALLOWED_SEGMENT_SHAPES = {(4, 16), (8, 8), (16, 4)}


def discover_manifest_shards(root: str | Path) -> tuple[Path, ...]:
    root_path = Path(root).resolve()
    return tuple(sorted(root_path.glob("MANIFEST.[0-9][0-9].sha256")))


def _parse_segmented_digest(rendered: str, line_number: int) -> str:
    segments = rendered.split(":")
    shape = (len(segments), len(segments[0]) if segments else 0)
    if shape not in _ALLOWED_SEGMENT_SHAPES:
        raise ValueError(f"invalid segmented digest on line {line_number}")
    if any(len(segment) != shape[1] for segment in segments):
        raise ValueError(f"invalid segmented digest on line {line_number}")
    if any(set(segment) - _HEX for segment in segments):
        raise ValueError(f"invalid segmented digest on line {line_number}")
    digest = "".join(segments)
    if len(digest) != 64:
        raise ValueError(f"invalid segmented digest on line {line_number}")
    return digest


def _parse_relative_path(rendered: str, item: Path, line_number: int) -> str:
    decoded = unquote(rendered)
    candidate = PurePosixPath(decoded)
    if (
        not decoded
        or decoded.startswith("/")
        or "\\" in decoded
        or "\x00" in decoded
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise ValueError(f"invalid manifest line {item}:{line_number}")
    return candidate.as_posix()


def load_manifest_shards(paths: Iterable[str | Path]) -> dict[str, str]:
    entries: dict[str, str] = {}
    seen_any = False
    for item in sorted(Path(path) for path in paths):
        seen_any = True
        for line_number, raw in enumerate(item.read_text(encoding="utf-8").splitlines(), 1):
            if not raw.strip():
                continue
            if "  " not in raw:
                raise ValueError(f"invalid manifest line {item}:{line_number}")
            rendered_digest, rendered_path = raw.split("  ", 1)
            digest = _parse_segmented_digest(rendered_digest, line_number)
            relative = _parse_relative_path(rendered_path, item, line_number)
            if relative in entries:
                raise ValueError(f"duplicate manifest path {relative}")
            entries[relative] = digest
    if not seen_any:
        raise ValueError("no manifest shards found")
    return entries


def verify_manifest_shards(
    root: str | Path,
    paths: Sequence[str | Path] | None = None,
) -> ManifestVerification:
    root_path = Path(root).resolve()
    selected = tuple(Path(path) for path in paths) if paths is not None else discover_manifest_shards(root_path)
    expected = load_manifest_shards(selected)
    current = build_manifest(root_path)
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
