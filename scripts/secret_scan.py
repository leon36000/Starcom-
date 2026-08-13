from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import tomllib
from collections.abc import Iterable, Sequence


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
_DATABASE_SUFFIXES = {".db", ".sqlite", ".sqlite3"}
_TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".css",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".txt",
    ".yaml",
    ".yml",
}
_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----"
)
_TOKEN_PATTERNS = (
    ("GITHUB_TOKEN", re.compile(r"\bgh[opsu]_[A-Za-z0-9]{20,}\b")),
    ("GITHUB_TOKEN", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
)
_ACTION_PATTERN = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
_FULL_COMMIT_REF = re.compile(r"^[^@]+@[0-9a-fA-F]{40}$")
_PLACEHOLDER_PATTERN = re.compile(
    r"\b(?:" + "|".join(("TO" + "DO", "T" + "BD", "FIX" + "ME", "X" + "XX")) + r")\b"
)
_PRODUCTION_PREFIXES = ("src/", "scripts/", ".github/")
_EXACT_REQUIREMENT = re.compile(r"^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[^*<>=!~;\s]+(?:\s*;.+)?$")
_PINNED_URL_REQUIREMENT = re.compile(r"^[A-Za-z0-9_.-]+\s*@\s*https://.+#sha256=[0-9a-fA-F]{64}(?:\s*;.+)?$")


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    line: int | None
    message: str


def _iter_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root)
        if any(part in _EXCLUDED_PARTS for part in relative.parts):
            continue
        yield path


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _read_text(path: Path) -> str | None:
    if path.suffix.lower() not in _TEXT_SUFFIXES and path.name not in {
        ".gitignore",
        "Dockerfile",
        "Makefile",
    }:
        return None
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None



def _dependency_findings(path: Path, relative: str, text: str) -> list[Finding]:
    if path.name != "pyproject.toml":
        return []
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return [Finding("INVALID_PYPROJECT", relative, None, "pyproject.toml is invalid TOML")]
    requirements: list[str] = []
    build_system = document.get("build-system", {})
    if isinstance(build_system, dict):
        requirements.extend(item for item in build_system.get("requires", []) if isinstance(item, str))
    project = document.get("project", {})
    if isinstance(project, dict):
        requirements.extend(item for item in project.get("dependencies", []) if isinstance(item, str))
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for values in optional.values():
                if isinstance(values, list):
                    requirements.extend(item for item in values if isinstance(item, str))
    return [
        Finding(
            "FLOATING_DEPENDENCY",
            relative,
            None,
            f"dependency must be pinned exactly: {requirement}",
        )
        for requirement in requirements
        if not (_EXACT_REQUIREMENT.fullmatch(requirement) or _PINNED_URL_REQUIREMENT.fullmatch(requirement))
    ]


def scan_repository(root: str | Path) -> tuple[Finding, ...]:
    root_path = Path(root).resolve()
    findings: list[Finding] = []

    for path in _iter_files(root_path):
        relative = path.relative_to(root_path).as_posix()
        name = path.name
        if path.suffix.lower() in _DATABASE_SUFFIXES:
            findings.append(
                Finding(
                    "DATABASE_ARTIFACT",
                    relative,
                    None,
                    "generated database files must not be committed",
                )
            )
        if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
            findings.append(
                Finding("ENV_FILE", relative, None, "environment secret file is forbidden")
            )

        text = _read_text(path)
        if text is None:
            continue

        findings.extend(_dependency_findings(path, relative, text))
        for match in _PRIVATE_KEY_PATTERN.finditer(text):
            findings.append(
                Finding(
                    "PRIVATE_KEY_MATERIAL",
                    relative,
                    _line_number(text, match.start()),
                    "private key material is forbidden",
                )
            )
        for token_name, pattern in _TOKEN_PATTERNS:
            for match in pattern.finditer(text):
                findings.append(
                    Finding(
                        token_name,
                        relative,
                        _line_number(text, match.start()),
                        "high-confidence secret token is forbidden",
                    )
                )
        for match in _ACTION_PATTERN.finditer(text):
            reference = match.group(1)
            if reference.startswith("./"):
                continue
            if not _FULL_COMMIT_REF.fullmatch(reference):
                findings.append(
                    Finding(
                        "UNPINNED_GITHUB_ACTION",
                        relative,
                        _line_number(text, match.start()),
                        "external GitHub Actions must use a full 40-character commit SHA",
                    )
                )
        if relative.startswith(_PRODUCTION_PREFIXES):
            for match in _PLACEHOLDER_PATTERN.finditer(text):
                findings.append(
                    Finding(
                        "PRODUCTION_PLACEHOLDER",
                        relative,
                        _line_number(text, match.start()),
                        "placeholder token is forbidden in production paths",
                    )
                )

    return tuple(findings)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan STARCOM for repository policy violations")
    parser.add_argument("--root", default=".")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    findings = scan_repository(args.root)
    if args.json:
        print(json.dumps([asdict(item) for item in findings], sort_keys=True, separators=(",", ":")))
    else:
        for item in findings:
            location = f"{item.path}:{item.line}" if item.line is not None else item.path
            print(f"{item.code} {location} {item.message}")
        print(f"secret_scan findings={len(findings)}")
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
