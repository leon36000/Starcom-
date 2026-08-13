from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import subprocess
import sys
from collections.abc import Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.build_manifest import parse_manifest, verify_manifest  # noqa: E402
from scripts.secret_scan import scan_repository  # noqa: E402
from scripts.text_style import inspect_text_style  # noqa: E402


@dataclass(frozen=True)
class StepResult:
    name: str
    ok: bool
    returncode: int
    command: tuple[str, ...]


def _run(name: str, command: Sequence[str]) -> StepResult:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(
        filter(None, [str(ROOT / "src"), str(ROOT), environment.get("PYTHONPATH", "")])
    )
    completed = subprocess.run(
        list(command),
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    print(f"===== {name} stdout =====")
    if completed.stdout:
        print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")
    print(f"===== {name} stderr =====")
    if completed.stderr:
        print(completed.stderr, end="" if completed.stderr.endswith("\n") else "\n")
    print(f"===== {name} exit={completed.returncode} =====")
    return StepResult(name, completed.returncode == 0, completed.returncode, tuple(command))


def main() -> int:
    steps = [
        _run(
            "compile",
            (sys.executable, "-m", "compileall", "-q", "src", "scripts", "tests"),
        ),
        _run(
            "tests",
            (sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"),
        ),
    ]

    secret_findings = scan_repository(ROOT)
    print("===== secret-scan =====")
    for finding in secret_findings:
        print(json.dumps(asdict(finding), sort_keys=True))
    print(f"secret_scan findings={len(secret_findings)}")
    steps.append(
        StepResult("secret-scan", not secret_findings, int(bool(secret_findings)), ("in-process",))
    )

    style_findings = []
    style_paths = [*parse_manifest(ROOT / "MANIFEST.sha256"), "MANIFEST.sha256"]
    for relative in style_paths:
        raw = (ROOT / relative).read_bytes()
        if b"\x00" in raw:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        style_findings.extend(inspect_text_style(relative, text))
    print("===== text-style =====")
    for finding in style_findings:
        print(json.dumps(asdict(finding), sort_keys=True))
    print(f"text_style findings={len(style_findings)}")
    steps.append(
        StepResult("text-style", not style_findings, int(bool(style_findings)), ("in-process",))
    )

    manifest = verify_manifest(ROOT, ROOT / "MANIFEST.sha256")
    print("===== manifest =====")
    print(json.dumps(asdict(manifest) | {"ok": manifest.ok}, sort_keys=True))
    steps.append(StepResult("manifest", manifest.ok, int(not manifest.ok), ("in-process",)))

    ok = all(step.ok for step in steps)
    summary = {
        "ok": ok,
        "python": sys.version.split()[0],
        "steps": [asdict(step) for step in steps],
    }
    print("===== verification-summary =====")
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
