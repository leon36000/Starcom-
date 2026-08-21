from __future__ import annotations

import base64
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
from typing import Any, Mapping
from urllib.parse import unquote, urlparse

from .adoption_execution import C3AdoptionExecutionRecord, C3ExecutorResult, C3RollbackResult
from .canonical import canonical_json, parse_strict_json_object, sha256_digest
from .errors import ConflictError, IntegrityError, StateTransitionError, ValidationError


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROFILE = "starcom-local-component-v1"
_MANIFEST_FIELDS = frozenset({"component", "version", "files"})
_FILE_FIELDS = frozenset({"path", "digest", "size"})
_SAFE_TARGET = re.compile(r"^[A-Za-z0-9._-]+$")


class SandboxComponentExecutor:
    """File-only C3 executor with content-addressed releases and pointer rollback."""

    executor_id = "sandbox-component-executor"
    implementation_name = "STARCOM local sandbox component executor"
    implementation_version = "1.0.0"
    implementation_digest = hashlib.sha256(
        b"starcom-local-component-executor-v1"
    ).hexdigest()

    def __init__(self, sandbox_root: str | Path, *, source_root: str | Path | None = None) -> None:
        self.sandbox_root = Path(sandbox_root).expanduser().resolve()
        self.source_root = Path(source_root).expanduser().resolve() if source_root is not None else None

    @staticmethod
    def _text(value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{field} must be a non-empty string")
        return value

    @staticmethod
    def _digest(value: object, field: str) -> str:
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise ValidationError(f"{field} must be a lowercase SHA-256 digest")
        return value

    @staticmethod
    def _safe_relative(value: object, field: str) -> str:
        value = SandboxComponentExecutor._text(value, field)
        if "\\" in value or value.startswith("/"):
            raise ValidationError(f"{field} must be a safe relative POSIX path")
        path = PurePosixPath(value)
        if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
            raise ValidationError(f"{field} must not contain traversal")
        normalized = "/".join(path.parts)
        if normalized != value or normalized == "component_manifest.json":
            raise ValidationError(f"{field} is not canonical or is reserved")
        return normalized

    def _manifest(self) -> dict[str, object]:
        if self.source_root is None:
            raise ValidationError("source_root must be explicitly configured")
        if not self.source_root.is_dir() or self.source_root.is_symlink():
            raise ValidationError("source_root must be a real directory")
        manifest_path = self.source_root / "component_manifest.json"
        try:
            value = parse_strict_json_object(
                manifest_path.read_bytes(), max_bytes=1024 * 1024, label="component manifest"
            )
        except OSError as exc:
            raise ValidationError("component_manifest.json could not be read") from exc
        if frozenset(value) != _MANIFEST_FIELDS:
            raise ValidationError("component manifest fields do not match the contract")
        component = self._text(value["component"], "component")
        version = self._text(value["version"], "version")
        raw_files = value["files"]
        if not isinstance(raw_files, list) or not raw_files:
            raise ValidationError("component manifest files must be a non-empty list")
        files: list[dict[str, object]] = []
        paths: list[str] = []
        for index, raw in enumerate(raw_files):
            if not isinstance(raw, dict) or frozenset(raw) != _FILE_FIELDS:
                raise ValidationError(f"component manifest files[{index}] is invalid")
            relative = self._safe_relative(raw["path"], f"files[{index}].path")
            digest = self._digest(raw["digest"], f"files[{index}].digest")
            size = raw["size"]
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                raise ValidationError(f"files[{index}].size must be a non-negative integer")
            paths.append(relative)
            files.append({"path": relative, "digest": digest, "size": size})
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValidationError("component manifest files must be sorted and unique")
        actual: set[str] = set()
        for path in self.source_root.rglob("*"):
            if path.is_symlink():
                raise ValidationError("source tree must not contain symlinks")
            if path.is_file() and path.name != "component_manifest.json":
                actual.add(path.relative_to(self.source_root).as_posix())
        if actual != set(paths):
            raise ValidationError(
                "component manifest does not exactly cover source files",
                {"missing": sorted(set(paths) - actual), "unexpected": sorted(actual - set(paths))},
            )
        for item in files:
            path = self._source_file(item["path"])
            if not path.is_file() or path.is_symlink():
                raise ValidationError(f"manifest file is not a regular file: {item['path']}")
            content = path.read_bytes()
            if len(content) != item["size"] or hashlib.sha256(content).hexdigest() != item["digest"]:
                raise IntegrityError(f"manifest digest or size mismatch: {item['path']}")
        return {"component": component, "version": version, "files": files}

    def _source_file(self, relative: object, field: str = "path") -> Path:
        if self.source_root is None:
            raise ValidationError("source_root must be explicitly configured")
        safe = self._safe_relative(relative, field)
        root = self.source_root.resolve()
        candidate = root / safe
        resolved = candidate.resolve()
        if resolved != candidate or not resolved.is_relative_to(root):
            raise ValidationError(f"{field} resolves outside source_root")
        return resolved

    def _ensure_sandbox_root(self) -> None:
        if self.sandbox_root.exists() and self.sandbox_root.is_symlink():
            raise ValidationError("sandbox_root must not be a symlink")
        self.sandbox_root.mkdir(parents=True, exist_ok=True)
        if self._releases.exists() and self._releases.is_symlink():
            raise IntegrityError("sandbox releases directory must not be a symlink")
        if self._journal_root.exists() and self._journal_root.is_symlink():
            raise IntegrityError("sandbox journal directory must not be a symlink")
        if self._current.exists() and self._current.is_symlink():
            raise IntegrityError("sandbox current pointer must not be a symlink")

    def validate_manifest(self) -> str:
        return sha256_digest(self._manifest())

    @property
    def source_digest(self) -> str:
        return self.validate_manifest()

    def descriptor(self) -> dict[str, object]:
        return {
            "executor_id": self.executor_id,
            "implementation_name": self.implementation_name,
            "implementation_version": self.implementation_version,
            "implementation_digest": self.implementation_digest,
            "artifact_digest": self.implementation_digest,
            "entrypoint": "starcom.sandbox_executor:SandboxComponentExecutor",
            "supported_sandbox_profiles": [_PROFILE],
            "network_mode": "DENY",
            "capabilities": ["atomic-install", "atomic-rollback"],
        }

    def _source_from_plan(self, value: object) -> Path:
        uri = self._text(value, "component_ref")
        parsed = urlparse(uri)
        if parsed.scheme != "file" or parsed.query or parsed.fragment or parsed.netloc not in {"", "localhost"}:
            raise ValidationError("component_ref must be a local file:// URI")
        path = Path(unquote(parsed.path)).resolve()
        if self.source_root is None or path != self.source_root:
            raise ValidationError("component_ref is outside the configured source root")
        return path

    def _validated_plan(self, request: C3AdoptionExecutionRecord) -> dict[str, object]:
        plan = request.execution_plan
        if not isinstance(plan, Mapping):
            raise ValidationError("execution_plan must be an object")
        self._source_from_plan(plan.get("component_ref"))
        if plan.get("sandbox_profile") != _PROFILE:
            raise ValidationError("sandbox_profile must be starcom-local-component-v1")
        target = self._text(plan.get("target_environment"), "target_environment")
        if not target.startswith("sandbox:") or not _SAFE_TARGET.fullmatch(target[8:]):
            raise ValidationError("target_environment must be sandbox:<safe-id>")
        if plan.get("requires_network") is not False or plan.get("network_allowlist") != []:
            raise ValidationError("sandbox executor requires network access to be disabled")
        if plan.get("requires_separate_rollback_authorization") is not False:
            raise ValidationError("sandbox rollback authorization must be false")
        source_digest = self._digest(plan.get("source_digest"), "source_digest")
        if source_digest != self.source_digest:
            raise ValidationError("execution plan source digest does not match the manifest")
        if request.executor_id != self.executor_id:
            raise StateTransitionError("execution request targets another executor")
        return dict(plan)

    def validate(self, request: C3AdoptionExecutionRecord) -> None:
        self._validated_plan(request)

    @property
    def _releases(self) -> Path:
        return self.sandbox_root / "releases"

    @property
    def _journal_root(self) -> Path:
        return self.sandbox_root / ".executor-journal"

    @property
    def _current(self) -> Path:
        return self.sandbox_root / "current.json"

    @staticmethod
    def _state_digest(raw: bytes | None) -> str:
        return hashlib.sha256(raw or b"").hexdigest()

    def _journal_path(self, key: str) -> Path:
        return self._journal_root / f"{hashlib.sha256(key.encode()).hexdigest()}.json"

    @staticmethod
    def _write_atomic(path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.staging")
        temporary.write_bytes(content)
        os.replace(temporary, path)

    def _load_journal(self, key: str) -> dict[str, object] | None:
        path = self._journal_path(key)
        if not path.exists():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise IntegrityError("sandbox executor journal is invalid") from exc
        if not isinstance(value, dict):
            raise IntegrityError("sandbox executor journal must be an object")
        return value

    def _result_from_journal(self, value: Mapping[str, object]) -> C3ExecutorResult:
        result = value.get("execution_result")
        if not isinstance(result, dict):
            raise IntegrityError("sandbox journal execution result is invalid")
        return C3ExecutorResult(
            succeeded=bool(result["succeeded"]),
            effect_started=bool(result["effect_started"]),
            pre_state_digest=str(result["pre_state_digest"]),
            post_state_digest=(str(result["post_state_digest"]) if result.get("post_state_digest") else None),
            receipt=dict(result["receipt"]),
            error=(str(result["error"]) if result.get("error") else None),
        )

    def execute(self, request: C3AdoptionExecutionRecord) -> C3ExecutorResult:
        self.validate(request)
        self._ensure_sandbox_root()
        fingerprint = sha256_digest({"execution_id": request.execution_id, "plan": dict(request.execution_plan)})
        journal = self._load_journal(request.idempotency_key)
        if journal is not None:
            if journal.get("fingerprint") != fingerprint:
                raise ConflictError("idempotency key binds different sandbox material")
            return self._result_from_journal(journal)
        manifest = self._manifest()
        self._releases.mkdir(parents=True, exist_ok=True)
        previous = self._current.read_bytes() if self._current.exists() else None
        pre_digest = self._state_digest(previous)
        release_digest = sha256_digest(manifest)
        release = self._releases / release_digest
        staging = self._releases / f".staging-{release_digest}-{hashlib.sha256(request.idempotency_key.encode()).hexdigest()[:12]}"
        try:
            if not release.exists():
                if staging.exists():
                    shutil.rmtree(staging)
                for item in manifest["files"]:
                    assert isinstance(item, dict)
                    source = self._source_file(item["path"])
                    destination = staging / str(item["path"])
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(source.read_bytes())
                os.replace(staging, release)
            elif release.is_symlink() or not release.is_dir():
                raise IntegrityError("content-addressed release is not a real directory")
            pointer = canonical_json(
                {
                    "component": manifest["component"],
                    "version": manifest["version"],
                    "release_digest": release_digest,
                    "files": manifest["files"],
                    "target_environment": request.execution_plan["target_environment"],
                }
            ).encode("utf-8")
            self._write_atomic(self._current, pointer)
            post_digest = self._state_digest(pointer)
            result = C3ExecutorResult(
                succeeded=True,
                effect_started=True,
                pre_state_digest=pre_digest,
                post_state_digest=post_digest,
                receipt={
                    "executor_id": self.executor_id,
                    "execution_id": request.execution_id,
                    "idempotency_key": request.idempotency_key,
                    "release_digest": release_digest,
                    "source_digest": release_digest,
                    "target_environment": request.execution_plan["target_environment"],
                    "version": manifest["version"],
                },
            )
            journal_value = {
                "fingerprint": fingerprint,
                "state": "EXECUTED",
                "previous_current_base64": base64.b64encode(previous).decode("ascii") if previous is not None else None,
                "execution_result": asdict(result),
            }
            self._write_atomic(self._journal_path(request.idempotency_key), canonical_json(journal_value).encode())
            return result
        except BaseException:
            if staging.exists():
                shutil.rmtree(staging)
            raise

    def rollback(
        self,
        request: C3AdoptionExecutionRecord,
        execution_result: C3ExecutorResult | None,
        reason: str,
    ) -> C3RollbackResult:
        reason = self._text(reason, "reason")
        self._ensure_sandbox_root()
        if request.executor_id != self.executor_id:
            raise StateTransitionError("execution request targets another executor")
        plan = request.execution_plan
        if not isinstance(plan, Mapping):
            raise ValidationError("execution_plan must be an object")
        self._source_from_plan(plan.get("component_ref"))
        if plan.get("sandbox_profile") != _PROFILE or plan.get("requires_network") is not False:
            raise ValidationError("sandbox rollback requires the local no-network profile")
        journal = self._load_journal(request.idempotency_key)
        if journal is None:
            return C3RollbackResult(False, None, {"executor_id": self.executor_id, "reason": reason}, "execution journal not found")
        fingerprint = sha256_digest({"execution_id": request.execution_id, "plan": dict(plan)})
        if journal.get("fingerprint") != fingerprint:
            raise ConflictError("idempotency key binds different sandbox material")
        if journal.get("state") == "ROLLED_BACK":
            rollback = journal.get("rollback_result")
            if not isinstance(rollback, dict):
                raise IntegrityError("sandbox rollback journal is invalid")
            return C3RollbackResult(
                succeeded=bool(rollback["succeeded"]),
                restored_state_digest=(str(rollback["restored_state_digest"]) if rollback.get("restored_state_digest") else None),
                receipt=dict(rollback["receipt"]),
                error=(str(rollback["error"]) if rollback.get("error") else None),
            )
        previous_encoded = journal.get("previous_current_base64")
        previous = base64.b64decode(previous_encoded) if isinstance(previous_encoded, str) else None
        if previous is None:
            if self._current.exists():
                self._current.unlink()
        else:
            self._write_atomic(self._current, previous)
        restored = self._state_digest(previous)
        result = C3RollbackResult(
            succeeded=True,
            restored_state_digest=restored,
            receipt={
                "executor_id": self.executor_id,
                "idempotency_key": request.idempotency_key,
                "reason": reason,
                "restored_state_digest": restored,
            },
        )
        journal["state"] = "ROLLED_BACK"
        journal["rollback_result"] = asdict(result)
        self._write_atomic(self._journal_path(request.idempotency_key), canonical_json(journal).encode())
        return result


__all__ = ["SandboxComponentExecutor"]
