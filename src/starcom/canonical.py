from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import date, datetime, timezone
from enum import Enum
import hashlib
import json
import math
from typing import Any
from uuid import UUID

from .errors import ValidationError


def _canonical_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError("datetime values must be timezone-aware")
    normalized = value.astimezone(timezone.utc)
    return normalized.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def utc_now() -> str:
    return _canonical_timestamp(datetime.now(timezone.utc))


def _normalize(value: Any, path: str = "$") -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValidationError("float values must be finite", {"path": path})
        return value
    if isinstance(value, datetime):
        return _canonical_timestamp(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Enum):
        return _normalize(value.value, path)
    if is_dataclass(value) and not isinstance(value, type):
        return _normalize(asdict(value), path)
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValidationError("canonical mappings require string keys", {"path": path})
            normalized[key] = _normalize(item, f"{path}.{key}")
        return normalized
    if isinstance(value, (list, tuple)):
        return [_normalize(item, f"{path}[{index}]") for index, item in enumerate(value)]
    raise ValidationError(
        "unsupported value for canonical JSON",
        {"path": path, "type": type(value).__name__},
    )


def canonical_json(value: Any) -> str:
    normalized = _normalize(value)
    try:
        return json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:  # defensive: normalization should catch these
        raise ValidationError("value cannot be encoded as canonical JSON") from exc


def canonical_json_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def parse_strict_json_object(
    payload: object,
    *,
    max_bytes: int,
    label: str,
) -> dict[str, object]:
    if not isinstance(payload, bytes) or not payload or len(payload) > max_bytes:
        raise ValidationError("payload must be non-empty bytes within the size limit")

    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=no_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("invalid JSON constant")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValidationError(f"{label} payload must be strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"{label} payload must be a JSON object")
    return value


def sha256_digest(value: Any | bytes) -> str:
    raw = value if isinstance(value, bytes) else canonical_json_bytes(value)
    return hashlib.sha256(raw).hexdigest()
