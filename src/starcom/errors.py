from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class StarcomError(Exception):
    """Base error carrying a stable machine-readable code."""

    default_code = "STARCOM_ERROR"

    def __init__(
        self,
        code: str | None = None,
        message: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        resolved_code = code or self.default_code
        resolved_message = message or resolved_code
        super().__init__(resolved_message)
        self.code = resolved_code
        self.message = resolved_message
        self.details = dict(details or {})

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"error": self.code, "message": self.message}
        if self.details:
            payload["details"] = self.details
        return payload


class ValidationError(StarcomError):
    default_code = "VALIDATION_ERROR"

    def __init__(self, message: str, details: Mapping[str, Any] | None = None) -> None:
        super().__init__(self.default_code, message, details)


class ConflictError(StarcomError):
    default_code = "CONFLICT"

    def __init__(self, message: str, details: Mapping[str, Any] | None = None) -> None:
        super().__init__(self.default_code, message, details)


class AuthorizationError(StarcomError):
    default_code = "AUTHORIZATION_DENIED"

    def __init__(self, message: str, details: Mapping[str, Any] | None = None) -> None:
        super().__init__(self.default_code, message, details)


class NotFoundError(StarcomError):
    default_code = "NOT_FOUND"

    def __init__(self, message: str, details: Mapping[str, Any] | None = None) -> None:
        super().__init__(self.default_code, message, details)


class IntegrityError(StarcomError):
    default_code = "INTEGRITY_ERROR"

    def __init__(self, message: str, details: Mapping[str, Any] | None = None) -> None:
        super().__init__(self.default_code, message, details)


class StateTransitionError(StarcomError):
    default_code = "INVALID_STATE_TRANSITION"

    def __init__(self, message: str, details: Mapping[str, Any] | None = None) -> None:
        super().__init__(self.default_code, message, details)
