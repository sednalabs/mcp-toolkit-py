"""Shared auth error types."""

from __future__ import annotations


class AuthError(Exception):
    """Auth error with structured metadata."""

    def __init__(self, message: str, *, status: int, code: str, reason: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.reason = reason
        self.hint = hint
