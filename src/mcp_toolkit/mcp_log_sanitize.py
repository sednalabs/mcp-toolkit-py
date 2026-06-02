"""Helpers for redacting and sanitizing MCP log payloads."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

_CONTROL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
_SENSITIVE_KEY_RE = re.compile(r"(token|secret|password|authorization)", re.IGNORECASE)
_DEFAULT_REDACT_VALUE_PATTERNS = [
    re.compile(r"(authorization:\s*bearer\s+)[^\s]+", re.IGNORECASE),
    re.compile(r"\bbearer\s+[A-Za-z0-9._~-]+", re.IGNORECASE),
    re.compile(r"(github_pat\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"gh[a-z]_[A-Za-z0-9_]{36,}"),
    re.compile(r"(password|token|secret|api_key)\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(
        r"(client_secret|subject_token|access_token|refresh_token)\s*[=:]\s*\S+",
        re.IGNORECASE,
    ),
    re.compile(r"postgresql(\+\w+)?://[^\s]+", re.IGNORECASE),
]
_STACK_KEYS = {"stack", "stacktrace", "traceback"}

MAX_VALUE_LENGTH = 2048
MAX_DEPTH = 2
MAX_KEYS = 32
MAX_ARRAY = 32
MAX_LOG_PAYLOAD = 4096


def _truncate(value: str, *, limit: int) -> str:
    if len(value) <= limit:
        return value
    return f"{value[: max(0, limit - 3)]}..."


def _redact_value(value: str) -> str:
    redacted = value
    for pattern in _DEFAULT_REDACT_VALUE_PATTERNS:
        replacement = r"\1REDACTED" if pattern.groups else "REDACTED"
        redacted = pattern.sub(replacement, redacted)
    return redacted


def scrub_text(value: str, *, limit: int = MAX_VALUE_LENGTH) -> str:
    cleaned = _CONTROL_RE.sub("", value)
    cleaned = _redact_value(cleaned)
    return _truncate(cleaned, limit=limit)


def _sanitize_value(value: Any, *, allow_stacks: bool, depth: int = 0) -> Any:
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, str):
        return scrub_text(value)
    if depth >= MAX_DEPTH:
        return scrub_text(str(value))
    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for key, entry in list(value.items())[:MAX_KEYS]:
            if key in _STACK_KEYS and not allow_stacks:
                continue
            if _SENSITIVE_KEY_RE.search(key):
                sanitized[key] = "<redacted>"
                continue
            sanitized[key] = _sanitize_value(entry, allow_stacks=allow_stacks, depth=depth + 1)
        return sanitized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [
            _sanitize_value(entry, allow_stacks=allow_stacks, depth=depth + 1)
            for entry in list(value)[:MAX_ARRAY]
        ]
    return scrub_text(str(value))


def sanitize_payload(
    message: str,
    data: Mapping[str, Any] | None,
    *,
    allow_stacks: bool,
    context: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"event": scrub_text(message)}
    if data:
        sanitized = _sanitize_value(data, allow_stacks=allow_stacks)
        if isinstance(sanitized, Mapping):
            payload.update(sanitized)
    if context:
        for key in ("request_id", "session_id", "actor"):
            if key in context:
                payload[key] = context[key]
    return payload
