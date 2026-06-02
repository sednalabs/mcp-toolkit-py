"""Redaction helpers for structured logging."""

from __future__ import annotations

import re
from collections.abc import Mapping

_DEFAULT_REDACT_KEYS = re.compile(r"token|secret|password|authorization", re.IGNORECASE)
_DEFAULT_REDACT_VALUE_PATTERNS = [
    re.compile(r"(authorization:\s*bearer\s+)[^\s]+", re.IGNORECASE),
]


def redact_value(value: object, patterns: list[re.Pattern[str]]) -> object:
    """Apply value-level redaction patterns to strings."""
    if not isinstance(value, str):
        return value
    redacted = value
    for pattern in patterns:
        redacted = pattern.sub(r"\1REDACTED", redacted)
    return redacted


def sanitize_extra(
    extra: Mapping[str, object] | None,
    redact_keys: re.Pattern[str],
    redact_value_patterns: list[re.Pattern[str]],
) -> dict[str, object] | None:
    """Sanitize log extras by key and value patterns."""
    if extra is None:
        return None
    out: dict[str, object] = {}
    for key, value in extra.items():
        if redact_keys.search(key):
            out[key] = "<redacted>"
        else:
            out[key] = redact_value(value, redact_value_patterns)
    return out


def default_redact_keys() -> re.Pattern[str]:
    return _DEFAULT_REDACT_KEYS


def default_redact_value_patterns() -> list[re.Pattern[str]]:
    return list(_DEFAULT_REDACT_VALUE_PATTERNS)
