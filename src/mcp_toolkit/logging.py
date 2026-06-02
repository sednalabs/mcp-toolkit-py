"""# MCP Toolkit Logging

Structured logging engine with built-in redaction.

## Rationale
Provides a high-performance, security-first logging infrastructure for MCP servers.
It ensures that all logs are structured (JSON or logfmt) and automatically scrubbed
of credentials before being emitted.

## Security Boundaries
* **Redaction**: Automatically masks common secret keys and token-like values.
* **Format Isolation**: Ensures that complex objects are safely serialized or redacted.

## References
* **DESIGN**: Shared MCP toolkit logging conventions.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from .logging_format import coerce_logfmt, now_iso
from .logging_redaction import (
    default_redact_keys,
    default_redact_value_patterns,
    sanitize_extra,
)

LogLevel = Literal["debug", "info", "warn", "error"]
LogFormat = Literal["json", "logfmt"]

_LEVELS: dict[LogLevel, int] = {
    "debug": 10,
    "info": 20,
    "warn": 30,
    "error": 40,
}



@dataclass(frozen=True)
class Logger:
    """Lightweight structured logger with redaction.

    Args:
        level: Minimum severity to emit.
        format: Output format for structured logs.
        redact_keys: Regex identifying sensitive field names.
        redact_value_patterns: Regex patterns for value redaction.

    Security:
        Redacts tokens and secrets using both key and value filters.
    """

    level: LogLevel
    format: LogFormat
    redact_keys: re.Pattern[str]
    redact_value_patterns: list[re.Pattern[str]]

    def debug(self, msg: str, extra: Mapping[str, object] | None = None) -> None:
        """Emit a debug log entry.

        Args:
            msg: Message to log.
            extra: Optional structured fields.

        Returns:
            None.

        Security:
            Relies on redaction policies configured on the logger.
        """

        self._emit("debug", msg, extra)

    def info(self, msg: str, extra: Mapping[str, object] | None = None) -> None:
        """Emit an info log entry.

        Args:
            msg: Message to log.
            extra: Optional structured fields.

        Returns:
            None.

        Security:
            Relies on redaction policies configured on the logger.
        """

        self._emit("info", msg, extra)

    def warn(self, msg: str, extra: Mapping[str, object] | None = None) -> None:
        """Emit a warning log entry.

        Args:
            msg: Message to log.
            extra: Optional structured fields.

        Returns:
            None.

        Security:
            Relies on redaction policies configured on the logger.
        """

        self._emit("warn", msg, extra)

    def error(self, msg: str, extra: Mapping[str, object] | None = None) -> None:
        """Emit an error log entry.

        Args:
            msg: Message to log.
            extra: Optional structured fields.

        Returns:
            None.

        Security:
            Relies on redaction policies configured on the logger.
        """

        self._emit("error", msg, extra)

    def _emit(self, level: LogLevel, msg: str, extra: Mapping[str, object] | None) -> None:
        if _LEVELS[level] < _LEVELS[self.level]:
            return
        payload = {
            "ts": now_iso(),
            "level": level,
            "msg": msg,
        }
        sanitized = sanitize_extra(extra, self.redact_keys, self.redact_value_patterns)
        if sanitized:
            payload.update(sanitized)
        if self.format == "json":
            sys.stdout.write(json.dumps(payload) + "\n")
            return
        parts = [f"{key}={coerce_logfmt(value)}" for key, value in payload.items()]
        sys.stdout.write(" ".join(parts) + "\n")


def create_logger(
    level: LogLevel = "info",
    format: LogFormat = "json",
    redact_keys: re.Pattern[str] | None = None,
    redact_value_patterns: list[re.Pattern[str]] | None = None,
) -> Logger:
    """Create a structured logger with redaction defaults.

    Args:
        level: Minimum severity to emit.
        format: Output format for structured logs.
        redact_keys: Regex identifying sensitive field names.
        redact_value_patterns: Regex patterns for value redaction.

    Returns:
        Logger instance.

    Security:
        Uses conservative default redaction to avoid leaking credentials.
    """

    return Logger(
        level=level,
        format=format,
        redact_keys=redact_keys or default_redact_keys(),
        redact_value_patterns=redact_value_patterns or default_redact_value_patterns(),
    )
