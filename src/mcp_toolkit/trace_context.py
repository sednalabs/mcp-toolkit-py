"""Trace context helpers for correlation and actor tracking.

Security:
    Trace values are treated as non-secret metadata and sanitized before
    being forwarded to downstream systems.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TypeAlias

from .request_id import DEFAULT_REQUEST_ID_HEADERS, extract_request_id

HeaderValue: TypeAlias = str | Sequence[str] | None

DEFAULT_ACTOR_ID_HEADERS: tuple[str, ...] = (
    "x-ops-actor-id",
    "ops-actor-id",
    "x-actor-id",
)

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _normalize_header_value(value: HeaderValue) -> str | None:
    if isinstance(value, str):
        return value
    if value:
        last_value = value[-1]
        if isinstance(last_value, str):
            return last_value
    return None


def _sanitize_trace_value(value: HeaderValue, *, max_len: int = 128) -> str | None:
    raw = _normalize_header_value(value)
    if raw is None:
        return None
    trimmed = _CONTROL_CHARS.sub("", raw).strip()
    if not trimmed:
        return None
    return trimmed[:max_len] if len(trimmed) > max_len else trimmed


def extract_actor_id(
    headers: Mapping[str, HeaderValue],
    candidates: Sequence[str] = DEFAULT_ACTOR_ID_HEADERS,
) -> str | None:
    """Extract the first matching actor id from headers.

    Args:
        headers: Mapping of header names to values.
        candidates: Header names to search in priority order.

    Returns:
        The actor id if found, otherwise None.

    Security:
        Sanitizes values to strip control characters and whitespace.
    """

    normalized = {key.lower(): value for key, value in headers.items()}
    for header in candidates:
        value = _sanitize_trace_value(normalized.get(header.lower()))
        if value:
            return value
    return None


@dataclass(frozen=True)
class TraceContext:
    """Trace context for request correlation and actor tracking."""

    request_id: str | None = None
    actor_id: str | None = None

    def merge(self, fallback: "TraceContext") -> "TraceContext":
        """Merge this context with fallback values.

        Args:
            fallback: Context to use for any missing fields.

        Returns:
            A merged TraceContext.
        """

        return TraceContext(
            request_id=self.request_id or fallback.request_id,
            actor_id=self.actor_id or fallback.actor_id,
        )

    def to_log_fields(self) -> dict[str, str]:
        """Render trace context fields for structured logs."""

        fields: dict[str, str] = {}
        if self.request_id:
            fields["request_id"] = self.request_id
        if self.actor_id:
            fields["actor_id"] = self.actor_id
        return fields

    def to_env(self, prefix: str = "MCP") -> dict[str, str]:
        """Render trace context fields for environment variables."""

        normalized = prefix.strip().upper() or "MCP"
        env: dict[str, str] = {}
        if self.request_id:
            env[f"{normalized}_REQUEST_ID"] = self.request_id
        if self.actor_id:
            env[f"{normalized}_ACTOR_ID"] = self.actor_id
        return env

    def to_db_settings(self, namespace: str = "mcp") -> dict[str, str]:
        """Render trace context fields for DB set_config-style usage."""

        normalized = namespace.strip() or "mcp"
        settings: dict[str, str] = {}
        if self.request_id:
            settings[f"{normalized}.request_id"] = self.request_id
        if self.actor_id:
            settings[f"{normalized}.actor_id"] = self.actor_id
        return settings


def trace_context_from_headers(
    headers: Mapping[str, HeaderValue],
    request_headers: Sequence[str] = DEFAULT_REQUEST_ID_HEADERS,
    actor_headers: Sequence[str] = DEFAULT_ACTOR_ID_HEADERS,
) -> TraceContext:
    """Build a TraceContext from request headers."""

    return TraceContext(
        request_id=extract_request_id(headers, request_headers),
        actor_id=extract_actor_id(headers, actor_headers),
    )


def trace_context_from_auth_info(auth_info: Mapping[str, object] | None) -> TraceContext:
    """Build a TraceContext from an auth info mapping."""

    extra = None
    if isinstance(auth_info, Mapping):
        candidate = auth_info.get("extra")
        if isinstance(candidate, Mapping):
            extra = candidate

    request_id = _sanitize_trace_value(extra.get("request_id") if extra else None)
    if request_id is None and extra:
        request_id = _sanitize_trace_value(extra.get("requestId"))
    actor_id = _sanitize_trace_value(
        extra.get("actor_id") if extra else None,
    )
    if actor_id is None and extra:
        actor_id = _sanitize_trace_value(extra.get("actor"))
    if actor_id is None and extra:
        actor_id = _sanitize_trace_value(extra.get("subject"))
    if actor_id is None and extra:
        actor_id = _sanitize_trace_value(extra.get("sub"))
    if actor_id is None and extra:
        actor_id = _sanitize_trace_value(extra.get("preferred_username"))

    return TraceContext(request_id=request_id, actor_id=actor_id)


def merge_trace_context(primary: TraceContext, fallback: TraceContext) -> TraceContext:
    """Merge two TraceContext instances with primary precedence."""

    return primary.merge(fallback)
