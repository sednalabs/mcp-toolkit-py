"""Correlation ID helpers for MCP services.

Security:
    Request identifiers are treated as non-secret metadata and must not be
    derived from credentials or tokens.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import TypeAlias
from uuid import uuid4

HeaderValue: TypeAlias = str | Sequence[str] | None

DEFAULT_REQUEST_ID_HEADERS: tuple[str, ...] = (
    "x-request-id",
    "x-trace-id",
    "trace-id",
    "traceparent",
)


def _normalize_header_value(value: HeaderValue) -> str | None:
    """Normalize header values to a single request id string.

    Args:
        value: Header value from a mapping.

    Returns:
        The normalized request id value, if present.

    Security:
        Does not attempt to parse or validate request ids beyond trimming.
    """

    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    if value:
        last_value = value[-1]
        if isinstance(last_value, str):
            stripped = last_value.strip()
            return stripped or None
    return None


def extract_request_id(
    headers: Mapping[str, HeaderValue],
    candidates: Sequence[str] = DEFAULT_REQUEST_ID_HEADERS,
) -> str | None:
    """Extract the first matching request id from headers.

    Args:
        headers: Mapping of header names to values.
        candidates: Header names to search in priority order.

    Returns:
        The request id if found, otherwise None.

    Security:
        Only inspects metadata headers and ignores any token-like values.
    """

    normalized = {key.lower(): value for key, value in headers.items()}
    for header in candidates:
        value = _normalize_header_value(normalized.get(header.lower()))
        if value:
            return value
    return None


def ensure_request_id(
    headers: Mapping[str, HeaderValue],
    candidates: Sequence[str] = DEFAULT_REQUEST_ID_HEADERS,
    generator: Callable[[], str] | None = None,
) -> str:
    """Return an existing request id or generate a new one.

    Args:
        headers: Mapping of header names to values.
        candidates: Header names to search in priority order.
        generator: Optional generator for new ids (defaults to uuid4).

    Returns:
        A request id suitable for correlation.

    Security:
        Uses UUIDs by default to avoid embedding sensitive data.
    """

    existing = extract_request_id(headers, candidates)
    if existing:
        return existing
    generator = generator or (lambda: str(uuid4()))
    return generator()


def attach_request_id(setter: Callable[[str, str], None], request_id: str) -> None:
    """Attach a request id to an outbound response or context.

    Args:
        setter: Callable that sets a header name/value pair.
        request_id: Request identifier to attach.

    Returns:
        None.

    Security:
        Emits only the correlation id, never tokens or secrets.
    """

    setter("x-request-id", request_id)
