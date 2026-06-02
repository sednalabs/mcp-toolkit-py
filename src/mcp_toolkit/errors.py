"""Helpers for emitting safe downstream authorization errors."""

from __future__ import annotations

import json
from typing import Any, Literal, Mapping, TypedDict


class DownstreamForbiddenPayload(TypedDict, total=False):
    status: Literal["error"]
    code: str
    message: str
    origin: Literal["downstream"]
    tool: str
    downstream_status: int
    hint: str
    request_id: str


def downstream_forbidden_payload(
    *,
    tool: str | None = None,
    request_id: str | None = None,
    downstream_status: int | None = None,
    hint: str | None = None,
    code: str | None = None,
    message: str | None = None,
) -> DownstreamForbiddenPayload:
    """Return a safe, structured payload for downstream 403 responses."""
    payload: DownstreamForbiddenPayload = {
        "status": "error",
        "code": code or "downstream.forbidden",
        "message": message or "Authorization denied by downstream service.",
        "origin": "downstream",
        "downstream_status": downstream_status if downstream_status is not None else 403,
        "hint": hint or "Verify the MCP server has permission for this operation.",
    }
    if tool:
        payload["tool"] = tool
    if request_id:
        payload["request_id"] = request_id
    return payload


def tool_error_from_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Wrap a payload into the MCP tool error content shape."""
    return {
        "isError": True,
        "content": [
            {
                "type": "text",
                "text": json.dumps(payload),
            }
        ],
    }


def downstream_forbidden_tool_error(
    *,
    tool: str | None = None,
    request_id: str | None = None,
    downstream_status: int | None = None,
    hint: str | None = None,
    code: str | None = None,
    message: str | None = None,
) -> dict[str, Any]:
    """Return an MCP CallToolResult-compatible error for downstream 403s."""
    payload = downstream_forbidden_payload(
        tool=tool,
        request_id=request_id,
        downstream_status=downstream_status,
        hint=hint,
        code=code,
        message=message,
    )
    return tool_error_from_payload(payload)
