import json

from mcp_toolkit.errors import (
    downstream_forbidden_payload,
    downstream_forbidden_tool_error,
)


def test_downstream_forbidden_payload_defaults():
    assert downstream_forbidden_payload() == {
        "status": "error",
        "code": "downstream.forbidden",
        "message": "Authorization denied by downstream service.",
        "origin": "downstream",
        "downstream_status": 403,
        "hint": "Verify the MCP server has permission for this operation.",
    }


def test_downstream_forbidden_payload_with_fields():
    payload = downstream_forbidden_payload(
        tool="events.list",
        request_id="req-1",
        downstream_status=403,
        hint="Check roles.",
    )
    assert payload == {
        "status": "error",
        "code": "downstream.forbidden",
        "message": "Authorization denied by downstream service.",
        "origin": "downstream",
        "downstream_status": 403,
        "hint": "Check roles.",
        "tool": "events.list",
        "request_id": "req-1",
    }


def test_downstream_forbidden_tool_error():
    result = downstream_forbidden_tool_error(request_id="req-2")
    assert result["isError"] is True
    payload = json.loads(result["content"][0]["text"])
    assert payload["request_id"] == "req-2"
    assert payload["code"] == "downstream.forbidden"
