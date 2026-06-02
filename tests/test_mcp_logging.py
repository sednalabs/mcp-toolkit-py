import asyncio

from mcp_toolkit.mcp_logging import MCP_LOGGING_SCHEMA, McpLogEmitter, McpLoggingConfig


class DummySession:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def send_log_message(self, **kwargs: object) -> None:
        self.calls.append(kwargs)


def test_emit_redacts_and_strips_stack() -> None:
    session = DummySession()
    emitter = McpLogEmitter(
        McpLoggingConfig(
            enabled=True,
            server_level="info",
            max_level="info",
            rate_limit_per_s=100.0,
            rate_limit_burst=100,
        )
    )
    asyncio.run(
        emitter.emit(
            session=session,
            level="info",
            message="resource.subscribe.start",
            data={
                "token": "secret",
                "stack": "trace",
                "nested": {"password": "nope"},
            },
        )
    )
    assert len(session.calls) == 1
    payload = session.calls[0]["data"]
    assert payload["event"] == "resource.subscribe.start"
    assert payload["token"] == "<redacted>"
    assert "stack" not in payload
    assert payload["nested"]["password"] == "<redacted>"


def test_rate_limit_blocks_info() -> None:
    session = DummySession()
    emitter = McpLogEmitter(
        McpLoggingConfig(
            enabled=True,
            server_level="info",
            max_level="info",
            rate_limit_per_s=1.0,
            rate_limit_burst=1,
        )
    )
    asyncio.run(emitter.emit(session=session, level="info", message="event.one", data=None))
    asyncio.run(emitter.emit(session=session, level="info", message="event.two", data=None))
    assert len(session.calls) == 1


def test_schema_documents_throttle_fields() -> None:
    events = MCP_LOGGING_SCHEMA["events"]
    tool_error = next(event for event in events if event["name"] == "tool.call.error")
    fields = tool_error["fields"]
    assert fields["reason"] == "string"
    assert fields["retry_after_s"] == "number"
