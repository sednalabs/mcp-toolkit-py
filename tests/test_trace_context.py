import unittest

from mcp_toolkit.trace_context import (
    TraceContext,
    merge_trace_context,
    trace_context_from_auth_info,
    trace_context_from_headers,
)


class TraceContextTests(unittest.TestCase):
    def test_trace_context_from_headers(self) -> None:
        ctx = trace_context_from_headers(
            {"x-request-id": "req-1", "x-ops-actor-id": "agent-1"}
        )
        self.assertEqual(ctx.request_id, "req-1")
        self.assertEqual(ctx.actor_id, "agent-1")

    def test_trace_context_from_auth_info(self) -> None:
        ctx = trace_context_from_auth_info(
            {
                "extra": {
                    "request_id": "req-2",
                    "subject": "user-9",
                }
            }
        )
        self.assertEqual(ctx.request_id, "req-2")
        self.assertEqual(ctx.actor_id, "user-9")

    def test_merge_trace_context(self) -> None:
        merged = merge_trace_context(
            TraceContext(request_id="req-3"),
            TraceContext(request_id="req-4", actor_id="agent-2"),
        )
        self.assertEqual(merged.request_id, "req-3")
        self.assertEqual(merged.actor_id, "agent-2")

    def test_trace_context_outputs(self) -> None:
        ctx = TraceContext(request_id="req-5", actor_id="agent-3")
        self.assertEqual(
            ctx.to_env(prefix="ops"),
            {"OPS_REQUEST_ID": "req-5", "OPS_ACTOR_ID": "agent-3"},
        )
        self.assertEqual(
            ctx.to_db_settings(namespace="ops"),
            {"ops.request_id": "req-5", "ops.actor_id": "agent-3"},
        )
        self.assertEqual(
            ctx.to_log_fields(),
            {"request_id": "req-5", "actor_id": "agent-3"},
        )


if __name__ == "__main__":
    unittest.main()
