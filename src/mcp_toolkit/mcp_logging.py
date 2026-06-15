"""MCP logging helpers with redaction and rate limiting.

Security:
    Redacts secret-like keys and token-like values before emitting MCP log
    notifications. Payloads are size-capped and depth-limited.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass
from threading import Lock
from typing import Any, Literal, Protocol
from weakref import WeakKeyDictionary

from .mcp_log_rate_limit import SessionCounters, TokenBucket
from .mcp_log_sanitize import MAX_LOG_PAYLOAD, sanitize_payload, scrub_text

McpLoggingLevel = Literal[
    "debug",
    "info",
    "notice",
    "warning",
    "error",
    "critical",
    "alert",
    "emergency",
]

_MCP_LEVELS: dict[McpLoggingLevel, int] = {
    "debug": 10,
    "info": 20,
    "notice": 25,
    "warning": 30,
    "error": 40,
    "critical": 50,
    "alert": 60,
    "emergency": 70,
}

_TO_CLIENT_LOGGER = logging.getLogger("mcp_toolkit.mcp_notify")


MCP_LOGGING_SCHEMA: dict[str, Any] = {
    "version": 1,
    "notes": [
        "All MCP log payloads include an `event` field.",
        "Payloads are redacted and size-capped before emission.",
    ],
    "events": [
        {
            "name": "session.initialize",
            "fields": {
                "protocol_version": "string",
                "client_name": "string",
                "client_version": "string",
            },
        },
        {"name": "session.initialized", "fields": {}},
        {"name": "session.disconnect", "fields": {"error": "boolean", "error_type": "string"}},
        {
            "name": "tool.call.start",
            "fields": {"tool_name": "string", "arg_keys": "string[]"},
        },
        {
            "name": "tool.call.error",
            "fields": {
                "tool_name": "string",
                "error": "string",
                "reason": "string",
                "retry_after_s": "number",
            },
        },
        {
            "name": "tool.call.finish",
            "fields": {"tool_name": "string", "duration_ms": "number", "error": "boolean"},
        },
        {
            "name": "discovery.tools.list.*",
            "fields": {"duration_ms": "number", "count": "number", "error": "boolean"},
        },
        {
            "name": "discovery.resources.list.*",
            "fields": {"duration_ms": "number", "count": "number", "error": "boolean"},
        },
        {
            "name": "discovery.resource_templates.list.*",
            "fields": {"duration_ms": "number", "count": "number", "error": "boolean"},
        },
        {
            "name": "discovery.prompts.list.*",
            "fields": {"duration_ms": "number", "count": "number", "error": "boolean"},
        },
        {
            "name": "resource.read.*",
            "fields": {"uri": "string", "duration_ms": "number", "error": "boolean"},
        },
        {
            "name": "resource.subscribe.*",
            "fields": {"uri": "string", "duration_ms": "number", "error": "boolean"},
        },
        {
            "name": "resource.unsubscribe.*",
            "fields": {"uri": "string", "duration_ms": "number", "error": "boolean"},
        },
        {
            "name": "prompt.render.*",
            "fields": {"prompt_name": "string", "duration_ms": "number", "error": "boolean"},
        },
    ],
}


class LogSession(Protocol):
    async def send_log_message(
        self,
        *,
        level: McpLoggingLevel,
        data: Mapping[str, Any],
        logger: str | None = None,
        related_request_id: str | None = None,
    ) -> None:
        pass


def _normalize_level(value: str) -> McpLoggingLevel:
    normalized = value.strip().lower()
    if normalized == "warn":
        return "warning"
    if normalized in _MCP_LEVELS:
        return normalized  # type: ignore[return-value]
    return "info"


def _server_cap_level(server_level: McpLoggingLevel, max_level: McpLoggingLevel) -> int:
    return max(_MCP_LEVELS[server_level], _MCP_LEVELS[max_level])


@dataclass(frozen=True)
class McpLoggingConfig:
    enabled: bool
    server_level: McpLoggingLevel
    max_level: McpLoggingLevel
    rate_limit_per_s: float = 60.0
    rate_limit_burst: int = 120
    to_client_logger: bool = False


class McpLogEmitter:
    def __init__(self, config: McpLoggingConfig) -> None:
        self.enabled = config.enabled
        self._server_cap = _server_cap_level(config.server_level, config.max_level)
        self._server_level = config.server_level
        self._max_level = config.max_level
        self._levels: WeakKeyDictionary[LogSession, McpLoggingLevel] = WeakKeyDictionary()
        self._to_client_logger = config.to_client_logger
        self._rate_limit_per_s = max(config.rate_limit_per_s, 0.0)
        self._rate_limit_burst = max(config.rate_limit_burst, 0)
        self._buckets: WeakKeyDictionary[LogSession, TokenBucket] = WeakKeyDictionary()
        self._session_ids: WeakKeyDictionary[LogSession, str] = WeakKeyDictionary()
        self._session_counters: WeakKeyDictionary[LogSession, SessionCounters] = WeakKeyDictionary()
        self._emitted_total = 0
        self._rate_limited_total = 0
        self._lock = Lock()

    @classmethod
    def disabled(cls) -> "McpLogEmitter":
        return cls(
            McpLoggingConfig(
                enabled=False,
                server_level="info",
                max_level="info",
                rate_limit_per_s=0.0,
                rate_limit_burst=0,
                to_client_logger=False,
            )
        )

    def set_level(self, session: LogSession | None, level: McpLoggingLevel) -> None:
        if not session:
            return
        self._levels[session] = _normalize_level(level)

    def register_session(self, session: LogSession | None, session_id: str | None) -> None:
        if not session or not session_id:
            return
        self._session_ids[session] = session_id
        if session not in self._session_counters:
            self._session_counters[session] = SessionCounters()

    def _consume_token(self, session: LogSession) -> bool:
        if self._rate_limit_per_s <= 0 or self._rate_limit_burst <= 0:
            return True
        bucket = self._buckets.get(session)
        if bucket is None:
            bucket = TokenBucket(
                capacity=float(self._rate_limit_burst),
                refill_rate=float(self._rate_limit_per_s),
                tokens=float(self._rate_limit_burst),
                updated_at=time.monotonic(),
            )
            self._buckets[session] = bucket
        return bucket.consume()

    def _record_emit(self, session: LogSession | None) -> None:
        with self._lock:
            self._emitted_total += 1
            if session is not None:
                counters = self._session_counters.get(session)
                if counters is None:
                    counters = SessionCounters()
                    self._session_counters[session] = counters
                counters.emitted_total += 1

    def _record_rate_limited(self, session: LogSession | None) -> None:
        with self._lock:
            self._rate_limited_total += 1
            if session is not None:
                counters = self._session_counters.get(session)
                if counters is None:
                    counters = SessionCounters()
                    self._session_counters[session] = counters
                counters.rate_limited_total += 1

    def _should_emit(self, level: McpLoggingLevel, session: LogSession | None) -> bool:
        if not self.enabled:
            return False
        if _MCP_LEVELS[level] < self._server_cap:
            return False
        if session is None:
            return False
        client_level = self._levels.get(session)
        if client_level and _MCP_LEVELS[level] < _MCP_LEVELS[client_level]:
            return False
        return True

    def _log_to_client_stream(
        self,
        *,
        level: McpLoggingLevel,
        logger_name: str | None,
        payload: Mapping[str, Any],
    ) -> None:
        if not self._to_client_logger:
            return
        payload_text = scrub_text(
            json.dumps(payload, separators=(",", ":"), ensure_ascii=True),
            limit=MAX_LOG_PAYLOAD,
        )
        _TO_CLIENT_LOGGER.log(
            _MCP_LEVELS[level],
            "MCP notification: level=%s logger=%s payload=%s",
            level,
            logger_name or "-",
            payload_text,
        )

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            emitted_total = self._emitted_total
            rate_limited_total = self._rate_limited_total
            session_rows: list[dict[str, Any]] = []
            for session, counters in list(self._session_counters.items()):
                session_id = self._session_ids.get(session)
                if not session_id:
                    continue
                session_rows.append(
                    {
                        "session_id": session_id,
                        "emitted_total": counters.emitted_total,
                        "rate_limited_total": counters.rate_limited_total,
                    }
                )
            session_rows.sort(
                key=lambda row: (row["rate_limited_total"], row["emitted_total"]),
                reverse=True,
            )
        return {
            "enabled": self.enabled,
            "server_level": self._server_level,
            "max_level": self._max_level,
            "rate_limit_per_s": self._rate_limit_per_s,
            "rate_limit_burst": self._rate_limit_burst,
            "to_client_logger": self._to_client_logger,
            "emitted_total": emitted_total,
            "rate_limited_total": rate_limited_total,
            "per_session": session_rows[:20],
        }

    async def emit(
        self,
        *,
        session: LogSession | None,
        level: McpLoggingLevel,
        message: str,
        data: Mapping[str, Any] | None = None,
        logger_name: str | None = None,
        related_request_id: str | None = None,
        context: Mapping[str, str] | None = None,
    ) -> None:
        if not self._should_emit(level, session):
            return
        if session is None:
            return
        if _MCP_LEVELS[level] < _MCP_LEVELS["error"] and not self._consume_token(session):
            self._record_rate_limited(session)
            return
        allow_stacks = self._server_cap <= _MCP_LEVELS["debug"]
        payload = sanitize_payload(message, data, allow_stacks=allow_stacks, context=context)
        try:
            await session.send_log_message(
                level=level,
                data=payload,
                logger=logger_name,
                related_request_id=related_request_id,
            )
            self._record_emit(session)
            self._log_to_client_stream(level=level, logger_name=logger_name, payload=payload)
        except Exception:  # noqa: BLE001
            _TO_CLIENT_LOGGER.debug("Failed to emit MCP log message.", exc_info=True)
