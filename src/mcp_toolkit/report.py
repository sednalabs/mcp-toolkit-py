"""Probe report schema shared across MCP probe implementations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

ProbeStepStatus = Literal["ok", "error"]


@dataclass(frozen=True)
class ProbeStep:
    """Single probe step outcome."""

    name: str
    status: ProbeStepStatus
    detail: str | None = None
    data: Any | None = None


@dataclass(frozen=True)
class ProbeReport:
    """Aggregated probe report."""

    ok: bool
    started_at: str
    finished_at: str
    steps: list[ProbeStep]
    auth: Any | None = None
    server_info: Any | None = None
    capabilities: Any | None = None
    tools: Any | None = None
    resources: Any | None = None
    prompts: Any | None = None


def now_iso() -> str:
    """Return an ISO-8601 UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()
