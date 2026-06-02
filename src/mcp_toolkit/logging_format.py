"""Formatting helpers for structured logs."""

from __future__ import annotations

from datetime import datetime, timezone


def coerce_logfmt(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    text = str(value)
    return text.replace(" ", "_")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
