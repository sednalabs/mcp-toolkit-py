"""Replay guard for token identifiers."""

from __future__ import annotations

import time
from collections.abc import Callable


class ReplayGuard:
    """Track token identifiers to prevent replay."""

    def __init__(self, ttl_seconds: int, max_entries: int, now: Callable[[], float] | None = None) -> None:
        self._ttl_s = max(1, ttl_seconds)
        self._max_entries = max(100, max_entries)
        self._now = now or time.time
        self._entries: dict[str, float] = {}

    def seen(self, token_id: str) -> bool:
        now = self._now()
        self._prune_expired(now)
        if token_id in self._entries:
            return True
        if len(self._entries) >= self._max_entries:
            self._evict_oldest()
        self._entries[token_id] = now
        return False

    def _prune_expired(self, now: float) -> None:
        expired = [key for key, ts in self._entries.items() if now - ts >= self._ttl_s]
        for key in expired:
            self._entries.pop(key, None)

    def _evict_oldest(self) -> None:
        evict_count = max(1, self._max_entries // 10)
        oldest = sorted(self._entries.items(), key=lambda item: item[1])[:evict_count]
        for key, _ts in oldest:
            self._entries.pop(key, None)
