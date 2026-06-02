"""Rate limiting helpers for MCP log emission."""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class TokenBucket:
    capacity: float
    refill_rate: float
    tokens: float
    updated_at: float

    def consume(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = max(0.0, now - self.updated_at)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.updated_at = now
        if self.tokens < cost:
            return False
        self.tokens -= cost
        return True


@dataclass
class SessionCounters:
    emitted_total: int = 0
    rate_limited_total: int = 0
