"""# OAuth 2.0 Token Introspection

Implements RFC 7662 token introspection for high-assurance MCP servers.

## Rationale
Enables servers to verify the validity, scope, and expiration of access tokens
in real-time by querying the authorization server. This is critical for supporting
revocation-aware security models.

## Security Boundaries
* **Credential Isolation**: Uses confidential client credentials to authenticate to the IdP.
* **Cache Integrity**: Keys introspection results by a cryptographic hash of the token.
* **Time Sensitivity**: Automatically purges expired cache entries.

## References
* **SPEC**: [RFC 7662 (OAuth 2.0 Token Introspection)](https://oauth.net/2/token-introspection/)
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

IntrospectionAuthMethod = Literal["client_secret_basic", "client_secret_post"]
RequestFn = Callable[[str, bytes, Mapping[str, str], float], tuple[int, str]]


class IntrospectionError(Exception):
    """Raised when introspection fails or returns invalid data."""


@dataclass(frozen=True)
class IntrospectionConfig:
    """Configuration for token introspection."""

    url: str
    client_id: str
    client_secret: str
    auth_method: IntrospectionAuthMethod = "client_secret_basic"
    timeout_s: float = 5.0
    cache_ttl_s: float = 0.0
    cache_max_entries: int = 1000
    now: Callable[[], float] | None = None
    request_fn: RequestFn | None = None


@dataclass
class _CacheEntry:
    value: dict[str, Any]
    expires_at: float
    created_at: float


class _IntrospectionCache:
    def __init__(self, ttl_s: float, max_entries: int, now: Callable[[], float]) -> None:
        self._ttl_s = max(0.0, ttl_s)
        self._max_entries = max(0, max_entries)
        self._now = now
        self._entries: dict[str, _CacheEntry] = {}

    def get(self, key: str) -> dict[str, Any] | None:
        if self._ttl_s <= 0:
            return None
        entry = self._entries.get(key)
        if not entry:
            return None
        now = self._now()
        if entry.expires_at <= now:
            self._entries.pop(key, None)
            return None
        return entry.value

    def set(self, key: str, value: dict[str, Any], expires_at: float) -> None:
        if self._ttl_s <= 0:
            return
        now = self._now()
        if expires_at <= now:
            return
        if self._max_entries and len(self._entries) >= self._max_entries:
            self._evict_oldest()
        self._entries[key] = _CacheEntry(value=value, expires_at=expires_at, created_at=now)

    def _evict_oldest(self) -> None:
        if not self._entries:
            return
        evict_count = max(1, len(self._entries) // 10)
        oldest = sorted(self._entries.items(), key=lambda item: item[1].created_at)[:evict_count]
        for key, _entry in oldest:
            self._entries.pop(key, None)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _default_request(url: str, data: bytes, headers: Mapping[str, str], timeout_s: float) -> tuple[int, str]:
    request = urllib.request.Request(url, data=data, headers=dict(headers), method="POST")
    with urllib.request.urlopen(request, timeout=timeout_s) as response:
        status = response.getcode()
        body = response.read().decode("utf-8")
    return status, body


class IntrospectionClient:
    """Introspect access tokens using RFC7662."""

    def __init__(self, config: IntrospectionConfig) -> None:
        self._config = config
        now = config.now or time.time
        self._cache = _IntrospectionCache(config.cache_ttl_s, config.cache_max_entries, now)
        self._request = config.request_fn or _default_request

    def introspect(self, token: str) -> dict[str, Any]:
        cache_key = _hash_token(token)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        headers = {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
        }
        params = {
            "token": token,
            "token_type_hint": "access_token",
        }
        if self._config.auth_method == "client_secret_post":
            params["client_id"] = self._config.client_id
            params["client_secret"] = self._config.client_secret
        else:
            token_bytes = f"{self._config.client_id}:{self._config.client_secret}".encode("utf-8")
            headers["authorization"] = "Basic " + base64.b64encode(token_bytes).decode("utf-8")

        payload = urllib.parse.urlencode(params).encode("utf-8")
        status, body = self._request(self._config.url, payload, headers, self._config.timeout_s)
        if status < 200 or status >= 300:
            raise IntrospectionError(f"Introspection failed with status {status}.")
        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise IntrospectionError("Introspection returned invalid JSON.") from exc
        if not isinstance(data, dict):
            raise IntrospectionError("Introspection payload must be an object.")

        ttl_s = max(0.0, self._config.cache_ttl_s)
        if ttl_s > 0:
            now = self._config.now or time.time
            expires_at = now() + ttl_s
            exp = data.get("exp")
            if isinstance(exp, (int, float)):
                expires_at = min(expires_at, float(exp))
            self._cache.set(cache_key, data, expires_at)

        return data
