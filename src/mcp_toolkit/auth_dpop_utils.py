"""Utility helpers for DPoP proof verification."""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.parse
from typing import Any, Mapping

from .auth_errors import AuthError

try:  # pragma: no cover - handled by import guard
    import jwt
except Exception:  # pragma: no cover - handled by import guard
    jwt = None


def require_jwt() -> Any:
    if jwt is None:  # pragma: no cover
        raise RuntimeError(
            "PyJWT is required for DPoP verification. Install with `mcp-toolkit[security]`."
        )
    return jwt


def read_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    trimmed = value.strip()
    return trimmed if trimmed else None


def normalize_htu(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower() if parsed.hostname else ""
    port = parsed.port
    default_port = 443 if scheme == "https" else 80
    if port and port != default_port:
        host_port = f"{host}:{port}"
    else:
        host_port = host
    return urllib.parse.urlunsplit((scheme, host_port, parsed.path, parsed.query, ""))


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    kty = jwk.get("kty")
    if kty == "RSA":
        members = {"e": jwk.get("e"), "kty": "RSA", "n": jwk.get("n")}
    elif kty == "EC":
        members = {"crv": jwk.get("crv"), "kty": "EC", "x": jwk.get("x"), "y": jwk.get("y")}
    elif kty == "OKP":
        members = {"crv": jwk.get("crv"), "kty": "OKP", "x": jwk.get("x")}
    else:
        raise AuthError(
            "Unsupported DPoP key type.",
            status=401,
            code="auth.invalid_token",
            reason="dpop_kty_invalid",
            hint="To fix this, use a supported DPoP key type.",
        )
    payload = json.dumps(members, separators=(",", ":"), sort_keys=True).encode("utf-8")
    digest = hashlib.sha256(payload).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("utf-8")


def hash_access_token(token: str) -> str:
    digest = hashlib.sha256(token.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("utf-8")


def token_binding_jkt(claims: Mapping[str, Any]) -> str | None:
    cnf = claims.get("cnf")
    if isinstance(cnf, dict):
        jkt = cnf.get("jkt")
        return jkt if isinstance(jkt, str) else None
    return None
