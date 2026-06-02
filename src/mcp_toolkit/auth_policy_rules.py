"""Validation rules for auth policy decisions."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .auth_errors import AuthError
from .auth_policy_claims import normalize_audience, read_string

_ALLOWED_TOKEN_TYPES = {"bearer", "at+jwt", "jwt"}


def check_token_type(value: str | None, strict: bool) -> dict[str, Any]:
    if not value:
        return {"allowed": not strict, "reason": "token_type_missing" if strict else None}
    if value.lower() not in _ALLOWED_TOKEN_TYPES:
        return {"allowed": False, "reason": "token_type_invalid"}
    return {"allowed": True}


def is_client_allowed(client_id: str, allowed_client_ids: Sequence[str]) -> bool:
    if not allowed_client_ids:
        return True
    return client_id in allowed_client_ids


def ensure_audience(payload: Mapping[str, Any], audience: str | None) -> None:
    if not audience:
        return
    aud_list = normalize_audience(payload.get("aud"))
    if not aud_list or audience not in aud_list:
        raise AuthError(
            "Invalid bearer token.",
            status=401,
            code="auth.invalid_token",
            reason="aud_mismatch" if aud_list else "aud_missing",
            hint="To fix this, request a token with the correct audience.",
        )


def ensure_issuer(payload: Mapping[str, Any], issuer: str | None) -> None:
    if not issuer:
        return
    iss = read_string(payload.get("iss"))
    if not iss or iss != issuer:
        raise AuthError(
            "Invalid bearer token.",
            status=401,
            code="auth.invalid_token",
            reason="iss_mismatch" if iss else "iss_missing",
            hint="To fix this, request a token from the correct issuer.",
        )
