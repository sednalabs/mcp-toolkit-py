"""# Auth Policy Module

High-level authorization rules and token validation for MCP servers.

## Rationale
Centralizes the decision-making logic for token validation, including issuer/audience
checks, scope extraction, and replay protection. It provides a stable `AuthDecision`
interface used across the toolkit.

## Security Boundaries
* **Introspection**: Validates tokens against the authorization server (IdP).
* **Policy Rules**: Enforces strict audience, issuer, and client allow-listing.
* **Replay Protection**: Optional JTI-based replay prevention.

## References
* **SPEC**: [OAuth 2.0 (RFC 6749)](https://oauth.net/2/)
* **SPEC**: [OAuth 2.0 Token Introspection (RFC 7662)](https://oauth.net/2/token-introspection/)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .auth_errors import AuthError
from .auth_introspection import (
    IntrospectionClient,
    IntrospectionConfig,
    IntrospectionError,
)
from .auth_policy_claims import (
    extract_roles,
    extract_scopes,
    read_client_id,
    read_string,
    read_string_list,
)
from .auth_policy_rules import (
    check_token_type,
    ensure_audience,
    ensure_issuer,
    is_client_allowed,
)
from .auth_replay_guard import ReplayGuard
from .auth_sender_constraints import (
    SenderConstraintConfig,
    SenderConstraintRequest,
    verify_sender_constraints,
)

_ALLOWED_CLAIMS = {
    "aud",
    "exp",
    "iss",
    "azp",
    "client_id",
    "resource",
    "token_type",
    "typ",
}


@dataclass(frozen=True)
class NonAuthoritativeClaims:
    """Filtered claims that are safe for routing/diagnostics."""

    _claims: Mapping[str, Any]

    @classmethod
    def from_raw(cls, raw: Mapping[str, Any]) -> "NonAuthoritativeClaims":
        filtered: dict[str, Any] = {}
        for key in _ALLOWED_CLAIMS:
            value = raw.get(key)
            if key in {"aud", "resource"}:
                filtered_value = read_string_list(value) or read_string(value)
            elif key == "exp":
                filtered_value = value if isinstance(value, (int, float)) else None
            else:
                filtered_value = read_string(value)
            if filtered_value is not None:
                filtered[key] = filtered_value
        return cls(filtered)

    def get(self, name: str) -> Any | None:
        return self._claims.get(name)

    def to_dict(self) -> dict[str, Any]:
        return dict(self._claims)


@dataclass(frozen=True)
class AuthDecision:
    """Normalized auth decision returned by token validation."""

    subject: str
    client_id: str
    scopes: tuple[str, ...]
    roles: tuple[str, ...]
    expires_at: int | None
    token_claims: NonAuthoritativeClaims


@dataclass(frozen=True)
class AuthConfig:
    """Auth configuration for token validation."""

    introspection: IntrospectionConfig
    audience: str | None = None
    issuer: str | None = None
    allowed_client_ids: Sequence[str] = ()
    strict_token_type: bool = False
    replay_guard: ReplayGuard | None = None
    sender_constraints: SenderConstraintConfig | None = None


def authenticate_token(
    token: str,
    config: AuthConfig,
    request: SenderConstraintRequest | None = None,
) -> AuthDecision:
    """Validate a token and return an authorization decision.

    # Security
    * **Introspection**: Calls the authorization server to verify token activity.
    * **Replay**: Checks the JTI against the replay guard if configured.
    * **Sender Constraints**: Verifies DPoP or other bindings if requested.
    """
    client = IntrospectionClient(config.introspection)
    try:
        payload = client.introspect(token)
    except IntrospectionError as exc:
        raise AuthError(
            "Token introspection failed.",
            status=401,
            code="auth.introspection_failed",
            reason="introspection_failed",
            hint="To fix this, verify the authorization server is reachable.",
        ) from exc

    active = payload.get("active")
    if active is not True and str(active).lower() != "true":
        raise AuthError(
            "Token is inactive.",
            status=401,
            code="auth.invalid_token",
            reason="inactive_token",
            hint="To fix this, refresh the access token and retry.",
        )

    ensure_audience(payload, config.audience)
    ensure_issuer(payload, config.issuer)

    token_type = read_string(payload.get("typ")) or read_string(payload.get("token_type"))
    type_check = check_token_type(token_type, config.strict_token_type)
    if not type_check["allowed"]:
        raise AuthError(
            "Invalid token type.",
            status=401,
            code="auth.invalid_token",
            reason=type_check.get("reason", "token_type_invalid"),
            hint="To fix this, use Bearer/at+jwt tokens or disable strict token type enforcement.",
        )

    subject = read_string(payload.get("sub")) or read_string(payload.get("username"))
    if not subject:
        raise AuthError(
            "Token missing subject.",
            status=401,
            code="auth.invalid_token",
            reason="missing_subject",
            hint="To fix this, ensure the token includes a non-empty subject (sub) claim.",
        )

    if config.replay_guard:
        jti = read_string(payload.get("jti"))
        if not jti:
            raise AuthError(
                "Token missing jti.",
                status=401,
                code="auth.invalid_token",
                reason="missing_jti",
                hint="To fix this, include a unique jti claim or disable replay protection.",
            )
        if config.replay_guard.seen(jti):
            raise AuthError(
                "Token replay detected.",
                status=401,
                code="auth.replay_detected",
                reason="replay_detected",
                hint="To fix this, request a fresh token with a new jti.",
            )

    client_id = read_client_id(payload)
    if not is_client_allowed(client_id, config.allowed_client_ids):
        raise AuthError(
            "Token client is not allowed.",
            status=403,
            code="auth.client_not_allowed",
            reason="client_not_allowed",
            hint="To fix this, use an allowed client_id or update the allowlist.",
        )

    verify_sender_constraints(payload, token, config.sender_constraints, request)
    scopes = extract_scopes(payload)
    roles = extract_roles(payload)
    exp = payload.get("exp")
    expires_at = int(exp) if isinstance(exp, (int, float)) else None

    return AuthDecision(
        subject=subject,
        client_id=client_id,
        scopes=tuple(scopes),
        roles=tuple(roles),
        expires_at=expires_at,
        token_claims=NonAuthoritativeClaims.from_raw(payload),
    )
