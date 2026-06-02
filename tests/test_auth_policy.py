import json

import pytest

from mcp_toolkit.auth_dpop import DpopConfig
from mcp_toolkit.auth_introspection import IntrospectionConfig
from mcp_toolkit.auth_policy import (
    AuthConfig,
    AuthError,
    NonAuthoritativeClaims,
    SenderConstraintConfig,
    authenticate_token,
)
from mcp_toolkit.auth_replay_guard import ReplayGuard


def test_non_authoritative_claims_filters():
    claims = NonAuthoritativeClaims.from_raw(
        {
            "sub": "user-1",
            "aud": ["mcp-toolkit", "other"],
            "client_id": "client-1",
            "exp": 123,
            "custom": "ignore",
        }
    )
    assert claims.get("aud") == ["mcp-toolkit", "other"]
    assert claims.get("client_id") == "client-1"
    assert claims.get("exp") == 123
    assert claims.get("custom") is None


def test_authenticate_token_accepts_active_tokens():
    def request_fn(_url: str, _data: bytes, _headers: dict[str, str], _timeout_s: float) -> tuple[int, str]:
        payload = {
            "active": True,
            "sub": "user-1",
            "scope": "ops:read",
            "client_id": "client-1",
            "aud": "mcp-toolkit",
            "exp": 123,
            "custom": "nope",
        }
        return 200, json.dumps(payload)

    config = AuthConfig(
        introspection=IntrospectionConfig(
            url="https://issuer.test/introspect",
            client_id="client",
            client_secret="secret",
            request_fn=request_fn,
        ),
        audience="mcp-toolkit",
    )

    decision = authenticate_token("token", config)
    assert decision.subject == "user-1"
    assert decision.scopes == ("ops:read",)
    assert decision.token_claims.get("aud") == "mcp-toolkit"


def test_authenticate_token_rejects_inactive_tokens():
    def request_fn(_url: str, _data: bytes, _headers: dict[str, str], _timeout_s: float) -> tuple[int, str]:
        payload = {"active": False, "sub": "user-1"}
        return 200, json.dumps(payload)

    config = AuthConfig(
        introspection=IntrospectionConfig(
            url="https://issuer.test/introspect",
            client_id="client",
            client_secret="secret",
            request_fn=request_fn,
        )
    )

    with pytest.raises(AuthError) as exc:
        authenticate_token("token", config)
    assert exc.value.reason == "inactive_token"


def test_authenticate_token_requires_sender_constraints():
    def request_fn(_url: str, _data: bytes, _headers: dict[str, str], _timeout_s: float) -> tuple[int, str]:
        payload = {
            "active": True,
            "sub": "user-1",
            "scope": "ops:read",
            "client_id": "client-1",
            "aud": "mcp-toolkit",
        }
        return 200, json.dumps(payload)

    config = AuthConfig(
        introspection=IntrospectionConfig(
            url="https://issuer.test/introspect",
            client_id="client",
            client_secret="secret",
            request_fn=request_fn,
        ),
        audience="mcp-toolkit",
        sender_constraints=SenderConstraintConfig(
            dpop=DpopConfig(replay_guard=ReplayGuard(ttl_seconds=10, max_entries=100))
        ),
    )

    with pytest.raises(AuthError) as exc:
        authenticate_token("token", config, request=None)
    assert exc.value.reason == "sender_constraints_missing"
