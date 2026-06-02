"""RFC8693 token exchange helpers."""

from __future__ import annotations

import base64
import json
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal


class TokenExchangeError(Exception):
    """Raised when token exchange fails."""


TokenExchangeAuthMethod = Literal["client_secret_basic", "client_secret_post"]


@dataclass(frozen=True)
class TokenExchangeConfig:
    """Configuration for token exchange."""

    token_endpoint: str
    client_id: str
    client_secret: str
    auth_method: TokenExchangeAuthMethod = "client_secret_basic"
    timeout_s: float = 5.0


@dataclass(frozen=True)
class TokenExchangeRequest:
    """Parameters for RFC8693 token exchange."""

    subject_token: str
    subject_token_type: str = "urn:ietf:params:oauth:token-type:access_token"
    actor_token: str | None = None
    actor_token_type: str | None = None
    audience: str | None = None
    resource: str | None = None
    scope: str | None = None
    requested_token_type: str = "urn:ietf:params:oauth:token-type:access_token"
    client_id: str | None = None
    extra_params: Mapping[str, str] | None = None
    require_audience_or_resource: bool = True
    allow_refresh_token: bool = False


@dataclass(frozen=True)
class TokenExchangeResponse:
    """Parsed token exchange response."""

    access_token: str
    issued_token_type: str | None = None
    token_type: str | None = None
    expires_in: int | None = None
    scope: str | None = None
    refresh_token: str | None = None


def exchange_token(config: TokenExchangeConfig, request: TokenExchangeRequest) -> TokenExchangeResponse:
    """Exchange a token via RFC8693."""

    params: dict[str, str] = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": request.subject_token,
        "subject_token_type": request.subject_token_type,
        "requested_token_type": request.requested_token_type,
    }
    if request.actor_token:
        params["actor_token"] = request.actor_token
        if request.actor_token_type:
            params["actor_token_type"] = request.actor_token_type
    if request.audience:
        params["audience"] = request.audience
    if request.resource:
        params["resource"] = request.resource
    if request.scope:
        params["scope"] = request.scope
    if request.client_id:
        params["client_id"] = request.client_id
    if request.extra_params:
        params.update(request.extra_params)

    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
    }

    if config.auth_method == "client_secret_post":
        params["client_id"] = config.client_id
        params["client_secret"] = config.client_secret
    else:
        token_bytes = f"{config.client_id}:{config.client_secret}".encode("utf-8")
        headers["authorization"] = "Basic " + base64.b64encode(token_bytes).decode("utf-8")

    payload = urllib.parse.urlencode(params).encode("utf-8")
    request_obj = urllib.request.Request(
        config.token_endpoint,
        data=payload,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(request_obj, timeout=config.timeout_s) as response:
            status = response.getcode()
            body = response.read().decode("utf-8")
    except Exception as exc:  # pragma: no cover - network failures
        raise TokenExchangeError("Token exchange request failed.") from exc

    if status < 200 or status >= 300:
        raise TokenExchangeError(f"Token exchange failed with status {status}.")

    try:
        payload_json = json.loads(body) if body else {}
    except json.JSONDecodeError as exc:
        raise TokenExchangeError("Token exchange returned invalid JSON.") from exc
    if not isinstance(payload_json, dict):
        raise TokenExchangeError("Token exchange response must be an object.")

    access_token = payload_json.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise TokenExchangeError("Token exchange response missing access_token.")

    return TokenExchangeResponse(
        access_token=access_token,
        issued_token_type=payload_json.get("issued_token_type"),
        token_type=payload_json.get("token_type"),
        expires_in=payload_json.get("expires_in"),
        scope=payload_json.get("scope"),
        refresh_token=payload_json.get("refresh_token"),
    )


def exchange_access_token(config: TokenExchangeConfig, request: TokenExchangeRequest) -> TokenExchangeResponse:
    """Policy-enforced RFC8693 helper that enforces audience/resource and disallows refresh tokens."""

    if not request.subject_token or not request.subject_token.strip():
        raise TokenExchangeError("Token exchange requires a non-empty subject_token.")
    if request.require_audience_or_resource and not (request.audience or request.resource):
        raise TokenExchangeError("Token exchange requires audience or resource.")

    response = exchange_token(config, request)
    if not request.allow_refresh_token and response.refresh_token:
        raise TokenExchangeError("Token exchange returned a refresh_token unexpectedly.")
    return response
