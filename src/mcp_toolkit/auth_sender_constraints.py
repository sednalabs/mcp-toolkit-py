"""Sender constraint checks for auth policy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .auth_dpop import DpopConfig, DpopRequest, verify_dpop_proof
from .auth_errors import AuthError
from .auth_mtls import MtlsConfig, MtlsRequest, verify_mtls_binding


@dataclass(frozen=True)
class SenderConstraintRequest:
    """Request metadata for sender-constrained tokens."""

    method: str
    url: str
    dpop_proof: str | None = None
    dpop_nonce: str | None = None
    client_certificate: bytes | str | None = None


@dataclass(frozen=True)
class SenderConstraintConfig:
    """Configuration for sender-constrained token checks."""

    dpop: DpopConfig | None = None
    mtls: MtlsConfig | None = None


def verify_sender_constraints(
    payload: Mapping[str, Any],
    token: str,
    config: SenderConstraintConfig | None,
    request: SenderConstraintRequest | None,
) -> None:
    if not config:
        return
    if not request:
        if (config.dpop and config.dpop.required) or (config.mtls and config.mtls.required):
            raise AuthError(
                "Sender-constrained token required.",
                status=401,
                code="auth.invalid_token",
                reason="sender_constraints_missing",
                hint="To fix this, include DPoP proof or mutual TLS credentials.",
            )
        return
    if config.dpop:
        verify_dpop_proof(
            payload,
            token,
            DpopRequest(
                method=request.method,
                url=request.url,
                proof=request.dpop_proof,
                nonce=request.dpop_nonce,
            ),
            config.dpop,
        )
    if config.mtls:
        verify_mtls_binding(payload, MtlsRequest(client_certificate=request.client_certificate), config.mtls)
