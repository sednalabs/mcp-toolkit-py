"""Mutual TLS token binding helpers."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from .auth_errors import AuthError


@dataclass(frozen=True)
class MtlsRequest:
    client_certificate: bytes | str | None


@dataclass(frozen=True)
class MtlsConfig:
    required: bool = True


def _parse_certificate(value: bytes | str) -> bytes:
    if isinstance(value, bytes):
        return value
    trimmed = value.strip()
    if "BEGIN CERTIFICATE" in trimmed:
        lines = [line.strip() for line in trimmed.splitlines()]
        body = "".join(line for line in lines if "CERTIFICATE" not in line)
        return base64.b64decode(body.encode("utf-8"))
    return base64.b64decode(trimmed.encode("utf-8"))


def _thumbprint(cert: bytes | str) -> str:
    der = _parse_certificate(cert)
    digest = hashlib.sha256(der).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("utf-8")


def verify_mtls_binding(claims: Mapping[str, Any], request: MtlsRequest, config: MtlsConfig) -> None:
    cnf = claims.get("cnf")
    expected = None
    if isinstance(cnf, dict):
        value = cnf.get("x5t#S256")
        expected = value if isinstance(value, str) else None
    if not expected:
        if config.required:
            raise AuthError(
                "Token missing certificate binding.",
                status=401,
                code="auth.invalid_token",
                reason="mtls_missing_cnf",
                hint="To fix this, request a token bound to a client certificate.",
            )
        return
    if not request.client_certificate:
        raise AuthError(
            "Missing client certificate.",
            status=401,
            code="auth.invalid_token",
            reason="mtls_missing_cert",
            hint="To fix this, present a client certificate for mutual TLS.",
        )
    actual = _thumbprint(request.client_certificate)
    if actual != expected:
        raise AuthError(
            "Client certificate does not match token binding.",
            status=401,
            code="auth.invalid_token",
            reason="mtls_binding_mismatch",
            hint="To fix this, use the certificate bound to the access token.",
        )
