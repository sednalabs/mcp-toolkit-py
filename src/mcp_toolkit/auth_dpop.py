"""DPoP proof verification."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .auth_dpop_utils import (
    hash_access_token,
    jwk_thumbprint,
    normalize_htu,
    read_string,
    require_jwt,
    token_binding_jkt,
)
from .auth_errors import AuthError
from .auth_replay_guard import ReplayGuard


@dataclass(frozen=True)
class DpopRequest:
    method: str
    url: str
    proof: str | None
    nonce: str | None = None


@dataclass(frozen=True)
class DpopConfig:
    replay_guard: ReplayGuard
    required: bool = True
    allowed_algorithms: Sequence[str] = ("ES256",)
    max_clock_skew_seconds: int = 300
    require_ath: bool = True


def verify_dpop_proof(
    claims: Mapping[str, Any],
    access_token: str,
    request: DpopRequest,
    config: DpopConfig,
) -> None:
    proof = request.proof
    if not proof:
        if config.required:
            raise AuthError(
                "Missing DPoP proof.",
                status=401,
                code="auth.invalid_token",
                reason="dpop_missing_proof",
                hint="To fix this, include a DPoP header.",
            )
        return

    jwt_module = require_jwt()
    header = jwt_module.get_unverified_header(proof)
    typ = header.get("typ")
    if typ and isinstance(typ, str) and typ.lower() != "dpop+jwt":
        raise AuthError(
            "Invalid DPoP proof type.",
            status=401,
            code="auth.invalid_token",
            reason="dpop_invalid_typ",
            hint="To fix this, set typ to dpop+jwt.",
        )
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise AuthError(
            "DPoP proof missing jwk.",
            status=401,
            code="auth.invalid_token",
            reason="dpop_missing_jwk",
            hint="To fix this, include a public JWK in the DPoP header.",
        )
    if "d" in jwk:
        raise AuthError(
            "DPoP proof jwk must be public.",
            status=401,
            code="auth.invalid_token",
            reason="dpop_private_jwk",
            hint="To fix this, include only the public JWK in the DPoP header.",
        )
    alg = header.get("alg")
    if not alg:
        raise AuthError(
            "DPoP proof missing alg.",
            status=401,
            code="auth.invalid_token",
            reason="dpop_missing_alg",
            hint="To fix this, include alg in the DPoP header.",
        )
    if alg not in config.allowed_algorithms:
        raise AuthError(
            "DPoP proof algorithm is not allowed.",
            status=401,
            code="auth.invalid_token",
            reason="dpop_alg_not_allowed",
            hint="To fix this, use an allowed DPoP algorithm.",
        )

    key = jwt_module.algorithms.get_default_algorithms()[alg].from_jwk(json.dumps(jwk))
    payload = jwt_module.decode(
        proof,
        key=key,
        algorithms=[alg],
        options={"verify_aud": False, "verify_iss": False},
    )

    htm = read_string(payload.get("htm"))
    htu = read_string(payload.get("htu"))
    jti = read_string(payload.get("jti"))
    iat = payload.get("iat")
    if not htm or not htu or not jti or not isinstance(iat, (int, float)):
        raise AuthError(
            "DPoP proof missing required claims.",
            status=401,
            code="auth.invalid_token",
            reason="dpop_missing_claims",
            hint="To fix this, include htm, htu, iat, and jti in the DPoP proof.",
        )

    if htm.upper() != request.method.upper():
        raise AuthError(
            "DPoP proof method mismatch.",
            status=401,
            code="auth.invalid_token",
            reason="dpop_htm_mismatch",
            hint="To fix this, ensure the DPoP htm matches the request method.",
        )

    if normalize_htu(htu) != normalize_htu(request.url):
        raise AuthError(
            "DPoP proof URL mismatch.",
            status=401,
            code="auth.invalid_token",
            reason="dpop_htu_mismatch",
            hint="To fix this, ensure the DPoP htu matches the request URL.",
        )

    now = time.time()
    if iat > now + config.max_clock_skew_seconds or iat < now - config.max_clock_skew_seconds:
        raise AuthError(
            "DPoP proof is outside the allowed time window.",
            status=401,
            code="auth.invalid_token",
            reason="dpop_iat_skew",
            hint="To fix this, ensure the DPoP iat is within the server time window.",
        )

    if config.replay_guard.seen(jti):
        raise AuthError(
            "DPoP proof replay detected.",
            status=401,
            code="auth.replay_detected",
            reason="dpop_replay",
            hint="To fix this, use a fresh DPoP proof.",
        )

    if request.nonce and payload.get("nonce") != request.nonce:
        raise AuthError(
            "DPoP proof nonce mismatch.",
            status=401,
            code="auth.invalid_token",
            reason="dpop_nonce_mismatch",
            hint="To fix this, include the provided DPoP nonce.",
        )

    jkt = token_binding_jkt(claims)
    if not jkt:
        raise AuthError(
            "Token missing DPoP binding.",
            status=401,
            code="auth.invalid_token",
            reason="dpop_missing_cnf",
            hint="To fix this, request a DPoP-bound access token.",
        )
    if jwk_thumbprint(jwk) != jkt:
        raise AuthError(
            "DPoP key mismatch.",
            status=401,
            code="auth.invalid_token",
            reason="dpop_jkt_mismatch",
            hint="To fix this, use the key bound to the access token.",
        )

    ath = read_string(payload.get("ath"))
    if config.require_ath and not ath:
        raise AuthError(
            "DPoP proof missing ath.",
            status=401,
            code="auth.invalid_token",
            reason="dpop_missing_ath",
            hint="To fix this, include the access token hash in ath.",
        )
    if ath and ath != hash_access_token(access_token):
        raise AuthError(
            "DPoP proof access token hash mismatch.",
            status=401,
            code="auth.invalid_token",
            reason="dpop_ath_mismatch",
            hint="To fix this, ensure ath matches the access token.",
        )
