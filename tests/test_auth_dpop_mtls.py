import base64
import hashlib
import importlib
import time

import pytest

jwt = pytest.importorskip("jwt")
pytest.importorskip("cryptography")
ec = importlib.import_module("cryptography.hazmat.primitives.asymmetric.ec")


def _b64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("utf-8")


def _hash_access_token(token: str) -> str:
    digest = hashlib.sha256(token.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("utf-8")


def _jwk_thumbprint(jwk: dict[str, str]) -> str:
    payload = f'{{"crv":"{jwk["crv"]}","kty":"{jwk["kty"]}","x":"{jwk["x"]}","y":"{jwk["y"]}"}}'
    digest = hashlib.sha256(payload.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("utf-8")


def test_dpop_proof_verification_and_replay():
    from mcp_toolkit.auth_dpop import DpopConfig, DpopRequest, verify_dpop_proof
    from mcp_toolkit.auth_errors import AuthError
    from mcp_toolkit.auth_replay_guard import ReplayGuard

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url_uint(numbers.x),
        "y": _b64url_uint(numbers.y),
    }
    jkt = _jwk_thumbprint(jwk)
    access_token = "access-token"
    payload = {
        "htm": "POST",
        "htu": "https://example.test/mcp",
        "iat": int(time.time()),
        "jti": "jti-1",
        "ath": _hash_access_token(access_token),
    }
    proof = jwt.encode(payload, private_key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": jwk})

    guard = ReplayGuard(ttl_seconds=10, max_entries=100)
    verify_dpop_proof(
        {"cnf": {"jkt": jkt}},
        access_token,
        DpopRequest(method="POST", url="https://example.test/mcp", proof=proof),
        DpopConfig(replay_guard=guard),
    )

    with pytest.raises(AuthError) as exc:
        verify_dpop_proof(
            {"cnf": {"jkt": jkt}},
            access_token,
            DpopRequest(method="POST", url="https://example.test/mcp", proof=proof),
            DpopConfig(replay_guard=guard),
        )
    assert exc.value.reason == "dpop_replay"


def test_mtls_binding():
    from mcp_toolkit.auth_mtls import MtlsConfig, MtlsRequest, verify_mtls_binding

    cert_bytes = b"cert-bytes"
    thumb = base64.urlsafe_b64encode(hashlib.sha256(cert_bytes).digest()).rstrip(b"=").decode("utf-8")
    verify_mtls_binding(
        {"cnf": {"x5t#S256": thumb}},
        MtlsRequest(client_certificate=cert_bytes),
        MtlsConfig(required=True),
    )
