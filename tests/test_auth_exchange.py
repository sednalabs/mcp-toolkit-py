import json
import urllib.request

import pytest

from mcp_toolkit.auth_exchange import (
    TokenExchangeConfig,
    TokenExchangeRequest,
    exchange_access_token,
    exchange_token,
)


def test_exchange_token(monkeypatch):
    captured = {}

    class DummyResponse:
        def __init__(self, body: str):
            self._body = body

        def getcode(self):
            return 200

        def read(self):
            return self._body.encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(request: urllib.request.Request, timeout: float):
        captured["data"] = request.data
        return DummyResponse(json.dumps({"access_token": "exchanged"}))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    result = exchange_token(
        TokenExchangeConfig(
            token_endpoint="https://issuer.test/token",
            client_id="client",
            client_secret="secret",
        ),
        TokenExchangeRequest(subject_token="subject", audience="aud"),
    )

    assert result.access_token == "exchanged"
    body = captured["data"].decode("utf-8")
    assert "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange" in body
    assert "subject_token=subject" in body


def test_exchange_access_token_requires_audience_or_resource():
    with pytest.raises(Exception) as excinfo:
        exchange_access_token(
            TokenExchangeConfig(
                token_endpoint="https://issuer.test/token",
                client_id="client",
                client_secret="secret",
            ),
            TokenExchangeRequest(subject_token="subject"),
        )
    assert "audience" in str(excinfo.value)


def test_exchange_access_token_rejects_refresh_token(monkeypatch):
    class DummyResponse:
        def __init__(self, body: str):
            self._body = body

        def getcode(self):
            return 200

        def read(self):
            return self._body.encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(request: urllib.request.Request, timeout: float):
        return DummyResponse(json.dumps({"access_token": "exchanged", "refresh_token": "nope"}))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(Exception) as excinfo:
        exchange_access_token(
            TokenExchangeConfig(
                token_endpoint="https://issuer.test/token",
                client_id="client",
                client_secret="secret",
            ),
            TokenExchangeRequest(subject_token="subject", audience="aud"),
        )
    assert "refresh" in str(excinfo.value)
