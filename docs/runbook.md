# Runbook

## Purpose
Provide reusable utilities for MCP servers and clients in Python.

## Setup
- Create a virtualenv and install from a local checkout in editable mode:
  `python -m pip install -e .`
- For DPoP/mTLS helpers, install the security extra:
  `python -m pip install -e ".[security]"`
- For GitHub-based consumption before a package-index release:
  `python -m pip install "mcp-toolkit @ git+https://github.com/sednalabs/mcp-toolkit-py.git"`

## Usage
- Import modules from `mcp_toolkit`.
- This package is intended for public GitHub consumption. Package-index
  publication is a separate release decision.
- Auth helpers include RFC7662 introspection with non-authoritative claims filtering.
- Sender-constrained access tokens can be enforced via DPoP or mTLS helpers, and RFC8693 token exchange is supported for downstream access.

## Sender-constraint integration (Python)

Pass request metadata into `authenticate_token` when you enable DPoP or mTLS:

```py
from mcp_toolkit import (
    AuthConfig,
    SenderConstraintConfig,
    SenderConstraintRequest,
    DpopConfig,
    ReplayGuard,
    authenticate_token,
)

decision = authenticate_token(
    token,
    AuthConfig(
        introspection=introspection_config,
        audience=audience,
        sender_constraints=SenderConstraintConfig(
            dpop=DpopConfig(replay_guard=ReplayGuard(ttl_seconds=300, max_entries=1000)),
        ),
    ),
    request=SenderConstraintRequest(
        method=request.method,
        url=str(request.url),
        dpop_proof=request.headers.get("dpop"),
        client_certificate=request.client_certificate,
    ),
)
```

## Tests
- Run lint:
  `python -m ruff check .`
- Run tests:
  `python -m pytest -q`
