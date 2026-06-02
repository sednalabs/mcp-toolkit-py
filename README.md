# mcp-toolkit (Python)

Shared utilities for MCP servers/clients. This repository intentionally starts small
and focuses on stable, reusable primitives (e.g., probe report schema, trace context)
that can be consumed across projects.

## Included utilities
- Scope checks, logging helpers, and trace context utilities.
- Opinionated auth policy helpers based on RFC7662 introspection and non-authoritative claims.
- Optional sender-constrained token helpers (DPoP/mTLS) and RFC8693 token exchange support.

## Docs
- Runbook: `docs/runbook.md`
- Auth philosophy: `docs/auth-philosophy.md`

## Development

Install from a local checkout:

```bash
python -m pip install -e ".[security]"
```

Install directly from GitHub:

```bash
python -m pip install "mcp-toolkit @ git+https://github.com/sednalabs/mcp-toolkit-py.git"
```

Run tests:

```bash
python -m pytest -q
```

Run lint:

```bash
python -m ruff check .
```

## Security extras

Install sender-constrained token helpers (DPoP/mTLS) with:

```bash
python -m pip install "mcp-toolkit[security]"
```
