"""Scope evaluation helpers for MCP access control.

Security:
    Centralizes scope checks to enforce least-privilege access decisions.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol


class AuthInfoLike(Protocol):
    """Protocol describing auth scope holders.

    Attributes:
        scopes: Sequence of granted scopes.

    Security:
        Assumes scopes are already validated by the upstream auth provider.
    """

    scopes: Sequence[str]


def missing_scopes(required_scopes: Sequence[str], granted_scopes: Sequence[str]) -> list[str]:
    """Return required scopes that are not granted.

    Args:
        required_scopes: Required scope values.
        granted_scopes: Granted scope values.

    Returns:
        List of missing scopes.

    Security:
        Used to enforce least-privilege access decisions.
    """

    if not required_scopes:
        return []
    granted = set(granted_scopes)
    return [scope for scope in required_scopes if scope not in granted]


def has_required_scopes(auth_info: AuthInfoLike | None, required_scopes: Sequence[str]) -> bool:
    """Check whether auth info includes all required scopes.

    Args:
        auth_info: Auth info containing scopes, if available.
        required_scopes: Scopes that must be present.

    Returns:
        True if all required scopes are granted.

    Security:
        Returns False if auth info is missing or scopes are insufficient.
    """

    if not required_scopes:
        return True
    if auth_info is None:
        return False
    return len(missing_scopes(required_scopes, auth_info.scopes)) == 0
