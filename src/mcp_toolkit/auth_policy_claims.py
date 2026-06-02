"""Claim parsing helpers for auth policy."""

from __future__ import annotations

from typing import Any, Mapping


def read_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    trimmed = value.strip()
    return trimmed if trimmed else None


def read_string_list(value: Any) -> list[str] | None:
    if not isinstance(value, (list, tuple)):
        return None
    filtered = [str(entry).strip() for entry in value if str(entry).strip()]
    return filtered if filtered else None


def normalize_audience(value: Any) -> list[str]:
    list_value = read_string_list(value)
    if list_value is not None:
        return list_value
    string_value = read_string(value)
    return [string_value] if string_value else []


def read_client_id(payload: Mapping[str, Any]) -> str:
    audience = normalize_audience(payload.get("aud"))
    return (
        read_string(payload.get("azp"))
        or read_string(payload.get("client_id"))
        or (audience[0] if audience else None)
        or "unknown"
    )


def extract_scopes(payload: Mapping[str, Any]) -> list[str]:
    raw = payload.get("scope") or payload.get("scp") or payload.get("scopes")
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        return [str(entry) for entry in raw if str(entry)]
    return [scope for scope in str(raw).split() if scope]


def extract_roles(payload: Mapping[str, Any]) -> list[str]:
    roles: list[str] = []
    realm_access = payload.get("realm_access")
    if isinstance(realm_access, dict):
        values = realm_access.get("roles")
        if isinstance(values, list):
            roles.extend(str(entry) for entry in values if str(entry))
    resource_access = payload.get("resource_access")
    if isinstance(resource_access, dict):
        for entry in resource_access.values():
            if not isinstance(entry, dict):
                continue
            values = entry.get("roles")
            if isinstance(values, list):
                roles.extend(str(value) for value in values if str(value))
    return sorted(set(roles))
