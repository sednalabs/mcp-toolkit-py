"""Shared MCP toolkit utilities."""

from .auth_dpop import DpopConfig, DpopRequest, verify_dpop_proof
from .auth_errors import AuthError
from .auth_exchange import (
    TokenExchangeConfig,
    TokenExchangeError,
    TokenExchangeRequest,
    TokenExchangeResponse,
    exchange_access_token,
    exchange_token,
)
from .auth_introspection import (
    IntrospectionClient,
    IntrospectionConfig,
    IntrospectionError,
)
from .auth_mtls import MtlsConfig, MtlsRequest, verify_mtls_binding
from .auth_policy import (
    AuthConfig,
    AuthDecision,
    NonAuthoritativeClaims,
    SenderConstraintConfig,
    SenderConstraintRequest,
    authenticate_token,
)
from .auth_replay_guard import ReplayGuard
from .auth_scopes import AuthInfoLike, has_required_scopes, missing_scopes
from .errors import (
    DownstreamForbiddenPayload,
    downstream_forbidden_payload,
    downstream_forbidden_tool_error,
    tool_error_from_payload,
)
from .logging import Logger, create_logger
from .mcp_logging import (
    MCP_LOGGING_SCHEMA,
    McpLogEmitter,
    McpLoggingConfig,
    McpLoggingLevel,
)
from .report import ProbeReport, ProbeStep, ProbeStepStatus, now_iso
from .request_id import (
    DEFAULT_REQUEST_ID_HEADERS,
    attach_request_id,
    ensure_request_id,
    extract_request_id,
)
from .trace_context import (
    DEFAULT_ACTOR_ID_HEADERS,
    TraceContext,
    extract_actor_id,
    merge_trace_context,
    trace_context_from_auth_info,
    trace_context_from_headers,
)

__all__ = [
    "AuthInfoLike",
    "AuthConfig",
    "AuthDecision",
    "AuthError",
    "DEFAULT_ACTOR_ID_HEADERS",
    "DEFAULT_REQUEST_ID_HEADERS",
    "DownstreamForbiddenPayload",
    "IntrospectionClient",
    "IntrospectionConfig",
    "IntrospectionError",
    "TokenExchangeConfig",
    "TokenExchangeRequest",
    "TokenExchangeResponse",
    "TokenExchangeError",
    "Logger",
    "MCP_LOGGING_SCHEMA",
    "McpLogEmitter",
    "McpLoggingConfig",
    "McpLoggingLevel",
    "NonAuthoritativeClaims",
    "SenderConstraintConfig",
    "SenderConstraintRequest",
    "ProbeReport",
    "ProbeStep",
    "ProbeStepStatus",
    "ReplayGuard",
    "TraceContext",
    "attach_request_id",
    "authenticate_token",
    "exchange_access_token",
    "exchange_token",
    "create_logger",
    "downstream_forbidden_payload",
    "downstream_forbidden_tool_error",
    "ensure_request_id",
    "extract_actor_id",
    "extract_request_id",
    "has_required_scopes",
    "merge_trace_context",
    "missing_scopes",
    "now_iso",
    "tool_error_from_payload",
    "trace_context_from_auth_info",
    "trace_context_from_headers",
    "DpopConfig",
    "DpopRequest",
    "verify_dpop_proof",
    "MtlsConfig",
    "MtlsRequest",
    "verify_mtls_binding",
]
