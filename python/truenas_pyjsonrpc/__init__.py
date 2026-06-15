"""truenas_pyjsonrpc — a pure-Python (msgspec) JSON-RPC 2.0 dispatch library.

Define request/response types as ``msgspec.Struct``s, declare a
:class:`JSONRPCMethod` (with a handler/callback) per method, register them on a
:class:`JSONRPCProtocol`, and call :meth:`JSONRPCProtocol.dispatch` to turn a
wire message into a handler call and a wire response. Optional
``authorization_handler``/``audit_handler`` wrap each call in an
``authorize -> dispatch -> audit`` pipeline (see :class:`AuthorizationResponse`
and :class:`JSONRPCRequest`).
"""
from .decorators import JRPCMethod, jrpc_method
from .errors import JsonRpcError
from .method import (
    FilterableJSONRPCMethod,
    JSONRPCFdPassMethod,
    JSONRPCFdTransferMethod,
    JSONRPCMethod,
)
from .query import QueryFilters, QueryOptions
from .protocol import (
    AuditRecord,
    JSONRPCProtocol,
    RequestState,
    SessionState,
    Subscription,
)
from .redaction import SECRET, redact
from .transfer import FileTransfer, Transfer, TransferDirection
from .types import (
    AuthorizationResponse,
    JSONRPCEnvelope,
    JSONRPCError,
    JSONRPCMessageType,
    JSONRPCRequest,
    MessageDirection,
    ServerInfo,
    SessionLifecycle,
)

__all__ = [
    "JSONRPCProtocol",
    "JSONRPCMethod",
    "JSONRPCFdTransferMethod",
    "JSONRPCFdPassMethod",
    "FilterableJSONRPCMethod",
    "QueryFilters",
    "QueryOptions",
    "TransferDirection",
    "FileTransfer",
    "Transfer",
    "jrpc_method",
    "JRPCMethod",
    "JSONRPCEnvelope",
    "JSONRPCRequest",
    "AuthorizationResponse",
    "ServerInfo",
    "SessionState",
    "SessionLifecycle",
    "RequestState",
    "Subscription",
    "AuditRecord",
    "SECRET",
    "redact",
    "MessageDirection",
    "JSONRPCError",
    "JSONRPCMessageType",
    "JsonRpcError",
]
