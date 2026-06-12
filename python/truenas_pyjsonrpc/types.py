"""Shared protocol vocabulary: enums, error codes, and the dispatch data types.

This module collects the small, dependency-free declarations the rest of the
package builds on:

- **Error codes** — :class:`JSONRPCError`, the standard JSON-RPC 2.0 codes plus
  the library/LSP-derived extensions (``NOT_AUTHORIZED``, ``REQUEST_FAILED`` …).
- **Enums** — :class:`JSONRPCMessageType` and :class:`MessageDirection`.
- **Data types** — :class:`JSONRPCEnvelope` (the permissive wire envelope used to
  parse an inbound frame), :class:`AuthorizationResponse` (the authorization
  result), :class:`JSONRPCRequest` (the request context passed to the authz/audit
  handlers), and :class:`ServerInfo` (the ``initialize`` handshake identity).
"""
from __future__ import annotations

import enum
from typing import Any

import msgspec
from msgspec import UNSET, Raw, UnsetType

# --- error codes -------------------------------------------------------------
class JSONRPCError(enum.IntEnum):
    """JSON-RPC error codes — the standard set plus the extensions this library uses.

    Three groups (all in one enum, the single source of truth — as an ``IntEnum``
    every member is usable anywhere the wire ``int`` code is expected):

    - the **standard JSON-RPC 2.0** codes;
    - ``NOT_AUTHORIZED``, a **library** code in the JSON-RPC implementation-defined
      server-error range (-32000..-32099);
    - codes **derived from the Language Server Protocol** (LSP), which reserves
      -32899..-32800 for itself and additionally defines ``ServerNotInitialized``
      (-32002).
    """
    # standard JSON-RPC 2.0
    INVALID_JSON = -32700        # "Parse error" in the spec
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603

    # library extension (JSON-RPC implementation-defined server-error range)
    #: An ``authorization_handler`` rejected the call.
    NOT_AUTHORIZED = -32000

    # LSP-derived
    #: A valid, authorized request whose operation failed for an *expected* reason —
    #: distinct from ``INTERNAL_ERROR`` (an unexpected server bug). Handlers raise
    #: ``JsonRpcError(JSONRPCError.REQUEST_FAILED, ...)``.
    REQUEST_FAILED = -32803
    #: A request that was cancelled via ``$/cancelRequest``.
    REQUEST_CANCELLED = -32800
    #: A non-``pre_auth`` method was called before the session was ESTABLISHED
    #: (or on a CLOSED session). (LSP's ServerNotInitialized code, -32002.)
    SESSION_NOT_ESTABLISHED = -32002


class SessionLifecycle(enum.StrEnum):
    """The authentication state of a connection's :class:`SessionState`.

    ``NONE`` — fresh, no setup started. ``INIT`` — setup in progress (a multi-step
    auth flow expecting ``$/sessionSetupContinue``). ``ESTABLISHED`` — authenticated;
    normal (non-``pre_auth``) methods are allowed. ``CLOSED`` — ended (client
    ``$/sessionClose`` or server-side socket drop); no further dispatch is accepted.
    A ``$/sessionSetup``/``$/sessionSetupContinue`` handler returns the next state.
    """
    NONE = "none"
    INIT = "init"
    ESTABLISHED = "established"
    CLOSED = "closed"


class JSONRPCMessageType(enum.StrEnum):
    """Classification of a JSON-RPC message."""
    REQUEST = "request"
    NOTIFICATION = "notification"
    RESPONSE = "response"
    ERROR = "error"


class MessageDirection(enum.StrEnum):
    """Which way a method's primary payload travels (sender -> receiver).

    ``CLIENT_SERVER`` (the default) is a normal request method the client calls.
    ``SERVER_CLIENT`` is a subscribable notification topic: the client subscribes
    by sending a request to it, and the server later pushes notifications to
    subscribers (see :meth:`JSONRPCProtocol.send_notification`).
    """
    CLIENT_SERVER = "client_server"
    SERVER_CLIENT = "server_client"


# --- dispatch data types -----------------------------------------------------
class JSONRPCEnvelope(msgspec.Struct):
    """The JSON-RPC message envelope, decoded **permissively**.

    Every member is typed ``object`` (or ``Raw`` for ``params``) and defaults to
    ``UNSET``, so any well-formed JSON *object* decodes successfully and each field
    is then validated in code rather than by the decoder. This is deliberate: it
    lets a parser (a) enforce this library's rules (e.g. UUID-only ids, by-name
    params) itself and (b) recover a present, valid ``id`` to echo in an error reply
    even when another field is malformed. Only malformed JSON or a non-object top
    level fails the decode itself (the latter is how a batch Array is rejected).

    Build a decoder with ``msgspec.json.Decoder(JSONRPCEnvelope)``. This is the
    primitive a transport/server layer parses inbound frames with — both the
    dispatch core and :mod:`truenas_pyjsonrpc_server` use it.
    """

    jsonrpc: object = UNSET
    method: object = UNSET
    id: object = UNSET
    params: Raw | UnsetType = UNSET


class AuthorizationResponse(msgspec.Struct):
    """The result an ``authorization_handler`` must return.

    ``authorized`` gates dispatch: when ``False`` the protocol skips the method
    handler and returns a ``NOT_AUTHORIZED`` (-32000) error built from
    ``message`` (the error message) and ``data`` (optional structured detail).
    """

    authorized: bool
    message: str = "Not authorized"
    data: Any = None


class JSONRPCRequest(msgspec.Struct, frozen=True):
    """The request context passed to the authorization and audit handlers.

    ``params`` is exactly what the method handler receives as its ``request``
    (the decoded+validated params struct), so authz/audit see the same payload
    plus the ``method`` name and request ``id`` (a UUID string, or ``None`` for
    a notification).

    ``roles`` are the dispatched method's declared roles (``JSONRPCMethod(...,
    roles=[...])``) — ``()`` for control ops or a method with no requirement. The
    authorization handler may intersect them with the session's granted roles to
    decide access; the protocol itself does not enforce them.
    """

    method: str
    id: str | None
    params: Any
    roles: tuple[str, ...] = ()


class ServerInfo(msgspec.Struct):
    """Server identity for the initialize handshake (LSP ``serverInfo``).

    A consumer composes its own ``InitializeResult`` from a ``ServerInfo`` plus
    application-defined capabilities; this component standardizes only the
    ``ServerInfo`` shape, not the capability contents.
    """

    name: str
    version: str | None = None
