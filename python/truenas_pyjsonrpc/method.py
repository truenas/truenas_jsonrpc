"""JSONRPCMethod — a named method: request/response Struct types + handler.

A method bundles its name, a :class:`MessageDirection`, the request (``accepts``)
and result (``returns``) ``msgspec.Struct`` types, an optional pair of imperative
validators, and a handler/callback. ``accepts`` is **required** (every method is
typed); a method that takes no parameters uses an empty Struct.

Two kinds of method, by ``direction``:

- ``CLIENT_SERVER`` (default) — a normal request method: ``accepts`` is the
  request params, ``returns`` the result, ``handler`` is dispatched.
- ``SERVER_CLIENT`` — a subscribable notification topic: ``accepts`` is the
  *subscribe-request* params, ``notifies`` is the published payload schema
  (required), and there is **no handler** (the protocol registers a subscription).
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

import msgspec

from .types import MessageDirection
from .transfer import TransferDirection
from .redaction import compile_plan

_StructType = type[msgspec.Struct]


def _is_struct(value: Any) -> bool:
    return isinstance(value, type) and issubclass(value, msgspec.Struct)


def _check_returns(value: Any) -> None:
    if value is not None and not _is_struct(value):
        raise TypeError("'returns' must be a msgspec.Struct subclass or None")


def _check_callable(value: Any, which: str) -> None:
    if value is not None and not callable(value):
        raise TypeError(f"'{which}' must be callable or None")


class JSONRPCMethod:
    """One JSON-RPC method (see the module docstring for the two ``direction``s).

    For a ``CLIENT_SERVER`` method the protocol strips the JSON-RPC envelope and
    calls the handler **by keyword** as ``handler(request=params_struct,
    server_state=..., request_state=<RequestState>)`` — so a handler is
    ``def h(request, server_state, request_state)`` (or accepts ``**kwargs``);
    the return is validated/typed against ``returns``. ``handler`` may be set
    after construction (``m.handler = fn``).

    A ``SERVER_CLIENT`` method has no handler: a client subscribes by sending a
    request to it, and the server publishes payloads (validated against
    ``notifies``) via :meth:`JSONRPCProtocol.send_notification`.

    Optional ``accepts_validator``/``returns_validator`` callables run after the
    msgspec validation pass (raise to reject); cross-field rules can also live in
    the Struct's ``__post_init__``.
    """

    def __init__(self, name: str, *,
                 accepts: _StructType,
                 returns: _StructType | None = None,
                 handler: Callable[..., Any] | None = None,
                 direction: MessageDirection = MessageDirection.CLIENT_SERVER,
                 notifies: _StructType | None = None,
                 doc: str | None = None,
                 pre_auth: bool = False,
                 audit: bool = False,
                 audit_message: str | None = None,
                 cancellable: bool = False,
                 roles: Iterable[str] = (),
                 accepts_validator: Callable[[Any], Any] | None = None,
                 returns_validator: Callable[[Any], Any] | None = None) -> None:
        if not isinstance(name, str) or not name:
            raise TypeError("name must be a non-empty str")
        if not isinstance(direction, MessageDirection):
            raise TypeError("'direction' must be a MessageDirection")
        if not _is_struct(accepts):
            raise TypeError("'accepts' must be a msgspec.Struct subclass")
        if audit_message is not None and not isinstance(audit_message, str):
            raise TypeError("'audit_message' must be a str or None")
        _check_returns(returns)
        _check_callable(accepts_validator, "accepts_validator")
        _check_callable(returns_validator, "returns_validator")
        if direction is MessageDirection.SERVER_CLIENT:
            if not _is_struct(notifies):
                raise TypeError("a SERVER_CLIENT method requires 'notifies' "
                                "(a msgspec.Struct subclass)")
            if handler is not None:
                raise TypeError(
                    "a SERVER_CLIENT (subscribable) method must not have a handler")
            if cancellable:
                raise TypeError(
                    "a SERVER_CLIENT (subscribable) method cannot be 'cancellable'")
        else:
            if notifies is not None:
                raise TypeError("'notifies' is only valid for SERVER_CLIENT methods")
            _check_callable(handler, "handler")

        self.name = name
        self.direction = direction
        self.accepts = accepts
        self.returns = returns
        self.notifies = notifies
        # ``doc`` (defaults to the handler's docstring) feeds introspection/codegen.
        # ``pre_auth`` marks a method callable **before** the session is ESTABLISHED
        # (the pre-auth allowlist; see JSONRPCProtocol's session-established gate).
        # API *versioning* is done by building a separate JSONRPCProtocol per
        # version — not via per-method version tags.
        self.doc = doc if doc is not None else (handler.__doc__ if handler else None)
        self.pre_auth = pre_auth
        # ``audit`` gates whether a call is audited at all; ``audit_message`` is the
        # static per-method audit description (the middleware ``audit='...'`` analog
        # — a plain string, never interpolated, so a secret param can't leak into
        # it). A handler may append runtime detail via ``request_state.set_audit``;
        # the two are joined into the single message handed to the audit handler.
        self.audit = audit
        self.audit_message = audit_message
        # ``cancellable`` opts the method into $/cancelRequest: a per-request
        # threading.Event is created and the handler is expected to cooperate
        # (check ``request_state``). Cancelling a non-cancellable method errors.
        self.cancellable = cancellable
        # ``roles`` are role names the authorization layer may require (OR-semantics: any one
        # grants access; empty = no requirement). Metadata only — surfaced on
        # ``JSONRPCRequest.roles`` for the authorization_handler to read; the protocol does
        # **not** enforce them (it owns no role registry — that is the application's policy).
        self.roles: tuple[str, ...] = tuple(roles)
        if not all(isinstance(r, str) for r in self.roles):
            raise TypeError("'roles' must be an iterable of str")
        self.accepts_validator = accepts_validator
        self.returns_validator = returns_validator
        self._handler = handler
        # Cache the params decoder once (the hot path).
        self._param_decoder: msgspec.json.Decoder[Any] = msgspec.json.Decoder(accepts)
        # Compiled secret-redaction plans (None when no secret fields). Used by the
        # audit path; computed once here (cached by type in redaction._PLAN_CACHE).
        self._accepts_plan = compile_plan(accepts)
        self._returns_plan = compile_plan(returns) if returns is not None else None

    @property
    def handler(self) -> Callable[..., Any] | None:
        return self._handler

    @handler.setter
    def handler(self, value: Callable[..., Any] | None) -> None:
        _check_callable(value, "handler")
        if value is not None and self.direction is MessageDirection.SERVER_CLIENT:
            raise TypeError(
                "a SERVER_CLIENT (subscribable) method must not have a handler")
        self._handler = value


class JSONRPCFdTransferMethod(JSONRPCMethod):
    """A **raw-fd transfer** method (e.g. ``zfs send``/``recv`` via libzfs).

    Two callbacks instead of one handler:

    - ``negotiate(request, session_state)`` runs like a normal handler (after authz),
      validates the request, and returns an **interim** result (any JSON-serializable
      value — e.g. ``{"size": n}`` or ``True``) sent to the client as "ready"; raise
      ``JsonRpcError`` to refuse.
    - ``transfer(file_transfer)`` then receives a
      :class:`~truenas_pyjsonrpc.FileTransfer` with exclusive access to the
      connection's raw socket fd (``file_transfer.fileno()``), does the bulk stream
      (hand the fd to ``lzc_send``/``lzc_receive``, ``os.sendfile``, …), and returns
      the final result (validated against ``returns``).

    ``direction`` (a :class:`~truenas_pyjsonrpc.TransferDirection`) is ``DOWNLOAD``
    (server produces) or ``UPLOAD`` (server consumes). Transfers are only possible on
    plain or kTLS connections (the fd must carry plaintext) — see the server docs.
    """

    def __init__(self, name: str, *,
                 accepts: _StructType,
                 returns: _StructType,
                 direction: TransferDirection,
                 negotiate: Callable[..., Any],
                 transfer: Callable[..., Any],
                 accepts_validator: Callable[[Any], Any] | None = None,
                 returns_validator: Callable[[Any], Any] | None = None,
                 pre_auth: bool = False,
                 audit: bool = False,
                 audit_message: str | None = None,
                 roles: Iterable[str] = (),
                 doc: str | None = None) -> None:
        if not _is_struct(returns):
            raise TypeError("a transfer method requires 'returns' (a msgspec.Struct)")
        if not isinstance(direction, TransferDirection):
            raise TypeError("'direction' must be a TransferDirection")
        if not callable(negotiate):
            raise TypeError("'negotiate' must be callable")
        if not callable(transfer):
            raise TypeError("'transfer' must be callable")
        super().__init__(name, accepts=accepts, returns=returns, handler=None,
                         direction=MessageDirection.CLIENT_SERVER,
                         doc=doc if doc is not None else transfer.__doc__,
                         pre_auth=pre_auth, audit=audit, audit_message=audit_message,
                         roles=roles,
                         accepts_validator=accepts_validator,
                         returns_validator=returns_validator)
        self.transfer_direction = direction
        self.negotiate = negotiate
        self.transfer = transfer


class JSONRPCFdPassMethod(JSONRPCFdTransferMethod):
    """A **file-descriptor passing** method — ``SCM_RIGHTS`` over an AF_UNIX connection.

    Identical to :class:`JSONRPCFdTransferMethod`, but the ``transfer`` callback passes or
    receives **open file descriptors** with ``file_transfer.send_fds([...])`` /
    ``file_transfer.recv_fds(maxfds)`` (the peer gets new fds for the same open files)
    instead of streaming bytes. ``direction`` is ``DOWNLOAD`` (server sends fds, client
    receives) or ``UPLOAD`` (client sends, server receives); the ``negotiate`` interim
    result typically carries the fd ``count`` so the receiver can size ``recv_fds``.

    **AF_UNIX only** — ``SCM_RIGHTS`` does not exist over TCP/WebSocket/TLS, so a call over
    any other transport is rejected with ``REQUEST_FAILED``. Passing an fd grants the peer
    the open file's access mode/offset; the receiver **owns** the new fds and must close
    them.
    """
