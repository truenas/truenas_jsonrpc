"""JSONRPCProtocol — a name-keyed dispatch table + the dispatch pipeline.

``dispatch(wire, session)`` handles a single JSON-RPC Request object (batch /
top-level Arrays are intentionally **not** supported and are rejected as Invalid
Request) and runs, per message:
  1. parse the wire and validate the JSON-RPC envelope. A request ``id``, if
     present, MUST be a UUID string (a refinement of the spec); a message with no
     ``id`` is a notification and produces no reply.
  2. strip the envelope and decode+validate the params into the method's
     ``accepts`` Struct (params are by-name objects only)
  3. run the **authorize -> dispatch -> audit** pipeline; the handler is called by
     keyword as ``handler(request=<params>, session_state=<SessionState>,
     request_state=<RequestState>)``
  4. rebuild the response envelope carrying the request's id

Per-connection context is a :class:`SessionState` (created via
:meth:`JSONRPCProtocol.new_session`, held by the server, passed to every
``dispatch``). It carries a protocol-generated ``session_uuid``, the protocol
``name``, a :class:`SessionLifecycle`, and the opaque ``server_state_internal`` /
``server_state_external``. When session setup is configured
(:meth:`add_session_setup`), normal methods require an ESTABLISHED session;
authentication is performed via the ``$/sessionSetup`` / ``$/sessionSetupContinue``
control requests (``$/sessionClose`` ends the session).

**Server→client** traffic (progress, events) is built and enqueued on an internal
outbound queue via :meth:`send_notification` (and, for progress,
``request_state.update_progress(...)``) and consumed by the server's own
notification thread through :meth:`poll_notification` — that thread, running
concurrently, delivers progress live. When a request completes, any of *its*
notifications still queued (undelivered) are dropped as superseded by the
response, so progress never arrives after the reply.

The dispatch state machine is **synchronous** and a single ``JSONRPCProtocol`` is
safe for concurrent use by multiple threads: the dispatch table is read-only once
configured, and the outbound queue + in-flight registry are guarded by a single
``threading.Condition``. A single connection's ``SessionState`` is expected to be
driven sequentially (don't pipeline a session's own messages during setup).
"""
from __future__ import annotations

import queue
import threading
import uuid
from collections import deque
from collections.abc import Callable, Iterable
from typing import Any, NamedTuple

import msgspec
from msgspec import UNSET, Raw

from .redaction import redact
from .types import (
    AuthorizationResponse,
    JSONRPCEnvelope,
    JSONRPCError,
    JSONRPCRequest,
    MessageDirection,
    SessionLifecycle,
)
from .errors import JsonRpcError
from .method import JSONRPCFdPassMethod, JSONRPCFdTransferMethod, JSONRPCMethod
from .transfer import FileTransfer, Transfer, TransferDirection

_VERSION = "2.0"
_EMPTY = Raw(b"{}")
_PROGRESS_METHOD = "$/progress"
_CANCEL_METHOD = "$/cancelRequest"
_SERVERINFO_METHOD = "$/serverInfo"
_SESSION_SETUP_METHOD = "$/sessionSetup"
_SESSION_SETUP_CONTINUE_METHOD = "$/sessionSetupContinue"
_SESSION_CLOSE_METHOD = "$/sessionClose"
#: Server-layer control messages for a raw-fd transfer (handled by the server, not
#: this dispatch core — like $/negotiate). $/transferReady: server -> client "ready".
#: $/transferGo: client -> server "consumer paused its reader, start" (download only).
_TRANSFER_READY_METHOD = "$/transferReady"
_TRANSFER_GO_METHOD = "$/transferGo"


class _CancelParams(msgspec.Struct):
    target_id: str


class _Pending(NamedTuple):
    """An outbound message waiting to be drained. ``request_id`` is the request a
    progress message correlates to (``None`` for a plain notification) — used to
    purge a completed request's pending messages; ``session`` is the routing target
    (the :class:`SessionState`) the drain thread delivers to."""
    session: Any
    request_id: str | None
    data: bytes


class Subscription(NamedTuple):
    """A registered subscription to a SERVER_CLIENT topic: its ``id`` (the sub id),
    the ``session_state`` captured at subscribe time (the routing + ownership target),
    and the decoded subscribe-request ``params``.

    Passed to the ``authorization_handler`` as ``target=`` when a ``$/cancelRequest``
    targets a subscription (the session-scoped-cancel analog of a ``RequestState``)."""
    id: str
    session_state: Any
    params: Any


class _AuditJob(NamedTuple):
    """A queued audit job (raw — redaction + message assembly are deferred to
    :meth:`poll_audit`). ``method`` supplies the redaction plans and the static
    ``audit_message``; ``detail`` is the runtime detail captured from the request's
    :class:`RequestState` (``None`` for control ops without a method)."""
    handler: Callable[..., Any]
    request: JSONRPCRequest
    response: dict[str, Any]
    session_state: Any
    method: "JSONRPCMethod | None"
    detail: str | None


class AuditRecord:
    """A ready-to-run audit record returned by :meth:`JSONRPCProtocol.poll_audit`.
    ``request``/``response`` are already secret-redacted and ``audit_message`` is
    the assembled human-readable description (or ``None``); :meth:`run` invokes the
    audit handler (swallowing exceptions so a faulty handler can't kill the drain
    thread)."""

    __slots__ = ("handler", "request", "response", "session_state", "audit_message")

    def __init__(self, handler: Callable[..., Any], request: JSONRPCRequest,
                 response: dict[str, Any], session_state: Any,
                 audit_message: str | None = None) -> None:
        self.handler = handler
        self.request = request
        self.response = response
        self.session_state = session_state
        self.audit_message = audit_message

    def run(self) -> None:
        try:
            self.handler(request=self.request, response=self.response,
                         session_state=self.session_state,
                         audit_message=self.audit_message)
        except Exception:
            pass


_ENV_DEC = msgspec.json.Decoder(JSONRPCEnvelope)
_CANCEL_DEC = msgspec.json.Decoder(_CancelParams)
_ENC = msgspec.json.Encoder()


def _is_uuid(value: str) -> bool:
    """True if ``value`` is a canonical hyphenated UUID string (case-insensitive)."""
    try:
        return str(uuid.UUID(value)) == value.lower()
    except ValueError:
        return False


class SessionState:
    """Per-connection context, created by :meth:`JSONRPCProtocol.new_session` and
    passed to every :meth:`JSONRPCProtocol.dispatch`. **Never** serialized to the
    wire.

    ``session_uuid`` (protocol-generated) uniquely identifies the connection;
    ``protocol_name`` is the owning protocol's ``name``; ``lifecycle`` tracks
    authentication state (:class:`SessionLifecycle`). The opaque user state is
    split: ``server_state_internal`` is server-side only (the connection handle and
    the authenticated identity/permissions — what handlers and the authorization
    handler read), seeded at :meth:`new_session` and typically enriched by a
    ``$/sessionSetup`` handler; ``server_state_external`` is the client-facing data
    surfaced in session-setup replies.
    """

    __slots__ = ("session_uuid", "protocol_name", "lifecycle",
                 "server_state_internal", "server_state_external")

    def __init__(self, session_uuid: str, protocol_name: str | None,
                 server_state_internal: Any = None) -> None:
        self.session_uuid = session_uuid
        self.protocol_name = protocol_name
        self.lifecycle: SessionLifecycle = SessionLifecycle.NONE
        self.server_state_internal = server_state_internal
        self.server_state_external: Any = None


class RequestState:
    """Per-request context, injected into a handler as ``request_state=``.

    Holds the originating request ``id`` (a UUID, or ``None`` for a notification),
    the request's ``session_state`` (the routing target), a back-reference to the
    protocol, and ``count`` — the number of notifications emitted for this request.
    :meth:`update_progress` emits a ``$/progress`` notification correlated to the
    request (a no-op once the request has completed, or for a notification with no
    id).

    **Cancellation** (only for a ``cancellable=True`` method): a per-request
    ``threading.Event`` is set when a ``$/cancelRequest`` targets this request
    (``None`` for a non-cancellable method). Cancellation is *cooperative* — the
    handler stops when it notices: poll via :attr:`cancelled` /
    :meth:`raise_if_cancelled`, or block responsively via :meth:`wait_for_cancel`
    (or the raw :attr:`cancel_event`).

    ``audit_message`` is the runtime audit detail (``None`` until a handler calls
    :meth:`set_audit`).
    """

    __slots__ = ("_protocol", "id", "session_state", "count", "_cancel_event",
                 "audit_message")

    def __init__(self, protocol: "JSONRPCProtocol", request_id: str | None,
                 session_state: Any,
                 cancel_event: threading.Event | None = None) -> None:
        self._protocol = protocol
        self.id = request_id
        self.session_state = session_state
        self.count = 0
        self._cancel_event = cancel_event
        self.audit_message: str | None = None

    @property
    def cancelled(self) -> bool:
        """True once a ``$/cancelRequest`` has targeted this (cancellable) request."""
        return self._cancel_event is not None and self._cancel_event.is_set()

    @property
    def cancel_event(self) -> threading.Event | None:
        """The raw cancellation ``threading.Event`` (``None`` if the method is not
        ``cancellable``) — e.g. to hand to another thread or an event-driven wait."""
        return self._cancel_event

    def wait_for_cancel(self, timeout: float | None = None) -> bool:
        """Block up to ``timeout`` seconds; return ``True`` as soon as the request is
        cancelled, ``False`` on timeout — the responsive alternative to polling
        :attr:`cancelled` in a sleep loop. Returns ``False`` immediately for a
        non-cancellable request (there is no event to wait on)."""
        if self._cancel_event is None:
            return False
        return self._cancel_event.wait(timeout)

    def set_audit(self, message: str) -> None:
        """Set this request's runtime audit detail (the middleware ``audit_callback``
        analog). **Single-valued — last call wins**: repeated calls replace, they do
        not accumulate, so a dispatched call emits **exactly one** audit message. The
        detail is joined to the method's static ``audit_message`` (``base detail``)
        for the audit handler. Not redacted — keep secrets out of it (put them in
        secret *fields*, which are redacted)."""
        self.audit_message = message

    def update_progress(self, percent: float | None = None,
                        description: str | None = None, extra: Any = None) -> None:
        self._protocol._update_progress(self, percent=percent,
                                        description=description, extra=extra)

    def raise_if_cancelled(self) -> None:
        """Raise ``JsonRpcError(JSONRPCError.REQUEST_CANCELLED)`` if this request
        has been cancelled — call it at checkpoints in a long-running handler."""
        if self.cancelled:
            raise JsonRpcError(JSONRPCError.REQUEST_CANCELLED, "Request cancelled")


class JSONRPCProtocol:
    """Registry of :class:`JSONRPCMethod` keyed by name, plus ``dispatch``.

    Optional ``authorization_handler`` and ``audit_handler`` wrap every valid
    method call in an ``authorize -> dispatch -> audit`` pipeline; both may be
    passed to the constructor or registered later via
    :meth:`register_authorization_handler` / :meth:`register_audit_handler`.

    ``name`` is stamped onto every :class:`SessionState` this protocol creates.
    """

    def __init__(self, methods: Iterable[JSONRPCMethod] = (), *,
                 name: str | None = None,
                 authorization_handler: Callable[..., Any] | None = None,
                 audit_handler: Callable[..., Any] | None = None,
                 cancellation_handler: Callable[..., Any] | None = None,
                 use_audit_queue: bool = False) -> None:
        self._name = name
        self._methods: dict[str, JSONRPCMethod] = {}
        self._authorization_handler: Callable[..., Any] | None = None
        self._audit_handler: Callable[..., Any] | None = None
        self._cancellation_handler: Callable[..., Any] | None = None
        # Unauthenticated $/serverInfo control request (opt-in via
        # register_server_info): a handler + the msgspec.Struct result type, set
        # together.
        self._server_info_handler: Callable[..., Any] | None = None
        self._server_info_returns: type[msgspec.Struct] | None = None
        # Session setup (opt-in via add_session_setup): the $/sessionSetup and
        # optional $/sessionSetupContinue methods. When set, normal methods require
        # an ESTABLISHED session.
        self._session_setup: JSONRPCMethod | None = None
        self._session_setup_continue: JSONRPCMethod | None = None
        # When set, audit jobs are enqueued (drained off the IO path by the
        # server's audit thread via poll_audit) instead of run inline.
        self._use_audit_queue = use_audit_queue
        self._audit_queue: queue.Queue[_AuditJob] = queue.Queue()
        # server->client outbound: a deque of ready-to-send messages, drained by
        # the server's notification thread (out of scope here). A single
        # Condition guards both the queue and the in-flight registry.
        self._outbound: deque[_Pending] = deque()
        self._cond = threading.Condition()
        # in-flight requests keyed by id, for progress correlation + purge.
        self._inflight: dict[str, RequestState] = {}
        # subscriptions to SERVER_CLIENT topics: method -> {sub_id: Subscription}.
        self._subscriptions: dict[str, dict[str, Subscription]] = {}
        for method in methods:
            self.register(method)
        if authorization_handler is not None:
            self.register_authorization_handler(authorization_handler)
        if audit_handler is not None:
            self.register_audit_handler(audit_handler)
        if cancellation_handler is not None:
            self.register_cancellation_handler(cancellation_handler)

    @property
    def name(self) -> str | None:
        """The protocol's configured ``name`` (the discriminator a client selects with
        ``$/negotiate``), or ``None``."""
        return self._name

    # --- sessions ------------------------------------------------------------
    def new_session(self, server_state: Any = None) -> SessionState:
        """Create a fresh :class:`SessionState` for a connection: a generated
        ``session_uuid``, this protocol's ``name``, ``lifecycle = NONE``, and
        ``server_state`` seeded into ``server_state_internal``. The server creates
        one per connection and passes it to every :meth:`dispatch`."""
        return SessionState(str(uuid.uuid4()), self._name, server_state)

    def close_session(self, session: SessionState) -> None:
        """Mark a session ``CLOSED`` and drop its subscriptions — call this on a
        server-side socket drop. Idempotent. (The client-initiated equivalent is the
        ``$/sessionClose`` control request.)"""
        session.lifecycle = SessionLifecycle.CLOSED
        self.unsubscribe_all(session)

    def register(self, method: JSONRPCMethod) -> None:
        if not isinstance(method, JSONRPCMethod):
            raise TypeError("method must be a JSONRPCMethod")
        if method.name.startswith("rpc.") or method.name.startswith("$/"):
            raise ValueError(
                "method names beginning with 'rpc.' or '$/' are reserved")
        if method.name in self._methods:
            raise ValueError(f"duplicate method: {method.name!r}")
        self._methods[method.name] = method

    def add_session_setup(self, setup: JSONRPCMethod,
                          continue_: JSONRPCMethod | None = None) -> None:
        """Enable the ``$/sessionSetup`` (and optional ``$/sessionSetupContinue``)
        authentication control requests. These cannot go through :meth:`register`
        (it rejects ``$/`` names); their ``name`` is cosmetic — the protocol uses the
        fixed wire names.

        Each is a CLIENT_SERVER :class:`JSONRPCMethod` with ``accepts``, ``returns``,
        and a **handler with a special contract**: it is called
        ``handler(request=<accepts>, session_state=<SessionState>)`` and returns
        ``(SessionLifecycle, result)``. The handler authenticates using ``request``,
        sets ``session_state.server_state_internal`` (the identity) as a side effect,
        and returns the new lifecycle plus the client reply. The protocol validates
        ``result`` against ``returns``, sets ``session_state.server_state_external``
        and ``session_state.lifecycle``, and replies. Setup **bypasses** the
        ``authorization_handler`` (it *is* the auth step) but **is always audited**
        (secret credential fields are redacted via the method's ``accepts`` plan).

        Once configured, a non-``pre_auth`` method requires an ESTABLISHED session.
        """
        for m, label in ((setup, "setup"), (continue_, "continue")):
            if m is None:
                continue
            if not isinstance(m, JSONRPCMethod):
                raise TypeError(f"session {label} must be a JSONRPCMethod")
            if m.direction is not MessageDirection.CLIENT_SERVER:
                raise TypeError(f"session {label} must be a CLIENT_SERVER method")
            if m.handler is None:
                raise TypeError(f"session {label} must have a handler")
            if m.returns is None:
                raise TypeError(f"session {label} must declare 'returns'")
        self._session_setup = setup
        self._session_setup_continue = continue_

    def register_authorization_handler(
            self, handler: Callable[..., Any] | None) -> None:
        """Register (or clear with ``None``) the authorization handler.

        Called as ``handler(request=<JSONRPCRequest>, session_state=...)`` and must
        return an :class:`AuthorizationResponse`; an ``authorized=False`` result
        skips dispatch and produces a ``NOT_AUTHORIZED`` error.

        For the ``$/cancelRequest`` control op the handler is additionally passed
        ``target=<RequestState | Subscription | None>`` — the in-flight request **or
        subscription** being cancelled (``None`` if the id matches neither) — so it
        can enforce session-scoped rules (e.g. compare ``session_state.session_uuid``
        against ``target.session_state.session_uuid``; both target types expose
        ``session_state``). A handler that authorizes cancels must therefore accept a
        ``target`` keyword (or ``**kwargs``); if it doesn't, cancels fail closed with
        ``INTERNAL_ERROR``. Use ``isinstance(target, RequestState)`` to distinguish a
        request from a subscription when you need request-only attributes.
        """
        if handler is not None and not callable(handler):
            raise TypeError("authorization_handler must be callable or None")
        self._authorization_handler = handler

    def register_audit_handler(self, handler: Callable[..., Any] | None) -> None:
        """Register (or clear with ``None``) the audit handler.

        Called as ``handler(request=<JSONRPCRequest>, response=<envelope dict>,
        session_state=..., audit_message=<str|None>)`` for every audited method call
        (``audit=True``) and every session/cancel control op — success, error, or
        denial — just before the wire response is encoded. ``audit_message`` is the
        assembled description (the method's static ``audit_message`` joined with any
        runtime ``request_state.set_audit`` detail), or ``None``. Its return is
        ignored and any exception it raises is swallowed.
        """
        if handler is not None and not callable(handler):
            raise TypeError("audit_handler must be callable or None")
        self._audit_handler = handler

    def register_cancellation_handler(
            self, handler: Callable[..., Any] | None) -> None:
        """Register (or clear with ``None``) the optional active-abort callback.

        Called as ``handler(request=<cancel JSONRPCRequest>, target=<RequestState>,
        session_state=...)`` when an *authorized* ``$/cancelRequest`` targets an
        in-flight **cancellable** request, **after** the protocol has set the
        request's cancellation event. Use it for *active* abort the cooperative
        event can't do alone (e.g. close a socket to unblock an I/O-bound handler).
        Authorization is the ``authorization_handler``'s job, not this; its return
        is ignored. Optional and additive. (It is **not** invoked when
        ``$/cancelRequest`` cancels a *subscription* — there is no active operation.)
        """
        if handler is not None and not callable(handler):
            raise TypeError("cancellation_handler must be callable or None")
        self._cancellation_handler = handler

    def register_server_info(self, handler: Callable[..., Any] | None,
                             returns: type[msgspec.Struct] | None = None) -> None:
        """Enable (or clear with ``handler=None``) the unauthenticated
        ``$/serverInfo`` control request.

        ``handler`` is called as ``handler(session_state=...)`` and must return a
        value convertible to ``returns`` (a ``msgspec.Struct`` subclass), which is
        validated and sent back as the result. ``$/serverInfo`` runs **before**
        authorization **and** the session-established gate — it is callable on a
        fresh, unauthenticated session — and is **not** audited. The handler may
        raise :class:`JsonRpcError` to return a chosen error. When no handler is
        registered, ``$/serverInfo`` behaves like any unknown ``$/`` method
        (``MethodNotFound`` for a request, ignored for a notification).
        """
        if handler is None:
            self._server_info_handler = None
            self._server_info_returns = None
            return
        if not callable(handler):
            raise TypeError("server_info handler must be callable or None")
        if not (isinstance(returns, type) and issubclass(returns, msgspec.Struct)):
            raise TypeError("'returns' must be a msgspec.Struct subclass")
        self._server_info_handler = handler
        self._server_info_returns = returns

    def poll_audit(self, block: bool = True,
                   timeout: float | None = None) -> "AuditRecord | None":
        """Pop the next queued audit job (when ``use_audit_queue=True``), apply
        secret redaction **here** (off the dispatch path), and return a ready-to-run
        :class:`AuditRecord`. Returns ``None`` if nothing is queued within
        ``timeout``. The server's audit thread loops: ``rec = poll_audit(...);
        rec.run()``."""
        try:
            job = self._audit_queue.get(block=block, timeout=timeout)
        except queue.Empty:
            return None
        return self._audit_record(*job)

    def _audit(self, handler: Callable[..., Any], request: JSONRPCRequest,
               response: dict[str, Any], session_state: Any,
               method: "JSONRPCMethod | None", detail: str | None) -> None:
        """Enqueue the audit job (queue mode) or run it inline (sync mode). The
        redaction plans and the static audit message come from ``method``;
        ``detail`` is the runtime detail captured from the request's
        :class:`RequestState`."""
        if self._use_audit_queue:
            self._audit_queue.put(_AuditJob(
                handler, request, response, session_state, method, detail))
        else:
            self._audit_record(handler, request, response, session_state,
                               method, detail).run()

    def _audit_record(self, handler: Callable[..., Any], request: JSONRPCRequest,
                      response: dict[str, Any], session_state: Any,
                      method: "JSONRPCMethod | None",
                      detail: str | None) -> AuditRecord:
        """Build the redacted audit view (without mutating the wire/authz objects)
        and assemble the audit message — both off the IO path when drained via
        :meth:`poll_audit`."""
        accepts_plan = method._accepts_plan if method is not None else None
        returns_plan = method._returns_plan if method is not None else None
        audit_req = request
        if accepts_plan is not None:
            audit_req = JSONRPCRequest(method=request.method, id=request.id,
                                       params=redact(request.params, accepts_plan),
                                       roles=request.roles)
        audit_resp = response
        if returns_plan is not None and "result" in response:
            audit_resp = {**response, "result": redact(response["result"], returns_plan)}
        base = method.audit_message if method is not None else None
        message = self._assemble_audit_message(base, detail)
        return AuditRecord(handler, audit_req, audit_resp, session_state, message)

    @staticmethod
    def _assemble_audit_message(base: str | None,
                                detail: str | None) -> str | None:
        """Join the static per-method ``audit_message`` (``base``) and the runtime
        ``detail`` (set via ``request_state.set_audit``) into the single audit
        message: ``"base detail"`` if both, else whichever is present, else
        ``None``."""
        if base and detail:
            return f"{base} {detail}"
        return base or detail or None

    @property
    def methods(self) -> dict[str, JSONRPCMethod]:
        """A copy of the {name: JSONRPCMethod} dispatch table."""
        return dict(self._methods)

    def describe(self) -> dict[str, dict[str, Any]]:
        """A catalog of the registered methods for introspection / codegen:
        ``{name: {direction, doc, accepts, returns, notifies, roles}}`` where the
        schemas are JSON Schema (``msgspec.json.schema``); ``returns``/``notifies``
        are ``None`` when absent and ``roles`` is the (possibly empty) list of
        declared role names. JSON-serializable."""
        out: dict[str, dict[str, Any]] = {}
        for name, m in self._methods.items():
            out[name] = {
                "direction": m.direction.value,
                "doc": m.doc,
                "accepts": msgspec.json.schema(m.accepts),
                "returns": (msgspec.json.schema(m.returns)
                            if m.returns is not None else None),
                "notifies": (msgspec.json.schema(m.notifies)
                             if m.notifies is not None else None),
                "roles": list(m.roles),
            }
        return out

    def dispatch(self, wire: bytes | str,
                 session: SessionState | None = None) -> bytes | None | Transfer:
        """Dispatch a single request against ``session`` (a :class:`SessionState`
        from :meth:`new_session`; ``None`` creates a fresh ephemeral one — fine for
        stateless / no-auth use). The session is forwarded to the matched method's
        handler (and to the authorization/audit handlers, and stored on the
        request's :class:`RequestState`) as the ``session_state`` keyword argument.
        Returns the wire response, ``None`` for a notification, or a :class:`Transfer`
        directive for a raw-fd transfer method (the server drives the handshake + fd
        handoff). A top-level JSON Array (batch) is rejected as Invalid Request."""
        data = wire.encode() if isinstance(wire, str) else wire
        if session is None:
            session = self.new_session()
        response = self._dispatch_one(data, session)
        if response is None or isinstance(response, Transfer):
            return response
        return _ENC.encode(response)

    # --- server -> client (pub/sub) ------------------------------------------
    def send_notification(self, method: str, payload: Any) -> None:
        """Publish a notification to every subscriber of a ``SERVER_CLIENT`` topic.

        ``payload`` is validated against the method's ``notifies`` schema, encoded
        once, and fanned out onto the outbound queue — one entry per subscriber,
        each tagged with the :class:`SessionState` captured when that client
        subscribed. Raises ``ValueError`` if ``method`` is not a registered
        ``SERVER_CLIENT`` method (server-side misuse); a bad ``payload`` raises a
        ``msgspec`` validation error. No subscribers → no-op."""
        m = self._methods.get(method)
        if m is None or m.direction is not MessageDirection.SERVER_CLIENT:
            raise ValueError(
                f"{method!r} is not a registered SERVER_CLIENT (subscribable) method")
        assert m.notifies is not None  # guaranteed for SERVER_CLIENT at construction
        validated = msgspec.convert(payload, type=m.notifies)
        data = msgspec.json.encode(
            {"jsonrpc": _VERSION, "method": method, "params": validated})
        with self._cond:
            subs = self._subscriptions.get(method)
            if not subs:
                return
            for sub in subs.values():
                self._outbound.append(_Pending(sub.session_state, None, data))
            self._cond.notify()

    def unsubscribe(self, sub_id: str) -> bool:
        """Drop a single subscription by its id. Returns True if it existed."""
        with self._cond:
            for subs in self._subscriptions.values():
                if subs.pop(sub_id, None) is not None:
                    return True
        return False

    def unsubscribe_all(self, session: SessionState) -> int:
        """Drop every subscription belonging to ``session`` (matched by
        ``session_uuid``) — the server calls this (or :meth:`close_session`) when a
        connection closes so subscriptions don't leak. Returns the number removed."""
        removed = 0
        with self._cond:
            for subs in self._subscriptions.values():
                for sid in [s for s, sub in subs.items()
                            if sub.session_state.session_uuid == session.session_uuid]:
                    del subs[sid]
                    removed += 1
        return removed

    def _update_progress(self, request_state: RequestState, *,
                         percent: float | None = None,
                         description: str | None = None,
                         extra: Any = None) -> None:
        """Enqueue a ``$/progress`` notification for ``request_state`` (internal —
        consumed by :meth:`RequestState.update_progress`, not part of the public
        API). The request ``id`` is carried in the params for correlation. A
        no-op if the request is no longer in flight (already completed, or a
        notification with no id), so progress is dropped rather than mis-sent."""
        rid = request_state.id
        if rid is None:
            return
        params: dict[str, Any] = {"id": rid}
        if percent is not None:
            params["percent"] = percent
        if description is not None:
            params["description"] = description
        if extra is not None:
            params["extra"] = extra
        data = msgspec.json.encode(
            {"jsonrpc": _VERSION, "method": _PROGRESS_METHOD, "params": params})
        with self._cond:
            if rid not in self._inflight:
                return                       # request already completed -> drop
            request_state.count += 1
            self._outbound.append(_Pending(request_state.session_state, rid, data))
            self._cond.notify()

    def poll_notification(self, block: bool = True,
                          timeout: float | None = None) -> tuple[Any, bytes] | None:
        """Pop one queued outbound message as ``(session_state, wire_bytes)`` for
        the server's notification thread. Blocks until one is available (or
        ``timeout``); returns ``None`` if nothing is available."""
        with self._cond:
            if not self._outbound:
                if not block:
                    return None
                if not self._cond.wait_for(lambda: len(self._outbound) > 0, timeout):
                    return None
            entry = self._outbound.popleft()
        return (entry.session, entry.data)

    def _complete(self, request_state: RequestState) -> None:
        """Finish a request: drop it from the in-flight registry and purge any of
        its notifications still queued (superseded by the response). Skips the
        queue scan when the request emitted nothing (``count == 0``)."""
        rid = request_state.id
        if rid is None:
            return
        with self._cond:
            self._inflight.pop(rid, None)
            if request_state.count:
                self._outbound = deque(
                    p for p in self._outbound if p.request_id != rid)

    # --- dispatch ------------------------------------------------------------
    def _dispatch_one(self, msg: bytes,
                      session: SessionState) -> dict[str, Any] | None | Transfer:
        """Process one message, returning the structured response envelope, ``None``
        when nothing should be sent (a notification), or a :class:`Transfer` directive
        for a raw-fd transfer method (the server drives it)."""
        # --- parse the envelope (only non-object / malformed JSON fails) ---
        try:
            env = _ENV_DEC.decode(msg)
        except msgspec.ValidationError as e:
            # Valid JSON but not an object (incl. a top-level Array / batch).
            # ValidationError subclasses DecodeError, so it must be caught first.
            return self._error_envelope(None, JSONRPCError.INVALID_REQUEST,
                                        "Invalid request", str(e))
        except msgspec.DecodeError as e:
            return self._error_envelope(None, JSONRPCError.INVALID_JSON,
                                        "Parse error", str(e))

        # --- resolve id: a present id MUST be a UUID string (refinement) ---
        rid: str | None
        if env.id is UNSET:
            rid, has_id = None, False
        elif isinstance(env.id, str) and _is_uuid(env.id):
            rid, has_id = env.id, True
        else:
            return self._error_envelope(None, JSONRPCError.INVALID_REQUEST,
                                        "Invalid request", "'id' must be a UUID string")

        # --- structural validation: never suppressed, even without an id ---
        if env.jsonrpc != _VERSION:
            return self._error_envelope(
                rid, JSONRPCError.INVALID_REQUEST, "Invalid request",
                "'jsonrpc' must be exactly '2.0'")
        method_name = env.method
        if not isinstance(method_name, str) or not method_name:
            return self._error_envelope(
                rid, JSONRPCError.INVALID_REQUEST, "Invalid request",
                "'method' must be a non-empty string")

        # A structurally valid message with no id is a notification (no reply).
        note = not has_id

        # A CLOSED session accepts nothing further.
        if session.lifecycle is SessionLifecycle.CLOSED:
            return None if note else self._error_envelope(
                rid, JSONRPCError.SESSION_NOT_ESTABLISHED, "Session is closed")

        # --- control messages (intercepted; each enforces its own lifecycle) ---
        if method_name == _CANCEL_METHOD:
            return self._handle_cancel(env, rid, note, session)
        if method_name == _SERVERINFO_METHOD:
            return self._handle_server_info(rid, note, session)
        if method_name == _SESSION_SETUP_METHOD:
            return self._handle_session_setup(env, rid, note, session)
        if method_name == _SESSION_SETUP_CONTINUE_METHOD:
            return self._handle_session_continue(env, rid, note, session)
        if method_name == _SESSION_CLOSE_METHOD:
            return self._handle_session_close(rid, note, session)

        method = self._methods.get(method_name)
        if method is None:
            return None if note else self._error_envelope(
                rid, JSONRPCError.METHOD_NOT_FOUND, "Method not found")

        # A subscribe (SERVER_CLIENT) is a request and must carry an id so the
        # client can receive the subscription id (and later unsubscribe).
        if method.direction is MessageDirection.SERVER_CLIENT and note:
            return self._error_envelope(
                None, JSONRPCError.INVALID_REQUEST, "Invalid request",
                "a subscribe request requires an 'id'")

        # --- session-established gate (only when session setup is configured) ---
        # A non-pre_auth method requires an ESTABLISHED session; with no setup
        # configured the gate is off (open), mirroring "no authz handler = open".
        if self._session_setup is not None and not method.pre_auth:
            if session.lifecycle is not SessionLifecycle.ESTABLISHED:
                return None if note else self._error_envelope(
                    rid, JSONRPCError.SESSION_NOT_ESTABLISHED, "Session not established")

        # --- strip envelope, decode + validate params (by-name object only) ---
        raw = _EMPTY if env.params is UNSET else env.params
        try:
            params: Any = method._param_decoder.decode(raw)
        except (msgspec.ValidationError, msgspec.DecodeError) as e:
            return None if note else self._error_envelope(
                rid, JSONRPCError.INVALID_PARAMS, "Invalid params", str(e))

        if method.accepts_validator is not None:
            try:
                replaced = method.accepts_validator(params)
            except Exception as e:
                return None if note else self._error_envelope(
                    rid, JSONRPCError.INVALID_PARAMS, "Invalid params", str(e))
            if replaced is not None:
                params = replaced

        # --- authorize -> dispatch -> audit ---
        req = JSONRPCRequest(method=method_name, id=rid, params=params, roles=method.roles)

        # A raw-fd transfer method: authorize + negotiate, then hand a Transfer
        # directive back to the server to drive the wire handshake + fd handoff.
        if isinstance(method, JSONRPCFdTransferMethod):
            return self._begin_transfer(method, req, params, rid, note, session)

        response, request_state = self._authorize_and_dispatch(
            method, req, params, rid, session)

        audit = self._audit_handler
        if audit is not None and method.audit:
            # Runtime audit detail is only present if the handler ran and set it.
            detail = request_state.audit_message if request_state is not None else None
            self._audit(audit, req, response, session, method, detail)

        return None if note else response

    # --- raw-fd transfer -----------------------------------------------------
    def _begin_transfer(self, method: JSONRPCFdTransferMethod, req: JSONRPCRequest,
                        params: Any, rid: str | None, note: bool,
                        session: SessionState) -> dict[str, Any] | Transfer:
        """Authorize, then run the transfer method's ``negotiate`` callback and return
        a :class:`Transfer` directive (or an error envelope). The server drives the
        wire handshake and the fd handoff from there."""
        if note:
            return self._error_envelope(
                None, JSONRPCError.INVALID_REQUEST, "Invalid request",
                "a transfer request requires an 'id'")
        assert rid is not None           # not a notification -> id present
        authorize = self._authorization_handler
        if authorize is not None:
            try:
                auth = authorize(request=req, session_state=session)
            except Exception as e:
                return self._error_envelope(
                    rid, JSONRPCError.INTERNAL_ERROR, "Internal error", str(e))
            if not isinstance(auth, AuthorizationResponse):
                return self._error_envelope(
                    rid, JSONRPCError.INTERNAL_ERROR, "Internal error",
                    "authorization_handler must return an AuthorizationResponse")
            if not auth.authorized:
                return self._error_envelope(
                    rid, JSONRPCError.NOT_AUTHORIZED, auth.message, auth.data)
        try:
            interim = method.negotiate(request=params, session_state=session)
        except JsonRpcError as e:
            return self._error_envelope(rid, e.code, e.message, e.data)
        except Exception as e:
            return self._error_envelope(
                rid, JSONRPCError.INTERNAL_ERROR, "Internal error", str(e))
        ready = {"jsonrpc": _VERSION, "method": _TRANSFER_READY_METHOD,
                 "params": {"id": rid,
                            "direction": method.transfer_direction.value,
                            "result": msgspec.to_builtins(interim)}}

        def run(file_transfer: FileTransfer) -> dict[str, Any]:
            return self._run_transfer(method, req, rid, session, file_transfer)

        return Transfer(rid=rid, direction=method.transfer_direction, params=params,
                        session_state=session, ready=ready, run=run,
                        af_unix=isinstance(method, JSONRPCFdPassMethod))

    def _run_transfer(self, method: JSONRPCFdTransferMethod, req: JSONRPCRequest,
                      rid: str | None, session: SessionState,
                      file_transfer: FileTransfer) -> dict[str, Any]:
        """Run the ``transfer`` callback (the server calls this in its executor — it
        blocks doing the bulk stream), validate the result, audit, and return the
        final response envelope."""
        response = self._do_transfer(method, rid, file_transfer)
        audit = self._audit_handler
        if audit is not None and method.audit:
            self._audit(audit, req, response, session, method, None)
        return response

    def _do_transfer(self, method: JSONRPCFdTransferMethod, rid: str | None,
                     file_transfer: FileTransfer) -> dict[str, Any]:
        try:
            result: Any = method.transfer(file_transfer)
        except JsonRpcError as e:
            return self._error_envelope(rid, e.code, e.message, e.data)
        except Exception as e:
            return self._error_envelope(
                rid, JSONRPCError.INTERNAL_ERROR, "Internal error", str(e))
        assert method.returns is not None    # required by JSONRPCFdTransferMethod
        try:
            result = msgspec.convert(result, type=method.returns)
        except msgspec.ValidationError as e:
            return self._error_envelope(
                rid, JSONRPCError.INTERNAL_ERROR, "Invalid result", str(e))
        if method.returns_validator is not None:
            try:
                replaced = method.returns_validator(result)
            except Exception as e:
                return self._error_envelope(
                    rid, JSONRPCError.INTERNAL_ERROR, "Invalid result", str(e))
            if replaced is not None:
                result = replaced
        return {"jsonrpc": _VERSION, "result": result, "id": rid}

    # --- control messages ----------------------------------------------------
    def _handle_cancel(self, env: JSONRPCEnvelope, rid: str | None, note: bool,
                       session: SessionState) -> dict[str, Any]:
        """Handle a ``$/cancelRequest`` control request: authorize (session-scoped),
        validate the target is in flight + cancellable, set its cancellation event +
        run the cancellation callback, and audit. A no-id cancel is Invalid Request."""
        if note:
            return self._error_envelope(
                None, JSONRPCError.INVALID_REQUEST, "Invalid request",
                "a $/cancelRequest requires an 'id'")
        raw = _EMPTY if env.params is UNSET else env.params
        try:
            params = _CANCEL_DEC.decode(raw)
        except (msgspec.ValidationError, msgspec.DecodeError) as e:
            return self._error_envelope(
                rid, JSONRPCError.INVALID_PARAMS, "Invalid params", str(e))

        req = JSONRPCRequest(method=_CANCEL_METHOD, id=rid, params=params)
        response = self._authorize_and_cancel(req, params.target_id, rid, session)

        audit = self._audit_handler
        if audit is not None:        # control-op audit: no method, no secrets, no message
            self._audit(audit, req, response, session, None, None)
        return response

    def _handle_server_info(self, rid: str | None, note: bool,
                            session: SessionState) -> dict[str, Any] | None:
        """Handle the unauthenticated ``$/serverInfo`` control request: no authz, no
        session gate, no audit, no params. Returns the registered handler's result
        validated against its result type, or ``MethodNotFound`` when not enabled."""
        handler = self._server_info_handler
        if handler is None:
            # not enabled -> behave like any unknown $/ control method
            return None if note else self._error_envelope(
                rid, JSONRPCError.METHOD_NOT_FOUND, "Method not found")
        if note:
            return self._error_envelope(
                None, JSONRPCError.INVALID_REQUEST, "Invalid request",
                "a $/serverInfo requires an 'id'")
        try:
            result: Any = handler(session_state=session)
        except JsonRpcError as e:
            return self._error_envelope(rid, e.code, e.message, e.data)
        except Exception as e:
            return self._error_envelope(
                rid, JSONRPCError.INTERNAL_ERROR, "Internal error", str(e))
        returns = self._server_info_returns
        assert returns is not None  # set together with the handler
        try:
            result = msgspec.convert(result, type=returns)
        except msgspec.ValidationError as e:
            return self._error_envelope(
                rid, JSONRPCError.INTERNAL_ERROR, "Invalid result", str(e))
        return {"jsonrpc": _VERSION, "result": result, "id": rid}

    def _handle_session_setup(self, env: JSONRPCEnvelope, rid: str | None, note: bool,
                              session: SessionState) -> dict[str, Any] | None:
        """Handle ``$/sessionSetup`` — the first auth step, allowed only at NONE."""
        method = self._session_setup
        if method is None:
            return None if note else self._error_envelope(
                rid, JSONRPCError.METHOD_NOT_FOUND, "Method not found")
        if note:
            return self._error_envelope(
                None, JSONRPCError.INVALID_REQUEST, "Invalid request",
                "a $/sessionSetup requires an 'id'")
        if session.lifecycle is not SessionLifecycle.NONE:
            return self._error_envelope(
                rid, JSONRPCError.REQUEST_FAILED, "Request failed",
                "session setup is already in progress or established")
        return self._run_session_setup(method, _SESSION_SETUP_METHOD, env, rid, session)

    def _handle_session_continue(self, env: JSONRPCEnvelope, rid: str | None, note: bool,
                                 session: SessionState) -> dict[str, Any] | None:
        """Handle ``$/sessionSetupContinue`` — a later auth step, allowed only at INIT."""
        method = self._session_setup_continue
        if method is None:
            return None if note else self._error_envelope(
                rid, JSONRPCError.METHOD_NOT_FOUND, "Method not found")
        if note:
            return self._error_envelope(
                None, JSONRPCError.INVALID_REQUEST, "Invalid request",
                "a $/sessionSetupContinue requires an 'id'")
        if session.lifecycle is not SessionLifecycle.INIT:
            return self._error_envelope(
                rid, JSONRPCError.REQUEST_FAILED, "Request failed",
                "no session setup is in progress")
        return self._run_session_setup(
            method, _SESSION_SETUP_CONTINUE_METHOD, env, rid, session)

    def _run_session_setup(self, method: JSONRPCMethod, method_name: str,
                           env: JSONRPCEnvelope, rid: str | None,
                           session: SessionState) -> dict[str, Any]:
        """Decode the credentials, run the setup handler (returns
        ``(lifecycle, result)``), validate + commit the new lifecycle / external
        state, and audit (credentials redacted via the method's plan). Shared by
        ``$/sessionSetup`` and ``$/sessionSetupContinue``. Bypasses authz."""
        raw = _EMPTY if env.params is UNSET else env.params
        try:
            params: Any = method._param_decoder.decode(raw)
        except (msgspec.ValidationError, msgspec.DecodeError) as e:
            return self._error_envelope(
                rid, JSONRPCError.INVALID_PARAMS, "Invalid params", str(e))
        if method.accepts_validator is not None:
            try:
                replaced = method.accepts_validator(params)
            except Exception as e:
                return self._error_envelope(
                    rid, JSONRPCError.INVALID_PARAMS, "Invalid params", str(e))
            if replaced is not None:
                params = replaced

        req = JSONRPCRequest(method=method_name, id=rid, params=params)
        response = self._dispatch_session_setup(method, params, rid, session)

        audit = self._audit_handler
        if audit is not None:        # auth events are always audited (creds redacted)
            self._audit(audit, req, response, session, method, None)
        return response

    def _dispatch_session_setup(self, method: JSONRPCMethod, params: Any,
                                rid: str | None,
                                session: SessionState) -> dict[str, Any]:
        """Run the setup handler and commit its ``(lifecycle, result)`` outcome."""
        handler = method.handler
        assert handler is not None  # guaranteed by add_session_setup
        try:
            outcome: Any = handler(request=params, session_state=session)
        except JsonRpcError as e:
            return self._error_envelope(rid, e.code, e.message, e.data)
        except Exception as e:
            return self._error_envelope(
                rid, JSONRPCError.INTERNAL_ERROR, "Internal error", str(e))
        if not (isinstance(outcome, tuple) and len(outcome) == 2):
            return self._error_envelope(
                rid, JSONRPCError.INTERNAL_ERROR, "Internal error",
                "session setup handler must return (lifecycle, result)")
        lifecycle, result = outcome
        if not isinstance(lifecycle, SessionLifecycle):
            return self._error_envelope(
                rid, JSONRPCError.INTERNAL_ERROR, "Internal error",
                "session setup handler must return a SessionLifecycle")
        assert method.returns is not None  # required by add_session_setup
        try:
            result = msgspec.convert(result, type=method.returns)
        except msgspec.ValidationError as e:
            return self._error_envelope(
                rid, JSONRPCError.INTERNAL_ERROR, "Invalid result", str(e))
        session.lifecycle = lifecycle
        session.server_state_external = result
        return {"jsonrpc": _VERSION, "result": result, "id": rid}

    def _handle_session_close(self, rid: str | None, note: bool,
                              session: SessionState) -> dict[str, Any]:
        """Handle ``$/sessionClose`` — client-initiated logout (INIT/ESTABLISHED →
        CLOSED). Drops the session's subscriptions and audits. No authz (closing
        your own session is always allowed)."""
        if note:
            return self._error_envelope(
                None, JSONRPCError.INVALID_REQUEST, "Invalid request",
                "a $/sessionClose requires an 'id'")
        if session.lifecycle not in (SessionLifecycle.INIT,
                                     SessionLifecycle.ESTABLISHED):
            return self._error_envelope(
                rid, JSONRPCError.REQUEST_FAILED, "Request failed",
                "no session to close")
        req = JSONRPCRequest(method=_SESSION_CLOSE_METHOD, id=rid, params=None)
        session.lifecycle = SessionLifecycle.CLOSED
        self.unsubscribe_all(session)
        response: dict[str, Any] = {"jsonrpc": _VERSION, "result": True, "id": rid}
        audit = self._audit_handler
        if audit is not None:
            self._audit(audit, req, response, session, None, None)
        return response

    def _find_subscription(self, sub_id: str) -> "Subscription | None":
        """Find a subscription by its id. **Caller must hold ``self._cond``.**"""
        for subs in self._subscriptions.values():
            sub = subs.get(sub_id)
            if sub is not None:
                return sub
        return None

    def _authorize_and_cancel(self, req: JSONRPCRequest, target_id: str,
                              rid: str | None,
                              session: SessionState) -> dict[str, Any]:
        """Authorize the cancel (session-scoped — the authorization handler is given
        the target's :class:`RequestState` or :class:`Subscription`, both of which
        expose ``session_state``), then act on it: for an in-flight request, set its
        cancellation event + invoke the optional active-abort callback; for a
        subscription, drop it (a wire-level unsubscribe). ``$/cancelRequest`` thus
        resolves a target id against both in-flight requests and subscriptions."""
        with self._cond:
            target: Any = self._inflight.get(target_id)
            if target is None:
                target = self._find_subscription(target_id)

        # Authorize with the target in hand so the handler can compare the canceller's
        # session against the target's owner (``target.session_state``). Done before
        # any existence error so an unauthorized caller is denied without learning
        # whether the target exists. ``target`` may be None.
        authorize = self._authorization_handler
        if authorize is not None:
            try:
                auth = authorize(request=req, session_state=session, target=target)
            except Exception as e:
                return self._error_envelope(
                    rid, JSONRPCError.INTERNAL_ERROR, "Internal error", str(e))
            if not isinstance(auth, AuthorizationResponse):
                return self._error_envelope(
                    rid, JSONRPCError.INTERNAL_ERROR, "Internal error",
                    "authorization_handler must return an AuthorizationResponse")
            if not auth.authorized:
                return self._error_envelope(
                    rid, JSONRPCError.NOT_AUTHORIZED, auth.message, auth.data)

        if target is None:
            return self._error_envelope(
                rid, JSONRPCError.REQUEST_FAILED, "Request failed",
                f"no active request or subscription with id {target_id!r}")

        # A subscription: drop it server-side (no active operation to abort).
        if not isinstance(target, RequestState):
            self.unsubscribe(target_id)
            return {"jsonrpc": _VERSION, "result": True, "id": rid}

        # An in-flight request: signal cooperative cancellation.
        event = target.cancel_event
        if event is None:
            return self._error_envelope(
                rid, JSONRPCError.REQUEST_FAILED, "Request failed",
                f"request {target_id!r} is not cancellable")
        event.set()                          # thread-safe; the cooperative signal

        cancel = self._cancellation_handler
        if cancel is not None:
            try:
                cancel(request=req, target=target, session_state=session)
            except Exception as e:
                return self._error_envelope(
                    rid, JSONRPCError.INTERNAL_ERROR, "Internal error", str(e))

        return {"jsonrpc": _VERSION, "result": True, "id": rid}

    def _authorize_and_dispatch(
            self, method: JSONRPCMethod, req: JSONRPCRequest, params: Any,
            rid: str | None, session: SessionState
            ) -> tuple[dict[str, Any], "RequestState | None"]:
        """Authorize, then dispatch + validate the return, returning
        ``(response, request_state)``: the structured response envelope
        (``{"jsonrpc","result","id"}`` on success or ``{"jsonrpc","error":{...},
        "id"}`` on failure/denial) that the caller audits and then encodes, plus
        the handler's :class:`RequestState` — or ``None`` for it when no handler
        ran (authz denied/errored, a subscribe, or no handler registered), so the
        caller knows there is no runtime audit detail to read. On handler error the
        ``RequestState`` is still returned (the handler may have set audit detail
        before raising)."""
        # authorize
        authorize = self._authorization_handler
        if authorize is not None:
            try:
                auth = authorize(request=req, session_state=session)
            except Exception as e:
                return self._error_envelope(
                    rid, JSONRPCError.INTERNAL_ERROR, "Internal error", str(e)), None
            if not isinstance(auth, AuthorizationResponse):
                return self._error_envelope(
                    rid, JSONRPCError.INTERNAL_ERROR, "Internal error",
                    "authorization_handler must return an AuthorizationResponse"), None
            if not auth.authorized:
                return self._error_envelope(
                    rid, JSONRPCError.NOT_AUTHORIZED, auth.message, auth.data), None

        # subscribe: a SERVER_CLIENT method has no handler — register a
        # subscription (capturing the session for routing) and ack with its id.
        if method.direction is MessageDirection.SERVER_CLIENT:
            sub_id = str(uuid.uuid4())
            with self._cond:
                self._subscriptions.setdefault(method.name, {})[sub_id] = (
                    Subscription(sub_id, session, params))
            return {"jsonrpc": _VERSION, "result": sub_id, "id": rid}, None

        # dispatch — register a per-request RequestState for the duration of the
        # handler so progress correlates; on completion drop it and purge any of
        # its still-queued notifications.
        handler = method.handler
        if handler is None:
            return self._error_envelope(
                rid, JSONRPCError.INTERNAL_ERROR,
                "No handler registered for method"), None
        # A cancellable method gets a per-request Event that $/cancelRequest sets.
        cancel_event = threading.Event() if method.cancellable else None
        request_state = RequestState(self, rid, session, cancel_event=cancel_event)
        if rid is not None:
            with self._cond:
                self._inflight[rid] = request_state
        try:
            result: Any = handler(request=params, session_state=session,
                                  request_state=request_state)
        except JsonRpcError as e:
            return self._error_envelope(rid, e.code, e.message, e.data), request_state
        except Exception as e:
            return self._error_envelope(
                rid, JSONRPCError.INTERNAL_ERROR, "Internal error", str(e)), request_state
        finally:
            self._complete(request_state)

        # validate/type the return
        if method.returns is not None:
            try:
                result = msgspec.convert(result, type=method.returns)
            except msgspec.ValidationError as e:
                return self._error_envelope(
                    rid, JSONRPCError.INTERNAL_ERROR, "Invalid result", str(e)
                    ), request_state
        if method.returns_validator is not None:
            try:
                replaced = method.returns_validator(result)
            except Exception as e:
                return self._error_envelope(
                    rid, JSONRPCError.INTERNAL_ERROR, "Invalid result", str(e)
                    ), request_state
            if replaced is not None:
                result = replaced

        return {"jsonrpc": _VERSION, "result": result, "id": rid}, request_state

    @staticmethod
    def _error_envelope(rid: str | None, code: "int | JSONRPCError",
                        message: str, data: Any = None) -> dict[str, Any]:
        err: dict[str, Any] = {"code": int(code), "message": message}
        if data is not None:
            err["data"] = data
        return {"jsonrpc": _VERSION, "error": err, "id": rid}

    @classmethod
    def _error(cls, rid: str | None, code: "int | JSONRPCError",
               message: str, data: Any = None) -> bytes:
        return _ENC.encode(cls._error_envelope(rid, code, message, data))
