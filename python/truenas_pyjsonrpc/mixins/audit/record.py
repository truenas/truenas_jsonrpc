"""The transport-agnostic audit-record builder — middleware's ``@cee:``/``TNAUDIT`` JSON
shape, independent of how it is emitted.

:class:`AuditFormatter` turns the protocol's ``(request, response, session_state,
audit_message)`` audit callback arguments into the middleware audit envelope::

    @cee:{"TNAUDIT": {"aid", "vers", "addr", "user", "sess", "time", "svc",
                      "svc_data", "event", "event_data", "success"}}

``svc_data`` and ``event_data`` are themselves JSON **strings** (exactly as middleware
nests them). ``request.params`` / ``response["result"]`` are **already secret-redacted** by
the protocol before the callback runs; the builder only serializes the masked values via
``msgspec.to_builtins`` and never sees a live secret.

The ``user`` / ``addr`` / ``credentials`` values and the ``event`` classification come from
small overridable callables (the ``default_*`` functions below), which duck-type the two
identity shapes seen in practice: a ``dict`` identity (e.g. ``TrueNASAuth``'s
``{"username", "account_attributes", "origin", "api_key_id"?}``) and the server-seeded
``Peer`` (pre-auth).
"""
from __future__ import annotations

import datetime
import enum
import json
import uuid
from typing import Any, Callable

import msgspec

from truenas_pyjsonrpc import JSONRPCRequest


class EventType(enum.StrEnum):
    """The default ``event`` vocabulary. A custom classifier may return any ``str`` (e.g.
    ``"AUTHENTICATION"``) — the builder just stringifies it."""
    METHOD_CALL = "METHOD_CALL"          # a normal application method
    CONTROL_MESSAGE = "CONTROL_MESSAGE"  # a ``$/`` control-namespace op (session setup/close, cancel)


#: Recorded as ``user`` when there is no identity yet / the identity is unknown.
UNAUTHENTICATED = ".UNAUTHENTICATED"
UNKNOWN_USER = ".UNKNOWN"


def _peerish(obj: Any) -> Any | None:
    """``obj`` if it looks like a server ``Peer`` (has a ``transport`` attribute and is not a
    dict identity), else ``None`` — duck-typed so this package needs no server import."""
    if obj is None or isinstance(obj, dict):
        return None
    return obj if hasattr(obj, "transport") else None


def _peer_origin(peer: Any) -> str | None:
    addr = getattr(peer, "address", None)
    if isinstance(addr, (tuple, list)) and len(addr) >= 2:
        return f"{addr[0]}:{addr[1]}"
    if addr:
        return str(addr)
    uid = getattr(peer, "uid", None)
    if uid is not None:
        return f"unix:uid={uid}"
    pid = getattr(peer, "pid", None)
    return f"unix:pid={pid}" if pid is not None else None


# --- the overridable extractors / classifier --------------------------------
def default_event_classifier(request: JSONRPCRequest) -> "EventType | str":
    """``$/``-namespaced method → ``CONTROL_MESSAGE``; anything else → ``METHOD_CALL``."""
    return (EventType.CONTROL_MESSAGE if request.method.startswith("$/")
            else EventType.METHOD_CALL)


def default_username(session_state: Any) -> str:
    """The audit ``user`` from ``session_state.server_state_internal``: a ``dict`` identity's
    ``username``/``user``, a ``Peer``'s ``uid``, else an unauthenticated/unknown sentinel."""
    ident = getattr(session_state, "server_state_internal", None)
    if isinstance(ident, dict):
        return str(ident.get("username") or ident.get("user") or UNKNOWN_USER)
    peer = _peerish(ident)
    if peer is not None:
        uid = getattr(peer, "uid", None)
        return f"unix:uid={uid}" if uid is not None else UNKNOWN_USER
    return UNAUTHENTICATED if ident is None else UNKNOWN_USER


def default_origin(session_state: Any) -> str | None:
    """The client origin for ``addr`` / ``svc_data.origin``: a ``dict`` identity's ``origin``
    (captured at auth time), or a still-present ``Peer``'s address, else ``None``."""
    ident = getattr(session_state, "server_state_internal", None)
    if isinstance(ident, dict):
        origin = ident.get("origin")
        return str(origin) if origin is not None else None
    peer = _peerish(ident)
    return _peer_origin(peer) if peer is not None else None


#: Identity-dict keys copied into a record's ``credentials_data``. An **allowlist**, not a
#: denylist, so a secret a stack happens to stash on the identity (a token, a session key)
#: can never leak into the audit log. A custom stack with extra *non-secret* identity fields
#: worth auditing should pass its own ``credentials`` extractor to :class:`AuditFormatter`.
_CREDENTIALS_KEYS = ("username", "account_attributes", "api_key_id")


def default_credentials(session_state: Any) -> dict[str, Any] | None:
    """The ``svc_data.credentials`` block: ``{"credentials": <kind>, "credentials_data":
    {...}}`` for a dict identity (kind ``API_KEY`` when an ``api_key_id`` is present, else
    ``USER_SESSION``), or ``None`` (no identity / a bare ``Peer``). Only the
    :data:`_CREDENTIALS_KEYS` allowlist is copied — never the whole identity dict — so a
    secret stashed on it is never written to the audit log."""
    ident = getattr(session_state, "server_state_internal", None)
    if not isinstance(ident, dict):
        return None
    kind = "API_KEY" if ident.get("api_key_id") else "USER_SESSION"
    data = {k: ident[k] for k in _CREDENTIALS_KEYS if k in ident}
    return {"credentials": kind, "credentials_data": data}


def _to_builtin(value: Any) -> Any:
    """JSON-ready builtins for an already-redacted params/result value (a msgspec Struct when
    nothing was secret, or a redacted ``dict`` when something was)."""
    try:
        return msgspec.to_builtins(value)
    except Exception:
        return str(value)


class AuditFormatter:
    """Build the middleware ``@cee``/``TNAUDIT`` audit record from the protocol's audit
    callback arguments. ``service`` is the consuming service's name (the ``svc`` field).
    Override ``event_classifier`` / ``username`` / ``origin`` / ``credentials`` to customize
    classification and identity extraction."""

    def __init__(self, service: str, *, version: tuple[int, int] = (0, 1),
                 protocol: str = "JSONRPC",
                 event_classifier: Callable[[JSONRPCRequest], "EventType | str"]
                 = default_event_classifier,
                 username: Callable[[Any], str] = default_username,
                 origin: Callable[[Any], "str | None"] = default_origin,
                 credentials: Callable[[Any], "dict[str, Any] | None"] = default_credentials
                 ) -> None:
        self.service = service
        self.version = version
        self.protocol = protocol
        self._classify = event_classifier
        self._username = username
        self._origin = origin
        self._credentials = credentials

    def build(self, request: JSONRPCRequest, response: dict[str, Any], session_state: Any,
              audit_message: str | None = None) -> dict[str, Any]:
        """The ``{"TNAUDIT": {...}}`` record dict (no I/O)."""
        vers = {"major": self.version[0], "minor": self.version[1]}
        success = "error" not in response
        origin = self._origin(session_state)
        event = str(self._classify(request))
        svc_data = {
            "vers": vers,
            "origin": origin,
            "protocol": self.protocol,
            "credentials": self._credentials(session_state),
        }
        event_data: dict[str, Any] = {
            "method": request.method,
            "params": [_to_builtin(request.params)],   # 1-elem list ~ middleware's positional params
            "description": audit_message,
            "success": success,
            "error": response.get("error") if not success else None,
            "vers": vers,
        }
        if event != EventType.METHOD_CALL and success and "result" in response:
            event_data["result"] = _to_builtin(response["result"])
        return {"TNAUDIT": {
            "aid": str(uuid.uuid4()),
            "vers": vers,
            "addr": origin,
            "user": self._username(session_state),
            "sess": getattr(session_state, "session_uuid", None),
            "time": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S.%f"),
            "svc": self.service,
            "svc_data": json.dumps(svc_data, default=str),
            "event": event,
            "event_data": json.dumps(event_data, default=str),
            "success": success,
        }}

    def format(self, request: JSONRPCRequest, response: dict[str, Any], session_state: Any,
               audit_message: str | None = None) -> str:
        """The wire string: ``"@cee:"`` + the JSON record (what middleware emits to syslog)."""
        record = self.build(request, response, session_state, audit_message)
        return "@cee:" + json.dumps(record, default=str)
