#!/usr/bin/env python3
"""A/B conformance oracle: drives the Python reference `JSONRPCProtocol.dispatch` over a corpus and
writes the golden responses (and audit records) the Zig engine must reproduce structurally.

The reference protocols here must mirror `zig/conformance/reference.zig` exactly (same method names,
accepts/returns shapes, handler results, hooks, audit flags, secret fields). Run from anywhere:

    python3 zig/conformance/generate.py

Output: zig/conformance/golden.json  (committed; CI regenerates it and `git diff --exit-code`s).
Framework-generated `error.data` (an impl-specific detail string) is stripped from both the wire
response and the audit response — the wire contract is the error *code* + *message*, which both
implementations match.
"""
import json
import os
import sys
import uuid
from typing import Annotated

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "python"))

import msgspec  # noqa: E402
from truenas_pyjsonrpc import (  # noqa: E402
    JSONRPCProtocol,
    JSONRPCMethod,
    FilterableJSONRPCMethod,
    JSONRPCFdTransferMethod,
    TransferDirection,
    JsonRpcError,
    JSONRPCError,
    AuthorizationResponse,
    MessageDirection,
    SessionLifecycle,
    SECRET,
)
from truenas_pyjsonrpc.transfer import FileTransfer  # noqa: E402
from truenas_pyfilter import tnfilter  # noqa: E402  (the normative C filter engine — the `filter` oracle)
from truenas_pyjsonrpc import xdr  # noqa: E402  (the normative XDR codec — emits the byte-exact `xdr` golden)


# Deterministic subscription ids: pin uuid4 to a counter so the pub/sub golden's sub_id is reproducible
# (the Zig side injects a matching FixedIdGen — a *consumer* concern, like the capturing audit sink). The
# session_uuid is also a uuid4 but never appears on the wire; resetting the counter per case AFTER
# new_session() consumes it first, so the first minted sub_id is ...000000000001.
class _SeqUuid:
    def __init__(self):
        self.n = 0

    def reset(self):
        self.n = 0

    def __call__(self):
        self.n += 1
        return uuid.UUID(f"00000000-0000-4000-8000-{self.n:012d}")


_SEQ_UUID = _SeqUuid()
uuid.uuid4 = _SEQ_UUID  # protocol.py calls uuid.uuid4() at runtime; _is_uuid uses uuid.UUID (unaffected)


class PoolCreateArgs(msgspec.Struct):
    name: str


class PoolCreateResult(msgspec.Struct):
    id: int
    name: str


class AddArgs(msgspec.Struct):
    a: int
    b: int


class AddResult(msgspec.Struct):
    sum: int


class NoArgs(msgspec.Struct):
    pass


class ServerInfoResult(msgspec.Struct):
    name: str
    version: str


# --- audit protocol: secret in/out, a runtime audit detail, a denial, an erroring audited method ---
class LoginArgs(msgspec.Struct):
    user: str
    password: Annotated[str, SECRET]


class LoginResult(msgspec.Struct):
    token: Annotated[str, SECRET]
    ok: bool


class PingArgs(msgspec.Struct):
    pass


class PingResult(msgspec.Struct):
    pong: bool


# --- gated protocol: session-setup + the ESTABLISHED gate + a pre_auth method ---
class SetupArgs(msgspec.Struct):
    user: str


class ContinueArgs(msgspec.Struct):
    otp: str


class SetupAck(msgspec.Struct):
    stage: str


class WhoamiResult(msgspec.Struct):
    who: str


class VersionResult(msgspec.Struct):
    v: str


# --- pubsub protocol: a SERVER_CLIENT subscribable topic (subscribe → a minted sub_id ack; no handler) ---
class SubArgs(msgspec.Struct):
    channel: str


class AlertEvent(msgspec.Struct):  # the `notifies` payload (required for a SERVER_CLIENT method)
    level: str
    text: str


def pool_create(request, session_state, request_state):
    return PoolCreateResult(id=7, name=request.name)


def add(request, session_state, request_state):
    return AddResult(sum=request.a + request.b)


def boom(request, session_state, request_state):
    raise RuntimeError("boom")


def failing(request, session_state, request_state):
    raise JsonRpcError(JSONRPCError.REQUEST_FAILED, "expected failure")


def secret_op(request, session_state, request_state):
    return AddResult(sum=request.a + request.b)


def authorize(request, session_state, target=None):  # cancel passes target= (None here, no registry)
    if request.method == "$/cancelRequest":
        return AuthorizationResponse(authorized=False, message="cannot cancel")
    if request.method == "secret_op":
        return AuthorizationResponse(authorized=False, message="nope")
    return AuthorizationResponse(authorized=True)


def server_info(session_state):
    return ServerInfoResult(name="truenas", version="42")


def login(request, session_state, request_state):
    request_state.set_audit(f"as {request.user}")
    return LoginResult(token="tok-secret", ok=True)


def ping(request, session_state, request_state):
    return PingResult(pong=True)


def crash(request, session_state, request_state):
    raise RuntimeError("kaboom")


def gated_setup(request, session_state):
    return (SessionLifecycle.INIT, SetupAck(stage="init"))


def gated_continue(request, session_state):
    return (SessionLifecycle.ESTABLISHED, SetupAck(stage="established"))


def whoami(request, session_state, request_state):
    return WhoamiResult(who="authed")


def version(request, session_state, request_state):
    return VersionResult(v="1.0")


# gated_audit: session-setup with a secret credential AND a secret result, plus an audit handler — so
# $/sessionSetup / $/sessionSetupContinue / $/sessionClose emit (redacted) control-op audit records.
class GAuthCreds(msgspec.Struct):
    user: str
    password: Annotated[str, SECRET]


class GAuthAck(msgspec.Struct):
    token: Annotated[str, SECRET]
    stage: str


class GAuthContinue(msgspec.Struct):
    otp: str


def gauth_setup(request, session_state):
    return (SessionLifecycle.INIT, GAuthAck(token="t0p", stage="init"))


def gauth_continue(request, session_state):
    return (SessionLifecycle.ESTABLISHED, GAuthAck(token="t1", stage="established"))


def audit_authorize(request, session_state, target=None):  # cancel passes target= (allowed here)
    # request.params is the decoded struct; deny `login` for a specific user.
    if request.method == "login" and getattr(request.params, "user", None) == "denyme":
        return AuthorizationResponse(authorized=False, message="denied")
    return AuthorizationResponse(authorized=True)


# --- filter protocol: a filterable query method; the handler push-downs through the normative C engine ---
class FQueryArgs(msgspec.Struct):  # the (empty) base accepts — augmented with query-filters/query-options
    pass


class FEntry(msgspec.Struct):  # the per-record element type (drives codegen/openrpc; not used at runtime)
    id: xdr.Hyper  # i64 on both wires: JSON ignores the marker; XDR encodes a hyper (matches Zig Entry.id)
    name: str
    ratio: float
    active: bool
    note: str | None = None


# Byte-for-byte the same records as reference.zig's `filter_data`, so the Zig engine and this oracle agree.
_FDATA = [
    {"id": 1, "name": "alpha", "ratio": 0.5, "active": True, "note": "x"},
    {"id": 2, "name": "beta", "ratio": 2.5, "active": False, "note": None},
    {"id": 3, "name": "alpha", "ratio": 1.5, "active": True, "note": None},
    {"id": 4, "name": "gamma", "ratio": 3.5, "active": False, "note": "y"},
    {"id": 5, "name": "Alpha", "ratio": 0.25, "active": True, "note": "z"},
]


def fquery(request, session_state, request_state, filters, options):
    # Push-down: stream the source through the compiled query (the C engine applies
    # filters/order_by/offset/limit/count). The framework's finalize then unwraps count→int.
    return tnfilter(_FDATA, filters=filters, options=options)


def _strip_error_data(obj):
    if isinstance(obj, dict) and isinstance(obj.get("error"), dict):
        err = obj["error"]
        err.pop("data", None)  # strip impl-specific detail
        # A filterable compile error's MESSAGE embeds the C engine's internal wording
        # (query.py raises `f"invalid query: {e}"`) — an impl-specific detail like `data`.
        # The asserted contract is INVALID_PARAMS with the canonical message; the Zig port
        # returns that rather than replicate the C engine's text, so normalize it here.
        if isinstance(err.get("message"), str) and err["message"].startswith("invalid query:"):
            err["message"] = "Invalid params"
    return obj


_AUDIT_LOG = []


def _record_audit(request, response, session_state, audit_message):
    _AUDIT_LOG.append({
        "method": request.method,
        "id": request.id,
        "params": msgspec.to_builtins(request.params),
        "roles": list(request.roles),
        "response": _strip_error_data(msgspec.to_builtins(response)),
        "message": audit_message,
    })


COMMON = [
    JSONRPCMethod("pool.create", accepts=PoolCreateArgs, returns=PoolCreateResult, handler=pool_create),
    JSONRPCMethod("add", accepts=AddArgs, returns=AddResult, handler=add),
    JSONRPCMethod("boom", accepts=NoArgs, returns=NoArgs, handler=boom),
    JSONRPCMethod("fail", accepts=NoArgs, returns=NoArgs, handler=failing),
]
PROTO_OPEN = JSONRPCProtocol(list(COMMON), name="test", version="1.0.0")
PROTO_OPEN.register_server_info(server_info, returns=ServerInfoResult)
PROTO_AUTHZ = JSONRPCProtocol(
    list(COMMON) + [JSONRPCMethod("secret_op", accepts=AddArgs, returns=AddResult, handler=secret_op)],
    name="test",
    version="1.0.0",
    authorization_handler=authorize,
)
PROTO_AUDIT = JSONRPCProtocol(
    [
        JSONRPCMethod("login", accepts=LoginArgs, returns=LoginResult, handler=login,
                      audit=True, audit_message="user login"),
        JSONRPCMethod("ping", accepts=PingArgs, returns=PingResult, handler=ping),
        JSONRPCMethod("crash", accepts=NoArgs, returns=PingResult, handler=crash,
                      audit=True, audit_message="crash op"),
    ],
    name="test",
    version="1.0.0",
    authorization_handler=audit_authorize,
)
PROTO_AUDIT.register_audit_handler(_record_audit)
PROTO_GATED = JSONRPCProtocol(
    [
        JSONRPCMethod("whoami", accepts=NoArgs, returns=WhoamiResult, handler=whoami),
        JSONRPCMethod("version", accepts=NoArgs, returns=VersionResult, handler=version, pre_auth=True),
    ],
    name="test",
    version="1.0.0",
)
PROTO_GATED.add_session_setup(
    JSONRPCMethod("setup", accepts=SetupArgs, returns=SetupAck, handler=gated_setup),
    JSONRPCMethod("continue", accepts=ContinueArgs, returns=SetupAck, handler=gated_continue),
)
PROTO_GATED_AUDIT = JSONRPCProtocol([], name="test", version="1.0.0")
PROTO_GATED_AUDIT.add_session_setup(
    JSONRPCMethod("setup", accepts=GAuthCreds, returns=GAuthAck, handler=gauth_setup),
    JSONRPCMethod("continue", accepts=GAuthContinue, returns=GAuthAck, handler=gauth_continue),
)
PROTO_GATED_AUDIT.register_audit_handler(_record_audit)
PROTO_PUBSUB = JSONRPCProtocol(
    [JSONRPCMethod("alerts.subscribe", accepts=SubArgs, direction=MessageDirection.SERVER_CLIENT,
                   notifies=AlertEvent)],
    name="test",
    version="1.0.0",
)
PROTO_FILTER = JSONRPCProtocol(
    [FilterableJSONRPCMethod("x.query", accepts=FQueryArgs, entry=FEntry, handler=fquery)],
    name="test",
    version="1.0.0",
)
PROTOS = {"open": PROTO_OPEN, "authz": PROTO_AUTHZ, "audit": PROTO_AUDIT,
          "gated": PROTO_GATED, "gated_audit": PROTO_GATED_AUDIT, "pubsub": PROTO_PUBSUB,
          "filter": PROTO_FILTER}

UID = "123e4567-e89b-12d3-a456-426614174000"
UID_UPPER = UID.upper()
TARGET = "00000000-0000-4000-8000-0000000000aa"  # a $/cancelRequest target id (never in flight here)


def _fq(params_json):  # a filterable `x.query` request wire with the given params
    return '{"jsonrpc":"2.0","id":"%s","method":"x.query","params":%s}' % (UID, params_json)

# (name, protocol, wire)
CASES = [
    ("happy_create", "open", '{"jsonrpc":"2.0","id":"%s","method":"pool.create","params":{"name":"tank"}}' % UID),
    ("typed_add", "open", '{"jsonrpc":"2.0","id":"%s","method":"add","params":{"a":2,"b":3}}' % UID),
    ("uppercase_id_echoed", "open", '{"jsonrpc":"2.0","id":"%s","method":"add","params":{"a":1,"b":1}}' % UID_UPPER),
    ("method_not_found", "open", '{"jsonrpc":"2.0","id":"%s","method":"nope"}' % UID),
    ("invalid_params_missing", "open", '{"jsonrpc":"2.0","id":"%s","method":"pool.create","params":{}}' % UID),
    ("invalid_params_wrongtype", "open", '{"jsonrpc":"2.0","id":"%s","method":"pool.create","params":{"name":123}}' % UID),
    ("invalid_params_array", "open", '{"jsonrpc":"2.0","id":"%s","method":"add","params":[2,3]}' % UID),
    ("internal_error", "open", '{"jsonrpc":"2.0","id":"%s","method":"boom"}' % UID),
    ("custom_request_failed", "open", '{"jsonrpc":"2.0","id":"%s","method":"fail"}' % UID),
    ("notification_no_reply", "open", '{"jsonrpc":"2.0","method":"pool.create","params":{"name":"tank"}}'),
    ("unknown_method_notification", "open", '{"jsonrpc":"2.0","method":"nope"}'),
    ("malformed_json", "open", "{not json"),
    ("top_level_array", "open", "[1,2,3]"),
    ("bad_jsonrpc_version", "open", '{"jsonrpc":"1.0","id":"%s","method":"add","params":{"a":1,"b":1}}' % UID),
    ("non_uuid_id", "open", '{"jsonrpc":"2.0","id":42,"method":"add","params":{"a":1,"b":1}}'),
    ("null_id", "open", '{"jsonrpc":"2.0","id":null,"method":"add","params":{"a":1,"b":1}}'),
    ("server_info", "open", '{"jsonrpc":"2.0","id":"%s","method":"$/serverInfo"}' % UID),
    ("server_info_no_id", "open", '{"jsonrpc":"2.0","method":"$/serverInfo"}'),
    ("unknown_control", "open", '{"jsonrpc":"2.0","id":"%s","method":"$/nope"}' % UID),
    ("unknown_control_notification", "open", '{"jsonrpc":"2.0","method":"$/nope"}'),
    # authz protocol — authorizer denies `secret_op`
    ("authz_allowed", "authz", '{"jsonrpc":"2.0","id":"%s","method":"add","params":{"a":1,"b":1}}' % UID),
    ("authz_denied", "authz", '{"jsonrpc":"2.0","id":"%s","method":"secret_op","params":{"a":1,"b":1}}' % UID),
    ("authz_denied_bad_params", "authz", '{"jsonrpc":"2.0","id":"%s","method":"secret_op","params":[1,2]}' % UID),
    # audit protocol — secret redaction (params + result), message join, denial/error/notification, gating
    ("audit_login_ok", "audit", '{"jsonrpc":"2.0","id":"%s","method":"login","params":{"user":"bob","password":"hunter2"}}' % UID),
    ("audit_login_denied", "audit", '{"jsonrpc":"2.0","id":"%s","method":"login","params":{"user":"denyme","password":"x"}}' % UID),
    ("audit_login_notification", "audit", '{"jsonrpc":"2.0","method":"login","params":{"user":"bob","password":"hunter2"}}'),
    ("audit_crash", "audit", '{"jsonrpc":"2.0","id":"%s","method":"crash"}' % UID),
    ("audit_ping_no_record", "audit", '{"jsonrpc":"2.0","id":"%s","method":"ping","params":{}}' % UID),
    # gated protocol — single-dispatch (fresh NONE session): gate, pre_auth bypass, wrong-state/shape
    ("gated_blocked_before_setup", "gated", '{"jsonrpc":"2.0","id":"%s","method":"whoami","params":{}}' % UID),
    ("gated_pre_auth_allowed", "gated", '{"jsonrpc":"2.0","id":"%s","method":"version","params":{}}' % UID),
    ("gated_setup_no_id", "gated", '{"jsonrpc":"2.0","method":"$/sessionSetup","params":{"user":"bob"}}'),
    ("gated_continue_wrong_state", "gated", '{"jsonrpc":"2.0","id":"%s","method":"$/sessionSetupContinue","params":{"otp":"x"}}' % UID),
    ("gated_close_wrong_state", "gated", '{"jsonrpc":"2.0","id":"%s","method":"$/sessionClose"}' % UID),
    # gated_audit — control-op audit: $/sessionSetup on a fresh NONE session, creds+result redacted.
    ("gated_audit_setup", "gated_audit", '{"jsonrpc":"2.0","id":"%s","method":"$/sessionSetup","params":{"user":"bob","password":"hunter2"}}' % UID),
    # pubsub — subscribe to a SERVER_CLIENT topic: a minted sub_id ack (deterministic via the pinned
    # uuid4 ↔ the Zig FixedIdGen); a subscribe-as-notification is INVALID_REQUEST; bad params → 422.
    ("subscribe_ok", "pubsub", '{"jsonrpc":"2.0","id":"%s","method":"alerts.subscribe","params":{"channel":"pool"}}' % UID),
    ("subscribe_no_id", "pubsub", '{"jsonrpc":"2.0","method":"alerts.subscribe","params":{"channel":"pool"}}'),
    ("subscribe_bad_params", "pubsub", '{"jsonrpc":"2.0","id":"%s","method":"alerts.subscribe","params":{}}' % UID),
    # $/cancelRequest — the sans-I/O control op (envelope checks, authz, audit; no registry → target not
    # found → REQUEST_FAILED). Target resolution + the cooperative cancel land with the transport.
    ("cancel_no_id", "open", '{"jsonrpc":"2.0","method":"$/cancelRequest","params":{"target_id":"%s"}}' % TARGET),
    ("cancel_bad_params", "open", '{"jsonrpc":"2.0","id":"%s","method":"$/cancelRequest","params":{}}' % UID),
    ("cancel_denied", "authz", '{"jsonrpc":"2.0","id":"%s","method":"$/cancelRequest","params":{"target_id":"%s"}}' % (UID, TARGET)),
    ("cancel_unknown_target", "audit", '{"jsonrpc":"2.0","id":"%s","method":"$/cancelRequest","params":{"target_id":"%s"}}' % (UID, TARGET)),
    # filter protocol — a filterable query method (x.query), filtered/ordered/counted by the normative C
    # engine. Only cross-engine-safe inputs: every filter names a real field with a type-correct literal, so
    # the typed Zig port (which is STRICTER — unknown field / type mismatch / dropped `~` are INVALID_PARAMS
    # there but a silent no-match / regex-match in the dict-based C engine) agrees on the result. Those
    # divergent inputs are Zig-only unit tests, not A/B cases. Result arrays compare order-sensitively, so
    # record ordering is part of the asserted contract.
    ("filter_all", "filter", _fq("{}")),
    ("filter_eq", "filter", _fq('{"query-filters":[["name","=","alpha"]]}')),
    ("filter_ci_eq", "filter", _fq('{"query-filters":[["name","C=","alpha"]]}')),
    ("filter_gt_float", "filter", _fq('{"query-filters":[["ratio",">",1.5]]}')),
    ("filter_ge_int", "filter", _fq('{"query-filters":[["id",">=",4]]}')),
    ("filter_in", "filter", _fq('{"query-filters":[["id","in",[1,4]]]}')),
    ("filter_nin", "filter", _fq('{"query-filters":[["id","nin",[1,4]]]}')),
    ("filter_startswith", "filter", _fq('{"query-filters":[["name","^","al"]]}')),
    ("filter_endswith", "filter", _fq('{"query-filters":[["name","$","ha"]]}')),
    ("filter_rin", "filter", _fq('{"query-filters":[["name","rin","ph"]]}')),
    ("filter_bool", "filter", _fq('{"query-filters":[["active","=",true]]}')),
    ("filter_null_eq", "filter", _fq('{"query-filters":[["note","=",null]]}')),
    ("filter_null_ne", "filter", _fq('{"query-filters":[["note","!=",null]]}')),
    ("filter_implicit_and", "filter", _fq('{"query-filters":[["name","=","alpha"],["active","=",true]]}')),
    ("filter_or", "filter", _fq('{"query-filters":[["OR",[["id","=",1],["id","=",4]]]]}')),
    ("filter_and_group_in_or", "filter", _fq('{"query-filters":[["OR",[[["name","=","alpha"],["active","=",true]],["id","=",4]]]]}')),
    ("filter_count", "filter", _fq('{"query-filters":[["name","=","alpha"]],"query-options":{"count":true}}')),
    ("filter_count_ignores_paging", "filter", _fq('{"query-filters":[],"query-options":{"count":true,"offset":1,"limit":2}}')),
    ("filter_order_desc", "filter", _fq('{"query-filters":[],"query-options":{"order_by":["-ratio"]}}')),
    ("filter_order_paging", "filter", _fq('{"query-filters":[],"query-options":{"order_by":["id"],"offset":1,"limit":2}}')),
    ("filter_order_multi", "filter", _fq('{"query-filters":[],"query-options":{"order_by":["name","-id"]}}')),
    ("filter_order_nulls_first", "filter", _fq('{"query-filters":[],"query-options":{"order_by":["nulls_first:note"]}}')),
    ("filter_order_nulls_last", "filter", _fq('{"query-filters":[],"query-options":{"order_by":["nulls_last:note"]}}')),
    ("filter_invalid_op", "filter", _fq('{"query-filters":[["name","??","a"]]}')),
    ("filter_invalid_arity", "filter", _fq('{"query-filters":[["name","="]]}')),
]

# Delivery cases: subscribe, then the SERVER publishes to the topic; the drained outbound notification
# stream is the golden the Zig transport must reproduce. (name, protocol, subscribe_wire, [(method, payload)])
DELIVERY_CASES = [
    ("pubsub_delivery", "pubsub",
     '{"jsonrpc":"2.0","id":"%s","method":"alerts.subscribe","params":{"channel":"pool"}}' % UID,
     [("alerts.subscribe", {"level": "warn", "text": "pool degraded"}),
      ("alerts.subscribe", {"level": "info", "text": "scrub done"})]),
]

# Stateful sequences dispatched on ONE session (lifecycle carries forward across steps).
SEQ_CASES = [
    ("gated_full_flow", "gated", [
        '{"jsonrpc":"2.0","id":"%s","method":"$/sessionSetup","params":{"user":"bob"}}' % UID,        # → init
        '{"jsonrpc":"2.0","id":"%s","method":"whoami","params":{}}' % UID,                            # still gated (init)
        '{"jsonrpc":"2.0","id":"%s","method":"$/sessionSetupContinue","params":{"otp":"x"}}' % UID,   # → established
        '{"jsonrpc":"2.0","id":"%s","method":"whoami","params":{}}' % UID,                            # now allowed
        '{"jsonrpc":"2.0","id":"%s","method":"$/sessionClose"}' % UID,                                # → closed (true)
        '{"jsonrpc":"2.0","id":"%s","method":"whoami","params":{}}' % UID,                            # session is closed
    ]),
    # control-op audit across the lifecycle: each step emits a redacted audit record (captured per-step).
    ("gated_audit_flow", "gated_audit", [
        '{"jsonrpc":"2.0","id":"%s","method":"$/sessionSetup","params":{"user":"bob","password":"hunter2"}}' % UID,  # → init, setup audit
        '{"jsonrpc":"2.0","id":"%s","method":"$/sessionSetupContinue","params":{"otp":"x"}}' % UID,                  # → established, continue audit
        '{"jsonrpc":"2.0","id":"%s","method":"$/sessionClose"}' % UID,                                               # → closed, close audit
    ]),
]


def _resp(out):
    return None if out is None else _strip_error_data(json.loads(out))


# --- xdr protocol: the byte-exact binary-wire golden, NORMATIVELY produced by the Python
#     JSONRPCProtocol's XDR dispatch (truenas_pyjsonrpc.xdr is the codec). The request frame is
#     built with xdr.py, then DISPATCHED through the reference server's binary path, so the golden
#     reply is exactly what the server emits — the Zig binary wire must reproduce these bytes. ---
class XdrAddArgs(msgspec.Struct):
    a: xdr.Int32
    b: xdr.Int32


class XdrAddResult(msgspec.Struct):
    sum: xdr.Hyper
    label: str


class XdrEcho(msgspec.Struct):
    items: list[xdr.Int32]
    note: str | None
    flag: bool


def xdr_add(request, session_state, request_state):
    return XdrAddResult(sum=request.a + request.b, label="ok")


def xdr_echo(request, session_state, request_state):
    return XdrEcho(items=request.items, note=request.note, flag=request.flag)


# proc-ids 1001/1002 mirror reference.zig's buildXdr (xdr.add → 1001, xdr.echo → 1002; 0..=1000 are
# reserved for protocol control messages).
PROTO_XDR = JSONRPCProtocol(
    [JSONRPCMethod("xdr.add", accepts=XdrAddArgs, returns=XdrAddResult, handler=xdr_add,
                   xdr=True, xdr_id=1001),
     JSONRPCMethod("xdr.echo", accepts=XdrEcho, returns=XdrEcho, handler=xdr_echo,
                   xdr=True, xdr_id=1002),
     # Filterable over XDR (proc 1003): same FEntry + tnfilter as the JSON filter A/B, binary wire.
     FilterableJSONRPCMethod("xdr.query", accepts=FQueryArgs, entry=FEntry, handler=fquery,
                             xdr=True, xdr_id=1003)],
    name="test", version="1.0.0")

_XDR_UID = bytes.fromhex("123e4567e89b12d3a456426614174000")


def _xdr_cases():
    """Byte-exact request/reply frame pairs the Zig XDR dispatch must reproduce. Each request is
    encoded with the normative xdr.py codec and then dispatched through PROTO_XDR's binary-wire
    path, so the golden reply is what the reference server actually emits (not a hand-assembled
    frame). The Zig A/B decodes the request, runs the matching handler, re-encodes, and asserts
    the wire equals these bytes."""
    cases = []

    def case(name, proc_id, args, args_t):
        req = xdr.request_frame(proc_id, _XDR_UID, xdr.encode(args, args_t))
        reply = PROTO_XDR.dispatch(req, PROTO_XDR.new_session())
        cases.append({"name": name, "request": req.hex(), "reply": reply.hex()})

    case("xdr_add", 1001, XdrAddArgs(a=2, b=3), XdrAddArgs)
    case("xdr_echo", 1002, XdrEcho(items=[1, 2, 3], note="hi", flag=True), XdrEcho)
    case("xdr_echo_empty", 1002, XdrEcho(items=[], note=None, flag=False), XdrEcho)
    # An error reply: an unknown proc-id → a METHOD_NOT_FOUND frame (status=1, int code + the
    # JSON {code,message} detail). Proves the Zig binary error frame matches byte-for-byte too.
    unknown = xdr.request_frame(9999, _XDR_UID, b"")
    cases.append({"name": "xdr_unknown_proc", "request": unknown.hex(),
                  "reply": PROTO_XDR.dispatch(unknown, PROTO_XDR.new_session()).hex()})

    # Filterable over XDR (xdr.query, proc 1003): the augmented accepts ride as XDR<base> +
    # XDR<XdrQueryOptions> + XDR<query-filters as JSON text>; the result is XDR<list[entry]> or a
    # XDR<hyper> (count). The C `tnfilter` engine is the same normative oracle as the JSON filter A/B.
    def qcase(name, opts, filters_json):
        params = (xdr.encode(FQueryArgs(), FQueryArgs)
                  + xdr.encode(opts, xdr.XdrQueryOptions)
                  + xdr.encode(filters_json, str))
        req = xdr.request_frame(1003, _XDR_UID, params)
        reply = PROTO_XDR.dispatch(req, PROTO_XDR.new_session())
        cases.append({"name": name, "request": req.hex(), "reply": reply.hex()})

    qcase("xdr_filter_eq", xdr.XdrQueryOptions(), '[["name","=","alpha"]]')          # → list of 2 (ids 1,3)
    qcase("xdr_filter_count", xdr.XdrQueryOptions(count=True), '[["name","=","alpha"]]')  # → hyper 2
    qcase("xdr_filter_order_desc", xdr.XdrQueryOptions(order_by=["-ratio"]), "[]")    # → all 5, ratio desc
    return cases


# --- transfer protocol: raw-fd transfer methods. The sans-I/O dispatch returns a `Transfer` directive (the
#     `$/transferReady` envelope + a complete() thunk); the actual fd handoff is the server's, exercised
#     end-to-end in tests/test_transfer.py. Here the oracle drives the directive over a MOCK FileTransfer
#     (no real fd) so the Zig dispatch can reproduce the ready envelope + the complete() final response. ---
class TDlArgs(msgspec.Struct):
    size: int


class TDlInterim(msgspec.Struct):
    size: int


class TDlResult(msgspec.Struct):
    sent: int
    label: str


class TUlArgs(msgspec.Struct):
    size: int


class TUlResult(msgspec.Struct):
    received: int
    ok: bool


def t_dl_negotiate(request, session_state):
    return TDlInterim(size=request.size)


def t_dl_transfer(ft):
    # A real DOWNLOAD os.sendfiles on ft.fileno(); the oracle returns a deterministic canned result.
    return TDlResult(sent=ft.params.size, label="ok")


def t_ul_negotiate(request, session_state):
    return True  # the upload interim is a bare bool (ready to receive)


def t_ul_transfer(ft):
    return TUlResult(received=ft.params.size, ok=True)


class _MockFT(FileTransfer):
    def fileno(self):
        return -1


PROTO_TRANSFER = JSONRPCProtocol([
    JSONRPCFdTransferMethod("file.download", accepts=TDlArgs, returns=TDlResult,
                            direction=TransferDirection.DOWNLOAD,
                            negotiate=t_dl_negotiate, transfer=t_dl_transfer, pre_auth=True),
    JSONRPCFdTransferMethod("file.upload", accepts=TUlArgs, returns=TUlResult,
                            direction=TransferDirection.UPLOAD,
                            negotiate=t_ul_negotiate, transfer=t_ul_transfer, pre_auth=True),
], name="test", version="1.0.0")


def _transfer_cases():
    """For each transfer method: dispatch → the `$/transferReady` envelope + the complete() final response
    (over a mock FileTransfer). The Zig dispatch must reproduce both `ready` and `final` structurally."""
    cases = []

    def case(name, wire):
        d = PROTO_TRANSFER.dispatch(wire, PROTO_TRANSFER.new_session())
        ft = _MockFT(d.direction, d.params, d.session_state, result=d.ready["params"]["result"])
        # `final`'s `result` is a msgspec Struct; to_builtins it (the ready dict is already plain).
        cases.append({"name": name, "wire": wire,
                      "ready": msgspec.to_builtins(d.ready),
                      "final": msgspec.to_builtins(d.complete(ft))})

    case("transfer_download", '{"jsonrpc":"2.0","id":"%s","method":"file.download","params":{"size":2048}}' % UID)
    case("transfer_upload", '{"jsonrpc":"2.0","id":"%s","method":"file.upload","params":{"size":4096}}' % UID)
    return cases


def main():
    records = []
    for name, protocol, wire in CASES:
        proto = PROTOS[protocol]
        sess = proto.new_session()
        _SEQ_UUID.reset()  # sub_ids count from ...001 per case (session_uuid already consumed)
        _AUDIT_LOG.clear()
        out = proto.dispatch(wire, sess)
        records.append({"name": name, "protocol": protocol, "wire": wire,
                        "response": _resp(out), "audits": list(_AUDIT_LOG), "steps": []})
    for name, protocol, wires in SEQ_CASES:
        proto = PROTOS[protocol]
        sess = proto.new_session()  # ONE session for the whole sequence
        _SEQ_UUID.reset()  # sub_ids count from ...001 across the sequence (session_uuid consumed first)
        steps = []
        for w in wires:
            _AUDIT_LOG.clear()  # capture audits emitted by THIS step
            response = _resp(proto.dispatch(w, sess))
            steps.append({"wire": w, "response": response, "audits": list(_AUDIT_LOG)})
        records.append({"name": name, "protocol": protocol, "wire": "",
                        "response": None, "audits": [], "steps": steps})
    for name, protocol, subscribe_wire, publishes in DELIVERY_CASES:
        proto = PROTOS[protocol]
        sess = proto.new_session()
        _SEQ_UUID.reset()
        proto.dispatch(subscribe_wire, sess)  # register the subscription
        for method, payload in publishes:
            proto.send_notification(method, payload)
        notifications = []
        while True:  # drain the outbound back-channel (the server's notification thread)
            item = proto.poll_notification(block=False)
            if item is None:
                break
            _session, wire = item
            notifications.append(json.loads(wire))
        records.append({"name": name, "protocol": protocol, "wire": "",
                        "response": None, "audits": [], "steps": [],
                        "delivery": {"subscribe": subscribe_wire,
                                     "publish": [{"method": m, "payload": p} for m, p in publishes],
                                     "notifications": notifications}})

    out_path = os.path.join(HERE, "golden.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    xdr_cases = _xdr_cases()
    transfer_cases = _transfer_cases()
    with open(out_path, "w") as f:
        json.dump({"cases": records, "xdr_cases": xdr_cases, "transfer_cases": transfer_cases},
                  f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"wrote {len(records)} cases + {len(xdr_cases)} xdr + {len(transfer_cases)} transfer "
          f"cases to {os.path.relpath(out_path)}")


if __name__ == "__main__":
    main()
