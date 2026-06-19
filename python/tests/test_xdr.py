"""XDR binary-wire tests: the additive RFC-4506 path (``truenas_pyjsonrpc.xdr`` codec +
``JSONRPCProtocol``'s magic-routed ``_dispatch_one_xdr``).

The codec is the normative reference for the Zig comptime codec (the conformance A/B in
``zig/conformance`` compares exact bytes); these tests pin the Python side: the codec
round-trips every supported type, and the protocol dispatches an XDR frame through the SAME
authorize/gate/audit core as JSON — selected purely by the 4-byte magic prefix.

Proc-ids 0..=1000 are reserved for protocol control messages, so application methods here use
ids >= 1001 (see ``XDR_RESERVED_PROC_MAX``).
"""
from enum import IntEnum

import msgspec
import pytest

from truenas_pyjsonrpc import (
    AuthorizationResponse,
    FilterableJSONRPCMethod,
    JSONRPCError,
    JSONRPCMethod,
    JSONRPCProtocol,
    MessageDirection,
    SessionLifecycle,
)

pytest.importorskip("xdrlib3")
import xdrlib3  # noqa: E402
from truenas_pyjsonrpc import xdr  # noqa: E402  (lazy optional dep; only XDR servers need it)

UID = bytes.fromhex("123e4567e89b12d3a456426614174000")
UID_STR = "123e4567-e89b-12d3-a456-426614174000"
PROC_ADD = 1001       # an application proc-id (>= 1001; 0..=1000 are reserved)
BAD_PROC = 9999       # an unregistered application proc-id


# --- types ------------------------------------------------------------------
class AddArgs(msgspec.Struct):
    a: xdr.Int32
    b: xdr.Int32


class AddResult(msgspec.Struct):
    sum: xdr.Hyper
    label: str


class Inner(msgspec.Struct):
    x: xdr.Int32


class Color(IntEnum):
    RED = 0
    GREEN = 1
    BLUE = 2


class Wide(msgspec.Struct):
    i: xdr.Int32
    big: xdr.Hyper
    u: xdr.U32
    f: float
    s: str
    flag: bool
    opt: str | None
    items: list[xdr.Int32]
    inner: Inner
    color: Color


def add(request, session_state, request_state):
    return AddResult(sum=request.a + request.b, label="ok")


def _add_proto(**proto_kw):
    return JSONRPCProtocol(
        [JSONRPCMethod("add", accepts=AddArgs, returns=AddResult, handler=add,
                       xdr=True, xdr_id=PROC_ADD)],
        name="t", version="1.0.0", **proto_kw)


def _parse_reply(reply):
    """(rid_bytes, status, rest_bytes) from a reply frame; rest is the result/error tail."""
    u = xdrlib3.Unpacker(reply)
    assert u.unpack_uint() == xdr.MAGIC
    assert u.unpack_uint() == xdr.VERSION
    rid = u.unpack_fopaque(16) if u.unpack_uint() else None
    status = u.unpack_uint()
    return rid, status, reply[u.get_position():]


def _err(reply):
    """(code, detail_bytes) from a status=1 error reply frame."""
    rid, status, rest = _parse_reply(reply)
    assert status == 1, "expected an error reply"
    u = xdrlib3.Unpacker(rest)
    return u.unpack_int(), u.unpack_string()


# --- codec round-trips ------------------------------------------------------
def test_codec_roundtrip_all_types():
    v = Wide(i=-7, big=2**40, u=4_000_000_000, f=1.5, s="héllo", flag=True,
             opt="present", items=[1, 2, 3], inner=Inner(x=9), color=Color.BLUE)
    blob = xdr.encode(v, Wide)
    assert len(blob) % 4 == 0  # canonical XDR is always 4-byte aligned
    assert xdr.decode(blob, Wide) == v


def test_codec_optional_absent_is_one_word():
    v = Wide(i=0, big=0, u=0, f=0.0, s="", flag=False, opt=None, items=[],
             inner=Inner(x=0), color=Color.RED)
    assert xdr.decode(xdr.encode(v, Wide), Wide) == v


def test_codec_string_padding_no_nul():
    # "abc" -> u32 len 3 + 'abc' + 1 pad byte; no NUL terminator.
    blob = xdr.encode(AddResult(sum=0, label="abc"), AddResult)
    assert blob.endswith(b"\x00\x00\x00\x03abc\x00")


# --- dispatch: success ------------------------------------------------------
def test_dispatch_success_roundtrip():
    proto = _add_proto()
    req = xdr.request_frame(PROC_ADD, UID, xdr.encode(AddArgs(a=2, b=3), AddArgs))
    rid, status, rest = _parse_reply(proto.dispatch(req, proto.new_session()))
    assert rid == UID and status == 0
    assert xdr.decode(rest, AddResult) == AddResult(sum=5, label="ok")


def test_dispatch_matches_manual_frame():
    # The dispatched reply must be byte-identical to a hand-assembled canonical frame.
    proto = _add_proto()
    req = xdr.request_frame(PROC_ADD, UID, xdr.encode(AddArgs(a=2, b=3), AddArgs))
    manual = xdr.reply_frame(UID, xdr.encode(AddResult(sum=5, label="ok"), AddResult))
    assert proto.dispatch(req, proto.new_session()) == manual


def test_dispatch_notification_no_reply():
    # No id -> a notification -> no reply (the handler still runs).
    proto = _add_proto()
    req = xdr.request_frame(PROC_ADD, None, xdr.encode(AddArgs(a=2, b=3), AddArgs))
    assert proto.dispatch(req, proto.new_session()) is None


# --- dispatch: errors -------------------------------------------------------
def test_dispatch_method_not_found():
    proto = _add_proto()
    req = xdr.request_frame(BAD_PROC, UID, b"")
    code, detail = _err(proto.dispatch(req, proto.new_session()))
    assert code == int(JSONRPCError.METHOD_NOT_FOUND)
    assert detail == b'{"code":-32601,"message":"Method not found"}'


def test_dispatch_unknown_method_notification_silent():
    proto = _add_proto()
    req = xdr.request_frame(BAD_PROC, None, b"")
    assert proto.dispatch(req, proto.new_session()) is None


def test_dispatch_invalid_params_truncated():
    proto = _add_proto()
    # AddArgs needs two int32s (8 bytes); supply only one.
    req = xdr.request_frame(PROC_ADD, UID, b"\x00\x00\x00\x01")
    code, _ = _err(proto.dispatch(req, proto.new_session()))
    assert code == int(JSONRPCError.INVALID_PARAMS)


def test_dispatch_version_mismatch():
    proto = _add_proto()
    req = xdr.request_frame(PROC_ADD, UID, xdr.encode(AddArgs(a=1, b=1), AddArgs))
    bad = req[:4] + (2).to_bytes(4, "big") + req[8:]  # bump the version word to 2
    code, _ = _err(proto.dispatch(bad, proto.new_session()))
    assert code == int(JSONRPCError.INVALID_REQUEST)


def test_dispatch_unparseable_frame():
    proto = _add_proto()
    # Magic only, then garbage that can't decode as the RequestEnvelope.
    code, _ = _err(proto.dispatch(b"TXDR\x00", proto.new_session()))
    assert code == int(JSONRPCError.INVALID_REQUEST)


# --- dual wire: the SAME method over JSON and XDR ---------------------------
def test_same_method_both_wires():
    proto = _add_proto()
    sess = proto.new_session()
    xreq = xdr.request_frame(PROC_ADD, UID, xdr.encode(AddArgs(a=2, b=3), AddArgs))
    _, status, rest = _parse_reply(proto.dispatch(xreq, sess))
    assert status == 0 and xdr.decode(rest, AddResult).sum == 5

    jreq = ('{"jsonrpc":"2.0","id":"%s","method":"add","params":{"a":2,"b":3}}' % UID_STR)
    jresp = msgspec.json.decode(proto.dispatch(jreq, sess))
    assert jresp["result"] == {"sum": 5, "label": "ok"}


def test_json_dispatch_unaffected_when_no_xdr():
    # A JSON-only protocol still dispatches JSON (the magic sniff never fires on `{`).
    proto = JSONRPCProtocol(
        [JSONRPCMethod("add", accepts=AddArgs, returns=AddResult, handler=add)],
        name="t", version="1.0.0")
    assert proto._xdr_methods == {}
    jreq = ('{"jsonrpc":"2.0","id":"%s","method":"add","params":{"a":4,"b":5}}' % UID_STR)
    assert msgspec.json.decode(proto.dispatch(jreq))["result"]["sum"] == 9


# --- registration / construction guards -------------------------------------
def test_duplicate_xdr_id_rejected():
    with pytest.raises(ValueError, match="duplicate xdr_id 1001"):
        JSONRPCProtocol(
            [JSONRPCMethod("add", accepts=AddArgs, returns=AddResult, handler=add,
                           xdr=True, xdr_id=PROC_ADD),
             JSONRPCMethod("add2", accepts=AddArgs, returns=AddResult, handler=add,
                           xdr=True, xdr_id=PROC_ADD)],
            name="t", version="1.0.0")


def test_xdr_id_reserved_range():
    # 0..=1000 are reserved for protocol control messages; an application method must use > 1000.
    for reserved in (0, 1, 1000):
        with pytest.raises(TypeError, match="reserved for protocol control"):
            JSONRPCMethod("add", accepts=AddArgs, returns=AddResult, handler=add,
                          xdr=True, xdr_id=reserved)
    # xdr=True with no xdr_id (defaults to 0) is likewise rejected.
    with pytest.raises(TypeError, match="reserved for protocol control"):
        JSONRPCMethod("add", accepts=AddArgs, returns=AddResult, handler=add, xdr=True)
    # 1001 (the first application id) is accepted.
    m = JSONRPCMethod("add", accepts=AddArgs, returns=AddResult, handler=add,
                      xdr=True, xdr_id=1001)
    assert m.xdr and m.xdr_id == 1001


def test_xdr_rejected_for_server_client():
    with pytest.raises(TypeError, match="SERVER_CLIENT"):
        JSONRPCMethod("topic", accepts=AddArgs, direction=MessageDirection.SERVER_CLIENT,
                      notifies=AddResult, xdr=True, xdr_id=1003)


# --- shared core: gate / authz / audit all apply over XDR -------------------
def test_session_gate_blocks_xdr():
    proto = _add_proto()
    proto.add_session_setup(
        JSONRPCMethod("setup", accepts=AddArgs, returns=AddResult,
                      handler=lambda **k: (SessionLifecycle.ESTABLISHED, AddResult(sum=0, label="x"))))
    req = xdr.request_frame(PROC_ADD, UID, xdr.encode(AddArgs(a=1, b=1), AddArgs))
    code, _ = _err(proto.dispatch(req, proto.new_session()))  # fresh NONE session
    assert code == int(JSONRPCError.SESSION_NOT_ESTABLISHED)


def test_closed_session_blocks_xdr():
    proto = _add_proto()
    sess = proto.new_session()
    proto.close_session(sess)
    req = xdr.request_frame(PROC_ADD, UID, xdr.encode(AddArgs(a=1, b=1), AddArgs))
    code, detail = _err(proto.dispatch(req, sess))
    assert code == int(JSONRPCError.SESSION_NOT_ESTABLISHED)
    assert b"Session is closed" in detail


def test_authz_denial_over_xdr():
    def deny(request, session_state, target=None):
        return AuthorizationResponse(authorized=False, message="nope")

    proto = _add_proto(authorization_handler=deny)
    req = xdr.request_frame(PROC_ADD, UID, xdr.encode(AddArgs(a=1, b=1), AddArgs))
    code, detail = _err(proto.dispatch(req, proto.new_session()))
    assert code == int(JSONRPCError.NOT_AUTHORIZED)
    assert b"nope" in detail


def test_audit_record_emitted_over_xdr():
    records = []

    def audit(request, response, session_state, audit_message):
        records.append((request.method, request.id, response, audit_message))

    proto = JSONRPCProtocol(
        [JSONRPCMethod("add", accepts=AddArgs, returns=AddResult, handler=add,
                       xdr=True, xdr_id=PROC_ADD, audit=True, audit_message="adding")],
        name="t", version="1.0.0", audit_handler=audit)
    req = xdr.request_frame(PROC_ADD, UID, xdr.encode(AddArgs(a=2, b=3), AddArgs))
    proto.dispatch(req, proto.new_session())
    assert len(records) == 1
    method, rid, response, _msg = records[0]
    # The id is canonicalized from the 16 wire bytes to the UUID string for audit/inflight.
    assert method == "add" and rid == UID_STR
    assert response["result"] == AddResult(sum=5, label="ok")


# --- filterable over XDR: augmented accepts (base · options · JSON-filters) → list / count ----
class FQueryArgs(msgspec.Struct):
    pass


class FEntry(msgspec.Struct):
    id: xdr.Hyper
    name: str
    ratio: float
    active: bool
    note: str | None = None


_FDATA = [
    {"id": 1, "name": "a", "ratio": 0.5, "active": True, "note": "x"},
    {"id": 2, "name": "b", "ratio": 2.5, "active": False, "note": None},
    {"id": 3, "name": "a", "ratio": 1.5, "active": True, "note": None},
]


def _filter_proto():
    pytest.importorskip("truenas_pyfilter")
    from truenas_pyfilter import tnfilter

    def fquery(request, session_state, request_state, filters, options):
        return tnfilter(_FDATA, filters=filters, options=options)

    return JSONRPCProtocol(
        [FilterableJSONRPCMethod("q", accepts=FQueryArgs, entry=FEntry, handler=fquery,
                                 xdr=True, xdr_id=2001)],
        name="t", version="1.0.0")


def _query_req(opts, filters_json):
    params = (xdr.encode(FQueryArgs(), FQueryArgs)
              + xdr.encode(opts, xdr.XdrQueryOptions)
              + xdr.encode(filters_json, str))
    return xdr.request_frame(2001, UID, params)


def test_filterable_xdr_list():
    proto = _filter_proto()
    req = _query_req(xdr.XdrQueryOptions(), '[["name","=","a"]]')
    _, status, rest = _parse_reply(proto.dispatch(req, proto.new_session()))
    assert status == 0
    u = xdrlib3.Unpacker(rest)
    assert u.unpack_uint() == 2  # two matches (ids 1, 3)
    e0 = xdr.decode(rest[u.get_position():], FEntry)
    assert e0.id == 1 and e0.name == "a"


def test_filterable_xdr_count():
    proto = _filter_proto()
    req = _query_req(xdr.XdrQueryOptions(count=True), '[["name","=","a"]]')
    _, status, rest = _parse_reply(proto.dispatch(req, proto.new_session()))
    assert status == 0
    assert xdr.decode(rest, xdr.Hyper) == 2  # count → a bare hyper


def test_filterable_xdr_order_desc():
    proto = _filter_proto()
    req = _query_req(xdr.XdrQueryOptions(order_by=["-id"]), "[]")
    _, status, rest = _parse_reply(proto.dispatch(req, proto.new_session()))
    assert status == 0
    u = xdrlib3.Unpacker(rest)
    assert u.unpack_uint() == 3
    pos = u.get_position()
    ids = []
    for _ in range(3):
        sub = xdrlib3.Unpacker(rest[pos:])
        ids.append(xdr._dec(sub, FEntry).id)
        pos += sub.get_position()
    assert ids == [3, 2, 1]


def test_filterable_xdr_bad_filter_invalid_params():
    proto = _filter_proto()
    req = _query_req(xdr.XdrQueryOptions(), '[["name","??","a"]]')
    code, _ = _err(proto.dispatch(req, proto.new_session()))
    assert code == int(JSONRPCError.INVALID_PARAMS)
