"""Dispatch-flow tests for JSONRPCProtocol (single messages)."""
import json
import uuid

import msgspec
import pytest

from truenas_pyjsonrpc import (
    JSONRPCError,
    JSONRPCMethod,
    JSONRPCProtocol,
    JsonRpcError,
)


class PoolCreateArgs(msgspec.Struct):
    name: str
    size: int = 0


class PoolCreateResult(msgspec.Struct):
    id: int
    name: str


class NoArgs(msgspec.Struct):
    pass


class AB(msgspec.Struct):
    a: int


def _pool_create(request, session_state, request_state) -> PoolCreateResult:
    return PoolCreateResult(id=7, name=request.name)


def _boom(request, session_state, request_state) -> PoolCreateResult:
    raise RuntimeError("kaboom")


def _custom(request, session_state, request_state) -> PoolCreateResult:
    raise JsonRpcError(-32001, "custom fail", {"x": 1})


def _bad_return(request, session_state, request_state) -> dict:
    return {"id": "not-an-int", "name": "x"}      # violates returns schema


PROTO = JSONRPCProtocol([
    JSONRPCMethod("pool.create", accepts=PoolCreateArgs,
                  returns=PoolCreateResult, handler=_pool_create),
    JSONRPCMethod("ping", accepts=NoArgs,
                  handler=lambda request, session_state, request_state: {"ok": True}),
    JSONRPCMethod("boom", accepts=PoolCreateArgs, handler=_boom),
    JSONRPCMethod("custom", accepts=PoolCreateArgs, handler=_custom),
    JSONRPCMethod("badret", accepts=PoolCreateArgs,
                  returns=PoolCreateResult, handler=_bad_return),
    JSONRPCMethod("orphan", accepts=PoolCreateArgs),          # no handler
])


def uid() -> str:
    return str(uuid.uuid4())


def req(method, params=None, id=...):
    msg = {"jsonrpc": "2.0", "method": method}
    if id is not ...:
        msg["id"] = id
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def rj(wire):
    out = PROTO.dispatch(wire)
    return None if out is None else msgspec.json.decode(out)


# --- happy path ---------------------------------------------------------------
def test_dispatch_happy_echoes_id():
    u = uid()
    r = rj(req("pool.create", {"name": "tank"}, id=u))
    assert r == {"jsonrpc": "2.0", "result": {"id": 7, "name": "tank"}, "id": u}


def test_bytes_and_str_input_equivalent():
    w = req("pool.create", {"name": "x"}, id=uid())
    assert PROTO.dispatch(w) == PROTO.dispatch(w.encode())


def test_empty_struct_method_result():
    u = uid()
    r = rj(req("ping", id=u))
    assert r["result"] == {"ok": True} and r["id"] == u


# --- batch is unsupported -----------------------------------------------------
def test_top_level_array_rejected():
    # batch is intentionally not supported: a top-level Array is Invalid Request
    r = rj('[{"jsonrpc":"2.0","method":"ping","id":"' + uid() + '"}]')
    assert r["error"]["code"] == JSONRPCError.INVALID_REQUEST and r["id"] is None


# --- ids must be UUIDs (refinement of spec) ----------------------------------
def test_int_id_rejected():
    r = rj(req("pool.create", {"name": "x"}, id=42))
    assert r["error"]["code"] == JSONRPCError.INVALID_REQUEST and r["id"] is None


def test_null_id_rejected():
    r = rj('{"jsonrpc":"2.0","method":"pool.create","params":{"name":"x"},"id":null}')
    assert r["error"]["code"] == JSONRPCError.INVALID_REQUEST and r["id"] is None


def test_non_uuid_string_id_rejected():
    r = rj(req("pool.create", {"name": "x"}, id="abc"))
    assert r["error"]["code"] == JSONRPCError.INVALID_REQUEST and r["id"] is None


def test_uppercase_uuid_accepted_and_echoed_verbatim():
    u = str(uuid.uuid4()).upper()
    r = rj(req("pool.create", {"name": "tank"}, id=u))
    assert r["result"] == {"id": 7, "name": "tank"} and r["id"] == u


def test_urn_uuid_rejected():
    u = "urn:uuid:" + str(uuid.uuid4())
    r = rj(req("pool.create", {"name": "x"}, id=u))
    assert r["error"]["code"] == JSONRPCError.INVALID_REQUEST and r["id"] is None


# --- notifications ------------------------------------------------------------
def test_notification_returns_none():
    assert PROTO.dispatch(req("pool.create", {"name": "x"})) is None  # no id


def test_notification_swallows_handler_error():
    assert PROTO.dispatch(req("boom", {"name": "x"})) is None


def test_notification_unknown_method_returns_none():
    assert PROTO.dispatch(req("does.not.exist", {"name": "x"})) is None


def test_notification_runs_handler_side_effect():
    seen = []
    p = JSONRPCProtocol([
        JSONRPCMethod("note", accepts=NoArgs,
                      handler=lambda request, session_state, request_state: seen.append(1)),
    ])
    assert p.dispatch(req("note", {})) is None
    assert seen == [1]


def test_session_state_passed_to_handler():
    captured = []

    def h(request, session_state, request_state):
        captured.append(session_state)
        return {"ok": True}

    p = JSONRPCProtocol([JSONRPCMethod("m", accepts=NoArgs, handler=h)])
    sentinel = {"uid": 0, "session": "abc"}
    session = p.new_session(server_state=sentinel)
    p.dispatch(req("m", {}, id=uid()), session)
    assert captured == [session] and captured[0] is session
    assert captured[0].server_state_internal is sentinel    # opaque, seeded


def test_ephemeral_session_when_none_passed():
    captured = []

    def h(request, session_state, request_state):
        captured.append(session_state)
        return {"ok": True}

    JSONRPCProtocol([JSONRPCMethod("m", accepts=NoArgs, handler=h)]).dispatch(
        req("m", {}, id=uid()))
    assert len(captured) == 1                                # an ephemeral session
    assert captured[0].server_state_internal is None


def test_handler_called_by_keyword():
    # handlers may use **kwargs and still receive request=, session_state=, request_state=
    seen = {}

    def h(**kw):
        seen.update(kw)
        return {"ok": True}

    p = JSONRPCProtocol([JSONRPCMethod("m", accepts=AB, handler=h)])
    p.dispatch(req("m", {"a": 1}, id=uid()), p.new_session(server_state="S"))
    assert set(seen) == {"request", "session_state", "request_state"}
    assert seen["request"].a == 1 and seen["session_state"].server_state_internal == "S"


# --- envelope errors ----------------------------------------------------------
def test_bad_json():
    r = rj("{not json")
    assert r["error"]["code"] == JSONRPCError.INVALID_JSON and r["id"] is None


def test_non_object_message():
    assert rj('"just a string"')["error"]["code"] == JSONRPCError.INVALID_REQUEST


def test_bad_version_echoes_id():
    u = uid()
    r = rj(f'{{"jsonrpc":"1.0","method":"pool.create","id":"{u}","params":{{"name":"x"}}}}')
    assert r["error"]["code"] == JSONRPCError.INVALID_REQUEST and r["id"] == u


def test_missing_method_echoes_id():
    u = uid()
    r = rj(f'{{"jsonrpc":"2.0","id":"{u}"}}')
    assert r["error"]["code"] == JSONRPCError.INVALID_REQUEST and r["id"] == u


def test_missing_method_no_id_is_invalid_request():
    # structural invalidity is never suppressed, even without an id
    assert rj('{"jsonrpc":"2.0"}')["error"]["code"] == JSONRPCError.INVALID_REQUEST


def test_unknown_method_echoes_id():
    u = uid()
    r = rj(req("does.not.exist", {}, id=u))
    assert r["error"]["code"] == JSONRPCError.METHOD_NOT_FOUND and r["id"] == u


# --- params / handler / return errors ----------------------------------------
def test_invalid_params_missing_required():
    u = uid()
    r = rj(req("pool.create", {}, id=u))            # missing 'name'
    assert r["error"]["code"] == JSONRPCError.INVALID_PARAMS and r["id"] == u


def test_invalid_params_wrong_type():
    r = rj(req("pool.create", {"name": 123}, id=uid()))
    assert r["error"]["code"] == JSONRPCError.INVALID_PARAMS


def test_array_params_rejected():
    # by-name only: positional/array params are Invalid params
    r = rj(req("pool.create", [42, 23], id=uid()))
    assert r["error"]["code"] == JSONRPCError.INVALID_PARAMS


def test_handler_exception_is_internal_error():
    u = uid()
    r = rj(req("boom", {"name": "x"}, id=u))
    assert r["error"]["code"] == JSONRPCError.INTERNAL_ERROR and r["id"] == u


def test_jsonrpc_error_passthrough():
    r = rj(req("custom", {"name": "x"}, id=uid()))
    assert r["error"]["code"] == -32001
    assert r["error"]["message"] == "custom fail"
    assert r["error"]["data"] == {"x": 1}


def test_returns_breach_is_internal_error():
    r = rj(req("badret", {"name": "x"}, id=uid()))
    assert r["error"]["code"] == JSONRPCError.INTERNAL_ERROR
    assert "Invalid result" in r["error"]["message"]


def test_method_without_handler():
    r = rj(req("orphan", {"name": "x"}, id=uid()))
    assert r["error"]["code"] == JSONRPCError.INTERNAL_ERROR


# --- registry -----------------------------------------------------------------
def test_methods_is_copy():
    p = JSONRPCProtocol([JSONRPCMethod(
        "m", accepts=NoArgs, handler=lambda request, session_state, request_state: {})])
    p.methods.clear()
    assert "m" in p.methods


def test_register_duplicate_rejected():
    p = JSONRPCProtocol([JSONRPCMethod(
        "m", accepts=NoArgs, handler=lambda request, session_state, request_state: {})])
    with pytest.raises(ValueError):
        p.register(JSONRPCMethod(
            "m", accepts=NoArgs, handler=lambda request, session_state, request_state: {}))


def test_register_rejects_non_method():
    with pytest.raises(TypeError):
        JSONRPCProtocol().register("nope")


def test_register_rejects_rpc_prefix():
    with pytest.raises(ValueError):
        JSONRPCProtocol().register(JSONRPCMethod("rpc.internal", accepts=NoArgs))


def test_register_rejects_dollar_prefix():
    with pytest.raises(ValueError):
        JSONRPCProtocol().register(JSONRPCMethod("$/control", accepts=NoArgs))


def test_request_failed_code_passthrough():
    from truenas_pyjsonrpc import JSONRPCError

    def h(request, session_state, request_state):
        raise JsonRpcError(JSONRPCError.REQUEST_FAILED, "expected failure")

    p = JSONRPCProtocol([JSONRPCMethod("f", accepts=NoArgs, handler=h)])
    r = msgspec.json.decode(p.dispatch(req("f", {}, id=uid())))
    assert r["error"]["code"] == JSONRPCError.REQUEST_FAILED == -32803
    assert r["error"]["message"] == "expected failure"
