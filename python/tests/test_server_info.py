"""Unauthenticated `$/serverInfo` control request."""
import json
import uuid

import msgspec
import pytest

from truenas_pyjsonrpc import (
    AuthorizationResponse,
    JsonRpcError,
    JSONRPCError,
    JSONRPCProtocol,
    ServerInfo,
)


class Info(msgspec.Struct):
    name: str
    version: str


def uid() -> str:
    return str(uuid.uuid4())


def info_req(id=...):
    msg = {"jsonrpc": "2.0", "method": "$/serverInfo"}
    if id is not ...:
        msg["id"] = id
    return json.dumps(msg)


def decode(out):
    return None if out is None else msgspec.json.decode(out)


def _info_handler(session_state):
    return Info(name="truenas", version="25.04")


# --- not registered -----------------------------------------------------------
def test_not_registered_request_is_method_not_found():
    r = decode(JSONRPCProtocol().dispatch(info_req(id=uid())))
    assert r["error"]["code"] == JSONRPCError.METHOD_NOT_FOUND


def test_not_registered_notification_is_ignored():
    assert JSONRPCProtocol().dispatch(info_req()) is None     # no id -> ignored


# --- registered happy path ----------------------------------------------------
def test_registered_returns_validated_result():
    p = JSONRPCProtocol()
    p.register_server_info(_info_handler, returns=Info)
    u = uid()
    r = decode(p.dispatch(info_req(id=u)))
    assert r == {"jsonrpc": "2.0",
                 "result": {"name": "truenas", "version": "25.04"}, "id": u}


def test_result_can_use_the_builtin_serverinfo_struct():
    p = JSONRPCProtocol()
    p.register_server_info(
        lambda session_state: ServerInfo(name="tn", version="1.0"), returns=ServerInfo)
    r = decode(p.dispatch(info_req(id=uid())))
    assert r["result"] == {"name": "tn", "version": "1.0"}


# --- unauthenticated: bypasses authz -----------------------------------------
def test_bypasses_authorization():
    calls = []
    p = JSONRPCProtocol(
        authorization_handler=lambda request, session_state: (
            calls.append("authz") or AuthorizationResponse(False, "denied")))
    p.register_server_info(_info_handler, returns=Info)
    r = decode(p.dispatch(info_req(id=uid())))
    assert r["result"] == {"name": "truenas", "version": "25.04"}   # not denied
    assert calls == []                                   # authz never consulted


# --- not audited (unlike $/cancelRequest) ------------------------------------
def test_not_audited():
    audited = []
    p = JSONRPCProtocol(
        audit_handler=lambda request, response, session_state, audit_message=None:
            audited.append(request.method))
    p.register_server_info(_info_handler, returns=Info)
    p.dispatch(info_req(id=uid()))
    assert audited == []                                 # $/serverInfo not audited


# --- request-only -------------------------------------------------------------
def test_registered_no_id_is_invalid_request():
    p = JSONRPCProtocol()
    p.register_server_info(_info_handler, returns=Info)
    r = decode(p.dispatch(info_req()))                   # no id
    assert r["error"]["code"] == JSONRPCError.INVALID_REQUEST
    assert r["id"] is None


# --- handler errors -----------------------------------------------------------
def test_handler_jsonrpcerror_passthrough():
    def boom(session_state):
        raise JsonRpcError(JSONRPCError.REQUEST_FAILED, "nope")

    p = JSONRPCProtocol()
    p.register_server_info(boom, returns=Info)
    r = decode(p.dispatch(info_req(id=uid())))
    assert r["error"]["code"] == JSONRPCError.REQUEST_FAILED
    assert r["error"]["message"] == "nope"


def test_handler_generic_exception_is_internal_error():
    def boom(session_state):
        raise RuntimeError("kaboom")

    p = JSONRPCProtocol()
    p.register_server_info(boom, returns=Info)
    r = decode(p.dispatch(info_req(id=uid())))
    assert r["error"]["code"] == JSONRPCError.INTERNAL_ERROR


def test_bad_result_shape_is_invalid_result():
    def bad(session_state):
        return {"name": "x"}                             # missing required 'version'

    p = JSONRPCProtocol()
    p.register_server_info(bad, returns=Info)
    r = decode(p.dispatch(info_req(id=uid())))
    assert r["error"]["code"] == JSONRPCError.INTERNAL_ERROR
    assert r["error"]["message"] == "Invalid result"


# --- params ignored / session_state passthrough -------------------------------
def test_params_are_ignored():
    p = JSONRPCProtocol()
    p.register_server_info(_info_handler, returns=Info)
    u = uid()
    wire = json.dumps({"jsonrpc": "2.0", "method": "$/serverInfo", "id": u,
                       "params": {"anything": 123}})
    assert decode(p.dispatch(wire))["result"] == {"name": "truenas", "version": "25.04"}


def test_handler_receives_session_state():
    seen = {}

    def h(session_state):
        seen["ss"] = session_state
        return Info(name="n", version="v")

    p = JSONRPCProtocol()
    p.register_server_info(h, returns=Info)
    sentinel = {"conn": 1}
    session = p.new_session(server_state=sentinel)
    p.dispatch(info_req(id=uid()), session)
    assert seen["ss"] is session                            # the SessionState
    assert seen["ss"].server_state_internal is sentinel     # opaque, seeded


# --- registration validation + clearing --------------------------------------
def test_register_validation():
    p = JSONRPCProtocol()
    with pytest.raises(TypeError):
        p.register_server_info(123, returns=Info)        # non-callable handler
    with pytest.raises(TypeError):
        p.register_server_info(_info_handler, returns=int)   # non-Struct returns
    with pytest.raises(TypeError):
        p.register_server_info(_info_handler)            # returns omitted (None)


def test_clear_disables():
    p = JSONRPCProtocol()
    p.register_server_info(_info_handler, returns=Info)
    assert decode(p.dispatch(info_req(id=uid())))["result"]["name"] == "truenas"
    p.register_server_info(None)                         # clear
    r = decode(p.dispatch(info_req(id=uid())))
    assert r["error"]["code"] == JSONRPCError.METHOD_NOT_FOUND
