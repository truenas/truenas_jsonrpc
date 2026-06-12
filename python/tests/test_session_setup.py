"""Session setup / authentication: $/sessionSetup, $/sessionSetupContinue,
$/sessionClose, the session-established gate, and SessionState."""
import json
import uuid
from typing import Annotated

import msgspec
import pytest

from truenas_pyjsonrpc import (
    SECRET,
    AuthorizationResponse,
    JsonRpcError,
    JSONRPCError,
    JSONRPCMethod,
    JSONRPCProtocol,
    MessageDirection,
    SessionLifecycle,
)
from truenas_pyjsonrpc.redaction import REDACTED


class Creds(msgspec.Struct):
    user: str
    password: Annotated[str, SECRET]


class LoginResult(msgspec.Struct):
    welcome: str


class OtpStep(msgspec.Struct):
    need: str


class Otp(msgspec.Struct):
    code: str


class NoArgs(msgspec.Struct):
    pass


def uid() -> str:
    return str(uuid.uuid4())


def req(method, params=None, id=...):
    msg = {"jsonrpc": "2.0", "method": method}
    if id is not ...:
        msg["id"] = id
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def decode(out):
    return None if out is None else msgspec.json.decode(out)


def _work():
    return JSONRPCMethod(
        "work", accepts=NoArgs,
        handler=lambda request, session_state, request_state: {"ok": True})


def _login(request, session_state):
    if request.password != "hunter2":
        raise JsonRpcError(JSONRPCError.NOT_AUTHORIZED, "bad creds")
    session_state.server_state_internal = {"user": request.user}   # identity
    return SessionLifecycle.ESTABLISHED, LoginResult(welcome=request.user)


def _setup_proto(**kw):
    """A protocol with a normal `work` method + single-step `$/sessionSetup`."""
    kw.setdefault("name", "v1")
    kw.setdefault("version", "1.0.0")
    p = JSONRPCProtocol([_work()], **kw)
    p.add_session_setup(JSONRPCMethod("$/sessionSetup", accepts=Creds,
                                      returns=LoginResult, handler=_login))
    return p


# --- SessionState / new_session ----------------------------------------------
def test_new_session_has_uuid_name_and_seeded_internal():
    p = JSONRPCProtocol(name="truenas", version="1.0.0")
    s = p.new_session(server_state={"conn": 1})
    uuid.UUID(s.session_uuid)                              # a valid uuid
    assert s.protocol_name == "truenas"
    assert s.lifecycle is SessionLifecycle.NONE
    assert s.server_state_internal == {"conn": 1}
    assert s.server_state_external is None
    assert p.new_session().session_uuid != s.session_uuid  # distinct per connection


def test_no_setup_means_no_gate():
    p = JSONRPCProtocol([_work()], name="test", version="1.0.0")                         # no add_session_setup
    assert decode(p.dispatch(req("work", {}, id=uid())))["result"] == {"ok": True}


# --- single-step setup -------------------------------------------------------
def test_single_step_setup_establishes_and_commits_state():
    p = _setup_proto()
    s = p.new_session()
    r = decode(p.dispatch(
        req("$/sessionSetup", {"user": "bob", "password": "hunter2"}, id=uid()), s))
    assert r["result"] == {"welcome": "bob"}              # the typed reply
    assert s.lifecycle is SessionLifecycle.ESTABLISHED
    assert s.server_state_internal == {"user": "bob"}     # identity set by handler
    assert s.server_state_external == LoginResult(welcome="bob")   # client-facing
    # a normal method now works on the established session
    assert decode(p.dispatch(req("work", {}, id=uid()), s))["result"] == {"ok": True}


# --- the session-established gate ---------------------------------------------
def test_normal_method_gated_before_established():
    p = _setup_proto()
    s = p.new_session()                                   # NONE
    r = decode(p.dispatch(req("work", {}, id=uid()), s))
    assert r["error"]["code"] == JSONRPCError.SESSION_NOT_ESTABLISHED


def test_pre_auth_method_allowed_before_established():
    p = JSONRPCProtocol([JSONRPCMethod(
        "ping", accepts=NoArgs, pre_auth=True,
        handler=lambda request, session_state, request_state: {"pong": True})], name="test", version="1.0.0")
    p.add_session_setup(JSONRPCMethod("$/sessionSetup", accepts=Creds,
                                      returns=LoginResult, handler=_login))
    s = p.new_session()                                   # NONE
    assert decode(p.dispatch(req("ping", {}, id=uid()), s))["result"] == {"pong": True}


# --- multi-step setup --------------------------------------------------------
def _login_2fa(request, session_state):
    return SessionLifecycle.INIT, OtpStep(need="otp")     # first step -> need OTP


def _continue_2fa(request, session_state):
    if request.code != "123456":
        raise JsonRpcError(JSONRPCError.NOT_AUTHORIZED, "bad otp")
    session_state.server_state_internal = {"user": "bob"}
    return SessionLifecycle.ESTABLISHED, LoginResult(welcome="bob")


def _twostep_proto():
    p = JSONRPCProtocol([_work()], name="test", version="1.0.0")
    p.add_session_setup(
        JSONRPCMethod("$/sessionSetup", accepts=Creds, returns=OtpStep,
                      handler=_login_2fa),
        JSONRPCMethod("$/sessionSetupContinue", accepts=Otp, returns=LoginResult,
                      handler=_continue_2fa))
    return p


def test_multi_step_setup_none_init_established():
    p = _twostep_proto()
    s = p.new_session()
    r1 = decode(p.dispatch(
        req("$/sessionSetup", {"user": "bob", "password": "x"}, id=uid()), s))
    assert r1["result"] == {"need": "otp"} and s.lifecycle is SessionLifecycle.INIT
    # normal method still gated mid-setup
    assert decode(p.dispatch(req("work", {}, id=uid()), s))["error"]["code"] == \
        JSONRPCError.SESSION_NOT_ESTABLISHED
    r2 = decode(p.dispatch(req("$/sessionSetupContinue", {"code": "123456"}, id=uid()), s))
    assert r2["result"] == {"welcome": "bob"}
    assert s.lifecycle is SessionLifecycle.ESTABLISHED
    assert decode(p.dispatch(req("work", {}, id=uid()), s))["result"] == {"ok": True}


def test_setup_only_at_none():
    p = _setup_proto()
    s = p.new_session()
    p.dispatch(req("$/sessionSetup", {"user": "b", "password": "hunter2"}, id=uid()), s)
    r = decode(p.dispatch(
        req("$/sessionSetup", {"user": "b", "password": "hunter2"}, id=uid()), s))
    assert r["error"]["code"] == JSONRPCError.REQUEST_FAILED   # already established


def test_continue_only_at_init():
    p = _twostep_proto()
    s = p.new_session()                                   # NONE, no setup in progress
    r = decode(p.dispatch(req("$/sessionSetupContinue", {"code": "x"}, id=uid()), s))
    assert r["error"]["code"] == JSONRPCError.REQUEST_FAILED


# --- not enabled / no id -----------------------------------------------------
def test_setup_not_registered_is_method_not_found():
    r = decode(JSONRPCProtocol(name="test", version="1.0.0").dispatch(req("$/sessionSetup", {}, id=uid())))
    assert r["error"]["code"] == JSONRPCError.METHOD_NOT_FOUND


def test_continue_not_registered_is_method_not_found():
    p = _setup_proto()                                    # setup but no continue
    r = decode(p.dispatch(req("$/sessionSetupContinue", {}, id=uid()), p.new_session()))
    assert r["error"]["code"] == JSONRPCError.METHOD_NOT_FOUND


def test_setup_requires_id():
    p = _setup_proto()
    r = decode(p.dispatch(req("$/sessionSetup", {"user": "b", "password": "hunter2"}),
                          p.new_session()))
    assert r["error"]["code"] == JSONRPCError.INVALID_REQUEST


# --- setup bypasses authz, but is always audited (creds redacted) ------------
def test_setup_bypasses_authorization():
    calls = []
    p = _setup_proto(authorization_handler=lambda request, session_state: (
        calls.append(1) or AuthorizationResponse(False, "no")))
    s = p.new_session()
    r = decode(p.dispatch(
        req("$/sessionSetup", {"user": "b", "password": "hunter2"}, id=uid()), s))
    assert r["result"] == {"welcome": "b"}               # not denied
    assert calls == []                                   # authz never consulted
    assert s.lifecycle is SessionLifecycle.ESTABLISHED


def test_setup_audited_with_redacted_credentials():
    audited = []

    def audit(request, response, session_state, audit_message=None):
        audited.append((request.method, request.params, response,
                        session_state.session_uuid))

    p = _setup_proto(audit_handler=audit)
    s = p.new_session()
    decode(p.dispatch(
        req("$/sessionSetup", {"user": "bob", "password": "hunter2"}, id=uid()), s))
    assert len(audited) == 1
    method, params, response, suuid = audited[0]
    assert method == "$/sessionSetup"
    assert params["user"] == "bob" and params["password"] == REDACTED   # redacted
    assert "result" in response and suuid == s.session_uuid


def test_setup_failure_is_audited_and_stays_none():
    audited = []
    p = _setup_proto(
        audit_handler=lambda request, response, session_state, audit_message=None:
            audited.append(response))
    s = p.new_session()
    r = decode(p.dispatch(
        req("$/sessionSetup", {"user": "bob", "password": "wrong"}, id=uid()), s))
    assert r["error"]["code"] == JSONRPCError.NOT_AUTHORIZED   # handler raised
    assert s.lifecycle is SessionLifecycle.NONE                # not established
    assert len(audited) == 1 and "error" in audited[0]         # failure audited


# --- handler-contract violations ---------------------------------------------
def test_setup_bad_return_shape_is_internal_error():
    p = JSONRPCProtocol(name="test", version="1.0.0")
    p.add_session_setup(JSONRPCMethod(
        "$/sessionSetup", accepts=Creds, returns=LoginResult,
        handler=lambda request, session_state: "not a tuple"))
    s = p.new_session()
    r = decode(p.dispatch(req("$/sessionSetup", {"user": "b", "password": "x"}, id=uid()), s))
    assert r["error"]["code"] == JSONRPCError.INTERNAL_ERROR
    assert s.lifecycle is SessionLifecycle.NONE           # not committed


def test_setup_bad_lifecycle_is_internal_error():
    p = JSONRPCProtocol(name="test", version="1.0.0")
    p.add_session_setup(JSONRPCMethod(
        "$/sessionSetup", accepts=Creds, returns=LoginResult,
        handler=lambda request, session_state: ("established", LoginResult(welcome="x"))))
    r = decode(p.dispatch(req("$/sessionSetup", {"user": "b", "password": "x"}, id=uid()),
                          p.new_session()))
    assert r["error"]["code"] == JSONRPCError.INTERNAL_ERROR


def test_setup_bad_result_is_invalid_result():
    p = JSONRPCProtocol(name="test", version="1.0.0")
    p.add_session_setup(JSONRPCMethod(
        "$/sessionSetup", accepts=Creds, returns=LoginResult,
        handler=lambda request, session_state: (SessionLifecycle.ESTABLISHED, {"nope": 1})))
    r = decode(p.dispatch(req("$/sessionSetup", {"user": "b", "password": "x"}, id=uid()),
                          p.new_session()))
    assert r["error"]["code"] == JSONRPCError.INTERNAL_ERROR
    assert r["error"]["message"] == "Invalid result"


# --- $/sessionClose + close_session ------------------------------------------
def test_session_close_transitions_to_closed_and_audits():
    audited = []
    p = _setup_proto(
        audit_handler=lambda request, response, session_state, audit_message=None:
            audited.append(request.method))
    s = p.new_session()
    p.dispatch(req("$/sessionSetup", {"user": "b", "password": "hunter2"}, id=uid()), s)
    r = decode(p.dispatch(req("$/sessionClose", id=uid()), s))
    assert r["result"] is True and s.lifecycle is SessionLifecycle.CLOSED
    assert "$/sessionClose" in audited
    # a CLOSED session rejects everything further
    assert decode(p.dispatch(req("work", {}, id=uid()), s))["error"]["code"] == \
        JSONRPCError.SESSION_NOT_ESTABLISHED


def test_session_close_requires_id():
    p = _setup_proto()
    s = p.new_session()
    p.dispatch(req("$/sessionSetup", {"user": "b", "password": "hunter2"}, id=uid()), s)
    r = decode(p.dispatch(req("$/sessionClose"), s))      # no id
    assert r["error"]["code"] == JSONRPCError.INVALID_REQUEST


def test_session_close_with_no_session_is_request_failed():
    p = _setup_proto()
    r = decode(p.dispatch(req("$/sessionClose", id=uid()), p.new_session()))  # NONE
    assert r["error"]["code"] == JSONRPCError.REQUEST_FAILED


def test_close_session_helper_drops_subscriptions():
    p = JSONRPCProtocol([JSONRPCMethod("evt", accepts=NoArgs, notifies=NoArgs,
                                       direction=MessageDirection.SERVER_CLIENT)], name="test", version="1.0.0")
    s = p.new_session()
    sub = decode(p.dispatch(req("evt", id=uid()), s))
    assert sub["result"] in p._subscriptions["evt"]
    p.close_session(s)                                    # server-side socket drop
    assert s.lifecycle is SessionLifecycle.CLOSED
    assert p._subscriptions["evt"] == {}                  # dropped (by session_uuid)


# --- $/serverInfo bypasses the session-established gate -----------------------
def test_server_info_works_before_established():
    class Info(msgspec.Struct):
        name: str

    p = _setup_proto()
    p.register_server_info(lambda session_state: Info(name="x"), returns=Info)
    s = p.new_session()                                   # NONE, gate active
    r = decode(p.dispatch(req("$/serverInfo", id=uid()), s))
    assert r["result"] == {"name": "x"}                  # not gated


# --- add_session_setup validation --------------------------------------------
def test_add_session_setup_validation():
    p = JSONRPCProtocol(name="test", version="1.0.0")
    with pytest.raises(TypeError):
        p.add_session_setup("nope")                       # not a JSONRPCMethod
    with pytest.raises(TypeError):                        # SERVER_CLIENT not allowed
        p.add_session_setup(JSONRPCMethod(
            "$/sessionSetup", accepts=Creds, notifies=NoArgs,
            direction=MessageDirection.SERVER_CLIENT))
    with pytest.raises(TypeError):                        # missing handler
        p.add_session_setup(JSONRPCMethod("$/sessionSetup", accepts=Creds,
                                          returns=LoginResult))
    with pytest.raises(TypeError):                        # missing returns
        p.add_session_setup(JSONRPCMethod("$/sessionSetup", accepts=Creds,
                                          handler=_login))
