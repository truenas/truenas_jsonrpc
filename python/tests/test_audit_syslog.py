"""Tests for truenas_pyjsonrpc.mixins.audit: the middleware-shaped ``@cee``/``TNAUDIT`` record
builder and the ``SyslogAuditHandler`` emitter. A capture handler stands in for syslog (no
real socket) except one self-contained AF_UNIX STREAM emit and a ``/dev/log`` smoke."""
import datetime
import json
import logging
import os
import socket
import uuid
from types import SimpleNamespace
from typing import Annotated

import msgspec
import pytest

from truenas_pyjsonrpc import (
    JSONRPCError,
    JSONRPCMethod,
    JSONRPCProtocol,
    JSONRPCRequest,
    JsonRpcError,
    SECRET,
    SessionLifecycle,
)
from truenas_pyjsonrpc.redaction import REDACTED
from truenas_pyjsonrpc.mixins.audit import (
    UNAUTHENTICATED,
    AuditFormatter,
    EventType,
    SyslogAuditHandler,
    default_event_classifier,
)
from truenas_pyjsonrpc_server import Peer

_ENC = msgspec.json.Encoder()


def uid() -> str:
    return str(uuid.uuid4())


def req(method, params=None, *, id=None) -> bytes:
    m = {"jsonrpc": "2.0", "method": method}
    if id is not None:
        m["id"] = id
    if params is not None:
        m["params"] = params
    return _ENC.encode(m)


def decode(b):
    return msgspec.json.decode(b)


def parse(line: str) -> dict:
    """Strip the ``@cee:`` prefix and decode the record + its nested JSON strings."""
    assert line.startswith("@cee:")
    rec = json.loads(line[len("@cee:"):])["TNAUDIT"]
    rec["svc_data"] = json.loads(rec["svc_data"])
    rec["event_data"] = json.loads(rec["event_data"])
    return rec


def _ss(identity=None, session_uuid="sess-x"):
    return SimpleNamespace(session_uuid=session_uuid, server_state_internal=identity)


# --- a capture sink instead of a real syslog socket --------------------------
class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(record.getMessage())


def _handler(**fmt_or_handler_kw):
    cap = _Capture()
    h = SyslogAuditHandler(service="svc", handler=cap,
                           logger=logging.getLogger("test-audit-" + uid()),
                           **fmt_or_handler_kw)
    return h, cap


# --- the audited API ---------------------------------------------------------
class Args(msgspec.Struct):
    name: str


class Result(msgspec.Struct):
    id: int


class Login(msgspec.Struct):
    user: str
    password: Annotated[str, SECRET]


class NoArgs(msgspec.Struct):
    pass


def _create(request, session_state, request_state) -> Result:
    return Result(id=7)


def _boom(request, session_state, request_state) -> Result:
    raise RuntimeError("kaboom")


def _echo(request, session_state, request_state) -> Login:
    return request                                    # returns the (secret-bearing) params


def _methods():
    return [
        JSONRPCMethod("pool.create", accepts=Args, returns=Result, handler=_create,
                      audit=True, audit_message="Create pool"),
        JSONRPCMethod("boom", accepts=NoArgs, returns=Result, handler=_boom, audit=True),
        JSONRPCMethod("login", accepts=Login, returns=Login, handler=_echo, audit=True),
    ]


def _proto(audit, **kw):
    return JSONRPCProtocol(_methods(), name="v1", version="1.0.0",
                           audit_handler=audit, **kw)


# --- record shape ------------------------------------------------------------
def test_record_shape_method_call_success():
    h, cap = _handler()
    p = _proto(h)
    s = p.new_session(server_state={"username": "admin", "account_attributes": [],
                                    "origin": "10.0.0.5:52344"})
    decode(p.dispatch(req("pool.create", {"name": "tank"}, id=uid()), s))
    assert len(cap.lines) == 1
    rec = parse(cap.lines[0])
    assert set(rec) == {"aid", "vers", "addr", "user", "sess", "time", "svc",
                        "svc_data", "event", "event_data", "success"}
    assert rec["svc"] == "svc"
    assert rec["vers"] == {"major": 0, "minor": 1}
    assert rec["success"] is True
    assert rec["event"] == "METHOD_CALL"
    assert rec["user"] == "admin"
    assert rec["addr"] == "10.0.0.5:52344"
    assert rec["sess"] == s.session_uuid
    uuid.UUID(rec["aid"])                                          # a valid uuid4
    datetime.datetime.strptime(rec["time"], "%Y-%m-%d %H:%M:%S.%f")  # the middleware format
    ed = rec["event_data"]
    assert ed["method"] == "pool.create"
    assert ed["params"] == [{"name": "tank"}]
    assert ed["description"] == "Create pool"
    assert ed["success"] is True and ed["error"] is None
    sd = rec["svc_data"]
    assert sd["protocol"] == "JSONRPC"
    assert sd["credentials"]["credentials_data"]["username"] == "admin"


def test_method_call_error():
    h, cap = _handler()
    p = _proto(h)
    s = p.new_session(server_state={"username": "admin"})
    decode(p.dispatch(req("boom", {}, id=uid()), s))
    rec = parse(cap.lines[0])
    assert rec["success"] is False
    ed = rec["event_data"]
    assert ed["success"] is False
    assert ed["error"]["code"] == JSONRPCError.INTERNAL_ERROR
    assert "result" not in ed                                      # METHOD_CALL omits result


# --- redaction preserved (sync + off-path queue) -----------------------------
def test_redaction_preserved_sync():
    h, cap = _handler()
    p = _proto(h)
    s = p.new_session(server_state={"username": "admin"})
    out = decode(p.dispatch(req("login", {"user": "bob", "password": "hunter2"}, id=uid()), s))
    assert out["result"]["password"] == "hunter2"                 # the wire keeps the secret
    rec = parse(cap.lines[0])
    assert rec["event_data"]["params"][0]["password"] == REDACTED  # the audit masks it


def test_redaction_preserved_queue():
    h, cap = _handler()
    p = _proto(h, use_audit_queue=True)
    s = p.new_session(server_state={"username": "admin"})
    p.dispatch(req("login", {"user": "bob", "password": "hunter2"}, id=uid()), s)
    assert cap.lines == []                                         # nothing on the IO path
    p.poll_audit(block=False).run()                                # drained off-path
    rec = parse(cap.lines[0])
    assert rec["event_data"]["params"][0]["password"] == REDACTED


# --- event classification ----------------------------------------------------
def test_default_event_classifier():
    assert default_event_classifier(
        JSONRPCRequest(method="pool.create", id="1", params=None)) == EventType.METHOD_CALL
    assert default_event_classifier(
        JSONRPCRequest(method="$/sessionSetup", id="1", params=None)) == EventType.CONTROL_MESSAGE


def test_custom_classifier_wins():
    fmt = AuditFormatter("svc", event_classifier=lambda r: (
        "AUTHENTICATION" if r.method == "$/sessionSetup" else "METHOD_CALL"))
    rec = parse(fmt.format(JSONRPCRequest(method="$/sessionSetup", id="1", params=None),
                           {"result": None}, _ss({"username": "x"})))
    assert rec["event"] == "AUTHENTICATION"


class Creds(msgspec.Struct):
    user: str
    password: Annotated[str, SECRET]


class SetupReply(msgspec.Struct):
    welcome: str


def _setup_login(request, session_state):
    if request.password != "hunter2":
        raise JsonRpcError(JSONRPCError.NOT_AUTHORIZED, "bad creds")
    session_state.server_state_internal = {"user": request.user}
    return SessionLifecycle.ESTABLISHED, SetupReply(welcome=request.user)


def test_control_message_via_session_setup():
    h, cap = _handler()
    p = JSONRPCProtocol([], name="v1", audit_handler=h, version="1.0.0")
    p.add_session_setup(JSONRPCMethod("$/sessionSetup", accepts=Creds, returns=SetupReply,
                                      handler=_setup_login))
    s = p.new_session(server_state=Peer(transport="tcp", tls=True, address=("10.0.0.9", 4444)))
    decode(p.dispatch(req("$/sessionSetup", {"user": "bob", "password": "hunter2"}, id=uid()), s))
    rec = parse(cap.lines[0])
    assert rec["event"] == "CONTROL_MESSAGE"
    ed = rec["event_data"]
    assert ed["method"] == "$/sessionSetup"
    assert ed["params"][0]["password"] == REDACTED                # creds redacted via accepts plan
    assert "result" in ed                                         # control includes the reply


# --- identity / origin extraction --------------------------------------------
def test_extractor_dict_identity():
    rec = parse(AuditFormatter("svc").format(
        JSONRPCRequest(method="m", id="1", params=None), {"result": None},
        _ss({"username": "admin", "account_attributes": ["2FA"], "origin": "1.2.3.4",
             "api_key_id": 2})))
    assert rec["user"] == "admin"
    assert rec["addr"] == "1.2.3.4"
    assert rec["svc_data"]["credentials"]["credentials"] == "API_KEY"     # api_key_id present
    assert "origin" not in rec["svc_data"]["credentials"]["credentials_data"]


def test_extractor_peer():
    rec = parse(AuditFormatter("svc").format(
        JSONRPCRequest(method="m", id="1", params=None), {"result": None},
        _ss(Peer(transport="unix", uid=0, gid=0, pid=4821))))
    assert rec["user"] == "unix:uid=0"
    assert rec["addr"] == "unix:uid=0"
    assert rec["svc_data"]["credentials"] is None


def test_extractor_unauthenticated():
    rec = parse(AuditFormatter("svc").format(
        JSONRPCRequest(method="m", id="1", params=None), {"result": None}, _ss(None)))
    assert rec["user"] == UNAUTHENTICATED
    assert rec["addr"] is None


def test_custom_extractors_override():
    rec = parse(AuditFormatter(
        "svc", username=lambda ss: "X", origin=lambda ss: "9.9.9.9",
        credentials=lambda ss: None).format(
            JSONRPCRequest(method="m", id="1", params=None), {"result": None}, _ss(None)))
    assert rec["user"] == "X" and rec["addr"] == "9.9.9.9"
    assert rec["svc_data"]["credentials"] is None


def test_handler_swallows_exceptions():
    def boom(ss):
        raise RuntimeError("extractor failed")

    h, cap = _handler(formatter=AuditFormatter("svc", username=boom))
    h(request=JSONRPCRequest(method="m", id="1", params=None), response={"result": None},
      session_state=_ss({"username": "a"}), audit_message=None)
    assert cap.lines == []                                         # raised + swallowed, nothing emitted


# --- real emit over a throwaway AF_UNIX STREAM socket (no syslog-ng needed) ---
def test_real_stream_socket_emit(tmp_path):
    sock_path = str(tmp_path / "audit.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(1)
    try:
        h = SyslogAuditHandler(service="svc", address=sock_path, socktype=socket.SOCK_STREAM)
        try:
            h(request=JSONRPCRequest(method="pool.create", id="1", params=None),
              response={"result": {"ok": True}}, session_state=_ss({"username": "admin"}),
              audit_message="X")
            conn, _ = srv.accept()
            data = conn.recv(8192).decode()
            conn.close()
        finally:
            h.close()
    finally:
        srv.close()
    assert "TNAUDIT_SVC: " in data                                # the syslog ident tag
    rec = parse(data[data.index("@cee:"):].rstrip("\x00\n"))
    assert rec["event"] == "METHOD_CALL" and rec["svc"] == "svc" and rec["user"] == "admin"


@pytest.mark.skipif(not os.path.exists("/dev/log"), reason="/dev/log not present")
def test_dev_log_smoke():
    h = SyslogAuditHandler(service="pytest_audit", address="/dev/log",
                           socktype=socket.SOCK_DGRAM)
    request = JSONRPCRequest(method="m", id="1", params=None)
    session_state = _ss({"username": "x"})
    try:
        # __call__ swallows every exception (auditing must never break drain), so calling it
        # can't fail the test on its own — assert the record it *would* emit is well-formed,
        # then exercise the real /dev/log write (fire-and-forget DGRAM, nothing to read back).
        rec = parse(h._formatter.format(request, {"result": None}, session_state))
        assert rec["svc"] == "pytest_audit" and rec["user"] == "x"
        assert rec["event"] == "METHOD_CALL" and rec["success"] is True
        h(request=request, response={"result": None},
          session_state=session_state, audit_message=None)
    finally:
        h.close()
