"""Tests for the protocol mixins in ``truenas_pyjsonrpc.mixins`` — they wire an auth stack /
audit handler onto a :class:`JSONRPCProtocol` subclass at construction (mixins **before** the
base). The underlying stacks are covered by test_auth/test_pam/test_audit_syslog; here we test
the cooperative-``__init__`` wiring and the configuration knobs."""
import socket
import uuid

import msgspec

from truenas_pyjsonrpc import JSONRPCMethod, JSONRPCProtocol, SessionLifecycle
from truenas_pyjsonrpc.mixins import (
    AuditMixin,
    AuthStackMixin,
    TrueNASAuditMixin,
    TrueNASAuthMixin,
)
from truenas_pyjsonrpc.mixins.auth import Authenticated, AuthStack, TrueNASAuth
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
    return None if b is None else msgspec.json.decode(b)


class NoArgs(msgspec.Struct):
    pass


class Ok(msgspec.Struct):
    ok: bool = True


def _work(request, session_state, request_state) -> Ok:
    return Ok()


def _methods():
    return [JSONRPCMethod("work", accepts=NoArgs, returns=Ok, handler=_work, audit=True)]


class _PeercredStack(AuthStack):
    """A trivial stack that trusts the local connection (enough to prove install())."""
    def peercred(self, peer):
        return Authenticated({"user": "local"})


# --- generic mixins ----------------------------------------------------------
def test_audit_mixin_registers_and_enables_queue():
    seen = []

    class P(AuditMixin, JSONRPCProtocol):
        def make_audit_handler(self):
            return lambda **kw: seen.append(kw["request"].method)

    p = P(_methods(), name="v1", version="1.0.0")
    assert p._use_audit_queue is True                # set at construction by the mixin
    assert p._audit_handler is not None
    p.dispatch(req("work", {}, id=uid()))            # no auth gate -> dispatches; audit queued
    assert seen == []                                # nothing on the IO path
    p.poll_audit(block=False).run()                  # drained off-path
    assert seen == ["work"]


def test_audit_use_queue_false_runs_inline():
    seen = []

    class P(AuditMixin, JSONRPCProtocol):
        audit_use_queue = False
        def make_audit_handler(self):
            return lambda **kw: seen.append(kw["request"].method)

    p = P(_methods(), name="v1", version="1.0.0")
    assert p._use_audit_queue is False
    p.dispatch(req("work", {}, id=uid()))            # inline audit
    assert seen == ["work"]


def test_auth_stack_mixin_installs_session_setup():
    class P(AuthStackMixin, JSONRPCProtocol):
        def make_auth_stack(self):
            return _PeercredStack()

    p = P(_methods(), name="v1", version="1.0.0")
    assert p._session_setup is not None              # install() ran
    s = p.new_session(server_state=Peer(transport="unix", uid=0))
    r = decode(p.dispatch(req("$/sessionSetup", {}, id=uid()), s))
    assert r["result"]["response"]["response_type"] == "SUCCESS"
    assert s.lifecycle is SessionLifecycle.ESTABLISHED


def test_default_hooks_install_nothing():
    # AuthStackMixin/AuditMixin with the default (None-returning) hooks wire nothing.
    class P(AuthStackMixin, AuditMixin, JSONRPCProtocol):
        audit_use_queue = False

    p = P(_methods(), name="v1", version="1.0.0")
    assert p._session_setup is None and p._audit_handler is None


def test_combined_mixins_cooperative_init():
    seen = []

    class P(AuthStackMixin, AuditMixin, JSONRPCProtocol):
        def make_auth_stack(self):
            return _PeercredStack()
        def make_audit_handler(self):
            return lambda **kw: seen.append(kw["request"].method)

    p = P(_methods(), name="v1", version="1.0.0")
    assert [c.__name__ for c in type(p).__mro__][:4] == [
        "P", "AuthStackMixin", "AuditMixin", "JSONRPCProtocol"]
    assert p._use_audit_queue is True
    assert p._session_setup is not None              # auth installed
    assert p._audit_handler is not None              # audit registered
    assert p.name == "v1"
    # establish via peercred, then call an audited method
    s = p.new_session(server_state=Peer(transport="unix", uid=0))
    decode(p.dispatch(req("$/sessionSetup", {}, id=uid()), s))
    p.dispatch(req("work", {}, id=uid()), s)
    while (rec := p.poll_audit(block=False)) is not None:
        rec.run()
    assert "work" in seen                            # the audited call reached the handler


# --- TrueNAS concretes -------------------------------------------------------
def test_truenas_auth_mixin_builds_truenas_auth():
    class P(TrueNASAuthMixin, JSONRPCProtocol):
        auth_scram_service = "x-scram"

    p = P(_methods(), name="v1", version="1.0.0")
    assert p._session_setup is not None              # installed at construction
    stack = p.make_auth_stack()
    assert isinstance(stack, TrueNASAuth)
    assert stack._scram_service == "x-scram"         # class attrs honored


def test_truenas_audit_mixin_emits_to_socket(tmp_path):
    sock_path = str(tmp_path / "audit.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(1)
    try:
        class P(TrueNASAuditMixin, JSONRPCProtocol):
            audit_address = sock_path
            audit_socktype = socket.SOCK_STREAM
            # audit_service unset -> defaults to the protocol name ("zfsd")

        p = P(_methods(), name="zfsd", version="1.0.0")
        assert p._use_audit_queue is True
        p.dispatch(req("work", {}, id=uid()))
        p.poll_audit(block=False).run()              # emits to the socket
        conn, _ = srv.accept()
        data = conn.recv(8192).decode()
        conn.close()
    finally:
        srv.close()
    assert "@cee:" in data
    assert "TNAUDIT_ZFSD: " in data                  # service defaulted to the protocol name
