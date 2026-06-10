"""Tests for the truenas_pyjsonrpc.mixins.auth reference auth layer: channel-aware session
setup (peercred over AF_UNIX, SCRAM / GSSAPI / mTLS over TCP/WS), the SCRAM + OTP second-factor
flow, channel-binding rejections, and audit redaction. Unit tests drive ``protocol.dispatch``
directly with a seeded ``Peer``; one end-to-end test runs over a real AF_UNIX server/client."""
import base64
import os
import uuid

import msgspec
import pytest

from truenas_pyjsonrpc import (
    JSONRPCMethod,
    JSONRPCProtocol,
    SessionLifecycle,
)
from truenas_pyjsonrpc.redaction import REDACTED
from truenas_pyjsonrpc.mixins.auth import (
    AuthStack,
    Authenticated,
    GssapiChallenge,
    NeedsOtp,
    Reject,
    generate_scram_credentials,
)
from truenas_pyjsonrpc_client import BaseClient, UnixConfig
from truenas_pyjsonrpc_server import Peer
from truenas_pyjsonrpc_server import UnixConfig as SrvUnixConfig
from test_client import _ServerThread
from test_server import _tmp_sock

# SCRAM crypto lives in the optional truenas_pyscram C extension; skip those tests if absent.
try:
    import truenas_pyscram
    _HAS_SCRAM = True
    # mint a real verifier once; the client below authenticates with the returned secret
    _SCRAM_CREDS, _SCRAM_SECRET = generate_scram_credentials(
        iterations=truenas_pyscram.SCRAM_MIN_ITERS,
        identity={"user": "scott"}, user_info={"uid": 1000})
except ImportError:
    _HAS_SCRAM = False
    _SCRAM_CREDS = _SCRAM_SECRET = None

requires_scram = pytest.mark.skipif(not _HAS_SCRAM, reason="truenas_pyscram not installed")

_ENC = msgspec.json.Encoder()


def uid() -> str:
    return str(uuid.uuid4())


def req(method: str, params=None, *, id=None) -> bytes:
    m = {"jsonrpc": "2.0", "method": method}
    if id is not None:
        m["id"] = id
    if params is not None:
        m["params"] = params
    return _ENC.encode(m)


def decode(b):
    return msgspec.json.decode(b)


def kind(reply) -> str:
    """The response_type of a setup reply."""
    return reply["result"]["response"]["response_type"]


# --- the api the protected protocol exposes ----------------------------------
class NoArgs(msgspec.Struct):
    pass

class Ok(msgspec.Struct):
    ok: bool = True

def _work(request, session_state, request_state) -> Ok:
    return Ok()


# --- a sample stack ----------------------------------------------------------
class _Stack(AuthStack):
    def peercred(self, peer):
        if getattr(peer, "uid", None) == 0:
            return Authenticated({"user": "root"})
        return None

    def scram_credentials(self, username):
        return _SCRAM_CREDS if username == "scott" else None

    def client_certificate(self, peercert, *, peer):
        return Authenticated({"user": "cert:" + peercert["subject"]})


def _proto(**kw) -> JSONRPCProtocol:
    p = JSONRPCProtocol(
        [JSONRPCMethod("work", accepts=NoArgs, returns=Ok, handler=_work)],
        name="v1", **kw)
    _Stack().install(p)
    return p


# --- drive SCRAM / GSSAPI from the wire --------------------------------------
def _scram(scram_type: str, rfc_str: str) -> dict:
    return {"mechanism": {"mechanism": "SCRAM",
                          "scram_type": scram_type, "rfc_str": rfc_str}}


def _gssapi(token: bytes) -> dict:
    return {"mechanism": {"mechanism": "GSSAPI", "token": base64.b64encode(token).decode()}}


def _scram_setup_first(p, s, username: str):
    """Send client-first; return (the ClientFirstMessage object, the reply)."""
    cf = truenas_pyscram.ClientFirstMessage(username=username)
    r = decode(p.dispatch(req("$/sessionSetup",
                              _scram("CLIENT_FIRST_MESSAGE", str(cf)), id=uid()), s))
    return cf, r


def _scram_continue_final(p, s, cf, secret: str, server_first_rfc: str):
    """Derive the proof from `secret` + the server's challenge, send client-final.
    Returns (reply, server_first, client_final, auth_data) for an optional mutual-auth check."""
    sf = truenas_pyscram.ServerFirstMessage(rfc_string=server_first_rfc)
    ad = truenas_pyscram.generate_scram_auth_data(           # re-derive the client keys
        salted_password=truenas_pyscram.CryptoDatum(base64.b64decode(secret)),
        salt=sf.salt, iterations=sf.iterations)
    cfin = truenas_pyscram.ClientFinalMessage(
        client_first=cf, server_first=sf,
        client_key=ad.client_key, stored_key=ad.stored_key)
    r = decode(p.dispatch(req("$/sessionSetupContinue",
                              _scram("CLIENT_FINAL_MESSAGE", str(cfin)), id=uid()), s))
    return r, sf, cfin, ad


# --- AF_UNIX peercred --------------------------------------------------------
def test_peercred_root_establishes_without_a_mechanism():
    p = _proto()
    s = p.new_session(server_state=Peer(transport="unix", uid=0))
    r = decode(p.dispatch(req("$/sessionSetup", {}, id=uid()), s))   # empty -> peercred
    assert kind(r) == "SUCCESS"
    assert s.lifecycle is SessionLifecycle.ESTABLISHED
    assert s.server_state_internal["user"] == "root"
    assert s.server_state_internal["origin"] == "unix:uid=0"   # origin captured for audit
    assert decode(p.dispatch(req("work", {}, id=uid()), s))["result"] == {"ok": True}


def test_unix_nonroot_declines_to_login():
    p = _proto()
    s = p.new_session(server_state=Peer(transport="unix", uid=1000))
    # peercred declines -> no mechanism means "authentication required" (fall through to login)
    assert kind(decode(p.dispatch(req("$/sessionSetup", {}, id=uid()), s))) == "AUTH_ERR"
    assert s.lifecycle is SessionLifecycle.NONE
    # the local socket still carries SCRAM (see the SCRAM tests for the full exchange).


# --- SCRAM (RFC 5802): truenas_pyscram runs the crypto, the stack drives it --
@requires_scram
def test_scram_full_exchange():
    p = _proto()
    s = p.new_session(server_state=Peer(transport="tcp", tls=True))
    cf, r = _scram_setup_first(p, s, "scott")
    assert kind(r) == "SCRAM_RESPONSE"
    assert r["result"]["response"]["scram_type"] == "SERVER_FIRST_RESPONSE"
    assert s.lifecycle is SessionLifecycle.INIT                # challenge issued, mid-exchange
    r, sf, cfin, ad = _scram_continue_final(
        p, s, cf, _SCRAM_SECRET, r["result"]["response"]["rfc_str"])
    assert kind(r) == "SCRAM_RESPONSE"
    assert r["result"]["response"]["scram_type"] == "SERVER_FINAL_RESPONSE"
    assert r["result"]["response"]["otp_required"] is False    # SCRAM-only: established outright
    assert s.lifecycle is SessionLifecycle.ESTABLISHED
    assert s.server_state_internal == {"user": "scott"}        # creds.identity
    # mutual auth: the client verifies the server's signature (raises on mismatch)
    sfin = truenas_pyscram.ServerFinalMessage(rfc_string=r["result"]["response"]["rfc_str"])
    truenas_pyscram.verify_server_signature(
        client_first=cf, server_first=sf, client_final=cfin,
        server_final=sfin, server_key=ad.server_key)
    assert decode(p.dispatch(req("work", {}, id=uid()), s))["result"] == {"ok": True}


@requires_scram
def test_scram_works_over_insecure_channel():
    # SCRAM carries no secret and is replay-resistant, so it needs no secure channel.
    p = _proto()
    s = p.new_session(server_state=Peer(transport="tcp", tls=False,
                                        address=("203.0.113.5", 443)))   # remote, no TLS
    cf, r = _scram_setup_first(p, s, "scott")
    assert kind(r) == "SCRAM_RESPONSE"                         # not DENIED
    r, *_ = _scram_continue_final(p, s, cf, _SCRAM_SECRET, r["result"]["response"]["rfc_str"])
    assert s.lifecycle is SessionLifecycle.ESTABLISHED


@requires_scram
def test_scram_bad_secret_is_auth_err():
    p = _proto()
    s = p.new_session(server_state=Peer(transport="tcp", tls=True))
    cf, r = _scram_setup_first(p, s, "scott")
    wrong = base64.b64encode(b"\x00" * 64).decode()            # wrong SaltedPassword
    r, *_ = _scram_continue_final(p, s, cf, wrong, r["result"]["response"]["rfc_str"])
    assert kind(r) == "AUTH_ERR"
    assert s.lifecycle is SessionLifecycle.NONE


@requires_scram
def test_scram_unknown_user_is_auth_err():
    # no fabricated challenge for an unknown user — rejected at the first message
    p = _proto()
    s = p.new_session(server_state=Peer(transport="tcp", tls=True))
    _cf, r = _scram_setup_first(p, s, "nobody")
    assert kind(r) == "AUTH_ERR"
    assert s.lifecycle is SessionLifecycle.NONE


# --- SCRAM + OTP second factor -----------------------------------------------
class _ScramOtpStack(AuthStack):
    """SCRAM whose verifier still demands an OTP second factor afterward — the real RFC 5802
    proof is checked first (via ``super().scram_finish``), then an OTP is required."""
    def scram_credentials(self, username):
        return _SCRAM_CREDS if username == "scott" else None

    def scram_finish(self, pending, client_final_rfc, *, peer):
        out = super().scram_finish(pending, client_final_rfc, peer=peer)
        if isinstance(out, Reject):
            return out
        sfinal, authd = out                       # proof verified -> now require a second factor
        return sfinal, NeedsOtp(pending=authd.identity, username="scott")

    def otp(self, pending, otp_token, *, peer):
        return Authenticated(pending) if otp_token == "123456" else Reject()


@requires_scram
def test_scram_then_otp():
    p = JSONRPCProtocol(
        [JSONRPCMethod("work", accepts=NoArgs, returns=Ok, handler=_work)], name="v1")
    _ScramOtpStack().install(p)
    s = p.new_session(server_state=Peer(transport="tcp", tls=True))
    cf, r = _scram_setup_first(p, s, "scott")
    assert kind(r) == "SCRAM_RESPONSE"
    assert s.lifecycle is SessionLifecycle.INIT
    # SCRAM proof accepted, but a second factor is still required: final reply flags it, stays INIT
    r, *_ = _scram_continue_final(p, s, cf, _SCRAM_SECRET, r["result"]["response"]["rfc_str"])
    assert kind(r) == "SCRAM_RESPONSE"
    assert r["result"]["response"]["scram_type"] == "SERVER_FINAL_RESPONSE"
    assert r["result"]["response"]["otp_required"] is True
    assert s.lifecycle is SessionLifecycle.INIT

    def otp(tok):
        return req("$/sessionSetupContinue",
                   {"mechanism": {"mechanism": "OTP_TOKEN", "otp_token": tok}}, id=uid())

    # wrong code -> retry (stays INIT)
    assert kind(decode(p.dispatch(otp("000000"), s))) == "AUTH_ERR"
    assert s.lifecycle is SessionLifecycle.INIT
    # right code -> ESTABLISHED
    r = decode(p.dispatch(otp("123456"), s))
    assert kind(r) == "SUCCESS"
    assert s.lifecycle is SessionLifecycle.ESTABLISHED
    assert s.server_state_internal == {"user": "scott"}    # creds.identity threaded through OTP


def test_mtls_client_certificate():
    p = _proto()
    s = p.new_session(server_state=Peer(transport="tcp", tls=True,
                                        peercert={"subject": "alice"}))
    r = decode(p.dispatch(req("$/sessionSetup",
        {"mechanism": {"mechanism": "CLIENT_CERTIFICATE"}}, id=uid()), s))
    assert kind(r) == "SUCCESS"
    assert s.server_state_internal == {"user": "cert:alice"}


# --- GSSAPI (RFC 4752): a variable-round token exchange ----------------------
def test_gssapi_stub_rejects():
    # the base AuthStack.gssapi_step is a stub that rejects until overridden
    p = _proto()
    s = p.new_session(server_state=Peer(transport="tcp", tls=True))
    r = decode(p.dispatch(req("$/sessionSetup", _gssapi(b"token"), id=uid()), s))
    assert kind(r) == "AUTH_ERR"
    assert s.lifecycle is SessionLifecycle.NONE


class _GssapiStack(AuthStack):
    """A fake two-round GSSAPI acceptor (a real impl wraps ``gssapi.SecurityContext``)."""
    def gssapi_step(self, pending, token, *, peer):
        if pending is None:                       # first token -> one challenge round
            return GssapiChallenge(server_token=b"challenge", pending="ctx")
        return b"final", Authenticated({"user": "alice@REALM"})


def test_gssapi_multi_round_exchange():
    p = JSONRPCProtocol(
        [JSONRPCMethod("work", accepts=NoArgs, returns=Ok, handler=_work)], name="v1")
    _GssapiStack().install(p)
    s = p.new_session(server_state=Peer(transport="tcp", tls=True))
    r = decode(p.dispatch(req("$/sessionSetup", _gssapi(b"t1"), id=uid()), s))
    assert kind(r) == "GSSAPI_RESPONSE"
    assert r["result"]["response"]["complete"] is False
    assert base64.b64decode(r["result"]["response"]["token"]) == b"challenge"
    assert s.lifecycle is SessionLifecycle.INIT
    r = decode(p.dispatch(req("$/sessionSetupContinue", _gssapi(b"t2"), id=uid()), s))
    assert kind(r) == "GSSAPI_RESPONSE"
    assert r["result"]["response"]["complete"] is True
    assert base64.b64decode(r["result"]["response"]["token"]) == b"final"
    assert s.lifecycle is SessionLifecycle.ESTABLISHED
    assert s.server_state_internal == {"user": "alice@REALM"}
    assert decode(p.dispatch(req("work", {}, id=uid()), s))["result"] == {"ok": True}


class _CertOtpStack(AuthStack):
    """First factor = client cert, second factor = OTP — a generic two-step flow used to
    reach the INIT/``_Pending`` state without needing SCRAM."""
    def client_certificate(self, peercert, *, peer):
        return NeedsOtp(pending="alice", username="alice")


def test_gssapi_continue_with_wrong_pending_is_auth_err():
    # a GSSAPI continue when the in-flight exchange isn't GSSAPI is rejected
    p = JSONRPCProtocol(
        [JSONRPCMethod("work", accepts=NoArgs, returns=Ok, handler=_work)], name="v1")
    _CertOtpStack().install(p)
    s = p.new_session(server_state=Peer(transport="tcp", tls=True,
                                        peercert={"subject": "alice"}))
    p.dispatch(req("$/sessionSetup",                       # cert first factor -> INIT (_Pending)
                   {"mechanism": {"mechanism": "CLIENT_CERTIFICATE"}}, id=uid()), s)
    assert s.lifecycle is SessionLifecycle.INIT
    r = decode(p.dispatch(req("$/sessionSetupContinue", _gssapi(b"t2"), id=uid()), s))
    assert kind(r) == "AUTH_ERR"                           # holder is _Pending, not _GssapiPending
    assert s.lifecycle is SessionLifecycle.NONE


# --- channel binding ---------------------------------------------------------
def test_client_cert_denied_without_a_cert():
    p = _proto()
    s = p.new_session(server_state=Peer(transport="tcp", tls=True))   # no peercert
    r = decode(p.dispatch(req("$/sessionSetup",
        {"mechanism": {"mechanism": "CLIENT_CERTIFICATE"}}, id=uid()), s))
    assert kind(r) == "DENIED"
    assert s.lifecycle is SessionLifecycle.NONE


# --- audit redaction ---------------------------------------------------------
def test_secrets_redacted_in_audit():
    audited = []

    def audit(request, response, session_state, audit_message=None):
        audited.append(request.params)

    p = JSONRPCProtocol(
        [JSONRPCMethod("work", accepts=NoArgs, returns=Ok, handler=_work)],
        name="v1", audit_handler=audit)
    _CertOtpStack().install(p)
    s = p.new_session(server_state=Peer(transport="tcp", tls=True,
                                        peercert={"subject": "alice"}))
    # first factor (client cert) -> OTP_REQUIRED (session INIT)
    p.dispatch(req("$/sessionSetup",
                   {"mechanism": {"mechanism": "CLIENT_CERTIFICATE"}}, id=uid()), s)
    # second factor carries the secret -> the control call is audited with the token redacted
    p.dispatch(req("$/sessionSetupContinue",
                   {"mechanism": {"mechanism": "OTP_TOKEN", "otp_token": "supersecret"}},
                   id=uid()), s)
    mech = audited[-1]["mechanism"]
    assert mech["otp_token"] == REDACTED          # secret, redacted (nested in the union)


# --- end-to-end over a real AF_UNIX connection -------------------------------
def test_e2e_peercred_over_unix():
    path = _tmp_sock()
    proto = JSONRPCProtocol(
        [JSONRPCMethod("work", accepts=NoArgs, returns=Ok, handler=_work)], name="v1")

    class _UidStack(AuthStack):                  # trust the connecting process's own uid
        def peercred(self, peer):
            return (Authenticated({"uid": peer.uid})
                    if getattr(peer, "uid", None) == os.getuid() else None)

    _UidStack().install(proto)
    srv = _ServerThread(proto, unix_config=SrvUnixConfig(path=path)).start()
    try:
        c = BaseClient("v1", unix_config=UnixConfig(path=path))
        c.connect()
        r = c.setup({})                          # peercred over AF_UNIX, no credentials
        assert r["response"]["response_type"] == "SUCCESS"
        assert c.call("work", {}) == {"ok": True}
        c.close()
    finally:
        srv.stop()
