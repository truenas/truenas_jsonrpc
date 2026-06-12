"""Real PAM tests for ``TrueNASAuth`` — drive SCRAM authentication through the actual
``pam_truenas.so`` module, exactly as ``pam_truenas``'s own suite proves it works (the
provisioning here is ported from ``pam_truenas/tests/conftest.py``).

The whole module **skips** unless the host has the PAM stack: ``truenas_pypam`` +
``truenas_authenticator`` + ``truenas_pyscram``, the keyring-provisioning packages, the
``/etc/pam.d/middleware-scram`` service, and the test user ``bob``. So it runs on a TrueNAS
host / the pam_truenas test box and self-skips elsewhere — never mocked."""
import os
import pwd
import uuid
from base64 import b64decode, b64encode

import msgspec
import pytest

from truenas_pyjsonrpc import JSONRPCMethod, JSONRPCProtocol, SessionLifecycle
from truenas_pyjsonrpc.mixins.auth import PAM_AVAILABLE, TrueNASAuth
from truenas_pyjsonrpc_server import Peer

try:
    import truenas_api_key
    import truenas_keyring
    import truenas_pypwenc
    import truenas_pyscram
    from truenas_pam_faillog import PamFaillog
    _HAS_PROVISION = True
except ImportError:
    _HAS_PROVISION = False

_SCRAM_SERVICE = "middleware-scram"

# The test API key provisioned into the keyring (verbatim from pam_truenas/tests/conftest.py).
_API_KEY = {
    "id": 2,
    "username": "bob",
    "salt": b"KCwXnX9l35e0ndOu",
    "salted_password_b64": "sljMczeiN9kEqyOIrjoQ1QiBhnrmL++DtRdeyv+DHmQkkzoypbkzHIVA1iM/NVviC50dVpDKKlD3L2pv9KDdfw==",
    "iterations": 500000,
    "raw_key": "2-DJpfT7q7dHu6RRfeMwP8aJlGeUOmRWbDKnnzxnsc8F1YAsDNbl8aDM4X1cYwPmcC",
}


def _user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


_RUNNABLE = (
    PAM_AVAILABLE and _HAS_PROVISION
    and os.path.exists(f"/etc/pam.d/{_SCRAM_SERVICE}")
    and _user_exists(_API_KEY["username"])
)

pytestmark = pytest.mark.skipif(
    not _RUNNABLE, reason="real pam_truenas stack (module, service files, bob) not present")


# --- provisioning (ported from pam_truenas/tests/conftest.py) ----------------
@pytest.fixture(scope="module")
def scram_auth_data():
    """Commit the test API key for `bob` into the keyring; return its SCRAM auth data."""
    salted = truenas_pyscram.CryptoDatum(b64decode(_API_KEY["salted_password_b64"]))
    auth_data = truenas_pyscram.generate_scram_auth_data(
        salted_password=salted,
        salt=truenas_pyscram.CryptoDatum(_API_KEY["salt"]),
        iterations=_API_KEY["iterations"])
    entry = truenas_api_key.UserApiKey(
        _API_KEY["username"], _API_KEY["id"], "sha512", _API_KEY["iterations"], 0,
        b64encode(_API_KEY["salt"]).decode(),
        b64encode(bytes(auth_data.server_key)).decode(),
        b64encode(bytes(auth_data.stored_key)).decode())
    ctx = truenas_pypwenc.get_context(create=True)
    truenas_api_key.keyring.commit_user_entry(
        _API_KEY["username"], [entry], lambda b: ctx.encrypt(b.encode()).decode())
    return auth_data


@pytest.fixture(autouse=True)
def _clear_keyring_state():
    """Clear faillog/tally/session before & after each test so reruns don't lock `bob` out."""
    def cleanup():
        PamFaillog().reset_tally(_API_KEY["username"])
        try:
            persistent = truenas_keyring.get_persistent_keyring()
            pam_keyring = persistent.search(key_type="keyring", description="PAM_TRUENAS")
            bob_keyring = pam_keyring.search(key_type="keyring", description=_API_KEY["username"])
            bob_keyring.search(key_type="keyring", description="SESSION").clear()
        except FileNotFoundError:
            pass
    cleanup()
    yield
    cleanup()


# --- harness -----------------------------------------------------------------
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


def kind(reply) -> str:
    return reply["result"]["response"]["response_type"]


def _scram(scram_type: str, rfc_str: str) -> dict:
    return {"mechanism": {"mechanism": "SCRAM",
                          "scram_type": scram_type, "rfc_str": rfc_str}}


class NoArgs(msgspec.Struct):
    pass


class Ok(msgspec.Struct):
    ok: bool = True


def _work(request, session_state, request_state) -> Ok:
    return Ok()


def _proto(stack: TrueNASAuth) -> JSONRPCProtocol:
    p = JSONRPCProtocol(
        [JSONRPCMethod("work", accepts=NoArgs, returns=Ok, handler=_work)], name="v1", version="1.0.0")
    stack.install(p)
    return p


def _scram_first(p, s, username, api_key_id):
    cf = truenas_pyscram.ClientFirstMessage(username=username, api_key_id=api_key_id)
    r = decode(p.dispatch(req("$/sessionSetup",
                              _scram("CLIENT_FIRST_MESSAGE", str(cf)), id=uid()), s))
    return cf, r


# --- SCRAM through pam_truenas ------------------------------------------------
def test_scram_success(scram_auth_data):
    p = _proto(TrueNASAuth(mechanisms={"SCRAM"}, scram_service=_SCRAM_SERVICE))
    s = p.new_session(server_state=Peer(transport="tcp", tls=True))
    cf, r = _scram_first(p, s, "bob", 2)
    assert kind(r) == "SCRAM_RESPONSE"
    assert r["result"]["response"]["scram_type"] == "SERVER_FIRST_RESPONSE"
    assert s.lifecycle is SessionLifecycle.INIT
    sf = truenas_pyscram.ServerFirstMessage(rfc_string=r["result"]["response"]["rfc_str"])
    assert bytes(sf.salt) == _API_KEY["salt"]                 # the real verifier from keyring
    assert sf.iterations == _API_KEY["iterations"]
    cfin = truenas_pyscram.ClientFinalMessage(
        client_first=cf, server_first=sf,
        client_key=scram_auth_data.client_key, stored_key=scram_auth_data.stored_key)
    r = decode(p.dispatch(req("$/sessionSetupContinue",
                              _scram("CLIENT_FINAL_MESSAGE", str(cfin)), id=uid()), s))
    assert kind(r) == "SCRAM_RESPONSE"
    assert r["result"]["response"]["scram_type"] == "SERVER_FINAL_RESPONSE"
    assert s.lifecycle is SessionLifecycle.ESTABLISHED
    assert s.server_state_internal["username"] == "bob"
    # mutual auth: pam_truenas proved itself with the ServerSignature
    sfin = truenas_pyscram.ServerFinalMessage(rfc_string=r["result"]["response"]["rfc_str"])
    truenas_pyscram.verify_server_signature(
        client_first=cf, server_first=sf, client_final=cfin, server_final=sfin,
        server_key=scram_auth_data.server_key)
    assert decode(p.dispatch(req("work", {}, id=uid()), s))["result"] == {"ok": True}


def test_scram_wrong_secret(scram_auth_data):
    p = _proto(TrueNASAuth(mechanisms={"SCRAM"}, scram_service=_SCRAM_SERVICE))
    s = p.new_session(server_state=Peer(transport="tcp", tls=True))
    cf, r = _scram_first(p, s, "bob", 2)
    sf = truenas_pyscram.ServerFirstMessage(rfc_string=r["result"]["response"]["rfc_str"])
    wrong = truenas_pyscram.generate_scram_auth_data(salt=sf.salt, iterations=sf.iterations)
    cfin = truenas_pyscram.ClientFinalMessage(
        client_first=cf, server_first=sf,
        client_key=wrong.client_key, stored_key=wrong.stored_key)
    r = decode(p.dispatch(req("$/sessionSetupContinue",
                              _scram("CLIENT_FINAL_MESSAGE", str(cfin)), id=uid()), s))
    assert kind(r) == "AUTH_ERR"                             # real PAM_AUTH_ERR
    assert s.lifecycle is SessionLifecycle.NONE


def test_scram_unknown_user():
    p = _proto(TrueNASAuth(mechanisms={"SCRAM"}, scram_service=_SCRAM_SERVICE))
    s = p.new_session(server_state=Peer(transport="tcp", tls=True))
    _cf, r = _scram_first(p, s, "alice", 2)                  # no key for alice
    assert kind(r) == "AUTH_ERR"                             # PAM_AUTHINFO_UNAVAIL at init
    assert s.lifecycle is SessionLifecycle.NONE


def test_scram_malformed_client_first():
    p = _proto(TrueNASAuth(mechanisms={"SCRAM"}, scram_service=_SCRAM_SERVICE))
    s = p.new_session(server_state=Peer(transport="tcp", tls=True))
    r = decode(p.dispatch(req("$/sessionSetup",
                              _scram("CLIENT_FIRST_MESSAGE", "not-a-scram-message"),
                              id=uid()), s))
    assert kind(r) == "AUTH_ERR"
    assert s.lifecycle is SessionLifecycle.NONE
