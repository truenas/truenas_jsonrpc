"""End-to-end tests for truenas_pyjsonrpc_server, driven by a raw asyncio socket
client over AF_UNIX (and TCP for the basics)."""
import asyncio
import os
import ssl
import struct
import tempfile
import time
import uuid

import msgspec
import pytest

from truenas_pyjsonrpc import (
    JSONRPCError,
    JSONRPCMethod,
    JSONRPCProtocol,
    JsonRpcError,
    MessageDirection,
    SessionLifecycle,
)
from truenas_pyjsonrpc_server import JSONRPCServer, TCPConfig, UnixConfig


# --- api types ---------------------------------------------------------------
class EchoArgs(msgspec.Struct):
    msg: str


class Result(msgspec.Struct):
    msg: str


class NoArgs(msgspec.Struct):
    pass


class Creds(msgspec.Struct):
    token: str


class LoginResult(msgspec.Struct):
    user: str


class Event(msgspec.Struct):
    x: int


# --- handlers ----------------------------------------------------------------
def _echo(request, session_state, request_state) -> Result:
    return Result(msg=request.msg)


def _progress(request, session_state, request_state) -> Result:
    for pct in (0, 50, 100):
        request_state.update_progress(percent=pct)
        time.sleep(0.03)                       # let the drain deliver live
    return Result(msg="done")


def _slow(request, session_state, request_state) -> Result:
    request_state.wait_for_cancel(2)           # blocks until cancelled (or 2s)
    request_state.raise_if_cancelled()
    return Result(msg="never")


def _login(request, session_state):
    if request.token != "ok":
        raise JsonRpcError(JSONRPCError.NOT_AUTHORIZED, "bad token")
    session_state.server_state_internal = {"user": "root"}
    return SessionLifecycle.ESTABLISHED, LoginResult(user="root")


def _auth_setup() -> JSONRPCMethod:
    """A minimal ``$/sessionSetup`` (token ``"ok"`` -> ESTABLISHED). A network transport
    requires authentication, so test protocols served over TCP/WS add this; their methods
    are marked ``pre_auth`` so the (unauthenticated) tests still drive them."""
    return JSONRPCMethod("$/sessionSetup", accepts=Creds, returns=LoginResult,
                         handler=_login)


def _build() -> JSONRPCProtocol:
    p = JSONRPCProtocol([
        JSONRPCMethod("echo", accepts=EchoArgs, returns=Result, handler=_echo),
        JSONRPCMethod("progress", accepts=NoArgs, returns=Result, handler=_progress),
        JSONRPCMethod("slow", accepts=NoArgs, returns=Result, handler=_slow,
                      cancellable=True),
        JSONRPCMethod("events", accepts=NoArgs, notifies=Event,
                      direction=MessageDirection.SERVER_CLIENT),
    ], name="v1")
    p.add_session_setup(JSONRPCMethod("$/sessionSetup", accepts=Creds,
                                      returns=LoginResult, handler=_login))
    return p


# --- wire helpers ------------------------------------------------------------
def uid() -> str:
    return str(uuid.uuid4())


def _tmp_sock() -> str:
    return os.path.join(tempfile.mkdtemp(dir="/tmp"), "s.sock")


_HEADER = struct.Struct(">I")           # 4-byte big-endian length prefix (framing)


async def send(w, method, params=None, id=None):
    m = {"jsonrpc": "2.0", "method": method}
    if id is not None:
        m["id"] = id
    if params is not None:
        m["params"] = params
    data = msgspec.json.encode(m)
    w.write(_HEADER.pack(len(data)) + data)
    await w.drain()


async def recv(r):
    header = await asyncio.wait_for(r.readexactly(4), 5)
    (length,) = _HEADER.unpack(header)
    data = await asyncio.wait_for(r.readexactly(length), 5)
    return msgspec.json.decode(data)


async def established_unix(path):
    r, w = await asyncio.open_unix_connection(path)
    await send(w, "$/negotiate", {"protocol": "v1"}, id=uid())
    await recv(r)
    await send(w, "$/sessionSetup", {"token": "ok"}, id=uid())
    await recv(r)
    return r, w


async def _run_server(fn, **kw):
    path = _tmp_sock()
    proto = _build()
    server = JSONRPCServer({"v1": proto}, name="test",
                           unix_config=UnixConfig(path=path), **kw)
    await server.start()
    try:
        await asyncio.wait_for(fn(server, proto, path), 15)
    finally:
        await server.aclose()


async def _wait_until(pred, timeout=2.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        if pred():
            return True
        await asyncio.sleep(0.02)
    return pred()


# --- tests -------------------------------------------------------------------
def test_negotiate_setup_and_gating():
    async def go(server, proto, path):
        r, w = await asyncio.open_unix_connection(path)
        # a method before $/negotiate is rejected
        await send(w, "echo", {"msg": "hi"}, id=uid())
        assert (await recv(r))["error"]["code"] == JSONRPCError.SESSION_NOT_ESTABLISHED

        # negotiate binds the protocol and reports identity + available
        await send(w, "$/negotiate", {"protocol": "v1"}, id=uid())
        neg = (await recv(r))["result"]
        assert neg == {"protocol": "v1", "server": "test", "available": ["v1"]}

        # a normal method before $/sessionSetup is gated
        await send(w, "echo", {"msg": "hi"}, id=uid())
        assert (await recv(r))["error"]["code"] == JSONRPCError.SESSION_NOT_ESTABLISHED

        # authenticate, then the call works
        await send(w, "$/sessionSetup", {"token": "ok"}, id=uid())
        assert (await recv(r))["result"] == {"user": "root"}
        u = uid()
        await send(w, "echo", {"msg": "hi"}, id=u)
        assert await recv(r) == {"jsonrpc": "2.0", "result": {"msg": "hi"}, "id": u}
        w.close()

    asyncio.run(_run_server(go))


def test_unknown_protocol_is_request_failed():
    async def go(server, proto, path):
        r, w = await asyncio.open_unix_connection(path)
        await send(w, "$/negotiate", {"protocol": "nope"}, id=uid())
        err = (await recv(r))["error"]
        assert err["code"] == JSONRPCError.REQUEST_FAILED
        assert err["data"]["available"] == ["v1"]
        w.close()

    asyncio.run(_run_server(go))


def test_pubsub_delivery():
    async def go(server, proto, path):
        r, w = await established_unix(path)
        await send(w, "events", id=uid())                 # subscribe
        sub = await recv(r)
        uuid.UUID(sub["result"])                          # ack is a sub id
        proto.send_notification("events", {"x": 7})       # server publishes
        note = await recv(r)
        assert note["method"] == "events" and note["params"] == {"x": 7}
        w.close()

    asyncio.run(_run_server(go))


def test_progress_delivered_live():
    async def go(server, proto, path):
        r, w = await established_unix(path)
        u = uid()
        await send(w, "progress", id=u)
        progress, result = 0, None
        for _ in range(6):
            frame = await recv(r)
            if frame.get("method") == "$/progress":
                progress += 1
            elif frame.get("id") == u:
                result = frame
                break
        assert progress >= 1                              # some progress arrived live
        assert result["result"] == {"msg": "done"}
        w.close()

    asyncio.run(_run_server(go))


def test_cancel_over_the_wire():
    async def go(server, proto, path):
        r, w = await established_unix(path)
        tid, cid = uid(), uid()
        await send(w, "slow", id=tid)                     # blocks in the executor
        await asyncio.sleep(0.05)                         # let it register in-flight
        await send(w, "$/cancelRequest", {"target_id": tid}, id=cid)
        seen = {}
        for _ in range(2):
            frame = await recv(r)
            seen[frame["id"]] = frame
        assert seen[cid]["result"] is True               # cancel accepted
        assert seen[tid]["error"]["code"] == JSONRPCError.REQUEST_CANCELLED
        w.close()

    asyncio.run(_run_server(go))


def test_disconnect_drops_subscriptions():
    async def go(server, proto, path):
        r, w = await established_unix(path)
        await send(w, "events", id=uid())                 # subscribe
        await recv(r)
        assert proto._subscriptions.get("events")         # registered
        w.close()
        await w.wait_closed()
        assert await _wait_until(lambda: not proto._subscriptions.get("events"))

    asyncio.run(_run_server(go))


def test_tcp_basic():
    async def go(server, proto, path):
        port = server._servers[0].sockets[0].getsockname()[1]
        r, w = await asyncio.open_connection("127.0.0.1", port)
        await send(w, "$/negotiate", {"protocol": "v1"}, id=uid())
        assert (await recv(r))["result"]["protocol"] == "v1"
        await send(w, "$/sessionSetup", {"token": "ok"}, id=uid())
        assert (await recv(r))["result"] == {"user": "root"}
        u = uid()
        await send(w, "echo", {"msg": "tcp"}, id=u)
        assert (await recv(r))["result"] == {"msg": "tcp"}
        w.close()

    # TCP-only server (no unix_path) on an ephemeral port
    async def runner():
        proto = _build()
        server = JSONRPCServer({"v1": proto}, name="test",
                               tcp_config=TCPConfig(host="127.0.0.1", port=0))
        await server.start()
        try:
            await asyncio.wait_for(go(server, proto, None), 15)
        finally:
            await server.aclose()

    asyncio.run(runner())


def test_oversized_frame_is_rejected():
    async def go(server, proto, path):
        r, w = await asyncio.open_unix_connection(path)
        w.write(struct.pack(">I", 50 * 1024 * 1024))      # declare 50 MiB (> 4 MiB limit)
        await w.drain()
        err = (await recv(r))["error"]                    # server replies, then closes
        assert err["code"] == JSONRPCError.INVALID_REQUEST
        assert "too large" in err["message"].lower()
        w.close()

    asyncio.run(_run_server(go))


# --- TLS ---------------------------------------------------------------------
class PeerProbe(msgspec.Struct):
    transport: str
    tls: bool
    cipher: str | None
    has_cert: bool


def _whoami(request, session_state, request_state) -> PeerProbe:
    # Before any session setup, server_state_internal is the connection's Peer.
    peer = session_state.server_state_internal
    return PeerProbe(
        transport=peer.transport if peer else "?",
        tls=bool(peer and peer.tls),
        cipher=(peer.cipher[0] if (peer and peer.cipher) else None),
        has_cert=bool(peer and peer.peercert))


def _build_peer_probe() -> JSONRPCProtocol:
    # whoami is pre_auth so it runs right after $/negotiate (before the session is
    # ESTABLISHED) and reports the Peer the server stamped onto the session. A session
    # setup is configured because a network transport requires authentication; whoami
    # bypasses the gate so it reads the seeded Peer, not the post-login identity.
    p = JSONRPCProtocol([
        JSONRPCMethod("whoami", accepts=NoArgs, returns=PeerProbe, handler=_whoami,
                      pre_auth=True),
    ], name="v1")
    p.add_session_setup(_auth_setup())
    return p


def _self_signed(directory: str) -> tuple[str, str]:
    """Write a throwaway self-signed cert+key to ``directory``; return their paths."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    certfile = os.path.join(directory, "cert.pem")
    keyfile = os.path.join(directory, "key.pem")
    with open(certfile, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(keyfile, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    return certfile, keyfile


def test_tcp_tls_stamps_peer():
    pytest.importorskip("cryptography")
    certfile, keyfile = _self_signed(tempfile.mkdtemp(dir="/tmp"))
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile, keyfile)

    async def go(server):
        port = server._servers[0].sockets[0].getsockname()[1]
        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE          # accept the self-signed cert
        r, w = await asyncio.open_connection(
            "127.0.0.1", port, ssl=client_ctx, server_hostname="localhost")
        await send(w, "$/negotiate", {"protocol": "v1"}, id=uid())
        assert (await recv(r))["result"]["protocol"] == "v1"
        await send(w, "whoami", id=uid())
        info = (await recv(r))["result"]
        assert info["transport"] == "tcp"
        assert info["tls"] is True
        assert info["cipher"]                            # a cipher was negotiated
        assert info["has_cert"] is False                 # plain TLS, no client cert
        w.close()

    async def runner():
        server = JSONRPCServer({"v1": _build_peer_probe()}, name="test",
                               tcp_config=TCPConfig(host="127.0.0.1", port=0,
                                                    ssl=server_ctx))
        await server.start()
        try:
            await asyncio.wait_for(go(server), 15)
        finally:
            await server.aclose()

    asyncio.run(runner())


def test_tcp_plaintext_peer_is_not_tls():
    async def go(server):
        port = server._servers[0].sockets[0].getsockname()[1]
        r, w = await asyncio.open_connection("127.0.0.1", port)
        await send(w, "$/negotiate", {"protocol": "v1"}, id=uid())
        await recv(r)
        await send(w, "whoami", id=uid())
        info = (await recv(r))["result"]
        assert info["transport"] == "tcp"
        assert info["tls"] is False                      # the Peer default
        assert info["cipher"] is None
        w.close()

    async def runner():
        server = JSONRPCServer({"v1": _build_peer_probe()}, name="test",
                               tcp_config=TCPConfig(host="127.0.0.1", port=0))
        await server.start()
        try:
            await asyncio.wait_for(go(server), 15)
        finally:
            await server.aclose()

    asyncio.run(runner())


def test_requires_a_transport():
    with pytest.raises(ValueError, match="at least one transport"):
        JSONRPCServer({"v1": _build_peer_probe()}, name="test")


def test_network_transport_requires_authentication():
    # A protocol with no $/sessionSetup would dispatch to unauthenticated remote
    # clients, so a TCP/WebSocket server must refuse to surface it.
    bare = JSONRPCProtocol(
        [JSONRPCMethod("whoami", accepts=NoArgs, returns=PeerProbe, handler=_whoami)],
        name="v1")
    with pytest.raises(ValueError, match="no authentication"):
        JSONRPCServer({"v1": bare}, name="test",
                      tcp_config=TCPConfig(host="127.0.0.1", port=0))
    # AF_UNIX is exempt (local peer-credential / filesystem trust).
    JSONRPCServer({"v1": bare}, name="test", unix_config=UnixConfig(path=_tmp_sock()))
    # A protocol that configures authentication may be served over the network.
    JSONRPCServer({"v1": _build_peer_probe()}, name="test",
                  tcp_config=TCPConfig(host="127.0.0.1", port=0))
