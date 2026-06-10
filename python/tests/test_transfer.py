"""Raw-fd transfer methods (JSONRPCFdTransferMethod) over the server, driven by a
raw-socket client. The fd handoff is exercised with a deterministic sized blob (a
stand-in for a libzfs zfs send/recv stream); integrity is hash-checked both ways."""
import asyncio
import hashlib
import io
import os
import ssl
import struct
import tempfile
import uuid

import msgspec
import pytest

from truenas_pyjsonrpc import (
    JSONRPCError,
    JSONRPCFdTransferMethod,
    JSONRPCMethod,
    JSONRPCProtocol,
    TransferDirection,
)
from truenas_pyjsonrpc_client import BaseClient, TCPConfig, UnixConfig
from truenas_pyjsonrpc_server import JSONRPCServer
from truenas_pyjsonrpc_server import TCPConfig as SrvTCPConfig
from truenas_pyjsonrpc_server import UnixConfig as SrvUnixConfig
from test_client import _ServerThread
from test_server import _self_signed

_HEADER = struct.Struct(">I")
SIZE = 256 * 1024                                   # exercises multi-syscall sendfile/recv


def _blob(n: int) -> bytes:
    return bytes(i % 251 for i in range(n))         # deterministic, hash-checkable


# --- api types ---------------------------------------------------------------
class DownloadArgs(msgspec.Struct):
    size: int

class DownloadResult(msgspec.Struct):
    sent: int
    sha256: str

class UploadArgs(msgspec.Struct):
    size: int
    sha256: str

class UploadResult(msgspec.Struct):
    received: int
    ok: bool

class EchoArgs(msgspec.Struct):
    msg: str

class EchoResult(msgspec.Struct):
    msg: str


# --- handlers ----------------------------------------------------------------
def _dl_negotiate(request, session_state):
    return {"size": request.size}                   # interim "ready": how many bytes follow

def _dl_transfer(ft):
    blob = _blob(ft.params.size)
    with tempfile.TemporaryFile() as f:
        f.write(blob)
        f.flush()
        f.seek(0)
        sent = ft.sendfile(f)                        # os.sendfile to the client
    return DownloadResult(sent=sent, sha256=hashlib.sha256(blob).hexdigest())

def _ul_negotiate(request, session_state):
    return True                                      # ready to receive

def _ul_transfer(ft):
    with tempfile.TemporaryFile() as f:
        got = ft.recvfile(f, ft.params.size)         # read size bytes from the client
        f.seek(0)
        data = f.read()
    ok = hashlib.sha256(data).hexdigest() == ft.params.sha256
    return UploadResult(received=got, ok=ok)

def _echo(request, session_state, request_state):
    return EchoResult(msg=request.msg)


def _build() -> JSONRPCProtocol:
    return JSONRPCProtocol([
        JSONRPCMethod("echo", accepts=EchoArgs, returns=EchoResult, handler=_echo),
        JSONRPCFdTransferMethod("file.download", accepts=DownloadArgs,
                                returns=DownloadResult,
                                direction=TransferDirection.DOWNLOAD,
                                negotiate=_dl_negotiate, transfer=_dl_transfer),
        JSONRPCFdTransferMethod("file.upload", accepts=UploadArgs, returns=UploadResult,
                                direction=TransferDirection.UPLOAD,
                                negotiate=_ul_negotiate, transfer=_ul_transfer),
    ], name="v1")


# --- wire helpers ------------------------------------------------------------
def uid() -> str:
    return str(uuid.uuid4())

def _tmp_sock() -> str:
    return os.path.join(tempfile.mkdtemp(dir="/tmp"), "s.sock")

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
    (n,) = _HEADER.unpack(await asyncio.wait_for(r.readexactly(4), 5))
    return msgspec.json.decode(await asyncio.wait_for(r.readexactly(n), 5))

async def negotiate(r, w):
    await send(w, "$/negotiate", {"protocol": "v1"}, id=uid())
    assert (await recv(r))["result"]["protocol"] == "v1"

async def _run(fn, **server_kw):
    path = _tmp_sock()
    proto = _build()
    server = JSONRPCServer({"v1": proto}, name="t",
                           unix_config=SrvUnixConfig(path=path), **server_kw)
    await server.start()
    try:
        await asyncio.wait_for(fn(server, proto, path), 15)
    finally:
        await server.aclose()


# --- tests -------------------------------------------------------------------
def test_download():
    async def go(server, proto, path):
        r, w = await asyncio.open_unix_connection(path)
        await negotiate(r, w)
        u = uid()
        await send(w, "file.download", {"size": SIZE}, id=u)
        ready = await recv(r)
        assert ready["method"] == "$/transferReady"
        assert ready["params"]["id"] == u
        assert ready["params"]["direction"] == "download"
        size = ready["params"]["result"]["size"]
        assert size == SIZE
        await send(w, "$/transferGo", {"id": u})         # consumer paused -> go
        blob = await asyncio.wait_for(r.readexactly(size), 5)   # raw stream
        final = await recv(r)
        assert final["id"] == u
        assert final["result"]["sent"] == size
        assert final["result"]["sha256"] == hashlib.sha256(blob).hexdigest()
        # the connection resumes normal JSON-RPC afterwards
        await send(w, "echo", {"msg": "after"}, id=uid())
        assert (await recv(r))["result"] == {"msg": "after"}
        w.close()

    asyncio.run(_run(go))


def test_upload():
    async def go(server, proto, path):
        r, w = await asyncio.open_unix_connection(path)
        await negotiate(r, w)
        blob = _blob(SIZE)
        sha = hashlib.sha256(blob).hexdigest()
        u = uid()
        await send(w, "file.upload", {"size": SIZE, "sha256": sha}, id=u)
        ready = await recv(r)
        assert ready["method"] == "$/transferReady"
        assert ready["params"]["direction"] == "upload"
        w.write(blob)                                    # raw stream (client produces)
        await w.drain()
        final = await recv(r)
        assert final["id"] == u
        assert final["result"] == {"received": SIZE, "ok": True}
        await send(w, "echo", {"msg": "after"}, id=uid())   # connection resumes
        assert (await recv(r))["result"] == {"msg": "after"}
        w.close()

    asyncio.run(_run(go))


def test_transfer_rejected_over_tls():
    pytest.importorskip("cryptography")
    certfile, keyfile = _self_signed(tempfile.mkdtemp(dir="/tmp"))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)

    async def go(server):
        port = server._servers[0].sockets[0].getsockname()[1]
        cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cctx.check_hostname = False
        cctx.verify_mode = ssl.CERT_NONE
        r, w = await asyncio.open_connection("127.0.0.1", port, ssl=cctx,
                                             server_hostname="localhost")
        await negotiate(r, w)
        u = uid()
        await send(w, "file.download", {"size": SIZE}, id=u)
        reply = await recv(r)                            # rejected: ciphertext fd
        assert reply["id"] == u
        assert reply["error"]["code"] == JSONRPCError.REQUEST_FAILED
        assert "plain or kTLS" in reply["error"]["data"]
        w.close()

    async def runner():
        proto = _build()
        server = JSONRPCServer({"v1": proto}, name="t",
                               tcp_config=SrvTCPConfig(host="127.0.0.1", port=0,
                                                       ssl=ctx))
        await server.start()
        try:
            await asyncio.wait_for(go(server), 15)
        finally:
            await server.aclose()

    asyncio.run(runner())


# --- end-to-end via BaseClient.transfer --------------------------------------
def test_client_download():
    path = _tmp_sock()
    srv = _ServerThread(_build(), unix_config=SrvUnixConfig(path=path)).start()
    try:
        c = BaseClient("v1", unix_config=UnixConfig(path=path))
        c.connect()
        buf = io.BytesIO()

        def recv_cb(ft):                                 # client consumes the stream
            ft.recvfile(buf, ft.params["size"])

        result = c.transfer("file.download", {"size": SIZE}, callback=recv_cb)
        assert result["sent"] == SIZE
        assert hashlib.sha256(buf.getvalue()).hexdigest() == result["sha256"]
        assert c.call("echo", {"msg": "after"}) == {"msg": "after"}   # resumes
        c.close()
    finally:
        srv.stop()


def test_client_upload():
    path = _tmp_sock()
    srv = _ServerThread(_build(), unix_config=SrvUnixConfig(path=path)).start()
    try:
        c = BaseClient("v1", unix_config=UnixConfig(path=path))
        c.connect()
        blob = _blob(SIZE)
        sha = hashlib.sha256(blob).hexdigest()

        def send_cb(ft):                                 # client produces the stream
            with tempfile.TemporaryFile() as f:
                f.write(blob)
                f.flush()
                f.seek(0)
                ft.sendfile(f)

        result = c.transfer("file.upload", {"size": SIZE, "sha256": sha},
                            callback=send_cb)
        assert result == {"received": SIZE, "ok": True}
        assert c.call("echo", {"msg": "after"}) == {"msg": "after"}   # resumes
        c.close()
    finally:
        srv.stop()


def test_ktls_transfer_encrypted():
    """A raw-fd transfer over a kTLS-encrypted connection: the fd is plaintext to us
    (kernel does the crypto), so the integrity check passing proves kTLS engaged."""
    pytest.importorskip("cryptography")
    certfile, keyfile = _self_signed(tempfile.mkdtemp(dir="/tmp"))
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.options |= ssl.OP_ENABLE_KTLS                # -> server uses the kTLS accept path
    sctx.load_cert_chain(certfile, keyfile)
    srv = _ServerThread(_build(),
                        tcp_config=SrvTCPConfig(host="127.0.0.1", port=0,
                                                ssl=sctx)).start()
    try:
        port = srv.server._ktls_listeners[0].getsockname()[1]
        cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cctx.options |= ssl.OP_ENABLE_KTLS
        cctx.check_hostname = False
        cctx.verify_mode = ssl.CERT_NONE
        c = BaseClient("v1", tcp_config=TCPConfig(host="127.0.0.1", port=port,
                                                  ssl=cctx,
                                                  server_hostname="localhost"))
        c.connect()
        assert c.call("echo", {"msg": "kt"}) == {"msg": "kt"}   # JSON-RPC over kTLS
        buf = io.BytesIO()
        dl = c.transfer("file.download", {"size": SIZE},
                        callback=lambda ft: ft.recvfile(buf, ft.params["size"]))
        assert hashlib.sha256(buf.getvalue()).hexdigest() == dl["sha256"]   # decrypted ok
        blob = _blob(SIZE)

        def send_cb(ft):
            with tempfile.TemporaryFile() as f:
                f.write(blob)
                f.flush()
                f.seek(0)
                ft.sendfile(f)

        ul = c.transfer("file.upload",
                        {"size": SIZE, "sha256": hashlib.sha256(blob).hexdigest()},
                        callback=send_cb)
        assert ul == {"received": SIZE, "ok": True}
        c.close()
    finally:
        srv.stop()
