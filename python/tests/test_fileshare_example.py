"""End-to-end test of the examples/fileshare.py bi-directional transfer API: a
lookup + get/put built on JSONRPCFdTransferMethod. Mirrors the demo flow — put a
file, re-lookup to verify its size and that the connection still works, then get it
back and hash-check the bytes."""
import hashlib
import io
import os
import shutil
import sys
import tempfile

import pytest

from truenas_pyjsonrpc import JSONRPCError, JsonRpcError
from truenas_pyjsonrpc_client import BaseClient, UnixConfig
from truenas_pyjsonrpc_server import UnixConfig as SrvUnixConfig

from test_client import _ServerThread
from test_server import _tmp_sock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "examples"))
from fileshare import build_protocol           # noqa: E402

SIZE = 200_000


def _blob(n: int) -> bytes:
    return bytes(i % 251 for i in range(n))


def _serve(root: str):
    return _ServerThread(build_protocol(root),
                         unix_config=SrvUnixConfig(path=_tmp_sock())).start()


def _connect(srv) -> BaseClient:
    c = BaseClient("v1", unix_config=UnixConfig(path=srv.server._unix_config.path))
    c.connect()
    return c


def test_fileshare_put_lookup_get_roundtrip():
    root = tempfile.mkdtemp(dir="/tmp")
    with open(os.path.join(root, "seed.txt"), "wb") as f:
        f.write(b"seeded\n")
    srv = _serve(root)
    try:
        c = _connect(srv)
        # lookup sees the pre-existing file with its type + size
        entries = {e["name"]: e for e in c.call("fs.lookup")["entries"]}
        assert entries["seed.txt"]["type"] == "file"
        assert entries["seed.txt"]["size"] == 7

        # PUT: the client streams the bytes; the server writes them to the share
        blob = _blob(SIZE)
        sha = hashlib.sha256(blob).hexdigest()

        def send_cb(ft):
            with tempfile.TemporaryFile() as f:
                f.write(blob)
                f.flush()
                f.seek(0)
                ft.sendfile(f)

        put = c.transfer("fs.put", {"name": "up.bin", "size": SIZE}, callback=send_cb)
        assert put["received"] == SIZE
        assert os.path.getsize(os.path.join(root, "up.bin")) == SIZE   # landed on disk

        # re-lookup verifies the size — and proves the connection resumed after a transfer
        entries = {e["name"]: e for e in c.call("fs.lookup")["entries"]}
        assert entries["up.bin"]["size"] == SIZE

        # GET: the byte count comes from the server's negotiated $/transferReady result
        buf = io.BytesIO()
        got = c.transfer("fs.get", {"name": "up.bin"},
                         callback=lambda ft: ft.recvfile(buf, ft.result["size"]))
        assert got["sent"] == SIZE
        assert hashlib.sha256(buf.getvalue()).hexdigest() == sha

        # normal connectivity restored
        assert any(e["name"] == "up.bin" for e in c.call("fs.lookup")["entries"])
        c.close()
    finally:
        srv.stop()
        shutil.rmtree(root, ignore_errors=True)


def test_fileshare_get_missing_is_clean_error():
    """A bad request fails in negotiate (before the handshake), so it surfaces as a
    normal JSON-RPC error and leaves the connection fully usable."""
    root = tempfile.mkdtemp(dir="/tmp")
    srv = _serve(root)
    try:
        c = _connect(srv)
        with pytest.raises(JsonRpcError) as ei:
            c.transfer("fs.get", {"name": "nope.bin"}, callback=lambda ft: None)
        assert ei.value.code == JSONRPCError.REQUEST_FAILED
        assert c.call("fs.lookup")["entries"] == []    # connection still works
        c.close()
    finally:
        srv.stop()
        shutil.rmtree(root, ignore_errors=True)


def test_fileshare_rejects_path_traversal():
    root = tempfile.mkdtemp(dir="/tmp")
    srv = _serve(root)
    try:
        c = _connect(srv)
        with pytest.raises(JsonRpcError) as ei:
            c.transfer("fs.put", {"name": "../escape", "size": 1},
                       callback=lambda ft: None)
        assert ei.value.code == JSONRPCError.INVALID_PARAMS
        assert not os.path.exists(os.path.join(os.path.dirname(root), "escape"))
        c.close()
    finally:
        srv.stop()
        shutil.rmtree(root, ignore_errors=True)
