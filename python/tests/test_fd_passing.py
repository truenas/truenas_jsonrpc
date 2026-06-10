"""SCM_RIGHTS file-descriptor passing (AF_UNIX) — a JSONRPCFdPassMethod hands the peer
an *actual open fd* instead of streaming bytes. Helper-level tests over a raw socketpair
exercise send_fds/recv_fds directly; end-to-end tests drive a real server/client over
AF_UNIX (the privilege-broker pattern) and assert the AF_UNIX-only gate."""
import hashlib
import os
import socket
import tempfile

import msgspec
import pytest

from truenas_pyjsonrpc import (
    FileTransfer,
    JSONRPCError,
    JSONRPCFdPassMethod,
    JSONRPCMethod,
    JSONRPCProtocol,
    JsonRpcError,
    TransferDirection,
)
from truenas_pyjsonrpc_client import BaseClient, ClientError, TCPConfig, UnixConfig
from truenas_pyjsonrpc_server import TCPConfig as SrvTCPConfig
from truenas_pyjsonrpc_server import UnixConfig as SrvUnixConfig
from test_client import _ServerThread
from test_server import _auth_setup, _tmp_sock


def _content(i: int) -> bytes:
    return (f"fd-passing payload #{i}\n" * 50).encode()


# --- helper-level (raw socketpair): send_fds / recv_fds mechanics -------------
class _FT(FileTransfer):
    """Minimal concrete FileTransfer over a fixed fd, for unit-testing the helpers."""

    def __init__(self, fd: int) -> None:
        super().__init__(TransferDirection.DOWNLOAD, None, None)
        self._fd = fd

    def fileno(self) -> int:
        return self._fd


def _readall(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    out = b""
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            return out
        out += chunk


def test_send_recv_fds_roundtrip():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        files = [tempfile.TemporaryFile() for _ in range(3)]
        for i, f in enumerate(files):
            f.write(_content(i))
            f.flush()
        _FT(a.fileno()).send_fds([f.fileno() for f in files])
        got = _FT(b.fileno()).recv_fds(3)
        assert len(got) == 3
        for i, fd in enumerate(got):
            assert _readall(fd) == _content(i)    # same open file the sender held
            os.close(fd)
        for f in files:
            f.close()
    finally:
        a.close()
        b.close()


def test_recv_fds_truncation_raises():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        f1, f2 = tempfile.TemporaryFile(), tempfile.TemporaryFile()
        _FT(a.fileno()).send_fds([f1.fileno(), f2.fileno()])    # send 2...
        with pytest.raises(JsonRpcError, match="truncated"):
            _FT(b.fileno()).recv_fds(1)                          # ...room for 1 -> MSG_CTRUNC
        f1.close()
        f2.close()
    finally:
        a.close()
        b.close()


def test_fd_helpers_reject_non_unix():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # not AF_UNIX
    try:
        ft = _FT(s.fileno())
        with pytest.raises(JsonRpcError, match="AF_UNIX"):
            ft.send_fds([0])
        with pytest.raises(JsonRpcError, match="AF_UNIX"):
            ft.recv_fds(1)
    finally:
        s.close()


# --- end-to-end over a live server/client ------------------------------------
class GetArgs(msgspec.Struct):
    count: int

class GetResult(msgspec.Struct):
    count: int

class PutArgs(msgspec.Struct):
    count: int

class PutResult(msgspec.Struct):
    sums: list[str]

class EchoArgs(msgspec.Struct):
    msg: str

class EchoResult(msgspec.Struct):
    msg: str


def _echo(request, session_state, request_state) -> EchoResult:
    return EchoResult(msg=request.msg)


def _get_negotiate(request, session_state):
    return {"count": request.count}              # -> client's ft.result["count"]


def _get_transfer(ft) -> GetResult:              # DOWNLOAD: server opens files, sends fds
    files = [tempfile.TemporaryFile() for _ in range(ft.params.count)]
    for i, f in enumerate(files):
        f.write(_content(i))
        f.flush()
    try:
        ft.send_fds([f.fileno() for f in files])
    finally:
        for f in files:                          # safe to close after send_fds
            f.close()
    return GetResult(count=len(files))


def _put_negotiate(request, session_state):
    return True


def _put_transfer(ft) -> PutResult:              # UPLOAD: server receives + reads the fds
    fds = ft.recv_fds(ft.params.count)
    try:
        sums = [hashlib.sha256(_readall(fd)).hexdigest() for fd in fds]
    finally:
        for fd in fds:
            os.close(fd)
    return PutResult(sums=sums)


def _build() -> JSONRPCProtocol:
    # pre_auth lets the (unauthenticated) tests drive these directly; the session setup
    # is required so the protocol may be served over a network transport.
    p = JSONRPCProtocol([
        JSONRPCMethod("echo", accepts=EchoArgs, returns=EchoResult, handler=_echo,
                      pre_auth=True),
        JSONRPCFdPassMethod("fs.get_fds", accepts=GetArgs, returns=GetResult,
                            direction=TransferDirection.DOWNLOAD,
                            negotiate=_get_negotiate, transfer=_get_transfer,
                            pre_auth=True),
        JSONRPCFdPassMethod("fs.put_fds", accepts=PutArgs, returns=PutResult,
                            direction=TransferDirection.UPLOAD,
                            negotiate=_put_negotiate, transfer=_put_transfer,
                            pre_auth=True),
    ], name="v1")
    p.add_session_setup(_auth_setup())
    return p


def test_recv_fds_download_roundtrip():
    path = _tmp_sock()
    srv = _ServerThread(_build(), unix_config=SrvUnixConfig(path=path)).start()
    try:
        c = BaseClient("v1", unix_config=UnixConfig(path=path))
        c.connect()
        result, fds = c.recv_fds("fs.get_fds", {"count": 3})   # maxfds from negotiate count
        assert result == {"count": 3}
        assert len(fds) == 3
        for i, fd in enumerate(fds):
            assert _readall(fd) == _content(i)                 # reads the server's open files
            os.close(fd)
        assert c.call("echo", {"msg": "after"}) == {"msg": "after"}   # connection resumes
        c.close()
    finally:
        srv.stop()


def test_send_fds_upload_roundtrip():
    path = _tmp_sock()
    srv = _ServerThread(_build(), unix_config=SrvUnixConfig(path=path)).start()
    try:
        c = BaseClient("v1", unix_config=UnixConfig(path=path))
        c.connect()
        files = [tempfile.TemporaryFile() for _ in range(2)]
        for i, f in enumerate(files):
            f.write(_content(i))
            f.flush()
        result = c.send_fds("fs.put_fds", {"count": 2},
                            fds=[f.fileno() for f in files])
        assert result["sums"] == [hashlib.sha256(_content(i)).hexdigest()
                                  for i in range(2)]
        for f in files:
            f.close()
        assert c.call("echo", {"msg": "after"}) == {"msg": "after"}   # connection resumes
        c.close()
    finally:
        srv.stop()


def test_server_rejects_fd_pass_over_tcp():
    # A fd-pass method driven over TCP: the server's AF_UNIX pre-check rejects it before
    # the handshake, and the (untouched) connection stays usable.
    srv = _ServerThread(_build(), tcp_config=SrvTCPConfig(host="127.0.0.1", port=0)).start()
    try:
        c = BaseClient("v1", tcp_config=TCPConfig(host="127.0.0.1", port=srv.port))
        c.connect()
        with pytest.raises(JsonRpcError) as ei:
            c.transfer("fs.get_fds", {"count": 1}, callback=lambda ft: None)
        assert ei.value.code == JSONRPCError.REQUEST_FAILED
        assert "AF_UNIX" in ei.value.data
        assert c.call("echo", {"msg": "alive"}) == {"msg": "alive"}
        c.close()
    finally:
        srv.stop()


def test_client_convenience_requires_unix():
    # The send_fds/recv_fds convenience pre-check the transport and refuse before starting
    # a transfer at all, so the connection is never wedged.
    srv = _ServerThread(_build(), tcp_config=SrvTCPConfig(host="127.0.0.1", port=0)).start()
    try:
        c = BaseClient("v1", tcp_config=TCPConfig(host="127.0.0.1", port=srv.port))
        c.connect()
        with pytest.raises(ClientError, match="AF_UNIX"):
            c.recv_fds("fs.get_fds", {"count": 1})
        with pytest.raises(ClientError, match="AF_UNIX"):
            c.send_fds("fs.put_fds", {"count": 1}, fds=[0])
        assert c.call("echo", {"msg": "ok"}) == {"msg": "ok"}   # no transfer started
        c.close()
    finally:
        srv.stop()
