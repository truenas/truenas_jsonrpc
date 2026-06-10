"""Raw-fd transfer methods — lend a handler exclusive access to the connection's
socket file descriptor for a **self-delimiting** bulk stream (e.g. libzfs
``lzc_send``/``lzc_receive`` for ``zfs send``/``recv``), then resume normal JSON-RPC.

A :class:`~truenas_pyjsonrpc.JSONRPCFdTransferMethod` runs in two steps: a
``negotiate`` callback validates the request and returns an interim "ready" result,
and — after the wire handshake — a ``transfer`` callback receives a
:class:`FileTransfer` whose core API is :meth:`FileTransfer.fileno`. The dispatch core
produces a :class:`Transfer` directive; the *server* drives the wire handshake and
provides the concrete fd (see ``truenas_pyjsonrpc_server``). The base library only
defines the contract — it never touches a socket.
"""
from __future__ import annotations

import abc
import enum
import os
import socket
from collections.abc import Callable
from typing import IO, Any

from .errors import JsonRpcError
from .types import JSONRPCError


class TransferDirection(enum.StrEnum):
    """Which way the bulk stream flows once the fd is handed over.

    ``DOWNLOAD`` — the **server produces** and the client consumes (server writes the
    stream). ``UPLOAD`` — the **client produces** and the server consumes (server
    reads the stream).
    """
    DOWNLOAD = "download"
    UPLOAD = "upload"


class FileTransfer(abc.ABC):
    """Exclusive handle to the connection's raw socket fd for one transfer.

    The handler's ``transfer`` callback receives this. :meth:`fileno` is the point of
    it — hand that fd to libzfs (``lzc_send``/``lzc_receive``), ``os.sendfile``,
    ``splice``, etc. The fd is **blocking** for the duration and is plaintext even over
    an encrypted (kTLS) connection. :meth:`sendfile`/:meth:`recvfile` are convenience
    helpers for the plain-file case. The concrete subclass (which supplies the real fd)
    lives in the server/client; this base is fd-source-agnostic.

    ``result`` is the interim value the ``negotiate`` callback returned (the
    ``$/transferReady`` payload). It is the channel for the producer to tell the
    consumer about the stream — e.g. a server ``DOWNLOAD`` can report the byte count so
    the client knows how much to read (``ft.result["size"]``).
    """

    def __init__(self, direction: TransferDirection, params: Any,
                 session_state: Any, request_state: Any = None,
                 result: Any = None) -> None:
        self.direction = direction
        self.params = params              # the decoded `accepts` struct
        self.session_state = session_state
        self.request_state = request_state
        self.result = result             # the negotiate() interim ($/transferReady) result

    @abc.abstractmethod
    def fileno(self) -> int:
        """The raw, blocking socket fd to read/write the stream on."""

    def sendfile(self, file: IO[bytes] | int, *, count: int | None = None,
                 offset: int = 0) -> int:
        """``os.sendfile`` ``count`` bytes (default: the rest of the file) from
        ``file`` (a file object or fd) to the peer; returns the number of bytes sent."""
        out_fd = self.fileno()
        in_fd = file if isinstance(file, int) else file.fileno()
        if count is None:
            count = os.fstat(in_fd).st_size - offset
        sent = 0
        while sent < count:
            n = os.sendfile(out_fd, in_fd, offset + sent, count - sent)
            if n == 0:
                break                    # peer closed
            sent += n
        return sent

    def recvfile(self, file: IO[bytes] | int, count: int) -> int:
        """Read exactly ``count`` bytes of the stream and write them to ``file`` (a
        file object or fd); returns the number received (< ``count`` if the peer
        closed early)."""
        in_fd = self.fileno()
        write: Callable[[bytes], object]
        if isinstance(file, int):
            out_fd = file
            write = lambda chunk: os.write(out_fd, chunk)   # noqa: E731
        else:
            write = file.write
        got = 0
        while got < count:
            chunk = os.read(in_fd, min(count - got, 1 << 20))
            if not chunk:
                break                    # peer closed early
            write(chunk)
            got += len(chunk)
        return got

    # --- SCM_RIGHTS file-descriptor passing (AF_UNIX only) -------------------
    def _unix_socket(self) -> socket.socket:
        """A short-lived :class:`socket.socket` over a **dup** of the connection fd, for
        ``SCM_RIGHTS`` ancillary I/O. Raises if the connection is not AF_UNIX (fd passing
        does not exist on TCP/WebSocket/TLS). The caller closes the returned socket (it
        owns the dup, not the connection fd)."""
        s = socket.socket(fileno=os.dup(self.fileno()))
        if s.family != socket.AF_UNIX:
            s.close()
            raise JsonRpcError(JSONRPCError.REQUEST_FAILED,
                               "fd passing requires an AF_UNIX connection")
        return s

    def send_fds(self, fds: list[int], *, close: bool = False) -> None:
        """Pass open file descriptors to the peer via ``SCM_RIGHTS`` (AF_UNIX only): the
        peer receives **new** fds referring to the same open files. One sentinel byte
        carries the ancillary data. With ``close=True`` this side's ``fds`` are closed
        after sending. Raises :class:`~truenas_pyjsonrpc.JsonRpcError` if the connection
        is not AF_UNIX."""
        s = self._unix_socket()
        try:
            socket.send_fds(s, [b"\x00"], fds)
        finally:
            s.close()
        if close:
            for fd in fds:
                os.close(fd)

    def recv_fds(self, maxfds: int) -> list[int]:
        """Receive up to ``maxfds`` file descriptors the peer passed via ``SCM_RIGHTS``
        (AF_UNIX only); returns the new fds, which **the caller owns and must close**.
        Raises :class:`~truenas_pyjsonrpc.JsonRpcError` if the ancillary data was
        truncated (the peer sent more than ``maxfds`` — the excess are dropped by the
        kernel) or the connection is not AF_UNIX."""
        s = self._unix_socket()
        try:
            _data, fds, flags, _addr = socket.recv_fds(s, 1, maxfds)
        finally:
            s.close()
        if flags & socket.MSG_CTRUNC:
            for fd in fds:
                os.close(fd)
            raise JsonRpcError(JSONRPCError.REQUEST_FAILED,
                               "received file descriptors were truncated "
                               "(maxfds too small)")
        return fds


class Transfer:
    """Directive returned by :meth:`JSONRPCProtocol.dispatch` for a transfer method.

    The server sends :attr:`ready` (the ``$/transferReady`` envelope), runs the wire
    handshake for :attr:`direction`, builds a concrete :class:`FileTransfer` (from
    :attr:`params` / :attr:`session_state` plus the connection's fd), then calls
    :meth:`complete` with it. :meth:`complete` runs the ``transfer`` callback (in the
    server's executor — it blocks), validates the result against the method's
    ``returns``, audits, and returns the final response envelope to send.
    """

    __slots__ = ("rid", "direction", "params", "session_state", "ready", "af_unix",
                 "_run")

    def __init__(self, *, rid: str, direction: TransferDirection,
                 params: Any, session_state: Any, ready: dict[str, Any],
                 run: Callable[[FileTransfer], dict[str, Any]],
                 af_unix: bool = False) -> None:
        self.rid = rid
        self.direction = direction
        self.params = params              # the decoded `accepts` struct
        self.session_state = session_state
        self.ready = ready               # the $/transferReady envelope dict
        self.af_unix = af_unix           # fd-pass method -> require an AF_UNIX connection
        self._run = run

    def complete(self, file_transfer: FileTransfer) -> dict[str, Any]:
        return self._run(file_transfer)
