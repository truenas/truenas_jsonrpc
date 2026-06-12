"""Per-connection handling: the AWAIT_NEGOTIATE -> BOUND -> CLOSED state machine,
``$/negotiate``, and the asyncio<->thread dispatch bridge.

The reader **pipelines**: each inbound frame's (synchronous, possibly-blocking)
``protocol.dispatch`` is submitted to the server's executor and the read loop
continues, so a ``$/cancelRequest`` can be processed while a long handler runs.
Outbound bytes (dispatch replies, plus ``$/progress`` / pub-sub notifications routed
in from the server's drain thread) flow through one per-connection queue drained by a
writer task, so backpressure is awaited on the event loop.
"""
from __future__ import annotations

import asyncio
import contextlib
import enum
import os
from typing import TYPE_CHECKING, Any

import msgspec
from msgspec import Raw

from truenas_pyjsonrpc import (
    FileTransfer,
    JSONRPCEnvelope,
    JSONRPCError,
    JSONRPCProtocol,
    SessionState,
    Transfer,
    TransferDirection,
)

from .channel import MessageChannel
from .framing import FrameTooLarge
from .negotiate import NEGOTIATE_METHOD, NegotiateParams, NegotiateResult

if TYPE_CHECKING:
    from .server import JSONRPCServer

_VERSION = "2.0"
_TRANSFER_GO_METHOD = "$/transferGo"   # client -> server: consumer paused, start (download)


# Permissive envelope peek used only during negotiation (fields validated in code).
_ENV_DEC = msgspec.json.Decoder(JSONRPCEnvelope)
_NEG_DEC = msgspec.json.Decoder(NegotiateParams)
_ENC = msgspec.json.Encoder()


class _FileTransfer(FileTransfer):
    """Concrete :class:`~truenas_pyjsonrpc.FileTransfer` over the connection's real
    socket fd (plaintext — plain or kTLS)."""

    def __init__(self, direction: TransferDirection, params: Any,
                 session_state: Any, fd: int, result: Any = None) -> None:
        super().__init__(direction, params, session_state, result=result)
        self._fd = fd

    def fileno(self) -> int:
        return self._fd


class _State(enum.Enum):
    AWAIT_NEGOTIATE = enum.auto()
    BOUND = enum.auto()
    CLOSED = enum.auto()


def _error(rid: str | None, code: "int | JSONRPCError", message: str,
           data: Any = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": int(code), "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": _VERSION, "error": err, "id": rid}


class Connection:
    """One client connection."""

    def __init__(self, server: "JSONRPCServer", channel: MessageChannel) -> None:
        self._server = server
        self._channel = channel
        self._peer = channel.peer
        self._loop = asyncio.get_running_loop()
        self._state = _State.AWAIT_NEGOTIATE
        self._protocol: JSONRPCProtocol | None = None
        self._session: SessionState | None = None
        self._outbound: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._inflight: set[asyncio.Future[Any]] = set()
        self._writer_task: asyncio.Task[None] | None = None
        # Raw-fd transfer state: a gate the writer waits on (cleared during a
        # transfer so notifications don't interleave the raw stream), and a future
        # the read loop fulfils with the next frame (the $/transferGo) when set.
        self._writer_gate = asyncio.Event()
        self._writer_gate.set()
        self._await_frame: asyncio.Future[bytes] | None = None

    async def serve(self) -> None:
        self._writer_task = self._loop.create_task(self._drain_outbound())
        try:
            while True:
                try:
                    msg = await self._channel.recv()
                except FrameTooLarge as e:
                    self._send(_error(None, JSONRPCError.INVALID_REQUEST,
                                      "Message too large", str(e)))
                    break
                if msg is None:                      # EOF
                    break
                if self._await_frame is not None and not self._await_frame.done():
                    fut, self._await_frame = self._await_frame, None
                    fut.set_result(msg)              # mid-transfer: hand over $/transferGo
                elif self._state is _State.AWAIT_NEGOTIATE:
                    self._handle_negotiate(msg)
                else:
                    self._dispatch(msg)
        finally:
            await self._close()

    # --- BOUND: bridge dispatch onto the executor ----------------------------
    def _dispatch(self, msg: bytes) -> None:
        assert self._protocol is not None and self._session is not None
        fut = self._loop.run_in_executor(
            self._server._executor, self._protocol.dispatch, msg, self._session)
        self._inflight.add(fut)
        fut.add_done_callback(self._on_dispatch_done)

    def _on_dispatch_done(self, fut: asyncio.Future[Any]) -> None:
        self._inflight.discard(fut)
        try:
            reply = fut.result()
        except Exception:
            return                                   # dispatch never raises; ignore
        if isinstance(reply, Transfer):
            self._loop.create_task(self._run_transfer(reply))
        elif reply is not None:
            self._send(reply)

    # --- AWAIT_NEGOTIATE -----------------------------------------------------
    def _handle_negotiate(self, msg: bytes) -> None:
        try:
            env = _ENV_DEC.decode(msg)
        except msgspec.DecodeError as e:
            self._send(_error(None, JSONRPCError.INVALID_JSON, "Parse error", str(e)))
            return
        rid = env.id if isinstance(env.id, str) else None
        if env.method != NEGOTIATE_METHOD:
            self._send(_error(rid, JSONRPCError.SESSION_NOT_ESTABLISHED,
                              "negotiate a protocol first"))
            return
        if env.jsonrpc != _VERSION or not isinstance(env.id, str):
            self._send(_error(rid, JSONRPCError.INVALID_REQUEST, "Invalid request",
                              "$/negotiate needs jsonrpc '2.0' and a string id"))
            return
        raw = env.params if isinstance(env.params, Raw) else Raw(b"{}")
        try:
            params = _NEG_DEC.decode(raw)
        except (msgspec.ValidationError, msgspec.DecodeError) as e:
            self._send(_error(rid, JSONRPCError.INVALID_PARAMS, "Invalid params",
                              str(e)))
            return
        protocol = self._server._protocols.get(params.protocol)
        if protocol is None:
            self._send(_error(rid, JSONRPCError.REQUEST_FAILED, "Request failed",
                              {"reason": "unknown protocol",
                               "available": self._server.protocol_names}))
            return
        self._protocol = protocol
        self._session = protocol.new_session(server_state=self._peer)
        self._server._register(self._session.session_uuid, self)
        self._state = _State.BOUND
        result = NegotiateResult(protocol=params.protocol, server=self._server.name,
                                 available=self._server.protocol_names)
        self._send({"jsonrpc": _VERSION, "result": msgspec.to_builtins(result),
                    "id": rid})

    # --- outbound ------------------------------------------------------------
    def _send(self, message: Any) -> None:
        """Queue an outbound message (a dict envelope, or already-encoded bytes)."""
        data = message if isinstance(message, (bytes, bytearray)) else _ENC.encode(message)
        self._outbound.put_nowait(bytes(data))

    def enqueue_outbound(self, data: bytes) -> None:
        """Queue raw encoded bytes — called from the server's drain thread via
        ``loop.call_soon_threadsafe`` (so it runs on the event loop)."""
        if self._state is not _State.CLOSED:
            self._outbound.put_nowait(data)

    async def _drain_outbound(self) -> None:
        try:
            while True:
                data = await self._outbound.get()
                if data is None:                     # stop sentinel
                    break
                await self._writer_gate.wait()       # held closed during a raw transfer
                await self._channel.send(data)
        except (ConnectionError, asyncio.CancelledError):
            pass

    # --- raw-fd transfer takeover --------------------------------------------
    async def _write_frame_now(self, message: Any) -> None:
        """Write one framed message directly (bypassing the gated queue) — used during
        a transfer for ``$/transferReady`` and the final response."""
        data = message if isinstance(message, (bytes, bytearray)) else _ENC.encode(message)
        await self._channel.send(bytes(data))

    async def _run_transfer(self, transfer: Transfer) -> None:
        """Take over the connection for a raw-fd transfer: run the no-buffering
        handshake, hand the plaintext fd to the handler's ``transfer`` callback (in the
        executor), then resume normal JSON-RPC and send the final response.

        A transfer needs a *plaintext* fd; the channel returns ``None`` for a userspace
        memory-BIO TLS connection (ciphertext on the fd) or a WebSocket connection (the
        ``websockets`` library owns the wire) -> reject."""
        # fd passing (SCM_RIGHTS) is AF_UNIX-only — reject before the handshake.
        if transfer.af_unix and (self._peer is None or self._peer.transport != "unix"):
            self._send(_error(transfer.rid, JSONRPCError.REQUEST_FAILED, "Request failed",
                              "fd passing requires an AF_UNIX connection"))
            return
        target = self._channel.transfer_target()
        if target is None:
            self._send(_error(transfer.rid, JSONRPCError.REQUEST_FAILED, "Request failed",
                              "raw-fd transfer requires a plain or kTLS connection"))
            return
        transport, fd = target.transport, target.fileno
        self._writer_gate.clear()                    # no notifications during raw I/O
        try:
            # The consumer pauses its reader before the producer streams, so no stream
            # byte is buffered by asyncio where the fd-owning callback can't reach it.
            if transfer.direction is TransferDirection.UPLOAD:   # server consumes
                transport.pause_reading()
                await self._write_frame_now(transfer.ready)
            else:                                                # DOWNLOAD: server produces
                self._await_frame = self._loop.create_future()
                await self._write_frame_now(transfer.ready)
                go = await self._await_frame                      # client paused, then $/transferGo
                if _ENV_DEC.decode(go).method != _TRANSFER_GO_METHOD:
                    raise ConnectionError("expected $/transferGo")
                transport.pause_reading()
            os.set_blocking(fd, True)
            ft = _FileTransfer(transfer.direction, transfer.params,
                               transfer.session_state, fd,
                               transfer.ready["params"]["result"])
            final = await self._loop.run_in_executor(
                self._server._executor, transfer.complete, ft)
        except Exception:
            self._await_frame = None
            with contextlib.suppress(Exception):
                os.set_blocking(fd, False)
                transport.resume_reading()
            self._writer_gate.set()
            return                                   # connection likely broken; serve() closes it
        os.set_blocking(fd, False)
        transport.resume_reading()
        self._writer_gate.set()
        self._send(final)

    async def _close(self) -> None:
        self._state = _State.CLOSED
        self._writer_gate.set()                      # release the writer if a transfer gated it
        if self._await_frame is not None and not self._await_frame.done():
            self._await_frame.cancel()               # unblock a transfer awaiting $/transferGo
        for fut in list(self._inflight):
            fut.cancel()                             # detach; the executor thread finishes on its own
        if self._session is not None and self._protocol is not None:
            self._server._unregister(self._session.session_uuid)
            self._protocol.close_session(self._session)
        self._outbound.put_nowait(None)              # stop the writer task
        if self._writer_task is not None:
            try:
                await self._writer_task
            except Exception:
                pass
        await self._channel.aclose()
