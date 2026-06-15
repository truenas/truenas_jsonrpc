"""``BaseClient`` — a thread-safe client over the length-prefixed JSON-RPC server.

The connection runs on a dedicated asyncio event loop in a background thread; the
public API is **synchronous and thread-safe** — many application threads may
``call()`` concurrently once the session is established. Requests correlate to
responses by their UUID id (a per-request future).

Server->client notifications are routed three ways: a ``$/progress`` message goes to
the originating ``call(..., progress=cb)`` callback (correlated by request id); a
pub/sub topic message goes to that topic's ``subscribe(topic, callback=cb)``
callback(s); anything unrouted falls back to the global ``on_notification`` callback
or the thread-safe :attr:`notifications` queue. **Callbacks run on a dedicated
backchannel thread** (not the IO thread), so a callback may block and may safely call
:meth:`call` / :meth:`subscribe` / :meth:`unsubscribe`. Delivery is ordered (single
thread), so a slow callback delays later ones — hand heavy work off if that matters.
(A per-call ``progress`` callback is therefore decoupled from the call: it may fire
shortly after :meth:`call` returns.)

Connect flow: ``connect()`` (`$/negotiate`) -> ``setup(...)`` (`$/sessionSetup`,
+ ``setup_continue`` for multi-step) -> ``call(...)`` / ``subscribe(...)``.
``close()`` sends ``$/sessionClose`` and tears the loop down.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import functools
import logging
import os
import queue
import socket
import ssl
import threading
import uuid
from collections.abc import Callable
from typing import Any, TypeVar, overload

import msgspec

from truenas_pyjsonrpc import FileTransfer, JsonRpcError, TransferDirection

from .channel import ClientChannel, StreamClientChannel
from .config import TCPConfig, UnixConfig, WebSocketConfig

_VERSION = "2.0"
_PROGRESS_METHOD = "$/progress"
_CANCEL_METHOD = "$/cancelRequest"
_TRANSFER_READY_METHOD = "$/transferReady"
_TRANSFER_GO_METHOD = "$/transferGo"
_ENC = msgspec.json.Encoder()
_MAX_FRAME = 4 * 1024 * 1024            # inbound length-prefix limit / open_connection buffer
_DEFAULT_TIMEOUT: Any = object()        # sentinel: "use the client's call_timeout"
_T = TypeVar("_T", bound=msgspec.Struct)
_log = logging.getLogger(__name__)


class ClientError(Exception):
    """A client-side transport/protocol error (distinct from a server
    :class:`~truenas_pyjsonrpc.JsonRpcError`)."""


# Linux kTLS confirmation probe — see truenas_pyjsonrpc_server._ktls.confirm_ktls_engaged.
# OP_ENABLE_KTLS is best-effort and ``ssl`` exposes no status query, so confirm kTLS attached
# by asking the kernel. SOL_TLS=282 (linux/socket.h), TLS_TX=1 / TLS_RX=2 (uapi/linux/tls.h);
# a 4-byte buffer is sizeof(struct tls_crypto_info).
_SOL_TLS, _TLS_TX, _TLS_RX, _TLS_CRYPTO_INFO_SIZE = 282, 1, 2, 4


def _confirm_ktls_engaged(sock: socket.socket) -> None:
    """Raise ``OSError`` unless kernel TLS crypto is installed for both TX and RX on ``sock``;
    a detached fd whose kTLS didn't engage would leak plaintext (TX) / read ciphertext (RX)."""
    for direction, label in ((_TLS_TX, "TX"), (_TLS_RX, "RX")):
        try:
            sock.getsockopt(_SOL_TLS, direction, _TLS_CRYPTO_INFO_SIZE)
        except OSError as e:
            raise OSError(
                f"kTLS did not engage for {label}; refusing to fall back to userspace TLS "
                "(is the kernel 'tls' module loaded and OpenSSL built with kTLS?)") from e


def _ktls_connect(ctx: ssl.SSLContext, host: str, port: int,
                  server_hostname: str | None) -> tuple[int, int]:
    """Blocking connect + TLS handshake with kTLS; returns ``(plaintext_fd, family)``
    (the kernel does the record crypto on the fd). Run in an executor."""
    raw = socket.create_connection((host, port))
    family = raw.family
    raw.setblocking(True)
    ss = ctx.wrap_socket(raw, server_hostname=server_hostname)
    try:
        cipher = ss.cipher()
        name = (cipher[0] if cipher else "") or ""
        if "GCM" not in name and "CHACHA20" not in name:
            raise OSError(f"kTLS requires an AES-GCM/ChaCha20 cipher; got {name!r}")
        _confirm_ktls_engaged(ss)     # positively confirm kTLS attached, both directions
    except BaseException:
        ss.close()
        raise
    return ss.detach(), family


class _FileTransfer(FileTransfer):
    """Concrete :class:`~truenas_pyjsonrpc.FileTransfer` over the client's socket fd."""

    def __init__(self, direction: TransferDirection, params: Any, fd: int,
                 result: Any = None) -> None:
        super().__init__(direction, params, session_state=None,  # client side: no session
                         result=result)
        self._fd = fd

    def fileno(self) -> int:
        return self._fd


class BaseClient:
    """Connect to a single server transport (AF_UNIX, TCP, or WebSocket) and call its
    methods.

    ``protocol`` is the name to ``$/negotiate``. Provide exactly one of
    :class:`UnixConfig` (``unix_config``), :class:`TCPConfig` (``tcp_config``), or
    :class:`WebSocketConfig` (``websocket_config``). ``on_notification(method, params)``
    (optional, invoked on the backchannel thread) is the **fallback** sink for
    server->client messages that aren't routed to a :meth:`subscribe` or per-call
    ``progress`` callback; without it, they accumulate on the thread-safe
    :attr:`notifications` queue.

    TLS is configured per transport via the ``ssl`` field of ``TCPConfig`` /
    ``WebSocketConfig`` (with ``server_hostname`` to override the certificate name).
    ``name`` (default: the ``protocol`` name) labels this client's threads — handy when
    one process holds several clients. A raw-fd :meth:`transfer` requires a plain or
    kTLS connection and is rejected over WebSocket.
    """

    def __init__(self, protocol: str, *,
                 unix_config: UnixConfig | None = None,
                 tcp_config: TCPConfig | None = None,
                 websocket_config: WebSocketConfig | None = None,
                 name: str | None = None,
                 on_notification: Callable[[str, Any], None] | None = None,
                 connect_timeout: float = 10.0,
                 call_timeout: float | None = 30.0) -> None:
        provided = [c for c in (unix_config, tcp_config, websocket_config)
                    if c is not None]
        if len(provided) != 1:
            raise ValueError("provide exactly one transport config: "
                             "unix_config, tcp_config, or websocket_config")
        self._protocol = protocol
        self._name = name or protocol
        self._unix_config = unix_config
        self._tcp_config = tcp_config
        self._websocket_config = websocket_config
        self._on_notification = on_notification
        self._connect_timeout = connect_timeout
        self._call_timeout = call_timeout
        self.notifications: "queue.Queue[tuple[str, Any]]" = queue.Queue()
        self.negotiation: dict[str, Any] | None = None

        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever,
            name=f"jsonrpc-client[{self._name}]", daemon=True)
        # User callbacks run on this dedicated thread (off the IO loop), so they may
        # block / re-enter call(). A None sentinel stops it.
        self._backchannel_q: "queue.Queue[Callable[[], None] | None]" = queue.Queue()
        self._backchannel_thread = threading.Thread(
            target=self._run_backchannel,
            name=f"jsonrpc-client[{self._name}]-backchannel", daemon=True)
        self._channel: ClientChannel | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._pending: dict[str, asyncio.Future[Any]] = {}
        # Callback registries — all read/written only on the loop thread.
        self._sub_callbacks: dict[str, list[Callable[[Any], None]]] = {}   # topic -> cbs
        self._sub_ids: dict[str, tuple[str, Callable[[Any], None]]] = {}   # sub_id -> (topic, cb)
        self._progress_callbacks: dict[str, Callable[[Any], None]] = {}    # req id -> cb
        self._transfer_ready: dict[str, asyncio.Future[Any]] = {}          # req id -> ready fut
        self._in_transfer = False        # a raw-fd transfer monopolizes the connection
        self._closed = False

    @property
    def name(self) -> str:
        """This client's label (used in its thread names)."""
        return self._name

    # --- public, synchronous, thread-safe ------------------------------------
    def connect(self) -> dict[str, Any]:
        """Start the background loop, connect, and ``$/negotiate`` the protocol.
        Returns the negotiation result (also stored as :attr:`negotiation`)."""
        if not self._thread.is_alive():
            self._thread.start()
        if not self._backchannel_thread.is_alive():
            self._backchannel_thread.start()
        cf = asyncio.run_coroutine_threadsafe(self._connect(), self._loop)
        self.negotiation = cf.result(self._connect_timeout)
        return self.negotiation

    def setup(self, params: Any = None) -> Any:
        """Authenticate via ``$/sessionSetup``; returns the setup result."""
        return self.call("$/sessionSetup", params)

    def setup_continue(self, params: Any = None) -> Any:
        """Continue multi-step setup via ``$/sessionSetupContinue``."""
        return self.call("$/sessionSetupContinue", params)

    def _settle(self, cf: concurrent.futures.Future[Any],
                timeout: float | None) -> Any:
        """Block on the loop coroutine ``cf`` up to ``timeout`` and return its result. On a
        *wait* timeout, cancel it — cancellation propagates to the asyncio task, so the
        coroutine's cleanup ``finally`` runs and releases its per-request state (pending
        future, progress callback) instead of leaking it — then raise :class:`ClientError`.
        ``asyncio.run_coroutine_threadsafe`` does *not* cancel the coroutine when
        ``Future.result(timeout)`` times out, so without this the entry leaks."""
        try:
            return cf.result(timeout)
        except TimeoutError:
            if cf.done():            # the coroutine itself raised TimeoutError -> surface it
                raise
            cf.cancel()              # -> task.cancel() on the loop; its finally cleans up
            raise ClientError("operation timed out") from None

    def call(self, method: str, params: Any = None,
             timeout: Any = _DEFAULT_TIMEOUT, *,
             progress: Callable[[Any], None] | None = None) -> Any:
        """Issue a request and return its result; raises
        :class:`~truenas_pyjsonrpc.JsonRpcError` on an error response. Thread-safe;
        callable from any thread, **including** a callback (which runs on the
        backchannel thread, not the IO loop thread).

        ``progress`` receives this call's ``$/progress`` notifications (the params
        dict ``{id, percent?, description?, extra?}``) on the backchannel thread; being
        async, a final progress message may arrive shortly after this returns."""
        if self._closed:
            raise ClientError("client is closed")
        if self._in_transfer:
            raise ClientError("a raw-fd transfer is in progress on this connection")
        t = self._call_timeout if timeout is _DEFAULT_TIMEOUT else timeout
        cf = asyncio.run_coroutine_threadsafe(
            self._invoke(method, params, progress), self._loop)
        return self._settle(cf, t)

    def transfer(self, method: str, params: Any = None, *,
                 callback: Callable[[FileTransfer], object],
                 timeout: float | None = None) -> Any:
        """Run a raw-fd transfer method (e.g. zfs send/recv). Sends the request, does
        the ``$/transferReady`` handshake, then calls ``callback(file_transfer)`` **on
        the calling thread** with exclusive access to the connection's plaintext socket
        fd (``file_transfer.fileno()`` — hand it to libzfs etc.); returns the server's
        final result. Monopolizes the connection (no concurrent ``call()``). Requires a
        plain or kTLS connection."""
        if self._closed:
            raise ClientError("client is closed")
        if self._in_transfer:
            raise ClientError("a raw-fd transfer is already in progress")
        self._in_transfer = True
        try:
            prep = asyncio.run_coroutine_threadsafe(
                self._transfer_prep(method, params), self._loop)
            rid, direction, fd, final, result = self._settle(prep, self._connect_timeout)
            try:
                callback(_FileTransfer(direction, params, fd, result))   # blocking, caller thread
            except BaseException:
                # A transfer callback that fails mid-stream leaves the wire in an
                # indeterminate state; tear the connection down cleanly rather than
                # leave its reader paused (wedged).
                self._closed = True
                with contextlib.suppress(Exception):
                    asyncio.run_coroutine_threadsafe(
                        self._teardown(), self._loop).result(5)
                raise
            finish = asyncio.run_coroutine_threadsafe(
                self._transfer_finish(rid, fd, final), self._loop)
            return self._settle(finish, timeout)
        finally:
            self._in_transfer = False

    def send_fds(self, method: str, params: Any = None, *,
                 fds: list[int],
                 timeout: float | None = None) -> Any:
        """Pass open file descriptors to the server via ``SCM_RIGHTS`` (AF_UNIX only) for
        an ``UPLOAD`` :class:`~truenas_pyjsonrpc.JSONRPCFdPassMethod`; returns the server's
        result. The server receives **new** fds referring to the same open files. Requires
        an AF_UNIX connection (raises :class:`ClientError` otherwise)."""
        if self._unix_config is None:
            raise ClientError("fd passing requires an AF_UNIX connection")
        return self.transfer(method, params,
                             callback=lambda ft: ft.send_fds(list(fds)), timeout=timeout)

    def recv_fds(self, method: str, params: Any = None, *,
                 maxfds: int | None = None,
                 timeout: float | None = None) -> tuple[Any, list[int]]:
        """Receive file descriptors the server passes via ``SCM_RIGHTS`` (AF_UNIX only)
        from a ``DOWNLOAD`` :class:`~truenas_pyjsonrpc.JSONRPCFdPassMethod`; returns
        ``(result, fds)``. The caller **owns** the returned fds and must close them.
        ``maxfds`` defaults to the ``count`` the server's negotiate reported (its interim
        result, e.g. ``{"count": n}``); pass it to override/cap. Requires an AF_UNIX
        connection (raises :class:`ClientError` otherwise)."""
        if self._unix_config is None:
            raise ClientError("fd passing requires an AF_UNIX connection")
        received: list[int] = []

        def cb(ft: FileTransfer) -> None:
            n = maxfds
            if n is None:
                result = ft.result
                if isinstance(result, dict) and isinstance(result.get("count"), int):
                    n = result["count"]
                else:
                    raise ClientError("recv_fds needs maxfds (the server's negotiate "
                                      "result has no integer 'count')")
            received.extend(ft.recv_fds(n))

        result = self.transfer(method, params, callback=cb, timeout=timeout)
        return result, received

    def subscribe(self, topic: str, params: Any = None, *,
                  callback: Callable[[Any], None] | None = None) -> str:
        """Subscribe to a server pub/sub ``topic`` and return the subscription id.

        ``callback`` (invoked on the backchannel thread — it may call :meth:`call`)
        receives each published payload. Without a callback the topic's messages fall
        through to ``on_notification`` / :attr:`notifications`. ``params`` are the raw
        subscribe-request params (a dict, or ``None``)."""
        if self._closed:
            raise ClientError("client is closed")
        cf = asyncio.run_coroutine_threadsafe(
            self._do_subscribe(topic, params, callback), self._loop)
        return str(self._settle(cf, self._call_timeout))

    def unsubscribe(self, sub_id: str) -> None:
        """Cancel a subscription: send ``$/cancelRequest`` so the **server** drops it
        (no more events for this connection), and remove the local callback. Safe to
        call from a callback. Best-effort — the local callback is removed even if the
        server rejects the cancel."""
        if self._closed:
            return
        try:
            self.call(_CANCEL_METHOD, {"target_id": sub_id})
        finally:
            self._loop.call_soon_threadsafe(self._remove_sub, sub_id)

    @overload
    def _typed_call(self, method: str, params: Any, returns: type[_T], *,
                    progress: Callable[[Any], None] | None = ...) -> _T: ...
    @overload
    def _typed_call(self, method: str, params: Any, returns: None, *,
                    progress: Callable[[Any], None] | None = ...) -> Any: ...

    def _typed_call(self, method: str, params: Any, returns: Any, *,
                    progress: Callable[[Any], None] | None = None) -> Any:
        """Used by generated clients: encode a Struct as ``params`` and decode the
        result into ``returns`` (a ``msgspec.Struct`` type, or ``None`` to return
        the raw result). ``progress`` receives this call's ``$/progress`` params."""
        raw = self.call(method,
                        msgspec.to_builtins(params) if params is not None else None,
                        progress=progress)
        return msgspec.convert(raw, returns) if returns is not None else raw

    def _typed_transfer(self, method: str, request: Any, returns: type[_T],
                        callback: Callable[[FileTransfer], object]) -> _T:
        """Used by generated clients: encode a Struct as the transfer request, run the
        transfer (``callback`` gets the fd), and decode the final result."""
        raw = self.transfer(method, msgspec.to_builtins(request), callback=callback)
        return msgspec.convert(raw, returns)

    def _typed_filterable(self, method: str, request: Any, query_filters: Any,
                          query_options: Any, entry: type[_T]) -> Any:
        """Used by generated clients for a filterable (query) method: merge the request
        Struct with the ``query-filters``/``query-options`` onto the wire, call, and
        decode the result into ``list[entry] | entry | int`` (a single ``entry`` for
        ``query-options.get``, an ``int`` for ``query-options.count``). The generated
        method carries the precise return annotation."""
        params: dict[str, Any] = (
            msgspec.to_builtins(request) if request is not None else {})
        params["query-filters"] = query_filters if query_filters is not None else []
        params["query-options"] = (
            msgspec.to_builtins(query_options) if query_options is not None else {})
        raw = self.call(method, params)
        # `entry` is a runtime class (type[_T]); the decode union is built from it
        # dynamically, which mypy can't treat as a static type subscription.
        return msgspec.convert(raw, list[entry] | entry | int)  # type: ignore[valid-type]

    def _subscribe(self, topic: str, request: Any, *,
                   callback: Callable[[Any], None] | None = None,
                   notifies: type | None = None) -> str:
        """Used by generated clients: subscribe to a SERVER_CLIENT topic (encode the
        subscribe-request Struct as params) and return the subscription id. When
        ``callback`` and ``notifies`` are given, each published payload is decoded
        into the ``notifies`` Struct before the callback is invoked."""
        if self._closed:
            raise ClientError("client is closed")
        cb: Callable[[Any], None] | None
        if callback is not None and notifies is not None:
            decode, inner = notifies, callback     # bind narrowed types for the closure

            def cb(params: Any) -> None:
                inner(msgspec.convert(params, decode))
        else:
            cb = callback
        cf = asyncio.run_coroutine_threadsafe(
            self._do_subscribe(topic, msgspec.to_builtins(request), cb), self._loop)
        return str(self._settle(cf, self._call_timeout))

    def close(self) -> None:
        """Best-effort ``$/sessionClose``, then tear down the connection + loop."""
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            asyncio.run_coroutine_threadsafe(
                self._invoke("$/sessionClose", None), self._loop).result(5)
        with contextlib.suppress(Exception):
            asyncio.run_coroutine_threadsafe(self._teardown(), self._loop).result(5)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
        with contextlib.suppress(Exception):
            self._loop.close()
        self._backchannel_q.put(None)                    # stop the backchannel thread
        self._backchannel_thread.join(timeout=5)

    def __enter__(self) -> "BaseClient":
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- on the loop ---------------------------------------------------------
    async def _connect(self) -> dict[str, Any]:
        if self._websocket_config is not None:
            self._channel = await self._connect_websocket(self._websocket_config)
        elif self._tcp_config is not None:
            tcfg = self._tcp_config
            ctx = tcfg.ssl
            if ctx is not None and ctx.options & ssl.OP_ENABLE_KTLS:
                # kTLS: handshake on the real fd (in the executor), then run asyncio over
                # the now-plaintext fd as a plain transport (so raw-fd transfers work).
                fd, family = await self._loop.run_in_executor(
                    None, functools.partial(_ktls_connect, ctx, tcfg.host, tcfg.port,
                                            tcfg.server_hostname or tcfg.host))
                plain = socket.socket(family, socket.SOCK_STREAM, fileno=fd)
                plain.setblocking(False)
                reader, writer = await asyncio.open_connection(
                    sock=plain, limit=_MAX_FRAME)
            else:
                # `server_hostname` is only valid with TLS; coalesce a falsy value (e.g.
                # an explicit "") to the connect host so it can't silently disable
                # certificate hostname verification (mirrors the kTLS path above).
                sni = (tcfg.server_hostname or tcfg.host) if ctx is not None else None
                reader, writer = await asyncio.open_connection(
                    tcfg.host, tcfg.port, limit=_MAX_FRAME, ssl=ctx,
                    server_hostname=sni)
            self._channel = StreamClientChannel(reader, writer, _MAX_FRAME)
        else:
            assert self._unix_config is not None
            reader, writer = await asyncio.open_unix_connection(
                self._unix_config.path, limit=_MAX_FRAME)
            self._channel = StreamClientChannel(reader, writer, _MAX_FRAME)
        self._reader_task = self._loop.create_task(self._read_loop())
        result: dict[str, Any] = await self._invoke(
            "$/negotiate", {"protocol": self._protocol})
        return result

    async def _connect_websocket(self, cfg: WebSocketConfig) -> ClientChannel:
        try:
            from .ws_channel import WebSocketClientChannel, ws_connect
        except ImportError as e:                          # optional dependency missing
            raise ClientError(
                "WebSocket transport requires the 'websockets' package. "
                "Install it with: pip install truenas_pyjsonrpc[websocket]") from e
        scheme = "wss" if cfg.ssl is not None else "ws"
        uri = f"{scheme}://{cfg.host}:{cfg.port}"
        kwargs: dict[str, Any] = {
            "max_size": cfg.max_size, "ping_interval": cfg.ping_interval,
            "ping_timeout": cfg.ping_timeout, "compression": cfg.compression}
        if cfg.ssl is not None:
            kwargs["ssl"] = cfg.ssl
            if cfg.server_hostname:        # falsy (e.g. "") -> let the library use the URI host
                kwargs["server_hostname"] = cfg.server_hostname
        kwargs.update(cfg.extra_options or {})
        ws = await ws_connect(uri, **kwargs)
        return WebSocketClientChannel(ws)

    async def _invoke(self, method: str, params: Any,
                      progress: Callable[[Any], None] | None = None) -> Any:
        rid = str(uuid.uuid4())
        fut: asyncio.Future[Any] = self._loop.create_future()
        self._pending[rid] = fut
        if progress is not None:
            self._progress_callbacks[rid] = progress
        msg: dict[str, Any] = {"jsonrpc": _VERSION, "method": method, "id": rid}
        if params is not None:
            msg["params"] = params
        try:
            if self._channel is None:
                raise ClientError("not connected")
            await self._channel.send(_ENC.encode(msg))
            return await fut
        finally:
            self._pending.pop(rid, None)
            self._progress_callbacks.pop(rid, None)

    async def _do_subscribe(self, topic: str, params: Any,
                            cb: Callable[[Any], None] | None) -> Any:
        # Register the callback BEFORE sending the subscribe, so an event published
        # right after the ack can't arrive before the callback is in place.
        if cb is not None:
            self._sub_callbacks.setdefault(topic, []).append(cb)
        try:
            sub_id = await self._invoke(topic, params)
        except BaseException:
            if cb is not None:
                self._drop_cb(topic, cb)
            raise
        if cb is not None and isinstance(sub_id, str):
            self._sub_ids[sub_id] = (topic, cb)
        return sub_id

    def _drop_cb(self, topic: str, cb: Callable[[Any], None]) -> None:
        cbs = self._sub_callbacks.get(topic)
        if cbs is not None and cb in cbs:
            cbs.remove(cb)
            if not cbs:
                del self._sub_callbacks[topic]

    def _remove_sub(self, sub_id: str) -> None:
        entry = self._sub_ids.pop(sub_id, None)
        if entry is not None:
            self._drop_cb(*entry)

    # --- raw-fd transfer (on the loop) ---------------------------------------
    async def _transfer_prep(self, method: str,
                             params: Any) -> tuple[str, TransferDirection, int,
                                                   asyncio.Future[Any], Any]:
        """Send the request, await ``$/transferReady``, run the consumer/producer
        handshake, and hand back the raw (blocking) fd, the final-response future, and
        the negotiated interim result (the ``$/transferReady`` payload). Raises
        :class:`ClientError` when the connection can't host a raw-fd transfer (WebSocket
        or userspace TLS)."""
        if self._channel is None:
            raise ClientError("not connected")
        target = self._channel.transfer_target()
        if target is None:
            raise ClientError("raw-fd transfer requires a plain or kTLS connection")
        rid = str(uuid.uuid4())
        final_fut: asyncio.Future[Any] = self._loop.create_future()
        self._pending[rid] = final_fut
        ready_fut: asyncio.Future[Any] = self._loop.create_future()
        self._transfer_ready[rid] = ready_fut
        msg: dict[str, Any] = {"jsonrpc": _VERSION, "method": method, "id": rid}
        if params is not None:
            msg["params"] = params
        ok = False
        try:
            await self._channel.send(_ENC.encode(msg))
            # The server either sends $/transferReady, or rejects with an error
            # response (e.g. over TLS) which resolves final_fut.
            await asyncio.wait({ready_fut, final_fut},
                               return_when=asyncio.FIRST_COMPLETED)
            if final_fut.done():
                await final_fut          # raises the server's error
                raise ClientError("transfer rejected before $/transferReady")
            ready = ready_fut.result()
            direction = TransferDirection(ready["direction"])
            target.transport.pause_reading()  # consumer parks its reader before raw bytes
            if direction is TransferDirection.DOWNLOAD:   # client consumes -> paused, now go
                await self._channel.send(_ENC.encode(
                    {"jsonrpc": _VERSION, "method": _TRANSFER_GO_METHOD,
                     "params": {"id": rid}}))
            fd = target.fileno
            os.set_blocking(fd, True)
            ok = True
            return rid, direction, fd, final_fut, ready.get("result")
        finally:
            self._transfer_ready.pop(rid, None)
            if not ok:
                # Failed/cancelled/timed out before the fd reached the caller: drop the
                # pending final-response slot and un-pause the reader (a no-op if we never
                # paused) so a partial setup can't leak the entry or wedge the connection.
                self._pending.pop(rid, None)
                with contextlib.suppress(Exception):
                    target.transport.resume_reading()

    async def _transfer_finish(self, rid: str, fd: int,
                               final_fut: asyncio.Future[Any]) -> Any:
        """Restore the loop's I/O and await the server's final response."""
        os.set_blocking(fd, False)
        target = self._channel.transfer_target() if self._channel is not None else None
        if target is not None:
            target.transport.resume_reading()
        try:
            return await final_fut
        finally:
            self._pending.pop(rid, None)

    async def _read_loop(self) -> None:
        assert self._channel is not None
        try:
            while True:
                data = await self._channel.recv()
                if data is None:
                    break                       # EOF / clean close
                try:
                    msg = msgspec.json.decode(data)
                except msgspec.DecodeError:
                    continue
                self._on_message(msg)
        finally:
            self._fail_pending(ClientError("connection closed"))

    def _on_message(self, msg: Any) -> None:
        if not isinstance(msg, dict):
            return
        rid = msg.get("id")
        if isinstance(rid, str) and rid in self._pending:
            fut = self._pending.get(rid)
            if fut is None or fut.done():
                return
            if "error" in msg:
                e = msg["error"] or {}
                fut.set_exception(JsonRpcError(
                    e.get("code", 0), e.get("message", ""), e.get("data")))
            else:
                fut.set_result(msg.get("result"))
            return
        # no matching pending id -> a server->client notification. Route, in order:
        # this call's progress callback, then the topic's subscription callback(s),
        # then the global handler / notifications queue.
        method = msg.get("method")
        if not isinstance(method, str):
            return
        params = msg.get("params")
        if method == _TRANSFER_READY_METHOD and isinstance(params, dict):
            tid = params.get("id")
            ready = self._transfer_ready.get(tid) if isinstance(tid, str) else None
            if ready is not None and not ready.done():
                ready.set_result(params)         # hand to the waiting transfer()
            return
        if method == _PROGRESS_METHOD and isinstance(params, dict):
            pid = params.get("id")
            cb = self._progress_callbacks.get(pid) if isinstance(pid, str) else None
            if cb is not None:
                self._backchannel_q.put(functools.partial(cb, params))
                return
        subs = self._sub_callbacks.get(method)
        if subs:
            for cb in list(subs):
                self._backchannel_q.put(functools.partial(cb, params))
            return
        if self._on_notification is not None:
            self._backchannel_q.put(
                functools.partial(self._on_notification, method, params))
        else:
            self.notifications.put((method, params))

    def _run_backchannel(self) -> None:
        """Drain the callback queue, running each user callback off the IO thread and
        isolating exceptions (a buggy callback can't take down the connection)."""
        while True:
            job = self._backchannel_q.get()
            if job is None:                          # stop sentinel
                return
            try:
                job()
            except Exception:
                _log.exception("notification callback raised")

    def _fail_pending(self, exc: Exception) -> None:
        for fut in list(self._pending.values()):
            if not fut.done():
                fut.set_exception(exc)
        self._pending.clear()

    async def _teardown(self) -> None:
        # Close the transport first so the read loop sees EOF and ends on its own; then
        # ensure the reader task is finished. (asyncio.CancelledError is a BaseException,
        # so suppress that too.)
        if self._channel is not None:
            await self._channel.aclose()
        if self._reader_task is not None:
            self._reader_task.cancel()
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(self._reader_task, 1)
