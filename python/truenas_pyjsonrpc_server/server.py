"""``JSONRPCServer`` — a few-option asyncio server over the dispatch component.

Declare named :class:`~truenas_pyjsonrpc.JSONRPCProtocol`\\ s, point it at an
AF_UNIX path, a TCP host+port, and/or a WebSocket host+port, and
``await serve_forever()``. It runs each
synchronous ``dispatch`` in a thread pool (handlers may block), bridges the blocking
``poll_notification`` via a per-protocol drain thread back onto the event loop, and
owns the ``session_uuid -> connection`` registry the drains route through.
"""
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import functools
import os
import socket
import threading
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from truenas_pyjsonrpc import JSONRPCProtocol

from . import _ktls
from .channel import StreamChannel
from .config import TCPConfig, UnixConfig, WebSocketConfig
from .connection import Connection
from .framing import DEFAULT_LIMIT
from .peercred import Peer, peer_from_socket


class JSONRPCServer:
    """Serve one or more named protocols over AF_UNIX, TCP, and/or WebSocket.

    ``protocols`` maps a negotiable name to a :class:`JSONRPCProtocol`. ``name`` is
    the server identity returned by ``$/negotiate``. Configure at least one transport
    via :class:`~truenas_pyjsonrpc_server.UnixConfig` (``unix_config``),
    :class:`~truenas_pyjsonrpc_server.TCPConfig` (``tcp_config``), and/or
    :class:`~truenas_pyjsonrpc_server.WebSocketConfig` (``websocket_config``); several
    may be combined.

    **A network-facing transport (TCP or WebSocket) requires authentication:** every
    protocol it exposes must configure ``$/sessionSetup`` via
    :meth:`~truenas_pyjsonrpc.JSONRPCProtocol.add_session_setup`, or construction raises
    ``ValueError``. Without it the dispatch gate is open and unauthenticated remote
    clients could call any method. AF_UNIX is exempt — it relies on local
    peer-credential / filesystem trust and may serve an unauthenticated protocol.

    TLS is configured per transport (the ``ssl`` field of ``TCPConfig`` /
    ``WebSocketConfig``); the negotiated cipher and, for mutual TLS, the client
    certificate are stamped onto the connection's
    :class:`~truenas_pyjsonrpc_server.Peer` (readable by a ``$/sessionSetup`` handler).
    ``websocket_config`` needs the optional ``websockets`` dependency
    (``pip install truenas_pyjsonrpc[websocket]``) and does not support raw-fd
    transfers.
    """

    def __init__(self, protocols: Mapping[str, JSONRPCProtocol], *,
                 name: str | None = None,
                 unix_config: UnixConfig | None = None,
                 tcp_config: TCPConfig | None = None,
                 websocket_config: WebSocketConfig | None = None,
                 max_workers: int | None = None, limit: int = DEFAULT_LIMIT) -> None:
        if not protocols:
            raise ValueError("at least one protocol is required")
        if unix_config is None and tcp_config is None and websocket_config is None:
            raise ValueError("configure at least one transport: "
                             "unix_config, tcp_config, and/or websocket_config")
        self._protocols: dict[str, JSONRPCProtocol] = dict(protocols)
        # A network-facing transport (TCP/WebSocket) must authenticate: every
        # protocol it exposes needs $/sessionSetup, or unauthenticated remote clients
        # could call its methods (the dispatch gate is open with no setup configured).
        # AF_UNIX is exempt — it relies on local peer-credential / filesystem trust.
        network = [n for n, c in (("tcp_config", tcp_config),
                                  ("websocket_config", websocket_config)) if c]
        if network:
            unauthenticated = sorted(n for n, p in self._protocols.items()
                                     if not p.has_session_setup)
            if unauthenticated:
                raise ValueError(
                    f"{' and '.join(network)} expose protocol(s) "
                    f"{', '.join(unauthenticated)} with no authentication: call "
                    "add_session_setup(...) to configure $/sessionSetup. A network "
                    "transport may not surface an unauthenticated protocol (use "
                    "unix_config for local, peer-credential-trusted access).")
        self._name = name
        self._unix_config = unix_config
        self._tcp_config = tcp_config
        self._websocket_config = websocket_config
        self._max_workers = max_workers
        self._limit = limit
        self._sessions: dict[str, Connection] = {}
        self._sessions_lock = threading.Lock()
        self._executor: ThreadPoolExecutor | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._servers: list[asyncio.AbstractServer] = []
        self._ws_servers: list[Any] = []                 # websockets.asyncio Server objects
        self._ktls_listeners: list[socket.socket] = []   # raw kTLS accept sockets
        self._ktls_tasks: set[asyncio.Task[Any]] = set()  # kTLS accept + connection tasks
        self._drains: list[threading.Thread] = []
        self._stop = threading.Event()
        self._serving: asyncio.Event | None = None
        self._started = False

    @property
    def name(self) -> str | None:
        return self._name

    @property
    def protocol_names(self) -> list[str]:
        return list(self._protocols)

    # --- session registry (shared with the drain threads) --------------------
    def _register(self, session_uuid: str, conn: Connection) -> None:
        with self._sessions_lock:
            self._sessions[session_uuid] = conn

    def _unregister(self, session_uuid: str) -> None:
        with self._sessions_lock:
            self._sessions.pop(session_uuid, None)

    def _conn_for(self, session_uuid: str) -> Connection | None:
        with self._sessions_lock:
            return self._sessions.get(session_uuid)

    # --- lifecycle -----------------------------------------------------------
    async def start(self) -> None:
        """Bind the transports and start the drain threads (idempotent)."""
        if self._started:
            return
        self._started = True
        self._loop = asyncio.get_running_loop()
        self._serving = asyncio.Event()
        self._executor = ThreadPoolExecutor(
            max_workers=self._max_workers, thread_name_prefix="jsonrpc-dispatch")

        if self._unix_config is not None:
            ucfg = self._unix_config
            with contextlib.suppress(FileNotFoundError):
                os.unlink(ucfg.path)                  # clear a stale socket
            srv = await asyncio.start_unix_server(
                self._on_stream_connect, path=ucfg.path, limit=self._limit)
            if ucfg.mode is not None:
                os.chmod(ucfg.path, ucfg.mode)
            self._servers.append(srv)
        if self._tcp_config is not None:
            tcfg = self._tcp_config
            if _ktls.enabled(tcfg.ssl):
                assert tcfg.ssl is not None
                # TLS 1.3 post-handshake session tickets are non-data records that
                # break the peer's kTLS RX (plain recv -> EIO); disable them.
                tcfg.ssl.num_tickets = 0
                self._start_ktls(tcfg.host, tcfg.port)     # kernel-TLS TCP listener
            else:
                srv = await asyncio.start_server(
                    self._on_stream_connect, tcfg.host, tcfg.port, limit=self._limit,
                    ssl=tcfg.ssl)
                self._servers.append(srv)
        if self._websocket_config is not None:
            await self._start_websocket(self._websocket_config)

        for pname, proto in self._protocols.items():
            self._spawn_drain(self._notification_drain, proto, f"notify[{pname}]")
            if getattr(proto, "_use_audit_queue", False):
                self._spawn_drain(self._audit_drain, proto, f"audit[{pname}]")

    async def serve_forever(self) -> None:
        """Start (if needed) and run until :meth:`aclose`."""
        await self.start()
        assert self._serving is not None
        try:
            await self._serving.wait()
        finally:
            await self.aclose()

    async def aclose(self) -> None:
        """Stop accepting, stop the drains, close open connections + the executor."""
        self._stop.set()
        if self._serving is not None:
            self._serving.set()
        for srv in self._servers:
            srv.close()
            close_clients = getattr(srv, "close_clients", None)
            if close_clients is not None:
                close_clients()                          # force-drop live conns (3.13+)
        for srv in self._servers:
            with contextlib.suppress(Exception):
                await srv.wait_closed()
        self._servers.clear()
        for ws_server in self._ws_servers:               # stop accepting + drop live WS conns
            ws_server.close()
        for ws_server in self._ws_servers:
            with contextlib.suppress(Exception):
                await ws_server.wait_closed()
        self._ws_servers.clear()
        for lsock in self._ktls_listeners:               # stop accepting kTLS conns
            with contextlib.suppress(Exception):
                lsock.close()
        self._ktls_listeners.clear()
        ktls_tasks = list(self._ktls_tasks)              # cancel accept + live conns
        for t in ktls_tasks:
            t.cancel()
        if ktls_tasks:
            await asyncio.gather(*ktls_tasks, return_exceptions=True)
        if self._executor is not None:
            self._executor.shutdown(wait=False)
            self._executor = None
        # drain threads are daemons; `_stop` makes them exit within one poll timeout

    async def __aenter__(self) -> "JSONRPCServer":
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    # --- internals -----------------------------------------------------------
    async def _on_stream_connect(self, reader: asyncio.StreamReader,
                                 writer: asyncio.StreamWriter) -> None:
        peer = peer_from_socket(writer.get_extra_info("socket"))
        # TLS state lives on the transport, not the socket (asyncio wraps SSL in
        # userspace); the handshake is complete by the time this callback runs.
        if peer is not None and writer.get_extra_info("ssl_object") is not None:
            peer = dataclasses.replace(
                peer,
                tls=True,
                peercert=writer.get_extra_info("peercert"),
                cipher=writer.get_extra_info("cipher"))
        channel = StreamChannel(reader, writer, peer, self._limit)
        await Connection(self, channel).serve()

    # --- WebSocket transport (framing handled by the optional `websockets` lib) ---
    async def _start_websocket(self, cfg: WebSocketConfig) -> None:
        try:
            from .ws_channel import ws_serve
        except ImportError as e:                          # optional dependency missing
            raise ImportError(
                "WebSocket transport requires the 'websockets' package. "
                "Install it with: pip install truenas_pyjsonrpc[websocket]") from e
        ws_server = await ws_serve(
            self._on_ws_connect, cfg.host, cfg.port, ssl=cfg.ssl,
            max_size=cfg.max_size, ping_interval=cfg.ping_interval,
            ping_timeout=cfg.ping_timeout, compression=cfg.compression,
            **(cfg.extra_options or {}))
        self._ws_servers.append(ws_server)

    async def _on_ws_connect(self, ws: Any) -> None:
        from .ws_channel import WebSocketChannel
        transport = ws.transport
        peer = peer_from_socket(transport.get_extra_info("socket"))
        # wss:// is userspace memory-BIO TLS, so TLS state is on the transport.
        if peer is not None and transport.get_extra_info("ssl_object") is not None:
            peer = dataclasses.replace(
                peer,
                tls=True,
                peercert=transport.get_extra_info("peercert"),
                cipher=transport.get_extra_info("cipher"))
        await Connection(self, WebSocketChannel(ws, peer)).serve()

    # --- kTLS TCP transport (real-fd handshake, then plain asyncio over the fd) ---
    def _start_ktls(self, host: str, port: int) -> None:
        lsock = socket.create_server((host, port))
        lsock.setblocking(False)
        self._ktls_listeners.append(lsock)
        assert self._loop is not None
        self._track_ktls(self._loop.create_task(self._accept_ktls(lsock)))

    def _track_ktls(self, task: asyncio.Task[Any]) -> None:
        self._ktls_tasks.add(task)
        task.add_done_callback(self._ktls_tasks.discard)

    async def _accept_ktls(self, lsock: socket.socket) -> None:
        assert self._loop is not None
        while not self._stop.is_set():
            try:
                conn, addr = await self._loop.sock_accept(lsock)
            except (OSError, asyncio.CancelledError):
                break                                    # listener closed / shutting down
            self._track_ktls(self._loop.create_task(self._handle_ktls(conn, addr)))

    async def _handle_ktls(self, conn: socket.socket, addr: Any) -> None:
        assert self._loop is not None and self._tcp_config is not None
        assert self._tcp_config.ssl is not None and self._executor is not None
        ssl_ctx = self._tcp_config.ssl
        try:
            fd, family, cipher, peercert = await self._loop.run_in_executor(
                self._executor,
                functools.partial(_ktls.handshake, ssl_ctx, conn, server_side=True))
        except Exception:
            with contextlib.suppress(Exception):
                conn.close()
            return                                       # handshake / kTLS failure
        plain = _ktls.plain_socket(fd, family)
        reader = asyncio.StreamReader(limit=self._limit, loop=self._loop)
        protocol = asyncio.StreamReaderProtocol(reader, loop=self._loop)
        transport, _ = await self._loop.connect_accepted_socket(
            lambda: protocol, plain)
        writer = asyncio.StreamWriter(transport, protocol, reader, self._loop)
        peer = Peer("tcp", address=addr, tls=True, peercert=peercert, cipher=cipher)
        channel = StreamChannel(reader, writer, peer, self._limit)
        await Connection(self, channel).serve()

    def _spawn_drain(self, target: Callable[[JSONRPCProtocol], None],
                     proto: JSONRPCProtocol, label: str) -> None:
        t = threading.Thread(target=target, args=(proto,), daemon=True,
                             name=f"jsonrpc-{label}")
        t.start()
        self._drains.append(t)

    def _notification_drain(self, proto: JSONRPCProtocol) -> None:
        while not self._stop.is_set():
            out = proto.poll_notification(block=True, timeout=0.5)
            if out is None:
                continue
            session, data = out
            conn = self._conn_for(session.session_uuid)
            if conn is not None and self._loop is not None:
                self._loop.call_soon_threadsafe(conn.enqueue_outbound, data)

    def _audit_drain(self, proto: JSONRPCProtocol) -> None:
        while not self._stop.is_set():
            rec = proto.poll_audit(block=True, timeout=0.5)
            if rec is not None:
                rec.run()
