"""Transport configuration for :class:`~truenas_pyjsonrpc_server.JSONRPCServer`.

A server binds one or more transports, each described by one of these dataclasses:
``UnixConfig`` (AF_UNIX), ``TCPConfig`` (length-prefixed JSON over TCP, optionally
TLS / kTLS), and ``WebSocketConfig`` (JSON-RPC framed as WebSocket messages over TCP,
optionally ``wss://``). Several may be configured at once (e.g. ``unix_config`` +
``websocket_config``); at least one is required.
"""
from __future__ import annotations

from dataclasses import dataclass
from ssl import SSLContext
from typing import Any

from .framing import DEFAULT_LIMIT


@dataclass(slots=True)
class UnixConfig:
    """Listen on an AF_UNIX socket. ``mode`` is applied to the socket file after bind
    (``None`` leaves the umask default)."""
    path: str
    mode: int | None = 0o660


@dataclass(slots=True)
class TCPConfig:
    """Listen on a TCP ``host``/``port`` with length-prefixed JSON framing.

    ``ssl`` (a server :class:`ssl.SSLContext`) enables TLS; if the context has
    ``OP_ENABLE_KTLS`` set the server uses the kernel-TLS accept path (so raw-fd
    transfers still work over the encrypted link)."""
    host: str
    port: int
    ssl: SSLContext | None = None


@dataclass(slots=True)
class WebSocketConfig:
    """Listen on a TCP ``host``/``port`` and frame JSON-RPC as WebSocket messages
    (``ws://``; ``wss://`` when ``ssl`` is set), using the ``websockets`` library.

    Requires the optional ``websockets`` dependency
    (``pip install truenas_pyjsonrpc[websocket]``). ``max_size`` bounds an inbound
    message (``websockets`` closes the connection on overflow). ``extra_options`` are
    passed verbatim to ``websockets.asyncio.server.serve`` for anything not surfaced
    here (e.g. ``max_queue``, ``write_limit``). Note: raw-fd transfers are **not**
    supported over WebSocket (the library owns the wire), so transfer methods are
    rejected on a WebSocket connection."""
    host: str
    port: int
    ssl: SSLContext | None = None
    max_size: int = DEFAULT_LIMIT
    ping_interval: float | None = 20.0
    ping_timeout: float | None = 20.0
    compression: str | None = "deflate"
    extra_options: dict[str, Any] | None = None
