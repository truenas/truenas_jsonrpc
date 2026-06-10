"""Transport configuration for :class:`~truenas_pyjsonrpc_client.BaseClient`.

A client connects to exactly one transport, selected by which of these is passed:
``UnixConfig`` (AF_UNIX), ``TCPConfig`` (length-prefixed JSON over TCP, optionally
TLS / kTLS), or ``WebSocketConfig`` (JSON-RPC framed as WebSocket messages over TCP,
optionally ``wss://``).
"""
from __future__ import annotations

from dataclasses import dataclass
from ssl import SSLContext
from typing import Any

_DEFAULT_MAX_SIZE = 4 * 1024 * 1024     # mirrors the server's DEFAULT_LIMIT (4 MiB)


@dataclass(slots=True)
class UnixConfig:
    """Connect to a server's AF_UNIX socket at ``path``."""
    path: str


@dataclass(slots=True)
class TCPConfig:
    """Connect to a server's TCP ``host``/``port`` with length-prefixed JSON framing.

    ``ssl`` (a client :class:`ssl.SSLContext`) connects over TLS; ``server_hostname``
    overrides the name checked against the server certificate (default: ``host``). A
    context with ``OP_ENABLE_KTLS`` set uses the kernel-TLS path so raw-fd transfers
    keep working."""
    host: str
    port: int
    ssl: SSLContext | None = None
    server_hostname: str | None = None


@dataclass(slots=True)
class WebSocketConfig:
    """Connect to a server's TCP ``host``/``port`` framing JSON-RPC as WebSocket
    messages (``ws://``; ``wss://`` when ``ssl`` is set), using the ``websockets``
    library.

    Requires the optional ``websockets`` dependency
    (``pip install truenas_pyjsonrpc[websocket]``). ``server_hostname`` overrides the
    TLS SNI / certificate name. ``max_size`` bounds an inbound message. ``extra_options``
    are passed verbatim to ``websockets.asyncio.client.connect``. Note: raw-fd transfers
    are **not** supported over WebSocket."""
    host: str
    port: int
    ssl: SSLContext | None = None
    server_hostname: str | None = None
    max_size: int = _DEFAULT_MAX_SIZE
    ping_interval: float | None = 20.0
    ping_timeout: float | None = 20.0
    compression: str | None = "deflate"
    extra_options: dict[str, Any] | None = None
