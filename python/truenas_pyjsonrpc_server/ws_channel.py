"""WebSocket transport channel (server side).

Imports the optional ``websockets`` dependency at module scope **on purpose**: this
module is only imported lazily by ``server.py`` when a ``websocket_config`` is in use,
so a base install (msgspec only) never pulls ``websockets`` in. Server code imports it
guarded::

    try:
        from .ws_channel import WebSocketChannel, ws_serve
    except ImportError as e:
        raise ImportError("...install truenas_pyjsonrpc[websocket]") from e
"""
from __future__ import annotations

import contextlib
from typing import Any

from websockets.asyncio.server import serve as ws_serve  # noqa: F401  (re-exported)
from websockets.exceptions import ConnectionClosed

from .channel import MessageChannel
from .peercred import Peer

__all__ = ["WebSocketChannel", "ws_serve"]


class WebSocketChannel(MessageChannel):
    """One JSON-RPC message per WebSocket frame. The ``websockets`` library owns the
    wire (framing, masking, ping/pong, flow control), so there is no plaintext fd to
    hand out — ``transfer_target`` stays ``None`` and raw-fd transfers are rejected."""

    def __init__(self, ws: Any, peer: Peer | None) -> None:
        self.peer = peer
        self._ws = ws

    async def recv(self) -> bytes | None:
        try:
            msg = await self._ws.recv()
        except ConnectionClosed:
            return None                          # clean close, or oversize -> 1009 close
        # Frames arrive as str (text) or bytes (binary); msgspec wants bytes.
        return msg.encode() if isinstance(msg, str) else msg

    async def send(self, data: bytes) -> None:
        try:
            await self._ws.send(data.decode())   # JSON-RPC convention: text frames
        except ConnectionClosed as e:
            raise ConnectionError("websocket closed") from e

    async def aclose(self) -> None:
        with contextlib.suppress(Exception):
            await self._ws.close()
