"""WebSocket transport channel (client side).

Imports the optional ``websockets`` dependency at module scope **on purpose**: this
module is only imported lazily by ``client.py`` when a ``websocket_config`` is in use,
so a base install (msgspec only) never pulls ``websockets`` in.
"""
from __future__ import annotations

import contextlib
from typing import Any

from websockets.asyncio.client import connect as ws_connect  # noqa: F401  (re-exported)
from websockets.exceptions import ConnectionClosed

from .channel import ClientChannel

__all__ = ["WebSocketClientChannel", "ws_connect"]


class WebSocketClientChannel(ClientChannel):
    """One JSON-RPC message per WebSocket frame. The ``websockets`` library owns the
    wire, so there is no plaintext fd to hand out — raw-fd transfers are rejected
    (``transfer_target`` stays ``None``)."""

    def __init__(self, ws: Any) -> None:
        self._ws = ws

    async def recv(self) -> bytes | None:
        try:
            msg = await self._ws.recv()
        except ConnectionClosed:
            return None
        return msg.encode() if isinstance(msg, str) else msg

    async def send(self, data: bytes) -> None:
        try:
            await self._ws.send(data.decode())   # JSON-RPC convention: text frames
        except ConnectionClosed as e:
            raise ConnectionError("websocket closed") from e

    async def aclose(self) -> None:
        with contextlib.suppress(Exception):
            await self._ws.close()
