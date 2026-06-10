"""The client's transport seam.

:class:`~truenas_pyjsonrpc_client.BaseClient`'s read/write paths drive a
``ClientChannel`` rather than a raw ``StreamReader``/``StreamWriter`` + framing, so the
read loop, request encoding, and teardown are framing-agnostic. ``StreamClientChannel``
is the length-prefixed JSON transport (AF_UNIX, TCP, kTLS); ``WebSocketClientChannel``
(in ``ws_channel.py``) is the WebSocket transport. A channel reports whether the
connection can host a raw-fd transfer via ``transfer_target`` (``None`` means no).
"""
from __future__ import annotations

import abc
import asyncio
import contextlib
import struct
from dataclasses import dataclass
from typing import cast

_HEADER = struct.Struct(">I")           # 4-byte big-endian length prefix (see server framing)


@dataclass(slots=True, frozen=True)
class TransferTarget:
    """Handles a raw-fd transfer needs: the bidirectional transport (to pause / resume
    reading around the raw stream) and the plaintext socket fd."""
    transport: asyncio.Transport
    fileno: int

    def __post_init__(self) -> None:
        if self.fileno < 0:
            raise ValueError("transfer target socket is closed (fileno < 0)")


class ClientChannel(abc.ABC):
    """One JSON-RPC message in, one out — framing and socket details hidden."""

    @abc.abstractmethod
    async def recv(self) -> bytes | None:
        """Receive one JSON-RPC message payload, or ``None`` at EOF/clean close."""

    @abc.abstractmethod
    async def send(self, data: bytes) -> None:
        """Frame and write one message, awaiting backpressure."""

    @abc.abstractmethod
    async def aclose(self) -> None:
        """Close the underlying transport (best-effort)."""

    def transfer_target(self) -> TransferTarget | None:
        """The plaintext-fd handles for a raw-fd transfer, or ``None`` when this
        connection can't host one (userspace TLS, or WebSocket)."""
        return None


class StreamClientChannel(ClientChannel):
    """Length-prefixed JSON over an asyncio stream (AF_UNIX, plain TCP, or kTLS)."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 limit: int) -> None:
        self._reader = reader
        self._writer = writer
        self._limit = limit

    async def recv(self) -> bytes | None:
        try:
            header = await self._reader.readexactly(_HEADER.size)
        except asyncio.IncompleteReadError:
            return None                          # EOF (clean, or partial header)
        (length,) = _HEADER.unpack(header)
        if length > self._limit:
            return None                          # framing error -> drop the connection
        try:
            return await self._reader.readexactly(length)
        except asyncio.IncompleteReadError:
            return None                          # EOF mid-frame

    async def send(self, data: bytes) -> None:
        self._writer.write(_HEADER.pack(len(data)) + data)
        await self._writer.drain()

    async def aclose(self) -> None:
        self._writer.close()
        with contextlib.suppress(Exception):
            await self._writer.wait_closed()

    def transfer_target(self) -> TransferTarget | None:
        if self._writer.get_extra_info("ssl_object") is not None:
            return None                          # userspace TLS: ciphertext on the fd
        sock = self._writer.get_extra_info("socket")
        if sock is None:
            return None
        return TransferTarget(cast(asyncio.Transport, self._writer.transport),
                              sock.fileno())
