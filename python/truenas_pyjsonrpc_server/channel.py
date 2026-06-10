"""The per-connection transport seam.

:class:`~truenas_pyjsonrpc_server.connection.Connection` drives a ``MessageChannel``
rather than a raw ``StreamReader``/``StreamWriter`` + framing, so the negotiate /
dispatch / notification logic is shared across framings. ``StreamChannel`` is the
length-prefixed JSON transport (AF_UNIX, TCP, kTLS); :class:`WebSocketChannel` (in
``ws_channel.py``) is the WebSocket transport. A channel also reports whether the
connection can host a raw-fd transfer (``transfer_target`` — ``None`` means no).
"""
from __future__ import annotations

import abc
import asyncio
import contextlib
from dataclasses import dataclass
from typing import cast

from .framing import frame, read_message
from .peercred import Peer


@dataclass(slots=True, frozen=True)
class TransferTarget:
    """The handles a raw-fd transfer needs: the bidirectional transport (to pause /
    resume reading around the raw stream) and the plaintext socket fd."""
    transport: asyncio.Transport
    fileno: int


class MessageChannel(abc.ABC):
    """One JSON-RPC message in, one out — framing and socket details hidden."""

    #: Identity of the connecting peer (seeded into the session); set by subclasses.
    peer: Peer | None

    @abc.abstractmethod
    async def recv(self) -> bytes | None:
        """Receive one JSON-RPC message payload, or ``None`` at EOF/clean close.
        May raise :class:`~truenas_pyjsonrpc_server.framing.FrameTooLarge`."""

    @abc.abstractmethod
    async def send(self, data: bytes) -> None:
        """Frame and write one message, awaiting backpressure. Raises
        :class:`ConnectionError` if the peer has gone away."""

    @abc.abstractmethod
    async def aclose(self) -> None:
        """Close the underlying transport (idempotent / best-effort)."""

    def transfer_target(self) -> TransferTarget | None:
        """The plaintext-fd handles for a raw-fd transfer, or ``None`` when this
        connection can't host one (encrypted userspace TLS, or WebSocket)."""
        return None


class StreamChannel(MessageChannel):
    """Length-prefixed JSON over an asyncio stream (AF_UNIX, plain TCP, or kTLS —
    a kTLS connection is a plain transport over the kernel-decrypted fd)."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 peer: Peer | None, limit: int) -> None:
        self.peer = peer
        self._reader = reader
        self._writer = writer
        self._limit = limit

    async def recv(self) -> bytes | None:
        return await read_message(self._reader, self._limit)

    async def send(self, data: bytes) -> None:
        self._writer.write(frame(data))
        await self._writer.drain()

    async def aclose(self) -> None:
        with contextlib.suppress(Exception):
            self._writer.close()

    def transfer_target(self) -> TransferTarget | None:
        # A raw-fd transfer needs a *plaintext* fd. A userspace memory-BIO TLS
        # connection carries ciphertext on the fd (and exposes an ssl_object) -> no.
        if self._writer.get_extra_info("ssl_object") is not None:
            return None
        sock = self._writer.get_extra_info("socket")
        if sock is None:
            return None
        return TransferTarget(cast(asyncio.Transport, self._writer.transport),
                              sock.fileno())
