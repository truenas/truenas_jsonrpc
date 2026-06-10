"""Peer identification for a connection's socket.

For AF_UNIX on Linux this reads ``SO_PEERCRED`` (the connecting process's pid/uid/
gid) so a ``$/sessionSetup`` handler can do local-socket auth; for TCP it records the
peer address. The result is seeded into the session's ``server_state_internal``.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True, frozen=True)
class Peer:
    """Identity of the connecting peer. ``transport`` is ``"unix"`` or ``"tcp"``;
    ``uid``/``gid``/``pid`` are set for AF_UNIX (Linux), ``address`` for TCP.

    The TLS fields are stamped by the server when the (TCP) connection is encrypted
    (``ssl=`` configured): ``tls`` is True, ``cipher`` is the negotiated
    ``(name, tls_version, secret_bits)`` tuple, and ``peercert`` is the client
    certificate dict for mutual TLS (``None`` when the client presented none) — so a
    ``$/sessionSetup`` handler can authenticate by client cert. They are read from
    the asyncio *transport* (not the socket: asyncio does TLS in userspace via memory
    BIOs, so the OS socket carries no SSL state)."""
    transport: str
    uid: int | None = None
    gid: int | None = None
    pid: int | None = None
    address: Any = None
    tls: bool = False
    peercert: Any = None
    cipher: Any = None


def peer_from_socket(sock: socket.socket | None) -> Peer | None:
    """Build a :class:`Peer` from a connection's socket (``None`` if unavailable)."""
    if sock is None:
        return None
    if sock.family == socket.AF_UNIX:
        so_peercred = getattr(socket, "SO_PEERCRED", None)
        if so_peercred is not None:
            try:
                raw = sock.getsockopt(socket.SOL_SOCKET, so_peercred,
                                      struct.calcsize("3i"))
                pid, uid, gid = struct.unpack("3i", raw)
                return Peer(transport="unix", uid=uid, gid=gid, pid=pid)
            except OSError:
                pass
        return Peer(transport="unix")
    try:
        address = sock.getpeername()
    except OSError:
        address = None
    return Peer(transport="tcp", address=address)
