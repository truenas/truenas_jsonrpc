"""Length-prefixed JSON framing over asyncio streams.

Each message is a **4-byte big-endian unsigned length** followed by exactly that many
bytes of (compact) JSON. This is self-delimiting regardless of the payload bytes, so —
unlike newline framing — it places no constraints on the JSON content.
"""
from __future__ import annotations

import asyncio
import struct

#: Max bytes for a single message payload; a larger declared length is rejected.
DEFAULT_LIMIT = 4 * 1024 * 1024     # 4 MiB

_HEADER = struct.Struct(">I")       # 4-byte big-endian unsigned length prefix
HEADER_SIZE = _HEADER.size          # 4


class FrameTooLarge(Exception):
    """An inbound frame's declared length exceeded the configured limit."""


def frame(payload: bytes) -> bytes:
    """Prefix ``payload`` with its 4-byte big-endian length, ready to write."""
    return _HEADER.pack(len(payload)) + payload


async def read_message(reader: asyncio.StreamReader,
                       limit: int = DEFAULT_LIMIT) -> bytes | None:
    """Read one length-prefixed message and return its payload bytes, or ``None`` at
    EOF (a clean close between messages, or a truncated frame). Raises
    :class:`FrameTooLarge` if the declared length exceeds ``limit``."""
    try:
        header = await reader.readexactly(HEADER_SIZE)
    except asyncio.IncompleteReadError:
        return None                          # EOF (clean, or partial header)
    (length,) = _HEADER.unpack(header)
    if length > limit:
        raise FrameTooLarge(f"frame of {length} bytes exceeds limit of {limit}")
    try:
        return await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        return None                          # EOF mid-frame -> treat as closed
