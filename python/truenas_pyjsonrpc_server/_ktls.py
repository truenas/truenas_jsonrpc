"""kTLS connection setup.

A normal asyncio TLS connection (`ssl=`) does the record crypto in userspace via memory
BIOs, so the socket fd carries ciphertext — unusable for a raw-fd transfer. **kTLS**
moves the record crypto into the kernel: after the handshake, ``read``/``write``/
``sendfile`` on the fd are plaintext to us while the wire stays encrypted. That requires
the handshake to run on a real socket fd with OpenSSL's ``OP_ENABLE_KTLS`` set; we then
hand the (now plaintext-to-us) fd to asyncio as a **plain** transport.

Enable it by setting ``ctx.options |= ssl.OP_ENABLE_KTLS`` on the ``SSLContext`` you pass
as ``ssl=`` (TCP only). Requires OpenSSL built with kTLS, the kernel ``tls`` module, and
an AES-GCM / ChaCha20 cipher.
"""
from __future__ import annotations

import socket
import ssl
from typing import Any


def enabled(ctx: ssl.SSLContext | None) -> bool:
    """True if ``ctx`` opts into kTLS (``OP_ENABLE_KTLS`` set)."""
    return ctx is not None and bool(ctx.options & ssl.OP_ENABLE_KTLS)


def handshake(ctx: ssl.SSLContext, sock: socket.socket, *, server_side: bool,
              server_hostname: str | None = None
              ) -> tuple[int, int, Any, Any]:
    """Blocking TLS handshake with kTLS, on ``sock``. Returns
    ``(plaintext_fd, family, cipher, peercert)`` — the detached fd carries plaintext
    (kernel does the crypto). **Run this in an executor** (it blocks).

    Raises ``OSError`` if the negotiated cipher isn't kTLS-capable (AES-GCM /
    ChaCha20) — the most common reason OpenSSL would silently fall back to userspace
    TLS, which would leave ciphertext on the fd.
    """
    family = sock.family
    sock.setblocking(True)
    ss = ctx.wrap_socket(sock, server_side=server_side,
                         server_hostname=server_hostname)
    try:
        cipher = ss.cipher()
        peercert = ss.getpeercert()
        name = (cipher[0] if cipher else "") or ""
        if "GCM" not in name and "CHACHA20" not in name:
            raise OSError(
                f"kTLS requires an AES-GCM/ChaCha20 cipher; negotiated {name!r}")
    except BaseException:
        ss.close()
        raise
    fd = ss.detach()                 # kTLS state stays on the kernel fd after detach
    return fd, family, cipher, peercert


def plain_socket(fd: int, family: int) -> socket.socket:
    """Wrap a (kTLS) fd as a plain blocking-cleared socket for asyncio."""
    sock = socket.socket(family, socket.SOCK_STREAM, fileno=fd)
    sock.setblocking(False)
    return sock
