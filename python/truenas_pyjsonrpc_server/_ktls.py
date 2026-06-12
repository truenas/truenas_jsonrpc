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

``OP_ENABLE_KTLS`` is **best-effort**: if any of those is missing OpenSSL still completes the
handshake but silently keeps the record crypto in userspace, so detaching the fd would put
plaintext on the wire (and feed ciphertext to a plain reader). CPython's ``ssl`` exposes no
way to confirm kTLS attached, so after the handshake we ask the kernel directly
(``getsockopt(SOL_TLS, TLS_TX/TLS_RX)``) and **refuse the connection** unless kTLS engaged
for both directions, rather than fall back to an unencrypted fd.
"""
from __future__ import annotations

import socket
import ssl
from typing import Any


def enabled(ctx: ssl.SSLContext | None) -> bool:
    """True if ``ctx`` opts into kTLS (``OP_ENABLE_KTLS`` set)."""
    return ctx is not None and bool(ctx.options & ssl.OP_ENABLE_KTLS)


# Linux kTLS confirmation probe. OP_ENABLE_KTLS is best-effort and CPython's ``ssl`` exposes
# no kTLS-status query, so we ask the kernel: getsockopt(SOL_TLS, TLS_TX/TLS_RX) returns the
# 4-byte ``struct tls_crypto_info`` header when that direction's crypto is installed, and
# errors (EBUSY / ENOPROTOOPT) otherwise. Constants: SOL_TLS=282 (linux/socket.h),
# TLS_TX=1 / TLS_RX=2 (uapi/linux/tls.h).
_SOL_TLS = 282
_TLS_TX = 1
_TLS_RX = 2
_TLS_CRYPTO_INFO_SIZE = 4              # sizeof(struct tls_crypto_info): version + cipher_type


def confirm_ktls_engaged(sock: socket.socket) -> None:
    """Raise ``OSError`` unless kernel TLS crypto is installed for **both** TX and RX on
    ``sock``. A detached fd whose kTLS didn't engage would put plaintext on the wire (TX) and
    feed ciphertext to a plain reader (RX), so callers must fail closed on this."""
    for direction, label in ((_TLS_TX, "TX"), (_TLS_RX, "RX")):
        try:
            sock.getsockopt(_SOL_TLS, direction, _TLS_CRYPTO_INFO_SIZE)
        except OSError as e:
            raise OSError(
                f"kTLS did not engage for {label}; refusing to fall back to userspace TLS "
                "(is the kernel 'tls' module loaded and OpenSSL built with kTLS?)") from e


def handshake(ctx: ssl.SSLContext, sock: socket.socket, *, server_side: bool,
              server_hostname: str | None = None
              ) -> tuple[int, int, Any, Any]:
    """Blocking TLS handshake with kTLS, on ``sock``. Returns
    ``(plaintext_fd, family, cipher, peercert)`` — the detached fd carries plaintext
    (kernel does the crypto). **Run this in an executor** (it blocks).

    Raises ``OSError`` if the negotiated cipher isn't kTLS-capable (AES-GCM / ChaCha20) or
    if kTLS didn't actually engage for both directions (see :func:`confirm_ktls_engaged`) —
    in either case OpenSSL would otherwise silently fall back to userspace TLS and leave
    ciphertext on the fd, so the connection is refused instead.
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
        confirm_ktls_engaged(ss)     # positively confirm kTLS attached, both directions
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
