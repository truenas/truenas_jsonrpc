"""SCRAM (RFC 5802) glue for the auth stack — all crypto is delegated to the
``truenas_pyscram`` C extension (SCRAM-SHA-512); this module only marshals the wire
strings and the stored verifier.

The server keeps a **verifier** per identity (salt + iteration count + ``StoredKey`` /
``ServerKey``) — never the secret. The exchange is two round trips: ``client-first`` ->
``server-first`` (challenge) -> ``client-final`` (proof) -> ``server-final`` (the server's
own signature, for the client's mutual-auth check). No secret crosses the wire and a
captured exchange can't be replayed, so SCRAM is safe even on an unencrypted channel.

``truenas_pyscram`` is an **optional** dependency (Debian ``python3-truenas-scram``): this
module imports without it, and only the SCRAM code paths raise :class:`ScramUnavailable`
if it is missing. :class:`AuthStack` drives this; users only provide a
:class:`ScramCredentials` per username (mint one with :func:`generate_scram_credentials`).
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Callable

try:
    import truenas_pyscram as _scram
except ImportError:                              # optional dependency — see module docstring
    _scram = None                                # type: ignore[assignment]

#: True when the ``truenas_pyscram`` C extension is importable (SCRAM is usable).
SCRAM_AVAILABLE = _scram is not None


class ScramError(Exception):
    """A malformed SCRAM message, an unknown user, or a failed proof verification."""


class ScramUnavailable(RuntimeError):
    """SCRAM was attempted but the ``truenas_pyscram`` package is not installed."""


def _require() -> Any:
    if _scram is None:
        raise ScramUnavailable(
            "SCRAM support requires the 'truenas_pyscram' package (python3-truenas-scram)")
    return _scram


@dataclass
class ScramCredentials:
    """A stored SCRAM verifier for one identity (RFC 5802 §3): the salt, iteration count,
    and the ``StoredKey`` / ``ServerKey`` derived by ``truenas_pyscram`` — **never** the
    secret. Mint one with :func:`generate_scram_credentials`, or rebuild it from fields you
    persisted from ``truenas_pyscram.generate_scram_auth_data()``. ``identity`` is recorded
    as the session's authenticated identity on success."""
    salt: bytes
    iterations: int
    stored_key: bytes
    server_key: bytes
    identity: Any = None
    user_info: dict[str, Any] | None = None


def generate_scram_credentials(*, iterations: int | None = None, identity: Any = None,
                               user_info: dict[str, Any] | None = None,
                               ) -> tuple[ScramCredentials, str]:
    """Mint a fresh, random SCRAM credential — the modern replacement for a plaintext API
    key. Returns ``(credentials, secret)``: **store** the :class:`ScramCredentials`, and
    hand the ``secret`` (the base64 ``SaltedPassword``) to the client **once**. The client
    authenticates with that secret; the server never needs it again."""
    s = _require()
    ad = s.generate_scram_auth_data(iterations=iterations or s.SCRAM_DEFAULT_ITERS)
    creds = ScramCredentials(
        salt=bytes(ad.salt), iterations=ad.iterations,
        stored_key=bytes(ad.stored_key), server_key=bytes(ad.server_key),
        identity=identity, user_info=user_info)
    return creds, base64.b64encode(bytes(ad.salted_password)).decode()


@dataclass
class ScramState:
    """Server-side state carried between :func:`server_first` and :func:`server_final`
    (stashed on the session during ``INIT``). The two RFC strings hold everything the
    verification needs (salt, nonce, iterations)."""
    username: str
    creds: ScramCredentials
    client_first: str                            # the client-first RFC string
    server_first: str                            # the server-first RFC string


def server_first(client_first_rfc: str,
                 lookup: Callable[[str], ScramCredentials | None],
                 ) -> tuple[str, ScramState]:
    """Process ``client-first-message``; return ``(server-first-message, state)``.
    ``lookup(username)`` returns the stored verifier, or ``None`` for an unknown user — in
    which case :class:`ScramError` is raised and the caller replies ``AUTH_ERR``. (To mask
    whether an account exists, have ``lookup`` return a stable decoy verifier instead of
    ``None`` — that is an application policy, not something this layer fabricates.)"""
    s = _require()
    try:
        cf = s.ClientFirstMessage(rfc_string=client_first_rfc)
        username = cf.username
    except (ValueError, s.ScramError) as e:
        raise ScramError("malformed client-first-message") from e
    creds = lookup(username)
    if creds is None:
        raise ScramError("unknown user")
    sf = s.ServerFirstMessage(client_first=cf, salt=s.CryptoDatum(creds.salt),
                              iterations=creds.iterations)
    return str(sf), ScramState(username, creds, client_first_rfc, str(sf))


def server_final(client_final_rfc: str, state: ScramState) -> str:
    """Process ``client-final-message``; return ``server-final-message`` (``v=...``).
    Raises :class:`ScramError` on a malformed message or a bad client proof."""
    s = _require()
    try:
        cf = s.ClientFirstMessage(rfc_string=state.client_first)
        sf = s.ServerFirstMessage(rfc_string=state.server_first)
        cfin = s.ClientFinalMessage(rfc_string=client_final_rfc)
    except (ValueError, s.ScramError) as e:
        raise ScramError("malformed client-final-message") from e
    stored = s.CryptoDatum(state.creds.stored_key)
    try:
        s.verify_client_final_message(client_first=cf, server_first=sf,
                                      client_final=cfin, stored_key=stored)
    except s.ScramError as e:                    # SCRAM_E_AUTH_FAILED — bad proof
        raise ScramError("bad client proof") from e
    sfin = s.ServerFinalMessage(client_first=cf, server_first=sf, client_final=cfin,
                                stored_key=stored, server_key=s.CryptoDatum(state.creds.server_key))
    return str(sfin)
