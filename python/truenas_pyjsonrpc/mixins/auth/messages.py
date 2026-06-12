"""The auth wire schema — tagged unions mirroring
``auth.login_ex`` / ``auth.login_ex_continue``.

Request **mechanisms** (discriminated on ``"mechanism"``) go to ``$/sessionSetup`` /
``$/sessionSetupContinue``; **responses** (discriminated on ``"response_type"``) come back
wrapped in :class:`AuthResult`. Secret credential fields are marked with ``SECRET`` so the
protocol redacts them in the audit trail.

The mechanisms are deliberately **non-plaintext**: SCRAM (RFC 5802 / API keys), GSSAPI
(Kerberos), the mTLS client certificate, and — over AF_UNIX — peer credentials. No password
or bearer token crosses the wire.
"""
from __future__ import annotations

from typing import Annotated, Any, Literal, Union

import msgspec
from msgspec import Struct

from truenas_pyjsonrpc import SECRET


# --- request mechanisms (tagged union on "mechanism") ------------------------
class Scram(Struct, tag_field="mechanism", tag="SCRAM"):
    """A SCRAM (RFC 5802) message — the client-first (``CLIENT_FIRST_MESSAGE``, to
    ``$/sessionSetup``) or client-final (``CLIENT_FINAL_MESSAGE``, to
    ``$/sessionSetupContinue``). ``rfc_str`` is the raw SCRAM message; **no replayable
    secret travels on the wire** (the proof is a one-time, nonce-bound challenge response),
    so SCRAM is safe even over an unencrypted channel. The field is nonetheless
    ``SECRET``-marked so the one-time client proof isn't retained in the audit trail."""
    scram_type: Literal["CLIENT_FIRST_MESSAGE", "CLIENT_FINAL_MESSAGE"]
    rfc_str: Annotated[str, SECRET]


class Gssapi(Struct, tag_field="mechanism", tag="GSSAPI"):
    """A GSSAPI (Kerberos, RFC 4752) token. GSSAPI is a **variable-round** exchange: the
    client sends a ``token`` to ``$/sessionSetup`` and then replies to each
    ``GSSAPI_RESPONSE`` challenge with another ``token`` on ``$/sessionSetupContinue`` for as
    many rounds as the mechanism needs. ``bytes`` is base64-encoded on the JSON wire."""
    token: bytes


class ClientCertificate(Struct, tag_field="mechanism", tag="CLIENT_CERTIFICATE"):
    """mTLS — no credential in the message; the client certificate is on the channel
    (``Peer.peercert``)."""


class OtpToken(Struct, tag_field="mechanism", tag="OTP_TOKEN"):
    """The second factor, sent to ``$/sessionSetupContinue`` after a SCRAM login replies
    ``otp_required`` (or after an ``OTP_REQUIRED`` response)."""
    otp_token: Annotated[str, SECRET]


#: The first-factor mechanisms accepted by ``$/sessionSetup``.
LoginMech = Union[ClientCertificate, Scram, Gssapi]

#: The mechanisms accepted by ``$/sessionSetupContinue`` (an OTP second factor, the SCRAM
#: client-final, or the next GSSAPI token).
ContinueMech = Union[OtpToken, Scram, Gssapi]


class LoginOptions(Struct):
    """Optional login flags (middleware ``login_options``)."""
    user_info: bool = True


class SetupArgs(Struct):
    """``$/sessionSetup`` params. ``mechanism`` is omitted (``None``) over AF_UNIX to
    request peer-credential authentication."""
    mechanism: LoginMech | None = None
    login_options: LoginOptions = msgspec.field(default_factory=LoginOptions)


class ContinueArgs(Struct):
    """``$/sessionSetupContinue`` params (an OTP second factor, the SCRAM client-final, or
    the next GSSAPI token)."""
    mechanism: ContinueMech
    login_options: LoginOptions = msgspec.field(default_factory=LoginOptions)


# --- responses (tagged union on "response_type") -----------------------------
class Success(Struct, tag_field="response_type", tag="SUCCESS"):
    """Authenticated; the session is ``ESTABLISHED``."""
    user_info: dict[str, Any] | None = None


class OtpRequired(Struct, tag_field="response_type", tag="OTP_REQUIRED"):
    """First factor accepted; a second factor is required (call
    ``$/sessionSetupContinue`` with ``OTP_TOKEN``)."""
    username: str


class ScramResponse(Struct, tag_field="response_type", tag="SCRAM_RESPONSE"):
    """A SCRAM server message: ``SERVER_FIRST_RESPONSE`` (the challenge — the session is
    ``INIT``, the client replies with ``CLIENT_FINAL_MESSAGE``) or
    ``SERVER_FINAL_RESPONSE`` (carries the server signature for the client's mutual-auth
    check). On the final message, ``otp_required=True`` means the SCRAM proof was accepted
    but a second factor is still needed — the session stays ``INIT`` and the client
    continues with an ``OTP_TOKEN``; otherwise the session is ``ESTABLISHED``. ``rfc_str``
    is the raw SCRAM message (``SECRET``-marked so the server signature isn't retained in
    the audit trail)."""
    scram_type: Literal["SERVER_FIRST_RESPONSE", "SERVER_FINAL_RESPONSE"]
    rfc_str: Annotated[str, SECRET]
    user_info: dict[str, Any] | None = None
    otp_required: bool = False


class GssapiResponse(Struct, tag_field="response_type", tag="GSSAPI_RESPONSE"):
    """A GSSAPI server token. While ``complete=False`` the session is ``INIT`` and the client
    must reply with the next ``GSSAPI`` token; when ``complete=True`` the exchange finished
    and the session is ``ESTABLISHED`` (``token`` may carry a final per-RFC-4752 token for
    the client). ``bytes`` is base64-encoded on the JSON wire."""
    token: bytes
    complete: bool = False
    user_info: dict[str, Any] | None = None


class AuthErr(Struct, tag_field="response_type", tag="AUTH_ERR"):
    """Authentication failed (generic — does not distinguish bad user vs bad secret)."""


class Expired(Struct, tag_field="response_type", tag="EXPIRED"):
    """The credential/token/account has expired."""


class Denied(Struct, tag_field="response_type", tag="DENIED"):
    """The credential is valid but not permitted on this channel (or lacks access)."""


#: Every response variant.
AuthResponse = Union[
    Success, OtpRequired, ScramResponse, GssapiResponse, AuthErr, Expired, Denied]


class AuthResult(Struct):
    """The ``returns`` of both setup methods (a Struct wrapping the response union)."""
    response: AuthResponse
