"""``truenas_pyjsonrpc.mixins.auth`` — a reusable, channel-aware, middlewared-style
authentication layer for :mod:`truenas_pyjsonrpc`.

Subclass :class:`AuthStack`, override the credential verifiers you support (each returns
:class:`Authenticated`, :class:`NeedsOtp`, or :class:`Reject`), and call
``stack.install(protocol)`` to wire up ``$/sessionSetup`` / ``$/sessionSetupContinue`` —
or, for the ergonomic path, mix :class:`TrueNASAuthMixin` (or :class:`AuthStackMixin`) into
your protocol class so it installs itself at construction. It mirrors middlewared's
``auth.login_ex`` flow (tagged-union mechanisms in, responses out, two-step OTP) and is
**channel-aware**: AF_UNIX uses ``SO_PEERCRED`` (with login fallthrough), TCP/WebSocket use
the login mechanisms + mTLS, and each mechanism is bound to the channel capabilities it
requires.
"""
from .messages import (
    AuthErr,
    AuthResponse,
    AuthResult,
    ClientCertificate,
    ContinueArgs,
    Denied,
    Expired,
    Gssapi,
    GssapiResponse,
    LoginMech,
    LoginOptions,
    OtpRequired,
    OtpToken,
    Scram,
    ScramResponse,
    SetupArgs,
    Success,
)
from .mixin import AuthStackMixin, TrueNASAuthMixin
from .pam import PAM_AVAILABLE, TrueNASAuth
from .scram import ScramCredentials, generate_scram_credentials
from .stack import (
    Authenticated,
    AuthStack,
    Capability,
    GssapiChallenge,
    NeedsOtp,
    Outcome,
    Reject,
    ScramChallenge,
)

__all__ = [
    # protocol mixins (the ergonomic entry point)
    "AuthStackMixin",
    "TrueNASAuthMixin",
    # the plug-in API
    "AuthStack",
    "Authenticated",
    "NeedsOtp",
    "Reject",
    "Outcome",
    "Capability",
    "ScramChallenge",
    "GssapiChallenge",
    # the ready-made TrueNAS PAM stack
    "TrueNASAuth",
    "PAM_AVAILABLE",
    # request mechanisms
    "ClientCertificate",
    "Scram",
    "Gssapi",
    "OtpToken",
    "LoginMech",
    "LoginOptions",
    "SetupArgs",
    "ContinueArgs",
    # SCRAM verifier helpers (crypto delegated to truenas_pyscram)
    "ScramCredentials",
    "generate_scram_credentials",
    # responses
    "Success",
    "OtpRequired",
    "ScramResponse",
    "GssapiResponse",
    "AuthErr",
    "Expired",
    "Denied",
    "AuthResponse",
    "AuthResult",
]
