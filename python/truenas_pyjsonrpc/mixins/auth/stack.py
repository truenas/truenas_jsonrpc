"""``AuthStack`` — a channel-aware, middlewared-style authentication stack that plugs
into ``JSONRPCProtocol.add_session_setup``.

Subclass it, override the verifiers you support (each returns :class:`Authenticated`,
:class:`NeedsOtp`, or :class:`Reject`), and call :meth:`install`. The stack drives the
``$/sessionSetup`` / ``$/sessionSetupContinue`` flow:

* **AF_UNIX** — :meth:`peercred` runs first (trust a local connection by its
  ``SO_PEERCRED`` uid/gid/pid); if it declines (``None``), the connection falls through to
  the login mechanisms.
* **TCP / WebSocket** — the login mechanisms (SCRAM, GSSAPI, mTLS client certificate), with
  an optional OTP second factor after SCRAM.

The mechanisms are deliberately **non-plaintext** — no password crosses the wire. Each
mechanism is also **channel-bound**: it is refused unless the connection's channel provides
the required :class:`Capability` (e.g. ``CLIENT_CERTIFICATE`` needs a client cert). SCRAM and
GSSAPI are replay-resistant and carry no channel requirement by default.
"""
from __future__ import annotations

import enum
import ipaddress
from dataclasses import dataclass
from typing import Any, Literal

from truenas_pyjsonrpc import JSONRPCMethod, JSONRPCProtocol, SessionLifecycle, SessionState

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
    LoginOptions,
    OtpRequired,
    Scram,
    ScramResponse,
    SetupArgs,
    Success,
)
from .scram import (
    SCRAM_AVAILABLE,
    ScramCredentials,
    ScramError,
    server_final,
    server_first,
)


class Capability(enum.Enum):
    """A trust property a connection's channel may provide. A mechanism's
    :attr:`AuthStack.requirements` are matched against these."""
    LOCAL = "local"              # AF_UNIX (a local process)
    ENCRYPTED = "encrypted"      # TLS, kTLS, AF_UNIX, or a loopback peer
    CLIENT_CERT = "client_cert"  # the peer presented a TLS client certificate
    PEERCRED = "peercred"        # AF_UNIX with SO_PEERCRED credentials


# --- outcomes a verifier returns ---------------------------------------------
@dataclass
class Authenticated:
    """The credential authenticated. ``identity`` is stored on the session's
    ``server_state_internal`` (what downstream method/authorization handlers read)."""
    identity: Any
    user_info: dict[str, Any] | None = None


@dataclass
class NeedsOtp:
    """First factor accepted; a second factor is required. ``pending`` is stashed and
    handed back to :meth:`AuthStack.otp` on ``$/sessionSetupContinue``."""
    pending: Any
    username: str


@dataclass
class Reject:
    """The credential was rejected. ``response`` selects the wire response."""
    response: Literal["AUTH_ERR", "EXPIRED", "DENIED"] = "AUTH_ERR"


Outcome = Authenticated | NeedsOtp | Reject


@dataclass
class ScramChallenge:
    """Returned by :meth:`AuthStack.scram_begin`: the ``SERVER_FIRST`` RFC string to relay to
    the client, plus opaque ``pending`` state handed back to :meth:`AuthStack.scram_finish` on
    the client-final."""
    server_first: str
    pending: Any


@dataclass
class GssapiChallenge:
    """Returned by :meth:`AuthStack.gssapi_step` mid-exchange: the GSSAPI ``server_token`` to
    relay to the client, plus opaque ``pending`` state (e.g. the live server-side GSS context)
    handed back to the next :meth:`AuthStack.gssapi_step` on the client's reply."""
    server_token: bytes
    pending: Any


@dataclass
class _Pending:
    """Internal: server_state_internal during INIT (between setup and continue)."""
    peer: Any
    pending: Any


@dataclass
class _ScramPending:
    """Internal: server_state_internal during a SCRAM exchange (INIT)."""
    peer: Any
    pending: Any


@dataclass
class _GssapiPending:
    """Internal: server_state_internal during a GSSAPI exchange (INIT)."""
    peer: Any
    pending: Any


def _is_loopback(address: Any) -> bool:
    try:
        host = address[0] if isinstance(address, (tuple, list)) else address
        return ipaddress.ip_address(host).is_loopback
    except (ValueError, TypeError, IndexError):
        return False


def _peer_origin(peer: Any) -> str | None:
    """A compact origin string (for an audit ``addr``) derived from the connection ``Peer``:
    ``host:port`` for TCP, ``unix:uid=N``/``unix:pid=N`` for AF_UNIX."""
    if peer is None:
        return None
    address = getattr(peer, "address", None)
    if isinstance(address, (tuple, list)) and len(address) >= 2:
        return f"{address[0]}:{address[1]}"
    if address:
        return str(address)
    uid = getattr(peer, "uid", None)
    if uid is not None:
        return f"unix:uid={uid}"
    pid = getattr(peer, "pid", None)
    return f"unix:pid={pid}" if pid is not None else None


def _attach_origin(identity: Any, peer: Any) -> Any:
    """Record the connection origin on a ``dict`` identity so it survives into audit records
    (the server-seeded ``Peer`` is replaced by the identity at establish time). Other identity
    shapes pass through unchanged; an existing ``origin`` is never overwritten."""
    if isinstance(identity, dict) and "origin" not in identity:
        origin = _peer_origin(peer)
        if origin is not None:
            return {**identity, "origin": origin}
    return identity


class AuthStack:
    """Channel-aware auth stack. Override the verifiers you support, then :meth:`install`."""

    #: Per-mechanism channel-capability requirements (override to customize). SCRAM and
    #: GSSAPI have none — they are replay-resistant, so they are safe even on an unencrypted
    #: channel.
    requirements: dict[type, set[Capability]] = {
        ClientCertificate: {Capability.CLIENT_CERT},
    }

    # --- verifiers: override the ones you support (defaults reject) -----------
    def peercred(self, peer: Any) -> Authenticated | None:
        """AF_UNIX peer-credential policy. Return :class:`Authenticated` to trust the
        local connection by its ``peer.uid``/``gid``/``pid``, or ``None`` to fall through
        to the login mechanisms. (Default: ``None`` — always log in.)"""
        return None

    def scram_credentials(self, username: str) -> ScramCredentials | None:
        """Return the stored SCRAM verifier for ``username`` (or ``None`` if unknown — the
        user is then rejected with ``AUTH_ERR``). Mint one with
        :func:`truenas_pyjsonrpc.mixins.auth.generate_scram_credentials` (store the verifier, never
        the secret)."""
        return None

    def client_certificate(self, peercert: Any, *, peer: Any) -> Outcome:
        return Reject()

    def otp(self, pending: Any, otp_token: str, *, peer: Any) -> Outcome:
        """The ``$/sessionSetupContinue`` second-factor check. ``pending`` is whatever a
        :class:`NeedsOtp` carried from the first factor (e.g. from :meth:`scram_finish`)."""
        return Reject()

    # --- channel binding (override to customize) -----------------------------
    def channel_capabilities(self, peer: Any) -> set[Capability]:
        """Derive the channel's :class:`Capability` set from the connection ``peer``
        (the server-seeded ``Peer``)."""
        caps: set[Capability] = set()
        if peer is None:
            return caps
        transport = getattr(peer, "transport", None)
        if transport == "unix":
            caps |= {Capability.LOCAL, Capability.ENCRYPTED}   # a local socket is trusted
            if getattr(peer, "uid", None) is not None:
                caps.add(Capability.PEERCRED)
        if getattr(peer, "tls", False):
            caps.add(Capability.ENCRYPTED)
        elif transport == "tcp" and _is_loopback(getattr(peer, "address", None)):
            caps.add(Capability.ENCRYPTED)
        if getattr(peer, "peercert", None):
            caps.add(Capability.CLIENT_CERT)
        return caps

    # --- wiring --------------------------------------------------------------
    def install(self, protocol: JSONRPCProtocol) -> None:
        """Register ``$/sessionSetup`` + ``$/sessionSetupContinue`` on ``protocol``."""
        setup = JSONRPCMethod("$/sessionSetup", accepts=SetupArgs, returns=AuthResult,
                              handler=self._on_setup, audit=True)
        cont = JSONRPCMethod("$/sessionSetupContinue", accepts=ContinueArgs,
                             returns=AuthResult, handler=self._on_continue, audit=True)
        protocol.add_session_setup(setup, cont)

    # --- handlers: the (SessionLifecycle, AuthResult) contract ---------------
    def _on_setup(self, request: SetupArgs,
                  session_state: SessionState) -> tuple[SessionLifecycle, AuthResult]:
        peer = session_state.server_state_internal      # the server-seeded Peer
        # 1. AF_UNIX: peer credentials first, then fall through to login.
        if getattr(peer, "transport", None) == "unix":
            out = self.peercred(peer)
            if out is not None:
                return self._establish(session_state, out, request.login_options, peer)
        # 2. a login mechanism (required off AF_UNIX, or when peercred declined).
        mech = request.mechanism
        if mech is None:
            return SessionLifecycle.NONE, AuthResult(AuthErr())
        required = self.requirements.get(type(mech), set())
        if not required <= self.channel_capabilities(peer):
            return SessionLifecycle.NONE, AuthResult(Denied())   # wrong channel
        if isinstance(mech, Scram):
            return self._scram_setup(mech, peer, session_state)
        if isinstance(mech, Gssapi):
            return self._gssapi_setup(mech, peer, session_state, request.login_options)
        return self._apply(session_state, self._verify(mech, peer),
                           request.login_options, peer)

    def _on_continue(self, request: ContinueArgs,
                     session_state: SessionState) -> tuple[SessionLifecycle, AuthResult]:
        holder = session_state.server_state_internal
        mech = request.mechanism
        if isinstance(mech, Scram):                  # SCRAM client-final
            if not isinstance(holder, _ScramPending):
                return SessionLifecycle.NONE, AuthResult(AuthErr())
            return self._scram_final(mech, holder, session_state, request.login_options)
        if isinstance(mech, Gssapi):                 # the next GSSAPI token
            if not isinstance(holder, _GssapiPending):
                return SessionLifecycle.NONE, AuthResult(AuthErr())
            return self._gssapi_continue(mech, holder, session_state, request.login_options)
        # OTP second factor
        if not isinstance(holder, _Pending):
            return SessionLifecycle.INIT, AuthResult(AuthErr())
        outcome = self.otp(holder.pending, mech.otp_token, peer=holder.peer)
        if isinstance(outcome, Authenticated):
            return self._establish(session_state, outcome, request.login_options, holder.peer)
        if isinstance(outcome, NeedsOtp):        # re-prompt; keep the pending holder
            session_state.server_state_internal = _Pending(holder.peer, outcome.pending)
            return SessionLifecycle.INIT, AuthResult(OtpRequired(outcome.username))
        if outcome.response == "AUTH_ERR":       # bad second factor -> let the client retry
            return SessionLifecycle.INIT, AuthResult(AuthErr())
        return SessionLifecycle.NONE, AuthResult(_reject(outcome.response))  # hard stop

    def _verify(self, mech: Any, peer: Any) -> Outcome:
        if isinstance(mech, ClientCertificate):
            return self.client_certificate(getattr(peer, "peercert", None), peer=peer)
        return Reject()

    def _apply(self, session_state: SessionState, outcome: Outcome,
               options: LoginOptions, peer: Any) -> tuple[SessionLifecycle, AuthResult]:
        if isinstance(outcome, Authenticated):
            return self._establish(session_state, outcome, options, peer)
        if isinstance(outcome, NeedsOtp):
            session_state.server_state_internal = _Pending(peer, outcome.pending)
            return SessionLifecycle.INIT, AuthResult(OtpRequired(outcome.username))
        return SessionLifecycle.NONE, AuthResult(_reject(outcome.response))

    def _establish(self, session_state: SessionState, out: Authenticated,
                   options: LoginOptions, peer: Any) -> tuple[SessionLifecycle, AuthResult]:
        session_state.server_state_internal = _attach_origin(out.identity, peer)
        resp = Success(user_info=out.user_info if options.user_info else None)
        return SessionLifecycle.ESTABLISHED, AuthResult(resp)

    # --- SCRAM (RFC 5802): an overridable engine wrapped into the lifecycle -----
    def scram_begin(self, client_first_rfc: str, *, peer: Any) -> ScramChallenge | Reject:
        """Process a SCRAM ``client-first`` and produce the ``server-first`` challenge.
        Default: the ``truenas_pyscram`` **verifier model** keyed on
        :meth:`scram_credentials`. Override (with :meth:`scram_finish`) to drive a different
        SCRAM backend — :class:`truenas_pyjsonrpc.mixins.auth.TrueNASAuth` relays through
        ``pam_truenas``. Returning :class:`Reject` replies ``AUTH_ERR``."""
        if not SCRAM_AVAILABLE:
            return Reject()
        try:
            sfirst, state = server_first(client_first_rfc, self.scram_credentials)
        except ScramError:                       # unknown user or malformed
            return Reject()
        return ScramChallenge(sfirst, state)

    def scram_finish(self, pending: Any, client_final_rfc: str, *, peer: Any
                     ) -> tuple[str, Authenticated] | tuple[str, NeedsOtp] | Reject:
        """Verify a SCRAM ``client-final`` and produce ``(server-final, outcome)``. Default:
        the verifier model (``pending`` is the ``ScramState`` from :meth:`scram_begin`),
        returning ``(server-final, Authenticated)``. Override alongside :meth:`scram_begin`
        — return ``(server-final, NeedsOtp)`` to require an **OTP second factor after SCRAM**
        (the client verifies the server signature, then continues with an ``OTP_TOKEN`` →
        :meth:`otp`)."""
        try:
            sfinal = server_final(client_final_rfc, pending)
        except ScramError:                       # bad proof
            return Reject()
        creds = pending.creds
        identity = creds.identity if creds.identity is not None else pending.username
        return sfinal, Authenticated(identity, user_info=creds.user_info)

    def _scram_setup(self, mech: Scram, peer: Any,
                     session_state: SessionState) -> tuple[SessionLifecycle, AuthResult]:
        if mech.scram_type != "CLIENT_FIRST_MESSAGE":
            return SessionLifecycle.NONE, AuthResult(AuthErr())
        out = self.scram_begin(mech.rfc_str, peer=peer)
        if isinstance(out, Reject):
            return SessionLifecycle.NONE, AuthResult(_reject(out.response))
        session_state.server_state_internal = _ScramPending(peer, out.pending)
        return SessionLifecycle.INIT, AuthResult(
            ScramResponse(scram_type="SERVER_FIRST_RESPONSE", rfc_str=out.server_first))

    def _scram_final(self, mech: Scram, holder: _ScramPending,
                     session_state: SessionState,
                     options: LoginOptions) -> tuple[SessionLifecycle, AuthResult]:
        if mech.scram_type != "CLIENT_FINAL_MESSAGE":
            return SessionLifecycle.NONE, AuthResult(AuthErr())
        out = self.scram_finish(holder.pending, mech.rfc_str, peer=holder.peer)
        if isinstance(out, Reject):
            return SessionLifecycle.NONE, AuthResult(_reject(out.response))
        sfinal, authd = out
        if isinstance(authd, NeedsOtp):          # SCRAM proof ok, but OTP still required
            session_state.server_state_internal = _Pending(holder.peer, authd.pending)
            return SessionLifecycle.INIT, AuthResult(
                ScramResponse(scram_type="SERVER_FINAL_RESPONSE", rfc_str=sfinal,
                              otp_required=True))
        session_state.server_state_internal = _attach_origin(authd.identity, holder.peer)
        resp = ScramResponse(scram_type="SERVER_FINAL_RESPONSE", rfc_str=sfinal,
                             user_info=authd.user_info if options.user_info else None)
        return SessionLifecycle.ESTABLISHED, AuthResult(resp)

    # --- GSSAPI (RFC 4752): a variable-round token exchange --------------------
    def gssapi_step(self, pending: Any, token: bytes, *, peer: Any
                    ) -> GssapiChallenge | tuple[bytes, Authenticated] | Reject:
        """Process one GSSAPI token and produce the next step. ``pending`` is ``None`` on the
        first token (from ``$/sessionSetup``) and otherwise the :class:`GssapiChallenge`
        ``pending`` from the previous round (a real impl carries its server-side GSS context
        there). Return :class:`GssapiChallenge` to continue the exchange, ``(final_token,
        Authenticated)`` when it completes, or :class:`Reject`.

        GSSAPI completes straight to :class:`Authenticated` — there is **no OTP second factor**
        as with SCRAM. Kerberos multi-factor is enforced at the KDC (OTP preauth / PKINIT /
        FAST), so a completed context already carries the assured identity; an app-layer OTP on
        top would be redundant and couldn't bind to the Kerberos credential.

        **This is a stub** — the default rejects. Override it to drive a real GSSAPI acceptor
        (see the auth README for a ``python-gssapi`` design)."""
        return Reject()

    def _gssapi_setup(self, mech: Gssapi, peer: Any, session_state: SessionState,
                      options: LoginOptions) -> tuple[SessionLifecycle, AuthResult]:
        return self._gssapi_apply(self.gssapi_step(None, mech.token, peer=peer),
                                  peer, session_state, options)

    def _gssapi_continue(self, mech: Gssapi, holder: _GssapiPending,
                         session_state: SessionState,
                         options: LoginOptions) -> tuple[SessionLifecycle, AuthResult]:
        return self._gssapi_apply(
            self.gssapi_step(holder.pending, mech.token, peer=holder.peer),
            holder.peer, session_state, options)

    def _gssapi_apply(self, out: GssapiChallenge | tuple[bytes, Authenticated] | Reject,
                      peer: Any, session_state: SessionState,
                      options: LoginOptions) -> tuple[SessionLifecycle, AuthResult]:
        if isinstance(out, Reject):
            return SessionLifecycle.NONE, AuthResult(_reject(out.response))
        if isinstance(out, GssapiChallenge):     # another round
            session_state.server_state_internal = _GssapiPending(peer, out.pending)
            return SessionLifecycle.INIT, AuthResult(
                GssapiResponse(token=out.server_token, complete=False))
        token, authd = out                       # complete
        session_state.server_state_internal = _attach_origin(authd.identity, peer)
        return SessionLifecycle.ESTABLISHED, AuthResult(
            GssapiResponse(token=token, complete=True,
                           user_info=authd.user_info if options.user_info else None))


def _reject(response: str) -> AuthResponse:
    if response == "EXPIRED":
        return Expired()
    if response == "DENIED":
        return Denied()
    return AuthErr()
