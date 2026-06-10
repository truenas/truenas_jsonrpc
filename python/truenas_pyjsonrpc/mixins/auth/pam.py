"""``TrueNASAuth`` — an :class:`~truenas_pyjsonrpc.mixins.auth.AuthStack` that delegates
authentication to **PAM** the way TrueNAS middleware does, so a local service can consume the
host's ``pam_truenas`` PAM files instead of holding any credentials itself.

**SCRAM (RFC 5802)** is **not** verified in-process — it is relayed through ``pam_truenas`` on
``scram_service`` (default ``"truenas-api-key"``): the client ``client-first`` /
``client-final`` RFC strings are fed into the PAM conversation and the module returns
``server-first`` / ``server-final``. The verifier lives in the system keyring; this layer
holds no secret.

``truenas_pypam`` / ``truenas_authenticator`` (Debian ``python3-truenas-pypam``) and
``truenas_pyscram`` are **optional**: this module imports without them and the PAM code paths
reject cleanly (see :data:`PAM_AVAILABLE`) when they are missing.

The PAM **service name depends on the deployment** — production TrueNAS installs
``truenas-api-key``; the ``pam_truenas`` test host uses ``middleware-scram``. Pass
``scram_service`` to match the host.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable

from .scram import SCRAM_AVAILABLE
from .stack import Authenticated, AuthStack, Reject, ScramChallenge

try:
    import truenas_pypam
    from truenas_authenticator import UserPamAuthenticator  # type: ignore[import-untyped]
    PAM_AVAILABLE = True
except ImportError:                              # optional dep — see module docstring
    truenas_pypam = None                         # type: ignore[assignment]
    UserPamAuthenticator = None
    PAM_AVAILABLE = False

try:
    import truenas_pyscram
except ImportError:                              # only needed to parse the SCRAM client-first
    truenas_pyscram = None                       # type: ignore[assignment]


#: Factory building a PAM authenticator handle; override to pass connection origin / rhost.
AuthenticatorFactory = Callable[..., Any]


def _default_authenticator(*, username: str, service: str) -> Any:
    return UserPamAuthenticator(username=username, service=service)


def _answer(reason: Any, value: str) -> list[str | None]:
    """One response per prompt: ``value`` for every echo-off (secret) prompt, ``None`` else."""
    return [value if m.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF else None
            for m in reason]


def _first_secret_msg(reason: Any) -> str | None:
    for m in reason:
        if m.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            return str(m.msg)
    return None


@dataclass
class _ScramPamPending:
    """Carried between :meth:`TrueNASAuth.scram_begin` and ``scram_finish`` (the live PAM
    handle, the outstanding prompt set, and the parsed identity)."""
    auth: Any
    reason: Any
    username: str
    api_key_id: int


class TrueNASAuth(AuthStack):
    """An :class:`AuthStack` that authenticates SCRAM against the host's PAM stack via
    ``pam_truenas`` (through ``truenas_pypam``). Install it like any other stack:
    ``TrueNASAuth().install(protocol)``."""

    def __init__(self, *, scram_service: str = "truenas-api-key",
                 mechanisms: Iterable[str] = frozenset({"SCRAM"}),
                 authenticator_factory: AuthenticatorFactory | None = None) -> None:
        self._scram_service = scram_service
        self._mechanisms = frozenset(mechanisms)
        self._new_authenticator = authenticator_factory or _default_authenticator
        #: PAM is usable if the bindings imported, or a custom factory was supplied.
        self._pam_ready = PAM_AVAILABLE or authenticator_factory is not None

    # --- SCRAM relayed through pam_truenas on `scram_service` -----------------
    def scram_begin(self, client_first_rfc: str, *, peer: Any) -> ScramChallenge | Reject:
        if "SCRAM" not in self._mechanisms or not self._pam_ready or truenas_pyscram is None:
            return Reject()
        try:
            cf = truenas_pyscram.ClientFirstMessage(rfc_string=client_first_rfc)
            username, api_key_id = cf.username, cf.api_key_id
        except Exception:
            return Reject()
        pam_user = f"{username}:{api_key_id}" if api_key_id else username
        auth = self._new_authenticator(username=pam_user, service=self._scram_service)
        try:
            resp = auth.auth_init()              # PAM_AUTHINFO_UNAVAIL here -> unknown key
            if resp.code != truenas_pypam.PAMCode.PAM_CONV_AGAIN:
                auth.end()
                return Reject()
            resp = auth.auth_continue(_answer(resp.reason, client_first_rfc))
            if resp.code != truenas_pypam.PAMCode.PAM_CONV_AGAIN:
                auth.end()
                return Reject()
            server_first = _first_secret_msg(resp.reason)
        except Exception:
            auth.end()
            return Reject()
        if server_first is None:
            auth.end()
            return Reject()
        return ScramChallenge(
            server_first, _ScramPamPending(auth, resp.reason, username, api_key_id))

    def scram_finish(self, pending: Any, client_final_rfc: str, *, peer: Any
                     ) -> tuple[str, Authenticated] | Reject:
        auth = pending.auth
        try:
            resp = auth.auth_continue(_answer(pending.reason, client_final_rfc))
            if resp.code != truenas_pypam.PAMCode.PAM_CONV_AGAIN or not resp.reason:
                auth.end()
                return Reject()                   # bad proof -> PAM_AUTH_ERR
            server_final = str(resp.reason[0].msg)
            final = auth.auth_continue([None])    # close out the conversation
        except Exception:
            auth.end()
            return Reject()
        auth.end()
        if final.code != truenas_pypam.PAMCode.PAM_SUCCESS:
            return Reject()
        ident = self._identity(pending.username, pending.api_key_id, final.user_info)
        return server_final, Authenticated(ident, user_info=ident)

    def _identity(self, username: str, api_key_id: int,
                  user_info: Any) -> dict[str, Any]:
        attrs = list((user_info or {}).get("account_attributes", []))
        ident: dict[str, Any] = {"username": username, "account_attributes": attrs}
        if api_key_id:
            ident["api_key_id"] = api_key_id
        return ident
