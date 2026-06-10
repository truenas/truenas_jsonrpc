"""Protocol mixins that install an authentication stack at construction.

Mix one in **before** :class:`~truenas_pyjsonrpc.JSONRPCProtocol` so cooperative
``super().__init__`` builds the protocol first, then the mixin installs its stack::

    class MyProtocol(TrueNASAuthMixin, JSONRPCProtocol):
        auth_scram_service = "truenas-api-key"
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .pam import TrueNASAuth
from .stack import AuthStack

if TYPE_CHECKING:                                # mixed into a JSONRPCProtocol; type self as one
    from truenas_pyjsonrpc import JSONRPCProtocol
    _Base = JSONRPCProtocol
else:
    _Base = object


class AuthStackMixin(_Base):
    """Install the :class:`AuthStack` returned by :meth:`make_auth_stack` onto the protocol
    when it is constructed (``None`` installs nothing). The base hook returns ``None`` —
    override it, or use a ready-made subclass like :class:`TrueNASAuthMixin`."""

    def make_auth_stack(self) -> AuthStack | None:
        return None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)        # JSONRPCProtocol builds (name now set)
        stack = self.make_auth_stack()
        if stack is not None:
            stack.install(self)                  # adds $/sessionSetup (+ $/sessionSetupContinue)


class TrueNASAuthMixin(AuthStackMixin):
    """Install a PAM-backed :class:`TrueNASAuth` — SCRAM (RFC 5802) relayed through
    ``pam_truenas``. Configure with the class attributes below, or override
    :meth:`make_auth_stack` for full control."""

    #: PAM service for SCRAM (the one that loads ``pam_truenas``).
    auth_scram_service: str = "truenas-api-key"
    #: The login mechanisms to accept.
    auth_mechanisms = frozenset({"SCRAM"})
    #: Optional authenticator factory (e.g. to inject the connection origin / PAM env).
    auth_authenticator_factory: Any = None

    def make_auth_stack(self) -> AuthStack:
        return TrueNASAuth(scram_service=self.auth_scram_service,
                           mechanisms=self.auth_mechanisms,
                           authenticator_factory=self.auth_authenticator_factory)
