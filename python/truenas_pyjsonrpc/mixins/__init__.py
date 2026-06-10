"""``truenas_pyjsonrpc.mixins`` — batteries-included protocol mixins (and the stacks they
wrap) for a full TrueNAS service: PAM/SCRAM **authentication** and structured syslog
**auditing**.

This is an **opt-in** layer — importing :mod:`truenas_pyjsonrpc` does not import it, so the
dispatch core stays dependency-light. Mix the pieces into a :class:`~truenas_pyjsonrpc.JSONRPCProtocol`
subclass (mixins **before** the base) and they wire themselves up at construction::

    from truenas_pyjsonrpc import JSONRPCProtocol
    from truenas_pyjsonrpc.mixins import TrueNASAuthMixin, TrueNASAuditMixin

    class ZFSDProtocol(TrueNASAuthMixin, TrueNASAuditMixin, JSONRPCProtocol):
        audit_service = "zfsd"
        auth_scram_service = "truenas-api-key"

The full APIs live in the :mod:`~truenas_pyjsonrpc.mixins.auth` and
:mod:`~truenas_pyjsonrpc.mixins.audit` subpackages; the most-used names are re-exported here.
"""
from .audit import (
    AuditFormatter,
    AuditMixin,
    EventType,
    SyslogAuditHandler,
    TrueNASAuditMixin,
)
from .auth import (
    AuthStack,
    AuthStackMixin,
    PAM_AVAILABLE,
    ScramCredentials,
    TrueNASAuth,
    TrueNASAuthMixin,
    generate_scram_credentials,
)

__all__ = [
    # auth
    "TrueNASAuthMixin",
    "AuthStackMixin",
    "AuthStack",
    "TrueNASAuth",
    "PAM_AVAILABLE",
    "ScramCredentials",
    "generate_scram_credentials",
    # audit
    "TrueNASAuditMixin",
    "AuditMixin",
    "SyslogAuditHandler",
    "AuditFormatter",
    "EventType",
]
