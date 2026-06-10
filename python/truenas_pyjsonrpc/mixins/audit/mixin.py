"""Protocol mixins that register an audit handler (and enable the off-IO-path audit queue)
at construction.

Mix one in **before** :class:`~truenas_pyjsonrpc.JSONRPCProtocol`::

    class MyProtocol(TrueNASAuditMixin, JSONRPCProtocol):
        audit_service = "vm.api"
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from .syslog import SyslogAuditHandler

if TYPE_CHECKING:                                # mixed into a JSONRPCProtocol; type self as one
    from truenas_pyjsonrpc import JSONRPCProtocol
    _Base = JSONRPCProtocol
else:
    _Base = object


class AuditMixin(_Base):
    """Register the audit handler returned by :meth:`make_audit_handler` (``None`` registers
    nothing) and enable the audit queue at construction, so the server drains audit off the
    dispatch path. The base hook returns ``None`` — override it, or use a ready-made subclass
    like :class:`TrueNASAuditMixin`."""

    #: Build the protocol with ``use_audit_queue=True`` (drained by the server's audit thread).
    audit_use_queue: bool = True

    def make_audit_handler(self) -> Callable[..., Any] | None:
        return None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("use_audit_queue", self.audit_use_queue)   # must be set at construction
        super().__init__(*args, **kwargs)
        handler = self.make_audit_handler()
        if handler is not None:
            self.register_audit_handler(handler)


class TrueNASAuditMixin(AuditMixin):
    """Register a :class:`SyslogAuditHandler` emitting middleware ``@cee``/``TNAUDIT`` records.
    Configure with the class attributes below, or override :meth:`make_audit_handler`."""

    #: The ``svc`` name; defaults to the protocol's ``name``.
    audit_service: str | None = None
    #: Syslog destination; ``None`` uses the SyslogAuditHandler default (syslog-ng STREAM sock).
    audit_address: Any = None
    audit_socktype: Any = None

    def make_audit_handler(self) -> Callable[..., Any]:
        service = self.audit_service or self.name
        if service is None:
            raise ValueError(
                "TrueNASAuditMixin: set `audit_service` or give the protocol a `name`")
        kw: dict[str, Any] = {}
        if self.audit_address is not None:
            kw["address"] = self.audit_address
        if self.audit_socktype is not None:
            kw["socktype"] = self.audit_socktype
        return SyslogAuditHandler(service=service, **kw)
