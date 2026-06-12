"""``truenas_pyjsonrpc.mixins.audit`` — structured syslog auditing for
:mod:`truenas_pyjsonrpc`.

Mix :class:`TrueNASAuditMixin` (or :class:`AuditMixin`) into your protocol, or pass a
:class:`SyslogAuditHandler` as the protocol's ``audit_handler`` directly; either way every
audited call is emitted to syslog as a ``@cee:{"TNAUDIT":{…}}`` record — the same JSON shape
TrueNAS middleware logs (``aid``/``vers``/``addr``/``user``/``sess``/``time``/``svc``/
``svc_data``/``event``/``event_data``/``success``), with the ``event`` classified
``METHOD_CALL`` vs ``CONTROL_MESSAGE``. Secret params are already redacted by the protocol
before they reach the record. Depends only on the stdlib + :mod:`truenas_pyjsonrpc`.

```python
from truenas_pyjsonrpc import JSONRPCProtocol
from truenas_pyjsonrpc.mixins import TrueNASAuditMixin

class VmProtocol(TrueNASAuditMixin, JSONRPCProtocol):
    audit_service = "vm.api"                            # -> /var/run/syslog-ng/vm.api.sock
```

Use :class:`AuditFormatter` directly to build the record for a non-syslog sink.
"""
from .mixin import AuditMixin, TrueNASAuditMixin
from .record import (
    UNAUTHENTICATED,
    UNKNOWN_USER,
    AuditFormatter,
    EventType,
    default_credentials,
    default_event_classifier,
    default_origin,
    default_username,
)
from .syslog import SyslogAuditHandler

__all__ = [
    # protocol mixins (the ergonomic entry point)
    "AuditMixin",
    "TrueNASAuditMixin",
    # the emitter + the transport-agnostic builder
    "SyslogAuditHandler",
    "AuditFormatter",
    "EventType",
    # overridable defaults (classifier + identity extractors)
    "default_event_classifier",
    "default_username",
    "default_origin",
    "default_credentials",
    # sentinels
    "UNAUTHENTICATED",
    "UNKNOWN_USER",
]
