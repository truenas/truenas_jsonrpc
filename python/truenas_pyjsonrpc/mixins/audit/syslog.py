"""``SyslogAuditHandler`` — emit middleware-shaped ``@cee`` audit records to syslog.

It is the ``audit_handler`` callable: pass an instance to ``JSONRPCProtocol(…,
audit_handler=…, use_audit_queue=True)``. Each audited call is formatted (via :class:`AuditFormatter`) into a
``@cee:{"TNAUDIT":{…}}`` line and written through a stdlib
``logging.handlers.SysLogHandler``.

The default destination is a **syslog-ng STREAM unix socket** at
``/var/run/syslog-ng/<service>.sock`` (like middleware); pass ``address`` / ``socktype`` to
point elsewhere (e.g. ``"/dev/log"``, ``socket.SOCK_DGRAM``). The socket must exist when the
handler is constructed (``SysLogHandler`` connects eagerly). With ``use_audit_queue=True`` the
(possibly blocking) write runs on the server's audit-drain thread, off the dispatch path — so
no extra internal queue is used here.
"""
from __future__ import annotations

import logging
import logging.handlers
import socket
from typing import Any

from truenas_pyjsonrpc import JSONRPCRequest

from .record import AuditFormatter


class SyslogAuditHandler:
    """A protocol ``audit_handler`` that writes ``@cee`` audit records to syslog. Build one
    per service; pass a custom ``formatter`` (an :class:`AuditFormatter`) to override the
    classifier / identity extractors. ``handler`` / ``logger`` are injectable for testing."""

    def __init__(self, service: str, *, address: "str | tuple[str, int] | None" = None,
                 socktype: socket.SocketKind = socket.SOCK_STREAM, ident: str | None = None,
                 facility: int = logging.handlers.SysLogHandler.LOG_LOCAL0,
                 formatter: AuditFormatter | None = None,
                 logger: logging.Logger | None = None,
                 handler: logging.Handler | None = None) -> None:
        self._formatter = formatter or AuditFormatter(service)
        if handler is None:
            if address is None:
                address = f"/var/run/syslog-ng/{service}.sock"
            handler = logging.handlers.SysLogHandler(
                address=address, facility=facility, socktype=socktype)
            handler.ident = ident or f"TNAUDIT_{service.upper()}: "
            handler.setFormatter(logging.Formatter("%(message)s"))   # emit the @cee blob as-is
        if logger is None:
            logger = logging.getLogger(f"truenas_pyjsonrpc.mixins.audit.{service}")
            for stale in list(logger.handlers):      # own this logger; avoid duplicate emits
                logger.removeHandler(stale)
        logger.propagate = False                     # audit is not application logging
        logger.setLevel(logging.INFO)                # else a fresh logger inherits root WARNING
        logger.addHandler(handler)
        self._logger = logger
        self._handler = handler

    def __call__(self, *, request: JSONRPCRequest, response: dict[str, Any],
                 session_state: Any, audit_message: str | None = None) -> None:
        try:
            self._logger.info(
                self._formatter.format(request, response, session_state, audit_message))
        except Exception as e:
            # Auditing must never break dispatch/drain — but don't lose the record
            # *silently*: a record too large for a SOCK_DGRAM syslog socket (the default
            # STREAM socket has no such limit) would otherwise vanish without a trace.
            logging.getLogger(__name__).warning(
                "dropped audit record for %r: %s", request.method, e)

    def close(self) -> None:
        """Detach and close the underlying syslog handler."""
        try:
            self._logger.removeHandler(self._handler)
            self._handler.close()
        except Exception:
            pass
