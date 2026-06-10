"""``$/negotiate`` — the server-level, unauthenticated protocol selector.

A connection begins by sending ``$/negotiate`` naming the protocol it wants; the
server binds one of its named :class:`~truenas_pyjsonrpc.JSONRPCProtocol`\\ s to the
connection and replies with the bound name, the server identity, and the available
names. After that the flow is the usual ``$/sessionSetup -> API calls`` against the
bound protocol. ``$/negotiate`` is handled entirely by the server — the base
protocol library never sees it.
"""
from __future__ import annotations

import msgspec

#: The control-method name. Server-layer; reserved like the protocol's ``$/`` names.
NEGOTIATE_METHOD = "$/negotiate"


class NegotiateParams(msgspec.Struct):
    """``$/negotiate`` request params."""
    protocol: str


class NegotiateResult(msgspec.Struct):
    """``$/negotiate`` reply: the bound protocol, the server identity, and every
    protocol the server offers."""
    protocol: str
    server: str | None
    available: list[str]
