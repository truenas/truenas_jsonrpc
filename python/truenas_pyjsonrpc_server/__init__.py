"""truenas_pyjsonrpc_server — an asyncio AF_UNIX/TCP/WebSocket server for the
:mod:`truenas_pyjsonrpc` dispatch component.

Declare named protocols, point :class:`JSONRPCServer` at one or more transports
(:class:`UnixConfig`, :class:`TCPConfig`, :class:`WebSocketConfig`), and
``await server.serve_forever()``. A connection negotiates a protocol with
``$/negotiate``, then authenticates with ``$/sessionSetup`` and issues calls. The
WebSocket transport needs the optional ``websockets`` dependency
(``pip install truenas_pyjsonrpc[websocket]``).
"""
from .config import TCPConfig, UnixConfig, WebSocketConfig
from .negotiate import NEGOTIATE_METHOD, NegotiateParams, NegotiateResult
from .peercred import Peer
from .server import JSONRPCServer

__all__ = [
    "JSONRPCServer",
    "UnixConfig",
    "TCPConfig",
    "WebSocketConfig",
    "Peer",
    "NEGOTIATE_METHOD",
    "NegotiateParams",
    "NegotiateResult",
]
