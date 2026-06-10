"""truenas_pyjsonrpc_client — a thread-safe client for the
:mod:`truenas_pyjsonrpc_server` (JSON-RPC over AF_UNIX / TCP / WebSocket).

Connect via one of :class:`UnixConfig`, :class:`TCPConfig`, or :class:`WebSocketConfig`,
``$/negotiate`` a protocol, ``$/sessionSetup`` (authenticate), then issue synchronous,
thread-safe :meth:`BaseClient.call`\\ s from any thread. The WebSocket transport needs
the optional ``websockets`` dependency (``pip install truenas_pyjsonrpc[websocket]``).
Generate a strongly-typed subclass from a protocol with the repo's ``python codegen.py``
tool.
"""
from .client import BaseClient, ClientError
from .config import TCPConfig, UnixConfig, WebSocketConfig

__all__ = ["BaseClient", "ClientError", "UnixConfig", "TCPConfig", "WebSocketConfig"]
