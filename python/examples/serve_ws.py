"""Serve the example protocol over a WebSocket (``ws://``) with truenas_pyjsonrpc_server.

Identical to ``serve_async.py`` except the transport: instead of an AF_UNIX socket, the
JSON-RPC frames are carried as WebSocket messages over TCP, using the optional
``websockets`` dependency (``pip install truenas_pyjsonrpc[websocket]``). The
application protocol (``$/negotiate`` -> ``$/sessionSetup`` -> calls / progress /
pub-sub) is unchanged — only the framing differs. For ``wss://``, pass an
:class:`ssl.SSLContext` as ``WebSocketConfig(..., ssl=...)``.

Run from the repo root::

    python examples/serve_ws.py            # serves ws://127.0.0.1:8888

then drive it with ``python examples/client_ws.py`` (self-contained — it also starts
its own server, so you don't strictly need this one). Ctrl-C to stop.
"""
import asyncio

from serve import protocol

from truenas_pyjsonrpc_server import JSONRPCServer, WebSocketConfig

HOST, PORT = "127.0.0.1", 8888


async def main() -> None:
    async with JSONRPCServer(
            {"truenas": protocol}, name="truenas",
            websocket_config=WebSocketConfig(host=HOST, port=PORT)) as server:
        print(f"serving {server.protocol_names} on ws://{HOST}:{PORT} (Ctrl-C to stop)")
        await asyncio.Event().wait()            # run until interrupted


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nstopped")
