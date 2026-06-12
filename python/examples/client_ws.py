"""Self-contained WebSocket demo of the generated, strongly-typed client end-to-end.

Mirrors ``client_async.py`` but over **WebSocket** framing (the optional ``websockets``
dependency): it starts a :class:`~truenas_pyjsonrpc_server.JSONRPCServer` with a
``websocket_config`` on a background thread, then drives it with the generated
``TruenasClient`` over ``ws://``. Shows ``$/negotiate`` -> auth -> a typed
``pool_create`` with a per-call ``progress`` callback -> a typed pub/sub subscription.

NOTE: raw-fd transfers (``file_download``) are **not** supported over WebSocket — the
``websockets`` library owns the wire — so, unlike ``client_async.py``, this demo omits
that step (it would raise ``ClientError``). Use an AF_UNIX or TCP transport for transfers.

Run from the repo root::  python examples/client_ws.py
"""
import asyncio
import threading
import time

from api import NoParams, PoolCreateArgs, PoolEvent
from client_gen import TruenasClient
from serve import protocol

from truenas_pyjsonrpc_client import WebSocketConfig
from truenas_pyjsonrpc_server import JSONRPCServer
from truenas_pyjsonrpc_server import WebSocketConfig as SrvWebSocketConfig

HOST, PORT = "127.0.0.1", 8889


def _serve_in_background() -> "tuple[asyncio.AbstractEventLoop, JSONRPCServer, threading.Thread]":
    """Run a WebSocket server on its own loop in a daemon thread; return (loop, server, thread)."""
    loop = asyncio.new_event_loop()
    server = JSONRPCServer({"truenas": protocol}, name="truenas",
                           websocket_config=SrvWebSocketConfig(host=HOST, port=PORT))
    ready = threading.Event()

    def run() -> None:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(server.start())
        ready.set()
        loop.run_forever()

    thread = threading.Thread(target=run, name="example-ws-server", daemon=True)
    thread.start()
    ready.wait(5)
    return loop, server, thread


def _on_progress(p: object) -> None:
    print(f"  progress: {p}")                    # invoked on the backchannel thread


def _on_pool_event(event: PoolEvent) -> None:
    print(f"  event: {event}")                   # already decoded into PoolEvent


def main() -> None:
    loop, server, thread = _serve_in_background()
    try:
        client = TruenasClient(websocket_config=WebSocketConfig(host=HOST, port=PORT))
        print("negotiated:", client.connect())
        print("setup     :", client.setup({"token": "root-token"}))

        # Typed request -> typed result, with a per-call progress callback.
        result = client.pool_create(PoolCreateArgs(name="tank"), progress=_on_progress)
        print(f"pool.create -> {result}  ({type(result).__name__})")

        # Typed subscription: each published event is decoded into PoolEvent and
        # delivered to the callback.
        sub_id = client.subscribe_pool_events(NoParams(), callback=_on_pool_event)
        print("subscribed:", sub_id)
        protocol.send_notification("pool.events", {"name": "tank", "state": "ONLINE"})
        time.sleep(0.1)                          # let the event flush before closing
        client.close()
    finally:
        asyncio.run_coroutine_threadsafe(server.aclose(), loop).result(5)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(5)
        loop.close()


if __name__ == "__main__":
    main()
