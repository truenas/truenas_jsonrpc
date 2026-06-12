"""Self-contained demo of the generated, strongly-typed client end-to-end.

Starts a :class:`~truenas_pyjsonrpc_server.JSONRPCServer` (the ``serve.py`` protocol)
on a background thread, then drives it with the **generated** ``TruenasClient`` from
``client_gen.py`` (produced from the repo root by ``PYTHONPATH=examples python
codegen.py serve:protocol --out examples/client_gen.py``). Shows: ``$/negotiate`` -> auth ->
a typed ``pool_create`` with a per-call ``progress`` callback -> a typed pub/sub
subscription with a callback that receives a decoded ``PoolEvent``.

Run from the repo root::  python examples/client_async.py
"""
import asyncio
import hashlib
import io
import threading
import time

from api import FileDownloadArgs, NoParams, PoolCreateArgs, PoolEvent
from client_gen import TruenasClient
from serve import protocol

from truenas_pyjsonrpc_client import UnixConfig
from truenas_pyjsonrpc_server import JSONRPCServer
from truenas_pyjsonrpc_server import UnixConfig as SrvUnixConfig

SOCK_PATH = "/tmp/truenas-jsonrpc-demo.sock"


def _serve_in_background() -> "tuple[asyncio.AbstractEventLoop, JSONRPCServer, threading.Thread]":
    """Run a server on its own loop in a daemon thread; return (loop, server, thread)."""
    loop = asyncio.new_event_loop()
    server = JSONRPCServer({"truenas": protocol}, name="truenas",
                           unix_config=SrvUnixConfig(path=SOCK_PATH))
    ready = threading.Event()

    def run() -> None:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(server.start())
        ready.set()
        loop.run_forever()

    thread = threading.Thread(target=run, name="example-server", daemon=True)
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
        client = TruenasClient(unix_config=UnixConfig(path=SOCK_PATH))
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
        time.sleep(0.1)                         # let the event flush before closing

        # Raw-fd transfer: the server streams bytes straight over the socket fd; our
        # callback reads them off the fd (a stand-in for libzfs lzc_receive). The typed
        # method returns the decoded FileDownloadResult.
        buf = io.BytesIO()
        dl = client.file_download(FileDownloadArgs(size=64 * 1024),
                                  callback=lambda ft: ft.recvfile(buf, ft.params["size"]))
        ok = hashlib.sha256(buf.getvalue()).hexdigest() == dl.sha256
        print(f"file.download -> {dl.sent} bytes, sha256 {'ok' if ok else 'MISMATCH'}")
        client.close()
    finally:
        asyncio.run_coroutine_threadsafe(server.aclose(), loop).result(5)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(5)
        loop.close()


if __name__ == "__main__":
    main()
