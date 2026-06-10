"""Serve the example protocol over an AF_UNIX socket with truenas_pyjsonrpc_server.

This is the whole server: name the protocol, point it at a socket, and run. It
reuses the ``protocol`` defined in ``serve.py`` (session setup + an authorized,
audited ``pool.create`` with live progress + a ``pool.events`` pub/sub topic). The
server runs each synchronous ``dispatch`` in a thread pool and bridges
``poll_notification`` back onto the loop, so progress and pub/sub are delivered live.

Run from the repo root::

    python examples/serve_async.py            # serves on /tmp/truenas-jsonrpc.sock

then drive it with ``python examples/client_async.py`` (self-contained — it also
starts its own server, so you don't strictly need this one). Ctrl-C to stop.
"""
import asyncio

from serve import protocol

from truenas_pyjsonrpc_server import JSONRPCServer, UnixConfig

SOCK_PATH = "/tmp/truenas-jsonrpc.sock"


async def main() -> None:
    async with JSONRPCServer({"truenas": protocol}, name="truenas",
                             unix_config=UnixConfig(path=SOCK_PATH)) as server:
        print(f"serving {server.protocol_names} on {SOCK_PATH} (Ctrl-C to stop)")
        await asyncio.Event().wait()            # run until interrupted


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nstopped")
