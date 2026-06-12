"""Self-contained end-to-end demo of the bi-directional file-transfer API in
``fileshare.py``: lookup -> put (upload) -> lookup-verify -> get (download)-verify,
then a final lookup to confirm the connection resumes normal JSON-RPC after a transfer.

Starts a :class:`~truenas_pyjsonrpc_server.JSONRPCServer` on a background thread over a
hard-coded ``/tmp`` share root, then drives it with a plain
:class:`~truenas_pyjsonrpc_client.BaseClient`.

  Run from the repo root::  python examples/fileshare_demo.py

NOTE: the share implementation is demo-only and is NOT safe for production — see the
security banner at the top of ``fileshare.py``.
"""
import asyncio
import hashlib
import io
import os
import tempfile
import threading

from fileshare import build_protocol

from truenas_pyjsonrpc_client import BaseClient, UnixConfig
from truenas_pyjsonrpc_server import JSONRPCServer
from truenas_pyjsonrpc_server import UnixConfig as SrvUnixConfig

SHARE_ROOT = "/tmp/truenas-fileshare-demo"        # hard-coded server root (demo)
SOCK_PATH = "/tmp/truenas-fileshare-demo.sock"


def _serve_in_background(protocol):
    """Run a server on its own loop in a daemon thread; return (loop, server, thread)."""
    loop = asyncio.new_event_loop()
    server = JSONRPCServer({"fileshare": protocol}, name="fileshare",
                           unix_config=SrvUnixConfig(path=SOCK_PATH))
    ready = threading.Event()

    def run() -> None:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(server.start())
        ready.set()
        loop.run_forever()

    thread = threading.Thread(target=run, name="fileshare-server", daemon=True)
    thread.start()
    ready.wait(5)
    return loop, server, thread


def _print_listing(client) -> None:
    res = client.call("fs.lookup")
    print(f"  lookup {res['root']}:")
    for e in res["entries"]:
        print(f"    {e['type']:5} {e['size']:>8}  {e['name']}")


def main() -> None:
    # seed the share with one pre-existing file so the first listing isn't empty
    os.makedirs(SHARE_ROOT, exist_ok=True)
    with open(os.path.join(SHARE_ROOT, "welcome.txt"), "wb") as f:
        f.write(b"hello from the file share\n")

    protocol = build_protocol(SHARE_ROOT)
    loop, server, thread = _serve_in_background(protocol)
    try:
        client = BaseClient("fileshare", unix_config=UnixConfig(path=SOCK_PATH))
        print("negotiated:", client.connect())

        print("\n# initial listing")
        _print_listing(client)

        # --- PUT (upload): the client streams bytes; the server writes them ----
        payload = bytes(i % 251 for i in range(200_000))
        sha = hashlib.sha256(payload).hexdigest()
        print(f"\n# put report.bin ({len(payload)} bytes, sha {sha[:12]}...)")

        def send_cb(ft):                              # client produces the stream
            with tempfile.TemporaryFile() as f:
                f.write(payload)
                f.flush()
                f.seek(0)
                ft.sendfile(f)

        put = client.transfer("fs.put", {"name": "report.bin", "size": len(payload)},
                              callback=send_cb)
        print(f"  put -> received {put['received']} bytes")

        # --- verify via a fresh lookup (and that the connection still works) ---
        print("\n# listing after put")
        _print_listing(client)
        after = {e["name"]: e for e in client.call("fs.lookup")["entries"]}
        assert "report.bin" in after, "uploaded file not listed"
        assert after["report.bin"]["size"] == len(payload), "size mismatch"
        print(f"  OK: report.bin is listed at {after['report.bin']['size']} bytes")

        # --- GET (download): the server streams bytes; the client reads them ---
        print("\n# get report.bin back")
        buf = io.BytesIO()                            # size comes from the server's
        got = client.transfer("fs.get", {"name": "report.bin"},   # $/transferReady result
                              callback=lambda ft: ft.recvfile(buf, ft.result["size"]))
        ok = hashlib.sha256(buf.getvalue()).hexdigest() == sha
        print(f"  get -> sent {got['sent']} bytes, sha256 {'ok' if ok else 'MISMATCH'}")

        # --- normal connectivity restored after the transfers -----------------
        print("\n# final lookup (connection resumes normal JSON-RPC)")
        _print_listing(client)
        client.close()
    finally:
        asyncio.run_coroutine_threadsafe(server.aclose(), loop).result(5)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(5)
        loop.close()


if __name__ == "__main__":
    main()
