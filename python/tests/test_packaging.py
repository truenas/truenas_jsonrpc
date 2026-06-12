"""Packaging guard: ``websockets`` is an *optional* dependency, imported lazily only
when a WebSocket transport is actually used. Importing the server/client packages on a
base install (msgspec only) must NOT pull ``websockets`` in. Run in a clean subprocess
so the assertion holds regardless of whether other tests imported ``websockets``."""
import os
import subprocess
import sys


def test_base_import_does_not_pull_in_websockets():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    code = (
        "import sys, truenas_pyjsonrpc_server, truenas_pyjsonrpc_client\n"
        "mods = [m for m in sys.modules if m == 'websockets' or m.startswith('websockets.')]\n"
        "assert not mods, f'base import unexpectedly loaded: {mods}'\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True,
                   env={**os.environ, "PYTHONPATH": repo_root})
