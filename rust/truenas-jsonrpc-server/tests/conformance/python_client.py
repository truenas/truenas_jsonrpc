#!/usr/bin/env python3
"""Cross-language smoke client: drive the **Rust** `truenas-jsonrpc-server` with the canonical
**Python** `truenas_pyjsonrpc_client` over an AF_UNIX socket, proving the two interoperate on
the wire (length-prefixed JSON framing + `$/negotiate` + dispatch).

Usage: python_client.py <unix-socket-path>
Prints a JSON object {"negotiate": <result>, "add": <result>} on success; exits non-zero on
any error.
"""
import json
import sys

from truenas_pyjsonrpc_client import BaseClient, UnixConfig

sock = sys.argv[1]
client = BaseClient("main", unix_config=UnixConfig(path=sock))
try:
    negotiate = client.connect()          # $/negotiate
    add = client.call("math.add", {"a": 2, "b": 40})
finally:
    client.close()

print(json.dumps({"negotiate": negotiate, "add": add}))
