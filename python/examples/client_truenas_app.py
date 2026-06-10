"""Drive the full TrueNAS service (``serve_truenas_app.py``): SCRAM-authenticate with an API
key, then exercise the API to show **authentication → authorization → audit** end to end:

  * ``system.info`` → allowed (read), not audited
  * ``vm.create``   → allowed (``bob`` has the ``VM_WRITE`` role), audited as a **success**
  * ``vm.delete``   → **denied** (``bob`` lacks the ``VM_DELETE`` role), audited as a **failure**

The two audited calls produce ``@cee:``/``TNAUDIT`` records on the server's syslog — watch them
with ``journalctl`` (``/dev/log``) or your ``AUDIT_SOCKET`` sink.

THIS IS EXAMPLE CODE — not hardened for production (it disables TLS certificate verification).

Run (after starting the server)::

    USERNAME=bob API_KEY=2-DJpf...  python examples/client_truenas_app.py
"""
import hashlib
import os
import ssl

import truenas_pyscram

from truenas_pyjsonrpc import JsonRpcError
from truenas_pyjsonrpc_client import BaseClient, TCPConfig

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8443"))
USERNAME = os.environ.get("USERNAME", "bob")
API_KEY = os.environ.get(
    "API_KEY", "2-DJpfT7q7dHu6RRfeMwP8aJlGeUOmRWbDKnnzxnsc8F1YAsDNbl8aDM4X1cYwPmcC")


def _scram(scram_type: str, rfc_str: str) -> dict:
    return {"mechanism": {"mechanism": "SCRAM",
                          "scram_type": scram_type, "rfc_str": rfc_str}}


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False                       # demo: server uses a self-signed cert
    ctx.verify_mode = ssl.CERT_NONE                  # production: verify the real server cert
    return ctx


def _scram_login(client: BaseClient, username: str, api_key: str) -> None:
    """Authenticate `client` with a ``<dbid>-<secret>`` API key over SCRAM (RFC 5802)."""
    dbid, secret = api_key.split("-", 1)
    cf = truenas_pyscram.ClientFirstMessage(username=username, api_key_id=int(dbid))
    r = client.setup(_scram("CLIENT_FIRST_MESSAGE", str(cf)))
    sf = truenas_pyscram.ServerFirstMessage(rfc_string=r["response"]["rfc_str"])
    salted = hashlib.pbkdf2_hmac("sha512", secret.encode(), bytes(sf.salt), sf.iterations)
    ad = truenas_pyscram.generate_scram_auth_data(
        salted_password=truenas_pyscram.CryptoDatum(salted),
        salt=sf.salt, iterations=sf.iterations)
    cfin = truenas_pyscram.ClientFinalMessage(
        client_first=cf, server_first=sf, client_key=ad.client_key, stored_key=ad.stored_key)
    r = client.setup_continue(_scram("CLIENT_FINAL_MESSAGE", str(cfin)))
    sfin = truenas_pyscram.ServerFinalMessage(rfc_string=r["response"]["rfc_str"])
    truenas_pyscram.verify_server_signature(                       # mutual auth
        client_first=cf, server_first=sf, client_final=cfin, server_final=sfin,
        server_key=ad.server_key)


def main() -> None:
    client = BaseClient("truenas.vm.v1",
                        tcp_config=TCPConfig(host=HOST, port=PORT, ssl=_tls_context(),
                                             server_hostname="localhost"))
    client.connect()
    _scram_login(client, USERNAME, API_KEY)
    print(f"authenticated as {USERNAME}")

    print("system.info ->", client.call("system.info", {}))        # read: allowed
    print("vm.create   ->", client.call("vm.create", {"name": "demo"}))  # allowed, audited ok
    try:
        client.call("vm.delete", {"id": 42})                       # denied, audited failure
    except JsonRpcError as exc:
        print("vm.delete   -> DENIED:", exc)
    client.close()


if __name__ == "__main__":
    main()
