"""Authenticate to the SCRAM-only TCP+TLS server (``serve_truenas_scram.py``) with a TrueNAS
**API key**, using ``truenas_pyscram`` for the RFC 5802 exchange.

A TrueNAS API key is ``"<dbid>-<secret>"`` (e.g. from ``midclt call api_key.create``). The
client:

  1. sends ``client-first`` carrying the username and the key's database id (``dbid``);
  2. derives its SCRAM keys from ``<secret>`` + the server's salt/iterations
     (``SaltedPassword = Hi(secret, salt, i)`` = PBKDF2-HMAC-SHA512) and sends ``client-final``;
  3. verifies the server's signature (mutual auth) before calling a method.

The secret never crosses the wire.

THIS IS EXAMPLE CODE — not hardened for production (it disables TLS certificate verification).

Run (after starting the server)::

    USERNAME=bob API_KEY=2-DJpf...  python examples/client_truenas_scram.py
"""
import hashlib
import os
import ssl

import truenas_pyscram

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
    ctx.check_hostname = False                    # demo: the server uses a self-signed cert
    ctx.verify_mode = ssl.CERT_NONE               # production: verify the real server cert
    return ctx


def main() -> None:
    dbid, secret = API_KEY.split("-", 1)
    api_key_id = int(dbid)

    client = BaseClient("truenas.example.v1",
                        tcp_config=TCPConfig(host=HOST, port=PORT, ssl=_tls_context(),
                                             server_hostname="localhost"))
    client.connect()

    # 1. client-first: username + the API key's database id.
    cf = truenas_pyscram.ClientFirstMessage(username=USERNAME, api_key_id=api_key_id)
    r = client.setup(_scram("CLIENT_FIRST_MESSAGE", str(cf)))
    sf = truenas_pyscram.ServerFirstMessage(rfc_string=r["response"]["rfc_str"])

    # 2. derive our keys from <secret> + the server's salt/iterations; build client-final.
    salted = hashlib.pbkdf2_hmac("sha512", secret.encode(), bytes(sf.salt), sf.iterations)
    ad = truenas_pyscram.generate_scram_auth_data(
        salted_password=truenas_pyscram.CryptoDatum(salted),
        salt=sf.salt, iterations=sf.iterations)
    cfin = truenas_pyscram.ClientFinalMessage(
        client_first=cf, server_first=sf, client_key=ad.client_key, stored_key=ad.stored_key)

    # 3. client-final -> server-final; verify the server proved itself (mutual auth).
    r = client.setup_continue(_scram("CLIENT_FINAL_MESSAGE", str(cfin)))
    sfin = truenas_pyscram.ServerFinalMessage(rfc_string=r["response"]["rfc_str"])
    truenas_pyscram.verify_server_signature(
        client_first=cf, server_first=sf, client_final=cfin, server_final=sfin,
        server_key=ad.server_key)
    print("authenticated; user_info:", r["response"].get("user_info"))

    # 4. the session is ESTABLISHED — call a normal method.
    print("whoami:", client.call("whoami", {}))
    client.close()


if __name__ == "__main__":
    main()
