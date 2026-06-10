"""Serve a JSON-RPC API over **TCP + TLS** that accepts **SCRAM authentication only**, backed
by the host's ``pam_truenas`` module through :class:`truenas_pyjsonrpc.mixins.auth.TrueNASAuth`.

It shows the "middleware auth stack" pattern for a local TrueNAS service: the server holds no
credentials. ``TrueNASAuth`` relays the SCRAM (RFC 5802) exchange into a ``pam_truenas`` PAM
conversation, which checks the client's proof against the API-key verifier in the system
keyring (``mechanisms={"SCRAM"}`` is the ``TrueNASAuth`` default — SCRAM is the only mechanism
it implements).

THIS IS EXAMPLE CODE — not hardened for production (it serves a throwaway self-signed TLS cert).

Requirements (a TrueNAS host, or the ``pam_truenas`` test box):
  * ``pam_truenas`` installed + the SCRAM PAM service file. Set ``SCRAM_SERVICE`` to match the
    host: production TrueNAS uses ``truenas-api-key``; the pam_truenas test box uses
    ``middleware-scram``.
  * a provisioned API key for the connecting user (e.g. ``midclt call api_key.create``).
  * ``pip install cryptography`` for the throwaway self-signed TLS cert below — **demo only**;
    in production pass a real cert/key via the ``TLS_CERT`` / ``TLS_KEY`` env vars.

Run::

    SCRAM_SERVICE=middleware-scram python examples/serve_truenas_scram.py

then drive it from another shell with ``python examples/client_truenas_scram.py``. Ctrl-C to
stop.
"""
import asyncio
import os
import ssl

import msgspec

from truenas_pyjsonrpc import JSONRPCMethod, JSONRPCProtocol
from truenas_pyjsonrpc.mixins.auth import TrueNASAuth
from truenas_pyjsonrpc_server import JSONRPCServer, TCPConfig

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8443"))
SCRAM_SERVICE = os.environ.get("SCRAM_SERVICE", "truenas-api-key")


class NoArgs(msgspec.Struct):
    pass


class WhoAmI(msgspec.Struct):
    username: str
    account_attributes: list[str]


def _whoami(request: NoArgs, session_state, request_state) -> WhoAmI:
    # server_state_internal is the identity TrueNASAuth recorded when SCRAM succeeded.
    ident = session_state.server_state_internal
    return WhoAmI(username=ident["username"],
                  account_attributes=list(ident["account_attributes"]))


protocol = JSONRPCProtocol(
    [JSONRPCMethod("whoami", accepts=NoArgs, returns=WhoAmI, handler=_whoami)],
    name="truenas.example.v1")

# SCRAM ONLY — every other mechanism is refused.
TrueNASAuth(mechanisms={"SCRAM"}, scram_service=SCRAM_SERVICE).install(protocol)


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert, key = os.environ.get("TLS_CERT"), os.environ.get("TLS_KEY")
    if cert and key:
        ctx.load_cert_chain(cert, key)
    else:
        ctx.load_cert_chain(*_self_signed())          # throwaway, demo only
    return ctx


async def main() -> None:
    async with JSONRPCServer(
            {"truenas.example.v1": protocol}, name="truenas-scram-demo",
            tcp_config=TCPConfig(host=HOST, port=PORT, ssl=_tls_context())) as server:
        print(f"SCRAM-only JSON-RPC over TLS on {HOST}:{PORT} "
              f"(service={SCRAM_SERVICE}, Ctrl-C to stop)")
        await asyncio.Event().wait()                  # run until interrupted


def _self_signed() -> tuple[str, str]:
    """Write a throwaway self-signed cert/key to a temp dir; return their paths (demo only)."""
    import datetime
    import tempfile

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp(prefix="scram-demo-")
    certfile, keyfile = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
    with open(certfile, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(keyfile, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    return certfile, keyfile


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nstopped")
