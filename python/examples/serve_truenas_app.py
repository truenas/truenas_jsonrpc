"""**Example** of a full TrueNAS service. The protocol mixes in **PAM authentication**
(`TrueNASAuthMixin`) + **syslog audit** (`TrueNASAuditMixin`) and adds **privilege
authorization**, served over **TCP + TLS**:

  * **auth** — `TrueNASAuthMixin` installs `$/sessionSetup`: SCRAM (RFC 5802) via the host's
    `pam_truenas` PAM files. The authenticated identity (``username``, ``account_attributes``,
    the connection ``origin``) lands on ``session_state.server_state_internal``.
  * **authz** — methods declare ``roles=[...]`` (surfaced on ``request.roles``); the
    `authorization_handler` enforces them against the user's granted roles. Here ``bob`` has
    ``VM_WRITE`` (may create) but not ``VM_DELETE`` (delete is denied).
  * **audit** — `TrueNASAuditMixin` registers a `SyslogAuditHandler` (and enables the audit
    queue) emitting middleware-style ``@cee:``/``TNAUDIT`` JSON to syslog, drained off the
    dispatch path. Denied and failed calls are audited too.

THIS IS EXAMPLE CODE — it illustrates how the pieces fit and is NOT hardened for production
(e.g. it serves a throwaway self-signed TLS cert and the demo authz rule is trivial).

Requirements (a TrueNAS host, or the ``pam_truenas`` test box): ``pam_truenas`` + the PAM
service files, a provisioned API key for the connecting user, a syslog socket, and
``cryptography`` for the throwaway demo TLS cert.

Run::

    # dev box (pam_truenas test service + /dev/log):
    SCRAM_SERVICE=middleware-scram python examples/serve_truenas_app.py
    # then, in another shell:
    python examples/client_truenas_app.py

Env: ``HOST``, ``PORT``, ``SCRAM_SERVICE`` (PAM service name — prod ``truenas-api-key``),
``AUDIT_SOCKET`` (default ``/dev/log``; prod is the syslog-ng STREAM socket — omit ``address``
to use ``/var/run/syslog-ng/<svc>.sock``), ``TLS_CERT`` / ``TLS_KEY`` (default: a throwaway
self-signed cert).
"""
import asyncio
import os
import socket
import ssl

import msgspec

from truenas_pyjsonrpc import (
    AuthorizationResponse,
    JSONRPCMethod,
    JSONRPCProtocol,
    JSONRPCRequest,
    RequestState,
    ServerInfo,
    SessionState,
)
from truenas_pyjsonrpc.mixins import TrueNASAuditMixin, TrueNASAuthMixin
from truenas_pyjsonrpc_server import JSONRPCServer, TCPConfig

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8443"))
SERVICE = "truenas.vm"
SCRAM_SERVICE = os.environ.get("SCRAM_SERVICE", "truenas-api-key")
AUDIT_SOCKET = os.environ.get("AUDIT_SOCKET", "/dev/log")


# --- the application API -----------------------------------------------------
class NoArgs(msgspec.Struct):
    pass


class SystemInfo(msgspec.Struct):
    version: str
    hostname: str


class VmCreateArgs(msgspec.Struct):
    name: str


class Vm(msgspec.Struct):
    id: int
    name: str


class VmDeleteArgs(msgspec.Struct):
    id: int


class VmDeleteResult(msgspec.Struct):
    deleted: bool


def system_info(request: NoArgs, session_state: SessionState,
                request_state: RequestState) -> SystemInfo:
    return SystemInfo(version="25.04", hostname="truenas")


def vm_create(request: VmCreateArgs, session_state: SessionState,
              request_state: RequestState) -> Vm:
    request_state.set_audit(request.name)            # runtime detail -> "Create VM <name>"
    return Vm(id=42, name=request.name)


def vm_delete(request: VmDeleteArgs, session_state: SessionState,
              request_state: RequestState) -> VmDeleteResult:
    request_state.set_audit(str(request.id))
    return VmDeleteResult(deleted=True)


# --- authorization: methods declare roles; enforce request.roles vs the user's roles ---
# Where a user's granted roles come from is the application's concern; this demo uses a static
# map (a real service would derive them from the identity's privileges / directory groups).
_ROLES_BY_USER = {"bob": {"VM_READ", "VM_WRITE"}}


def authorize(request: JSONRPCRequest,
              session_state: SessionState) -> AuthorizationResponse:
    ident = session_state.server_state_internal      # the identity TrueNASAuth recorded
    username = ident.get("username") if isinstance(ident, dict) else None
    granted = _ROLES_BY_USER.get(username, set())
    # request.roles = the method's declared roles (OR-semantics); empty = no requirement.
    if not request.roles or (set(request.roles) & granted):
        return AuthorizationResponse(True)
    return AuthorizationResponse(
        False, f"{username!r} lacks a required role for {request.method}")


def server_info(session_state: SessionState) -> ServerInfo:
    return ServerInfo(name=SERVICE, version="25.04")  # unauthenticated probe ($/serverInfo)


# --- assemble: a protocol that mixes in PAM auth + syslog audit --------------
# The mixins wire themselves up at construction: TrueNASAuthMixin installs the PAM auth stack
# ($/sessionSetup), TrueNASAuditMixin registers the syslog handler + enables the audit queue.
class VmProtocol(TrueNASAuthMixin, TrueNASAuditMixin, JSONRPCProtocol):
    audit_service = SERVICE
    audit_address = AUDIT_SOCKET
    audit_socktype = socket.SOCK_DGRAM
    auth_scram_service = SCRAM_SERVICE


protocol = VmProtocol(
    [
        JSONRPCMethod("system.info", accepts=NoArgs, returns=SystemInfo, handler=system_info),
        JSONRPCMethod("vm.create", accepts=VmCreateArgs, returns=Vm, handler=vm_create,
                      roles=["VM_WRITE"], audit=True, audit_message="Create VM"),
        JSONRPCMethod("vm.delete", accepts=VmDeleteArgs, returns=VmDeleteResult,
                      handler=vm_delete, roles=["VM_DELETE"], audit=True,
                      audit_message="Delete VM"),
    ],
    name="truenas.vm.v1",
    version="1.0.0",
    authorization_handler=authorize,
)
protocol.register_server_info(server_info, returns=ServerInfo)


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert, key = os.environ.get("TLS_CERT"), os.environ.get("TLS_KEY")
    if cert and key:
        ctx.load_cert_chain(cert, key)
    else:
        ctx.load_cert_chain(*_self_signed())          # throwaway, demo only
    return ctx


async def main() -> None:
    async with JSONRPCServer({"truenas.vm.v1": protocol}, name=SERVICE,
                             tcp_config=TCPConfig(host=HOST, port=PORT,
                                                  ssl=_tls_context())):
        print(f"{SERVICE}: PAM auth + privilege authz + syslog audit on {HOST}:{PORT}\n"
              f"  scram_service={SCRAM_SERVICE}  audit->{AUDIT_SOCKET}  (Ctrl-C to stop)")
        await asyncio.Event().wait()                  # the server drains the audit queue itself


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
    d = tempfile.mkdtemp(prefix="truenas-app-")
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
