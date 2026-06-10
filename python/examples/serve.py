"""Drive a protocol through a full session: setup (auth) -> an authorized + audited
call with live progress -> pub/sub -> close.

Each connection has a :class:`SessionState` (``protocol.new_session()``); the server
passes it to every ``dispatch``. With session setup configured, normal methods
require an ESTABLISHED session. Run from the repo root: ``python examples/serve.py``
"""
import hashlib
import json
import tempfile
import threading
import time
import uuid

import msgspec
from api import (
    FileDownloadArgs,
    FileDownloadResult,
    NoParams,
    PoolCreateArgs,
    PoolCreateResult,
    PoolEvent,
)

from truenas_pyjsonrpc import (
    AuthorizationResponse,
    FileTransfer,
    JSONRPCFdTransferMethod,
    JSONRPCMethod,
    JSONRPCProtocol,
    JSONRPCRequest,
    MessageDirection,
    RequestState,
    ServerInfo,
    SessionLifecycle,
    SessionState,
    TransferDirection,
)


class LoginArgs(msgspec.Struct):
    token: str


class LoginResult(msgspec.Struct):
    user: str


def session_setup(request: LoginArgs, session_state: SessionState):
    # Authenticate the connection: record the identity in the (server-side) internal
    # state and ESTABLISH the session; return the client-facing result. A real impl
    # might return SessionLifecycle.INIT and expect a $/sessionSetupContinue (2FA).
    uid, user = (0, "root") if request.token == "root-token" else (1000, "guest")
    session_state.server_state_internal = {"uid": uid, "user": user}
    return SessionLifecycle.ESTABLISHED, LoginResult(user=user)


def pool_create(request: PoolCreateArgs, session_state: SessionState,
                request_state: RequestState) -> PoolCreateResult:
    request_state.set_audit(request.name)          # runtime audit detail
    # progress is enqueued correlated to this request and delivered live by the drain
    for percent, desc in ((0, "starting"), (50, "halfway"), (100, "created")):
        request_state.update_progress(percent=percent, description=desc)
        time.sleep(0.02)
    return PoolCreateResult(id=7, name=request.name)


def file_download_negotiate(request: FileDownloadArgs, session_state: SessionState):
    # Step 1 (on the dispatch thread, after authz): validate + report what's coming.
    # The returned value is sent to the client as the $/transferReady "ready" payload.
    return {"size": request.size}


def file_download_transfer(file_transfer: FileTransfer) -> FileDownloadResult:
    # Step 2 (in the thread pool): exclusive use of the connection's raw socket fd.
    # os.sendfile() a blob straight onto the wire — a stand-in for libzfs writing a
    # zfs-send stream with lzc_send(..., file_transfer.fileno(), ...).
    blob = bytes(i % 251 for i in range(file_transfer.params.size))
    with tempfile.TemporaryFile() as f:
        f.write(blob)
        f.flush()
        f.seek(0)
        sent = file_transfer.sendfile(f)
    return FileDownloadResult(sent=sent, sha256=hashlib.sha256(blob).hexdigest())


def authorize(request: JSONRPCRequest,
              session_state: SessionState) -> AuthorizationResponse:
    ss = session_state.server_state_internal       # the identity set at session setup
    if isinstance(ss, dict) and ss.get("uid") == 0:
        return AuthorizationResponse(True)
    return AuthorizationResponse(False, "root session required")


def audit(request: JSONRPCRequest, response: dict, session_state: SessionState,
          audit_message: str | None = None) -> None:
    outcome = "error" if "error" in response else "ok"
    print(f"audit   : {request.method} session={session_state.session_uuid[:8]} "
          f"-> {outcome} ({audit_message})")


def server_info(session_state: SessionState) -> ServerInfo:
    return ServerInfo(name="truenas", version="25.04")   # unauthenticated probe


protocol = JSONRPCProtocol(
    [
        JSONRPCMethod("pool.create", accepts=PoolCreateArgs,
                      returns=PoolCreateResult, handler=pool_create,
                      audit=True, audit_message="Create pool"),
        # a subscribable topic (server -> client): no handler, a payload schema
        JSONRPCMethod("pool.events", accepts=NoParams, notifies=PoolEvent,
                      direction=MessageDirection.SERVER_CLIENT),
        # a raw-fd transfer (server -> client stream): negotiate + transfer callbacks
        JSONRPCFdTransferMethod("file.download", accepts=FileDownloadArgs,
                                returns=FileDownloadResult,
                                direction=TransferDirection.DOWNLOAD,
                                negotiate=file_download_negotiate,
                                transfer=file_download_transfer,
                                audit=True, audit_message="Download file"),
    ],
    name="truenas",
    authorization_handler=authorize,
    audit_handler=audit,
)
protocol.add_session_setup(JSONRPCMethod(
    "$/sessionSetup", accepts=LoginArgs, returns=LoginResult, handler=session_setup))
protocol.register_server_info(server_info, returns=ServerInfo)


def _msg(method, params=None):
    m = {"jsonrpc": "2.0", "method": method, "id": str(uuid.uuid4())}
    if params is not None:
        m["params"] = params
    return json.dumps(m)


def main() -> None:
    stop = threading.Event()

    def drain_loop() -> None:
        # A real server runs this per connection, routing by the session target;
        # here we just print whatever is emitted.
        while not stop.is_set():
            out = protocol.poll_notification(timeout=0.05)
            if out is not None:
                _session, data = out
                print("notify  :", data.decode())

    drainer = threading.Thread(target=drain_loop, daemon=True)
    drainer.start()

    def d(session, method, params=None):
        out = protocol.dispatch(_msg(method, params), session)
        return out.decode() if out else None

    # a normal method before the session is established is gated
    print("# pool.create before setup:")
    print("response:", d(protocol.new_session(), "pool.create", {"name": "tank"}))

    # $/serverInfo is unauthenticated — works on a fresh (unestablished) session
    print("# server info (no session):")
    print("response:", d(protocol.new_session(), "$/serverInfo"))

    # authenticate as root, then create a pool with live progress
    root = protocol.new_session()
    print("# session setup (root):")
    print("response:", d(root, "$/sessionSetup", {"token": "root-token"}))
    print("# pool.create (authorized):")
    print("response:", d(root, "pool.create", {"name": "tank"}))

    # a guest session establishes but is denied pool.create
    guest = protocol.new_session()
    d(guest, "$/sessionSetup", {"token": "guest-token"})
    print("# pool.create (guest, denied):")
    print("response:", d(guest, "pool.create", {"name": "tank"}))

    # pub/sub on the established root session
    print("# subscribe + publish:")
    print("response:", d(root, "pool.events"))
    protocol.send_notification("pool.events", {"name": "tank", "state": "ONLINE"})
    time.sleep(0.05)                           # let the notify flush

    # close the session
    print("# session close:")
    print("response:", d(root, "$/sessionClose"))

    stop.set()
    drainer.join(timeout=1)


if __name__ == "__main__":
    main()
