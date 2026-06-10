"""End-to-end tests for the optional WebSocket transport (server + client), driven by
the library's own thread-safe BaseClient over ``ws://`` / ``wss://``. Skipped entirely
when the optional ``websockets`` dependency is not installed."""
import queue
import ssl
import tempfile
import uuid

import pytest

pytest.importorskip("websockets")

from truenas_pyjsonrpc_client import BaseClient, ClientError, UnixConfig, WebSocketConfig
from truenas_pyjsonrpc_server import UnixConfig as SrvUnixConfig
from truenas_pyjsonrpc_server import WebSocketConfig as SrvWebSocketConfig
from test_server import _build, _build_peer_probe, _self_signed, _tmp_sock
from test_client import _ServerThread
from test_transfer import _build as _build_transfer


def _ws(**kw) -> SrvWebSocketConfig:
    return SrvWebSocketConfig(host="127.0.0.1", port=0, **kw)


def _ws_port(srv) -> int:
    return srv.server._ws_servers[0].sockets[0].getsockname()[1]


def _client(srv, **kw) -> BaseClient:
    return BaseClient("v1", websocket_config=WebSocketConfig(
        host="127.0.0.1", port=_ws_port(srv), **kw))


def test_ws_negotiate_setup_and_call():
    srv = _ServerThread(_build(), websocket_config=_ws()).start()
    try:
        c = _client(srv)
        neg = c.connect()
        assert neg == {"protocol": "v1", "server": "test", "available": ["v1"]}
        assert c.setup({"token": "ok"}) == {"user": "root"}      # auth over the WS framing
        assert c.call("echo", {"msg": "ws"}) == {"msg": "ws"}
        c.close()
        with pytest.raises(ClientError):                         # closed -> no more calls
            c.call("echo", {"msg": "x"})
    finally:
        srv.stop()


def test_ws_notifications_to_queue():
    proto = _build()
    srv = _ServerThread(proto, websocket_config=_ws()).start()
    try:
        c = _client(srv)
        c.connect()
        c.setup({"token": "ok"})
        uuid.UUID(c.call("events"))                              # subscribe -> sub id
        proto.send_notification("events", {"x": 9})              # server publishes
        method, params = c.notifications.get(timeout=5)
        assert method == "events" and params == {"x": 9}
        c.close()
    finally:
        srv.stop()


def test_ws_progress_live():
    srv = _ServerThread(_build(), websocket_config=_ws()).start()
    try:
        c = _client(srv)
        c.connect()
        c.setup({"token": "ok"})
        got: "queue.Queue[dict]" = queue.Queue()
        assert c.call("progress", progress=got.put) == {"msg": "done"}
        seen = [got.get(timeout=5) for _ in range(3)]
        assert [p.get("percent") for p in seen] == [0, 50, 100]
        c.close()
    finally:
        srv.stop()


def test_ws_subscribe_callback():
    proto = _build()
    srv = _ServerThread(proto, websocket_config=_ws()).start()
    try:
        c = _client(srv)
        c.connect()
        c.setup({"token": "ok"})
        got: "queue.Queue[dict]" = queue.Queue()
        c.subscribe("events", callback=got.put)
        proto.send_notification("events", {"x": 9})
        assert got.get(timeout=5) == {"x": 9}                    # routed to the callback...
        with pytest.raises(queue.Empty):                         # ...not the global queue
            c.notifications.get(timeout=0.3)
        c.close()
    finally:
        srv.stop()


def test_ws_transfer_rejected():
    # The transfer protocol has no session setup, so calls work right after connect.
    srv = _ServerThread(_build_transfer(), websocket_config=_ws()).start()
    try:
        c = _client(srv)
        c.connect()
        with pytest.raises(ClientError, match="plain or kTLS"):
            c.transfer("file.download", {"size": 1024}, callback=lambda ft: None)
        # the rejection leaves the connection fully usable
        assert c.call("echo", {"msg": "after"}) == {"msg": "after"}
        c.close()
    finally:
        srv.stop()


def test_wss_round_trip_stamps_tls_peer():
    pytest.importorskip("cryptography")
    certfile, keyfile = _self_signed(tempfile.mkdtemp(dir="/tmp"))
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile, keyfile)
    # _build_peer_probe has a `whoami` method and no session setup.
    srv = _ServerThread(_build_peer_probe(), websocket_config=_ws(ssl=server_ctx)).start()
    try:
        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE                   # accept the self-signed cert
        c = _client(srv, ssl=client_ctx, server_hostname="localhost")
        c.connect()
        info = c.call("whoami")
        assert info["transport"] == "tcp"
        assert info["tls"] is True                               # wss:// -> Peer stamped TLS
        assert info["cipher"]                                    # a cipher was negotiated
        c.close()
    finally:
        srv.stop()


def test_ws_and_unix_on_one_server():
    path = _tmp_sock()
    proto = _build()
    srv = _ServerThread(proto, unix_config=SrvUnixConfig(path=path),
                        websocket_config=_ws()).start()
    try:
        cu = BaseClient("v1", unix_config=UnixConfig(path=path))
        cw = _client(srv)
        for c in (cu, cw):
            c.connect()
            c.setup({"token": "ok"})
        assert cu.call("echo", {"msg": "u"}) == {"msg": "u"}     # unix transport
        assert cw.call("echo", {"msg": "w"}) == {"msg": "w"}     # websocket transport
        uuid.UUID(cu.call("events"))
        uuid.UUID(cw.call("events"))
        proto.send_notification("events", {"x": 5})              # fans out to both conns
        assert cu.notifications.get(timeout=5) == ("events", {"x": 5})
        assert cw.notifications.get(timeout=5) == ("events", {"x": 5})
        cu.close()
        cw.close()
    finally:
        srv.stop()
