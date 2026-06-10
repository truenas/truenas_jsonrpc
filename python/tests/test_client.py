"""End-to-end tests for truenas_pyjsonrpc_client against a live
truenas_pyjsonrpc_server (server on its own loop+thread; the sync client drives it).
"""
import asyncio
import queue
import ssl
import tempfile
import threading
import uuid

import pytest

from truenas_pyjsonrpc import JSONRPCError, JsonRpcError
from truenas_pyjsonrpc_client import BaseClient, ClientError, TCPConfig, UnixConfig
from truenas_pyjsonrpc_server import JSONRPCServer
from truenas_pyjsonrpc_server import TCPConfig as SrvTCPConfig
from truenas_pyjsonrpc_server import UnixConfig as SrvUnixConfig
from test_server import _build, _self_signed, _tmp_sock


class _ServerThread:
    """Run a JSONRPCServer on a dedicated loop in a background thread."""

    def __init__(self, proto, **kw):
        self.proto = proto
        self.server = JSONRPCServer({"v1": proto}, name="test", **kw)
        self.loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.server.start())
        self._ready.set()
        self.loop.run_forever()

    def start(self):
        self._thread.start()
        assert self._ready.wait(5)
        return self

    def stop(self):
        asyncio.run_coroutine_threadsafe(self.server.aclose(), self.loop).result(5)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self._thread.join(5)
        self.loop.close()

    @property
    def port(self):
        servers = self.server._servers or self.server._ws_servers
        return servers[0].sockets[0].getsockname()[1]


def test_round_trip_unix():
    path = _tmp_sock()
    srv = _ServerThread(_build(), unix_config=SrvUnixConfig(path=path)).start()
    try:
        c = BaseClient("v1", unix_config=UnixConfig(path=path))
        neg = c.connect()
        assert neg == {"protocol": "v1", "server": "test", "available": ["v1"]}
        assert c.setup({"token": "ok"}) == {"user": "root"}
        assert c.call("echo", {"msg": "hi"}) == {"msg": "hi"}
        c.close()
        with pytest.raises(ClientError):                 # closed -> no more calls
            c.call("echo", {"msg": "x"})
    finally:
        srv.stop()


def test_error_responses_raise_jsonrpcerror():
    path = _tmp_sock()
    srv = _ServerThread(_build(), unix_config=SrvUnixConfig(path=path)).start()
    try:
        c = BaseClient("v1", unix_config=UnixConfig(path=path))
        c.connect()
        with pytest.raises(JsonRpcError) as gated:       # gated before setup
            c.call("echo", {"msg": "x"})
        assert gated.value.code == JSONRPCError.SESSION_NOT_ESTABLISHED
        with pytest.raises(JsonRpcError) as bad:         # bad credentials
            c.setup({"token": "nope"})
        assert bad.value.code == JSONRPCError.NOT_AUTHORIZED
        c.close()
    finally:
        srv.stop()


def test_notifications_delivered_to_queue():
    path = _tmp_sock()
    proto = _build()
    srv = _ServerThread(proto, unix_config=SrvUnixConfig(path=path)).start()
    try:
        c = BaseClient("v1", unix_config=UnixConfig(path=path))
        c.connect()
        c.setup({"token": "ok"})
        uuid.UUID(c.call("events"))                      # subscribe -> sub id
        proto.send_notification("events", {"x": 9})      # server publishes
        method, params = c.notifications.get(timeout=5)
        assert method == "events" and params == {"x": 9}
        c.close()
    finally:
        srv.stop()


def test_progress_notifications_arrive():
    path = _tmp_sock()
    srv = _ServerThread(_build(), unix_config=SrvUnixConfig(path=path)).start()
    try:
        c = BaseClient("v1", unix_config=UnixConfig(path=path))
        c.connect()
        c.setup({"token": "ok"})
        assert c.call("progress") == {"msg": "done"}     # progress streamed during
        got = []
        while True:
            try:
                got.append(c.notifications.get(timeout=0.5))
            except queue.Empty:
                break
        assert any(m == "$/progress" for m, _ in got)
        c.close()
    finally:
        srv.stop()


def test_multithreaded_calls_correlate():
    path = _tmp_sock()
    srv = _ServerThread(_build(), unix_config=SrvUnixConfig(path=path)).start()
    try:
        c = BaseClient("v1", unix_config=UnixConfig(path=path))
        c.connect()
        c.setup({"token": "ok"})
        errors = []

        def worker(n):
            for i in range(20):
                tag = f"{n}-{i}"
                try:
                    r = c.call("echo", {"msg": tag})
                except Exception as e:               # a raised call (timeout / mis-routed future)
                    errors.append((tag, e))          # must surface, not die silently in the thread
                    return
                if r != {"msg": tag}:
                    errors.append((tag, r))

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []                              # all 160 correlated by id
        c.close()
    finally:
        srv.stop()


def test_tcp_and_context_manager():
    srv = _ServerThread(_build(),
                        tcp_config=SrvTCPConfig(host="127.0.0.1", port=0)).start()
    try:
        with BaseClient("v1", tcp_config=TCPConfig(host="127.0.0.1", port=srv.port)) as c:
            c.setup({"token": "ok"})
            assert c.call("echo", {"msg": "tcp"}) == {"msg": "tcp"}
    finally:
        srv.stop()


def test_tls_round_trip():
    pytest.importorskip("cryptography")
    certfile, keyfile = _self_signed(tempfile.mkdtemp(dir="/tmp"))
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile, keyfile)
    srv = _ServerThread(_build(),
                        tcp_config=SrvTCPConfig(host="127.0.0.1", port=0,
                                                ssl=server_ctx)).start()
    try:
        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE          # accept the self-signed cert
        with BaseClient("v1", tcp_config=TCPConfig(host="127.0.0.1", port=srv.port,
                                                   ssl=client_ctx,
                                                   server_hostname="localhost")) as c:
            c.setup({"token": "ok"})
            assert c.call("echo", {"msg": "tls"}) == {"msg": "tls"}
    finally:
        srv.stop()


def test_subscribe_with_callback():
    path = _tmp_sock()
    proto = _build()
    srv = _ServerThread(proto, unix_config=SrvUnixConfig(path=path)).start()
    try:
        c = BaseClient("v1", unix_config=UnixConfig(path=path))
        c.connect()
        c.setup({"token": "ok"})
        got: "queue.Queue[dict]" = queue.Queue()      # cb runs on the backchannel thread
        sub_id = c.subscribe("events", callback=got.put)
        uuid.UUID(sub_id)
        proto.send_notification("events", {"x": 9})
        assert got.get(timeout=5) == {"x": 9}         # routed to the callback...
        with pytest.raises(queue.Empty):              # ...not the global queue
            c.notifications.get(timeout=0.3)
        c.close()
    finally:
        srv.stop()


def test_per_call_progress_callback():
    path = _tmp_sock()
    srv = _ServerThread(_build(), unix_config=SrvUnixConfig(path=path)).start()
    try:
        c = BaseClient("v1", unix_config=UnixConfig(path=path))
        c.connect()
        c.setup({"token": "ok"})
        got: "queue.Queue[dict]" = queue.Queue()
        assert c.call("progress", progress=got.put) == {"msg": "done"}
        # Callbacks run on the backchannel thread, so progress is decoupled from call()'s
        # return — poll for the three updates rather than assume they're all in yet.
        seen = [got.get(timeout=5) for _ in range(3)]
        assert [p.get("percent") for p in seen] == [0, 50, 100]
        assert all(p["id"] for p in seen)             # correlated to the request id
        with pytest.raises(queue.Empty):              # didn't leak to the global queue
            c.notifications.get(timeout=0.3)
        c.close()
    finally:
        srv.stop()


def test_unsubscribe_cancels_server_side():
    path = _tmp_sock()
    proto = _build()
    srv = _ServerThread(proto, unix_config=SrvUnixConfig(path=path)).start()
    try:
        c = BaseClient("v1", unix_config=UnixConfig(path=path))
        c.connect()
        c.setup({"token": "ok"})
        got: "queue.Queue[dict]" = queue.Queue()
        sub_id = c.subscribe("events", callback=got.put)
        proto.send_notification("events", {"x": 1})
        assert got.get(timeout=5) == {"x": 1}
        c.unsubscribe(sub_id)                         # wire $/cancelRequest -> server drops it
        assert not proto._subscriptions.get("events")  # gone server-side
        proto.send_notification("events", {"x": 2})   # delivered to nobody now
        with pytest.raises(queue.Empty):
            got.get(timeout=0.3)                      # not the callback
        with pytest.raises(queue.Empty):
            c.notifications.get(timeout=0.3)          # not the fallback queue either
        c.close()
    finally:
        srv.stop()


def test_callback_may_call_client():
    path = _tmp_sock()
    proto = _build()
    srv = _ServerThread(proto, unix_config=SrvUnixConfig(path=path)).start()
    try:
        c = BaseClient("v1", unix_config=UnixConfig(path=path))
        c.connect()
        c.setup({"token": "ok"})
        result: "queue.Queue[dict]" = queue.Queue()

        def react(event):                             # runs on the backchannel thread
            result.put(c.call("echo", {"msg": str(event["x"])}))  # re-enters call()

        c.subscribe("events", callback=react)
        proto.send_notification("events", {"x": 42})
        assert result.get(timeout=5) == {"msg": "42"}
        c.close()
    finally:
        srv.stop()


def test_callback_exception_does_not_kill_connection():
    path = _tmp_sock()
    proto = _build()
    srv = _ServerThread(proto, unix_config=SrvUnixConfig(path=path)).start()
    try:
        c = BaseClient("v1", unix_config=UnixConfig(path=path))
        c.connect()
        c.setup({"token": "ok"})

        def boom(_event):
            raise RuntimeError("callback blew up")

        c.subscribe("events", callback=boom)
        proto.send_notification("events", {"x": 1})   # cb raises -> swallowed + logged
        # the connection survived: a normal call still round-trips
        assert c.call("echo", {"msg": "alive"}) == {"msg": "alive"}
        c.close()
    finally:
        srv.stop()
