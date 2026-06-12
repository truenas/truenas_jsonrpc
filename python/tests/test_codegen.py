"""Tests for the repo-root codegen tool: generate a typed client from a live
protocol, then exercise it end-to-end against a real server."""
import hashlib
import io
import queue
import sys
import tempfile
import uuid

import msgspec
import pytest

from truenas_pyjsonrpc import JSONRPCMethod, JSONRPCProtocol
from truenas_pyjsonrpc_client import UnixConfig
from truenas_pyjsonrpc_server import UnixConfig as SrvUnixConfig

from codegen import _class_name_for, _pyname, generate, main
from test_server import Event, EchoArgs, NoArgs, Result, _build, _tmp_sock
from test_client import _ServerThread
from test_transfer import (
    SIZE,
    DownloadArgs,
    DownloadResult,
    UploadArgs,
    UploadResult,
    _blob,
)
from test_transfer import _build as _build_transfer


def _gen_client_class(proto=None):
    """generate() -> exec the source -> return the generated client class."""
    proto = proto if proto is not None else _build()
    src = generate(proto)
    ns: dict = {}
    exec(compile(src, "<generated>", "exec"), ns)
    return ns["V1Client"]


def test_pyname_and_class_name():
    assert _pyname("pool.create") == "pool_create"
    assert _pyname("events") == "events"
    assert _pyname("$/weird-name") == "__weird_name"
    assert _pyname("2fast") == "_2fast"
    assert _pyname("class") == "class_"        # keyword -> suffixed so `def` isn't a SyntaxError
    assert _pyname("import") == "import_"
    assert _pyname("match") == "match"         # soft keyword: valid as a method name, left as-is
    assert _class_name_for("v1") == "V1Client"
    assert _class_name_for("directoryservices.v1") == "DirectoryservicesV1Client"


def test_generate_skips_control_methods_and_reuses_types():
    src = generate(_build())
    assert "from test_server import EchoArgs, Event, NoArgs, Result" in src
    assert ("def echo(self, request: EchoArgs, *, progress: "
            "Callable[[Any], None] | None = None) -> Result:") in src
    assert "self._typed_call('echo', request, Result, progress=progress)" in src
    assert ("def subscribe_events(self, request: NoArgs, *, callback: "
            "Callable[[Event], None] | None = None) -> str:") in src
    assert "callback=callback, notifies=Event)" in src
    assert "TOPICS: dict[str, type] = {'events': Event}" in src
    assert "$/sessionSetup" not in src          # control methods are not generated
    assert "def slow(self, request: NoArgs, *, progress:" in src


def test_generate_requires_a_protocol_name():
    # A JSONRPCProtocol always carries a name now, but codegen still guards the
    # explicit override path: an empty protocol_name has nothing to $/negotiate.
    proto = JSONRPCProtocol(
        [JSONRPCMethod("echo", accepts=EchoArgs, returns=Result)],
        name="v1", version="1.0.0")
    with pytest.raises(ValueError, match="no protocol name"):
        generate(proto, protocol_name="")


def test_generate_rejects_main_module_structs():
    class Local(msgspec.Struct):                # __module__ == this test module...
        a: int
    Local.__module__ = "__main__"               # ...pretend it's __main__
    proto = JSONRPCProtocol([
        JSONRPCMethod("x", accepts=Local, returns=Result)], name="v1", version="1.0.0")
    with pytest.raises(ValueError, match="__main__"):
        generate(proto)


def test_generate_keyword_method_name_is_valid_python():
    # A method named after a Python keyword must not emit `def class(...)` (a SyntaxError).
    proto = JSONRPCProtocol(
        [JSONRPCMethod("class", accepts=EchoArgs, returns=Result)],
        name="v1", version="1.0.0")
    src = generate(proto)
    assert "def class_(self" in src
    compile(src, "<generated>", "exec")         # would raise SyntaxError before the fix


def test_generate_rejects_identifier_collision():
    # Two wire names mapping to the same Python identifier would silently shadow each other.
    proto = JSONRPCProtocol([
        JSONRPCMethod("pool.create", accepts=EchoArgs, returns=Result),
        JSONRPCMethod("pool_create", accepts=EchoArgs, returns=Result),
    ], name="v1", version="1.0.0")
    with pytest.raises(ValueError, match="collision"):
        generate(proto)


def test_generate_rejects_baseclient_member_collision():
    # A method whose identifier collides with an inherited BaseClient method (e.g. `connect`)
    # would override it with the wrong signature and break the client at runtime.
    proto = JSONRPCProtocol(
        [JSONRPCMethod("connect", accepts=EchoArgs, returns=Result)],
        name="v1", version="1.0.0")
    with pytest.raises(ValueError, match="collision"):
        generate(proto)


def test_generated_client_typed_round_trip():
    path = _tmp_sock()
    srv = _ServerThread(_build(), unix_config=SrvUnixConfig(path=path)).start()
    try:
        client_cls = _gen_client_class()
        c = client_cls(unix_config=UnixConfig(path=path))
        c.connect()
        c.setup({"token": "ok"})
        result = c.echo(EchoArgs(msg="hi"))     # typed in, typed out
        assert isinstance(result, Result)
        assert result.msg == "hi"
        c.close()
    finally:
        srv.stop()


def test_generated_client_typed_subscription():
    path = _tmp_sock()
    proto = _build()
    srv = _ServerThread(proto, unix_config=SrvUnixConfig(path=path)).start()
    try:
        client_cls = _gen_client_class()
        c = client_cls(unix_config=UnixConfig(path=path))
        c.connect()
        c.setup({"token": "ok"})
        sub_id = c.subscribe_events(NoArgs())
        uuid.UUID(sub_id)                        # the ack is a subscription id
        proto.send_notification("events", {"x": 11})
        method, params = c.notifications.get(timeout=5)
        assert method == "events"
        evt = msgspec.convert(params, client_cls.TOPICS[method])  # decode via TOPICS
        assert isinstance(evt, Event)
        assert evt.x == 11
        c.close()
    finally:
        srv.stop()


def test_generated_client_typed_subscription_callback():
    path = _tmp_sock()
    proto = _build()
    srv = _ServerThread(proto, unix_config=SrvUnixConfig(path=path)).start()
    try:
        client_cls = _gen_client_class()
        c = client_cls(unix_config=UnixConfig(path=path))
        c.connect()
        c.setup({"token": "ok"})
        got: "queue.Queue[Event]" = queue.Queue()    # callback runs on the IO thread
        c.subscribe_events(NoArgs(), callback=got.put)
        proto.send_notification("events", {"x": 11})
        evt = got.get(timeout=5)
        assert isinstance(evt, Event)                # decoded into the notifies Struct
        assert evt.x == 11
        c.close()
    finally:
        srv.stop()


def test_generate_transfer_methods():
    src = generate(_build_transfer())
    assert "from truenas_pyjsonrpc import FileTransfer" in src
    assert ("def file_download(self, request: DownloadArgs, *, "
            "callback: Callable[[FileTransfer], object]) -> DownloadResult:") in src
    assert ("self._typed_transfer('file.download', request, DownloadResult, "
            "callback)") in src
    assert ("def file_upload(self, request: UploadArgs, *, "
            "callback: Callable[[FileTransfer], object]) -> UploadResult:") in src
    compile(src, "<generated>", "exec")          # the emitted source parses


def test_generated_client_transfer_round_trip():
    """The generated typed transfer methods drive a real fd handoff both directions."""
    path = _tmp_sock()
    proto = _build_transfer()
    srv = _ServerThread(proto, unix_config=SrvUnixConfig(path=path)).start()
    try:
        ns: dict = {}
        exec(compile(generate(proto), "<generated>", "exec"), ns)
        c = ns["V1Client"](unix_config=UnixConfig(path=path))   # transfer proto has no session setup
        c.connect()

        buf = io.BytesIO()                        # DOWNLOAD: server produces, we consume
        dl = c.file_download(DownloadArgs(size=SIZE),
                             callback=lambda ft: ft.recvfile(buf, ft.params["size"]))
        assert isinstance(dl, DownloadResult)
        assert dl.sent == SIZE
        assert hashlib.sha256(buf.getvalue()).hexdigest() == dl.sha256

        blob = _blob(SIZE)                        # UPLOAD: we produce, server consumes
        sha = hashlib.sha256(blob).hexdigest()

        def send_cb(ft):
            with tempfile.TemporaryFile() as f:
                f.write(blob)
                f.flush()
                f.seek(0)
                ft.sendfile(f)

        ul = c.file_upload(UploadArgs(size=SIZE, sha256=sha), callback=send_cb)
        assert isinstance(ul, UploadResult)
        assert ul.received == SIZE and ul.ok
        c.close()
    finally:
        srv.stop()


def test_codegen_cli_writes_importable_source(tmp_path):
    mod = tmp_path / "myapi.py"
    mod.write_text(
        "import msgspec\n"
        "from truenas_pyjsonrpc import JSONRPCProtocol, JSONRPCMethod\n"
        "class Ping(msgspec.Struct):\n"
        "    n: int\n"
        "protocol = JSONRPCProtocol(\n"
        "    [JSONRPCMethod('ping', accepts=Ping, returns=Ping)],\n"
        "    name='cli.v1', version='1.0.0')\n")
    out = tmp_path / "gen.py"
    sys.path.insert(0, str(tmp_path))
    try:
        rc = main(["myapi:protocol", "--out", str(out)])
    finally:
        sys.path.remove(str(tmp_path))
        sys.modules.pop("myapi", None)
    assert rc == 0
    text = out.read_text()
    assert "class CliV1Client(BaseClient):" in text
    assert "from myapi import Ping" in text
    assert ("def ping(self, request: Ping, *, progress: "
            "Callable[[Any], None] | None = None) -> Ping:") in text
    compile(text, str(out), "exec")              # the emitted source parses
