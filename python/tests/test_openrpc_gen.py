"""OpenRPC document generation (openrpc_gen.generate_openrpc / main) tests.

Structural assertions only — no jsonschema/openrpc validator dependency (the project
depends on msgspec alone)."""
import json
import sys

import msgspec
import pytest

from truenas_pyjsonrpc import (
    JSONRPCError,
    JSONRPCFdPassMethod,
    JSONRPCFdTransferMethod,
    JSONRPCMethod,
    JSONRPCProtocol,
    MessageDirection,
    TransferDirection,
)
from openrpc_gen import OPENRPC_VERSION, generate_openrpc, main


# --- api types ---------------------------------------------------------------
class Nested(msgspec.Struct):
    x: int


class PoolCreateArgs(msgspec.Struct):
    name: str                                          # required
    nested: Nested                                     # required, pulls in Nested
    size: int = 0                                      # optional (has a default)


class PoolCreateResult(msgspec.Struct):
    id: int


class PoolEvent(msgspec.Struct):
    x: int


class NoArgs(msgspec.Struct):
    pass


class DownloadArgs(msgspec.Struct):
    path: str


class DownloadResult(msgspec.Struct):
    sent: int


class UploadArgs(msgspec.Struct):
    path: str


class UploadResult(msgspec.Struct):
    ok: bool


# --- handlers / callbacks ----------------------------------------------------
def _create(request, session_state, request_state):
    return PoolCreateResult(id=1)


def _ping(request, session_state, request_state):
    return None                                        # void method (no `returns`)


def _negotiate(request, session_state):
    return True


def _transfer(ft):
    return None


# --- protocol builders -------------------------------------------------------
def _build(**kw) -> JSONRPCProtocol:
    kw.setdefault("name", "v1")
    kw.setdefault("version", "1.0.0")
    return JSONRPCProtocol([
        JSONRPCMethod("pool.create", accepts=PoolCreateArgs, returns=PoolCreateResult,
                      doc="Make a pool.\n\nLong description here.", handler=_create,
                      roles=["POOL_WRITE"]),
        JSONRPCMethod("pool.events", accepts=NoArgs, notifies=PoolEvent,
                      direction=MessageDirection.SERVER_CLIENT),
        JSONRPCMethod("pool.ping", accepts=NoArgs, handler=_ping),     # void method
    ], **kw)


def _build_transfer(**kw) -> JSONRPCProtocol:
    kw.setdefault("name", "transfer.v1")
    kw.setdefault("version", "1.0.0")
    return JSONRPCProtocol([
        JSONRPCFdTransferMethod("file.download", accepts=DownloadArgs,
                                returns=DownloadResult,
                                direction=TransferDirection.DOWNLOAD,
                                negotiate=_negotiate, transfer=_transfer),
        JSONRPCFdTransferMethod("file.upload", accepts=UploadArgs, returns=UploadResult,
                                direction=TransferDirection.UPLOAD,
                                negotiate=_negotiate, transfer=_transfer),
        JSONRPCFdPassMethod("fd.pass", accepts=DownloadArgs, returns=DownloadResult,
                            direction=TransferDirection.DOWNLOAD,
                            negotiate=_negotiate, transfer=_transfer),
    ], **kw)


def _method(doc, name="m"):
    return next(m for m in doc["methods"] if m["name"] == name)


# --- 1. envelope -------------------------------------------------------------
def test_document_envelope():
    doc = generate_openrpc(_build())
    assert doc["openrpc"] == OPENRPC_VERSION == "1.3.2"
    assert set(doc["info"]) == {"title", "version"}
    assert isinstance(doc["methods"], list) and doc["methods"]
    assert "schemas" in doc["components"]


# --- 2. info.title/version come from the protocol (no 0.0.0), overridable ----
def test_info_uses_protocol_identity_and_overrides():
    doc = generate_openrpc(_build(name="v1", version="2.5.0"))
    assert doc["info"] == {"title": "v1", "version": "2.5.0"}     # real version, not 0.0.0

    over = generate_openrpc(_build(name="v1", version="2.5.0"),
                            title="My API", version="9.9", openrpc_version="1.2.6")
    assert over["info"] == {"title": "My API", "version": "9.9"}
    assert over["openrpc"] == "1.2.6"


# --- 3. control methods are skipped ------------------------------------------
def test_skips_control_methods():
    p = _build()
    # $/ and rpc. names cannot go through register(); inject to exercise the filter.
    p._methods["$/secret"] = JSONRPCMethod("$/secret", accepts=NoArgs, handler=_ping)
    p._methods["rpc.discover"] = JSONRPCMethod("rpc.discover", accepts=NoArgs,
                                               handler=_ping)
    names = [m["name"] for m in generate_openrpc(p)["methods"]]
    assert "$/secret" not in names and "rpc.discover" not in names
    assert "pool.create" in names


# --- 4. normal method shape --------------------------------------------------
def test_normal_method_shape():
    pc = _method(generate_openrpc(_build()), "pool.create")
    assert pc["paramStructure"] == "by-name"
    assert pc["x-direction"] == "client_server"
    assert pc["summary"] == "Make a pool."                        # first line of the doc
    assert "Long description" in pc["description"]                # full text (multi-line)
    assert pc["result"] == {"name": "PoolCreateResult",
                            "schema": {"$ref": "#/components/schemas/PoolCreateResult"}}


# --- 5. params decomposition (required first, optional keeps default) ---------
def test_params_decomposition():
    pc = _method(generate_openrpc(_build()), "pool.create")
    params = pc["params"]
    required = {p["name"]: p["required"] for p in params}
    assert required == {"name": True, "nested": True, "size": False}
    names = [p["name"] for p in params]
    assert names.index("size") == len(names) - 1                  # optional comes last
    size_schema = next(p["schema"] for p in params if p["name"] == "size")
    assert size_schema.get("default") == 0                        # default preserved


# --- 6. empty params + void method -------------------------------------------
def test_empty_params_and_void_method():
    doc = generate_openrpc(_build())
    assert _method(doc, "pool.events")["params"] == []           # NoArgs -> []
    ping = _method(doc, "pool.ping")
    assert ping["params"] == []
    assert "result" not in ping                                  # void: returns is None


# --- 7. pub/sub topic --------------------------------------------------------
def test_pubsub_topic():
    ev = _method(generate_openrpc(_build()), "pool.events")
    assert "result" not in ev                                    # notification-only
    assert ev["x-direction"] == "server_client"
    assert ev["x-notifies"] == {"$ref": "#/components/schemas/PoolEvent"}
    assert ev["params"] == []


# --- 8. components.schemas include auto-pulled nested Structs -----------------
def test_components_schemas_include_nested():
    schemas = generate_openrpc(_build())["components"]["schemas"]
    assert {"PoolCreateArgs", "PoolCreateResult", "PoolEvent", "Nested"} <= set(schemas)
    assert schemas["PoolCreateArgs"]["properties"]["nested"] == {
        "$ref": "#/components/schemas/Nested"}


# --- 9. x-roles --------------------------------------------------------------
def test_x_roles_present_only_when_set():
    doc = generate_openrpc(_build())
    assert _method(doc, "pool.create")["x-roles"] == ["POOL_WRITE"]
    assert "x-roles" not in _method(doc, "pool.events")


# --- 10. components.errors ---------------------------------------------------
def test_error_components():
    errors = generate_openrpc(_build())["components"]["errors"]
    assert errors["INVALID_PARAMS"] == {"code": -32602, "message": "Invalid Params"}
    assert set(errors) == {e.name for e in JSONRPCError}
    assert "errors" not in generate_openrpc(_build(), include_errors=False)["components"]


# --- 11. fd-transfer methods -------------------------------------------------
def test_fd_transfer_methods():
    doc = generate_openrpc(_build_transfer())
    by = {m["name"]: m for m in doc["methods"]}
    assert by["file.download"]["x-transfer-direction"] == "download"
    assert "result" in by["file.download"]
    assert by["file.upload"]["x-transfer-direction"] == "upload"
    assert by["fd.pass"]["x-transfer-direction"] == "download"
    assert by["fd.pass"]["x-fd-pass"] is True
    # a plain method carries neither extension
    pc = _method(generate_openrpc(_build()), "pool.create")
    assert "x-transfer-direction" not in pc and "x-fd-pass" not in pc


# --- 12. struct name collision -----------------------------------------------
def _dup_a():
    class Dup(msgspec.Struct):
        a: int
    return Dup


def _dup_b():
    class Dup(msgspec.Struct):
        b: int
    return Dup


def test_struct_name_collision_raises():
    p = JSONRPCProtocol([
        JSONRPCMethod("m1", accepts=_dup_a(), handler=_ping),
        JSONRPCMethod("m2", accepts=_dup_b(), handler=_ping),
    ], name="v1", version="1.0.0")
    with pytest.raises(ValueError, match="collision"):
        generate_openrpc(p)


def _outer_with_dup():
    class Dup(msgspec.Struct):       # distinct from _dup_a's Dup; only reachable via Outer
        b: int

    class Outer(msgspec.Struct):
        d: Dup
    return Outer


def test_nested_name_collision_generates_without_keyerror():
    # A *nested* Struct sharing a top-level Struct's name slips past _collect_types (which
    # only sees top-level types), so msgspec qualifies the colliding schema keys. Keying off
    # the refs schema_components returns (not bare __name__) must still resolve them.
    p = JSONRPCProtocol([
        JSONRPCMethod("m1", accepts=_dup_a(), handler=_ping),       # top-level Dup{a}
        JSONRPCMethod("m2", accepts=_outer_with_dup(), handler=_ping),
    ], name="v1", version="1.0.0")
    doc = generate_openrpc(p)                        # raised KeyError('Dup') before the fix
    assert {m["name"] for m in doc["methods"]} == {"m1", "m2"}
    assert [pd["name"] for pd in _method(doc, "m1")["params"]] == ["a"]


# --- 13. the whole document round-trips --------------------------------------
def test_document_round_trips():
    doc = generate_openrpc(_build_transfer())
    assert json.loads(json.dumps(doc)) == doc
    msgspec.json.encode(doc)                                     # also msgspec-encodable


# --- 14. CLI -----------------------------------------------------------------
def test_cli_writes_json(tmp_path):
    mod = tmp_path / "myapi.py"
    mod.write_text(
        "import msgspec\n"
        "from truenas_pyjsonrpc import JSONRPCProtocol, JSONRPCMethod\n"
        "class Ping(msgspec.Struct):\n"
        "    n: int\n"
        "protocol = JSONRPCProtocol(\n"
        "    [JSONRPCMethod('ping', accepts=Ping, returns=Ping)],\n"
        "    name='cli.v1', version='3.2.1')\n")
    out = tmp_path / "openrpc.json"
    sys.path.insert(0, str(tmp_path))
    try:
        rc = main(["myapi:protocol", "--out", str(out)])
        assert rc == 0
        doc = json.loads(out.read_text())                       # output parses as JSON
        assert doc["info"] == {"title": "cli.v1", "version": "3.2.1"}   # from protocol
        assert [m["name"] for m in doc["methods"]] == ["ping"]

        rc = main(["myapi:protocol", "--out", str(out),
                   "--title", "CLI", "--version", "9.9"])
        assert rc == 0
        assert json.loads(out.read_text())["info"] == {"title": "CLI", "version": "9.9"}
    finally:
        sys.path.remove(str(tmp_path))
        sys.modules.pop("myapi", None)
