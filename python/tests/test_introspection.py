"""Introspection (`protocol.describe()`) tests."""
import msgspec
import pytest

from truenas_pyjsonrpc import JSONRPCMethod, JSONRPCProtocol, MessageDirection


class Args(msgspec.Struct):
    name: str


class Result(msgspec.Struct):
    id: int


class Event(msgspec.Struct):
    x: int


class NoArgs(msgspec.Struct):
    pass


def test_describe_catalog():
    p = JSONRPCProtocol([
        JSONRPCMethod("pool.create", accepts=Args, returns=Result, doc="make a pool",
                      handler=lambda request, session_state, request_state: Result(id=1)),
        JSONRPCMethod("pool.events", accepts=NoArgs, notifies=Event,
                      direction=MessageDirection.SERVER_CLIENT),
    ], name="test", version="1.0.0")
    d = p.describe()

    assert set(d) == {"pool.create", "pool.events"}

    create = d["pool.create"]
    assert create["direction"] == "client_server"
    assert create["doc"] == "make a pool"
    assert isinstance(create["accepts"], dict) and create["accepts"]   # JSON Schema
    assert create["returns"] is not None
    assert create["notifies"] is None

    events = d["pool.events"]
    assert events["direction"] == "server_client"
    assert events["notifies"] is not None
    assert events["returns"] is None

    # the whole catalog is JSON-serializable (for a wire `system.describe`, codegen)
    msgspec.json.encode(d)


def test_describe_empty_protocol():
    assert JSONRPCProtocol(name="test", version="1.0.0").describe() == {}


def test_describe_doc_defaults_from_handler():
    def h(request, session_state, request_state):
        "the docstring"
        return Result(id=1)

    p = JSONRPCProtocol([JSONRPCMethod("m", accepts=NoArgs, handler=h)], name="test", version="1.0.0")
    assert p.describe()["m"]["doc"] == "the docstring"


def test_protocol_requires_name_and_version():
    # missing entirely -> TypeError (required keyword-only args)
    with pytest.raises(TypeError):
        JSONRPCProtocol(version="1.0.0")            # type: ignore[call-arg]
    with pytest.raises(TypeError):
        JSONRPCProtocol(name="v1")                  # type: ignore[call-arg]
    # present but empty / wrong type -> ValueError
    with pytest.raises(ValueError, match="name"):
        JSONRPCProtocol(name="", version="1.0.0")
    with pytest.raises(ValueError, match="version"):
        JSONRPCProtocol(name="v1", version="")
    with pytest.raises(ValueError, match="name"):
        JSONRPCProtocol(name=None, version="1.0.0")  # type: ignore[arg-type]


def test_protocol_name_and_version_properties():
    p = JSONRPCProtocol(name="truenas.api.v1", version="25.04")
    assert p.name == "truenas.api.v1"
    assert p.version == "25.04"
