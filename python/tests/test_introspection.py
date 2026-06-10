"""Introspection (`protocol.describe()`) tests."""
import msgspec

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
    ])
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
    assert JSONRPCProtocol().describe() == {}


def test_describe_doc_defaults_from_handler():
    def h(request, session_state, request_state):
        "the docstring"
        return Result(id=1)

    p = JSONRPCProtocol([JSONRPCMethod("m", accepts=NoArgs, handler=h)])
    assert p.describe()["m"]["doc"] == "the docstring"
