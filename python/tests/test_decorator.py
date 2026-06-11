"""Tests for the @jrpc_method decorator (convenience registration)."""
import json
import uuid

import msgspec
import pytest

from truenas_pyjsonrpc import (
    JSONRPCMethod,
    JSONRPCProtocol,
    MessageDirection,
    jrpc_method,
)


class Args(msgspec.Struct):
    name: str


class Result(msgspec.Struct):
    id: int
    name: str


class NoArgs(msgspec.Struct):
    pass


class Event(msgspec.Struct):
    name: str


def uid() -> str:
    return str(uuid.uuid4())


def req(method, id, params=None):
    msg = {"jsonrpc": "2.0", "method": method, "id": id}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def test_builds_method_and_registers():
    p = JSONRPCProtocol(name="test", version="1.0.0")

    @jrpc_method(name="pool.create", accepts=Args, returns=Result, protocols=[p])
    def pool_create(request, session_state, request_state):
        return Result(id=7, name=request.name)

    m = pool_create.method
    assert isinstance(m, JSONRPCMethod)
    assert m.name == "pool.create" and m.accepts is Args and m.returns is Result
    assert m.direction is MessageDirection.CLIENT_SERVER
    assert m.handler is pool_create               # the function is the handler
    assert "pool.create" in p.methods


def test_function_stays_callable():
    @jrpc_method(accepts=Args)
    def h(request, session_state, request_state):
        return {"ok": request.name}

    assert h(request=Args(name="x"), session_state=None,
             request_state=None) == {"ok": "x"}


def test_name_defaults_to_func_name():
    @jrpc_method(accepts=NoArgs)
    def ping(request, session_state, request_state):
        return {}

    assert ping.method.name == "ping"


def test_dispatches_end_to_end():
    p = JSONRPCProtocol(name="test", version="1.0.0")

    @jrpc_method(name="pool.create", accepts=Args, returns=Result, protocols=[p])
    def pool_create(request, session_state, request_state):
        return Result(id=7, name=request.name)

    u = uid()
    out = msgspec.json.decode(p.dispatch(req("pool.create", u, {"name": "tank"})))
    assert out == {"jsonrpc": "2.0", "result": {"id": 7, "name": "tank"}, "id": u}


def test_registers_into_multiple_protocols_sharing_one_method():
    a, b = JSONRPCProtocol(name="test", version="1.0.0"), JSONRPCProtocol(name="test", version="1.0.0")

    @jrpc_method(name="m", accepts=NoArgs, protocols=[a, b])
    def m(request, session_state, request_state):
        return {"ok": True}

    assert "m" in a.methods and "m" in b.methods
    assert a.methods["m"] is b.methods["m"]       # same method object shared


def test_no_protocols_attaches_method_for_manual_registration():
    @jrpc_method(name="m", accepts=NoArgs)
    def m(request, session_state, request_state):
        return {}

    assert isinstance(m.method, JSONRPCMethod)
    p = JSONRPCProtocol(name="test", version="1.0.0")
    p.register(m.method)
    assert "m" in p.methods


def test_server_client_topic_has_no_handler_and_works():
    p = JSONRPCProtocol(name="test", version="1.0.0")

    @jrpc_method(name="pool.events", accepts=NoArgs, notifies=Event,
                 direction=MessageDirection.SERVER_CLIENT, protocols=[p])
    def pool_events():
        """declaration stub — never invoked by the protocol"""

    m = pool_events.method
    assert m.direction is MessageDirection.SERVER_CLIENT
    assert m.handler is None and m.notifies is Event

    sub = msgspec.json.decode(p.dispatch(req("pool.events", uid()),
                                         p.new_session(server_state="c1")))
    uuid.UUID(sub["result"])                       # ack is a sub id
    p.send_notification("pool.events", {"name": "tank"})
    target, data = p.poll_notification(block=False)
    assert target.server_state_internal == "c1"    # routing target is the session
    assert msgspec.json.decode(data)["method"] == "pool.events"


def test_duplicate_name_raises_through_register():
    p = JSONRPCProtocol(name="test", version="1.0.0")

    @jrpc_method(name="m", accepts=NoArgs, protocols=[p])
    def m1(request, session_state, request_state):
        return {}

    with pytest.raises(ValueError):
        @jrpc_method(name="m", accepts=NoArgs, protocols=[p])
        def m2(request, session_state, request_state):
            return {}


def test_rpc_prefix_raises_through_register():
    p = JSONRPCProtocol(name="test", version="1.0.0")
    with pytest.raises(ValueError):
        @jrpc_method(name="rpc.internal", accepts=NoArgs, protocols=[p])
        def x(request, session_state, request_state):
            return {}


def test_decorator_doc_defaults_from_func_docstring():
    @jrpc_method(name="m", accepts=NoArgs)
    def m(request, session_state, request_state):
        "does a thing"
        return {}

    assert m.method.doc == "does a thing"


def test_decorator_passes_pre_auth():
    @jrpc_method(name="m", accepts=NoArgs, pre_auth=True)
    def m(request, session_state, request_state):
        return {}

    assert m.method.pre_auth is True
