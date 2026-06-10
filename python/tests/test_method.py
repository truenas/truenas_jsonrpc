"""Construction/validation tests for JSONRPCMethod."""
import msgspec
import pytest

from truenas_pyjsonrpc import JSONRPCMethod, MessageDirection


class Args(msgspec.Struct):
    x: int


class NoArgs(msgspec.Struct):
    pass


class Payload(msgspec.Struct):
    x: int


def test_minimal():
    m = JSONRPCMethod("m", accepts=NoArgs)
    assert m.name == "m" and m.accepts is NoArgs and m.returns is None
    assert m.handler is None


def test_accepts_is_required():
    with pytest.raises(TypeError):
        JSONRPCMethod("m")                          # accepts has no default


def test_full_construction():
    h = lambda request, session_state: request
    m = JSONRPCMethod("m", accepts=Args, returns=Args, handler=h)
    assert m.accepts is Args and m.returns is Args and m.handler is h


def test_name_must_be_nonempty():
    with pytest.raises(TypeError):
        JSONRPCMethod("", accepts=Args)


def test_accepts_must_be_struct():
    with pytest.raises(TypeError):
        JSONRPCMethod("m", accepts=dict)            # dict is not a msgspec.Struct


def test_returns_must_be_struct_or_none():
    with pytest.raises(TypeError):
        JSONRPCMethod("m", accepts=Args, returns=dict)


def test_handler_must_be_callable():
    with pytest.raises(TypeError):
        JSONRPCMethod("m", accepts=Args, handler=123)


def test_handler_settable_after_construction():
    m = JSONRPCMethod("m", accepts=Args)
    fn = lambda request, session_state: request
    m.handler = fn
    assert m.handler is fn
    m.handler = None
    assert m.handler is None
    with pytest.raises(TypeError):
        m.handler = 123


def test_validators_must_be_callable():
    with pytest.raises(TypeError):
        JSONRPCMethod("m", accepts=Args, accepts_validator=123)


# --- direction (CLIENT_SERVER vs SERVER_CLIENT) ------------------------------
def test_default_direction_is_client_server():
    assert JSONRPCMethod("m", accepts=NoArgs).direction is MessageDirection.CLIENT_SERVER


def test_client_server_forbids_notifies():
    with pytest.raises(TypeError):
        JSONRPCMethod("m", accepts=NoArgs, notifies=Payload)


def test_server_client_requires_notifies():
    with pytest.raises(TypeError):
        JSONRPCMethod("evt", accepts=NoArgs,
                      direction=MessageDirection.SERVER_CLIENT)


def test_server_client_forbids_handler():
    with pytest.raises(TypeError):
        JSONRPCMethod("evt", accepts=NoArgs, notifies=Payload,
                      direction=MessageDirection.SERVER_CLIENT,
                      handler=lambda **kw: None)


def test_server_client_construction_ok():
    m = JSONRPCMethod("evt", accepts=NoArgs, notifies=Payload,
                      direction=MessageDirection.SERVER_CLIENT)
    assert m.direction is MessageDirection.SERVER_CLIENT
    assert m.notifies is Payload and m.handler is None


def test_cannot_set_handler_on_server_client():
    m = JSONRPCMethod("evt", accepts=NoArgs, notifies=Payload,
                      direction=MessageDirection.SERVER_CLIENT)
    with pytest.raises(TypeError):
        m.handler = lambda **kw: None


def test_cancellable_rejected_on_server_client():
    with pytest.raises(TypeError):
        JSONRPCMethod("evt", accepts=NoArgs, notifies=Payload,
                      direction=MessageDirection.SERVER_CLIENT, cancellable=True)


def test_cancellable_flag_defaults_false_and_settable():
    assert JSONRPCMethod("m", accepts=NoArgs).cancellable is False
    assert JSONRPCMethod("m", accepts=NoArgs, cancellable=True).cancellable is True


# --- metadata: doc + pre_auth ------------------------------------------------
def test_doc_defaults_from_handler_docstring():
    def h(request, session_state, request_state):
        "creates a pool"
        return {}

    assert JSONRPCMethod("m", accepts=NoArgs, handler=h).doc == "creates a pool"


def test_doc_explicit_and_none():
    assert JSONRPCMethod("m", accepts=NoArgs, doc="explicit").doc == "explicit"
    assert JSONRPCMethod("m", accepts=NoArgs).doc is None     # no handler, no doc


def test_pre_auth_flag():
    assert JSONRPCMethod("m", accepts=NoArgs).pre_auth is False
    assert JSONRPCMethod("m", accepts=NoArgs, pre_auth=True).pre_auth is True
