"""Runtime behavior of the accepts_validator / returns_validator hooks.

Construction-time checks ("must be callable") live in test_method.py; this file
exercises what the validators actually *do* during dispatch: reject, replace, or
pass through. ``accepts_validator`` runs after msgspec decodes the params (in
``_dispatch_one``); ``returns_validator`` runs after the return is type-converted
(in ``_authorize_and_dispatch``).
"""
import json
import uuid

import msgspec

from truenas_pyjsonrpc import (
    JSONRPCError,
    JSONRPCMethod,
    JSONRPCProtocol,
)


class Args(msgspec.Struct):
    name: str


class Result(msgspec.Struct):
    id: int
    name: str


def uid() -> str:
    return str(uuid.uuid4())


def req(method, params=None, id=...):
    msg = {"jsonrpc": "2.0", "method": method}
    if id is not ...:
        msg["id"] = id
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def decode(out):
    return None if out is None else msgspec.json.decode(out)


# --- accepts_validator --------------------------------------------------------
def test_accepts_validator_raises_is_invalid_params_and_skips_handler():
    called = []

    def validator(params):
        raise ValueError("bad name")

    def handler(request, session_state, request_state):
        called.append(1)
        return Result(id=1, name=request.name)

    p = JSONRPCProtocol([JSONRPCMethod(
        "m", accepts=Args, returns=Result, handler=handler,
        accepts_validator=validator)])
    r = decode(p.dispatch(req("m", {"name": "x"}, id=uid())))
    assert r["error"]["code"] == JSONRPCError.INVALID_PARAMS
    assert r["error"]["data"] == "bad name"              # str(exc) surfaced
    assert called == []                                  # handler never ran


def test_accepts_validator_replacement_is_passed_to_handler():
    def validator(params):
        return Args(name=params.name.upper())            # replace the params

    def handler(request, session_state, request_state):
        return Result(id=1, name=request.name)

    p = JSONRPCProtocol([JSONRPCMethod(
        "m", accepts=Args, returns=Result, handler=handler,
        accepts_validator=validator)])
    r = decode(p.dispatch(req("m", {"name": "tank"}, id=uid())))
    assert r["result"] == {"id": 1, "name": "TANK"}      # handler saw replacement


def test_accepts_validator_returning_none_keeps_params():
    seen = {}

    def validator(params):
        seen["name"] = params.name
        return None                                      # no replacement

    def handler(request, session_state, request_state):
        return Result(id=1, name=request.name)

    p = JSONRPCProtocol([JSONRPCMethod(
        "m", accepts=Args, returns=Result, handler=handler,
        accepts_validator=validator)])
    r = decode(p.dispatch(req("m", {"name": "tank"}, id=uid())))
    assert seen["name"] == "tank"                        # validator saw the params
    assert r["result"] == {"id": 1, "name": "tank"}      # unchanged


def test_accepts_validator_error_on_notification_is_swallowed():
    called = []

    def validator(params):
        raise ValueError("bad")

    def handler(request, session_state, request_state):
        called.append(1)
        return None

    p = JSONRPCProtocol([JSONRPCMethod(
        "m", accepts=Args, handler=handler, accepts_validator=validator)])
    assert p.dispatch(req("m", {"name": "x"})) is None   # no id -> no reply
    assert called == []                                  # validator error skipped the handler


# --- returns_validator --------------------------------------------------------
def test_returns_validator_raises_is_internal_error():
    def validator(result):
        raise ValueError("bad result")

    def handler(request, session_state, request_state):
        return Result(id=1, name=request.name)

    p = JSONRPCProtocol([JSONRPCMethod(
        "m", accepts=Args, returns=Result, handler=handler,
        returns_validator=validator)])
    r = decode(p.dispatch(req("m", {"name": "x"}, id=uid())))
    assert r["error"]["code"] == JSONRPCError.INTERNAL_ERROR
    assert r["error"]["message"] == "Invalid result"
    assert r["error"]["data"] == "bad result"


def test_returns_validator_replacement_is_on_the_wire():
    def validator(result):
        return Result(id=result.id, name=result.name + "!")   # replace the result

    def handler(request, session_state, request_state):
        return Result(id=7, name=request.name)

    p = JSONRPCProtocol([JSONRPCMethod(
        "m", accepts=Args, returns=Result, handler=handler,
        returns_validator=validator)])
    r = decode(p.dispatch(req("m", {"name": "tank"}, id=uid())))
    assert r["result"] == {"id": 7, "name": "tank!"}     # replacement on the wire


def test_returns_validator_returning_none_keeps_result():
    seen = {}

    def validator(result):
        seen["name"] = result.name
        return None                                      # no replacement

    def handler(request, session_state, request_state):
        return Result(id=7, name=request.name)

    p = JSONRPCProtocol([JSONRPCMethod(
        "m", accepts=Args, returns=Result, handler=handler,
        returns_validator=validator)])
    r = decode(p.dispatch(req("m", {"name": "tank"}, id=uid())))
    assert seen["name"] == "tank"                        # validator saw the result
    assert r["result"] == {"id": 7, "name": "tank"}      # unchanged
