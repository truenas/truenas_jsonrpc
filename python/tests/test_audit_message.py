"""Audit message — static per-method text + runtime ``set_audit`` detail.

The audit handler receives ``audit_message=`` — the method's static
``audit_message`` joined with any runtime detail set via
``request_state.set_audit`` (``"base detail"``). Exactly one message per
dispatched call (``set_audit`` is single-valued, last wins).
"""
import json
import uuid
from typing import Annotated

import msgspec
import pytest

from truenas_pyjsonrpc import (
    SECRET,
    AuditRecord,
    AuthorizationResponse,
    JSONRPCMethod,
    JSONRPCProtocol,
)
from truenas_pyjsonrpc.redaction import REDACTED


class Args(msgspec.Struct):
    name: str


class NoArgs(msgspec.Struct):
    pass


class Login(msgspec.Struct):
    user: str
    password: Annotated[str, SECRET]


def uid() -> str:
    return str(uuid.uuid4())


def req(method, params=None, id=...):
    msg = {"jsonrpc": "2.0", "method": method}
    if id is not ...:
        msg["id"] = id
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def _capture():
    """An audit handler that records each call's ``audit_message``."""
    seen: list = []

    def audit(request, response, session_state, audit_message=None):
        seen.append(audit_message)

    return seen, audit


def _proto(handler, *, audit=True, audit_message=None, authorization_handler=None,
           use_audit_queue=False):
    seen, audit_handler = _capture()
    p = JSONRPCProtocol(
        [JSONRPCMethod("m", accepts=Args, audit=audit, audit_message=audit_message,
                       handler=handler)],
        authorization_handler=authorization_handler,
        audit_handler=audit_handler,
        use_audit_queue=use_audit_queue)
    return seen, p


def _ok(request, session_state, request_state):
    return {"ok": True}


# --- assembly: static / runtime / both / neither -----------------------------
def test_static_message_only():
    seen, p = _proto(_ok, audit_message="Create pool")
    p.dispatch(req("m", {"name": "tank"}, id=uid()))
    assert seen == ["Create pool"]


def test_runtime_detail_only():
    def h(request, session_state, request_state):
        request_state.set_audit("tank")
        return {"ok": True}

    seen, p = _proto(h)                                   # no static message
    p.dispatch(req("m", {"name": "tank"}, id=uid()))
    assert seen == ["tank"]


def test_static_and_runtime_joined():
    def h(request, session_state, request_state):
        request_state.set_audit(request.name)
        return {"ok": True}

    seen, p = _proto(h, audit_message="Create pool")
    p.dispatch(req("m", {"name": "tank"}, id=uid()))
    assert seen == ["Create pool tank"]                  # "base detail"


def test_audited_with_no_message_is_none():
    seen, p = _proto(_ok)                                 # audit=True, no message
    p.dispatch(req("m", {"name": "tank"}, id=uid()))
    assert seen == [None]                                 # still audited; no desc


# --- exactly one message per call (set_audit last-wins) ----------------------
def test_set_audit_last_call_wins_single_message():
    def h(request, session_state, request_state):
        request_state.set_audit("first")
        request_state.set_audit("second")                # replaces, doesn't append
        return {"ok": True}

    seen, p = _proto(h, audit_message="Base")
    p.dispatch(req("m", {"name": "x"}, id=uid()))
    assert seen == ["Base second"]                       # one message; last detail


# --- gate: an unaudited method emits nothing (set_audit is harmless) ---------
def test_unaudited_method_emits_no_message():
    def h(request, session_state, request_state):
        request_state.set_audit("tank")                  # harmless, never consumed
        return {"ok": True}

    seen, p = _proto(h, audit=False, audit_message="Create pool")
    p.dispatch(req("m", {"name": "tank"}, id=uid()))
    assert seen == []                                    # not audited at all


# --- error / denial paths ----------------------------------------------------
def test_handler_error_still_carries_detail_set_before_raise():
    def h(request, session_state, request_state):
        request_state.set_audit(request.name)            # set, then fail
        raise RuntimeError("boom")

    seen, p = _proto(h, audit_message="Create pool")
    r = msgspec.json.decode(p.dispatch(req("m", {"name": "tank"}, id=uid())))
    assert "error" in r
    assert seen == ["Create pool tank"]                  # detail survives the raise


def test_denied_uses_static_message_only_handler_never_ran():
    def h(request, session_state, request_state):
        request_state.set_audit("should-not-run")
        return {"ok": True}

    seen, p = _proto(
        h, audit_message="Create pool",
        authorization_handler=lambda request, session_state: AuthorizationResponse(False))
    p.dispatch(req("m", {"name": "tank"}, id=uid()))
    assert seen == ["Create pool"]                       # no handler -> no detail


# --- notifications (no id) are still audited with the message ----------------
def test_notification_carries_message():
    def h(request, session_state, request_state):
        request_state.set_audit("tank")

    seen, audit = _capture()
    p = JSONRPCProtocol(
        [JSONRPCMethod("note", accepts=Args, audit=True, audit_message="Note",
                       handler=h)],
        audit_handler=audit)
    assert p.dispatch(req("note", {"name": "tank"})) is None   # notification
    assert seen == ["Note tank"]


# --- queue mode: message assembled in the drain, off the IO path -------------
def test_queue_mode_assembles_message_in_drain():
    def h(request, session_state, request_state):
        request_state.set_audit(request.name)
        return {"ok": True}

    seen, p = _proto(h, audit_message="Create pool", use_audit_queue=True)
    p.dispatch(req("m", {"name": "tank"}, id=uid()))
    assert seen == []                                    # not assembled on IO path
    rec = p.poll_audit(block=False)
    assert isinstance(rec, AuditRecord)
    assert rec.audit_message == "Create pool tank"       # assembled in the drain
    rec.run()
    assert seen == ["Create pool tank"]


# --- message text is NOT redacted; secret *fields* still are -----------------
def test_secret_field_redacted_while_message_passed_verbatim():
    captured: dict = {}

    def h(request, session_state, request_state):
        request_state.set_audit(request.user)            # username in the message
        return Login(user=request.user, password=request.password)

    def audit(request, response, session_state, audit_message=None):
        captured["msg"] = audit_message
        captured["pw_in"] = request.params["password"]
        captured["pw_out"] = response["result"]["password"]

    p = JSONRPCProtocol(
        [JSONRPCMethod("login", accepts=Login, returns=Login, audit=True,
                       audit_message="Login", handler=h)],
        audit_handler=audit)
    wire = msgspec.json.decode(p.dispatch(
        req("login", {"user": "u", "password": "hunter2"}, id=uid())))
    assert wire["result"]["password"] == "hunter2"       # real value on the wire
    assert captured["msg"] == "Login u"                  # message verbatim
    assert captured["pw_in"] == REDACTED                 # secret field redacted
    assert captured["pw_out"] == REDACTED


# --- control op (cancel) carries no message ----------------------------------
def test_cancel_audit_message_is_none():
    seen = []

    def audit(request, response, session_state, audit_message=None):
        if request.method == "$/cancelRequest":
            seen.append(audit_message)

    p = JSONRPCProtocol(audit_handler=audit)
    p.dispatch(json.dumps({"jsonrpc": "2.0", "method": "$/cancelRequest",
                           "id": uid(), "params": {"target_id": uid()}}))
    assert seen == [None]                                # control op, no message


# --- validation --------------------------------------------------------------
def test_non_string_audit_message_rejected():
    with pytest.raises(TypeError):
        JSONRPCMethod("m", accepts=NoArgs, audit_message=123)  # type: ignore[arg-type]
