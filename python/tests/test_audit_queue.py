"""Selective per-method audit + off-IO-path audit queue."""
import json
import threading
import uuid
from typing import Annotated

import msgspec

from truenas_pyjsonrpc import (
    SECRET,
    AuditRecord,
    JSONRPCMethod,
    JSONRPCProtocol,
)
from truenas_pyjsonrpc.redaction import REDACTED


class NoArgs(msgspec.Struct):
    pass


class Login(msgspec.Struct):
    user: str
    password: Annotated[str, SECRET]


def uid() -> str:
    return str(uuid.uuid4())


def req(method, id, params=None):
    msg = {"jsonrpc": "2.0", "method": method, "id": id}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def _handler(request, session_state, request_state):
    return {"ok": True}


# --- selective auditing -------------------------------------------------------
def test_audit_disabled_method_not_audited():
    seen = []
    p = JSONRPCProtocol(
        [JSONRPCMethod("m", accepts=NoArgs, handler=_handler)],      # audit=False
        audit_handler=lambda request, response, session_state, audit_message=None: seen.append(1), name="test", version="1.0.0")
    p.dispatch(req("m", uid(), {}))
    assert seen == []                                    # not audited
    assert p.poll_audit(block=False) is None             # nothing queued either


def test_audit_enabled_sync_called_inline():
    seen = []
    p = JSONRPCProtocol(
        [JSONRPCMethod("m", accepts=NoArgs, handler=_handler, audit=True)],
        audit_handler=lambda request, response, session_state, audit_message=None: seen.append(request.method), name="test", version="1.0.0")
    p.dispatch(req("m", uid(), {}))
    assert seen == ["m"]                                 # inline (sync)
    assert p.poll_audit(block=False) is None             # queue unused


# --- queue mode ---------------------------------------------------------------
def test_audit_queue_defers_off_path():
    seen = []
    p = JSONRPCProtocol(
        [JSONRPCMethod("m", accepts=NoArgs, handler=_handler, audit=True)],
        audit_handler=lambda request, response, session_state, audit_message=None: seen.append(request.method),
        use_audit_queue=True, name="test", version="1.0.0")
    p.dispatch(req("m", uid(), {}))
    assert seen == []                                    # NOT called on the IO path
    rec = p.poll_audit(block=False)
    assert isinstance(rec, AuditRecord) and rec.request.method == "m"
    rec.run()                                            # the drain runs it
    assert seen == ["m"]
    assert p.poll_audit(block=False) is None


def test_poll_audit_empty_returns_none():
    assert JSONRPCProtocol(name="test", version="1.0.0").poll_audit(block=False) is None


def test_audit_queue_redacts_off_path():
    def handler(request, session_state, request_state):
        return Login(user=request.user, password=request.password)

    captured = []
    p = JSONRPCProtocol(
        [JSONRPCMethod("login", accepts=Login, returns=Login, handler=handler,
                       audit=True)],
        audit_handler=lambda request, response, session_state, audit_message=None: captured.append(
            (request.params["password"], response["result"]["password"])),
        use_audit_queue=True, name="test", version="1.0.0")
    wire = msgspec.json.decode(p.dispatch(req("login", uid(),
                                              {"user": "u", "password": "hunter2"})))
    assert wire["result"]["password"] == "hunter2"       # wire unredacted
    assert captured == []                                # nothing yet (queued)
    p.poll_audit(block=False).run()                      # redaction happens here
    assert captured == [(REDACTED, REDACTED)]


# --- thread-safety ------------------------------------------------------------
def test_audit_queue_concurrent_dispatch_and_drain():
    p = JSONRPCProtocol(
        [JSONRPCMethod("m", accepts=NoArgs, handler=_handler, audit=True)],
        audit_handler=lambda request, response, session_state, audit_message=None: None,
        use_audit_queue=True, name="test", version="1.0.0")
    n_threads, per = 8, 200
    drained = []
    stop = threading.Event()

    def drain():
        while True:
            rec = p.poll_audit(block=True, timeout=0.05)
            if rec is not None:
                drained.append(rec.request.id)
            elif stop.is_set():
                break

    def worker(t):
        for i in range(per):
            p.dispatch(req("m", f"{uuid.uuid4()}", {}))

    d = threading.Thread(target=drain)
    d.start()
    workers = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    stop.set()
    d.join(timeout=2)
    assert len(drained) == n_threads * per              # every audit job drained
