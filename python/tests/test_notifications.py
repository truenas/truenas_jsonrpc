"""Server→client outbound queue + per-request progress tests."""
import json
import threading
import uuid

import msgspec

from truenas_pyjsonrpc import JSONRPCMethod, JSONRPCProtocol, RequestState


class Args(msgspec.Struct):
    name: str


class Result(msgspec.Struct):
    id: int
    name: str


class NoArgs(msgspec.Struct):
    pass


def uid() -> str:
    return str(uuid.uuid4())


def req(method, params=None, id=...):
    msg = {"jsonrpc": "2.0", "method": method}
    if id is not ...:
        msg["id"] = id
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def _proto_with(handler):
    return JSONRPCProtocol(
        [JSONRPCMethod("work", accepts=NoArgs, returns=Result, handler=handler)], name="test", version="1.0.0")


# --- poll_notification -------------------------------------------------------
# (server->client publish lives in test_pubsub.py; here we only exercise progress
# + the drain queue.)
def test_poll_empty_returns_none():
    assert JSONRPCProtocol(name="test", version="1.0.0").poll_notification(block=False) is None


# --- progress: live delivery vs purge-on-completion --------------------------
def test_progress_delivered_when_drained_before_completion():
    # A concurrently-running drain consumes the progress before the handler
    # finishes; the handler blocks until then, so nothing is purged.
    collected = []
    proceed = threading.Event()
    sstate = {"conn": "c1"}

    def handler(request, session_state, request_state):
        request_state.update_progress(percent=50, description="half")
        proceed.wait(timeout=2)
        return Result(id=1, name="x")

    p = _proto_with(handler)

    def drain():
        collected.append(p.poll_notification(timeout=2))   # blocks until enqueued
        proceed.set()

    t = threading.Thread(target=drain)
    t.start()
    u = uid()
    session = p.new_session(server_state=sstate)
    resp = msgspec.json.decode(p.dispatch(req("work", {}, id=u), session))
    t.join(timeout=2)

    assert resp["result"] == {"id": 1, "name": "x"}
    assert len(collected) == 1 and collected[0] is not None
    target, data = collected[0]
    assert target is session                             # routed to the session
    assert msgspec.json.decode(data) == {
        "jsonrpc": "2.0", "method": "$/progress",
        "params": {"id": u, "percent": 50, "description": "half"}}


def test_progress_purged_at_completion_if_undrained():
    captured = []

    def handler(request, session_state, request_state):
        captured.append(request_state)
        request_state.update_progress(percent=10)
        request_state.update_progress(percent=90)
        return Result(id=1, name="x")

    p = _proto_with(handler)
    p.dispatch(req("work", {}, id=uid()))
    assert captured[0].count == 2                        # both were enqueued...
    assert p.poll_notification(block=False) is None      # ...then purged on completion


def test_progress_after_completion_is_dropped():
    captured = []

    def handler(request, session_state, request_state):
        captured.append(request_state)                  # stash, emit nothing now
        return Result(id=1, name="x")

    p = _proto_with(handler)
    p.dispatch(req("work", {}, id=uid()))
    captured[0].update_progress(percent=99)             # request already completed
    assert p.poll_notification(block=False) is None
    assert captured[0].count == 0                        # never enqueued


def test_progress_is_noop_for_notification():
    captured = []

    def handler(request, session_state, request_state):
        captured.append(request_state)
        request_state.update_progress(percent=10)       # no id to correlate
        return Result(id=1, name="x")

    p = _proto_with(handler)
    assert p.dispatch(req("work", {})) is None           # notification (no id)
    assert isinstance(captured[0], RequestState)
    assert captured[0].id is None and captured[0].count == 0
    assert p.poll_notification(block=False) is None


# --- in-flight registry lifecycle --------------------------------------------
def test_inflight_cleared_after_dispatch():
    p = _proto_with(
        lambda request, session_state, request_state: Result(id=1, name="x"))
    p.dispatch(req("work", {}, id=uid()))
    assert p._inflight == {}                             # registered then removed


def test_inflight_cleared_on_handler_error():
    def boom(request, session_state, request_state):
        raise RuntimeError("kaboom")

    p = JSONRPCProtocol([JSONRPCMethod("work", accepts=NoArgs, handler=boom)], name="test", version="1.0.0")
    p.dispatch(req("work", {}, id=uid()))
    assert p._inflight == {}                             # finally-cleanup ran


# --- concurrency --------------------------------------------------------------
def test_concurrent_dispatch_is_safe():
    proto = JSONRPCProtocol([JSONRPCMethod(
        "echo", accepts=Args, returns=Result,
        handler=lambda request, session_state, request_state: Result(
            id=1, name=request.name))], name="test", version="1.0.0")
    errors = []

    def worker(n):
        for i in range(500):
            u = uid()
            name = f"{n}-{i}"
            out = proto.dispatch(req("echo", {"name": name}, id=u))
            r = msgspec.json.decode(out)
            if r.get("id") != u or r.get("result", {}).get("name") != name:
                errors.append((u, r))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert proto._inflight == {}                         # all cleaned up
