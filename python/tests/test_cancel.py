"""Cancellation (`$/cancelRequest`) tests."""
import json
import threading
import uuid

import msgspec

from truenas_pyjsonrpc import (
    AuthorizationResponse,
    JSONRPCError,
    JSONRPCMethod,
    JSONRPCProtocol,
    MessageDirection,
    Subscription,
)


class NoArgs(msgspec.Struct):
    pass


class Event(msgspec.Struct):
    x: int


def uid() -> str:
    return str(uuid.uuid4())


def req(method, params=None, id=...):
    msg = {"jsonrpc": "2.0", "method": method}
    if id is not ...:
        msg["id"] = id
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def cancel_req(target_id, id=None):
    return json.dumps({"jsonrpc": "2.0", "method": "$/cancelRequest",
                       "id": id or uid(), "params": {"target_id": target_id}})


def decode(out):
    return None if out is None else msgspec.json.decode(out)


# --- simple (no concurrency) paths -------------------------------------------
def test_cancel_no_id_is_invalid_request():
    p = JSONRPCProtocol(name="test", version="1.0.0")
    r = decode(p.dispatch('{"jsonrpc":"2.0","method":"$/cancelRequest",'
                          '"params":{"target_id":"x"}}'))
    assert r["error"]["code"] == JSONRPCError.INVALID_REQUEST and r["id"] is None


def test_cancel_bad_params_is_invalid_params():
    p = JSONRPCProtocol(name="test", version="1.0.0")
    u = uid()
    r = decode(p.dispatch(json.dumps({"jsonrpc": "2.0", "method": "$/cancelRequest",
                                      "id": u, "params": {}})))   # no target_id
    assert r["error"]["code"] == JSONRPCError.INVALID_PARAMS and r["id"] == u


def test_cancel_unknown_target_is_request_failed_and_audited():
    audited = []
    p = JSONRPCProtocol(
        audit_handler=lambda request, response, session_state, audit_message=None: audited.append(
            (request.method, response)), name="test", version="1.0.0")
    r = decode(p.dispatch(cancel_req(uid())))            # target not in flight
    assert r["error"]["code"] == -32803                  # REQUEST_FAILED
    assert audited and audited[-1][0] == "$/cancelRequest"
    assert "error" in audited[-1][1]


def test_cancel_denied_by_authz():
    p = JSONRPCProtocol(
        authorization_handler=lambda request, session_state, target=None:
            AuthorizationResponse(False), name="test", version="1.0.0")
    r = decode(p.dispatch(cancel_req(uid())))
    assert r["error"]["code"] == -32000                  # NOT_AUTHORIZED


# --- end-to-end with a concurrently in-flight target -------------------------
def _inflight_protocol(handler, **kw):
    kw.setdefault("name", "v1")
    kw.setdefault("version", "1.0.0")
    return JSONRPCProtocol(
        [JSONRPCMethod("slow", accepts=NoArgs, handler=handler, audit=True,
                       cancellable=True)], **kw)


def test_cancel_cooperative_callback_and_audit():
    started = threading.Event()
    applied = threading.Event()
    captured = {}
    audited = []

    def slow(request, session_state, request_state):
        started.set()
        applied.wait(2)                       # block until the cancel has applied
        request_state.raise_if_cancelled()    # -> RequestCancelled
        return {"never": True}

    def on_cancel(request, target, session_state):
        captured.update(target_id=target.id, ss=session_state, method=request.method)

    p = _inflight_protocol(
        slow, cancellation_handler=on_cancel,
        audit_handler=lambda request, response, session_state, audit_message=None:
            audited.append((request.method, response)))
    s = p.new_session(server_state="S")

    tid = uid()
    result = {}
    th = threading.Thread(
        target=lambda: result.__setitem__(
            "t", decode(p.dispatch(req("slow", {}, id=tid), s))))
    th.start()
    assert started.wait(2)

    cancel = decode(p.dispatch(cancel_req(tid), s))
    applied.set()
    th.join(2)

    assert cancel["result"] is True                      # cancel accepted
    assert captured == {"target_id": tid, "ss": s, "method": "$/cancelRequest"}
    assert result["t"]["error"]["code"] == JSONRPCError.REQUEST_CANCELLED
    # both audit events present: the cancel op (success) and the target (cancelled)
    assert ("$/cancelRequest", {"jsonrpc": "2.0", "result": True, "id": cancel["id"]}
            ) in [(m, r) for m, r in audited]
    assert any(m == "slow" and r.get("error", {}).get("code") == JSONRPCError.REQUEST_CANCELLED
               for m, r in audited)
    assert p._inflight == {}                              # cleaned up


def test_cancellation_callback_error_is_internal_error():
    started = threading.Event()
    release = threading.Event()

    def blocker(request, session_state, request_state):
        started.set()
        release.wait(2)
        return {"ok": True}

    def bad_cancel(request, target, session_state):
        raise RuntimeError("boom")

    p = _inflight_protocol(blocker, cancellation_handler=bad_cancel)
    tid = uid()
    th = threading.Thread(target=lambda: p.dispatch(req("slow", {}, id=tid)))
    th.start()
    assert started.wait(2)

    r = decode(p.dispatch(cancel_req(tid)))
    assert r["error"]["code"] == JSONRPCError.INTERNAL_ERROR
    release.set()
    th.join(2)


def test_cancel_is_cooperative_handler_ignoring_flag_still_completes():
    # Cancellation is advisory: the flag is set, but a handler that never calls
    # raise_if_cancelled() runs to completion and returns a normal result.
    started = threading.Event()
    applied = threading.Event()
    observed = {}

    def slow(request, session_state, request_state):
        started.set()
        applied.wait(2)                       # wait until the cancel has applied
        observed["flag"] = request_state.cancelled   # flag is set, but ignored
        return {"done": True}

    def on_cancel(request, target, session_state):
        applied.set()                         # target.cancelled already set by now

    p = _inflight_protocol(slow, cancellation_handler=on_cancel)
    tid = uid()
    result = {}
    th = threading.Thread(target=lambda: result.__setitem__(
        "t", decode(p.dispatch(req("slow", {}, id=tid)))))
    th.start()
    assert started.wait(2)

    cancel = decode(p.dispatch(cancel_req(tid)))
    th.join(2)

    assert cancel["result"] is True                       # cancel accepted
    assert observed["flag"] is True                       # flag WAS set on target
    # ...but the handler ignored it, so the request completed normally
    assert result["t"] == {"jsonrpc": "2.0", "result": {"done": True}, "id": tid}
    assert p._inflight == {}                              # cleaned up


# --- the cancellable gate ----------------------------------------------------
def test_cancel_non_cancellable_method_is_request_failed():
    started = threading.Event()
    release = threading.Event()

    def blocker(request, session_state, request_state):
        started.set()
        release.wait(2)
        return {"ok": True}

    p = JSONRPCProtocol([JSONRPCMethod("work", accepts=NoArgs, handler=blocker)], name="test", version="1.0.0")
    tid = uid()                                          # NOT cancellable (default)
    th = threading.Thread(target=lambda: p.dispatch(req("work", {}, id=tid)))
    th.start()
    assert started.wait(2)

    r = decode(p.dispatch(cancel_req(tid)))              # in flight, but not cancellable
    assert r["error"]["code"] == JSONRPCError.REQUEST_FAILED
    assert "not cancellable" in r["error"]["data"]
    release.set()
    th.join(2)


def test_cancel_event_present_only_when_cancellable():
    seen = {}

    def h(request, session_state, request_state):
        seen["event"] = request_state.cancel_event
        return {"ok": True}

    JSONRPCProtocol([JSONRPCMethod("c", accepts=NoArgs, handler=h,
                                   cancellable=True)], name="test", version="1.0.0").dispatch(req("c", {}, id=uid()))
    assert isinstance(seen["event"], threading.Event)    # cancellable -> an Event

    JSONRPCProtocol([JSONRPCMethod("n", accepts=NoArgs, handler=h)], name="test", version="1.0.0").dispatch(
        req("n", {}, id=uid()))
    assert seen["event"] is None                         # not cancellable -> None


# --- wait_for_cancel ---------------------------------------------------------
def test_wait_for_cancel_wakes_on_cancel():
    started = threading.Event()
    woke = {}

    def waiter(request, session_state, request_state):
        started.set()
        woke["v"] = request_state.wait_for_cancel(2)     # blocks until cancelled
        return {"woke": woke["v"]}

    p = JSONRPCProtocol([JSONRPCMethod("w", accepts=NoArgs, handler=waiter,
                                       cancellable=True)], name="test", version="1.0.0")
    tid = uid()
    result = {}
    th = threading.Thread(target=lambda: result.__setitem__(
        "t", decode(p.dispatch(req("w", {}, id=tid)))))
    th.start()
    assert started.wait(2)
    cancel = decode(p.dispatch(cancel_req(tid)))
    th.join(2)
    assert cancel["result"] is True
    assert woke["v"] is True                              # woke because cancelled
    assert result["t"]["result"] == {"woke": True}


def test_wait_for_cancel_timeout_and_non_cancellable_return_false():
    seen = {}

    def c(request, session_state, request_state):
        seen["timed_out"] = request_state.wait_for_cancel(0.01)   # never cancelled
        return {"ok": True}

    JSONRPCProtocol([JSONRPCMethod("c", accepts=NoArgs, handler=c,
                                   cancellable=True)], name="test", version="1.0.0").dispatch(req("c", {}, id=uid()))
    assert seen["timed_out"] is False                    # timed out, not cancelled

    def n(request, session_state, request_state):
        seen["nc"] = request_state.wait_for_cancel(5)    # no event -> immediate False
        return {"ok": True}

    JSONRPCProtocol([JSONRPCMethod("n", accepts=NoArgs, handler=n)], name="test", version="1.0.0").dispatch(
        req("n", {}, id=uid()))
    assert seen["nc"] is False


# --- session-scoped authorization (the headline) -----------------------------
def test_cancel_session_scoped_authz():
    started = threading.Event()
    release = threading.Event()
    seen = {}

    def slow(request, session_state, request_state):
        started.set()
        release.wait(2)
        request_state.raise_if_cancelled()
        return {"done": True}

    def authz(request, session_state, target=None):
        if request.method != "$/cancelRequest":
            return AuthorizationResponse(True)
        seen["target"] = target                          # authz sees the target
        caller = session_state.server_state_internal
        if caller.get("admin"):
            return AuthorizationResponse(True)           # admin cancels anything
        if (target is not None and
                target.session_state.session_uuid == session_state.session_uuid):
            return AuthorizationResponse(True)           # owner cancels own session
        return AuthorizationResponse(False, "cannot cancel another session's request")

    p = JSONRPCProtocol(
        [JSONRPCMethod("slow", accepts=NoArgs, handler=slow, cancellable=True)],
        authorization_handler=authz, name="test", version="1.0.0")

    owner = p.new_session(server_state={"uid": 1})
    other = p.new_session(server_state={"uid": 2})
    admin = p.new_session(server_state={"uid": 0, "admin": True})

    tid = uid()
    result = {}
    th = threading.Thread(target=lambda: result.__setitem__(
        "t", decode(p.dispatch(req("slow", {}, id=tid), owner))))
    th.start()
    assert started.wait(2)

    # a different non-admin session cannot cancel another session's request
    r_other = decode(p.dispatch(cancel_req(tid), other))
    assert r_other["error"]["code"] == JSONRPCError.NOT_AUTHORIZED
    assert seen["target"] is not None and seen["target"].session_state is owner

    # the owner may cancel its own request; an admin may cancel any
    assert decode(p.dispatch(cancel_req(tid), owner))["result"] is True
    assert decode(p.dispatch(cancel_req(tid), admin))["result"] is True

    release.set()
    th.join(2)
    assert result["t"]["error"]["code"] == JSONRPCError.REQUEST_CANCELLED


def test_cancel_authz_gets_none_target_when_not_in_flight():
    seen = {}

    def authz(request, session_state, target=None):
        seen["target"] = target
        return AuthorizationResponse(False, "nope")      # deny regardless

    p = JSONRPCProtocol(authorization_handler=authz, name="test", version="1.0.0")
    r = decode(p.dispatch(cancel_req(uid())))            # target not in flight
    assert seen["target"] is None                        # authz saw None...
    assert r["error"]["code"] == JSONRPCError.NOT_AUTHORIZED  # ...denied before leak


# --- $/cancelRequest cancels subscriptions (wire-level unsubscribe) -----------
def _pubsub_protocol(**kw):
    kw.setdefault("name", "v1")
    kw.setdefault("version", "1.0.0")
    return JSONRPCProtocol(
        [JSONRPCMethod("events", accepts=NoArgs, notifies=Event,
                       direction=MessageDirection.SERVER_CLIENT)], **kw)


def test_cancel_drops_subscription():
    p = _pubsub_protocol()
    s = p.new_session(server_state="S")
    sub_id = decode(p.dispatch(req("events", {}, id=uid()), s))["result"]
    uuid.UUID(sub_id)                                     # subscribe ack is a sub id
    assert p._subscriptions.get("events")                # registered
    r = decode(p.dispatch(cancel_req(sub_id), s))
    assert r["result"] is True                           # cancel accepted
    assert not p._subscriptions.get("events")            # dropped server-side


def test_cancel_subscription_session_scoped():
    seen = {}

    def authz(request, session_state, target=None):
        if request.method != "$/cancelRequest":
            return AuthorizationResponse(True)           # allow subscribe
        seen["target"] = target
        if session_state.server_state_internal.get("admin"):
            return AuthorizationResponse(True)
        if (target is not None and
                target.session_state.session_uuid == session_state.session_uuid):
            return AuthorizationResponse(True)           # owner cancels own sub
        return AuthorizationResponse(False, "not your subscription")

    p = _pubsub_protocol(authorization_handler=authz)
    owner = p.new_session(server_state={"uid": 1})
    other = p.new_session(server_state={"uid": 2})
    sub_id = decode(p.dispatch(req("events", {}, id=uid()), owner))["result"]

    # a different session cannot cancel the owner's subscription
    r_other = decode(p.dispatch(cancel_req(sub_id), other))
    assert r_other["error"]["code"] == JSONRPCError.NOT_AUTHORIZED
    assert isinstance(seen["target"], Subscription)      # authz sees the Subscription
    assert seen["target"].id == sub_id
    assert seen["target"].session_state is owner
    assert p._subscriptions.get("events")                # still subscribed (denied)

    # the owner may cancel its own
    assert decode(p.dispatch(cancel_req(sub_id), owner))["result"] is True
    assert not p._subscriptions.get("events")            # now gone


def test_cancel_unknown_id_mentions_subscription():
    p = _pubsub_protocol()
    r = decode(p.dispatch(cancel_req(uid())))            # neither request nor sub
    assert r["error"]["code"] == JSONRPCError.REQUEST_FAILED
    assert "subscription" in r["error"]["data"]
