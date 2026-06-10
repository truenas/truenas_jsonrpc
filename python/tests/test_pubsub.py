"""Pub/sub tests: SERVER_CLIENT (subscribable) methods — subscribe + publish.

A subscriber is a connection's :class:`SessionState`; the routing target carried
on the outbound queue (and returned by ``poll_notification``) is that session.
"""
import json
import threading
import uuid

import msgspec
import pytest

from truenas_pyjsonrpc import (
    AuthorizationResponse,
    JSONRPCError,
    JSONRPCMethod,
    JSONRPCProtocol,
    MessageDirection,
)


class NoArgs(msgspec.Struct):
    pass


class PoolEvent(msgspec.Struct):
    name: str
    state: str


def _topic() -> JSONRPCMethod:
    return JSONRPCMethod("pool.events", accepts=NoArgs, notifies=PoolEvent,
                         direction=MessageDirection.SERVER_CLIENT, audit=True)


def uid() -> str:
    return str(uuid.uuid4())


def sub_req(method, id, params=None):
    msg = {"jsonrpc": "2.0", "method": method, "id": id}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def decode(out):
    return None if out is None else msgspec.json.decode(out)


def _subscribe(p, session):
    """Subscribe ``session`` (a SessionState = one connection) to the topic."""
    r = decode(p.dispatch(sub_req("pool.events", uid()), session))
    return r["result"]


# --- subscribe ----------------------------------------------------------------
def test_subscribe_returns_sub_id_and_registers():
    p = JSONRPCProtocol([_topic()])
    u = uid()
    r = decode(p.dispatch(sub_req("pool.events", u),
                          p.new_session(server_state="conn1")))
    assert r["id"] == u
    sub_id = r["result"]
    uuid.UUID(sub_id)                                # the ack is a uuid
    assert sub_id in p._subscriptions["pool.events"]


def test_subscribe_without_id_is_invalid_request():
    p = JSONRPCProtocol([_topic()])
    r = decode(p.dispatch(json.dumps({"jsonrpc": "2.0", "method": "pool.events"})))
    assert r["error"]["code"] == JSONRPCError.INVALID_REQUEST and r["id"] is None
    assert p._subscriptions.get("pool.events", {}) == {}     # nothing registered


def test_subscribe_denied_by_authz_registers_nothing():
    p = JSONRPCProtocol(
        [_topic()],
        authorization_handler=lambda request, session_state: AuthorizationResponse(False),
    )
    r = decode(p.dispatch(sub_req("pool.events", uid()),
                          p.new_session(server_state="conn1")))
    assert r["error"]["code"] == -32000                       # NOT_AUTHORIZED
    assert p._subscriptions.get("pool.events", {}) == {}


def test_subscribe_is_audited():
    seen = []
    p = JSONRPCProtocol(
        [_topic()],
        audit_handler=lambda request, response, session_state, audit_message=None:
            seen.append((request.method, response)),
    )
    p.dispatch(sub_req("pool.events", uid()), p.new_session(server_state="conn1"))
    assert len(seen) == 1 and seen[0][0] == "pool.events" and "result" in seen[0][1]


# --- publish ------------------------------------------------------------------
def test_publish_fans_out_to_each_subscriber():
    p = JSONRPCProtocol([_topic()])
    s1 = p.new_session(server_state="conn1")
    s2 = p.new_session(server_state="conn2")
    _subscribe(p, s1)
    _subscribe(p, s2)
    p.send_notification("pool.events", {"name": "tank", "state": "ONLINE"})
    got = {}
    for _ in range(2):
        target, data = p.poll_notification(block=False)
        got[target] = msgspec.json.decode(data)
    assert set(got) == {s1, s2}                      # one Pending per subscriber session
    assert got[s1] == {"jsonrpc": "2.0", "method": "pool.events",
                       "params": {"name": "tank", "state": "ONLINE"}}
    assert p.poll_notification(block=False) is None           # exactly one each


def test_publish_no_subscribers_is_noop():
    p = JSONRPCProtocol([_topic()])
    p.send_notification("pool.events", {"name": "x", "state": "ONLINE"})
    assert p.poll_notification(block=False) is None


def test_publish_unknown_method_raises():
    p = JSONRPCProtocol([_topic()])
    with pytest.raises(ValueError):
        p.send_notification("nope", {"name": "x", "state": "y"})


def test_publish_client_server_method_raises():
    p = JSONRPCProtocol([
        JSONRPCMethod("ping", accepts=NoArgs,
                      handler=lambda request, session_state, request_state: {}),
    ])
    with pytest.raises(ValueError):
        p.send_notification("ping", {})


def test_publish_invalid_payload_raises_and_enqueues_nothing():
    p = JSONRPCProtocol([_topic()])
    _subscribe(p, p.new_session())
    with pytest.raises(msgspec.ValidationError):
        p.send_notification("pool.events", {"name": "tank"})  # missing 'state'
    assert p.poll_notification(block=False) is None


# --- unsubscribe --------------------------------------------------------------
def test_unsubscribe_stops_delivery():
    p = JSONRPCProtocol([_topic()])
    sid = _subscribe(p, p.new_session())
    assert p.unsubscribe(sid) is True
    p.send_notification("pool.events", {"name": "x", "state": "ONLINE"})
    assert p.poll_notification(block=False) is None
    assert p.unsubscribe(sid) is False                        # already gone


def test_unsubscribe_all_clears_one_connection():
    p = JSONRPCProtocol([_topic()])
    c1 = p.new_session(server_state={"conn": 1})              # one connection...
    c2 = p.new_session(server_state={"conn": 2})              # ...another
    _subscribe(p, c1)
    _subscribe(p, c1)                                         # two subs on c1
    _subscribe(p, c2)
    assert p.unsubscribe_all(c1) == 2                         # matched by session_uuid
    p.send_notification("pool.events", {"name": "x", "state": "ONLINE"})
    target, _ = p.poll_notification(block=False)
    assert target is c2
    assert p.poll_notification(block=False) is None


# --- concurrency --------------------------------------------------------------
def test_concurrent_subscribe_then_publish():
    p = JSONRPCProtocol([_topic()])
    n = 20

    def sub(i):
        _subscribe(p, p.new_session(server_state=f"conn{i}"))

    threads = [threading.Thread(target=sub, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(len(s) for s in p._subscriptions.values()) == n

    p.send_notification("pool.events", {"name": "x", "state": "ONLINE"})
    count = 0
    while p.poll_notification(block=False) is not None:
        count += 1
    assert count == n
