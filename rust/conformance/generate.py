#!/usr/bin/env python3
"""Generate the A/B differential **golden corpus** from the Python reference
implementation (`truenas_pyjsonrpc`).

This builds two small *reference protocols* (`open` and `gated`) that the Rust
conformance test (`truenas-jsonrpc/tests/conformance.rs`) mirrors **exactly**, runs a
fixed request corpus through `JSONRPCProtocol.dispatch`, and writes the responses and
audit records to ``truenas-jsonrpc/tests/conformance/golden.json``. The Rust test then
asserts its own `dispatch` reproduces these — the gating proof of wire-compatibility.

`uuid.uuid4` is pinned for determinism. Run from anywhere:

    python3 rust/conformance/generate.py

Re-run whenever the reference protocols change; commit the regenerated golden.json.
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from typing import Annotated, Any

import msgspec

HERE = os.path.dirname(os.path.abspath(__file__))
PY_DIR = os.path.abspath(os.path.join(HERE, "..", "..", "python"))
GOLDEN = os.path.abspath(
    os.path.join(HERE, "..", "truenas-jsonrpc", "tests", "conformance", "golden.json")
)
sys.path.insert(0, PY_DIR)

from truenas_pyjsonrpc import (  # noqa: E402
    FilterableJSONRPCMethod,
    JSONRPCMethod,
    JSONRPCProtocol,
    JsonRpcError,
    MessageDirection,
    SessionLifecycle,
)
from truenas_pyjsonrpc.redaction import SECRET  # noqa: E402
from truenas_pyjsonrpc.types import AuthorizationResponse, JSONRPCError  # noqa: E402
from truenas_pyfilter import tnfilter  # noqa: E402

# Pin uuid4 so any server-minted id (session uuid; later, subscription ids) is
# deterministic. Session uuids never appear in a dispatch response, but pinning keeps
# the corpus reproducible regardless.
uuid.uuid4 = lambda: uuid.UUID("00000000-0000-4000-8000-000000000000")  # noqa: E731

ID = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
ID2 = "f81d4fae-7dec-11d0-a765-00a0c91e6bf7"
# Every server-minted id (session uuid; subscription id) is the pinned uuid4 above.
SUB = "00000000-0000-4000-8000-000000000000"


# --- reference structs -------------------------------------------------------
class Empty(msgspec.Struct):
    pass


class EchoArgs(msgspec.Struct):
    msg: str


class EchoResult(msgspec.Struct):
    echo: str


class AddArgs(msgspec.Struct):
    a: int
    b: int


class AddResult(msgspec.Struct):
    sum: int


class OkResult(msgspec.Struct):
    ok: bool


class PingResult(msgspec.Struct):
    pong: bool


class AuditArgs(msgspec.Struct):
    user: str
    password: Annotated[str, SECRET]


class AuditResult(msgspec.Struct):
    user: str
    password: Annotated[str, SECRET]


class SetupArgs(msgspec.Struct):
    token: str


class SetupResult(msgspec.Struct):
    welcome: str


class SrvInfo(msgspec.Struct):
    name: str
    version: str


class PoolEvent(msgspec.Struct):
    name: str
    state: str


# --- reference handlers ------------------------------------------------------
def h_echo(request, session_state, request_state):
    return EchoResult(echo=request.msg)


def h_add(request, session_state, request_state):
    return AddResult(sum=request.a + request.b)


def h_boom(request, session_state, request_state):
    raise JsonRpcError(JSONRPCError.REQUEST_FAILED, "kaboom")


def h_ok(request, session_state, request_state):
    return OkResult(ok=True)


def h_ping(request, session_state, request_state):
    return PingResult(pong=True)


def h_audit(request, session_state, request_state):
    return AuditResult(user=request.user, password=request.password)


def h_setup(request, session_state):
    if request.token == "good":
        session_state.server_state_internal = {"user": "root"}
        return SessionLifecycle.ESTABLISHED, SetupResult(welcome="hi")
    raise JsonRpcError(JSONRPCError.NOT_AUTHORIZED, "bad token")


def srv_info(session_state):
    return SrvInfo(name="ref", version="1.0.0")


def authz(request, session_state, target=None):
    if request.method == "secret_op":
        return AuthorizationResponse(authorized=False, message="denied")
    return AuthorizationResponse(authorized=True)


# --- filterable (query) reference method (mirrors python/tests/test_filterable.py) ------
class QueryArgs(msgspec.Struct):
    pass


class QueryEntry(msgspec.Struct):
    id: int
    name: str


_QDATA = [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}, {"id": 3, "name": "a"}]


def h_query(request, session_state, request_state, filters, options):
    # Push-down: stream the source through the compiled query (the framework applies the
    # get/count finalize on the returned narrowed result).
    return tnfilter(_QDATA, filters=filters, options=options)


def build_open():
    audit_log: list[dict] = []

    def audit(request, response, session_state, audit_message=None):
        audit_log.append(
            {
                "method": request.method,
                "params": msgspec.to_builtins(request.params),
                "response": msgspec.to_builtins(response),
                "audit_message": audit_message,
            }
        )

    proto = JSONRPCProtocol(
        [
            JSONRPCMethod("echo", accepts=EchoArgs, returns=EchoResult, handler=h_echo),
            JSONRPCMethod("add", accepts=AddArgs, returns=AddResult, handler=h_add),
            JSONRPCMethod("boom", accepts=Empty, returns=OkResult, handler=h_boom),
            JSONRPCMethod(
                "audit_me",
                accepts=AuditArgs,
                returns=AuditResult,
                handler=h_audit,
                audit=True,
                audit_message="audited op",
            ),
            JSONRPCMethod(
                "events",
                accepts=Empty,
                notifies=PoolEvent,
                direction=MessageDirection.SERVER_CLIENT,
                audit=True,
                audit_message="subscribed",
            ),
            FilterableJSONRPCMethod("x.query", accepts=QueryArgs, entry=QueryEntry, handler=h_query),
        ],
        name="ref-open",
        version="1.0.0",
        audit_handler=audit,
    )
    proto.register_server_info(srv_info, returns=SrvInfo)
    return proto, audit_log


def build_gated():
    proto = JSONRPCProtocol(
        [
            JSONRPCMethod("ping", accepts=Empty, returns=PingResult, handler=h_ping, pre_auth=True),
            JSONRPCMethod("echo", accepts=EchoArgs, returns=EchoResult, handler=h_echo),
            JSONRPCMethod("add", accepts=AddArgs, returns=AddResult, handler=h_add),
            JSONRPCMethod("boom", accepts=Empty, returns=OkResult, handler=h_boom),
            JSONRPCMethod("secret_op", accepts=Empty, returns=OkResult, handler=h_ok),
        ],
        name="ref-gated",
        version="1.0.0",
        authorization_handler=authz,
    )
    proto.add_session_setup(
        JSONRPCMethod("$/sessionSetup", accepts=SetupArgs, returns=SetupResult, handler=h_setup)
    )
    return proto, []


def build_pubsub():
    proto = JSONRPCProtocol(
        [
            JSONRPCMethod(
                "events",
                accepts=Empty,
                notifies=PoolEvent,
                direction=MessageDirection.SERVER_CLIENT,
            ),
        ],
        name="ref-pubsub",
        version="1.0.0",
    )
    return proto, []


# --- request corpus ----------------------------------------------------------
def mk(method: str, params: Any = None, id: Any = ID) -> str:
    d: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if id is not None:
        d["id"] = id
    if params is not None:
        d["params"] = params
    return json.dumps(d)


CASES = [
    # name, protocol, [wire, ...]
    ("open/echo_ok", "open", [mk("echo", {"msg": "hi"})]),
    ("open/add_ok", "open", [mk("add", {"a": 2, "b": 3})]),
    ("open/boom_request_failed", "open", [mk("boom", {})]),
    ("open/missing_required_param", "open", [mk("echo", {})]),
    ("open/wrong_param_type", "open", [mk("add", {"a": "x", "b": 3})]),
    ("open/unknown_method", "open", [mk("nope", {})]),
    ("open/notification_no_reply", "open", [mk("echo", {"msg": "hi"}, id=None)]),
    ("open/malformed_json", "open", ["{not json"]),
    ("open/top_level_array", "open", ["[]"]),
    ("open/non_uuid_id", "open", [mk("echo", {"msg": "x"}, id="not-a-uuid")]),
    (
        "open/bad_jsonrpc_version",
        "open",
        ['{"jsonrpc": "1.0", "method": "echo", "id": "%s", "params": {"msg": "x"}}' % ID],
    ),
    ("open/server_info", "open", [mk("$/serverInfo", None)]),
    ("open/audit_redaction", "open", [mk("audit_me", {"user": "u", "password": "hunter2"})]),
    ("gated/ping_preauth", "gated", [mk("ping", {})]),
    ("gated/echo_before_setup_gated", "gated", [mk("echo", {"msg": "x"})]),
    ("gated/unknown_before_setup", "gated", [mk("nope", {})]),
    (
        "gated/setup_then_echo",
        "gated",
        [mk("$/sessionSetup", {"token": "good"}), mk("echo", {"msg": "hi"})],
    ),
    ("gated/setup_bad_token", "gated", [mk("$/sessionSetup", {"token": "bad"})]),
    (
        "gated/secret_op_denied",
        "gated",
        [mk("$/sessionSetup", {"token": "good"}), mk("secret_op", {})],
    ),
    (
        "gated/session_close_then_call",
        "gated",
        [
            mk("$/sessionSetup", {"token": "good"}),
            mk("$/sessionClose", None),
            mk("echo", {"msg": "x"}),
        ],
    ),
    (
        "gated/cancel_unknown_target",
        "gated",
        [mk("$/sessionSetup", {"token": "good"}), mk("$/cancelRequest", {"target_id": ID2})],
    ),
    # --- pub/sub (SERVER_CLIENT) -------------------------------------------------
    ("open/subscribe_ok", "open", [mk("events", {})]),  # ack carries the (pinned) sub id; audited
    ("open/subscribe_without_id", "open", [mk("events", {}, id=None)]),  # INVALID_REQUEST
    (
        "pubsub/subscribe_then_publish",
        "pubsub",
        [mk("events", {}), ("events", {"name": "tank", "state": "ONLINE"})],
    ),
    (
        "pubsub/unsubscribe_via_cancel",
        "pubsub",
        [
            mk("events", {}),
            mk("$/cancelRequest", {"target_id": SUB}),
            ("events", {"name": "x", "state": "y"}),  # delivered to nobody now
        ],
    ),
    ("pubsub/cancel_unknown", "pubsub", [mk("$/cancelRequest", {"target_id": ID2})]),
    # --- filterable (query) ------------------------------------------------------
    ("open/query_all", "open", [mk("x.query", {})]),
    ("open/query_filter", "open", [mk("x.query", {"query-filters": [["name", "=", "a"]]})]),
    (
        "open/query_count",
        "open",
        [mk("x.query", {"query-filters": [["name", "=", "a"]], "query-options": {"count": True}})],
    ),
    (
        "open/query_get",
        "open",
        [mk("x.query", {"query-filters": [["name", "=", "a"]], "query-options": {"get": True}})],
    ),
    (
        "open/query_get_nomatch",
        "open",
        [mk("x.query", {"query-filters": [["name", "=", "zzz"]], "query-options": {"get": True}})],
    ),
    ("open/query_invalid_filter", "open", [mk("x.query", {"query-filters": [["name", "??", "a"]]})]),
]


def run_case(name: str, proto_name: str, steps: list) -> dict:
    builders = {"open": build_open, "gated": build_gated, "pubsub": build_pubsub}
    proto, audit_log = builders[proto_name]()
    session = proto.new_session(server_state=None)
    out_steps = []
    for step in steps:
        if isinstance(step, str):  # a dispatch step (a wire request)
            resp = proto.dispatch(step, session)
            out_steps.append(
                {"kind": "dispatch", "wire": step, "response": None if resp is None else json.loads(resp)}
            )
        else:  # a publish step: (topic, payload)
            topic, payload = step
            proto.send_notification(topic, payload)
            out_steps.append({"kind": "publish", "topic": topic, "payload": payload})
    # Drain any server->client notifications the publishes fanned out (FIFO, deterministic).
    notifications = []
    while (pending := proto.poll_notification(block=False)) is not None:
        notifications.append(json.loads(pending[1]))
    return {
        "name": name,
        "protocol": proto_name,
        "steps": out_steps,
        "audits": audit_log,
        "notifications": notifications,
    }


def main() -> None:
    cases = [run_case(name, proto, steps) for (name, proto, steps) in CASES]
    os.makedirs(os.path.dirname(GOLDEN), exist_ok=True)
    with open(GOLDEN, "w") as f:
        json.dump({"cases": cases}, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"wrote {len(cases)} cases to {GOLDEN}")


if __name__ == "__main__":
    main()
