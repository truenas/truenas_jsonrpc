#!/usr/bin/env python3
"""A/B conformance oracle: drives the Python reference `JSONRPCProtocol.dispatch` over a corpus and
writes the golden responses (and audit records) the Zig engine must reproduce structurally.

The reference protocols here must mirror `zig/conformance/reference.zig` exactly (same method names,
accepts/returns shapes, handler results, hooks, audit flags, secret fields). Run from anywhere:

    python3 zig/conformance/generate.py

Output: zig/conformance/golden.json  (committed; CI regenerates it and `git diff --exit-code`s).
Framework-generated `error.data` (an impl-specific detail string) is stripped from both the wire
response and the audit response — the wire contract is the error *code* + *message*, which both
implementations match.
"""
import json
import os
import sys
from typing import Annotated

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "python"))

import msgspec  # noqa: E402
from truenas_pyjsonrpc import (  # noqa: E402
    JSONRPCProtocol,
    JSONRPCMethod,
    JsonRpcError,
    JSONRPCError,
    AuthorizationResponse,
    SessionLifecycle,
    SECRET,
)


class PoolCreateArgs(msgspec.Struct):
    name: str


class PoolCreateResult(msgspec.Struct):
    id: int
    name: str


class AddArgs(msgspec.Struct):
    a: int
    b: int


class AddResult(msgspec.Struct):
    sum: int


class NoArgs(msgspec.Struct):
    pass


class ServerInfoResult(msgspec.Struct):
    name: str
    version: str


# --- audit protocol: secret in/out, a runtime audit detail, a denial, an erroring audited method ---
class LoginArgs(msgspec.Struct):
    user: str
    password: Annotated[str, SECRET]


class LoginResult(msgspec.Struct):
    token: Annotated[str, SECRET]
    ok: bool


class PingArgs(msgspec.Struct):
    pass


class PingResult(msgspec.Struct):
    pong: bool


# --- gated protocol: session-setup + the ESTABLISHED gate + a pre_auth method ---
class SetupArgs(msgspec.Struct):
    user: str


class ContinueArgs(msgspec.Struct):
    otp: str


class SetupAck(msgspec.Struct):
    stage: str


class WhoamiResult(msgspec.Struct):
    who: str


class VersionResult(msgspec.Struct):
    v: str


def pool_create(request, session_state, request_state):
    return PoolCreateResult(id=7, name=request.name)


def add(request, session_state, request_state):
    return AddResult(sum=request.a + request.b)


def boom(request, session_state, request_state):
    raise RuntimeError("boom")


def failing(request, session_state, request_state):
    raise JsonRpcError(JSONRPCError.REQUEST_FAILED, "expected failure")


def secret_op(request, session_state, request_state):
    return AddResult(sum=request.a + request.b)


def authorize(request, session_state):
    if request.method == "secret_op":
        return AuthorizationResponse(authorized=False, message="nope")
    return AuthorizationResponse(authorized=True)


def server_info(session_state):
    return ServerInfoResult(name="truenas", version="42")


def login(request, session_state, request_state):
    request_state.set_audit(f"as {request.user}")
    return LoginResult(token="tok-secret", ok=True)


def ping(request, session_state, request_state):
    return PingResult(pong=True)


def crash(request, session_state, request_state):
    raise RuntimeError("kaboom")


def gated_setup(request, session_state):
    return (SessionLifecycle.INIT, SetupAck(stage="init"))


def gated_continue(request, session_state):
    return (SessionLifecycle.ESTABLISHED, SetupAck(stage="established"))


def whoami(request, session_state, request_state):
    return WhoamiResult(who="authed")


def version(request, session_state, request_state):
    return VersionResult(v="1.0")


def audit_authorize(request, session_state):
    # request.params is the decoded struct; deny `login` for a specific user.
    if request.method == "login" and getattr(request.params, "user", None) == "denyme":
        return AuthorizationResponse(authorized=False, message="denied")
    return AuthorizationResponse(authorized=True)


def _strip_error_data(obj):
    if isinstance(obj, dict) and isinstance(obj.get("error"), dict):
        obj["error"].pop("data", None)
    return obj


_AUDIT_LOG = []


def _record_audit(request, response, session_state, audit_message):
    _AUDIT_LOG.append({
        "method": request.method,
        "id": request.id,
        "params": msgspec.to_builtins(request.params),
        "roles": list(request.roles),
        "response": _strip_error_data(msgspec.to_builtins(response)),
        "message": audit_message,
    })


COMMON = [
    JSONRPCMethod("pool.create", accepts=PoolCreateArgs, returns=PoolCreateResult, handler=pool_create),
    JSONRPCMethod("add", accepts=AddArgs, returns=AddResult, handler=add),
    JSONRPCMethod("boom", accepts=NoArgs, returns=NoArgs, handler=boom),
    JSONRPCMethod("fail", accepts=NoArgs, returns=NoArgs, handler=failing),
]
PROTO_OPEN = JSONRPCProtocol(list(COMMON), name="test", version="1.0.0")
PROTO_OPEN.register_server_info(server_info, returns=ServerInfoResult)
PROTO_AUTHZ = JSONRPCProtocol(
    list(COMMON) + [JSONRPCMethod("secret_op", accepts=AddArgs, returns=AddResult, handler=secret_op)],
    name="test",
    version="1.0.0",
    authorization_handler=authorize,
)
PROTO_AUDIT = JSONRPCProtocol(
    [
        JSONRPCMethod("login", accepts=LoginArgs, returns=LoginResult, handler=login,
                      audit=True, audit_message="user login"),
        JSONRPCMethod("ping", accepts=PingArgs, returns=PingResult, handler=ping),
        JSONRPCMethod("crash", accepts=NoArgs, returns=PingResult, handler=crash,
                      audit=True, audit_message="crash op"),
    ],
    name="test",
    version="1.0.0",
    authorization_handler=audit_authorize,
)
PROTO_AUDIT.register_audit_handler(_record_audit)
PROTO_GATED = JSONRPCProtocol(
    [
        JSONRPCMethod("whoami", accepts=NoArgs, returns=WhoamiResult, handler=whoami),
        JSONRPCMethod("version", accepts=NoArgs, returns=VersionResult, handler=version, pre_auth=True),
    ],
    name="test",
    version="1.0.0",
)
PROTO_GATED.add_session_setup(
    JSONRPCMethod("setup", accepts=SetupArgs, returns=SetupAck, handler=gated_setup),
    JSONRPCMethod("continue", accepts=ContinueArgs, returns=SetupAck, handler=gated_continue),
)
PROTOS = {"open": PROTO_OPEN, "authz": PROTO_AUTHZ, "audit": PROTO_AUDIT, "gated": PROTO_GATED}

UID = "123e4567-e89b-12d3-a456-426614174000"
UID_UPPER = UID.upper()

# (name, protocol, wire)
CASES = [
    ("happy_create", "open", '{"jsonrpc":"2.0","id":"%s","method":"pool.create","params":{"name":"tank"}}' % UID),
    ("typed_add", "open", '{"jsonrpc":"2.0","id":"%s","method":"add","params":{"a":2,"b":3}}' % UID),
    ("uppercase_id_echoed", "open", '{"jsonrpc":"2.0","id":"%s","method":"add","params":{"a":1,"b":1}}' % UID_UPPER),
    ("method_not_found", "open", '{"jsonrpc":"2.0","id":"%s","method":"nope"}' % UID),
    ("invalid_params_missing", "open", '{"jsonrpc":"2.0","id":"%s","method":"pool.create","params":{}}' % UID),
    ("invalid_params_wrongtype", "open", '{"jsonrpc":"2.0","id":"%s","method":"pool.create","params":{"name":123}}' % UID),
    ("invalid_params_array", "open", '{"jsonrpc":"2.0","id":"%s","method":"add","params":[2,3]}' % UID),
    ("internal_error", "open", '{"jsonrpc":"2.0","id":"%s","method":"boom"}' % UID),
    ("custom_request_failed", "open", '{"jsonrpc":"2.0","id":"%s","method":"fail"}' % UID),
    ("notification_no_reply", "open", '{"jsonrpc":"2.0","method":"pool.create","params":{"name":"tank"}}'),
    ("unknown_method_notification", "open", '{"jsonrpc":"2.0","method":"nope"}'),
    ("malformed_json", "open", "{not json"),
    ("top_level_array", "open", "[1,2,3]"),
    ("bad_jsonrpc_version", "open", '{"jsonrpc":"1.0","id":"%s","method":"add","params":{"a":1,"b":1}}' % UID),
    ("non_uuid_id", "open", '{"jsonrpc":"2.0","id":42,"method":"add","params":{"a":1,"b":1}}'),
    ("null_id", "open", '{"jsonrpc":"2.0","id":null,"method":"add","params":{"a":1,"b":1}}'),
    ("server_info", "open", '{"jsonrpc":"2.0","id":"%s","method":"$/serverInfo"}' % UID),
    ("server_info_no_id", "open", '{"jsonrpc":"2.0","method":"$/serverInfo"}'),
    ("unknown_control", "open", '{"jsonrpc":"2.0","id":"%s","method":"$/nope"}' % UID),
    ("unknown_control_notification", "open", '{"jsonrpc":"2.0","method":"$/nope"}'),
    # authz protocol — authorizer denies `secret_op`
    ("authz_allowed", "authz", '{"jsonrpc":"2.0","id":"%s","method":"add","params":{"a":1,"b":1}}' % UID),
    ("authz_denied", "authz", '{"jsonrpc":"2.0","id":"%s","method":"secret_op","params":{"a":1,"b":1}}' % UID),
    ("authz_denied_bad_params", "authz", '{"jsonrpc":"2.0","id":"%s","method":"secret_op","params":[1,2]}' % UID),
    # audit protocol — secret redaction (params + result), message join, denial/error/notification, gating
    ("audit_login_ok", "audit", '{"jsonrpc":"2.0","id":"%s","method":"login","params":{"user":"bob","password":"hunter2"}}' % UID),
    ("audit_login_denied", "audit", '{"jsonrpc":"2.0","id":"%s","method":"login","params":{"user":"denyme","password":"x"}}' % UID),
    ("audit_login_notification", "audit", '{"jsonrpc":"2.0","method":"login","params":{"user":"bob","password":"hunter2"}}'),
    ("audit_crash", "audit", '{"jsonrpc":"2.0","id":"%s","method":"crash"}' % UID),
    ("audit_ping_no_record", "audit", '{"jsonrpc":"2.0","id":"%s","method":"ping","params":{}}' % UID),
    # gated protocol — single-dispatch (fresh NONE session): gate, pre_auth bypass, wrong-state/shape
    ("gated_blocked_before_setup", "gated", '{"jsonrpc":"2.0","id":"%s","method":"whoami","params":{}}' % UID),
    ("gated_pre_auth_allowed", "gated", '{"jsonrpc":"2.0","id":"%s","method":"version","params":{}}' % UID),
    ("gated_setup_no_id", "gated", '{"jsonrpc":"2.0","method":"$/sessionSetup","params":{"user":"bob"}}'),
    ("gated_continue_wrong_state", "gated", '{"jsonrpc":"2.0","id":"%s","method":"$/sessionSetupContinue","params":{"otp":"x"}}' % UID),
    ("gated_close_wrong_state", "gated", '{"jsonrpc":"2.0","id":"%s","method":"$/sessionClose"}' % UID),
]

# Stateful sequences dispatched on ONE session (lifecycle carries forward across steps).
SEQ_CASES = [
    ("gated_full_flow", "gated", [
        '{"jsonrpc":"2.0","id":"%s","method":"$/sessionSetup","params":{"user":"bob"}}' % UID,        # → init
        '{"jsonrpc":"2.0","id":"%s","method":"whoami","params":{}}' % UID,                            # still gated (init)
        '{"jsonrpc":"2.0","id":"%s","method":"$/sessionSetupContinue","params":{"otp":"x"}}' % UID,   # → established
        '{"jsonrpc":"2.0","id":"%s","method":"whoami","params":{}}' % UID,                            # now allowed
        '{"jsonrpc":"2.0","id":"%s","method":"$/sessionClose"}' % UID,                                # → closed (true)
        '{"jsonrpc":"2.0","id":"%s","method":"whoami","params":{}}' % UID,                            # session is closed
    ]),
]


def _resp(out):
    response = None if out is None else json.loads(out)
    if isinstance(response, dict) and isinstance(response.get("error"), dict):
        response["error"].pop("data", None)  # strip impl-specific detail
    return response


def main():
    records = []
    for name, protocol, wire in CASES:
        proto = PROTOS[protocol]
        sess = proto.new_session()
        _AUDIT_LOG.clear()
        out = proto.dispatch(wire, sess)
        records.append({"name": name, "protocol": protocol, "wire": wire,
                        "response": _resp(out), "audits": list(_AUDIT_LOG), "steps": []})
    for name, protocol, wires in SEQ_CASES:
        proto = PROTOS[protocol]
        sess = proto.new_session()  # ONE session for the whole sequence
        steps = []
        for w in wires:
            steps.append({"wire": w, "response": _resp(proto.dispatch(w, sess))})
        records.append({"name": name, "protocol": protocol, "wire": "",
                        "response": None, "audits": [], "steps": steps})

    out_path = os.path.join(HERE, "golden.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump({"cases": records}, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"wrote {len(records)} cases to {os.path.relpath(out_path)}")


if __name__ == "__main__":
    main()
