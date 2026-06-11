"""Authorization + audit pipeline tests for JSONRPCProtocol."""
import json
import uuid

import msgspec
import pytest

from truenas_pyjsonrpc import (
    AuthorizationResponse,
    JSONRPCError,
    JSONRPCMethod,
    JSONRPCProtocol,
    JSONRPCRequest,
)


class Args(msgspec.Struct):
    name: str


class Result(msgspec.Struct):
    id: int
    name: str


class NoArgs(msgspec.Struct):
    pass


def _create(request, session_state, request_state) -> Result:
    return Result(id=7, name=request.name)


def _boom(request, session_state, request_state) -> Result:
    raise RuntimeError("kaboom")


def _methods() -> list[JSONRPCMethod]:
    return [
        JSONRPCMethod("pool.create", accepts=Args, returns=Result, handler=_create,
                      audit=True),
        JSONRPCMethod("boom", accepts=Args, handler=_boom, audit=True),
    ]


def _allow(request, session_state):
    return AuthorizationResponse(True)


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


# --- authorized path ----------------------------------------------------------
def test_authorized_dispatches_and_audits():
    u = uid()
    seen = []
    p = JSONRPCProtocol(
        _methods(),
        authorization_handler=_allow,
        audit_handler=lambda request, response, session_state, audit_message=None: seen.append(
            (request, response)), name="test", version="1.0.0"
    )
    r = decode(p.dispatch(req("pool.create", {"name": "tank"}, id=u)))
    assert r == {"jsonrpc": "2.0", "result": {"id": 7, "name": "tank"}, "id": u}
    assert len(seen) == 1
    request, response = seen[0]
    assert isinstance(request, JSONRPCRequest)
    assert request.method == "pool.create" and request.id == u
    assert isinstance(request.params, Args) and request.params.name == "tank"
    # audit sees the validated return Struct inside the success envelope
    assert "error" not in response and response["result"].name == "tank"


def test_no_handlers_behaves_as_plain_dispatch():
    u = uid()
    p = JSONRPCProtocol(_methods(), name="test", version="1.0.0")
    r = decode(p.dispatch(req("pool.create", {"name": "tank"}, id=u)))
    assert r == {"jsonrpc": "2.0", "result": {"id": 7, "name": "tank"}, "id": u}


def test_authz_and_audit_receive_session_state():
    captured = []
    p = JSONRPCProtocol(
        _methods(),
        authorization_handler=lambda request, session_state: (
            captured.append(("authz", session_state)) or AuthorizationResponse(True)),
        audit_handler=lambda request, response, session_state, audit_message=None: captured.append(
            ("audit", session_state)), name="test", version="1.0.0"
    )
    sentinel = {"session": "abc"}
    session = p.new_session(server_state=sentinel)
    p.dispatch(req("pool.create", {"name": "x"}, id=uid()), session)
    assert captured == [("authz", session), ("audit", session)]
    assert captured[0][1] is session and captured[1][1] is session


def test_authz_handler_called_by_keyword():
    seen = {}

    def authz(**kw):
        seen.update(kw)
        return AuthorizationResponse(True)

    p = JSONRPCProtocol(_methods(), authorization_handler=authz, name="test", version="1.0.0")
    p.dispatch(req("pool.create", {"name": "x"}, id=uid()),
               p.new_session(server_state="S"))
    assert set(seen) == {"request", "session_state"}
    assert isinstance(seen["request"], JSONRPCRequest)
    assert seen["session_state"].server_state_internal == "S"


# --- denied path --------------------------------------------------------------
def test_denied_skips_dispatch_audits_and_returns_error():
    u = uid()
    dispatched = []
    audited = []

    def create(request, session_state, request_state):
        dispatched.append(1)
        return Result(id=7, name=request.name)

    p = JSONRPCProtocol(
        [JSONRPCMethod("pool.create", accepts=Args, returns=Result, handler=create,
                       audit=True)],
        authorization_handler=lambda request, session_state: AuthorizationResponse(
            False, "nope", {"reason": "rbac"}),
        audit_handler=lambda request, response, session_state, audit_message=None: audited.append(response), name="test", version="1.0.0"
    )
    r = decode(p.dispatch(req("pool.create", {"name": "tank"}, id=u)))
    assert dispatched == []                                  # dispatch skipped
    assert r["error"]["code"] == JSONRPCError.NOT_AUTHORIZED
    assert r["error"]["message"] == "nope"
    assert r["error"]["data"] == {"reason": "rbac"}
    assert r["id"] == u
    assert len(audited) == 1 and audited[0]["error"]["code"] == JSONRPCError.NOT_AUTHORIZED


def test_denied_default_message_omits_none_data():
    p = JSONRPCProtocol(
        _methods(),
        authorization_handler=lambda request, session_state: AuthorizationResponse(False), name="test", version="1.0.0"
    )
    r = decode(p.dispatch(req("pool.create", {"name": "x"}, id=uid())))
    assert r["error"]["code"] == JSONRPCError.NOT_AUTHORIZED
    assert r["error"]["message"] == "Not authorized"
    assert "data" not in r["error"]


# --- audit sees success + error ----------------------------------------------
def test_audit_sees_handler_error():
    audited = []
    p = JSONRPCProtocol(
        _methods(),
        audit_handler=lambda request, response, session_state, audit_message=None: audited.append(response), name="test", version="1.0.0"
    )
    r = decode(p.dispatch(req("boom", {"name": "x"}, id=uid())))
    assert r["error"]["code"] == JSONRPCError.INTERNAL_ERROR
    assert len(audited) == 1
    assert audited[0]["error"]["code"] == JSONRPCError.INTERNAL_ERROR


def test_audit_exception_does_not_break_response():
    u = uid()

    def audit(request, response, session_state, audit_message=None):
        raise RuntimeError("audit blew up")

    p = JSONRPCProtocol(_methods(), audit_handler=audit, name="test", version="1.0.0")
    r = decode(p.dispatch(req("pool.create", {"name": "tank"}, id=u)))
    assert r == {"jsonrpc": "2.0", "result": {"id": 7, "name": "tank"}, "id": u}


# --- notifications ------------------------------------------------------------
def test_notification_authorized_dispatched_audited_returns_none():
    dispatched = []
    audited = []
    p = JSONRPCProtocol(
        [JSONRPCMethod("note", accepts=NoArgs, audit=True,
                       handler=lambda request, session_state, request_state: dispatched.append(1))],
        authorization_handler=_allow,
        audit_handler=lambda request, response, session_state, audit_message=None: audited.append(response), name="test", version="1.0.0"
    )
    assert p.dispatch(req("note", {})) is None               # no id => notification
    assert dispatched == [1]
    assert len(audited) == 1 and "error" not in audited[0]


def test_notification_denied_audited_returns_none():
    dispatched = []
    audited = []
    p = JSONRPCProtocol(
        [JSONRPCMethod("note", accepts=NoArgs, audit=True,
                       handler=lambda request, session_state, request_state: dispatched.append(1))],
        authorization_handler=lambda request, session_state: AuthorizationResponse(False),
        audit_handler=lambda request, response, session_state, audit_message=None: audited.append(response), name="test", version="1.0.0"
    )
    assert p.dispatch(req("note", {})) is None
    assert dispatched == []                                   # denied => not dispatched
    assert len(audited) == 1 and audited[0]["error"]["code"] == JSONRPCError.NOT_AUTHORIZED


# --- authz faults => INTERNAL_ERROR ------------------------------------------
def test_authz_raising_is_internal_error_and_audited():
    audited = []

    def authz(request, session_state):
        raise RuntimeError("authz blew up")

    p = JSONRPCProtocol(
        _methods(),
        authorization_handler=authz,
        audit_handler=lambda request, response, session_state, audit_message=None: audited.append(response), name="test", version="1.0.0"
    )
    r = decode(p.dispatch(req("pool.create", {"name": "x"}, id=uid())))
    assert r["error"]["code"] == JSONRPCError.INTERNAL_ERROR
    assert audited[0]["error"]["code"] == JSONRPCError.INTERNAL_ERROR


def test_authz_returning_non_response_is_internal_error():
    p = JSONRPCProtocol(
        _methods(),
        authorization_handler=lambda request, session_state: True, name="test", version="1.0.0"   # not Authz...
    )
    r = decode(p.dispatch(req("pool.create", {"name": "x"}, id=uid())))
    assert r["error"]["code"] == JSONRPCError.INTERNAL_ERROR


# --- pre-method errors bypass authz/audit ------------------------------------
def test_pre_method_errors_skip_authz_and_audit():
    cases = [
        ("{not json", JSONRPCError.INVALID_JSON),
        ('"a string"', JSONRPCError.INVALID_REQUEST),
        (f'{{"jsonrpc":"2.0","method":"nope","id":"{uid()}"}}',
         JSONRPCError.METHOD_NOT_FOUND),
    ]
    for wire, expect_code in cases:
        calls = []
        p = JSONRPCProtocol(
            _methods(),
            authorization_handler=lambda request, session_state: (
                calls.append("authz") or AuthorizationResponse(True)),
            audit_handler=lambda request, response, session_state, audit_message=None: calls.append("audit"), name="test", version="1.0.0"
        )
        r = decode(p.dispatch(wire))
        assert r["error"]["code"] == expect_code
        assert calls == []                                   # neither ran


def test_invalid_params_skips_authz_and_audit():
    calls = []
    p = JSONRPCProtocol(
        _methods(),
        authorization_handler=lambda request, session_state: (
            calls.append("authz") or AuthorizationResponse(True)),
        audit_handler=lambda request, response, session_state, audit_message=None: calls.append("audit"), name="test", version="1.0.0"
    )
    r = decode(p.dispatch(req("pool.create", {}, id=uid())))   # missing 'name'
    assert r["error"]["code"] == JSONRPCError.INVALID_PARAMS
    assert calls == []


# --- registration setters -----------------------------------------------------
def test_register_setters_toggle_and_validate():
    p = JSONRPCProtocol(_methods(), name="test", version="1.0.0")
    p.register_authorization_handler(
        lambda request, session_state: AuthorizationResponse(False))
    assert decode(p.dispatch(req("pool.create", {"name": "x"}, id=uid())))[
        "error"]["code"] == JSONRPCError.NOT_AUTHORIZED
    p.register_authorization_handler(None)                   # clear -> plain dispatch
    assert decode(p.dispatch(req("pool.create", {"name": "x"}, id=uid())))[
        "result"] == {"id": 7, "name": "x"}
    with pytest.raises(TypeError):
        p.register_authorization_handler(123)
    with pytest.raises(TypeError):
        p.register_audit_handler(123)


# --- per-method roles (declarative RBAC metadata, surfaced to authorize) -------
def _role_methods() -> list[JSONRPCMethod]:
    return [
        JSONRPCMethod("vm.create", accepts=Args, returns=Result, handler=_create,
                      roles=["VM_WRITE"], audit=True),
        JSONRPCMethod("vm.read", accepts=Args, returns=Result, handler=_create,
                      roles=["VM_READ", "VM_WRITE"]),          # OR-semantics
        JSONRPCMethod("ping", accepts=Args, returns=Result, handler=_create),   # no roles
    ]


def _role_authorizer(granted):
    """OR-semantics enforcer: allow if the method declares no roles or the session's granted
    roles intersect the required ones (the documented `request.roles` pattern)."""
    def authz(request, session_state):
        if not request.roles or set(request.roles) & set(granted):
            return AuthorizationResponse(True)
        return AuthorizationResponse(False, "missing required role")
    return authz


def test_method_roles_surfaced_to_authorize():
    seen = {}

    def authz(request, session_state):
        seen[request.method] = request.roles
        return AuthorizationResponse(True)

    p = JSONRPCProtocol(_role_methods(), authorization_handler=authz, name="test", version="1.0.0")
    for m in ("vm.create", "vm.read", "ping"):
        decode(p.dispatch(req(m, {"name": "x"}, id=uid())))
    assert seen["vm.create"] == ("VM_WRITE",)
    assert seen["vm.read"] == ("VM_READ", "VM_WRITE")          # tuple, ordered
    assert seen["ping"] == ()                                  # no declared roles


def test_roles_enforced_allow_on_overlap():
    p = JSONRPCProtocol(_role_methods(),
                        authorization_handler=_role_authorizer({"VM_WRITE"}), name="test", version="1.0.0")
    r = decode(p.dispatch(req("vm.create", {"name": "x"}, id=uid())))
    assert r["result"] == {"id": 7, "name": "x"}              # VM_WRITE overlaps -> allowed


def test_roles_enforced_deny_without_overlap():
    u = uid()
    p = JSONRPCProtocol(_role_methods(),
                        authorization_handler=_role_authorizer({"VM_READ"}), name="test", version="1.0.0")
    r = decode(p.dispatch(req("vm.create", {"name": "x"}, id=u)))   # needs VM_WRITE
    assert r["error"]["code"] == JSONRPCError.NOT_AUTHORIZED
    assert r["id"] == u
    # vm.read accepts VM_READ (OR), and ping has no requirement -> both allowed
    assert decode(p.dispatch(req("vm.read", {"name": "x"}, id=uid())))["result"]["id"] == 7
    assert decode(p.dispatch(req("ping", {"name": "x"}, id=uid())))["result"]["id"] == 7


def test_roles_in_describe():
    d = JSONRPCProtocol(_role_methods(), name="test", version="1.0.0").describe()
    assert d["vm.create"]["roles"] == ["VM_WRITE"]
    assert d["vm.read"]["roles"] == ["VM_READ", "VM_WRITE"]
    assert d["ping"]["roles"] == []


def test_roles_in_audit_request():
    seen = []
    p = JSONRPCProtocol(
        _role_methods(),
        audit_handler=lambda request, response, session_state, audit_message=None: seen.append(
            request.roles), name="test", version="1.0.0")
    decode(p.dispatch(req("vm.create", {"name": "x"}, id=uid())))   # audit=True
    assert seen == [("VM_WRITE",)]                            # roles reach the audit handler


def test_fd_transfer_method_carries_roles():
    from truenas_pyjsonrpc import JSONRPCFdTransferMethod, TransferDirection
    m = JSONRPCFdTransferMethod(
        "file.download", accepts=Args, returns=Result,
        direction=TransferDirection.DOWNLOAD,
        negotiate=lambda *a, **k: {}, transfer=lambda *a, **k: None, roles=["FILE_READ"])
    assert m.roles == ("FILE_READ",)


def test_roles_must_be_strings():
    with pytest.raises(TypeError):
        JSONRPCMethod("bad", accepts=Args, returns=Result, handler=_create, roles=[1, 2])
