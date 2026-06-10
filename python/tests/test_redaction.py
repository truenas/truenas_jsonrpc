"""Secret-field redaction tests."""
import json
import uuid
from typing import Annotated, Optional, Union

import msgspec

from truenas_pyjsonrpc import (
    SECRET,
    AuthorizationResponse,
    JSONRPCMethod,
    JSONRPCProtocol,
    redact,
)
from truenas_pyjsonrpc.redaction import REDACTED, compile_plan


def _redact(obj):
    return redact(obj, compile_plan(type(obj)))


class Login(msgspec.Struct):
    user: str
    password: Annotated[str, SECRET]


class NoSecrets(msgspec.Struct):
    a: int
    b: str


class Inner(msgspec.Struct):
    token: Annotated[str, SECRET]
    ok: int


class Nested(msgspec.Struct):
    name: str
    inner: Inner


class OptSecret(msgspec.Struct):
    maybe: Optional[Annotated[str, SECRET]] = None


class Container(msgspec.Struct):
    items: list[Inner]
    bag: dict[str, Inner]


class Renamed(msgspec.Struct):
    api_key: Annotated[str, SECRET] = msgspec.field(default="", name="apiKey")


class A(msgspec.Struct, tag="a"):
    val: Annotated[str, SECRET]


class B(msgspec.Struct, tag="b"):
    val: int


class UnionHolder(msgspec.Struct):
    item: Union[A, B]


class Node(msgspec.Struct):
    secret: Annotated[str, SECRET]
    child: "Node | None" = None


# --- redact() unit tests ------------------------------------------------------
def test_top_level_secret_masked():
    assert _redact(Login(user="u", password="hunter2")) == {
        "user": "u", "password": REDACTED}


def test_no_secrets_plan_is_none_and_passthrough_is_identity():
    assert compile_plan(NoSecrets) is None
    obj = NoSecrets(a=1, b="x")
    assert redact(obj, None) is obj                       # no plan -> no copy


def test_nested_struct_secret():
    assert _redact(Nested(name="n", inner=Inner(token="t", ok=1))) == {
        "name": "n", "inner": {"token": REDACTED, "ok": 1}}


def test_optional_secret_value_masked_none_stays_null():
    assert _redact(OptSecret(maybe="x")) == {"maybe": REDACTED}
    assert _redact(OptSecret(maybe=None)) == {"maybe": None}


def test_container_secrets():
    assert _redact(Container(items=[Inner(token="t1", ok=1)],
                            bag={"k": Inner(token="t2", ok=2)})) == {
        "items": [{"token": REDACTED, "ok": 1}],
        "bag": {"k": {"token": REDACTED, "ok": 2}}}


def test_renamed_secret_masked_by_wire_name():
    assert _redact(Renamed(api_key="abc")) == {"apiKey": REDACTED}   # encode_name


def test_tagged_union_only_matching_member_masked():
    assert _redact(UnionHolder(item=A(val="s"))) == {
        "item": {"type": "a", "val": REDACTED}}
    assert _redact(UnionHolder(item=B(val=7))) == {       # B.val not secret
        "item": {"type": "b", "val": 7}}


def test_recursive_struct_terminates_and_masks_each_level():
    obj = Node(secret="s1", child=Node(secret="s2", child=Node(secret="s3")))
    assert _redact(obj) == {
        "secret": REDACTED,
        "child": {"secret": REDACTED,
                  "child": {"secret": REDACTED, "child": None}}}


# --- end-to-end: audit sees redacted, wire + authz see the real value --------
def test_audit_redacted_wire_and_authz_real():
    audit_seen: dict = {}
    authz_seen: dict = {}

    def handler(request, session_state, request_state):
        return Login(user=request.user, password=request.password)

    def authz(request, session_state):
        authz_seen["pw"] = request.params.password       # live Struct, real value
        return AuthorizationResponse(True)

    def audit(request, response, session_state, audit_message=None):
        audit_seen["params_pw"] = request.params["password"]    # redacted -> dict
        audit_seen["result_pw"] = response["result"]["password"]

    p = JSONRPCProtocol(
        [JSONRPCMethod("login", accepts=Login, returns=Login, handler=handler,
                       audit=True)],
        authorization_handler=authz, audit_handler=audit)
    u = str(uuid.uuid4())
    wire = msgspec.json.decode(p.dispatch(json.dumps(
        {"jsonrpc": "2.0", "method": "login", "id": u,
         "params": {"user": "u", "password": "hunter2"}})))

    assert wire["result"]["password"] == "hunter2"       # real value on the wire
    assert authz_seen["pw"] == "hunter2"                 # real value to authz
    assert audit_seen == {"params_pw": REDACTED, "result_pw": REDACTED}  # masked


# --- redact() never mutates the live object (real plan) ----------------------
def test_redact_real_plan_returns_copy_and_leaves_original_intact():
    obj = Nested(name="n", inner=Inner(token="t", ok=1))
    red = redact(obj, compile_plan(Nested))
    assert red == {"name": "n", "inner": {"token": REDACTED, "ok": 1}}
    assert red is not obj                                 # a builtins copy
    # the live object (and its nested struct) still hold the REAL secret
    assert isinstance(obj.inner, Inner) and obj.inner.token == "t"


# --- fixed heterogeneous tuple: positional masking ---------------------------
class TupleHolder(msgspec.Struct):
    pair: tuple[Annotated[str, SECRET], int]


def test_fixed_tuple_masks_only_secret_position():
    # regression: to_builtins keeps the tuple a tuple; _apply must still redact it
    # (position 0 masked, position 1 kept). Output is normalized to a list.
    assert _redact(TupleHolder(pair=("s", 7))) == {"pair": [REDACTED, 7]}


class VarTupleHolder(msgspec.Struct):
    tokens: tuple[Annotated[str, SECRET], ...]            # compiles to a "list" plan


def test_var_tuple_masks_every_element():
    assert _redact(VarTupleHolder(tokens=("a", "b"))) == {
        "tokens": [REDACTED, REDACTED]}


# --- untagged Union[Struct, scalar]: best-effort path ------------------------
class Detail(msgspec.Struct):
    token: Annotated[str, SECRET]
    label: str


class UntaggedHolder(msgspec.Struct):
    item: Union[Detail, int]                              # msgspec-legal (object|int)


def test_untagged_union_masks_struct_arm():
    assert _redact(UntaggedHolder(item=Detail(token="t", label="x"))) == {
        "item": {"token": REDACTED, "label": "x"}}


def test_untagged_union_passes_scalar_arm_through():
    assert _redact(UntaggedHolder(item=5)) == {"item": 5}   # struct plan no-ops


# --- masking is type-erasing (non-str secret -> string sentinel) -------------
class IntSecret(msgspec.Struct):
    pin: Annotated[int, SECRET]


def test_non_str_secret_masks_to_string_sentinel():
    # documents the contract: the audit view replaces with the REDACTED *string*
    # regardless of the field's real type (int here, not the int 1234).
    assert _redact(IntSecret(pin=1234)) == {"pin": REDACTED}
