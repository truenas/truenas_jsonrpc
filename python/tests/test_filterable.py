"""Tests for FilterableJSONRPCMethod.

Cover: accepts augmentation (the two optional query-filters/query-options fields,
non-breaking + clash rejection), dispatch narrowing (filters, get -> single, count
-> int, get-no-match -> REQUEST_FAILED, invalid filter -> INVALID_PARAMS), and the
codegen emission of the typed query method. Filtering is delegated to the
truenas_pyfilter C engine, so these import it (skipped if unavailable).
"""
import json
import uuid

import msgspec
import pytest

from truenas_pyjsonrpc import FilterableJSONRPCMethod, JSONRPCProtocol
from truenas_pyjsonrpc.query import QueryOptions, augment_accepts
from truenas_pyjsonrpc.types import JSONRPCError

pytest.importorskip("truenas_pyfilter")
from truenas_pyfilter import tnfilter  # noqa: E402


class _Args(msgspec.Struct):
    pass


class _Entry(msgspec.Struct):
    id: int
    name: str


_DATA = [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}, {"id": 3, "name": "a"}]


def _handler(request, session_state, request_state, filters, options):
    # Push-down: the handler streams its source through the compiled query (here a
    # list; in practice a lazy generator) so the full set is never materialized.
    return tnfilter(_DATA, filters=filters, options=options)


def _protocol():
    return JSONRPCProtocol(
        [FilterableJSONRPCMethod("x.query", accepts=_Args, entry=_Entry, handler=_handler)],
        name="t", version="1")


def _call(proto, params):
    msg = json.dumps({"jsonrpc": "2.0", "method": "x.query",
                      "id": str(uuid.uuid4()), "params": params}).encode()
    return json.loads(proto.dispatch(msg))


# --- accepts augmentation -------------------------------------------------
def test_augment_adds_optional_query_fields():
    aug = augment_accepts(_Args)
    wire = {f.name: f.encode_name for f in msgspec.structs.fields(aug)}
    assert wire["query_filters"] == "query-filters"
    assert wire["query_options"] == "query-options"
    # both optional: an empty object decodes with sensible defaults
    obj = msgspec.json.decode(b"{}", type=aug)
    assert obj.query_filters == []
    assert isinstance(obj.query_options, QueryOptions)


def test_augment_rejects_field_clash():
    class Clash(msgspec.Struct):
        query_filters: list = []

    with pytest.raises(TypeError):
        augment_accepts(Clash)


# --- dispatch -------------------------------------------------------------
def test_dispatch_no_filter_returns_all():
    assert _call(_protocol(), {})["result"] == _DATA


def test_dispatch_filter_narrows():
    r = _call(_protocol(), {"query-filters": [["name", "=", "a"]]})["result"]
    assert [x["id"] for x in r] == [1, 3]


def test_dispatch_count_returns_int():
    r = _call(_protocol(), {"query-filters": [["name", "=", "a"]],
                            "query-options": {"count": True}})["result"]
    assert r == 2


def test_dispatch_get_returns_single_record():
    r = _call(_protocol(), {"query-filters": [["name", "=", "a"]],
                            "query-options": {"get": True}})["result"]
    assert r == {"id": 1, "name": "a"}


def test_dispatch_get_no_match_is_request_failed():
    e = _call(_protocol(), {"query-filters": [["name", "=", "zzz"]],
                            "query-options": {"get": True}})["error"]
    assert e["code"] == JSONRPCError.REQUEST_FAILED


def test_dispatch_invalid_filter_is_invalid_params():
    e = _call(_protocol(), {"query-filters": [["name", "??", "a"]]})["error"]
    assert e["code"] == JSONRPCError.INVALID_PARAMS


# --- codegen --------------------------------------------------------------
def test_codegen_emits_typed_query_method():
    import codegen

    src = codegen.generate(_protocol(), class_name="C")
    assert "def x_query(self, request: _Args, *," in src
    assert "query_filters: QueryFilters | None = None" in src
    assert "query_options: QueryOptions | None = None" in src
    assert "-> list[_Entry] | _Entry | int:" in src
    assert "self._typed_filterable(" in src
    # the framework query types are imported in the generated module
    assert "from truenas_pyjsonrpc import QueryFilters, QueryOptions" in src
