#!/usr/bin/env python3
"""Generate the truenas-filter A/B **golden corpus** from the `truenas_pyfilter` C engine.

The datasets and case matrix are derived from the upstream engine's own test suite
(`/CODE/claudedir/truens_pos/tests/test_filter_list.py`) per the plan: the Python data
arrays are converted to JSON (canonicalized via a json round-trip, so tuples become arrays
and the data is exactly what the Rust engine will see), run through the **C** engine
(`compile_filters` / `compile_options` / `tnfilter` / `match`) — the oracle — and the
results written to ``truenas-filter/tests/conformance/golden.json``. The Rust conformance
test replays each case through the Rust engine and asserts it is **byte-identical**.

`SAMPLE_AUDIT` (datetime objects) is intentionally excluded — datetime ordering is not
JSON-representable without changing semantics; the protocol always sees JSON on the wire.

Run from anywhere; needs only the installed `truenas_pyfilter`:

    python3 rust/truenas-filter/conformance/generate.py
"""
from __future__ import annotations

import json
import os

from truenas_pyfilter import compile_filters, compile_options, match, tnfilter

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.abspath(os.path.join(HERE, "..", "tests", "conformance", "golden.json"))

# --- datasets (copied from truens_pos/tests/test_filter_list.py; JSON-friendly) ---------
DATASETS = {
    "BASIC": [
        {"id": 1, "name": "alice", "score": 100, "active": True, "tags": ["a", "b"]},
        {"id": 2, "name": "bob", "score": 85, "active": True, "tags": ["b", "c"]},
        {"id": 3, "name": "carol", "score": 90, "active": False, "tags": ["a", "c"]},
        {"id": 4, "name": "dave", "score": 70, "active": False, "tags": ["d"]},
        {"id": 5, "name": "eve", "score": 95, "active": True, "tags": ["a", "b", "c"]},
    ],
    "NULLS": [
        {"id": 1, "value": "alpha", "num": 10},
        {"id": 2, "value": None, "num": 20},
        {"id": 3, "value": "beta", "num": 30},
        {"id": 4, "num": 40},  # 'value' key absent
    ],
    "NESTED": [
        {"id": 1, "user": {"name": "alice", "role": "admin"}, "dept": {"name": "eng"}},
        {"id": 2, "user": {"name": "bob", "role": "user"}, "dept": {"name": "hr"}},
        {"id": 3, "user": {"name": "carol", "role": "admin"}, "dept": {"name": "eng"}},
        {"id": 4, "user": {"name": "dave", "role": "user"}, "dept": {"name": "fin"}},
    ],
    "WITH_CASE": [
        {"foo": "foo", "number": 1},
        {"foo": "Foo", "number": 2},
        {"foo": "foO_", "number": 3},
        {"foo": "bar", "number": 4},
    ],
    "WITH_LISTODICTS": [
        {"foo": "foo", "list": [{"number": 1}, {"number": 2}]},
        {"foo": "Foo", "list": [{"number": 2}, {"number": 3}]},
        {"foo": "foO_", "list": [{"number": 3}]},
        {"foo": "bar", "list": [{"number": 0}]},
    ],
    "WITH_DEEP_LISTS": [
        {"foo": "foo", "list": [{"list2": [{"number": 1}, {"number": 2}]}, {"list2": [{"number": 3}]}]},
        {"foo": "bar", "list": [{"list2": [{"number": 2}, {"number": 4}]}]},
    ],
    "INCONSISTENT": [
        {"foo": "foo", "list": [{"number": 1}, "canary"]},
        {"foo": "Foo", "list": [1, {"number": 3}]},
        {"foo": "foO_", "list": [{"number": 3}, ("bob", 1)]},
        {"foo": "bar", "list": [{"number": 0}]},
        {"foo": "bar", "list": "whointheirrightmindwoulddothis"},
        {"foo": "bar"},
        {"foo": "bar", "list": None},
        {"foo": "bar", "list": 42},
        "canary",  # top-level non-dict item
    ],
    "COMPLEX_DATA": [
        {
            "timestamp": "2022-11-10T07:40:17",
            "type": "Authentication",
            "Authentication": {
                "status": "NT_STATUS_NO_SUCH_USER",
                "clientAccount": "awalker325@outlook.com",
                "version": {"major": 1, "minor": 2},
            },
        },
        {
            "timestamp": "2023-01-24T12:37:39",
            "type": "Authentication",
            "Authentication": {
                "status": "NT_STATUS_OK",
                "clientAccount": "joiner",
                "version": {"major": 1, "minor": 3},
            },
        },
    ],
}

# Canonicalize to exactly the JSON the Rust engine sees (tuples -> arrays, etc.).
DATASETS = {k: json.loads(json.dumps(v)) for k, v in DATASETS.items()}

# --- case matrix (ds, filters, options); mirrors test_filter_list.py categories ---------
CASES: list[tuple[str, str, list, dict]] = []


def c(label, ds, filters, **opts):
    CASES.append((label, ds, filters, opts))


# comparison operators
for op, val in [("=", "alice"), ("!=", "alice")]:
    c(f"cmp/name{op}", "BASIC", [["name", op, val]])
for op in [">", ">=", "<", "<="]:
    c(f"cmp/score{op}90", "BASIC", [["score", op, 90]])
c("cmp/id=int", "BASIC", [["id", "=", 3]])
c("cmp/active=true", "BASIC", [["active", "=", True]])
c("cmp/active=false", "BASIC", [["active", "=", False]])
# None / missing-key
c("none/eq_none", "NULLS", [["value", "=", None]])
c("none/ne_none", "NULLS", [["value", "!=", None]])
c("none/missing_key", "BASIC", [["nonexistent", "=", "x"]])
# string operators
for op, val in [("^", "a"), ("!^", "a"), ("$", "e"), ("!$", "e")]:
    c(f"str/{op}{val}", "BASIC", [["name", op, val]])
c("str/none_sw", "NULLS", [["value", "^", "al"]])
c("str/none_ew", "NULLS", [["value", "$", "ha"]])
c("str/none_nsw", "NULLS", [["value", "!^", "z"]])
# membership
c("mem/in", "BASIC", [["id", "in", [1, 3, 5]]])
c("mem/in_str", "BASIC", [["name", "in", ["alice", "eve"]]])
c("mem/nin", "BASIC", [["id", "nin", [1, 2]]])
c("mem/rin", "BASIC", [["tags", "rin", "a"]])
c("mem/rnin", "BASIC", [["tags", "rnin", "a"]])
c("mem/in_none_in", "NULLS", [["value", "in", [None, "alpha"]]])
c("mem/in_none_notin", "NULLS", [["value", "in", ["alpha", "beta"]]])
c("mem/nin_none_src", "NULLS", [["value", "nin", ["alpha"]]])
c("mem/rin_substr", "BASIC", [["name", "rin", "ali"]])
# case-insensitive
for op, val in [("C=", "FOO"), ("C^", "FO"), ("C$", "OO")]:
    c(f"ci/{op}", "WITH_CASE", [["foo", op, val]])
c("ci/in", "WITH_CASE", [["foo", "Cin", ["FOO", "BAR"]]])
c("ci/nested", "COMPLEX_DATA", [["Authentication.clientAccount", "C=", "JOINER"]])
c("ci/none", "NULLS", [["value", "C=", "ALPHA"]])
# compound / OR
c("bool/and", "BASIC", [["active", "=", True], ["score", ">", 90]])
c("bool/or", "BASIC", [["OR", [["name", "=", "bob"], ["name", "=", "eve"]]]])
c("bool/or_and", "BASIC", [["OR", [[["active", "=", True], ["score", ">", 90]], [["name", "=", "dave"]]]]])
c("bool/nested_or", "BASIC", [["OR", [["name", "=", "alice"], ["OR", [["name", "=", "bob"]]]]]])
# path traversal
c("path/dotted", "NESTED", [["user.role", "=", "admin"]])
c("path/deep", "COMPLEX_DATA", [["Authentication.version.major", "=", 1]])
c("path/deep_minor", "COMPLEX_DATA", [["Authentication.version.minor", "=", 3]])
c("path/array_index", "WITH_LISTODICTS", [["list.0.number", "=", 2]])
c("path/array_oob", "WITH_LISTODICTS", [["list.5.number", "=", 1]])
c("path/wildcard", "WITH_LISTODICTS", [["list.*.number", "=", 3]])
c("path/wildcard_deep", "WITH_DEEP_LISTS", [["list.*.list2.*.number", "=", 4]])
c("path/escaped_dot", "NESTED", [["user\\.role", "=", "admin"]])  # literal key 'user.role' (absent)
c("path/inconsistent_wild", "INCONSISTENT", [["list.*.number", "=", 3]])
c("path/top_level_nondict", "INCONSISTENT", [["foo", "=", "canary"]])
# options
c("opt/get", "BASIC", [["active", "=", True]], get=True)
c("opt/get_nomatch", "BASIC", [["name", "=", "zzz"]], get=True)
c("opt/count", "BASIC", [["active", "=", True]], count=True)
c("opt/offset_limit", "BASIC", [], offset=1, limit=2, order_by=["id"])
c("opt/limit_only", "BASIC", [], limit=2, order_by=["id"])
c("opt/order_asc", "BASIC", [], order_by=["name"])
c("opt/order_desc", "BASIC", [], order_by=["-name"])
c("opt/order_int", "BASIC", [], order_by=["score"])
c("opt/order_nested", "NESTED", [], order_by=["user.name"])
c("opt/order_nulls_first", "NULLS", [], order_by=["nulls_first:value"])
c("opt/order_nulls_last", "NULLS", [], order_by=["nulls_last:value"])
c("opt/order_nulls_first_rev", "NULLS", [], order_by=["nulls_first:-value"])
c("opt/order_multi", "BASIC", [], order_by=["active", "-score"])
c("opt/count_with_offset", "BASIC", [["active", "=", True]], count=True, offset=1, limit=1)
c("opt/limit_no_order", "BASIC", [], limit=2)  # cap path: page without ordering
c("opt/count_get", "BASIC", [["name", "=", "a"]], count=True, get=True)  # count + shortcircuit
# error cases
c("err/unknown_op", "BASIC", [["name", "??", "x"]])
c("err/cmp_incomparable", "NULLS", [["value", ">", "a"]])
c("err/order_null_no_prefix", "NULLS", [], order_by=["value"])
c("err/get_limit", "BASIC", [], get=True, limit=5)
c("err/get_offset", "BASIC", [], get=True, offset=3)
c("err/limit_too_big", "BASIC", [], limit=10001)
c("err/empty_order_field", "BASIC", [], order_by=[""])

# --- match() cases: (item, filters) -> bool (predicate; select is not supported) --------
MATCH_CASES: list[tuple[str, object, list]] = [
    ("match/hit", DATASETS["BASIC"][0], [["name", "=", "alice"]]),
    ("match/miss", DATASETS["BASIC"][0], [["name", "=", "zzz"]]),
]


def run_filter(ds_data, filters, options):
    try:
        cf = compile_filters(filters)
        co = compile_options(**options)
    except (ValueError, TypeError):
        return {"error": "compile"}
    try:
        out = tnfilter(ds_data, filters=cf, options=co)
    except (ValueError, TypeError):
        return {"error": "eval"}
    return {"count": out} if isinstance(out, int) else {"rows": out}


def run_match(item, filters):
    try:
        cf = compile_filters(filters)
    except (ValueError, TypeError):
        return {"error": "compile"}
    try:
        out = match(item, filters=cf)
    except (ValueError, TypeError):
        return {"error": "eval"}
    # The Rust port's `tnmatch` is a pure predicate (no select), so compare the boolean.
    return {"matched": out is not None}


def main() -> None:
    cases = [
        {"label": label, "dataset": ds, "filters": filters, "options": opts,
         "result": run_filter(DATASETS[ds], filters, opts)}
        for (label, ds, filters, opts) in CASES
    ]
    match_cases = [
        {"label": label, "item": item, "filters": filters, "result": run_match(item, filters)}
        for (label, item, filters) in MATCH_CASES
    ]
    os.makedirs(os.path.dirname(GOLDEN), exist_ok=True)
    with open(GOLDEN, "w") as f:
        json.dump({"datasets": DATASETS, "cases": cases, "match_cases": match_cases},
                  f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"wrote {len(cases)} filter cases + {len(match_cases)} match cases to {GOLDEN}")


if __name__ == "__main__":
    main()
