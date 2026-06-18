#!/usr/bin/env python3
"""A/B check: the OpenRPC document api-specs/gen.py emits from a spec must structurally equal what the
normative python/openrpc_gen.py produces for the *same* API. Single source of truth — the spec: this
builds live msgspec Structs + a JSONRPCProtocol from the spec's `$defs`/`methods` (no duplicated mirror),
runs openrpc_gen on it, and compares (order-insensitively) to the committed openrpc.json.

    python3 api-specs/openrpc_ab.py api-specs/sample.json zig/conformance/openrpc.json

Note: a spec that uses a string `enum` in a method-referenced type is intentionally out of scope here —
gen.py emits it inline while msgspec emits a named component; keep enums out of A/B'd methods.
"""
import json
import os
import sys
from typing import Annotated, Any, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "python"))

import msgspec  # noqa: E402
from truenas_pyjsonrpc import (  # noqa: E402
    JSONRPCMethod, JSONRPCProtocol, MessageDirection, SECRET,
)
import openrpc_gen  # noqa: E402

_PRIMS = {"string": str, "integer": int, "number": float, "boolean": bool}


def make_type_builder(defs: dict):
    """Return a lazy `get(name)` building each `$def` object schema -> a live msgspec.Struct on demand
    (memoized, recursive for `$ref`). Lazy so only METHOD-referenced types (+ their nested deps) are built
    — e.g. an unreferenced `Demo` with a string enum is never touched."""
    built: dict = {}

    def base_type(node: dict):
        ref = node.get("$ref")
        if ref:
            return get(ref.rsplit("/", 1)[-1])
        if "enum" in node:
            raise SystemExit("openrpc_ab: string enums in A/B'd types are out of scope (inline vs named)")
        t = node.get("type")
        if t == "array":
            return list[base_type(node["items"])]
        return _PRIMS[t]

    def field_type(node: dict):
        ft = base_type(node)
        return Annotated[ft, SECRET] if node.get("secret") else ft

    def get(name: str):
        if name in built:
            return built[name]
        schema = defs[name]
        required = set(schema.get("required", []))
        fields = []
        for prop, ps in schema.get("properties", {}).items():
            ft = field_type(ps)
            if "default" in ps:
                fields.append((prop, ft, ps["default"]))
            elif prop in required:
                fields.append((prop, ft))
            else:
                fields.append((prop, Optional[ft], None))
        built[name] = msgspec.defstruct(name, fields)
        return built[name]

    return get


def build_protocol(spec: dict) -> JSONRPCProtocol:
    defs = spec.get("$defs", {})
    get = make_type_builder(defs)

    def ref(node):
        return get(node["$ref"].rsplit("/", 1)[-1]) if isinstance(node, dict) and "$ref" in node else None

    methods = []
    for name, m in spec["methods"].items():
        # A handler whose docstring is the spec summary, so openrpc_gen derives the same `summary`.
        def handler(request, session_state, request_state):  # noqa: ARG001
            ...
        handler.__doc__ = m.get("summary")
        direction = MessageDirection(m.get("direction", "client_server"))
        kw: dict[str, Any] = dict(name=name, accepts=ref(m["params"]), direction=direction,
                                  audit=bool(m.get("audit")), audit_message=m.get("auditMessage"),
                                  roles=m.get("roles", ()))
        if direction is MessageDirection.SERVER_CLIENT:
            kw["notifies"] = ref(m["notifies"])
        else:
            kw["handler"] = handler
            kw["returns"] = ref(m.get("result"))
        methods.append(JSONRPCMethod(**kw))
    return JSONRPCProtocol(methods, name=spec["name"], version=spec["version"])


def _norm(o):
    if isinstance(o, dict):
        return {k: _norm(v) for k, v in sorted(o.items())}
    if isinstance(o, list):
        return [_norm(x) for x in o]
    return o


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: openrpc_ab.py <spec.json> <openrpc.json>", file=sys.stderr)
        return 2
    spec = json.load(open(sys.argv[1]))
    golden = openrpc_gen.generate_openrpc(build_protocol(spec))
    candidate = json.load(open(sys.argv[2]))
    candidate.pop("x-generated", None)  # gen.py's generated-file marker; not part of openrpc_gen's output

    if _norm(golden) == _norm(candidate):
        print(f"openrpc A/B OK: {sys.argv[2]} == openrpc_gen.py output ({len(golden['methods'])} methods)")
        return 0
    print(f"openrpc A/B MISMATCH: {sys.argv[2]} != openrpc_gen.py output", file=sys.stderr)
    import difflib
    a = json.dumps(_norm(golden), indent=1).splitlines()
    b = json.dumps(_norm(candidate), indent=1).splitlines()
    print("\n".join(difflib.unified_diff(a, b, "openrpc_gen.py", sys.argv[2], lineterm="")), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
