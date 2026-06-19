#!/usr/bin/env python3
"""Spec-first codegen: api-specs/*.json (JSON Schema, draft 2020-12) -> a committed Zig source file
(`rpc_gen.zig`) of typed structs + a `register()` table that feeds the existing dispatch engine.

This is the Zig analogue of the code-first `python/openrpc_gen.py`, run in the OPPOSITE direction: the
spec is the source of truth and the Zig boilerplate is generated. Like that tool it is a build-time
script (committed output, CI-`git diff`'d) with no installed entry point. Run:

    python3 api-specs/gen.py api-specs/sample.json --out zig/conformance/rpc_gen.zig

Output is deterministic (spec order preserved) so the CI drift gate is meaningful. Handlers are NOT
generated: each method names a `handler` symbol; the app writes a struct whose `pub fn`s have those
names, and the generated `register(b, handlers)` binds them via the conformance-proven `b.method`
primitive (a missing/mistyped handler is a Zig compile error).

Type mapping (JSON Schema -> Zig): object -> struct, $ref -> named type, string -> []const u8,
integer -> i64, number -> f64, boolean -> bool, array -> []const T, string enum -> inline `enum {..}`,
`"secret": true` -> `trpc.Secret(T)`. A property that is `required` -> `T`; with a `default` -> `T = d`;
otherwise -> `?T = null`.
"""
import argparse
import json
import os
import re
import sys
import tempfile

ZIG_PRIMITIVES = {"string": "[]const u8", "integer": "i64", "number": "f64", "boolean": "bool"}

# --- OpenRPC emission (mirrors python/openrpc_gen.py's format) -----------------------------------
OPENRPC_VERSION = "1.3.2"
_SCHEMAS_REF = "#/components/schemas/{name}"

#: The protocol-wide error taxonomy as OpenRPC components.errors. Mirrors openrpc_gen._error_components()
#: (and Zig errors.zig ErrorCode); keyed by the UPPER_SNAKE member name with a Title-Cased message. The
#: OpenRPC A/B re-derives this from JSONRPCError and will fail if it ever drifts.
_ERROR_CODES = {
    "INVALID_JSON": -32700, "INVALID_REQUEST": -32600, "METHOD_NOT_FOUND": -32601,
    "INVALID_PARAMS": -32602, "INTERNAL_ERROR": -32603, "NOT_AUTHORIZED": -32000,
    "SESSION_NOT_ESTABLISHED": -32002, "REQUEST_CANCELLED": -32800, "REQUEST_FAILED": -32803,
}

#: Meta-schema for a user-provided api-spec: validate its SHAPE before generating code, so a malformed
#: spec fails fast with a clear error instead of producing broken Zig (UB). Mirrors truenas_build's
#: jsonschema.validate(TRUENAS_DATASETS, fhs.TRUENAS_DATASET_SCHEMA) pattern. (Per-$def schemas are checked
#: separately against draft-2020-12 in validate(); here we only constrain the spec's own structure.)
API_SPEC_SCHEMA = {
    "type": "object",
    "required": ["name", "version", "methods"],
    "additionalProperties": False,
    "properties": {
        "name": {"type": "string", "minLength": 1},
        "version": {"type": "string", "minLength": 1},
        "$schema": {"type": "string"},
        "$comment": {"type": "string"},
        "$defs": {"type": "object"},
        "methods": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "required": ["handler", "params"],
                "additionalProperties": False,
                "properties": {
                    "handler": {"type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]*$"},
                    "summary": {"type": "string"},
                    "params": {"type": "object"},
                    "result": {"type": "object"},
                    "notifies": {"type": "object"},
                    "audit": {"type": "boolean"},
                    "auditMessage": {"type": "string"},
                    "preAuth": {"type": "boolean"},
                    "cancellable": {"type": "boolean"},
                    "roles": {"type": "array", "items": {"type": "string"}},
                    "direction": {"enum": ["client_server", "server_client"]},
                    # A filterable (query) method: codegen emits `b.filterableMethod` and the result is the
                    # `entry` element type streamed through a FilterSink (no `result` — it is array-of-entry).
                    "filterable": {"type": "boolean"},
                    "entry": {"type": "object"},
                    # XDR binary-wire opt-in: the method is ALSO reachable over the RFC-4506 wire,
                    # addressed by a spec-assigned proc-id (u32). `xdr` ⇒ `xdr_id` required (allOf below)
                    # and unique across the spec (validate()). Proc-ids 0..=1000 are RESERVED for
                    # protocol control messages (the `$/` namespace over the binary wire), so an
                    # application method must use `xdr_id` >= 1001.
                    "xdr": {"type": "boolean"},
                    "xdr_id": {"type": "integer", "minimum": 1001},
                },
                # filterable ⇒ `entry` is required and `result` is forbidden (the result shape is derived);
                # xdr ⇒ xdr_id is required (the proc-id that addresses the method on the binary wire).
                "allOf": [
                    {
                        "if": {"required": ["filterable"], "properties": {"filterable": {"const": True}}},
                        "then": {"required": ["entry"], "not": {"required": ["result"]}},
                    },
                    {
                        "if": {"required": ["xdr"], "properties": {"xdr": {"const": True}}},
                        "then": {"required": ["xdr_id"]},
                    },
                ],
            },
        },
    },
}

# Zig keywords that can't be a bare field/enum identifier (escaped as @"...").
ZIG_KEYWORDS = {
    "addrspace", "align", "allowzero", "and", "anyframe", "anytype", "asm", "async", "await", "break",
    "callconv", "catch", "comptime", "const", "continue", "defer", "else", "enum", "errdefer", "error",
    "export", "extern", "fn", "for", "if", "inline", "linksection", "noalias", "noinline", "nosuspend",
    "opaque", "or", "orelse", "packed", "pub", "resume", "return", "struct", "suspend", "switch", "test",
    "threadlocal", "try", "union", "unreachable", "usingnamespace", "var", "volatile", "while",
}

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def die(msg: str) -> "None":
    print(f"gen.py: error: {msg}", file=sys.stderr)
    sys.exit(1)


def ident(name: str) -> str:
    """A Zig identifier for a (field/enum) name — bare when safe, else `@"..."`."""
    if _IDENT.match(name) and name not in ZIG_KEYWORDS:
        return name
    return '@"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def zstr(s: str) -> str:
    """A Zig string literal. json.dumps gives valid Zig escapes for our (ASCII/UTF-8) content."""
    return json.dumps(s, ensure_ascii=False)


def ref_name(schema: dict) -> "str | None":
    ref = schema.get("$ref")
    if ref is None:
        return None
    m = re.fullmatch(r"#/\$defs/(\w+)", ref)
    if not m:
        die(f"unsupported $ref (only #/$defs/<Name> is allowed): {ref!r}")
    return m.group(1)


def zig_type(schema: dict, defs: dict) -> str:
    """The Zig type for a JSON-Schema node (a `secret` flag wraps the base in trpc.Secret(..))."""
    rn = ref_name(schema)
    if rn is not None:
        if rn not in defs:
            die(f"$ref to unknown $defs type: {rn!r}")
        base = rn
    elif "enum" in schema:
        variants = schema["enum"]
        if not variants or not all(isinstance(v, str) for v in variants):
            die(f"only non-empty string enums are supported: {schema.get('enum')!r}")
        base = "enum { " + ", ".join(ident(v) for v in variants) + " }"
    elif schema.get("type") == "array":
        items = schema.get("items")
        if not isinstance(items, dict):
            die("array schema must have an object 'items'")
        base = "[]const " + zig_type(items, defs)
    elif schema.get("type") == "object":
        base = "struct {" + struct_fields(schema, defs) + "}"
    elif schema.get("type") in ZIG_PRIMITIVES:
        base = ZIG_PRIMITIVES[schema["type"]]
    else:
        die(f"unsupported schema (need $ref, enum, or a known type): {schema!r}")
    return f"trpc.Secret({base})" if schema.get("secret") else base


def zig_default(schema: dict) -> str:
    d = schema["default"]
    if "enum" in schema:
        return "." + ident(d)
    t = schema.get("type")
    if t == "string":
        return zstr(d)
    if t == "integer":
        return str(int(d))
    if t == "number":
        return repr(float(d))
    if t == "boolean":
        return "true" if d else "false"
    if t == "array":
        if d == []:
            return "&.{}"
        die("only an empty-array default ([]) is supported")
    die(f"unsupported default for type {t!r}")


def struct_fields(schema: dict, defs: dict) -> str:
    """The `field: type[ = default],` lines for an object schema (empty string for no properties)."""
    props = schema.get("properties", {})
    required = set(schema.get("required", []))
    lines = []
    for pname, pschema in props.items():
        zt = zig_type(pschema, defs)
        if "default" in pschema:
            lines.append(f"    {ident(pname)}: {zt} = {zig_default(pschema)},")
        elif pname in required:
            lines.append(f"    {ident(pname)}: {zt},")
        else:  # optional: not required and no default
            lines.append(f"    {ident(pname)}: ?{zt} = null,")
    return ("\n" + "\n".join(lines) + "\n") if lines else ""


def emit_struct(name: str, schema: dict, defs: dict) -> str:
    if schema.get("type") != "object":
        die(f"$defs.{name} must be a JSON object schema (got type={schema.get('type')!r})")
    return f"pub const {name} = struct {{{struct_fields(schema, defs)}}};"


def emit_opts(m: dict) -> str:
    parts = []
    if m.get("preAuth"):
        parts.append(".pre_auth = true")
    if m.get("audit"):
        parts.append(".audit = true")
    if m.get("cancellable"):
        parts.append(".cancellable = true")
    if m.get("auditMessage") is not None:
        parts.append(f".audit_message = {zstr(m['auditMessage'])}")
    if m.get("roles"):
        parts.append(".roles = &.{ " + ", ".join(zstr(r) for r in m["roles"]) + " }")
    if m.get("xdr"):
        parts.append(".xdr = true")
        parts.append(f".xdr_id = {int(m['xdr_id'])}")
    return ".{}" if not parts else ".{ " + ", ".join(parts) + " }"


def validate(spec: dict) -> None:
    for key in ("name", "version", "methods"):
        if key not in spec:
            die(f"spec is missing required top-level key {key!r}")
    defs = spec.get("$defs", {})
    try:
        import jsonschema
        from jsonschema import Draft202012Validator
    except ImportError:
        print("gen.py: warning: jsonschema not installed; skipping schema validation", file=sys.stderr)
    else:
        # 1. Validate the SPEC'S OWN SHAPE first — fail fast before generating any code (avoid UB from a
        #    malformed user-provided spec). Mirrors truenas_build's jsonschema.validate(data, SCHEMA).
        try:
            jsonschema.validate(spec, API_SPEC_SCHEMA)
        except jsonschema.ValidationError as e:
            where = "/".join(str(p) for p in e.absolute_path) or "<root>"
            die(f"spec has invalid shape at {where}: {e.message}")
        # 2. Each $def must itself be a valid draft-2020-12 schema.
        for name, schema in defs.items():
            try:
                Draft202012Validator.check_schema(schema)
            except Exception as e:  # jsonschema.exceptions.SchemaError
                die(f"$defs.{name} is not a valid draft-2020-12 schema: {e}")
    for wire, m in spec["methods"].items():
        if not isinstance(m, dict) or "handler" not in m:
            die(f"method {wire!r} must be an object with a 'handler'")
        if not _IDENT.match(m["handler"]):
            die(f"method {wire!r} handler {m['handler']!r} is not a valid Zig identifier")
        if "params" not in m:
            die(f"method {wire!r} must declare 'params' (use an empty-object $def for no params)")
        for slot in ("params", "result", "entry"):
            s = m.get(slot)
            if isinstance(s, dict) and "$ref" in s:
                rn = ref_name(s)
                if rn not in defs:
                    die(f"method {wire!r} {slot} $ref to unknown $defs type: {rn!r}")
    # XDR proc-ids are the binary wire's addressing; they MUST be unique across xdr-enabled methods. A
    # duplicate would collide in the runtime slot table (proc-id → method, indexed by proc-id; caught
    # there as error.DuplicateXdrId), but failing here gives a spec-level diagnostic before codegen.
    seen_ids: dict = {}
    for wire, m in spec["methods"].items():
        if not m.get("xdr"):
            continue
        xid = m.get("xdr_id")
        # 0..=1000 are reserved for protocol control messages (the `$/` namespace over the binary
        # wire); an application method must use a proc-id above that band. (Also enforced by the
        # meta-schema `minimum`, but repeated here for the no-jsonschema path + a clearer message.)
        if isinstance(xid, int) and xid <= 1000:
            die(f"method {wire!r} xdr_id {xid} is reserved (0..=1000 are for protocol control "
                f"messages); use an id >= 1001")
        if xid in seen_ids:
            die(f"method {wire!r} xdr_id {xid} collides with method {seen_ids[xid]!r}")
        seen_ids[xid] = wire


def generate(spec: dict, spec_basename: str) -> str:
    defs = spec.get("$defs", {})
    out = [
        f"//! GENERATED by api-specs/gen.py from api-specs/{spec_basename} — DO NOT EDIT BY HAND.",
        f"//! Regenerate: python3 api-specs/gen.py api-specs/{spec_basename} --out <this file>",
        "//!",
        "//! Typed structs + a `register()` table for the spec's methods. Handlers are NOT generated:",
        "//! pass a `*Handlers` whose `pub fn`s match each method's `handler` symbol; `register` binds",
        "//! them via the engine's `b.method` primitive (a missing/mistyped handler is a compile error).",
        "",
    ]
    body = []
    for name, schema in defs.items():
        body.append(emit_struct(name, schema, defs))
        body.append("")
    body.append("/// Register every spec method onto `b`, binding each to `handlers.<handler>`.")
    body.append("pub fn register(b: anytype, handlers: anytype) !void {")
    body.append("    const H = @TypeOf(handlers.*);")
    for wire, m in spec["methods"].items():
        if m.get("filterable"):
            # A filterable method threads its `entry` element type (a $def emitted above) explicitly.
            entry = ref_name(m["entry"])
            body.append(f"    try b.filterableMethod({zstr(wire)}, handlers, H.{m['handler']}, {entry}, {emit_opts(m)});")
        else:
            body.append(f"    try b.method({zstr(wire)}, handlers, H.{m['handler']}, {emit_opts(m)});")
    body.append("}")

    text = "\n".join(body) + "\n"
    # Only import the library when a generated type actually references it (avoid an unused const).
    if "trpc." in text:
        out.append('const trpc = @import("truenas_jsonrpc");')
        out.append("")
    return "\n".join(out) + text


# --- OpenRPC document (the same spec -> an OpenRPC 1.3.2 description) --------------------------------
# Transforms the custom-dialect spec into the format python/openrpc_gen.py emits (verified by A/B), so a
# client/doc dev (openrpc.json) and a `$/describe` request (the .zig static string) get a standard contract.


def _error_components() -> "dict":
    """components.errors — `{UPPER_NAME: {code, message: Title Case}}` (mirrors openrpc_gen)."""
    return {n: {"code": c, "message": n.replace("_", " ").title()} for n, c in _ERROR_CODES.items()}


def _ref_or_none(node: dict) -> "str | None":
    return ref_name(node) if isinstance(node, dict) and "$ref" in node else None


def _base_schema(node: dict, defs: dict) -> dict:
    """A custom-dialect type node -> the msgspec-style JSON Schema for it (drops `secret`)."""
    rn = _ref_or_none(node)
    if rn is not None:
        return {"$ref": _SCHEMAS_REF.format(name=rn)}
    if "enum" in node:
        return {"type": "string", "enum": list(node["enum"])}
    t = node.get("type")
    if t == "array":
        return {"type": "array", "items": _base_schema(node["items"], defs)}
    if t == "object":  # rare inline object (the dialect normally uses $ref)
        return _component_body(None, node, defs)
    if t in ("string", "integer", "number", "boolean"):
        return {"type": t}
    die(f"cannot map schema to OpenRPC: {node!r}")


def _property_schema(pschema: dict, required: bool, defs: dict) -> dict:
    """A property's schema as msgspec emits it: `default` inlined; an optional (not required, no default)
    field as `{anyOf: [base, {type: null}], default: null}`; otherwise the bare base."""
    base = _base_schema(pschema, defs)
    if "default" in pschema:
        return {**base, "default": pschema["default"]}
    if not required:
        return {"anyOf": [base, {"type": "null"}], "default": None}
    return base


def _component_body(name: "str | None", schema: dict, defs: dict) -> dict:
    props = schema.get("properties", {})
    required = set(schema.get("required", []))
    body: dict = {}
    if name is not None:
        body["title"] = name
    body["type"] = "object"
    body["properties"] = {p: _property_schema(ps, p in required, defs) for p, ps in props.items()}
    body["required"] = list(schema.get("required", []))
    return body


def _collect_component_names(public: dict, defs: dict) -> "list":
    """Ordered, de-duplicated names of every $def referenced by `public` (params/result/notifies + nested),
    in first-seen order — the OpenRPC components.schemas set (= msgspec.json.schema_components)."""
    seen: "list" = []

    def visit_refs(node: dict) -> None:
        rn = _ref_or_none(node)
        if rn is not None:
            add(rn)
        elif isinstance(node, dict) and node.get("type") == "array" and isinstance(node.get("items"), dict):
            visit_refs(node["items"])

    def add(name: str) -> None:
        if name in seen:
            return
        seen.append(name)
        for ps in defs.get(name, {}).get("properties", {}).values():
            visit_refs(ps)

    for m in public.values():
        for slot in ("params", "result", "notifies", "entry"):
            s = m.get(slot)
            if isinstance(s, dict):
                visit_refs(s)
    return seen


def _query_param_descriptors() -> list:
    """The two augmented content descriptors a filterable request carries — the Zig port's REDUCED query
    surface (get + select dropped). Both optional. (Filterable methods are scoped out of the openrpc_gen.py
    A/B precisely because this differs from Python's full QueryOptions; see openrpc_ab.py.)"""
    return [
        {"name": "query-filters", "required": False,
         "schema": {"type": "array", "items": {"type": "array"}, "default": []}},
        {"name": "query-options", "required": False, "schema": {
            "type": "object",
            "properties": {
                "count": {"type": "boolean", "default": False},
                "order_by": {"anyOf": [{"type": "array", "items": {"type": "string"}}, {"type": "null"}],
                             "default": None},
                "offset": {"type": "integer", "default": 0},
                "limit": {"type": "integer", "default": 0},
            },
        }},
    ]


def _method_object(wire: str, m: dict, defs: dict) -> dict:
    params_def = defs[ref_name(m["params"])]
    required = set(params_def.get("required", []))
    params = [{"name": p, "required": p in required, "schema": _property_schema(ps, p in required, defs)}
              for p, ps in params_def.get("properties", {}).items()]
    params.sort(key=lambda d: not d["required"])  # required params before optional (stable)
    filterable = bool(m.get("filterable"))
    if filterable:  # the framework augments the request with the query fields (appended after the base params)
        params = params + _query_param_descriptors()

    obj: dict = {"name": wire}
    if m.get("summary"):
        obj["summary"] = m["summary"]
    obj["paramStructure"] = "by-name"
    obj["params"] = params
    direction = m.get("direction", "client_server")
    if filterable:  # result is array-of-entry (the count→int / no-match variants are flagged via x-query)
        entry_rn = ref_name(m["entry"])
        obj["result"] = {"name": entry_rn,
                         "schema": {"type": "array", "items": {"$ref": _SCHEMAS_REF.format(name=entry_rn)}}}
        obj["x-query"] = True
    elif direction != "server_client" and isinstance(m.get("result"), dict):
        rn = ref_name(m["result"])
        obj["result"] = {"name": rn, "schema": {"$ref": _SCHEMAS_REF.format(name=rn)}}
    obj["x-direction"] = direction
    if direction == "server_client" and isinstance(m.get("notifies"), dict):
        obj["x-notifies"] = {"$ref": _SCHEMAS_REF.format(name=ref_name(m["notifies"]))}
    if m.get("roles"):
        obj["x-roles"] = list(m["roles"])
    return obj


def generate_openrpc(spec: dict) -> dict:
    """The spec as an OpenRPC 1.3.2 document (matching python/openrpc_gen.py). `$/` + `rpc.` methods are
    skipped; methods are sorted; components.schemas is the shared, de-duplicated type set."""
    defs = spec.get("$defs", {})
    public = {w: m for w, m in sorted(spec["methods"].items())
              if not (w.startswith("$/") or w.startswith("rpc."))}
    schemas = {n: _component_body(n, defs[n], defs) for n in _collect_component_names(public, defs)}
    return {
        "openrpc": OPENRPC_VERSION,
        "info": {"title": spec["name"], "version": spec["version"]},
        "methods": [_method_object(w, m, defs) for w, m in public.items()],
        "components": {"schemas": schemas, "errors": _error_components()},
    }


def _atomic_write(path: str, text: str, suffix: str) -> None:
    """Write `text` to `path` atomically (temp + os.replace), mirroring python/openrpc_gen.py."""
    out_dir = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=out_dir, suffix=suffix)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate rpc_gen.zig + OpenRPC artifacts from a JSON-Schema API spec.")
    ap.add_argument("spec", help="path to the api-specs/*.json spec")
    ap.add_argument("--out", help="output rpc_gen.zig path (default: stdout if no other output is requested)")
    ap.add_argument("--openrpc-json", help="also write the OpenRPC 1.3.2 document to this .json path (the "
                                           "library @embedFiles it for $/describe)")
    args = ap.parse_args()

    with open(args.spec) as f:
        spec = json.load(f)
    validate(spec)
    basename = os.path.basename(args.spec)

    # rpc_gen.zig: to --out, else stdout only when no other artifact was requested.
    zig_text = generate(spec, basename)
    if args.out:
        _atomic_write(args.out, zig_text, ".zig.tmp")
        print(f"wrote {len(spec.get('methods', {}))} methods, {len(spec.get('$defs', {}))} types to {args.out}")
    elif not args.openrpc_json:
        sys.stdout.write(zig_text)

    if args.openrpc_json:
        # The JSON IS the $/describe payload (the app @embedFiles it), so the "generated, don't edit"
        # marker is a spec-valid `x-generated` extension (a top-level `$comment` would fail strict OpenRPC
        # validators) — concise + harmless on the wire. The OpenRPC A/B strips it before comparing.
        doc = generate_openrpc(spec)
        marked = {"x-generated": f"Generated from api-specs/{basename} by api-specs/gen.py — do not edit by hand.",
                  **doc}
        text = json.dumps(marked, indent=2, ensure_ascii=False) + "\n"
        _atomic_write(args.openrpc_json, text, ".json.tmp")
        print(f"wrote OpenRPC ({len(doc['methods'])} methods) to {args.openrpc_json}")


if __name__ == "__main__":
    main()
