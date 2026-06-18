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
    return ".{}" if not parts else ".{ " + ", ".join(parts) + " }"


def validate(spec: dict) -> None:
    for key in ("name", "version", "methods"):
        if key not in spec:
            die(f"spec is missing required top-level key {key!r}")
    defs = spec.get("$defs", {})
    try:
        from jsonschema import Draft202012Validator
        for name, schema in defs.items():
            try:
                Draft202012Validator.check_schema(schema)
            except Exception as e:  # jsonschema.exceptions.SchemaError
                die(f"$defs.{name} is not a valid draft-2020-12 schema: {e}")
    except ImportError:
        print("gen.py: warning: jsonschema not installed; skipping schema validation", file=sys.stderr)
    for wire, m in spec["methods"].items():
        if not isinstance(m, dict) or "handler" not in m:
            die(f"method {wire!r} must be an object with a 'handler'")
        if not _IDENT.match(m["handler"]):
            die(f"method {wire!r} handler {m['handler']!r} is not a valid Zig identifier")
        if "params" not in m:
            die(f"method {wire!r} must declare 'params' (use an empty-object $def for no params)")
        for slot in ("params", "result"):
            s = m.get(slot)
            if isinstance(s, dict) and "$ref" in s:
                rn = ref_name(s)
                if rn not in defs:
                    die(f"method {wire!r} {slot} $ref to unknown $defs type: {rn!r}")


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
        body.append(f"    try b.method({zstr(wire)}, handlers, H.{m['handler']}, {emit_opts(m)});")
    body.append("}")

    text = "\n".join(body) + "\n"
    # Only import the library when a generated type actually references it (avoid an unused const).
    if "trpc." in text:
        out.append('const trpc = @import("truenas_jsonrpc");')
        out.append("")
    return "\n".join(out) + text


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate rpc_gen.zig from a JSON-Schema API spec.")
    ap.add_argument("spec", help="path to the api-specs/*.json spec")
    ap.add_argument("--out", help="output .zig path (default: stdout)")
    args = ap.parse_args()

    with open(args.spec) as f:
        spec = json.load(f)
    validate(spec)
    text = generate(spec, os.path.basename(args.spec))

    if not args.out:
        sys.stdout.write(text)
        return
    # Atomic write (temp + replace), mirroring python/openrpc_gen.py.
    out_dir = os.path.dirname(os.path.abspath(args.out))
    fd, tmp = tempfile.mkstemp(dir=out_dir, suffix=".zig.tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, args.out)
    except BaseException:
        os.unlink(tmp)
        raise
    print(f"wrote {len(spec.get('methods', {}))} methods, {len(spec.get('$defs', {}))} types to {args.out}")


if __name__ == "__main__":
    main()
