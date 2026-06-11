"""Generate an OpenRPC (https://spec.open-rpc.org/) service description from a live
:class:`~truenas_pyjsonrpc.JSONRPCProtocol`.

OpenRPC is the JSON-RPC analogue of OpenAPI/Swagger: a machine-readable contract usable
for docs, validators, mock servers, and cross-language client generators. Like
``codegen.py`` this is a **build-time tool** — it imports the server's protocol and
introspects it; there is no over-the-wire discovery RPC.

It walks ``protocol.methods`` directly (not ``protocol.describe()``) so it can tell a
:class:`~truenas_pyjsonrpc.JSONRPCFdTransferMethod` from a normal method and emit **one**
shared ``components.schemas`` set (via ``msgspec.json.schema_components``) instead of the
per-method ``$defs`` that ``describe()`` produces. The ``accepts`` Struct of each method is
decomposed into by-name Content Descriptors; ``returns`` becomes the ``result`` (omitted for
void / pub-sub methods, which are notification-only); fd-transfer, pub/sub, and role
metadata are surfaced as ``x-*`` extensions (spec-valid, ignored by generic tooling).

``info.title`` / ``info.version`` default to the protocol's (required) ``name`` / ``version``,
so the mandatory OpenRPC Info Object is always valid; override with ``--title`` / ``--version``.
The ``openrpc`` spec-version string defaults to :data:`OPENRPC_VERSION` (the one field OpenRPC
requires to be a real semver spec release); override with ``--openrpc-version``.

CLI (run from the repo root)::

    python openrpc_gen.py mypkg.api:protocol --out openrpc.json
"""
from __future__ import annotations

import json
from typing import Any

import msgspec

from truenas_pyjsonrpc import (
    JSONRPCError,
    JSONRPCFdPassMethod,
    JSONRPCFdTransferMethod,
    JSONRPCMethod,
    JSONRPCProtocol,
    MessageDirection,
)

#: Default ``openrpc`` document version — the last release with a broadly tool-validated
#: meta-schema. Override per invocation with ``--openrpc-version`` / ``openrpc_version=``.
OPENRPC_VERSION = "1.3.2"

_StructType = type[msgspec.Struct]
_SCHEMAS_REF = "#/components/schemas/{name}"


def _summary_description(doc: str | None) -> tuple[str | None, str | None]:
    """Split a method docstring into an OpenRPC ``summary`` (the first non-empty line) and
    ``description`` (the full normalized text, only when it adds more than that one line)."""
    if not doc:
        return None, None
    nonempty = [line.strip() for line in doc.splitlines() if line.strip()]
    if not nonempty:
        return None, None
    summary = nonempty[0]
    description = " ".join(nonempty) if len(nonempty) > 1 else None
    return summary, description


def _collect_types(methods: dict[str, JSONRPCMethod]) -> list[_StructType]:
    """The ordered, de-duplicated (by ``__name__``) list of every non-None ``msgspec.Struct``
    referenced by ``methods`` (accepts / returns / notifies), to feed
    ``msgspec.json.schema_components``. Raises if two **distinct** types share a ``__name__``
    (mirrors codegen's collision guard), since ``components.schemas`` is keyed by name. Unlike
    codegen we only read ``__name__`` — the types are never imported — so ``__main__``-defined
    Structs are fine."""
    by_name: dict[str, _StructType] = {}
    ordered: list[_StructType] = []
    for m in methods.values():
        for t in (m.accepts, m.returns, m.notifies):
            if t is None:
                continue
            prev = by_name.get(t.__name__)
            if prev is not None and prev is not t:
                raise ValueError(
                    f"Struct name collision: {t.__name__!r} is defined by two distinct "
                    f"types ({prev!r} and {t!r}); OpenRPC components.schemas is keyed by "
                    "name and cannot hold both")
            if prev is None:
                by_name[t.__name__] = t
                ordered.append(t)
    return ordered


def _content_descriptor(name: str, schema: dict[str, Any], *,
                        required: bool) -> dict[str, Any]:
    """An OpenRPC Content Descriptor: a named (non-)required parameter and its JSON Schema."""
    return {"name": name, "required": required, "schema": schema}


def _method_object(name: str, m: JSONRPCMethod,
                   schemas: dict[str, Any]) -> dict[str, Any]:
    """Build the OpenRPC Method Object for the wire method ``name``."""
    accepts_schema = schemas[m.accepts.__name__]
    required = set(accepts_schema.get("required", ()))
    params = [_content_descriptor(prop, schema, required=prop in required)
              for prop, schema in accepts_schema.get("properties", {}).items()]
    params.sort(key=lambda p: not p["required"])      # required params before optional

    obj: dict[str, Any] = {"name": name}
    summary, description = _summary_description(m.doc)
    if summary is not None:
        obj["summary"] = summary
    if description is not None:
        obj["description"] = description
    obj["paramStructure"] = "by-name"                 # this server is by-name only
    obj["params"] = params
    # A method with no `returns` is notification-only — omit `result` (correct for void
    # methods and SERVER_CLIENT pub/sub topics).
    if m.returns is not None:
        rname = m.returns.__name__
        obj["result"] = {"name": rname,
                         "schema": {"$ref": _SCHEMAS_REF.format(name=rname)}}

    # Extensions (x-*): spec-valid, ignored by generic tooling.
    obj["x-direction"] = m.direction.value
    if m.direction is MessageDirection.SERVER_CLIENT and m.notifies is not None:
        obj["x-notifies"] = {"$ref": _SCHEMAS_REF.format(name=m.notifies.__name__)}
    if isinstance(m, JSONRPCFdTransferMethod):
        obj["x-transfer-direction"] = m.transfer_direction.value
        if isinstance(m, JSONRPCFdPassMethod):
            obj["x-fd-pass"] = True
    if m.roles:
        obj["x-roles"] = list(m.roles)
    return obj


def _error_components() -> dict[str, dict[str, Any]]:
    """The protocol-wide :class:`~truenas_pyjsonrpc.JSONRPCError` taxonomy as OpenRPC
    ``components.errors`` (keyed by the enum member name)."""
    return {member.name: {"code": int(member),
                          "message": member.name.replace("_", " ").title()}
            for member in JSONRPCError}


def generate_openrpc(protocol: JSONRPCProtocol, *,
                     title: str | None = None,
                     version: str | None = None,
                     openrpc_version: str = OPENRPC_VERSION,
                     include_errors: bool = True) -> dict[str, Any]:
    """Return a JSON-ready OpenRPC document describing ``protocol``.

    ``title`` / ``version`` default to the protocol's (required) ``name`` / ``version`` — so
    the mandatory Info Object is always valid — and may be overridden. ``$/`` and ``rpc.``
    control methods are skipped. Set ``include_errors=False`` to drop ``components.errors``.
    """
    public = {name: m for name, m in sorted(protocol.methods.items())
              if not (name.startswith("$/") or name.startswith("rpc."))}

    types = _collect_types(public)
    schemas: dict[str, Any] = {}
    if types:
        # schema_components pulls in nested Structs automatically and cross-references
        # them with the ref template — a 1:1 fit for OpenRPC components.schemas.
        _, schemas = msgspec.json.schema_components(
            tuple(types), ref_template=_SCHEMAS_REF)

    methods = [_method_object(name, m, schemas) for name, m in public.items()]

    components: dict[str, Any] = {"schemas": schemas}
    if include_errors:
        components["errors"] = _error_components()

    return {
        "openrpc": openrpc_version,
        "info": {"title": title or protocol.name,
                 "version": version or protocol.version},
        "methods": methods,
        "components": components,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    import importlib

    parser = argparse.ArgumentParser(
        prog="python openrpc_gen.py",
        description="Generate an OpenRPC document from a JSONRPCProtocol.")
    parser.add_argument(
        "target", help="import target 'module:protocol_var', e.g. mypkg.api:protocol")
    parser.add_argument("--out", default=None,
                        help="write to this file (default: stdout)")
    parser.add_argument("--title", default=None,
                        help="info.title (default: the protocol's name)")
    parser.add_argument("--version", default=None,
                        help="info.version (default: the protocol's version)")
    parser.add_argument("--openrpc-version", default=OPENRPC_VERSION,
                        help=f"the 'openrpc' spec version (default: {OPENRPC_VERSION})")
    parser.add_argument("--no-errors", action="store_true",
                        help="omit components.errors")
    ns = parser.parse_args(argv)

    mod_name, sep, var = ns.target.partition(":")
    if not sep or not var:
        parser.error("target must be 'module:protocol_var'")
    module = importlib.import_module(mod_name)
    protocol = getattr(module, var, None)
    if not isinstance(protocol, JSONRPCProtocol):
        parser.error(f"{ns.target} is not a JSONRPCProtocol")

    doc = generate_openrpc(protocol, title=ns.title, version=ns.version,
                           openrpc_version=ns.openrpc_version,
                           include_errors=not ns.no_errors)
    text = json.dumps(doc, indent=2)
    if ns.out:
        with open(ns.out, "w") as f:
            f.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
