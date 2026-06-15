"""Generate a strongly-typed :class:`~truenas_pyjsonrpc_client.BaseClient`
subclass from a live :class:`~truenas_pyjsonrpc.JSONRPCProtocol`.

This is a **build-time tool** (it introspects a server's protocol), kept out of the
runtime ``truenas_pyjsonrpc_client`` package. The protocol's
``accepts``/``returns``/``notifies`` ``msgspec.Struct`` types are **reused** (imported
from their defining modules), not regenerated from schema, so the generated client
shares the exact types the server validates against. Each ``CLIENT_SERVER`` method
becomes ``def <name>(self, request: Accepts) -> Returns`` (via
:meth:`BaseClient._typed_call`); each ``SERVER_CLIENT`` topic becomes
``subscribe_<name>(self, request: Accepts, *, callback=...) -> str`` plus an entry in
the class's ``TOPICS`` map (wire name -> notifies type) for decoding inbound payloads.

CLI (run from the repo root)::

    python codegen.py mypkg.api:protocol --out client_gen.py

Note: the generated ``__init__`` ``$/negotiate``\\ s the protocol's own ``name``;
the server must register the protocol under that same name (the usual convention).
Override with ``protocol_name=`` / ``--protocol-name`` if they differ.
"""
from __future__ import annotations

import keyword
import re

import msgspec

from truenas_pyjsonrpc import (
    FilterableJSONRPCMethod,
    JSONRPCFdTransferMethod,
    JSONRPCProtocol,
    MessageDirection,
)

_StructType = type[msgspec.Struct]


def _pyname(name: str) -> str:
    """Turn a wire method name into a valid Python identifier (``pool.create`` ->
    ``pool_create``), suffixing ``_`` to dodge a Python keyword (``import`` ->
    ``import_``) so the generated ``def`` is never a syntax error. (Soft keywords like
    ``match``/``type`` are valid method names and left as-is.)"""
    out = re.sub(r"\W", "_", name)
    if out and out[0].isdigit():
        out = "_" + out
    if keyword.iskeyword(out):
        out += "_"
    return out


def _class_name_for(protocol_name: str) -> str:
    """Default generated class name from a protocol name (``directoryservices.v1``
    -> ``DirectoryservicesV1Client``)."""
    parts = [p for p in re.split(r"\W+", protocol_name) if p]
    return "".join(p[:1].upper() + p[1:] for p in parts) + "Client"


def _emit_doc(doc: str, indent: str) -> str:
    """Render ``doc`` as a single-line, escape-safe docstring statement."""
    text = " ".join(doc.split()).replace("\\", "\\\\").replace('"', '\\"')
    return f'{indent}"""{text}"""\n'


def generate(protocol: JSONRPCProtocol, *, class_name: str | None = None,
             protocol_name: str | None = None) -> str:
    """Return Python source for a typed ``BaseClient`` subclass for ``protocol``.

    ``protocol_name`` is the name the client will ``$/negotiate`` (defaults to the
    protocol's own ``name``). ``class_name`` defaults to one derived from it.
    """
    if protocol_name is None:
        protocol_name = protocol.name
    if not protocol_name:
        raise ValueError(
            "no protocol name to negotiate: build the JSONRPCProtocol with "
            "name=... or pass protocol_name=")
    if class_name is None:
        class_name = _class_name_for(protocol_name)

    imports: dict[str, str] = {}        # type name -> defining module

    def ref(t: _StructType) -> str:
        name = t.__name__
        module = t.__module__
        prev = imports.get(name)
        if prev is not None and prev != module:
            raise ValueError(
                f"Struct name collision: {name!r} is defined in both {prev} and "
                f"{module}; codegen cannot import both unambiguously")
        if module == "__main__":
            raise ValueError(
                f"{name!r} is defined in __main__; move it to an importable module "
                "so the generated client can import it")
        imports[name] = module
        return name

    methods_src: list[str] = []
    topics: dict[str, str] = {}         # wire topic name -> notifies type name
    needs_file_transfer = False         # generated code references FileTransfer?
    # Reserved: identifiers this generated class defines or inherits from BaseClient. A wire
    # method whose Python identifier hits one of these (or another method's) would silently
    # shadow it — and override an inherited member with the wrong signature — so reject it.
    emitted: set[str] = {
        "__init__", "TOPICS", "name", "connect", "setup", "setup_continue", "call",
        "transfer", "send_fds", "recv_fds", "subscribe", "unsubscribe", "close",
    }

    def claim(ident: str, wire: str) -> None:
        if ident in emitted:
            raise ValueError(
                f"method name collision: {wire!r} maps to the Python identifier "
                f"{ident!r}, already used by another method or a BaseClient member; "
                "rename the method (or hand-write the client over BaseClient)")
        emitted.add(ident)

    for name, m in sorted(protocol.methods.items()):
        if name.startswith("$/") or name.startswith("rpc."):
            continue                    # control methods are handled by BaseClient
        py = _pyname(name)
        # SERVER_CLIENT topics are emitted as subscribe_<py>; everything else as <py>.
        claim(f"subscribe_{py}" if m.direction is MessageDirection.SERVER_CLIENT else py,
              name)
        # A filterable method's `accepts` is a synthetic (augmented) struct with no
        # importable name; the client method takes the *base* accepts plus explicit
        # query kwargs, so reference base_accepts here.
        accepts = ref(m.base_accepts if isinstance(m, FilterableJSONRPCMethod)
                      else m.accepts)
        if isinstance(m, JSONRPCFdTransferMethod):
            assert m.returns is not None        # transfer methods require returns
            returns = ref(m.returns)
            needs_file_transfer = True
            block = (
                f"    def {py}(self, request: {accepts}, *, "
                f"callback: Callable[[FileTransfer], object]) -> {returns}:\n"
                f'        """{m.transfer_direction.value.capitalize()} (raw-fd '
                f"transfer); ``callback(file_transfer)`` gets exclusive access to the "
                f'connection\'s fd (``file_transfer.fileno()``) for the stream."""\n'
                f"        return self._typed_transfer({name!r}, request, {returns}, "
                f"callback)\n")
        elif m.direction is MessageDirection.SERVER_CLIENT:
            assert m.notifies is not None       # guaranteed for SERVER_CLIENT
            notifies = ref(m.notifies)
            topics[name] = notifies
            block = (
                f"    def subscribe_{py}(self, request: {accepts}, *, callback: "
                f"Callable[[{notifies}], None] | None = None) -> str:\n"
                f'        """Subscribe to the {name!r} topic; returns the '
                f'subscription id.\n\n'
                f"        ``callback`` (invoked on the backchannel thread) receives "
                f"each published\n"
                f"        {notifies}. Without it, messages fall through to "
                f'on_notification."""\n'
                f"        return self._subscribe({name!r}, request, "
                f"callback=callback, notifies={notifies})\n")
        elif isinstance(m, FilterableJSONRPCMethod):
            entry = ref(m.entry)
            imports["QueryFilters"] = "truenas_pyjsonrpc"
            imports["QueryOptions"] = "truenas_pyjsonrpc"
            ret = f"list[{entry}] | {entry} | int"
            doc = _emit_doc(m.doc, "        ") if m.doc else ""
            block = (
                f"    def {py}(self, request: {accepts}, *, "
                f"query_filters: QueryFilters | None = None, "
                f"query_options: QueryOptions | None = None) -> {ret}:\n"
                f"{doc}"
                f"        return self._typed_filterable({name!r}, request, "
                f"query_filters, query_options, {entry})\n")
        else:
            ret = ref(m.returns) if m.returns is not None else None
            ret_anno = ret if ret is not None else "Any"
            ret_arg = ret if ret is not None else "None"
            doc = _emit_doc(m.doc, "        ") if m.doc else ""
            block = (
                f"    def {py}(self, request: {accepts}, *, progress: "
                f"Callable[[Any], None] | None = None) -> {ret_anno}:\n"
                f"{doc}"
                f"        return self._typed_call({name!r}, request, {ret_arg}, "
                f"progress=progress)\n")
        methods_src.append(block)

    return _render(class_name, protocol_name, imports, topics, methods_src,
                   needs_file_transfer)


def _render(class_name: str, protocol_name: str, imports: dict[str, str],
            topics: dict[str, str], methods_src: list[str],
            needs_file_transfer: bool = False) -> str:
    lines: list[str] = [
        "# Generated by truenas_pyjsonrpc codegen — do not edit by hand.",
        f"# Protocol: {protocol_name!r}",
        "from __future__ import annotations",
        "",
        "from collections.abc import Callable",
        "from typing import Any",
        "",
    ]
    if needs_file_transfer:
        lines.append("from truenas_pyjsonrpc import FileTransfer")
    lines.append("from truenas_pyjsonrpc_client import "
                 "BaseClient, TCPConfig, UnixConfig, WebSocketConfig")
    if imports:
        by_module: dict[str, list[str]] = {}
        for nm, module in imports.items():
            by_module.setdefault(module, []).append(nm)
        lines.append("")
        for module in sorted(by_module):
            names = ", ".join(sorted(by_module[module]))
            lines.append(f"from {module} import {names}")

    lines += [
        "",
        "",
        f"class {class_name}(BaseClient):",
        f'    """Typed client for the {protocol_name!r} protocol (generated)."""',
        "",
        "    def __init__(self, *, unix_config: UnixConfig | None = None,",
        "                 tcp_config: TCPConfig | None = None,",
        "                 websocket_config: WebSocketConfig | None = None,",
        "                 name: str | None = None,",
        "                 on_notification: Callable[[str, Any], None] | None = None,",
        "                 connect_timeout: float = 10.0,",
        "                 call_timeout: float | None = 30.0) -> None:",
        f"        super().__init__({protocol_name!r}, unix_config=unix_config,",
        "                         tcp_config=tcp_config,",
        "                         websocket_config=websocket_config,",
        "                         name=name, on_notification=on_notification,",
        "                         connect_timeout=connect_timeout,",
        "                         call_timeout=call_timeout)",
        "",
    ]
    if topics:
        items = ", ".join(f"{k!r}: {v}" for k, v in sorted(topics.items()))
        lines.append(f"    TOPICS: dict[str, type] = {{{items}}}")
        lines.append("")
    for block in methods_src:
        lines.append(block.rstrip("\n"))
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def _write_output(path: str, text: str) -> None:
    """Write ``text`` to ``path`` atomically as UTF-8: a temp file in the same directory,
    then ``os.replace`` over the target. UTF-8 keeps the ``—`` in the header from raising
    ``UnicodeEncodeError`` under a non-UTF-8 locale (e.g. ``LC_ALL=C`` in CI), and the
    atomic rename means a failed/interrupted write can't truncate a previously-good
    committed artifact."""
    import contextlib
    import os
    import tempfile

    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".codegen-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def main(argv: list[str] | None = None) -> int:
    import argparse
    import importlib

    parser = argparse.ArgumentParser(
        prog="python codegen.py",
        description="Generate a typed client from a JSONRPCProtocol.")
    parser.add_argument(
        "target", help="import target 'module:protocol_var', e.g. mypkg.api:protocol")
    parser.add_argument("--class-name", default=None,
                        help="generated class name (default: derived from protocol)")
    parser.add_argument("--protocol-name", default=None,
                        help="name to $/negotiate (default: the protocol's name)")
    parser.add_argument("--out", default=None,
                        help="write to this file (default: stdout)")
    ns = parser.parse_args(argv)

    mod_name, sep, var = ns.target.partition(":")
    if not sep or not var:
        parser.error("target must be 'module:protocol_var'")
    module = importlib.import_module(mod_name)
    protocol = getattr(module, var, None)
    if not isinstance(protocol, JSONRPCProtocol):
        parser.error(f"{ns.target} is not a JSONRPCProtocol")

    source = generate(protocol, class_name=ns.class_name,
                      protocol_name=ns.protocol_name)
    if ns.out:
        _write_output(ns.out, source)
    else:
        print(source, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
