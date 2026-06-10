"""Secret-field redaction for audit records.

Mark a Struct field secret with ``Annotated[T, SECRET]``; the audit view masks it
while the real value still flows on the wire. Pure Python, no msgspec fork: a
per-type **redaction plan** is compiled once (cached) from ``msgspec.inspect`` and
applied as an overlay on a ``msgspec.to_builtins`` copy. We key on the *wire*
name (``Field.encode_name``) so ``rename``d secrets are still caught.
"""
from __future__ import annotations

import threading
from typing import Any

import msgspec
import msgspec.inspect as mi

#: Mark a Struct field secret: ``password: Annotated[str, SECRET]``.
SECRET = msgspec.Meta(extra={"secret": True})

#: Substituted for a secret value in the redacted (audit) view.
REDACTED = "********"

# A plan is a small tagged tuple tree, or None when nothing below is secret:
#   ("mask",)                                   -> value becomes REDACTED
#   ("struct", {encode_name: plan, ...})        -> recurse into named keys
#   ("list", plan)                              -> apply to each element
#   ("dict", plan)                              -> apply to each value
#   ("tuple", [plan|None, ...])                 -> apply positionally
#   ("union", tag_field|None, [(tag, plan), ...]) -> tag-aware; else best-effort
#   ("recurse", cls)                            -> cycle node (lazy, cached)
_Plan = "tuple[Any, ...]"

_PLAN_CACHE: dict[type, "tuple[Any, ...] | None"] = {}
_CACHE_LOCK = threading.Lock()

# inspect nodes whose element type lives on ``.item_type``
_ITEM_NODES = tuple(
    n for n in (getattr(mi, name, None)
                for name in ("ListType", "SetType", "FrozenSetType", "VarTupleType"))
    if n is not None
)


def compile_plan(struct_cls: type) -> "tuple[Any, ...] | None":
    """Compile (and cache) the redaction plan for a ``msgspec.Struct`` class
    (``None`` if it has no secret fields anywhere)."""
    with _CACHE_LOCK:
        if struct_cls in _PLAN_CACHE:
            return _PLAN_CACHE[struct_cls]
    plan = _compile(mi.type_info(struct_cls), frozenset())
    with _CACHE_LOCK:
        _PLAN_CACHE[struct_cls] = plan
    return plan


def _compile(t: Any, stack: "frozenset[type]") -> "tuple[Any, ...] | None":
    if isinstance(t, mi.Metadata):
        if t.extra and t.extra.get("secret"):
            return ("mask",)
        return _compile(t.type, stack)
    if isinstance(t, mi.StructType):
        if t.cls in stack:
            return ("recurse", t.cls)
        inner = stack | {t.cls}
        sub: dict[str, Any] = {}
        for f in t.fields:
            p = _compile(f.type, inner)
            if p is not None:
                sub[f.encode_name] = p
        return ("struct", sub) if sub else None
    if _ITEM_NODES and isinstance(t, _ITEM_NODES):
        p = _compile(t.item_type, stack)
        return ("list", p) if p is not None else None
    if isinstance(t, mi.DictType):
        p = _compile(t.value_type, stack)
        return ("dict", p) if p is not None else None
    if isinstance(t, mi.TupleType):
        parts = [_compile(x, stack) for x in t.item_types]
        return ("tuple", parts) if any(p is not None for p in parts) else None
    if isinstance(t, mi.UnionType):
        members: list[tuple[Any, Any]] = []
        tag_field = None
        for x in t.types:
            p = _compile(x, stack)
            if p is None:
                continue
            tag = getattr(x, "tag", None)
            if tag is not None:
                tag_field = getattr(x, "tag_field", None)
            members.append((tag, p))
        return ("union", tag_field, members) if members else None
    return None


def redact(obj: Any, plan: "tuple[Any, ...] | None") -> Any:
    """Return a redacted **builtins copy** of ``obj`` (secrets -> ``REDACTED``).
    With ``plan is None`` returns ``obj`` unchanged. Never mutates ``obj`` (the
    live value still goes on the wire). For a standalone redaction use
    ``redact(obj, compile_plan(type(obj)))``."""
    if plan is None:
        return obj
    return _apply(msgspec.to_builtins(obj), plan)


def _apply(value: Any, plan: "tuple[Any, ...]") -> Any:
    kind = plan[0]
    if kind == "mask":
        return REDACTED if value is not None else None
    if value is None:
        return None
    if kind == "struct":
        if isinstance(value, dict):
            for k, sub in plan[1].items():
                if k in value:
                    value[k] = _apply(value[k], sub)
        return value
    if kind == "list":
        # accept tuple too: to_builtins preserves tuples (list/set/var-tuple all
        # compile to a "list" plan), and a non-redacting check here would leak.
        if isinstance(value, (list, tuple)):
            return [_apply(v, plan[1]) for v in value]
        return value
    if kind == "dict":
        if isinstance(value, dict):
            return {k: _apply(v, plan[1]) for k, v in value.items()}
        return value
    if kind == "tuple":
        subs = plan[1]
        if isinstance(value, (list, tuple)):
            return [_apply(v, subs[i]) if i < len(subs) and subs[i] is not None else v
                    for i, v in enumerate(value)]
        return value
    if kind == "union":
        tag_field, members = plan[1], plan[2]
        if isinstance(value, dict) and tag_field is not None and tag_field in value:
            tv = value[tag_field]
            for tag, sub in members:
                if tag == tv:
                    return _apply(value, sub)
            return value
        for _tag, sub in members:            # untagged: best-effort (safe over-mask)
            value = _apply(value, sub)
        return value
    if kind == "recurse":
        sub = compile_plan(plan[1])
        return _apply(value, sub) if sub is not None else value
    return value
