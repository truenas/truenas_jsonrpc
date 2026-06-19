"""Canonical XDR (RFC 4506) codec for the binary wire — a reflective walker over the SAME `msgspec.Struct`
types the JSON path uses, built on pynfs's `xdrlib3` Packer/Unpacker. It is byte-for-byte identical to the
Zig comptime codec (and FreeBSD `sys/xdr`); the A/B conformance compares exact bytes.

A Python `int` carries no width, so annotate fields whose Zig peer isn't a 4-byte signed int:
`Hyper` (i64, 8 bytes) · `Int32`/plain `int` (i32, 4 bytes) · `U32` (unsigned, 4 bytes). `msgspec.json`
ignores these annotations, so the same Struct serves both wires. `str`/`bytes` → variable opaque (u32 len +
bytes + 0-pad to 4); `float` → IEEE double (8 bytes); `Optional[X]` → u32 0/1 + value; `list[X]` → u32 count
+ elements; nested `Struct` → fields concatenated; `IntEnum` → i32.

Frame layout mirrors `zig/src/xdr_frame.zig` (magic + envelope + payload).
"""
import types
import typing
from enum import IntEnum

import msgspec
import xdrlib3 as xdrlib

MAGIC = 0x54584452  # "TXDR"
VERSION = 1


# Width markers (the metadata of an Annotated[int, _Marker]); the same Struct stays JSON-decodable.
class _I32:
    pass


class _I64:
    pass


class _U32:
    pass


Int32 = typing.Annotated[int, _I32]
Hyper = typing.Annotated[int, _I64]
U32 = typing.Annotated[int, _U32]

_NoneType = type(None)
_UnionTypes = (typing.Union, types.UnionType)


def _struct_fields(t: type) -> list[tuple[str, typing.Any]]:
    hints = typing.get_type_hints(t, include_extras=True)
    return [(name, hints[name]) for name in getattr(t, "__struct_fields__")]


def _enc(p: xdrlib.Packer, value: typing.Any, t: typing.Any) -> None:
    origin = typing.get_origin(t)
    if origin is typing.Annotated:
        meta = t.__metadata__
        if _I64 in meta:
            p.pack_hyper(value)
        elif _U32 in meta:
            p.pack_uint(value)
        elif _I32 in meta:
            p.pack_int(value)
        else:
            _enc(p, value, typing.get_args(t)[0])
        return
    if origin in _UnionTypes:
        args = typing.get_args(t)
        if _NoneType in args:  # Optional[X] / X | None
            inner = next(a for a in args if a is not _NoneType)
            if value is None:
                p.pack_uint(0)
            else:
                p.pack_uint(1)
                _enc(p, value, inner)
            return
        raise TypeError("XDR: non-optional unions not yet supported")
    if origin is list:
        (elem_t,) = typing.get_args(t)
        p.pack_uint(len(value))
        for el in value:
            _enc(p, el, elem_t)
        return
    # scalars (bool before int — bool is an int subclass)
    if t is bool:
        p.pack_bool(value)
    elif t is int:
        p.pack_int(value)  # default: i32
    elif t is float:
        p.pack_double(value)
    elif t is str:
        p.pack_string(value.encode("utf-8"))
    elif t is bytes:
        p.pack_opaque(value)
    elif isinstance(t, type) and issubclass(t, IntEnum):
        p.pack_int(int(value))
    elif isinstance(t, type) and issubclass(t, msgspec.Struct):
        for name, ft in _struct_fields(t):
            _enc(p, getattr(value, name), ft)
    else:
        raise TypeError(f"XDR: unsupported type {t!r}")


def _dec(u: xdrlib.Unpacker, t: typing.Any) -> typing.Any:
    origin = typing.get_origin(t)
    if origin is typing.Annotated:
        meta = t.__metadata__
        if _I64 in meta:
            return u.unpack_hyper()
        if _U32 in meta:
            return u.unpack_uint()
        if _I32 in meta:
            return u.unpack_int()
        return _dec(u, typing.get_args(t)[0])
    if origin in _UnionTypes:
        args = typing.get_args(t)
        if _NoneType in args:
            inner = next(a for a in args if a is not _NoneType)
            return _dec(u, inner) if u.unpack_uint() else None
        raise TypeError("XDR: non-optional unions not yet supported")
    if origin is list:
        (elem_t,) = typing.get_args(t)
        return [_dec(u, elem_t) for _ in range(u.unpack_uint())]
    if t is bool:
        return u.unpack_bool()
    if t is int:
        return u.unpack_int()
    if t is float:
        return u.unpack_double()
    if t is str:
        return u.unpack_string().decode("utf-8")
    if t is bytes:
        return u.unpack_opaque()
    if isinstance(t, type) and issubclass(t, IntEnum):
        return t(u.unpack_int())
    if isinstance(t, type) and issubclass(t, msgspec.Struct):
        return t(**{name: _dec(u, ft) for name, ft in _struct_fields(t)})
    raise TypeError(f"XDR: unsupported type {t!r}")


def encode(value: typing.Any, t: typing.Any = None) -> bytes:
    """Encode `value` (of msgspec type `t`, defaulting to `type(value)`) to canonical XDR bytes."""
    p = xdrlib.Packer()
    _enc(p, value, t if t is not None else type(value))
    return p.get_buffer()


def decode(buf: bytes, t: typing.Any) -> typing.Any:
    """Decode an XDR blob into an instance of msgspec type `t` (lenient: trailing bytes allowed)."""
    return _dec(xdrlib.Unpacker(buf), t)


# ── Frame envelope (mirrors zig/src/xdr_frame.zig) ────────────────────────────


def is_xdr(wire: bytes) -> bool:
    return len(wire) >= 4 and int.from_bytes(wire[:4], "big") == MAGIC


def _pack_id(p: xdrlib.Packer, rid_bytes: bytes | None) -> None:
    if rid_bytes is None:
        p.pack_uint(0)
    else:
        p.pack_uint(1)
        p.pack_fopaque(16, rid_bytes)


def request_frame(proc_id: int, rid_bytes: bytes | None, params_xdr: bytes) -> bytes:
    """magic + RequestEnvelope{version, proc_id, id} + params (already XDR-encoded)."""
    p = xdrlib.Packer()
    p.pack_uint(MAGIC)
    p.pack_uint(VERSION)
    p.pack_uint(proc_id)
    _pack_id(p, rid_bytes)
    return p.get_buffer() + params_xdr


def reply_frame(rid_bytes: bytes | None, result_xdr: bytes) -> bytes:
    """magic + ReplyEnvelope{version, id, status=0} + result (already XDR-encoded)."""
    p = xdrlib.Packer()
    p.pack_uint(MAGIC)
    p.pack_uint(VERSION)
    _pack_id(p, rid_bytes)
    p.pack_uint(0)  # status: ok
    return p.get_buffer() + result_xdr


def error_frame(rid_bytes: bytes | None, code: int, detail_json: bytes) -> bytes:
    """magic + ReplyEnvelope{version, id, status=1} + {code:i32, detail:string<>}."""
    p = xdrlib.Packer()
    p.pack_uint(MAGIC)
    p.pack_uint(VERSION)
    _pack_id(p, rid_bytes)
    p.pack_uint(1)  # status: err
    p.pack_int(code)
    p.pack_string(detail_json)
    return p.get_buffer()


class ParsedRequest(typing.NamedTuple):
    version: int
    proc_id: int
    rid_bytes: typing.Optional[bytes]
    params: bytes


def parse_request(wire: bytes) -> ParsedRequest:
    u = xdrlib.Unpacker(wire)
    if u.unpack_uint() != MAGIC:
        raise ValueError("not an XDR frame")
    ver = u.unpack_uint()
    proc = u.unpack_uint()
    rid = u.unpack_fopaque(16) if u.unpack_uint() else None
    return ParsedRequest(ver, proc, rid, wire[u.get_position():])


# ── Filterable (query) methods over XDR ───────────────────────────────────────
# A filterable request's augmented accepts ride as XDR<base> + XDR<XdrQueryOptions> + XDR<query-filters as a
# JSON-text string<>>, and the result as XDR<hyper> (count) or XDR<list[entry]> (records). The dynamic,
# recursive query-filters stay JSON text inside the binary frame; the base params, query-options, and result
# are XDR. The options are the REDUCED set the Zig port supports (`get` + `select` were dropped), field-ordered
# to match the Zig `filter.QueryOptions` struct so the bytes line up. offset/limit are u64 on the Zig side;
# `Hyper` (i64) is wire-identical for the non-negative values they always hold.


class XdrQueryOptions(msgspec.Struct):
    count: bool = False
    order_by: typing.Optional[list[str]] = None
    offset: Hyper = 0
    limit: Hyper = 0


def decode_query_params(buf: bytes, base_t: typing.Any) -> tuple[typing.Any, "XdrQueryOptions", str]:
    """Decode the XDR filterable accepts → (base_struct, XdrQueryOptions, filters_json_text)."""
    u = xdrlib.Unpacker(buf)
    base = _dec(u, base_t)
    opts = _dec(u, XdrQueryOptions)
    filters: str = u.unpack_string().decode("utf-8")
    return base, opts, filters


def encode_query_result(result: typing.Any, entry_t: typing.Any) -> bytes:
    """Encode a finalized filterable result as XDR: an int count → a hyper; a list of records →
    `u32 count + each entry` (each coerced to `entry_t`, so a dict-or-struct record encodes identically)."""
    if isinstance(result, int) and not isinstance(result, bool):
        return encode(result, Hyper)
    records = [msgspec.convert(r, entry_t) for r in result]
    return encode(records, list[entry_t])
