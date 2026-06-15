"""Query (filter / options) support for :class:`FilterableJSONRPCMethod`.

A filterable method's ``accepts`` is augmented with two optional fields,
``query-filters`` and ``query-options`` (see :func:`augment_accepts`). At dispatch
the framework **compiles** them (:func:`compile_query`) and passes the resulting
``truenas_pyfilter`` ``CompiledFilters`` / ``CompiledOptions`` **into the handler**
as ``filters=`` / ``options=`` keyword arguments. The handler applies them at its
source - typically by streaming a lazy generator through
``truenas_pyfilter.tnfilter`` - so a large result set (e.g. a million audit rows) is
never materialized just to be filtered; only the matching records are retained.

The handler returns the narrowed result (an ``int`` when ``query-options.count``,
otherwise a ``list``). The framework then applies the small ``get`` single-record
convention (:func:`finalize_result`) to match middleware's ``query`` semantics. The
:class:`QueryOptions` field set mirrors ``truenas_pyfilter.compile_options`` exactly.
"""
from __future__ import annotations

from typing import Any

import msgspec

from .errors import JsonRpcError
from .types import JSONRPCError

# A ``query-filters`` value is the middleware filter-condition list, e.g.
# ``[["name", "=", "x"], ["OR", [...]]]``; it is handed verbatim to
# ``compile_filters``.
QueryFilters = list[Any]


class QueryOptions(msgspec.Struct, frozen=True):
    """Wire model for ``query-options``. The fields are exactly the keyword
    arguments accepted by ``truenas_pyfilter.compile_options``."""
    get: bool = False
    count: bool = False
    select: list[str | list[Any]] | None = None
    order_by: list[str] | None = None
    offset: int = 0
    limit: int = 0


def augment_accepts(accepts: type[msgspec.Struct]) -> type[msgspec.Struct]:
    """Return a ``msgspec.Struct`` subclass of ``accepts`` with two **optional**
    fields added: ``query-filters`` (a filter list) and ``query-options``
    (:class:`QueryOptions`). Both default to empty, so augmenting an existing
    method's accepts is additive and non-breaking. Raises ``TypeError`` if the base
    already declares either field."""
    existing = {f.name for f in msgspec.structs.fields(accepts)}
    clash = existing & {"query_filters", "query_options"}
    if clash:
        raise TypeError(
            f"{accepts.__name__} already declares {sorted(clash)}; cannot augment it "
            "with query-filters/query-options")
    return msgspec.defstruct(
        f"{accepts.__name__}Query",
        (
            ("query_filters", QueryFilters,
             msgspec.field(default_factory=list, name="query-filters")),
            ("query_options", QueryOptions,
             msgspec.field(default_factory=QueryOptions, name="query-options")),
        ),
        bases=(accepts,),
    )


def compile_query(query_filters: QueryFilters, query_options: QueryOptions) -> tuple[Any, Any]:
    """Compile a request's ``query-filters``/``query-options`` into the
    ``truenas_pyfilter`` ``(CompiledFilters, CompiledOptions)`` the framework passes
    to a filterable handler. ``truenas_pyfilter`` is imported lazily so the framework
    stays importable without the (compiled) engine when no filterable methods are
    used. Invalid filter/option syntax becomes ``INVALID_PARAMS``."""
    from truenas_pyfilter import compile_filters, compile_options

    try:
        cf = compile_filters(list(query_filters or []))
        co = compile_options(
            get=query_options.get,
            count=query_options.count,
            select=query_options.select,
            order_by=query_options.order_by,
            offset=query_options.offset,
            limit=query_options.limit,
        )
    except (ValueError, TypeError) as e:
        raise JsonRpcError(JSONRPCError.INVALID_PARAMS, f"invalid query: {e}") from e
    return cf, co


def finalize_result(result: Any, query_options: QueryOptions) -> Any:
    """Apply the ``get`` single-record convention to a filterable handler's result.

    The handler is expected to have honored the rest of the options already (filters,
    select, order_by, offset, limit, and ``count`` -> an ``int``) - typically via
    ``tnfilter``. This only unwraps ``get`` to the single matching record (raising
    ``REQUEST_FAILED`` if none matched), matching middleware's ``query`` semantics;
    ``count`` passes straight through as an ``int``."""
    if query_options.count:
        return result
    if query_options.get:
        if not result:
            raise JsonRpcError(JSONRPCError.REQUEST_FAILED,
                               "no record matched query with get=True")
        return result[0]
    return result
