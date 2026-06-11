"""``jrpc_method`` — a decorator that builds a :class:`JSONRPCMethod` from a
handler function and (optionally) registers it into one or more
:class:`JSONRPCProtocol` instances.

This is pure convenience over constructing ``JSONRPCMethod`` by hand: it produces
the same objects and has no effect on dispatch performance — the decorated function
is returned unchanged (still directly callable), with the built method attached as
``func.method``.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any, TypeVar

import msgspec

from .types import MessageDirection
from .method import JSONRPCMethod
from .protocol import JSONRPCProtocol

_StructType = type[msgspec.Struct]
F = TypeVar("F", bound=Callable[..., Any])


def jrpc_method(*, name: str | None = None,
                accepts: _StructType,
                returns: _StructType | None = None,
                direction: MessageDirection = MessageDirection.CLIENT_SERVER,
                notifies: _StructType | None = None,
                doc: str | None = None,
                pre_auth: bool = False,
                audit: bool = False,
                audit_message: str | None = None,
                cancellable: bool = False,
                roles: Iterable[str] = (),
                protocols: Iterable[JSONRPCProtocol] = (),
                accepts_validator: Callable[[Any], Any] | None = None,
                returns_validator: Callable[[Any], Any] | None = None
                ) -> Callable[[F], F]:
    """Build a :class:`JSONRPCMethod` from the decorated function and register it
    into each protocol in ``protocols``.

    For a ``CLIENT_SERVER`` method (the default) the decorated function is the
    handler. For a ``SERVER_CLIENT`` (subscribable) topic there is no handler — the
    decorated function is a declaration stub (its body is not invoked; publish via
    :meth:`JSONRPCProtocol.send_notification`). ``name`` defaults to the function's
    ``__name__`` (pass it explicitly for dotted names like ``"pool.create"``).

    The original function is returned unchanged (still directly callable), with the
    built method attached as ``func.method``.
    """
    def decorator(func: F) -> F:
        handler = None if direction is MessageDirection.SERVER_CLIENT else func
        method = JSONRPCMethod(
            name or func.__name__,
            accepts=accepts, returns=returns, direction=direction,
            notifies=notifies, handler=handler,
            doc=doc if doc is not None else func.__doc__, pre_auth=pre_auth,
            audit=audit, audit_message=audit_message, cancellable=cancellable,
            roles=roles,
            accepts_validator=accepts_validator,
            returns_validator=returns_validator)
        for proto in protocols:
            proto.register(method)
        setattr(func, "method", method)
        return func
    return decorator


# Class-style spelling, matching the JSONRPCMethod class name.
JRPCMethod = jrpc_method
