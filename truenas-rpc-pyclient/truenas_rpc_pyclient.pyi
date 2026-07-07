"""Type stubs for the ``truenas_rpc_pyclient`` extension (the ``pyo3-ffi`` ``RawClient`` byte
transport). Ships alongside the compiled module so a consumer's generated ``<Proto>Client`` — and any
direct user — type-checks against a typed runtime (no ``# type: ignore`` needed in generated code).
"""

from typing import TypedDict

class RpcError(Exception):
    """A server-returned JSON-RPC error, or a local transport / encode / decode failure.

    Raised with ``(code, message)`` args for a server error.
    """

class Negotiated(TypedDict):
    """The ``$/negotiate`` result."""

    protocol: str
    server: str | None
    available: list[str]

class RawClient:
    """A thin byte-boundary RPC client over the Rust engine. Created by :func:`connect` (never
    directly)."""

    def call(self, method: str, params: bytes) -> bytes:
        """Call ``method`` with pre-encoded ``params`` bytes; returns the raw result bytes."""
        ...

    def negotiated(self) -> Negotiated | None:
        """The ``$/negotiate`` result, or ``None`` for a client built without negotiating."""
        ...

def connect(path: str, protocol: str) -> RawClient:
    """Connect over AF_UNIX at ``path`` and ``$/negotiate`` ``protocol``; raises :class:`RpcError`
    if the server does not offer it."""
    ...
