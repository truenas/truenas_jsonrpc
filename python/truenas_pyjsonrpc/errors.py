"""The exception a handler raises to return a chosen JSON-RPC error."""
from __future__ import annotations

from typing import Any

from .types import JSONRPCError


class JsonRpcError(Exception):
    """Raise from a handler to produce a JSON-RPC error response.

    ``code`` may be a :class:`JSONRPCError` member or any ``int`` (e.g. a custom
    code in the reserved -32000..-32099 range). ``data`` is attached to the wire
    error object's ``data`` member when not ``None``.
    """

    def __init__(self, code: int | JSONRPCError, message: str,
                 data: Any = None) -> None:
        self.code = int(code)
        self.message = message
        self.data = data
        super().__init__(f"[{self.code}] {message}")
