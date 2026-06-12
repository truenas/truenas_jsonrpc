"""Example consumer ``api/`` module: request and response msgspec Structs.

A real consumer would split these across per-namespace files (pool.py, user.py, …).
"""
import msgspec


class PoolCreateArgs(msgspec.Struct):
    name: str
    size: int = 0


class PoolCreateResult(msgspec.Struct):
    id: int
    name: str


class NoParams(msgspec.Struct):
    pass


class PoolEvent(msgspec.Struct):       # the payload pushed to pool.events subscribers
    name: str
    state: str


class FileDownloadArgs(msgspec.Struct):   # a raw-fd transfer request (zfs-send-like)
    size: int                             # bytes the server will stream over the socket fd


class FileDownloadResult(msgspec.Struct):  # the post-transfer summary (final response)
    sent: int
    sha256: str
