"""A small, functional bi-directional file-transfer API built on
``JSONRPCFdTransferMethod`` — a `lookup` (directory listing) plus `get`/`put`
(download/upload) that stream file bytes over the connection's raw socket fd.

It demonstrates the raw-fd transfer mechanism end to end: the ``negotiate`` callback
opens the file (so a missing-file / bad-name error is reported as a normal JSON-RPC
error *before* the ``$/transferReady`` handshake), and the ``transfer`` callback runs
the ``sendfile``/``recvfile`` loop on the fd.

================================================================================
                          !!!  SECURITY WARNING  !!!
================================================================================
THIS IS DEMO CODE. IT IS NOT SAFE FOR PRODUCTION USE.

It resolves files by joining a hard-coded root with a client-supplied name and
calling a plain ``os.open()``:

  * It rejects path separators, so a name cannot traverse out of the root — but
  * ``os.open()`` FOLLOWS SYMLINKS and is subject to TOCTOU races. A symlink placed
    in the share root (or a path component swapped between the stat and the open)
    can redirect a read or write ANYWHERE on the filesystem. There is no
    symlink-race resistance whatsoever.

A real server MUST resolve every path component safely against an O_PATH root fd,
e.g. ``truenas_os.openat2(name, flags, dir_fd=root_fd,
resolve=RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)`` (or a file-handle-based lookup),
never a string ``os.path.join`` + ``os.open``. This example deliberately keeps the
resolution trivial to stay focused on the transfer wire mechanism.
================================================================================
"""
import os
import stat

import msgspec

from truenas_pyjsonrpc import (
    JSONRPCError,
    JSONRPCFdTransferMethod,
    JSONRPCMethod,
    JSONRPCProtocol,
    JsonRpcError,
    TransferDirection,
)


# --- api types ---------------------------------------------------------------
class LookupArgs(msgspec.Struct):
    pass                                  # root-only listing; no path argument


class DirEntry(msgspec.Struct):
    name: str
    type: str                            # "file" | "dir" | "other"
    size: int


class LookupResult(msgspec.Struct):
    root: str
    entries: list[DirEntry]


class GetArgs(msgspec.Struct):
    name: str


class GetResult(msgspec.Struct):
    name: str
    sent: int


class PutArgs(msgspec.Struct):
    name: str
    size: int                            # bytes the client will stream (self-delimiting)


class PutResult(msgspec.Struct):
    name: str
    received: int


# --- the share ---------------------------------------------------------------
class FileShare:
    """Serves files out of a single flat directory (the ``root``).

    ``get``/``put`` are raw-fd transfers: ``*_negotiate`` opens the file before the
    ``$/transferReady`` handshake (and stashes the fd, keyed by the session), and
    ``*_transfer`` runs the bulk ``sendfile``/``recvfile`` loop on it. A transfer
    monopolizes the connection, so at most one fd is pending per session at a time.
    """

    def __init__(self, root: str) -> None:
        self.root = root
        self._pending: dict[str, int] = {}    # session_uuid -> open fd (negotiate->transfer)

    # WARNING: see the module-level security banner. This is NOT a safe resolver.
    def _path(self, name: str) -> str:
        if "/" in name or name in ("", ".", ".."):
            raise JsonRpcError(JSONRPCError.INVALID_PARAMS, "Invalid name",
                               "name must be a single path component")
        return os.path.join(self.root, name)

    def _stash(self, key: str, fd: int) -> None:
        old = self._pending.pop(key, None)    # defensively close a leaked prior fd
        if old is not None:
            os.close(old)
        self._pending[key] = fd

    # lookup: an ordinary request/response method (no transfer) ----------------
    def lookup(self, request: LookupArgs, session_state, request_state) -> LookupResult:
        entries = []
        with os.scandir(self.root) as it:
            for de in it:
                st = de.stat(follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode):
                    kind = "dir"
                elif stat.S_ISREG(st.st_mode):
                    kind = "file"
                else:
                    kind = "other"
                entries.append(DirEntry(name=de.name, type=kind, size=st.st_size))
        entries.sort(key=lambda e: e.name)
        return LookupResult(root=self.root, entries=entries)

    # get: DOWNLOAD (server produces, client consumes) -------------------------
    def get_negotiate(self, request: GetArgs, session_state):
        try:
            fd = os.open(self._path(request.name), os.O_RDONLY)   # WARNING: follows symlinks
        except FileNotFoundError:
            raise JsonRpcError(JSONRPCError.REQUEST_FAILED, "No such file", request.name)
        except OSError as e:
            raise JsonRpcError(JSONRPCError.REQUEST_FAILED, "Open failed", str(e))
        size = os.fstat(fd).st_size
        self._stash(session_state.session_uuid, fd)
        return {"name": request.name, "size": size}   # -> client as $/transferReady result

    def get_transfer(self, ft) -> GetResult:
        fd = self._pending.pop(ft.session_state.session_uuid)
        try:
            sent = ft.sendfile(fd)                     # os.sendfile fd -> socket
        finally:
            os.close(fd)
        return GetResult(name=ft.params.name, sent=sent)

    # put: UPLOAD (client produces, server consumes) ---------------------------
    def put_negotiate(self, request: PutArgs, session_state):
        try:
            fd = os.open(self._path(request.name),     # WARNING: follows symlinks, no O_EXCL
                         os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        except OSError as e:
            raise JsonRpcError(JSONRPCError.REQUEST_FAILED, "Open failed", str(e))
        self._stash(session_state.session_uuid, fd)
        return True                                    # ready to receive

    def put_transfer(self, ft) -> PutResult:
        fd = self._pending.pop(ft.session_state.session_uuid)
        try:
            got = ft.recvfile(fd, ft.params.size)      # socket -> fd, exactly size bytes
        finally:
            os.close(fd)
        return PutResult(name=ft.params.name, received=got)


def build_protocol(root: str, *, name: str = "fileshare") -> JSONRPCProtocol:
    """A ``JSONRPCProtocol`` serving ``lookup`` + ``get`` + ``put`` out of ``root``."""
    os.makedirs(root, exist_ok=True)
    share = FileShare(root)
    return JSONRPCProtocol([
        JSONRPCMethod("fs.lookup", accepts=LookupArgs, returns=LookupResult,
                      handler=share.lookup),
        JSONRPCFdTransferMethod("fs.get", accepts=GetArgs, returns=GetResult,
                                direction=TransferDirection.DOWNLOAD,
                                negotiate=share.get_negotiate,
                                transfer=share.get_transfer),
        JSONRPCFdTransferMethod("fs.put", accepts=PutArgs, returns=PutResult,
                                direction=TransferDirection.UPLOAD,
                                negotiate=share.put_negotiate,
                                transfer=share.put_transfer),
    ], name=name)
