"""Private Linux receipt storage; records are recovery data, not signatures."""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
import errno
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import threading
from typing import Any, Iterator

from promotion_common import PromotionError


MAX_RECEIPT_BYTES = 64 * 1024
_LOCAL_FILESYSTEMS = frozenset(
    {"ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "bcachefs", "zfs"}
)
_PROC_LIMIT = 4 * 1024 * 1024


def _require_linux() -> None:
    if os.name != "posix" or sys.platform != "linux":
        raise PromotionError(
            "receipt storage requires native Linux or WSL with a native Linux "
            "filesystem; native Windows is not supported"
        )


def _canonical(document: Any) -> bytes:
    if type(document) is not dict:
        raise PromotionError("receipt must be a JSON object")
    remaining = MAX_RECEIPT_BYTES
    pending = [document]
    while pending:
        value = pending.pop()
        remaining -= 1
        if remaining < 0:
            raise PromotionError("receipt exceeds the 64 KiB limit")
        if type(value) is dict:
            if len(value) > remaining:
                raise PromotionError("receipt exceeds the 64 KiB limit")
            for key, item in value.items():
                if type(key) is not str:
                    raise PromotionError("receipt JSON object keys must be strings")
                pending.extend((key, item))
        elif type(value) is list:
            if len(value) > remaining:
                raise PromotionError("receipt exceeds the 64 KiB limit")
            pending.extend(value)
        elif type(value) is str:
            remaining -= len(value)
        elif type(value) is int:
            if value.bit_length() > MAX_RECEIPT_BYTES * 4:
                raise PromotionError("receipt exceeds the 64 KiB limit")
        elif value is not None and type(value) not in (bool, float):
            raise PromotionError("receipt contains a non-JSON value")
    encoded = bytearray()
    try:
        encoder = json.JSONEncoder(
            sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
        )
        for chunk in encoder.iterencode(document):
            encoded.extend(chunk.encode("ascii"))
            if len(encoded) + 1 > MAX_RECEIPT_BYTES:
                raise PromotionError("receipt exceeds the 64 KiB limit")
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise PromotionError("receipt contains invalid or excessively nested JSON") from None
    return bytes(encoded) + b"\n"


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise PromotionError("receipt contains duplicate JSON keys")
        result[key] = value
    return result


def _constant(value: str) -> Any:
    raise PromotionError("receipt contains a non-finite JSON number")


def _decode(payload: bytes) -> dict[str, Any]:
    if len(payload) > MAX_RECEIPT_BYTES:
        raise PromotionError("receipt exceeds the 64 KiB limit")
    try:
        document = json.loads(
            payload.decode("ascii"), object_pairs_hook=_pairs, parse_constant=_constant
        )
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise PromotionError("receipt is not valid canonical JSON") from None
    if _canonical(document) != payload:
        raise PromotionError("receipt is not canonical sorted ASCII JSON with one newline")
    return document


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _stamp(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _regular(info: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise PromotionError(
            f"{label} must be a current-owner 0600 regular file with no hardlinks"
        )


def _directory(info: os.stat_result, path: Path, *, parent: bool) -> None:
    if not stat.S_ISDIR(info.st_mode):
        raise PromotionError("receipt path must contain only real directories")
    if parent:
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise PromotionError("receipt parent must be a preexisting current-owner 0700 directory")
    elif info.st_uid not in {0, os.geteuid()} or (
        info.st_mode & 0o022
        and not (
            info.st_uid == 0
            and info.st_mode & stat.S_ISVTX
            and path in {Path("/tmp"), Path("/var/tmp")}  # nosec B108 # Exact root-owned sticky ancestors only.
        )
    ):
        raise PromotionError("receipt ancestors must be owner/root-owned and not writable by others")


def _local_storage(fd: int) -> None:
    # Mount IDs identify the descriptor's mount even when a path is bind-mounted.
    with open(f"/proc/self/fdinfo/{fd}", "rb") as stream:
        descriptor_info = stream.read(16385)
    if len(descriptor_info) > 16384:
        raise PromotionError("cannot establish receipt filesystem identity")
    mount_ids = [
        line.split()[1]
        for line in descriptor_info.splitlines()
        if line.startswith(b"mnt_id:") and len(line.split()) == 2
    ]
    if len(mount_ids) != 1:
        raise PromotionError("cannot establish receipt filesystem identity")
    with open("/proc/self/mountinfo", "rb") as stream:
        mounts = stream.read(_PROC_LIMIT + 1)
    if len(mounts) > _PROC_LIMIT:
        raise PromotionError("mount information exceeds the safety limit")
    matching = [line for line in mounts.splitlines() if line.split(b" ", 1)[0] == mount_ids[0]]
    try:
        filesystem = matching[0].split(b" - ", 1)[1].split()[0].decode("ascii")
    except (IndexError, UnicodeError):
        raise PromotionError("cannot establish receipt filesystem identity") from None
    if len(matching) != 1 or filesystem not in _LOCAL_FILESYSTEMS:
        raise PromotionError(
            "receipt storage requires a native local Linux filesystem; "
            "Windows/DrvFS, network, and unrecognized mounts are refused"
        )


class _Parent:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.chain: list[tuple[int, Path]] = []

    @property
    def fd(self) -> int:
        return self.chain[-1][0]

    def open(self) -> None:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        self.chain.append((os.open("/", flags), Path("/")))
        for component in self.path.parts[1:]:
            previous_fd, previous_path = self.chain[-1]
            _directory(os.fstat(previous_fd), previous_path, parent=False)
            child = os.open(component, flags, dir_fd=previous_fd)
            self.chain.append((child, previous_path / component))
        self.check()
        _local_storage(self.fd)

    def check(self) -> None:
        for index, (fd, path) in enumerate(self.chain):
            info = os.fstat(fd)
            _directory(info, path, parent=index == len(self.chain) - 1)
            named = (
                os.stat("/", follow_symlinks=False)
                if index == 0 else os.stat(
                    path.name, dir_fd=self.chain[index - 1][0], follow_symlinks=False
                )
            )
            if _identity(named) != _identity(info):
                raise PromotionError("receipt directory identity changed; stop and reconcile locally")

    def close(self) -> None:
        for fd, _ in reversed(self.chain):
            os.close(fd)
        self.chain.clear()


def _rename_create(source: str, target: str, parent_fd: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        rename = libc.renameat2
    except AttributeError:
        raise PromotionError("Linux atomic create-only receipt writes are unavailable") from None
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent_fd, os.fsencode(source), parent_fd, os.fsencode(target), 1):
        failure = ctypes.get_errno()
        if failure == errno.EEXIST:
            raise PromotionError("receipt already exists; explicit resume is required")
        raise PromotionError("atomic create-only receipt write failed; existing state was not reset")


class ReceiptStore:
    """Canonical receipts with a permanent lock; valid same-user edits are not authenticated."""

    def __init__(self, path: Path) -> None:
        _require_linux()
        if not isinstance(path, Path) or not path.is_absolute() or not path.name or ".." in path.parts:
            raise PromotionError("receipt path must be absolute without parent traversal")
        self._path = path
        self._parent: _Parent | None = None
        self._lock_fd: int | None = None
        self._holder: tuple[int, int] | None = None
        self._observed: tuple[int, ...] | None = None

    @property
    def path(self) -> Path:
        return self._path

    @property
    def _lock_name(self) -> str:
        return self.path.name + ".lock"

    @contextmanager
    def _directory(self) -> Iterator[_Parent]:
        parent = _Parent(self.path.parent)
        try:
            parent.open()
            yield parent
        except OSError:
            raise PromotionError(
                "receipt path could not be opened safely; require preexisting private "
                "directories without symlinks"
            ) from None
        finally:
            parent.close()

    def _check_lock(self) -> _Parent:
        if (
            self._parent is None or self._lock_fd is None
            or self._holder != (os.getpid(), threading.get_ident())
        ):
            raise PromotionError("receipt writes require this process's active exclusive lock")
        self._parent.check()
        held = os.fstat(self._lock_fd)
        try:
            named = os.stat(self._lock_name, dir_fd=self._parent.fd, follow_symlinks=False)
        except FileNotFoundError:
            raise PromotionError("stable receipt lock was removed; stop and reconcile locally") from None
        if _identity(held) != _identity(named):
            raise PromotionError("stable receipt lock was replaced; stop and reconcile locally")
        _regular(held, "receipt lock")
        return self._parent

    def _read(self, parent: _Parent) -> tuple[dict[str, Any], tuple[int, ...]]:
        try:
            named = os.stat(self.path.name, dir_fd=parent.fd, follow_symlinks=False)
        except FileNotFoundError:
            raise PromotionError("receipt does not exist; explicit creation is required") from None
        _regular(named, "receipt")
        fd = os.open(
            self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=parent.fd,
        )
        try:
            initial = os.fstat(fd)
            _regular(initial, "receipt")
            if _stamp(initial) != _stamp(named):
                raise PromotionError("receipt changed while opening; stop and reconcile locally")
            if initial.st_size > MAX_RECEIPT_BYTES:
                raise PromotionError("receipt exceeds the 64 KiB limit")
            payload = bytearray()
            while len(payload) <= MAX_RECEIPT_BYTES:
                chunk = os.read(fd, min(8192, MAX_RECEIPT_BYTES + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
            final = os.fstat(fd)
            current = os.stat(self.path.name, dir_fd=parent.fd, follow_symlinks=False)
            if _stamp(initial) != _stamp(final) or _stamp(final) != _stamp(current):
                raise PromotionError("receipt changed during reading; stop and reconcile locally")
            parent.check()
            return _decode(bytes(payload)), _stamp(final)
        finally:
            os.close(fd)

    def read(self) -> dict[str, Any]:
        """Read existing state without creating a receipt, directory, or lock."""
        _require_linux()
        try:
            if self._parent is not None:
                document, observed = self._read(self._check_lock())
                self._observed = observed
                return document
            with self._directory() as parent:
                return self._read(parent)[0]
        except OSError:
            raise PromotionError("receipt could not be read safely; existing state was not reset") from None

    @contextmanager
    def locked(self) -> Iterator[ReceiptStore]:
        """Serialize writers; neither the sibling lock nor its parent is replaced."""
        _require_linux()
        import fcntl

        if self._parent is not None:
            raise PromotionError("receipt lock is already active in this store")
        with self._directory() as parent:
            lock_fd = None
            try:
                # The directory lock prevents split locking if the sibling is replaced.
                # It deliberately serializes all receipt writers in this directory.
                try:
                    fcntl.flock(parent.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise PromotionError("receipt directory is locked by another promotion") from None
                flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                try:
                    lock_fd = os.open(
                        self._lock_name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent.fd
                    )
                except FileExistsError:
                    named = os.stat(self._lock_name, dir_fd=parent.fd, follow_symlinks=False)
                    _regular(named, "receipt lock")
                    lock_fd = os.open(self._lock_name, flags, dir_fd=parent.fd)
                    if _identity(os.fstat(lock_fd)) != _identity(named):
                        raise PromotionError("stable receipt lock changed while opening")
                else:
                    os.fchmod(lock_fd, 0o600)
                    os.fsync(lock_fd)
                    os.fsync(parent.fd)
                _regular(os.fstat(lock_fd), "receipt lock")
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise PromotionError("receipt is locked by another promotion") from None
                self._parent, self._lock_fd = parent, lock_fd
                self._holder = (os.getpid(), threading.get_ident())
                self._observed = None
                self._check_lock()
                yield self
            except OSError:
                raise PromotionError(
                    "receipt lock could not be used safely; do not delete or replace the stable lock"
                ) from None
            finally:
                self._parent = self._lock_fd = self._holder = self._observed = None
                if lock_fd is not None:
                    os.close(lock_fd)

    def write(self, document: dict[str, Any], *, create: bool = False) -> None:
        """Durably save canonical state under the lock; never reset malformed state."""
        _require_linux()
        temporary: str | None = None
        temporary_fd: int | None = None
        parent: _Parent | None = None
        replaced = False
        try:
            parent = self._check_lock()
            payload = _canonical(document)
            if create:
                try:
                    os.stat(self.path.name, dir_fd=parent.fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise PromotionError("receipt already exists; explicit resume is required")
                previous = None
            else:
                _, previous = self._read(parent)
                if self._observed is not None and self._observed != previous:
                    raise PromotionError("receipt changed since it was read; stop and reconcile locally")
            temporary = ".promotion-" + secrets.token_hex(16) + ".tmp"
            temporary_fd = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600, dir_fd=parent.fd,
            )
            os.fchmod(temporary_fd, 0o600)
            _regular(os.fstat(temporary_fd), "temporary receipt")
            remaining = memoryview(payload)
            while remaining:
                count = os.write(temporary_fd, remaining)
                if count <= 0:
                    raise OSError("short receipt write")
                remaining = remaining[count:]
            os.fsync(temporary_fd)
            self._check_lock()
            if previous is not None:
                _, current = self._read(parent)
                if previous != current:
                    raise PromotionError("receipt changed before replacement; stop and reconcile locally")
            staged = os.fstat(temporary_fd)
            _regular(staged, "temporary receipt")
            named = os.stat(temporary, dir_fd=parent.fd, follow_symlinks=False)
            if _stamp(staged) != _stamp(named):
                raise PromotionError("temporary receipt identity changed; stop and reconcile locally")
            if create:
                _rename_create(temporary, self.path.name, parent.fd)
            else:
                os.replace(temporary, self.path.name, src_dir_fd=parent.fd, dst_dir_fd=parent.fd)
            replaced = True
            os.fsync(parent.fd)
            current = os.stat(self.path.name, dir_fd=parent.fd, follow_symlinks=False)
            _regular(current, "receipt")
            if _identity(current) != _identity(staged):
                raise PromotionError("receipt changed after replacement; stop and reconcile locally")
            self._check_lock()
            self._observed = _stamp(current)
        except OSError:
            raise PromotionError(
                "receipt write or durability check failed; reconcile existing state without resetting it"
            ) from None
        finally:
            if temporary_fd is not None:
                try:
                    if temporary is not None and parent is not None and not replaced:
                        try:
                            named = os.stat(temporary, dir_fd=parent.fd, follow_symlinks=False)
                        except FileNotFoundError:
                            pass
                        else:
                            if _identity(named) == _identity(os.fstat(temporary_fd)):
                                os.unlink(temporary, dir_fd=parent.fd)
                except OSError:
                    raise PromotionError(
                        "could not safely remove this invocation's temporary receipt; "
                        "inspect locally without resetting existing state"
                    ) from None
                finally:
                    os.close(temporary_fd)
