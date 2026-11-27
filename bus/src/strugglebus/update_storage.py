"""Updater-only descriptor-relative, bounded persistent cache primitives."""

from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import Protocol

from strugglebus.release_validation import STATEMENT_NAME

from strugglebus.update_types import (
    JsonValue, UpdateCandidate, UpdateError, UpdateLimits, decode_json, encode_json,
    require_hex,
)

JOURNAL = "updater-journal.json"
NEXT_JOURNAL = "updater-journal.next"
LOCK = "updater-worker.lock"


class StateStorage(Protocol):
    def load(self) -> JsonValue:
        raise NotImplementedError

    def save(self, value: JsonValue) -> None:
        raise NotImplementedError

    def create_slot(self, operation_id: str) -> Path:
        raise NotImplementedError

    def slot_path(self, operation_id: str) -> Path:
        raise NotImplementedError

    def retire_slot(self, operation_id: str) -> None:
        raise NotImplementedError

    def validate_slot(self, operation_id: str, candidate: UpdateCandidate) -> None:
        raise NotImplementedError

    def validate_inventory(self, identities: tuple[str, ...]) -> None:
        raise NotImplementedError


# A prepared release is its five files and the publisher's signed statement.
MAXIMUM_SLOT_ENTRIES = 6


def check_metadata(info: os.stat_result, uid: int, mode: int, directory: bool) -> None:
    kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not kind or info.st_uid != uid or stat.S_IMODE(info.st_mode) != mode:
        raise UpdateError("storage_unsafe")
    if not directory and info.st_nlink != 1:
        raise UpdateError("storage_unsafe")


def check_ancestry(path: Path, *, owner: int = 0) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise UpdateError("storage_unsafe")
    for parent in reversed(path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise UpdateError("storage_unsafe")


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _file_flags() -> int:
    return os.O_NOFOLLOW | os.O_CLOEXEC


def read_protected_file(path: Path, maximum: int, *, owner: int = 0) -> bytes:
    check_ancestry(path)
    before = path.lstat()
    mode = stat.S_IMODE(before.st_mode)
    if mode not in {0o600, 0o640, 0o644}:
        raise UpdateError("storage_unsafe")
    check_metadata(before, owner, mode, False)
    fd = os.open(path, os.O_RDONLY | _file_flags())
    try:
        if _identity(os.fstat(fd)) != _identity(before):
            raise UpdateError("storage_unsafe")
        result = _read_bounded(fd, maximum)
        if _identity(path.lstat()) != _identity(before):
            raise UpdateError("storage_unsafe")
        return result
    finally:
        os.close(fd)


def _read_bounded(fd: int, maximum: int) -> bytes:
    data = bytearray()
    while len(data) <= maximum:
        part = os.read(fd, min(65536, maximum + 1 - len(data)))
        if not part:
            return bytes(data)
        data.extend(part)
    raise UpdateError("storage_full")


def _write_all(fd: int, data: bytes) -> None:
    position = 0
    while position < len(data):
        written = os.write(fd, data[position:])
        if written <= 0:
            raise UpdateError("storage_full")
        position += written


class SecureCache:
    def __init__(self, path: Path, limits: UpdateLimits):
        self.path = path
        self.limits = limits
        self.uid = os.getuid()
        check_ancestry(path)
        check_metadata(path.lstat(), self.uid, 0o700, True)
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | _file_flags())
        self.identity = _identity(os.fstat(self.fd))
        self.lock_fd: int | None = None
        self._check_root()

    def close(self) -> None:
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None
        os.close(self.fd)

    def _check_root(self) -> None:
        info = self.path.lstat()
        check_metadata(info, self.uid, 0o700, True)
        if _identity(info) != self.identity:
            raise UpdateError("storage_unsafe")

    def acquire(self) -> None:
        import fcntl

        self._check_root()
        try:
            fd = self._create_file(LOCK)
            os.fsync(fd)
            os.fsync(self.fd)
        except FileExistsError:
            fd = self._open_file(LOCK)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise UpdateError("busy") from None
        self.lock_fd = fd

    def initialize(self, value: JsonValue) -> None:
        self._check_root()
        if set(os.listdir(self.fd)) != {LOCK}:
            raise UpdateError("state_corrupt")
        self._check_space(self.limits.artifact_bytes)
        self.save(value)

    def _create_file(self, name: str, *, parent: int | None = None) -> int:
        directory = self.fd if parent is None else parent
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | _file_flags(),
                     0o600, dir_fd=directory)
        try:
            os.fchmod(fd, 0o600)
            check_metadata(os.fstat(fd), self.uid, 0o600, False)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _open_file(self, name: str, *, parent: int | None = None) -> int:
        directory = self.fd if parent is None else parent
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        check_metadata(before, self.uid, 0o600, False)
        fd = os.open(name, os.O_RDONLY | _file_flags(), dir_fd=directory)
        if _identity(os.fstat(fd)) != _identity(before):
            os.close(fd)
            raise UpdateError("storage_unsafe")
        return fd

    def load(self) -> JsonValue:
        self._check_root()
        if NEXT_JOURNAL in os.listdir(self.fd):
            raise UpdateError("state_corrupt")
        try:
            fd = self._open_file(JOURNAL)
            try:
                return decode_json(_read_bounded(fd, self.limits.journal_bytes // 2),
                                   self.limits.journal_bytes // 2)
            finally:
                os.close(fd)
        except (OSError, UpdateError):
            raise UpdateError("state_corrupt") from None

    def save(self, value: JsonValue) -> None:
        self._check_root()
        self._check_space(0)
        data = encode_json(value, self.limits.journal_bytes // 2)
        existing: int | None = None
        if JOURNAL in os.listdir(self.fd):
            existing = self._open_file(JOURNAL)
        try:
            self._replace_journal(data, existing)
        finally:
            if existing is not None:
                os.close(existing)

    def _replace_journal(self, data: bytes, existing: int | None) -> None:
        fd = self._create_file(NEXT_JOURNAL)
        try:
            _write_all(fd, data)
            os.fsync(fd)
            self._check_entry(self.fd, NEXT_JOURNAL, fd)
        finally:
            os.close(fd)
        self._check_root()
        if existing is not None:
            self._check_entry(self.fd, JOURNAL, existing)
        os.replace(NEXT_JOURNAL, JOURNAL, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        os.fsync(self.fd)

    def _check_space(self, additional: int) -> None:
        info = os.fstatvfs(self.fd)
        free = info.f_bavail * info.f_frsize
        if free < self.limits.reserve_bytes + self.limits.journal_bytes + additional:
            raise UpdateError("storage_full")

    def slot_path(self, operation_id: str) -> Path:
        require_hex(operation_id, 32)
        return self.path / ("operation-" + operation_id)

    def _open_slot(self, operation_id: str) -> int:
        self._check_root()
        name = self.slot_path(operation_id).name
        before = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        check_metadata(before, self.uid, 0o700, True)
        if before.st_dev != self.identity[0]:
            raise UpdateError("storage_unsafe")
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | _file_flags(), dir_fd=self.fd)
        if _identity(os.fstat(fd)) != _identity(before):
            os.close(fd)
            raise UpdateError("storage_unsafe")
        return fd

    def create_slot(self, operation_id: str) -> Path:
        self._check_root()
        self._check_space(self.limits.candidate_bytes)
        if self._artifact_usage() + self.limits.candidate_bytes > self.limits.artifact_bytes:
            raise UpdateError("storage_full")
        path = self.slot_path(operation_id)
        os.mkdir(path.name, 0o700, dir_fd=self.fd)
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | _file_flags(), dir_fd=self.fd)
        try:
            os.fchmod(fd, 0o700)
            os.fsync(fd)
            os.fsync(self.fd)
        finally:
            os.close(fd)
        return path

    def _artifact_usage(self) -> int:
        total = 0
        names = set(os.listdir(self.fd)) - {JOURNAL, LOCK}
        if len(names) >= 2:
            raise UpdateError("cleanup_pending")
        for name in names:
            if not name.startswith("operation-"):
                raise UpdateError("storage_unsafe")
            fd = self._open_slot(name.removeprefix("operation-"))
            try:
                entries = os.listdir(fd)
                if len(entries) > MAXIMUM_SLOT_ENTRIES:
                    raise UpdateError("storage_unsafe")
                for child in entries:
                    item = self._open_file(child, parent=fd)
                    try:
                        total += os.fstat(item).st_size
                    finally:
                        os.close(item)
            finally:
                os.close(fd)
        return total

    def validate_slot(self, operation_id: str, candidate: UpdateCandidate) -> None:
        fd = self._open_slot(operation_id)
        try:
            # The release's files and, beside them, the publisher's signed statement.
            if set(os.listdir(fd)) != {asset.name for asset in candidate.assets} | {STATEMENT_NAME}:
                raise UpdateError("verification_failed")
            for asset in candidate.assets:
                child = self._open_file(asset.name, parent=fd)
                try:
                    if _hash_file(child, asset.size_bytes) != asset.sha256:
                        raise UpdateError("verification_failed")
                    self._check_entry(fd, asset.name, child)
                    os.fsync(child)
                finally:
                    os.close(child)
            os.fsync(fd)
            self._check_entry(self.fd, self.slot_path(operation_id).name, fd)
            self._check_space(0)
        finally:
            os.close(fd)

    def retire_slot(self, operation_id: str) -> None:
        name = self.slot_path(operation_id).name
        try:
            fd = self._open_slot(operation_id)
        except FileNotFoundError:
            return
        try:
            entries = os.listdir(fd)
            if len(entries) > MAXIMUM_SLOT_ENTRIES:
                raise UpdateError("storage_unsafe")
            for entry in entries:
                child = self._open_file(entry, parent=fd)
                try:
                    self._check_entry(fd, entry, child)
                    os.unlink(entry, dir_fd=fd)
                finally:
                    os.close(child)
            os.fsync(fd)
            self._check_entry(self.fd, name, fd)
            os.rmdir(name, dir_fd=self.fd)
        finally:
            os.close(fd)
        os.fsync(self.fd)

    def _check_entry(self, parent: int, name: str, fd: int) -> None:
        path_info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if _identity(path_info) != _identity(os.fstat(fd)):
            raise UpdateError("storage_unsafe")

    def validate_inventory(self, identities: tuple[str, ...]) -> None:
        self._check_root()
        allowed = {JOURNAL, LOCK}
        allowed.update(self.slot_path(identity).name for identity in identities)
        if set(os.listdir(self.fd)) - allowed:
            raise UpdateError("state_corrupt")


def _hash_file(fd: int, size: int) -> str:
    import hashlib

    if os.fstat(fd).st_size != size:
        raise UpdateError("verification_failed")
    digest = hashlib.sha256()
    count = 0
    while count <= size:
        part = os.read(fd, min(65536, size + 1 - count))
        if not part:
            break
        count += len(part)
        digest.update(part)
    if count != size:
        raise UpdateError("verification_failed")
    return digest.hexdigest()
