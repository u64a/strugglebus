"""Persistent emergency agent-access freeze controls."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime
import errno
import os
from pathlib import Path
import stat
import time
from typing import TYPE_CHECKING

from strugglebus.errors import DomainValidationError, StorageError
from strugglebus.models import AccessFreezeState

if TYPE_CHECKING:
    from strugglebus.store import SQLiteStore

ACCESS_FREEZE_CAPABILITY = "global-v1"
MAX_ACCESS_FREEZE_REASON_CHARACTERS = 256
MAX_ACCESS_FREEZE_REASON_BYTES = 1024
ACCESS_FREEZE_LOCK_DIRECTORY = ".access-freeze-lock"
ACCESS_FREEZE_LOCK_NAME = "transition.lock"
ACCESS_FREEZE_LOCK_TIMEOUT_SECONDS = 30.0
LOCK_POLL_SECONDS = 0.05


def _prepare_lock_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, exist_ok=True)
        metadata = path.lstat()
    except OSError as error:
        raise StorageError("access-freeze lock directory is unavailable") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise StorageError("access-freeze lock directory is unsafe")
    if os.name == "posix" and (
        metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise StorageError("access-freeze lock directory is unsafe")


def _open_or_create_lock_file(path: Path, flags: int) -> tuple[int, bool]:
    """Return the descriptor and whether this call created the lock file."""
    try:
        return os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600), True
    except FileExistsError:
        return os.open(path, flags), False


def _require_private_lock_file(
    descriptor: int,
    metadata: os.stat_result,
    *,
    created: bool,
) -> None:
    if created and hasattr(os, "fchmod"):
        os.fchmod(descriptor, 0o600)
    elif os.name == "posix" and (
        metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise StorageError("access-freeze lock file is unsafe")


def _require_safe_lock_file(descriptor: int, path: Path, *, created: bool) -> None:
    metadata = os.fstat(descriptor)
    path_metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(path_metadata.st_mode)
        or metadata.st_nlink != 1
        or (metadata.st_dev, metadata.st_ino)
        != (path_metadata.st_dev, path_metadata.st_ino)
    ):
        raise StorageError("access-freeze lock path is unsafe")
    _require_private_lock_file(descriptor, metadata, created=created)


def _open_lock_file(directory: Path) -> int:
    path = directory / ACCESS_FREEZE_LOCK_NAME
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor, created = _open_or_create_lock_file(path, flags)
    except OSError as error:
        raise StorageError("access-freeze lock could not be opened safely") from error
    try:
        _require_safe_lock_file(descriptor, path, created=created)
        return descriptor
    except (OSError, StorageError):
        os.close(descriptor)
        raise


def _try_lock(descriptor: int) -> bool:
    os.lseek(descriptor, 0, os.SEEK_SET)
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError as error:
        if error.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
            return False
        raise


def _unlock(descriptor: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_UN)


@contextmanager
def access_freeze_transition_lock(directory: Path) -> Iterator[None]:
    _prepare_lock_directory(directory)
    descriptor = _open_lock_file(directory)
    acquired = False
    deadline = time.monotonic() + ACCESS_FREEZE_LOCK_TIMEOUT_SECONDS
    try:
        while not acquired:
            try:
                acquired = _try_lock(descriptor)
            except OSError as error:
                raise StorageError("access-freeze lock could not be acquired") from error
            if acquired:
                break
            if time.monotonic() >= deadline:
                raise StorageError("timed out waiting for the access-freeze lock")
            time.sleep(min(LOCK_POLL_SECONDS, max(0.0, deadline - time.monotonic())))
        yield
    finally:
        try:
            if acquired:
                _unlock(descriptor)
        except OSError as error:
            raise StorageError("access-freeze lock could not be released") from error
        finally:
            os.close(descriptor)


def normalize_access_freeze_reason(value: str) -> str:
    if not isinstance(value, str):
        raise DomainValidationError("access-freeze reason must be text")
    reason = value.strip()
    if not reason:
        raise DomainValidationError("access-freeze reason must not be empty")
    if "\x00" in reason:
        raise DomainValidationError("access-freeze reason must not contain NUL")
    if len(reason) > MAX_ACCESS_FREEZE_REASON_CHARACTERS:
        raise DomainValidationError(
            "access-freeze reason must not exceed "
            f"{MAX_ACCESS_FREEZE_REASON_CHARACTERS} characters"
        )
    if len(reason.encode("utf-8")) > MAX_ACCESS_FREEZE_REASON_BYTES:
        raise DomainValidationError(
            f"access-freeze reason must not exceed {MAX_ACCESS_FREEZE_REASON_BYTES} bytes"
        )
    return reason


class AccessFreezeService:
    def __init__(
        self,
        store: SQLiteStore,
        *,
        clock: Callable[[], datetime],
        transition_lock_directory: Path,
    ) -> None:
        self.store = store
        self._clock = clock
        self.transition_lock_directory = transition_lock_directory

    def status(self) -> AccessFreezeState:
        return self.store.get_access_freeze()

    def operator_status(self) -> AccessFreezeState:
        with access_freeze_transition_lock(self.transition_lock_directory):
            self.store.initialize()
            return self.status()

    def _transition(
        self,
        *,
        frozen: bool,
        reason: str,
        actor_type: str,
        actor_id: str,
    ) -> tuple[AccessFreezeState, bool]:
        return self.store.set_access_freeze(
            frozen=frozen,
            reason=reason,
            changed_at=self._clock(),
            actor_type=actor_type,
            actor_id=actor_id,
        )

    def freeze(self, reason: str) -> tuple[AccessFreezeState, bool]:
        normalized_reason = normalize_access_freeze_reason(reason)
        with access_freeze_transition_lock(self.transition_lock_directory):
            return self._transition(
                frozen=True,
                reason=normalized_reason,
                actor_type="system",
                actor_id="system:access-service",
            )

    def unfreeze(self, reason: str) -> tuple[AccessFreezeState, bool]:
        normalized_reason = normalize_access_freeze_reason(reason)
        with access_freeze_transition_lock(self.transition_lock_directory):
            return self._transition(
                frozen=False,
                reason=normalized_reason,
                actor_type="system",
                actor_id="system:access-service",
            )

    def operator_freeze(self, reason: str) -> tuple[AccessFreezeState, bool]:
        normalized_reason = normalize_access_freeze_reason(reason)
        with access_freeze_transition_lock(self.transition_lock_directory):
            self.store.initialize()
            return self._transition(
                frozen=True,
                reason=normalized_reason,
                actor_type="local-admin",
                actor_id="local-cli",
            )

    def operator_unfreeze(self, reason: str) -> tuple[AccessFreezeState, bool]:
        normalized_reason = normalize_access_freeze_reason(reason)
        with access_freeze_transition_lock(self.transition_lock_directory):
            self.store.initialize()
            return self._transition(
                frozen=False,
                reason=normalized_reason,
                actor_type="local-admin",
                actor_id="local-cli",
            )

    def operator_freeze_mobile(
        self,
        reason: str,
        *,
        device_id: str,
    ) -> tuple[AccessFreezeState, bool]:
        normalized_reason = normalize_access_freeze_reason(reason)
        with access_freeze_transition_lock(self.transition_lock_directory):
            self.store.initialize()
            return self._transition(
                frozen=True,
                reason=normalized_reason,
                actor_type="remote-admin",
                actor_id=f"device:{device_id}",
            )

    def operator_unfreeze_mobile(
        self,
        reason: str,
        *,
        device_id: str,
        credential_id: str,
        candidate_grant_digest: str,
    ) -> tuple[AccessFreezeState, bool] | None:
        """Clear the freeze only while the device proofs remain live."""

        normalized_reason = normalize_access_freeze_reason(reason)
        changed_at = self._clock()
        with access_freeze_transition_lock(self.transition_lock_directory):
            self.store.initialize()
            return self.store.clear_access_freeze_for_mobile(
                reason=normalized_reason,
                changed_at=changed_at,
                device_id=device_id,
                credential_id=credential_id,
                candidate_grant_digest=candidate_grant_digest,
            )
