"""Atomic, integrity-checked SQLite backup primitives."""

from __future__ import annotations

import errno
import os
import sqlite3
import stat
import tempfile
import time
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from collections.abc import Iterator
from collections.abc import Callable

from strugglebus.errors import BackupError

BACKUP_PATTERN = "strugglebus-*.db"
BACKUP_LOCK_NAME = ".strugglebus-backup.lock"
DEFAULT_BACKUP_RETENTION = 7
DEFAULT_LOCK_TIMEOUT_SECONDS = 10.0
LOCK_POLL_SECONDS = 0.05


def _open_or_create_lock_file(lock_path: Path, flags: int) -> tuple[int, bool]:
    """Return the descriptor and whether this call created the lock file."""
    try:
        return os.open(lock_path, flags | os.O_CREAT | os.O_EXCL, 0o600), True
    except FileExistsError:
        return os.open(lock_path, flags), False


def _require_private_lock_file(
    descriptor: int,
    metadata: os.stat_result,
    *,
    created: bool,
) -> None:
    if created:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
    elif os.name == "posix" and (
        metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise BackupError("backup lock file has unsafe ownership or permissions")


def _require_safe_lock_file(descriptor: int, lock_path: Path, *, created: bool) -> None:
    metadata = os.fstat(descriptor)
    path_metadata = os.lstat(lock_path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(path_metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino)
        != (path_metadata.st_dev, path_metadata.st_ino)
    ):
        raise BackupError("backup lock path is unsafe")
    _require_private_lock_file(descriptor, metadata, created=created)


def _open_lock_file(backup_dir: Path) -> int:
    lock_path = backup_dir / BACKUP_LOCK_NAME
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor, created = _open_or_create_lock_file(lock_path, flags)
    except OSError as error:
        raise BackupError("backup lock file could not be opened safely") from error

    try:
        _require_safe_lock_file(descriptor, lock_path, created=created)
        return descriptor
    except (OSError, BackupError):
        os.close(descriptor)
        raise


def _try_acquire_lock(descriptor: int) -> bool:
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


def _release_lock(descriptor: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_UN)


def _wait_for_lock(
    descriptor: int,
    *,
    deadline: float,
    on_contended: Callable[[], None] | None,
) -> None:
    """Poll until the lock is held; raise once the deadline has passed."""
    while True:
        try:
            if _try_acquire_lock(descriptor):
                return
        except OSError as error:
            raise BackupError("backup lock could not be acquired") from error
        if on_contended is not None:
            on_contended()
        if time.monotonic() >= deadline:
            raise BackupError("timed out waiting for the backup lock")
        time.sleep(
            min(LOCK_POLL_SECONDS, max(0.0, deadline - time.monotonic()))
        )


@contextmanager
def _backup_directory_lock(
    backup_dir: Path,
    *,
    timeout_seconds: float,
    on_acquired: Callable[[], None] | None = None,
    on_contended: Callable[[], None] | None = None,
) -> Iterator[None]:
    descriptor = _open_lock_file(backup_dir)
    acquired = False
    deadline = time.monotonic() + timeout_seconds
    try:
        _wait_for_lock(descriptor, deadline=deadline, on_contended=on_contended)
        acquired = True
        if on_acquired is not None:
            on_acquired()
        yield
    finally:
        try:
            if acquired:
                _release_lock(descriptor)
        except OSError as error:
            raise BackupError("backup lock could not be released") from error
        finally:
            os.close(descriptor)


def _select_destination(
    backup_dir: Path,
    destination_name: str | None,
) -> tuple[Path, bool]:
    if destination_name is not None:
        destination = backup_dir / destination_name
        if os.path.lexists(destination):
            raise BackupError("backup destination already exists")
        return destination, True

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    base_name = f"strugglebus-{timestamp}"
    counter = 0
    while True:
        suffix = "" if counter == 0 else f"-{counter}"
        destination = backup_dir / f"{base_name}{suffix}.db"
        if not os.path.lexists(destination):
            return destination, False
        counter += 1


def _replace_stable_backup(
    temporary: Path,
    destination: Path,
    *,
    retry_while_in_use: bool,
    timeout_seconds: float,
    on_contended: Callable[[], None] | None,
) -> None:
    """Replace the stable copy, waiting out readers where replacement is denied."""
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            os.replace(temporary, destination)
            return
        except PermissionError as error:
            if not retry_while_in_use:
                raise
            if on_contended is not None:
                on_contended()
            if time.monotonic() >= deadline:
                raise BackupError(
                    "timed out publishing stable backup because it is in use"
                ) from error
            time.sleep(
                min(LOCK_POLL_SECONDS, max(0.0, deadline - time.monotonic()))
            )


def _link_new_backup(
    temporary: Path,
    backup_dir: Path,
    destination_name: str | None,
) -> Path:
    """Publish under a name that never overwrites an existing backup."""
    while True:
        destination, explicit = _select_destination(
            backup_dir,
            destination_name,
        )
        try:
            os.link(temporary, destination)
        except FileExistsError as error:
            if explicit:
                raise BackupError("backup destination already exists") from error
            continue
        temporary.unlink()
        return destination


def _publish_backup(
    temporary: Path,
    backup_dir: Path,
    destination_name: str | None,
    retention: int | None,
    database: Path,
    replace_timeout_seconds: float,
    on_replace_contended: Callable[[], None] | None,
) -> Path:
    if destination_name is None and retention == 1:
        destination = backup_dir / "strugglebus-latest.db"
        if os.path.lexists(destination) and os.path.samefile(destination, database):
            raise BackupError("backup destination must differ from the database")
        # Only Windows refuses to replace a file that a reader still has open.
        _replace_stable_backup(
            temporary,
            destination,
            retry_while_in_use=os.name == "nt",
            timeout_seconds=replace_timeout_seconds,
            on_contended=on_replace_contended,
        )
        return destination
    return _link_new_backup(temporary, backup_dir, destination_name)


def _prune_backups(
    backup_dir: Path,
    database: Path,
    destination: Path,
    retention: int,
) -> None:
    backups = [destination]
    backups.extend(
        sorted(
            (
                path
                for path in backup_dir.glob(BACKUP_PATTERN)
                if path != destination
                and path.is_file()
                and not path.is_symlink()
                and path.resolve() != database
            ),
            key=lambda path: (
                path.stat().st_mtime_ns,
                path.name != "strugglebus-latest.db",
                path.name,
            ),
            reverse=True,
        )
    )
    for expired in backups[retention:]:
        expired.unlink()


def _require_valid_retention(retention: int | None) -> None:
    if retention is not None and (
        isinstance(retention, bool) or not isinstance(retention, int) or retention < 1
    ):
        raise BackupError("backup retention must be a positive integer")


def _require_valid_lock_timeout(lock_timeout_seconds: float) -> None:
    if (
        isinstance(lock_timeout_seconds, bool)
        or not isinstance(lock_timeout_seconds, (int, float))
        or not 0 < lock_timeout_seconds <= 300
    ):
        raise BackupError("backup lock timeout must be between 0 and 300 seconds")


def _validate_backup_request(
    database_path: Path,
    backup_dir: Path,
    destination_name: str | None,
    retention: int | None,
    lock_timeout_seconds: float,
) -> None:
    if not database_path.is_absolute() or not backup_dir.is_absolute():
        raise BackupError("database and backup paths must be absolute")
    _require_valid_retention(retention)
    _require_valid_lock_timeout(lock_timeout_seconds)
    if destination_name is not None and Path(destination_name).name != destination_name:
        raise BackupError("backup destination name must not contain a path")


def _prepare_backup_directory(backup_dir: Path) -> Path:
    """Create the private backup directory if needed and return its real path."""
    if backup_dir.is_symlink():
        raise BackupError("backup directory must not be a symbolic link")
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    resolved_backup_dir = backup_dir.resolve(strict=True)
    if resolved_backup_dir != backup_dir.absolute():
        raise BackupError("backup directory path must not contain symbolic links")
    directory_metadata = resolved_backup_dir.stat()
    if os.name == "posix" and (
        directory_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(directory_metadata.st_mode) & 0o077
    ):
        raise BackupError(
            "backup directory has unsafe ownership or permissions"
        )
    return resolved_backup_dir


def _copy_and_verify(database: Path, temporary: Path) -> None:
    source_uri = f"{database.as_uri()}?mode=ro"
    with closing(sqlite3.connect(source_uri, uri=True)) as source:
        with closing(sqlite3.connect(temporary)) as target:
            source.backup(target)
            integrity = target.execute(
                "PRAGMA integrity_check"
            ).fetchone()
            if integrity != ("ok",):
                raise BackupError(
                    "backup failed integrity verification"
                )
    temporary.chmod(0o600)


def _publish_verified_copy(
    database: Path,
    resolved_backup_dir: Path,
    *,
    destination_name: str | None,
    retention: int | None,
    replace_timeout_seconds: float,
    on_replace_contended: Callable[[], None] | None,
) -> Path:
    """Copy, verify, publish and prune; the caller holds the directory lock."""
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".strugglebus-backup-",
        suffix=".db",
        dir=resolved_backup_dir,
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        _copy_and_verify(database, temporary)
        destination = _publish_backup(
            temporary,
            resolved_backup_dir,
            destination_name,
            retention,
            database,
            replace_timeout_seconds,
            on_replace_contended,
        )
    finally:
        temporary.unlink(missing_ok=True)

    if destination.resolve() == database:
        destination.unlink(missing_ok=True)
        raise BackupError("backup destination must differ from the database")
    if retention is not None:
        _prune_backups(
            resolved_backup_dir,
            database,
            destination,
            retention,
        )
    return destination


def _create_verified_backup(
    database_path: Path,
    backup_dir: Path,
    *,
    destination_name: str | None = None,
    retention: int | None = None,
    lock_timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
    on_lock_acquired: Callable[[], None] | None = None,
    on_lock_contended: Callable[[], None] | None = None,
    on_replace_contended: Callable[[], None] | None = None,
) -> Path:
    """Publish and prune a verified backup under one cross-process lock."""

    _validate_backup_request(
        database_path, backup_dir, destination_name, retention, lock_timeout_seconds,
    )
    try:
        database = database_path.resolve(strict=True)
        resolved_backup_dir = _prepare_backup_directory(backup_dir)
        with _backup_directory_lock(
            resolved_backup_dir,
            timeout_seconds=float(lock_timeout_seconds),
            on_acquired=on_lock_acquired,
            on_contended=on_lock_contended,
        ):
            return _publish_verified_copy(
                database,
                resolved_backup_dir,
                destination_name=destination_name,
                retention=retention,
                replace_timeout_seconds=float(lock_timeout_seconds),
                on_replace_contended=on_replace_contended,
            )
    except BackupError:
        raise
    except (OSError, sqlite3.Error) as error:
        raise BackupError("could not create verified database backup") from error


def create_verified_backup(
    database_path: Path,
    backup_dir: Path,
    *,
    destination_name: str | None = None,
    retention: int | None = None,
    lock_timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
) -> Path:
    """Publish and prune a verified backup under one cross-process lock."""

    return _create_verified_backup(
        database_path,
        backup_dir,
        destination_name=destination_name,
        retention=retention,
        lock_timeout_seconds=lock_timeout_seconds,
    )
