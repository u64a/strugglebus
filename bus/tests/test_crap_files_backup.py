"""Failure paths of the backup and access-freeze lock/publish primitives."""

from __future__ import annotations

import errno
import os
import sqlite3
import stat
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest

import strugglebus.access as access
import strugglebus.backup as backup
from strugglebus.errors import BackupError, StorageError


class _OsProxy:
    """The real ``os`` module with a few attributes replaced for one module."""

    def __init__(self, **overrides: object) -> None:
        self._overrides = overrides

    def __getattr__(self, name: str) -> object:
        overrides = self.__dict__["_overrides"]
        if name in overrides:
            return overrides[name]
        return getattr(os, name)


class _Clock:
    """A monotonic clock that only advances when the code under test sleeps."""

    def __init__(self) -> None:
        self.now = 100.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _database(tmp_path: Path) -> Path:
    path = tmp_path.resolve() / "source.db"
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE sample (value TEXT)")
        connection.execute("INSERT INTO sample VALUES ('kept')")
        connection.commit()
    return path


def _private_directory(tmp_path: Path, name: str = "backups") -> Path:
    directory = tmp_path.resolve() / name
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return directory


# --- Request validation -------------------------------------------------------


@pytest.mark.parametrize("retention", [0, -1, True, 1.5, "7"])
def test_backup_rejects_retention_that_is_not_a_positive_integer(tmp_path, retention):
    with pytest.raises(BackupError, match="retention must be a positive integer"):
        backup.create_verified_backup(
            _database(tmp_path), tmp_path.resolve() / "backups", retention=retention,
        )
    assert not (tmp_path / "backups").exists()


@pytest.mark.parametrize("timeout", [0, -1, 300.5, True, "10", float("nan")])
def test_backup_rejects_lock_timeouts_outside_the_supported_window(tmp_path, timeout):
    with pytest.raises(BackupError, match="lock timeout must be between 0 and 300"):
        backup.create_verified_backup(
            _database(tmp_path),
            tmp_path.resolve() / "backups",
            lock_timeout_seconds=timeout,
        )
    assert not (tmp_path / "backups").exists()


def test_backup_rejects_relative_paths_and_destination_names_with_directories(tmp_path):
    database = _database(tmp_path)
    with pytest.raises(BackupError, match="must be absolute"):
        backup.create_verified_backup(Path("source.db"), tmp_path.resolve() / "backups")
    with pytest.raises(BackupError, match="must be absolute"):
        backup.create_verified_backup(database, Path("backups"))
    with pytest.raises(BackupError, match="must not contain a path"):
        backup.create_verified_backup(
            database, tmp_path.resolve() / "backups", destination_name="nested/copy.db",
        )
    assert not (tmp_path / "backups").exists()


def test_backup_reports_a_missing_database_without_creating_the_directory(tmp_path):
    with pytest.raises(BackupError, match="could not create verified database backup"):
        backup.create_verified_backup(
            tmp_path.resolve() / "absent.db", tmp_path.resolve() / "backups",
        )
    assert not (tmp_path / "backups").exists()


# --- Backup directory ---------------------------------------------------------


def test_backup_directory_is_created_private_and_returned_resolved(tmp_path):
    directory = tmp_path.resolve() / "nested" / "backups"

    assert backup._prepare_backup_directory(directory) == directory
    assert directory.is_dir()
    if os.name == "posix":
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700


def test_backup_directory_must_not_be_reached_through_a_symbolic_link(tmp_path):
    real = _private_directory(tmp_path, "real")
    link = tmp_path.resolve() / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are unavailable")

    with pytest.raises(BackupError, match="must not be a symbolic link"):
        backup._prepare_backup_directory(link)
    with pytest.raises(BackupError, match="must not contain symbolic links"):
        backup._prepare_backup_directory(link / "below")
    with pytest.raises(BackupError, match="must not be a symbolic link"):
        backup.create_verified_backup(_database(tmp_path), link)
    assert list(real.iterdir()) == [real / "below"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode contract")
def test_backup_directory_must_not_be_readable_by_other_accounts(tmp_path):
    directory = _private_directory(tmp_path)
    directory.chmod(0o750)

    with pytest.raises(BackupError, match="unsafe ownership or permissions"):
        backup.create_verified_backup(_database(tmp_path), directory)
    assert list(directory.iterdir()) == []


def test_backup_directory_owned_by_another_account_is_rejected(monkeypatch, tmp_path):
    directory = _private_directory(tmp_path)
    monkeypatch.setattr(backup, "os", _OsProxy(name="posix", geteuid=lambda: 424242))

    with pytest.raises(BackupError, match="unsafe ownership or permissions"):
        backup._prepare_backup_directory(directory)


# --- Lock file ----------------------------------------------------------------


def test_backup_lock_file_is_created_once_and_reopened(tmp_path):
    directory = _private_directory(tmp_path)

    first = backup._open_lock_file(directory)
    os.close(first)
    second = backup._open_lock_file(directory)
    os.close(second)

    lock = directory / backup.BACKUP_LOCK_NAME
    assert lock.read_bytes() == b""
    if os.name == "posix":
        assert stat.S_IMODE(lock.stat().st_mode) == 0o600


def test_backup_lock_that_cannot_be_opened_is_reported(tmp_path):
    directory = _private_directory(tmp_path)
    (directory / backup.BACKUP_LOCK_NAME).mkdir()

    with pytest.raises(BackupError, match="could not be opened safely") as raised:
        backup._open_lock_file(directory)
    assert isinstance(raised.value.__cause__, OSError)


@pytest.mark.skipif(os.name != "posix", reason="O_NOFOLLOW lock contract")
def test_backup_lock_refuses_a_symbolic_link(tmp_path):
    directory = _private_directory(tmp_path)
    target = tmp_path / "elsewhere"
    target.write_bytes(b"")
    target.chmod(0o600)
    (directory / backup.BACKUP_LOCK_NAME).symlink_to(target)

    with pytest.raises(BackupError, match="could not be opened safely"):
        backup._open_lock_file(directory)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode contract")
def test_existing_backup_lock_with_broad_permissions_is_rejected(tmp_path):
    directory = _private_directory(tmp_path)
    lock = directory / backup.BACKUP_LOCK_NAME
    lock.write_bytes(b"")
    lock.chmod(0o644)

    with pytest.raises(BackupError, match="lock file has unsafe ownership or permissions"):
        backup.create_verified_backup(_database(tmp_path), directory)
    assert sorted(path.name for path in directory.iterdir()) == [backup.BACKUP_LOCK_NAME]


def _track_close(module, monkeypatch, **overrides):
    closed: list[int] = []
    real_close = os.close

    def close(descriptor: int) -> None:
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(module, "os", _OsProxy(close=close, **overrides))
    return closed


def test_backup_lock_swapped_after_open_is_rejected_and_closed(monkeypatch, tmp_path):
    directory = _private_directory(tmp_path)
    real_lstat = os.lstat

    def other_file(path):
        metadata = real_lstat(path)
        return SimpleNamespace(
            st_mode=metadata.st_mode, st_dev=metadata.st_dev, st_ino=metadata.st_ino + 1,
        )

    closed = _track_close(backup, monkeypatch, lstat=other_file)

    with pytest.raises(BackupError, match="backup lock path is unsafe"):
        backup._open_lock_file(directory)
    assert len(closed) == 1


def test_backup_lock_owned_by_another_account_is_rejected_and_closed(
    monkeypatch, tmp_path,
):
    directory = _private_directory(tmp_path)
    os.close(backup._open_lock_file(directory))
    closed = _track_close(backup, monkeypatch, name="posix", geteuid=lambda: 424242)

    with pytest.raises(BackupError, match="lock file has unsafe ownership or permissions"):
        backup._open_lock_file(directory)
    assert len(closed) == 1


def test_new_backup_lock_is_restricted_without_an_ownership_check(monkeypatch):
    restricted = []
    monkeypatch.setattr(
        backup,
        "os",
        _OsProxy(
            name="posix",
            geteuid=lambda: 424242,
            fchmod=lambda descriptor, mode: restricted.append((descriptor, mode)),
        ),
    )
    foreign = SimpleNamespace(st_uid=1, st_mode=stat.S_IFREG | 0o666)

    backup._require_private_lock_file(11, foreign, created=True)

    assert restricted == [(11, 0o600)]


def test_existing_backup_lock_is_not_checked_for_ownership_off_posix(monkeypatch):
    monkeypatch.setattr(backup, "os", _OsProxy(name="nt"))
    foreign = SimpleNamespace(st_uid=1, st_mode=stat.S_IFREG | 0o666)

    backup._require_private_lock_file(11, foreign, created=False)


# --- Waiting for the lock -----------------------------------------------------


def test_waiting_for_the_backup_lock_reports_contention_until_acquired(monkeypatch):
    clock = _Clock()
    attempts = iter([False, False, True])
    contended = []
    monkeypatch.setattr(backup, "time", clock)
    monkeypatch.setattr(backup, "_try_acquire_lock", lambda descriptor: next(attempts))

    backup._wait_for_lock(5, deadline=clock.now + 10, on_contended=lambda: contended.append(1))

    assert contended == [1, 1]
    assert clock.sleeps == [backup.LOCK_POLL_SECONDS] * 2


def test_waiting_for_the_backup_lock_times_out_at_the_deadline(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(backup, "time", clock)
    monkeypatch.setattr(backup, "_try_acquire_lock", lambda descriptor: False)

    with pytest.raises(BackupError, match="timed out waiting for the backup lock"):
        backup._wait_for_lock(5, deadline=clock.now + 0.12, on_contended=None)

    assert clock.sleeps[:2] == [backup.LOCK_POLL_SECONDS] * 2
    assert sum(clock.sleeps) == pytest.approx(0.12)


def test_backup_lock_acquisition_errors_are_reported_and_the_file_closed(
    monkeypatch, tmp_path,
):
    directory = _private_directory(tmp_path)

    def fail(descriptor):
        raise OSError(errno.EIO, "synthetic lock fault")

    monkeypatch.setattr(backup, "_try_acquire_lock", fail)
    released = []
    monkeypatch.setattr(backup, "_release_lock", released.append)
    closed = _track_close(backup, monkeypatch)

    with pytest.raises(BackupError, match="backup lock could not be acquired"):
        with backup._backup_directory_lock(directory, timeout_seconds=1):
            pytest.fail("the lock body must not run")
    assert released == []
    assert len(closed) == 1


def test_backup_lock_release_errors_are_reported_and_the_file_closed(
    monkeypatch, tmp_path,
):
    directory = _private_directory(tmp_path)

    def fail(descriptor):
        raise OSError(errno.EIO, "synthetic unlock fault")

    monkeypatch.setattr(backup, "_release_lock", fail)
    closed = _track_close(backup, monkeypatch)
    acquired = []

    with pytest.raises(BackupError, match="backup lock could not be released"):
        with backup._backup_directory_lock(
            directory, timeout_seconds=1, on_acquired=lambda: acquired.append(True),
        ):
            pass
    assert acquired == [True]
    assert len(closed) == 1


def _fail_platform_lock(monkeypatch, error: OSError) -> None:
    def fail(*arguments):
        raise error

    if os.name == "nt":
        import msvcrt

        monkeypatch.setattr(msvcrt, "locking", fail)
    else:
        import fcntl

        monkeypatch.setattr(fcntl, "flock", fail)


def test_backup_lock_can_be_taken_and_released(tmp_path):
    descriptor = backup._open_lock_file(_private_directory(tmp_path))
    try:
        assert backup._try_acquire_lock(descriptor) is True
        backup._release_lock(descriptor)
        assert backup._try_acquire_lock(descriptor) is True
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("code", [errno.EACCES, errno.EAGAIN, errno.EDEADLK])
def test_backup_lock_held_elsewhere_is_contention_not_failure(
    monkeypatch, tmp_path, code,
):
    descriptor = backup._open_lock_file(_private_directory(tmp_path))
    try:
        _fail_platform_lock(monkeypatch, OSError(code, "held elsewhere"))
        assert backup._try_acquire_lock(descriptor) is False
    finally:
        os.close(descriptor)


def test_backup_lock_fault_is_not_mistaken_for_contention(monkeypatch, tmp_path):
    descriptor = backup._open_lock_file(_private_directory(tmp_path))
    try:
        _fail_platform_lock(monkeypatch, OSError(errno.EIO, "synthetic fault"))
        with pytest.raises(OSError) as raised:
            backup._try_acquire_lock(descriptor)
        assert raised.value.errno == errno.EIO
    finally:
        os.close(descriptor)


# --- Publishing ---------------------------------------------------------------


def test_stable_replace_does_not_retry_where_replacement_cannot_be_blocked(monkeypatch):
    attempts = []

    def deny(source, destination):
        attempts.append((source, destination))
        raise PermissionError("synthetic denial")

    contended = []
    monkeypatch.setattr(backup, "os", _OsProxy(replace=deny))

    with pytest.raises(PermissionError, match="synthetic denial"):
        backup._replace_stable_backup(
            Path("temporary"),
            Path("stable"),
            retry_while_in_use=False,
            timeout_seconds=5,
            on_contended=lambda: contended.append(1),
        )
    assert attempts == [(Path("temporary"), Path("stable"))]
    assert contended == []


def test_stable_replace_waits_for_a_reader_to_release_the_file(monkeypatch, tmp_path):
    clock = _Clock()
    temporary = tmp_path / "temporary.db"
    temporary.write_bytes(b"new")
    stable = tmp_path / "stable.db"
    stable.write_bytes(b"old")
    denials = iter([True, True, False])

    def replace(source, destination):
        if next(denials):
            raise PermissionError("in use")
        os.replace(source, destination)

    contended = []
    monkeypatch.setattr(backup, "os", _OsProxy(replace=replace))
    monkeypatch.setattr(backup, "time", clock)

    backup._replace_stable_backup(
        temporary,
        stable,
        retry_while_in_use=True,
        timeout_seconds=5,
        on_contended=lambda: contended.append(1),
    )

    assert stable.read_bytes() == b"new"
    assert not temporary.exists()
    assert contended == [1, 1]
    assert clock.sleeps == [backup.LOCK_POLL_SECONDS] * 2


def test_stable_replace_times_out_while_the_file_stays_in_use(monkeypatch):
    clock = _Clock()

    def deny(source, destination):
        raise PermissionError("in use")

    monkeypatch.setattr(backup, "os", _OsProxy(replace=deny))
    monkeypatch.setattr(backup, "time", clock)

    with pytest.raises(BackupError, match="timed out publishing stable backup") as raised:
        backup._replace_stable_backup(
            Path("temporary"),
            Path("stable"),
            retry_while_in_use=True,
            timeout_seconds=0.1,
            on_contended=None,
        )
    assert isinstance(raised.value.__cause__, PermissionError)
    assert sum(clock.sleeps) == pytest.approx(0.1)


def test_publish_retries_only_on_windows(monkeypatch, tmp_path):
    seen = []

    def record(temporary, destination, **options):
        seen.append(options["retry_while_in_use"])

    monkeypatch.setattr(backup, "_replace_stable_backup", record)
    arguments = (tmp_path / "temporary", tmp_path, None, 1, tmp_path / "source.db", 1.0, None)

    monkeypatch.setattr(backup, "os", _OsProxy(name="nt"))
    assert backup._publish_backup(*arguments) == tmp_path / "strugglebus-latest.db"
    monkeypatch.setattr(backup, "os", _OsProxy(name="posix"))
    assert backup._publish_backup(*arguments) == tmp_path / "strugglebus-latest.db"

    assert seen == [True, False]


def test_stable_backup_destination_must_not_be_the_database(tmp_path):
    directory = _private_directory(tmp_path)
    database = directory / "strugglebus-latest.db"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("CREATE TABLE sample (value TEXT)")
        connection.execute("INSERT INTO sample VALUES ('kept')")
        connection.commit()

    with pytest.raises(BackupError, match="must differ from the database"):
        backup.create_verified_backup(database, directory, retention=1)

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT value FROM sample").fetchone() == ("kept",)
    assert sorted(path.name for path in directory.iterdir()) == [
        backup.BACKUP_LOCK_NAME, "strugglebus-latest.db",
    ]


def test_named_backup_never_overwrites_an_existing_destination(tmp_path):
    directory = _private_directory(tmp_path)
    database = _database(tmp_path)
    existing = directory / "named.backup"
    existing.write_bytes(b"earlier")

    with pytest.raises(BackupError, match="destination already exists"):
        backup.create_verified_backup(database, directory, destination_name="named.backup")

    assert existing.read_bytes() == b"earlier"
    assert sorted(path.name for path in directory.iterdir()) == [
        backup.BACKUP_LOCK_NAME, "named.backup",
    ]


def test_named_backup_losing_a_creation_race_is_rejected(monkeypatch, tmp_path):
    directory = _private_directory(tmp_path)
    temporary = directory / "temporary.db"
    temporary.write_bytes(b"copy")

    def lose_race(source, destination):
        raise FileExistsError(errno.EEXIST, "synthetic race")

    monkeypatch.setattr(backup, "os", _OsProxy(link=lose_race))

    with pytest.raises(BackupError, match="destination already exists") as raised:
        backup._link_new_backup(temporary, directory, "named.backup")
    assert isinstance(raised.value.__cause__, FileExistsError)
    assert temporary.exists()


def test_timestamped_backup_picks_another_name_after_losing_a_race(
    monkeypatch, tmp_path,
):
    directory = _private_directory(tmp_path)
    temporary = directory / "temporary.db"
    temporary.write_bytes(b"copy")
    attempts = []

    def link(source, destination):
        attempts.append(Path(destination))
        if len(attempts) == 1:
            Path(destination).write_bytes(b"winner")
            raise FileExistsError(errno.EEXIST, "synthetic race")
        os.link(source, destination)

    monkeypatch.setattr(backup, "os", _OsProxy(link=link))

    published = backup._link_new_backup(temporary, directory, None)

    assert len(attempts) == 2
    assert published == attempts[1] != attempts[0]
    assert attempts[0].read_bytes() == b"winner"
    assert published.read_bytes() == b"copy"
    assert not temporary.exists()


def test_backup_that_fails_integrity_verification_is_not_published(
    monkeypatch, tmp_path,
):
    directory = _private_directory(tmp_path)
    database = _database(tmp_path)

    class _Corrupt:
        def __init__(self, connection):
            self._connection = connection

        def backup(self, target):
            self._connection.backup(target._connection)

        def execute(self, statement):
            assert statement == "PRAGMA integrity_check"
            return SimpleNamespace(fetchone=lambda: ("row 3 missing from index",))

        def close(self):
            self._connection.close()

    real_connect = sqlite3.connect
    monkeypatch.setattr(
        backup,
        "sqlite3",
        SimpleNamespace(
            connect=lambda *args, **kwargs: _Corrupt(real_connect(*args, **kwargs)),
            Error=sqlite3.Error,
        ),
    )

    with pytest.raises(BackupError, match="backup failed integrity verification"):
        backup.create_verified_backup(database, directory)

    assert sorted(path.name for path in directory.iterdir()) == [backup.BACKUP_LOCK_NAME]


def test_backup_of_a_file_that_is_not_a_database_is_reported(tmp_path):
    directory = _private_directory(tmp_path)
    database = tmp_path.resolve() / "not-a-database.db"
    database.write_bytes(b"this is not an SQLite file" * 64)

    with pytest.raises(BackupError, match="could not create verified database backup") as raised:
        backup.create_verified_backup(database, directory)
    assert isinstance(raised.value.__cause__, sqlite3.Error)
    assert sorted(path.name for path in directory.iterdir()) == [backup.BACKUP_LOCK_NAME]


def test_pruning_keeps_the_newest_backups_and_never_the_database_or_links(tmp_path):
    directory = _private_directory(tmp_path)
    database = directory / "strugglebus-live.db"
    database.write_bytes(b"live")
    names = ["strugglebus-1.db", "strugglebus-2.db", "strugglebus-3.db"]
    for index, name in enumerate(names):
        path = directory / name
        path.write_bytes(b"copy")
        os.utime(path, ns=(index * 10**9, index * 10**9))
    (directory / "strugglebus-folder.db").mkdir()
    (directory / "unrelated.txt").write_bytes(b"other")
    newest = directory / "strugglebus-9.db"
    newest.write_bytes(b"new")

    backup._prune_backups(directory, database, newest, 2)

    assert sorted(path.name for path in directory.iterdir()) == [
        "strugglebus-3.db", "strugglebus-9.db", "strugglebus-folder.db",
        "strugglebus-live.db", "unrelated.txt",
    ]


# --- Access-freeze lock -------------------------------------------------------


def _freeze_directory(tmp_path: Path) -> Path:
    directory = tmp_path.resolve() / access.ACCESS_FREEZE_LOCK_DIRECTORY
    access._prepare_lock_directory(directory)
    return directory


def test_access_freeze_lock_directory_is_created_private(tmp_path):
    directory = _freeze_directory(tmp_path)

    assert directory.is_dir()
    if os.name == "posix":
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    access._prepare_lock_directory(directory)


def test_access_freeze_lock_directory_must_be_a_real_directory(tmp_path):
    blocker = tmp_path.resolve() / "not-a-directory"
    blocker.write_bytes(b"")

    with pytest.raises(StorageError, match="lock directory is unavailable"):
        access._prepare_lock_directory(blocker)
    with pytest.raises(StorageError, match="lock directory is unavailable"):
        access._prepare_lock_directory(tmp_path.resolve() / "missing" / "child")


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode contract")
def test_access_freeze_lock_directory_with_broad_permissions_is_rejected(tmp_path):
    directory = _freeze_directory(tmp_path)
    directory.chmod(0o750)

    with pytest.raises(StorageError, match="lock directory is unsafe"):
        with access.access_freeze_transition_lock(directory):
            pytest.fail("the lock body must not run")
    assert list(directory.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="symlinked directory contract")
def test_access_freeze_lock_directory_must_not_be_a_symbolic_link(tmp_path):
    real = tmp_path.resolve() / "real"
    real.mkdir(mode=0o700)
    link = tmp_path.resolve() / "link"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(StorageError, match="lock directory is unsafe"):
        access._prepare_lock_directory(link)


def test_access_freeze_lock_file_is_created_once_and_reopened(tmp_path):
    directory = _freeze_directory(tmp_path)

    os.close(access._open_lock_file(directory))
    os.close(access._open_lock_file(directory))

    lock = directory / access.ACCESS_FREEZE_LOCK_NAME
    assert lock.read_bytes() == b""
    if os.name == "posix":
        assert stat.S_IMODE(lock.stat().st_mode) == 0o600


def test_access_freeze_lock_that_cannot_be_opened_is_reported(tmp_path):
    directory = _freeze_directory(tmp_path)
    (directory / access.ACCESS_FREEZE_LOCK_NAME).mkdir()

    with pytest.raises(StorageError, match="could not be opened safely") as raised:
        access._open_lock_file(directory)
    assert isinstance(raised.value.__cause__, OSError)


def test_access_freeze_lock_with_a_second_name_is_rejected_and_closed(
    monkeypatch, tmp_path,
):
    directory = _freeze_directory(tmp_path)
    os.close(access._open_lock_file(directory))
    lock = directory / access.ACCESS_FREEZE_LOCK_NAME
    os.link(lock, directory / "second-name")
    closed = _track_close(access, monkeypatch)

    with pytest.raises(StorageError, match="lock path is unsafe"):
        access._open_lock_file(directory)
    assert len(closed) == 1


def test_access_freeze_lock_swapped_after_open_is_rejected_and_closed(
    monkeypatch, tmp_path,
):
    directory = _freeze_directory(tmp_path)
    real_lstat = os.lstat

    def other_file(path):
        metadata = real_lstat(path)
        return SimpleNamespace(
            st_mode=metadata.st_mode, st_dev=metadata.st_dev + 1, st_ino=metadata.st_ino,
        )

    closed = _track_close(access, monkeypatch, lstat=other_file)

    with pytest.raises(StorageError, match="lock path is unsafe"):
        access._open_lock_file(directory)
    assert len(closed) == 1


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode contract")
def test_existing_access_freeze_lock_with_broad_permissions_is_rejected(tmp_path):
    directory = _freeze_directory(tmp_path)
    lock = directory / access.ACCESS_FREEZE_LOCK_NAME
    lock.write_bytes(b"")
    lock.chmod(0o640)

    with pytest.raises(StorageError, match="lock file is unsafe"):
        with access.access_freeze_transition_lock(directory):
            pytest.fail("the lock body must not run")


def test_access_freeze_lock_owned_by_another_account_is_rejected_and_closed(
    monkeypatch, tmp_path,
):
    directory = _freeze_directory(tmp_path)
    os.close(access._open_lock_file(directory))
    closed = _track_close(access, monkeypatch, name="posix", geteuid=lambda: 424242)

    with pytest.raises(StorageError, match="lock file is unsafe"):
        access._open_lock_file(directory)
    assert len(closed) == 1


def test_new_access_freeze_lock_without_fchmod_falls_back_to_the_ownership_check(
    monkeypatch,
):
    class _NoFchmod(_OsProxy):
        def __getattr__(self, name):
            if name == "fchmod":
                raise AttributeError(name)
            return super().__getattr__(name)

    monkeypatch.setattr(access, "os", _NoFchmod(name="posix", geteuid=lambda: 1000))

    access._require_private_lock_file(
        11, SimpleNamespace(st_uid=1000, st_mode=stat.S_IFREG | 0o600), created=True,
    )
    with pytest.raises(StorageError, match="lock file is unsafe"):
        access._require_private_lock_file(
            11, SimpleNamespace(st_uid=1000, st_mode=stat.S_IFREG | 0o644), created=True,
        )


def test_access_freeze_lock_times_out_while_another_holder_keeps_it(
    monkeypatch, tmp_path,
):
    directory = _freeze_directory(tmp_path)
    clock = _Clock()
    monkeypatch.setattr(access, "time", clock)
    monkeypatch.setattr(access, "_try_lock", lambda descriptor: False)
    unlocked = []
    monkeypatch.setattr(access, "_unlock", unlocked.append)
    closed = _track_close(access, monkeypatch)

    with pytest.raises(StorageError, match="timed out waiting for the access-freeze lock"):
        with access.access_freeze_transition_lock(directory):
            pytest.fail("the lock body must not run")

    assert sum(clock.sleeps) == pytest.approx(access.ACCESS_FREEZE_LOCK_TIMEOUT_SECONDS)
    assert unlocked == []
    assert len(closed) == 1


def test_access_freeze_lock_acquire_and_release_faults_are_reported(
    monkeypatch, tmp_path,
):
    directory = _freeze_directory(tmp_path)

    def fail(descriptor):
        raise OSError(errno.EIO, "synthetic lock fault")

    with monkeypatch.context() as patch:
        patch.setattr(access, "_try_lock", fail)
        with pytest.raises(StorageError, match="lock could not be acquired"):
            with access.access_freeze_transition_lock(directory):
                pytest.fail("the lock body must not run")

    entered = []
    with monkeypatch.context() as patch:
        patch.setattr(access, "_unlock", fail)
        with pytest.raises(StorageError, match="lock could not be released"):
            with access.access_freeze_transition_lock(directory):
                entered.append(True)
    assert entered == [True]

    with access.access_freeze_transition_lock(directory):
        entered.append(True)
    assert entered == [True, True]


def test_access_freeze_lock_can_be_taken_and_released(tmp_path):
    descriptor = access._open_lock_file(_freeze_directory(tmp_path))
    try:
        assert access._try_lock(descriptor) is True
        access._unlock(descriptor)
        assert access._try_lock(descriptor) is True
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("code", [errno.EACCES, errno.EAGAIN, errno.EDEADLK])
def test_access_freeze_lock_held_elsewhere_is_contention_not_failure(
    monkeypatch, tmp_path, code,
):
    descriptor = access._open_lock_file(_freeze_directory(tmp_path))
    try:
        _fail_platform_lock(monkeypatch, OSError(code, "held elsewhere"))
        assert access._try_lock(descriptor) is False
    finally:
        os.close(descriptor)


def test_access_freeze_lock_fault_is_not_mistaken_for_contention(monkeypatch, tmp_path):
    descriptor = access._open_lock_file(_freeze_directory(tmp_path))
    try:
        _fail_platform_lock(monkeypatch, OSError(errno.EIO, "synthetic fault"))
        with pytest.raises(OSError) as raised:
            access._try_lock(descriptor)
        assert raised.value.errno == errno.EIO
    finally:
        os.close(descriptor)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (7, "must be text"),
        ("   ", "must not be empty"),
        ("bad\x00reason", "must not contain NUL"),
        ("x" * 257, "must not exceed 256 characters"),
    ],
    ids=["not-text", "blank", "nul", "too-many-characters"],
)
def test_access_freeze_reason_bounds(value, message):
    with pytest.raises(access.DomainValidationError, match=message):
        access.normalize_access_freeze_reason(value)


def test_access_freeze_reason_is_trimmed_and_accepts_the_limits():
    assert access.normalize_access_freeze_reason("  key leaked  ") == "key leaked"
    assert access.normalize_access_freeze_reason("x" * 256) == "x" * 256
    assert access.normalize_access_freeze_reason("é" * 256) == "é" * 256
