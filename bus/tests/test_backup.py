from __future__ import annotations

import multiprocessing
import os
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path
from queue import Empty

import pytest

from strugglebus.backup import (
    BACKUP_LOCK_NAME,
    _backup_directory_lock,
    _create_verified_backup,
    create_verified_backup,
)
from strugglebus.errors import BackupError


def _backup_worker(
    database: str,
    backup_dir: str,
    retention: int,
    results: multiprocessing.queues.Queue,
    acquired: multiprocessing.synchronize.Event | None,
    release: multiprocessing.synchronize.Event | None,
    contended: multiprocessing.synchronize.Event | None,
    verify_result: bool,
) -> None:
    def on_acquired() -> None:
        if acquired is None or release is None:
            return
        acquired.set()
        if not release.wait(timeout=10):
            raise RuntimeError("test did not release held backup lock")

    def on_contended() -> None:
        if contended is not None:
            contended.set()

    try:
        path = _create_verified_backup(
            Path(database),
            Path(backup_dir),
            retention=retention,
            on_lock_acquired=on_acquired,
            on_lock_contended=on_contended,
        )
        if verify_result:
            with sqlite3.connect(path) as connection:
                integrity = connection.execute("PRAGMA integrity_check").fetchone()
                value = connection.execute("SELECT value FROM sample").fetchone()
            results.put(("ok", str(path), path.exists(), integrity, value))
        else:
            results.put(("ok", str(path)))
    except Exception as error:
        results.put(("error", type(error).__name__, str(error)))


def _lock_holder(
    backup_dir: str,
    acquired: multiprocessing.synchronize.Event,
    release: multiprocessing.synchronize.Event,
) -> None:
    with _backup_directory_lock(Path(backup_dir), timeout_seconds=5):
        acquired.set()
        release.wait(timeout=10)


def _stable_replace_worker(
    database: str,
    backup_dir: str,
    results: multiprocessing.queues.Queue,
    contended: multiprocessing.synchronize.Event,
) -> None:
    try:
        path = _create_verified_backup(
            Path(database),
            Path(backup_dir),
            retention=1,
            on_replace_contended=contended.set,
        )
        results.put(("ok", str(path)))
    except Exception as error:
        results.put(("error", type(error).__name__, str(error)))


def _source_database(tmp_path: Path) -> Path:
    database = tmp_path / "source.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE sample(value TEXT, padding BLOB)")
        connection.execute(
            "INSERT INTO sample VALUES ('safe', zeroblob(8388608))"
        )
    return database


def _run_contended_backups(
    database: Path,
    backup_dir: Path,
    *,
    retention: int,
    verify_results: bool,
    callers: int = 2,
) -> tuple[tuple[object, ...], ...]:
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    acquired = context.Event()
    release = context.Event()
    holder = context.Process(
        target=_backup_worker,
        args=(
            str(database),
            str(backup_dir),
            retention,
            results,
            acquired,
            release,
            None,
            verify_results,
        ),
    )
    contended_events = [context.Event() for _ in range(callers - 1)]
    waiters = tuple(
        context.Process(
            target=_backup_worker,
            args=(
                str(database),
                str(backup_dir),
                retention,
                results,
                None,
                None,
                contended,
                verify_results,
            ),
        )
        for contended in contended_events
    )
    processes = (holder, *waiters)
    started = []
    holder.start()
    started.append(holder)
    try:
        assert acquired.wait(timeout=10)
        for waiter in waiters:
            waiter.start()
            started.append(waiter)
        assert all(contended.wait(timeout=10) for contended in contended_events)
        release.set()
        outcomes = tuple(results.get(timeout=20) for _ in processes)
    except Empty:
        pytest.fail("concurrent backup worker timed out")
    finally:
        release.set()
        for process in started:
            process.join(timeout=10)
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
    assert all(process.exitcode == 0 for process in processes)
    return outcomes


def test_concurrent_backups_return_distinct_existing_verified_files(
    tmp_path: Path,
) -> None:
    database = _source_database(tmp_path)
    backup_dir = tmp_path / "backups"

    outcomes = _run_contended_backups(
        database,
        backup_dir,
        retention=2,
        verify_results=True,
    )

    assert all(outcome[0] == "ok" for outcome in outcomes)
    paths = {Path(str(outcome[1])) for outcome in outcomes}
    assert len(paths) == 2
    assert all(outcome[2:] == (True, ("ok",), ("safe",)) for outcome in outcomes)
    assert all(path.is_file() for path in paths)
    assert set(backup_dir.glob("strugglebus-*.db")) == paths


def test_lock_file_does_not_require_initialization_data(tmp_path: Path) -> None:
    database = _source_database(tmp_path)
    backup_dir = tmp_path / "backups"

    create_verified_backup(database, backup_dir, retention=1)

    assert (backup_dir / BACKUP_LOCK_NAME).read_bytes() == b""


def test_concurrent_retention_one_always_leaves_one_verified_backup(
    tmp_path: Path,
) -> None:
    database = _source_database(tmp_path)
    backup_dir = tmp_path / "backups"

    outcomes = _run_contended_backups(
        database,
        backup_dir,
        retention=1,
        verify_results=True,
        callers=3,
    )

    assert all(outcome[0] == "ok" for outcome in outcomes)
    assert all(outcome[2:] == (True, ("ok",), ("safe",)) for outcome in outcomes)
    returned = [Path(str(outcome[1])) for outcome in outcomes]
    assert len(set(returned)) == 1
    assert all(path.is_file() for path in returned)
    backups = list(backup_dir.glob("strugglebus-*.db"))
    assert backups == [returned[0]]
    with sqlite3.connect(backups[0]) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("SELECT value FROM sample").fetchone() == ("safe",)


def test_sequential_retention_one_atomically_updates_stable_path(
    tmp_path: Path,
) -> None:
    database = _source_database(tmp_path)
    backup_dir = tmp_path / "backups"

    first = create_verified_backup(database, backup_dir, retention=1)
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE sample SET value = 'new'")
    second = create_verified_backup(database, backup_dir, retention=1)

    assert second == first
    assert second.name == "strugglebus-latest.db"
    assert second.is_file()
    with sqlite3.connect(second) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("SELECT value FROM sample").fetchone() == ("new",)


def test_increasing_retention_ages_out_stable_slot(tmp_path: Path) -> None:
    database = _source_database(tmp_path)
    backup_dir = tmp_path / "backups"
    stable = create_verified_backup(database, backup_dir, retention=1)

    first = create_verified_backup(database, backup_dir, retention=2)
    second = create_verified_backup(database, backup_dir, retention=2)

    assert set(backup_dir.glob("strugglebus-*.db")) == {first, second}
    assert not stable.exists()


def test_failed_retention_one_update_preserves_previous_backup(
    tmp_path: Path,
) -> None:
    database = _source_database(tmp_path)
    backup_dir = tmp_path / "backups"
    stable = create_verified_backup(database, backup_dir, retention=1)
    database.write_bytes(b"not a sqlite database")

    with pytest.raises(BackupError, match="could not create verified"):
        create_verified_backup(database, backup_dir, retention=1)

    assert stable.is_file()
    with sqlite3.connect(stable) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("SELECT value FROM sample").fetchone() == ("safe",)


@pytest.mark.skipif(os.name != "nt", reason="requires Windows sharing semantics")
def test_retention_one_waits_for_reader_before_atomic_replace(
    tmp_path: Path,
) -> None:
    database = _source_database(tmp_path)
    backup_dir = tmp_path / "backups"
    stable = create_verified_backup(database, backup_dir, retention=1)
    reader = sqlite3.connect(stable)
    assert reader.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    contended = context.Event()
    worker = context.Process(
        target=_stable_replace_worker,
        args=(str(database), str(backup_dir), results, contended),
    )
    worker.start()
    try:
        assert contended.wait(timeout=10)
    finally:
        reader.close()
    outcome = results.get(timeout=20)
    worker.join(timeout=10)
    if worker.is_alive():
        worker.terminate()
        worker.join(timeout=5)

    assert worker.exitcode == 0
    assert outcome == ("ok", str(stable))
    assert stable.is_file()
    with closing(sqlite3.connect(stable)) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)


def test_retention_one_refuses_to_replace_live_database(tmp_path: Path) -> None:
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(mode=0o700)
    database = backup_dir / "strugglebus-latest.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE sample(value TEXT)")
        connection.execute("INSERT INTO sample VALUES ('live')")

    with pytest.raises(BackupError, match="destination must differ"):
        create_verified_backup(database, backup_dir, retention=1)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("SELECT value FROM sample").fetchone() == ("live",)


def test_backup_lock_timeout_fails_explicitly(tmp_path: Path) -> None:
    database = _source_database(tmp_path)
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(mode=0o700)
    context = multiprocessing.get_context("spawn")
    acquired = context.Event()
    release = context.Event()
    holder = context.Process(
        target=_lock_holder,
        args=(str(backup_dir), acquired, release),
    )
    holder.start()
    assert acquired.wait(timeout=10)
    try:
        with pytest.raises(BackupError, match="timed out waiting"):
            create_verified_backup(
                database,
                backup_dir,
                retention=1,
                lock_timeout_seconds=0.1,
            )
    finally:
        release.set()
        holder.join(timeout=10)
        if holder.is_alive():
            holder.terminate()
            holder.join(timeout=5)
    assert holder.exitcode == 0


def test_deployed_helper_uses_the_package_lock_protocol(tmp_path: Path) -> None:
    database = _source_database(tmp_path)
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(mode=0o700)
    template = (
        Path(__file__).parents[1]
        / "deploy"
        / "roles"
        / "systemd"
        / "templates"
        / "sqlite_backup.py.j2"
    )
    helper = tmp_path / "sqlite_backup.py"
    helper.write_text(
        template.read_text(encoding="utf-8").replace(
            "LOCK_TIMEOUT_SECONDS = 10.0",
            "LOCK_TIMEOUT_SECONDS = 0.2",
        ),
        encoding="utf-8",
    )
    context = multiprocessing.get_context("spawn")
    acquired = context.Event()
    release = context.Event()
    holder = context.Process(
        target=_lock_holder,
        args=(str(backup_dir), acquired, release),
    )
    holder.start()
    assert acquired.wait(timeout=10)
    try:
        blocked = subprocess.run(
            [
                sys.executable,
                str(helper),
                str(database),
                str(backup_dir),
                "2",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert blocked.returncode != 0
        assert "timed out waiting for the backup lock" in blocked.stderr
    finally:
        release.set()
        holder.join(timeout=10)
        if holder.is_alive():
            holder.terminate()
            holder.join(timeout=5)
    assert holder.exitcode == 0

    completed = subprocess.run(
        [
            sys.executable,
            str(helper),
            str(database),
            str(backup_dir),
            "2",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    backup = Path(completed.stdout.strip())
    assert backup.is_file()
    with closing(sqlite3.connect(backup)) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)

    first_latest = subprocess.run(
        [
            sys.executable,
            str(helper),
            str(database),
            str(backup_dir),
            "1",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert first_latest.returncode == 0, first_latest.stderr
    second_latest = subprocess.run(
        [
            sys.executable,
            str(helper),
            str(database),
            str(backup_dir),
            "1",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert first_latest.stdout.strip() == second_latest.stdout.strip()
    assert Path(second_latest.stdout.strip()).name == "strugglebus-latest.db"
    assert list(backup_dir.glob("strugglebus-*.db")) == [
        Path(second_latest.stdout.strip())
    ]


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX symlink semantics")
def test_backup_rejects_symlink_lock_path(tmp_path: Path) -> None:
    database = _source_database(tmp_path)
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(mode=0o700)
    (backup_dir / BACKUP_LOCK_NAME).symlink_to(tmp_path / "elsewhere")

    with pytest.raises(BackupError, match="lock file could not be opened safely"):
        create_verified_backup(database, backup_dir, retention=1)
