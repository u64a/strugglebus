from __future__ import annotations

import errno
import hashlib
import importlib.machinery
import importlib.util
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path
from types import ModuleType

import pytest

from strugglebus.backup import _backup_directory_lock, create_verified_backup
from strugglebus.migrations import LATEST_SCHEMA_VERSION
from strugglebus.store import SQLiteStore

TEMPLATE = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "roles"
    / "systemd"
    / "templates"
    / "sqlite_backup.py.j2"
)
MAINTENANCE_ID = "0123456789abcdef" * 2


@pytest.fixture
def backup() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("maintenance_backup", str(TEMPLATE))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.fixture
def database(tmp_path: Path) -> Path:
    path = tmp_path / "source.db"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("CREATE TABLE sample(value TEXT)")
        connection.execute("INSERT INTO sample VALUES (?)", ("original",))
    return path


@pytest.fixture
def backup_dir(tmp_path: Path) -> Path:
    path = tmp_path / "backups"
    path.mkdir(mode=0o700)
    return path


def _arguments(
    database: Path,
    backup_dir: Path,
    *options: str,
    retention: int = 7,
) -> list[str]:
    return [
        str(TEMPLATE),
        str(database),
        str(backup_dir),
        str(retention),
        *options,
    ]


def _run(
    backup: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    database: Path,
    backup_dir: Path,
    *options: str,
    retention: int = 7,
) -> int:
    monkeypatch.setattr(
        sys, "argv", _arguments(database, backup_dir, *options, retention=retention)
    )
    return backup.main()


def _existing_daily_backups(database: Path, backup_dir: Path) -> dict[Path, bytes]:
    for index in range(9):
        shutil.copyfile(database, backup_dir / f"strugglebus-existing-{index}.db")
    return {path: path.read_bytes() for path in backup_dir.glob("strugglebus-*.db")}


def _assert_preserved(backups: dict[Path, bytes], backup_dir: Path) -> None:
    assert {path: path.read_bytes() for path in backup_dir.glob("strugglebus-*.db")} == backups
    assert not list(backup_dir.glob(".strugglebus-backup-*.db"))


def _symlink(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError) as error:
        if isinstance(error, OSError) and (
            error.errno not in {errno.EPERM, errno.EACCES}
            and getattr(error, "winerror", None) != 1314
        ):
            raise
        pytest.skip("symlink creation is unavailable for this account")


def test_maintenance_snapshot_restores_after_more_than_seven_daily_rotations(
    backup: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    backup_dir: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "application.db"
    assert SQLiteStore(database, backup_dir=backup_dir).initialize() == LATEST_SCHEMA_VERSION
    timestamp = "2026-09-05T00:00:00Z"
    verifier = "a" * 64
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute(
            "INSERT INTO agents(id, name, created_at) VALUES (?, ?, ?)",
            ("agent-1", "restore-agent", timestamp),
        )
        connection.execute(
            "INSERT INTO channels(id, name, created_at) VALUES (?, ?, ?)",
            ("channel-1", "restore-channel", timestamp),
        )
        connection.execute(
            "INSERT INTO messages(id, channel_id, agent_id, body, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            ("message-1", "channel-1", "agent-1", "pinned content", timestamp),
        )
        connection.execute(
            "UPDATE agent_access_state "
            "SET frozen = 1, transition = 'freeze', changed_at = ?, reason = ?",
            (timestamp, "local maintenance"),
        )
        connection.execute(
            "INSERT INTO agent_access_audit("
            "transition, changed_at, reason, actor_type, actor_id) "
            "VALUES ('freeze', ?, ?, 'local-admin', 'local-cli')",
            (timestamp, "local maintenance"),
        )
        connection.execute(
            "INSERT INTO agent_credentials("
            "id, agent_id, kind, secret_hash, status, creation_method, "
            "creation_reason, issuance_request_id, created_at, "
            "activated_at, identity_verified_at) "
            "VALUES (?, ?, 'sb1', ?, 'active', ?, ?, ?, ?, ?, ?)",
            (
                "credential-1", "agent-1", verifier, "test-fixture", "restore test",
                "request-1", timestamp, timestamp, timestamp,
            ),
        )
        expected_schema = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name"
        ).fetchall()

    migration_backup = create_verified_backup(
        database, backup_dir, destination_name="pre-migration-restore.db"
    )
    migration_bytes = migration_backup.read_bytes()
    result = subprocess.run(
        [sys.executable, *_arguments(
            database, backup_dir, "--maintenance-id", MAINTENANCE_ID
        )],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    pin = backup_dir / f"maintenance-{MAINTENANCE_ID}.db"
    assert result.stdout.strip() == str(pin)
    assert result.stderr == ""
    original_digest = hashlib.sha256(pin.read_bytes()).hexdigest()
    assert pin.stat().st_nlink == 1
    if os.name == "posix":
        assert stat.S_IMODE(pin.stat().st_mode) == 0o600

    for index in range(10):
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.execute("UPDATE messages SET body = ?", (f"daily-{index}",))
        assert _run(backup, monkeypatch, database, backup_dir) == 0
        daily = Path(capsys.readouterr().out.strip())
        assert daily.name.startswith("strugglebus-")
        assert len(list(backup_dir.glob("strugglebus-*.db"))) == min(index + 1, 7)
        assert hashlib.sha256(pin.read_bytes()).hexdigest() == original_digest
    assert migration_backup.read_bytes() == migration_bytes
    with closing(sqlite3.connect(daily)) as connection:
        assert connection.execute("SELECT body FROM messages").fetchone() == ("daily-9",)
        assert connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)]

    restored = tmp_path / "restored.db"
    shutil.copyfile(pin, restored)
    with closing(sqlite3.connect(restored)) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA user_version").fetchone() == (LATEST_SCHEMA_VERSION,)
        assert connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name"
        ).fetchall() == expected_schema
        assert connection.execute(
            "SELECT seq, id, body, agent_id, channel_id FROM messages"
        ).fetchall() == [(1, "message-1", "pinned content", "agent-1", "channel-1")]
        assert connection.execute(
            "SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?",
            ("pinned",),
        ).fetchall() == [(1,)]
        assert connection.execute("SELECT * FROM agent_access_state").fetchall() == [
            (1, 1, "freeze", timestamp, "local maintenance")
        ]
        assert connection.execute("SELECT * FROM agent_access_audit").fetchall() == [
            (
                1, "freeze", timestamp, "local maintenance",
                "local-admin", "local-cli",
            )
        ]
        assert connection.execute(
            "SELECT id, agent_id, kind, secret_hash, status FROM agent_credentials"
        ).fetchall() == [("credential-1", "agent-1", "sb1", verifier, "active")]


@pytest.mark.parametrize("retention", [1, 7])
def test_maintenance_creation_never_prunes_daily_backups(
    backup, monkeypatch, database, backup_dir, capsys, retention
) -> None:
    existing = _existing_daily_backups(database, backup_dir)
    assert _run(
        backup, monkeypatch, database, backup_dir,
        "--maintenance-id", MAINTENANCE_ID, retention=retention,
    ) == 0
    pin = backup_dir / f"maintenance-{MAINTENANCE_ID}.db"
    assert capsys.readouterr().out.strip() == str(pin)
    _assert_preserved(existing, backup_dir)
    assert pin.is_file()
    assert not list(backup_dir.glob(".cutover-backup-receipt-*"))


@pytest.mark.parametrize("option", ["--maintenance-id", "--verify-maintenance-id"])
@pytest.mark.parametrize(
    "identifier",
    ["", "a" * 31, "a" * 33, "A" * 32, "g" * 32, "../" + "a" * 29,
     "a" * 31 + "/", "a" * 31 + "\\", "a" * 32 + "\n", "a" * 31 + "\u00e9"],
)
def test_malformed_maintenance_ids_fail_without_side_effects(
    backup, monkeypatch, database, backup_dir, identifier, capsys, option
) -> None:
    with pytest.raises(SystemExit, match="exactly 32 lowercase hex"):
        _run(backup, monkeypatch, database, backup_dir, option, identifier)
    assert list(backup_dir.iterdir()) == []
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("option", ["--maintenance-id", "--verify-maintenance-id"])
def test_missing_and_duplicate_maintenance_id_are_rejected(
    backup, monkeypatch, database, backup_dir, option
) -> None:
    with pytest.raises(SystemExit, match="requires a value"):
        _run(backup, monkeypatch, database, backup_dir, option)
    with pytest.raises(SystemExit, match="only once"):
        _run(
            backup, monkeypatch, database, backup_dir,
            option, MAINTENANCE_ID, option, MAINTENANCE_ID,
        )
    assert list(backup_dir.iterdir()) == []


@pytest.mark.parametrize("option", ["--maintenance-id", "--verify-maintenance-id"])
@pytest.mark.parametrize(
    "receipt_args",
    [
        ("--operation-id", "a" * 32),
        ("--receipt-dir", "unused"),
        ("--operation-id", "a" * 32, "--receipt-dir", "unused"),
    ],
)
def test_maintenance_cannot_mix_with_cutover_receipt_arguments(
    backup, monkeypatch, database, backup_dir, receipt_args, option
) -> None:
    with pytest.raises(SystemExit, match="cannot be combined"):
        _run(
            backup, monkeypatch, database, backup_dir,
            option, MAINTENANCE_ID, *receipt_args,
        )
    assert list(backup_dir.iterdir()) == []


def test_existing_operation_snapshot_is_never_recreated(
    backup, monkeypatch, database, backup_dir, capsys
) -> None:
    existing = _existing_daily_backups(database, backup_dir)
    assert _run(
        backup, monkeypatch, database, backup_dir, "--maintenance-id", MAINTENANCE_ID
    ) == 0
    capsys.readouterr()
    destination = backup_dir / f"maintenance-{MAINTENANCE_ID}.db"
    original = destination.read_bytes()
    metadata = destination.stat()
    database.write_bytes(b"invalid source must not matter when a snapshot exists")
    with pytest.raises(RuntimeError, match="maintenance backup already exists"):
        _run(
            backup, monkeypatch, database, backup_dir,
            "--maintenance-id", MAINTENANCE_ID,
        )
    assert destination.read_bytes() == original
    assert destination.stat().st_ino == metadata.st_ino
    assert destination.stat().st_mtime_ns == metadata.st_mtime_ns
    assert capsys.readouterr().out == ""
    _assert_preserved(existing, backup_dir)


@pytest.mark.parametrize("kind", ["directory", "symlink", "dangling-symlink", "hardlink"])
def test_unsafe_existing_destination_is_not_followed_or_replaced(
    backup, monkeypatch, database, backup_dir, kind
) -> None:
    destination = backup_dir / f"maintenance-{MAINTENANCE_ID}.db"
    original = database.read_bytes()
    if kind == "directory":
        destination.mkdir()
    elif kind == "hardlink":
        os.link(database, destination)
    else:
        target = database if kind == "symlink" else database.with_name("absent.db")
        _symlink(destination, target)
    with pytest.raises(RuntimeError, match="maintenance backup already exists"):
        _run(
            backup, monkeypatch, database, backup_dir,
            "--maintenance-id", MAINTENANCE_ID,
        )
    assert os.path.lexists(destination)
    assert database.read_bytes() == original
    assert not list(backup_dir.glob(".strugglebus-backup-*.db"))


@pytest.mark.parametrize("option", ["--maintenance-id", "--verify-maintenance-id"])
@pytest.mark.parametrize("kind", ["relative", "file", "symlink", "parent-symlink", "reparse"])
def test_unsafe_backup_root_is_rejected(
    backup, monkeypatch, database, backup_dir, tmp_path, kind, option
) -> None:
    if kind == "relative":
        monkeypatch.chdir(tmp_path)
        root = Path("backups")
    elif kind == "file":
        root = database
    elif kind == "reparse":
        root = backup_dir
        monkeypatch.setattr(backup, "_is_reparse_point", lambda metadata: True)
    else:
        root = tmp_path / "linked"
        if kind == "parent-symlink":
            _symlink(root, tmp_path, directory=True)
            root /= "backups"
        else:
            _symlink(root, backup_dir, directory=True)
    with pytest.raises(SystemExit, match="backup directory path is unsafe"):
        _run(backup, monkeypatch, database, root, option, MAINTENANCE_ID)
    assert list(backup_dir.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX ownership and modes")
@pytest.mark.parametrize("unsafe", ["mode", "owner"])
def test_unprotected_backup_root_is_rejected(
    backup, monkeypatch, database, backup_dir, unsafe
) -> None:
    if unsafe == "mode":
        backup_dir.chmod(0o750)
    else:
        monkeypatch.setattr(backup.os, "geteuid", lambda: backup_dir.stat().st_uid + 1)
    with pytest.raises(SystemExit, match="backup directory permissions are unsafe"):
        _run(
            backup, monkeypatch, database, backup_dir,
            "--maintenance-id", MAINTENANCE_ID,
        )
    assert list(backup_dir.iterdir()) == []


@pytest.mark.parametrize("kind", ["symlink", "reparse"])
def test_unsafe_backup_lock_is_rejected(
    backup, monkeypatch, database, backup_dir, kind
) -> None:
    lock = backup_dir / backup.LOCK_NAME
    original = database.read_bytes()
    if kind == "symlink":
        _symlink(lock, database)
    else:
        lock.touch(mode=0o600)
        inode = lock.stat().st_ino
        monkeypatch.setattr(
            backup, "_is_reparse_point", lambda metadata: metadata.st_ino == inode
        )
    with pytest.raises(RuntimeError, match="backup lock"):
        _run(
            backup, monkeypatch, database, backup_dir,
            "--maintenance-id", MAINTENANCE_ID,
        )
    assert database.read_bytes() == original
    assert not list(backup_dir.glob("maintenance-*.db"))


@pytest.mark.parametrize("option", ["--maintenance-id", "--verify-maintenance-id"])
def test_maintenance_uses_existing_package_backup_lock(
    backup, monkeypatch, database, backup_dir, capsys, option
) -> None:
    monkeypatch.setattr(backup, "LOCK_TIMEOUT_SECONDS", 0.05)
    with _backup_directory_lock(backup_dir, timeout_seconds=1):
        with pytest.raises(RuntimeError, match="timed out waiting for the backup lock"):
            _run(
                backup, monkeypatch, database, backup_dir,
                option, MAINTENANCE_ID,
            )
    assert not list(backup_dir.glob("maintenance-*.db"))
    assert not list(backup_dir.glob(".strugglebus-backup-*.db"))
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("failure", ["backup", "integrity", "fsync", "link"])
def test_failure_before_publication_leaves_no_pin_and_does_not_prune(
    backup, monkeypatch, database, backup_dir, capsys, failure
) -> None:
    existing = _existing_daily_backups(database, backup_dir)
    connect = sqlite3.connect

    class FailingConnection(sqlite3.Connection):
        def backup(self, target, *args, **kwargs):
            if failure == "backup":
                raise sqlite3.OperationalError("injected backup failure")
            return super().backup(target, *args, **kwargs)

        def execute(self, sql, parameters=()):
            if failure == "integrity" and sql == "PRAGMA integrity_check":
                return super().execute("SELECT 'injected corruption'")
            return super().execute(sql, parameters)

    def fail(*args, **kwargs):
        raise OSError("injected publication failure")

    if failure in {"backup", "integrity"}:
        monkeypatch.setattr(
            backup.sqlite3, "connect",
            lambda *args, **kwargs: connect(*args, factory=FailingConnection, **kwargs),
        )
    elif failure == "fsync":
        monkeypatch.setattr(backup.os, "fsync", fail)
    else:
        monkeypatch.setattr(backup.os, "link", fail)
    expected_error = {
        "backup": sqlite3.OperationalError,
        "integrity": RuntimeError,
        "fsync": OSError,
        "link": OSError,
    }[failure]
    with pytest.raises(expected_error, match="injected|integrity check failed"):
        _run(
            backup, monkeypatch, database, backup_dir,
            "--maintenance-id", MAINTENANCE_ID,
        )
    assert not list(backup_dir.glob("maintenance-*.db"))
    assert capsys.readouterr().out == ""
    _assert_preserved(existing, backup_dir)


def test_atomic_publication_refuses_a_destination_created_after_preflight(
    backup, monkeypatch, database, backup_dir, capsys
) -> None:
    existing = _existing_daily_backups(database, backup_dir)
    link = os.link

    def competing_publication(source, destination):
        destination.write_bytes(b"competing operation snapshot")
        link(source, destination)

    monkeypatch.setattr(backup.os, "link", competing_publication)
    with pytest.raises(RuntimeError, match="maintenance backup already exists"):
        _run(
            backup, monkeypatch, database, backup_dir,
            "--maintenance-id", MAINTENANCE_ID,
        )
    assert (backup_dir / f"maintenance-{MAINTENANCE_ID}.db").read_bytes() == (
        b"competing operation snapshot"
    )
    assert capsys.readouterr().out == ""
    _assert_preserved(existing, backup_dir)


def test_snapshot_is_synced_before_link_and_directory_after_publication(
    backup, monkeypatch, database, backup_dir
) -> None:
    events = []
    fsync = os.fsync
    link = os.link
    sync_directory = backup._sync_directory
    destination = backup_dir / f"maintenance-{MAINTENANCE_ID}.db"

    def record_fsync(descriptor):
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            assert not destination.exists()
            events.append("file")
        return fsync(descriptor)

    def record_link(source, target):
        assert events == ["file"]
        with closing(sqlite3.connect(source)) as connection:
            assert connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        events.append("link")
        return link(source, target)

    def record_directory(path):
        assert destination.is_file()
        assert destination.stat().st_nlink == 1
        assert not list(backup_dir.glob(".strugglebus-backup-*.db"))
        events.append("directory")
        return sync_directory(path)

    monkeypatch.setattr(backup.os, "fsync", record_fsync)
    monkeypatch.setattr(backup.os, "link", record_link)
    monkeypatch.setattr(backup, "_sync_directory", record_directory)
    assert _run(
        backup, monkeypatch, database, backup_dir, "--maintenance-id", MAINTENANCE_ID
    ) == 0
    assert events == ["file", "link", "directory"]


def test_publish_before_result_failure_keeps_snapshot_and_retry_fails_explicitly(
    backup, monkeypatch, database, backup_dir, capsys
) -> None:
    existing = _existing_daily_backups(database, backup_dir)

    def fail(path):
        raise OSError("injected directory sync failure")

    monkeypatch.setattr(backup, "_sync_directory", fail)
    with pytest.raises(OSError, match="injected directory sync failure"):
        _run(
            backup, monkeypatch, database, backup_dir,
            "--maintenance-id", MAINTENANCE_ID,
        )
    pin = backup_dir / f"maintenance-{MAINTENANCE_ID}.db"
    original = pin.read_bytes()
    with closing(sqlite3.connect(pin)) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert connection.execute("SELECT value FROM sample").fetchone() == ("original",)
    with pytest.raises(RuntimeError, match="maintenance backup already exists"):
        _run(
            backup, monkeypatch, database, backup_dir,
            "--maintenance-id", MAINTENANCE_ID,
        )
    assert pin.read_bytes() == original
    assert capsys.readouterr().out == ""
    _assert_preserved(existing, backup_dir)


def _interrupted_publication(database: Path, backup_dir: Path) -> tuple[Path, Path]:
    pin = backup_dir / f"maintenance-{MAINTENANCE_ID}.db"
    shutil.copyfile(database, pin)
    pin.chmod(0o600)
    temporary = backup_dir / ".strugglebus-backup-abcdefgh.db"
    os.link(pin, temporary)
    return pin, temporary


def test_create_and_verify_modes_cannot_be_combined(
    backup, monkeypatch, database, backup_dir
) -> None:
    with pytest.raises(SystemExit, match="cannot be combined"):
        _run(
            backup, monkeypatch, database, backup_dir,
            "--maintenance-id", MAINTENANCE_ID,
            "--verify-maintenance-id", MAINTENANCE_ID,
        )
    assert list(backup_dir.iterdir()) == []


def test_verify_missing_snapshot_never_creates_it(
    backup, monkeypatch, database, backup_dir, capsys
) -> None:
    existing = _existing_daily_backups(database, backup_dir)
    with pytest.raises(FileNotFoundError):
        _run(
            backup, monkeypatch, database, backup_dir,
            "--verify-maintenance-id", MAINTENANCE_ID,
        )
    assert not list(backup_dir.glob("maintenance-*.db"))
    assert capsys.readouterr().out == ""
    _assert_preserved(existing, backup_dir)


def test_process_killed_after_link_is_reconciled_only_by_explicit_new_invocation(
    backup, database, backup_dir, tmp_path
) -> None:
    existing = _existing_daily_backups(database, backup_dir)
    marker = tmp_path / "publication-linked"
    code = """
import os
from pathlib import Path
import runpy
import sys
import time

marker = Path(sys.argv[1])
sys.argv = sys.argv[2:]
link = os.link
def pause_after_link(source, destination):
    link(source, destination)
    marker.write_text("linked", encoding="ascii")
    while True:
        time.sleep(0.05)
os.link = pause_after_link
runpy.run_path(sys.argv[0], run_name="__main__")
"""
    process = subprocess.Popen(
        [
            sys.executable, "-c", code, str(marker),
            *_arguments(database, backup_dir, "--maintenance-id", MAINTENANCE_ID),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10
        while not marker.exists():
            if process.poll() is not None:
                pytest.fail(f"publisher exited before linking: {process.communicate()[1]}")
            if time.monotonic() >= deadline:
                pytest.fail("publisher did not reach the post-link seam")
            time.sleep(0.01)
        process.kill()
        stdout, stderr = process.communicate(timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=10)
    assert process.returncode != 0
    assert stdout == stderr == ""
    pin = backup_dir / f"maintenance-{MAINTENANCE_ID}.db"
    staging = list(backup_dir.glob(".strugglebus-backup-*.db"))
    assert len(staging) == 1
    assert os.path.samefile(pin, staging[0])
    assert pin.stat().st_nlink == 2
    original = pin.read_bytes()
    inode = pin.stat().st_ino
    unrelated = backup_dir / ".strugglebus-backup-12345678.db"
    unrelated.write_bytes(b"unrelated interrupted backup")
    database.write_bytes(b"changed source must never be used to recreate the snapshot")

    retry_create = subprocess.run(
        [sys.executable, *_arguments(
            database, backup_dir, "--maintenance-id", MAINTENANCE_ID
        )],
        capture_output=True, text=True, check=False, timeout=10,
    )
    assert retry_create.returncode != 0
    assert retry_create.stdout == ""
    assert "maintenance backup already exists" in retry_create.stderr
    assert pin.stat().st_nlink == 2
    assert staging[0].is_file()

    for _ in range(2):
        verified = subprocess.run(
            [sys.executable, *_arguments(
                database, backup_dir, "--verify-maintenance-id", MAINTENANCE_ID
            )],
            capture_output=True, text=True, check=False, timeout=10,
        )
        assert verified.returncode == 0, verified.stderr
        assert verified.stdout.strip() == str(pin)
        assert verified.stderr == ""
        assert pin.read_bytes() == original
        assert pin.stat().st_ino == inode
        assert pin.stat().st_nlink == 1
        assert not staging[0].exists()
        assert unrelated.read_bytes() == b"unrelated interrupted backup"
    assert backup._sha256_regular_file(pin) == (
        hashlib.sha256(original).hexdigest(), len(original)
    )
    with closing(sqlite3.connect(pin)) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert connection.execute("SELECT value FROM sample").fetchone() == ("original",)
    assert {
        path: path.read_bytes() for path in backup_dir.glob("strugglebus-*.db")
    } == existing
    assert list(backup_dir.glob(".strugglebus-backup-*.db")) == [unrelated]


@pytest.mark.parametrize(
    "unsafe", ["foreign-link", "outside-link", "three-links", "staging-name", "staging-symlink"]
)
def test_verify_rejects_unrecognized_or_unsafe_links_without_unlinking(
    backup, monkeypatch, database, backup_dir, tmp_path, capsys, unsafe
) -> None:
    pin, temporary = _interrupted_publication(database, backup_dir)
    other = None
    if unsafe == "foreign-link":
        other = temporary.rename(backup_dir / "foreign.db")
    elif unsafe == "outside-link":
        other = temporary.rename(tmp_path / "outside.db")
    elif unsafe == "three-links":
        other = backup_dir / ".strugglebus-backup-ijklmnop.db"
        os.link(pin, other)
    elif unsafe == "staging-name":
        other = temporary.rename(backup_dir / ".strugglebus-backup-not-a-producer.db")
    else:
        other = temporary.rename(backup_dir / "foreign.db")
        _symlink(temporary, pin)
    original = pin.read_bytes()
    links = pin.stat().st_nlink
    with pytest.raises(RuntimeError, match="unsafe|unrecognized hard links"):
        _run(
            backup, monkeypatch, database, backup_dir,
            "--verify-maintenance-id", MAINTENANCE_ID,
        )
    assert capsys.readouterr().out == ""
    assert pin.read_bytes() == original
    assert pin.stat().st_nlink == links
    assert other.is_file()


@pytest.mark.parametrize("unsafe", ["empty", "corrupt", "directory", "symlink", "reparse"])
def test_verify_rejects_unsafe_snapshot_without_recreating_it(
    backup, monkeypatch, database, backup_dir, capsys, unsafe
) -> None:
    pin = backup_dir / f"maintenance-{MAINTENANCE_ID}.db"
    temporary = None
    if unsafe == "directory":
        pin.mkdir()
    elif unsafe == "symlink":
        _symlink(pin, database)
    else:
        pin, temporary = _interrupted_publication(database, backup_dir)
        if unsafe == "empty":
            pin.write_bytes(b"")
        elif unsafe == "corrupt":
            pin.write_bytes(b"corrupt database")
        else:
            inode = pin.stat().st_ino
            monkeypatch.setattr(
                backup, "_is_reparse_point", lambda metadata: metadata.st_ino == inode
            )
    with pytest.raises((RuntimeError, sqlite3.DatabaseError)):
        _run(
            backup, monkeypatch, database, backup_dir,
            "--verify-maintenance-id", MAINTENANCE_ID,
        )
    assert capsys.readouterr().out == ""
    assert os.path.lexists(pin)
    if temporary is not None:
        assert temporary.is_file()
        assert pin.stat().st_nlink == 2


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX ownership and modes")
@pytest.mark.parametrize("unsafe", ["mode", "owner"])
def test_verify_rejects_unprotected_snapshot(
    backup, monkeypatch, database, backup_dir, capsys, unsafe
) -> None:
    pin, temporary = _interrupted_publication(database, backup_dir)
    if unsafe == "mode":
        pin.chmod(0o640)
    else:
        monkeypatch.setattr(
            backup.os, "geteuid", lambda: pin.stat().st_uid + 1
        )
    with pytest.raises(RuntimeError, match="evidence is unsafe"):
        backup._verify_maintenance_backup(pin, database)
    assert pin.stat().st_nlink == 2
    assert temporary.exists()
    assert capsys.readouterr().out == ""


def test_verify_refuses_snapshot_alias_of_live_source(
    backup, monkeypatch, database, backup_dir, capsys
) -> None:
    database.chmod(0o600)
    pin = backup_dir / f"maintenance-{MAINTENANCE_ID}.db"
    os.link(database, pin)
    original = database.read_bytes()
    with pytest.raises(RuntimeError, match="must differ from the database"):
        _run(
            backup, monkeypatch, database, backup_dir,
            "--verify-maintenance-id", MAINTENANCE_ID,
        )
    assert database.read_bytes() == original
    assert pin.stat().st_nlink == 2
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("failure", ["integrity", "fsync"])
def test_verify_failure_before_reconciliation_retains_both_links(
    backup, monkeypatch, database, backup_dir, capsys, failure
) -> None:
    pin, temporary = _interrupted_publication(database, backup_dir)
    original = pin.read_bytes()
    if failure == "fsync":
        def fail(descriptor):
            raise OSError("injected verification sync failure")
        monkeypatch.setattr(backup.os, "fsync", fail)
    else:
        connect = sqlite3.connect

        class CorruptConnection(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if sql == "PRAGMA integrity_check":
                    return super().execute("SELECT 'injected corruption'")
                return super().execute(sql, parameters)

        monkeypatch.setattr(
            backup.sqlite3, "connect",
            lambda *args, **kwargs: connect(*args, factory=CorruptConnection, **kwargs),
        )
    with pytest.raises((RuntimeError, OSError), match="injected|integrity check failed"):
        _run(
            backup, monkeypatch, database, backup_dir,
            "--verify-maintenance-id", MAINTENANCE_ID,
        )
    assert capsys.readouterr().out == ""
    assert pin.read_bytes() == original
    assert pin.stat().st_nlink == 2
    assert os.path.samefile(pin, temporary)


def test_verify_does_not_unlink_a_staging_path_replaced_during_validation(
    backup, monkeypatch, database, backup_dir, capsys
) -> None:
    pin, temporary = _interrupted_publication(database, backup_dir)
    fsync = os.fsync
    metadata = backup._maintenance_file_metadata
    synced = False

    def record_sync(descriptor):
        nonlocal synced
        fsync(descriptor)
        synced = True

    def replace_after_sync(path, reference=None):
        nonlocal synced
        if synced:
            synced = False
            temporary.rename(backup_dir / "moved.db")
            temporary.write_bytes(b"unrelated replacement")
        return metadata(path, reference)

    monkeypatch.setattr(backup.os, "fsync", record_sync)
    monkeypatch.setattr(backup, "_maintenance_file_metadata", replace_after_sync)
    with pytest.raises(RuntimeError, match="evidence is unsafe or changed"):
        _run(
            backup, monkeypatch, database, backup_dir,
            "--verify-maintenance-id", MAINTENANCE_ID,
        )
    assert temporary.read_bytes() == b"unrelated replacement"
    assert pin.stat().st_nlink == 2
    assert capsys.readouterr().out == ""


def test_verify_syncs_before_unlink_and_retries_directory_sync_failure(
    backup, monkeypatch, database, backup_dir, capsys
) -> None:
    pin, temporary = _interrupted_publication(database, backup_dir)
    original = pin.read_bytes()
    fsync = os.fsync
    sync_directory = backup._sync_directory
    events = []

    def record_file_sync(descriptor):
        assert temporary.is_file()
        assert pin.stat().st_nlink == 2
        events.append("file")
        return fsync(descriptor)

    def fail_directory_sync(path):
        assert path == backup_dir
        assert not temporary.exists()
        assert pin.stat().st_nlink == 1
        events.append("directory")
        raise OSError("injected directory sync failure")

    monkeypatch.setattr(backup.os, "fsync", record_file_sync)
    monkeypatch.setattr(backup, "_sync_directory", fail_directory_sync)
    with pytest.raises(OSError, match="injected directory sync failure"):
        _run(
            backup, monkeypatch, database, backup_dir,
            "--verify-maintenance-id", MAINTENANCE_ID,
        )
    assert events == ["file", "directory"]
    assert capsys.readouterr().out == ""
    assert pin.read_bytes() == original
    monkeypatch.setattr(backup.os, "fsync", fsync)
    monkeypatch.setattr(backup, "_sync_directory", sync_directory)
    assert _run(
        backup, monkeypatch, database, backup_dir,
        "--verify-maintenance-id", MAINTENANCE_ID,
    ) == 0
    assert capsys.readouterr().out.strip() == str(pin)
    assert pin.read_bytes() == original
