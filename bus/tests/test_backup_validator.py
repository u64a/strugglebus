from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace

import pytest


if sys.platform != "linux":
    pytest.skip(
        "the production validator enforces Linux ownership and mode semantics",
        allow_module_level=True,
    )

import pwd


REPOSITORY = Path(__file__).resolve().parents[1]
HELPER = (
    REPOSITORY
    / "deploy/roles/guest_base/files/strugglebus-validate-backup.py"
)
SPEC = importlib.util.spec_from_file_location("backup_validator", HELPER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the backup validator")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
BackupValidationError = MODULE.BackupValidationError
validate_backup = MODULE.validate_backup


def service_user() -> str:
    return pwd.getpwuid(os.geteuid()).pw_name


def create_backup(root: Path, name: str = "strugglebus-test.db") -> Path:
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    backup = root / name
    backup.write_bytes(b"SQLite format 3\x00")
    backup.chmod(0o600)
    return backup


def create_valid_database(root: Path, name: str = "strugglebus-test.db") -> Path:
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    backup = root / name
    with sqlite3.connect(backup) as database:
        database.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY)")
        database.execute("INSERT INTO messages DEFAULT VALUES")
    backup.chmod(0o600)
    return backup


def test_valid_protected_backup_is_canonicalized(tmp_path: Path) -> None:
    root = tmp_path / "backups"
    backup = create_backup(root)
    assert validate_backup(root, backup, service_user()) == {"backup": str(backup)}


def test_integrity_check_accepts_valid_database_without_mutation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "backups"
    backup = create_valid_database(root)
    before = backup.read_bytes()

    result = validate_backup(
        root,
        backup,
        service_user(),
        check_integrity=True,
    )

    assert result == {"backup": str(backup)}
    assert backup.read_bytes() == before
    assert sorted(path.name for path in root.iterdir()) == [backup.name]


def test_integrity_check_rejects_corrupt_database(tmp_path: Path) -> None:
    root = tmp_path / "backups"
    backup = create_backup(root)
    with pytest.raises(BackupValidationError, match="integrity"):
        validate_backup(
            root,
            backup,
            service_user(),
            check_integrity=True,
        )


def test_failed_staged_integrity_check_cleans_up(tmp_path: Path) -> None:
    root = tmp_path / "backups"
    backup = create_backup(root)
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)
    stage.chmod(0o700)

    with pytest.raises(BackupValidationError, match="integrity"):
        validate_backup(
            root,
            backup,
            service_user(),
            stage,
            "c" * 64,
            check_integrity=True,
        )

    assert list(stage.iterdir()) == []


def test_validated_backup_is_staged_from_the_open_inode(tmp_path: Path) -> None:
    root = tmp_path / "backups"
    backup = create_backup(root)
    original = backup.read_bytes()
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)
    stage.chmod(0o700)

    token = "a" * 64
    result = validate_backup(root, backup, service_user(), stage, token)
    staged = Path(result["staged_backup"])
    backup.unlink()
    backup.write_bytes(b"replacement")
    backup.chmod(0o600)

    assert staged.parent == stage
    assert staged.name == f"rollback-backup-{token}.db"
    assert staged.read_bytes() == original
    assert staged.stat().st_mode & 0o777 == 0o600
    staged.unlink()


def test_staging_requires_capacity_plus_safety_margin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "backups"
    backup = create_backup(root)
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)
    stage.chmod(0o700)
    free = backup.stat().st_size + MODULE.STAGING_MARGIN_BYTES - 1
    monkeypatch.setattr(
        MODULE.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=free),
    )
    with pytest.raises(BackupValidationError, match="capacity"):
        validate_backup(root, backup, service_user(), stage, "b" * 64)
    assert list(stage.iterdir()) == []


def test_parent_traversal_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "backups"
    create_backup(root)
    outside = tmp_path / "outside.db"
    outside.write_bytes(b"SQLite format 3\x00")
    outside.chmod(0o600)
    candidate = root / ".." / outside.name
    with pytest.raises(BackupValidationError, match="traversal"):
        validate_backup(root, candidate, service_user())


def test_symlink_parent_escape_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "backups"
    create_backup(root)
    outside = tmp_path / "outside"
    outside.mkdir()
    backup = outside / "strugglebus-outside.db"
    backup.write_bytes(b"SQLite format 3\x00")
    backup.chmod(0o600)
    (root / "escape").symlink_to(outside, target_is_directory=True)
    with pytest.raises(BackupValidationError):
        validate_backup(root, root / "escape" / backup.name, service_user())


def test_symlink_candidate_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "backups"
    backup = create_backup(root)
    link = root / "strugglebus-linked.db"
    link.symlink_to(backup)
    with pytest.raises(BackupValidationError):
        validate_backup(root, link, service_user())


@pytest.mark.parametrize("mode", [0o640, 0o660, 0o666])
def test_backup_with_unsafe_mode_is_rejected(tmp_path: Path, mode: int) -> None:
    root = tmp_path / "backups"
    backup = create_backup(root)
    backup.chmod(mode)
    with pytest.raises(BackupValidationError):
        validate_backup(root, backup, service_user())


def test_hard_linked_backup_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "backups"
    backup = create_backup(root)
    os.link(backup, root / "strugglebus-other.db")
    with pytest.raises(BackupValidationError):
        validate_backup(root, backup, service_user())
