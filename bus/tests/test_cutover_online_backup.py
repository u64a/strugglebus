"""Offline tests for the cutover online backup receipt and backward compatibility."""

from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
TEMPLATE = REPOSITORY / "deploy/roles/systemd/templates/sqlite_backup.py.j2"


def _load_backup_module():
    """Load the backup template as a module (it's a .j2 but valid Python)."""
    import shutil
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="backup-test-")
    py_copy = Path(tmpdir) / "sqlite_backup.py"
    shutil.copy2(TEMPLATE, py_copy)
    spec = importlib.util.spec_from_file_location("sqlite_backup", py_copy)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load backup template")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BACKUP = _load_backup_module()


def _create_test_db(path: Path) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA user_version = 8")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS messages "
            "(id TEXT PRIMARY KEY, seq INTEGER, channel_id TEXT, "
            "agent_id TEXT, body TEXT, created_at TEXT)"
        )
        conn.execute(
            "INSERT INTO messages (id, seq, channel_id, agent_id, body, created_at) "
            "VALUES ('m1', 1, 'c1', 'a1', 'hello', '2024-01-01T00:00:00Z')"
        )


class TestReceiptWrite:
    def test_receipt_written_with_valid_operation_id(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        backup_path = tmp_path / "backup.db"
        receipt_dir = tmp_path / "receipts"
        receipt_dir.mkdir()
        _create_test_db(db_path)

        # Create a backup copy.
        with sqlite3.connect(db_path) as source:
            with sqlite3.connect(backup_path) as target:
                source.backup(target)

        operation_id = "a" * 32
        BACKUP._write_receipt(receipt_dir, operation_id, backup_path, db_path)

        receipt_path = receipt_dir / f".cutover-backup-receipt-{operation_id}.json"
        assert receipt_path.exists()

        receipt = json.loads(receipt_path.read_text())
        assert receipt["receipt_version"] == 1
        assert receipt["operation_id"] == operation_id
        assert receipt["receipt_workspace"] == str(receipt_dir)
        assert len(receipt["backup_helper_sha256"]) == 64
        assert receipt["backup_basename"] == backup_path.name
        assert receipt["message_count"] == 1
        assert receipt["max_seq"] == 1
        assert receipt["schema_version"] == 8
        assert len(receipt["backup_sha256"]) == 64

    def test_receipt_refuses_overwrite(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        backup_path = tmp_path / "backup.db"
        receipt_dir = tmp_path / "receipts"
        receipt_dir.mkdir()
        _create_test_db(db_path)
        with sqlite3.connect(db_path) as source:
            with sqlite3.connect(backup_path) as target:
                source.backup(target)

        operation_id = "b" * 32
        BACKUP._write_receipt(receipt_dir, operation_id, backup_path, db_path)

        with pytest.raises(RuntimeError, match="receipt already exists"):
            BACKUP._write_receipt(receipt_dir, operation_id, backup_path, db_path)

    def test_receipt_rejects_invalid_operation_id(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        backup_path = tmp_path / "backup.db"
        receipt_dir = tmp_path / "receipts"
        receipt_dir.mkdir()
        _create_test_db(db_path)
        with sqlite3.connect(db_path) as source:
            with sqlite3.connect(backup_path) as target:
                source.backup(target)

        with pytest.raises(RuntimeError, match="32 hex"):
            BACKUP._write_receipt(receipt_dir, "short", backup_path, db_path)

        with pytest.raises(RuntimeError, match="32 hex"):
            BACKUP._write_receipt(receipt_dir, "X" * 32, backup_path, db_path)


class TestOperationIdPattern:
    def test_valid_pattern(self) -> None:
        assert BACKUP.OPERATION_ID_PATTERN.fullmatch("a" * 32) is not None
        assert BACKUP.OPERATION_ID_PATTERN.fullmatch("0123456789abcdef" * 2) is not None

    def test_invalid_pattern(self) -> None:
        assert BACKUP.OPERATION_ID_PATTERN.fullmatch("A" * 32) is None  # uppercase
        assert BACKUP.OPERATION_ID_PATTERN.fullmatch("a" * 31) is None  # too short
        assert BACKUP.OPERATION_ID_PATTERN.fullmatch("a" * 33) is None  # too long


class TestBackwardCompatibility:
    """Verify the backup helper works without --operation-id/--receipt-dir."""

    def test_backup_without_receipt_args(self, tmp_path: Path) -> None:
        """The main function should work with just positional args."""
        db_path = tmp_path / "test.db"
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        if os.name == "posix":
            os.chmod(backup_dir, 0o700)
        _create_test_db(db_path)

        # Simulate the main() call with just positional args (no receipt).
        with patch.object(
            BACKUP.sys, "argv",
            ["sqlite_backup", str(db_path), str(backup_dir), "7"],
        ):
            result = BACKUP.main()

        assert result == 0
        backups = list(backup_dir.glob("strugglebus-*.db"))
        assert len(backups) >= 1

        # No receipt files should exist.
        receipts = list(backup_dir.glob(".cutover-backup-receipt-*.json"))
        assert len(receipts) == 0

    def test_backup_with_receipt_args(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """main() should write a receipt when both args are provided."""
        db_path = tmp_path / "test.db"
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        if os.name == "posix":
            os.chmod(backup_dir, 0o700)
        receipt_root = tmp_path / "receipts"
        receipt_root.mkdir()
        receipt_root.chmod(0o750)
        operation_id = "c" * 32
        receipt_dir = receipt_root / operation_id
        receipt_dir.mkdir()
        receipt_dir.chmod(0o700)
        monkeypatch.setattr(BACKUP, "RECEIPT_WORKSPACE_ROOT", receipt_root)
        _create_test_db(db_path)

        with patch.object(
            BACKUP.sys, "argv",
            [
                "sqlite_backup",
                str(db_path), str(backup_dir), "7",
                "--operation-id", operation_id,
                "--receipt-dir", str(receipt_dir),
            ],
        ):
            result = BACKUP.main()

        assert result == 0
        receipt_path = receipt_dir / f".cutover-backup-receipt-{operation_id}.json"
        assert receipt_path.exists()

    def test_main_rejects_unbound_receipt_workspace(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db_path = tmp_path / "test.db"
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        backup_dir.chmod(0o700)
        receipt_root = tmp_path / "receipts"
        receipt_root.mkdir()
        receipt_root.chmod(0o750)
        unbound = receipt_root / "wrong"
        unbound.mkdir()
        unbound.chmod(0o700)
        monkeypatch.setattr(BACKUP, "RECEIPT_WORKSPACE_ROOT", receipt_root)
        _create_test_db(db_path)
        with patch.object(
            BACKUP.sys,
            "argv",
            [
                "sqlite_backup",
                str(db_path),
                str(backup_dir),
                "7",
                "--operation-id",
                "c" * 32,
                "--receipt-dir",
                str(unbound),
            ],
        ):
            with pytest.raises(RuntimeError, match="operation-bound"):
                BACKUP.main()

    def test_mismatched_receipt_args_fails(self, tmp_path: Path) -> None:
        """Providing only one of --operation-id/--receipt-dir should fail."""
        db_path = tmp_path / "test.db"
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        if os.name == "posix":
            os.chmod(backup_dir, 0o700)
        _create_test_db(db_path)

        with patch.object(
            BACKUP.sys, "argv",
            ["sqlite_backup", str(db_path), str(backup_dir), "7",
             "--operation-id", "a" * 32],
        ):
            with pytest.raises(SystemExit, match="together"):
                BACKUP.main()


class TestReceiptPrivacy:
    def test_no_message_bodies_in_receipt(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        backup_path = tmp_path / "backup.db"
        receipt_dir = tmp_path / "receipts"
        receipt_dir.mkdir()
        _create_test_db(db_path)
        with sqlite3.connect(db_path) as source:
            with sqlite3.connect(backup_path) as target:
                source.backup(target)

        operation_id = "d" * 32
        BACKUP._write_receipt(receipt_dir, operation_id, backup_path, db_path)

        receipt_path = receipt_dir / f".cutover-backup-receipt-{operation_id}.json"
        payload = receipt_path.read_text()
        assert "hello" not in payload
        assert "SECRET" not in payload
