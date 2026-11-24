from datetime import UTC, datetime
import json
import sqlite3

import pytest

import strugglebus.maintenance_notice as notice_module
from strugglebus.maintenance_notice import publish_notice
from strugglebus.store import (
    MAINTENANCE_SYSTEM_AGENT_ID,
    SQLiteStore,
)


def test_maintenance_notice_is_a_system_authored_idempotent_announce(tmp_path):
    database = tmp_path / "bus.db"
    backups = tmp_path / "backups"
    store = SQLiteStore(database, backup_dir=backups)
    store.initialize()
    store.ensure_default_channels(
        (("announce", "Important changes"),),
        created_at=datetime(2026, 10, 1, tzinfo=UTC),
    )
    operation = "a" * 32
    first = publish_notice(
        database=database,
        backup_dir=backups,
        operation_id=operation,
        version="0.2.31",
        scheduled_at=1790816700,
        automatic=True,
        now=datetime(2026, 10, 1, tzinfo=UTC),
    )
    second = publish_notice(
        database=database,
        backup_dir=backups,
        operation_id=operation,
        version="0.2.31",
        scheduled_at=1790816700,
        automatic=True,
        now=datetime(2026, 10, 1, tzinfo=UTC),
    )
    assert second == first
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT agent_id, kind, body, meta FROM messages WHERE seq = ?",
            (first,),
        ).fetchone()
        assert row is not None
        assert row[0] == MAINTENANCE_SYSTEM_AGENT_ID
        assert row[1] == "announce"
        assert "release 0.2.31" in row[2]
        assert json.loads(row[3])["maintenance"]["automatic"] is True


def test_maintenance_notice_uses_bounded_contention_tolerance(tmp_path, monkeypatch):
    calls = []

    class Store:
        def __init__(self, database, *, backup_dir, busy_timeout_ms):
            calls.append((database, backup_dir, busy_timeout_ms))

        def create_maintenance_announcement(self, **kwargs):
            return type("Message", (), {"seq": 7})()

    monkeypatch.setattr(notice_module, "SQLiteStore", Store)
    database = (tmp_path / "bus.db").absolute()
    backups = (tmp_path / "backups").absolute()

    assert publish_notice(
        database=database,
        backup_dir=backups,
        operation_id="a" * 32,
        version="0.2.36",
        scheduled_at=1,
        automatic=False,
    ) == 7
    assert calls == [(database, backups, 30_000)]


def test_main_reports_only_bounded_sqlite_failure_code(monkeypatch, capsys):
    def fail(**kwargs):
        try:
            raise sqlite3.OperationalError("sensitive database detail")
        except sqlite3.OperationalError as cause:
            raise RuntimeError("wrapper detail") from cause

    monkeypatch.setattr(notice_module, "publish_notice", fail)

    assert notice_module.main([
        "--database", "/var/lib/strugglebus/strugglebus.db",
        "--backup-dir", "/var/backups/strugglebus",
        "--operation-id", "a" * 32,
        "--version", "0.2.40",
        "--scheduled-at", "1",
    ]) == 1
    assert json.loads(capsys.readouterr().out) == {
        "cause": "SQLITE_ERROR",
        "error": "maintenance_notice_failed",
        "ok": False,
    }


def test_system_author_is_hidden_and_cannot_receive_credentials(tmp_path):
    database = tmp_path / "bus.db"
    store = SQLiteStore(database, backup_dir=tmp_path / "backups")
    store.initialize()
    assert all(agent.id != MAINTENANCE_SYSTEM_AGENT_ID for agent in store.list_agents())
    with sqlite3.connect(database) as connection, pytest.raises(
        sqlite3.IntegrityError, match="cannot receive credentials",
    ):
        connection.execute(
            """
            INSERT INTO agent_credentials (
                id, agent_id, kind, secret_hash, status, predecessor_id,
                creation_method, creation_reason, issuance_request_id,
                created_at, activated_at, identity_verified_at,
                pending_expires_at, last_used_at, retired_at, revoked_at,
                expired_at, version
            ) VALUES (?, ?, 'sb1', ?, 'pending', NULL, 'test', 'test',
                      'test-request', ?, NULL, NULL, ?, NULL, NULL, NULL, NULL, 0)
            """,
            (
                "credential-test",
                MAINTENANCE_SYSTEM_AGENT_ID,
                "a" * 64,
                "2026-10-01T00:00:00Z",
                "2026-10-01T00:05:00Z",
            ),
        )


@pytest.mark.parametrize("version", ["latest", "1.2", "../1.2.3"])
def test_notice_rejects_unbounded_version(tmp_path, version):
    with pytest.raises(ValueError, match="invalid maintenance notice"):
        publish_notice(
            database=(tmp_path / "bus.db").absolute(),
            backup_dir=(tmp_path / "backups").absolute(),
            operation_id="a" * 32,
            version=version,
            scheduled_at=1,
            automatic=True,
        )
