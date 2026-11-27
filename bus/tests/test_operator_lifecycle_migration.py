from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier

import pytest

from strugglebus.auth import AgentService, mint_credential, mint_enrollment_token
from strugglebus.errors import DatabaseVersionError, MigrationError
from strugglebus.migrations import (
    LATEST_SCHEMA_VERSION,
    Migration,
    apply_migrations,
    load_packaged_migrations,
)
from strugglebus.roe import INITIAL_GLOBAL_CONTENT, INITIAL_GLOBAL_CONTENT_SHA256, INITIAL_GLOBAL_REVISION_ID
from strugglebus.store import SQLiteStore


TABLES = (
    "agents", "agent_credentials", "agent_credential_requests", "agent_credential_audit",
    "agent_enrollments", "agent_enrollment_redemptions", "channels", "messages",
    "messages_fts", "mentions", "subscriptions", "cursors", "mention_cursors",
    "roe_revisions", "roe_current", "roe_acknowledgements", "roe_audit",
    "agent_access_state", "agent_access_audit",
)


def snapshot(connection):
    return {
        table: (
            [row[1] for row in connection.execute(f"PRAGMA table_info({table})")],
            connection.execute(f"SELECT * FROM {table}").fetchall(),
        )
        for table in TABLES
    }


@pytest.fixture
def existing(tmp_path):
    path = tmp_path / "existing-eleven.db"
    store = SQLiteStore(path, backup_dir=tmp_path / "backups")
    timestamp = "2026-09-01T00:00:00.000000Z"
    credential_id, digest, secret = mint_credential()
    enrollment_id, enrollment_digest, _ = mint_enrollment_token()
    with sqlite3.connect(path, isolation_level=None) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        apply_migrations(connection, load_packaged_migrations()[:11])
        connection.execute(
            "INSERT INTO agents (id, name, description, host, created_at, credential_epoch) "
            "VALUES ('stable-id', 'stable-copilot', 'historical', 'historical-host', ?, 2)",
            (timestamp,),
        )
        connection.execute(
            "INSERT INTO agents (id, name, created_at, revoked_at, credential_epoch) "
            "VALUES ('terminal-id', 'retired-copilot', ?, ?, 3)", (timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO agent_credentials (id, agent_id, kind, secret_hash, status, "
            "creation_method, creation_reason, issuance_request_id, created_at, activated_at, "
            "identity_verified_at) VALUES (?, 'stable-id', 'sb1', ?, 'active', 'registration', "
            "'historic issuance', 'historic-request', ?, ?, ?)",
            (credential_id, digest, timestamp, timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO agent_credential_requests VALUES "
            "('historic-request', 'register', ?, 'stable-id', ?, ?)",
            ("a" * 64, credential_id, timestamp),
        )
        connection.execute(
            "INSERT INTO agent_credential_audit (id, event_type, agent_id, credential_id, "
            "actor_type, actor_id, method, reason, request_id, occurred_at) "
            "VALUES ('historic-event', 'issue', 'stable-id', ?, 'local-admin', "
            "'local-admin', 'registration', 'historic issuance', 'historic-request', ?)",
            (credential_id, timestamp),
        )
        connection.execute(
            "INSERT INTO agent_enrollments (id, secret_hash, name_prefix, name_match, "
            "description, status, uses_allowed, uses_remaining, created_at, expires_at, "
            "actor_type, actor_id, creation_reason) VALUES (?, ?, 'new-copilot', 'exact', "
            "'preserved', 'pending', 1, 1, ?, '2099-01-01T00:00:00.000000Z', "
            "'local-admin', 'local-admin', 'preserved allowance')",
            (enrollment_id, enrollment_digest, timestamp),
        )
        connection.execute(
            "INSERT INTO channels VALUES ('channel-id', 'history', '', ?, 'stable-id')",
            (timestamp,),
        )
        for number in (1, 2):
            connection.execute(
                "INSERT INTO messages (id, channel_id, agent_id, body, kind, reply_to, created_at) "
                "VALUES (?, 'channel-id', 'stable-id', 'history @stable-copilot', 'chat', ?, ?)",
                (f"message-{number}", None if number == 1 else 1, timestamp),
            )
        connection.execute("INSERT INTO mentions VALUES (1, 'stable-id')")
        connection.execute(
            "INSERT INTO subscriptions VALUES ('stable-id', 'channel-id', ?)", (timestamp,),
        )
        for scope in (0, 1):
            connection.execute(
                "INSERT INTO cursors VALUES ('stable-id', 'channel-id', ?, ?, ?)",
                (scope, scope + 1, timestamp),
            )
            connection.execute(
                "INSERT INTO mention_cursors VALUES ('stable-id', ?, 1, ?)", (scope, timestamp),
            )
    store.ensure_initial_roe(
        revision_id=INITIAL_GLOBAL_REVISION_ID,
        content_json=INITIAL_GLOBAL_CONTENT.decode(),
        content_sha256=INITIAL_GLOBAL_CONTENT_SHA256,
        created_at=datetime(2026, 9, 1, tzinfo=UTC),
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO roe_acknowledgements (id, agent_id, credential_record_id, "
            "global_revision_id, global_content_sha256, effective_sha256, acknowledged_at, "
            "credential_kind, credential_id) VALUES ('historic-receipt', 'stable-id', ?, ?, ?, "
            "?, ?, 'sb1', ?)",
            (credential_id, INITIAL_GLOBAL_REVISION_ID, INITIAL_GLOBAL_CONTENT_SHA256,
             "b" * 64, timestamp, credential_id),
        )
    changed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE agent_access_state SET frozen = 1, transition = 'freeze', "
            "changed_at = ?, reason = 'preserve containment'",
            (changed_at,),
        )
        connection.execute(
            "INSERT INTO agent_access_audit (transition, changed_at, reason) "
            "VALUES ('freeze', ?, 'preserve containment')",
            (changed_at,),
        )
    with sqlite3.connect(path) as connection:
        original = snapshot(connection)
    return store, original, secret


def assert_preserved(connection, original):
    for table, (columns, rows) in original.items():
        current = connection.execute(
            f"SELECT {', '.join(columns)} FROM {table}",
        ).fetchall()
        if table == "agents":
            name_index = columns.index("name")
            current = [
                row for row in current
                if row[name_index] not in {"system:strugglebus-maintenance", "human:operator"}
            ]
        assert current == rows


def test_populated_eleven_upgrade_preserves_every_old_byte_and_verified_backup(existing):
    store, original, secret = existing
    assert store.initialize() == LATEST_SCHEMA_VERSION
    with sqlite3.connect(store.database_path) as connection:
        assert_preserved(connection, original)
        assert connection.execute(
            "SELECT blocked_at FROM agents WHERE name NOT IN ('system:strugglebus-maintenance', 'human:operator')",
        ).fetchall() == [(None,), (None,)]
        assert connection.execute("SELECT COUNT(*) FROM agent_lifecycle_audit").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM agent_reconnect_grants").fetchone() == (0,)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    backups = list(store.backup_dir.glob("*.backup"))
    assert len(backups) == 1
    with sqlite3.connect(backups[0]) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (11,)
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert_preserved(connection, original)
    assert AgentService(store).verify_credential(secret) is not None
    assert store.get_managed_agent("terminal-id", require_access=False).state == "retired"


def test_schema_twelve_upgrade_is_serialized_with_one_backup(existing):
    store, original, _ = existing
    barrier = Barrier(3)

    def initialize():
        barrier.wait(timeout=5)
        return store.initialize()

    with ThreadPoolExecutor(max_workers=3) as executor:
        assert list(executor.map(lambda _: initialize(), range(3))) == [
            LATEST_SCHEMA_VERSION,
            LATEST_SCHEMA_VERSION,
            LATEST_SCHEMA_VERSION,
        ]
    with sqlite3.connect(store.database_path) as connection:
        assert_preserved(connection, original)
    assert len(list(store.backup_dir.glob("*.backup"))) == 1


def test_migration_twelve_failure_restores_complete_eleven_transaction(existing):
    store, original, _ = existing
    migrations = load_packaged_migrations()
    last = migrations[-1]
    broken = (*migrations[:-1], Migration(12, last.name, last.sql + "\nTHIS IS NOT SQL;\n"))
    with sqlite3.connect(store.database_path, isolation_level=None) as connection:
        with pytest.raises(MigrationError):
            apply_migrations(connection, broken, database_path=store.database_path,
                             backup_dir=store.backup_dir)
        assert connection.execute("PRAGMA user_version").fetchone() == (11,)
        assert_preserved(connection, original)
        assert "blocked_at" not in {r[1] for r in connection.execute("PRAGMA table_info(agents)")}
        assert connection.execute(
            "SELECT name FROM sqlite_schema WHERE name = 'agent_reconnect_grants'"
        ).fetchone() is None


@pytest.mark.parametrize("statement", [
    "DROP TRIGGER agents_valid_lifecycle",
    "DROP TRIGGER agent_lifecycle_audit_no_delete",
    "DROP TRIGGER agent_reconnect_valid_update",
    "DROP INDEX idx_agent_reconnect_pending_agent",
    # Guards from earlier migrations must stay pinned once a newer migration
    # lands. Pinning only the newest migration's objects would quietly retire
    # every one of the schema-12 checks above.
    "DROP TRIGGER mobile_devices_label_is_immutable",
    "DROP TRIGGER mobile_device_audit_no_delete",
    "DROP TABLE mobile_enrollment_redemptions",
    "DROP TRIGGER mobile_write_grants_are_append_only",
    "DROP TRIGGER mobile_action_confirmations_bindings_are_immutable",
    "DROP INDEX idx_mobile_write_grants_one_active",
    "DROP TABLE mobile_action_confirmations",
    "PRAGMA user_version=26",
])
def test_missing_or_forged_schema_guards_and_future_versions_are_refused(agent_service, statement):
    with sqlite3.connect(agent_service.store.database_path) as connection:
        connection.execute(statement)
    with pytest.raises((MigrationError, DatabaseVersionError)):
        agent_service.store.initialize()
