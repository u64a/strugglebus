import hashlib
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from strugglebus.errors import (
    DatabaseVersionError,
    DuplicateAgentNameError,
    MigrationError,
    MissingMigrationError,
)
from strugglebus.auth import AgentService
from strugglebus.migrations import (
    LATEST_SCHEMA_VERSION,
    Migration,
    apply_migrations,
    load_packaged_migrations,
)
from strugglebus.roe import INITIAL_GLOBAL_REVISION_ID, RoeService
from strugglebus.store import SQLiteStore


def connect(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path, isolation_level=None)


def test_empty_database_receives_every_packaged_migration(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "empty.db"
    store = SQLiteStore(database_path, backup_dir=tmp_path / "backups")

    assert store.initialize() == LATEST_SCHEMA_VERSION

    with connect(database_path) as database:
        objects = {
            row[0]
            for row in database.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type IN ('table', 'view')"
            )
        }
        assert {
            "agents",
            "channels",
            "messages",
            "mentions",
            "subscriptions",
            "cursors",
            "mention_cursors",
            "messages_fts",
            "agent_access_state",
            "agent_access_audit",
            "agent_credentials",
            "agent_credential_requests",
            "agent_credential_audit",
        } <= objects
        assert database.execute("PRAGMA user_version").fetchone() == (
            LATEST_SCHEMA_VERSION,
        )
        indexes = database.execute(
            "PRAGMA index_list(agent_credentials)"
        ).fetchall()
        assert any(
            row[1] == "idx_agent_credentials_legacy_hash" and row[2] == 1
            for row in indexes
        )
        message_indexes = database.execute(
            "PRAGMA index_list(messages)"
        ).fetchall()
        assert any(
            row[1] == "idx_messages_kind_created_seq"
            for row in message_indexes
        )
        assert any(
            row[1] == "idx_messages_reply_to_seq"
            for row in message_indexes
        )
        assert any(
            row[1] == "idx_messages_channel_agent_seq"
            for row in message_indexes
        )
        cursor_columns = {
            row[1] for row in database.execute("PRAGMA table_info(cursors)")
        }
        assert "include_stale" in cursor_columns


def test_schema_fourteen_freeze_audit_gains_actor_identity_with_backup(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "schema-fourteen.db"
    backup_dir = tmp_path / "backups"
    migrations = load_packaged_migrations()
    with connect(database_path) as database:
        assert apply_migrations(database, migrations[:14]) == 14
        database.execute(
            """
            INSERT INTO agent_access_audit (transition, changed_at, reason)
            VALUES ('freeze', '2026-09-14T00:00:00Z', 'legacy incident')
            """
        )

    store = SQLiteStore(database_path, backup_dir=backup_dir)
    assert store.initialize() == LATEST_SCHEMA_VERSION

    with connect(database_path) as database:
        columns = {
            row[1] for row in database.execute(
                "PRAGMA table_info(agent_access_audit)"
            )
        }
        assert {"actor_type", "actor_id"} <= columns
        assert database.execute(
            "SELECT transition, reason, actor_type, actor_id "
            "FROM agent_access_audit"
        ).fetchone() == (
            "freeze", "legacy incident", "system", "migration:schema15-legacy",
        )
    backups = list(backup_dir.glob("*.backup"))
    assert len(backups) == 1
    with connect(backups[0]) as backup:
        assert backup.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert backup.execute("PRAGMA user_version").fetchone() == (14,)
        columns = {
            row[1] for row in backup.execute(
                "PRAGMA table_info(agent_access_audit)"
            )
        }
        assert "actor_type" not in columns


def test_store_connections_enforce_operational_pragmas(tmp_path: Path) -> None:
    database_path = tmp_path / "pragmas.db"
    store = SQLiteStore(
        database_path,
        backup_dir=tmp_path / "backups",
        busy_timeout_ms=1234,
    )
    store.initialize()

    with store._connection() as database:
        assert database.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert database.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert database.execute("PRAGMA busy_timeout").fetchone()[0] == 1234


def test_existing_current_database_is_preserved(tmp_path: Path) -> None:
    database_path = tmp_path / "existing.db"
    store = SQLiteStore(database_path, backup_dir=tmp_path / "backups")
    store.initialize()
    with connect(database_path) as database:
        database.execute(
            """
            INSERT INTO agents (id, name, created_at)
            VALUES (?, ?, ?)
            """,
            ("agent-1", "project-agent", "2026-01-01T00:00:00Z"),
        )

    assert store.initialize() == LATEST_SCHEMA_VERSION

    with connect(database_path) as database:
        assert database.execute(
            "SELECT name FROM agents WHERE id = ?", ("agent-1",)
        ).fetchone() == ("project-agent",)


def test_schema_eighteen_preserves_existing_maintenance_named_agent(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "schema-seventeen.db"
    migrations = load_packaged_migrations()
    with connect(database_path) as database:
        assert apply_migrations(database, migrations[:17]) == 17
        database.execute(
            """
            INSERT INTO agents (id, name, created_at)
            VALUES (?, ?, ?)
            """,
            (
                "existing-maintenance-agent",
                "strugglebus-maintenance",
                "2026-01-01T00:00:00Z",
            ),
        )

    store = SQLiteStore(database_path, backup_dir=tmp_path / "backups")
    assert store.initialize() == LATEST_SCHEMA_VERSION

    with connect(database_path) as database:
        assert database.execute(
            "SELECT id, name FROM agents WHERE id = ?",
            ("existing-maintenance-agent",),
        ).fetchone() == (
            "existing-maintenance-agent",
            "strugglebus-maintenance",
        )
        assert database.execute(
            "SELECT name FROM agents WHERE id = ?",
            ("00000000-0000-4000-8000-000000000018",),
        ).fetchone() == ("system:strugglebus-maintenance",)


def test_newer_database_version_is_refused(tmp_path: Path) -> None:
    database_path = tmp_path / "future.db"
    with connect(database_path) as database:
        database.execute(
            f"PRAGMA user_version = {LATEST_SCHEMA_VERSION + 1}"
        )
    store = SQLiteStore(database_path, backup_dir=tmp_path / "backups")

    with pytest.raises(DatabaseVersionError, match="newer than supported"):
        store.initialize()


def test_unversioned_nonempty_database_is_refused(tmp_path: Path) -> None:
    database_path = tmp_path / "unversioned.db"
    with connect(database_path) as database:
        database.execute("CREATE TABLE unexpected (value TEXT)")
    store = SQLiteStore(database_path, backup_dir=tmp_path / "backups")

    with pytest.raises(DatabaseVersionError, match="no recognized schema"):
        store.initialize()


def test_missing_migration_version_is_refused_before_changes() -> None:
    database = sqlite3.connect(":memory:", isolation_level=None)
    migrations = (
        Migration(1, "0001_first.sql", "CREATE TABLE first (id INTEGER);"),
        Migration(3, "0003_third.sql", "CREATE TABLE third (id INTEGER);"),
    )

    with pytest.raises(MissingMigrationError):
        apply_migrations(database, migrations)

    assert database.execute("PRAGMA user_version").fetchone() == (0,)
    assert database.execute(
        "SELECT name FROM sqlite_master WHERE name = 'first'"
    ).fetchone() is None


def test_migration_failure_rolls_back_all_pending_versions() -> None:
    database = sqlite3.connect(":memory:", isolation_level=None)
    migrations = (
        Migration(1, "0001_first.sql", "CREATE TABLE first (id INTEGER);"),
        Migration(
            2,
            "0002_broken.sql",
            "CREATE TABLE second (id INTEGER);\nTHIS IS NOT SQL;",
        ),
    )

    with pytest.raises(MigrationError, match="starting at version 1 failed"):
        apply_migrations(database, migrations)

    assert database.execute("PRAGMA user_version").fetchone() == (0,)
    assert database.execute(
        "SELECT name FROM sqlite_master WHERE name IN ('first', 'second')"
    ).fetchall() == []


def test_known_upgrade_creates_integrity_checked_backup(tmp_path: Path) -> None:
    database_path = tmp_path / "upgrade.db"
    backup_dir = tmp_path / "backups"
    first = Migration(1, "0001_first.sql", "CREATE TABLE first (id INTEGER);")
    second = Migration(2, "0002_second.sql", "CREATE TABLE second (id INTEGER);")
    with connect(database_path) as database:
        assert apply_migrations(database, (first,)) == 1
        database.execute("INSERT INTO first (id) VALUES (?)", (7,))
        assert apply_migrations(
            database,
            (first, second),
            database_path=database_path,
            backup_dir=backup_dir,
        ) == 2

    backups = list(backup_dir.glob("*.backup"))
    assert len(backups) == 1
    with connect(backups[0]) as backup:
        assert backup.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert backup.execute("PRAGMA user_version").fetchone() == (1,)
        assert backup.execute("SELECT id FROM first").fetchone() == (7,)


def test_populated_schema_nine_migrates_enrollments_and_preserves_state(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "schema-nine.db"
    backup_dir = tmp_path / "backups"
    migrations = load_packaged_migrations()
    timestamp = "2026-01-01T00:00:00Z"
    with connect(database_path) as database:
        assert apply_migrations(database, migrations[:9]) == 9
        database.execute(
            """
            INSERT INTO agents (
                id, name, description, host, created_at, credential_epoch
            )
            VALUES ('agent-1', 'pre-enrollment-agent', '', '', ?, 1)
            """,
            (timestamp,),
        )
        database.execute(
            """
            INSERT INTO agent_credentials (
                id, agent_id, kind, secret_hash, status, creation_method,
                creation_reason, issuance_request_id, created_at, activated_at,
                identity_verified_at
            )
            VALUES ('cred-1', 'agent-1', 'sb1', ?, 'active', 'registration',
                    'initial agent credential', 'request-1', ?, ?, ?)
            """,
            ("d" * 64, timestamp, timestamp, timestamp),
        )

    store = SQLiteStore(database_path, backup_dir=backup_dir)
    assert store.initialize() == LATEST_SCHEMA_VERSION

    # Pre-existing identities and credentials survive untouched.
    with connect(database_path) as database:
        assert database.execute(
            "SELECT name FROM agents WHERE id = 'agent-1'"
        ).fetchone() == ("pre-enrollment-agent",)
        assert database.execute(
            "SELECT status FROM agent_credentials WHERE id = 'cred-1'"
        ).fetchone() == ("active",)
        assert database.execute(
            "SELECT COUNT(*) FROM agent_enrollments"
        ).fetchone() == (0,)

    # A verified pre-migration backup of the existing database is retained.
    backups = list(backup_dir.glob("*.backup"))
    assert len(backups) == 1
    with connect(backups[0]) as backup:
        assert backup.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert backup.execute("PRAGMA user_version").fetchone() == (9,)

    # Enrollment works against the upgraded database, and cannot take over the
    # identity that existed before the migration.
    service = AgentService(store)
    issued = service.create_enrollment(name_prefix="pre")
    with pytest.raises(DuplicateAgentNameError):
        service.redeem_enrollment(
            issued.token, claimed_name="pre-enrollment-agent"
        )
    redeemed = service.redeem_enrollment(
        issued.token, claimed_name="pre-enrollment-new"
    )
    assert redeemed.agent.name == "pre-enrollment-new"


def test_populated_schema_eight_migrates_credentials_and_preserves_state(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "schema-eight.db"
    backup_dir = tmp_path / "backups"
    migrations = load_packaged_migrations()
    active_secret = "legacy-active-secret"
    revoked_secret = "legacy-revoked-secret"
    active_hash = hashlib.sha256(active_secret.encode("ascii")).hexdigest()
    revoked_hash = hashlib.sha256(revoked_secret.encode("ascii")).hexdigest()
    timestamp = "2026-01-01T00:00:00Z"
    revoked_at = "2026-01-02T00:00:00Z"
    global_hash = "a" * 64
    effective_hash = "b" * 64
    with connect(database_path) as database:
        assert apply_migrations(database, migrations[:8]) == 8
        database.executemany(
            """
            INSERT INTO agents (
                id, name, description, host, key_hash,
                created_at, last_seen_at, revoked_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    "agent-active",
                    "migration-active",
                    "active",
                    "active.lan",
                    active_hash,
                    timestamp,
                    revoked_at,
                    None,
                ),
                (
                    "agent-revoked",
                    "migration-revoked",
                    "revoked",
                    "revoked.lan",
                    revoked_hash,
                    timestamp,
                    timestamp,
                    revoked_at,
                ),
            ),
        )
        database.execute(
            """
            INSERT INTO channels (id, name, purpose, created_at, created_by)
            VALUES ('channel-1', 'migration', 'preserved', ?, 'agent-active')
            """,
            (timestamp,),
        )
        database.execute(
            """
            INSERT INTO messages (
                id, channel_id, agent_id, body, kind, meta, created_at
            )
            VALUES ('message-1', 'channel-1', 'agent-active',
                    'migration searchable body', 'chat', '{"safe":true}', ?)
            """,
            (timestamp,),
        )
        database.execute(
            "INSERT INTO mentions VALUES (1, 'agent-revoked')"
        )
        database.execute(
            "INSERT INTO subscriptions VALUES ('agent-active', 'channel-1', ?)",
            (timestamp,),
        )
        database.execute(
            """
            INSERT INTO cursors
                (agent_id, channel_id, include_stale, last_seq, updated_at)
            VALUES ('agent-active', 'channel-1', 0, 1, ?)
            """,
            (timestamp,),
        )
        database.execute(
            """
            INSERT INTO mention_cursors
                (agent_id, include_stale, last_seq, updated_at)
            VALUES ('agent-revoked', 0, 1, ?)
            """,
            (timestamp,),
        )
        database.execute(
            """
            UPDATE agent_access_state
            SET frozen = 1, transition = 'freeze', changed_at = ?,
                reason = 'migration preservation'
            WHERE singleton = 1
            """,
            (timestamp,),
        )
        database.execute(
            """
            INSERT INTO agent_access_audit (transition, changed_at, reason)
            VALUES ('freeze', ?, 'migration preservation')
            """,
            (timestamp,),
        )
        database.execute(
            """
            INSERT INTO roe_revisions (
                id, target_key, scope, agent_id, version,
                policy_schema_version, content_json, content_sha256,
                author_label, publisher_type, publisher_identity, created_at
            )
            VALUES (
                'roe-global-1', 'global', 'global', NULL, 1, 1, '{}', ?,
                'migration', 'system', 'migration-test', ?
            )
            """,
            (global_hash, timestamp),
        )
        database.execute(
            """
            INSERT INTO roe_current (
                target_key, scope, agent_id, revision_id, updated_at
            )
            VALUES ('global', 'global', NULL, 'roe-global-1', ?)
            """,
            (timestamp,),
        )
        database.execute(
            """
            INSERT INTO roe_acknowledgements (
                id, agent_id, global_revision_id, global_content_sha256,
                effective_sha256, acknowledged_at,
                credential_kind, credential_id
            )
            VALUES (
                'ack-1', 'agent-active', 'roe-global-1', ?, ?, ?,
                'agent-api-key-sha256-v1', 'legacy-context'
            )
            """,
            (global_hash, effective_hash, timestamp),
        )
        database.execute(
            """
            INSERT INTO roe_audit (
                id, event_type, target_key, agent_id, global_revision_id,
                effective_sha256, actor_type, actor_id, occurred_at
            )
            VALUES (
                'roe-audit-1', 'acknowledge', 'agent:agent-active',
                'agent-active', 'roe-global-1', ?, 'agent',
                'agent-active', ?
            )
            """,
            (effective_hash, timestamp),
        )

    store = SQLiteStore(database_path, backup_dir=backup_dir)
    assert store.initialize() == LATEST_SCHEMA_VERSION
    service = AgentService(store)
    authenticated = service.authenticate(active_secret)
    assert authenticated is not None
    assert authenticated.agent.id == "agent-active"
    assert authenticated.credential.id == "legacy-agent:agent-active"
    assert service.authenticate(revoked_secret) is None

    with connect(database_path) as database:
        database.row_factory = sqlite3.Row
        credentials = database.execute(
            """
            SELECT id, agent_id, secret_hash, status, revoked_at
            FROM agent_credentials ORDER BY agent_id
            """
        ).fetchall()
        assert [tuple(row) for row in credentials] == [
            (
                "legacy-agent:agent-active",
                "agent-active",
                active_hash,
                "active",
                None,
            ),
            (
                "legacy-agent:agent-revoked",
                "agent-revoked",
                revoked_hash,
                "revoked",
                revoked_at,
            ),
        ]
        assert [
            tuple(row)
            for row in database.execute(
                """
                SELECT credential_epoch FROM agents
                WHERE id NOT IN ('00000000-0000-4000-8000-000000000018', '00000000-0000-4000-8000-000000000019')
                ORDER BY id
                """
            ).fetchall()
        ] == [(1,), (1,)]
        acknowledgement = database.execute(
            """
            SELECT id, agent_id, credential_record_id, global_revision_id,
                   effective_sha256, credential_kind, credential_id
            FROM roe_acknowledgements
            """
        ).fetchone()
        assert tuple(acknowledgement) == (
            "ack-1",
            "agent-active",
            "legacy-agent:agent-active",
            "roe-global-1",
            effective_hash,
            "agent-api-key-sha256-v1",
            "legacy-context",
        )
        assert tuple(database.execute(
            "SELECT body FROM messages_fts WHERE messages_fts MATCH 'searchable'"
        ).fetchone()) == ("migration searchable body",)
        assert database.execute("SELECT COUNT(*) FROM mentions").fetchone()[0] == 1
        assert database.execute("SELECT COUNT(*) FROM subscriptions").fetchone()[0] == 1
        assert database.execute("SELECT last_seq FROM cursors").fetchone()[0] == 1
        assert database.execute("SELECT last_seq FROM mention_cursors").fetchone()[0] == 1
        assert tuple(database.execute(
            "SELECT frozen, reason FROM agent_access_state"
        ).fetchone()) == (1, "migration preservation")
        assert database.execute(
            "SELECT COUNT(*) FROM agent_access_audit"
        ).fetchone()[0] == 1
        assert database.execute("SELECT COUNT(*) FROM roe_audit").fetchone()[0] == 1
        assert database.execute(
            "SELECT COUNT(*) FROM agent_credential_audit WHERE event_type = 'migrate'"
        ).fetchone()[0] == 2

    backups = list(backup_dir.glob("*.backup"))
    assert len(backups) == 1
    with connect(backups[0]) as backup:
        assert backup.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert backup.execute("PRAGMA user_version").fetchone() == (8,)
        assert backup.execute(
            "SELECT key_hash FROM agents WHERE id = 'agent-active'"
        ).fetchone() == (active_hash,)


def test_existing_version_one_database_is_upgraded_and_backed_up(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "version-one.db"
    backup_dir = tmp_path / "backups"
    migrations = load_packaged_migrations()
    with connect(database_path) as database:
        assert apply_migrations(database, migrations[:1]) == 1
        database.execute(
            """
            INSERT INTO agents (id, name, key_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            ("agent-1", "project-agent", "a" * 64, "2026-01-01T00:00:00Z"),
        )

    store = SQLiteStore(database_path, backup_dir=backup_dir)
    assert store.initialize() == LATEST_SCHEMA_VERSION

    backups = list(backup_dir.glob("*.backup"))
    assert len(backups) == 1
    with connect(backups[0]) as backup:
        assert backup.execute("PRAGMA user_version").fetchone() == (1,)
        assert backup.execute(
            "SELECT name FROM agents WHERE id = ?", ("agent-1",)
        ).fetchone() == ("project-agent",)


def test_version_three_cursor_is_preserved_in_default_scope(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "version-three.db"
    backup_dir = tmp_path / "backups"
    migrations = load_packaged_migrations()
    with connect(database_path) as database:
        assert apply_migrations(database, migrations[:3]) == 3
        database.execute(
            """
            INSERT INTO agents (id, name, key_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            ("agent-1", "project-agent", "a" * 64, "2026-01-01T00:00:00Z"),
        )
        database.execute(
            """
            INSERT INTO channels (id, name, created_at)
            VALUES (?, ?, ?)
            """,
            ("channel-1", "general", "2026-01-01T00:00:00Z"),
        )
        database.execute(
            """
            INSERT INTO cursors (agent_id, channel_id, last_seq, updated_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                "agent-1",
                "channel-1",
                42,
                "2026-01-01T00:00:00Z",
            ),
        )

    store = SQLiteStore(database_path, backup_dir=backup_dir)
    assert store.initialize() == LATEST_SCHEMA_VERSION

    with connect(database_path) as database:
        assert database.execute(
            """
            SELECT include_stale, last_seq
            FROM cursors
            WHERE agent_id = ? AND channel_id = ?
            """,
            ("agent-1", "channel-1"),
        ).fetchone() == (0, 42)
        assert database.execute(
            "SELECT COUNT(*) FROM mention_cursors"
        ).fetchone() == (0,)
    backups = list(backup_dir.glob("*.backup"))
    assert len(backups) == 1
    with connect(backups[0]) as backup:
        assert backup.execute("PRAGMA user_version").fetchone() == (3,)


def test_version_four_database_adds_reply_index_after_verified_backup(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "version-four.db"
    backup_dir = tmp_path / "backups"
    migrations = load_packaged_migrations()
    with connect(database_path) as database:
        assert apply_migrations(database, migrations[:4]) == 4

    store = SQLiteStore(database_path, backup_dir=backup_dir)
    assert store.initialize() == LATEST_SCHEMA_VERSION

    with connect(database_path) as database:
        indexes = database.execute("PRAGMA index_list(messages)").fetchall()
        assert any(row[1] == "idx_messages_reply_to_seq" for row in indexes)
    backups = list(backup_dir.glob("*.backup"))
    assert len(backups) == 1
    with connect(backups[0]) as backup:
        assert backup.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert backup.execute("PRAGMA user_version").fetchone() == (4,)


def test_version_five_database_adds_inactive_freeze_with_verified_backup(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "version-five.db"
    backup_dir = tmp_path / "backups"
    migrations = load_packaged_migrations()
    with connect(database_path) as database:
        assert apply_migrations(database, migrations[:5]) == 5
        database.execute(
            """
            INSERT INTO agents (id, name, key_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            ("agent-1", "project-agent", "a" * 64, "2026-01-01T00:00:00Z"),
        )

    store = SQLiteStore(database_path, backup_dir=backup_dir)
    assert store.initialize() == LATEST_SCHEMA_VERSION
    assert store.get_access_freeze().frozen is False

    backups = list(backup_dir.glob("*.backup"))
    assert len(backups) == 1
    with connect(backups[0]) as backup:
        assert backup.execute("PRAGMA user_version").fetchone() == (5,)
        assert backup.execute(
            "SELECT name FROM agents WHERE id = ?", ("agent-1",)
        ).fetchone() == ("project-agent",)


def test_version_six_database_adds_dashboard_index_after_verified_backup(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "version-six.db"
    backup_dir = tmp_path / "backups"
    migrations = load_packaged_migrations()
    with connect(database_path) as database:
        assert apply_migrations(database, migrations[:6]) == 6

    store = SQLiteStore(database_path, backup_dir=backup_dir)
    assert store.initialize() == LATEST_SCHEMA_VERSION

    with connect(database_path) as database:
        indexes = database.execute("PRAGMA index_list(messages)").fetchall()
        assert any(
            row[1] == "idx_messages_channel_agent_seq"
            for row in indexes
        )
    backups = list(backup_dir.glob("*.backup"))
    assert len(backups) == 1
    with connect(backups[0]) as backup:
        assert backup.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert backup.execute("PRAGMA user_version").fetchone() == (6,)


def test_production_schema_seven_migrates_to_roe_with_all_state_preserved(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "version-seven.db"
    backup_dir = tmp_path / "backups"
    migrations = load_packaged_migrations()
    with connect(database_path) as database:
        assert apply_migrations(database, migrations[:7]) == 7
        database.execute(
            """
            INSERT INTO agents (id, name, key_hash, created_at)
            VALUES ('agent-1', 'project-agent', ?, '2026-01-01T00:00:00Z')
            """,
            ("a" * 64,),
        )
        database.execute(
            """
            INSERT INTO channels (id, name, purpose, created_at)
            VALUES ('channel-1', 'general', 'preserved', '2026-01-01T00:00:00Z')
            """
        )
        database.execute(
            """
            INSERT INTO subscriptions (agent_id, channel_id, created_at)
            VALUES ('agent-1', 'channel-1', '2026-01-01T00:00:00Z')
            """
        )
        database.execute(
            """
            INSERT INTO messages (
                id, channel_id, agent_id, body, kind, meta, created_at
            )
            VALUES (
                'message-1', 'channel-1', 'agent-1', 'preserved searchable body',
                'chat', '{}', '2026-01-01T00:00:00Z'
            )
            """
        )
        database.execute(
            """
            INSERT INTO cursors (
                agent_id, channel_id, include_stale, last_seq, updated_at
            )
            VALUES ('agent-1', 'channel-1', 0, 1, '2026-01-01T00:00:00Z')
            """
        )
        database.execute(
            """
            INSERT INTO mention_cursors (
                agent_id, include_stale, last_seq, updated_at
            )
            VALUES ('agent-1', 1, 1, '2026-01-01T00:00:00Z')
            """
        )
        database.execute(
            """
            UPDATE agent_access_state
            SET frozen = 1, transition = 'freeze',
                changed_at = '2026-01-02T00:00:00Z',
                reason = 'preserve migration freeze'
            WHERE singleton = 1
            """
        )
        database.execute(
            """
            INSERT INTO agent_access_audit (transition, changed_at, reason)
            VALUES (
                'freeze', '2026-01-02T00:00:00Z',
                'preserve migration freeze'
            )
            """
        )

    store = SQLiteStore(database_path, backup_dir=backup_dir)
    roe = RoeService(store, enforcement_mode="observe")
    assert roe.initialize() == LATEST_SCHEMA_VERSION

    with connect(database_path) as database:
        assert database.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert database.execute("PRAGMA foreign_key_check").fetchall() == []
        assert database.execute(
            "SELECT body FROM messages WHERE id = 'message-1'"
        ).fetchone() == ("preserved searchable body",)
        assert database.execute(
            "SELECT rowid FROM messages_fts WHERE messages_fts MATCH 'searchable'"
        ).fetchone() == (1,)
        assert database.execute(
            "SELECT include_stale, last_seq FROM cursors"
        ).fetchone() == (0, 1)
        assert database.execute(
            "SELECT include_stale, last_seq FROM mention_cursors"
        ).fetchone() == (1, 1)
        assert database.execute(
            "SELECT frozen, reason FROM agent_access_state"
        ).fetchone() == (1, "preserve migration freeze")
        assert database.execute(
            "SELECT transition, reason FROM agent_access_audit"
        ).fetchone() == ("freeze", "preserve migration freeze")
        assert database.execute(
            "SELECT revision_id FROM roe_current WHERE target_key = 'global'"
        ).fetchone() == (INITIAL_GLOBAL_REVISION_ID,)

    backups = list(backup_dir.glob("*.backup"))
    assert len(backups) == 1
    with connect(backups[0]) as backup:
        assert backup.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert backup.execute("PRAGMA user_version").fetchone() == (7,)
        assert backup.execute(
            "SELECT body FROM messages WHERE id = 'message-1'"
        ).fetchone() == ("preserved searchable body",)
        assert backup.execute(
            "SELECT frozen FROM agent_access_state"
        ).fetchone() == (1,)


class _CoordinatedConnection(sqlite3.Connection):
    stale_read_barrier: threading.Barrier

    def execute(self, sql, parameters=(), /):
        if (
            sql.strip().upper() == "PRAGMA USER_VERSION"
            and not self.in_transaction
        ):
            self.stale_read_barrier.wait(timeout=5)
        return super().execute(sql, parameters)


def test_concurrent_startup_serializes_before_reading_schema_version(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "concurrent.db"
    start_barrier = threading.Barrier(2)
    _CoordinatedConnection.stale_read_barrier = threading.Barrier(2)

    def initialize() -> int:
        database = sqlite3.connect(
            database_path,
            isolation_level=None,
            timeout=5,
            factory=_CoordinatedConnection,
        )
        try:
            start_barrier.wait(timeout=5)
            return apply_migrations(database, load_packaged_migrations())
        finally:
            database.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        versions = list(executor.map(lambda _: initialize(), range(2)))

    assert versions == [LATEST_SCHEMA_VERSION, LATEST_SCHEMA_VERSION]
    with connect(database_path) as database:
        assert database.execute("PRAGMA user_version").fetchone() == (
            LATEST_SCHEMA_VERSION,
        )


def test_packaged_migration_set_is_complete() -> None:
    migrations = load_packaged_migrations()

    assert tuple(migration.version for migration in migrations) == tuple(
        range(1, LATEST_SCHEMA_VERSION + 1)
    )
