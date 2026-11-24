import sqlite3
from pathlib import Path

import pytest

from strugglebus.migrations import LATEST_SCHEMA_VERSION
from strugglebus.store import SQLiteStore


def create_database(tmp_path: Path):
    database_path = tmp_path / "schema.db"
    SQLiteStore(database_path, backup_dir=tmp_path / "backups").initialize()
    database = sqlite3.connect(database_path)
    database.execute("PRAGMA foreign_keys = ON")
    return database


def test_schema_initializes_expected_tables(tmp_path):
    database = create_database(tmp_path)

    objects = {
        row[0]
        for row in database.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')"
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
        "roe_revisions",
        "roe_current",
        "roe_acknowledgements",
        "roe_audit",
    } <= objects
    assert database.execute("PRAGMA user_version").fetchone() == (
        LATEST_SCHEMA_VERSION,
    )
    indexes = database.execute("PRAGMA index_list(messages)").fetchall()
    assert any(row[1] == "idx_messages_reply_to_seq" for row in indexes)
    assert any(row[1] == "idx_messages_channel_agent_seq" for row in indexes)


@pytest.mark.parametrize("table, identifier", [("agents", "agent-1"), ("channels", "general")])
def test_message_history_blocks_parent_deletion(table, identifier, tmp_path):
    database = create_database(tmp_path)
    database.execute(
        """
        INSERT INTO agents (id, name, created_at)
        VALUES ('agent-1', 'project-agent', '2026-01-01T00:00:00Z')
        """
    )
    database.execute(
        """
        INSERT INTO channels (id, name, created_at)
        VALUES ('general', 'general', '2026-01-01T00:00:00Z')
        """
    )
    database.execute(
        """
        INSERT INTO messages (id, channel_id, agent_id, body, created_at)
        VALUES ('message-1', 'general', 'agent-1', 'hello', '2026-01-01T00:00:00Z')
        """
    )

    with pytest.raises(sqlite3.IntegrityError):
        database.execute(f"DELETE FROM {table} WHERE id = ?", (identifier,))
