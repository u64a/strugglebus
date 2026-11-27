from __future__ import annotations

import json
import inspect
import shutil
import sqlite3
import subprocess
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from mcp.server.auth.provider import AccessToken
from mcp.server.mcpserver.exceptions import ToolError

from strugglebus import app as app_module
from strugglebus import integration
from strugglebus import migrations
from strugglebus.access import AccessFreezeService
from strugglebus.auth import AgentService
from strugglebus.backup import create_verified_backup
from strugglebus.errors import (
    AgentAccessFrozenError,
    AgentNotFoundError,
    ChannelNotFoundError,
    DomainValidationError,
    MessageTooLargeError,
    MigrationError,
    PostRequestConflictError,
    ReplyNotFoundError,
    StorageError,
    UnknownMentionError,
)
from strugglebus.service import BoardService, DEFAULT_CHANNELS, MAX_SEQUENCE
from strugglebus.store import SQLiteStore
from strugglebus.roe import RoeService


NOW = datetime(2026, 9, 17, tzinfo=UTC)
REQUEST_ID = "d7c922a5-31bb-40b1-b1e5-9c987ac4a540"


def _board(store, *, clock=lambda: NOW):
    return BoardService(
        store,
        max_message_bytes=1024,
        max_metadata_bytes=1024,
        max_channels=100,
        clock=clock,
    )


@pytest.fixture
def bus(app_config):
    store = SQLiteStore(app_config.database_path, backup_dir=app_config.backup_dir)
    board = _board(store)
    board.initialize()
    # These tests pin the guarantees of a bus that keeps everything. What
    # retention may remove, and when, is covered in test_retention.py.
    store.set_retention(
        message_days=None, idle_agent_days=None, changed_by="test", changed_at=NOW,
    )
    agents = AgentService(store, clock=lambda: NOW)
    writer = agents.create_agent("writer-copilot").agent
    reader = agents.create_agent("reader-copilot").agent
    return store, board, agents, writer, reader


def _post(board, agent_id, **changes):
    values = dict(
        body="message @reader-copilot",
        kind="chat",
        reply_to=None,
        metadata={},
        request_id=REQUEST_ID,
    )
    channel = changes.pop("channel", "status")
    values.update(changes)
    return board.create_message(channel, agent_id=agent_id, **values)


def _board_state(store):
    tables = (
        "messages", "mentions", "subscriptions", "cursors", "mention_cursors",
        "sqlite_sequence", "messages_fts_data", "messages_fts_idx",
        "messages_fts_docsize", "messages_fts_config",
    )
    with sqlite3.connect(store.database_path) as database:
        return {
            table: database.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
            for table in tables
        }


def test_replay_preserves_every_board_effect_and_both_cursor_scopes(bus):
    store, board, _, writer, reader = bus
    board.subscribe("status", agent_id=reader.id)
    accepted = _post(board, writer.id)
    for include_stale in (False, True):
        board.catch_up(agent_id=reader.id, limit=10, include_stale=include_stale)
    before = _board_state(store)

    assert _post(board, writer.id) == accepted
    assert _board_state(store) == before
    with sqlite3.connect(store.database_path) as database:
        assert database.execute(
            "SELECT rowid FROM messages_fts WHERE messages_fts MATCH 'message'"
        ).fetchall() == [(accepted.seq,)]
    following = _post(board, writer.id, request_id=str(uuid.uuid4()))
    assert following.seq == accepted.seq + 1


def test_normalized_channels_and_canonical_metadata_replay(bus):
    store, board, _, writer, _ = bus
    board.create_channel("team-updates", purpose="", created_by=writer.id)
    metadata = {"b": {"z": "\u00e9", "a": 1}, "a": [1, True, 1.0]}
    accepted = _post(board, writer.id, channel="#Team_Updates", metadata=metadata)
    before = _board_state(store)
    reordered = json.loads('{"a":[1,true,1.0],"b":{"a":1,"z":"\\u00e9"}}')
    assert _post(board, writer.id, channel="team-updates", metadata=reordered) == accepted
    assert _board_state(store) == before


@pytest.mark.parametrize("change", [
    {"body": "message @reader-copilot "},
    {"body": "message @reader-copilot\n"},
    {"kind": "status"},
    {"reply_to": 99},
    {"metadata": {"different": True}},
    {"channel": "help"},
    {"channel": "missing-channel"},
])
def test_conflicts_do_not_change_accepted_state(bus, change):
    store, board, _, writer, _ = bus
    _post(board, writer.id)
    before = _board_state(store)
    with pytest.raises(PostRequestConflictError, match="^post request_id conflicts"):
        _post(board, writer.id, **change)
    assert _board_state(store) == before


@pytest.mark.parametrize(("first", "second"), [
    ({"v": 1}, {"v": True}),
    ({"v": 1}, {"v": 1.0}),
    ({"v": True}, {"v": 1.0}),
    ({"v": [1, 2]}, {"v": [2, 1]}),
    ({"v": -0.0}, {"v": 0.0}),
])
def test_metadata_equality_uses_canonical_json_not_python_equality(bus, first, second):
    _, board, _, writer, _ = bus
    _post(board, writer.id, metadata=first)
    with pytest.raises(PostRequestConflictError):
        _post(board, writer.id, metadata=second)


def test_body_unicode_is_not_normalized(bus):
    _, board, _, writer, _ = bus
    _post(board, writer.id, body="\u00e9")
    with pytest.raises(PostRequestConflictError):
        _post(board, writer.id, body="e\u0301")


def test_distinct_agents_keys_and_legacy_calls_remain_distinct(bus):
    store, board, _, writer, reader = bus
    messages = [
        _post(board, writer.id),
        _post(board, reader.id),
        _post(board, writer.id, request_id=str(uuid.uuid4())),
        _post(board, writer.id, request_id=None),
        _post(board, writer.id, request_id=None),
    ]
    assert len({message.id for message in messages}) == 5
    assert [message.seq for message in messages] == list(range(1, 6))
    assert len(_board_state(store)["messages"]) == 5


@pytest.mark.parametrize("conflicting", [False, True])
def test_concurrent_independent_stores_accept_one_intent(bus, conflicting):
    store, _, _, writer, _ = bus
    start = threading.Barrier(8)

    def attempt(index):
        independent = SQLiteStore(store.database_path, backup_dir=store.backup_dir)
        body = f"message {index % 2}" if conflicting else "message"
        start.wait(timeout=10)
        try:
            return _post(_board(independent), writer.id, body=body)
        except PostRequestConflictError:
            return None

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(attempt, range(8)))
    accepted = [result for result in results if result is not None]
    assert len(accepted) == (4 if conflicting else 8)
    assert all(message == accepted[0] for message in accepted)
    assert len(_board_state(store)["messages"]) == 1
    assert dict(_board_state(store)["sqlite_sequence"])["messages"] == accepted[0].seq


def test_no_ttl_and_revoked_historical_recipient_do_not_change_replay(bus):
    store, board, agents, writer, reader = bus
    accepted = _post(board, writer.id)
    agents.revoke_agent(reader.id)
    before = _board_state(store)
    later = _board(store, clock=lambda: NOW + timedelta(days=36500))
    assert _post(later, writer.id) == accepted
    assert _board_state(store) == before
    with pytest.raises(UnknownMentionError):
        _post(later, writer.id, request_id=str(uuid.uuid4()))


@pytest.mark.parametrize("hit", [False, True])
def test_freeze_denies_even_existing_key_before_lookup_then_thaw_recovers(bus, hit):
    store, board, _, writer, _ = bus
    accepted = _post(board, writer.id)
    access = AccessFreezeService(
        store, clock=lambda: NOW,
        transition_lock_directory=store.database_path.parent / "freeze-lock",
    )
    access.operator_freeze("test containment")
    before = _board_state(store)
    with pytest.raises(AgentAccessFrozenError):
        _post(board, writer.id, request_id=REQUEST_ID if hit else str(uuid.uuid4()))
    assert _board_state(store) == before
    access.operator_unfreeze("test recovery")
    assert _post(board, writer.id) == accepted


def test_retired_sender_and_unknown_sender_cannot_replay(bus):
    store, board, agents, writer, _ = bus
    _post(board, writer.id)
    agents.revoke_agent(writer.id)
    before = _board_state(store)
    for agent_id in (writer.id, str(uuid.uuid4())):
        with pytest.raises(AgentNotFoundError):
            _post(board, agent_id)
    assert _board_state(store) == before


def test_post_transaction_wins_racing_freeze_without_losing_retry_binding(bus, monkeypatch):
    store, board, _, writer, _ = bus
    entered = threading.Event()
    release = threading.Event()
    freeze_requested = threading.Event()
    original = store._transaction
    other = SQLiteStore(store.database_path, backup_dir=store.backup_dir)
    access = AccessFreezeService(
        other, clock=lambda: NOW,
        transition_lock_directory=store.database_path.parent / "freeze-race-lock",
    )

    @contextmanager
    def pause_writer():
        with original() as connection:
            entered.set()
            assert release.wait(timeout=10)
            yield connection

    def freeze():
        freeze_requested.set()
        return access.operator_freeze("racing containment")

    with monkeypatch.context() as patch, ThreadPoolExecutor(max_workers=2) as executor:
        patch.setattr(store, "_transaction", pause_writer)
        posting = executor.submit(_post, board, writer.id)
        assert entered.wait(timeout=10)
        freezing = executor.submit(freeze)
        assert freeze_requested.wait(timeout=10)
        release.set()
        accepted = posting.result(timeout=15)
        freezing.result(timeout=15)
    assert other.get_access_freeze().frozen is True
    with pytest.raises(AgentAccessFrozenError):
        _post(board, writer.id)
    access.operator_unfreeze("race recovery")
    assert _post(board, writer.id) == accepted
    assert len(_board_state(store)["messages"]) == 1


@pytest.mark.parametrize(("values", "error"), [
    ({"body": 7}, DomainValidationError),
    ({"body": ""}, DomainValidationError),
    ({"body": "\x00"}, DomainValidationError),
    ({"body": "\u00e9" * 513}, MessageTooLargeError),
    ({"kind": "invalid"}, DomainValidationError),
    ({"reply_to": True}, DomainValidationError),
    ({"reply_to": "1"}, DomainValidationError),
    ({"reply_to": 0}, DomainValidationError),
    ({"reply_to": MAX_SEQUENCE + 1}, DomainValidationError),
    ({"metadata": []}, DomainValidationError),
    ({"metadata": {"v": float("inf")}}, DomainValidationError),
    ({"metadata": {"v": float("nan")}}, DomainValidationError),
    ({"metadata": {"v": "x" * 1024}}, DomainValidationError),
    ({"request_id": ""}, DomainValidationError),
    ({"request_id": REQUEST_ID.upper()}, DomainValidationError),
    ({"request_id": REQUEST_ID.replace("-", "")}, DomainValidationError),
    ({"request_id": "z" + REQUEST_ID[1:]}, DomainValidationError),
    ({"request_id": 7}, DomainValidationError),
])
def test_invalid_static_input_never_replays_or_binds(bus, values, error):
    store, board, _, writer, _ = bus
    _post(board, writer.id)
    before = _board_state(store)
    with pytest.raises(error):
        _post(board, writer.id, **values)
    assert _board_state(store) == before


def test_exact_utf8_metadata_depth_and_mentions_limits(bus):
    store, board, agents, writer, reader = bus
    body = "\u00e9" * 512
    metadata = {"v": "x" * (1024 - len('{"v":""}'))}
    accepted = _post(board, writer.id, body=body, metadata=metadata)
    assert _post(board, writer.id, body=body, metadata=metadata) == accepted
    board.max_message_bytes = 1023
    with pytest.raises(MessageTooLargeError):
        _post(board, writer.id, body=body, metadata=metadata)
    board.max_message_bytes = 1024
    board.max_metadata_bytes = 1023
    with pytest.raises(DomainValidationError, match="1023 bytes"):
        _post(board, writer.id, body=body, metadata=metadata)
    board.max_metadata_bytes = 1024
    nested = None
    for _ in range(8):
        nested = {"v": nested}
    _post(board, writer.id, request_id=str(uuid.uuid4()), metadata=nested)
    with pytest.raises(DomainValidationError, match="nesting"):
        _post(board, writer.id, request_id=str(uuid.uuid4()), metadata={"v": nested})
    names = [reader.name]
    for index in range(31):
        names.append(agents.create_agent(f"mention-{index}").agent.name)
    body = " ".join(f"@{name}" for name in names)
    accepted = _post(board, writer.id, request_id=str(uuid.uuid4()), body=body)
    assert accepted.body == body
    before = _board_state(store)
    with pytest.raises(DomainValidationError, match="more than 32"):
        _post(board, writer.id, body=body + " @extra-agent")
    assert _board_state(store) == before


def test_new_key_keeps_channel_reply_and_mention_validation(bus):
    store, board, _, writer, _ = bus
    before = _board_state(store)
    for values, error in (
        ({"channel": "missing"}, ChannelNotFoundError),
        ({"reply_to": 999}, ReplyNotFoundError),
        ({"body": "@missing-agent"}, UnknownMentionError),
    ):
        with pytest.raises(error):
            _post(board, writer.id, **values)
    assert _board_state(store) == before
    parent = _post(board, writer.id, request_id=None)
    reply = _post(board, writer.id, reply_to=parent.seq)
    assert _post(board, writer.id, reply_to=parent.seq) == reply


@pytest.mark.parametrize("failure_after_mentions", [0, 1])
def test_message_fts_and_partial_mentions_rollback_with_key(bus, failure_after_mentions):
    store, board, _, writer, reader = bus
    before = _board_state(store)
    with sqlite3.connect(store.database_path) as database:
        database.execute(
            f"""
            CREATE TRIGGER injected_failure BEFORE INSERT ON mentions
            WHEN (SELECT COUNT(*) FROM mentions) = {failure_after_mentions}
            BEGIN SELECT RAISE(ABORT, 'injected test failure'); END
            """
        )
    body = f"message @{writer.name} @{reader.name}"
    with pytest.raises(StorageError):
        _post(board, writer.id, body=body)
    assert _board_state(store) == before
    with sqlite3.connect(store.database_path) as database:
        database.execute("DROP TRIGGER injected_failure")
    accepted = _post(board, writer.id, body=body)
    assert accepted.seq == 1
    assert _post(board, writer.id, body=body) == accepted
    assert len(_board_state(store)["mentions"]) == 2


def test_commit_failure_is_not_success_and_rolls_back(bus, monkeypatch):
    store, board, _, writer, _ = bus
    original = store._connection

    @contextmanager
    def fail_commit():
        with original() as connection:
            connection.set_authorizer(
                lambda action, argument, *_: (
                    sqlite3.SQLITE_DENY
                    if action == sqlite3.SQLITE_TRANSACTION and argument == "COMMIT"
                    else sqlite3.SQLITE_OK
                )
            )
            yield connection

    before = _board_state(store)
    with monkeypatch.context() as patch:
        patch.setattr(store, "_connection", fail_commit)
        with pytest.raises(StorageError):
            _post(board, writer.id)
    assert _board_state(store) == before
    accepted = _post(board, writer.id)
    with monkeypatch.context() as patch:
        patch.setattr(store, "_connection", fail_commit)
        with pytest.raises(StorageError):
            _post(board, writer.id)
    assert _post(board, writer.id) == accepted


def test_lost_readback_after_commit_can_replay_retained_result(bus, monkeypatch):
    store, board, _, writer, _ = bus
    original = store._connection

    @contextmanager
    def lose_readback():
        with original() as connection:
            connection.row_factory = lambda cursor, row: (
                None if cursor.description[0][0] == "seq" else sqlite3.Row(cursor, row)
            )
            yield connection

    with monkeypatch.context() as patch:
        patch.setattr(store, "_connection", lose_readback)
        with pytest.raises(StorageError, match="could not be read back"):
            _post(board, writer.id)
    assert len(_board_state(store)["messages"]) == 1
    assert _post(board, writer.id).seq == 1


def test_lock_timeout_cannot_serve_an_unguarded_cached_hit(bus):
    store, board, _, writer, _ = bus
    accepted = _post(board, writer.id)
    short = SQLiteStore(store.database_path, backup_dir=store.backup_dir, busy_timeout_ms=1)
    before = _board_state(store)
    with sqlite3.connect(store.database_path) as blocker:
        blocker.execute("BEGIN IMMEDIATE")
        with pytest.raises(StorageError):
            _post(_board(short), writer.id)
    assert _board_state(store) == before
    assert _post(board, writer.id) == accepted


@pytest.mark.parametrize("crash_point", ["before-commit", "after-commit"])
def test_process_exit_and_fresh_store_recover_atomic_acceptance(bus, crash_point):
    store, _, _, writer, _ = bus
    script = """
import os, sys
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from strugglebus.store import SQLiteStore
from strugglebus.service import BoardService
class CrashStore(SQLiteStore):
    @contextmanager
    def _transaction(self):
        with super()._transaction() as connection:
            yield connection
            if sys.argv[4] == 'before-commit':
                os._exit(0)
store = CrashStore(Path(sys.argv[1]), backup_dir=Path(sys.argv[2]))
board = BoardService(store, max_message_bytes=1024, max_metadata_bytes=1024,
                     max_channels=100, clock=lambda: datetime(2026,9,17,tzinfo=UTC))
board.create_message('status', agent_id=sys.argv[3], body='message @reader-copilot',
                     kind='chat', reply_to=None, metadata={}, request_id=sys.argv[5])
os._exit(0)
"""
    subprocess.run(
        [sys.executable, "-c", script, str(store.database_path), str(store.backup_dir),
         writer.id, crash_point, REQUEST_ID],
        check=True, capture_output=True, timeout=20,
    )
    assert len(_board_state(store)["messages"]) == (crash_point == "after-commit")
    fresh = SQLiteStore(store.database_path, backup_dir=store.backup_dir)
    fresh.initialize()
    accepted = _post(_board(fresh), writer.id)
    assert accepted.seq == 1
    assert _post(_board(fresh), writer.id) == accepted
    assert len(_board_state(store)["mentions"]) == 1


@pytest.mark.parametrize("statement", [
    "UPDATE messages SET post_request_id = NULL WHERE seq = ?",
    "UPDATE messages SET post_request_id = '00000000-0000-0000-0000-000000000000' WHERE seq = ?",
    "UPDATE messages SET body = 'changed' WHERE seq = ?",
    "UPDATE messages SET created_at = '2027-01-01T00:00:00Z' WHERE seq = ?",
    "UPDATE messages SET reply_to = NULL WHERE seq = ?",
    "UPDATE messages SET seq = seq + 100 WHERE seq = ?",
    "DELETE FROM messages WHERE seq = ?",
])
def test_keyed_rows_and_bindings_cannot_mutate(bus, statement):
    store, board, _, writer, _ = bus
    accepted = _post(board, writer.id)
    before = _board_state(store)
    with sqlite3.connect(store.database_path) as database:
        with pytest.raises(sqlite3.IntegrityError):
            database.execute(statement, (accepted.seq,))
    assert _board_state(store) == before


def test_legacy_rows_cannot_gain_a_key_and_reply_fk_cannot_rewrite_keyed_rows(bus):
    store, board, _, writer, _ = bus
    parent = _post(board, writer.id, request_id=None)
    with sqlite3.connect(store.database_path) as database:
        with pytest.raises(sqlite3.IntegrityError):
            database.execute(
                "UPDATE messages SET post_request_id = ? WHERE seq = ?", (REQUEST_ID, parent.seq)
            )
        database.execute("UPDATE messages SET body = 'legacy edit' WHERE seq = ?", (parent.seq,))
    reply = _post(board, writer.id, reply_to=parent.seq)
    before = _board_state(store)
    with sqlite3.connect(store.database_path) as database:
        database.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(sqlite3.IntegrityError):
            database.execute("DELETE FROM messages WHERE seq = ?", (parent.seq,))
    assert _board_state(store) == before
    assert _post(board, writer.id, reply_to=parent.seq) == reply


def test_lookup_uses_partial_unique_index_and_sql_constraints(bus, monkeypatch):
    store, board, _, writer, _ = bus
    accepted = _post(board, writer.id)
    lookups = []
    original = store._connection

    @contextmanager
    def record_lookup():
        with original() as connection:
            connection.set_trace_callback(
                lambda sql: lookups.append(sql) if "m.post_request_id = " in sql else None
            )
            yield connection

    with monkeypatch.context() as patch:
        patch.setattr(store, "_connection", record_lookup)
        assert _post(board, writer.id) == accepted
    assert len(lookups) == 1
    with sqlite3.connect(store.database_path) as database:
        plan = database.execute("EXPLAIN QUERY PLAN " + lookups[0]).fetchall()
        assert any("idx_messages_post_request" in row[-1] for row in plan)
        assert all("SCAN m" not in row[-1] for row in plan)
        for key in (REQUEST_ID, "bad", REQUEST_ID.upper(), "\u00e9" + REQUEST_ID[1:], REQUEST_ID + "\x00"):
            with pytest.raises(sqlite3.IntegrityError):
                database.execute(
                    """
                    INSERT INTO messages
                        (id, channel_id, agent_id, body, kind, meta, created_at, post_request_id)
                    SELECT ?, channel_id, agent_id, body, kind, meta, created_at, ?
                    FROM messages WHERE seq = ?
                    """,
                    (str(uuid.uuid4()), key, accepted.seq),
                )


def test_verified_backup_containing_key_restores_replay(bus, tmp_path):
    store, board, _, writer, _ = bus
    accepted = _post(board, writer.id)
    backup = create_verified_backup(store.database_path, store.backup_dir)
    restored_path = tmp_path / "restored.db"
    shutil.copy2(backup, restored_path)
    restored = SQLiteStore(restored_path, backup_dir=tmp_path / "restored-backups")
    restored.initialize()
    before = _board_state(restored)
    assert _post(_board(restored), writer.id) == accepted
    assert _board_state(restored) == before


def _historical_state(database):
    tables = database.execute(
        "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name"
    ).fetchall()
    result = {}
    for (name,) in tables:
        quoted = '"' + name.replace('"', '""') + '"'
        cursor = database.execute(f"SELECT * FROM {quoted} ORDER BY 1")
        columns = tuple(item[0] for item in cursor.description)
        result[name] = (columns, cursor.fetchall())
    return result


def _legacy_database(tmp_path, frozen):
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path, isolation_level=None) as database:
        assert migrations.apply_migrations(
            database, migrations.load_packaged_migrations()[:15]
        ) == 15
    store = SQLiteStore(path, backup_dir=tmp_path / "legacy-backups")
    store.ensure_default_channels(DEFAULT_CHANNELS, created_at=NOW)
    writer = AgentService(store).create_agent("legacy-writer").agent
    board = _board(store)
    board.subscribe("status", agent_id=writer.id)
    with sqlite3.connect(path) as database:
        database.execute(
            """
            INSERT INTO messages (id, channel_id, agent_id, body, meta, created_at)
            SELECT ?, id, ?, 'legacy message', '{}', ? FROM channels WHERE name = 'status'
            """,
            (str(uuid.uuid4()), writer.id, NOW.isoformat()),
        )
        database.execute("INSERT INTO mentions VALUES (1, ?)", (writer.id,))
    board.catch_up(agent_id=writer.id, limit=10)
    board.catch_up(agent_id=writer.id, limit=10, include_stale=True)
    if frozen:
        store.set_access_freeze(
            frozen=True, reason="legacy containment", changed_at=NOW,
            actor_type="local-admin", actor_id="local-cli",
        )
    return store


@pytest.mark.parametrize("frozen", [False, True])
def test_schema15_migration_preserves_every_historical_table_and_backup(tmp_path, frozen):
    store = _legacy_database(tmp_path, frozen)
    with sqlite3.connect(store.database_path) as database:
        before = _historical_state(database)
    assert store.initialize() == 25
    with sqlite3.connect(store.database_path) as database:
        after = _historical_state(database)
        assert set(before) <= set(after)
        for table, (columns, rows) in before.items():
            new_columns, new_rows = after[table]
            assert new_columns[:len(columns)] == columns
            if table == "agents":
                name_index = columns.index("name")
                new_rows = [
                    row for row in new_rows
                    if row[name_index] not in {"system:strugglebus-maintenance", "human:operator"}
                ]
            assert [row[:len(columns)] for row in new_rows] == rows
        assert database.execute("SELECT post_request_id FROM messages").fetchall() == [(None,)]
        assert database.execute("PRAGMA foreign_key_check").fetchall() == []
        assert database.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    backups = list(store.backup_dir.glob("*.backup"))
    assert len(backups) == 1
    with sqlite3.connect(backups[0]) as database:
        assert database.execute("PRAGMA user_version").fetchone() == (15,)
        assert _historical_state(database) == before
    assert store.get_access_freeze().frozen is frozen


def test_schema16_failure_rolls_back_and_unknown_or_missing_guards_fail_startup(tmp_path, monkeypatch):
    store = _legacy_database(tmp_path, True)
    original = migrations.load_packaged_migrations()
    broken = (*original[:-1], replace(original[-1], sql=original[-1].sql + "\nINVALID SQL;"))
    with monkeypatch.context() as patch:
        patch.setattr(migrations, "load_packaged_migrations", lambda: broken)
        with pytest.raises(MigrationError):
            store.initialize()
    with sqlite3.connect(store.database_path) as database:
        assert database.execute("PRAGMA user_version").fetchone() == (15,)
        assert "post_request_id" not in {
            row[1] for row in database.execute("PRAGMA table_info(messages)")
        }
    assert store.initialize() == 25
    with sqlite3.connect(store.database_path) as database:
        database.execute("PRAGMA user_version = 26")
    with pytest.raises(MigrationError):
        store.initialize()
    with sqlite3.connect(store.database_path) as database:
        database.execute("PRAGMA user_version = 17")
        database.execute("DROP TRIGGER messages_keyed_immutable")
    with pytest.raises(MigrationError, match="migration starting at version 18 failed"):
        store.initialize()


def test_retry_guide_enforces_its_exact_serialized_response_limit(app_config, monkeypatch):
    guide = integration.build_integration_guide(app_config)
    size = len(json.dumps(
        guide.model_dump(mode="json"), ensure_ascii=True,
        separators=(",", ":"), sort_keys=True,
    ).encode("utf-8"))
    monkeypatch.setattr(integration, "MAX_GUIDE_RESPONSE_BYTES", size)
    assert integration.build_integration_guide(app_config) == guide
    monkeypatch.setattr(integration, "MAX_GUIDE_RESPONSE_BYTES", size - 1)
    with pytest.raises(RuntimeError, match="fixed response bound"):
        integration.build_integration_guide(app_config)


@pytest.mark.asyncio
@pytest.mark.parametrize("context", [
    "absent", "wrong-subject", "missing-credential", "frozen", "retired",
])
async def test_mcp_operational_callback_rechecks_context_and_current_authority(
    bus, app_config, monkeypatch, context,
):
    store, board, agents, writer, _ = bus
    _post(board, writer.id)
    roe = RoeService(store, enforcement_mode="observe")
    roe.initialize()
    server = app_module._create_mcp_server(agents, board, roe, app_config)
    tool = server._tool_manager.get_tool("post")
    assert tool is not None
    operation = inspect.getclosurevars(tool.fn).nonlocals["run_operational_board_operation"]
    credential_id = store.get_live_credential_id(writer.id)
    token = AccessToken(
        token="synthetic-unit-context", client_id=writer.id, subject=writer.id,
        scopes=[app_module.MCP_SCOPE], claims={"credential_id": credential_id},
    )
    if context == "absent":
        token = None
    elif context == "wrong-subject":
        token = token.model_copy(update={"subject": str(uuid.uuid4())})
    elif context == "missing-credential":
        token = token.model_copy(update={"claims": {}})
    elif context == "frozen":
        store.set_access_freeze(
            frozen=True, reason="callback race", changed_at=NOW,
            actor_type="local-admin", actor_id="local-cli",
        )
    else:
        agents.revoke_agent(writer.id)
    monkeypatch.setattr(app_module, "get_access_token", lambda: token)
    before = _board_state(store)
    expected = "agent access is frozen" if context == "frozen" else "identity is unavailable"
    with pytest.raises(ToolError, match=expected):
        await operation(writer.id, _post, board, writer.id)
    assert _board_state(store) == before
