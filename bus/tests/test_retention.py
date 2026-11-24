"""Retention: old messages are removed and silent agents blocked, by setting."""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from strugglebus.access import AccessFreezeService
from strugglebus.app import create_app
from strugglebus.auth import AgentService
from strugglebus.errors import DomainValidationError
from strugglebus.migrations import apply_migrations, load_packaged_migrations
from strugglebus.models import LifecycleActor
from strugglebus.retention import RetentionSweeper
from strugglebus.service import BoardService
from strugglebus.store import SQLiteStore
from test_operator_dashboard import PASSWORD, csrf, login, verifier  # noqa: F401 - fixture

# The delete guard in the database compares against the real clock, so these
# tests place their old messages relative to it.
NOW = datetime.now(UTC)
OLD = NOW - timedelta(days=90)
RECENT = NOW - timedelta(days=5)
ORIGIN = {"Origin": "https://bus.lan"}


def _board(store: SQLiteStore, when: datetime) -> BoardService:
    return BoardService(
        store, max_message_bytes=1024, max_metadata_bytes=1024, max_channels=100,
        clock=lambda: when,
    )


def _post(store: SQLiteStore, agent_id: str, when: datetime, **changes):
    values = dict(body="hello", kind="chat", reply_to=None, metadata={}, request_id=None)
    values.update(changes)
    return _board(store, when).create_message("status", agent_id=agent_id, **values)


def _count(store: SQLiteStore, table: str = "messages") -> int:
    with sqlite3.connect(store.database_path) as database:
        return database.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


@pytest.fixture
def bus(app_config):
    store = SQLiteStore(app_config.database_path, backup_dir=app_config.backup_dir)
    _board(store, OLD).initialize()
    writer = AgentService(store, clock=lambda: OLD).create_agent("writer-copilot").agent
    return store, writer


def test_a_new_install_starts_with_sixty_days_for_both(bus):
    store, _ = bus
    settings = store.get_retention()
    assert (settings.message_days, settings.idle_agent_days) == (60, 60)
    assert settings.changed_by == "system:new-install"
    assert settings.last_run_at is None


@pytest.mark.parametrize("row", [
    "INSERT INTO agents (id, name, created_at) VALUES ('a', 'host-one', '2026-01-01T00:00:00Z')",
    None,
])
def test_an_upgraded_bus_starts_with_retention_off(tmp_path, row):
    database_path = tmp_path / "existing.db"
    with sqlite3.connect(database_path, isolation_level=None) as database:
        assert apply_migrations(database, load_packaged_migrations()[:22]) == 22
        database.execute(
            "INSERT INTO agents (id, name, created_at) "
            "VALUES ('w', 'writer', '2026-01-01T00:00:00Z')"
        )
        if row is not None:
            database.execute(row)
        else:
            database.execute(
                "INSERT INTO channels (id, name, created_at) "
                "VALUES ('c', 'work', '2026-01-01T00:00:00Z')"
            )
            database.execute(
                "INSERT INTO messages (id, channel_id, agent_id, body, created_at) "
                "VALUES ('m', 'c', 'w', 'history', '2026-01-01T00:00:00Z')"
            )
    store = SQLiteStore(database_path, backup_dir=tmp_path / "backups")

    assert store.initialize() == 24

    settings = store.get_retention()
    assert (settings.message_days, settings.idle_agent_days) == (None, None)
    assert settings.changed_by == "system:upgrade"
    assert store.remove_expired_messages(now=NOW) == 0
    assert store.block_idle_agents(now=NOW) == ()
    assert _count(store) == (0 if row is not None else 1)


def test_old_messages_are_removed_and_recent_ones_kept(bus):
    store, writer = bus
    plain = _post(store, writer.id, OLD, body="old plain @writer-copilot")
    keyed = _post(store, writer.id, OLD, request_id=str(uuid.uuid4()), body="old keyed")
    task = _post(
        store, writer.id, OLD, kind="task",
        metadata={"task": {"schema": "example.task/1", "action": "build"}},
    )
    store.claim_message(message_seq=task.seq, agent_id=writer.id, claimed_at=OLD)
    reply = _post(
        store, writer.id, RECENT, reply_to=keyed.seq, request_id=str(uuid.uuid4()),
        body="recent reply",
    )
    fresh = _post(store, writer.id, NOW, body="fresh")

    assert store.remove_expired_messages(now=NOW) == 3

    with sqlite3.connect(store.database_path) as database:
        assert database.execute(
            "SELECT seq, reply_to FROM messages ORDER BY seq"
        ).fetchall() == [(reply.seq, None), (fresh.seq, None)]
        assert database.execute("SELECT COUNT(*) FROM message_claims").fetchone() == (0,)
        assert database.execute("SELECT COUNT(*) FROM mentions").fetchone() == (0,)
        assert database.execute(
            "SELECT rowid FROM messages_fts WHERE messages_fts MATCH 'old'"
        ).fetchall() == []
    assert plain.seq < reply.seq
    assert store.remove_expired_messages(now=NOW) == 0
    # New posts continue the sequence; nothing reuses a removed number.
    assert _post(store, writer.id, NOW).seq == fresh.seq + 1


def test_removal_works_in_batches(bus):
    store, writer = bus
    for _ in range(5):
        _post(store, writer.id, OLD)
    _post(store, writer.id, NOW)

    assert store.remove_expired_messages(now=NOW, batch_size=2) == 2
    assert store.remove_expired_messages(now=NOW, batch_size=2) == 2
    assert store.remove_expired_messages(now=NOW, batch_size=2) == 1
    assert _count(store) == 1


def test_the_database_refuses_to_delete_a_keyed_message_inside_the_period(bus):
    store, writer = bus
    young = _post(store, writer.id, RECENT, request_id=str(uuid.uuid4()))
    old = _post(store, writer.id, RECENT, request_id=str(uuid.uuid4()))
    with sqlite3.connect(store.database_path) as database:
        with pytest.raises(sqlite3.IntegrityError, match="keyed message cannot be deleted"):
            database.execute("DELETE FROM messages WHERE seq = ?", (young.seq,))
        with pytest.raises(sqlite3.IntegrityError, match="keyed message is immutable"):
            database.execute("UPDATE messages SET body = 'x' WHERE seq = ?", (old.seq,))
        with pytest.raises(sqlite3.IntegrityError, match="retention settings"):
            database.execute("DELETE FROM retention_settings")
        with pytest.raises(sqlite3.IntegrityError):
            database.execute("UPDATE retention_settings SET message_days = 1")
    assert _count(store) == 2


def test_nothing_is_removed_or_blocked_while_off_or_frozen(bus):
    store, writer = bus
    _post(store, writer.id, OLD)
    access = AccessFreezeService(
        store, clock=lambda: NOW,
        transition_lock_directory=store.database_path.parent / "freeze-lock",
    )
    access.operator_freeze("incident")
    assert store.remove_expired_messages(now=NOW) == 0
    assert store.block_idle_agents(now=NOW) == ()
    access.operator_unfreeze("recovered")

    store.set_retention(
        message_days=None, idle_agent_days=None, changed_by="test", changed_at=NOW,
    )
    assert store.remove_expired_messages(now=NOW) == 0
    assert store.block_idle_agents(now=NOW) == ()
    assert _count(store) == 1
    assert store.get_managed_agent(writer.id).state == "enabled"


def test_silent_agents_are_blocked_and_can_be_unblocked(bus):
    store, silent = bus
    recent = AgentService(store, clock=lambda: RECENT).create_agent("recent-copilot").agent

    assert store.block_idle_agents(now=NOW) == ("writer-copilot",)

    blocked = store.get_managed_agent(silent.id)
    assert blocked.state == "blocked"
    assert store.get_managed_agent(recent.id).state == "enabled"
    event = store.list_agent_lifecycle_events(silent.id)[-1]
    assert (event.action, event.actor_type, event.actor_id, event.reason) == (
        "block", "system", "system:retention", "no activity for 60 days",
    )
    # The built-in authors are never touched, and a second pass finds nothing.
    assert store.block_idle_agents(now=NOW) == ()

    store.transition_agent(
        silent.id, action="unblock", expected_credential_epoch=blocked.credential_epoch,
        request_id=str(uuid.uuid4()), reason="back at work",
        actor=LifecycleActor("local-admin", "test-operator", lambda: None), changed_at=NOW,
    )
    assert store.get_managed_agent(silent.id).state == "enabled"
    # Just unblocked: it has the full period to come back before the next block.
    assert store.block_idle_agents(now=NOW + timedelta(days=30)) == ()
    assert store.block_idle_agents(now=NOW + timedelta(days=61)) == (
        "recent-copilot", "writer-copilot",
    )


@pytest.mark.parametrize("values", [
    {"message_days": 6}, {"message_days": 3651}, {"idle_agent_days": 0},
    {"message_days": True}, {"idle_agent_days": "60"},
])
def test_periods_outside_seven_days_to_ten_years_are_refused(bus, values):
    store, _ = bus
    settings = {"message_days": 60, "idle_agent_days": 60, **values}
    with pytest.raises(DomainValidationError):
        store.set_retention(**settings, changed_by="test", changed_at=NOW)
    assert store.get_retention().message_days == 60


def test_a_clean_up_logs_what_it_did_and_records_the_run(bus):
    store, writer = bus
    for _ in range(3):
        _post(store, writer.id, OLD)
    lines: list[str] = []
    sweeper = RetentionSweeper(store, clock=lambda: NOW, emit=lines.append, batch_size=2)

    run = sweeper.run_once()

    assert (run.removed_messages, run.blocked_agents) == (3, ("writer-copilot",))
    assert lines == [
        "removed 3 messages older than 60 days",
        "blocked 1 agents with no activity for 60 days: writer-copilot",
    ]
    settings = store.get_retention()
    assert settings.last_run_at == NOW
    assert (settings.last_removed_messages, settings.last_blocked_agents) == (3, 1)

    lines.clear()
    assert sweeper.run_once().removed_messages == 0
    assert lines == []
    settings = store.get_retention()
    assert (settings.last_removed_messages, settings.total_removed_messages) == (0, 3)
    assert settings.total_blocked_agents == 1


@pytest.fixture
def console(app_config, monkeypatch, verifier):  # noqa: F811
    monkeypatch.setattr("strugglebus.operator_auth.load_password_verifier", lambda path: verifier)
    with TestClient(
        create_app(config=app_config), base_url="https://bus.lan", follow_redirects=False,
    ) as client:
        yield client


def test_the_console_shows_and_changes_the_setting(console, capsys):
    assert console.get("/operator/retention").status_code == 303
    login(console)
    assert "/operator/retention" in console.get("/system").text

    page = console.get("/operator/retention")
    assert page.status_code == 200
    assert "Messages are kept for</dt><dd>60 days" in page.text
    assert "Silent agents are blocked after</dt><dd>60 days" in page.text
    assert 'name="message_days" type="number" min="7" max="3650" value="60"' in page.text

    saved = console.post(
        "/operator/retention", headers=ORIGIN,
        data={"csrf": csrf(page), "message_days": "30", "idle_agent_days": "",
              "password": PASSWORD},
    )
    assert saved.status_code == 303 and saved.headers["location"] == "/operator/retention"
    store = console.app.state.agent_service.store
    settings = store.get_retention()
    assert (settings.message_days, settings.idle_agent_days) == (30, None)
    assert settings.changed_by.startswith("operator:owner:")
    assert (
        "strugglebus-retention: setting changed by operator:owner:" in capsys.readouterr().out
    )
    page = console.get("/operator/retention")
    assert "Messages are kept for</dt><dd>30 days" in page.text
    assert "Silent agents are blocked after</dt><dd>Never" in page.text

    off = console.post(
        "/operator/retention", headers=ORIGIN,
        data={"csrf": csrf(page), "message_days": "", "idle_agent_days": "",
              "password": PASSWORD},
    )
    assert off.status_code == 303
    assert "Retention is off on this bus" in console.get("/operator/retention").text


@pytest.mark.parametrize("fields", [
    {"message_days": "3", "password": PASSWORD},
    {"message_days": "sixty", "password": PASSWORD},
    {"message_days": "-60", "password": PASSWORD},
    {"idle_agent_days": "99999", "password": PASSWORD},
    {"message_days": "30", "password": "not the password"},
    {"message_days": "30"},
])
def test_the_console_refuses_bad_periods_and_a_wrong_password(console, fields):
    login(console)
    page = console.get("/operator/retention")

    response = console.post(
        "/operator/retention", headers=ORIGIN, data={"csrf": csrf(page), **fields},
    )

    assert response.status_code in {400, 403}
    settings = console.app.state.agent_service.store.get_retention()
    assert (settings.message_days, settings.idle_agent_days) == (60, 60)
