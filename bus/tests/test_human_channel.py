from __future__ import annotations

import re
import sqlite3
import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from operator_test_support import operator_client
from strugglebus.access import AccessFreezeService
from strugglebus.app import create_app
from strugglebus.auth import AgentService
from strugglebus.errors import (
    AgentAccessFrozenError,
    AgentNotFoundError,
    ConfigurationError,
    DomainValidationError,
    PostRequestConflictError,
    ReplyNotFoundError,
)
from strugglebus.migrations import LATEST_SCHEMA_VERSION, apply_migrations, load_packaged_migrations
from strugglebus.service import BoardService
from strugglebus.store import HUMAN_OPERATOR_AGENT_ID, SQLiteStore

NOW = datetime(2026, 10, 4, tzinfo=UTC)


def _services(config):
    store = SQLiteStore(config.database_path, backup_dir=config.backup_dir)
    agents = AgentService(store, clock=lambda: NOW)
    board = BoardService(
        store, max_message_bytes=1024, max_metadata_bytes=1024, max_channels=100,
        clock=lambda: NOW,
    )
    board.initialize()
    return store, agents, board


def _human(board, body="Can someone check the dev bus?", **changes):
    values = dict(body=body, kind="question", reply_to=None, request_id=str(uuid.uuid4()))
    values.update(changes)
    return board.create_human_message(**values)


def test_operator_and_agents_converse_only_in_humans(app_config):
    store, agents, board = _services(app_config)
    agent = agents.create_agent("helper-copilot").agent
    question = _human(board, body="@helper-copilot are you there?")
    assert (question.channel, question.agent_name) == ("humans", "human:operator")
    answer = board.create_message(
        "humans", agent_id=agent.id, body="Yes - what do you need?", kind="answer",
        reply_to=question.seq, metadata={},
    )
    follow_up = _human(board, body="Thanks", kind="chat", reply_to=answer.seq)
    assert [m.seq for m in board.read_replies(question.seq)] == [answer.seq]
    assert follow_up.reply_to == answer.seq
    assert [m.seq for m in board.list_messages("humans", since=0, limit=10)] == [
        question.seq, answer.seq, follow_up.seq,
    ]
    status = board.create_message(
        "status", agent_id=agent.id, body="elsewhere", kind="status", reply_to=None, metadata={},
    )
    with pytest.raises(ReplyNotFoundError):
        _human(board, reply_to=status.seq)


def test_human_author_is_not_an_agent(app_config):
    store, agents, board = _services(app_config)
    assert all(agent.id != HUMAN_OPERATOR_AGENT_ID for agent in board.list_agents())
    with pytest.raises(AgentNotFoundError):
        agents.get_managed_agent(HUMAN_OPERATOR_AGENT_ID, require_access=False)
    with pytest.raises(ConfigurationError):
        agents.create_agent("human:operator")
    snapshot = board.dashboard_snapshot(channel_name=None, agent_name=None, before=None, limit=10)
    assert snapshot.counts.active_agents == 0
    with sqlite3.connect(app_config.database_path) as database:
        for statement, values in (
            ("UPDATE agents SET blocked_at = ? WHERE id = ?", (NOW.isoformat(), HUMAN_OPERATOR_AGENT_ID)),
            ("INSERT INTO messages (id, channel_id, agent_id, body, kind, meta, created_at) "
             "VALUES (?, 'status', ?, 'x', 'chat', '{}', ?)", (str(uuid.uuid4()), HUMAN_OPERATOR_AGENT_ID, NOW.isoformat())),
        ):
            with pytest.raises(sqlite3.IntegrityError):
                database.execute(statement, values)
        tables = {row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    assert {
        "human_operator_agent_no_credential", "human_operator_agent_no_reconnect",
    } <= tables


def test_human_posts_are_bounded_idempotent_and_survive_freeze(app_config):
    store, agents, board = _services(app_config)
    with pytest.raises(DomainValidationError):
        _human(board, body="x" * 1025)
    with pytest.raises(DomainValidationError):
        _human(board, kind="announce")
    with pytest.raises(DomainValidationError):
        _human(board, request_id="not-a-uuid")
    request_id = str(uuid.uuid4())
    first = _human(board, request_id=request_id)
    assert _human(board, request_id=request_id).seq == first.seq
    with pytest.raises(PostRequestConflictError):
        _human(board, body="different", request_id=request_id)
    agent = agents.create_agent("frozen-copilot").agent
    AccessFreezeService(
        store, clock=lambda: NOW,
        transition_lock_directory=app_config.database_path.parent / "freeze-lock",
    ).operator_freeze("test containment")
    assert _human(board, body="still here").channel == "humans"
    with pytest.raises(AgentAccessFrozenError):
        board.create_message(
            "humans", agent_id=agent.id, body="denied", kind="chat", reply_to=None, metadata={},
        )


def test_schema_nineteen_upgrades_an_existing_database(tmp_path):
    database_path = tmp_path / "schema-eighteen.db"
    with sqlite3.connect(database_path, isolation_level=None) as database:
        assert apply_migrations(database, load_packaged_migrations()[:18]) == 18
        database.execute(
            "INSERT INTO agents (id, name, created_at) VALUES ('existing', 'operator', '2026-01-01T00:00:00Z')",
        )
    store = SQLiteStore(database_path, backup_dir=tmp_path / "backups")
    assert store.initialize() == LATEST_SCHEMA_VERSION == 25
    assert list((tmp_path / "backups").iterdir())
    with sqlite3.connect(database_path) as database:
        assert database.execute("SELECT name FROM agents WHERE id = 'existing'").fetchone() == ("operator",)
        assert database.execute(
            "SELECT name, host FROM agents WHERE id = ?", (HUMAN_OPERATOR_AGENT_ID,),
        ).fetchone() == ("human:operator", "operator-console")


def _application(app_config):
    store, agents, board = _services(app_config)
    return create_app(config=app_config, agent_service=agents, board_service=board), agents, board


def _form(page):
    return {
        name: re.search(rf'name="{name}" value="([^"]+)"', page.text)[1]
        for name in ("csrf", "request_id")
    }


def test_operator_web_posts_and_renders_humans_conversation(app_config):
    application, agents, board = _application(app_config)
    agent = agents.create_agent("helper-copilot").agent
    asked = board.create_message(
        "humans", agent_id=agent.id, body="<b>Which VLAN?</b>", kind="question",
        reply_to=None, metadata={},
    )
    with operator_client(application) as client:
        page = client.get("/humans")
        assert page.status_code == 200
        assert "&lt;b&gt;Which VLAN?&lt;/b&gt;" in page.text and "<b>Which" not in page.text
        fields = _form(page) | {"body": "Main u64a network", "kind": "answer", "reply_to": str(asked.seq)}
        origin = {"Origin": "https://bus.lan"}
        posted = client.post("/humans", data=fields, headers=origin)
        assert posted.status_code == 303, posted.text
        assert client.post("/humans", data=fields, headers=origin).headers["location"] == posted.headers["location"]
        replies = board.read_replies(asked.seq)
        assert [(m.agent_name, m.body) for m in replies] == [("human:operator", "Main u64a network")]
        assert "human:operator" in client.get("/humans").text
        bad_csrf = client.post("/humans", data=fields | {"csrf": "wrong"}, headers=origin)
        assert bad_csrf.status_code in {400, 403}
        too_big = client.post(
            "/humans", data=_form(client.get("/humans")) | {"body": "x" * 2000, "kind": "chat"},
            headers=origin,
        )
        assert too_big.status_code in {413, 422}
        assert client.get("/humans?x=1").status_code == 422
        replying = client.get("/humans?reply=1")
        assert replying.status_code == 200 and 'value="1"' in replying.text
        assert client.get("/humans?reply=abc").status_code == 422
        assert client.get("/humans?reply=0").status_code == 422
    assert len(board.list_messages("humans", since=0, limit=10)) == 2


def test_anonymous_humans_post_is_rejected_before_any_write(app_config):
    with operator_client(_application(app_config)[0]):
        pass
    application, _, board = _application(app_config)
    with TestClient(application, base_url="https://bus.lan", follow_redirects=False) as client:
        response = client.post(
            "/humans", data={"body": "spoof", "kind": "chat", "request_id": str(uuid.uuid4())},
            headers={"Origin": "https://bus.lan"},
        )
    assert response.status_code in {401, 403, 503}
    assert board.list_messages("humans", since=0, limit=10) == ()
