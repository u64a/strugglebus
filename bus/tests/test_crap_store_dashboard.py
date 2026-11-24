"""Dashboard read models, exercised directly against the store."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from strugglebus.auth import AgentService
from strugglebus.config import AppConfig
from strugglebus.models import LifecycleActor
from strugglebus.service import BoardService
from strugglebus.store import SQLiteStore

_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def services(app_config: AppConfig) -> tuple[SQLiteStore, AgentService, BoardService]:
    store = SQLiteStore(
        app_config.database_path,
        backup_dir=app_config.backup_dir,
        busy_timeout_ms=app_config.sqlite_busy_timeout_ms,
    )
    board = BoardService(
        store,
        max_message_bytes=app_config.max_message_bytes,
        max_metadata_bytes=app_config.max_metadata_bytes,
        max_channels=app_config.max_channels,
        clock=lambda: _NOW,
    )
    board.initialize()
    return store, AgentService(store, clock=lambda: _NOW), board


def _post(board: BoardService, agent_id: str, body: str, **options: object):
    return board.create_message(
        options.pop("channel", "status"),
        agent_id=agent_id,
        body=body,
        kind="chat",
        reply_to=options.pop("reply_to", None),
        metadata={},
    )


def _registered(names: tuple[str, ...]) -> list[str]:
    """Drop the built-in credential-less authors, whose names carry a colon."""

    return [name for name in names if ":" not in name]


def test_agent_roster_pages_by_name_and_omits_retired_identities(services) -> None:
    store, agents, _ = services
    created = {
        name: agents.create_agent(name)
        for name in ("delta-copilot", "alpha-copilot", "charlie-copilot", "bravo-copilot")
    }
    agents.revoke_agent(created["charlie-copilot"].agent.id, request_id=str(uuid.uuid4()))
    agents.transition_agent(
        created["bravo-copilot"].agent.id,
        action="block",
        expected_credential_epoch=created["bravo-copilot"].agent.credential_epoch,
        request_id=str(uuid.uuid4()),
        reason="containment",
        actor=LifecycleActor("local-admin", "tester"),
    )
    assert agents.authorize(created["alpha-copilot"].api_key) is not None

    first = store.dashboard_agents(after=None, limit=2)
    rest = store.dashboard_agents(after="bravo-copilot", limit=50)
    exact = store.dashboard_agents(after="bravo-copilot", limit=len(rest.agents))

    assert [agent.name for agent in first.agents] == ["alpha-copilot", "bravo-copilot"]
    assert first.has_more is True
    assert first.agents[0].last_seen_at == _NOW
    assert first.agents[0].created_at == _NOW
    assert first.agents[1].last_seen_at is None
    assert _registered(tuple(agent.name for agent in rest.agents)) == ["delta-copilot"]
    assert rest.has_more is False
    assert exact.agents == rest.agents
    assert exact.has_more is False
    assert store.dashboard_agents(after="zulu-copilot", limit=5).agents == ()


def test_snapshot_counts_agents_by_state_and_ignores_builtin_authors(services) -> None:
    store, agents, board = services
    active = agents.create_agent("active-copilot").agent
    blocked = agents.create_agent("blocked-copilot").agent
    retired = agents.create_agent("retired-copilot").agent
    board.subscribe("status", agent_id=active.id)
    board.subscribe("status", agent_id=blocked.id)
    agents.transition_agent(
        blocked.id, action="block", expected_credential_epoch=blocked.credential_epoch,
        request_id=str(uuid.uuid4()), reason="containment",
        actor=LifecycleActor("local-admin", "tester"),
    )
    agents.revoke_agent(retired.id, request_id=str(uuid.uuid4()))

    empty = store.dashboard_snapshot(
        channel_name=None, agent_name=None, before=None, limit=10,
    )

    assert (
        empty.counts.active_agents,
        empty.counts.blocked_agents,
        empty.counts.retired_agents,
        empty.counts.subscriptions,
    ) == (1, 1, 1, 1)
    assert empty.counts.channels == len(board.list_channels())
    assert empty.messages == ()
    assert empty.parent_messages == ()
    assert empty.has_older is False
    assert empty.board_has_messages is False


def test_snapshot_filters_pages_and_fetches_only_off_page_parents(services) -> None:
    store, agents, board = services
    author = agents.create_agent("author-copilot").agent
    other = agents.create_agent("other-copilot").agent
    root = _post(board, author.id, "root")
    reply = _post(board, other.id, "reply", reply_to=root.seq)
    nested = _post(board, author.id, "nested", reply_to=reply.seq)
    elsewhere = _post(board, author.id, "elsewhere", channel="help")

    newest = store.dashboard_snapshot(
        channel_name="status", agent_name=None, before=None, limit=1,
    )
    older = store.dashboard_snapshot(
        channel_name="status", agent_name=None, before=nested.seq, limit=5,
    )
    by_author = store.dashboard_snapshot(
        channel_name=None, agent_name="author-copilot", before=None, limit=5,
    )
    both = store.dashboard_snapshot(
        channel_name="status", agent_name="other-copilot", before=nested.seq, limit=5,
    )

    assert [message.seq for message in newest.messages] == [nested.seq]
    assert [message.seq for message in newest.parent_messages] == [reply.seq]
    assert newest.has_older is True
    assert newest.board_has_messages is True
    # Both the reply and its parent are on the page, so no parent is fetched.
    assert [message.seq for message in older.messages] == [reply.seq, root.seq]
    assert older.parent_messages == ()
    assert older.has_older is False
    assert [message.seq for message in by_author.messages] == [
        elsewhere.seq, nested.seq, root.seq,
    ]
    assert [message.seq for message in by_author.parent_messages] == [reply.seq]
    assert [message.seq for message in both.messages] == [reply.seq]
    assert [message.seq for message in both.parent_messages] == [root.seq]


@pytest.mark.parametrize(
    ("channel_name", "agent_name"),
    [("no-such-channel", None), (None, "no-such-agent"), ("status", "no-such-agent")],
)
def test_snapshot_filter_naming_nothing_shows_no_messages_but_keeps_counts(
    services, channel_name: str | None, agent_name: str | None,
) -> None:
    store, agents, board = services
    author = agents.create_agent("author-copilot").agent
    _post(board, author.id, "visible elsewhere")

    snapshot = store.dashboard_snapshot(
        channel_name=channel_name, agent_name=agent_name, before=None, limit=5,
    )

    assert snapshot.messages == ()
    assert snapshot.parent_messages == ()
    assert snapshot.has_older is False
    assert snapshot.board_has_messages is True
    assert snapshot.counts.active_agents == 1


def test_recent_messages_are_returned_oldest_first(services) -> None:
    store, agents, board = services
    author = agents.create_agent("author-copilot").agent
    posted = [_post(board, author.id, f"message {index}") for index in range(3)]

    recent = store.list_recent_messages(limit=2)

    assert [message.seq for message in recent] == [posted[1].seq, posted[2].seq]
    assert recent[0].created_at == _NOW
