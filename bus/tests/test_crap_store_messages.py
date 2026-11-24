"""Catch-up paging and system posts, exercised directly against the store."""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from strugglebus.auth import AgentService
from strugglebus.drain import CatchUpPage, CatchUpSnapshot
from strugglebus.errors import (
    ChannelNotFoundError,
    DomainValidationError,
    PostRequestConflictError,
)
from strugglebus.store import MAINTENANCE_SYSTEM_AGENT_ID, SQLiteStore

_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
_LONG_AGO = _NOW - timedelta(days=30)
_NEVER_RECENT = _NOW + timedelta(days=1)


class _Board:
    """A store with two channels, one reader and one writer."""

    def __init__(self, tmp_path: Path) -> None:
        self.store = SQLiteStore(tmp_path / "strugglebus.db", backup_dir=tmp_path / "backups")
        agents = AgentService(self.store, clock=lambda: _NOW)
        agents.initialize()
        self.store.ensure_default_channels(
            (("status", "updates"), ("help", "questions"), ("announce", "news")),
            created_at=_NOW,
        )
        self.reader = agents.create_agent("reader-copilot").agent
        self.writer = agents.create_agent("writer-copilot").agent
        self.other = agents.create_agent("other-copilot").agent
        self.pages: list[tuple[CatchUpSnapshot, int, bool]] = []

    def post(
        self,
        channel: str = "status",
        *,
        mention: bool = False,
        kind: str = "chat",
        created_at: datetime = _NOW,
    ) -> int:
        return self.store.create_message(
            message_id=str(uuid.uuid4()),
            channel_name=channel,
            agent_id=self.writer.id,
            body="body",
            kind=kind,
            reply_to=None,
            metadata_json="{}",
            created_at=created_at,
            mentioned_names=(self.reader.name,) if mention else (),
        ).seq

    def _build(self, snapshot, messages, position, drained) -> CatchUpPage:
        self.pages.append((snapshot, position, drained))
        return CatchUpPage(messages=messages)

    def page(self, **overrides: object) -> list[int]:
        arguments: dict[str, object] = dict(
            agent_id=self.reader.id,
            limit=50,
            overlap_since=_NEVER_RECENT,
            stale_before=_LONG_AGO,
            include_stale=False,
            updated_at=_NOW,
            snapshot=None,
            after_seq=0,
            candidate_limit=1000,
            max_channels=10,
            build_page=self._build,
        )
        page = self.store.catch_up_page(**(arguments | overrides))
        return [message.seq for message in page.messages]

    def cursors(self) -> tuple[dict[str, int], list[int]]:
        with sqlite3.connect(self.store.database_path) as database:
            channels = dict(
                database.execute(
                    "SELECT channel_id, last_seq FROM cursors WHERE agent_id = ?",
                    (self.reader.id,),
                ).fetchall()
            )
            mentions = [
                row[0]
                for row in database.execute(
                    "SELECT last_seq FROM mention_cursors WHERE agent_id = ?",
                    (self.reader.id,),
                )
            ]
        return channels, mentions


@pytest.fixture
def board(tmp_path: Path) -> _Board:
    board = _Board(tmp_path)
    board.store.subscribe(agent_id=board.reader.id, channel_name="status", created_at=_NOW)
    return board


def test_page_merges_subscriptions_and_mentions_within_one_snapshot(board: _Board) -> None:
    subscribed = board.post("status")
    mentioned = board.post("help", mention=True)
    both = board.post("status", mention=True)
    board.post("help")

    first = board.page(limit=2)
    snapshot, position, drained = board.pages[-1]
    cursors_after_first = board.cursors()
    late = board.post("status")
    second = board.page(limit=2, snapshot=snapshot, after_seq=position)

    assert first == [subscribed, mentioned]
    assert (position, drained) == (mentioned, False)
    assert snapshot.upper_seq == both + 1
    assert cursors_after_first == ({"status": subscribed}, [mentioned])
    # The message posted after the snapshot waits for the next drain, and one
    # that is both subscribed and mentioned is delivered once.
    assert second == [both]
    assert board.pages[-1][1:] == (both, True)
    assert board.cursors() == ({"status": both}, [both])
    assert board.page() == [late]


def test_cursors_stop_redelivery_unless_the_message_is_inside_the_overlap(
    board: _Board,
) -> None:
    old = board.post("status", created_at=_NOW - timedelta(hours=2))
    recent = board.post("status", mention=True, created_at=_NOW)

    assert board.page() == [old, recent]
    # Already-delivered messages are still examined, so the scan position moves.
    assert board.page() == []
    assert board.pages[-1][1:] == (recent, True)
    assert board.page(overlap_since=_NOW - timedelta(hours=1)) == [recent]
    assert board.page(overlap_since=_NOW - timedelta(hours=3)) == [old, recent]
    assert board.cursors() == ({"status": recent}, [recent])


def test_stale_status_is_examined_but_withheld_unless_requested(board: _Board) -> None:
    stale = board.post("status", kind="status", created_at=_NOW - timedelta(days=2))
    fresh_status = board.post("status", kind="status", created_at=_NOW)
    old_chat = board.post("status", created_at=_NOW - timedelta(days=2))
    cutoff = _NOW - timedelta(days=1)

    assert board.page(stale_before=cutoff) == [fresh_status, old_chat]
    assert board.pages[-1][1:] == (old_chat, True)
    # Each stale mode keeps its own cursor, so the withheld status is still owed.
    assert board.page(stale_before=cutoff, include_stale=True) == [
        stale, fresh_status, old_chat,
    ]


def test_candidate_budget_ends_a_page_and_reports_where_to_resume(board: _Board) -> None:
    stale = board.post("status", kind="status", created_at=_NOW - timedelta(days=2))
    wanted = board.post("status")
    cutoff = _NOW - timedelta(days=1)

    assert board.page(stale_before=cutoff, candidate_limit=1) == []
    snapshot, position, drained = board.pages[-1]
    assert (position, drained) == (stale, False)
    assert board.cursors() == ({}, [])

    assert board.page(
        stale_before=cutoff, candidate_limit=1, snapshot=snapshot, after_seq=position,
    ) == [wanted]
    assert board.pages[-1][1:] == (wanted, True)


def test_snapshot_is_bound_to_its_agent_limit_and_stale_mode(board: _Board) -> None:
    posted = board.post("status")
    assert board.page(limit=1) == [posted]
    snapshot = board.pages[-1][0]
    cursors = board.cursors()

    for mismatch in (
        {"agent_id": board.other.id},
        {"limit": 2},
        {"include_stale": True},
    ):
        with pytest.raises(DomainValidationError, match="snapshot scope mismatch"):
            board.page(**({"limit": 1, "snapshot": snapshot} | mismatch))

    assert len(board.pages) == 1
    assert board.cursors() == cursors


def test_new_drain_refuses_more_subscriptions_than_the_configured_capacity(
    board: _Board,
) -> None:
    board.store.subscribe(agent_id=board.reader.id, channel_name="help", created_at=_NOW)
    posted = board.post("help")

    with pytest.raises(DomainValidationError, match="exceed configured channel capacity"):
        board.page(max_channels=1)

    assert board.pages == []
    assert board.page(max_channels=2) == [posted]


def test_unsubscribing_from_an_unknown_channel_is_reported(board: _Board) -> None:
    with pytest.raises(ChannelNotFoundError, match="'nowhere' was not found"):
        board.store.unsubscribe(agent_id=board.reader.id, channel_name="nowhere")

    removed = board.store.unsubscribe(agent_id=board.reader.id, channel_name="status")

    assert removed.name == "status"
    assert board.store.list_subscriptions(board.reader.id) == ()


def test_maintenance_announcement_is_idempotent_per_request(board: _Board) -> None:
    request_id = str(uuid.uuid4())

    def announce(body: str, request: str):
        return board.store.create_maintenance_announcement(
            message_id=str(uuid.uuid4()),
            body=body,
            metadata_json="{}",
            created_at=_NOW,
            request_id=request,
        )

    first = announce("maintenance at noon", request_id)
    replayed = announce("maintenance at noon", request_id)

    assert first.channel == "announce"
    assert first.kind == "announce"
    assert first.agent_id == MAINTENANCE_SYSTEM_AGENT_ID
    assert replayed == first
    with pytest.raises(PostRequestConflictError, match="conflicts with previously accepted"):
        announce("maintenance at one", request_id)
    assert [message.seq for message in board.store.list_messages("announce", since=0, limit=10)] == [
        first.seq,
    ]


def test_maintenance_announcement_needs_the_announce_channel(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "strugglebus.db", backup_dir=tmp_path / "backups")
    store.initialize()

    with pytest.raises(ChannelNotFoundError, match="'announce' was not found"):
        store.create_maintenance_announcement(
            message_id=str(uuid.uuid4()),
            body="maintenance at noon",
            metadata_json="{}",
            created_at=_NOW,
            request_id=str(uuid.uuid4()),
        )

    assert store.list_recent_messages(limit=5) == ()
