from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta

import pytest

from strugglebus.drain import CatchUpPage, DrainRegistry
from strugglebus.errors import (
    CatchUpCapacityError,
    CatchUpUnavailableError,
    DomainValidationError,
    StorageError,
)
from strugglebus.service import BoardService
from test_product_layer import NOW, _post, _services


def _finish(board, agent_id, page, *, limit=50, include_stale=False):
    messages = list(page.messages)
    for _ in range(3000):
        if page.complete:
            return messages
        assert page.continuation
        page = board.catch_up_page(
            agent_id=agent_id, limit=limit, include_stale=include_stale,
            continuation=page.continuation,
        )
        messages.extend(page.messages)
    pytest.fail("drain did not make finite progress")


def _cursors(config):
    with sqlite3.connect(config.database_path) as connection:
        return (
            connection.execute("SELECT * FROM cursors ORDER BY 1, 2, 3").fetchall(),
            connection.execute("SELECT * FROM mention_cursors ORDER BY 1, 2").fetchall(),
        )


@pytest.mark.parametrize("limit", [1, 50, 200])
def test_large_recent_backlog_has_fixed_size_forward_pages(app_config, limit):
    agents, board = _services(app_config)
    reader = agents.create_agent("drain-reader").agent
    writer = agents.create_agent("drain-writer").agent
    board.subscribe("status", agent_id=reader.id)
    expected = [
        _post(board, agent_id=writer.id, body=str(index)).seq
        for index in range(505)
    ]
    page = board.catch_up_page(agent_id=reader.id, limit=limit, start_drain=True)
    seen = []
    while True:
        seqs = [message.seq for message in page.messages]
        assert seqs == sorted(seqs)
        assert len(seqs) == min(limit, len(expected) - len(seen))
        seen.extend(seqs)
        if page.complete:
            break
        assert page.continuation
        page = board.catch_up_page(
            agent_id=reader.id, limit=limit, continuation=page.continuation
        )
    assert seen == expected
    assert page.snapshot_seq == expected[-1]
    assert page.continuation is None


def test_concurrent_drains_ignore_later_shared_cursors_and_posts(app_config):
    agents, board = _services(app_config)
    reader = agents.create_agent("drain-reader").agent
    writer = agents.create_agent("drain-writer").agent
    board.subscribe("status", agent_id=reader.id)
    expected = [_post(board, agent_id=writer.id, body=str(i)).seq for i in range(8)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = list(pool.map(
            lambda _: board.catch_up_page(agent_id=reader.id, limit=1, start_drain=True),
            range(2),
        ))
    assert [m.seq for m in _finish(board, reader.id, first, limit=1)] == expected
    new = _post(board, agent_id=writer.id, body="after snapshot")
    assert [m.seq for m in _finish(board, reader.id, second, limit=1)] == expected
    fresh = board.catch_up_page(agent_id=reader.id, start_drain=True)
    assert new.seq in [m.seq for m in fresh.messages]


def test_replay_is_stable_after_completion_and_clock_cutoff_changes(app_config):
    agents, board = _services(app_config)
    reader = agents.create_agent("drain-reader").agent
    writer = agents.create_agent("drain-writer").agent
    board.subscribe("status", agent_id=reader.id)
    _post(board, agent_id=writer.id, body="first")
    status = _post(board, agent_id=writer.id, body="recent", kind="status")
    first = board.catch_up_page(agent_id=reader.id, limit=1, start_drain=True)
    board._clock = lambda: NOW + timedelta(days=8)
    kwargs = dict(agent_id=reader.id, limit=1, continuation=first.continuation)
    second = board.catch_up_page(**kwargs)
    replay = board.catch_up_page(**kwargs)
    assert second == replay
    assert [m.seq for m in second.messages] == [status.seq]
    assert second.complete


def test_subscription_snapshot_survives_unsubscribe_resubscribe(app_config):
    agents, board = _services(app_config)
    reader = agents.create_agent("drain-reader").agent
    writer = agents.create_agent("drain-writer").agent
    board.subscribe("status", agent_id=reader.id)
    expected = [_post(board, agent_id=writer.id, body=str(i)).seq for i in range(4)]
    older_help = _post(board, agent_id=writer.id, channel="help", body="older help")
    mentioned = _post(
        board, agent_id=writer.id, channel="help", body="@drain-reader mention"
    )
    page = board.catch_up_page(agent_id=reader.id, limit=1, start_drain=True)
    board.unsubscribe("status", agent_id=reader.id)
    board.subscribe("status", agent_id=reader.id)
    board.subscribe("help", agent_id=reader.id)
    received = _finish(board, reader.id, page, limit=1)
    assert [m.seq for m in received] == [*expected, mentioned.seq]
    with sqlite3.connect(app_config.database_path) as connection:
        assert connection.execute(
            """SELECT COUNT(*) FROM cursors c JOIN channels h ON h.id=c.channel_id
               WHERE c.agent_id=? AND h.name='help'""", (reader.id,)
        ).fetchone()[0] == 0
    fresh = board.catch_up_page(agent_id=reader.id, start_drain=True)
    assert older_help.seq in [m.seq for m in fresh.messages]


def test_stale_filter_and_candidate_budget_have_empty_progress_pages(app_config):
    agents, board = _services(app_config)
    reader = agents.create_agent("drain-reader").agent
    writer = agents.create_agent("drain-writer").agent
    board.subscribe("status", agent_id=reader.id)
    stale = [_post(board, agent_id=writer.id, body=str(i), kind="status").seq
             for i in range(6)]
    with sqlite3.connect(app_config.database_path) as connection:
        connection.execute(
            "UPDATE messages SET created_at=?",
            ((NOW - timedelta(days=8)).isoformat().replace("+00:00", "Z"),),
        )
    durable = _post(board, agent_id=writer.id, body="@drain-reader durable")
    board.catch_up_candidate_limit = 1
    page = board.catch_up_page(agent_id=reader.id, start_drain=True)
    assert page.messages == () and page.complete is False
    assert _cursors(app_config) == ([], [])
    received = _finish(board, reader.id, page)
    assert [m.seq for m in received] == [durable.seq]
    stale_page = board.catch_up_page(
        agent_id=reader.id, include_stale=True, start_drain=True
    )
    assert [m.seq for m in _finish(
        board, reader.id, stale_page, include_stale=True
    )] == [*stale, durable.seq]


def test_tokens_are_scope_bound_and_rejections_do_not_change_cursors(app_config):
    agents, board = _services(app_config)
    reader = agents.create_agent("drain-reader").agent
    other = agents.create_agent("other-reader").agent
    board.subscribe("status", agent_id=reader.id)
    for i in range(3):
        _post(board, agent_id=reader.id, body=str(i))
    first = board.catch_up_page(agent_id=reader.id, limit=1, start_drain=True)
    token = first.continuation
    assert token and reader.id not in token
    prefix, signature = token.rsplit(".", 1)
    tampered = prefix + "." + ("0" if signature[0] != "0" else "1") + signature[1:]
    baseline = _cursors(app_config)
    for extra in [
        {"continuation": "garbage"}, {"continuation": "x" * 257},
        {"continuation": tampered}, {"agent_id": other.id},
        {"include_stale": True}, {"limit": 2}, {"start_drain": True},
    ]:
        kwargs = dict(agent_id=reader.id, limit=1, continuation=token)
        kwargs.update(extra)
        with pytest.raises(DomainValidationError):
            board.catch_up_page(**kwargs)
        assert _cursors(app_config) == baseline


def test_registry_capacity_expiry_restart_and_legacy_allocation(app_config):
    agents, board = _services(app_config)
    reader = agents.create_agent("drain-reader").agent
    board.subscribe("status", agent_id=reader.id)
    for i in range(3):
        _post(board, agent_id=reader.id, body=str(i))
    moment = [0.0]
    board._drains = DrainRegistry(
        maximum=1, per_agent=1, ttl_seconds=5, monotonic=lambda: moment[0]
    )
    for _ in range(20):
        assert board.catch_up_page(agent_id=reader.id, limit=1).mode == "legacy"
    first = board.catch_up_page(agent_id=reader.id, limit=1, start_drain=True)
    _finish(board, reader.id, first, limit=1)
    baseline = _cursors(app_config)
    with pytest.raises(CatchUpCapacityError):
        board.catch_up_page(agent_id=reader.id, start_drain=True)
    assert _cursors(app_config) == baseline
    moment[0] = 6
    with pytest.raises(CatchUpUnavailableError):
        board.catch_up_page(
            agent_id=reader.id, limit=1, continuation=first.continuation
        )
    assert _cursors(app_config) == baseline
    for _ in range(10):
        assert board.catch_up_page(agent_id=reader.id, start_drain=True).complete
    restarted = BoardService(
        board.store, max_message_bytes=app_config.max_message_bytes,
        max_metadata_bytes=app_config.max_metadata_bytes,
        max_channels=app_config.max_channels, clock=lambda: NOW,
    )
    with pytest.raises(CatchUpUnavailableError):
        restarted.catch_up_page(
            agent_id=reader.id, limit=1, continuation=first.continuation
        )


def test_simultaneous_admission_has_one_winner_and_failed_construction_releases(app_config):
    agents, board = _services(app_config)
    reader = agents.create_agent("drain-reader").agent
    board.subscribe("status", agent_id=reader.id)
    for i in range(3):
        _post(board, agent_id=reader.id, body=str(i))
    board._drains = DrainRegistry(maximum=1, per_agent=1, ttl_seconds=300)

    def start(_):
        try:
            return board.catch_up_page(agent_id=reader.id, limit=1, start_drain=True)
        except CatchUpCapacityError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(start, range(2)))
    assert sum(isinstance(result, CatchUpPage) for result in outcomes) == 1
    board._drains = DrainRegistry(maximum=1, per_agent=1, ttl_seconds=300)
    before = _cursors(app_config)
    with sqlite3.connect(app_config.database_path) as connection:
        connection.execute("UPDATE messages SET meta='bad' WHERE seq=2")
    with pytest.raises(StorageError):
        board.catch_up_page(agent_id=reader.id, start_drain=True)
    assert _cursors(app_config) == before
    with sqlite3.connect(app_config.database_path) as connection:
        connection.execute("UPDATE messages SET meta='{}' WHERE seq=2")
    assert board.catch_up_page(agent_id=reader.id, start_drain=True).complete


def test_per_agent_and_global_capacity_never_evict_other_drains(app_config):
    agents, board = _services(app_config)
    readers = [agents.create_agent(f"drain-reader-{i}").agent for i in range(3)]
    for reader in readers:
        board.subscribe("status", agent_id=reader.id)
    for index in range(3):
        _post(board, agent_id=readers[0].id, body=str(index))
    board._drains = DrainRegistry(maximum=2, per_agent=1, ttl_seconds=300)
    first = board.catch_up_page(agent_id=readers[0].id, limit=1, start_drain=True)
    with pytest.raises(CatchUpCapacityError):
        board.catch_up_page(agent_id=readers[0].id, limit=1, start_drain=True)
    second = board.catch_up_page(agent_id=readers[1].id, limit=1, start_drain=True)
    baseline = _cursors(app_config)
    with pytest.raises(CatchUpCapacityError):
        board.catch_up_page(agent_id=readers[2].id, limit=1, start_drain=True)
    assert _cursors(app_config) == baseline
    assert len(_finish(board, readers[0].id, first, limit=1)) == 3
    assert len(_finish(board, readers[1].id, second, limit=1)) == 3


def test_candidate_work_is_indexed_and_bounded_before_stale_filter(app_config, monkeypatch):
    agents, board = _services(app_config)
    reader = agents.create_agent("drain-reader").agent
    board.subscribe("status", agent_id=reader.id)
    for _ in range(20):
        _post(board, agent_id=reader.id, body="@drain-reader stale", kind="status")
    for _ in range(100):
        _post(board, agent_id=reader.id, body="irrelevant", channel="help")
    with sqlite3.connect(app_config.database_path) as connection:
        connection.execute(
            "UPDATE messages SET created_at=?",
            ((NOW - timedelta(days=8)).isoformat().replace("+00:00", "Z"),),
        )
    board.catch_up_candidate_limit = 2
    statements = []
    original = board.store._connection

    @contextmanager
    def traced_connection():
        with original() as connection:
            connection.set_trace_callback(statements.append)
            yield connection

    monkeypatch.setattr(board.store, "_connection", traced_connection)
    page = board.catch_up_page(agent_id=reader.id, start_drain=True)
    assert page.messages == () and not page.complete
    metadata_reads = [
        sql for sql in statements
        if sql.startswith("SELECT channel_id, kind, created_at FROM messages")
    ]
    assert len(metadata_reads) == 2
    source_reads = [
        sql for sql in statements
        if "INDEXED BY idx_messages_channel_seq" in sql
        or "INDEXED BY idx_mentions_agent" in sql
    ]
    assert len(source_reads) <= 2 * board.catch_up_candidate_limit + 2
    with sqlite3.connect(app_config.database_path) as connection:
        for query in source_reads:
            plan = " ".join(
                row[3] for row in connection.execute("EXPLAIN QUERY PLAN " + query)
            )
            assert "SEARCH" in plan and "SCAN" not in plan
    assert _cursors(app_config) == ([], [])
