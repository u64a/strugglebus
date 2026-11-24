from __future__ import annotations

import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from operator_test_support import operator_client, verifier
from strugglebus.api import LeasedStreamingResponse
from strugglebus.app import create_app
from strugglebus.auth import AgentService
from strugglebus.config import AppConfig
from strugglebus.dashboard import DASHBOARD_STYLESHEET_PATH
from strugglebus.errors import (
    DomainValidationError,
    ReplyNotFoundError,
    StorageError,
    UnknownMentionError,
)
from strugglebus.rate_limit import ConcurrentConnectionLimiter
from strugglebus.service import BoardService, parse_mentions
from strugglebus.store import SQLiteStore


NOW = datetime(2026, 8, 28, 3, 35, tzinfo=UTC)


def _services(config: AppConfig) -> tuple[AgentService, BoardService]:
    store = SQLiteStore(
        config.database_path,
        backup_dir=config.backup_dir,
        busy_timeout_ms=config.sqlite_busy_timeout_ms,
    )
    agents = AgentService(store)
    board = BoardService(
        store,
        max_message_bytes=config.max_message_bytes,
        max_metadata_bytes=config.max_metadata_bytes,
        max_channels=config.max_channels,
        clock=lambda: NOW,
    )
    board.initialize()
    return agents, board


def _post(
    board: BoardService,
    *,
    agent_id: str,
    body: str,
    channel: str = "status",
    kind: str = "chat",
    reply_to: int | None = None,
):
    return board.create_message(
        channel,
        agent_id=agent_id,
        body=body,
        kind=kind,
        reply_to=reply_to,
        metadata={},
    )


def test_mentions_are_boundary_safe_deduplicated_and_transactional(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)
    writer = agents.create_agent("writer-copilot").agent
    reader = agents.create_agent("reader-copilot").agent

    body = (
        "reader-copilot@example.com @reader-copilot "
        "@READER-COPILOT (@reader-copilot) @reader-copilot.example"
    )
    assert parse_mentions(body) == ("reader-copilot",)
    message = _post(board, agent_id=writer.id, body=body)

    with sqlite3.connect(app_config.database_path) as database:
        assert database.execute(
            "SELECT message_seq, agent_id FROM mentions"
        ).fetchall() == [(message.seq, reader.id)]
        before = database.execute("SELECT COUNT(*) FROM messages").fetchone()[0]

    with pytest.raises(UnknownMentionError, match="missing-agent"):
        _post(
            board,
            agent_id=writer.id,
            body="Please check this @missing-agent",
        )

    with sqlite3.connect(app_config.database_path) as database:
        assert database.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == before

    too_many = " ".join(f"@project-{index}" for index in range(33))
    with pytest.raises(DomainValidationError, match="more than 32"):
        _post(board, agent_id=writer.id, body=too_many)


def test_catch_up_combines_subscriptions_mentions_stale_filter_and_limits(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)
    writer = agents.create_agent("writer-copilot").agent
    reader = agents.create_agent("reader-copilot").agent
    board.subscribe("status", agent_id=reader.id)

    stale_status = _post(
        board,
        agent_id=writer.id,
        body="old status",
        kind="status",
    )
    old_chat = _post(board, agent_id=writer.id, body="old durable chat")
    recent_status = _post(
        board,
        agent_id=writer.id,
        body="@reader-copilot recent status",
        kind="status",
    )
    mention = _post(
        board,
        agent_id=writer.id,
        channel="help",
        body="@reader-copilot please review",
    )
    stale_time = (NOW - timedelta(days=8)).isoformat().replace("+00:00", "Z")
    with sqlite3.connect(app_config.database_path) as database:
        database.executemany(
            "UPDATE messages SET created_at = ? WHERE seq = ?",
            [(stale_time, stale_status.seq), (stale_time, old_chat.seq)],
        )

    first = board.catch_up(agent_id=reader.id, limit=2)
    second = board.catch_up(agent_id=reader.id, limit=10)
    with_stale = board.catch_up(
        agent_id=reader.id,
        limit=10,
        include_stale=True,
    )

    assert [message.seq for message in first] == [old_chat.seq, recent_status.seq]
    assert [message.seq for message in second] == [recent_status.seq, mention.seq]
    assert [message.seq for message in with_stale] == [
        stale_status.seq,
        old_chat.seq,
        recent_status.seq,
        mention.seq,
    ]
    with sqlite3.connect(app_config.database_path) as database:
        cursors = {
            (name, bool(include_stale)): last_seq
            for name, include_stale, last_seq in database.execute(
                """
                SELECT c.name, cursor.include_stale, cursor.last_seq
                FROM cursors AS cursor
                JOIN channels AS c ON c.id = cursor.channel_id
                WHERE cursor.agent_id = ?
                """,
                (reader.id,),
            )
        }
        mention_cursors = dict(
            database.execute(
                """
                SELECT include_stale, last_seq
                FROM mention_cursors
                WHERE agent_id = ?
                """,
                (reader.id,),
            )
        )
    assert cursors == {
        ("status", False): recent_status.seq,
        ("status", True): recent_status.seq,
    }
    assert mention_cursors == {0: mention.seq, 1: mention.seq}


def test_mention_only_delivery_does_not_consume_future_subscription_history(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)
    writer = agents.create_agent("writer-copilot").agent
    reader = agents.create_agent("reader-copilot").agent
    older = _post(
        board,
        agent_id=writer.id,
        channel="help",
        body="older channel history",
    )
    mention = _post(
        board,
        agent_id=writer.id,
        channel="help",
        body="@reader-copilot mention-only delivery",
    )
    old_time = (NOW - timedelta(hours=3)).isoformat().replace("+00:00", "Z")
    with sqlite3.connect(app_config.database_path) as database:
        database.execute(
            "UPDATE messages SET created_at = ? WHERE seq IN (?, ?)",
            (old_time, older.seq, mention.seq),
        )

    assert [
        message.seq for message in board.catch_up(agent_id=reader.id)
    ] == [mention.seq]
    assert board.catch_up(agent_id=reader.id) == ()
    board.subscribe("help", agent_id=reader.id)
    assert [
        message.seq for message in board.catch_up(agent_id=reader.id)
    ] == [older.seq, mention.seq]


def test_catch_up_does_not_advance_cursor_when_result_construction_fails(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)
    writer = agents.create_agent("writer-copilot").agent
    reader = agents.create_agent("reader-copilot").agent
    board.subscribe("status", agent_id=reader.id)
    first = _post(board, agent_id=writer.id, body="first")
    second = _post(board, agent_id=writer.id, body="second")
    with sqlite3.connect(app_config.database_path) as database:
        database.execute(
            "UPDATE messages SET meta = ? WHERE seq = ?",
            ("not-json", second.seq),
        )

    with pytest.raises(StorageError, match="invalid message metadata"):
        board.catch_up(agent_id=reader.id)

    with sqlite3.connect(app_config.database_path) as database:
        assert database.execute(
            "SELECT COUNT(*) FROM cursors WHERE agent_id = ?",
            (reader.id,),
        ).fetchone() == (0,)
        database.execute(
            "UPDATE messages SET meta = '{}' WHERE seq = ?",
            (second.seq,),
        )

    assert [
        message.seq for message in board.catch_up(agent_id=reader.id)
    ] == [first.seq, second.seq]


def test_concurrent_catch_up_sessions_receive_overlap_without_missing(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)
    writer = agents.create_agent("writer-copilot").agent
    reader = agents.create_agent("reader-copilot").agent
    message = _post(
        board,
        agent_id=writer.id,
        body="@reader-copilot shared recent update",
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda _: board.catch_up(agent_id=reader.id),
                range(2),
            )
        )

    assert [[item.seq for item in result] for result in results] == [
        [message.seq],
        [message.seq],
    ]


def test_direct_reply_reads_are_ordered_bounded_and_cursor_neutral(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)
    writer = agents.create_agent("writer-copilot").agent
    reader = agents.create_agent("reader-copilot").agent
    board.subscribe("status", agent_id=reader.id)
    original = _post(board, agent_id=writer.id, body="original request")
    first = _post(
        board,
        agent_id=reader.id,
        body="first direct reply",
        reply_to=original.seq,
    )
    nested = _post(
        board,
        agent_id=writer.id,
        body="nested reply",
        reply_to=first.seq,
    )
    second = _post(
        board,
        agent_id=reader.id,
        body="second direct reply",
        reply_to=original.seq,
    )

    assert [message.seq for message in board.read_replies(original.seq, limit=1)] == [
        first.seq
    ]
    assert [
        message.seq
        for message in board.read_replies(
            original.seq,
            since=first.seq,
            limit=10,
        )
    ] == [second.seq]
    assert board.read_replies(nested.seq) == ()
    assert [message.seq for message in board.catch_up(agent_id=reader.id)] == [
        original.seq,
        first.seq,
        nested.seq,
        second.seq,
    ]


@pytest.mark.parametrize(
    ("message_seq", "since", "limit"),
    [
        (0, 0, 50),
        (True, 0, 50),
        (2**63, 0, 50),
        (1, -1, 50),
        (1, True, 50),
        (1, 0, 0),
        (1, 0, 201),
    ],
)
def test_reply_read_validation_and_missing_targets(
    app_config: AppConfig,
    message_seq: int,
    since: int,
    limit: int,
) -> None:
    _, board = _services(app_config)

    with pytest.raises(DomainValidationError):
        board.read_replies(message_seq, since=since, limit=limit)

    with pytest.raises(ReplyNotFoundError, match="reply target was not found"):
        board.read_replies(1)


def test_bounded_literal_fts_search_is_deterministic_and_filters_stale(
    app_config: AppConfig,
) -> None:
    agents, board = _services(app_config)
    writer = agents.create_agent("writer-copilot").agent
    stale = _post(
        board,
        agent_id=writer.id,
        body="<script>alpha needle</script>",
        kind="status",
    )
    first = _post(board, agent_id=writer.id, body="alpha needle first")
    second = _post(
        board,
        agent_id=writer.id,
        body="alpha needle second",
        channel="help",
    )
    stale_time = (NOW - timedelta(days=8)).isoformat().replace("+00:00", "Z")
    with sqlite3.connect(app_config.database_path) as database:
        database.execute(
            "UPDATE messages SET created_at = ? WHERE seq = ?",
            (stale_time, stale.seq),
        )

    hits = board.search("alpha needle", limit=10)
    status_hits = board.search(
        "alpha needle",
        channel_name="status",
        include_stale=True,
        limit=10,
    )

    assert [hit.message.seq for hit in hits] == [second.seq, first.seq]
    assert [hit.message.seq for hit in status_hits] == [first.seq, stale.seq]
    assert status_hits[-1].snippet == "<script>alpha needle</script>"
    assert board.search('alpha OR "needle" --', limit=10) == ()
    for query in ('"""', "x" * 257, " ".join(f"term{i}" for i in range(17))):
        with pytest.raises(DomainValidationError):
            board.search(query)


def test_rest_catch_search_sse_and_human_view_are_safe(
    app_config: AppConfig,
) -> None:
    config = replace(
        app_config,
        sse_poll_interval_ms=10,
        sse_heartbeat_seconds=1,
        sse_connection_seconds=1,
    )
    agents, board = _services(config)
    writer = agents.create_agent("writer-copilot")
    reader = agents.create_agent("reader-copilot")
    pending = agents.verify_credential(reader.api_key)
    assert pending is not None
    agents.prove(
        pending,
        request_id=str(uuid.uuid4()),
        expected_agent_id=reader.agent.id,
        expected_agent_name=reader.agent.name,
        expected_credential_epoch=reader.agent.credential_epoch,
        expected_credential_version=reader.issued_credential.credential.version,
    )
    board.subscribe("status", agent_id=reader.agent.id)
    first = _post(
        board,
        agent_id=writer.agent.id,
        body="<script>alert(1)</script> searchable",
    )
    second = _post(
        board,
        agent_id=writer.agent.id,
        body="@reader-copilot later searchable",
        channel="help",
    )
    application = create_app(
        config=config,
        agent_service=agents,
        board_service=board,
    )
    headers = {"Authorization": f"Bearer {reader.api_key}"}

    with operator_client(application) as client:
        catch = client.get("/api/catch-up", headers=headers)
        search = client.get(
            "/api/search",
            headers=headers,
            params={"query": "searchable", "limit": 10},
        )
        stream = client.get(
            "/api/stream",
            headers={**headers, "Last-Event-ID": str(first.seq)},
        )
        missing_auth = client.get("/api/stream")
        bad_host = client.get(
            "/api/stream",
            headers={**headers, "Host": "public.example"},
        )
        page = client.get("/")
        activity_page = client.get("/activity")
        channels_page = client.get("/channels")
        agents_page = client.get("/agents")
        system_page = client.get("/system")
        huge_since = client.get(
            "/api/stream",
            headers=headers,
            params={"since": str(2**63)},
        )
        huge_event_id = client.get(
            "/api/stream",
            headers={**headers, "Last-Event-ID": str(2**63)},
        )

    assert [message["seq"] for message in catch.json()] == [first.seq, second.seq]
    assert [message["seq"] for message in search.json()] == [second.seq, first.seq]
    assert stream.status_code == 200
    assert stream.headers["content-type"].startswith("text/event-stream")
    assert stream.headers["x-accel-buffering"] == "no"
    assert f"id: {second.seq}\n" in stream.text
    assert f"id: {first.seq}\n" not in stream.text
    assert missing_auth.status_code == 401
    assert bad_host.status_code == 421
    assert huge_since.status_code == 422
    assert huge_event_id.status_code == 422
    assert page.status_code == 200
    assert "<script>alert(1)</script>" not in page.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
    assert "searchable" in page.text
    assert "default-src 'none'" in page.headers["content-security-policy"]
    assert "metadata" not in page.text

    for human_page in (activity_page, channels_page, agents_page, system_page):
        assert human_page.status_code == 200
        assert "<script>alert(1)</script>" not in human_page.text
        assert "default-src 'none'" in human_page.headers["content-security-policy"]
        assert "metadata" not in human_page.text

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in activity_page.text
    assert "searchable" in activity_page.text


def test_stream_channel_filter_restricts_delivery_without_granting_access(
    app_config: AppConfig,
) -> None:
    config = replace(
        app_config,
        sse_poll_interval_ms=10,
        sse_heartbeat_seconds=1,
        sse_connection_seconds=1,
    )
    agents, board = _services(config)
    writer = agents.create_agent("writer-copilot")
    reader = agents.create_agent("reader-copilot")
    pending = agents.verify_credential(reader.api_key)
    assert pending is not None
    agents.prove(
        pending,
        request_id=str(uuid.uuid4()),
        expected_agent_id=reader.agent.id,
        expected_agent_name=reader.agent.name,
        expected_credential_epoch=reader.agent.credential_epoch,
        expected_credential_version=reader.issued_credential.credential.version,
    )
    status_message = _post(board, agent_id=writer.agent.id, body="status body")
    help_message = _post(
        board, agent_id=writer.agent.id, body="help body", channel="help"
    )
    application = create_app(
        config=config, agent_service=agents, board_service=board
    )
    headers = {"Authorization": f"Bearer {reader.api_key}"}

    with operator_client(application) as client:
        filtered = client.get(
            "/api/stream", headers=headers, params={"channel": "help"}
        )
        unfiltered = client.get("/api/stream", headers=headers)
        unknown = client.get(
            "/api/stream", headers=headers, params={"channel": "absent-channel"}
        )
        invalid = client.get(
            "/api/stream", headers=headers, params={"channel": "in!valid"}
        )
        empty = client.get("/api/stream", headers=headers, params={"channel": ""})
        canonicalized = client.get(
            "/api/stream", headers=headers, params={"channel": "#Help"}
        )

    # Delivery is restricted to the requested channel, and event ids stay
    # global sequences so Last-Event-ID resume is unchanged.
    assert filtered.status_code == 200
    assert f"id: {help_message.seq}\n" in filtered.text
    assert f"id: {status_message.seq}\n" not in filtered.text
    assert "help body" in filtered.text
    assert "status body" not in filtered.text

    assert unfiltered.status_code == 200
    assert f"id: {status_message.seq}\n" in unfiltered.text
    assert f"id: {help_message.seq}\n" in unfiltered.text

    # A mistyped channel must fail loudly rather than look like a quiet one.
    assert unknown.status_code == 404
    assert invalid.status_code == 422
    assert empty.status_code == 422

    # The filter canonicalizes exactly like every other channel reference.
    assert canonicalized.status_code == 200
    assert f"id: {help_message.seq}\n" in canonicalized.text
    assert f"id: {status_message.seq}\n" not in canonicalized.text


def test_human_view_uses_unauthenticated_source_rate_limit(
    app_config: AppConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("strugglebus.operator_auth.load_password_verifier", lambda path: verifier())
    config = replace(app_config, unauthenticated_requests_per_minute=1)
    application = create_app(config=config)

    with TestClient(application, follow_redirects=False) as client:
        first = client.get("/")
        limited = client.get("/")

    assert first.status_code == 303
    assert limited.status_code == 429
    assert limited.headers["retry-after"]


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/activity",
        "/channels",
        "/agents",
        "/system",
        DASHBOARD_STYLESHEET_PATH,
    ],
)
def test_each_human_view_and_asset_is_rate_limited_and_shares_the_source_bucket(
    app_config: AppConfig,
    path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("strugglebus.operator_auth.load_password_verifier", lambda path: verifier())
    config = replace(app_config, unauthenticated_requests_per_minute=1)
    application = create_app(config=config)

    with TestClient(application, follow_redirects=False) as client:
        first = client.get(path)
        limited = client.get(path)

    assert first.status_code == (200 if path == DASHBOARD_STYLESHEET_PATH else 303)
    assert limited.status_code == 429
    assert limited.headers["retry-after"]


def test_human_view_rate_limit_bucket_is_shared_across_all_paths(
    app_config: AppConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("strugglebus.operator_auth.load_password_verifier", lambda path: verifier())
    config = replace(app_config, unauthenticated_requests_per_minute=1)
    application = create_app(config=config)

    with TestClient(application, follow_redirects=False) as client:
        first = client.get("/")
        second_path = client.get("/activity")

    assert first.status_code == 303
    assert second_path.status_code == 429
    assert second_path.headers["retry-after"]


@pytest.mark.asyncio
async def test_sse_lease_releases_when_response_start_send_fails() -> None:
    limiter = ConcurrentConnectionLimiter()
    key = "sole-stream-agent"
    iterated = False
    assert limiter.acquire(key, 1) is True

    async def content():
        nonlocal iterated
        iterated = True
        yield b"data: unreachable\n\n"

    async def receive():
        return {"type": "http.disconnect"}

    async def failing_send(message):
        assert message["type"] == "http.response.start"
        raise RuntimeError("response transport failed")

    response = LeasedStreamingResponse(
        content(),
        media_type="text/event-stream",
        lease_limiter=limiter,
        lease_key=key,
    )
    scope = {"type": "http", "asgi": {"spec_version": "2.4"}}

    with pytest.raises(RuntimeError, match="response transport failed"):
        await response(scope, receive, failing_send)

    assert iterated is False
    assert limiter.acquire(key, 1) is True
    limiter.release(key)
