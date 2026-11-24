from __future__ import annotations

import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from strugglebus.app import create_app
from strugglebus.auth import AgentService
from strugglebus.config import AppConfig
from strugglebus.errors import DomainValidationError
from strugglebus.models import AgentOrientation
from strugglebus.orientation import guidance, required_actions
from strugglebus.service import BoardService, ORIENTATION_COUNT_CAP
from strugglebus.store import SQLiteStore

ADMIN_TOKEN = "test-only-admin-secret"


def _application(config: AppConfig):
    service = AgentService(
        SQLiteStore(
            config.database_path,
            backup_dir=config.backup_dir,
            busy_timeout_ms=config.sqlite_busy_timeout_ms,
        )
    )
    return create_app(config=config, agent_service=service)


@pytest.fixture
def client(app_config: AppConfig):
    with TestClient(_application(app_config)) as rest:
        yield rest


def _register(client: TestClient, name: str) -> dict:
    response = client.post(
        "/api/agents",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        json={"request_id": str(uuid.uuid4()), "name": name},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _headers(created: dict) -> dict[str, str]:
    return {"Authorization": f"Bearer {created['credential_secret']}"}


def _prove(client: TestClient, created: dict) -> None:
    response = client.post(
        "/api/credentials/prove",
        headers=_headers(created),
        json={
            "request_id": str(uuid.uuid4()),
            "expected_agent_id": created["agent"]["id"],
            "expected_agent_name": created["agent"]["name"],
            "expected_credential_epoch": created["agent"]["credential_epoch"],
            "expected_credential_version": created["credential"]["version"],
        },
    )
    assert response.status_code == 200, response.text


def _acknowledge(client: TestClient, created: dict) -> None:
    effective = client.get("/api/roe/effective", headers=_headers(created)).json()
    payload = {
        "global_revision_id": effective["global_revision"]["id"],
        "global_content_sha256": effective["global_revision"]["content_sha256"],
        "effective_sha256": effective["effective_sha256"],
    }
    if effective.get("agent_revision"):
        payload["agent_revision_id"] = effective["agent_revision"]["id"]
        payload["agent_content_sha256"] = effective["agent_revision"][
            "content_sha256"
        ]
    response = client.post(
        "/api/roe/acknowledgements", headers=_headers(created), json=payload
    )
    assert response.status_code in {200, 201}, response.text


def _orientation(client: TestClient, created: dict) -> dict:
    response = client.get("/api/orientation", headers=_headers(created))
    assert response.status_code == 200, response.text
    return response.json()


def _subscribe(client: TestClient, created: dict, channel: str) -> None:
    # Subscription is an MCP operation; reach the service directly for REST tests.
    client.app.state.board_service.subscribe(
        channel, agent_id=created["agent"]["id"]
    )


def _actions(body: dict) -> list[str]:
    return [item["action"] for item in body["required_actions"]]


def test_pending_credential_is_told_to_prove_first(client: TestClient) -> None:
    created = _register(client, "orient-cli-win")
    body = _orientation(client, created)
    # Orientation must work before proving; it is how an agent learns it must.
    assert _actions(body)[0] == "prove_credential"
    assert "pending" in body["required_actions"][0]["reason"]
    assert body["roe_acknowledgement_status"] == "missing"


def test_actions_advance_as_the_agent_bootstraps(client: TestClient) -> None:
    created = _register(client, "orient-cli-win")
    assert _actions(_orientation(client, created)) == [
        "prove_credential",
        "acknowledge_roe",
        "choose_subscriptions",
    ]
    _prove(client, created)
    assert _actions(_orientation(client, created)) == [
        "acknowledge_roe",
        "choose_subscriptions",
    ]
    _acknowledge(client, created)
    body = _orientation(client, created)
    assert _actions(body) == ["choose_subscriptions"]
    assert "only direct mentions" in body["guidance"]
    assert "mention-only use is valid" in body["guidance"]
    assert "up to date" not in body["guidance"]
    assert body["subscribed_channels"] == []
    assert body["subscription_count"] == 0


def test_unread_and_mentions_are_reported_and_cleared(client: TestClient) -> None:
    reader = _register(client, "orient-cli-win")
    writer = _register(client, "poster-cli-win")
    for created in (reader, writer):
        _prove(client, created)
        _acknowledge(client, created)

    for index in range(3):
        posted = client.post(
            "/api/channels/announce/messages",
            headers=_headers(writer),
            json={"body": f"note {index}", "kind": "announce"},
        )
        assert posted.status_code == 201, posted.text
    mention = client.post(
        "/api/channels/help/messages",
        headers=_headers(writer),
        json={"body": "please look @orient-cli-win", "kind": "question"},
    )
    assert mention.status_code == 201, mention.text

    body = _orientation(client, reader)
    assert body["unread"] == 1
    assert body["pending_mentions"] == 1
    assert "catch_up" in _actions(body)
    assert body["latest_seq"] >= 4

    caught = client.get("/api/catch-up", headers=_headers(reader))
    assert caught.status_code == 200
    after = _orientation(client, reader)
    assert after["unread"] == 0
    assert after["pending_mentions"] == 0
    assert _actions(after) == ["choose_subscriptions"]
    assert "up to date" not in after["guidance"]


def test_orientation_never_moves_a_cursor(client: TestClient) -> None:
    reader = _register(client, "orient-cli-win")
    writer = _register(client, "poster-cli-win")
    for created in (reader, writer):
        _prove(client, created)
        _acknowledge(client, created)
    _subscribe(client, reader, "announce")
    client.post(
        "/api/channels/announce/messages",
        headers=_headers(writer),
        json={"body": "something to read", "kind": "announce"},
    )

    first = _orientation(client, reader)
    second = _orientation(client, reader)
    third = _orientation(client, reader)
    assert first["unread"] == second["unread"] == third["unread"]
    # The message must still be delivered by catch_up afterwards.
    caught = client.get("/api/catch-up", headers=_headers(reader)).json()
    assert any(message["body"] == "something to read" for message in caught)


def test_new_channels_since_the_last_cursor_update_are_listed(
    client: TestClient,
) -> None:
    reader = _register(client, "orient-cli-win")
    writer = _register(client, "poster-cli-win")
    for created in (reader, writer):
        _prove(client, created)
        _acknowledge(client, created)
    _subscribe(client, reader, "announce")
    # A cursor only exists once something has actually been read, and the
    # baseline for new-channel discovery is the actual cursor update.
    client.post(
        "/api/channels/announce/messages",
        headers=_headers(writer),
        json={"body": "first visit", "kind": "announce"},
    )
    client.get("/api/catch-up", headers=_headers(reader))

    made = client.post(
        "/api/channels",
        headers=_headers(writer),
        json={"name": "late-arrival", "purpose": "created after the last read"},
    )
    assert made.status_code == 201, made.text
    body = _orientation(client, reader)
    assert "late-arrival" in body["new_channels"]
    assert "#late-arrival" in body["guidance"]
    assert body["last_cursor_update_at"] == body["last_caught_up_at"]
    assert "since that recorded cursor update" in body["guidance"]


def test_counts_are_bounded(app_config: AppConfig) -> None:
    store = SQLiteStore(
        app_config.database_path,
        backup_dir=app_config.backup_dir,
        busy_timeout_ms=app_config.sqlite_busy_timeout_ms,
    )
    agents = AgentService(store)
    board = BoardService(
        store,
        max_message_bytes=app_config.max_message_bytes,
        max_metadata_bytes=app_config.max_metadata_bytes,
        max_channels=app_config.max_channels,
    )
    board.initialize()
    reader = agents.create_agent("orient-cli-win")
    writer = agents.create_agent("poster-cli-win")
    board.subscribe("announce", agent_id=reader.agent.id)
    for index in range(ORIENTATION_COUNT_CAP + 5):
        board.create_message(
            channel_name="announce",
            agent_id=writer.agent.id,
            body=f"note {index}",
            kind="chat",
            reply_to=None,
            metadata={},
        )
    summary = board.orientation(agent_id=reader.agent.id)
    assert summary.unread == ORIENTATION_COUNT_CAP
    assert summary.unread_capped is True
    assert summary.channels[0].unread == ORIENTATION_COUNT_CAP
    assert summary.channels[0].unread_capped is True
    assert summary.counts_complete is False
    assert summary.pending_mentions == 0
    assert summary.pending_mentions_capped is False


def test_stale_statuses_follow_the_catch_up_rule(app_config: AppConfig) -> None:
    store = SQLiteStore(
        app_config.database_path,
        backup_dir=app_config.backup_dir,
        busy_timeout_ms=app_config.sqlite_busy_timeout_ms,
    )
    agents = AgentService(store)
    old = datetime.now(UTC) - timedelta(days=30)
    board = BoardService(
        store,
        max_message_bytes=app_config.max_message_bytes,
        max_metadata_bytes=app_config.max_metadata_bytes,
        max_channels=app_config.max_channels,
        clock=lambda: old,
    )
    board.initialize()
    reader = agents.create_agent("orient-cli-win")
    writer = agents.create_agent("poster-cli-win")
    board.subscribe("status", agent_id=reader.agent.id)
    board.create_message(
        channel_name="status",
        agent_id=writer.agent.id,
        body="ancient status",
        kind="status",
        reply_to=None,
        metadata={},
    )
    current = BoardService(
        store,
        max_message_bytes=app_config.max_message_bytes,
        max_metadata_bytes=app_config.max_metadata_bytes,
        max_channels=app_config.max_channels,
    )
    assert current.orientation(agent_id=reader.agent.id).unread == 0
    assert (
        current.orientation(agent_id=reader.agent.id, include_stale=True).unread == 1
    )


def test_missing_cursor_is_not_misrepresented_as_a_first_session(
    client: TestClient,
) -> None:
    created = _register(client, "orient-cli-win")
    _prove(client, created)
    _acknowledge(client, created)
    body = _orientation(client, created)
    # With no cursor there is no baseline, so no channel is reported as new and
    # the guidance says so instead of inventing a history.
    assert body["last_caught_up_at"] is None
    assert body["last_cursor_update_at"] is None
    assert body["new_channels"] == []
    assert "No recorded cursor update" in body["guidance"]
    assert "first session" not in body["guidance"]


def test_orientation_requires_authentication(client: TestClient) -> None:
    assert client.get("/api/orientation").status_code == 401


def test_orientation_is_denied_while_frozen(client: TestClient) -> None:
    created = _register(client, "orient-cli-win")
    _prove(client, created)
    _acknowledge(client, created)
    client.app.state.access_freeze_service.freeze("incident drill")
    response = client.get("/api/orientation", headers=_headers(created))
    assert response.status_code == 503


@pytest.fixture
def board_state(app_config: AppConfig):
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
    )
    board.initialize()
    agents = AgentService(store)
    return (
        store,
        board,
        agents.create_agent("orient-cli-win").agent,
        agents.create_agent("poster-cli-win").agent,
    )


def _seed_messages(
    store: SQLiteStore,
    *,
    channel: str,
    writer: str,
    count: int,
    kind: str = "chat",
    created_at: datetime | None = None,
    mention_agent: str | None = None,
) -> list[int]:
    timestamp = (created_at or datetime.now(UTC)).isoformat()
    with store._transaction() as connection:
        channel_id = connection.execute(
            "SELECT id FROM channels WHERE name = ?", (channel,)
        ).fetchone()[0]
        previous = connection.execute(
            "SELECT COALESCE(MAX(seq), 0) FROM messages"
        ).fetchone()[0]
        connection.executemany(
            """
            INSERT INTO messages (id, channel_id, agent_id, body, kind, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                (str(uuid.uuid4()), channel_id, writer, f"note {index}", kind, timestamp)
                for index in range(count)
            ),
        )
        sequences = [
            row[0]
            for row in connection.execute(
                "SELECT seq FROM messages WHERE seq > ? ORDER BY seq", (previous,)
            )
        ]
        if mention_agent is not None:
            connection.executemany(
                "INSERT INTO mentions (message_seq, agent_id) VALUES (?, ?)",
                ((seq, mention_agent) for seq in sequences),
            )
    return sequences


def _set_cursor(
    store: SQLiteStore,
    *,
    reader: str,
    channel: str | None,
    seq: int,
    include_stale: bool = False,
    updated_at: datetime | None = None,
) -> None:
    timestamp = (updated_at or datetime.now(UTC)).isoformat()
    with store._transaction() as connection:
        if channel is None:
            connection.execute(
                """
                INSERT INTO mention_cursors (
                    agent_id, include_stale, last_seq, updated_at
                ) VALUES (?, ?, ?, ?)
                """,
                (reader, int(include_stale), seq, timestamp),
            )
        else:
            connection.execute(
                """
                INSERT INTO cursors (
                    agent_id, channel_id, include_stale, last_seq, updated_at
                )
                SELECT ?, id, ?, ?, ? FROM channels WHERE name = ?
                """,
                (reader, int(include_stale), seq, timestamp, channel),
            )


def _observe(store: SQLiteStore, reader: str, **options) -> AgentOrientation:
    return store.agent_orientation(
        agent_id=reader,
        stale_before=datetime.now(UTC) - timedelta(days=7),
        include_stale=options.pop("include_stale", False),
        count_cap=options.pop("count_cap", 500),
        channel_cap=options.pop("channel_cap", 50),
        **options,
    )


def _observe_work(
    store: SQLiteStore, reader: str, monkeypatch: pytest.MonkeyPatch, **options
):
    statements: list[str] = []
    steps = 0
    original = store._connection

    def progress() -> int:
        nonlocal steps
        steps += 100
        return 0

    @contextmanager
    def measured_connection():
        with original() as connection:
            connection.set_trace_callback(statements.append)
            connection.set_progress_handler(progress, 100)
            yield connection

    with monkeypatch.context() as patch:
        patch.setattr(store, "_connection", measured_connection)
        summary = _observe(store, reader, **options)
    return summary, statements, steps


def _source_queries(statements: list[str]) -> list[str]:
    return [
        statement
        for statement in statements
        if "INDEXED BY idx_messages_channel_seq" in statement
        or "INDEXED BY idx_mentions_agent" in statement
    ]


def test_exact_count_at_cap_does_not_claim_a_lower_bound(board_state) -> None:
    store, board, reader, writer = board_state
    board.subscribe("announce", agent_id=reader.id)
    _seed_messages(
        store, channel="announce", writer=writer.id, count=500, mention_agent=reader.id
    )
    summary = _observe(store, reader.id)
    assert summary.unread == summary.pending_mentions == 500
    assert summary.channels[0].unread == 500
    assert not summary.unread_capped
    assert not summary.pending_mentions_capped
    assert not summary.channels[0].unread_capped
    assert summary.counts_complete


def test_subscription_and_mention_union_is_deduplicated(board_state) -> None:
    store, board, reader, writer = board_state
    board.subscribe("announce", agent_id=reader.id)
    board.subscribe("status", agent_id=reader.id)
    for channel in ("announce", "status", "help"):
        _seed_messages(
            store,
            channel=channel,
            writer=writer.id,
            count=2,
            mention_agent=reader.id if channel != "status" else None,
        )
    summary = _observe(store, reader.id)
    assert summary.unread == 6
    assert summary.pending_mentions == 4
    assert [(channel.name, channel.unread) for channel in summary.channels] == [
        ("announce", 2),
        ("status", 2),
    ]
    assert summary.subscription_count == 2
    assert summary.counts_complete


def test_one_candidate_budget_handles_a_duplicate_source_head(board_state) -> None:
    store, board, reader, writer = board_state
    board.subscribe("announce", agent_id=reader.id)
    _seed_messages(
        store, channel="announce", writer=writer.id, count=1, mention_agent=reader.id
    )
    summary = _observe(store, reader.id, candidate_limit=1)
    assert summary.unread == 1 and summary.unread_capped
    assert summary.pending_mentions == 0 and summary.pending_mentions_capped
    assert summary.channels[0].unread == 1
    assert not summary.channels[0].unread_capped
    assert not summary.counts_complete
    assert _observe(store, reader.id, candidate_limit=1) == summary


@pytest.mark.parametrize("mention_only", [False, True])
def test_stale_candidates_are_bounded_before_filtering(
    board_state, monkeypatch: pytest.MonkeyPatch, mention_only: bool
) -> None:
    store, board, reader, writer = board_state
    if not mention_only:
        board.subscribe("status", agent_id=reader.id)
    _seed_messages(
        store,
        channel="status",
        writer=writer.id,
        count=5000,
        kind="status",
        created_at=datetime.now(UTC) - timedelta(days=30),
        mention_agent=reader.id if mention_only else None,
    )
    _seed_messages(
        store,
        channel="status",
        writer=writer.id,
        count=1,
        mention_agent=reader.id if mention_only else None,
    )
    summary, statements, steps = _observe_work(
        store, reader.id, monkeypatch, candidate_limit=8
    )
    assert summary.unread == 0
    assert summary.pending_mentions == 0
    assert summary.unread_capped
    assert summary.pending_mentions_capped is mention_only
    assert not summary.counts_complete
    assert len(_source_queries(statements)) == 8 + (1 if mention_only else 2)
    assert steps < 3000
    if not mention_only:
        assert summary.channels[0].unread == 0
        assert summary.channels[0].unread_capped
    assert not any(
        statement.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
        for statement in statements
    )


def test_incomplete_channel_does_not_obscure_exact_mentions_or_empty_channel(
    board_state,
) -> None:
    store, board, reader, writer = board_state
    board.subscribe("status", agent_id=reader.id)
    board.subscribe("help", agent_id=reader.id)
    _seed_messages(
        store, channel="announce", writer=writer.id, count=1, mention_agent=reader.id
    )
    _seed_messages(
        store,
        channel="status",
        writer=writer.id,
        count=20,
        kind="status",
        created_at=datetime.now(UTC) - timedelta(days=30),
    )
    summary = _observe(store, reader.id, candidate_limit=3)
    assert summary.unread == 1 and summary.unread_capped
    assert summary.pending_mentions == 1 and not summary.pending_mentions_capped
    channels = {channel.name: channel for channel in summary.channels}
    assert channels["help"].unread == 0 and not channels["help"].unread_capped
    assert channels["status"].unread == 0 and channels["status"].unread_capped


def test_incomplete_mentions_do_not_obscure_an_exact_channel(board_state) -> None:
    store, board, reader, writer = board_state
    board.subscribe("announce", agent_id=reader.id)
    _seed_messages(
        store, channel="announce", writer=writer.id, count=1
    )
    _seed_messages(
        store, channel="help", writer=writer.id, count=20, mention_agent=reader.id
    )
    summary = _observe(store, reader.id, candidate_limit=3)
    assert summary.unread == 3 and summary.unread_capped
    assert summary.pending_mentions == 2 and summary.pending_mentions_capped
    assert summary.channels[0].unread == 1
    assert not summary.channels[0].unread_capped


@pytest.mark.parametrize("caught_up", [False, True])
def test_irrelevant_history_does_not_change_indexed_orientation_work(
    board_state, monkeypatch: pytest.MonkeyPatch, caught_up: bool
) -> None:
    store, board, reader, writer = board_state
    board.subscribe("announce", agent_id=reader.id)
    subscribed = _seed_messages(
        store, channel="announce", writer=writer.id, count=1
    )
    mentioned = _seed_messages(
        store, channel="help", writer=writer.id, count=1, mention_agent=reader.id
    )
    if caught_up:
        _set_cursor(store, reader=reader.id, channel="announce", seq=subscribed[-1])
        _set_cursor(store, reader=reader.id, channel=None, seq=mentioned[-1])
    before, queries_before, steps_before = _observe_work(store, reader.id, monkeypatch)
    _seed_messages(store, channel="help", writer=writer.id, count=12000)
    if caught_up:
        more = _seed_messages(store, channel="announce", writer=writer.id, count=8000)
        with store._transaction() as connection:
            connection.execute(
                "UPDATE cursors SET last_seq = ? WHERE agent_id = ?",
                (more[-1], reader.id),
            )
    after, queries_after, steps_after = _observe_work(store, reader.id, monkeypatch)
    assert after.unread == before.unread == (0 if caught_up else 2)
    assert after.pending_mentions == before.pending_mentions == (0 if caught_up else 1)
    assert after.counts_complete
    assert len(_source_queries(queries_before)) == len(_source_queries(queries_after))
    assert steps_after <= steps_before + 300
    with store._connection() as connection:
        plans = [
            " ".join(
                row["detail"]
                for row in connection.execute("EXPLAIN QUERY PLAN " + query)
            )
            for query in _source_queries(queries_after)
        ]
    assert any("idx_messages_channel_seq (channel_id=? AND seq>?)" in p for p in plans)
    assert any("idx_mentions_agent (agent_id=? AND message_seq>?)" in p for p in plans)
    assert any("INTEGER PRIMARY KEY (rowid=?)" in p for p in plans)
    assert all("SCAN message" not in p and "TEMP B-TREE" not in p for p in plans)


def test_channel_output_caps_do_not_cap_scope_counts(board_state) -> None:
    store, board, reader, writer = board_state
    _set_cursor(
        store,
        reader=reader.id,
        channel=None,
        seq=0,
        updated_at=datetime.now(UTC) - timedelta(days=1),
    )
    for index in range(55):
        name = f"project-{index:02}"
        board.create_channel(name, purpose="test", created_by=writer.id)
        board.subscribe(name, agent_id=reader.id)
    summary = _observe(store, reader.id)
    assert summary.subscription_count == 55
    assert len(summary.channels) == 50
    assert len(summary.new_channels) == 50
    assert summary.subscribed_channels_truncated
    assert summary.new_channels_truncated
    assert summary.counts_complete
    assert not summary.unread_capped
    assert all(not channel.unread_capped for channel in summary.channels)


def test_lowered_channel_capacity_does_not_claim_complete_counts(board_state) -> None:
    store, board, reader, _ = board_state
    for name in ("announce", "help", "status"):
        board.subscribe(name, agent_id=reader.id)
    _set_cursor(
        store,
        reader=reader.id,
        channel=None,
        seq=0,
        updated_at=datetime.now(UTC) - timedelta(days=1),
    )
    summary = _observe(store, reader.id, max_channels=2)
    assert summary.subscription_count == 3
    assert len(summary.channels) == 2
    assert summary.unread == 0 and summary.unread_capped
    assert summary.pending_mentions == 0 and not summary.pending_mentions_capped
    assert not summary.counts_complete
    assert summary.subscribed_channels_truncated
    assert summary.new_channels_truncated


@pytest.mark.parametrize("latest_source", ["channel", "mention"])
def test_timestamp_alias_preserves_all_cursor_scopes_and_new_channel_baseline(
    board_state, latest_source: str,
) -> None:
    store, board, reader, writer = board_state
    board.subscribe("announce", agent_id=reader.id)
    old = datetime.now(UTC) - timedelta(days=3)
    newest = old + timedelta(days=2)
    messages = _seed_messages(
        store,
        channel="announce",
        writer=writer.id,
        count=1,
        mention_agent=reader.id,
    )
    _set_cursor(
        store, reader=reader.id, channel="announce", seq=messages[-1], updated_at=old
    )
    _set_cursor(
        store,
        reader=reader.id,
        channel="status",
        seq=0,
        include_stale=True,
        updated_at=newest if latest_source == "channel" else old + timedelta(days=1),
    )
    _set_cursor(
        store,
        reader=reader.id,
        channel=None,
        seq=messages[-1],
        include_stale=True,
        updated_at=newest if latest_source == "mention" else old + timedelta(days=1),
    )
    with store._transaction() as connection:
        connection.execute(
            "UPDATE channels SET created_at = ? WHERE name = ?",
            ((old + timedelta(hours=1)).isoformat(), "help"),
        )
    default = _observe(store, reader.id)
    inclusive = _observe(store, reader.id, include_stale=True)
    assert default.unread == default.pending_mentions == 1
    assert default.channels[0].unread == 0
    assert inclusive.unread == inclusive.channels[0].unread == 1
    assert inclusive.pending_mentions == 0
    for summary in (default, inclusive):
        assert summary.last_cursor_update_at == summary.last_caught_up_at == newest
        assert "help" not in summary.new_channels
        text = guidance(actions=(), orientation=summary, now=datetime.now(UTC))
        assert newest.isoformat() in text
        assert "last caught up" not in text
        assert "hour" not in text
        assert "first session" not in text


def test_incomplete_zero_requires_an_explicit_drain_after_optional_setup(
    client: TestClient,
) -> None:
    created = _register(client, "orient-cli-win")
    roe = client.app.state.roe_service.get_effective(created["agent"]["id"])
    summary = AgentOrientation(
        latest_seq=100,
        unread=0,
        unread_capped=True,
        pending_mentions=0,
        pending_mentions_capped=True,
        last_caught_up_at=None,
        channels=(),
        new_channels=(),
        counts_complete=False,
    )
    actions = required_actions(
        credential_status="pending", roe=roe, orientation=summary
    )
    assert [action.action for action in actions] == [
        "prove_credential",
        "acknowledge_roe",
        "choose_subscriptions",
        "catch_up",
    ]
    assert "exact returned revision IDs and hashes" in actions[1].reason
    assert "catch_up(start_drain=true)" in actions[-1].reason
    assert "empty or short pages" in actions[-1].reason
    text = guidance(actions=actions, orientation=summary, now=datetime.now(UTC))
    assert "zero does not establish" in text
    assert "complete=true" in text
    assert "only direct mentions" in text


def test_service_passes_configured_orientation_limits(
    board_state, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _, reader, writer = board_state
    board = BoardService(
        store,
        max_message_bytes=1024,
        max_metadata_bytes=1024,
        max_channels=2,
        orientation_count_cap=2,
        orientation_channel_cap=1,
        orientation_candidate_limit=3,
    )
    for name in ("announce", "help", "status"):
        board.subscribe(name, agent_id=reader.id)
        _seed_messages(store, channel=name, writer=writer.id, count=5)
    original = store.agent_orientation
    received = {}

    def observed_orientation(**kwargs):
        received.update(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(store, "agent_orientation", observed_orientation)
    summary = board.orientation(agent_id=reader.id)
    assert received["count_cap"] == 2
    assert received["channel_cap"] == 1
    assert received["candidate_limit"] == 3
    assert received["max_channels"] == 2
    assert summary.unread == 2 and summary.unread_capped
    assert len(summary.channels) == 1
    assert summary.subscription_count == 3
    assert summary.subscribed_channels_truncated
    assert not summary.counts_complete


@pytest.mark.parametrize("include_stale", [None, 0, 1, "true"])
def test_orientation_rejects_non_boolean_stale_mode(board_state, include_stale) -> None:
    _, board, reader, _ = board_state
    with pytest.raises(DomainValidationError, match="include_stale"):
        board.orientation(agent_id=reader.id, include_stale=include_stale)
