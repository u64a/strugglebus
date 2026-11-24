from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from strugglebus.migrations import (
    LATEST_SCHEMA_VERSION,
    apply_migrations,
    load_packaged_migrations,
)
from strugglebus.store import SQLiteStore
from test_rest_api import _agent_headers, _register, rest_client  # noqa: F401

TASK = {"task": {"schema": "example.task/1", "action": "build"}}


def test_schema_twenty_upgrades_an_existing_database(tmp_path) -> None:
    database_path = tmp_path / "schema-nineteen.db"
    with sqlite3.connect(database_path, isolation_level=None) as database:
        assert apply_migrations(database, load_packaged_migrations()[:19]) == 19
        database.execute(
            "INSERT INTO agents (id, name, created_at) "
            "VALUES ('host', 'host-one', '2026-01-01T00:00:00Z')"
        )
        database.execute(
            "INSERT INTO channels (id, name, created_at) "
            "VALUES ('c', 'work', '2026-01-01T00:00:00Z')"
        )
        for kind in ("task", "chat"):
            database.execute(
                "INSERT INTO messages (id, channel_id, agent_id, body, kind, meta, created_at) "
                "VALUES (?, 'c', 'host', 'existing', ?, '{}', '2026-01-01T00:00:00Z')",
                (kind, kind),
            )
    store = SQLiteStore(database_path, backup_dir=tmp_path / "backups")

    assert store.initialize() == LATEST_SCHEMA_VERSION == 24
    assert list((tmp_path / "backups").iterdir())
    claim, created = store.claim_message(
        message_seq=1, agent_id="host", claimed_at=datetime(2026, 1, 2, tzinfo=UTC)
    )
    assert created and claim.agent_name == "host-one"
    with sqlite3.connect(database_path) as database:
        assert database.execute("SELECT COUNT(*) FROM messages").fetchone() == (2,)
        with pytest.raises(sqlite3.IntegrityError, match="only task messages"):
            database.execute(
                "INSERT INTO message_claims VALUES (2, 'host', '2026-01-02T00:00:00Z')"
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            database.execute("UPDATE message_claims SET agent_id = 'host'")


def _post_task(client: TestClient, headers: dict[str, str]) -> dict[str, object]:
    response = client.post(
        "/api/channels/status/messages",
        headers=headers,
        json={"body": "build please", "kind": "task", "metadata": TASK},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_task_kind_requires_structured_task_metadata(
    rest_client: TestClient,  # noqa: F811
) -> None:
    headers = _agent_headers(_register(rest_client))

    task = _post_task(rest_client, headers)
    missing = rest_client.post(
        "/api/channels/status/messages",
        headers=headers,
        json={"body": "no payload", "kind": "task"},
    )
    not_object = rest_client.post(
        "/api/channels/status/messages",
        headers=headers,
        json={"body": "bad", "kind": "task", "metadata": {"task": "build"}},
    )

    assert task["kind"] == "task"
    assert task["metadata"] == TASK
    assert missing.status_code == not_object.status_code == 400


def test_claim_first_caller_wins_and_retry_is_idempotent(
    rest_client: TestClient,  # noqa: F811
) -> None:
    first = _agent_headers(_register(rest_client, "host-one"))
    second = _agent_headers(_register(rest_client, "host-two"))
    task = _post_task(rest_client, first)
    path = f"/api/messages/{task['seq']}/claim"

    unclaimed = rest_client.get(path, headers=first)
    won = rest_client.post(path, headers=first)
    retry = rest_client.post(path, headers=first)
    lost = rest_client.post(path, headers=second)
    seen = rest_client.get(path, headers=second)

    assert unclaimed.status_code == 404
    assert won.status_code == 201
    assert won.json()["agent_name"] == "host-one"
    assert retry.status_code == 200
    assert retry.json() == won.json()
    assert lost.status_code == 409
    assert lost.json()["detail"]["claim"]["agent_name"] == "host-one"
    assert seen.json() == won.json()


def test_concurrent_claims_have_exactly_one_winner(
    rest_client: TestClient,  # noqa: F811
) -> None:
    hosts = [
        _agent_headers(_register(rest_client, f"host-{index}"))
        for index in range(6)
    ]
    task = _post_task(rest_client, hosts[0])
    path = f"/api/messages/{task['seq']}/claim"

    with ThreadPoolExecutor(max_workers=len(hosts)) as pool:
        codes = list(
            pool.map(lambda h: rest_client.post(path, headers=h).status_code, hosts)
        )

    assert sorted(codes) == [201] + [409] * (len(hosts) - 1)


def test_only_claimant_releases_and_release_allows_reclaim(
    rest_client: TestClient,  # noqa: F811
) -> None:
    first = _agent_headers(_register(rest_client, "host-one"))
    second = _agent_headers(_register(rest_client, "host-two"))
    task = _post_task(rest_client, first)
    path = f"/api/messages/{task['seq']}/claim"

    assert rest_client.delete(path, headers=first).status_code == 404
    assert rest_client.post(path, headers=first).status_code == 201
    assert rest_client.delete(path, headers=second).status_code == 409
    assert rest_client.delete(path, headers=first).status_code == 204
    reclaimed = rest_client.post(path, headers=second)

    assert reclaimed.status_code == 201
    assert reclaimed.json()["agent_name"] == "host-two"


def test_claim_held_by_a_revoked_agent_can_be_taken(
    rest_client: TestClient,  # noqa: F811
) -> None:
    gone = _register(rest_client, "host-gone")
    other = _agent_headers(_register(rest_client, "host-other"))
    task = _post_task(rest_client, _agent_headers(gone))
    path = f"/api/messages/{task['seq']}/claim"
    assert rest_client.post(path, headers=_agent_headers(gone)).status_code == 201

    rest_client.app.state.agent_service.revoke_agent(gone["id"])
    taken = rest_client.post(path, headers=other)

    assert taken.status_code == 201
    assert taken.json()["agent_name"] == "host-other"


def test_claim_rejects_non_task_missing_invalid_and_anonymous(
    rest_client: TestClient,  # noqa: F811
) -> None:
    headers = _agent_headers(_register(rest_client))
    chat = rest_client.post(
        "/api/channels/status/messages", headers=headers, json={"body": "hi"}
    ).json()

    assert rest_client.post(
        f"/api/messages/{chat['seq']}/claim", headers=headers
    ).status_code == 409
    assert rest_client.post("/api/messages/999999/claim", headers=headers).status_code == 404
    assert rest_client.post("/api/messages/0/claim", headers=headers).status_code == 422
    assert rest_client.post(f"/api/messages/{chat['seq']}/claim").status_code == 401


@pytest.mark.parametrize("method", ["post", "get", "delete"])
def test_claim_routes_are_denied_while_frozen(
    rest_client: TestClient,  # noqa: F811
    method: str,
) -> None:
    headers = _agent_headers(_register(rest_client))
    task = _post_task(rest_client, headers)
    path = f"/api/messages/{task['seq']}/claim"
    freeze = rest_client.app.state.access_freeze_service
    freeze.freeze("claim freeze test")
    try:
        assert getattr(rest_client, method)(path, headers=headers).status_code == 503
    finally:
        freeze.unfreeze("claim freeze test done")
    assert rest_client.get(path, headers=headers).status_code == 404
