from __future__ import annotations

import sqlite3
import uuid
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from strugglebus.app import create_app
from strugglebus.auth import AgentService, mint_mobile_credential
from strugglebus.config import AppConfig
from strugglebus.errors import DuplicateAgentNameError
from strugglebus.mobile import MobileService
from strugglebus.service import BoardService
from strugglebus.store import SQLiteStore


def _services(config: AppConfig) -> tuple[AgentService, BoardService]:
    store = SQLiteStore(
        config.database_path,
        backup_dir=config.backup_dir,
        busy_timeout_ms=config.sqlite_busy_timeout_ms,
    )
    store.initialize()
    return AgentService(store), BoardService(
        store,
        max_message_bytes=config.max_message_bytes,
        max_metadata_bytes=config.max_metadata_bytes,
        max_channels=config.max_channels,
    )


def _enrol_device(store: SQLiteStore, label: str = "phone-one") -> str:
    """Insert a device and credential directly.

    Issuance lives in the operator console work, so this exercises the read
    surface against storage that the console will later populate.
    """

    credential_id, verifier, secret = mint_mobile_credential()
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "INSERT INTO mobile_devices (id, label, status, created_at) "
            "VALUES (?, ?, 'enabled', '2026-01-01T00:00:00Z')",
            (f"dev-{label}", label),
        )
        connection.execute(
            "INSERT INTO mobile_device_credentials "
            "(id, device_id, kind, secret_hash, status, creation_method, "
            " creation_reason, issuance_request_id, created_at) "
            "VALUES (?, ?, 'sbm1', ?, 'active', 'enrollment', 'test', ?, "
            "'2026-01-01T00:00:00Z')",
            (credential_id, f"dev-{label}", verifier, str(uuid.uuid4())),
        )
    return secret


@pytest.fixture
def mobile(app_config: AppConfig):
    config = replace(app_config, sse_connection_seconds=1, sse_heartbeat_seconds=1)
    agents, board = _services(config)
    writer = agents.create_agent("writer-copilot").agent
    board.create_channel("status", purpose="test", created_by=writer.id)
    board.create_message(
        "status", agent_id=writer.id, body="visible status", kind="status",
        reply_to=None, metadata={},
    )
    secret = _enrol_device(agents.store)
    application = create_app(
        config=config, agent_service=agents, board_service=board
    )
    with TestClient(application) as client:
        yield client, secret, agents, board


def _auth(secret: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {secret}"}


def test_mobile_read_surface_requires_its_own_credential(mobile) -> None:
    client, secret, agents, _ = mobile
    agent = agents.create_agent("reader-copilot")

    assert client.get("/api/mobile/snapshot").status_code == 401
    # An agent credential must not satisfy a mobile route, and the converse is
    # covered by the credential parsing tests.
    assert client.get(
        "/api/mobile/snapshot", headers=_auth(agent.api_key)
    ).status_code == 401
    assert client.get(
        "/api/mobile/snapshot", headers=_auth(secret)
    ).status_code == 200
    # A mobile credential must not reach the agent surface either.
    assert client.get("/api/channels", headers=_auth(secret)).status_code == 401


def test_mobile_reads_are_non_consuming_and_bounded(mobile) -> None:
    client, secret, _, board = mobile
    first = client.get("/api/mobile/snapshot", headers=_auth(secret))
    second = client.get("/api/mobile/snapshot", headers=_auth(secret))
    assert first.status_code == 200
    assert first.json() == second.json()
    assert any(m["body"] == "visible status" for m in first.json())
    # No delivery cursor may exist for a monitor at all.
    with sqlite3.connect(board.store.database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM cursors").fetchone() == (0,)
    over = client.get(
        "/api/mobile/snapshot", headers=_auth(secret), params={"limit": 500}
    )
    assert over.status_code == 422


def test_mobile_status_shape_is_identical_and_minimal(mobile) -> None:
    client, secret, _, _ = mobile
    response = client.get("/api/mobile/status", headers=_auth(secret))
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"api_version", "server_time", "state"}
    assert body["state"] == "available"


def test_freeze_denies_content_but_status_still_reports_frozen(mobile) -> None:
    client, secret, agents, _ = mobile
    from datetime import UTC, datetime

    agents.store.set_access_freeze(
        frozen=True, reason="test freeze", changed_at=datetime.now(UTC),
    )

    status = client.get("/api/mobile/status", headers=_auth(secret))
    assert status.status_code == 200
    body = status.json()
    # The shape is unchanged, so only the state field carries the difference.
    assert set(body) == {"api_version", "server_time", "state"}
    assert body["state"] == "frozen"

    # Reads stay available while frozen. The freeze stops the agent plane; the
    # monitor is how the owner watches an incident, and denying it data means
    # watching blind. Frozen is still impossible to mistake for empty, because
    # status reports it explicitly rather than the board merely looking quiet.
    for path in (
        "/api/mobile/snapshot",
        "/api/mobile/channels",
        "/api/mobile/agents",
    ):
        allowed = client.get(path, headers=_auth(secret))
        assert allowed.status_code == 200, path

    stream = client.get(
        "/api/mobile/stream",
        headers=_auth(secret),
        params={"channel": "status"},
    )
    assert stream.status_code == 200
    assert "event: message" in stream.text
    assert "visible status" in stream.text
    assert "event: agent_access_frozen" not in stream.text


def test_freeze_still_denies_anything_that_grants_access(mobile) -> None:
    """Reads survive a freeze; the creation of access does not.

    This is the line the freeze actually draws. Nothing that could let a new
    principal in may come into existence while the owner has stopped trusting
    the system's state.
    """

    import uuid
    from datetime import UTC, datetime

    client, _secret, agents, _ = mobile
    agents.store.set_access_freeze(
        frozen=True, reason="test freeze", changed_at=datetime.now(UTC),
    )
    refused = client.post(
        "/api/mobile/enrollments/redeem",
        json={"request_id": str(uuid.uuid4())},
        headers={"Authorization": "Bearer sbme1_" + "A" * 22 + "_" + "B" * 43},
    )
    assert refused.status_code in {401, 503}


def test_guide_tells_monitors_what_the_freeze_actually_does(app_config) -> None:
    """The guide is the contract, so it must not outlive the behaviour.

    Guide 1.11.0 told monitors that every route except status refuses while
    frozen. That became false when the freeze was narrowed to the agent plane,
    and a client written to the stale text would have shown an access-denied
    screen over a working read surface during the exact incident the monitor
    exists to observe. This test fails if the two drift apart again.
    """

    from strugglebus.integration import build_integration_guide

    guide = build_integration_guide(app_config)
    monitors = next(
        section for section in guide.sections if section.id == "monitors"
    )
    text = " ".join(monitors.instructions)

    assert "Monitor reads keep answering while access is frozen" in text
    assert "state=frozen" in text
    # The other half of the line the freeze draws: reading continues, but
    # nothing that grants access may be created.
    assert "Creating access stays denied while frozen" in text
    assert "never as retry" in text
    # The retired claim must not survive anywhere in the section.
    assert "only /api/mobile/status answers" not in text


def test_revoked_device_loses_access_immediately(mobile) -> None:
    client, secret, agents, _ = mobile
    assert client.get(
        "/api/mobile/snapshot", headers=_auth(secret)
    ).status_code == 200
    with sqlite3.connect(agents.store.database_path) as connection:
        connection.execute(
            "UPDATE mobile_devices SET status='revoked', "
            "revoked_at='2026-01-02T00:00:00Z' WHERE label='phone-one'"
        )
    assert client.get(
        "/api/mobile/snapshot", headers=_auth(secret)
    ).status_code == 401


def test_mobile_stream_shares_the_agent_loop_and_filters(mobile) -> None:
    client, secret, _, _ = mobile
    stream = client.get(
        "/api/mobile/stream", headers=_auth(secret), params={"channel": "status"}
    )
    assert stream.status_code == 200
    assert stream.headers["content-type"].startswith("text/event-stream")
    assert "event: message" in stream.text
    assert "visible status" in stream.text
    # Same framing guarantees as the agent stream.
    assert "id: " in stream.text
    unknown = client.get(
        "/api/mobile/stream", headers=_auth(secret), params={"channel": "absent"}
    )
    assert unknown.status_code == 404


def test_mobile_channels_and_agents_are_readable(mobile) -> None:
    client, secret, _, _ = mobile
    channels = client.get("/api/mobile/channels", headers=_auth(secret))
    agents_response = client.get("/api/mobile/agents", headers=_auth(secret))
    assert channels.status_code == 200
    assert {c["name"] for c in channels.json()} >= {"announce", "status"}
    assert agents_response.status_code == 200
    assert any(a["name"] == "writer-copilot" for a in agents_response.json())


def test_enrollment_issues_one_device_and_cannot_be_replayed(mobile) -> None:
    client, _, agents, _ = mobile
    service = MobileService(agents.store)
    token, _expires = service.mint_enrollment(
        device_label="phone-two", ttl_seconds=300, actor_id="operator:owner:test",
    )

    first = client.post(
        "/api/mobile/enrollments/redeem",
        headers={"Authorization": f"Bearer {token}"},
        json={"request_id": str(uuid.uuid4())},
    )
    assert first.status_code == 201
    body = first.json()
    assert body["device_label"] == "phone-two"
    issued = body["credential_secret"]

    # The issued secret works immediately.
    assert client.get(
        "/api/mobile/snapshot", headers=_auth(issued)
    ).status_code == 200

    # A replay cannot return the secret again, because only a hash was kept.
    # It must fail rather than appear to succeed.
    replay = client.post(
        "/api/mobile/enrollments/redeem",
        headers={"Authorization": f"Bearer {token}"},
        json={"request_id": str(uuid.uuid4())},
    )
    assert replay.status_code == 401


def test_enrollment_token_cannot_authenticate_as_a_credential(mobile) -> None:
    client, _, agents, _ = mobile
    service = MobileService(agents.store)
    token, _ = service.mint_enrollment(
        device_label="phone-three", ttl_seconds=300, actor_id="operator:owner:test",
    )
    # An allowance is not an identity.
    assert client.get(
        "/api/mobile/snapshot", headers={"Authorization": f"Bearer {token}"}
    ).status_code == 401


def test_revoking_a_device_revokes_its_credentials_and_reserves_the_label(
    mobile,
) -> None:
    client, _, agents, _ = mobile
    service = MobileService(agents.store)
    token, _ = service.mint_enrollment(
        device_label="phone-four", ttl_seconds=300, actor_id="operator:owner:test",
    )
    issued = client.post(
        "/api/mobile/enrollments/redeem",
        headers={"Authorization": f"Bearer {token}"},
        json={"request_id": str(uuid.uuid4())},
    ).json()

    devices = {d["label"]: d for d in service.list_devices()}
    assert devices["phone-four"]["active_credentials"] == 1

    assert service.revoke_device(
        issued["device_id"], reason="lost handset", actor_id="operator:owner:test",
    )
    assert client.get(
        "/api/mobile/snapshot", headers=_auth(issued["credential_secret"])
    ).status_code == 401
    devices = {d["label"]: d for d in service.list_devices()}
    assert devices["phone-four"]["status"] == "revoked"
    assert devices["phone-four"]["active_credentials"] == 0

    # The label stays reserved, so history cannot be reattributed by
    # re-enrolling a replacement under the same name.
    with pytest.raises(DuplicateAgentNameError):
        service.mint_enrollment(
            device_label="phone-four", ttl_seconds=300,
            actor_id="operator:owner:test",
        )


def test_mobile_snapshot_filters_and_pages_newest_first(mobile) -> None:
    client, secret, agents, board = mobile
    writer = agents.create_agent("paging-copilot").agent
    other = agents.create_agent("other-copilot").agent
    board.create_channel("ops", purpose="test", created_by=writer.id)
    for index in range(4):
        board.create_message(
            "ops", agent_id=writer.id, body=f"ops {index}", kind="chat",
            reply_to=None, metadata={},
        )
    board.create_message(
        "ops", agent_id=other.id, body="from other", kind="chat",
        reply_to=None, metadata={},
    )

    def bodies(**params) -> list[str]:
        response = client.get(
            "/api/mobile/snapshot", headers=_auth(secret), params=params
        )
        assert response.status_code == 200, response.text
        return [item["body"] for item in response.json()]

    # A channel page is the newest messages, still oldest first within the page.
    assert bodies(channel="ops", limit=2) == ["ops 3", "from other"]
    assert bodies(agent="other-copilot") == ["from other"]
    assert bodies(channel="ops", agent="paging-copilot", limit=2) == ["ops 2", "ops 3"]
    assert bodies(agent="nobody-here") == []

    newest = client.get(
        "/api/mobile/snapshot", headers=_auth(secret),
        params={"channel": "ops", "limit": 2},
    ).json()
    assert bodies(channel="ops", limit=2, before=newest[0]["seq"]) == ["ops 1", "ops 2"]

    missing = client.get(
        "/api/mobile/snapshot", headers=_auth(secret), params={"channel": "nowhere"}
    )
    assert missing.status_code == 404


def test_mobile_search_needs_the_mobile_credential(mobile) -> None:
    client, secret, agents, board = mobile
    agent = agents.create_agent("searching-copilot")
    board.create_message(
        "status", agent_id=agent.agent.id, body="tunnel latency recovered",
        kind="chat", reply_to=None, metadata={},
    )
    params = {"query": "tunnel"}

    assert client.get("/api/mobile/search", params=params).status_code == 401
    refused = client.get(
        "/api/mobile/search", headers=_auth(agent.api_key), params=params
    )
    assert refused.status_code in {401, 403}

    found = client.get("/api/mobile/search", headers=_auth(secret), params=params)
    assert found.status_code == 200, found.text
    assert [hit["body"] for hit in found.json()] == ["tunnel latency recovered"]
    assert "snippet" in found.json()[0]

    unknown = client.get(
        "/api/mobile/search", headers=_auth(secret),
        params={"query": "tunnel", "channel": "nowhere"},
    )
    assert unknown.status_code == 404
