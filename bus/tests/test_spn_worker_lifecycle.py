"""Time-limited SPN worker identities, SPN retire, cascade and self-rotation."""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from strugglebus.migrations import apply_migrations, load_packaged_migrations
from strugglebus.store import SQLiteStore
from test_spn_onboarding import _actor, _create_spn, spn_client  # noqa: F401


def _package(client: TestClient, secret: str, name: str, ttl: int | None = None):
    body: dict[str, object] = {"request_id": str(uuid.uuid4()), "agent_name": name}
    if ttl is not None:
        body["identity_ttl_seconds"] = ttl
    return client.post(
        "/api/spn/onboarding-packages", json=body,
        headers={"Authorization": f"Bearer {secret}"},
    )


def _worker(client: TestClient, secret: str, name: str, ttl: int | None = None) -> str:
    issued = _package(client, secret, name, ttl)
    assert issued.status_code == 201, issued.text
    package = issued.json()["package"]
    redeemed = client.post(
        package["redeem_path"],
        json={"request_id": str(uuid.uuid4()), "name": name},
        headers={"Authorization": f"Bearer {package['enrollment_token']}"},
    )
    assert redeemed.status_code == 201, redeemed.text
    return redeemed.json()["credential_secret"]


def _whoami(client: TestClient, credential: str) -> int:
    return client.get(
        "/api/whoami", headers={"Authorization": f"Bearer {credential}"},
    ).status_code


def _retire(client: TestClient, secret: str, name: str, request_id: str | None = None):
    return client.post(
        f"/api/spn/agents/{name}/retire",
        json={"request_id": request_id or str(uuid.uuid4())},
        headers={"Authorization": f"Bearer {secret}"},
    )


def _state(client: TestClient, name: str) -> str:
    with sqlite3.connect(client.app.state.config.database_path) as database:
        row = database.execute(
            "SELECT revoked_at, blocked_at FROM agents WHERE name = ?", (name,),
        ).fetchone()
    return "retired" if row[0] else "blocked" if row[1] else "enabled"


def test_ttl_identity_stops_at_expiry_and_is_swept(spn_client, monkeypatch) -> None:
    _, secret = _create_spn(spn_client)
    issued = _package(spn_client, secret, "build-w1-20261104a", ttl=600)
    assert issued.status_code == 201
    expires = datetime.fromisoformat(issued.json()["identity_expires_at"])
    assert timedelta(seconds=590) < expires - datetime.now(UTC) <= timedelta(seconds=600)
    assert _package(spn_client, secret, "build-w9", ttl=43201).status_code == 422

    credential = _worker(spn_client, secret, "build-w2-20261104a", ttl=600)
    assert _whoami(spn_client, credential) == 200

    later = datetime.now(UTC) + timedelta(seconds=601)
    monkeypatch.setattr("strugglebus.store._common.utc_now", lambda: later)
    assert _whoami(spn_client, credential) == 401
    assert _state(spn_client, "build-w2-20261104a") == "enabled"

    # The next package by the same SPN retires what has expired.
    spn_client.app.state.spn_service._clock = lambda: later
    assert _package(spn_client, secret, "build-w3").status_code == 201
    assert _state(spn_client, "build-w2-20261104a") == "retired"


def test_spn_retires_only_its_own_identities(spn_client) -> None:
    _, secret = _create_spn(spn_client)
    credential = _worker(spn_client, secret, "build-w1")
    other = spn_client.app.state.spn_service.create(
        name="other-onboarder", agent_name_prefix="other",
        request_id=str(uuid.uuid4()), actor=_actor(),
    ).secret

    assert _retire(spn_client, other, "build-w1").status_code == 404
    assert _retire(spn_client, secret, "build-missing").status_code == 404
    # A worker's own credential is not an SPN credential.
    assert _retire(spn_client, credential, "build-w1").status_code == 401

    request_id = str(uuid.uuid4())
    first = _retire(spn_client, secret, "build-w1", request_id)
    assert first.status_code == 200
    assert first.json()["state"] == "retired"
    assert _retire(spn_client, secret, "build-w1", request_id).json() == first.json()
    assert _retire(spn_client, secret, "build-w1").status_code == 200
    assert _whoami(spn_client, credential) == 401
    assert _state(spn_client, "build-w1") == "retired"


def test_blocking_an_spn_retires_its_live_ttl_identities_only(spn_client) -> None:
    principal, secret = _create_spn(spn_client)
    temporary = _worker(spn_client, secret, "build-w1", ttl=3600)
    durable = _worker(spn_client, secret, "build-w2")
    spn_client.app.state.spn_service.transition(
        principal.id, action="block", expected_version=principal.version,
        request_id=str(uuid.uuid4()), reason="host compromised", actor=_actor(),
    )
    assert _state(spn_client, "build-w1") == "retired"
    assert _whoami(spn_client, temporary) == 401
    assert _state(spn_client, "build-w2") == "enabled"
    assert _whoami(spn_client, durable) == 200


def test_spn_self_rotation_replaces_its_credential_once(spn_client, monkeypatch) -> None:
    _, secret = _create_spn(spn_client)
    request_id = str(uuid.uuid4())
    rotated = spn_client.post(
        "/api/spn/credentials/rotate", json={"request_id": request_id},
        headers={"Authorization": f"Bearer {secret}"},
    )
    assert rotated.status_code == 201
    assert rotated.headers["Cache-Control"] == "no-store"
    successor = rotated.json()["credential"]
    assert successor.startswith("sbsp1_")
    # The predecessor keeps working for a minute, then stops.
    assert _package(spn_client, secret, "build-w1").status_code == 201
    later = datetime.now(UTC) + timedelta(seconds=61)
    spn_client.app.state.spn_service._clock = lambda: later
    monkeypatch.setattr("strugglebus.store._service_principals.utc_now", lambda: later)
    assert _package(spn_client, secret, "build-w2").status_code == 401
    assert _package(spn_client, successor, "build-w2").status_code == 201

    replay = spn_client.post(
        "/api/spn/credentials/rotate", json={"request_id": request_id},
        headers={"Authorization": f"Bearer {successor}"},
    )
    assert replay.status_code == 200
    assert replay.json()["credential"] is None

    second = spn_client.post(
        "/api/spn/credentials/rotate", json={"request_id": str(uuid.uuid4())},
        headers={"Authorization": f"Bearer {successor}"},
    ).json()["credential"]
    limited = spn_client.post(
        "/api/spn/credentials/rotate", json={"request_id": str(uuid.uuid4())},
        headers={"Authorization": f"Bearer {second}"},
    )
    assert limited.status_code == 409
    assert secret.encode("ascii") not in (
        spn_client.app.state.config.database_path.read_bytes()
    )


def test_schema_twenty_one_upgrades_with_durable_identities(tmp_path) -> None:
    path = tmp_path / "schema21.db"
    migrations = load_packaged_migrations()
    with sqlite3.connect(path, isolation_level=None) as database:
        assert apply_migrations(database, migrations[:21]) == 21
        database.execute(
            "INSERT INTO agents (id, name, created_at) VALUES (?, ?, ?)",
            ("legacy-agent", "legacy-agent", datetime.now(UTC).isoformat()),
        )
    assert SQLiteStore(path, backup_dir=tmp_path / "backups").initialize() == 25
    with sqlite3.connect(path) as database:
        assert database.execute(
            "SELECT expires_at FROM agents WHERE id = 'legacy-agent'"
        ).fetchone() == (None,)
        try:
            database.execute(
                "UPDATE agents SET expires_at = '2026-01-01' WHERE id = 'legacy-agent'"
            )
        except sqlite3.IntegrityError as error:
            assert "immutable" in str(error)
        else:
            raise AssertionError("agent expiry must be immutable")
    assert list((tmp_path / "backups").iterdir())


def test_refused_and_lifecycle_requests_reach_the_audit_feed(
    spn_client, monkeypatch,
) -> None:
    import json

    _, secret = _create_spn(spn_client)
    emitted: list[str] = []
    monkeypatch.setattr("strugglebus.api.emit_audit", emitted.append)
    assert _package(spn_client, secret, "build-w1", ttl=43201).status_code == 422
    assert _whoami(spn_client, "sb1_not-a-real-credential") == 401
    assert all(line.startswith("strugglebus-audit ") for line in emitted)
    lines = [json.loads(line.removeprefix("strugglebus-audit ")) for line in emitted]
    requests = [line for line in lines if line["table"] == "request"]
    assert [(line["event"], line["status"], line["outcome"]) for line in requests] == [
        ("POST /api/spn/onboarding-packages", 422, "refused"),
        ("GET /api/whoami", 401, "refused"),
    ]
    assert all(line["remote_address"] == "testclient" for line in requests)
    assert requests[0]["spn_id"] is not None
    assert secret not in json.dumps(lines)
