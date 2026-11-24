"""The device containment surface: two proofs, one action, one target.

These tests exist because the write path is the first mechanism that lets
something other than the console change state, and because most of its
guarantees are invisible in a happy-path response.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from strugglebus.app import create_app
from strugglebus.auth import AgentService, mint_mobile_credential
from strugglebus.config import AppConfig
from strugglebus.mobile import MobileService
from strugglebus.operator_auth import create_password_verifier
from strugglebus.service import BoardService
from strugglebus.store import SQLiteStore

OPERATOR_PASSWORD = "correct horse battery staple"


def _auth(secret: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {secret}"}


@pytest.fixture
def surface(tmp_path, app_config: AppConfig, monkeypatch):
    # The credential loader requires root ownership unless the file is a
    # systemd credential projection, which is how the service actually
    # receives it. Mirroring that here keeps the test honest and is the only
    # shape that works for a non-root CI user.
    projection = tmp_path / "projected-credentials"
    projection.mkdir(mode=0o700)
    verifier_path = projection / "operator-password"
    verifier_path.write_bytes(create_password_verifier(OPERATOR_PASSWORD))
    verifier_path.chmod(0o400)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(projection))
    config = replace(
        app_config,
        operator_credential_path=verifier_path,
        sse_poll_interval_ms=10,
    )
    store = SQLiteStore(
        config.database_path,
        backup_dir=config.backup_dir,
        busy_timeout_ms=config.sqlite_busy_timeout_ms,
    )
    store.initialize()
    agents = AgentService(store)
    board = BoardService(
        store,
        max_message_bytes=config.max_message_bytes,
        max_metadata_bytes=config.max_metadata_bytes,
        max_channels=config.max_channels,
    )
    mobile = MobileService(store)

    credential_id, verifier, secret = mint_mobile_credential()
    now = datetime.now(UTC)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "INSERT INTO mobile_devices (id, label, status, created_at) "
            "VALUES ('dev-1', 'phone-one', 'enabled', ?)",
            (now.isoformat().replace("+00:00", "Z"),),
        )
        connection.execute(
            "INSERT INTO mobile_device_credentials "
            "(id, device_id, kind, secret_hash, status, creation_method, "
            " creation_reason, issuance_request_id, created_at) "
            "VALUES (?, 'dev-1', 'sbm1', ?, 'active', 'enrollment', 'test', "
            "?, ?)",
            (
                credential_id, verifier, str(uuid.uuid4()),
                now.isoformat().replace("+00:00", "Z"),
            ),
        )

    application = create_app(
        agent_service=agents, board_service=board, config=config,
    )
    application.state.mobile_service = mobile
    with TestClient(application) as client:
        yield client, secret, agents, store


def _grant(client, secret: str) -> str:
    response = client.post(
        "/api/mobile/grants",
        json={
            "request_id": str(uuid.uuid4()),
            "operator_password": OPERATOR_PASSWORD,
            "reason": "device setup",
        },
        headers=_auth(secret),
    )
    assert response.status_code == 201, response.text
    return response.json()["grant_secret"]


def _confirm(client, secret: str, action: str, target_id: str):
    return client.post(
        "/api/mobile/confirmations",
        json={
            "request_id": str(uuid.uuid4()),
            "action": action,
            "target_id": target_id,
        },
        headers=_auth(secret),
    )


def _enabled_agent(agents: AgentService, name: str):
    created = agents.create_agent(name)
    identity = agents.authorize(created.api_key)
    assert identity is not None
    agents.prove(
        identity,
        request_id=str(uuid.uuid4()),
        expected_agent_id=identity.agent.id,
        expected_agent_name=identity.agent.name,
        expected_credential_epoch=identity.agent.credential_epoch,
        expected_credential_version=identity.credential.version,
    )
    return agents.get_managed_agent(created.agent.id, require_access=False)


def test_a_read_credential_alone_cannot_write(surface) -> None:
    """The property the whole design exists for.

    Possession of the running app must not be a write capability. The device
    is fully authenticated here - its reads work - and the action is still
    refused because it carries no grant.
    """

    client, secret, agents, _store = surface
    agent = _enabled_agent(agents, "target-agent")
    assert client.get("/api/mobile/snapshot", headers=_auth(secret)).status_code == 200

    confirmation = _confirm(client, secret, "block-agent", agent.id)
    assert confirmation.status_code == 201

    refused = client.post(
        "/api/mobile/actions",
        json={
            "request_id": str(uuid.uuid4()),
            "confirmation_id": confirmation.json()["confirmation_id"],
            "action": "block-agent",
            "target_id": agent.id,
            "grant_secret": "sbmw1_" + "A" * 43,
            "reason": "should not apply",
        },
        headers=_auth(secret),
    )
    assert refused.status_code == 401
    assert agents.get_managed_agent(agent.id).state == "enabled"


def test_a_confirmation_cannot_be_spent_on_a_different_action(surface) -> None:
    """A confirmation is bound, not a general permission to write.

    The dangerous version of this bug is silent: spend a confirmation for a
    small action, execute the bound larger one, and record an audit entry that
    is truthful about the wrong thing. The server must refuse instead.
    """

    client, secret, agents, _store = surface
    grant = _grant(client, secret)
    agent = _enabled_agent(agents, "bound-agent")
    confirmation = _confirm(client, secret, "block-agent", agent.id)
    assert confirmation.status_code == 201

    mismatched = client.post(
        "/api/mobile/actions",
        json={
            "request_id": str(uuid.uuid4()),
            "confirmation_id": confirmation.json()["confirmation_id"],
            "action": "activate-freeze",
            "target_id": "global",
            "grant_secret": grant,
            "reason": "action swap",
        },
        headers=_auth(secret),
    )
    assert mismatched.status_code == 409
    # Neither the declared action nor the bound one may have happened.
    assert agents.get_managed_agent(agent.id).state == "enabled"


def test_a_confirmation_is_single_use(surface) -> None:
    client, secret, agents, _store = surface
    grant = _grant(client, secret)
    agent = _enabled_agent(agents, "once-agent")
    confirmation_id = _confirm(
        client, secret, "block-agent", agent.id
    ).json()["confirmation_id"]

    def spend() -> int:
        return client.post(
            "/api/mobile/actions",
            json={
                "request_id": str(uuid.uuid4()),
                "confirmation_id": confirmation_id,
                "action": "block-agent",
                "target_id": agent.id,
                "grant_secret": grant,
                "reason": "containment",
            },
            headers=_auth(secret),
        ).status_code

    assert spend() == 200
    assert agents.get_managed_agent(agent.id).state == "blocked"
    assert spend() == 409


def test_expansion_actions_are_refused_by_name(surface) -> None:
    """The confirmation flow stays containment only.

    Management actions have their own routes, so a confirmation can never be
    minted for one. Checked here so the app is told early, and enforced
    independently by the database CHECK constraint.
    """

    client, secret, agents, _store = surface
    agent = _enabled_agent(agents, "expansion-agent")
    for action in ("unblock-agent", "retire-agent", "enrol-device", "enroll-agent"):
        response = _confirm(client, secret, action, agent.id)
        assert response.status_code == 422, action
        assert "/api/mobile/admin" in response.json()["detail"]


def test_containment_works_while_frozen_but_granting_does_not(surface) -> None:
    """The asymmetry the freeze design turns on.

    A freeze is declared because something is wrong, so the actions that
    contain it must keep working - otherwise the control prevents its own use.
    What must not happen during a freeze is new authority coming into
    existence, so establishing a grant is refused.
    """

    client, secret, agents, store = surface
    grant = _grant(client, secret)
    agent = _enabled_agent(agents, "frozen-agent")
    store.set_access_freeze(
        frozen=True, reason="incident", changed_at=datetime.now(UTC),
    )

    confirmation = _confirm(client, secret, "block-agent", agent.id)
    assert confirmation.status_code == 201, confirmation.text
    applied = client.post(
        "/api/mobile/actions",
        json={
            "request_id": str(uuid.uuid4()),
            "confirmation_id": confirmation.json()["confirmation_id"],
            "action": "block-agent",
            "target_id": agent.id,
            "grant_secret": grant,
            "reason": "containment during incident",
        },
        headers=_auth(secret),
    )
    assert applied.status_code == 200, applied.text
    # Read it back the way an operator surface would: the freeze is still on,
    # and console-class reads are exempt from it by design.
    assert agents.get_managed_agent(agent.id, require_access=False).state == "blocked"

    refused = client.post(
        "/api/mobile/grants",
        json={
            "request_id": str(uuid.uuid4()),
            "operator_password": OPERATOR_PASSWORD,
            "reason": "second device during a freeze",
        },
        headers=_auth(secret),
    )
    assert refused.status_code == 503
    # Status alone is not proof; no new grant may exist.
    with sqlite3.connect(store.database_path) as connection:
        active = connection.execute(
            "SELECT COUNT(*) FROM mobile_write_grants WHERE status = 'active'"
        ).fetchone()[0]
    assert active == 1


def test_revoking_the_device_kills_its_write_grant(surface) -> None:
    """Containment is the justification for holding a second secret at all.

    If revoking a device left a live grant behind, the argument for storing a
    per-device secret rather than the operator password would collapse.
    """

    client, secret, _agents, store = surface
    grant = _grant(client, secret)
    confirmation = _confirm(client, secret, "revoke-device", "dev-1")
    assert confirmation.status_code == 201

    revoked = client.post(
        "/api/mobile/actions",
        json={
            "request_id": str(uuid.uuid4()),
            "confirmation_id": confirmation.json()["confirmation_id"],
            "action": "revoke-device",
            "target_id": "dev-1",
            "grant_secret": grant,
            "reason": "handset lost",
        },
        headers=_auth(secret),
    )
    assert revoked.status_code == 200

    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM mobile_write_grants WHERE status = 'active'"
        ).fetchone()[0] == 0
    # And the device cannot read either.
    assert client.get(
        "/api/mobile/snapshot", headers=_auth(secret)
    ).status_code == 401


def test_mobile_freeze_records_the_deciding_device(surface) -> None:
    client, secret, _agents, store = surface
    grant = _grant(client, secret)
    confirmation = _confirm(client, secret, "activate-freeze", "global")

    response = client.post(
        "/api/mobile/actions",
        json={
            "request_id": str(uuid.uuid4()),
            "confirmation_id": confirmation.json()["confirmation_id"],
            "action": "activate-freeze",
            "target_id": "global",
            "grant_secret": grant,
            "reason": "mobile containment",
        },
        headers=_auth(secret),
    )

    assert response.status_code == 200, response.text
    assert store.get_access_freeze().frozen is True
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT actor_type, actor_id FROM agent_access_audit "
            "WHERE transition = 'freeze'"
        ).fetchone() == ("remote-admin", "device:dev-1")


def test_live_device_and_grant_can_clear_freeze(surface) -> None:
    client, secret, _agents, store = surface
    grant = _grant(client, secret)
    store.set_access_freeze(
        frozen=True, reason="incident", changed_at=datetime.now(UTC),
    )
    confirmation = _confirm(client, secret, "clear-freeze", "global")

    response = client.post(
        "/api/mobile/actions",
        json={
            "request_id": str(uuid.uuid4()),
            "confirmation_id": confirmation.json()["confirmation_id"],
            "action": "clear-freeze",
            "target_id": "global",
            "grant_secret": grant,
            "reason": "owner confirmed recovery",
        },
        headers=_auth(secret),
    )

    assert response.status_code == 200, response.text
    assert response.json()["applied"] is True
    assert store.get_access_freeze().frozen is False
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT actor_type, actor_id FROM agent_access_audit "
            "WHERE transition = 'unfreeze'"
        ).fetchone() == ("remote-admin", "device:dev-1")


def test_revoked_device_cannot_clear_freeze_after_initial_validation(
    surface, monkeypatch,
) -> None:
    client, secret, _agents, store = surface
    grant = _grant(client, secret)
    store.set_access_freeze(
        frozen=True, reason="incident", changed_at=datetime.now(UTC),
    )
    confirmation = _confirm(client, secret, "clear-freeze", "global")
    assert confirmation.status_code == 201

    service = client.app.state.mobile_service
    consume_confirmation = service.consume_confirmation

    def consume_then_revoke(**kwargs):
        bound = consume_confirmation(**kwargs)
        assert bound is not None
        assert store.revoke_mobile_device(
            device_id="dev-1",
            reason="revoked during action",
            actor_type="remote-admin",
            actor_id="operator:test",
            revoked_at=datetime.now(UTC),
        )
        return bound

    monkeypatch.setattr(service, "consume_confirmation", consume_then_revoke)
    refused = client.post(
        "/api/mobile/actions",
        json={
            "request_id": str(uuid.uuid4()),
            "confirmation_id": confirmation.json()["confirmation_id"],
            "action": "clear-freeze",
            "target_id": "global",
            "grant_secret": grant,
            "reason": "must not clear after revocation",
        },
        headers=_auth(secret),
    )

    assert refused.status_code == 401, refused.text
    assert store.get_access_freeze().frozen is True
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM agent_access_audit WHERE transition = 'unfreeze'"
        ).fetchone()[0] == 0


def test_revoked_grant_cannot_clear_freeze_after_initial_validation(
    surface, monkeypatch,
) -> None:
    client, secret, _agents, store = surface
    grant = _grant(client, secret)
    store.set_access_freeze(
        frozen=True, reason="incident", changed_at=datetime.now(UTC),
    )
    confirmation = _confirm(client, secret, "clear-freeze", "global")
    service = client.app.state.mobile_service
    consume_confirmation = service.consume_confirmation

    def consume_then_revoke_grant(**kwargs):
        bound = consume_confirmation(**kwargs)
        assert bound is not None
        with sqlite3.connect(store.database_path) as connection:
            connection.execute(
                "UPDATE mobile_write_grants SET status = 'revoked', "
                "revoked_at = ?, revocation_reason = 'test revocation' "
                "WHERE device_id = 'dev-1' AND status = 'active'",
                (datetime.now(UTC).isoformat().replace("+00:00", "Z"),),
            )
        return bound

    monkeypatch.setattr(service, "consume_confirmation", consume_then_revoke_grant)
    refused = client.post(
        "/api/mobile/actions",
        json={
            "request_id": str(uuid.uuid4()),
            "confirmation_id": confirmation.json()["confirmation_id"],
            "action": "clear-freeze",
            "target_id": "global",
            "grant_secret": grant,
            "reason": "must not clear with replaced grant",
        },
        headers=_auth(secret),
    )

    assert refused.status_code == 401, refused.text
    assert store.get_access_freeze().frozen is True


def test_a_grant_is_bound_to_one_device(surface) -> None:
    """A grant lifted from one handset must not work as another's.

    The device identity is part of the hash input, so the same secret bytes
    presented for a different device produce a different verifier.
    """

    from strugglebus.auth import mint_mobile_write_grant, parse_mobile_write_grant

    _client, _secret, _agents, _store = surface
    verifier, token = mint_mobile_write_grant("dev-1")
    assert parse_mobile_write_grant(token, "dev-1") == verifier
    assert parse_mobile_write_grant(token, "dev-2") != verifier


def test_establishing_a_grant_revokes_its_predecessor(surface) -> None:
    """A device holds one write secret, never two.

    Re-establishing is how an owner recovers from a suspected leak, so the old
    secret has to stop working at that moment rather than expiring later.
    """

    client, secret, _agents, store = surface
    first = _grant(client, secret)
    second = _grant(client, secret)
    assert first != second

    confirmation = _confirm(client, secret, "activate-freeze", "global")
    stale = client.post(
        "/api/mobile/actions",
        json={
            "request_id": str(uuid.uuid4()),
            "confirmation_id": confirmation.json()["confirmation_id"],
            "action": "activate-freeze",
            "target_id": "global",
            "grant_secret": first,
            "reason": "using the retired secret",
        },
        headers=_auth(secret),
    )
    assert stale.status_code == 401
    assert store.get_access_freeze().frozen is False


def test_the_confirmation_describes_the_effect_not_just_the_verb(surface) -> None:
    """The owner approves a consequence, so a consequence must be shown."""

    client, secret, _agents, _store = surface
    response = _confirm(client, secret, "activate-freeze", "global")
    body = response.json()
    assert body["target_label"] == "agent access"
    assert "Monitors and the operator console keep reading" in body["effect"]
    assert "Every agent is denied" in body["effect"]


def _human_post(client, secret: str, grant: str | None, **fields):
    payload = {"request_id": str(uuid.uuid4()), "body": "hello agents", **fields}
    if grant is not None:
        payload["grant_secret"] = grant
    return client.post(
        "/api/mobile/humans/messages", json=payload, headers=_auth(secret),
    )


def _human_count(store) -> int:
    with sqlite3.connect(store.database_path) as connection:
        return connection.execute(
            "SELECT COUNT(*) FROM messages AS m JOIN channels AS c "
            "ON c.id = m.channel_id WHERE c.name = 'humans'"
        ).fetchone()[0]


def test_device_with_grant_posts_to_humans_as_the_operator(surface) -> None:
    client, secret, _agents, store = surface
    grant = _grant(client, secret)
    posted = _human_post(client, secret, grant, kind="question", body="ready @x?")
    assert posted.status_code == 201, posted.text
    message = posted.json()
    assert message["channel"] == "humans"
    assert message["agent_name"] == "human:operator"
    assert message["kind"] == "question"
    assert "grant_secret" not in posted.text and grant not in posted.text
    snapshot = client.get(
        "/api/mobile/snapshot", params={"channel": "humans"}, headers=_auth(secret),
    )
    assert [item["seq"] for item in snapshot.json()] == [message["seq"]]


def test_device_human_post_requires_a_valid_grant(surface) -> None:
    client, secret, _agents, store = surface
    assert _human_post(client, secret, None).status_code == 422
    assert _human_post(client, secret, "sbmw1_" + "x" * 43).status_code == 401
    assert _human_count(store) == 0


def test_device_human_post_refuses_agent_credentials_and_anonymous(surface) -> None:
    client, _secret, agents, store = surface
    created = agents.create_agent("poster-agent")
    for headers in ({}, _auth(created.api_key)):
        response = client.post(
            "/api/mobile/humans/messages",
            json={"request_id": str(uuid.uuid4()), "body": "x", "grant_secret": "x"},
            headers=headers,
        )
        assert response.status_code == 401
    assert _human_count(store) == 0


def test_revoked_device_cannot_post_to_humans(surface) -> None:
    client, secret, _agents, store = surface
    grant = _grant(client, secret)
    confirmation = _confirm(client, secret, "revoke-device", "dev-1")
    revoked = client.post(
        "/api/mobile/actions",
        json={
            "request_id": str(uuid.uuid4()),
            "confirmation_id": confirmation.json()["confirmation_id"],
            "action": "revoke-device", "target_id": "dev-1",
            "grant_secret": grant, "reason": "handset lost",
        },
        headers=_auth(secret),
    )
    assert revoked.status_code == 200
    assert _human_post(client, secret, grant).status_code == 401
    assert _human_count(store) == 0


def test_device_human_post_continues_while_frozen(surface) -> None:
    client, secret, _agents, store = surface
    grant = _grant(client, secret)
    store.set_access_freeze(frozen=True, reason="incident", changed_at=datetime.now(UTC))
    assert _human_post(client, secret, grant).status_code == 201
    assert store.get_access_freeze().frozen is True


def test_device_human_post_is_idempotent_and_bounded(surface) -> None:
    client, secret, _agents, store = surface
    grant = _grant(client, secret)
    request_id = str(uuid.uuid4())
    first = _human_post(client, secret, grant, request_id=request_id)
    again = _human_post(client, secret, grant, request_id=request_id)
    assert first.status_code == again.status_code == 201
    assert first.json()["seq"] == again.json()["seq"]
    changed = _human_post(client, secret, grant, request_id=request_id, body="other")
    assert changed.status_code == 409
    assert _human_post(client, secret, grant, kind="announce").status_code == 422
    assert _human_post(client, secret, grant, request_id="not-a-uuid").status_code == 422
    assert _human_post(client, secret, grant, body="x" * 2_000_000).status_code in {413, 422}
    assert _human_count(store) == 1


def test_device_human_reply_must_target_humans(surface) -> None:
    client, secret, agents, store = surface
    grant = _grant(client, secret)
    agent = _enabled_agent(agents, "elsewhere-agent")
    board = BoardService(store, max_message_bytes=65536, max_metadata_bytes=4096, max_channels=64)
    other = board.create_message(
        "announce", agent_id=agent.id, body="not humans", kind="chat",
        reply_to=None, metadata={}, request_id=str(uuid.uuid4()),
    )
    response = _human_post(client, secret, grant, kind="answer", reply_to=other.seq)
    assert response.status_code == 400
    assert _human_count(store) == 0


def _enroll_agent(client, secret: str, grant: str | None, name: str = "adlab-cli-win"):
    body = {
        "request_id": str(uuid.uuid4()), "name": name,
        "description": "test agent", "reason": "set up from the app",
    }
    if grant is not None:
        body["grant_secret"] = grant
    return client.post(
        "/api/mobile/enrollments/agents", json=body, headers=_auth(secret)
    )


def test_device_creates_an_agent_enrollment_that_redeems(surface) -> None:
    client, secret, agents, _store = surface
    grant = _grant(client, secret)

    created = _enroll_agent(client, secret, grant)

    assert created.status_code == 201, created.text
    assert created.headers["cache-control"] == "no-store"
    body = created.json()
    assert body["agent_name"] == "adlab-cli-win"
    package = body["package"]
    token = next(
        line.split(":", 1)[1].strip()
        for line in package.splitlines() if line.startswith("Enrollment")
    )
    # The package stays short: redemption, the one timed call, then orientation
    # takes over.
    assert "call orientation" in package
    assert "agent recover" not in package and len(package.splitlines()) < 70
    assert grant not in package

    redeemed = client.post(
        "/api/enrollments/redeem",
        json={"request_id": str(uuid.uuid4()), "name": "adlab-cli-win"},
        headers=_auth(token),
    )
    assert redeemed.status_code == 201, redeemed.text
    assert redeemed.json()["agent"]["name"] == "adlab-cli-win"


def test_device_enrollment_needs_the_grant_and_a_valid_name(surface) -> None:
    client, secret, agents, _store = surface
    grant = _grant(client, secret)
    agent = agents.create_agent("plain-copilot")

    assert _enroll_agent(client, secret, None).status_code == 422
    assert _enroll_agent(client, secret, "not-the-grant").status_code == 401
    assert _enroll_agent(client, agent.api_key, grant).status_code in {401, 403}
    assert _enroll_agent(client, secret, grant, name="nohyphen").status_code == 422


def test_device_enrollment_is_refused_while_frozen(surface) -> None:
    client, secret, _agents, store = surface
    grant = _grant(client, secret)
    store.set_access_freeze(
        frozen=True, reason="test freeze", changed_at=datetime.now(UTC),
    )

    assert _enroll_agent(client, secret, grant).status_code == 503


def test_device_creates_a_service_principal_once(surface) -> None:
    client, secret, _agents, _store = surface
    grant = _grant(client, secret)
    body = {
        "request_id": str(uuid.uuid4()), "name": "nightly-audit",
        "agent_name_prefix": "audit-worker", "reason": "automation",
        "grant_secret": grant,
    }

    created = client.post(
        "/api/mobile/enrollments/service-principals", json=body, headers=_auth(secret)
    )
    assert created.status_code == 201, created.text
    assert created.json()["secret_issued"] is True
    assert created.json()["credential_secret"]

    # The same request again commits nothing new and never repeats the secret.
    replay = client.post(
        "/api/mobile/enrollments/service-principals", json=body, headers=_auth(secret)
    )
    assert replay.status_code in {201, 409}
    if replay.status_code == 201:
        assert replay.json()["credential_secret"] is None

    refused = client.post(
        "/api/mobile/enrollments/service-principals",
        json={**body, "request_id": str(uuid.uuid4()), "grant_secret": "wrong"},
        headers=_auth(secret),
    )
    assert refused.status_code == 401


def test_device_enrollment_of_a_device_needs_a_published_ca(surface) -> None:
    client, secret, _agents, _store = surface
    grant = _grant(client, secret)
    body = {
        "request_id": str(uuid.uuid4()), "label": "second-pc",
        "reason": "new workstation", "grant_secret": grant,
    }

    # This fixture publishes no CA root, so a device could not verify the bus.
    missing = client.post(
        "/api/mobile/enrollments/devices", json=body, headers=_auth(secret)
    )
    assert missing.status_code == 503

    refused = client.post(
        "/api/mobile/enrollments/devices",
        json={**body, "grant_secret": "wrong"}, headers=_auth(secret),
    )
    assert refused.status_code == 401


# ---- Operator management from a device -----------------------------------


def _control(client, secret, grant, agent, action, **overrides):
    body = {
        "request_id": str(uuid.uuid4()), "action": action,
        "expected_name": agent.name,
        "expected_credential_epoch": agent.credential_epoch,
        "reason": "operator decision", "grant_secret": grant,
    }
    body.update(overrides)
    return client.post(
        f"/api/mobile/admin/agents/{agent.id}/control", json=body, headers=_auth(secret)
    )


def _listed(client, secret, name, state="all"):
    response = client.get(
        "/api/mobile/admin/agents", params={"state": state}, headers=_auth(secret)
    )
    assert response.status_code == 200, response.text
    return next((row for row in response.json() if row["name"] == name), None)


def test_device_lists_agents_with_the_actions_their_state_allows(surface) -> None:
    client, secret, agents, _store = surface
    agent = _enabled_agent(agents, "roster-agent")

    row = _listed(client, secret, "roster-agent", state="managed")
    assert row["id"] == agent.id and row["state"] == "enabled"
    assert [option["action"] for option in row["actions"]] == ["block", "retire"]
    assert all(option["effect"] for option in row["actions"])

    assert client.get("/api/mobile/admin/agents").status_code == 401
    assert client.get(
        "/api/mobile/admin/agents", params={"state": "nonsense"}, headers=_auth(secret)
    ).status_code == 422


def test_device_blocks_unblocks_and_retires_an_agent(surface) -> None:
    client, secret, agents, _store = surface
    agent = _enabled_agent(agents, "lifecycle-agent")
    grant = _grant(client, secret)

    blocked = _control(client, secret, grant, agent, "block")
    assert blocked.status_code == 200, blocked.text
    assert blocked.json()["applied"] is True and blocked.json()["state"] == "blocked"
    assert blocked.json()["secret"] is None
    assert blocked.headers["cache-control"] == "no-store"

    row = _listed(client, secret, "lifecycle-agent")
    assert [option["action"] for option in row["actions"]] == ["unblock", "retire"]

    # The epoch the owner was shown is now stale, so the old view cannot act.
    stale = _control(client, secret, grant, agent, "unblock")
    assert stale.status_code == 409

    current = agents.get_managed_agent(agent.id, require_access=False)
    unblocked = _control(client, secret, grant, current, "unblock")
    assert unblocked.status_code == 200, unblocked.text
    assert unblocked.json()["state"] == "enabled"

    current = agents.get_managed_agent(agent.id, require_access=False)
    retired = _control(client, secret, grant, current, "retire")
    assert retired.status_code == 200, retired.text
    assert retired.json()["state"] == "retired"
    row = _listed(client, secret, "lifecycle-agent")
    assert row["state"] == "retired" and row["actions"] == [] and row["retired_at"]
    assert _listed(client, secret, "lifecycle-agent", state="managed") is None

    events = agents.store.list_agent_lifecycle_events(agent.id, require_access=False)
    assert [event.action for event in events][-3:] == ["block", "unblock", "retire"]
    assert {event.actor_id for event in events[-3:]} == {"device:phone-one"}


def test_device_agent_control_needs_the_grant_and_the_exact_target(surface) -> None:
    client, secret, agents, _store = surface
    agent = _enabled_agent(agents, "guarded-agent")
    grant = _grant(client, secret)

    assert _control(client, secret, "wrong", agent, "block").status_code == 401
    assert _control(
        client, secret, grant, agent, "block", expected_name="other-agent"
    ).status_code == 409
    assert _control(client, secret, grant, agent, "delete").status_code == 422
    # Reconnect packages stay on the console.
    assert _control(client, secret, grant, agent, "reconnect").status_code == 422
    missing = client.post(
        f"/api/mobile/admin/agents/{uuid.uuid4()}/control",
        json={
            "request_id": str(uuid.uuid4()), "action": "block",
            "expected_name": agent.name, "expected_credential_epoch": 0,
            "reason": "x", "grant_secret": grant,
        },
        headers=_auth(secret),
    )
    assert missing.status_code == 404
    assert agents.get_managed_agent(agent.id).state == "enabled"


def test_device_can_block_but_not_unblock_while_frozen(surface) -> None:
    client, secret, agents, _store = surface
    agent = _enabled_agent(agents, "frozen-agent")
    grant = _grant(client, secret)
    confirmation = _confirm(client, secret, "activate-freeze", "system").json()
    frozen = client.post(
        "/api/mobile/actions",
        json={
            "request_id": str(uuid.uuid4()),
            "confirmation_id": confirmation["confirmation_id"],
            "action": "activate-freeze", "target_id": "system",
            "grant_secret": grant, "reason": "incident",
        },
        headers=_auth(secret),
    )
    assert frozen.status_code == 200, frozen.text

    blocked = _control(client, secret, grant, agent, "block")
    assert blocked.status_code == 200, blocked.text
    current = agents.get_managed_agent(agent.id, require_access=False)
    refused = _control(client, secret, grant, current, "unblock")
    assert refused.status_code == 503
    assert agents.get_managed_agent(agent.id, require_access=False).state == "blocked"


def test_revoked_device_cannot_manage_agents(surface) -> None:
    client, secret, agents, store = surface
    agent = _enabled_agent(agents, "survivor-agent")
    grant = _grant(client, secret)
    MobileService(store).revoke_device("dev-1", reason="lost", actor_id="operator")

    assert _control(client, secret, grant, agent, "retire").status_code == 401
    assert agents.get_managed_agent(agent.id).state == "enabled"


def test_device_lists_devices_and_marks_itself(surface) -> None:
    client, secret, _agents, _store = surface
    _grant(client, secret)

    response = client.get("/api/mobile/admin/devices", headers=_auth(secret))
    assert response.status_code == 200, response.text
    (device,) = response.json()
    assert device["id"] == "dev-1" and device["label"] == "phone-one"
    assert device["this_device"] is True and device["has_write_grant"] is True
    assert [option["action"] for option in device["actions"]] == ["revoke-device"]


def test_device_manages_a_service_principal(surface) -> None:
    client, secret, _agents, _store = surface
    grant = _grant(client, secret)
    created = client.post(
        "/api/mobile/enrollments/service-principals",
        json={
            "request_id": str(uuid.uuid4()), "name": "managed-spn",
            "agent_name_prefix": "managed-worker", "reason": "automation",
            "grant_secret": grant,
        },
        headers=_auth(secret),
    )
    assert created.status_code == 201, created.text
    original_secret = created.json()["credential_secret"]

    def listed():
        response = client.get(
            "/api/mobile/admin/service-principals", headers=_auth(secret)
        )
        assert response.status_code == 200, response.text
        return next(row for row in response.json() if row["name"] == "managed-spn")

    def control(action, row, **overrides):
        body = {
            "request_id": str(uuid.uuid4()), "action": action,
            "expected_name": row["name"], "expected_version": row["version"],
            "reason": "operator decision", "grant_secret": grant,
        }
        body.update(overrides)
        return client.post(
            f"/api/mobile/admin/service-principals/{row['id']}/control",
            json=body, headers=_auth(secret),
        )

    row = listed()
    assert row["status"] == "enabled"
    assert [option["action"] for option in row["actions"]] == ["block", "rotate", "revoke"]

    assert control("rotate", row, grant_secret="wrong").status_code == 401
    assert control("rotate", row, expected_name="someone-else").status_code == 409

    rotated = control("rotate", row)
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["secret_kind"] == "service-principal-credential"
    assert rotated.json()["secret"] and rotated.json()["secret"] != original_secret
    assert control("block", row).status_code == 409  # version moved on

    blocked = control("block", listed())
    assert blocked.status_code == 200, blocked.text
    assert blocked.json()["state"] == "blocked"
    assert [option["action"] for option in listed()["actions"]] == ["unblock", "revoke"]

    assert control("unblock", listed()).json()["state"] == "enabled"
    revoked = control("revoke", listed())
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["state"] == "revoked" and listed()["actions"] == []


def test_device_reads_recent_bus_logs(surface) -> None:
    import logging

    from strugglebus import audit_feed, server_log

    client, secret, _agents, _store = surface
    _grant(client, secret)
    recent = server_log.RecentLog()
    recent.emit(logging.makeLogRecord({
        "name": "uvicorn.error", "levelno": logging.ERROR, "levelname": "ERROR",
        "msg": "x" * 900,
    }))
    recent.emit(logging.makeLogRecord({
        "name": audit_feed.LOGGER.name, "levelno": logging.INFO,
        "msg": audit_feed.request_line(
            ts="2099-01-01T00:00:00.000000Z", event="POST /api/mobile/grants",
            status=401, remote_address="192.0.2.7",
        ),
    }))
    # A committed table row on the audit logger is read from its table instead.
    recent.emit(logging.makeLogRecord({
        "name": audit_feed.LOGGER.name, "levelno": logging.INFO,
        "msg": audit_feed.PREFIX + '{"table":"spn_audit","ts":"2099-01-01T00:00:00Z"}',
    }))
    recent.emit(logging.makeLogRecord({
        "name": audit_feed.LOGGER.name, "levelno": logging.INFO, "msg": "not json",
    }))
    assert len(recent.entries) == 2

    original = server_log.RECENT
    server_log.RECENT = recent
    try:
        response = client.get("/api/mobile/admin/logs", headers=_auth(secret))
    finally:
        server_log.RECENT = original
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["started_at"] is None
    entries = body["entries"]
    assert entries == sorted(entries, key=lambda entry: entry["ts"], reverse=True)
    refused = entries[0]
    assert refused["source"] == "request" and refused["level"] == "warning"
    assert refused["status"] == 401 and refused["remote_address"] == "192.0.2.7"
    server = next(entry for entry in entries if entry["source"] == "server")
    assert server["level"] == "error" and len(server["detail"]) == 500
    audit = [entry for entry in entries if entry["source"] == "audit"]
    assert any(entry["detail"] == "mobile device" for entry in audit)
    assert "device setup" not in response.text  # reasons never leave the tables

    assert len(client.get(
        "/api/mobile/admin/logs?limit=1", headers=_auth(secret)
    ).json()["entries"]) == 1
    assert client.get("/api/mobile/admin/logs?limit=501", headers=_auth(secret)).status_code == 422
    assert client.get("/api/mobile/admin/logs").status_code == 401
