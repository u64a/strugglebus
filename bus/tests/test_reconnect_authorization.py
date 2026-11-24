import sqlite3
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from test_credential_lifecycle import _activate, _request_id
from test_rest_api import (
    _agent_headers, _application, _receipt_payload, _register, rest_client,
)


def _start(client):
    agent = _register(client, "guarded-drain")
    headers = _agent_headers(agent)
    effective = client.get("/api/roe/effective", headers=headers).json()
    assert client.post(
        "/api/roe/acknowledgements", headers=headers,
        json=_receipt_payload(effective),
    ).status_code in {200, 201}
    client.put("/api/subscriptions/status", headers=headers)
    for index in range(3):
        client.post("/api/channels/status/messages", headers=headers,
                    json={"body": str(index)})
    page = client.get("/api/catch-up", headers=headers,
                      params={"start_drain": True, "limit": 1})
    assert page.status_code == 200
    return agent, page.headers["Catch-Up-Continuation"]


def _positions(client):
    with sqlite3.connect(client.app.state.config.database_path) as connection:
        return (
            connection.execute("SELECT * FROM cursors ORDER BY 1,2,3").fetchall(),
            connection.execute("SELECT * FROM mention_cursors ORDER BY 1,2").fetchall(),
        )


def test_continuation_survives_proved_rotation_but_not_retirement_or_revocation(rest_client):
    agent, token = _start(rest_client)
    service = rest_client.app.state.agent_service
    previous = service.authenticate(agent["api_key"])
    successor = service.rotate(
        previous, request_id=_request_id(),
        expected_agent_id=previous.agent.id,
        expected_credential_id=previous.credential.id,
        expected_credential_epoch=previous.agent.credential_epoch,
    )
    headers = {"Authorization": "Bearer " + successor.secret}
    params = {"limit": 1, "continuation": token}
    before = _positions(rest_client)
    assert rest_client.get("/api/catch-up", headers=headers, params=params).status_code == 403
    assert _positions(rest_client) == before
    current = _activate(service, successor.secret)
    assert rest_client.get("/api/catch-up", headers=headers, params=params).status_code == 200
    service.retire_predecessor(
        current, credential_id=previous.credential.id,
        request_id=_request_id(),
        expected_credential_epoch=current.agent.credential_epoch,
        expected_credential_version=previous.credential.version,
    )
    assert rest_client.get(
        "/api/catch-up", headers=_agent_headers(agent), params=params
    ).status_code == 401
    service.revoke_agent(current.agent.id)
    before = _positions(rest_client)
    assert rest_client.get("/api/catch-up", headers=headers, params=params).status_code == 401
    assert _positions(rest_client) == before


@pytest.mark.parametrize("in_flight", [False, True])
def test_stale_roe_cannot_resume_even_after_initial_authorization(app_config, monkeypatch, in_flight):
    from strugglebus.roe import GlobalRoePolicyV1, INITIAL_GLOBAL_POLICY

    with TestClient(_application(replace(app_config, roe_enforcement_mode="enforce"))) as client:
        agent, token = _start(client)
        roe = client.app.state.roe_service
        before = _positions(client)

        def change_policy():
            current = roe.get_effective(agent["id"]).global_revision
            roe.publish_global(
                revision_id=_request_id(),
                expected_current_revision_id=current.id,
                author_label="Test owner",
                policy=GlobalRoePolicyV1.model_validate({
                    **INITIAL_GLOBAL_POLICY.model_dump(mode="json"),
                    "title": "Updated policy for resume guard",
                }),
                publisher_kind="api-key-sha256-v1",
                publisher_id="sha256:" + "c" * 64,
            )

        if in_flight:
            original = client.app.state.board_service.catch_up_page

            def changed(**kwargs):
                change_policy()
                return original(**kwargs)

            monkeypatch.setattr(client.app.state.board_service, "catch_up_page", changed)
        else:
            change_policy()
        response = client.get(
            "/api/catch-up", headers=_agent_headers(agent),
            params={"limit": 1, "continuation": token},
        )
        assert response.status_code == 428
        assert _positions(client) == before


@pytest.mark.parametrize("transition", ["freeze", "revoke", "credential"])
def test_resume_rechecks_safety_inside_transaction(rest_client, monkeypatch, transition):
    agent, token = _start(rest_client)
    board = rest_client.app.state.board_service
    original = board.catch_up_page
    before = _positions(rest_client)

    def changed_after_request_authorization(**kwargs):
        if transition == "freeze":
            rest_client.app.state.access_freeze_service.freeze("in-flight drain")
        elif transition == "credential":
            service = rest_client.app.state.agent_service
            identity = service.authenticate(agent["api_key"])
            service.revoke_credential(
                identity.agent.name, identity.credential.id,
                request_id=_request_id(),
                expected_credential_epoch=identity.agent.credential_epoch,
                expected_credential_version=identity.credential.version,
                reason="in-flight credential revocation",
            )
        else:
            rest_client.app.state.agent_service.revoke_agent(agent["id"])
        return original(**kwargs)

    monkeypatch.setattr(board, "catch_up_page", changed_after_request_authorization)
    response = rest_client.get(
        "/api/catch-up", headers=_agent_headers(agent),
        params={"limit": 1, "continuation": token},
    )
    assert response.status_code == (503 if transition == "freeze" else 401)
    assert _positions(rest_client) == before


@pytest.mark.parametrize(
    "method,path,operation",
    [
        ("GET", "/api/subscriptions", "list_subscriptions"),
        ("PUT", "/api/subscriptions/help", "subscribe"),
        ("DELETE", "/api/subscriptions/status", "unsubscribe"),
    ],
)
def test_subscription_routes_recheck_revocation(rest_client, monkeypatch, method, path, operation):
    agent, _ = _start(rest_client)
    board = rest_client.app.state.board_service
    original = getattr(board, operation)
    before = _positions(rest_client)

    def revoke_before_store(*args, **kwargs):
        rest_client.app.state.agent_service.revoke_agent(agent["id"])
        return original(*args, **kwargs)

    monkeypatch.setattr(board, operation, revoke_before_store)
    response = rest_client.request(method, path, headers=_agent_headers(agent))
    assert response.status_code == 401
    assert _positions(rest_client) == before
