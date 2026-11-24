"""Cross-feature regression for enrollment, subscriptions, drains and freeze."""

from __future__ import annotations

import html
import re
import sqlite3
import uuid

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from operator_test_support import operator_client
from strugglebus.config import AppConfig
from strugglebus.migrations import LATEST_SCHEMA_VERSION
from test_agent_enrollment import _application, _redeem
from test_rest_api import _receipt_payload


def _expect(response: Response, *statuses: int) -> None:
    assert response.status_code in statuses, (
        f"{response.request.method} {response.request.url.path}: "
        f"unexpected status {response.status_code}"
    )


def _package_token(client: TestClient, name: str) -> str:
    response = client.register(name)
    _expect(response, 201)
    match = re.search(r"\bsbe1_[A-Za-z0-9_-]+", html.unescape(response.text))
    assert match is not None, "Onboarding package omitted its enrollment token"
    return match.group(0)


def _headers(created: dict) -> dict[str, str]:
    return {"Authorization": "Bearer " + created["credential_secret"]}


def _bootstrap(client: TestClient, created: dict) -> None:
    headers = _headers(created)
    response = client.post(
        "/api/credentials/prove",
        headers=headers,
        json={
            "request_id": str(uuid.uuid4()),
            "expected_agent_id": created["agent"]["id"],
            "expected_agent_name": created["agent"]["name"],
            "expected_credential_epoch": created["agent"]["credential_epoch"],
            "expected_credential_version": created["credential"]["version"],
        },
    )
    _expect(response, 200)
    response = client.get("/api/roe/effective", headers=headers)
    _expect(response, 200)
    response = client.post(
        "/api/roe/acknowledgements",
        headers=headers,
        json=_receipt_payload(response.json()),
    )
    _expect(response, 200, 201)


def _post(client: TestClient, writer: dict, channel: str, body: str) -> int:
    response = client.post(
        f"/api/channels/{channel}/messages",
        headers=_headers(writer),
        json={"body": body, "kind": "chat"},
    )
    _expect(response, 201)
    return response.json()["seq"]


def _finish_drain(
    client: TestClient, headers: dict[str, str], response: Response,
) -> list[int]:
    seen: list[int] = []
    for _ in range(100):
        _expect(response, 200)
        assert response.headers["Catch-Up-Mode"] == "drain"
        page = [message["seq"] for message in response.json()]
        assert page == sorted(page)
        seen.extend(page)
        complete = response.headers["Catch-Up-Complete"]
        assert complete in {"true", "false"}
        if complete == "true":
            assert "Catch-Up-Continuation" not in response.headers
            return seen
        response = client.get(
            "/api/catch-up",
            headers=headers,
            params={
                "continuation": response.headers["Catch-Up-Continuation"],
                "limit": 50,
                "include_stale": "false",
            },
        )
    raise AssertionError("A small combined-fixture drain failed to terminate")


@pytest.mark.skipif(
    LATEST_SCHEMA_VERSION < 11,
    reason="Exact-name enrollment requires workstream B's schema 11 migration",
)
def test_combined_enrollment_subscription_drain_and_freeze(
    app_config: AppConfig,
) -> None:
    with operator_client(_application(app_config)) as client:
        with sqlite3.connect(app_config.database_path) as database:
            assert database.execute("PRAGMA user_version").fetchone() == (
                LATEST_SCHEMA_VERSION,
            )

        reader_token = _package_token(client, "integration-reader")
        _expect(_redeem(client, reader_token, "integration-reader-extra"), 401)
        response = _redeem(client, reader_token, "integration-reader")
        _expect(response, 201)
        reader = response.json()
        reader_headers = _headers(reader)
        assert reader["credential"]["status"] == "pending"
        _expect(
            client.put("/api/subscriptions/announce", headers=reader_headers),
            403,
        )
        _bootstrap(client, reader)

        writer_token = _package_token(client, "integration-writer")
        response = _redeem(client, writer_token, "integration-writer")
        _expect(response, 201)
        writer = response.json()
        _bootstrap(client, writer)
        unseen_help = _post(client, writer, "help", "Older unsubscribed history")
        announcements = [
            _post(client, writer, "announce", f"Integration note {index}")
            for index in range(505)
        ]

        response = client.get("/api/orientation", headers=reader_headers)
        _expect(response, 200)
        orientation = response.json()
        assert orientation["subscription_count"] == 0
        assert orientation["unread"] == 0
        assert "you are up to date" not in orientation["guidance"].lower()
        _expect(
            client.put("/api/subscriptions/announce", headers=reader_headers),
            200,
        )

        response = client.get(
            "/api/catch-up",
            headers=reader_headers,
            params={"start_drain": "true", "limit": 50},
        )
        _expect(response, 200)
        assert response.headers["Catch-Up-Complete"] == "false"
        assert int(response.headers["Catch-Up-Snapshot-Seq"]) == announcements[-1]
        continuation = response.headers["Catch-Up-Continuation"]
        first_page = [message["seq"] for message in response.json()]
        assert first_page == announcements[:50]

        _expect(client.put("/api/subscriptions/help", headers=reader_headers), 200)
        later = _post(client, writer, "announce", "After the fixed snapshot")
        client.app.state.access_freeze_service.freeze("combined integration drill")
        _expect(
            client.get(
                "/api/catch-up",
                headers=reader_headers,
                params={"continuation": continuation, "limit": 50},
            ),
            503,
        )
        _expect(
            # The console is no longer blacked out by a freeze, so this POST is
            # now refused by the ordinary operator origin check rather than by
            # the freeze. Minting itself stays denied, which the dashboard
            # registration tests assert directly against a signed-in operator.
            client.post("/register", data={"name": "integration-frozen"}), 403
        )
        client.app.state.access_freeze_service.unfreeze(
            "combined integration drill complete"
        )

        resumed = client.get(
            "/api/catch-up",
            headers=reader_headers,
            params={"continuation": continuation, "limit": 50},
        )
        seen = first_page + _finish_drain(client, reader_headers, resumed)
        assert seen == announcements
        assert unseen_help not in seen
        assert later not in seen

        fresh = client.get(
            "/api/catch-up",
            headers=reader_headers,
            params={"start_drain": "true", "limit": 50},
        )
        refreshed = _finish_drain(client, reader_headers, fresh)
        assert unseen_help in refreshed
        assert later in refreshed
