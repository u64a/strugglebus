from __future__ import annotations

import uuid
import asyncio
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from operator_test_support import operator_client
from strugglebus.operator_auth import SESSION_COOKIE
from strugglebus.app import create_app
from strugglebus.auth import AgentService
from strugglebus.config import AppConfig
from strugglebus.errors import AgentAccessFrozenError
from strugglebus.errors import StorageError
from strugglebus.store import SQLiteStore


def _application(config: AppConfig, **kwargs: object):
    service = AgentService(
        SQLiteStore(
            config.database_path,
            backup_dir=config.backup_dir,
            busy_timeout_ms=config.sqlite_busy_timeout_ms,
        ),
        **kwargs,
    )
    return create_app(config=config, agent_service=service)


@pytest.fixture
def console(app_config: AppConfig):
    with operator_client(_application(app_config)) as client:
        yield client


def _register(client: TestClient, name: str, description: str = ""):
    return client.register(name, description)


def _token_from(body: str) -> str:
    marker = "Enrollment  : "
    start = body.index(marker) + len(marker)
    return body[start:].split("\n", 1)[0].strip()


def test_register_form_is_reachable_and_linked(console: TestClient) -> None:
    page = console.get("/register")
    assert page.status_code == 200
    assert 'action="/register"' in page.text
    assert 'name="name"' in page.text
    assert 'href="/system"' in console.get("/").text
    assert 'href="/register"' in console.get("/system").text


def test_register_returns_a_single_use_onboarding_package(
    console: TestClient,
) -> None:
    response = _register(console, "adlab-cli-win")
    assert response.status_code == 201
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    body = response.text
    assert "Onboarding package" in body
    assert "adlab-cli-win" in body
    assert "/api/enrollments/redeem" in body
    token = _token_from(body)
    assert token.startswith("sbe1_")

    redeemed = console.post(
        "/api/enrollments/redeem",
        json={
            "request_id": str(uuid.uuid4()),
            "name": "adlab-cli-win",
            "host": "ws1",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert redeemed.status_code == 201
    assert redeemed.json()["agent"]["name"] == "adlab-cli-win"

    replay = console.post(
        "/api/enrollments/redeem",
        json={
            "request_id": str(uuid.uuid4()),
            "name": "adlab-cli-two",
            "host": "ws1",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert replay.status_code == 401


def test_package_token_is_bound_to_the_exact_registered_name(
    console: TestClient,
) -> None:
    token = _token_from(_register(console, "adlab-cli-win").text)
    for name in ("adlab-cli-win-extra", "other-project-cli"):
        other = console.post(
            "/api/enrollments/redeem",
            json={"request_id": str(uuid.uuid4()), "name": name, "host": "ws1"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert other.status_code == 401
        assert console.app.state.agent_service.list_enrollments()[0].uses_remaining == 1
    intended = console.post(
        "/api/enrollments/redeem",
        json={"request_id": str(uuid.uuid4()), "name": "adlab-cli-win"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert intended.status_code == 201


@pytest.mark.parametrize(
    "name",
    ["", "   ", "nohyphen", "-leading", "trailing-", "a" * 200],
)
def test_invalid_names_are_refused_without_minting(
    console: TestClient, name: str
) -> None:
    response = _register(console, name)
    assert response.status_code == 422
    assert "Register an agent" in response.text
    assert not console.app.state.agent_service.list_enrollments()


def test_names_are_canonicalized_before_binding(console: TestClient) -> None:
    response = _register(console, "  AdLab CLI Win  ")
    assert response.status_code == 201
    # The package must show the canonical identity the token actually creates.
    assert "adlab-cli-win" in response.text
    enrollment = console.app.state.agent_service.list_enrollments()[0]
    assert enrollment.name_prefix == "adlab-cli-win"
    assert enrollment.name_match == "exact"
    assert enrollment.actor_type == "remote-admin"
    assert enrollment.actor_id.startswith("operator:owner:")


def test_registration_reflects_input_without_executing_it(
    console: TestClient,
) -> None:
    hostile = '"><script>alert(1)</script>'
    response = _register(console, "nohyphen", description=hostile)
    assert response.status_code == 422
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_registration_page_survives_a_freeze_but_minting_does_not(
    console: TestClient,
) -> None:
    """A freeze stops the agent plane, not the operator's ability to look.

    The page is a read and now loads. The mint is the creation of access and
    stays refused, so nothing that could let a new agent in comes into
    existence while the owner has stopped trusting the system's state.
    """

    console.app.state.access_freeze_service.freeze("incident drill")
    page = console.get("/register")
    assert page.status_code == 200
    assert "Agent access is frozen" in page.text
    assert 'type="submit" disabled aria-describedby="action-access-note"' in page.text
    assert _register(console, "adlab-cli-win").status_code == 503
    assert not console.app.state.agent_service.list_enrollments()
    console.app.state.access_freeze_service.unfreeze("drill complete")
    assert 'type="submit" disabled' not in console.get("/register").text
    assert _register(console, "adlab-cli-win").status_code == 201


def test_oversized_registration_body_is_rejected(console: TestClient) -> None:
    response = console.post(
        "/register",
        data={"name": "adlab-cli-win", "description": "x" * 16384},
        headers={"Origin": "https://bus.lan"},
    )
    assert response.status_code == 413
    assert not console.app.state.agent_service.list_enrollments()


def test_unavailable_access_observation_is_explicit_and_disables_enrollment(
    console: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable():
        raise StorageError("PRIVATE ACCESS STORE")

    monkeypatch.setattr(console.app.state.access_freeze_service, "status", unavailable)
    page = console.get("/register")
    assert page.status_code == 200
    assert "Access state unavailable" in page.text
    assert "PRIVATE ACCESS STORE" not in page.text
    assert 'type="submit" disabled aria-describedby="action-access-note"' in page.text
    assert 'href="/system"' in page.text
    assert not console.app.state.agent_service.list_enrollments()


@pytest.mark.parametrize("description", ["x" * 1025, "bad\x00description"])
def test_invalid_description_never_mints(console: TestClient, description: str) -> None:
    assert _register(console, "review-reader", description).status_code == 422
    assert not console.app.state.agent_service.list_enrollments()


def test_registration_leads_to_setup_without_operator_configuration(
    app_config: AppConfig,
) -> None:
    limited = replace(app_config, unauthenticated_requests_per_minute=1)
    with TestClient(_application(limited)) as client:
        response = client.get("/register", follow_redirects=False)
        assert (response.status_code, response.headers["location"]) == (303, "/setup")
        assert client.post("/register", data={"name": "adlab-cli-win"}).status_code == 429


def test_system_page_states_the_registration_capability(
    console: TestClient,
) -> None:
    page = console.get("/system").text
    assert "You sign in here with the operator password" in page
    assert "one-time package for one exact agent name" in page
    assert "currently open to" not in page


def test_page_tells_the_operator_how_to_recover_a_failed_signup(console):
    text = _register(console, "review-reader").text
    assert "agent enroll revoke" in text
    assert "agent recover" in text and "--expected-credential-epoch" in text
    assert "Retiring is permanent" in text
    assert "register the agent again to mint a replacement" not in text


def test_package_stops_at_redemption_and_defers_to_orientation(console):
    text = _register(console, "review-reader").text
    package = text[text.index('<textarea id="package-text"'):text.index("</textarea>")]
    assert "call orientation and do what" in package
    assert "do not enroll the same name" in package
    # The one deadline and the two calls a REST-only agent cannot discover.
    assert "within 15 minutes of redeeming" in package
    assert "/api/credentials/prove" in package and "/api/orientation" in package
    assert "expected_credential_version (credential.version)" in package
    # Windows curl cannot check revocation against a LAN CA.
    assert "curl.exe --fail --silent --show-error --ssl-revoke-best-effort" in package
    # Agents may share a machine.
    assert "Other agents may share this machine" in package
    # Day-to-day working rules live in the integration guide, which the agent
    # reads after redeeming, so they are not repeated in a one-time handoff.
    assert "catch_up" not in package and "SSE" not in package
    assert "agent recover" not in package


def test_the_package_page_says_what_to_do_next_and_keeps_the_package_selectable(console):
    text = _register(console, "review-reader").text
    steps = text[text.index('<ol class="steps">'):text.index("</ol>")]
    assert steps.count("<li>") == 4
    assert "Give it to review-reader privately" in steps
    assert "Ctrl+A" in steps and '<a href="/agents">Agents</a>' in steps
    assert "<time datetime=" in steps
    # A read-only text box, so select-all takes the package and nothing else.
    assert '<textarea id="package-text" class="package-block" readonly' in text
    assert "<pre>" not in text
    assert "<script" not in text


@pytest.mark.asyncio
async def test_body_delivered_after_local_freeze_cannot_mint(
    app_config: AppConfig,
) -> None:
    with operator_client(_application(app_config)) as client:
        app = client.app
        body = f"name=review-reader&description=delayed&csrf={client.operator_csrf}".encode()
        responses = []
        reads = 0

        async def receive():
            nonlocal reads
            reads += 1
            assert reads == 1
            await asyncio.to_thread(
                app.state.access_freeze_service.freeze, "body delivery race"
            )
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            responses.append(message)

        await app(
            {
                "type": "http", "asgi": {"version": "3.0"},
                "http_version": "1.1", "method": "POST", "scheme": "https",
                "path": "/register", "raw_path": b"/register",
                "query_string": b"", "root_path": "",
                "headers": [(b"host", b"bus.lan"), (b"origin", b"https://bus.lan"),
                            (b"cookie", f"{SESSION_COOKIE}={client.cookies.get(SESSION_COOKIE)}".encode()),
                            (b"content-type", b"application/x-www-form-urlencoded")],
                "client": ("127.0.0.1", 12345), "server": ("testserver", 443),
            },
            receive,
            send,
        )
        assert reads == 1
        assert responses[0]["status"] == 503
        assert b"sbe1_" not in b"".join(item.get("body", b"") for item in responses)
        assert not app.state.agent_service.list_enrollments()
        assert not app.state.agent_service.store.list_agents()


@pytest.mark.parametrize("freeze_first", [False, True])
def test_mint_and_freeze_serialize_at_the_write_transaction(
    console: TestClient, monkeypatch: pytest.MonkeyPatch, freeze_first: bool
) -> None:
    service = console.app.state.agent_service
    access = console.app.state.access_freeze_service
    first_store = access.store if freeze_first else service.store
    original = first_store._transaction
    locked = threading.Event()
    release = threading.Event()

    @contextmanager
    def held_transaction():
        with original() as connection:
            locked.set()
            assert release.wait(5)
            yield connection

    monkeypatch.setattr(first_store, "_transaction", held_transaction)
    authority = console.app.state.operator_auth
    operator = authority.authenticate(console.cookies.get(SESSION_COOKIE))
    assert operator is not None
    mint = lambda: service.create_dashboard_enrollment(
        name="review-reader", operator=operator,
        authorize=lambda: authority.require_active(operator),
    )
    freeze = lambda: access.freeze("serialized registration")
    with ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(freeze if freeze_first else mint)
        assert locked.wait(5)
        second_started = threading.Event()

        def run_second():
            second_started.set()
            return (mint if freeze_first else freeze)()

        second = workers.submit(run_second)
        assert second_started.wait(5)
        release.set()
        first.result(timeout=5)
        if freeze_first:
            with pytest.raises(AgentAccessFrozenError):
                second.result(timeout=5)
        else:
            second.result(timeout=5)
    assert access.status().frozen
    with sqlite3.connect(service.store.database_path) as database:
        assert database.execute("SELECT COUNT(*) FROM agent_enrollments").fetchone() == (
            0 if freeze_first else 1,
        )
    # The intentional protected-local service path remains available.
    local = service.create_enrollment(name_prefix="local")
    assert local.enrollment.actor_type == "local-admin"
    assert local.enrollment.name_match == "prefix"
