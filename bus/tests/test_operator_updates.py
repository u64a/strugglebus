"""Synthetic worker, real HTTP admission, session and password boundary tests."""

from dataclasses import replace
from pathlib import Path
import time
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from strugglebus import __version__
from strugglebus.app import create_app
from strugglebus.dashboard import DASHBOARD_STYLESHEET_PATH
from strugglebus.maintenance_types import (
    MaintenanceAttempt,
    MaintenancePolicy,
    MaintenanceStatus,
)
from strugglebus.operator_auth import SESSION_COOKIE, OperatorContext, OperatorFormError, OperatorCapacityError
from strugglebus.operator_updates import UpdateConsole
from strugglebus.update_types import (
    UpdateAsset, UpdateCandidate, UpdateDiscovery, UpdateError, UpdateObservation,
    UpdateOperation, UpdatePrepared, UpdateStatus,
)
from test_operator_dashboard import PASSWORD, csrf, login, verifier
from live_test_support import hidden, stylesheet

ROOT = "/operator/updates"
ORIGIN = {"Origin": "https://bus.lan"}
POLICY = "f" * 64
BUNDLED_PATH = DASHBOARD_STYLESHEET_PATH


def observed(config):
    assets = tuple(
        UpdateAsset(index + 1, name, 1, "a" * 64, media)
        for index, (name, media) in enumerate((
            ("strugglebus-0.2.28-py3-none-any.whl", "application/vnd.python.wheel"),
            ("requirements.lock", "text/plain"),
            ("strugglebus-deployment-support-0.2.28.tar.gz", "application/gzip"),
            ("strugglebus-release-manifest-v1.json", "application/json"),
            ("SHA256SUMS", "text/plain"),
        ))
    )
    candidate = UpdateCandidate("0.2.28", 123, "v0.2.28", "1" * 40, "2" * 40, "3" * 40, POLICY, assets)
    observation = UpdateObservation(
        "a" * 32, int(time.time()), int(time.time()) + 900, __version__, config.release_id,
        UpdateDiscovery(candidate, True, 1, None, None),
    )
    return UpdateStatus("observed", __version__, POLICY, None, observation, None, True)


class Worker:
    def __init__(self, config):
        self.value = observed(config)
        self.calls = []
        self.error = None
        self.on_status = None
        self.on_prepare = None

    async def status(self, operation_id=None):
        self.calls.append(("status", operation_id))
        if self.on_status is not None:
            self.on_status()
        if self.error is not None:
            raise UpdateError(self.error)
        return self.value

    async def check(self, operation_id, actor_id, application_version, application_release_id):
        self.calls.append(("check", operation_id, actor_id, application_version, application_release_id))
        self.value = replace(self.value, operation=UpdateOperation(
            operation_id, "check", actor_id, "succeeded", int(time.time()), int(time.time()), None,
        ))
        return self.value

    async def prepare(self, operation_id, actor_id, application_version, application_release_id, observation_id, digest):
        self.calls.append((
            "prepare", operation_id, actor_id, application_version, application_release_id, observation_id, digest,
        ))
        assert self.value.observation is not None
        candidate = self.value.observation.discovery.candidate
        assert candidate is not None and digest == candidate.digest
        self.value = replace(
            self.value, state="prepared",
            operation=UpdateOperation(operation_id, "prepare", actor_id, "succeeded", int(time.time()), int(time.time()), None),
            prepared=UpdatePrepared(candidate, int(time.time()), operation_id),
        )
        if self.on_prepare is not None:
            self.on_prepare()
        return self.value


class MaintenanceWorker:
    def __init__(self):
        self.value = MaintenanceStatus(
            MaintenancePolicy(), __version__, None, int(time.time()) + 3600, None,
        )
        self.calls = []

    async def status(self):
        self.calls.append(("status",))
        return self.value

    async def configure(self, operation_id, actor_id, *, enabled, hour, minute):
        self.calls.append(("configure", operation_id, actor_id, enabled, hour, minute))
        self.value = replace(
            self.value,
            policy=MaintenancePolicy(enabled=enabled, hour=hour, minute=minute),
        )
        return self.value

    async def install(self, operation_id, actor_id):
        self.calls.append(("install", operation_id, actor_id))
        self.value = replace(
            self.value,
            attempt=MaintenanceAttempt(
                operation_id, "manual", actor_id, "accepted", int(time.time()),
            ),
        )
        return self.value

@pytest.fixture
def console(app_config, monkeypatch, verifier):
    config = replace(app_config, updater_socket_path=Path(app_config.data_dir.anchor) / "updater-fixture" / "control.sock")
    worker = Worker(config)
    monkeypatch.setattr("strugglebus.operator_updates.UpdateClient", lambda path: worker)
    monkeypatch.setattr("strugglebus.operator_auth.load_password_verifier", lambda path: verifier)
    with TestClient(create_app(config=config), base_url="https://bus.lan", follow_redirects=False) as client:
        yield client, worker


@pytest.fixture
def maintenance_console(app_config, monkeypatch, verifier):
    root = Path(app_config.data_dir.anchor)
    config = replace(
        app_config,
        updater_socket_path=root / "updater-fixture" / "control.sock",
        maintenance_socket_path=root / "maintenance-fixture" / "control.sock",
    )
    worker = Worker(config)
    maintenance = MaintenanceWorker()
    monkeypatch.setattr("strugglebus.operator_updates.UpdateClient", lambda path: worker)
    monkeypatch.setattr(
        "strugglebus.operator_updates.MaintenanceClient", lambda path: maintenance,
    )
    monkeypatch.setattr("strugglebus.operator_auth.load_password_verifier", lambda path: verifier)
    with TestClient(
        create_app(config=config), base_url="https://bus.lan", follow_redirects=False,
    ) as client:
        yield client, maintenance


def review(client):
    response = client.get(ROOT + "/review/" + "a" * 32)
    assert response.status_code == 200, response.text
    return response


def prepare(client, page, **changes):
    return client.post(ROOT + "/prepare", data=hidden(page) | {"password": PASSWORD} | changes, headers=ORIGIN)


def context(client):
    value = client.app.state.operator_auth.authenticate(client.cookies.get(SESSION_COOKIE))
    assert value is not None
    return value


def test_maintenance_controls_render_and_pause(maintenance_console):
    client, maintenance = maintenance_console
    login(client)
    page = client.get(ROOT)
    assert page.status_code == 200
    assert "Automatic updates" in page.text
    assert "01:00 Australia/Brisbane" in page.text
    response = client.post(
        ROOT + "/maintenance/toggle",
        data={"csrf": csrf(page), "enabled": "false", "password": PASSWORD},
        headers=ORIGIN,
    )
    assert response.status_code == 303
    assert maintenance.value.policy.enabled is False
    assert maintenance.calls[-1][0] == "configure"


def test_maintenance_schedule_requires_bounded_brisbane_time(maintenance_console):
    client, maintenance = maintenance_console
    login(client)
    page = client.get(ROOT)
    refused = client.post(
        ROOT + "/maintenance/schedule",
        data={"csrf": csrf(page), "hour": "24", "minute": "00", "password": PASSWORD},
        headers=ORIGIN,
    )
    assert refused.status_code == 400
    accepted = client.post(
        ROOT + "/maintenance/schedule",
        data={"csrf": csrf(page), "hour": "2", "minute": "15", "password": PASSWORD},
        headers=ORIGIN,
    )
    assert accepted.status_code == 303, accepted.text
    assert (maintenance.value.policy.hour, maintenance.value.policy.minute) == (2, 15)


def test_manual_maintenance_is_admitted_while_automatic_updates_are_paused(
    maintenance_console,
):
    client, maintenance = maintenance_console
    maintenance.value = replace(
        maintenance.value,
        policy=MaintenancePolicy(enabled=False),
    )
    login(client)
    page = client.get(ROOT)
    response = client.post(
        ROOT + "/maintenance/install",
        data={"csrf": csrf(page), "password": PASSWORD},
        headers=ORIGIN,
    )
    assert response.status_code == 303, response.text
    assert maintenance.value.attempt is not None
    assert maintenance.value.attempt.mode == "manual"


def test_default_disabled_does_not_contact_worker_or_change_health(app_config, monkeypatch, verifier):
    def unexpected(path):
        pytest.fail("Disabled updater must not construct a worker client")

    monkeypatch.setattr("strugglebus.operator_updates.UpdateClient", unexpected)
    monkeypatch.setattr("strugglebus.operator_auth.load_password_verifier", lambda path: verifier)
    with TestClient(create_app(config=app_config), base_url="https://bus.lan", follow_redirects=False) as client:
        assert client.get("/healthz").status_code == 200
        login(client)
        response = client.get(ROOT)
        assert response.status_code == 200
        assert "disabled" in response.text
        assert stylesheet(response) == [BUNDLED_PATH]
        assert ROOT + "/check" not in response.text
        assert client.post(ROOT + "/check", data={"csrf": csrf(client.get("/operator/session"))}, headers=ORIGIN).status_code == 400
        updater = client.app.state.updater
    assert updater._reviews == {}


@pytest.mark.parametrize("bearer", [None, "agent-credential", "admin-bearer", "device-credential", "containment-grant"])
def test_non_operator_credentials_never_contact_worker(console, bearer):
    client, worker = console
    if bearer == "agent-credential":
        bearer = client.app.state.agent_service.create_agent("updater-denied-agent").api_key
    elif bearer == "admin-bearer":
        bearer = client.app.state.config.admin_secret.decode()
    headers = ORIGIN | ({"Authorization": "Bearer " + bearer} if bearer else {})
    for path in (ROOT, ROOT + "/review/" + "a" * 32, ROOT + "/operations/" + "b" * 32):
        response = client.get(path, headers=headers)
        assert response.status_code in {303, 401, 403}
    for path in (ROOT + "/check", ROOT + "/prepare"):
        response = client.post(path, headers=headers, content=b"not-a-form")
        assert response.status_code in {303, 401, 403}
    assert worker.calls == []


def test_check_review_prepare_and_replay_bind_only_server_intent(console):
    client, worker = console
    login(client)
    controls = client.get(ROOT)
    assert stylesheet(controls) == [BUNDLED_PATH]
    assert "script-src 'none'" in controls.headers["content-security-policy"]
    checked = client.post(ROOT + "/check", data={"csrf": csrf(controls)}, headers=ORIGIN)
    assert checked.status_code == 303
    assert client.get(checked.headers["location"]).status_code == 200
    page = review(client)
    assert set(hidden(page)) == {"csrf", "review_id"}
    assert "not a later installation" in page.text
    assert PASSWORD not in page.text
    first = prepare(client, page)
    assert first.status_code == 303, first.text
    second = prepare(client, page)
    assert second.headers["location"] == first.headers["location"]
    calls = [call for call in worker.calls if call[0] == "prepare"]
    assert len(calls) == 2 and calls[0] == calls[1]
    assert calls[0][2] == context(client).actor_id
    assert calls[0][3:5] == (__version__, client.app.state.config.release_id)
    serialized = repr(worker.calls)
    assert PASSWORD not in serialized and hidden(page)["csrf"] not in serialized
    assert client.cookies.get(SESSION_COOKIE) not in serialized
    receipt = client.get(first.headers["location"])
    assert receipt.status_code == 200
    assert "Currently prepared files" in receipt.text
    assert "have not been installed" in receipt.text
    assert receipt.headers["cache-control"] == "no-store"
    assert stylesheet(receipt) == [BUNDLED_PATH]


@pytest.mark.parametrize("change", [
    {"csrf": "incorrect"}, {"password": "incorrect synthetic password"}, {"review_id": "b" * 32},
    {"review_id": "bad"}, {"actor_id": "operator:forged"}, {"candidate_digest": "b" * 64},
    {"application_version": "99.0.0"}, {"application_release_id": "forged"},
    {"source_url": "https://example.invalid"}, {"frozen": "false"},
])
def test_denied_prepare_never_sends_any_ipc(console, change):
    client, worker = console
    login(client)
    page = review(client)
    worker.calls.clear()
    assert prepare(client, page, **change).status_code in {400, 403}
    assert worker.calls == []


@pytest.mark.parametrize("headers", [
    {}, {"Origin": "https://other.invalid"}, {"Origin": "null"},
    {"Origin": "http://bus.lan"}, {"Origin": "https://bus.lan", "Content-Type": "application/json"},
])
def test_origin_and_content_type_fail_before_worker(console, headers):
    client, worker = console
    login(client)
    token = csrf(client.get("/operator/session"))
    worker.calls.clear()
    response = client.post(ROOT + "/check", data={"csrf": token}, headers=headers)
    assert response.status_code in {400, 403, 415}
    assert worker.calls == []


def test_oversized_and_duplicate_forms_do_not_contact_worker(console):
    client, worker = console
    login(client)
    token = csrf(client.get("/operator/session"))
    worker.calls.clear()
    for body in (f"csrf={token}&csrf={token}", "x=" + "a" * 9000):
        response = client.post(
            ROOT + "/check", content=body,
            headers=ORIGIN | {"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert response.status_code in {400, 413}
    assert worker.calls == []


def test_review_expiry_logout_and_restart_never_restore_authority(console):
    client, worker = console
    login(client)
    page = review(client)
    updater = client.app.state.updater
    updater._clock = lambda: time.monotonic() + 301
    worker.calls.clear()
    assert prepare(client, page).status_code == 400
    assert worker.calls == []
    updater._clock = time.monotonic
    page = review(client)
    updater.clear()
    worker.calls.clear()
    assert prepare(client, page).status_code == 400
    assert worker.calls == []
    page = review(client)
    client.app.state.operator_auth.logout(context(client))
    worker.calls.clear()
    assert prepare(client, page).status_code == 401
    assert worker.calls == []
    login(client)
    assert prepare(client, page, csrf=csrf(client.get("/operator/session"))).status_code == 400
    assert worker.calls == []


@pytest.mark.parametrize("change", ["worker", "policy", "observation", "session"])
def test_change_after_password_before_dispatch_never_prepares(console, change):
    client, worker = console
    login(client)
    page = review(client)
    prior = context(client)

    def drift():
        if change == "worker":
            worker.value = replace(worker.value, worker_version="0.0.1")
        elif change == "policy":
            discovery = worker.value.observation.discovery
            observation = replace(worker.value.observation, discovery=replace(
                discovery, candidate=replace(discovery.candidate, policy_id="e" * 64),
            ))
            worker.value = replace(worker.value, policy_id="e" * 64, observation=observation)
        elif change == "observation":
            worker.value = replace(worker.value, observation=replace(worker.value.observation, observation_id="b" * 32))
        else:
            client.app.state.operator_auth.logout(prior)

    worker.on_status = drift
    worker.calls.clear()
    assert prepare(client, page).status_code == (401 if change == "session" else 400)
    assert all(call[0] != "prepare" for call in worker.calls)


def test_logout_after_authorizing_cache_job_does_not_claim_distributed_cancellation(console):
    client, worker = console
    login(client)
    page = review(client)
    prior = context(client)
    worker.on_prepare = lambda: client.app.state.operator_auth.logout(prior)
    response = prepare(client, page)
    assert response.status_code == 401
    assert len([call for call in worker.calls if call[0] == "prepare"]) == 1
    assert worker.value.prepared is not None
    login(client)
    assert "Currently prepared files" in client.get(ROOT).text


def test_worker_unavailable_and_missing_history_are_not_success_or_bus_failure(console):
    client, worker = console
    login(client)
    worker.error = "unavailable"
    response = client.get(ROOT)
    assert response.status_code == 503
    assert stylesheet(response) == [BUNDLED_PATH]
    assert client.get("/healthz").status_code == 200
    worker.error = None
    worker.value = replace(worker.value, history_available=False)
    response = client.get(ROOT + "/operations/" + "b" * 32)
    assert response.status_code == 200
    assert "does not prove the operation did not run" in response.text


def test_unknown_acknowledgement_shows_exact_operation_lookup(console, monkeypatch):
    client, worker = console
    login(client)
    page = review(client)
    real_prepare = worker.prepare

    async def lost(*args):
        await real_prepare(*args)
        raise UpdateError("unknown_outcome")

    monkeypatch.setattr(worker, "prepare", lost)
    response = prepare(client, page)
    assert response.status_code == 503
    assert worker.value.operation.operation_id in response.text
    assert "not proof that no work occurred" in response.text


def test_review_tickets_are_deduplicated_bounded_and_context_bound(app_config):
    clock = [100.0]
    config = replace(app_config, updater_review_tickets=1)
    console = UpdateConsole(config, clock=lambda: clock[0])
    status = observed(config)
    first = OperatorContext("operator:first", 9999, "session-first", "csrf-first")
    second = OperatorContext("operator:second", 9999, "session-second", "csrf-second")
    ticket = console.issue(first, status)
    assert console.issue(first, status) is ticket
    with pytest.raises(OperatorCapacityError):
        console.issue(second, status)
    with pytest.raises(OperatorFormError):
        console.require_review(ticket.review_id, second)
    with pytest.raises(OperatorFormError):
        console.require_review(ticket.review_id, replace(first, actor_id="operator:forged"))
    clock[0] += 300
    with pytest.raises(OperatorFormError):
        console.require_review(ticket.review_id, first)
    assert console.issue(second, status).review_id != ticket.review_id
    assert "session-second" not in repr(console.issue(second, status))


@pytest.mark.parametrize("change", ["missing", "candidate", "busy", "expired", "application", "release"])
def test_ineligible_observations_cannot_be_reviewed(app_config, change):
    console = UpdateConsole(app_config)
    status = observed(app_config)
    observation = status.observation
    if change == "missing":
        status = replace(status, observation=None)
    elif change == "candidate":
        status = replace(status, observation=replace(observation, discovery=UpdateDiscovery(None, True, 0, None, None)))
    elif change == "busy":
        status = replace(status, state="preparing")
    elif change == "expired":
        status = replace(status, observation=replace(
            observation, checked_at=int(time.time()) - 100, expires_at=int(time.time()) - 1,
        ))
    elif change == "application":
        status = replace(status, observation=replace(observation, application_version="0.0.1"))
    elif change == "release":
        status = replace(status, observation=replace(observation, application_release_id="different"))
    with pytest.raises(OperatorFormError):
        console.issue(OperatorContext("operator:first", 9999, "session-first", "csrf-first"), status)


@pytest.mark.parametrize("path", ["?extra=1", "/operations/not-an-id", "/review/not-an-id", "/review/" + "b" * 32])
def test_invalid_queries_and_observation_ids_never_prepare(console, path):
    client, worker = console
    login(client)
    response = client.get(ROOT + path)
    assert response.status_code in {307, 400, 422}
    assert all(call[0] != "prepare" for call in worker.calls)


def test_cache_preparation_while_frozen_never_creates_access_or_changes_freeze(console):
    client, worker = console
    login(client)
    freeze = client.app.state.access_freeze_service
    freeze.freeze("synthetic updater isolation check")
    before = freeze.status()
    configuration = client.app.state.config
    assert prepare(client, review(client)).status_code == 303
    assert worker.value.prepared is not None
    assert freeze.status() == before
    assert client.app.state.config is configuration
    assert client.get("/healthz").status_code == 200


def test_update_views_and_errors_use_the_bundled_stylesheet(console):
    client, _ = console
    login(client)
    for path in (ROOT, ROOT + "/review/" + "a" * 32, ROOT + "?invalid=1"):
        response = client.get(path)
        assert response.status_code in {200, 400}
        assert stylesheet(response) == [BUNDLED_PATH]


def test_receipt_mismatch_is_explicit_unknown_outcome_not_another_operations_success(console):
    client, worker = console
    login(client)
    response = client.get(ROOT + "/operations/" + "b" * 32)
    assert response.status_code == 503
    assert "not proof that no work occurred" in response.text


@pytest.mark.parametrize("mismatch", ["missing", "id", "action", "actor"])
def test_wrong_acknowledgement_cannot_be_shown_as_authorized_success(console, monkeypatch, mismatch):
    client, worker = console
    login(client)
    token = csrf(client.get(ROOT))
    original = worker.check

    async def mismatched(*args):
        result = await original(*args)
        if mismatch == "missing":
            return replace(result, operation=None)
        changes = {
            "id": {"operation_id": "b" * 32}, "action": {"action": "prepare"},
            "actor": {"actor_id": "operator:different"},
        }[mismatch]
        return replace(result, operation=replace(result.operation, **changes))

    monkeypatch.setattr(worker, "check", mismatched)
    response = client.post(ROOT + "/check", data={"csrf": token}, headers=ORIGIN)
    assert response.status_code == 503
    assert "not proof that no work occurred" in response.text


def test_partial_blocked_empty_busy_and_interrupted_discovery_are_distinct(console):
    client, worker = console
    login(client)
    observation = worker.value.observation
    worker.value = replace(worker.value, observation=replace(
        observation, discovery=UpdateDiscovery(None, False, 40, None, None),
    ))
    page = client.get(ROOT)
    assert "Discovery is incomplete" in page.text
    assert "No eligible newer candidate" in page.text
    assert "Review exact release" not in page.text
    worker.value = replace(worker.value, observation=replace(
        observation, discovery=UpdateDiscovery(None, True, 1, "0.2.28", "unavailable"),
    ))
    page = client.get(ROOT)
    assert "Blocked version" in page.text and "0.2.28" in page.text
    assert "Review exact release" not in page.text
    worker.value = replace(worker.value, state="preparing")
    assert "Check published releases" not in client.get(ROOT).text
    worker.value = replace(worker.value, state="interrupted")
    assert "Check published releases" in client.get(ROOT).text


def test_rendering_formats_utc_and_escapes_metadata():
    from strugglebus import update_rendering as rendering

    assert rendering._time(None) == "Not recorded"
    assert rendering._time(0) == "1970-01-01T00:00:00+00:00"
    assert rendering._time(253402300800) == "253402300800 UTC epoch seconds"
    assert "&lt;untrusted&gt;" in rendering.failure("<untrusted>", None)
    assert 'href="&quot;&gt;&lt;script&gt;"' in rendering.refresh('"><script>')


def test_idle_worker_has_no_previous_observation_or_prepared_claim(console):
    client, worker = console
    worker.value = replace(worker.value, state="idle", observation=None)
    login(client)
    page = client.get(ROOT)
    assert page.status_code == 200
    assert "Last release observation" not in page.text
    assert "Currently prepared files" not in page.text
    assert "Check published releases" in page.text
    assert client.get("/system").status_code == 200


def test_missing_console_state_is_explicit_without_worker_contact(console):
    client, worker = console
    login(client)
    original = client.app.state.updater
    try:
        client.app.state.updater = None
        page = client.get(ROOT)
        assert page.status_code == 400
        assert "update console is unavailable" in page.text
        assert worker.calls == []
    finally:
        client.app.state.updater = original


def test_incomplete_startup_closes_authority_and_clears_optional_services(app_config, monkeypatch, verifier):
    from strugglebus.operator_auth import OperatorAuth

    closed = []
    original_close = OperatorAuth.close

    def close(authority):
        closed.append(authority)
        original_close(authority)

    def fail_configuration(config):
        raise RuntimeError("synthetic constructor failure")

    monkeypatch.setattr(OperatorAuth, "close", close)
    monkeypatch.setattr("strugglebus.operator_auth.load_password_verifier", lambda path: verifier)
    application = create_app(config=app_config)
    monkeypatch.setattr("strugglebus.operator_updates.UpdateConsole", fail_configuration)
    with pytest.raises(RuntimeError, match="synthetic constructor failure"):
        with TestClient(application, base_url="https://bus.lan"):
            pytest.fail("Invalid application construction cannot enter lifespan")
    assert len(closed) == 1
    assert application.state.operator_auth is None
    assert application.state.updater is None
    assert application.state.admin_verifier is None


async def test_unauthenticated_prepare_is_rejected_before_consuming_body(console):
    client, worker = console
    responses = []

    async def receive():
        pytest.fail("Unauthenticated updater request consumed its body")

    async def send(message):
        responses.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": "POST", "scheme": "https", "path": ROOT + "/prepare",
        "raw_path": (ROOT + "/prepare").encode(), "query_string": b"", "root_path": "",
        "headers": [
            (b"host", b"bus.lan"), (b"origin", b"https://bus.lan"),
            (b"content-type", b"application/x-www-form-urlencoded"),
            (b"content-length", b"9000000"),
        ],
        "client": ("127.0.0.1", 12345), "server": ("bus.lan", 443),
    }
    await client.app(scope, receive, send)
    assert responses[0]["status"] == 401
    assert worker.calls == []


def test_real_unreachable_client_does_not_block_startup_or_bus_health(app_config, monkeypatch, verifier):
    socket_path = Path(app_config.data_dir.anchor) / "updater-fixture" / (uuid4().hex + ".sock")
    config = replace(app_config, updater_socket_path=socket_path)
    monkeypatch.setattr("strugglebus.operator_auth.load_password_verifier", lambda path: verifier)
    with TestClient(create_app(config=config), base_url="https://bus.lan", follow_redirects=False) as client:
        login(client)
        assert client.get("/healthz").status_code == 200
        response = client.get(ROOT)
        assert response.status_code == 503
        assert str(socket_path) not in response.text
        assert "worker is unavailable" in response.text
        assert client.get("/healthz").status_code == 200
