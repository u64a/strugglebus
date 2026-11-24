import re
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from strugglebus.app import create_app
from strugglebus.config import AppConfig
from strugglebus.dashboard import DASHBOARD_STYLESHEET_PATH
from strugglebus.errors import ConfigurationError
from strugglebus.operator_auth import (
    SESSION_COOKIE,
    PasswordVerifier,
    create_password_verifier,
)

PASSWORD = "synthetic browser operator password"
HUMAN_PATHS = (
    "/", "/activity", "/agents", "/channels", "/system", "/register",
    "/operator/session", "/agents/", "/register/", "/humans",
)


@pytest.fixture(scope="module")
def verifier():
    return PasswordVerifier.parse(create_password_verifier(PASSWORD))


@pytest.fixture
def browser(app_config, monkeypatch, verifier):
    monkeypatch.setattr(
        "strugglebus.operator_auth.load_password_verifier", lambda path: verifier,
    )
    with TestClient(
        create_app(config=app_config), base_url="https://bus.lan",
        follow_redirects=False,
    ) as client:
        yield client


def csrf(response):
    return re.search(r'name="csrf" value="([^"]+)"', response.text)[1]


def login(client):
    page = client.get("/login")
    assert page.status_code == 200
    assert page.headers["referrer-policy"] == "same-origin"
    assert "script-src 'none'" in page.headers["content-security-policy"]
    response = client.post(
        "/login", data={"csrf": csrf(page), "password": PASSWORD},
        headers={"Origin": "https://bus.lan"},
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    return response


@pytest.mark.parametrize("path", HUMAN_PATHS)
def test_all_human_paths_redirect_anonymous_without_board_data(browser, path):
    response = browser.get(path)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert "<summary>Versions" not in response.text


def test_unconfigured_console_offers_only_first_use_setup(app_config):
    with TestClient(
        create_app(config=app_config), base_url="https://bus.lan", follow_redirects=False,
    ) as client:
        for path in (*HUMAN_PATHS, "/login"):
            response = client.get(path)
            assert response.status_code == 303
            assert response.headers["location"] == "/setup"
        assert client.get("/setup").status_code == 200
        assert client.post(
            "/login", data={"password": PASSWORD}, headers={"Origin": "https://bus.lan"},
        ).status_code == 503
        assert client.get("/healthz").status_code == 200
        assert client.get(DASHBOARD_STYLESHEET_PATH).status_code == 200


def test_first_enablement_loads_real_private_verifier_without_maintenance_history(
    app_config, tmp_path, monkeypatch,
):
    from strugglebus.operator_local import require_resolved_maintenance

    state = tmp_path / "never-initialized-maintenance"
    old_helpers = tmp_path / "never-installed-maintenance-helpers"
    assert require_resolved_maintenance(state_directory=state, helper_root=old_helpers) is None
    projection = tmp_path / "private-projected-credentials"
    projection.mkdir(mode=0o700)
    path = projection / "operator-password"
    path.write_bytes(create_password_verifier(PASSWORD))
    path.chmod(0o400)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(projection))
    config = replace(app_config, operator_credential_path=path)
    with TestClient(
        create_app(config=config), base_url="https://bus.lan", follow_redirects=False,
    ) as client:
        assert client.get("/").status_code == 303
        login(client)
        assert client.get("/").status_code == 200
    assert not state.exists()
    assert not old_helpers.exists()


def test_application_and_local_services_honor_reconnect_configuration(app_config):
    from strugglebus.cli import _services

    config = replace(app_config, reconnect_grant_seconds=60, reconnect_max_grants=3)
    application = create_app(config=config)
    local, _ = _services(config)
    for service in (application.state.agent_service, local):
        assert service.reconnect_ttl_seconds == 60
        assert service.max_outstanding_reconnect_grants == 3
        prepared = service.prepare_reconnect_grant()
        assert (prepared.expires_at - prepared.created_at).total_seconds() == 60


def test_login_uses_secure_opaque_cookie_and_logout_is_post_only(browser):
    response = login(browser)
    cookie = next(
        value for value in response.headers.get_list("set-cookie")
        if value.startswith(SESSION_COOKIE + "=")
    )
    for expected in (
        "Secure", "HttpOnly", "SameSite=strict", "Path=/",
        f"Max-Age={AppConfig().operator_session_seconds}",
    ):
        assert expected in cookie
    assert "Domain=" not in cookie
    assert PASSWORD not in cookie
    for path in ("/", "/activity", "/channels", "/agents", "/system", "/register"):
        page = browser.get(path)
        assert page.status_code == 200
        assert "script-src 'none'" in page.headers["content-security-policy"]
        assert page.headers["referrer-policy"] == "same-origin"
    assert browser.get("/logout").status_code in {404, 405}
    session = browser.get("/operator/session")
    assert session.headers["referrer-policy"] == "same-origin"
    assert 'action="/logout"' in session.text
    old_cookie = browser.cookies.get(SESSION_COOKIE)
    response = browser.post(
        "/logout", data={"csrf": csrf(session)}, headers={"Origin": "https://bus.lan"},
    )
    assert response.status_code == 303
    assert browser.get("/").status_code == 303
    assert browser.app.state.operator_auth.authenticate(old_cookie) is None


@pytest.mark.parametrize("frozen", [False, True])
def test_session_navigation_is_current_in_desktop_and_mobile_menus(browser, frozen):
    login(browser)
    if frozen:
        browser.app.state.access_freeze_service.freeze("synthetic session navigation check")
    response = browser.get("/operator/session")
    assert response.status_code == 200
    current = re.findall(r'<a\b[^>]*aria-current="page"[^>]*>', response.text)
    assert len(current) == 2
    assert all('href="/operator/session"' in link for link in current)
    assert "You are signed out after the first time above" in response.text


@pytest.mark.parametrize("origin", [None, "null", "https://foreign.invalid", "http://bus.lan"])
def test_wrong_origin_cannot_login(browser, origin):
    page = browser.get("/login")
    response = browser.post(
        "/login", data={"csrf": csrf(page), "password": PASSWORD},
        headers={"Referer": "https://bus.lan/login"} | (
            {} if origin is None else {"Origin": origin}
        ),
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "operator origin rejected"
    assert SESSION_COOKIE not in browser.cookies


@pytest.mark.parametrize("origin", [None, "null", "https://foreign.invalid", "http://bus.lan"])
@pytest.mark.parametrize("path", ["/logout", "/register"])
def test_wrong_origin_cannot_mutate_even_with_same_origin_referer(browser, origin, path):
    login(browser)
    session = browser.get("/operator/session")
    response = browser.post(
        path, data={"csrf": csrf(session), "name": "origin-enrollment"},
        headers={"Referer": "https://bus.lan/operator/session"} | (
            {} if origin is None else {"Origin": origin}
        ),
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "operator origin rejected"
    assert browser.get("/").status_code == 200
    assert not browser.app.state.agent_service.list_enrollments()


def test_csrf_and_duplicate_form_fields_are_rejected(browser):
    page = browser.get("/login")
    response = browser.post(
        "/login", data={"csrf": "forged", "password": PASSWORD},
        headers={"Origin": "https://bus.lan"},
    )
    assert response.status_code == 401
    page = browser.get("/login")
    response = browser.post(
        "/login", content=f"csrf={csrf(page)}&password=a&password=b",
        headers={
            "Origin": "https://bus.lan",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert response.status_code == 403
    assert PASSWORD not in response.text
    assert SESSION_COOKIE not in browser.cookies


def test_registration_never_accepts_admin_bearer_as_browser_authority(browser):
    response = browser.post(
        "/register", headers={"Authorization": "Bearer test-only-admin-secret"},
        data={"name": "synthetic-agent"},
    )
    assert response.status_code == 401
    assert not browser.app.state.agent_service.list_enrollments()


async def test_unauthorized_and_cross_origin_posts_never_read_body(browser):
    application = browser.app
    called = False

    async def receive():
        nonlocal called
        called = True
        raise AssertionError("unauthorized request consumed its body")

    sent = []

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": "POST", "scheme": "https", "path": "/register",
        "raw_path": b"/register", "query_string": b"",
        "headers": [(b"host", b"bus.lan")],
        "client": ("192.0.2.1", 54321), "server": ("bus.lan", 443),
    }
    await application(scope, receive, send)
    assert sent[0]["status"] == 401
    assert not called


def test_configured_bad_password_file_fails_startup_not_common_config(app_config, tmp_path):
    config = replace(app_config, operator_credential_path=tmp_path / "missing")
    assert config.load_admin_secret() == b"test-only-admin-secret"
    with pytest.raises(ConfigurationError, match="operator credential file is unavailable"):
        with TestClient(create_app(config=config)):
            pass


def test_the_operator_plane_survives_a_freeze_and_health_stays_up(browser):
    """A freeze stops the agent plane, not the human containing the incident.

    Every console page used to return 503 while frozen, and the owner could not
    even sign in, so the control prevented the containment it exists to enable.
    Reads, sign-in and sign-out now work; anything that creates access does not,
    which is asserted where minting is exercised.
    """

    login(browser)
    session = browser.get("/operator/session")
    browser.app.state.access_freeze_service.freeze("synthetic containment test")
    for path in HUMAN_PATHS:
        # Not 503: the point is that the freeze no longer blacks the console
        # out. Individual pages may still 404 on unconfigured optionals such as
        # the CA download, which is a configuration fact rather than a freeze.
        assert browser.get(path).status_code != 503, path
    assert browser.get("/healthz").status_code == 200
    assert browser.get(DASHBOARD_STYLESHEET_PATH).status_code == 200
    assert browser.app.state.access_freeze_service.status().frozen
    # Signing out still works, so a frozen console is not a trap.
    assert browser.post(
        "/logout", data={"csrf": csrf(session)},
        headers={"Origin": "https://bus.lan"},
    ).status_code == 303
    # And the owner can sign back in to keep working the incident.
    login(browser)
    assert browser.get("/").status_code == 200


def test_duplicate_cookie_and_cross_origin_mutation_are_rejected(browser):
    login(browser)
    session = browser.get("/operator/session")
    token = browser.cookies.get(SESSION_COOKIE)
    duplicate = f"{SESSION_COOKIE}={token}; {SESSION_COOKIE}={token}"
    assert browser.get("/", headers={"Cookie": duplicate}).status_code == 303
    response = browser.post(
        "/logout", data={"csrf": csrf(session)},
        headers={"Origin": "https://foreign.invalid"},
    )
    assert response.status_code == 403
    assert browser.get("/").status_code == 200


def test_protected_forms_bound_real_bytes_and_require_content_type(browser):
    login(browser)
    assert browser.post(
        "/logout", content=b"x",
        headers={"Origin": "https://bus.lan", "Content-Type": "application/json"},
    ).status_code == 415
    assert browser.post(
        "/logout", content=b"x" * 8193,
        headers={
            "Origin": "https://bus.lan",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    ).status_code == 413


def _setup(client, code, password=PASSWORD, confirmation=None, origin="https://bus.lan"):
    return client.post(
        "/setup",
        data={"code": code, "password": password, "confirmation": confirmation or password},
        headers={"Origin": origin},
    )


def test_first_use_setup_sets_the_password_once_and_survives_restart(app_config):
    directory = app_config.data_dir / "operator"
    with TestClient(
        create_app(config=app_config), base_url="https://bus.lan", follow_redirects=False,
    ) as client:
        assert "Setup code" in client.get("/setup").text
        code = (directory / "setup-code").read_text().strip()
        response = _setup(client, code)
        assert (response.status_code, response.headers["location"]) == (303, "/login")
        assert not (directory / "setup-code").exists()
        stored = (directory / "password").read_bytes()
        assert PASSWORD.encode() not in stored
        login(client)
        assert client.get("/").status_code == 200
        # The code is spent and setup is gone; the password is unchanged.
        assert _setup(client, code, "a different operator password").headers["location"] == "/login"
        assert (directory / "password").read_bytes() == stored
    with TestClient(
        create_app(config=app_config), base_url="https://bus.lan", follow_redirects=False,
    ) as client:
        assert client.get("/").headers["location"] == "/login"
        assert client.get("/setup").headers["location"] == "/login"
        login(client)
    assert not (directory / "setup-code").exists()


def test_first_use_setup_refuses_bad_codes_passwords_and_origins(app_config):
    directory = app_config.data_dir / "operator"
    with TestClient(
        create_app(config=app_config), base_url="https://bus.lan", follow_redirects=False,
    ) as client:
        code = (directory / "setup-code").read_text().strip()
        assert _setup(client, "0" * 24).status_code == 401
        assert _setup(client, code, confirmation=PASSWORD + " mismatch").status_code == 401
        assert _setup(client, code, "too short").status_code == 401
        assert _setup(client, code, origin="https://evil.example").status_code == 403
        assert client.post("/register", data={"name": "x"}, headers={
            "Origin": "https://bus.lan",
        }).status_code == 503
        assert not (directory / "password").exists()
        # Refusals do not spend the code.
        assert _setup(client, code).status_code == 303
        login(client)


def test_first_use_setup_code_expires(app_config):
    import asyncio

    from strugglebus.operator_auth import OperatorAuth, OperatorAuthError

    now = [1_000.0]
    directory = app_config.data_dir / "operator"
    authority = OperatorAuth(
        app_config, None, clock=lambda: now[0], setup_directory=directory,
    )
    try:
        authority.prepare_setup()
        code = (directory / "setup-code").read_text().strip()
        now[0] += 86_400
        with pytest.raises(OperatorAuthError):
            asyncio.run(authority.complete_setup(
                source="test", code=code, password=PASSWORD, confirmation=PASSWORD,
            ))
        assert not (directory / "password").exists()
    finally:
        authority.close()


def test_root_credential_takes_priority_over_first_use_setup(browser, app_config):
    assert browser.get("/setup").headers["location"] == "/login"
    assert not (app_config.data_dir / "operator").exists()
    login(browser)
