import hashlib
import html
import re
import ssl
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4
from types import SimpleNamespace

import pytest

from test_ca_anchor import chain
from test_operator_dashboard import browser, login, verifier
from strugglebus.models import LifecycleActor
from strugglebus.operator_auth import SESSION_COOKIE
from strugglebus.reconnect import decode_package


def fields(response):
    assert response.status_code == 200, response.text
    assert response.headers["referrer-policy"] == "same-origin"
    assert "script-src 'none'" in response.headers["content-security-policy"]
    result = {
        name: html.unescape(value)
        for name, value in re.findall(r'name="([^"]+)" value="([^"]*)"', response.text)
    }
    result["reason"] = "synthetic operator action"
    return result


def submit(browser, agent_id, control_action, **overrides):
    path = f"/agents/{agent_id}/control"
    data = fields(browser.get(path, params={"action": control_action}))
    if control_action == "retire":
        data["name"] = browser.app.state.agent_service.get_managed_agent(agent_id).name
    data.update(overrides)
    return browser.post(path, data=data, headers={"Origin": "https://bus.lan"}), data


def transition(service, agent_id, action):
    return service.transition_agent(
        agent_id, action=action,
        expected_credential_epoch=service.get_managed_agent(agent_id).credential_epoch,
        request_id=str(uuid4()), reason="synthetic concurrent lifecycle change",
        actor=LifecycleActor("remote-admin", f"operator:owner:{uuid4()}", lambda: None),
    )


def grant(service, created):
    return service.issue_reconnect(
        created.agent.id, expected_agent_name=created.agent.name,
        expected_credential_epoch=service.get_managed_agent(created.agent.id).credential_epoch,
        request_id=str(uuid4()), reason="synthetic recipient replacement",
        actor=LifecycleActor("remote-admin", f"operator:owner:{uuid4()}", lambda: None),
    )


def redeem(browser, created, allowance, **changes):
    payload = {
        "request_id": str(uuid4()), "expected_agent_id": created.agent.id,
        "expected_agent_name": created.agent.name,
    } | changes
    return browser.post(
        "/api/reconnect/redeem", json=payload,
        headers={"Authorization": f"Bearer {allowance.token}"},
    )


def test_browser_lifecycle_preserves_credentials_and_reserves_retired_name(browser):
    login(browser)
    service = browser.app.state.agent_service
    created = service.create_agent("controls-copilot", description="<script>untrusted</script>")
    identity = created.agent.id
    assert "&lt;script&gt;untrusted&lt;/script&gt;" in browser.get(f"/agents/{identity}").text
    blocked, original_form = submit(browser, identity, "block", reason="<b>bounded reason</b>")
    assert blocked.status_code == 200
    assert service.get_managed_agent(identity).state == "blocked"
    assert service.verify_credential(created.api_key) is None
    assert "Blocked" in browser.get("/agents?state=blocked").text
    assert created.agent.name not in browser.get("/agents?state=enabled").text
    replay = browser.post(
        f"/agents/{identity}/control", data=original_form,
        headers={"Origin": "https://bus.lan"},
    )
    assert replay.status_code == 200 and "Already recorded" in replay.text
    history = browser.get(f"/agents/{identity}")
    assert "&lt;b&gt;bounded reason&lt;/b&gt;" in history.text
    assert "operator:owner:" in history.text
    assert submit(browser, identity, "unblock")[0].status_code == 200
    assert service.verify_credential(created.api_key) is not None
    assert submit(browser, identity, "retire")[0].status_code == 200
    assert service.get_managed_agent(identity).state == "retired"
    assert created.agent.name not in browser.get("/agents").text
    assert created.agent.name in browser.get("/agents?state=retired").text
    assert "This agent's messages" in browser.get(f"/agents/{identity}").text
    assert service.verify_credential(created.api_key) is None
    assert browser.get(f"/agents/{identity}/control?action=unblock").status_code == 409


@pytest.mark.parametrize("action", ["block", "retire", "reconnect"])
@pytest.mark.parametrize("origin", [None, "null", "https://foreign.invalid"])
def test_control_origin_remains_required_with_valid_session_and_csrf(browser, action, origin):
    login(browser)
    service = browser.app.state.agent_service
    created = service.create_agent("origin-copilot")
    path = f"/agents/{created.agent.id}/control"
    data = fields(browser.get(path, params={"action": action}))
    data["name"] = created.agent.name
    response = browser.post(
        path, data=data,
        headers={"Referer": "https://bus.lan" + path} | (
            {} if origin is None else {"Origin": origin}
        ),
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "operator origin rejected"
    assert service.get_managed_agent(created.agent.id).state == "enabled"
    assert service.verify_credential(created.api_key) is not None
    assert service.store.list_agent_lifecycle_events(created.agent.id) == ()


@pytest.mark.parametrize("overrides,code", [
    ({"epoch": "999"}, 409), ({"epoch": "-1"}, 422),
    ({"request_id": "invalid"}, 422), ({"reason": "x" * 257}, 422),
    ({"reason": "bad\nreason"}, 422), ({"name": "wrong-name"}, 422),
    ({"confirm": "unblock"}, 422), ({"action": "freeze"}, 422),
    ({"actor": "local-admin"}, 403), ({"csrf": "forged"}, 403),
])
def test_control_rejects_stale_unconfirmed_unbounded_or_forged_intent(browser, overrides, code):
    login(browser)
    service = browser.app.state.agent_service
    created = service.create_agent("intent-copilot")
    response, _ = submit(browser, created.agent.id, "block", **overrides)
    assert response.status_code == code, response.text
    assert service.get_managed_agent(created.agent.id).state == "enabled"
    assert service.store.list_agent_lifecycle_events(created.agent.id) == ()


def test_expired_browser_session_inside_writer_does_not_commit(browser, monkeypatch):
    login(browser)
    service = browser.app.state.agent_service
    created = service.create_agent("session-copilot")
    context = browser.app.state.operator_auth.authenticate(browser.cookies.get(SESSION_COOKIE))
    original = service.transition_agent

    def expire(*args, **kwargs):
        browser.app.state.operator_auth.logout(context)
        return original(*args, **kwargs)

    monkeypatch.setattr(service, "transition_agent", expire)
    response, _ = submit(browser, created.agent.id, "block")
    assert response.status_code == 401
    assert service.get_managed_agent(created.agent.id).state == "enabled"
    assert service.store.list_agent_lifecycle_events(created.agent.id) == ()


@pytest.mark.parametrize("path", [
    "/agents?state=invalid", "/agents?state=enabled&state=blocked",
    "/agents?limit=201", "/agents?limit=-1", "/agents?after=",
])
def test_managed_roster_query_bounds(browser, path):
    login(browser)
    assert browser.get(path).status_code == 422


def test_roster_filters_and_identity_history_keep_bounded_cursors(browser):
    login(browser)
    service = browser.app.state.agent_service
    first = service.create_agent("alpha-copilot")
    second = service.create_agent("beta-copilot")
    page = browser.get("/agents?state=enabled&limit=1")
    assert first.agent.name in page.text and second.agent.name not in page.text
    assert 'name="state"' in page.text and 'name="limit"' in page.text
    assert 'name="after"' not in page.text
    href = html.unescape(re.search(r'href="([^"]+)">Next agents', page.text)[1])
    following = browser.get(href)
    assert first.agent.name not in following.text.split("<tbody>")[1].split("</tbody>")[0]
    assert second.agent.name in following.text
    assert f'name="after" value="{first.agent.name}"' in following.text
    assert browser.get("/agents?state=blocked&limit=1").status_code == 200
    for action in ("block", "unblock"):
        assert submit(browser, first.agent.id, action)[0].status_code == 200
    history = browser.get(f"/agents/{first.agent.id}?limit=1")
    assert "Next history" in history.text and "Audit details" in history.text
    events = service.store.list_agent_lifecycle_events(first.agent.id)
    for value in (events[0].id, events[0].request_id, events[0].actor_id, events[0].intent_sha256):
        assert value in history.text
    next_history = html.unescape(re.search(r'href="([^"]+)">Next history', history.text)[1])
    assert events[1].request_id in browser.get(next_history).text
    empty = browser.get(f"/agents/{first.agent.id}?after={events[-1].seq}&limit=1")
    assert "Nothing on this page." in empty.text
    assert browser.get(f"/agents/{uuid4()}").status_code == 404


@pytest.mark.parametrize("action", ["unblock", "reconnect"])
def test_access_restoration_discloses_freeze_but_post_keeps_backend_boundary(browser, action):
    login(browser)
    service = browser.app.state.agent_service
    created = service.create_agent("freeze-ui-copilot")
    if action == "unblock":
        transition(service, created.agent.id, "block")
    path = f"/agents/{created.agent.id}/control"
    original = fields(browser.get(path, params={"action": action}))
    browser.app.state.access_freeze_service.freeze("synthetic control disclosure check")
    review = browser.get(path, params={"action": action})
    assert review.status_code == 200
    assert "Creating or restoring access is paused." in review.text
    assert re.search(r'<button\b[^>]*type="submit"[^>]* disabled', review.text)
    identity = browser.get(f"/agents/{created.agent.id}")
    assert "Creating or restoring access is paused." in identity.text
    assert f"/control?action={action}" not in identity.text
    assert "/control?action=retire" in identity.text
    denied = browser.post(path, data=original, headers={"Origin": "https://bus.lan"})
    assert denied.status_code == 503
    assert service.get_managed_agent(created.agent.id, require_access=False).state == (
        "blocked" if action == "unblock" else "enabled"
    )


def test_reconnect_preflight_failure_never_cuts_off_old_key(browser):
    login(browser)
    service = browser.app.state.agent_service
    created = service.create_agent("preflight-copilot")
    response, _ = submit(browser, created.agent.id, "reconnect")
    assert response.status_code == 503
    assert service.get_managed_agent(created.agent.id).credential_epoch == created.agent.credential_epoch
    assert service.verify_credential(created.api_key) is not None
    assert service.store.list_agent_lifecycle_events(created.agent.id) == ()


def test_browser_package_and_grant_only_redemption_end_to_end(browser, chain, caplog):
    login(browser)
    ca_path = chain / "root.crt"
    ca = ca_path.read_bytes()
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca.decode("ascii"))).hexdigest()
    browser.app.state.config = replace(
        browser.app.state.config, ca_bundle_path=str(ca_path), ca_root_sha256=digest,
    )
    service = browser.app.state.agent_service
    created = service.create_agent("package-copilot")
    response, original_form = submit(browser, created.agent.id, "reconnect")
    assert response.status_code == 201, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"].startswith("attachment;")
    assert response.headers["referrer-policy"] == "no-referrer"
    package = decode_package(response.content)
    assert package.agent_id == created.agent.id and package.agent_name == created.agent.name
    assert service.verify_credential(created.api_key) is None
    replay = browser.post(
        f"/agents/{created.agent.id}/control", data=original_form,
        headers={"Origin": "https://bus.lan"},
    )
    assert replay.status_code == 200 and "already went through" in replay.text
    assert package.grant not in replay.text
    browser.cookies.clear()
    allowance = SimpleNamespace(token=package.grant)
    redeemed = redeem(browser, created, allowance)
    assert redeemed.status_code == 201, redeemed.text
    value = redeemed.json()
    assert set(value) == {"agent", "credential", "credential_secret"}
    assert value["agent"]["id"] == created.agent.id
    assert value["credential"]["status"] == "pending"
    assert service.verify_credential(value["credential_secret"]) is not None
    assert redeem(browser, created, allowance).status_code == 401
    assert package.grant not in caplog.text
    assert value["credential_secret"] not in caplog.text


@pytest.mark.parametrize("cutoff", ["block", "retire", "expired", "freeze"])
def test_redemption_fails_closed_after_lifecycle_or_expiry(browser, cutoff):
    service = browser.app.state.agent_service
    created = service.create_agent("cutoff-copilot")
    allowance = grant(service, created)
    if cutoff in {"block", "retire"}:
        transition(service, created.agent.id, cutoff)
    elif cutoff == "expired":
        service._clock = lambda: allowance.grant.expires_at + timedelta(seconds=1)
    else:
        browser.app.state.access_freeze_service.freeze("synthetic test containment")
    response = redeem(browser, created, allowance)
    assert response.status_code == (503 if cutoff == "freeze" else 401)


def test_wrong_identity_and_malformed_json_never_spend_grant(browser):
    service = browser.app.state.agent_service
    created = service.create_agent("identity-copilot")
    allowance = grant(service, created)
    assert redeem(browser, created, allowance, expected_agent_id=str(uuid4())).status_code == 401
    bad = browser.post(
        "/api/reconnect/redeem", content=b'{"request_id":"a","request_id":"b"}',
        headers={"Authorization": f"Bearer {allowance.token}", "Content-Type": "application/json"},
    )
    assert bad.status_code == 422
    assert service.verify_reconnect(allowance.token) is not None
    assert redeem(browser, created, allowance).status_code == 201


async def test_invalid_grant_never_reads_request_body(browser):
    sent = []

    async def receive():
        raise AssertionError("invalid allowance consumed a body")

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": "POST", "scheme": "https", "path": "/api/reconnect/redeem",
        "raw_path": b"/api/reconnect/redeem", "query_string": b"",
        "headers": [(b"host", b"bus.lan"), (b"authorization", b"Bearer sbr1_invalid")],
        "client": ("192.0.2.1", 54321), "server": ("bus.lan", 443),
    }
    await browser.app(scope, receive, send)
    assert sent[0]["status"] == 401


def test_generated_dashboard_response_rechecks_session(browser, monkeypatch):
    login(browser)
    context = browser.app.state.operator_auth.authenticate(browser.cookies.get(SESSION_COOKIE))

    def render(*args, **kwargs):
        browser.app.state.operator_auth.logout(context)
        return "private generated dashboard"

    monkeypatch.setattr("strugglebus.routes.console.render_system", render)
    response = browser.get("/system")
    assert response.status_code == 401
    assert "private generated dashboard" not in response.text


@pytest.mark.parametrize("change", ["block", "retire", "expired", "freeze"])
def test_generated_agent_reply_revalidates_before_headers(browser, monkeypatch, change):
    import strugglebus.routes.agents as agent_routes

    service = browser.app.state.agent_service
    created = service.create_agent("generated-copilot")
    original = agent_routes.build_server_info

    def render(config):
        # The test uses a separate store context, as an independent operator does.
        from strugglebus.auth import AgentService
        from strugglebus.store import SQLiteStore, utc_now

        separate = AgentService(SQLiteStore(
            service.store.database_path, backup_dir=service.store.backup_dir,
        ))
        if change in {"block", "retire"}:
            transition(separate, created.agent.id, change)
        elif change == "expired":
            service._clock = lambda: created.issued_credential.credential.pending_expires_at + timedelta(seconds=1)
        else:
            from strugglebus.access import AccessFreezeService

            AccessFreezeService(
                separate.store, clock=utc_now,
                transition_lock_directory=browser.app.state.config.data_dir / ".access-freeze-lock",
            ).freeze("synthetic generated-response containment")
        return original(config)

    monkeypatch.setattr(agent_routes, "build_server_info", render)
    response = browser.get(
        "/api/server-info", headers={"Authorization": f"Bearer {created.api_key}"},
    )
    assert response.status_code == (503 if change == "freeze" else 401)
    assert "application_version" not in response.text
