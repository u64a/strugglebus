"""Operator console device page: enrolment, display and revocation.

The page mints an operator-class read grant onto a handset, so these tests
cover the authorisation failure paths as carefully as the happy path.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import uuid
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from operator_test_support import PASSWORD, operator_client
from strugglebus.app import create_app
from strugglebus.auth import AgentService
from strugglebus.config import AppConfig, OPERATOR_SETTING_BOUNDS
from strugglebus.store import SQLiteStore

# A synthetic anchor: the console only needs a validated PEM to carry, and
# real certificate validation is covered by the trust anchor tests.
_ROOT_DER = b"synthetic-lan-root-certificate" * 12
_ROOT_PEM = (
    b"-----BEGIN CERTIFICATE-----\n"
    + base64.b64encode(_ROOT_DER)
    + b"\n-----END CERTIFICATE-----\n"
)
_ROOT_SHA256 = "b" * 64


def _application(config: AppConfig):
    service = AgentService(
        SQLiteStore(
            config.database_path,
            backup_dir=config.backup_dir,
            busy_timeout_ms=config.sqlite_busy_timeout_ms,
        )
    )
    return create_app(config=config, agent_service=service)


@pytest.fixture
def console(app_config: AppConfig, tmp_path, monkeypatch: pytest.MonkeyPatch):
    bundle = tmp_path / "lan-root.pem"
    bundle.write_bytes(_ROOT_PEM)
    config = replace(
        app_config, ca_bundle_path=str(bundle), ca_root_sha256=_ROOT_SHA256,
    )
    monkeypatch.setattr(
        "strugglebus.routes.devices.load_trust_anchor", lambda path, digest: _ROOT_PEM
    )
    with operator_client(_application(config)) as client:
        yield client


def _enroll(
    client: TestClient,
    label: str = "owner-phone",
    *,
    password: str = PASSWORD,
    confirm: str = "enroll",
):
    return client.post(
        "/devices",
        data={
            "csrf": client.operator_csrf,
            "label": label,
            "password": password,
            "confirm": confirm,
        },
        headers={"Origin": str(client.base_url).rstrip("/")},
    )


def _payload(body: str) -> dict:
    # The package is on the page in full, in the block a Windows user copies.
    start = body.index(">", body.index('<textarea id="device-package"')) + 1
    encoded = body[start : body.index("</textarea>", start)]
    return json.loads(
        encoded.replace("&quot;", '"').replace("&#x27;", "'")
        .replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
    )


def _devices(client: TestClient) -> tuple[dict, ...]:
    return client.app.state.mobile_service.list_devices()


def _enrollments(client: TestClient) -> int:
    with sqlite3.connect(client.app.state.agent_service.store.database_path) as db:
        return db.execute("SELECT COUNT(*) FROM mobile_enrollments").fetchone()[0]


def test_devices_page_is_a_separate_navigable_page(console: TestClient) -> None:
    page = console.get("/devices")
    assert page.status_code == 200
    assert 'action="/devices"' in page.text
    assert 'href="/system"' in console.get("/").text
    assert 'href="/devices"' in console.get("/system").text
    # It must never be the agent registration form.
    assert 'action="/register"' not in page.text
    assert "Agent name" not in page.text


def test_devices_page_offers_revocation_only(console: TestClient) -> None:
    token = _payload(_enroll(console).text)["enrollment"]
    console.post(
        "/api/mobile/enrollments/redeem",
        json={"request_id": str(uuid.uuid4())},
        headers={"Authorization": f"Bearer {token}"},
    )
    page = console.get("/devices").text
    assert "Revoke" in page
    for absent in ("Block", "Unblock", "Retire"):
        assert absent not in page


def test_enrollment_renders_a_scannable_self_contained_code(
    console: TestClient,
) -> None:
    response = _enroll(console)
    assert response.status_code == 201
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "<svg" in response.text
    # No script may reach a console whose policy forbids one.
    assert "<script" not in response.text
    assert "script-src 'none'" in response.headers["Content-Security-Policy"]

    payload = _payload(response.text)
    assert payload["version"] == 1
    assert payload["device_label"] == "owner-phone"
    assert payload["enrollment"].startswith("sbme1_")
    assert payload["ca_sha256"] == _ROOT_SHA256
    # The root travels inside the code, so the handset never has to fetch it
    # from a connection it cannot yet verify.
    assert base64.b64decode(payload["ca_der"]) == _ROOT_DER


def test_enrollment_window_is_minutes_not_the_agent_default(
    console: TestClient,
) -> None:
    minimum, maximum = OPERATOR_SETTING_BOUNDS["mobile_enrollment_seconds"]
    assert (minimum, maximum) == (120, 300)
    assert console.app.state.config.mobile_enrollment_seconds <= maximum
    with sqlite3.connect(
        console.app.state.agent_service.store.database_path
    ) as database:
        _enroll(console)
        created, expires = database.execute(
            "SELECT created_at, expires_at FROM mobile_enrollments"
        ).fetchone()
    assert created < expires


def test_enrollment_is_single_use_and_redeems_to_a_device(
    console: TestClient,
) -> None:
    token = _payload(_enroll(console).text)["enrollment"]
    redeemed = console.post(
        "/api/mobile/enrollments/redeem",
        json={"request_id": str(uuid.uuid4())},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert redeemed.status_code == 201
    assert redeemed.json()["device_label"] == "owner-phone"
    replay = console.post(
        "/api/mobile/enrollments/redeem",
        json={"request_id": str(uuid.uuid4())},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert replay.status_code == 401
    assert [device["label"] for device in _devices(console)] == ["owner-phone"]


def test_enrollment_requires_the_password_again(console: TestClient) -> None:
    response = _enroll(console, password="not the operator password at all")
    assert response.status_code == 401
    assert _enrollments(console) == 0
    # The session itself survives; only the mint was refused.
    assert console.get("/devices").status_code == 200


def test_repeated_password_guesses_are_bounded(console: TestClient) -> None:
    limit = console.app.state.config.mobile_enroll_session_per_minute
    codes = [
        _enroll(console, password=f"wrong operator password {index}").status_code
        for index in range(limit + 2)
    ]
    assert codes[-1] == 429
    assert _enrollments(console) == 0
    # Reauthentication must not consume the budget that lets an operator sign
    # in again after being locked out of enrolment.
    assert console.get("/login").status_code in {200, 303}


def test_enrollment_requires_explicit_confirmation(console: TestClient) -> None:
    assert _enroll(console, confirm="no").status_code == 422
    assert _enrollments(console) == 0


@pytest.mark.parametrize("label", ["", "   ", "-leading", "a" * 200])
def test_invalid_labels_never_mint(console: TestClient, label: str) -> None:
    assert _enroll(console, label).status_code == 422
    assert _enrollments(console) == 0


def test_label_input_is_reflected_without_executing_it(console: TestClient) -> None:
    response = _enroll(console, '"><script>alert(1)</script>')
    assert response.status_code == 422
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_enrollment_requires_csrf(console: TestClient) -> None:
    response = console.post(
        "/devices",
        data={
            "csrf": "x" * 43, "label": "owner-phone",
            "password": PASSWORD, "confirm": "enroll",
        },
        headers={"Origin": str(console.base_url).rstrip("/")},
    )
    assert response.status_code in {401, 403}
    assert _enrollments(console) == 0


def test_enrollment_requires_a_published_trust_anchor(
    app_config: AppConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "strugglebus.routes.devices.load_trust_anchor", lambda path, digest: None
    )
    with operator_client(_application(app_config)) as client:
        response = _enroll(client)
        assert response.status_code == 503
        assert _enrollments(client) == 0


def test_duplicate_labels_are_refused(console: TestClient) -> None:
    token = _payload(_enroll(console).text)["enrollment"]
    console.post(
        "/api/mobile/enrollments/redeem",
        json={"request_id": str(uuid.uuid4())},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert _enroll(console).status_code == 409


def test_the_console_survives_a_freeze_but_minting_does_not(
    console: TestClient,
) -> None:
    """A freeze stops the agent plane, not the humans containing the incident.

    The console used to return 503 for every page while frozen, which meant the
    freeze prevented the very revocation it exists to enable. Reads and
    containment now work; anything that creates access still refuses.
    """

    device_id, secret = _redeemed_device(console)
    console.app.state.access_freeze_service.freeze("incident drill")

    # The operator can still see the roster and reach the revoke confirmation.
    page = console.get("/devices")
    assert page.status_code == 200
    assert "Agent access is frozen" in page.text
    assert 'type="submit" disabled aria-describedby="action-access-note"' in page.text
    revocation = console.get(f"/devices/{device_id}/revoke")
    assert revocation.status_code == 200
    assert 'type="submit" disabled' not in revocation.text

    # Containment works: this is the whole point of keeping the plane alive.
    assert _revoke(console, device_id, label="owner-phone").status_code == 200
    assert console.app.state.mobile_service.authorize(secret) is None

    # Minting does not, for any actor, so nothing that grants access is
    # created while the owner has stopped trusting the system's state.
    assert _enroll(console, "owner-phone-two").status_code == 503
    assert _enrollments(console) == 1

    console.app.state.access_freeze_service.unfreeze("drill complete")
    assert _enroll(console, "owner-phone-two").status_code == 201


def _redeemed_device(console: TestClient) -> tuple[str, str]:
    token = _payload(_enroll(console).text)["enrollment"]
    redeemed = console.post(
        "/api/mobile/enrollments/redeem",
        json={"request_id": str(uuid.uuid4())},
        headers={"Authorization": f"Bearer {token}"},
    ).json()
    return redeemed["device_id"], redeemed["credential_secret"]


def _revoke(
    console: TestClient, device_id: str, *, label: str, reason: str = "handset lost",
):
    return console.post(
        f"/devices/{device_id}/revoke",
        data={
            "csrf": console.operator_csrf, "label": label,
            "reason": reason, "confirm": "revoke",
        },
        headers={"Origin": str(console.base_url).rstrip("/")},
    )


def test_revocation_confirms_the_exact_label_before_acting(
    console: TestClient,
) -> None:
    device_id, secret = _redeemed_device(console)
    page = console.get(f"/devices/{device_id}/revoke")
    assert page.status_code == 200
    assert "owner-phone" in page.text

    wrong = _revoke(console, device_id, label="owner-tablet")
    assert wrong.status_code == 422
    assert _devices(console)[0]["status"] == "enabled"
    assert console.app.state.mobile_service.authorize(secret) is not None

    applied = _revoke(console, device_id, label="owner-phone")
    assert applied.status_code == 200
    assert _devices(console)[0]["status"] == "revoked"
    assert _devices(console)[0]["active_credentials"] == 0
    assert console.app.state.mobile_service.authorize(secret) is None


def test_revoking_twice_reports_the_changed_state(console: TestClient) -> None:
    device_id, _secret = _redeemed_device(console)
    assert _revoke(console, device_id, label="owner-phone").status_code == 200
    assert console.get(f"/devices/{device_id}/revoke").status_code == 404
    assert _revoke(console, device_id, label="owner-phone").status_code == 404


def test_revocation_requires_a_reason(console: TestClient) -> None:
    device_id, secret = _redeemed_device(console)
    assert _revoke(console, device_id, label="owner-phone", reason=" ").status_code == 422
    assert console.app.state.mobile_service.authorize(secret) is not None


def test_unknown_device_identity_is_refused(console: TestClient) -> None:
    assert console.get("/devices/not-a-uuid/revoke").status_code == 422
    assert console.get(f"/devices/{uuid.uuid4()}/revoke").status_code == 404


def _replace(
    console: TestClient,
    device_id: str,
    *,
    label: str,
    new_label: str = "owner-phone-two",
    reason: str = "handset replaced",
    password: str = PASSWORD,
    confirm: str = "replace",
):
    return console.post(
        f"/devices/{device_id}/replace",
        data={
            "csrf": console.operator_csrf, "label": label,
            "new_label": new_label, "password": password,
            "reason": reason, "confirm": confirm,
        },
        headers={"Origin": str(console.base_url).rstrip("/")},
    )


def test_replacement_revokes_the_old_keys_at_issue_time(
    console: TestClient,
) -> None:
    device_id, secret = _redeemed_device(console)
    assert console.get(f"/devices/{device_id}/replace").status_code == 200

    response = _replace(console, device_id, label="owner-phone")
    assert response.status_code == 201
    assert response.headers["Cache-Control"] == "no-store"
    # The outgoing keys die now, not when the replacement is finally redeemed.
    assert console.app.state.mobile_service.authorize(secret) is None
    states = {device["label"]: device["status"] for device in _devices(console)}
    assert states == {"owner-phone": "revoked"}

    payload = _payload(response.text)
    assert payload["device_label"] == "owner-phone-two"
    assert "owner-phone" in response.text
    redeemed = console.post(
        "/api/mobile/enrollments/redeem",
        json={"request_id": str(uuid.uuid4())},
        headers={"Authorization": f"Bearer {payload['enrollment']}"},
    )
    assert redeemed.status_code == 201
    assert console.app.state.mobile_service.authorize(
        redeemed.json()["credential_secret"]
    ) is not None


def test_replacement_will_not_reuse_the_retired_label(console: TestClient) -> None:
    device_id, secret = _redeemed_device(console)
    response = _replace(console, device_id, label="owner-phone", new_label="owner-phone")
    assert response.status_code == 409
    assert console.app.state.mobile_service.authorize(secret) is not None
    assert _devices(console)[0]["status"] == "enabled"


@pytest.mark.parametrize(
    "kwargs, code",
    [
        ({"label": "owner-tablet"}, 422),
        ({"label": "owner-phone", "confirm": "no"}, 422),
        ({"label": "owner-phone", "reason": " "}, 422),
        ({"label": "owner-phone", "new_label": "-bad"}, 422),
        ({"label": "owner-phone", "password": "wrong operator password"}, 401),
    ],
)
def test_refused_replacements_leave_the_device_working(
    console: TestClient, kwargs: dict, code: int
) -> None:
    device_id, secret = _redeemed_device(console)
    assert _replace(console, device_id, **kwargs).status_code == code
    assert console.app.state.mobile_service.authorize(secret) is not None
    assert _devices(console)[0]["status"] == "enabled"
    assert _enrollments(console) == 1


def test_replacement_needs_a_trust_anchor_before_it_revokes(
    console: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    device_id, secret = _redeemed_device(console)
    monkeypatch.setattr(
        "strugglebus.routes.devices.load_trust_anchor", lambda path, digest: None
    )
    assert _replace(console, device_id, label="owner-phone").status_code == 503
    # A deployment without a published root must not retire a working device
    # and then fail to issue its successor.
    assert console.app.state.mobile_service.authorize(secret) is not None
    assert _devices(console)[0]["status"] == "enabled"


def test_replacement_is_denied_while_frozen(console: TestClient) -> None:
    device_id, secret = _redeemed_device(console)
    console.app.state.access_freeze_service.freeze("incident drill")
    assert _replace(console, device_id, label="owner-phone").status_code == 503
    console.app.state.access_freeze_service.unfreeze("drill complete")
    assert console.app.state.mobile_service.authorize(secret) is not None
    assert _devices(console)[0]["status"] == "enabled"


def test_a_revoked_device_cannot_be_replaced(console: TestClient) -> None:
    device_id, _secret = _redeemed_device(console)
    assert _revoke(console, device_id, label="owner-phone").status_code == 200
    assert console.get(f"/devices/{device_id}/replace").status_code == 404
    assert _replace(console, device_id, label="owner-phone").status_code == 404


def test_replacement_is_recorded_in_the_device_audit(console: TestClient) -> None:
    device_id, _secret = _redeemed_device(console)
    _replace(console, device_id, label="owner-phone", reason="left on a train")
    with sqlite3.connect(
        console.app.state.agent_service.store.database_path
    ) as database:
        rows = database.execute(
            "SELECT event_type, reason, details_json FROM mobile_device_audit "
            "WHERE device_id = ? ORDER BY seq",
            (device_id,),
        ).fetchall()
    assert [row[0] for row in rows] == ["issued", "replaced"]
    assert rows[1][1] == "left on a train"
    assert json.loads(rows[1][2]) == {"replacement_label": "owner-phone-two"}


def test_device_pages_require_an_operator_session(app_config: AppConfig) -> None:
    with TestClient(
        _application(app_config), base_url="https://bus.lan", follow_redirects=False
    ) as client:
        assert client.get("/devices").status_code in {303, 503}
        assert client.post(
            "/devices", data={"label": "owner-phone"},
        ).status_code in {401, 403, 415, 503}
        assert client.get(f"/devices/{uuid.uuid4()}/replace").status_code in {303, 503}
