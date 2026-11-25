"""Satellite sites: schema, certificate issue, console, and admission.

A site reaches the agent plane through a gateway the bus does not control, so
these tests weigh the refusals as heavily as the happy path.
"""

from __future__ import annotations

import base64
import html
import json
import sqlite3
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

from operator_test_support import PASSWORD, operator_client
from strugglebus.app import create_app
from strugglebus.auth import AgentService
from strugglebus.config import AppConfig
from strugglebus.errors import ConfigurationError, DomainValidationError
from strugglebus.migrations import (
    LATEST_SCHEMA_VERSION,
    apply_migrations,
    load_packaged_migrations,
)
from strugglebus.satellite import (
    BUNDLE_PREFIX,
    SITE_CERT_HEADER,
    SiteAuthority,
    encode_join_request,
    parse_join_request,
)
from strugglebus.store import SQLiteStore

HOSTNAME = "sb-gw.example.cloudapp.azure.com"
GATEWAY = "10.99.0.1"
# The satellite proxy appends the gateway's tunnel address, its only peer.
FROM_GATEWAY = {"X-Forwarded-For": GATEWAY}


def _ca() -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test site CA")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def _join_request(key=None) -> str:
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "anything")]))
        .sign(key, hashes.SHA256())
    )
    return encode_join_request(csr)


@pytest.fixture
def satellite_config(app_config: AppConfig, tmp_path, monkeypatch: pytest.MonkeyPatch):
    cert_pem, key_pem = _ca()
    cert_path = tmp_path / "site-ca.pem"
    cert_path.write_bytes(cert_pem)
    # The credential reader's ownership checks are covered by the admin token
    # tests; here the key only needs to arrive.
    monkeypatch.setattr(AppConfig, "load_satellite_ca_key", lambda self: key_pem)
    return replace(
        app_config,
        satellite_hostname=HOSTNAME,
        satellite_ca_cert_path=cert_path,
        satellite_ca_key_path=tmp_path / "site-ca.key",
        satellite_gateway_wg_address=GATEWAY,
        # The test client stands in for the satellite proxy on loopback.
        trusted_proxy_sources=(*app_config.trusted_proxy_sources, "testclient"),
    )


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
def console(satellite_config: AppConfig):
    with operator_client(_application(satellite_config)) as client:
        client.headers.update(FROM_GATEWAY)
        yield client


def _add(client: TestClient, label: str = "devbox-one", **overrides):
    data = {
        "csrf": client.operator_csrf,
        "label": label,
        "join_request": _join_request(),
        "password": PASSWORD,
        "confirm": "add",
        **overrides,
    }
    return client.post(
        "/sites", data=data, headers={"Origin": str(client.base_url).rstrip("/")},
    )


def _bundle(body: str) -> dict:
    start = body.index("<pre>") + len("<pre>")
    text = html.unescape(body[start: body.index("</pre>", start)])
    assert text.startswith(BUNDLE_PREFIX)
    encoded = text[len(BUNDLE_PREFIX):]
    return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))


def _fingerprint(bundle: dict) -> str:
    certificate = x509.load_pem_x509_certificate(bundle["cert_pem"].encode())
    return certificate.fingerprint(hashes.SHA256()).hex()


def test_schema_twenty_one_upgrades_an_existing_database(tmp_path) -> None:
    database_path = tmp_path / "schema-twenty.db"
    with sqlite3.connect(database_path, isolation_level=None) as database:
        assert apply_migrations(database, load_packaged_migrations()[:20]) == 20
        database.execute(
            "INSERT INTO agents (id, name, created_at) "
            "VALUES ('host', 'host-one', '2026-01-01T00:00:00Z')"
        )
    store = SQLiteStore(database_path, backup_dir=tmp_path / "backups")

    assert store.initialize() == LATEST_SCHEMA_VERSION == 24
    assert list((tmp_path / "backups").iterdir())
    assert store.list_satellite_sites() == ()
    with sqlite3.connect(database_path) as database:
        assert ("host-one",) in database.execute("SELECT name FROM agents").fetchall()


def test_issued_certificate_is_a_short_lived_client_certificate(satellite_config) -> None:
    authority = SiteAuthority.load(satellite_config)
    key = ec.generate_private_key(ec.SECP256R1())
    issued = authority.issue("devbox-one", parse_join_request(_join_request(key)))
    encoded = issued.bundle[len(BUNDLE_PREFIX):]
    bundle = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    certificate = x509.load_pem_x509_certificate(bundle["cert_pem"].encode())

    assert bundle["hostname"] == HOSTNAME and bundle["port"] == 443
    assert certificate.public_key() == key.public_key()
    # The subject comes from the operator's label, never from the request.
    assert certificate.subject.rfc4514_string() == "CN=devbox-one"
    assert certificate.extensions.get_extension_for_class(
        x509.ExtendedKeyUsage
    ).value == x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
    assert not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    lifetime = certificate.not_valid_after_utc - certificate.not_valid_before_utc
    assert lifetime <= timedelta(days=30, minutes=5)
    assert issued.cert_sha256 == _fingerprint(bundle)
    assert "PRIVATE KEY" not in issued.bundle


@pytest.mark.parametrize(
    "request_text",
    ["", "sb-join-1.", "sb-join-1.not-base64!", "not-a-request", "sb-join-1." + "A" * 5000],
)
def test_malformed_join_requests_are_refused(request_text: str) -> None:
    with pytest.raises(DomainValidationError):
        parse_join_request(request_text)


def test_only_p256_site_keys_are_accepted() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(DomainValidationError, match="P-256"):
        parse_join_request(_join_request(key))


def test_partial_satellite_configuration_is_refused(app_config: AppConfig, tmp_path) -> None:
    with pytest.raises(ConfigurationError, match="all be set"):
        replace(app_config, satellite_hostname=HOSTNAME)
    with pytest.raises(ConfigurationError, match="public DNS name"):
        replace(
            app_config, satellite_hostname="satellite-spike.strugglebus_",
            satellite_ca_cert_path=tmp_path / "c", satellite_ca_key_path=tmp_path / "k",
        )
    for address in ("", "gateway"):
        with pytest.raises(ConfigurationError, match="tunnel address"):
            replace(
                app_config, satellite_hostname=HOSTNAME, satellite_gateway_wg_address=address,
                satellite_ca_cert_path=tmp_path / "c", satellite_ca_key_path=tmp_path / "k",
            )


def test_mismatched_ca_key_refuses_startup(satellite_config, monkeypatch) -> None:
    _, other_key = _ca()
    monkeypatch.setattr(AppConfig, "load_satellite_ca_key", lambda self: other_key)
    with pytest.raises(ConfigurationError, match="does not match"):
        SiteAuthority.load(satellite_config)


def test_adding_a_site_returns_a_bundle_and_records_it(console: TestClient) -> None:
    response = _add(console)
    assert response.status_code == 201, response.text
    assert response.headers["Cache-Control"] == "no-store"
    bundle = _bundle(response.text)
    assert bundle["site"] == "devbox-one"
    sites = console.app.state.satellite_service.list_sites()
    assert [(s["label"], s["status"]) for s in sites] == [("devbox-one", "enabled")]
    assert console.app.state.satellite_service.admits(_fingerprint(bundle))
    assert 'href="/sites"' in console.get("/system").text


def test_adding_a_site_requires_the_password_again(console: TestClient) -> None:
    response = _add(console, password="wrong")
    assert response.status_code == 401
    assert console.app.state.satellite_service.list_sites() == ()


def test_adding_a_site_requires_confirmation_and_csrf(console: TestClient) -> None:
    assert _add(console, confirm="").status_code == 422
    assert _add(console, csrf="forged").status_code in {400, 403}
    assert console.app.state.satellite_service.list_sites() == ()


def test_labels_are_reserved_after_revocation(console: TestClient) -> None:
    _add(console)
    site = console.app.state.satellite_service.list_sites()[0]
    console.app.state.satellite_service.revoke_site(site["id"], reason="r", actor_id="o")
    assert _add(console).status_code == 409


def test_adding_a_site_is_refused_while_frozen(console: TestClient) -> None:
    console.app.state.access_freeze_service.freeze("incident drill")
    try:
        response = _add(console)
    finally:
        console.app.state.access_freeze_service.unfreeze("drill complete")
    assert response.status_code == 503
    assert "frozen" in response.text
    assert console.app.state.satellite_service.list_sites() == ()


def test_unconfigured_deployments_explain_rather_than_offer_the_form(
    app_config: AppConfig,
) -> None:
    with operator_client(_application(app_config)) as client:
        page = client.get("/sites")
        assert page.status_code == 200
        assert "not set up on this bus" in page.text
        assert 'action="/sites"' not in page.text
        assert _add(client).status_code == 503


def test_revocation_confirms_the_exact_label(console: TestClient) -> None:
    bundle = _bundle(_add(console).text)
    site_id = console.app.state.satellite_service.list_sites()[0]["id"]
    origin = {"Origin": str(console.base_url).rstrip("/")}
    form = {"csrf": console.operator_csrf, "reason": "machine returned", "confirm": "revoke"}

    wrong = console.post(f"/sites/{site_id}/revoke", data={**form, "label": "other"}, headers=origin)
    assert wrong.status_code == 422
    assert console.app.state.satellite_service.admits(_fingerprint(bundle))

    done = console.post(f"/sites/{site_id}/revoke", data={**form, "label": "devbox-one"}, headers=origin)
    assert done.status_code == 200 and "Revoked devbox-one" in done.text
    assert not console.app.state.satellite_service.admits(_fingerprint(bundle))
    again = console.post(f"/sites/{site_id}/revoke", data={**form, "label": "devbox-one"}, headers=origin)
    assert again.status_code == 404


def test_site_pages_require_an_operator_session(satellite_config: AppConfig) -> None:
    with TestClient(
        _application(satellite_config), base_url="https://bus.lan", follow_redirects=False,
    ) as client:
        assert client.get("/sites").status_code in {303, 503}
        assert client.post("/sites", data={"label": "x"}).status_code in {401, 403, 415, 503}
        assert client.get(f"/sites/{uuid.uuid4()}/revoke").status_code in {303, 503}


def test_satellite_requests_reach_agent_routes_only_while_admitted(
    console: TestClient,
) -> None:
    fingerprint = _fingerprint(_bundle(_add(console).text))
    via_site = {SITE_CERT_HEADER: fingerprint}

    # Admitted: the request reaches agent authentication, which still applies.
    admitted = console.get("/api/whoami", headers=via_site)
    assert admitted.status_code == 401, admitted.text
    # The console is never reachable through a site, even with a session.
    assert console.get("/sites", headers=via_site).status_code == 403
    assert console.get("/", headers=via_site).status_code == 403
    # Admin, mobile and service-principal routes stay LAN-only, whatever token.
    admin = {**via_site, "Authorization": "Bearer admin-token"}
    for method, route in (
        ("POST", "/api/agents"),
        ("GET", "/api/admin/identity-provenance"),
        ("GET", "/api/mobile/status"),
        ("POST", "/api/mobile/enrollments/redeem"),
        ("POST", "/api/spn/onboarding-packages"),
    ):
        refused = console.request(method, route, headers=admin, json={})
        assert refused.status_code == 403, route
        assert "agent routes only" in refused.text, route
    # A site header from anywhere but the gateway is a LAN client's claim.
    for lan in ({"X-Forwarded-For": "192.168.1.50"}, {"X-Forwarded-For": f"{GATEWAY}, 192.168.1.50"}):
        assert console.get("/api/whoami", headers={**via_site, **lan}).status_code == 403
        assert console.post(
            "/api/satellite/renew", headers={**via_site, **lan}, json={"join_request": _join_request()},
        ).status_code == 403
    # Unknown, malformed or duplicated site headers are refused outright.
    for headers in (
        {SITE_CERT_HEADER: "b" * 64},
        {SITE_CERT_HEADER: "not-a-digest"},
    ):
        assert console.get("/api/whoami", headers=headers).status_code == 403
        assert console.post("/mcp", headers=headers, json={}).status_code == 403
    duplicated = console.get(
        "/api/whoami", headers=[(SITE_CERT_HEADER, fingerprint), (SITE_CERT_HEADER, fingerprint)],
    )
    assert duplicated.status_code == 403

    site_id = console.app.state.satellite_service.list_sites()[0]["id"]
    console.app.state.satellite_service.revoke_site(site_id, reason="lost", actor_id="o")
    assert console.get("/api/whoami", headers=via_site).status_code == 403


def test_open_streams_from_a_revoked_site_end_at_their_next_check() -> None:
    import asyncio
    from types import SimpleNamespace

    from strugglebus.routes.streams import _agent_revalidator

    admitted = {"value": True}
    checked: list[str] = []

    def admits(fingerprint: str) -> bool:
        checked.append(fingerprint)
        return admitted["value"]

    state = SimpleNamespace(
        access_freeze_service=SimpleNamespace(status=lambda: SimpleNamespace(frozen=False)),
        agent_service=SimpleNamespace(store=SimpleNamespace(credential_is_active=lambda a, c: True)),
        roe_service=SimpleNamespace(require_current_receipt=lambda a, c: None),
        satellite_service=SimpleNamespace(admits=admits),
    )
    identity = SimpleNamespace(agent=SimpleNamespace(id="a"), credential=SimpleNamespace(id="c"))

    def revalidator(headers: dict[str, str]):
        request = SimpleNamespace(headers=headers, app=SimpleNamespace(state=state))
        return _agent_revalidator(request, identity)

    via_site = revalidator({SITE_CERT_HEADER: "c" * 64})
    assert asyncio.run(via_site()) is None
    admitted["value"] = False
    assert "satellite_site_revoked" in asyncio.run(via_site())
    # A LAN stream carries no site header and is never checked against sites.
    checked.clear()
    assert asyncio.run(revalidator({})()) is None
    assert checked == []


def test_each_site_has_its_own_unauthenticated_budget(satellite_config: AppConfig) -> None:
    # Every site arrives from the gateway's one tunnel address, so one site
    # exhausting the budget must not lock out the others.
    with operator_client(_application(satellite_config)) as console:
        console.headers.update(FROM_GATEWAY)
        first = {SITE_CERT_HEADER: _fingerprint(_bundle(_add(console, "devbox-one").text))}
        second = {SITE_CERT_HEADER: _fingerprint(_bundle(_add(console, "devbox-two").text))}
        state = console.app.state
        state.config = replace(state.config, unauthenticated_requests_per_minute=2)
        codes = [
            console.post("/api/enrollments/redeem", headers=first, json={}).status_code
            for _ in range(3)
        ]
        assert codes[-1] == 429, codes
        assert console.post("/api/enrollments/redeem", headers=second, json={}).status_code != 429
