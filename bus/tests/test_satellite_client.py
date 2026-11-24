"""Satellite renewal and release routes, and the satellite client itself."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from strugglebus import satellite_client
from strugglebus.errors import ConfigurationError
from strugglebus.satellite import BUNDLE_PREFIX, SITE_CERT_HEADER, SiteAuthority, parse_join_request
from test_satellite_sites import (  # noqa: F401
    _add,
    _bundle,
    _fingerprint,
    _join_request,
    console,
    satellite_config,
)


def _site_client(console: TestClient, fingerprint: str) -> TestClient:
    console.headers[SITE_CERT_HEADER] = fingerprint
    return console


def _admitted(console: TestClient) -> tuple[str, dict]:
    bundle = _bundle(_add(console).text)
    return _fingerprint(bundle), bundle


def test_renewal_swaps_the_admitted_certificate(console: TestClient) -> None:
    old, _ = _admitted(console)
    response = console.post(
        "/api/satellite/renew", json={"join_request": _join_request()},
        headers={SITE_CERT_HEADER: old},
    )
    assert response.status_code == 200, response.text
    encoded = response.json()["bundle"][len(BUNDLE_PREFIX):]
    renewed = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert renewed["site"] == "devbox-one"
    service = console.app.state.satellite_service
    assert service.admits(_fingerprint(renewed))
    assert not service.admits(old)


def test_satellite_routes_refuse_the_lan_path(console: TestClient) -> None:
    for method, path in (
        ("POST", "/api/satellite/renew"),
        ("GET", "/api/satellite/release"),
        ("GET", "/api/satellite/release/wheel"),
    ):
        response = console.request(method, path, json={"join_request": _join_request()})
        assert response.status_code == 403
        assert response.json()["detail"] == "satellite path required"


def test_renewal_refuses_revoked_frozen_and_malformed(console: TestClient) -> None:
    fingerprint, _ = _admitted(console)
    via_site = {SITE_CERT_HEADER: fingerprint}
    malformed = console.post(
        "/api/satellite/renew", json={"join_request": "sb-join-1.nope"}, headers=via_site,
    )
    assert malformed.status_code == 422

    console.app.state.access_freeze_service.freeze("incident drill")
    try:
        frozen = console.post(
            "/api/satellite/renew", json={"join_request": _join_request()}, headers=via_site,
        )
    finally:
        console.app.state.access_freeze_service.unfreeze("drill complete")
    assert frozen.status_code == 503
    assert console.app.state.satellite_service.admits(fingerprint)

    site = console.app.state.satellite_service.list_sites()[0]
    console.app.state.satellite_service.revoke_site(site["id"], reason="lost", actor_id="o")
    revoked = console.post(
        "/api/satellite/renew", json={"join_request": _join_request()}, headers=via_site,
    )
    assert revoked.status_code == 403


@pytest.fixture
def release_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "release"
    directory.mkdir()
    (directory / "strugglebus-9.9.9-py3-none-any.whl").write_bytes(b"synthetic wheel")
    (directory / "requirements.lock").write_bytes(b"synthetic==1\n")
    for target in ("strugglebus.satellite", "strugglebus.routes.satellite"):
        monkeypatch.setattr(f"{target}.release_directory", lambda: directory)
    return directory


def test_release_manifest_and_downloads(console: TestClient, release_dir: Path) -> None:
    fingerprint, _ = _admitted(console)
    via_site = {SITE_CERT_HEADER: fingerprint}
    manifest = console.get("/api/satellite/release", headers=via_site)
    assert manifest.status_code == 200
    body = manifest.json()
    assert body["wheel"]["sha256"] == hashlib.sha256(b"synthetic wheel").hexdigest()
    wheel = console.get("/api/satellite/release/wheel", headers=via_site)
    assert wheel.content == b"synthetic wheel"
    lock = console.get("/api/satellite/release/requirements-lock", headers=via_site)
    assert lock.content == b"synthetic==1\n"

    (release_dir / "requirements.lock").unlink()
    assert console.get("/api/satellite/release", headers=via_site).status_code == 503


def test_join_accepts_only_a_bundle_for_its_own_key(tmp_path: Path, satellite_config) -> None:
    authority = SiteAuthority.load(satellite_config)
    _, join_request = satellite_client._new_key(tmp_path)
    issued = authority.issue("devbox-one", parse_join_request(join_request))

    foreign = authority.issue("devbox-one", parse_join_request(_join_request()))
    with pytest.raises(ConfigurationError, match="different join request"):
        satellite_client.accept_bundle(tmp_path, foreign.bundle)

    bundle = satellite_client.accept_bundle(tmp_path, issued.bundle)
    assert bundle["site"] == "devbox-one"
    assert not (tmp_path / "key.pending.pem").exists()
    assert satellite_client.load_site(tmp_path)["hostname"] == satellite_config.satellite_hostname
    satellite_client.tls_context(tmp_path)


def _joined(console: TestClient, directory: Path) -> str:
    _, join_request = satellite_client._new_key(directory)
    response = _add(console, join_request=join_request)
    assert response.status_code == 201
    start = response.text.index("<pre>") + len("<pre>")
    import html

    satellite_client.accept_bundle(
        directory, html.unescape(response.text[start: response.text.index("</pre>", start)]),
    )
    return _fingerprint(satellite_client.load_site(directory))


def test_renew_and_update_through_the_bus(
    console: TestClient, tmp_path: Path, release_dir: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "state"
    first = _joined(console, directory)

    def client(directory: Path, site: dict) -> contextlib.AbstractContextManager:
        console.headers[SITE_CERT_HEADER] = _fingerprint(site)
        return contextlib.nullcontext(console)

    monkeypatch.setattr(satellite_client, "_client", client)
    satellite_client.renew(directory)
    second = _fingerprint(satellite_client.load_site(directory))
    assert second != first
    assert console.app.state.satellite_service.admits(second)
    assert not console.app.state.satellite_service.admits(first)

    calls: list[list[str]] = []

    class Done:
        returncode = 0

    monkeypatch.setattr(
        satellite_client.subprocess, "run", lambda argv, **kw: calls.append(argv) or Done(),
    )
    assert not satellite_client.update(directory, uv="uv")
    monkeypatch.setattr(satellite_client, "__version__", "0.0.0")
    assert satellite_client.update(directory, uv="uv")
    assert calls[0][:5] == ["uv", "tool", "install", "--force", "--constraints"]
    assert calls[0][-1].endswith("strugglebus-9.9.9-py3-none-any.whl")

    (release_dir / "requirements.lock").write_bytes(b"tampered\n")
    original = satellite_client.update.__globals__["_sha256"]
    monkeypatch.setitem(
        satellite_client.update.__globals__, "_sha256",
        lambda path: "0" * 64 if path.name == "requirements.lock" else original(path),
    )
    assert not satellite_client.update(directory, uv="uv")


def _certificate(key, subject: str, issuer, signer, *, ca: bool, san: str | None = None):
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(issuer).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        # Python's default client context verifies strictly, so these carry the
        # key identifiers and usages a real CA would.
        .add_extension(
            x509.KeyUsage(
                digital_signature=not ca, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=ca,
                crl_sign=ca, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()),
            critical=False,
        )
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False,
        )
    return builder.sign(signer, hashes.SHA256())


def _pem(value) -> bytes:
    if isinstance(value, x509.Certificate):
        return value.public_bytes(serialization.Encoding.PEM)
    return value.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def test_proxy_pipes_bytes_over_mutual_tls(tmp_path: Path) -> None:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test site CA")])
    ca = _certificate(ca_key, "test site CA", ca_name, ca_key, ca=True)
    server_key = ec.generate_private_key(ec.SECP256R1())
    server = _certificate(server_key, "localhost", ca_name, ca_key, ca=False, san="localhost")
    site_key = ec.generate_private_key(ec.SECP256R1())
    site = _certificate(site_key, "devbox-one", ca_name, ca_key, ca=False)
    other_ca_key = ec.generate_private_key(ec.SECP256R1())
    other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other CA")])
    other_ca = _certificate(other_ca_key, "other CA", other_name, other_ca_key, ca=True)

    for name, value in (("server.pem", server), ("server.key", server_key)):
        (tmp_path / name).write_bytes(_pem(value))
    server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cadata=_pem(ca).decode())
    server_context.load_cert_chain(tmp_path / "server.pem", tmp_path / "server.key")
    server_context.verify_mode = ssl.CERT_REQUIRED

    async def gateway(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("ssl_object").getpeercert()
        subject = dict(item[0] for item in peer["subject"])["commonName"]
        writer.write(f"{subject}:".encode() + await reader.read(100))
        await writer.drain()
        writer.close()

    def state(directory: Path, port: int, trusted) -> None:
        directory.mkdir()
        (directory / "key.pem").write_bytes(_pem(site_key))
        (directory / "cert.pem").write_bytes(_pem(site))
        (directory / "ca.pem").write_bytes(_pem(trusted))
        (directory / "bundle.json").write_text(json.dumps({
            "site": "devbox-one", "hostname": "localhost", "port": port,
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        }))

    async def exchange(directory: Path) -> bytes:
        proxy = satellite_client.Satellite(directory, 0)
        local = await asyncio.start_server(proxy._connection, "127.0.0.1", 0)
        port = local.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET /mcp")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), timeout=10)
        writer.close()
        local.close()
        return data

    async def scenario() -> tuple[bytes, bytes]:
        remote = await asyncio.start_server(gateway, "127.0.0.1", 0, ssl=server_context)
        port = remote.sockets[0].getsockname()[1]
        state(tmp_path / "good", port, ca)
        state(tmp_path / "wrong-ca", port, other_ca)
        async with remote:
            return await exchange(tmp_path / "good"), await exchange(tmp_path / "wrong-ca")

    trusted, untrusted = asyncio.run(scenario())
    assert trusted == b"devbox-one:GET /mcp"
    # A gateway whose certificate is not from the bundle's CA gets nothing.
    assert untrusted == b""


def test_install_task_prints_a_user_unit_off_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture,
) -> None:
    monkeypatch.setattr(satellite_client.os, "name", "posix")
    monkeypatch.setattr(satellite_client.shutil, "which", lambda name: "/home/u/.local/bin/strugglebus")
    unit = satellite_client.install_task(tmp_path, 8765)
    assert "ExecStart=/home/u/.local/bin/strugglebus satellite run --port 8765" in unit
    assert "Restart=always" in unit
