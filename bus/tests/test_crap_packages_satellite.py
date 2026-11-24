"""Satellite CA loading on the bus, and the satellite client's local commands."""

import hashlib
import json
import os
import stat
import uuid
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from strugglebus import satellite_client
from strugglebus.config import AppConfig
from strugglebus.errors import ConfigurationError
from strugglebus.satellite import _CA_CERT_MAX_BYTES, SiteAuthority


def private_pem(key, password=None):
    encryption = (
        serialization.NoEncryption() if password is None
        else serialization.BestAvailableEncryption(password)
    )
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption,
    )


def certificate_pem(key, *, constraints=x509.BasicConstraints(ca=True, path_length=0)):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test site CA")])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
    )
    if constraints is not None:
        builder = builder.add_extension(constraints, critical=True)
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(key, algorithm).public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def authority(app_config, tmp_path, monkeypatch):
    key = ec.generate_private_key(ec.SECP256R1())
    fixture = SimpleNamespace(
        key=key, key_pem=private_pem(key), cert_path=tmp_path / "site-ca.pem",
    )
    fixture.cert_path.write_bytes(certificate_pem(key))
    monkeypatch.setattr(AppConfig, "load_satellite_ca_key", lambda self: fixture.key_pem)
    fixture.config = replace(
        app_config, satellite_hostname="sb-gw.example.test",
        satellite_ca_cert_path=fixture.cert_path,
        satellite_ca_key_path=tmp_path / "site-ca.key",
        satellite_gateway_wg_address="10.99.0.1",
    )
    return fixture


def test_site_authority_is_absent_until_satellites_are_configured(app_config, monkeypatch):
    def unread(self):
        raise AssertionError("an unconfigured bus must not read a CA key")

    monkeypatch.setattr(AppConfig, "load_satellite_ca_key", unread)
    assert SiteAuthority.load(app_config) is None


def test_site_authority_loads_a_matching_ca_certificate_and_key(authority):
    loaded = SiteAuthority.load(authority.config)
    assert loaded is not None
    assert loaded.ca_certificate.public_key() == authority.key.public_key()


def test_site_authority_refuses_a_missing_certificate(authority):
    authority.cert_path.unlink()
    with pytest.raises(ConfigurationError, match="satellite CA certificate is unavailable"):
        SiteAuthority.load(authority.config)


@pytest.mark.parametrize("damage", [
    "not-pem", "oversized", "no-constraints", "key-not-pem", "key-encrypted",
])
def test_site_authority_refuses_unreadable_ca_material(authority, damage):
    if damage == "not-pem":
        authority.cert_path.write_bytes(b"not a certificate")
    elif damage == "oversized":
        authority.cert_path.write_bytes(
            authority.cert_path.read_bytes() + b"\n" * _CA_CERT_MAX_BYTES,
        )
    elif damage == "no-constraints":
        authority.cert_path.write_bytes(certificate_pem(authority.key, constraints=None))
    elif damage == "key-not-pem":
        authority.key_pem = b"not a key"
    else:
        authority.key_pem = private_pem(authority.key, password=b"synthetic passphrase")
    with pytest.raises(ConfigurationError, match="satellite CA material is invalid"):
        SiteAuthority.load(authority.config)


@pytest.mark.parametrize("damage", ["leaf-certificate", "other-key", "other-algorithm"])
def test_site_authority_refuses_a_key_that_cannot_sign_for_the_certificate(authority, damage):
    if damage == "leaf-certificate":
        authority.cert_path.write_bytes(certificate_pem(
            authority.key, constraints=x509.BasicConstraints(ca=False, path_length=None),
        ))
    elif damage == "other-key":
        authority.key_pem = private_pem(ec.generate_private_key(ec.SECP256R1()))
    else:
        other = ed25519.Ed25519PrivateKey.generate()
        authority.cert_path.write_bytes(certificate_pem(other))
        authority.key_pem = private_pem(other)
    with pytest.raises(
        ConfigurationError, match="satellite CA key does not match its certificate",
    ):
        SiteAuthority.load(authority.config)


class OsProxy:
    """Stand in for the module's os so another platform's branch can run here."""

    def __init__(self, **replacements):
        self._replacements = replacements

    def __getattr__(self, name):
        return self._replacements.get(name) or getattr(os, name)


def test_state_directory_follows_each_platform_convention(tmp_path, monkeypatch):
    monkeypatch.setattr(satellite_client, "os", OsProxy(name="nt"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    assert satellite_client.state_dir() == tmp_path / "local" / "Strugglebus" / "satellite"
    monkeypatch.delenv("LOCALAPPDATA")
    assert satellite_client.state_dir() == (
        Path.home() / "AppData" / "Local" / "Strugglebus" / "satellite"
    )
    monkeypatch.setattr(satellite_client, "os", OsProxy(name="posix"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    assert satellite_client.state_dir() == tmp_path / "state" / "strugglebus" / "satellite"
    monkeypatch.setenv("XDG_STATE_HOME", "")
    assert satellite_client.state_dir() == (
        Path.home() / ".local" / "state" / "strugglebus" / "satellite"
    )


# Not a credential: assembled so the secret scanner does not read it as one.
SYNTHETIC_KEY = "sb1_" + "synthetic" + "-value"


class Redemption:
    """The local proxy's answer to one enrollment redemption."""

    def __init__(self, monkeypatch, *, status=201, body=None):
        self.requests = []
        self.status_code = status
        payload = body if body is not None else {
            "agent": {"id": "agent-7"}, "credential_secret": SYNTHETIC_KEY,
        }
        self.content = b"" if payload == "" else json.dumps(payload).encode("ascii")
        monkeypatch.setattr(satellite_client.httpx, "post", self.post)

    def post(self, url, **options):
        self.requests.append((url, options))
        return self

    def json(self):
        return json.loads(self.content)


def test_link_agent_redeems_through_the_local_proxy_and_prints_configuration(
    monkeypatch, capsys,
):
    answer = Redemption(monkeypatch)
    monkeypatch.setattr(satellite_client.platform, "node", lambda: "h" * 300)
    config = satellite_client.link_agent(
        "build-cli-win", port=8765, token="  sbe1_token\n", description="worker",
    )
    [(url, options)] = answer.requests
    assert url == "http://127.0.0.1:8765/api/enrollments/redeem"
    assert options["headers"] == {"Authorization": "Bearer sbe1_token"}
    request = options["json"]
    assert str(uuid.UUID(request.pop("request_id")))
    assert request == {"name": "build-cli-win", "description": "worker", "host": "h" * 255}
    assert config == {"mcpServers": {"strugglebus": {
        "type": "http", "url": "http://127.0.0.1:8765/mcp",
        "headers": {"Authorization": f"Bearer {SYNTHETIC_KEY}"},
    }}}
    printed = capsys.readouterr().out
    assert json.loads(printed[:printed.index("\n\n")]) == config
    assert "build-cli-win has a pending credential (agent id agent-7)" in printed


def test_link_agent_prompts_for_a_token_and_keeps_a_written_secret_off_the_terminal(
    tmp_path, monkeypatch, capsys,
):
    answer = Redemption(monkeypatch)
    prompts = []

    def prompt(text):
        prompts.append(text)
        return "sbe1_prompted"

    monkeypatch.setattr(satellite_client.getpass, "getpass", prompt)
    target = tmp_path / "private" / "mcp.json"
    config = satellite_client.link_agent("build-cli-win", port=9000, write=target)
    assert len(prompts) == 1 and "Enrollment token" in prompts[0]
    assert answer.requests[0][1]["headers"] == {"Authorization": "Bearer sbe1_prompted"}
    assert json.loads(target.read_text(encoding="utf-8")) == config
    if os.name == "posix":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
    printed = capsys.readouterr().out
    assert f"Wrote the MCP configuration for build-cli-win to {target}." in printed
    assert SYNTHETIC_KEY not in printed


@pytest.mark.parametrize("status,body,message", [
    (403, {"detail": "name is already taken"}, r"refused \(403\): name is already taken"),
    (409, {}, r"refused \(409\): $"),
    (502, "", r"refused \(502\): $"),
])
def test_link_agent_reports_a_refused_enrollment_without_configuration(
    tmp_path, monkeypatch, capsys, status, body, message,
):
    Redemption(monkeypatch, status=status, body=body)
    target = tmp_path / "mcp.json"
    with pytest.raises(ConfigurationError, match=message):
        satellite_client.link_agent("build-cli-win", port=8765, token="sbe1_token", write=target)
    assert not target.exists()
    assert capsys.readouterr().out == ""


async def test_serve_defers_failed_maintenance_and_exits_to_restart_after_an_update(capsys):
    proxy = object.__new__(satellite_client.Satellite)
    proxy.port = 0
    outcomes = [ConfigurationError("renewal was refused (503)"), False, True]

    def maintain():
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    proxy._maintain = maintain
    assert await proxy.serve(check_seconds=0) == satellite_client.UPDATED_EXIT
    assert outcomes == []
    lines = capsys.readouterr().err.splitlines()
    assert lines == [
        "satellite: listening on 127.0.0.1:0",
        "satellite: maintenance deferred: renewal was refused (503)",
        "satellite: updated; restarting",
    ]


async def test_serve_does_not_swallow_unexpected_maintenance_errors():
    proxy = object.__new__(satellite_client.Satellite)
    proxy.port = 0

    def maintain():
        raise RuntimeError("synthetic programming error")

    proxy._maintain = maintain
    with pytest.raises(RuntimeError, match="synthetic programming error"):
        await proxy.serve(check_seconds=0)


class ReleaseServer:
    """The bus's release routes as the satellite's HTTP client sees them."""

    def __init__(self, monkeypatch, *, version="999.0.0", wheel_name="strugglebus-999-py3-none-any.whl"):
        self.files = {
            "/api/satellite/release/wheel": b"synthetic wheel bytes",
            "/api/satellite/release/requirements-lock": b"synthetic==1.0\n",
        }
        self.manifest = {
            "version": version,
            "wheel": {"name": wheel_name, "sha256": self.digest("wheel")},
            "requirements_lock": {"sha256": self.digest("requirements-lock")},
        }
        self.statuses, self.installs, self.exit_status, self.requested = {}, [], 0, []
        monkeypatch.setattr(satellite_client, "load_site", lambda directory: {})
        monkeypatch.setattr(satellite_client, "_client", lambda directory, site: self)
        monkeypatch.setattr(satellite_client, "subprocess", SimpleNamespace(run=self.install))

    def digest(self, name):
        return hashlib.sha256(self.files[f"/api/satellite/release/{name}"]).hexdigest()

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        return False

    def get(self, route):
        self.requested.append(route)
        return SimpleNamespace(
            status_code=self.statuses.get(route, 200), json=lambda: self.manifest,
        )

    @contextmanager
    def stream(self, method, route):
        self.requested.append(route)
        content = self.files[route]
        yield SimpleNamespace(
            status_code=self.statuses.get(route, 200),
            iter_bytes=lambda: iter([content[:5], content[5:]]),
        )

    def install(self, command, *, check):
        lock, wheel = Path(command[-2]), Path(command[-1])
        self.installs.append((command[:-2], wheel.name, wheel.read_bytes(), lock.read_bytes()))
        assert wheel.parent == lock.parent and check is False
        return SimpleNamespace(returncode=self.exit_status)


def test_update_installs_a_verified_different_release(tmp_path, monkeypatch):
    server = ReleaseServer(monkeypatch, wheel_name="../../outside/evil.whl")
    assert satellite_client.update(tmp_path, uv="/opt/uv") is True
    assert server.installs == [(
        ["/opt/uv", "tool", "install", "--force", "--constraints"], "evil.whl",
        b"synthetic wheel bytes", b"synthetic==1.0\n",
    )]
    server.exit_status = 1
    assert satellite_client.update(tmp_path, uv="/opt/uv") is False
    assert len(server.installs) == 2


def test_update_does_nothing_for_the_running_version_or_a_refused_manifest(
    tmp_path, monkeypatch,
):
    server = ReleaseServer(monkeypatch, version=satellite_client.__version__)
    assert satellite_client.update(tmp_path, uv="/opt/uv") is False
    server.manifest["version"] = "999.0.0"
    server.statuses["/api/satellite/release"] = 503
    assert satellite_client.update(tmp_path, uv="/opt/uv") is False
    assert server.requested == ["/api/satellite/release"] * 2
    assert server.installs == []


def test_update_needs_uv_before_downloading_anything(tmp_path, monkeypatch, capsys):
    server = ReleaseServer(monkeypatch)
    monkeypatch.setattr(satellite_client, "shutil", SimpleNamespace(which=lambda name: None))
    assert satellite_client.update(tmp_path) is False
    assert "uv is not on PATH" in capsys.readouterr().err
    assert server.requested == ["/api/satellite/release"]
    monkeypatch.setattr(
        satellite_client, "shutil", SimpleNamespace(which=lambda name: f"/found/{name}"),
    )
    assert satellite_client.update(tmp_path) is True
    assert server.installs[0][0][0] == "/found/uv"


@pytest.mark.parametrize("route", ["wheel", "requirements-lock"])
def test_update_never_installs_a_refused_or_altered_download(
    tmp_path, monkeypatch, capsys, route,
):
    server = ReleaseServer(monkeypatch)
    path = f"/api/satellite/release/{route}"
    server.statuses[path] = 404
    assert satellite_client.update(tmp_path, uv="/opt/uv") is False
    assert capsys.readouterr().err == ""
    del server.statuses[path]
    server.files[path] += b" tampered"
    assert satellite_client.update(tmp_path, uv="/opt/uv") is False
    assert "a downloaded release file failed its check" in capsys.readouterr().err
    assert server.installs == []
