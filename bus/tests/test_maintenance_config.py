from __future__ import annotations

import base64
from dataclasses import fields
from datetime import UTC, datetime, timedelta
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys

import pytest

from strugglebus.config import AppConfig
from strugglebus.ca import load_trust_anchor
from strugglebus.migrations import LATEST_SCHEMA_VERSION


REPOSITORY = Path(__file__).resolve().parents[1]
HELPER = (
    REPOSITORY / "deploy" / "roles" / "guest_base" / "files"
    / "strugglebus-validate-maintenance-config.py"
)
SPEC = importlib.util.spec_from_file_location("maintenance_config", HELPER)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
MaintenanceConfigError = MODULE.MaintenanceConfigError

UNIT = """[Unit]
Description=Strugglebus LAN message board
After=network-online.target
Wants=network-online.target
ConditionPathIsDirectory=/opt/strugglebus/current

[Service]
Type=simple
User=strugglebus
Group=strugglebus
WorkingDirectory=/opt/strugglebus/current
RuntimeDirectory=strugglebus
RuntimeDirectoryMode=0750
LoadCredential=admin-token:/etc/strugglebus/credentials/admin-token
Environment=STRUGGLEBUS_ADMIN_CREDENTIAL_PATH=%d/admin-token
EnvironmentFile=-/opt/strugglebus/current/release.env
Environment=STRUGGLEBUS_DATA_DIR=/var/lib/strugglebus
Environment=STRUGGLEBUS_RUNTIME_DIR=/run/strugglebus
Environment=STRUGGLEBUS_BACKUP_DIR=/var/lib/strugglebus/backups
Environment=STRUGGLEBUS_DATABASE_PATH=/var/lib/strugglebus/strugglebus.db
Environment=STRUGGLEBUS_PUBLIC_BASE_URL=https://bus.lan
Environment=STRUGGLEBUS_BIND_HOST=127.0.0.1
Environment=STRUGGLEBUS_BIND_PORT=8080
Environment=STRUGGLEBUS_ALLOWED_HOSTS=bus.lan,bus.lan:*,127.0.0.1:*,localhost:*,[::1]:*
Environment=STRUGGLEBUS_ALLOWED_ORIGINS=https://bus.lan
Environment=STRUGGLEBUS_MAX_MESSAGE_BYTES=1048576
Environment=STRUGGLEBUS_MAX_REQUEST_BODY_BYTES=1048576
Environment=STRUGGLEBUS_MAX_METADATA_BYTES=16384
Environment=STRUGGLEBUS_MAX_REST_REQUEST_BODY_BYTES=6308864
Environment=STRUGGLEBUS_AUTHENTICATED_REQUESTS_PER_MINUTE=600
Environment=STRUGGLEBUS_UNAUTHENTICATED_REQUESTS_PER_MINUTE=60
Environment=STRUGGLEBUS_SQLITE_BUSY_TIMEOUT_MS=5000
Environment=STRUGGLEBUS_MAX_CHANNELS=1000
Environment=STRUGGLEBUS_SSE_BATCH_SIZE=100
Environment=STRUGGLEBUS_SSE_POLL_INTERVAL_MS=250
Environment=STRUGGLEBUS_SSE_HEARTBEAT_SECONDS=15
Environment=STRUGGLEBUS_SSE_CONNECTION_SECONDS=300
Environment=STRUGGLEBUS_SSE_MAX_CONNECTIONS_PER_AGENT=3
Environment=STRUGGLEBUS_HUMAN_ACTIVITY_LIMIT=100
Environment=STRUGGLEBUS_TRUSTED_PROXY_SOURCES=127.0.0.1,::1
Environment=STRUGGLEBUS_ROE_ENFORCEMENT_MODE=observe
Environment=STRUGGLEBUS_MAX_ACTIVE_CREDENTIALS_PER_AGENT=2
Environment=STRUGGLEBUS_MAX_PENDING_CREDENTIALS_PER_AGENT=1
Environment=STRUGGLEBUS_CREDENTIAL_PENDING_SECONDS=900
Environment=STRUGGLEBUS_SELF_ROTATIONS_PER_WINDOW=2
Environment=STRUGGLEBUS_SELF_ROTATION_WINDOW_SECONDS=86400
Environment=STRUGGLEBUS_ENROLLMENT_TTL_SECONDS=900
Environment=STRUGGLEBUS_MAX_ENROLLMENT_USES=1
Environment=STRUGGLEBUS_CA_BUNDLE_PATH=
Environment=STRUGGLEBUS_CA_ROOT_SHA256=
ExecStart=/opt/strugglebus/current/venv/bin/strugglebus serve
Restart=always
RestartSec=5s
TimeoutStartSec=60s
TimeoutStopSec=30s
UMask=0027
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
ProcSubset=pid
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RemoveIPC=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
ReadWritePaths=/var/lib/strugglebus /run/strugglebus /var/lib/strugglebus/backups

[Install]
WantedBy=multi-user.target
"""


@pytest.fixture
def environment(tmp_path: Path) -> dict[str, str]:
    values = MODULE.parse_environment(UNIT)
    values.update({
        "STRUGGLEBUS_DATA_DIR": str(tmp_path / "data"),
        "STRUGGLEBUS_RUNTIME_DIR": str(tmp_path / "run"),
        "STRUGGLEBUS_BACKUP_DIR": str(tmp_path / "backups"),
        "STRUGGLEBUS_DATABASE_PATH": str(tmp_path / "database.db"),
        "STRUGGLEBUS_ADMIN_CREDENTIAL_PATH": str(tmp_path / "unread-admin-token"),
        "STRUGGLEBUS_RELEASE_ID": "candidate-0.2.12",
    })
    return values


def probe(environment: dict[str, str]) -> dict[str, object]:
    return MODULE.candidate_config_probe(Path(sys.executable), environment)


def _pem(der: bytes) -> bytes:
    return (
        b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(der)
        + b"\n-----END CERTIFICATE-----\n"
    )


@pytest.fixture(scope="module")
def ca_certificates(tmp_path_factory) -> dict[str, bytes]:
    executable = shutil.which("openssl")
    if executable is None:
        pytest.skip("openssl is required for real certificate tests")
    directory = tmp_path_factory.mktemp("maintenance-ca")

    def openssl(*arguments: str) -> None:
        subprocess.run(
            [executable, *arguments], cwd=directory, check=True,
            capture_output=True, timeout=30,
        )

    (directory / "index.txt").write_text("", encoding="ascii")
    (directory / "serial").write_text("1000\n", encoding="ascii")
    (directory / "ca.cnf").write_text(
        "[ca]\ndefault_ca=test_ca\n"
        "[test_ca]\ndatabase=index.txt\nserial=serial\nnew_certs_dir=.\n"
        "default_md=sha256\npolicy=common_name\nunique_subject=no\n"
        "[common_name]\ncommonName=supplied\n"
        "[ca_extensions]\nbasicConstraints=critical,CA:TRUE\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        "[leaf_extensions]\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n",
        encoding="ascii",
    )
    openssl(
        "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-keyout", "root.key", "-out", "root.csr",
        "-subj", "/CN=Maintenance Test CA",
    )
    openssl(
        "req", "-x509", "-key", "root.key", "-in", "root.csr",
        "-out", "bootstrap.crt", "-days", "2",
        "-addext", "basicConstraints=critical,CA:TRUE",
    )
    now = datetime.now(UTC)
    certificates = {}
    for name, start_days, end_days in (
        ("root", -1, 2), ("other", -1, 2), ("leaf", -1, 2),
        ("expired", -3, -2), ("future", 2, 3),
    ):
        openssl(
            "ca", "-batch", "-notext", "-selfsign", "-config", "ca.cnf",
            "-cert", "bootstrap.crt", "-keyfile", "root.key",
            "-in", "root.csr", "-out", f"{name}.crt",
            "-startdate", (now + timedelta(days=start_days)).strftime("%y%m%d%H%M%SZ"),
            "-enddate", (now + timedelta(days=end_days)).strftime("%y%m%d%H%M%SZ"),
            "-extensions", "leaf_extensions" if name == "leaf" else "ca_extensions",
        )
        certificates[name] = ssl.PEM_cert_to_DER_cert(
            (directory / f"{name}.crt").read_text(encoding="ascii")
        )
    for name, days in (("bad-before", -1), ("bad-after", 2)):
        date = (now + timedelta(days=days)).strftime("%y%m%d%H%M%SZ").encode("ascii")
        assert certificates["root"].count(date) == 1
        # Equal-length invalid month leaves the DER structure and pinned digest
        # testable while exercising the loader's date decoding failure.
        certificates[name] = certificates["root"].replace(date, date[:2] + b"99" + date[4:])
    return certificates


@pytest.fixture
def ca_environment(environment: dict[str, str], tmp_path: Path, ca_certificates) -> dict[str, str]:
    der = ca_certificates["root"]
    bundle = tmp_path / "roots.pem"
    bundle.write_bytes(_pem(ca_certificates["other"]) + _pem(der))
    return {
        **environment,
        "STRUGGLEBUS_CA_BUNDLE_PATH": str(bundle),
        "STRUGGLEBUS_CA_ROOT_SHA256": hashlib.sha256(der).hexdigest(),
    }


def test_realistic_unit_parses_without_reading_references(monkeypatch) -> None:
    def forbidden(*args, **kwargs):
        pytest.fail("parsing must not read credentials, release.env or database")

    monkeypatch.setattr(Path, "open", forbidden)
    values = MODULE.parse_environment(UNIT)
    assert values["STRUGGLEBUS_ADMIN_CREDENTIAL_PATH"] == MODULE.PROJECTED_CREDENTIAL
    assert values["STRUGGLEBUS_MAX_ACTIVE_CREDENTIALS_PER_AGENT"] == "2"
    assert values["STRUGGLEBUS_CA_BUNDLE_PATH"] == ""
    assert values["STRUGGLEBUS_CA_ROOT_SHA256"] == ""
    assert "STRUGGLEBUS_RELEASE_ID" not in values


def test_legacy_uvicorn_unit_can_only_transition_to_shutdown_aware_entry_point() -> None:
    legacy = UNIT.replace(
        "ExecStart=/opt/strugglebus/current/venv/bin/strugglebus serve",
        "ExecStart=/opt/strugglebus/current/venv/bin/uvicorn strugglebus.app:app "
        "--host 127.0.0.1 --port 8080 --no-access-log --no-proxy-headers "
        "--no-server-header",
    )

    assert MODULE.validate_unit_scope(legacy, UNIT)["STRUGGLEBUS_BIND_HOST"] == "127.0.0.1"
    with pytest.raises(MaintenanceConfigError, match="unsupported service command"):
        MODULE.parse_environment(legacy)
    with pytest.raises(MaintenanceConfigError, match="unsupported service command"):
        MODULE.validate_unit_scope(UNIT, legacy)


def operator_unit(unit: str = UNIT) -> str:
    return unit.replace(
        "Environment=STRUGGLEBUS_ADMIN_CREDENTIAL_PATH=%d/admin-token",
        "Environment=STRUGGLEBUS_ADMIN_CREDENTIAL_PATH=%d/admin-token\n"
        "LoadCredential=operator-password:/etc/strugglebus/credentials/operator-password\n"
        "Environment=STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH=%d/operator-password",
    )


def test_operator_projection_has_exact_named_sources_and_narrow_transition():
    candidate = operator_unit()
    assert MODULE.credential_sources(candidate) == {
        "admin-token": "/etc/strugglebus/credentials/admin-token",
        "operator-password": "/etc/strugglebus/credentials/operator-password",
    }
    environment = MODULE.validate_unit_scope(UNIT, candidate)
    assert environment["STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH"] == MODULE.PROJECTED_OPERATOR_CREDENTIAL
    assert MODULE.validate_unit_scope(candidate, candidate) == environment
    for changed in (
        UNIT,
        candidate.replace(
            "operator-password:/etc/strugglebus/credentials/operator-password",
            "operator-password:/etc/other/operator-password",
        ),
    ):
        with pytest.raises(MaintenanceConfigError, match="protected topology"):
            MODULE.validate_unit_scope(candidate, changed)


@pytest.mark.parametrize("replace_old,replace_new", [
    ("operator-password:/etc/strugglebus/credentials/operator-password",
     "operator-password:/etc/strugglebus/credentials/admin-token"),
    ("operator-password:/etc/strugglebus/credentials/operator-password",
     "operator-password:/run/credentials/strugglebus.service/operator-password"),
    ("%d/operator-password", "%d/other"),
    ("LoadCredential=operator-password:", "LoadCredential=unreviewed:"),
    ("Environment=STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH=%d/operator-password",
     "Environment=STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH=%d/operator-password\n"
     "LoadCredential=operator-password:/etc/other/operator-password"),
    ("Environment=STRUGGLEBUS_CA_BUNDLE_PATH=",
     "Environment=STRUGGLEBUS_CA_BUNDLE_PATH=/etc/strugglebus/credentials/operator-password"),
])
def test_operator_projection_aliases_duplicates_and_unknown_names_fail(
    replace_old, replace_new,
):
    with pytest.raises(MaintenanceConfigError):
        MODULE.parse_environment(operator_unit().replace(replace_old, replace_new))


def test_operator_projection_probe_does_not_load_the_verifier(environment, tmp_path):
    missing = tmp_path / "operator-verifier-not-present"
    environment["STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH"] = str(missing)
    result = probe(environment)
    assert result["schema_version"] == LATEST_SCHEMA_VERSION
    assert not missing.exists()


def satellite_unit(unit: str = UNIT) -> str:
    return unit.replace(
        "Environment=STRUGGLEBUS_CA_ROOT_SHA256=",
        "Environment=STRUGGLEBUS_CA_ROOT_SHA256=\n"
        "Environment=STRUGGLEBUS_SATELLITE_HOSTNAME=gw.example.com\n"
        "Environment=STRUGGLEBUS_SATELLITE_GATEWAY_WG_ADDRESS=10.99.0.1\n"
        "LoadCredential=satellite-ca-key:/etc/strugglebus/credentials/satellite-ca-key\n"
        "Environment=STRUGGLEBUS_SATELLITE_CA_KEY_PATH=%d/satellite-ca-key\n"
        "Environment=STRUGGLEBUS_SATELLITE_CA_CERT_PATH=/etc/strugglebus-satellite/ca.crt",
    )


def test_satellite_key_projection_is_accepted_and_can_be_enabled_or_disabled():
    candidate = satellite_unit(operator_unit())
    environment = MODULE.validate_unit_scope(operator_unit(), candidate)
    assert environment["STRUGGLEBUS_SATELLITE_CA_KEY_PATH"] == MODULE.PROJECTED_SATELLITE_KEY
    assert "STRUGGLEBUS_SATELLITE_CA_KEY_PATH" not in MODULE.validate_unit_scope(
        candidate, operator_unit()
    )
    # The key is the app's own projection; maintenance never observes it.
    assert set(MODULE.credential_sources(candidate)) == {"admin-token", "operator-password"}


@pytest.mark.parametrize("replace_old,replace_new", [
    ("satellite-ca-key:/etc/strugglebus/credentials/satellite-ca-key",
     "satellite-ca-key:/etc/strugglebus/credentials/admin-token"),
    ("satellite-ca-key:/etc/strugglebus/credentials/satellite-ca-key",
     "satellite-ca-key:/etc/strugglebus/credentials/operator-password"),
    ("satellite-ca-key:/etc/strugglebus/credentials/satellite-ca-key",
     "satellite-ca-key:/run/credentials/strugglebus.service/satellite-ca-key"),
    ("%d/satellite-ca-key", "%d/other"),
    ("LoadCredential=satellite-ca-key:/etc/strugglebus/credentials/satellite-ca-key\n", ""),
    ("Environment=STRUGGLEBUS_SATELLITE_CA_KEY_PATH=%d/satellite-ca-key",
     "Environment=STRUGGLEBUS_SATELLITE_CA_KEY_PATH=%d/satellite-ca-key\n"
     "LoadCredential=satellite-ca-key:/etc/other/satellite-ca-key"),
    ("Environment=STRUGGLEBUS_CA_BUNDLE_PATH=",
     "Environment=STRUGGLEBUS_CA_BUNDLE_PATH=/etc/strugglebus/credentials/satellite-ca-key"),
])
def test_satellite_projection_aliases_duplicates_and_omissions_fail(replace_old, replace_new):
    with pytest.raises(MaintenanceConfigError):
        MODULE.parse_environment(
            satellite_unit(operator_unit()).replace(replace_old, replace_new)
        )


def test_satellite_projection_probe_does_not_load_the_key(environment, tmp_path):
    missing = tmp_path / "satellite-key-not-present"
    environment.update({
        "STRUGGLEBUS_SATELLITE_HOSTNAME": "gw.example.com",
        "STRUGGLEBUS_SATELLITE_GATEWAY_WG_ADDRESS": "10.99.0.1",
        "STRUGGLEBUS_SATELLITE_CA_CERT_PATH": str(tmp_path / "ca.crt"),
        "STRUGGLEBUS_SATELLITE_CA_KEY_PATH": str(missing),
    })
    assert probe(environment)["schema_version"] == LATEST_SCHEMA_VERSION
    assert not missing.exists()


def test_legacy_unit_can_omit_optional_ca_settings():
    old = UNIT.replace("Environment=STRUGGLEBUS_CA_BUNDLE_PATH=\n", "").replace(
        "Environment=STRUGGLEBUS_CA_ROOT_SHA256=\n", ""
    )
    assert MODULE.credential_sources(old) == {
        "admin-token": "/etc/strugglebus/credentials/admin-token",
    }


def test_fixture_matches_repository_unit_directives() -> None:
    template = (
        REPOSITORY / "deploy" / "roles" / "systemd" / "templates"
        / "strugglebus.service.j2"
    ).read_text(encoding="utf-8")
    names = lambda text: {
        line.partition("=")[0] for line in text.splitlines()
        if "=" in line and not line.startswith(("{", "#"))
    }
    assert names(UNIT) == names(template)


@pytest.mark.parametrize("quote", ["'", '"'])
def test_whole_assignment_quotes_and_multiple_assignments(quote: str) -> None:
    original = (
        "Environment=STRUGGLEBUS_CA_BUNDLE_PATH=\n"
        "Environment=STRUGGLEBUS_CA_ROOT_SHA256="
    )
    replacement = (
        f"Environment={quote}STRUGGLEBUS_CA_BUNDLE_PATH={quote} "
        f"{quote}STRUGGLEBUS_CA_ROOT_SHA256={quote}"
    )
    assert MODULE.parse_environment(UNIT.replace(original, replacement)) == MODULE.parse_environment(UNIT)


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        ("Environment=STRUGGLEBUS_MAX_CHANNELS=1000", "Environment="),
        ("STRUGGLEBUS_MAX_CHANNELS=1000", 'STRUGGLEBUS_MAX_CHANNELS="1000"'),
        ("STRUGGLEBUS_MAX_CHANNELS=1000", '"STRUGGLEBUS_MAX_CHANNELS=1000'),
        ("STRUGGLEBUS_MAX_CHANNELS=1000", r"STRUGGLEBUS_MAX_CHANNELS=\x31"),
        ("STRUGGLEBUS_MAX_CHANNELS=1000", "STRUGGLEBUS_MAX_CHANNELS=1000\\\n  Environment=X=1"),
        ("STRUGGLEBUS_MAX_CHANNELS=1000", "STRUGGLEBUS_MAX_CHANNELS=1000\x00"),
        ("STRUGGLEBUS_MAX_CHANNELS=1000", 'STRUGGLEBUS_MAX_CHANNELS=1000\nEnvironment="X=secret"'),
        ("STRUGGLEBUS_MAX_CHANNELS=1000", 'STRUGGLEBUS_MAX_CHANNELS=1000\nEnvironment="STRUGGLEBUS_RELEASE_ID=line\nbreak"'),
        ("STRUGGLEBUS_MAX_CHANNELS=1000", "STRUGGLEBUS_MAX_CHANNELS=1000\nEnvironment=STRUGGLEBUS_MAX_CHANNELS=3"),
        ("STRUGGLEBUS_MAX_CHANNELS=1000", "STRUGGLEBUS_ADMIN_SECRET=secret"),
        ("STRUGGLEBUS_MAX_CHANNELS=1000", "PYTHONPATH=/untrusted"),
        ("STRUGGLEBUS_MAX_CHANNELS=1000", "STRUGGLEBUS_MAX_CHANNELS=$(touch /should-not-exist)"),
        ("STRUGGLEBUS_MAX_CHANNELS=1000", "STRUGGLEBUS_MAX_CHANNELS=%i"),
        ("STRUGGLEBUS_MAX_CHANNELS=1000", "STRUGGLEBUS_MAX_CHANNELS=1000\r"),
        ("STRUGGLEBUS_DATA_DIR=/var/lib/strugglebus", "STRUGGLEBUS_DATA_DIR=relative"),
        ("STRUGGLEBUS_DATA_DIR=/var/lib/strugglebus", "STRUGGLEBUS_DATA_DIR=/var/../strugglebus"),
        ("EnvironmentFile=-/opt/strugglebus/current/release.env", "EnvironmentFile=-/etc/secret"),
        ("EnvironmentFile=-/opt/strugglebus/current/release.env", "EnvironmentFile=/opt/strugglebus/current/release.env"),
        ("LoadCredential=admin-token:", "LoadCredential=other:"),
        ("LoadCredential=admin-token:/etc", "LoadCredential=admin-token:relative"),
        ("%d/admin-token", "%d/other"),
        ("venv/bin/strugglebus serve", "venv/bin/strugglebus serve --reload"),
        ("venv/bin/strugglebus", "venv/bin/uvicorn"),
        ("strugglebus serve", "strugglebus serve;touch"),
        ("ExecStart=/opt", "ExecStart=/bin/sh /opt"),
        ("PrivateTmp=true", "PrivateTmp=false"),
        ("PrivateTmp=true", "ExecStartPre=/bin/true"),
        ("PrivateTmp=true", "PrivateTmp=true\nPrivateTmp=true"),
        ("[Install]", "[Service]"),
        ("[Unit]", "[Unknown]"),
        ("User=strugglebus", "User=root:0"),
        ("RuntimeDirectory=strugglebus\n", ""),
    ],
)
def test_unsafe_or_unsupported_unit_syntax_fails_closed(
    original: str, replacement: str,
) -> None:
    with pytest.raises(MaintenanceConfigError):
        MODULE.parse_environment(UNIT.replace(original, replacement))


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.2", "localhost", "127.0.0.1%eth0"])
def test_unit_requires_matching_loopback_bind(host: str) -> None:
    with pytest.raises(MaintenanceConfigError):
        MODULE.parse_environment(UNIT.replace("127.0.0.1", host))


@pytest.mark.parametrize("host", ["::1", "127.0.0.2"])
def test_loopback_alternatives_are_valid(host: str) -> None:
    assert MODULE.parse_environment(UNIT.replace("127.0.0.1", host))["STRUGGLEBUS_BIND_HOST"] == host


def test_unit_and_assignment_size_limits() -> None:
    with pytest.raises(MaintenanceConfigError):
        MODULE.parse_environment(UNIT + "#" * MODULE.MAX_UNIT_BYTES)
    with pytest.raises(MaintenanceConfigError):
        MODULE.parse_environment(
            UNIT.replace("STRUGGLEBUS_MAX_CHANNELS=1000", "STRUGGLEBUS_MAX_CHANNELS=" + "1" * 4097)
        )
    with pytest.raises(MaintenanceConfigError):
        MODULE.parse_environment(UNIT.replace("[Install]", "\n".join(
            f"Environment=STRUGGLEBUS_EXTRA_{index}=1" for index in range(129)
        ) + "\n[Install]"))


def test_application_setting_changes_leave_topology_unchanged() -> None:
    changed = UNIT.replace("STRUGGLEBUS_MAX_CHANNELS=1000", "STRUGGLEBUS_MAX_CHANNELS=2000")
    assert MODULE.validate_unit_scope(UNIT, changed)["STRUGGLEBUS_MAX_CHANNELS"] == "2000"


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("User=strugglebus", "User=other"),
        ("Group=strugglebus", "Group=other"),
        ("/etc/strugglebus/credentials/admin-token", "/etc/other/admin-token"),
        ("/opt/strugglebus/current", "/opt/other/current"),
        ("/var/lib/strugglebus", "/var/lib/other"),
        ("https://bus.lan", "https://other.lan"),
        ("127.0.0.1", "::1"),
        ("8080", "8081"),
        (
            "STRUGGLEBUS_TRUSTED_PROXY_SOURCES=127.0.0.1,::1",
            '"STRUGGLEBUS_TRUSTED_PROXY_SOURCES=127.0.0.2"',
        ),
    ],
)
def test_topology_changes_are_rejected_even_with_quoted_assignments(old: str, new: str) -> None:
    with pytest.raises(MaintenanceConfigError, match="protected topology"):
        MODULE.validate_unit_scope(UNIT, UNIT.replace(old, new))


def test_actual_candidate_config_and_packaged_schema_are_validated(environment) -> None:
    assert AppConfig.from_env(environment).max_active_credentials_per_agent == 2
    result = probe(environment)
    assert result["schema_version"] == LATEST_SCHEMA_VERSION
    assert result["config_fields"] == sorted(
        item.name for item in fields(AppConfig) if item.name != "admin_secret"
    )
    assert result["config_sha256"] == hashlib.sha256(
        json.dumps(environment, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    assert "unread-admin-token" not in json.dumps(result)
    assert "candidate-0.2.12" not in json.dumps(result)


@pytest.mark.parametrize(
    "name",
    [
        "STRUGGLEBUS_MAX_ACTIVE_CREDENTIALS",
        "STRUGGLEBUS_UNKNOWN_SETTING",
    ],
)
def test_baseline_loader_ignores_unknown_settings_but_probe_rejects_them(environment, name) -> None:
    environment[name] = "7"
    AppConfig.from_env(environment)
    with pytest.raises(MaintenanceConfigError, match="unsupported candidate setting"):
        probe(environment)


@pytest.mark.parametrize(
    ("name", "limit"),
    [("ORIENTATION_COUNT_CAP", 10_000), ("CATCH_UP_DRAIN_TTL_SECONDS", 3_600)],
)
def test_optional_settings_follow_actual_candidate_capabilities(environment, name, limit) -> None:
    field = name.lower()
    supported = field in {item.name for item in fields(AppConfig)}
    environment["STRUGGLEBUS_" + name] = "7"
    if supported:
        assert getattr(AppConfig.from_env(environment), field) == 7
        result = probe(environment)
        assert field in result["config_fields"]
        assert result["schema_version"] == LATEST_SCHEMA_VERSION
    else:
        # An actual older candidate must reject the setting, not silently use
        # defaults as its permissive AppConfig loader would.
        assert not hasattr(AppConfig.from_env(environment), field)
        with pytest.raises(MaintenanceConfigError, match="^unsupported candidate setting$"):
            probe(environment)
    for value in ("0", str(limit + 1), "not-a-number"):
        environment["STRUGGLEBUS_" + name] = value
        error = "invalid candidate configuration" if supported else "unsupported candidate setting"
        with pytest.raises(MaintenanceConfigError, match=f"^{error}$"):
            probe(environment)


def test_retired_presentation_settings_from_an_older_unit_are_accepted(environment, tmp_path):
    environment["STRUGGLEBUS_PRESENTATION_CATALOG_DIR"] = str(tmp_path / "catalog")
    environment["STRUGGLEBUS_PRESENTATION_WORKERS"] = "1"
    result = probe(environment)
    assert "presentation_catalog_dir" in result["config_fields"]
    assert "presentation_workers" in result["config_fields"]
    assert not (tmp_path / "catalog").exists()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("MAX_CHANNELS", "0"),
        ("MAX_CHANNELS", "not-a-number"),
        ("MAX_MESSAGE_BYTES", "9000000"),
        ("MAX_REST_REQUEST_BODY_BYTES", "1024"),
        ("SSE_BATCH_SIZE", "201"),
        ("SSE_CONNECTION_SECONDS", "3601"),
        ("SSE_POLL_INTERVAL_MS", "9"),
        ("MAX_ACTIVE_CREDENTIALS_PER_AGENT", "9"),
        ("BIND_HOST", "0.0.0.0"),
        ("BIND_HOST", "localhost"),
        ("BIND_PORT", "65536"),
        ("PUBLIC_BASE_URL", "http://bus.lan"),
        ("ROE_ENFORCEMENT_MODE", "disabled"),
        ("RELEASE_ID", "unsafe release id"),
        ("ALLOWED_HOSTS", "*"),
        ("ALLOWED_ORIGINS", "*"),
        ("DATA_DIR", "relative"),
        ("ADMIN_CREDENTIAL_PATH", "relative"),
        ("MAX_CHANNELS", "1\nSTRUGGLEBUS_MAX_CHANNELS=3"),
        ("RELEASE_ID", "nul\x00"),
        ("RELEASE_ID", "%i"),
        ("RELEASE_ID", "\ud800"),
        ("ADMIN_SECRET", "must-not-be-read"),
    ],
)
def test_malformed_settings_fail_closed(environment, name: str, value: str) -> None:
    environment["STRUGGLEBUS_" + name] = value
    with pytest.raises(MaintenanceConfigError):
        probe(environment)


def test_probe_does_not_inherit_application_or_python_environment(environment, monkeypatch) -> None:
    monkeypatch.setenv("STRUGGLEBUS_ADMIN_SECRET", "must-not-be-read")
    monkeypatch.setenv("STRUGGLEBUS_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("PYTHONPATH", "must-not-be-used")
    assert probe(environment)["schema_version"] == LATEST_SCHEMA_VERSION


@pytest.mark.parametrize("with_ca", [False, True])
def test_probe_does_not_start_app_open_db_read_secret_or_write_files(
    environment, tmp_path, monkeypatch, with_ca, request,
) -> None:
    if with_ca:
        environment = request.getfixturevalue("ca_environment")
    secret = Path(environment["STRUGGLEBUS_ADMIN_CREDENTIAL_PATH"])
    secret.write_text("sensitive-test-only-value", encoding="ascii")
    database = Path(environment["STRUGGLEBUS_DATABASE_PATH"])
    database.write_bytes(b"not-a-sqlite-database")
    audit = r'''
    blocked = {
        os.path.normcase(os.path.abspath(environment[key]))
        for key in ("STRUGGLEBUS_DATABASE_PATH", "STRUGGLEBUS_ADMIN_CREDENTIAL_PATH")
    }
    def audit(event, args):
        if event in {"sqlite3.connect", "os.mkdir", "os.remove", "os.rename"}:
            raise RuntimeError("forbidden side effect")
        if event == "import" and args[0] in {"strugglebus.app", "strugglebus.service"}:
            raise RuntimeError("forbidden application import")
        if event == "open":
            path, mode, flags = args
            if isinstance(path, (str, bytes)) and os.path.normcase(os.path.abspath(path)) in blocked:
                raise RuntimeError("forbidden sensitive read")
            if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                raise RuntimeError("forbidden write")
    sys.addaudithook(audit)
'''
    monkeypatch.setattr(
        MODULE, "PROBE_CODE",
        MODULE.PROBE_CODE.replace("    from strugglebus.config import AppConfig", audit + "\n    from strugglebus.config import AppConfig"),
    )
    assert probe(environment)["schema_version"] == LATEST_SCHEMA_VERSION
    expected = ["database.db", "unread-admin-token"]
    if with_ca:
        expected.insert(1, "roots.pem")
    assert sorted(path.name for path in tmp_path.iterdir()) == expected
    assert database.read_bytes() == b"not-a-sqlite-database"


def test_probe_does_not_create_missing_database_or_directories(environment, tmp_path) -> None:
    assert probe(environment)["schema_version"] == LATEST_SCHEMA_VERSION
    assert list(tmp_path.iterdir()) == []


def test_public_ca_selects_declared_der_digest_without_publishing_bytes(ca_environment) -> None:
    assert load_trust_anchor(
        ca_environment["STRUGGLEBUS_CA_BUNDLE_PATH"],
        ca_environment["STRUGGLEBUS_CA_ROOT_SHA256"],
    ) is not None
    result = probe(ca_environment)
    assert result["schema_version"] == LATEST_SCHEMA_VERSION
    encoded = json.dumps(result)
    assert "CERTIFICATE" not in encoded and "roots.pem" not in encoded
    assert ca_environment["STRUGGLEBUS_CA_ROOT_SHA256"] not in encoded


@pytest.mark.parametrize(
    "kind", ["malformed-der", "leaf", "expired", "future", "bad-before", "bad-after"],
)
def test_public_ca_rejects_unusable_certificate_even_with_matching_digest(
    ca_environment, ca_certificates, kind,
) -> None:
    der = b"declared-public-root-certificate" if kind == "malformed-der" else ca_certificates[kind]
    Path(ca_environment["STRUGGLEBUS_CA_BUNDLE_PATH"]).write_bytes(_pem(der))
    ca_environment["STRUGGLEBUS_CA_ROOT_SHA256"] = hashlib.sha256(der).hexdigest()
    with pytest.raises(MaintenanceConfigError, match="^invalid public CA configuration$"):
        probe(ca_environment)


@pytest.mark.parametrize(
    ("boundary", "offset", "valid"),
    [("notBefore", -1, False), ("notBefore", 0, True),
     ("notAfter", -1, True), ("notAfter", 0, False)],
)
def test_public_ca_validity_boundaries(ca_environment, ca_certificates, monkeypatch, boundary, offset, valid):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(ca_certificates["root"]))
    timestamp = ssl.cert_time_to_seconds(context.get_ca_certs()[0][boundary]) + offset
    monkeypatch.setattr(MODULE, "PROBE_CODE", MODULE.PROBE_CODE.replace(
        "    from strugglebus.config import AppConfig",
        f"    time.time = lambda: {timestamp!r}\n    from strugglebus.config import AppConfig",
    ))
    if valid:
        assert probe(ca_environment)["schema_version"] == LATEST_SCHEMA_VERSION
    else:
        with pytest.raises(MaintenanceConfigError, match="^invalid public CA configuration$"):
            probe(ca_environment)


@pytest.mark.parametrize("missing", ["STRUGGLEBUS_CA_BUNDLE_PATH", "STRUGGLEBUS_CA_ROOT_SHA256"])
def test_public_ca_requires_both_settings_or_neither(ca_environment, missing: str) -> None:
    ca_environment[missing] = ""
    with pytest.raises(MaintenanceConfigError):
        probe(ca_environment)


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("CA_BUNDLE_PATH", "relative.pem"),
        ("CA_ROOT_SHA256", "a" * 64),
        ("CA_ROOT_SHA256", "A" * 64),
        ("CA_ROOT_SHA256", "not-a-digest"),
    ],
)
def test_public_ca_rejects_invalid_path_or_digest(ca_environment, setting: str, value: str) -> None:
    ca_environment["STRUGGLEBUS_" + setting] = value
    with pytest.raises(MaintenanceConfigError):
        probe(ca_environment)


@pytest.mark.parametrize(
    "content",
    [
        b"no certificate",
        b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
        b"-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n",
        _pem(b"declared-public-root-certificate") + b"\nPRIVATE KEY",
        _pem(b"declared-public-root-certificate") + b"#" * (256 * 1024),
    ],
    ids=["not-pem", "invalid-base64", "private-key", "mixed-key-bundle", "oversized"],
)
def test_public_ca_rejects_malformed_private_or_oversized_bundle(ca_environment, content: bytes) -> None:
    Path(ca_environment["STRUGGLEBUS_CA_BUNDLE_PATH"]).write_bytes(content)
    with pytest.raises(MaintenanceConfigError, match="public CA"):
        probe(ca_environment)


def test_public_ca_rejects_missing_file_and_directory(ca_environment, tmp_path) -> None:
    for path in (tmp_path / "missing.pem", tmp_path):
        ca_environment["STRUGGLEBUS_CA_BUNDLE_PATH"] = str(path)
        with pytest.raises(MaintenanceConfigError):
            probe(ca_environment)


def test_public_ca_allows_exact_limit(ca_environment) -> None:
    path = Path(ca_environment["STRUGGLEBUS_CA_BUNDLE_PATH"])
    content = path.read_bytes()
    path.write_bytes(content + b"#" * (256 * 1024 - len(content)))
    assert probe(ca_environment)["schema_version"] == LATEST_SCHEMA_VERSION


def test_public_ca_rejects_symlink(ca_environment, tmp_path) -> None:
    link = tmp_path / "linked.pem"
    try:
        link.symlink_to(Path(ca_environment["STRUGGLEBUS_CA_BUNDLE_PATH"]))
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    ca_environment["STRUGGLEBUS_CA_BUNDLE_PATH"] = str(link)
    with pytest.raises(MaintenanceConfigError, match="public CA"):
        probe(ca_environment)


@pytest.mark.skipif(os.name == "nt", reason="POSIX file permission semantics")
def test_public_ca_must_be_readable_as_service_user(ca_environment) -> None:
    if os.geteuid() == 0:
        pytest.skip("root bypasses service-user file permissions")
    path = Path(ca_environment["STRUGGLEBUS_CA_BUNDLE_PATH"])
    path.chmod(0)
    try:
        with pytest.raises(MaintenanceConfigError, match="public CA"):
            probe(ca_environment)
    finally:
        path.chmod(0o600)


@pytest.mark.parametrize(
    "path",
    [
        "/etc/strugglebus/credentials/admin-token",
        "/run/credentials/strugglebus.service/admin-token",
        "/var/lib/strugglebus/strugglebus.db",
    ],
)
def test_unit_cannot_repurpose_credential_or_database_as_public_ca(path: str) -> None:
    with pytest.raises(MaintenanceConfigError, match="public CA"):
        MODULE.parse_environment(UNIT.replace(
            "STRUGGLEBUS_CA_BUNDLE_PATH=", "STRUGGLEBUS_CA_BUNDLE_PATH=" + path
        ))


@pytest.mark.parametrize("key", ["STRUGGLEBUS_ADMIN_CREDENTIAL_PATH", "STRUGGLEBUS_DATABASE_PATH"])
def test_probe_rejects_sensitive_ca_target_without_opening_it(environment, key: str) -> None:
    environment["STRUGGLEBUS_CA_BUNDLE_PATH"] = environment[key]
    environment["STRUGGLEBUS_CA_ROOT_SHA256"] = "a" * 64
    with pytest.raises(MaintenanceConfigError, match="public CA"):
        probe(environment)


@pytest.mark.parametrize("timeout", [0, -1, 301, float("inf"), float("nan"), True])
def test_probe_timeout_is_bounded(environment, timeout) -> None:
    with pytest.raises(MaintenanceConfigError, match="arguments"):
        MODULE.candidate_config_probe(sys.executable, environment, timeout=timeout)


def test_probe_executes_only_fixed_code_and_passes_settings_on_stdin(environment, monkeypatch) -> None:
    real_run = subprocess.run
    observed = []

    def record(argv, **kwargs):
        observed.append((argv, kwargs))
        return real_run(argv, **kwargs)

    monkeypatch.setattr(MODULE.subprocess, "run", record)
    assert probe(environment)["schema_version"] == LATEST_SCHEMA_VERSION
    argv, kwargs = observed[0]
    assert argv == [sys.executable, "-I", "-c", MODULE.PROBE_CODE]
    assert json.loads(kwargs["input"]) == environment
    assert not any(name.startswith("STRUGGLEBUS_") for name in kwargs["env"])
    assert kwargs.get("shell", False) is False
    assert kwargs["stderr"] is subprocess.DEVNULL
    assert kwargs["timeout"] == 30


@pytest.mark.parametrize(
    "response",
    [
        b"private raw exception",
        b"{}",
        b"null",
        b'{"error":"private raw exception"}',
        b"x" * (MODULE.MAX_OUTPUT_BYTES + 1),
    ],
    ids=["raw-exception", "empty-object", "null", "private-error", "oversized"],
)
def test_unexpected_probe_output_is_sanitized(environment, response: bytes, monkeypatch) -> None:
    monkeypatch.setattr(
        MODULE.subprocess, "run",
        lambda *args, **kwargs: subprocess.CompletedProcess([], 1, stdout=response),
    )
    with pytest.raises(MaintenanceConfigError, match="^candidate configuration probe failed$"):
        probe(environment)


@pytest.mark.parametrize("error", [
    OSError("sensitive-path-or-token"),
    subprocess.TimeoutExpired(["sensitive-command"], 1, output=b"secret", stderr=b"secret"),
])
def test_probe_execution_failures_are_sanitized(environment, error, monkeypatch) -> None:
    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(MODULE.subprocess, "run", fail)
    with pytest.raises(MaintenanceConfigError) as caught:
        probe(environment)
    assert str(caught.value) == "candidate configuration probe failed"


def test_candidate_exception_and_diagnostics_are_silenced(environment, monkeypatch, capsys) -> None:
    monkeypatch.setattr(MODULE, "PROBE_CODE", MODULE.PROBE_CODE.replace(
        "    from strugglebus.config import AppConfig",
        '    print("private diagnostic")\n'
        '    print("private diagnostic", file=sys.stderr)\n'
        '    raise ValueError("private exception")\n'
        "    from strugglebus.config import AppConfig",
    ))
    with pytest.raises(MaintenanceConfigError, match="^invalid candidate configuration$"):
        probe(environment)
    assert capsys.readouterr() == ("", "")


def test_candidate_packaged_migrations_must_be_complete(environment, monkeypatch) -> None:
    monkeypatch.setattr(MODULE, "PROBE_CODE", MODULE.PROBE_CODE.replace(
        "    migrations = load_packaged_migrations()",
        "    migrations = load_packaged_migrations()[:-1]",
    ))
    with pytest.raises(MaintenanceConfigError, match="^invalid candidate migration package$"):
        probe(environment)


def test_candidate_timeout_terminates_probe(environment, monkeypatch) -> None:
    monkeypatch.setattr(MODULE, "PROBE_CODE", MODULE.PROBE_CODE.replace(
        "    from strugglebus.config import AppConfig",
        "    import time\n    time.sleep(5)\n    from strugglebus.config import AppConfig",
    ))
    with pytest.raises(MaintenanceConfigError, match="^candidate configuration probe failed$"):
        MODULE.candidate_config_probe(sys.executable, environment, timeout=0.1)


def test_cli_supplies_verified_release_id_without_reading_environment_file(tmp_path, monkeypatch, capsys) -> None:
    unit = tmp_path / "candidate.service"
    unit.write_bytes(UNIT.encode("ascii"))
    called = []

    def fake_probe(python, environment, timeout):
        called.append((python, environment, timeout))
        return {"schema_version": 10, "config_fields": [], "config_sha256": "a" * 64}

    monkeypatch.setattr(MODULE, "candidate_config_probe", fake_probe)
    assert MODULE.main([
        "--unit", str(unit), "--current-unit", str(unit),
        "--candidate-python", sys.executable, "--release-id", "release-123",
    ]) == 0
    assert called[0][1]["STRUGGLEBUS_RELEASE_ID"] == "release-123"
    result = json.loads(capsys.readouterr().out)
    assert set(result) == {"candidate_schema", "environment"}
    assert result["candidate_schema"] == 10
    assert result["environment"] == called[0][1]


@pytest.mark.parametrize("argv", [[], ["--unknown", "private-argument"], [
    "--unit", "private-path", "--candidate-python", "private-python",
    "--release-id", "private/identity",
]])
def test_cli_errors_are_bounded_json_without_raw_arguments(argv, capsys) -> None:
    assert MODULE.main(argv) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    result = json.loads(captured.out)
    assert set(result) == {"error"}
    assert "private" not in captured.out


def test_cli_refuses_unit_release_identity_override(tmp_path, capsys) -> None:
    unit = tmp_path / "candidate.service"
    unit.write_bytes(UNIT.replace(
        "[Install]", "Environment=STRUGGLEBUS_RELEASE_ID=wrong\n[Install]"
    ).encode("ascii"))
    assert MODULE.main([
        "--unit", str(unit), "--candidate-python", sys.executable,
        "--release-id", "release-123",
    ]) == 1
    assert json.loads(capsys.readouterr().out) == {
        "error": "unit overrides candidate release identity"
    }


def test_stdin_cli_runs_actual_candidate_without_service_reading_private_unit(environment) -> None:
    del environment["STRUGGLEBUS_RELEASE_ID"]
    result = subprocess.run(
        [
            sys.executable, "-I", str(HELPER), "--environment-stdin",
            "--candidate-python", sys.executable, "--release-id", "candidate-123",
        ],
        input=json.dumps(environment).encode("ascii"),
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0
    assert result.stderr == b""
    parsed = json.loads(result.stdout)
    assert set(parsed) == {"candidate_schema", "environment"}
    assert parsed["candidate_schema"] == LATEST_SCHEMA_VERSION
    assert parsed["environment"] == {**environment, "STRUGGLEBUS_RELEASE_ID": "candidate-123"}


def test_updater_settings_are_opt_in_and_preserved_by_maintenance_parser() -> None:
    settings = (
        "Environment=STRUGGLEBUS_UPDATER_SOCKET_PATH=/run/strugglebus-updater/worker.sock\n"
        "Environment=STRUGGLEBUS_UPDATER_CONFIRM_SESSION_PER_MINUTE=3\n"
        "Environment=STRUGGLEBUS_UPDATER_CONFIRM_GLOBAL_PER_MINUTE=6\n"
        "Environment=STRUGGLEBUS_UPDATER_REVIEW_SECONDS=300\n"
        "Environment=STRUGGLEBUS_UPDATER_REVIEW_TICKETS=8\n"
    )
    candidate = UNIT.replace("ExecStart=", settings + "ExecStart=")
    environment = MODULE.validate_unit_scope(UNIT, candidate)
    assert environment["STRUGGLEBUS_UPDATER_REVIEW_TICKETS"] == "8"
    MODULE._validate_updater_settings(environment)
    assert "STRUGGLEBUS_UPDATER_SOCKET_PATH" not in MODULE.parse_environment(UNIT)
    disabled = candidate.replace("/run/strugglebus-updater/worker.sock", "")
    assert MODULE.parse_environment(disabled)["STRUGGLEBUS_UPDATER_SOCKET_PATH"] == ""
    MODULE._validate_environment({"STRUGGLEBUS_UPDATER_REVIEW_TICKETS": "8"})
    with pytest.raises(MaintenanceConfigError, match="updater"):
        MODULE._validate_environment({"STRUGGLEBUS_UPDATER_REVIEW_TICKETS": "9"})


@pytest.mark.parametrize("name,value", [
    ("UPDATER_CONFIRM_SESSION_PER_MINUTE", "4"),
    ("UPDATER_CONFIRM_GLOBAL_PER_MINUTE", "7"),
    ("UPDATER_REVIEW_SECONDS", "301"), ("UPDATER_REVIEW_TICKETS", "9"),
    ("UPDATER_REVIEW_TICKETS", "0"), ("UPDATER_REVIEW_TICKETS", "true"),
    ("UPDATER_REVIEW_TICKETS", "1.0"), ("UPDATER_REVIEW_TICKETS", "-1"),
    ("UPDATER_SOCKET_PATH", "/var/lib/strugglebus/worker.sock"),
    ("UPDATER_SOCKET_PATH", "/run/strugglebus/worker.sock"),
    ("UPDATER_SOCKET_PATH", "/var/lib/strugglebus/backups/worker.sock"),
    ("UPDATER_SOCKET_PATH", "/var/lib/strugglebus"),
    ("UPDATER_SOCKET_PATH", "relative"), ("UPDATER_SOCKET_PATH", "/a/../b"),
    ("UPDATER_SOCKET_PATH", "/" + "a" * 107),
])
def test_updater_maintenance_scope_refuses_unsafe_limits_and_socket_paths(name, value) -> None:
    candidate = UNIT.replace("ExecStart=", f"Environment=STRUGGLEBUS_{name}={value}\nExecStart=")
    with pytest.raises(MaintenanceConfigError, match="updater"):
        MODULE.parse_environment(candidate)


@pytest.mark.parametrize(
    "raw",
    [
        b"{invalid", b"[]", b"null", b'"private-value"', b"x" * (64 * 1024 + 1),
        b"[" * 2000 + b"]" * 2000,
        b'{"STRUGGLEBUS_BIND_HOST":"127.0.0.1","STRUGGLEBUS_BIND_HOST":"0.0.0.0"}',
    ],
    ids=["malformed", "list", "null", "string", "oversized", "nested", "duplicate"],
)
def test_stdin_cli_refuses_malformed_input_without_echoing_it(raw: bytes) -> None:
    result = subprocess.run(
        [
            sys.executable, "-I", str(HELPER), "--environment-stdin",
            "--candidate-python", sys.executable, "--release-id", "candidate-123",
        ],
        input=raw,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 1 and result.stderr == b""
    assert set(json.loads(result.stdout)) == {"error"}
    assert b"private-value" not in result.stdout


def test_unit_stdin_cli_emits_only_validated_runtime_comparison_environment(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(UNIT.encode("ascii"))))
    called = []

    def fake_probe(python, environment, timeout):
        called.append(environment)
        return {"schema_version": 10, "config_fields": [], "config_sha256": "a" * 64}

    monkeypatch.setattr(MODULE, "candidate_config_probe", fake_probe)
    assert MODULE.main([
        "--unit-stdin", "--candidate-python", sys.executable,
        "--release-id", "candidate-123",
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert set(result) == {"candidate_schema", "environment"}
    assert result["candidate_schema"] == 10
    assert result["environment"] == called[0]
    assert result["environment"]["STRUGGLEBUS_ADMIN_CREDENTIAL_PATH"] == MODULE.PROJECTED_CREDENTIAL
    assert "STRUGGLEBUS_ADMIN_SECRET" not in result["environment"]


@pytest.mark.parametrize(
    "unit",
    [
        UNIT.replace("STRUGGLEBUS_MAX_CHANNELS=1000", "STRUGGLEBUS_ADMIN_SECRET=private-value"),
        UNIT.replace("STRUGGLEBUS_MAX_CHANNELS=1000", "PRIVATE_OTHER_SECRET=private-value"),
        UNIT + "#" * (64 * 1024),
    ],
    ids=["admin-secret", "non-app-setting", "oversized"],
)
def test_unit_stdin_cli_never_echoes_rejected_unit_or_secrets(unit: str) -> None:
    result = subprocess.run(
        [
            sys.executable, "-I", str(HELPER), "--unit-stdin",
            "--candidate-python", sys.executable, "--release-id", "candidate-123",
        ],
        input=unit.encode("ascii"),
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 1 and result.stderr == b""
    assert set(json.loads(result.stdout)) == {"error"}
    assert b"private-value" not in result.stdout
