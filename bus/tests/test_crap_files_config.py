"""Configuration bounds and credential-file handling not covered elsewhere."""

from __future__ import annotations

import os
import stat
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import strugglebus.config as config_module
from strugglebus.config import (
    AppConfig,
    _classify_systemd_credential_directory,
    _validate_credential_metadata,
)
from strugglebus.errors import ConfigurationError


class _OsProxy:
    """The real ``os`` module with a few attributes replaced for one module."""

    def __init__(self, **overrides: object) -> None:
        self._overrides = overrides

    def __getattr__(self, name: str) -> object:
        overrides = self.__dict__["_overrides"]
        if name in overrides:
            return overrides[name]
        return getattr(os, name)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("sse_batch_size", 201, "sse_batch_size must not exceed 200"),
        ("sse_connection_seconds", 3_601, "sse_connection_seconds must not exceed 3600"),
        ("sse_max_connections_per_agent", 11, "sse_max_connections_per_agent must not exceed 10"),
        ("human_activity_limit", 201, "human_activity_limit must not exceed 200"),
        ("shutdown_grace_seconds", 61, "shutdown_grace_seconds must be between 1 and 60"),
        ("max_channels", 2, "max_channels must accommodate the original three"),
        ("release_id", "has space", "release_id must be 1-64 safe identifier characters"),
        ("release_id", 7, "release_id must be 1-64 safe identifier characters"),
        ("roe_enforcement_mode", "ignore", "roe_enforcement_mode must be observe or enforce"),
        ("max_active_credentials_per_agent", 9,
         "max_active_credentials_per_agent must not exceed 8"),
        ("max_enrollment_uses", 65, "max_enrollment_uses must not exceed 64"),
        ("liveness_refresh_seconds", 3_601, "liveness_refresh_seconds must not exceed 3600"),
        ("spn_package_ttl_seconds", 59, "spn_package_ttl_seconds must be at least 60"),
        ("ca_bundle_path", 5, "ca_bundle_path must be text"),
        ("ca_root_sha256", None, "ca_root_sha256 must be text"),
        ("ca_root_sha256", "a" * 64, "must both be set or both be empty"),
        ("public_base_url", "ftp://bus.lan", "public_base_url must be an absolute HTTP\\(S\\) URL"),
        ("public_base_url", "bus.lan", "public_base_url must be an absolute HTTP\\(S\\) URL"),
        ("bind_host", 5, "bind_host must be a loopback IP address"),
        ("allowed_origins", ("*",), "allowed_origins must contain explicit non-empty"),
        ("allowed_origins", ("https://bus.lan", " "), "allowed_origins must contain explicit"),
        ("allowed_origins", ["https://bus.lan"], "allowed_origins must contain explicit"),
        ("database_path", "strugglebus.db", "database_path must be a pathlib.Path"),
        ("backup_dir", "backups", "backup_dir must be a pathlib.Path"),
        ("operator_credential_path", "verifier", "operator_credential_path must be a pathlib.Path"),
    ],
)
def test_configuration_values_outside_their_bounds_are_refused(
    app_config, field, value, message,
):
    with pytest.raises(ConfigurationError, match=message):
        replace(app_config, **{field: value})


def test_ca_publication_needs_an_absolute_bundle_and_a_lowercase_digest(app_config, tmp_path):
    with pytest.raises(ConfigurationError, match="ca_bundle_path must be an absolute path"):
        replace(app_config, ca_bundle_path="relative/ca.pem", ca_root_sha256="a" * 64)
    with pytest.raises(ConfigurationError, match="must be a lowercase hex SHA-256 digest"):
        replace(app_config, ca_bundle_path=str(tmp_path / "ca.pem"), ca_root_sha256="A" * 64)

    accepted = replace(
        app_config, ca_bundle_path=str(tmp_path / "ca.pem"), ca_root_sha256="a" * 64,
    )
    assert accepted.ca_root_sha256 == "a" * 64


def test_admin_credential_must_be_exactly_one_well_typed_source(app_config, tmp_path):
    with pytest.raises(ConfigurationError, match="admin_credential_path must be a pathlib.Path"):
        replace(app_config, admin_secret=None, admin_credential_path="admin-token")
    with pytest.raises(ConfigurationError, match="configure exactly one of"):
        replace(app_config, admin_secret=None)
    with pytest.raises(ConfigurationError, match="configure exactly one of"):
        replace(app_config, admin_credential_path=tmp_path / "admin-token")
    with pytest.raises(ConfigurationError, match="admin_secret must be non-empty bytes"):
        replace(app_config, admin_secret="text-secret")
    with pytest.raises(ConfigurationError, match="admin_secret must be non-empty bytes"):
        replace(app_config, admin_secret=b"")


@pytest.mark.parametrize("value", ["eighty", "", "8080.0", "0", "-1"])
def test_integer_settings_from_the_environment_must_be_positive_integers(value):
    with pytest.raises(ConfigurationError, match="STRUGGLEBUS_BIND_PORT|bind_port"):
        AppConfig.from_env({"STRUGGLEBUS_BIND_PORT": value})


def test_satellite_ca_key_is_only_read_when_configured(app_config):
    with pytest.raises(ConfigurationError, match="satellite CA key is not configured"):
        app_config.load_satellite_ca_key()


def test_systemd_credential_directory_must_be_a_directory():
    regular = SimpleNamespace(st_mode=stat.S_IFREG | 0o500, st_uid=1000, st_gid=1000)
    private = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1000, st_gid=1000)
    shared = SimpleNamespace(st_mode=stat.S_IFDIR | 0o750, st_uid=1000, st_gid=1000)
    projected = SimpleNamespace(st_mode=stat.S_IFDIR | 0o550, st_uid=0, st_gid=0)

    assert _classify_systemd_credential_directory(regular, runtime_uid=1000) == (False, False)
    assert _classify_systemd_credential_directory(private, runtime_uid=1000) == (True, False)
    assert _classify_systemd_credential_directory(private, runtime_uid=2000) == (False, False)
    assert _classify_systemd_credential_directory(shared, runtime_uid=1000) == (False, False)
    assert _classify_systemd_credential_directory(projected, runtime_uid=1000) == (True, True)


def _file(mode: int, *, uid: int = 0, gid: int = 0) -> SimpleNamespace:
    return SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=uid, st_gid=gid)


def test_root_group_readable_credential_is_only_accepted_as_a_systemd_projection():
    projected = _file(0o440)

    _validate_credential_metadata(
        projected, require_root_owner=True, protected_systemd_projection=True,
    )
    with pytest.raises(ConfigurationError, match="unsafe ownership or permissions"):
        _validate_credential_metadata(projected, require_root_owner=True)
    for other in (_file(0o440, gid=1000), _file(0o440, uid=1000), _file(0o444), _file(0o640)):
        with pytest.raises(ConfigurationError, match="unsafe ownership or permissions"):
            _validate_credential_metadata(
                other,
                require_root_owner=True,
                runtime_uid=1000 if other.st_uid else None,
                protected_systemd_projection=True,
            )


def test_credential_ownership_rules_only_apply_where_requested():
    _validate_credential_metadata(_file(0o666, uid=4242), require_root_owner=False)
    _validate_credential_metadata(_file(0o600, uid=1000), require_root_owner=True, runtime_uid=1000)
    with pytest.raises(ConfigurationError, match="unsafe ownership or permissions"):
        _validate_credential_metadata(_file(0o600, uid=1000), require_root_owner=True)
    with pytest.raises(ConfigurationError, match="must be a regular file"):
        _validate_credential_metadata(
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0),
            require_root_owner=False,
        )


def _credential_file(tmp_path: Path, content: bytes) -> Path:
    path = tmp_path / "credential"
    path.write_bytes(content)
    path.chmod(0o600)
    return path


def _off_posix(monkeypatch, **overrides) -> None:
    """Skip the ownership rules so the read path itself is what is exercised."""
    monkeypatch.setattr(config_module, "os", _OsProxy(name="nt", **overrides))


def test_credential_file_must_exist_and_hold_a_bounded_secret(monkeypatch, tmp_path):
    _off_posix(monkeypatch)
    read = config_module._read_credential_file

    assert read(_credential_file(tmp_path, b"secret"), name="site key", maximum=6) == b"secret"
    with pytest.raises(ConfigurationError, match="^site key file is unavailable$"):
        read(tmp_path / "absent", name="site key", maximum=6)
    with pytest.raises(ConfigurationError, match="^site key must contain between 1 and 6 bytes$"):
        read(_credential_file(tmp_path, b"secret!"), name="site key", maximum=6)
    with pytest.raises(ConfigurationError, match="^site key must contain between 1 and 6 bytes$"):
        read(_credential_file(tmp_path, b""), name="site key", maximum=6)


def test_credential_file_read_fault_is_reported_and_the_file_closed(monkeypatch, tmp_path):
    path = _credential_file(tmp_path, b"secret")
    closed = []
    real_close = os.close

    def fail(descriptor, size):
        raise OSError("synthetic read fault")

    def close(descriptor):
        closed.append(descriptor)
        real_close(descriptor)

    _off_posix(monkeypatch, read=fail, close=close)

    with pytest.raises(ConfigurationError, match="^site key file is unreadable$"):
        config_module._read_credential_file(path, name="site key", maximum=64)
    assert len(closed) == 1


@pytest.mark.parametrize(
    ("content", "expected"),
    [(b"token\n", b"token"), (b"token\r\n", b"token"), (b"token", b"token"),
     (b"token\n\n", b"token\n"), (b" token \n", b" token ")],
)
def test_admin_token_loses_one_line_ending_and_nothing_else(
    monkeypatch, tmp_path, content, expected,
):
    _off_posix(monkeypatch)
    loaded = AppConfig(admin_credential_path=_credential_file(tmp_path.resolve(), content))

    assert loaded.load_admin_secret() == expected


@pytest.mark.parametrize("content", [b"\n", b"\r\n"])
def test_admin_token_file_with_only_a_line_ending_holds_no_token(
    monkeypatch, tmp_path, content,
):
    _off_posix(monkeypatch)
    loaded = AppConfig(admin_credential_path=_credential_file(tmp_path.resolve(), content))

    with pytest.raises(ConfigurationError, match="admin credential file holds no token"):
        loaded.load_admin_secret()
