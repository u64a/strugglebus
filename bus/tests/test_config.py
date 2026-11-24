import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from strugglebus.config import (
    DEFAULT_ADMIN_CREDENTIAL_PATH,
    DEFAULT_AUTHENTICATED_REQUESTS_PER_MINUTE,
    DEFAULT_DATABASE_PATH,
    DEFAULT_MAX_CHANNELS,
    DEFAULT_MESSAGE_BYTES,
    DEFAULT_RELEASE_ID,
    DEFAULT_ROE_ENFORCEMENT_MODE,
    DEFAULT_SSE_MAX_CONNECTIONS_PER_AGENT,
    DEFAULT_TRUSTED_PROXY_SOURCES,
    DEFAULT_UNAUTHENTICATED_REQUESTS_PER_MINUTE,
    AppConfig,
    _classify_systemd_credential_directory,
    _systemd_credential_context,
    _validate_credential_metadata,
)
from strugglebus.errors import ConfigurationError
from dataclasses import replace


RECONNECT_SETTINGS = [
    ("orientation_count_cap", 500, 10_000),
    ("orientation_channel_cap", 50, 1_000),
    ("orientation_candidate_limit", 4096, 100_000),
    ("catch_up_candidate_limit", 4096, 100_000),
    ("catch_up_drain_ttl_seconds", 300, 3_600),
    ("catch_up_max_drains", 256, 1_024),
    ("catch_up_max_drains_per_agent", 16, 16),
]


@pytest.mark.parametrize("field,default,maximum", RECONNECT_SETTINGS)
def test_reconnect_settings_are_defaulted_parsed_and_bounded(field, default, maximum):
    assert getattr(AppConfig(), field) == default
    assert getattr(AppConfig.from_env({
        "STRUGGLEBUS_" + field.upper(): str(default),
    }), field) == default
    for value in (True, 0, -1, maximum + 1, "5"):
        with pytest.raises(ConfigurationError, match=field):
            replace(AppConfig(), **{field: value})


def test_reconnect_per_agent_capacity_cannot_exceed_global():
    with pytest.raises(ConfigurationError, match="per_agent"):
        replace(AppConfig(), catch_up_max_drains=1)


def test_shutdown_grace_is_bounded_below_the_unit_stop_timeout() -> None:
    """The default must lose the race against systemd, not win it.

    A graceful shutdown that outlives TimeoutStopSec (30s in the deployed unit)
    is killed, and the resulting failed unit state blocks maintenance from
    continuing. The upper bound exists so a configuration mistake cannot
    reintroduce that; the lower bound stops a value so small it truncates
    legitimate in-flight work.
    """

    assert AppConfig().shutdown_grace_seconds == 10
    assert AppConfig().shutdown_grace_seconds < 30
    assert AppConfig.from_env({
        "STRUGGLEBUS_SHUTDOWN_GRACE_SECONDS": "20",
    }).shutdown_grace_seconds == 20
    for value in (True, 0, -1, 61, "5"):
        with pytest.raises(ConfigurationError, match="shutdown_grace_seconds"):
            replace(AppConfig(), shutdown_grace_seconds=value)


def test_production_defaults_are_bounded_and_file_backed() -> None:
    config = AppConfig()

    assert config.database_path == DEFAULT_DATABASE_PATH
    assert config.admin_credential_path == DEFAULT_ADMIN_CREDENTIAL_PATH
    assert config.max_message_bytes == DEFAULT_MESSAGE_BYTES == 1024 * 1024
    assert (
        config.authenticated_requests_per_minute
        == DEFAULT_AUTHENTICATED_REQUESTS_PER_MINUTE
        == 600
    )
    assert "*" not in config.allowed_hosts
    assert config.max_channels == DEFAULT_MAX_CHANNELS == 1_000
    assert (
        config.unauthenticated_requests_per_minute
        == DEFAULT_UNAUTHENTICATED_REQUESTS_PER_MINUTE
        == 60
    )
    assert config.trusted_proxy_sources == DEFAULT_TRUSTED_PROXY_SOURCES
    assert (
        config.sse_max_connections_per_agent
        == DEFAULT_SSE_MAX_CONNECTIONS_PER_AGENT
        == 3
    )
    assert config.bind_host == "127.0.0.1"
    assert config.bind_port == 8080
    assert config.release_id == DEFAULT_RELEASE_ID == "development"
    assert config.roe_enforcement_mode == DEFAULT_ROE_ENFORCEMENT_MODE == "observe"


def test_environment_configuration_is_typed_and_never_loads_secret_from_env(
    tmp_path: Path,
) -> None:
    config = AppConfig.from_env(
        {
            "STRUGGLEBUS_DATA_DIR": str(tmp_path),
            "STRUGGLEBUS_RUNTIME_DIR": str(tmp_path / "run"),
            "STRUGGLEBUS_ADMIN_CREDENTIAL_PATH": str(tmp_path / "admin-token"),
            "STRUGGLEBUS_MAX_MESSAGE_BYTES": "2048",
            "STRUGGLEBUS_AUTHENTICATED_REQUESTS_PER_MINUTE": "42",
            "STRUGGLEBUS_UNAUTHENTICATED_REQUESTS_PER_MINUTE": "7",
            "STRUGGLEBUS_MAX_CHANNELS": "12",
            "STRUGGLEBUS_SSE_MAX_CONNECTIONS_PER_AGENT": "4",
            "STRUGGLEBUS_TRUSTED_PROXY_SOURCES": "127.0.0.1",
            "STRUGGLEBUS_ALLOWED_HOSTS": "bus.lan,localhost:*",
            "STRUGGLEBUS_ALLOWED_ORIGINS": "https://bus.lan",
            "STRUGGLEBUS_ADMIN_SECRET": "must-not-be-read",
            "STRUGGLEBUS_BIND_HOST": "::1",
            "STRUGGLEBUS_BIND_PORT": "9090",
            "STRUGGLEBUS_RELEASE_ID": "release-2026.08.30",
            "STRUGGLEBUS_ROE_ENFORCEMENT_MODE": "enforce",
        }
    )

    assert config.database_path == tmp_path / "strugglebus.db"
    assert config.backup_dir == tmp_path / "backups"
    assert config.max_message_bytes == 2048
    assert config.authenticated_requests_per_minute == 42
    assert config.unauthenticated_requests_per_minute == 7
    assert config.max_channels == 12
    assert config.sse_max_connections_per_agent == 4
    assert config.trusted_proxy_sources == ("127.0.0.1",)
    assert config.allowed_hosts == ("bus.lan", "localhost:*")
    assert config.admin_secret is None
    assert config.bind_host == "::1"
    assert config.bind_port == 9090
    assert config.release_id == "release-2026.08.30"
    assert config.roe_enforcement_mode == "enforce"


@pytest.mark.parametrize(
    "overrides",
    [
        {"database_path": Path("relative.db")},
        {"max_message_bytes": 0},
        {"max_message_bytes": "1024"},
        {"authenticated_requests_per_minute": -1},
        {"unauthenticated_requests_per_minute": 0},
        {"max_channels": 0},
        {"max_channels": 1},
        {"release_id": ""},
        {"release_id": "bad release"},
        {"release_id": "x" * 65},
        {"roe_enforcement_mode": "off"},
        {"max_rest_request_body_bytes": 1024},
        {"sse_poll_interval_ms": 9},
        {"sse_poll_interval_ms": 10_001},
        {"sse_heartbeat_seconds": 301},
        {"sse_max_connections_per_agent": 11},
        {"trusted_proxy_sources": ["127.0.0.1"]},
        {"allowed_hosts": ()},
        {"allowed_hosts": ("*",)},
        {"allowed_hosts": ["bus.lan"]},
        {"public_base_url": "https://bus.lan/path"},
        {"public_base_url": "http://bus.lan"},
        {"public_base_url": 7},
        {"public_base_url": "https://[::1"},
        {"public_base_url": "https://bus.lan:invalid"},
        {"public_base_url": "https://bus.lan:0"},
        {"bind_host": "0.0.0.0"},
        {"bind_host": "localhost"},
        {"bind_port": 0},
        {"bind_port": 65_536},
        {"admin_credential_path": None},
        {
            "admin_credential_path": None,
            "admin_secret": b"",
        },
        {
            "admin_credential_path": None,
            "admin_secret": "not-bytes",
        },
        {
            "admin_credential_path": Path("/run/secret"),
            "admin_secret": b"also-set",
        },
    ],
)
def test_invalid_or_ambiguous_configuration_fails_closed(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ConfigurationError):
        AppConfig(**overrides)


def test_loaded_admin_secret_is_redacted_from_config_representation() -> None:
    secret = b"test-only-sensitive-value"
    config = AppConfig(admin_credential_path=None, admin_secret=secret)

    assert config.load_admin_secret() == secret
    assert secret.decode() not in repr(config)


def test_unavailable_credential_file_fails_closed(tmp_path: Path) -> None:
    config = AppConfig(admin_credential_path=tmp_path / "missing")

    with pytest.raises(
        ConfigurationError, match="credential file is unavailable"
    ):
        config.load_admin_secret()


@pytest.mark.parametrize("mode", [0o400, 0o600])
def test_secure_systemd_credential_modes_are_accepted(mode: int) -> None:
    metadata = SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=0)

    _validate_credential_metadata(metadata, require_root_owner=True)


def test_systemd_runtime_user_owned_credential_is_accepted() -> None:
    metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o400, st_uid=1000)

    _validate_credential_metadata(
        metadata,
        require_root_owner=True,
        runtime_uid=1000,
    )


def test_systemd_root_group_runtime_projection_is_accepted() -> None:
    metadata = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o440,
        st_uid=0,
        st_gid=0,
    )

    _validate_credential_metadata(
        metadata,
        require_root_owner=True,
        runtime_uid=1000,
        protected_systemd_projection=True,
    )


@pytest.mark.parametrize(
    ("owner", "group", "mode", "protected"),
    [
        (0, 0, 0o440, False),
        (1000, 0, 0o440, True),
        (0, 1000, 0o440, True),
        (0, 0, 0o460, True),
        (0, 0, 0o640, True),
        (0, 0, 0o660, True),
        (0, 0, 0o444, True),
    ],
)
def test_unsafe_systemd_projection_is_rejected(
    owner: int,
    group: int,
    mode: int,
    protected: bool,
) -> None:
    metadata = SimpleNamespace(
        st_mode=stat.S_IFREG | mode,
        st_uid=owner,
        st_gid=group,
    )

    with pytest.raises(ConfigurationError, match="unsafe ownership"):
        _validate_credential_metadata(
            metadata,
            require_root_owner=True,
            runtime_uid=1000,
            protected_systemd_projection=protected,
        )


def test_production_systemd_credential_directory_shape_is_accepted() -> None:
    metadata = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o550,
        st_uid=0,
        st_gid=0,
    )

    assert _classify_systemd_credential_directory(
        metadata,
        runtime_uid=1000,
    ) == (True, True)


@pytest.mark.parametrize(
    ("owner", "group", "mode"),
    [
        (0, 1000, 0o550),
        (1000, 0, 0o550),
        (0, 0, 0o570),
        (0, 0, 0o750),
        (0, 0, 0o555),
    ],
)
def test_unsafe_systemd_credential_directory_shape_is_rejected(
    owner: int,
    group: int,
    mode: int,
) -> None:
    metadata = SimpleNamespace(
        st_mode=stat.S_IFDIR | mode,
        st_uid=owner,
        st_gid=group,
    )

    assert _classify_systemd_credential_directory(
        metadata,
        runtime_uid=1000,
    ) == (False, False)


@pytest.mark.parametrize("configured_directory", [None, "relative/credentials"])
def test_missing_or_relative_systemd_credential_context_is_rejected(
    tmp_path: Path,
    configured_directory: str | None,
) -> None:
    credential = tmp_path / "credentials" / "admin-token"

    assert _systemd_credential_context(
        credential,
        configured_directory,
        runtime_uid=1000,
    ) == (None, False)


def test_missing_systemd_credential_directory_is_rejected(
    tmp_path: Path,
) -> None:
    credential_dir = tmp_path / "missing"

    assert _systemd_credential_context(
        credential_dir / "admin-token",
        str(credential_dir),
        runtime_uid=1000,
    ) == (None, False)


@pytest.mark.skipif(
    os.name != "posix",
    reason="requires POSIX ownership and mode semantics",
)
def test_systemd_credential_context_requires_direct_child_and_safe_parent(
    tmp_path: Path,
) -> None:
    credential_dir = tmp_path / "credentials"
    credential_dir.mkdir(mode=0o700)
    credential_dir.chmod(0o700)
    nested = credential_dir / "nested" / "admin-token"

    assert _systemd_credential_context(
        nested,
        str(credential_dir),
        runtime_uid=os.geteuid(),
    ) == (None, False)

    credential_dir.chmod(0o755)
    assert _systemd_credential_context(
        credential_dir / "admin-token",
        str(credential_dir),
        runtime_uid=os.geteuid(),
    ) == (None, False)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX symlink semantics")
def test_systemd_credential_context_rejects_symlink_parent(
    tmp_path: Path,
) -> None:
    real_directory = tmp_path / "real-credentials"
    real_directory.mkdir(mode=0o700)
    linked_directory = tmp_path / "credentials"
    linked_directory.symlink_to(real_directory, target_is_directory=True)

    assert _systemd_credential_context(
        linked_directory / "admin-token",
        str(linked_directory),
        runtime_uid=os.geteuid(),
    ) == (None, False)


def test_systemd_runtime_credential_directory_is_accepted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential_dir = tmp_path / "credentials"
    credential_dir.mkdir(mode=0o700)
    credential_dir.chmod(0o700)
    credential = credential_dir / "admin-token"
    credential.write_bytes(b"runtime-credential")
    credential.chmod(0o400)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credential_dir))
    config = AppConfig(admin_credential_path=credential)

    assert config.load_admin_secret() == b"runtime-credential"


@pytest.mark.skipif(os.name != "posix", reason="requires O_NOFOLLOW")
def test_systemd_runtime_credential_symlink_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential_dir = tmp_path / "credentials"
    credential_dir.mkdir(mode=0o700)
    target = credential_dir / "target"
    target.write_bytes(b"runtime-credential")
    target.chmod(0o400)
    credential = credential_dir / "admin-token"
    credential.symlink_to(target)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credential_dir))

    with pytest.raises(ConfigurationError, match="unavailable"):
        AppConfig(admin_credential_path=credential).load_admin_secret()


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0,
    reason="requires a non-root POSIX runtime owner",
)
def test_runtime_owned_credential_outside_systemd_directory_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential = tmp_path / "admin-token"
    credential.write_bytes(b"runtime-credential")
    credential.chmod(0o400)
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    config = AppConfig(admin_credential_path=credential)

    with pytest.raises(ConfigurationError, match="unsafe ownership"):
        config.load_admin_secret()


@pytest.mark.parametrize(
    "mode,owner",
    [
        (0o400, 1000),
        (0o640, 0),
        (0o444, 0),
        (0o700, 0),
    ],
)
def test_insecure_credential_metadata_is_rejected(
    mode: int,
    owner: int,
) -> None:
    metadata = SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=owner)

    with pytest.raises(ConfigurationError):
        _validate_credential_metadata(metadata, require_root_owner=True)


def test_non_regular_credential_is_rejected() -> None:
    metadata = SimpleNamespace(st_mode=stat.S_IFDIR | 0o400, st_uid=0)

    with pytest.raises(ConfigurationError, match="regular file"):
        _validate_credential_metadata(metadata, require_root_owner=True)
