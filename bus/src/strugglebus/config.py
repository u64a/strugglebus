"""Typed, fail-closed application configuration."""

from __future__ import annotations

import os
import ipaddress
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from strugglebus.errors import ConfigurationError

DEFAULT_MESSAGE_BYTES = 1024 * 1024
DEFAULT_REQUEST_BODY_BYTES = 1024 * 1024
DEFAULT_METADATA_BYTES = 16 * 1024
MIN_REST_REQUEST_BODY_BYTES = 10 * 1024
DEFAULT_REST_REQUEST_BODY_BYTES = (
    6 * DEFAULT_MESSAGE_BYTES + DEFAULT_METADATA_BYTES + 1024
)
DEFAULT_AUTHENTICATED_REQUESTS_PER_MINUTE = 600
DEFAULT_UNAUTHENTICATED_REQUESTS_PER_MINUTE = 60
DEFAULT_TRUSTED_PROXY_SOURCES = ("127.0.0.1", "::1")
DEFAULT_MAX_CHANNELS = 1_000
DEFAULT_SSE_BATCH_SIZE = 100
DEFAULT_SSE_POLL_INTERVAL_MS = 250
DEFAULT_SSE_HEARTBEAT_SECONDS = 15
DEFAULT_SSE_CONNECTION_SECONDS = 300
DEFAULT_SHUTDOWN_GRACE_SECONDS = 10
DEFAULT_SSE_MAX_CONNECTIONS_PER_AGENT = 3
DEFAULT_HUMAN_ACTIVITY_LIMIT = 100
DEFAULT_RELEASE_ID = "development"
DEFAULT_ROE_ENFORCEMENT_MODE = "observe"
DEFAULT_MAX_ACTIVE_CREDENTIALS = 2
DEFAULT_MAX_PENDING_CREDENTIALS = 1
DEFAULT_CREDENTIAL_PENDING_SECONDS = 15 * 60
DEFAULT_SELF_ROTATIONS_PER_WINDOW = 2
DEFAULT_SELF_ROTATION_WINDOW_SECONDS = 24 * 60 * 60
DEFAULT_ENROLLMENT_TTL_SECONDS = 15 * 60
DEFAULT_MAX_ENROLLMENT_USES = 1
DEFAULT_SPN_PACKAGE_TTL_SECONDS = 300
DEFAULT_SPN_MAX_OUTSTANDING_PACKAGES = 32
DEFAULT_SPN_ISSUES_PER_MINUTE = 10
DEFAULT_ORIENTATION_COUNT_CAP = 500
DEFAULT_ORIENTATION_CHANNEL_CAP = 50
DEFAULT_ORIENTATION_CANDIDATE_LIMIT = 4096
DEFAULT_CATCH_UP_CANDIDATE_LIMIT = 4096
DEFAULT_CATCH_UP_DRAIN_TTL_SECONDS = 300
DEFAULT_CATCH_UP_MAX_DRAINS = 256
DEFAULT_CATCH_UP_MAX_DRAINS_PER_AGENT = 16
RECONNECT_SETTING_LIMITS = {
    "orientation_count_cap": 10_000,
    "orientation_channel_cap": 1_000,
    "orientation_candidate_limit": 100_000,
    "catch_up_candidate_limit": 100_000,
    "catch_up_drain_ttl_seconds": 3_600,
    "catch_up_max_drains": 1_024,
    "catch_up_max_drains_per_agent": 16,
}
OPERATOR_SETTING_BOUNDS = {
    "operator_session_seconds": (60, 28_800),
    "operator_session_idle_seconds": (60, 3_600),
    "operator_max_sessions": (1, 64),
    "operator_login_source_per_minute": (1, 20),
    "operator_login_global_per_minute": (1, 100),
    "operator_password_workers": (1, 4),
    "operator_form_bytes": (2_048, 16_384),
    "operator_form_timeout_seconds": (1, 30),
    "reconnect_grant_seconds": (60, 900),
    "reconnect_max_grants": (1, 1_024),
    "reconnect_issue_session_per_minute": (1, 20),
    "reconnect_issue_global_per_minute": (1, 100),
    "reconnect_redeem_source_per_minute": (1, 60),
    "reconnect_redeem_global_per_minute": (1, 300),
    # A device enrollment is displayed on a screen rather than handed over a
    # private channel, and it grants an operator-class read surface, so its
    # window is bounded far below the agent default of fifteen minutes.
    "mobile_enrollment_seconds": (120, 300),
    "mobile_enroll_session_per_minute": (1, 20),
    "mobile_enroll_global_per_minute": (1, 100),
    # A confirmation is spent by an app the owner is holding, so it needs only
    # enough life to read the described effect and present a fingerprint. Long
    # enough to bank confirmations in advance would defeat the point of binding
    # them to one action.
    "mobile_confirmation_seconds": (30, 300),
    # Establishing a grant is the one mobile call that verifies the operator
    # password, on a worker pool shared with console login. Kept deliberately
    # small: it is a once-per-device operation, not a routine one.
    "mobile_grant_device_per_minute": (1, 10),
    "mobile_grant_global_per_minute": (1, 30),
    # Satellites renew well before expiry, so a short life bounds what a
    # copied site key is worth without making renewal a routine risk.
    "satellite_cert_days": (1, 90),
    "satellite_port": (1, 65_535),
    "updater_confirm_session_per_minute": (1, 3),
    "updater_confirm_global_per_minute": (1, 6),
    "updater_review_seconds": (1, 300),
    "updater_review_tickets": (1, 8),
}
_RELEASE_ID = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$")
if os.name == "nt":
    _PROGRAM_DATA = Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData"))
    DEFAULT_DATA_DIR = _PROGRAM_DATA / "strugglebus"
    DEFAULT_RUNTIME_DIR = DEFAULT_DATA_DIR / "run"
    DEFAULT_ADMIN_CREDENTIAL_PATH = DEFAULT_DATA_DIR / "admin-token"
else:
    DEFAULT_DATA_DIR = Path("/var/lib/strugglebus")
    DEFAULT_RUNTIME_DIR = Path("/run/strugglebus")
    DEFAULT_ADMIN_CREDENTIAL_PATH = Path(
        "/run/credentials/strugglebus/admin-token"
    )
DEFAULT_BACKUP_DIR = DEFAULT_DATA_DIR / "backups"
DEFAULT_DATABASE_PATH = DEFAULT_DATA_DIR / "strugglebus.db"
DEFAULT_ALLOWED_HOSTS = (
    "bus.lan",
    "bus.lan:*",
    "127.0.0.1:*",
    "localhost:*",
    "[::1]:*",
    "testserver",
)
DEFAULT_ALLOWED_ORIGINS = (
    "https://bus.lan",
    "http://127.0.0.1:*",
    "http://localhost:*",
    "http://[::1]:*",
)


def _positive_integer(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ConfigurationError(f"{name} must be a positive integer")


def _absolute_path(name: str, value: Path) -> None:
    if not value.is_absolute():
        raise ConfigurationError(f"{name} must be an absolute path")


def _local_socket_path(name: str, path: Path) -> None:
    _absolute_path(name, path)
    if ".." in path.parts or any(ord(char) < 32 or ord(char) == 127 for char in str(path)):
        raise ConfigurationError(f"{name} is invalid")
    if str(path).startswith("\\\\") or (os.name == "posix" and len(os.fsencode(path)) > 107):
        raise ConfigurationError(f"{name} is not a supported local socket path")


def validate_reconnect_settings(settings: Mapping[str, int]) -> None:
    for name, maximum in RECONNECT_SETTING_LIMITS.items():
        value = settings[name]
        _positive_integer(name, value)
        if value > maximum:
            raise ConfigurationError(f"{name} must not exceed {maximum}")
    if settings["catch_up_max_drains_per_agent"] > settings["catch_up_max_drains"]:
        raise ConfigurationError(
            "catch_up_max_drains_per_agent must not exceed catch_up_max_drains"
        )


def _is_protected_root_group_file(metadata: os.stat_result) -> bool:
    """Match systemd's root:root 0440 projection inside a protected directory."""
    return (
        metadata.st_uid == 0
        and metadata.st_gid == 0
        and stat.S_IMODE(metadata.st_mode) == 0o440
    )


def _validate_credential_metadata(
    metadata: os.stat_result,
    *,
    require_root_owner: bool,
    runtime_uid: int | None = None,
    protected_systemd_projection: bool = False,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise ConfigurationError(
            "admin credential path must be a regular file"
        )
    allowed_owners = {0}
    if runtime_uid is not None:
        allowed_owners.add(runtime_uid)
    mode = stat.S_IMODE(metadata.st_mode)
    protected_root_group_file = (
        protected_systemd_projection
        and _is_protected_root_group_file(metadata)
    )
    if require_root_owner and (
        metadata.st_uid not in allowed_owners
        or (mode not in {0o400, 0o600} and not protected_root_group_file)
    ):
        raise ConfigurationError(
            "admin credential file has unsafe ownership or permissions"
        )


def _classify_systemd_credential_directory(
    metadata: os.stat_result,
    *,
    runtime_uid: int,
) -> tuple[bool, bool]:
    if not stat.S_ISDIR(metadata.st_mode):
        return False, False
    mode = stat.S_IMODE(metadata.st_mode)
    protected_root_directory = (
        metadata.st_uid == 0
        and metadata.st_gid == 0
        and mode == 0o550
    )
    protected_runtime_directory = (
        metadata.st_uid == runtime_uid
        and mode in {0o500, 0o700}
    )
    return (
        protected_root_directory or protected_runtime_directory,
        protected_root_directory,
    )


def _systemd_credential_context(
    path: Path,
    configured_directory: str | None,
    *,
    runtime_uid: int,
) -> tuple[int | None, bool]:
    if configured_directory is None:
        return None, False
    directory = Path(configured_directory)
    if (
        not directory.is_absolute()
        or path.parent != directory
        or directory != directory.absolute()
    ):
        return None, False
    try:
        metadata = directory.lstat()
        canonical_directory = directory.resolve(strict=True)
    except (OSError, RuntimeError):
        return None, False
    if canonical_directory != directory:
        return None, False
    protected, allow_root_group_file = (
        _classify_systemd_credential_directory(
            metadata,
            runtime_uid=runtime_uid,
        )
    )
    if not protected:
        return None, False
    return runtime_uid, allow_root_group_file


def _parse_positive_integer(environment: Mapping[str, str], name: str, default: int) -> int:
    raw_value = environment.get(name)
    if raw_value is None:
        return default
    try:
        value = int(raw_value)
    except ValueError as error:
        raise ConfigurationError(f"{name} must be a positive integer") from error
    _positive_integer(name, value)
    return value


def _parse_csv(
    environment: Mapping[str, str],
    name: str,
    default: tuple[str, ...],
) -> tuple[str, ...]:
    raw_value = environment.get(name)
    if raw_value is None:
        return default
    return tuple(part.strip() for part in raw_value.split(",") if part.strip())


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Validated settings shared by the application, store, and transports."""

    database_path: Path = DEFAULT_DATABASE_PATH
    data_dir: Path = DEFAULT_DATA_DIR
    runtime_dir: Path = DEFAULT_RUNTIME_DIR
    backup_dir: Path = DEFAULT_BACKUP_DIR
    admin_credential_path: Path | None = DEFAULT_ADMIN_CREDENTIAL_PATH
    admin_secret: bytes | None = field(default=None, repr=False, compare=False)
    operator_credential_path: Path | None = None
    operator_session_seconds: int = 28_800
    """Absolute session lifetime, fixed at login and never extended."""
    operator_session_idle_seconds: int = 1_800
    """Sliding idle window, refreshed by console activity. Effectively clamped
    to operator_session_seconds when configured larger than it."""
    operator_max_sessions: int = 16
    operator_login_source_per_minute: int = 5
    operator_login_global_per_minute: int = 20
    operator_password_workers: int = 2
    operator_form_bytes: int = 8_192
    operator_form_timeout_seconds: int = 10
    reconnect_grant_seconds: int = 900
    reconnect_max_grants: int = 256
    reconnect_issue_session_per_minute: int = 5
    reconnect_issue_global_per_minute: int = 20
    reconnect_redeem_source_per_minute: int = 10
    reconnect_redeem_global_per_minute: int = 60
    mobile_enrollment_seconds: int = 180
    """Device enrollment lifetime. Deliberately minutes, not the agent default."""
    mobile_enroll_session_per_minute: int = 5
    mobile_enroll_global_per_minute: int = 20
    mobile_confirmation_seconds: int = 120
    """How long a device action confirmation stays spendable."""
    mobile_grant_device_per_minute: int = 3
    mobile_grant_global_per_minute: int = 10
    updater_socket_path: Path | None = None
    maintenance_socket_path: Path | None = None
    satellite_hostname: str = ""
    """Public gateway hostname satellites connect to; empty disables sites."""
    satellite_port: int = 443
    satellite_ca_cert_path: Path | None = None
    satellite_ca_key_path: Path | None = None
    satellite_gateway_wg_address: str = ""
    """The gateway's tunnel address: every satellite request arrives from it."""
    satellite_cert_days: int = 30
    updater_confirm_session_per_minute: int = 3
    updater_confirm_global_per_minute: int = 6
    updater_review_seconds: int = 300
    updater_review_tickets: int = 8
    # Retired presentation settings, accepted and ignored. A unit rendered for
    # an earlier release may still set them, and maintenance validation rejects
    # a candidate that does not declare every configured setting. Remove them
    # once no deployed unit sets STRUGGLEBUS_PRESENTATION_*.
    presentation_catalog_dir: object = None
    presentation_css_bytes: object = None
    presentation_descriptor_bytes: object = None
    presentation_catalog_bytes: object = None
    presentation_catalog_entries: object = None
    presentation_object_bytes: object = None
    presentation_state_bytes: object = None
    presentation_receipts: object = None
    presentation_preparations: object = None
    presentation_preparations_per_session: object = None
    presentation_preparation_seconds: object = None
    presentation_workers: object = None
    presentation_lock_timeout_ms: object = None
    presentation_confirm_session_per_minute: object = None
    presentation_confirm_global_per_minute: object = None
    max_message_bytes: int = DEFAULT_MESSAGE_BYTES
    max_request_body_bytes: int = DEFAULT_REQUEST_BODY_BYTES
    max_metadata_bytes: int = DEFAULT_METADATA_BYTES
    max_rest_request_body_bytes: int = DEFAULT_REST_REQUEST_BODY_BYTES
    authenticated_requests_per_minute: int = (
        DEFAULT_AUTHENTICATED_REQUESTS_PER_MINUTE
    )
    unauthenticated_requests_per_minute: int = (
        DEFAULT_UNAUTHENTICATED_REQUESTS_PER_MINUTE
    )
    trusted_proxy_sources: tuple[str, ...] = DEFAULT_TRUSTED_PROXY_SOURCES
    max_channels: int = DEFAULT_MAX_CHANNELS
    orientation_count_cap: int = DEFAULT_ORIENTATION_COUNT_CAP
    orientation_channel_cap: int = DEFAULT_ORIENTATION_CHANNEL_CAP
    orientation_candidate_limit: int = DEFAULT_ORIENTATION_CANDIDATE_LIMIT
    catch_up_candidate_limit: int = DEFAULT_CATCH_UP_CANDIDATE_LIMIT
    catch_up_drain_ttl_seconds: int = DEFAULT_CATCH_UP_DRAIN_TTL_SECONDS
    catch_up_max_drains: int = DEFAULT_CATCH_UP_MAX_DRAINS
    catch_up_max_drains_per_agent: int = DEFAULT_CATCH_UP_MAX_DRAINS_PER_AGENT
    sqlite_busy_timeout_ms: int = 5_000
    liveness_refresh_seconds: int = 60
    """How stale a last-used/last-seen timestamp may be before authentication
    takes a write transaction to refresh it. Authentication is otherwise a
    write on every request, including pure reads."""
    sse_batch_size: int = DEFAULT_SSE_BATCH_SIZE
    sse_poll_interval_ms: int = DEFAULT_SSE_POLL_INTERVAL_MS
    sse_heartbeat_seconds: int = DEFAULT_SSE_HEARTBEAT_SECONDS
    sse_connection_seconds: int = DEFAULT_SSE_CONNECTION_SECONDS
    sse_max_connections_per_agent: int = DEFAULT_SSE_MAX_CONNECTIONS_PER_AGENT
    shutdown_grace_seconds: int = DEFAULT_SHUTDOWN_GRACE_SECONDS
    """Hard bound on graceful shutdown.

    A stop that outlives the unit's stop timeout is killed, which leaves the
    service failed and blocks a deployment from continuing. Keep this well
    below TimeoutStopSec so the application always loses that race."""
    human_activity_limit: int = DEFAULT_HUMAN_ACTIVITY_LIMIT
    release_id: str = DEFAULT_RELEASE_ID
    roe_enforcement_mode: Literal["observe", "enforce"] = (
        DEFAULT_ROE_ENFORCEMENT_MODE
    )
    max_active_credentials_per_agent: int = DEFAULT_MAX_ACTIVE_CREDENTIALS
    max_pending_credentials_per_agent: int = DEFAULT_MAX_PENDING_CREDENTIALS
    credential_pending_seconds: int = DEFAULT_CREDENTIAL_PENDING_SECONDS
    self_rotations_per_window: int = DEFAULT_SELF_ROTATIONS_PER_WINDOW
    self_rotation_window_seconds: int = DEFAULT_SELF_ROTATION_WINDOW_SECONDS
    enrollment_ttl_seconds: int = DEFAULT_ENROLLMENT_TTL_SECONDS
    max_enrollment_uses: int = DEFAULT_MAX_ENROLLMENT_USES
    spn_package_ttl_seconds: int = DEFAULT_SPN_PACKAGE_TTL_SECONDS
    spn_max_outstanding_packages: int = DEFAULT_SPN_MAX_OUTSTANDING_PACKAGES
    spn_issues_per_minute: int = DEFAULT_SPN_ISSUES_PER_MINUTE
    ca_bundle_path: str = ""
    ca_root_sha256: str = ""
    public_base_url: str = "https://bus.lan"
    bind_host: str = "127.0.0.1"
    bind_port: int = 8080
    allowed_hosts: tuple[str, ...] = DEFAULT_ALLOWED_HOSTS
    allowed_origins: tuple[str, ...] = DEFAULT_ALLOWED_ORIGINS

    def __post_init__(self) -> None:
        self._validate_paths()
        self._validate_admin_credentials()
        self._validate_operator_settings()
        self._validate_message_limits()
        self._validate_stream_limits()
        self._validate_identity_limits()
        self._validate_ca_settings()
        self._validate_public_url()
        self._validate_listener()
        self._validate_allowed_hosts()
        self._validate_allowed_origins()
        self._validate_proxy_sources()
        self._validate_updater_socket()
        self._validate_satellite()

    @property
    def satellite_enabled(self) -> bool:
        return bool(self.satellite_hostname)

    def _validate_satellite(self) -> None:
        values = (
            self.satellite_hostname, self.satellite_ca_cert_path,
            self.satellite_ca_key_path,
        )
        if not any(values):
            return
        if not all(values):
            raise ConfigurationError(
                "satellite_hostname, satellite_ca_cert_path and "
                "satellite_ca_key_path must all be set or all be empty"
            )
        if len(self.satellite_hostname) > 253 or not re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
            self.satellite_hostname,
        ):
            raise ConfigurationError(
                "satellite_hostname must be a lowercase public DNS name"
            )
        try:
            ipaddress.ip_address(self.satellite_gateway_wg_address)
        except ValueError:
            raise ConfigurationError(
                "satellite_gateway_wg_address must be the gateway's tunnel address"
            ) from None
        for name in ("satellite_ca_cert_path", "satellite_ca_key_path"):
            path = getattr(self, name)
            if not isinstance(path, Path):
                raise ConfigurationError(f"{name} must be a pathlib.Path")
            _absolute_path(name, path)

    def _validate_updater_socket(self) -> None:
        for name in ("updater_socket_path", "maintenance_socket_path"):
            path = getattr(self, name)
            if path is None:
                continue
            if not isinstance(path, Path):
                raise ConfigurationError(f"{name} must be a pathlib.Path")
            _local_socket_path(name, path)
            if any(
                path.is_relative_to(writable) or writable.is_relative_to(path)
                for writable in (self.data_dir, self.runtime_dir, self.backup_dir)
            ):
                raise ConfigurationError(
                    f"{name} must be outside application-writable paths"
                )

    def _validate_paths(self) -> None:
        for name in ("database_path", "data_dir", "runtime_dir", "backup_dir"):
            value = getattr(self, name)
            if not isinstance(value, Path):
                raise ConfigurationError(f"{name} must be a pathlib.Path")
            _absolute_path(name, value)

    def _validate_admin_credentials(self) -> None:
        if self.admin_credential_path is not None:
            if not isinstance(self.admin_credential_path, Path):
                raise ConfigurationError(
                    "admin_credential_path must be a pathlib.Path"
                )
            _absolute_path("admin_credential_path", self.admin_credential_path)
        if (self.admin_credential_path is None) == (self.admin_secret is None):
            raise ConfigurationError(
                "configure exactly one of admin_credential_path or admin_secret"
            )
        if self.admin_secret is not None:
            if not isinstance(self.admin_secret, bytes) or not self.admin_secret:
                raise ConfigurationError(
                    "admin_secret must be non-empty bytes"
                )

    def _validate_operator_settings(self) -> None:
        if self.operator_credential_path is not None:
            if not isinstance(self.operator_credential_path, Path):
                raise ConfigurationError(
                    "operator_credential_path must be a pathlib.Path"
                )
            _absolute_path("operator_credential_path", self.operator_credential_path)
        for name, (minimum, maximum) in OPERATOR_SETTING_BOUNDS.items():
            value = getattr(self, name)
            _positive_integer(name, value)
            if not minimum <= value <= maximum:
                raise ConfigurationError(
                    f"{name} must be between {minimum} and {maximum}"
                )

    def _validate_message_limits(self) -> None:
        _positive_integer("max_message_bytes", self.max_message_bytes)
        _positive_integer("max_request_body_bytes", self.max_request_body_bytes)
        _positive_integer("max_metadata_bytes", self.max_metadata_bytes)
        _positive_integer(
            "max_rest_request_body_bytes",
            self.max_rest_request_body_bytes,
        )
        minimum_rest_body_bytes = max(
            6 * self.max_message_bytes + self.max_metadata_bytes + 1024,
            MIN_REST_REQUEST_BODY_BYTES,
        )
        if self.max_rest_request_body_bytes < minimum_rest_body_bytes:
            raise ConfigurationError(
                "max_rest_request_body_bytes is too small for configured "
                "message and metadata limits"
            )
        _positive_integer(
            "authenticated_requests_per_minute",
            self.authenticated_requests_per_minute,
        )
        _positive_integer(
            "unauthenticated_requests_per_minute",
            self.unauthenticated_requests_per_minute,
        )
        _positive_integer("sqlite_busy_timeout_ms", self.sqlite_busy_timeout_ms)
        _positive_integer("max_channels", self.max_channels)
        validate_reconnect_settings({
            name: getattr(self, name) for name in RECONNECT_SETTING_LIMITS
        })

    def _validate_stream_limits(self) -> None:
        _positive_integer("sse_batch_size", self.sse_batch_size)
        _positive_integer("sse_poll_interval_ms", self.sse_poll_interval_ms)
        _positive_integer("sse_heartbeat_seconds", self.sse_heartbeat_seconds)
        _positive_integer("sse_connection_seconds", self.sse_connection_seconds)
        _positive_integer(
            "sse_max_connections_per_agent",
            self.sse_max_connections_per_agent,
        )
        _positive_integer("human_activity_limit", self.human_activity_limit)
        _positive_integer("shutdown_grace_seconds", self.shutdown_grace_seconds)
        if not 1 <= self.shutdown_grace_seconds <= 60:
            # Bounded on both sides deliberately. Too small truncates a legitimate
            # in-flight request; too large loses the race against the unit's stop
            # timeout, which is the failure this setting exists to prevent.
            raise ConfigurationError(
                "shutdown_grace_seconds must be between 1 and 60"
            )
        if self.sse_batch_size > 200:
            raise ConfigurationError("sse_batch_size must not exceed 200")
        if self.sse_connection_seconds > 3_600:
            raise ConfigurationError(
                "sse_connection_seconds must not exceed 3600"
            )
        if not 10 <= self.sse_poll_interval_ms <= 10_000:
            raise ConfigurationError(
                "sse_poll_interval_ms must be between 10 and 10000"
            )
        if self.sse_heartbeat_seconds > 300:
            raise ConfigurationError(
                "sse_heartbeat_seconds must not exceed 300"
            )
        if self.sse_max_connections_per_agent > 10:
            raise ConfigurationError(
                "sse_max_connections_per_agent must not exceed 10"
            )
        if self.human_activity_limit > 200:
            raise ConfigurationError("human_activity_limit must not exceed 200")

    def _validate_identity_limits(self) -> None:
        if self.max_channels < 3:
            raise ConfigurationError(
                "max_channels must accommodate the original three default channels"
            )
        if (
            not isinstance(self.release_id, str)
            or _RELEASE_ID.fullmatch(self.release_id) is None
        ):
            raise ConfigurationError(
                "release_id must be 1-64 safe identifier characters"
            )
        if self.roe_enforcement_mode not in {"observe", "enforce"}:
            raise ConfigurationError(
                "roe_enforcement_mode must be observe or enforce"
            )
        for name, maximum in (
            ("max_active_credentials_per_agent", 8),
            ("max_pending_credentials_per_agent", 4),
            ("credential_pending_seconds", 86_400),
            ("self_rotations_per_window", 24),
            ("self_rotation_window_seconds", 7 * 86_400),
            ("enrollment_ttl_seconds", 86_400),
            ("max_enrollment_uses", 64),
            ("spn_package_ttl_seconds", 900),
            ("spn_max_outstanding_packages", 1024),
            ("spn_issues_per_minute", 600),
            ("liveness_refresh_seconds", 3_600),
        ):
            value = getattr(self, name)
            _positive_integer(name, value)
            if value > maximum:
                raise ConfigurationError(f"{name} must not exceed {maximum}")
        if self.spn_package_ttl_seconds < 60:
            raise ConfigurationError(
                "spn_package_ttl_seconds must be at least 60"
            )

    def _validate_ca_settings(self) -> None:
        for name in ("ca_bundle_path", "ca_root_sha256"):
            value = getattr(self, name)
            if not isinstance(value, str):
                raise ConfigurationError(f"{name} must be text")
        if bool(self.ca_bundle_path) != bool(self.ca_root_sha256):
            raise ConfigurationError(
                "ca_bundle_path and ca_root_sha256 must both be set or both be empty"
            )
        if self.ca_bundle_path and not Path(self.ca_bundle_path).is_absolute():
            raise ConfigurationError("ca_bundle_path must be an absolute path")
        if self.ca_root_sha256 and not re.fullmatch(
            r"[0-9a-f]{64}", self.ca_root_sha256
        ):
            raise ConfigurationError(
                "ca_root_sha256 must be a lowercase hex SHA-256 digest"
            )

    def _validate_public_url(self) -> None:
        if not isinstance(self.public_base_url, str):
            raise ConfigurationError("public_base_url must be text")
        try:
            parsed_url = urlsplit(self.public_base_url)
            public_hostname = parsed_url.hostname
            public_port = parsed_url.port
        except ValueError as error:
            raise ConfigurationError(
                "public_base_url must be a valid HTTP(S) URL"
            ) from error
        self._validate_public_origin(
            parsed_url.scheme, parsed_url.netloc, public_hostname, public_port,
        )
        if (
            parsed_url.path not in {"", "/"}
            or parsed_url.query
            or parsed_url.fragment
        ):
            raise ConfigurationError(
                "public_base_url must not include a path, query, or fragment"
            )

    @staticmethod
    def _validate_public_origin(
        scheme: str, netloc: str, public_hostname: str | None,
        public_port: int | None,
    ) -> None:
        if scheme not in {"http", "https"} or not netloc:
            raise ConfigurationError(
                "public_base_url must be an absolute HTTP(S) URL"
            )
        if public_hostname is None or (
            public_port is not None and not 1 <= public_port <= 65_535
        ):
            raise ConfigurationError(
                "public_base_url must contain a valid host and port"
            )
        if scheme != "https" and public_hostname not in {
            "127.0.0.1",
            "::1",
            "localhost",
        }:
            raise ConfigurationError(
                "public_base_url must use HTTPS except for loopback development"
            )

    def _validate_listener(self) -> None:
        if not isinstance(self.bind_host, str):
            raise ConfigurationError("bind_host must be a loopback IP address")
        try:
            bind_address = ipaddress.ip_address(self.bind_host)
        except ValueError as error:
            raise ConfigurationError(
                "bind_host must be a loopback IP address"
            ) from error
        if not bind_address.is_loopback:
            raise ConfigurationError(
                "bind_host must remain loopback-only behind Caddy"
            )
        if (
            isinstance(self.bind_port, bool)
            or not isinstance(self.bind_port, int)
            or not 1 <= self.bind_port <= 65_535
        ):
            raise ConfigurationError("bind_port must be between 1 and 65535")

    def _validate_allowed_hosts(self) -> None:
        if not isinstance(self.allowed_hosts, tuple) or not self.allowed_hosts:
            raise ConfigurationError("allowed_hosts must not be empty")
        if any(
            not isinstance(host, str)
            or not host.strip()
            or host.strip() == "*"
            for host in self.allowed_hosts
        ):
            raise ConfigurationError(
                "allowed_hosts must contain explicit non-empty host patterns"
            )

    def _validate_allowed_origins(self) -> None:
        if not isinstance(self.allowed_origins, tuple) or any(
            not isinstance(origin, str)
            or not origin.strip()
            or origin.strip() == "*"
            for origin in self.allowed_origins
        ):
            raise ConfigurationError(
                "allowed_origins must contain explicit non-empty origin patterns"
            )

    def _validate_proxy_sources(self) -> None:
        if not isinstance(self.trusted_proxy_sources, tuple) or any(
            not isinstance(source, str) or not source.strip()
            for source in self.trusted_proxy_sources
        ):
            raise ConfigurationError(
                "trusted_proxy_sources must contain source addresses"
            )

    @property
    def mcp_resource_url(self) -> str:
        return f"{self.public_base_url.rstrip('/')}/mcp"

    @classmethod
    def from_env(cls, environment: Mapping[str, str] | None = None) -> AppConfig:
        """Load non-secret settings; admin credentials remain file-backed."""

        values = os.environ if environment is None else environment
        data_dir = Path(values.get("STRUGGLEBUS_DATA_DIR", str(DEFAULT_DATA_DIR)))
        runtime_dir = Path(
            values.get("STRUGGLEBUS_RUNTIME_DIR", str(DEFAULT_RUNTIME_DIR))
        )
        database_path = Path(
            values.get(
                "STRUGGLEBUS_DATABASE_PATH",
                str(data_dir / "strugglebus.db"),
            )
        )
        backup_dir = Path(
            values.get("STRUGGLEBUS_BACKUP_DIR", str(data_dir / "backups"))
        )
        credential_path = Path(
            values.get(
                "STRUGGLEBUS_ADMIN_CREDENTIAL_PATH",
                str(DEFAULT_ADMIN_CREDENTIAL_PATH),
            )
        )
        return cls(
            database_path=database_path,
            data_dir=data_dir,
            runtime_dir=runtime_dir,
            backup_dir=backup_dir,
            admin_credential_path=credential_path,
            operator_credential_path=(
                Path(values["STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH"])
                if values.get("STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH")
                else None
            ),
            updater_socket_path=(
                Path(values["STRUGGLEBUS_UPDATER_SOCKET_PATH"])
                if values.get("STRUGGLEBUS_UPDATER_SOCKET_PATH")
                else None
            ),
            maintenance_socket_path=(
                Path(values["STRUGGLEBUS_MAINTENANCE_SOCKET_PATH"])
                if values.get("STRUGGLEBUS_MAINTENANCE_SOCKET_PATH")
                else None
            ),
            satellite_hostname=values.get("STRUGGLEBUS_SATELLITE_HOSTNAME", ""),
            satellite_ca_cert_path=(
                Path(values["STRUGGLEBUS_SATELLITE_CA_CERT_PATH"])
                if values.get("STRUGGLEBUS_SATELLITE_CA_CERT_PATH")
                else None
            ),
            satellite_ca_key_path=(
                Path(values["STRUGGLEBUS_SATELLITE_CA_KEY_PATH"])
                if values.get("STRUGGLEBUS_SATELLITE_CA_KEY_PATH")
                else None
            ),
            satellite_gateway_wg_address=values.get(
                "STRUGGLEBUS_SATELLITE_GATEWAY_WG_ADDRESS", ""
            ),
            **{
                name: _parse_positive_integer(
                    values, "STRUGGLEBUS_" + name.upper(),
                    cls.__dataclass_fields__[name].default,
                )
                for name in OPERATOR_SETTING_BOUNDS
            },
            max_message_bytes=_parse_positive_integer(
                values,
                "STRUGGLEBUS_MAX_MESSAGE_BYTES",
                DEFAULT_MESSAGE_BYTES,
            ),
            max_request_body_bytes=_parse_positive_integer(
                values,
                "STRUGGLEBUS_MAX_REQUEST_BODY_BYTES",
                DEFAULT_REQUEST_BODY_BYTES,
            ),
            max_metadata_bytes=_parse_positive_integer(
                values,
                "STRUGGLEBUS_MAX_METADATA_BYTES",
                DEFAULT_METADATA_BYTES,
            ),
            max_rest_request_body_bytes=_parse_positive_integer(
                values,
                "STRUGGLEBUS_MAX_REST_REQUEST_BODY_BYTES",
                DEFAULT_REST_REQUEST_BODY_BYTES,
            ),
            authenticated_requests_per_minute=_parse_positive_integer(
                values,
                "STRUGGLEBUS_AUTHENTICATED_REQUESTS_PER_MINUTE",
                DEFAULT_AUTHENTICATED_REQUESTS_PER_MINUTE,
            ),
            unauthenticated_requests_per_minute=_parse_positive_integer(
                values,
                "STRUGGLEBUS_UNAUTHENTICATED_REQUESTS_PER_MINUTE",
                DEFAULT_UNAUTHENTICATED_REQUESTS_PER_MINUTE,
            ),
            sqlite_busy_timeout_ms=_parse_positive_integer(
                values,
                "STRUGGLEBUS_SQLITE_BUSY_TIMEOUT_MS",
                5_000,
            ),
            sse_batch_size=_parse_positive_integer(
                values,
                "STRUGGLEBUS_SSE_BATCH_SIZE",
                DEFAULT_SSE_BATCH_SIZE,
            ),
            sse_poll_interval_ms=_parse_positive_integer(
                values,
                "STRUGGLEBUS_SSE_POLL_INTERVAL_MS",
                DEFAULT_SSE_POLL_INTERVAL_MS,
            ),
            sse_heartbeat_seconds=_parse_positive_integer(
                values,
                "STRUGGLEBUS_SSE_HEARTBEAT_SECONDS",
                DEFAULT_SSE_HEARTBEAT_SECONDS,
            ),
            sse_connection_seconds=_parse_positive_integer(
                values,
                "STRUGGLEBUS_SSE_CONNECTION_SECONDS",
                DEFAULT_SSE_CONNECTION_SECONDS,
            ),
            sse_max_connections_per_agent=_parse_positive_integer(
                values,
                "STRUGGLEBUS_SSE_MAX_CONNECTIONS_PER_AGENT",
                DEFAULT_SSE_MAX_CONNECTIONS_PER_AGENT,
            ),
            shutdown_grace_seconds=_parse_positive_integer(
                values,
                "STRUGGLEBUS_SHUTDOWN_GRACE_SECONDS",
                DEFAULT_SHUTDOWN_GRACE_SECONDS,
            ),
            human_activity_limit=_parse_positive_integer(
                values,
                "STRUGGLEBUS_HUMAN_ACTIVITY_LIMIT",
                DEFAULT_HUMAN_ACTIVITY_LIMIT,
            ),
            max_channels=_parse_positive_integer(
                values,
                "STRUGGLEBUS_MAX_CHANNELS",
                DEFAULT_MAX_CHANNELS,
            ),
            orientation_count_cap=_parse_positive_integer(
                values, "STRUGGLEBUS_ORIENTATION_COUNT_CAP",
                DEFAULT_ORIENTATION_COUNT_CAP,
            ),
            orientation_channel_cap=_parse_positive_integer(
                values, "STRUGGLEBUS_ORIENTATION_CHANNEL_CAP",
                DEFAULT_ORIENTATION_CHANNEL_CAP,
            ),
            orientation_candidate_limit=_parse_positive_integer(
                values, "STRUGGLEBUS_ORIENTATION_CANDIDATE_LIMIT",
                DEFAULT_ORIENTATION_CANDIDATE_LIMIT,
            ),
            catch_up_candidate_limit=_parse_positive_integer(
                values, "STRUGGLEBUS_CATCH_UP_CANDIDATE_LIMIT",
                DEFAULT_CATCH_UP_CANDIDATE_LIMIT,
            ),
            catch_up_drain_ttl_seconds=_parse_positive_integer(
                values, "STRUGGLEBUS_CATCH_UP_DRAIN_TTL_SECONDS",
                DEFAULT_CATCH_UP_DRAIN_TTL_SECONDS,
            ),
            catch_up_max_drains=_parse_positive_integer(
                values, "STRUGGLEBUS_CATCH_UP_MAX_DRAINS",
                DEFAULT_CATCH_UP_MAX_DRAINS,
            ),
            catch_up_max_drains_per_agent=_parse_positive_integer(
                values, "STRUGGLEBUS_CATCH_UP_MAX_DRAINS_PER_AGENT",
                DEFAULT_CATCH_UP_MAX_DRAINS_PER_AGENT,
            ),
            liveness_refresh_seconds=_parse_positive_integer(
                values, "STRUGGLEBUS_LIVENESS_REFRESH_SECONDS", 60,
            ),
            release_id=values.get("STRUGGLEBUS_RELEASE_ID", DEFAULT_RELEASE_ID),
            roe_enforcement_mode=values.get(
                "STRUGGLEBUS_ROE_ENFORCEMENT_MODE",
                DEFAULT_ROE_ENFORCEMENT_MODE,
            ),
            max_active_credentials_per_agent=_parse_positive_integer(
                values,
                "STRUGGLEBUS_MAX_ACTIVE_CREDENTIALS_PER_AGENT",
                DEFAULT_MAX_ACTIVE_CREDENTIALS,
            ),
            max_pending_credentials_per_agent=_parse_positive_integer(
                values,
                "STRUGGLEBUS_MAX_PENDING_CREDENTIALS_PER_AGENT",
                DEFAULT_MAX_PENDING_CREDENTIALS,
            ),
            credential_pending_seconds=_parse_positive_integer(
                values,
                "STRUGGLEBUS_CREDENTIAL_PENDING_SECONDS",
                DEFAULT_CREDENTIAL_PENDING_SECONDS,
            ),
            enrollment_ttl_seconds=_parse_positive_integer(
                values,
                "STRUGGLEBUS_ENROLLMENT_TTL_SECONDS",
                DEFAULT_ENROLLMENT_TTL_SECONDS,
            ),
            ca_bundle_path=values.get("STRUGGLEBUS_CA_BUNDLE_PATH", ""),
            ca_root_sha256=values.get("STRUGGLEBUS_CA_ROOT_SHA256", ""),
            max_enrollment_uses=_parse_positive_integer(
                values,
                "STRUGGLEBUS_MAX_ENROLLMENT_USES",
                DEFAULT_MAX_ENROLLMENT_USES,
            ),
            spn_package_ttl_seconds=_parse_positive_integer(
                values,
                "STRUGGLEBUS_SPN_PACKAGE_TTL_SECONDS",
                DEFAULT_SPN_PACKAGE_TTL_SECONDS,
            ),
            spn_max_outstanding_packages=_parse_positive_integer(
                values,
                "STRUGGLEBUS_SPN_MAX_OUTSTANDING_PACKAGES",
                DEFAULT_SPN_MAX_OUTSTANDING_PACKAGES,
            ),
            spn_issues_per_minute=_parse_positive_integer(
                values,
                "STRUGGLEBUS_SPN_ISSUES_PER_MINUTE",
                DEFAULT_SPN_ISSUES_PER_MINUTE,
            ),
            self_rotations_per_window=_parse_positive_integer(
                values,
                "STRUGGLEBUS_SELF_ROTATIONS_PER_WINDOW",
                DEFAULT_SELF_ROTATIONS_PER_WINDOW,
            ),
            self_rotation_window_seconds=_parse_positive_integer(
                values,
                "STRUGGLEBUS_SELF_ROTATION_WINDOW_SECONDS",
                DEFAULT_SELF_ROTATION_WINDOW_SECONDS,
            ),
            public_base_url=values.get(
                "STRUGGLEBUS_PUBLIC_BASE_URL", "https://bus.lan"
            ),
            bind_host=values.get("STRUGGLEBUS_BIND_HOST", "127.0.0.1"),
            bind_port=_parse_positive_integer(
                values,
                "STRUGGLEBUS_BIND_PORT",
                8080,
            ),
            allowed_hosts=_parse_csv(
                values, "STRUGGLEBUS_ALLOWED_HOSTS", DEFAULT_ALLOWED_HOSTS
            ),
            allowed_origins=_parse_csv(
                values,
                "STRUGGLEBUS_ALLOWED_ORIGINS",
                DEFAULT_ALLOWED_ORIGINS,
            ),
            trusted_proxy_sources=_parse_csv(
                values,
                "STRUGGLEBUS_TRUSTED_PROXY_SOURCES",
                DEFAULT_TRUSTED_PROXY_SOURCES,
            ),
        )

    def load_admin_secret(self) -> bytes:
        """Return the injected secret or securely read its systemd credential file."""

        if self.admin_secret is not None:
            return self.admin_secret
        path = self.admin_credential_path
        if path is None:
            raise ConfigurationError("admin credential is not configured")
        secret = _read_credential_file(path, name="admin credential", maximum=4096)
        # `openssl rand -hex 32 > admin-token` and most editors end the file
        # with a newline, which no HTTP client can send in a header.
        for ending in (b"\r\n", b"\n"):
            if secret.endswith(ending):
                secret = secret[: -len(ending)]
                break
        if not secret:
            raise ConfigurationError("admin credential file holds no token")
        return secret

    def load_satellite_ca_key(self) -> bytes:
        """Read the site CA signing key from its root-owned systemd credential."""

        if self.satellite_ca_key_path is None:
            raise ConfigurationError("satellite CA key is not configured")
        return _read_credential_file(
            self.satellite_ca_key_path, name="satellite CA key", maximum=16_384,
        )


def _read_credential_file(path: Path, *, name: str, maximum: int) -> bytes:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ConfigurationError(f"{name} file is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        runtime_uid, protected_systemd_projection = (
            _systemd_credential_context(
                path,
                os.environ.get("CREDENTIALS_DIRECTORY"),
                runtime_uid=os.geteuid(),
            )
            if os.name == "posix"
            else (None, False)
        )
        _validate_credential_metadata(
            metadata,
            require_root_owner=os.name == "posix",
            runtime_uid=runtime_uid,
            protected_systemd_projection=protected_systemd_projection,
        )
        secret = os.read(descriptor, maximum + 1)
    except OSError as error:
        raise ConfigurationError(f"{name} file is unreadable") from error
    finally:
        os.close(descriptor)
    if not secret or len(secret) > maximum:
        raise ConfigurationError(
            f"{name} must contain between 1 and {maximum} bytes"
        )
    return secret
