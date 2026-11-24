"""Authentication must not write on every request.

Authentication updates liveness timestamps inside the authorising transaction,
so without coalescing every authenticated read becomes a SQLite writer
competing with message creation. The agent path already skipped the write for a
recently used credential; the monitor path did not, and monitors poll hardest.

These tests pin the behaviour that matters: the authorisation decision is
identical either way, and only the timestamp write is skipped.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from strugglebus.auth import AgentService, mint_mobile_credential
from strugglebus.config import AppConfig
from strugglebus.errors import StorageError
from strugglebus.mobile import MobileService
from strugglebus.store import SQLiteStore


class _Clock:
    """A clock the test advances explicitly, so nothing depends on wall time."""

    def __init__(self) -> None:
        self.now = datetime(2026, 9, 8, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def _store(config: AppConfig, *, window: int = 60) -> SQLiteStore:
    store = SQLiteStore(
        config.database_path,
        backup_dir=config.backup_dir,
        busy_timeout_ms=config.sqlite_busy_timeout_ms,
        liveness_refresh_seconds=window,
    )
    store.initialize()
    return store


def _device(store: SQLiteStore, label: str = "owner-phone") -> tuple[str, str]:
    credential_id, verifier, secret = mint_mobile_credential()
    device_id = str(uuid.uuid4())
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "INSERT INTO mobile_devices (id, label, status, created_at) "
            "VALUES (?, ?, 'enabled', '2026-09-08T11:00:00Z')",
            (device_id, label),
        )
        connection.execute(
            "INSERT INTO mobile_device_credentials "
            "(id, device_id, kind, secret_hash, status, creation_method, "
            " creation_reason, issuance_request_id, created_at) "
            "VALUES (?, ?, 'sbm1', ?, 'active', 'enrollment', 'test', ?, "
            "'2026-09-08T11:00:00Z')",
            (credential_id, device_id, verifier, str(uuid.uuid4())),
        )
    return device_id, secret


def _last_used(store: SQLiteStore) -> str | None:
    with sqlite3.connect(store.database_path) as connection:
        return connection.execute(
            "SELECT last_used_at FROM mobile_device_credentials"
        ).fetchone()[0]


def test_monitor_authentication_skips_the_write_inside_the_window(
    app_config: AppConfig,
) -> None:
    store = _store(app_config, window=60)
    _device_id, secret = _device(store)
    clock = _Clock()
    service = MobileService(store, clock=clock)

    assert service.authorize(secret) is not None
    first = _last_used(store)
    assert first is not None

    clock.advance(30)
    assert service.authorize(secret) is not None
    # Inside the window the timestamp is deliberately left alone, which is the
    # whole point: the read did not take the write path.
    assert _last_used(store) == first

    clock.advance(31)
    assert service.authorize(secret) is not None
    assert _last_used(store) != first


def test_monitor_liveness_window_is_configurable(app_config: AppConfig) -> None:
    store = _store(app_config, window=600)
    _device_id, secret = _device(store)
    clock = _Clock()
    service = MobileService(store, clock=clock)

    assert service.authorize(secret) is not None
    first = _last_used(store)
    clock.advance(120)
    assert service.authorize(secret) is not None
    assert _last_used(store) == first


def test_coalescing_never_changes_the_authorisation_decision(
    app_config: AppConfig,
) -> None:
    """A revoked device must be refused on the fast path too.

    This is the failure that would matter: skipping the write must never
    become skipping the check.
    """

    store = _store(app_config, window=3600)
    device_id, secret = _device(store)
    clock = _Clock()
    service = MobileService(store, clock=clock)
    assert service.authorize(secret) is not None

    revoked = store.revoke_mobile_device(
        device_id=device_id, reason="handset lost",
        actor_type="remote-admin", actor_id="operator:owner:test",
        revoked_at=clock(),
    )
    assert revoked

    # Well inside the window, so this resolves on the read path.
    clock.advance(5)
    assert service.authorize(secret) is None
    assert store.mobile_credential_is_active("missing") is False


def test_unknown_and_wrong_monitor_secrets_are_still_refused(
    app_config: AppConfig,
) -> None:
    store = _store(app_config)
    _device_id, secret = _device(store)
    service = MobileService(store, clock=_Clock())
    assert service.authorize(secret) is not None
    _credential_id, _verifier, other = mint_mobile_credential()
    assert service.authorize(other) is None
    assert service.authorize("not-a-credential") is None


def test_agent_authentication_uses_the_same_configured_window(
    app_config: AppConfig,
) -> None:
    store = _store(app_config, window=600)
    service = AgentService(store)
    issued = service.create_agent("window-probe-cli")
    secret = issued.issued_credential.secret
    agent_id = issued.agent.id

    identity = service.authorize(secret)
    assert identity is not None
    service.prove(
        identity,
        request_id=str(uuid.uuid4()),
        expected_agent_id=identity.agent.id,
        expected_agent_name=identity.agent.name,
        expected_credential_epoch=identity.agent.credential_epoch,
        expected_credential_version=identity.credential.version,
    )

    def last_seen() -> str | None:
        with sqlite3.connect(store.database_path) as connection:
            return connection.execute(
                "SELECT last_seen_at FROM agents WHERE id = ?", (agent_id,)
            ).fetchone()[0]

    assert service.authorize(secret) is not None
    first = last_seen()
    assert first is not None
    # A second authentication moments later must not rewrite the row.
    assert service.authorize(secret) is not None
    assert last_seen() == first


@pytest.mark.parametrize("window", [0, -1, True])
def test_a_non_positive_window_is_refused(app_config: AppConfig, window) -> None:
    with pytest.raises(StorageError):
        SQLiteStore(
            app_config.database_path,
            backup_dir=app_config.backup_dir,
            liveness_refresh_seconds=window,
        )
