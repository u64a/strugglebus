from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import shutil
import time

import pytest

from strugglebus.access import (
    AccessFreezeService,
    access_freeze_transition_lock,
    normalize_access_freeze_reason,
)
from strugglebus.auth import AgentService
from strugglebus.backup import create_verified_backup
from strugglebus.errors import (
    AgentAccessFrozenError,
    DomainValidationError,
    StorageError,
)
from strugglebus.service import BoardService
from strugglebus.store import SQLiteStore


def _services(tmp_path):
    store = SQLiteStore(
        tmp_path / "strugglebus.db",
        backup_dir=tmp_path / "backups",
    )
    now = datetime(2026, 8, 30, 0, 0, tzinfo=UTC)
    board = BoardService(
        store,
        max_message_bytes=1024,
        max_metadata_bytes=1024,
        max_channels=100,
        clock=lambda: now,
    )
    board.initialize()
    return (
        store,
        board,
        AgentService(store, clock=lambda: now),
        AccessFreezeService(
            store,
            clock=lambda: now,
            transition_lock_directory=tmp_path / ".access-freeze-lock",
        ),
    )


def test_freeze_transitions_are_persistent_idempotent_and_audited(tmp_path) -> None:
    store, _, _, access = _services(tmp_path)

    assert access.status().transition == "initialized"
    frozen, changed = access.freeze("operator incident 42")
    repeated, repeated_changed = access.freeze("must not replace evidence")

    assert changed is True
    assert repeated_changed is False
    assert repeated == frozen
    assert repeated.reason == "operator incident 42"
    assert SQLiteStore(
        store.database_path,
        backup_dir=store.backup_dir,
    ).get_access_freeze() == frozen

    restored, restored_changed = access.unfreeze("reviewed recovery complete")
    assert restored_changed is True
    assert restored.frozen is False
    assert restored.transition == "unfreeze"

    with sqlite3.connect(store.database_path) as database:
        assert database.execute(
            """
            SELECT transition, reason, actor_type, actor_id
            FROM agent_access_audit
            ORDER BY seq
            """
        ).fetchall() == [
            (
                "freeze", "operator incident 42",
                "system", "system:access-service",
            ),
            (
                "unfreeze", "reviewed recovery complete",
                "system", "system:access-service",
            ),
        ]


def test_protected_local_operator_transitions_record_the_deciding_identity(
    tmp_path,
) -> None:
    store, _, _, access = _services(tmp_path)

    access.operator_freeze("local containment")
    access.operator_unfreeze("local recovery")

    with sqlite3.connect(store.database_path) as database:
        assert database.execute(
            "SELECT transition, actor_type, actor_id "
            "FROM agent_access_audit ORDER BY seq"
        ).fetchall() == [
            ("freeze", "local-admin", "local-cli"),
            ("unfreeze", "local-admin", "local-cli"),
        ]


def test_freeze_transition_rejects_invalid_audit_identity(tmp_path) -> None:
    store, _, _, _ = _services(tmp_path)

    with pytest.raises(DomainValidationError, match="actor type"):
        store.set_access_freeze(
            frozen=True,
            reason="invalid actor",
            changed_at=datetime(2026, 8, 30, tzinfo=UTC),
            actor_type="agent",
            actor_id="agent:untrusted",
        )

    assert store.get_access_freeze().frozen is False
    with sqlite3.connect(store.database_path) as database:
        assert database.execute(
            "SELECT COUNT(*) FROM agent_access_audit"
        ).fetchone() == (0,)


def test_concurrent_freeze_records_exactly_one_transition(tmp_path) -> None:
    store, _, _, access = _services(tmp_path)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(access.freeze, ["concurrent incident"] * 8))

    assert sum(changed for _, changed in results) == 1
    assert all(state.frozen for state, _ in results)
    with sqlite3.connect(store.database_path) as database:
        assert database.execute(
            "SELECT COUNT(*) FROM agent_access_audit"
        ).fetchone() == (1,)


def test_transition_waits_for_the_shared_release_lock(tmp_path) -> None:
    _, _, _, access = _services(tmp_path)

    with ThreadPoolExecutor(max_workers=1) as executor:
        with access_freeze_transition_lock(access.transition_lock_directory):
            pending = executor.submit(access.freeze, "serialized incident")
            time.sleep(0.1)
            assert not pending.done()

        state, changed = pending.result(timeout=2)
    assert changed is True
    assert state.frozen is True


def test_transition_rejects_an_unsafe_lock_directory(tmp_path) -> None:
    store, _, _, _ = _services(tmp_path)
    unsafe = tmp_path / "not-a-directory"
    unsafe.write_text("unsafe", encoding="ascii")
    access = AccessFreezeService(
        store,
        clock=lambda: datetime(2026, 8, 30, tzinfo=UTC),
        transition_lock_directory=unsafe,
    )

    with pytest.raises(StorageError, match="lock directory"):
        access.freeze("must fail closed")


def test_verified_backup_and_restore_preserve_freeze_state_and_audit(tmp_path) -> None:
    store, _, _, access = _services(tmp_path)
    expected, changed = access.freeze("preserve incident evidence")
    assert changed is True

    backup = create_verified_backup(
        store.database_path,
        store.backup_dir,
        destination_name="freeze-restore.db",
    )
    restored_path = tmp_path / "restored.db"
    shutil.copy2(backup, restored_path)
    restored = SQLiteStore(restored_path, backup_dir=tmp_path / "restored-backups")

    assert restored.get_access_freeze() == expected
    with sqlite3.connect(restored_path) as database:
        assert database.execute(
            "SELECT transition, reason, actor_type, actor_id "
            "FROM agent_access_audit ORDER BY seq"
        ).fetchall() == [(
            "freeze", "preserve incident evidence",
            "system", "system:access-service",
        )]


@pytest.mark.parametrize(
    "reason",
    ["", "   ", "x\x00y", "x" * 257],
)
def test_freeze_reason_is_bounded(reason: str) -> None:
    with pytest.raises(DomainValidationError):
        normalize_access_freeze_reason(reason)


def test_authorization_and_agent_mutations_fail_closed_without_last_seen_write(
    tmp_path,
) -> None:
    _, board, agents, access = _services(tmp_path)
    created = agents.create_agent("freeze-test-agent")
    access.freeze("credential containment")

    with pytest.raises(AgentAccessFrozenError, match="agent access is frozen"):
        agents.authorize(created.api_key)
    assert agents.verify_credential(created.api_key) is not None
    assert agents.get_active_agent(created.agent.id).last_seen_at is None
    with pytest.raises(AgentAccessFrozenError, match="agent access is frozen"):
        board.create_message(
            "status",
            agent_id=created.agent.id,
            body="must not persist",
            kind="status",
            reply_to=None,
            metadata={},
        )


def test_remote_registration_guard_is_transactional_but_local_admin_remains_available(
    tmp_path,
) -> None:
    _, _, agents, access = _services(tmp_path)
    access.freeze("contain remote registration")

    with pytest.raises(AgentAccessFrozenError, match="agent access is frozen"):
        agents.create_agent("remote-blocked-agent", require_access=True)

    locally_created = agents.create_agent("local-operator-agent")
    assert locally_created.agent.name == "local-operator-agent"


def test_missing_singleton_fails_startup_readiness_and_access(tmp_path) -> None:
    store, board, agents, _ = _services(tmp_path)
    created = agents.create_agent("missing-state-agent")
    with sqlite3.connect(store.database_path) as database:
        database.execute("DELETE FROM agent_access_state")

    with pytest.raises(StorageError, match="agent access state is unavailable"):
        store.initialize()
    with pytest.raises(StorageError, match="agent access state is unavailable"):
        board.check_readiness()
    with pytest.raises(StorageError, match="agent access state is unavailable"):
        agents.authorize(created.api_key)


@pytest.mark.parametrize(
    ("changed_at", "reason"),
    [
        ("2026-08-30T00:00:00Z", " padded "),
        ("not-a-timestamp", "incident"),
    ],
)
def test_malformed_persisted_transition_fails_as_bounded_storage_error(
    tmp_path,
    changed_at: str,
    reason: str,
) -> None:
    store, _, _, _ = _services(tmp_path)
    with sqlite3.connect(store.database_path) as database:
        database.execute(
            """
            UPDATE agent_access_state
            SET frozen = 1,
                transition = 'freeze',
                changed_at = ?,
                reason = ?
            WHERE singleton = 1
            """,
            (changed_at, reason),
        )

    with pytest.raises(StorageError, match="agent access state is invalid"):
        store.get_access_freeze()


def test_transition_clock_must_be_utc_aware(tmp_path) -> None:
    store, _, _, _ = _services(tmp_path)
    access = AccessFreezeService(
        store,
        clock=lambda: datetime(2026, 8, 30) + timedelta(seconds=1),
        transition_lock_directory=tmp_path / ".access-freeze-lock",
    )

    with pytest.raises(ValueError, match="timezone-aware"):
        access.freeze("invalid clock")
