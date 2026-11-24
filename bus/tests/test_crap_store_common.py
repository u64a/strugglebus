"""Shared store helpers: persisted freeze state and trusted-actor validation."""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime

import pytest

from strugglebus.errors import DomainValidationError, StorageError
from strugglebus.models import AccessFreezeState, LifecycleActor
from strugglebus.roe import RoeService
from strugglebus.store import SQLiteStore
from strugglebus.store._common import (
    _access_freeze_from_connection,
    _effective_roe_from_connection,
    _validate_actor,
)


def _state_connection(*rows: tuple[object, ...]) -> sqlite3.Connection:
    """A connection whose access-state table has none of the schema's CHECKs.

    The production table refuses most malformed rows, so the reader's own
    validation is exercised against a table that accepts anything.
    """

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        "CREATE TABLE agent_access_state "
        "(singleton, frozen, transition, changed_at, reason)"
    )
    connection.executemany(
        "INSERT INTO agent_access_state VALUES (?, ?, ?, ?, ?)", rows,
    )
    return connection


def test_never_changed_state_reads_as_thawed_without_time_or_reason() -> None:
    connection = _state_connection((1, 0, "initialized", None, None))

    assert _access_freeze_from_connection(connection) == AccessFreezeState(
        frozen=False, transition="initialized", changed_at=None, reason=None,
    )


def test_recorded_freeze_and_unfreeze_carry_their_time_and_reason() -> None:
    frozen = _access_freeze_from_connection(
        _state_connection((1, 1, "freeze", "2026-08-30T00:00:00.000000Z", "incident")),
    )
    thawed = _access_freeze_from_connection(
        _state_connection((1, 0, "unfreeze", "2026-08-31T00:00:00.000000Z", "resolved")),
    )

    assert frozen == AccessFreezeState(
        frozen=True,
        transition="freeze",
        changed_at=datetime(2026, 8, 30, tzinfo=UTC),
        reason="incident",
    )
    assert thawed == AccessFreezeState(
        frozen=False,
        transition="unfreeze",
        changed_at=datetime(2026, 8, 31, tzinfo=UTC),
        reason="resolved",
    )


@pytest.mark.parametrize(
    "rows",
    [
        (),
        ((1, 0, "initialized", None, None), (2, 0, "initialized", None, None)),
        ((2, 0, "initialized", None, None),),
    ],
    ids=["no-row", "two-rows", "wrong-singleton"],
)
def test_state_without_exactly_one_singleton_row_is_unavailable(
    rows: tuple[tuple[object, ...], ...],
) -> None:
    with pytest.raises(StorageError, match="agent access state is unavailable"):
        _access_freeze_from_connection(_state_connection(*rows))


@pytest.mark.parametrize(
    "row",
    [
        (1, 2, "freeze", "2026-08-30T00:00:00Z", "incident"),
        (1, 1, "paused", "2026-08-30T00:00:00Z", "incident"),
        (1, 1, "initialized", None, None),
        (1, 0, "initialized", "2026-08-30T00:00:00Z", None),
        (1, 0, "initialized", None, "incident"),
        (1, 0, "freeze", "2026-08-30T00:00:00Z", "incident"),
        (1, 1, "unfreeze", "2026-08-30T00:00:00Z", "incident"),
        (1, 1, "freeze", None, "incident"),
        (1, 1, "freeze", 20260830, "incident"),
        (1, 1, "freeze", "2026-08-30T00:00:00Z", None),
        (1, 1, "freeze", "2026-08-30T00:00:00Z", 7),
        (1, 1, "freeze", "yesterday", "incident"),
        (1, 1, "freeze", "2026-08-30T00:00:00", "incident"),
        (1, 1, "freeze", "2026-08-30T00:00:00Z", "   "),
        (1, 1, "freeze", "2026-08-30T00:00:00Z", " padded "),
    ],
    ids=[
        "frozen-not-boolean",
        "unknown-transition",
        "initialized-but-frozen",
        "initialized-with-time",
        "initialized-with-reason",
        "freeze-not-frozen",
        "unfreeze-still-frozen",
        "missing-time",
        "numeric-time",
        "missing-reason",
        "numeric-reason",
        "unparseable-time",
        "time-without-zone",
        "blank-reason",
        "untrimmed-reason",
    ],
)
def test_malformed_state_row_is_reported_as_invalid(row: tuple[object, ...]) -> None:
    with pytest.raises(StorageError, match="agent access state is invalid"):
        _access_freeze_from_connection(_state_connection(row))


def _operator_id(identifier: str | None = None) -> str:
    return f"operator:owner:{identifier or uuid.uuid4()}"


def test_actor_must_be_a_trusted_human_context() -> None:
    with pytest.raises(DomainValidationError, match="trusted human context"):
        _validate_actor(("local-admin", "tester"))  # type: ignore[arg-type]
    with pytest.raises(DomainValidationError, match="trusted human context"):
        _validate_actor(LifecycleActor("agent", "tester"))
    with pytest.raises(DomainValidationError, match="audit text"):
        _validate_actor(LifecycleActor("local-admin", " padded "))


def test_plain_admin_actor_passes_and_runs_its_revalidator_once() -> None:
    calls: list[str] = []

    _validate_actor(LifecycleActor("local-admin", "tester"))
    _validate_actor(
        LifecycleActor("remote-admin", "admin", lambda: calls.append("checked")),
    )

    assert calls == ["checked"]


def test_operator_actor_needs_remote_owner_uuid_and_revalidator() -> None:
    calls: list[str] = []

    def revalidate() -> None:
        calls.append("checked")

    with pytest.raises(DomainValidationError, match="operator context is required"):
        _validate_actor(LifecycleActor("local-admin", _operator_id(), revalidate))
    with pytest.raises(DomainValidationError, match="operator context is required"):
        _validate_actor(LifecycleActor("remote-admin", "operator:guest:1", revalidate))
    with pytest.raises(DomainValidationError, match="must contain a UUID"):
        _validate_actor(LifecycleActor("remote-admin", _operator_id("nobody"), revalidate))
    with pytest.raises(DomainValidationError, match="must contain a UUID"):
        _validate_actor(
            LifecycleActor(
                "remote-admin", _operator_id(str(uuid.uuid4()).upper()), revalidate,
            )
        )
    with pytest.raises(DomainValidationError, match="session revalidation is required"):
        _validate_actor(LifecycleActor("remote-admin", _operator_id()))
    assert calls == []

    _validate_actor(LifecycleActor("remote-admin", _operator_id(), revalidate))
    _validate_actor(
        LifecycleActor("remote-admin", _operator_id(uuid.uuid4().hex), revalidate),
        operator_only=True,
    )

    assert calls == ["checked", "checked"]


def test_operator_only_operations_refuse_a_plain_admin() -> None:
    with pytest.raises(DomainValidationError, match="operator context is required"):
        _validate_actor(
            LifecycleActor("remote-admin", "admin", lambda: None), operator_only=True,
        )


def test_device_actor_is_accepted_only_for_operator_operations_with_revalidation() -> None:
    calls: list[str] = []

    with pytest.raises(DomainValidationError, match="device revalidation is required"):
        _validate_actor(
            LifecycleActor("local-admin", "device:phone", lambda: None),
            operator_only=True,
        )
    with pytest.raises(DomainValidationError, match="device revalidation is required"):
        _validate_actor(
            LifecycleActor("remote-admin", "device:phone"), operator_only=True,
        )

    _validate_actor(
        LifecycleActor("remote-admin", "device:phone", lambda: calls.append("device")),
        operator_only=True,
    )

    assert calls == ["device"]


def test_effective_roe_requires_a_current_global_revision(tmp_path) -> None:
    store = SQLiteStore(tmp_path / "strugglebus.db", backup_dir=tmp_path / "backups")
    store.initialize()

    with store._read_transaction() as connection:
        with pytest.raises(StorageError, match="current global RoE revision is unavailable"):
            _effective_roe_from_connection(connection, None)

    RoeService(
        store,
        enforcement_mode="observe",
        clock=lambda: datetime(2026, 9, 1, tzinfo=UTC),
    ).initialize()
    with store._read_transaction() as connection:
        effective = _effective_roe_from_connection(connection, None)

    assert effective.agent_revision is None
    assert effective.acknowledgement is None
    assert effective.acknowledgement_status == "missing"
