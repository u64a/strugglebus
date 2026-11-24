from datetime import UTC, datetime, timedelta
import json
import os

import pytest

from strugglebus.maintenance_state import MaintenanceState
from strugglebus.maintenance_types import MaintenanceError, MaintenancePolicy


def test_default_policy_is_enabled_daily_brisbane_with_five_minute_notice(tmp_path):
    state = MaintenanceState(tmp_path / "maintenance.json", "0.2.30")
    status = state.status(datetime(2026, 10, 1, 0, 0, tzinfo=UTC))
    assert status.policy == MaintenancePolicy()
    assert status.policy.enabled is True
    assert (status.policy.hour, status.policy.minute) == (1, 0)
    assert status.policy.timezone == "Australia/Brisbane"
    assert status.policy.window_minutes == 30
    assert status.policy.notice_seconds == 300
    if os.name == "posix":
        assert (tmp_path / "maintenance.json").stat().st_mode & 0o777 == 0o600


def test_due_uses_brisbane_time_and_only_once_per_window():
    policy = MaintenancePolicy()
    before = datetime(2026, 9, 30, 14, 59, tzinfo=UTC)
    inside = datetime(2026, 9, 30, 15, 5, tzinfo=UTC)
    after = datetime(2026, 9, 30, 15, 30, tzinfo=UTC)
    assert policy.due(before, None) is False
    assert policy.due(inside, None) is True
    assert policy.due(inside, "2026-10-01") is False
    assert policy.due(after, None) is False


def test_pause_and_time_configuration_persist(tmp_path):
    path = tmp_path / "maintenance.json"
    state = MaintenanceState(path, "0.2.30")
    state.configure(enabled=False, hour=3, minute=45)
    restored = MaintenanceState(path, "0.2.30")
    assert restored.journal.policy.enabled is False
    assert (restored.journal.policy.hour, restored.journal.policy.minute) == (3, 45)


def test_automatic_attempt_consumes_window_before_running(tmp_path):
    state = MaintenanceState(tmp_path / "maintenance.json", "0.2.30")
    operation = "a" * 32
    state.accept(
        operation, "automatic", "system:auto-maintenance",
        now=100, window="2026-10-01",
    )
    assert state.journal.last_window == "2026-10-01"
    state.start(operation)
    state.bind_candidate(operation, "0.2.31")
    state.finish(operation, now=120, error="installation_failed")
    attempt = state.journal.attempt
    assert attempt is not None
    assert attempt.phase == "failed"
    assert attempt.candidate_version == "0.2.31"
    assert attempt.error == "installation_failed"


def test_manual_attempt_does_not_consume_daily_window(tmp_path):
    state = MaintenanceState(tmp_path / "maintenance.json", "0.2.30")
    state.accept("a" * 32, "manual", "operator:owner:test", now=100)
    assert state.journal.last_window is None


def test_active_attempt_blocks_distinct_operation_and_replays_same_id(tmp_path):
    state = MaintenanceState(tmp_path / "maintenance.json", "0.2.30")
    first = state.accept("a" * 32, "manual", "operator:owner:test", now=100)
    assert state.accept("a" * 32, "manual", "operator:owner:test", now=101) == first
    with pytest.raises(MaintenanceError, match="busy"):
        state.accept("b" * 32, "manual", "operator:owner:test", now=101)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(version=2),
        lambda value: value.update(extra=True),
        lambda value: value["policy"].update(timezone="Not/AZone"),
        lambda value: value["policy"].update(window_minutes=60),
        lambda value: value["policy"].update(notice_seconds=60),
    ],
)
def test_corrupt_or_widened_state_fails_closed(tmp_path, mutation):
    path = tmp_path / "maintenance.json"
    MaintenanceState(path, "0.2.30")
    value = json.loads(path.read_text(encoding="ascii"))
    mutation(value)
    path.write_text(json.dumps(value), encoding="ascii")
    os.chmod(path, 0o600)
    with pytest.raises(MaintenanceError, match="state_corrupt"):
        MaintenanceState(path, "0.2.30")


def test_next_window_moves_to_tomorrow_after_window():
    policy = MaintenancePolicy()
    now = datetime(2026, 9, 30, 15, 31, tzinfo=UTC)
    next_window = datetime.fromtimestamp(policy.next_window(now), UTC)
    assert next_window - now < timedelta(days=1)
    assert next_window == datetime(2026, 10, 1, 15, 0, tzinfo=UTC)
