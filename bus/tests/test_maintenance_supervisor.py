from datetime import UTC, datetime
from pathlib import Path

import pytest

from strugglebus.maintenance_state import MaintenanceState
from strugglebus.maintenance_supervisor import (
    MaintenanceController,
    MaintenanceRunner,
    PreparedRelease,
)
from strugglebus.maintenance_types import MaintenanceError, MaintenanceRequest


class Gateway:
    def __init__(self, release=True):
        self.release = release
        self.actors = []

    def prepare_latest(self, *, actor_id):
        self.actors.append(actor_id)
        if not self.release:
            return None
        return PreparedRelease("0.2.31", Path("/cache/release"))


class Installer:
    def __init__(self, error=None):
        self.calls = []
        self.error = error

    def install(self, release, *, operation_id):
        self.calls.append((release, operation_id))
        if self.error is not None:
            raise MaintenanceError(self.error)


class Announcer:
    def __init__(self):
        self.calls = []

    def announce(self, release, *, operation_id, scheduled_at, automatic):
        self.calls.append((release, operation_id, scheduled_at, automatic))


def instant():
    return datetime(2026, 9, 30, 15, 0, tzinfo=UTC)


def test_manual_install_is_durably_accepted_before_trigger(tmp_path):
    state = MaintenanceState(tmp_path / "state.json", "0.2.30")
    events = []
    controller = MaintenanceController(state, trigger=lambda: events.append("triggered"), clock=instant)
    status = controller.dispatch(MaintenanceRequest(
        "install", "a" * 32, "operator:owner:test",
    ))
    assert events == ["triggered"]
    assert status.attempt is not None
    assert status.attempt.phase == "accepted"
    assert status.attempt.mode == "manual"


def test_configuration_is_persisted_without_triggering_install(tmp_path):
    state = MaintenanceState(tmp_path / "state.json", "0.2.30")
    events = []
    controller = MaintenanceController(state, trigger=lambda: events.append("triggered"), clock=instant)
    status = controller.dispatch(MaintenanceRequest(
        "configure", "a" * 32, "operator:owner:test", False, 2, 15,
    ))
    assert events == []
    assert status.policy.enabled is False
    assert (status.policy.hour, status.policy.minute) == (2, 15)


def test_automatic_run_announces_waits_and_installs_once(tmp_path):
    state = MaintenanceState(tmp_path / "state.json", "0.2.30")
    gateway, installer, announcer = Gateway(), Installer(), Announcer()
    sleeps = []
    runner = MaintenanceRunner(
        state, gateway, installer, announcer, clock=instant, sleep=sleeps.append,
    )
    assert runner.run_pending() is True
    attempt = state.journal.attempt
    assert attempt is not None and attempt.phase == "succeeded"
    assert attempt.mode == "automatic"
    assert attempt.candidate_version == "0.2.31"
    assert gateway.actors == ["system:auto-maintenance"]
    assert sleeps == [300]
    assert announcer.calls[0][3] is True
    assert installer.calls[0][1] == attempt.operation_id
    assert runner.run_pending() is False


def test_no_candidate_consumes_window_without_announcement_or_outage(tmp_path):
    state = MaintenanceState(tmp_path / "state.json", "0.2.30")
    gateway, installer, announcer = Gateway(False), Installer(), Announcer()
    runner = MaintenanceRunner(
        state, gateway, installer, announcer, clock=instant, sleep=lambda _: None,
    )
    assert runner.run_pending() is True
    assert state.journal.attempt is not None
    assert state.journal.attempt.phase == "succeeded"
    assert state.journal.attempt.candidate_version is None
    assert installer.calls == []
    assert announcer.calls == []


def test_failed_announcement_does_not_block_update(tmp_path, capsys):
    class FailingAnnouncer(Announcer):
        def announce(self, release, **kwargs):
            super().announce(release, **kwargs)
            raise MaintenanceError("installation_failed")

    state = MaintenanceState(tmp_path / "state.json", "0.2.30")
    installer, announcer, sleeps = Installer(), FailingAnnouncer(), []
    runner = MaintenanceRunner(
        state, Gateway(), installer, announcer, clock=instant, sleep=sleeps.append,
    )
    assert runner.run_pending() is True
    attempt = state.journal.attempt
    assert attempt is not None and attempt.phase == "succeeded"
    assert len(announcer.calls) == 1
    assert sleeps == [300]
    assert len(installer.calls) == 1
    assert capsys.readouterr().err == "maintenance_notice_skipped\n"


def test_failed_install_is_not_retried_in_same_window(tmp_path):
    state = MaintenanceState(tmp_path / "state.json", "0.2.30")
    runner = MaintenanceRunner(
        state, Gateway(), Installer("installation_failed"), Announcer(),
        clock=instant, sleep=lambda _: None,
    )
    with pytest.raises(MaintenanceError, match="installation_failed"):
        runner.run_pending()
    attempt = state.journal.attempt
    assert attempt is not None and attempt.phase == "failed"
    assert state.journal.last_window == "2026-10-01"
    assert runner.run_pending() is False


def test_interrupted_running_attempt_is_failed_without_reexecution(tmp_path):
    path = tmp_path / "state.json"
    state = MaintenanceState(path, "0.2.30")
    operation_id = "a" * 32
    state.accept(
        operation_id,
        "manual",
        "operator:owner:test",
        now=int(instant().timestamp()),
    )
    state.start(operation_id)

    gateway, installer, announcer = Gateway(), Installer(), Announcer()
    runner = MaintenanceRunner(
        MaintenanceState(path, "0.2.30"),
        gateway,
        installer,
        announcer,
        clock=instant,
        sleep=lambda _: None,
    )

    assert runner.run_pending() is False
    attempt = runner.state.journal.attempt
    assert attempt is not None
    assert attempt.phase == "failed"
    assert attempt.error == "unknown_outcome"
    assert gateway.actors == []
    assert installer.calls == []
    assert announcer.calls == []

    events = []
    controller = MaintenanceController(
        runner.state,
        trigger=lambda: events.append("triggered"),
        clock=instant,
    )
    status = controller.dispatch(MaintenanceRequest(
        "install",
        operation_id,
        "operator:owner:test",
    ))
    assert events == []
    assert status.attempt is not None
    assert status.attempt.phase == "failed"
    assert status.attempt.error == "unknown_outcome"

    retry = runner.state.accept(
        "b" * 32,
        "manual",
        "operator:owner:test",
        now=int(instant().timestamp()),
    )
    assert retry.phase == "accepted"


def test_paused_policy_skips_automatic_but_manual_still_runs(tmp_path):
    state = MaintenanceState(tmp_path / "state.json", "0.2.30")
    state.configure(enabled=False, hour=1, minute=0)
    gateway, installer, announcer = Gateway(), Installer(), Announcer()
    runner = MaintenanceRunner(
        state, gateway, installer, announcer, clock=instant, sleep=lambda _: None,
    )
    assert runner.run_pending() is False
    state.accept("a" * 32, "manual", "operator:owner:test", now=int(instant().timestamp()))
    assert runner.run_pending() is True
    assert gateway.actors == ["operator:owner:test"]
