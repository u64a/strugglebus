"""The bus's own updates reach the stored event log."""

from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from strugglebus import __version__, bus_events, update_events
from strugglebus.errors import StorageError
from strugglebus.maintenance_types import (
    MaintenanceAttempt, MaintenanceError, MaintenancePolicy, MaintenanceStatus,
)
from strugglebus.migrations import LATEST_SCHEMA_VERSION
from strugglebus.selfhost_updates import LastCheck
from test_mobile_write_path import _auth, surface  # noqa: F401

NOW = datetime(2026, 11, 28, 3, 5, 0, tzinfo=UTC)
OPERATION = "a" * 32
STARTED = int(NOW.timestamp()) - 120


def status(current: str = "0.2.74", **attempt) -> MaintenanceStatus:
    made = None if attempt.get("none") else MaintenanceAttempt(
        attempt.pop("operation_id", OPERATION), "automatic", "system:maintenance",
        attempt.pop("phase", "running"), attempt.pop("started_at", STARTED), **attempt,
    )
    return MaintenanceStatus(MaintenancePolicy(), current, None, int(NOW.timestamp()) + 3600, made)


def told(events: list[bus_events.Event]) -> list[tuple]:
    return [(event.type, event.level, event.subject, event.fields) for event in events]


def check(result: str, version: str = "0.2.75", ago: timedelta = timedelta(minutes=5)) -> LastCheck:
    return LastCheck(checked_at=NOW - ago, result=result, latest_version=version, detail="whatever it said")


# ---- an Ansible install's maintenance attempt -------------------------------------------------


def test_an_update_under_way_is_started_and_names_the_version_it_replaces() -> None:
    events = update_events.attempt_events(status(candidate_version="0.2.75"), NOW)

    assert told(events) == [("update-started", "info", "0.2.75", {"version": "0.2.75", "previous": "0.2.74"})]


def test_an_update_that_worked_is_started_and_applied() -> None:
    done = status("0.2.75", phase="succeeded", finished_at=STARTED + 60, candidate_version="0.2.75")

    assert told(update_events.attempt_events(done, NOW)) == [
        ("update-started", "info", "0.2.75", {"version": "0.2.75"}),
        ("update-applied", "info", "0.2.75", {"version": "0.2.75"}),
    ]


def test_a_check_that_failed_before_any_release_was_chosen_says_why() -> None:
    failed = status(phase="failed", finished_at=STARTED + 5, error="updater_unavailable")

    assert told(update_events.attempt_events(failed, NOW)) == [
        ("update-check-failed", "warning", "", {"reason": "updater-unavailable"}),
    ]


def test_an_update_that_failed_names_the_version_and_why() -> None:
    failed = status(phase="failed", finished_at=STARTED + 50, candidate_version="0.2.75", error="installation_failed")

    assert told(update_events.attempt_events(failed, NOW))[1] == (
        "update-failed", "error", "0.2.75", {"version": "0.2.75", "reason": "installation-failed"},
    )


@pytest.mark.parametrize("quiet", [
    status(none=True),
    status(phase="accepted"),
    status(phase="succeeded", finished_at=STARTED + 5),
    status(phase="failed", finished_at=STARTED - 31 * 86400, started_at=STARTED - 31 * 86400 - 5, error="busy"),
])
def test_no_attempt_nothing_newer_and_an_attempt_too_old_to_keep_record_nothing(quiet) -> None:
    assert update_events.attempt_events(quiet, NOW) == []


def test_the_same_attempt_read_again_gives_the_same_ids_and_another_attempt_others() -> None:
    done = status("0.2.75", phase="succeeded", finished_at=STARTED + 60, candidate_version="0.2.75")
    other = status("0.2.75", phase="succeeded", finished_at=STARTED + 60, candidate_version="0.2.75", operation_id="b" * 32)

    first = [event.event_id for event in update_events.attempt_events(done, NOW)]

    assert first == [event.event_id for event in update_events.attempt_events(done, NOW)]
    assert len(set(first)) == 2
    assert not set(first) & {event.event_id for event in update_events.attempt_events(other, NOW)}


# ---- a self-hosted updater's report -----------------------------------------------------------


@pytest.mark.parametrize("result,expected", [
    ("updated", ("update-applied", "info", "0.2.75", {"version": "0.2.75"})),
    ("unreachable", ("update-check-failed", "warning", "0.2.75", {"reason": "source-unreachable"})),
    ("invalid", ("update-blocked", "warning", "0.2.75", {"version": "0.2.75", "reason": "release-refused"})),
    ("failed", ("update-failed", "error", "0.2.75", {"version": "0.2.75", "reason": "install-failed"})),
])
def test_a_self_hosted_updaters_report_becomes_an_event_and_its_free_text_is_left_behind(result, expected) -> None:
    [event] = update_events.selfhost_events(check(result), NOW)

    assert told([event])[0] == expected
    assert "whatever" not in str(event)


def test_a_report_with_no_version_or_one_that_is_not_a_version_keeps_none() -> None:
    [event] = update_events.selfhost_events(check("unreachable", version=""), NOW)
    [odd] = update_events.selfhost_events(check("failed", version="<script>"), NOW)

    assert (event.subject, event.fields) == ("", {"reason": "source-unreachable"})
    assert odd.fields == {"reason": "install-failed"}


@pytest.mark.parametrize("quiet", [None, check("current"), check("off"), check("nonsense"), check("failed", ago=timedelta(days=31))])
def test_nothing_to_tell_from_a_self_hosted_updater(quiet) -> None:
    assert update_events.selfhost_events(quiet, NOW) == []


def test_each_self_hosted_report_is_its_own_event() -> None:
    first = update_events.selfhost_events(check("failed"), NOW)[0].event_id

    assert first == update_events.selfhost_events(check("failed"), NOW)[0].event_id
    assert first != update_events.selfhost_events(check("failed", ago=timedelta(days=1)), NOW)[0].event_id
    assert first != update_events.selfhost_events(check("updated"), NOW)[0].event_id


# ---- the recorder -----------------------------------------------------------------------------


class Maintenance:
    def __init__(self, answer) -> None:
        self.answer = answer

    async def status(self):
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def console(maintenance=None, last_check=None):
    return SimpleNamespace(
        maintenance=maintenance, client=None, selfhost=SimpleNamespace(last_check=lambda: last_check),
    )


def recorder(store, updater):
    log = bus_events.BusEventLog(store, clock=lambda: NOW)
    return update_events.UpdateEventRecorder(log, lambda: updater, clock=lambda: NOW), log


def stored(log) -> list[tuple[str, str]]:
    return [(item.event.type, item.event.subject) for item in reversed(log.recent(50, admin=True))]


def test_the_recorder_stores_what_is_new_and_nothing_twice(surface) -> None:  # noqa: F811
    *_, store = surface
    maintenance = Maintenance(status(candidate_version="0.2.75"))
    record, log = recorder(store, console(maintenance, check("unreachable")))

    assert asyncio.run(record.poll_once()) == 2
    assert asyncio.run(record.poll_once()) == 0
    maintenance.answer = status("0.2.75", phase="succeeded", finished_at=STARTED + 60, candidate_version="0.2.75")
    assert asyncio.run(record.poll_once()) == 1

    assert [row for row in stored(log) if row[0] != "started"] == [
        ("update-started", "0.2.75"), ("update-check-failed", "0.2.75"), ("update-applied", "0.2.75"),
    ]


def test_a_restarted_bus_reads_the_same_record_and_stores_nothing_again(surface) -> None:  # noqa: F811
    *_, store = surface
    updater = console(Maintenance(status(phase="failed", finished_at=STARTED + 5, error="updater_unavailable")))

    assert asyncio.run(recorder(store, updater)[0].poll_once()) == 1
    assert asyncio.run(recorder(store, updater)[0].poll_once()) == 0


def test_an_install_with_no_updater_or_one_that_is_away_records_nothing(surface) -> None:  # noqa: F811
    *_, store = surface

    assert asyncio.run(recorder(store, None)[0].poll_once()) == 0
    assert asyncio.run(recorder(store, console())[0].poll_once()) == 0
    assert asyncio.run(recorder(store, console(Maintenance(MaintenanceError("unavailable"))))[0].poll_once()) == 0


def test_the_recorder_keeps_going_when_a_read_fails(surface, monkeypatch, capsys) -> None:  # noqa: F811
    *_, store = surface
    record, _ = recorder(store, console())
    polls = []

    async def poll():
        polls.append(1)
        if len(polls) == 1:
            raise RuntimeError("anything at all")
        raise asyncio.CancelledError

    async def no_wait(seconds):
        assert seconds == update_events.POLL_SECONDS

    monkeypatch.setattr(record, "poll_once", poll)
    monkeypatch.setattr(update_events.asyncio, "sleep", no_wait)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(record.run())

    assert len(polls) == 2
    assert "could not record" in capsys.readouterr().err


# ---- the bus starting -------------------------------------------------------------------------


def test_the_bus_notes_that_it_started_and_as_which_version(surface) -> None:  # noqa: F811
    client, secret, *_ = surface

    entries = client.get("/api/mobile/admin/logs", headers=_auth(secret)).json()["entries"]

    assert [(e["source"], e["event"], e["detail"]) for e in entries if e["source"] == "bus"] == [
        ("bus", "started", f"schema={LATEST_SCHEMA_VERSION} version={__version__}"),
    ]


def test_a_start_that_cannot_be_noted_still_starts(capsys) -> None:
    from strugglebus.app import _record_start

    def broken(*args, **kwargs):
        raise StorageError("disk")

    _record_start(SimpleNamespace(record=broken))

    assert "could not record the start" in capsys.readouterr().err


# ---- the real cause of a check that did not finish --------------------------------------------


class Worker:
    def __init__(self, answer) -> None:
        self.answer = answer
        self.asked = 0

    async def status(self):
        self.asked += 1
        if isinstance(self.answer, Exception):
            raise self.answer
        return SimpleNamespace(operation=self.answer)


def operation(error: str | None = "rate_limited", phase: str = "failed", finished_at: int | None = STARTED + 3):
    return SimpleNamespace(phase=phase, error=error, finished_at=finished_at)


def unavailable(**more) -> MaintenanceStatus:
    return status(phase="failed", finished_at=STARTED + 5, error="updater_unavailable", **more)


def recorded_reason(store, worker, attempt=None) -> dict:
    updater = console(Maintenance(attempt or unavailable()))
    updater.client = worker
    record, log = recorder(store, updater)
    asyncio.run(record.poll_once())
    return next(item.event.fields for item in log.recent(50, admin=True) if item.event.source == "update")


def test_a_check_stopped_by_the_sources_request_limit_says_so(surface) -> None:  # noqa: F811
    *_, store = surface

    assert recorded_reason(store, Worker(operation())) == {"reason": "rate-limited"}


@pytest.mark.parametrize("worker", [
    None,
    Worker(None),
    Worker(update_events.UpdateError("unavailable")),
    Worker(operation(phase="succeeded", error=None)),
    Worker(operation(finished_at=None)),
    # The worker's last failure was some other time, not this attempt's.
    Worker(operation(finished_at=STARTED - 3600)),
    Worker(operation(finished_at=STARTED + 3600)),
])
def test_without_the_workers_reason_for_this_attempt_the_general_one_stands(surface, worker) -> None:  # noqa: F811
    *_, store = surface

    assert recorded_reason(store, worker) == {"reason": "updater-unavailable"}


def test_the_worker_is_not_asked_when_the_attempt_already_says_why(surface) -> None:  # noqa: F811
    *_, store = surface
    worker = Worker(operation())
    failed = status(phase="failed", finished_at=STARTED + 50, candidate_version="0.2.75", error="installation_failed")

    assert recorded_reason(store, worker, failed)["reason"] == "installation-failed"
    assert worker.asked == 0


def test_the_updates_page_says_what_went_wrong_in_plain_words() -> None:
    from strugglebus import update_rendering as page

    limited = page._what_went_wrong(page.ERROR_MESSAGES, "rate_limited")["What went wrong"]
    shown = page.maintenance_status(unavailable())

    assert "GitHub is limiting requests from this network" in limited and "60 an hour" in limited
    assert "What went wrong" in shown and "recorded operation" in shown
    assert page._what_went_wrong(page.MAINTENANCE_MESSAGES, None) == {}
    assert page._what_went_wrong(page.MAINTENANCE_MESSAGES, "not-a-code") == {}
    assert "What went wrong" not in page.maintenance_status(status(phase="succeeded", finished_at=STARTED + 5))
    assert "supervisor refused this operation (odd)" in page.maintenance_failure("odd")
    assert "already active" in page.maintenance_failure("busy")
