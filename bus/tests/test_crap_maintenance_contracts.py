"""Wire contracts, durable state and the board notice for self-updating maintenance."""

from datetime import UTC, datetime
import json
import os
from pathlib import Path
import sqlite3

import pytest

import strugglebus.maintenance_notice as notice_module
import strugglebus.maintenance_state as state_module
from strugglebus.maintenance_state import (
    STATE_BYTES,
    MaintenanceJournal,
    MaintenanceState,
    journal_from_json,
    journal_to_json,
)
from strugglebus.maintenance_types import (
    MAINTENANCE_PROTOCOL_VERSION,
    MaintenanceAttempt,
    MaintenanceError,
    MaintenancePolicy,
    MaintenanceRequest,
    MaintenanceStatus,
    request_from_json,
    request_to_json,
    response_from_json,
    response_to_json,
    status_from_json,
    status_to_json,
)
from strugglebus.update_types import UpdateError

OPERATION = "a" * 32
ACTOR = "operator:test"


def _attempt(**changes) -> MaintenanceAttempt:
    fields = {
        "operation_id": OPERATION,
        "mode": "manual",
        "actor_id": ACTOR,
        "phase": "failed",
        "started_at": 100,
        "finished_at": 160,
        "candidate_version": "0.2.50",
        "error": "installation_failed",
    }
    fields.update(changes)
    return MaintenanceAttempt(**fields)


def _status(attempt: MaintenanceAttempt | None = None) -> MaintenanceStatus:
    return MaintenanceStatus(MaintenancePolicy(), "0.2.49", "2026-09-30", 1_800_000_000, attempt)


# --- MaintenanceError -------------------------------------------------------


def test_unknown_failure_codes_are_reported_as_internal_errors():
    assert MaintenanceError("busy").code == "busy"
    assert MaintenanceError("secret detail from an upstream").code == "internal_error"
    assert str(MaintenanceError("secret detail from an upstream")) == "internal_error"


# --- MaintenanceAttempt -----------------------------------------------------


@pytest.mark.parametrize(
    "fields",
    [
        {"phase": "accepted", "finished_at": None, "error": None},
        {"phase": "running", "finished_at": None, "error": None, "candidate_version": None},
        {"phase": "succeeded", "error": None},
        {"phase": "failed"},
        {"phase": "failed", "finished_at": 100},
    ],
)
def test_attempt_accepts_each_coherent_phase(fields):
    attempt = _attempt(**fields)
    assert attempt.phase == fields["phase"]


@pytest.mark.parametrize(
    "fields",
    [
        pytest.param({"mode": "scheduled"}, id="unknown-mode"),
        pytest.param({"phase": "paused"}, id="unknown-phase"),
        pytest.param({"finished_at": 99}, id="finished-before-start"),
        pytest.param({"phase": "running"}, id="running-yet-finished"),
        pytest.param({"phase": "accepted", "error": None}, id="accepted-yet-finished"),
        pytest.param({"finished_at": None}, id="failed-without-end"),
        pytest.param({"phase": "succeeded"}, id="succeeded-with-error"),
        pytest.param({"error": None}, id="failed-without-error"),
        pytest.param({"error": "made_up_code"}, id="unknown-error"),
    ],
)
def test_attempt_rejects_incoherent_outcomes(fields):
    with pytest.raises(MaintenanceError, match="invalid_request"):
        _attempt(**fields)


@pytest.mark.parametrize(
    "fields",
    [
        pytest.param({"operation_id": "A" * 32}, id="uppercase-operation"),
        pytest.param({"operation_id": "a" * 31}, id="short-operation"),
        pytest.param({"actor_id": "bad\nactor"}, id="control-in-actor"),
        pytest.param({"started_at": -1}, id="negative-start"),
        pytest.param({"started_at": True}, id="boolean-start"),
        pytest.param({"finished_at": 253402300800}, id="end-past-year-9999"),
        pytest.param({"candidate_version": "v1"}, id="malformed-version"),
    ],
)
def test_attempt_rejects_malformed_fields(fields):
    with pytest.raises(UpdateError, match="invalid_request"):
        _attempt(**fields)


# --- MaintenancePolicy and MaintenanceStatus --------------------------------


@pytest.mark.parametrize(
    ("fields", "error"),
    [
        ({"enabled": 1}, UpdateError),
        ({"hour": 24}, UpdateError),
        ({"minute": 60}, UpdateError),
        ({"timezone": "Europe/London"}, MaintenanceError),
        ({"window_minutes": 31}, MaintenanceError),
        ({"notice_seconds": 0}, MaintenanceError),
    ],
)
def test_policy_cannot_widen_the_reviewed_window(fields, error):
    with pytest.raises(error, match="invalid_request"):
        MaintenancePolicy(**fields)


def test_paused_policy_is_never_due_inside_its_window():
    inside = datetime(2026, 9, 30, 15, 5, tzinfo=UTC)
    assert MaintenancePolicy().due(inside, None) is True
    assert MaintenancePolicy(enabled=False).due(inside, None) is False


@pytest.mark.parametrize(
    "fields",
    [{"current_version": "latest"}, {"last_window": "x" * 11}, {"next_window": -1}],
)
def test_status_rejects_malformed_fields(fields):
    values = {
        "policy": MaintenancePolicy(),
        "current_version": "0.2.49",
        "last_window": None,
        "next_window": 0,
        "attempt": None,
    }
    values.update(fields)
    with pytest.raises(UpdateError, match="invalid_request"):
        MaintenanceStatus(**values)


def test_status_survives_a_wire_round_trip_with_and_without_an_attempt():
    for status in (_status(), _status(_attempt())):
        encoded = json.loads(json.dumps(status_to_json(status)))
        assert status_from_json(encoded) == status


# --- MaintenanceRequest -----------------------------------------------------


def test_requests_survive_a_wire_round_trip():
    requests = [
        MaintenanceRequest("status"),
        MaintenanceRequest("install", OPERATION, ACTOR),
        MaintenanceRequest("configure", OPERATION, ACTOR, False, 23, 59),
    ]
    for request in requests:
        encoded = json.loads(json.dumps(request_to_json(request)))
        assert encoded["version"] == MAINTENANCE_PROTOCOL_VERSION
        assert request_from_json(encoded) == request


@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param(("reboot",), id="unknown-action"),
        pytest.param(("status", OPERATION), id="status-with-operation"),
        pytest.param(("status", None, None, None, 1), id="status-with-hour"),
        pytest.param(("install", OPERATION, ACTOR, True), id="install-with-policy"),
        pytest.param(("install", OPERATION, ACTOR, None, None, 5), id="install-with-minute"),
    ],
)
def test_request_rejects_fields_that_do_not_belong_to_the_action(arguments):
    with pytest.raises(MaintenanceError, match="invalid_request"):
        MaintenanceRequest(*arguments)


@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param(("install",), id="install-without-operation"),
        pytest.param(("install", OPERATION), id="install-without-actor"),
        pytest.param(("configure", OPERATION, ACTOR), id="configure-without-policy"),
        pytest.param(("configure", OPERATION, ACTOR, True, 24, 0), id="configure-hour-range"),
        pytest.param(("configure", OPERATION, ACTOR, True, 1, 60), id="configure-minute-range"),
        pytest.param(("configure", OPERATION, ACTOR, 1, 1, 0), id="configure-integer-flag"),
    ],
)
def test_request_rejects_missing_or_out_of_range_fields(arguments):
    with pytest.raises(UpdateError, match="invalid_request"):
        MaintenanceRequest(*arguments)


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(lambda value: value.update(version=2), id="future-protocol"),
        pytest.param(lambda value: value.pop("minute"), id="missing-key"),
        pytest.param(lambda value: value.update(extra=None), id="extra-key"),
        pytest.param(lambda value: value.update(operation_id=7), id="numeric-operation"),
        pytest.param(lambda value: value.update(actor_id=""), id="empty-actor"),
        pytest.param(lambda value: value.update(enabled="yes"), id="text-flag"),
        pytest.param(lambda value: value.update(hour="1"), id="text-hour"),
        pytest.param(lambda value: value.update(minute=-1), id="negative-minute"),
        pytest.param(lambda value: value.update(action=None), id="missing-action"),
    ],
)
def test_request_decoder_rejects_malformed_frames(mutation):
    value = request_to_json(MaintenanceRequest("configure", OPERATION, ACTOR, True, 1, 30))
    mutation(value)
    with pytest.raises(UpdateError, match="invalid_request"):
        request_from_json(value)


def test_request_decoder_rejects_a_non_object():
    with pytest.raises(UpdateError, match="invalid_request"):
        request_from_json([])


# --- responses --------------------------------------------------------------


def test_successful_response_decodes_to_its_status():
    status = _status(_attempt(phase="succeeded", error=None))
    encoded = json.loads(json.dumps(response_to_json(status)))
    assert encoded["ok"] is True
    assert encoded["error"] is None
    assert response_from_json(encoded) == status


def test_failed_response_raises_the_supervisor_code():
    encoded = response_to_json(None, "outside_window")
    assert encoded == {
        "version": MAINTENANCE_PROTOCOL_VERSION,
        "ok": False,
        "error": "outside_window",
        "status": None,
    }
    with pytest.raises(MaintenanceError) as caught:
        response_from_json(encoded)
    assert caught.value.code == "outside_window"


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(lambda value: value.update(ok=False), id="failure-without-code"),
        pytest.param(
            lambda value: value.update(ok=False, error="busy"), id="failure-with-status",
        ),
        pytest.param(lambda value: value.update(error="busy"), id="success-with-code"),
        pytest.param(lambda value: value.update(status=None), id="success-without-status"),
        pytest.param(lambda value: value.update(error="made_up_code"), id="unknown-code"),
    ],
)
def test_response_decoder_rejects_contradictory_frames(mutation):
    value = response_to_json(_status())
    mutation(value)
    with pytest.raises(MaintenanceError) as caught:
        response_from_json(value)
    assert caught.value.code == "invalid_request"


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(lambda value: value.update(version=0), id="old-protocol"),
        pytest.param(lambda value: value.update(ok=1), id="integer-flag"),
        pytest.param(lambda value: value.update(error=5), id="numeric-code"),
        pytest.param(lambda value: value.pop("status"), id="missing-key"),
        pytest.param(lambda value: value["status"].pop("policy"), id="truncated-status"),
    ],
)
def test_response_decoder_rejects_malformed_frames(mutation):
    value = response_to_json(_status())
    mutation(value)
    with pytest.raises(UpdateError, match="invalid_request"):
        response_from_json(value)


# --- journal ----------------------------------------------------------------


def test_journal_survives_a_round_trip_with_window_and_attempt():
    journal = MaintenanceJournal(
        MaintenancePolicy(enabled=False, hour=3, minute=15), "2026-09-30", _attempt(),
    )
    encoded = json.loads(json.dumps(journal_to_json(journal)))
    assert journal_from_json(encoded) == journal


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(lambda value: value.update(version=2), id="future-version"),
        pytest.param(lambda value: value.update(last_window=20260930), id="numeric-window"),
        pytest.param(lambda value: value.update(last_window="2026-9-30"), id="short-window"),
        pytest.param(lambda value: value.update(last_window="2026/09-30"), id="first-separator"),
        pytest.param(lambda value: value.update(last_window="2026-09/30"), id="second-separator"),
        pytest.param(lambda value: value["attempt"].update(phase="paused"), id="unknown-phase"),
        pytest.param(lambda value: value["attempt"].pop("error"), id="truncated-attempt"),
        pytest.param(lambda value: value.pop("attempt"), id="missing-key"),
    ],
)
def test_journal_decoder_reports_every_defect_as_corrupt_state(mutation):
    value = journal_to_json(MaintenanceJournal(MaintenancePolicy(), "2026-09-30", _attempt()))
    mutation(value)
    with pytest.raises(MaintenanceError) as caught:
        journal_from_json(value)
    assert caught.value.code == "state_corrupt"


def test_journal_decoder_rejects_a_non_object():
    with pytest.raises(MaintenanceError, match="state_corrupt"):
        journal_from_json("{}")


# --- MaintenanceState -------------------------------------------------------


def _state(tmp_path: Path) -> MaintenanceState:
    return MaintenanceState(tmp_path / "state" / "supervisor.json", "0.2.49")


def test_state_file_is_private_ascii_json_with_no_leftover_temporary(tmp_path):
    state = _state(tmp_path)
    state.configure(enabled=False, hour=4, minute=45)

    assert sorted(path.name for path in state.path.parent.iterdir()) == ["supervisor.json"]
    raw = state.path.read_bytes()
    assert raw.endswith(b"\n")
    assert json.loads(raw.decode("ascii"))["policy"]["hour"] == 4
    if os.name == "posix":
        assert state.path.stat().st_mode & 0o777 == 0o600
        assert state.path.parent.stat().st_mode & 0o777 == 0o700
    assert MaintenanceState(state.path, "0.2.49").journal == state.journal


def test_attempt_lifecycle_is_durable_and_records_its_outcome(tmp_path):
    state = _state(tmp_path)
    state.accept(OPERATION, "manual", ACTOR, now=100)
    assert state.start(OPERATION).phase == "running"
    assert state.bind_candidate(OPERATION, "0.2.50").candidate_version == "0.2.50"
    state.finish(OPERATION, now=50, error="installation_failed")

    reloaded = MaintenanceState(state.path, "0.2.49").journal.attempt
    assert reloaded == MaintenanceAttempt(
        OPERATION, "manual", ACTOR, "failed", 100, 100, "0.2.50", "installation_failed",
    )

    other = "b" * 32
    state.accept(other, "manual", ACTOR, now=200)
    state.finish(other, now=260)
    finished = MaintenanceState(state.path, "0.2.49").journal.attempt
    assert (finished.phase, finished.finished_at, finished.error) == ("succeeded", 260, None)


def test_operations_on_an_unknown_attempt_conflict(tmp_path):
    state = _state(tmp_path)
    with pytest.raises(MaintenanceError, match="conflict"):
        state.start(OPERATION)
    state.accept(OPERATION, "manual", ACTOR, now=100)
    with pytest.raises(MaintenanceError, match="conflict"):
        state.finish("b" * 32, now=101)
    assert state.journal.attempt.phase == "accepted"


def test_new_operation_ids_are_distinct_request_identifiers():
    first, second = MaintenanceState.new_operation_id(), MaintenanceState.new_operation_id()
    assert first != second
    assert MaintenanceRequest("install", first, ACTOR).operation_id == first


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(b"\xff\xfe", id="not-ascii"),
        pytest.param(b"{", id="not-json"),
        pytest.param(b"[" * 100_000, id="unbounded-nesting"),
        pytest.param(b" " * (STATE_BYTES + 1), id="oversized"),
    ],
)
def test_unreadable_state_content_fails_closed(tmp_path, content):
    state = _state(tmp_path)
    state.path.write_bytes(content)
    os.chmod(state.path, 0o600)
    with pytest.raises(MaintenanceError, match="state_corrupt"):
        MaintenanceState(state.path, "0.2.49")


def test_state_path_that_is_not_a_regular_file_fails_closed(tmp_path):
    state = _state(tmp_path)
    state.path.unlink()
    state.path.mkdir()
    with pytest.raises(MaintenanceError, match="state_corrupt"):
        MaintenanceState(state.path, "0.2.49")


def test_hard_linked_state_fails_closed(tmp_path):
    state = _state(tmp_path)
    os.link(state.path, state.path.with_name("alias.json"))
    with pytest.raises(MaintenanceError, match="state_corrupt"):
        MaintenanceState(state.path, "0.2.49")


def test_state_that_disappears_after_inspection_fails_closed(tmp_path, monkeypatch):
    state = _state(tmp_path)

    def vanish(path):
        raise FileNotFoundError(path)

    monkeypatch.setattr(Path, "read_bytes", vanish)
    with pytest.raises(MaintenanceError, match="state_corrupt"):
        MaintenanceState(state.path, "0.2.49")


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX ownership and modes")
def test_state_readable_by_other_users_fails_closed(tmp_path):
    state = _state(tmp_path)
    os.chmod(state.path, 0o640)
    with pytest.raises(MaintenanceError, match="state_corrupt"):
        MaintenanceState(state.path, "0.2.49")


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX ownership and modes")
def test_state_owned_by_another_user_fails_closed(tmp_path, monkeypatch):
    state = _state(tmp_path)
    monkeypatch.setattr(state_module.os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(MaintenanceError, match="state_corrupt"):
        MaintenanceState(state.path, "0.2.49")


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX ownership and modes")
def test_state_is_not_written_into_a_shared_directory(tmp_path):
    state = _state(tmp_path)
    before = state.path.read_bytes()
    os.chmod(state.path.parent, 0o750)
    with pytest.raises(MaintenanceError, match="state_corrupt"):
        state.configure(enabled=False, hour=2, minute=0)
    assert state.path.read_bytes() == before
    assert state.journal.policy.enabled is True


def test_oversized_journal_is_not_written(tmp_path, monkeypatch):
    state = _state(tmp_path)
    before = state.path.read_bytes()
    monkeypatch.setattr(
        state_module, "journal_to_json", lambda journal: {"padding": "x" * STATE_BYTES},
    )
    with pytest.raises(MaintenanceError, match="state_corrupt"):
        state.configure(enabled=False, hour=2, minute=0)
    assert state.path.read_bytes() == before


def test_failed_replace_keeps_the_previous_state_and_removes_the_temporary(
    tmp_path, monkeypatch,
):
    state = _state(tmp_path)
    before = state.path.read_bytes()

    def refuse(source, destination):
        raise PermissionError("replace refused")

    monkeypatch.setattr(state_module.os, "replace", refuse)
    with pytest.raises(MaintenanceError, match="state_corrupt"):
        state.configure(enabled=False, hour=2, minute=0)

    assert state.path.read_bytes() == before
    assert state.journal.policy.enabled is True
    assert sorted(path.name for path in state.path.parent.iterdir()) == ["supervisor.json"]


def test_failed_write_closes_and_removes_the_temporary(tmp_path, monkeypatch):
    state = _state(tmp_path)

    def refuse(descriptor):
        raise OSError("disk full")

    monkeypatch.setattr(state_module.os, "fsync", refuse)
    with pytest.raises(MaintenanceError, match="state_corrupt"):
        state.configure(enabled=False, hour=2, minute=0)
    assert sorted(path.name for path in state.path.parent.iterdir()) == ["supervisor.json"]


# --- board notice -----------------------------------------------------------


def _notice(tmp_path: Path, **changes):
    arguments = {
        "database": tmp_path / "bus.db",
        "backup_dir": tmp_path / "backups",
        "operation_id": OPERATION,
        "version": "0.2.50",
        "scheduled_at": 1_800_000_000,
        "automatic": True,
    }
    arguments.update(changes)
    return arguments


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param({"database": Path("bus.db")}, id="relative-database"),
        pytest.param({"backup_dir": Path("backups")}, id="relative-backups"),
        pytest.param({"operation_id": "A" * 32}, id="uppercase-operation"),
        pytest.param({"operation_id": "a" * 33}, id="long-operation"),
        pytest.param({"version": "0.2"}, id="short-version"),
        pytest.param({"scheduled_at": 1.5}, id="fractional-time"),
        pytest.param({"scheduled_at": True}, id="boolean-time"),
        pytest.param({"scheduled_at": -1}, id="negative-time"),
        pytest.param({"scheduled_at": 253402300800}, id="time-past-year-9999"),
        pytest.param({"automatic": 1}, id="integer-flag"),
    ],
)
def test_invalid_notice_is_rejected_before_the_database_is_opened(
    tmp_path, monkeypatch, changes,
):
    def unexpected(*args, **kwargs):
        raise AssertionError("an invalid notice must not reach the store")

    monkeypatch.setattr(notice_module, "SQLiteStore", unexpected)
    with pytest.raises(ValueError, match="invalid maintenance notice"):
        notice_module.publish_notice(**_notice(tmp_path, **changes))
    assert not (tmp_path / "bus.db").exists()


@pytest.mark.parametrize(("automatic", "mode"), [(True, "automatic"), (False, "operator-triggered")])
def test_notice_records_how_the_installation_was_started(tmp_path, monkeypatch, automatic, mode):
    created = {}

    class Store:
        def __init__(self, database, *, backup_dir, busy_timeout_ms):
            created.update(database=database, backup_dir=backup_dir, busy=busy_timeout_ms)

        def create_maintenance_announcement(self, **message):
            created.update(message)
            return type("Message", (), {"seq": 41})()

    monkeypatch.setattr(notice_module, "SQLiteStore", Store)
    sequence = notice_module.publish_notice(
        **_notice(tmp_path, automatic=automatic),
        now=datetime(2026, 9, 30, 15, 0, tzinfo=UTC),
    )

    assert sequence == 41
    assert created["busy"] == 30_000
    assert created["created_at"] == datetime(2026, 9, 30, 15, 0, tzinfo=UTC)
    assert created["request_id"] == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    assert "release 0.2.50 is scheduled for installation at 2027-01-15T08:00:00+00:00" in (
        created["body"]
    )
    assert json.loads(created["metadata_json"]) == {
        "maintenance": {
            "automatic": automatic,
            "mode": mode,
            "operation_id": OPERATION,
            "scheduled_at": 1_800_000_000,
            "version": "0.2.50",
        }
    }


def _chained(cause: BaseException) -> Exception:
    try:
        try:
            raise cause
        except BaseException as inner:
            raise RuntimeError("wrapper with sensitive text") from inner
    except RuntimeError as outer:
        return outer


def _named_sqlite_error(name: object) -> sqlite3.Error:
    error = sqlite3.OperationalError("database is locked: /secret/path")
    error.sqlite_errorname = name
    return error


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (_named_sqlite_error("SQLITE_BUSY"), "SQLITE_BUSY"),
        (_chained(_named_sqlite_error("SQLITE_READONLY_DBMOVED")), "SQLITE_READONLY_DBMOVED"),
        (_named_sqlite_error("sqlite busy; rm -rf"), "SQLITE_ERROR"),
        (_named_sqlite_error(None), "SQLITE_ERROR"),
        (PermissionError("secret/path"), "NON_SQLITE_ERROR"),
        (_chained(ValueError("secret")), "NON_SQLITE_ERROR"),
    ],
)
def test_failure_code_names_only_a_bounded_sqlite_cause(error, code):
    assert notice_module._failure_code(error) == code


def test_failure_code_stops_following_an_endless_cause_chain():
    first, second = RuntimeError("first"), RuntimeError("second")
    first.__cause__, second.__cause__ = second, first
    assert notice_module._failure_code(first) == "NON_SQLITE_ERROR"


def test_main_prints_the_published_sequence(monkeypatch, capsys):
    received = {}

    def publish(**kwargs):
        received.update(kwargs)
        return 7

    monkeypatch.setattr(notice_module, "publish_notice", publish)
    code = notice_module.main([
        "--database", "/var/lib/strugglebus/strugglebus.db",
        "--backup-dir", "/var/backups/strugglebus",
        "--operation-id", OPERATION,
        "--version", "0.2.50",
        "--scheduled-at", "1800000000",
        "--automatic",
    ])

    assert code == 0
    assert json.loads(capsys.readouterr().out) == {"ok": True, "sequence": 7}
    assert received == {
        "database": Path("/var/lib/strugglebus/strugglebus.db"),
        "backup_dir": Path("/var/backups/strugglebus"),
        "operation_id": OPERATION,
        "version": "0.2.50",
        "scheduled_at": 1_800_000_000,
        "automatic": True,
    }


def test_main_reports_an_invalid_notice_without_its_text(capsys):
    code = notice_module.main([
        "--database", "relative.db",
        "--backup-dir", "/var/backups/strugglebus",
        "--operation-id", OPERATION,
        "--version", "0.2.50",
        "--scheduled-at", "1",
    ])
    assert code == 1
    assert json.loads(capsys.readouterr().out) == {
        "cause": "NON_SQLITE_ERROR",
        "error": "maintenance_notice_failed",
        "ok": False,
    }
