"""Execute maintenance recovery rather than a second model of its phases."""

import copy
from contextlib import closing, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import stat
import shutil
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest


HARNESS = Path(__file__).resolve().parents[1] / "deploy" / "tests" / "maintenance_rehearsal.py"
SPEC = importlib.util.spec_from_file_location("maintenance_rehearsal", HARNESS)
assert SPEC is not None and SPEC.loader is not None
rehearsal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rehearsal)
maintenance = rehearsal.maintenance


@pytest.mark.parametrize("optimized", [False, True])
def test_rehearsal_invariants_cannot_be_disabled_by_python_optimization(optimized):
    command = [sys.executable]
    if optimized:
        command.append("-O")
    command.extend([
        "-c",
        "import importlib.util, sys; "
        "spec = importlib.util.spec_from_file_location('rehearsal', sys.argv[1]); "
        "module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); "
        "module.require(False, 'rehearsal invariant failed')",
        str(HARNESS),
    ])
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 1
    assert "AssertionError: rehearsal invariant failed" in result.stderr


@pytest.fixture
def scenario(tmp_path):
    try:
        return rehearsal.Scenario(tmp_path / "rehearsal")
    except OSError as error:
        if os.name == "nt" and getattr(error, "winerror", None) == 1314:
            pytest.skip("Windows developer mode or symlink privilege is required")
        raise


@pytest.fixture
def boundary_scenario(tmp_path):
    return rehearsal.Scenario(tmp_path / "rehearsal", selection=False)


@pytest.mark.parametrize("checkpoint", rehearsal.BASELINE_CHECKPOINTS)
def test_real_process_death_recovers_every_baseline_boundary(scenario, checkpoint):
    rehearsal.rehearse_baseline(scenario, checkpoint)


@pytest.mark.parametrize("checkpoint", rehearsal.HANDOFF_CHECKPOINTS)
def test_next_completed_upgrade_keeps_at_most_two_pins(scenario, checkpoint):
    rehearsal.rehearse_handoff(scenario, checkpoint)


@pytest.mark.parametrize("failure", ("start", "readiness", "identity", "identity-change", "timer"))
def test_failed_candidate_never_restarts_predecessor_or_restores_database(scenario, failure):
    rehearsal.rehearse_failure(scenario, failure)


def test_unresolved_operation_blocks_distinct_upgrade_before_stop(scenario):
    scenario.crash("snapshot-ready")
    record = scenario.journal()
    commands = rehearsal.read_json(scenario.os_state)["commands"]
    other = scenario.prepare("0.4.0")
    result = scenario.invoke(other)
    assert result.returncode == 1
    assert "unresolved maintenance" in result.stderr
    assert scenario.journal() == record
    assert rehearsal.read_json(scenario.os_state)["commands"] == commands
    scenario.success()
    scenario.assert_complete()


def test_existing_selection_is_verified_without_fabricating_completed_operation(scenario):
    request = scenario.prepare("0.2.0")
    response = scenario.success(request)
    assert response == {"state": "verified-existing", "release": "0.2.0"}
    assert maintenance.Journal(scenario.state).read() is None
    assert not scenario.pins()
    assert not rehearsal.read_json(scenario.os_state)["starts"]
    assert rehearsal.read_json(scenario.os_state)["commands"] == [
        ["systemctl", "is-active", "strugglebus-backup.timer"],
        ["systemctl", "is-enabled", "strugglebus-backup.timer"],
    ]


@pytest.mark.parametrize("timer_field", ("timer_active", "timer_enabled"))
def test_legacy_selection_never_repairs_timer_without_journal(scenario, timer_field):
    request = scenario.prepare("0.2.0")
    state = rehearsal.read_json(scenario.os_state)
    state[timer_field] = False
    rehearsal.write_json(scenario.os_state, state)
    result = scenario.invoke(request)
    assert result.returncode == 1
    assert maintenance.Journal(scenario.state).read() is None
    after = rehearsal.read_json(scenario.os_state)
    assert after["active"] and not after[timer_field]
    assert not after["starts"]
    assert all(command[1] in ("is-active", "is-enabled") for command in after["commands"])
    assert not scenario.pins()


@pytest.mark.parametrize("failure", ("readiness", "identity"))
def test_existing_selection_failure_does_not_fabricate_provenance(scenario, failure):
    request = scenario.prepare("0.2.0")
    scenario.failure(failure)
    result = scenario.invoke(request)
    assert result.returncode == 1
    assert maintenance.Journal(scenario.state).read() is None
    assert not scenario.pins()


def test_completed_receipt_reconciles_disabled_timer_and_stopped_candidate(scenario):
    scenario.success()
    operation = scenario.journal()["operation_id"]
    state = rehearsal.read_json(scenario.os_state)
    state.update(active=False, timer_active=False, timer_enabled=False)
    rehearsal.write_json(scenario.os_state, state)
    scenario.success()
    scenario.assert_complete()
    assert scenario.journal()["operation_id"] == operation


def test_completed_retry_accepts_legitimate_local_unfreeze(scenario):
    scenario.success()
    original = scenario.journal()
    pin = scenario.pins()[0].read_bytes()
    with closing(sqlite3.connect(scenario.database)) as connection, connection:
        connection.execute(
            "UPDATE simulated_safety SET frozen=0, credentials='legitimate-local-unfreeze'"
        )
    response = scenario.success()
    assert response["operation_id"] == original["operation_id"]
    assert scenario.journal()["phase"] == "complete"
    assert scenario.journal()["error"] is None
    assert scenario.journal()["snapshot"] == original["snapshot"]
    assert original["snapshot"]["database"]["frozen"]
    assert scenario.pins()[0].read_bytes() == pin
    state = rehearsal.read_json(scenario.os_state)
    assert state["active"] and state["timer_active"]
    facts = rehearsal.RehearsalHost(scenario.request).database_facts(scenario.database)
    assert not facts["frozen"]
    assert facts["credential_state_sha256"] == maintenance.digest(b"legitimate-local-unfreeze")


@pytest.mark.parametrize("completed_retry", (False, True))
def test_tls_readiness_is_bracketed_by_same_running_identity(scenario, completed_retry):
    if completed_retry:
        scenario.success()
    before = len(rehearsal.read_json(scenario.os_state)["observations"])
    scenario.success()
    observations = rehearsal.read_json(scenario.os_state)["observations"][before:]
    assert [observation["kind"] for observation in observations] == [
        "readiness", "running", "readiness", "running",
    ]
    assert len({observation["generation"] for observation in observations}) == 1
    assert scenario.journal()["evidence"]["start_ticks"] == observations[-1]["generation"]


@pytest.mark.parametrize("completed_retry", (False, True))
def test_identity_replacement_during_second_tls_probe_is_not_success(scenario, completed_retry):
    if completed_retry:
        scenario.success()
    scenario.failure("identity-during-tls")
    result = scenario.invoke()
    assert result.returncode == 1
    assert scenario.journal()["error"] == "maintenance-failed"
    assert not rehearsal.read_json(scenario.os_state)["active"]
    assert len(scenario.pins()) == 1
    assert scenario.current.resolve() == scenario.releases / "0.3.0"
    assert "0.2.0" not in rehearsal.read_json(scenario.os_state)["starts"]
    scenario.failure(None)
    scenario.success()
    scenario.assert_complete()


@pytest.mark.parametrize("target", ("receipt", "pin", "saved-config", "predecessor-marker"))
def test_previous_completed_provenance_is_checked_before_new_snapshot(scenario, target):
    scenario.success()
    previous = scenario.journal()
    candidate = scenario.prepare("0.4.0")
    scenario.crash("prepared", candidate)
    record = scenario.journal()
    assert record["previous_operation"] == previous
    assert record["previous_pin"] == previous["snapshot"]
    assert record["previous_config"] == previous["binding"]["config_sha256"]
    if target == "receipt":
        record["previous_operation"]["predecessor_config"] = "f" * 64
        rehearsal.write_json(scenario.state / "operation.json", record)
    elif target == "pin":
        path = scenario.pins()[0]
        path.write_bytes(path.read_bytes() + b"tampered")
    elif target == "saved-config":
        path = scenario.state / f"predecessor-{previous['operation_id']}.service"
        path.write_bytes(path.read_bytes() + b"\n# tampered\n")
    else:
        marker = scenario.releases / "0.2.0" / "marker.json"
        value = rehearsal.read_json(marker)
        value["wheel_sha256"] = "e" * 64
        rehearsal.write_json(marker, value)
    commands = rehearsal.read_json(scenario.os_state)["commands"]
    result = scenario.invoke(candidate)
    assert result.returncode == 1
    assert scenario.journal()["phase"] == "prepared"
    assert scenario.journal()["previous_operation"] is not None
    assert len(scenario.pins()) == 1
    assert rehearsal.read_json(scenario.os_state)["commands"] == commands
    assert scenario.current.resolve() == scenario.releases / "0.3.0"


@pytest.mark.parametrize("target", ("candidate", "live", "saved-predecessor", "helper", "pin"))
def test_tampered_provenance_never_activates_candidate(scenario, target):
    scenario.crash("snapshot-ready")
    record = scenario.journal()
    paths = {
        "candidate": Path(scenario.request["candidate_config"]),
        "live": scenario.unit,
        "saved-predecessor": scenario.state / f"predecessor-{record['operation_id']}.service",
        "helper": scenario.helpers / "strugglebus-maintenance",
        "pin": scenario.pins()[0],
    }
    path = paths[target]
    path.write_bytes(path.read_bytes() + b"\n# tampered\n")
    result = scenario.invoke()
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert scenario.current.resolve() == scenario.releases / "0.2.0"
    assert not rehearsal.read_json(scenario.os_state)["starts"]
    assert scenario.journal()["phase"] != "complete"


@pytest.mark.parametrize("mutation", (
    "version", "phase", "field", "snapshot-operation", "snapshot-sha", "revision",
    "identity-field", "identity-type", "previous-config", "missing-previous-operation",
))
def test_malformed_journal_fails_before_systemd_commands(scenario, mutation):
    scenario.crash("snapshot-ready")
    record = scenario.journal()
    if mutation == "version":
        record["version"] = 999
    elif mutation == "phase":
        record["phase"] = "rolled-back"
    elif mutation == "field":
        record["unexpected"] = True
    elif mutation == "snapshot-operation":
        record["snapshot"]["operation_id"] = "f" * 32
    elif mutation == "snapshot-sha":
        record["snapshot"]["sha256"] = "invalid"
    elif mutation == "revision":
        record["revision"] = True
    elif mutation == "identity-field":
        del record["database_identity"]["inode"]
    elif mutation == "identity-type":
        record["database_identity"]["device"] = True
    elif mutation == "previous-config":
        record["previous_config"] = "not-a-sha256"
    elif mutation == "missing-previous-operation":
        del record["previous_operation"]
    rehearsal.write_json(scenario.state / "operation.json", record)
    commands = rehearsal.read_json(scenario.os_state)["commands"]
    result = scenario.invoke()
    assert result.returncode == 1
    assert rehearsal.read_json(scenario.os_state)["commands"] == commands


def test_duplicate_record_fields_are_rejected(scenario):
    scenario.crash("prepared")
    path = scenario.state / "operation.json"
    path.write_bytes(path.read_bytes()[:-1] + b',"phase":"complete"}')
    with pytest.raises(maintenance.MaintenanceError, match="duplicate"):
        maintenance.Journal(scenario.state).read()


@pytest.mark.parametrize("target", ("pin", "candidate", "journal"))
def test_provenance_symlinks_are_not_followed(scenario, target):
    scenario.crash("snapshot-ready")
    path = {
        "pin": scenario.pins()[0],
        "candidate": Path(scenario.request["candidate_config"]),
        "journal": scenario.state / "operation.json",
    }[target]
    moved = path.with_name(f"untrusted-{path.name}")
    path.rename(moved)
    path.symlink_to(moved)
    result = scenario.invoke()
    assert result.returncode == 1
    assert not rehearsal.read_json(scenario.os_state)["starts"]


def test_database_replacement_is_not_mistaken_for_original_identity(scenario):
    scenario.crash("snapshot-ready")
    original = scenario.database.with_suffix(".original")
    scenario.database.rename(original)
    scenario.database.write_bytes(original.read_bytes())
    result = scenario.invoke()
    assert result.returncode == 1
    assert "database identity changed" in result.stderr
    assert not rehearsal.read_json(scenario.os_state)["starts"]


def test_prepared_journal_binds_exact_request_shape_and_database_identity(scenario):
    scenario.crash("prepared")
    record = scenario.journal()
    assert set(record) == {
        "version", "revision", "operation_id", "phase", "binding", "predecessor",
        "predecessor_config", "database_before", "database_identity", "snapshot",
        "previous_pin", "previous_config", "previous_operation", "error", "evidence",
    }
    assert record["binding"] == scenario.request
    assert record["previous_config"] is None
    assert record["previous_operation"] is None
    assert record["database_identity"] == rehearsal.RehearsalHost(scenario.request).database_identity()
    assert set(record["database_identity"]) == {"device", "inode"}
    assert all(type(value) is int for value in record["database_identity"].values())


@pytest.mark.parametrize("checkpoint", ("prepared", "stop-intent"))
def test_predecessor_traffic_before_stop_is_captured_in_stopped_snapshot(scenario, checkpoint):
    scenario.crash(checkpoint)
    before = scenario.journal()
    assert rehearsal.read_json(scenario.os_state)["active"]
    with closing(sqlite3.connect(scenario.database)) as connection, connection:
        connection.execute("INSERT INTO messages(body) VALUES('legitimate-predecessor-traffic')")
        connection.execute("UPDATE simulated_safety SET credentials='legitimate-credential-rotation'")
    expected_facts = rehearsal.RehearsalHost(scenario.request).database_facts(scenario.database)
    assert expected_facts != before["database_before"]
    scenario.success()
    scenario.assert_complete()
    record = scenario.journal()
    assert record["operation_id"] == before["operation_id"]
    assert record["database_identity"] == before["database_identity"]
    assert record["database_before"] == expected_facts
    assert record["snapshot"]["database"] == expected_facts
    with closing(sqlite3.connect(scenario.pins()[0])) as connection:
        assert connection.execute(
            "SELECT count(*) FROM messages WHERE body='legitimate-predecessor-traffic'"
        ).fetchone() == (1,)


@pytest.mark.parametrize("mutation", ("freeze", "credentials", "schema"))
def test_changed_stopped_database_safety_facts_block_candidate_start(scenario, mutation):
    scenario.crash("snapshot-ready")
    pin = scenario.pins()[0].read_bytes()
    with closing(sqlite3.connect(scenario.database)) as connection, connection:
        if mutation == "freeze":
            connection.execute("UPDATE simulated_safety SET frozen=0")
        elif mutation == "credentials":
            connection.execute("UPDATE simulated_safety SET credentials='changed'")
        else:
            connection.execute("PRAGMA user_version=11")
    result = scenario.invoke()
    assert result.returncode == 1
    assert not rehearsal.read_json(scenario.os_state)["starts"]
    assert scenario.current.resolve() == scenario.releases / "0.2.0"
    assert scenario.pins()[0].read_bytes() == pin
    assert scenario.journal()["phase"] != "complete"


def test_freeze_loss_after_possible_candidate_start_is_not_auto_restored(scenario):
    scenario.crash("started")
    pin = scenario.pins()[0].read_bytes()
    with closing(sqlite3.connect(scenario.database)) as connection, connection:
        connection.execute("UPDATE simulated_safety SET frozen=0")
    result = scenario.invoke()
    assert result.returncode == 1
    assert not rehearsal.read_json(scenario.os_state)["active"]
    assert scenario.current.resolve() == scenario.releases / "0.3.0"
    assert scenario.pins()[0].read_bytes() == pin
    with closing(sqlite3.connect(scenario.database)) as connection:
        assert connection.execute("SELECT frozen FROM simulated_safety").fetchone() == (0,)
    assert scenario.journal()["phase"] != "complete"


def test_predecessor_reselection_after_start_intent_is_blocked(scenario):
    scenario.crash("start-intent")
    scenario.current.unlink()
    scenario.current.symlink_to(scenario.releases / "0.2.0", target_is_directory=True)
    result = scenario.invoke()
    assert result.returncode == 1
    assert not rehearsal.read_json(scenario.os_state)["starts"]
    assert scenario.journal()["phase"] == "start-intent"
    assert len(scenario.pins()) == 1


def test_missing_completed_pin_does_not_recreate_a_snapshot(scenario):
    scenario.success()
    operation = scenario.journal()["operation_id"]
    scenario.pins()[0].unlink()
    result = scenario.invoke()
    assert result.returncode == 1
    assert scenario.journal()["operation_id"] == operation
    assert scenario.journal()["error"] == "maintenance-failed"
    assert not scenario.pins()
    assert not rehearsal.read_json(scenario.os_state)["active"]


@pytest.mark.parametrize("target", ("selection", "unit", "predecessor-marker"))
def test_completed_record_drift_is_not_reported_as_success(scenario, target):
    scenario.success()
    if target == "selection":
        scenario.current.unlink()
        scenario.current.symlink_to(scenario.releases / "0.4.0", target_is_directory=True)
    elif target == "unit":
        scenario.unit.write_bytes(scenario.unit.read_bytes() + b"\n# changed\n")
    else:
        marker = scenario.releases / "0.2.0" / "marker.json"
        value = rehearsal.read_json(marker)
        value["wheel_sha256"] = "e" * 64
        rehearsal.write_json(marker, value)
    commands = rehearsal.read_json(scenario.os_state)["commands"]
    result = scenario.invoke()
    assert result.returncode == 1
    assert rehearsal.read_json(scenario.os_state)["commands"] == commands


def test_journal_compare_and_swap_rejects_stale_revision_and_operation(scenario):
    scenario.crash("prepared")
    journal = maintenance.Journal(scenario.state)
    record = journal.read()
    stale = copy.deepcopy(record)
    journal.write(record, "stop-intent")
    with pytest.raises(maintenance.MaintenanceError, match="changed concurrently"):
        journal.write(stale, "stopped")
    other = copy.deepcopy(record)
    other["operation_id"] = "f" * 32
    with pytest.raises(maintenance.MaintenanceError, match="changed concurrently"):
        journal.write(other)
    assert journal.read() == record


def test_journal_rejects_backward_transition_and_unresolved_replacement(scenario):
    scenario.crash("snapshot-ready")
    journal = maintenance.Journal(scenario.state)
    record = journal.read()
    with pytest.raises(maintenance.MaintenanceError, match="invalid maintenance transition"):
        journal.write(record, "prepared")
    with pytest.raises(maintenance.MaintenanceError, match="unresolved"):
        journal.replace_completed(record)


def test_orphan_reconciliation_removes_only_private_managed_staging_files(boundary_scenario):
    scenario = boundary_scenario
    orphan_content = b"orphaned configuration"
    sha = maintenance.digest(orphan_content)
    operation = "a" * 32
    nonce = "b" * 16
    orphans = {
        f"predecessor-{operation}.service": b"orphaned predecessor",
        f"candidate-{sha}.service": orphan_content,
        f".operation.json.{nonce}": b"partial JSON",
        f".predecessor-{operation}.service.{nonce}": b"partial predecessor",
        f".candidate-{sha}.service.{nonce}": b"partial candidate",
    }
    for name, content in orphans.items():
        path = scenario.state / name
        path.write_bytes(content)
        path.chmod(0o600)
    unrelated = scenario.state / "operator-notes"
    maintenance.publish(unrelated, b"leave unrelated files alone")
    candidate = Path(scenario.request["candidate_config"])
    maintenance.Journal(scenario.state).reconcile_staging(None, candidate)
    assert all(not (scenario.state / name).exists() for name in orphans)
    assert candidate.read_bytes() == scenario.config("0.3.0")
    assert unrelated.read_bytes() == b"leave unrelated files alone"
    assert scenario.os_state.exists()


def test_orphan_reconciliation_retains_both_handoff_receipts_and_configs(scenario):
    scenario.success()
    previous = scenario.journal()
    candidate = scenario.prepare("0.4.0")
    scenario.crash("prepared", candidate)
    record = scenario.journal()
    retained = [
        scenario.state / "operation.json",
        scenario.state / f"predecessor-{record['operation_id']}.service",
        scenario.state / f"predecessor-{previous['operation_id']}.service",
        Path(candidate["candidate_config"]),
        Path(scenario.request["candidate_config"]),
    ]
    contents = {path: path.read_bytes() for path in retained}
    maintenance.Journal(scenario.state).reconcile_staging(record, Path(candidate["candidate_config"]))
    assert {path: path.read_bytes() for path in retained} == contents
    assert scenario.journal()["previous_operation"] == previous


def test_orphan_reconciliation_rejects_misbound_candidate_content(boundary_scenario):
    scenario = boundary_scenario
    path = scenario.state / f"candidate-{'f' * 64}.service"
    maintenance.publish(path, b"content does not match the claimed digest")
    with pytest.raises(maintenance.MaintenanceError, match="not content-bound"):
        maintenance.Journal(scenario.state).reconcile_staging(
            None, Path(scenario.request["candidate_config"]),
        )
    assert path.exists()


def test_orphan_reconciliation_scan_is_bounded_before_deletion(boundary_scenario):
    scenario = boundary_scenario
    for index in range(129):
        maintenance.publish(
            scenario.state / f"predecessor-{index:032x}.service", b"orphaned predecessor",
        )
    before = set(scenario.state.iterdir())
    with pytest.raises(maintenance.MaintenanceError, match="bounded recovery limit"):
        maintenance.Journal(scenario.state).reconcile_staging(
            None, Path(scenario.request["candidate_config"]),
        )
    assert set(scenario.state.iterdir()) == before


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission contract")
def test_publish_applies_the_requested_mode_under_a_strict_umask(tmp_path):
    target = tmp_path / "strugglebus.service"
    previous = os.umask(0o077)
    try:
        maintenance.publish(target, b"[Unit]\n", mode=0o644)
    finally:
        os.umask(previous)
    assert stat.S_IMODE(target.stat().st_mode) == 0o644


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and permission contract")
@pytest.mark.parametrize("unsafe", ("symlink", "hardlink", "permissions"))
def test_orphan_reconciliation_never_removes_unsafe_evidence(scenario, unsafe):
    target = scenario.state / "unrelated-evidence"
    maintenance.publish(target, b"must remain untouched")
    orphan = scenario.state / f"predecessor-{'f' * 32}.service"
    if unsafe == "symlink":
        orphan.symlink_to(target)
    elif unsafe == "hardlink":
        os.link(target, orphan)
    else:
        maintenance.publish(orphan, b"unsafe writable evidence", mode=0o666)
        orphan.chmod(0o666)
    with pytest.raises((maintenance.MaintenanceError, OSError)):
        maintenance.Journal(scenario.state).reconcile_staging(
            None, Path(scenario.request["candidate_config"]),
        )
    assert os.path.lexists(orphan)
    assert target.read_bytes() == b"must remain untouched"


def test_supported_candidate_schemas_keep_pace_with_the_application() -> None:
    """The deploy gate must not silently lag a shipped migration.

    Schema 13 shipped while this helper still accepted only 10-12, which made
    the candidate undeployable and was only discovered during a maintenance
    window. The gate stays explicit and fail-closed; this test is what makes
    forgetting to widen it a test failure rather than an outage-time surprise.
    """

    from strugglebus.migrations import LATEST_SCHEMA_VERSION

    assert LATEST_SCHEMA_VERSION in maintenance.SUPPORTED_CANDIDATE_SCHEMAS
    assert maintenance.SUPPORTED_CANDIDATE_SCHEMAS == tuple(
        sorted(maintenance.SUPPORTED_CANDIDATE_SCHEMAS)
    )
    # It is an allowlist, not an upper bound: an unreviewed future schema is
    # still refused.
    assert LATEST_SCHEMA_VERSION + 1 not in maintenance.SUPPORTED_CANDIDATE_SCHEMAS


def test_unreviewed_candidate_schema_is_refused_without_side_effects(
    boundary_scenario,
) -> None:
    scenario = boundary_scenario
    request = copy.deepcopy(scenario.request)
    request["candidate_schema"] = max(maintenance.SUPPORTED_CANDIDATE_SCHEMAS) + 1
    with pytest.raises(maintenance.MaintenanceError):
        maintenance.run(request, rehearsal.RehearsalHost(request))
    assert maintenance.Journal(scenario.state).read() is None
    assert not rehearsal.read_json(scenario.os_state)["commands"]


@pytest.mark.parametrize("mutation", (
    "extra", "public-bind", "secret", "http", "schema", "config-path",
    "config-basename", "helper-missing", "helper-not-mapping",
))
def test_strict_request_validation_has_no_side_effects(boundary_scenario, mutation):
    scenario = boundary_scenario
    request = copy.deepcopy(scenario.request)
    if mutation == "extra":
        request["allow_unprivileged"] = True
    elif mutation == "public-bind":
        request["environment"]["STRUGGLEBUS_BIND_HOST"] = "0.0.0.0"
    elif mutation == "secret":
        request["environment"]["STRUGGLEBUS_ADMIN_TOKEN"] = "test-only"
    elif mutation == "http":
        request["health_url"] = "http://bus.example.test/healthz"
    elif mutation == "schema":
        request["candidate_schema"] = True
    elif mutation == "config-path":
        request["candidate_config"] = str(scenario.root / "unbound.service")
    elif mutation == "config-basename":
        request["candidate_config"] = str(scenario.state / "candidate-unbound.service")
    elif mutation == "helper-missing":
        del request["helper_sha256"]
    elif mutation == "helper-not-mapping":
        request["helper_sha256"] = []
    with pytest.raises(maintenance.MaintenanceError):
        maintenance.run(request, rehearsal.RehearsalHost(request))
    assert maintenance.Journal(scenario.state).read() is None
    assert not rehearsal.read_json(scenario.os_state)["commands"]


def test_staged_candidate_filename_is_bound_to_content_hash(boundary_scenario):
    scenario = boundary_scenario
    request = scenario.request
    candidate = Path(request["candidate_config"])
    assert candidate.parent == Path(request["state_dir"])
    assert candidate.name == f"candidate-{request['config_sha256']}.service"
    assert maintenance.digest(candidate.read_bytes()) == request["config_sha256"]
    maintenance.validate_request(request)


def test_injected_host_can_use_explicit_empty_helper_mapping(scenario):
    request = copy.deepcopy(scenario.request)
    request["helper_sha256"] = {}
    scenario.success(request)
    scenario.assert_complete(request)
    assert scenario.journal()["binding"]["helper_sha256"] == {}


def test_shared_helper_validation_is_read_only_and_checks_exact_bytes(boundary_scenario):
    scenario = boundary_scenario
    before = rehearsal.read_json(scenario.os_state)
    maintenance.validate_helpers(scenario.request)
    helper = scenario.helpers / "strugglebus-maintenance"
    helper.write_bytes(helper.read_bytes() + b"\n# changed helper\n")
    with pytest.raises(maintenance.MaintenanceError, match="helper provenance mismatch"):
        maintenance.validate_helpers(scenario.request)
    assert rehearsal.read_json(scenario.os_state) == before
    assert maintenance.Journal(scenario.state).read() is None


def test_installed_helper_and_evidence_have_separate_size_bounds(boundary_scenario):
    scenario = boundary_scenario
    helper = scenario.helpers / "strugglebus-maintenance"
    original = helper.read_bytes()
    content = original + b"\n#" + b"x" * maintenance.MAX_BYTES
    assert maintenance.MAX_BYTES < len(content) < 1024 * 1024
    helper.write_bytes(content)
    request = copy.deepcopy(scenario.request)
    request["helper_sha256"]["strugglebus-maintenance"] = maintenance.digest(content)
    maintenance.validate_helpers(request)
    with pytest.raises(maintenance.MaintenanceError, match="exceeds its limit"):
        maintenance.publish(scenario.state / "oversized-evidence.json", content)
    helper.write_bytes(b"x" * (1024 * 1024 + 1))
    request["helper_sha256"]["strugglebus-maintenance"] = maintenance.digest(helper.read_bytes())
    with pytest.raises(maintenance.MaintenanceError):
        maintenance.validate_helpers(request)
    assert maintenance.Journal(scenario.state).read() is None


@pytest.fixture
def operator_projection(scenario, monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX credential projection metadata")
    import pwd

    credential_dir = scenario.root / "operator-source"
    credential_dir.mkdir(mode=0o700)
    admin = credential_dir / "admin-token"
    admin.write_bytes(b"synthetic-admin-projection")
    admin.chmod(0o600)
    operator = credential_dir / "operator-password"
    operator.write_bytes(b"sbop1$600000$" + b"11" * 16 + b"$" + b"22" * 32 + b"\n")
    operator.chmod(0o600)
    request = copy.deepcopy(scenario.request)
    content = scenario.config(request["candidate"]).replace(
        b"LoadCredential=admin-token:/etc/strugglebus/credentials/admin-token",
        (
            f"LoadCredential=admin-token:{admin}\n"
            f"LoadCredential=operator-password:{operator}\n"
            "Environment=STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH=%d/operator-password"
        ).encode(),
    )
    # Existing admin authority does not change during operator enablement.
    scenario.unit.write_bytes(scenario.unit.read_bytes().replace(
        b"/etc/strugglebus/credentials/admin-token", str(admin).encode(),
    ))
    request["config_sha256"] = maintenance.digest(content)
    candidate = scenario.state / f"candidate-{request['config_sha256']}.service"
    maintenance.publish(candidate, content)
    request["candidate_config"] = str(candidate)
    request["candidate_schema"] = 12
    request["operator_credential"] = maintenance.operator_observation(operator)
    projected = maintenance.PROJECTED_CREDENTIAL_DIRECTORY
    request["environment"]["STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH"] = f"{projected}/operator-password"
    proc = scenario.root / "simulated-proc"
    directory = proc / "root" / projected.lstrip("/")
    directory.mkdir(parents=True, mode=0o700)
    for source in (admin, operator):
        destination = directory / source.name
        destination.write_bytes(source.read_bytes())
        destination.chmod(0o400)
    monkeypatch.setattr(pwd, "getpwnam", lambda _: SimpleNamespace(
        pw_uid=os.geteuid(), pw_gid=os.getegid(),
    ))
    environment = {
        key.encode(): value.encode() for key, value in request["environment"].items()
    } | {b"CREDENTIALS_DIRECTORY": projected.encode()}
    return SimpleNamespace(
        scenario=scenario, request=request, proc=proc, directory=directory,
        admin=admin, operator=operator, environment=environment,
    )


@pytest.mark.parametrize("mutation", [
    None, "admin-generation", "operator-generation", "source-generation",
    "missing-environment", "wrong-directory", "unsafe-mode", "symlink", "hardlink",
])
def test_running_credential_projection_is_exact_and_bounded(operator_projection, mutation):
    p = operator_projection
    projected = p.directory / "operator-password"
    if mutation in {"admin-generation", "operator-generation", "unsafe-mode"}:
        path = p.directory / ("admin-token" if mutation == "admin-generation" else "operator-password")
        path.chmod(0o600)
        if mutation == "unsafe-mode":
            path.chmod(0o666)
        else:
            path.write_bytes(b"wrong-generation")
    elif mutation == "source-generation":
        p.operator.write_bytes(b"sbop1$600000$" + b"11" * 16 + b"$" + b"33" * 32 + b"\n")
    elif mutation == "missing-environment":
        del p.environment[b"STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH"]
    elif mutation == "wrong-directory":
        p.environment[b"CREDENTIALS_DIRECTORY"] = b"/untrusted"
    elif mutation == "symlink":
        projected.unlink()
        projected.symlink_to(p.operator)
    elif mutation == "hardlink":
        os.link(projected, projected.with_name("extra-link"))
    host = maintenance.Host(p.request)
    if mutation is None:
        evidence = host.credential_projection(p.proc, p.environment)
        assert evidence == {
            "admin_credential_projected": True,
            "operator_credential_sha256": maintenance.digest(p.operator.read_bytes()),
        }
        assert "synthetic-admin-projection" not in json.dumps(evidence)
    else:
        with pytest.raises((maintenance.MaintenanceError, OSError)):
            host.credential_projection(p.proc, p.environment)


@pytest.mark.parametrize("old_projection", [False, True])
def test_completed_operator_reset_requires_restart_and_preserves_receipt(
    operator_projection, old_projection,
):
    p = operator_projection
    scenario = p.scenario

    class ProjectedHost(rehearsal.RehearsalHost):
        def start(self):
            was_active = rehearsal.read_json(self.os_state)["active"]
            super().start()
            if not was_active:
                for source in (p.admin, p.operator):
                    path = p.directory / source.name
                    path.chmod(0o600)
                    path.write_bytes(source.read_bytes())
                    path.chmod(0o400)

        def running(self):
            return super().running() | self.credential_projection(p.proc, p.environment)

    maintenance.run(p.request, ProjectedHost(p.request))
    before = scenario.journal()
    snapshot_before = scenario.pins()[0].read_bytes()
    old_evidence = copy.deepcopy(before["evidence"])
    p.operator.write_bytes(b"sbop1$600000$" + b"11" * 16 + b"$" + b"44" * 32 + b"\n")
    authorization = {
        "version": 1, "source": str(p.operator),
        "verifier_sha256": maintenance.digest(p.operator.read_bytes()),
        "maintenance_operation_id": before["operation_id"],
        "maintenance_binding_sha256": maintenance.digest(json.dumps(
            before["binding"], sort_keys=True, separators=(",", ":"),
        ).encode("ascii")),
    }
    maintenance.publish(
        p.operator.parent / maintenance.OPERATOR_AUTHORIZATION,
        json.dumps(authorization).encode("ascii"),
    )
    after_request = copy.deepcopy(p.request)
    after_request["operator_credential"] = maintenance.operator_observation(p.operator)
    # Even a matching projected file alone cannot bless the old running PID.
    if not old_projection:
        projected = p.directory / "operator-password"
        projected.chmod(0o600)
        projected.write_bytes(p.operator.read_bytes())
        projected.chmod(0o400)
    with pytest.raises(maintenance.MaintenanceError, match="application stopped") as failure:
        maintenance.run(after_request, ProjectedHost(after_request))
    assert str(failure.value.__cause__) == (
        "running operator credential generation mismatch" if old_projection
        else "operator password reset requires proven service restart"
    )
    assert not rehearsal.read_json(scenario.os_state)["active"]
    maintenance.run(after_request, ProjectedHost(after_request))
    after = scenario.journal()
    assert after["operation_id"] == before["operation_id"]
    assert after["binding"] == before["binding"]
    assert after["snapshot"] == before["snapshot"]
    assert scenario.pins()[0].read_bytes() == snapshot_before
    assert after["evidence"]["start_ticks"] != old_evidence["start_ticks"]
    assert after["evidence"]["operator_credential_sha256"] == authorization["verifier_sha256"]


@pytest.fixture
def stage_entrypoint(boundary_scenario, monkeypatch, capsys):
    scenario = boundary_scenario
    request = copy.deepcopy(scenario.request)
    names = (
        "strugglebus-maintenance", "strugglebus-validate-maintenance-config",
        "strugglebus-inspect-access-freeze", "strugglebus-sqlite-backup",
    )
    request["helper_sha256"] = {}
    for name in names:
        source = rehearsal.HELPER_PATH.parent / f"{name}.py"
        if name == "strugglebus-sqlite-backup":
            # Stage authenticates these bytes but never executes the backup
            # helper; its rendering/execution has separate backup tests.
            source = rehearsal.ROOT / "deploy" / "roles" / "systemd" / "templates" / "sqlite_backup.py.j2"
        content = source.read_bytes()
        helper = scenario.helpers / name
        helper.write_bytes(content)
        helper.chmod(0o600)
        request["helper_sha256"][name] = maintenance.digest(content)
    candidate = Path(request["candidate_config"])
    candidate.unlink()
    locks = [
        {"metadata": "/run/lock/strugglebus/release.json", "token": "a" * 64},
        {
            "metadata": str(
                Path(request["environment"]["STRUGGLEBUS_DATA_DIR"])
                / ".access-freeze-lock" / "release.json"
            ),
            "token": "b" * 64,
        },
    ]
    payload = {"request": request, "locks": locks, "unit_content": scenario.config("0.3.0").decode()}
    events = []
    helpers_verified = False
    original_validate_helpers = maintenance.validate_helpers
    original_publish = maintenance.publish
    original_host = maintenance.Host

    class StageOS:
        def __init__(self):
            self.entrypoint = True

        def __getattr__(self, name):
            return getattr(os, name)

        def geteuid(self):
            # Simulate only main()'s initial privilege gate. Subsequent file
            # ownership checks still use this unprivileged test user's real UID.
            if self.entrypoint:
                self.entrypoint = False
                return 0
            return os.geteuid() if hasattr(os, "geteuid") else 0

    @contextmanager
    def ownership_fence(actual_locks):
        assert actual_locks == locks
        events.append("fence-enter")
        try:
            yield
        finally:
            events.append("fence-exit")

    def validate_helpers(actual_request):
        nonlocal helpers_verified
        assert not candidate.exists()
        events.append("validate-helpers")
        original_validate_helpers(actual_request)
        helpers_verified = True
        events.append("helpers-verified")

    def publish(path, content, **kwargs):
        assert path == candidate
        assert helpers_verified
        events.append("publish-candidate")
        return original_publish(path, content, **kwargs)

    class StageHost(original_host):
        def command(self, argv, **kwargs):
            assert argv == ["systemd-analyze", "verify", str(candidate)]
            assert candidate.read_bytes() == scenario.config("0.3.0")
            events.append("systemd-verify")
            return ""

    monkeypatch.setattr(maintenance, "ownership_fence", ownership_fence)
    monkeypatch.setattr(maintenance, "validate_helpers", validate_helpers)
    monkeypatch.setattr(maintenance, "publish", publish)
    monkeypatch.setattr(maintenance, "Host", StageHost)

    def invoke(value):
        monkeypatch.setattr(maintenance, "os", StageOS())
        raw = value if isinstance(value, bytes) else json.dumps(value).encode()
        monkeypatch.setattr(maintenance.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw)))
        monkeypatch.setattr(maintenance.sys, "argv", ["strugglebus-maintenance", "stage"])
        result = maintenance.main()
        output = capsys.readouterr()
        return result, output

    return SimpleNamespace(
        scenario=scenario, request=request, payload=payload, candidate=candidate,
        events=events, invoke=invoke,
    )


@pytest.mark.parametrize("malformed", ("json", "envelope", "request"))
def test_real_stage_main_sanitizes_malformed_requests_before_ownership(stage_entrypoint, malformed):
    stage = stage_entrypoint
    if malformed == "json":
        payload = b'{"test-only-sensitive-input":"not valid JSON"'
    elif malformed == "envelope":
        payload = {}
    else:
        payload = {**stage.payload, "request": {}}
    before = persisted_tree(stage.scenario.root)
    result, output = stage.invoke(payload)
    assert result == 1
    assert not output.out
    assert output.err.strip()
    assert "UnboundLocalError" not in output.err
    assert "Traceback" not in output.err
    assert "test-only-sensitive-input" not in output.err
    assert stage.events == []
    assert not stage.candidate.exists()
    assert persisted_tree(stage.scenario.root) == before


def test_real_stage_main_validates_helper_bundle_before_publishing(stage_entrypoint):
    stage = stage_entrypoint
    result, output = stage.invoke(stage.payload)
    assert result == 0, output.err
    assert json.loads(output.out) == {
        "state": "staged", "config_sha256": stage.request["config_sha256"],
    }
    assert stage.events == [
        "fence-enter", "validate-helpers", "helpers-verified",
        "publish-candidate", "systemd-verify", "fence-exit",
    ]
    assert stage.candidate.read_bytes() == stage.scenario.config("0.3.0")
    assert maintenance.Journal(stage.scenario.state).read() is None
    assert not rehearsal.read_json(stage.scenario.os_state)["commands"]


def test_real_stage_main_rejects_changed_helper_before_publication(stage_entrypoint):
    stage = stage_entrypoint
    helper = stage.scenario.helpers / "strugglebus-sqlite-backup"
    helper.write_bytes(helper.read_bytes() + b"\n# changed after binding\n")
    before = persisted_tree(stage.scenario.root)
    result, output = stage.invoke(stage.payload)
    assert result == 1
    assert output.err.strip() == "maintenance helper provenance mismatch"
    assert stage.events == ["fence-enter", "validate-helpers", "fence-exit"]
    assert not stage.candidate.exists()

    # Ownership was held, so the refusal is recorded. The Ansible task that
    # invokes maintenance runs under no_log because its stdin carries ownership
    # tokens, which hides this message; without the record a refusal reports
    # only that a phase did not complete. Nothing else may change.
    note = stage.scenario.state / "last-failure.json"
    assert json.loads(note.read_text(encoding="utf-8"))["reason"] == (
        "maintenance helper provenance mismatch"
    )
    after = {
        path: value
        for path, value in persisted_tree(stage.scenario.root).items()
        if path not in {"state", str(Path("state") / "last-failure.json")}
    }
    assert after == {
        path: value for path, value in before.items() if path != "state"
    }


def test_real_stage_main_rejects_incomplete_helper_bundle_before_ownership(stage_entrypoint):
    stage = stage_entrypoint
    payload = copy.deepcopy(stage.payload)
    del payload["request"]["helper_sha256"]["strugglebus-sqlite-backup"]
    before = persisted_tree(stage.scenario.root)
    result, output = stage.invoke(payload)
    assert result == 1
    assert output.err.strip() == "maintenance helper bundle is incomplete"
    assert stage.events == []
    assert not stage.candidate.exists()
    assert persisted_tree(stage.scenario.root) == before


PROTECTED_UNIT_PREFIXES = (
    "User=", "Group=", "LoadCredential=", "WorkingDirectory=", "ExecStart=",
    "Environment=STRUGGLEBUS_DATA_DIR=", "Environment=STRUGGLEBUS_RUNTIME_DIR=",
    "Environment=STRUGGLEBUS_BACKUP_DIR=", "Environment=STRUGGLEBUS_DATABASE_PATH=",
    "Environment=STRUGGLEBUS_ADMIN_CREDENTIAL_PATH=",
    "Environment=STRUGGLEBUS_PUBLIC_BASE_URL=", "Environment=STRUGGLEBUS_BIND_HOST=",
    "Environment=STRUGGLEBUS_BIND_PORT=", "Environment=STRUGGLEBUS_ALLOWED_HOSTS=",
    "Environment=STRUGGLEBUS_ALLOWED_ORIGINS=", "Environment=STRUGGLEBUS_TRUSTED_PROXY_SOURCES=",
)


@pytest.mark.parametrize("prefix", PROTECTED_UNIT_PREFIXES)
def test_changed_protected_unit_topology_is_rejected_before_stop(scenario, prefix):
    lines = scenario.config("0.3.0").decode().splitlines()
    matches = [index for index, line in enumerate(lines) if line.startswith(prefix)]
    assert len(matches) == 1
    lines[matches[0]] = prefix + "changed-topology"
    content = ("\n".join(lines) + "\n").encode()
    request = copy.deepcopy(scenario.request)
    request["config_sha256"] = maintenance.digest(content)
    candidate = scenario.state / f"candidate-{request['config_sha256']}.service"
    maintenance.publish(candidate, content)
    request["candidate_config"] = str(candidate)
    result = scenario.invoke(request)
    assert result.returncode == 1
    assert (
        "does not change topology or credentials" in result.stderr
        or result.stderr.strip() == "unsupported credential projection"
    )
    assert maintenance.Journal(scenario.state).read() is None
    assert not scenario.pins()
    assert not rehearsal.read_json(scenario.os_state)["commands"]


@pytest.mark.parametrize("mutation", ("missing", "duplicate"))
def test_protected_unit_fields_must_occur_exactly_once(boundary_scenario, mutation):
    previous = boundary_scenario.config("0.2.0")
    candidate = boundary_scenario.config("0.3.0")
    if mutation == "missing":
        candidate = candidate.replace(b"User=strugglebus\n", b"")
    else:
        candidate += b"User=strugglebus\n"
    with pytest.raises(maintenance.MaintenanceError, match="topology or credentials"):
        maintenance.require_same_topology(previous, candidate)


def test_realistic_units_allow_nonsecret_message_limit_changes(boundary_scenario):
    scenario = boundary_scenario
    previous = scenario.config("0.2.0")
    candidate = scenario.config("0.3.0")
    assert b"Environment=STRUGGLEBUS_MAX_MESSAGE_BYTES=1048576\n" in previous
    assert b"Environment=STRUGGLEBUS_MAX_MESSAGE_BYTES=524288\n" in candidate
    assert b"Environment=STRUGGLEBUS_RELEASE_ID=" not in candidate
    assert (scenario.releases / "0.3.0" / "release.env").read_text() == "STRUGGLEBUS_RELEASE_ID=0.3.0\n"
    assert scenario.request["environment"]["STRUGGLEBUS_MAX_MESSAGE_BYTES"] == "524288"
    for prefix in PROTECTED_UNIT_PREFIXES:
        assert sum(line.startswith(prefix.encode()) for line in previous.splitlines()) == 1
        assert sum(line.startswith(prefix.encode()) for line in candidate.splitlines()) == 1
    maintenance.require_same_topology(previous, candidate)


@pytest.mark.parametrize("checkpoint", ("prepared", "snapshot-ready", "complete"))
def test_real_status_cli_exposes_snapshot_and_predecessor(scenario, checkpoint):
    scenario.crash(checkpoint)
    record = scenario.journal()
    result = subprocess.run(
        [sys.executable, str(rehearsal.HELPER_PATH), "status", "--state-dir", str(scenario.state)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == 0, result.stderr
    status = json.loads(result.stdout)
    assert status["state"] == checkpoint
    assert status["operation_id"] == record["operation_id"]
    assert status["snapshot"] == record["snapshot"]
    assert status["predecessor"] == record["predecessor"]
    assert status["candidate"] == scenario.request["candidate"]
    assert status["config_sha256"] == scenario.request["config_sha256"]


def persisted_tree(root):
    result = {}
    for path in root.rglob("*"):
        metadata = path.lstat()
        if path.is_symlink():
            facts = ("symlink", str(path.readlink()))
        elif path.is_file():
            facts = ("file", metadata.st_size, maintenance.digest(path.read_bytes()))
        else:
            facts = ("directory",)
        result[str(path.relative_to(root))] = (
            metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_mtime_ns, facts,
        )
    return result


@pytest.mark.parametrize("checkpoint", ("prepared", "snapshot-ready", "complete"))
def test_status_verify_cli_checks_provenance_without_runtime_or_file_mutation(scenario, checkpoint):
    scenario.crash(checkpoint)
    before = persisted_tree(scenario.root)
    result = scenario.invoke(status_verify=True)
    assert result.returncode == 0, result.stderr
    status = json.loads(result.stdout)
    assert status["state"] == checkpoint
    assert status["provenance"] == "verified"
    assert status["runtime"] == "not-observed"
    assert status["snapshot"] == scenario.journal()["snapshot"]
    assert persisted_tree(scenario.root) == before


@pytest.mark.parametrize("target", ("helper", "candidate", "predecessor-config", "pin", "missing-pin"))
def test_status_verify_refuses_tampered_provenance_without_mutation(scenario, target):
    scenario.crash("snapshot-ready")
    record = scenario.journal()
    path = {
        "helper": scenario.helpers / "strugglebus-maintenance",
        "candidate": Path(scenario.request["candidate_config"]),
        "predecessor-config": scenario.state / f"predecessor-{record['operation_id']}.service",
        "pin": scenario.pins()[0],
        "missing-pin": scenario.pins()[0],
    }[target]
    if target == "missing-pin":
        path.unlink()
    else:
        path.write_bytes(path.read_bytes() + b"\n# changed provenance\n")
    before = persisted_tree(scenario.root)
    result = scenario.invoke(status_verify=True)
    assert result.returncode == 1
    assert not result.stdout
    assert "Traceback" not in result.stderr
    assert persisted_tree(scenario.root) == before


def test_status_verify_includes_previous_predecessor_during_handoff(scenario):
    scenario.success()
    previous = scenario.journal()
    candidate = scenario.prepare("0.4.0")
    scenario.crash("prepared", candidate)
    before = persisted_tree(scenario.root)
    result = scenario.invoke(candidate, status_verify=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["provenance"] == "verified"
    assert persisted_tree(scenario.root) == before
    assert scenario.journal()["previous_operation"] == previous
    marker = scenario.releases / "0.2.0" / "marker.json"
    value = rehearsal.read_json(marker)
    value["wheel_sha256"] = "e" * 64
    rehearsal.write_json(marker, value)
    before = persisted_tree(scenario.root)
    result = scenario.invoke(candidate, status_verify=True)
    assert result.returncode == 1
    assert persisted_tree(scenario.root) == before


@pytest.mark.parametrize("action", ("run", "stage", "guard"))
def test_verify_flag_is_restricted_to_read_only_status(boundary_scenario, action):
    scenario = boundary_scenario
    before = persisted_tree(scenario.root)
    result = subprocess.run(
        [sys.executable, str(rehearsal.HELPER_PATH), action, "--verify", "--state-dir", str(scenario.state)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == 1
    assert result.stderr.strip() == "provenance verification requires read-only status"
    assert persisted_tree(scenario.root) == before


def test_real_cli_sanitizes_malformed_record_content(boundary_scenario):
    scenario = boundary_scenario
    marker = "test-only-untrusted-error-marker"
    maintenance.publish(scenario.state / "operation.json", f'{{"error":"{marker}",broken'.encode())
    result = subprocess.run(
        [sys.executable, str(rehearsal.HELPER_PATH), "status", "--state-dir", str(scenario.state)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == 1
    assert not result.stdout
    assert result.stderr.strip() == "invalid maintenance record"
    assert marker not in result.stderr
    assert "Traceback" not in result.stderr


def test_production_command_rejects_nonzero_and_bounds_output(boundary_scenario):
    scenario = boundary_scenario
    host = maintenance.Host(scenario.request)
    with pytest.raises(maintenance.MaintenanceError, match="command failed"):
        host.command([sys.executable, "-c", "raise SystemExit(19)"])
    with pytest.raises(maintenance.MaintenanceError, match="command failed"):
        host.command([sys.executable, "-c", "print('x' * 65537)"])
    assert host.command([sys.executable, "-c", "print('inactive'); raise SystemExit(3)"], allowed=(3,)) == "inactive"


def test_snapshot_adapter_closes_sqlite_handles_before_return(boundary_scenario, monkeypatch):
    scenario = boundary_scenario
    original_connect = sqlite3.connect
    connections = []

    def connect(*args, **kwargs):
        connection = original_connect(*args, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(rehearsal.sqlite3, "connect", connect)
    adapter = rehearsal.RehearsalHost(scenario.request)
    operation = "a" * 32
    adapter.snapshot(operation, create=True)
    assert len(connections) >= 4
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")
    adapter.snapshot_path(operation).unlink()
    assert not adapter.snapshot_path(operation).exists()


@pytest.mark.parametrize("create", (False, True))
@pytest.mark.parametrize("exists", (False, True))
def test_production_snapshot_selects_create_only_for_missing_new_pin(
    boundary_scenario, monkeypatch, create, exists,
):
    scenario = boundary_scenario
    host = maintenance.Host(scenario.request)
    adapter = rehearsal.RehearsalHost(scenario.request)
    operation = "a" * 32
    path = host.snapshot_path(operation)
    if exists:
        adapter.snapshot(operation, create=True)
    original = path.read_bytes() if exists else None
    calls = []

    def command(argv, *, timeout):
        calls.append((argv, timeout))
        if argv[-2] == "--maintenance-id":
            adapter.snapshot(operation, create=True)
        elif not path.exists():
            raise maintenance.MaintenanceError("recorded pin does not exist")
        return ""

    monkeypatch.setattr(host, "command", command)
    monkeypatch.setattr(host, "snapshot_identity", adapter.snapshot_identity)
    monkeypatch.setattr(host, "database_facts", adapter.database_facts)
    if not create and not exists:
        with pytest.raises(maintenance.MaintenanceError, match="recorded pin"):
            host.snapshot(operation, create=create)
        assert not path.exists()
    else:
        result = host.snapshot(operation, create=create)
        assert result == adapter.snapshot(operation, create=False)
    option = "--maintenance-id" if create and not exists else "--verify-maintenance-id"
    assert calls == [([
        "/usr/sbin/runuser", "--user", "strugglebus", "--",
        "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LANG=C.UTF-8",
        "/usr/bin/python3.13", "-I", str(scenario.helpers / "strugglebus-sqlite-backup"),
        str(scenario.database), str(scenario.backups), "7", option, operation,
    ], 300)]
    if exists:
        assert path.read_bytes() == original


@pytest.mark.parametrize("create", (False, True))
def test_production_snapshot_verification_failure_never_recreates_pin(
    boundary_scenario, monkeypatch, create,
):
    scenario = boundary_scenario
    host = maintenance.Host(scenario.request)
    operation = "a" * 32
    rehearsal.RehearsalHost(scenario.request).snapshot(operation, create=True)
    path = host.snapshot_path(operation)
    original = path.read_bytes()
    calls = []

    def command(argv, *, timeout):
        calls.append(argv)
        raise maintenance.MaintenanceError("existing pin verification failed")

    monkeypatch.setattr(host, "command", command)
    monkeypatch.setattr(
        host, "snapshot_identity",
        lambda _: pytest.fail("pin facts must not be read after failed verification"),
    )
    with pytest.raises(maintenance.MaintenanceError, match="verification failed"):
        host.snapshot(operation, create=create)
    assert len(calls) == 1
    assert calls[0][-2:] == ["--verify-maintenance-id", operation]
    assert path.read_bytes() == original


@pytest.mark.skipif(sys.platform != "linux", reason="production snapshot descriptors use Linux /proc")
def test_production_snapshot_identity_is_read_only_and_never_invokes_backup(boundary_scenario, monkeypatch):
    import pwd

    scenario = boundary_scenario
    operation = "a" * 32
    snapshot = rehearsal.RehearsalHost(scenario.request).snapshot(operation, create=True)
    host = maintenance.Host(scenario.request)
    current_user = pwd.getpwuid(os.geteuid())
    monkeypatch.setattr(pwd, "getpwnam", lambda _: current_user)
    monkeypatch.setattr(
        host, "command", lambda *args, **kwargs: pytest.fail("snapshot_identity must not execute a command"),
    )
    before = persisted_tree(scenario.root)
    assert host.snapshot_identity(operation) == {
        "sha256": snapshot["sha256"], "size": snapshot["size"],
    }
    assert persisted_tree(scenario.root) == before


@pytest.mark.skipif(sys.platform != "linux", reason="production snapshot descriptors use Linux /proc")
@pytest.mark.parametrize("mutation", ("corrupt", "symlink", "hardlink", "mode"))
def test_production_snapshot_identity_rejects_unsafe_or_corrupt_pins(
    boundary_scenario, monkeypatch, mutation,
):
    import pwd

    scenario = boundary_scenario
    operation = "a" * 32
    rehearsal.RehearsalHost(scenario.request).snapshot(operation, create=True)
    host = maintenance.Host(scenario.request)
    path = host.snapshot_path(operation)
    if mutation == "corrupt":
        path.write_bytes(b"not a SQLite database")
    elif mutation == "symlink":
        moved = path.with_name("untrusted.db")
        path.rename(moved)
        path.symlink_to(moved)
    elif mutation == "hardlink":
        os.link(path, path.with_name("extra-link.db"))
    else:
        path.chmod(0o644)
    current_user = pwd.getpwuid(os.geteuid())
    monkeypatch.setattr(pwd, "getpwnam", lambda _: current_user)
    monkeypatch.setattr(
        host, "command", lambda *args, **kwargs: pytest.fail("snapshot_identity must not execute a command"),
    )
    before = persisted_tree(scenario.root)
    with pytest.raises((maintenance.MaintenanceError, OSError, sqlite3.Error)):
        host.snapshot_identity(operation)
    assert persisted_tree(scenario.root) == before


def test_production_stop_does_not_accept_nonzero_systemctl(boundary_scenario, monkeypatch):
    scenario = boundary_scenario
    host = maintenance.Host(scenario.request)
    original = subprocess.run
    calls = []

    def child(argv, **kwargs):
        calls.append(argv)
        return original([sys.executable, "-c", "raise SystemExit(1)"], **kwargs)

    monkeypatch.setattr(maintenance.subprocess, "run", child)
    with pytest.raises(maintenance.MaintenanceError, match="command failed"):
        host.stop()
    assert calls == [["systemctl", "stop", "strugglebus-backup.timer"]]


def test_production_stop_rejects_real_occupied_loopback_port(boundary_scenario, monkeypatch):
    scenario = boundary_scenario
    host = maintenance.Host(scenario.request)
    original = subprocess.run
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        scenario.request["bind_port"] = port

        def child(argv, **kwargs):
            if argv[0] == "ss":
                assert argv[-1] == f"sport = :{port}"
                code = (
                    "import socket; s=socket.create_connection(('127.0.0.1',"
                    f"{port}), timeout=3); print('LISTEN 127.0.0.1:{port}'); s.close()"
                )
            elif argv[1] == "is-active":
                code = "print('inactive'); raise SystemExit(3)"
            else:
                code = "raise SystemExit(0)"
            if os.name == "nt":
                # Winsock needs this OS boundary variable; the production Linux
                # command implementation still owns status/output validation.
                kwargs["env"] = {**kwargs["env"], "SYSTEMROOT": os.environ["SYSTEMROOT"]}
            return original([sys.executable, "-c", code], **kwargs)

        monkeypatch.setattr(maintenance.subprocess, "run", child)
        with pytest.raises(maintenance.MaintenanceError, match="listener remains occupied"):
            host.stop()


@pytest.mark.parametrize("failure", ("stop", "occupied-port"))
def test_stop_guards_prevent_snapshot_or_selection(scenario, failure):
    scenario.failure(failure)
    result = scenario.invoke()
    assert result.returncode == 1
    assert not scenario.pins()
    assert scenario.current.resolve() == scenario.releases / "0.2.0"
    assert not rehearsal.read_json(scenario.os_state)["starts"]


@pytest.fixture(scope="module")
def local_tls_certificates(tmp_path_factory):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("existing OpenSSL executable required for local test-only certificates")
    directory = tmp_path_factory.mktemp("maintenance-tls")
    directory.chmod(0o700)
    commands = [
        ["req", "-config", "openssl.cnf", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=Maintenance test CA", "-keyout", "ca.key", "-out", "ca.pem"],
        ["req", "-config", "openssl.cnf", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
         "-keyout", "server.key", "-out", "server.csr"],
        ["x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
         "-CAcreateserial", "-days", "1", "-extfile", "server.ext", "-out", "server.pem"],
        ["req", "-config", "openssl.cnf", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=Unrelated maintenance test CA", "-keyout", "untrusted.key",
         "-out", "untrusted.pem"],
    ]
    (directory / "openssl.cnf").write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n"
        "[dn]\nCN=Maintenance test CA\n"
        "[ca]\nbasicConstraints=critical,CA:TRUE\n"
        "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid:always\n",
        encoding="ascii",
    )
    (directory / "server.ext").write_text(
        "subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n"
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n",
        encoding="ascii",
    )
    for command in commands:
        result = subprocess.run(
            [openssl, *command], cwd=directory, capture_output=True, text=True,
            timeout=30, check=False,
        )
        assert result.returncode == 0, result.stderr
    return directory


@pytest.fixture
def local_tls_server(local_tls_certificates):
    observations = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            observations.append(self.path)
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        local_tls_certificates / "server.pem", local_tls_certificates / "server.key",
    )
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        yield server.server_port, local_tls_certificates, observations
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


@pytest.mark.parametrize("verification", ("trusted-hostname", "wrong-hostname", "untrusted-ca"))
def test_production_readiness_performs_real_tls_and_hostname_verification(
    boundary_scenario, local_tls_server, monkeypatch, verification,
):
    port, certificates, observations = local_tls_server
    # The server listens on IPv4 only; on Windows each refused ::1 attempt costs
    # about two seconds, so twenty retries would take forty.
    real_getaddrinfo = socket.getaddrinfo
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda host, *args, **kwargs: [
            info for info in real_getaddrinfo(host, *args, **kwargs)
            if host != "localhost" or info[0] == socket.AF_INET
        ],
    )
    request = copy.deepcopy(boundary_scenario.request)
    hostname = "127.0.0.1" if verification == "wrong-hostname" else "localhost"
    request["health_url"] = f"https://{hostname}:{port}/healthz"
    request["ca_path"] = str(
        certificates / ("untrusted.pem" if verification == "untrusted-ca" else "ca.pem")
    )
    host = maintenance.Host(request)
    if verification == "trusted-hostname":
        host.readiness()
        assert observations == ["/healthz"]
    else:
        monkeypatch.setattr(maintenance.time, "sleep", lambda _: None)
        with pytest.raises(maintenance.MaintenanceError, match="TLS-verified") as error:
            host.readiness()
        assert isinstance(error.value.__cause__.reason, ssl.SSLCertVerificationError)
        assert not observations


@pytest.mark.skipif(sys.platform != "linux", reason="real running identity requires Linux /proc and ss")
@pytest.mark.parametrize("mutation", (
    None, "uid", "release", "environment", "cwd", "interpreter", "entrypoint", "listener",
))
def test_production_running_checks_real_process_and_loopback_listener(scenario, monkeypatch, mutation):
    import pwd

    if shutil.which("ss") is None:
        pytest.skip("existing ss executable required for actual listener ownership checks")
    request = copy.deepcopy(scenario.request)
    target = scenario.releases / request["candidate"]
    binaries = target / "venv" / "bin"
    binaries.mkdir(parents=True)
    (binaries / "python").symlink_to(
        Path("/bin/false").resolve() if mutation == "interpreter" else Path(sys.executable).resolve()
    )
    entrypoint = binaries / "strugglebus"
    entrypoint.write_text(
        "import os, pathlib, socket, sys\n"
        "listener = socket.socket(fileno=int(sys.argv[2]))\n"
        "pathlib.Path(sys.argv[3]).write_text(str(os.getpid()))\n"
        "while True:\n"
        "    connection, _ = listener.accept()\n"
        "    connection.close()\n",
        encoding="ascii",
    )
    if mutation == "entrypoint":
        different_entrypoint = target / "different-entrypoint.py"
        different_entrypoint.write_bytes(entrypoint.read_bytes())
        entrypoint = different_entrypoint
    scenario.current.unlink()
    scenario.current.symlink_to(target, target_is_directory=True)
    ready = scenario.root / "real-process-ready"
    process = None
    with socket.socket() as listener, socket.socket() as other_listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        other_listener.bind(("127.0.0.1", 0))
        other_listener.listen()
        port = other_listener.getsockname()[1] if mutation == "listener" else listener.getsockname()[1]
        request["bind_port"] = port
        request["environment"]["STRUGGLEBUS_BIND_PORT"] = str(port)
        content = scenario.config("0.3.0").replace(b"--port 8765 ", f"--port {port} ".encode())
        content = content.replace(b"STRUGGLEBUS_BIND_PORT=8765\n", f"STRUGGLEBUS_BIND_PORT={port}\n".encode())
        request["config_sha256"] = maintenance.digest(content)
        maintenance.publish(scenario.unit, content, mode=0o644)
        environment = {
            "PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8",
            **request["environment"], "STRUGGLEBUS_RELEASE_ID": request["candidate"],
        }
        if mutation == "release":
            environment["STRUGGLEBUS_RELEASE_ID"] = "0.4.0"
        elif mutation == "environment":
            environment["STRUGGLEBUS_MAX_MESSAGE_BYTES"] = "1"
        host = maintenance.Host(request)
        original_command = host.command
        original_getpwnam = pwd.getpwnam
        local_user = (
            SimpleNamespace(pw_uid=os.geteuid() + 1)
            if mutation == "uid" else pwd.getpwuid(os.geteuid())
        )
        monkeypatch.setattr(
            pwd, "getpwnam",
            lambda name: local_user if name == "strugglebus" else original_getpwnam(name),
        )
        commands = []

        def systemd_observation(argv, **kwargs):
            commands.append(argv)
            if argv == ["systemctl", "is-active", "strugglebus.service"]:
                return "active"
            if argv == ["systemctl", "show", "strugglebus.service", "--property=MainPID", "--value"]:
                return str(process.pid)
            assert argv[0] == "ss", argv
            return original_command(argv, **kwargs)

        monkeypatch.setattr(host, "command", systemd_observation)
        try:
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(entrypoint),
                    "serve",
                    str(listener.fileno()),
                    str(ready),
                ],
                cwd=scenario.releases / "0.2.0" if mutation == "cwd" else target,
                env=environment, pass_fds=(listener.fileno(),),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            deadline = time.monotonic() + 10
            while not ready.exists():
                assert process.poll() is None, process.communicate()
                assert time.monotonic() < deadline, "real listener child did not become ready"
                time.sleep(0.01)
            listener.close()
            if mutation is None:
                assert host.running() == {
                    "pid": process.pid, "start_ticks": maintenance.process_ticks(process.pid),
                    "release": request["candidate"],
                }
                assert any(command[0] == "ss" for command in commands)
            else:
                with pytest.raises(maintenance.MaintenanceError, match="identity mismatch|configuration mismatch|configured loopback listener|release environment mismatch"):
                    host.running()
        finally:
            if process is not None:
                process.terminate()
                process.communicate(timeout=5)


def make_fences(scenario):
    locks = []
    for name in ("release-lock", "freeze-lock"):
        directory = scenario.root / name
        directory.mkdir(mode=0o700)
        maintenance.publish(directory / "control.lock", b"")
        metadata = directory / "release.json"
        token = ("a" if name == "release-lock" else "b") * 64
        rehearsal.write_json(metadata, {
            "version": 1, "token": token, "pid": os.getpid(),
            "start_ticks": maintenance.process_ticks(os.getpid()),
            "heartbeat_ns": time.monotonic_ns(), "lease_seconds": 600,
        })
        locks.append({"metadata": str(metadata), "token": token})
    path = scenario.root / "fences.json"
    rehearsal.write_json(path, {"locks": locks})
    return path, locks


@pytest.mark.skipif(sys.platform != "linux", reason="production fencing requires Linux flock and /proc")
@pytest.mark.parametrize("mutation", ("token", "pid", "start-ticks", "expired"))
def test_production_ownership_fence_rejects_stale_lease_before_run(scenario, mutation):
    _, locks = make_fences(scenario)
    path = Path(locks[1]["metadata"])
    metadata = rehearsal.read_json(path)
    if mutation == "token":
        metadata["token"] = "c" * 64
    elif mutation == "pid":
        metadata["pid"] = 2**30
    elif mutation == "start-ticks":
        metadata["start_ticks"] += 1
    else:
        metadata["heartbeat_ns"] = 0
        metadata["lease_seconds"] = 0
    rehearsal.write_json(path, metadata)
    with pytest.raises((maintenance.MaintenanceError, OSError)):
        with maintenance.ownership_fence(locks):
            maintenance.run(scenario.request, rehearsal.RehearsalHost(scenario.request))
    assert not rehearsal.read_json(scenario.os_state)["commands"]
    assert maintenance.Journal(scenario.state).read() is None


@pytest.mark.skipif(sys.platform != "linux", reason="production fencing requires Linux flock and /proc")
def test_concurrent_real_runs_are_fenced_and_resume_same_operation(scenario):
    locks_path, locks = make_fences(scenario)
    ready = scenario.root / "paused"
    release = scenario.root / "continue"
    state = rehearsal.read_json(scenario.os_state)
    state["pause"] = {"phase": "snapshot-ready", "ready": str(ready), "release": str(release)}
    rehearsal.write_json(scenario.os_state, state)
    argv = [
        sys.executable, str(HARNESS), "--child",
        str(scenario.root / "request-0.3.0.json"), "--fence-locks", str(locks_path),
    ]
    processes = []
    try:
        first = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        processes.append(first)
        deadline = time.monotonic() + 10
        while not ready.exists():
            assert first.poll() is None, first.communicate()
            assert time.monotonic() < deadline, "first process never reached real recovery checkpoint"
            time.sleep(0.02)
        operation = scenario.journal()["operation_id"]
        commands = rehearsal.read_json(scenario.os_state)["commands"]
        second = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        processes.append(second)
        time.sleep(0.2)
        assert second.poll() is None
        assert rehearsal.read_json(scenario.os_state)["commands"] == commands
        assert scenario.journal()["operation_id"] == operation
        maintenance.publish(release, b"continue")
        for process in processes:
            stdout, stderr = process.communicate(timeout=20)
            assert process.returncode == 0, (stdout, stderr)
            assert json.loads(stdout)["operation_id"] == operation
        scenario.assert_complete()
        assert rehearsal.read_json(scenario.os_state)["starts"] == ["0.3.0"]
        with maintenance.ownership_fence(locks):
            assert scenario.journal()["operation_id"] == operation
    finally:
        maintenance.publish(release, b"continue")
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
