import copy
import importlib.util
import json
import os
import hashlib
import sqlite3
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4
from pathlib import Path

import pytest

from strugglebus.errors import ConfigurationError
from strugglebus.migrations import LATEST_SCHEMA_VERSION
from strugglebus.operator_auth import create_password_verifier
from strugglebus.operator_local import (
    PASSWORD_AUTHORIZATION_FILE, PASSWORD_CONTROL_FILE, password_source_lock,
)


HELPER = (
    Path(__file__).resolve().parents[1] / "deploy" / "roles" / "guest_base" / "files"
    / "strugglebus-maintenance.py"
)
SPEC = importlib.util.spec_from_file_location("operator_maintenance", HELPER)
assert SPEC is not None and SPEC.loader is not None
maintenance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(maintenance)


def database_facts(path):
    from test_access_freeze_inspector import inspect_access_freeze

    host = SimpleNamespace(
        expected_schema=LATEST_SCHEMA_VERSION, helper_root=path.parent,
        command=lambda argv: json.dumps(inspect_access_freeze(path)),
    )
    return maintenance.Host.database_facts(host, path)


def test_schema_fifteen_digest_binds_freeze_actor_identity(agent_service) -> None:
    path = agent_service.store.database_path
    agent_service.store.set_access_freeze(
        frozen=True,
        reason="incident",
        changed_at=datetime.now(UTC),
        actor_type="local-admin",
        actor_id="local-cli",
    )
    before = database_facts(path)

    with sqlite3.connect(path) as database:
        database.execute(
            "UPDATE agent_access_audit SET actor_id = 'device:forged'"
        )

    assert database_facts(path)["credential_state_sha256"] != before[
        "credential_state_sha256"
    ]


@pytest.mark.parametrize("version", [10, 11])
def test_older_schema_receipt_digests_remain_byte_identical(tmp_path, version):
    from strugglebus.migrations import apply_migrations, load_packaged_migrations

    path = tmp_path / "old.db"
    with sqlite3.connect(path) as connection:
        apply_migrations(connection, load_packaged_migrations()[:version])
        connection.execute(
            "INSERT INTO agents (id,name,created_at) VALUES ('historical','history-copilot','2026-01-01T00:00:00Z')"
        )
    expected = hashlib.sha256()
    with sqlite3.connect(path) as connection:
        for query in (
            "SELECT id, credential_epoch, revoked_at FROM agents ORDER BY id",
            "SELECT id, agent_id, status, version, revoked_at, retired_at, expired_at "
            "FROM agent_credentials ORDER BY id",
            "SELECT singleton, frozen, transition, changed_at FROM agent_access_state",
        ):
            for row in connection.execute(query):
                expected.update(json.dumps(row, separators=(",", ":")).encode("utf-8") + b"\n")
    assert database_facts(path) == {
        "schema": version, "frozen": False, "credential_state_sha256": expected.hexdigest(),
    }


@pytest.mark.parametrize("target,field,value", [
    ("agents", "blocked_at", "2026-01-01T00:00:00Z"),
    ("agent_reconnect_grants", "reason", "changed retained reason"),
    ("agent_reconnect_grants", "secret_hash", "e" * 64),
    ("agent_reconnect_grants", "intent_sha256", "e" * 64),
    ("agent_reconnect_grants", "bound_epoch", 100),
    ("agent_reconnect_grants", "issuance_request_id", "00000000-0000-0000-0000-000000000001"),
    ("agent_reconnect_grants", "expires_at", "2999-01-01T00:00:00Z"),
    ("agent_reconnect_grants", "actor_id", "operator:owner:00000000000000000000000000000001"),
    ("agent_reconnect_grants", "redemption_request_id", "00000000-0000-0000-0000-000000000001"),
    ("agent_reconnect_grants", "result_credential_id", "unrelated-result-link"),
    ("agent_lifecycle_audit", "reason", "changed immutable history"),
    ("agent_lifecycle_audit", "actor_id", "changed actor"),
    ("agent_lifecycle_audit", "intent_sha256", "e" * 64),
    ("agent_lifecycle_audit", "request_id", "00000000-0000-0000-0000-000000000001"),
])
def test_operator_digest_detects_state_changes_even_with_restored_schema(
    agent_service, target, field, value,
):
    from strugglebus.models import LifecycleActor

    service = agent_service
    created = service.create_agent("digest-copilot")
    issued = service.issue_reconnect(
        created.agent.id, expected_agent_name=created.agent.name,
        expected_credential_epoch=created.agent.credential_epoch,
        request_id=str(uuid4()), reason="synthetic digest grant",
        actor=LifecycleActor("remote-admin", f"operator:owner:{uuid4()}", lambda: None),
    )
    if field in {"redemption_request_id", "result_credential_id"}:
        assert issued.token is not None
        service.redeem_reconnect(
            issued.token, expected_agent_id=created.agent.id,
            expected_agent_name=created.agent.name, request_id=str(uuid4()),
        )
    path = service.store.database_path
    before = database_facts(path)
    # Simulate offline record tampering, restoring the exact reviewed DDL so
    # these assertions test the data digest rather than the schema fingerprint.
    with sqlite3.connect(path) as connection:
        triggers = connection.execute(
            "SELECT name, sql FROM sqlite_schema WHERE type='trigger' AND tbl_name=?",
            (target,),
        ).fetchall()
        for name, _ in triggers:
            assert name.replace("_", "").isalnum()
            connection.execute(f'DROP TRIGGER "{name}"')
        connection.execute(f"UPDATE {target} SET {field}=?", (value,))
        for _, sql in triggers:
            connection.execute(sql)
    after = database_facts(path)
    assert after["schema"] == before["schema"] == LATEST_SCHEMA_VERSION
    assert after["credential_state_sha256"] != before["credential_state_sha256"]


@pytest.fixture(scope="module")
def verifier():
    return create_password_verifier("synthetic maintenance operator password")


@pytest.fixture
def source(tmp_path, verifier):
    tmp_path.chmod(0o700)
    path = tmp_path / "operator-password"
    path.write_bytes(verifier)
    path.chmod(0o600)
    return path


def authorize(source, *, operation="a" * 32, binding="b" * 64):
    receipt = {
        "version": 1, "source": str(source),
        "verifier_sha256": maintenance.digest(source.read_bytes()),
        "maintenance_operation_id": operation,
        "maintenance_binding_sha256": binding,
    }
    path = source.parent / PASSWORD_AUTHORIZATION_FILE
    path.write_text(json.dumps(receipt), encoding="ascii")
    path.chmod(0o600)
    return receipt


def test_root_observation_is_opaque_and_matches_application_verifier(source, verifier):
    observed = maintenance.operator_observation(source)
    assert observed["sha256"] == maintenance.digest(verifier)
    assert observed["source"] == str(source)
    assert observed["authorization"] is None
    assert observed["inode"] == source.stat().st_ino
    serialized = json.dumps(observed)
    assert verifier.decode().strip() not in serialized
    assert "synthetic maintenance operator password" not in serialized
    assert maintenance.operator_observation(None) is None
    maintenance.validate_operator_observation(None)
    with maintenance.operator_source_fence(None):
        assert not (source.parent / PASSWORD_CONTROL_FILE).exists()


@pytest.mark.parametrize("invalid", [
    b"", b"plaintext-password-must-not-appear", b"x" * 257,
    b"sbop1$600001$" + b"a" * 32 + b"$" + b"b" * 64,
    b"sbop1$600000$" + b"a" * 32 + b"$" + b"b" * 64 + b"\n\n",
    b"\xff",
])
def test_invalid_source_is_bounded_and_never_echoed(source, invalid):
    source.write_bytes(invalid)
    with pytest.raises(maintenance.MaintenanceError) as failure:
        maintenance.operator_observation(source)
    assert "plaintext-password" not in str(failure.value)


def test_source_change_during_read_is_not_accepted(source, monkeypatch):
    original = maintenance.read_regular

    def changed(path, **kwargs):
        raw = original(path, **kwargs)
        if path == source:
            metadata = source.stat()
            os.utime(source, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000))
        return raw

    monkeypatch.setattr(maintenance, "read_regular", changed)
    with pytest.raises(maintenance.MaintenanceError, match="changed"):
        maintenance.operator_observation(source)


def test_authorized_generation_is_bound_to_source_and_retained_operation(source):
    receipt = authorize(source)
    observed = maintenance.operator_observation(source)
    assert observed["authorization"] == receipt
    receipt["verifier_sha256"] = "c" * 64
    (source.parent / PASSWORD_AUTHORIZATION_FILE).write_text(json.dumps(receipt), encoding="ascii")
    with pytest.raises(maintenance.MaintenanceError, match="authorization"):
        maintenance.operator_observation(source)


@pytest.mark.parametrize("field,value", [
    ("version", True), ("inode", True), ("size", 257), ("sha256", "not-a-digest"),
    ("source", "relative"), ("authorization", {"version": 1}),
])
def test_observation_contract_rejects_partial_and_ambiguous_evidence(source, field, value):
    observed = maintenance.operator_observation(source)
    observed[field] = value
    with pytest.raises(maintenance.MaintenanceError):
        maintenance.validate_operator_observation(observed)


def test_staging_binds_exact_source_generation(source, monkeypatch):
    monkeypatch.setattr(maintenance, "operator_source", lambda content: source)
    observed = maintenance.operator_observation(source)
    request = {"operator_credential": observed}
    maintenance.require_operator_binding(request, b"reviewed unit")
    with pytest.raises(maintenance.MaintenanceError, match="legacy"):
        maintenance.require_operator_binding({}, b"reviewed unit")
    parts = source.read_bytes().split(b"$")
    parts[2] = b"0" * 32 if parts[2] != b"0" * 32 else b"1" * 32
    source.write_bytes(b"$".join(parts))
    with pytest.raises(maintenance.MaintenanceError, match="source changed"):
        maintenance.require_operator_binding(request, b"reviewed unit")


@pytest.mark.parametrize("mutation", [
    None, "pending", "other-candidate", "other-source", "other-operation", "other-binding",
    "missing-authorization", "removal", "introduction",
])
def test_completed_password_reobservation_is_a_narrow_authorized_exception(source, mutation):
    before = maintenance.operator_observation(source)
    record = {
        "phase": "complete", "operation_id": "a" * 32,
        "binding": {"candidate": "0.3.0", "operator_credential": before},
    }
    binding_hash = maintenance.digest(
        json.dumps(record["binding"], sort_keys=True, separators=(",", ":")).encode("ascii"),
    )
    authorize(source, binding=binding_hash)
    after = maintenance.operator_observation(source)
    request = {"candidate": "0.3.0", "operator_credential": after}
    if mutation == "pending":
        record["phase"] = "started"
    elif mutation == "other-candidate":
        request["candidate"] = "0.4.0"
    elif mutation == "other-source":
        after["source"] = str(source.with_name("other"))
    elif mutation == "other-operation":
        after["authorization"]["maintenance_operation_id"] = "d" * 32
    elif mutation == "other-binding":
        after["authorization"]["maintenance_binding_sha256"] = "e" * 64
    elif mutation == "missing-authorization":
        after["authorization"] = None
    elif mutation == "removal":
        request["operator_credential"] = None
    elif mutation == "introduction":
        record["binding"]["operator_credential"] = None
    retained = copy.deepcopy(record)
    assert maintenance.completed_operator_reset(record, request) is (mutation is None)
    assert record == retained


@pytest.mark.skipif(os.name != "posix", reason="POSIX password and maintenance flock boundary")
def test_maintenance_and_password_command_share_the_same_exclusive_fence(source):
    assert maintenance.OPERATOR_CONTROL == PASSWORD_CONTROL_FILE
    assert maintenance.OPERATOR_AUTHORIZATION == PASSWORD_AUTHORIZATION_FILE
    with password_source_lock(source.parent):
        with pytest.raises(maintenance.MaintenanceError, match="in use"):
            with maintenance.operator_source_fence(source):
                pytest.fail("maintenance entered a password-owned source")
    with maintenance.operator_source_fence(source):
        with pytest.raises(ConfigurationError, match="in use"):
            with password_source_lock(source.parent):
                pytest.fail("password reset entered a maintenance-owned source")


@pytest.mark.skipif(os.name != "posix", reason="POSIX read-only credential mount")
def test_maintenance_fence_needs_no_write_access_to_an_existing_control(source, monkeypatch):
    with password_source_lock(source.parent):
        pass
    import fcntl

    competitor = os.open(source.parent / maintenance.OPERATOR_CONTROL, os.O_RDONLY)
    real_open = os.open

    def read_only_mount(path, flags, *args):
        if Path(path).name == maintenance.OPERATOR_CONTROL and flags & (os.O_WRONLY | os.O_RDWR):
            raise OSError(30, "Read-only file system", str(path))
        return real_open(path, flags, *args)

    monkeypatch.setattr(maintenance.os, "open", read_only_mount)
    try:
        with maintenance.operator_source_fence(source):
            with pytest.raises(BlockingIOError):
                fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(competitor)


@pytest.mark.skipif(os.name != "posix", reason="POSIX root source permissions and file kinds")
@pytest.mark.parametrize("mutation", ["public-file", "hardlink", "symlink", "fifo"])
def test_root_source_rejects_unsafe_files_without_blocking(source, mutation):
    if mutation == "public-file":
        source.chmod(0o644)
    elif mutation == "hardlink":
        os.link(source, source.with_name("alias"))
    elif mutation == "symlink":
        target = source.with_name("target")
        source.rename(target)
        source.symlink_to(target)
    else:
        source.unlink()
        os.mkfifo(source, mode=0o600)
    with pytest.raises((maintenance.MaintenanceError, OSError)):
        maintenance.operator_observation(source)
