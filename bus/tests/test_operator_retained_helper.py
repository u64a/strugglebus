"""Retained-helper reset admission with real files and simulated root/status observations."""

import hashlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from strugglebus import operator_local as local
from strugglebus.errors import ConfigurationError
from strugglebus.operator_auth import PasswordVerifier, create_password_verifier


pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux private files and source flock")


@pytest.fixture
def missing_journal(tmp_path, monkeypatch):
    source_directory = tmp_path / "source"
    source_directory.mkdir(mode=0o700)
    fixture = SimpleNamespace(
        state=tmp_path / "maintenance",
        helpers=tmp_path / "unbound-helpers",
        source=source_directory / "operator-password",
        receipt=source_directory / local.PASSWORD_AUTHORIZATION_FILE,
        prompts=[],
    )
    actual_guard = local.require_resolved_maintenance

    def guard():
        return actual_guard(state_directory=fixture.state, helper_root=fixture.helpers)

    def no_unbound_helper(*args, **kwargs):
        pytest.fail("missing maintenance journal must never execute an unbound helper")

    def prompt(*args, **kwargs):
        fixture.prompts.append(True)
        return "synthetic new operator password"

    fixture.guard = guard
    monkeypatch.setattr(local, "require_resolved_maintenance", guard)
    monkeypatch.setattr(local, "require_root_terminal", lambda _: None)
    monkeypatch.setattr(local.subprocess, "run", no_unbound_helper)
    monkeypatch.setattr(local.getpass, "getpass", prompt)
    return fixture


def prior_password_files(fixture, reset):
    if reset:
        fixture.source.write_bytes(create_password_verifier("synthetic previous operator password"))
        fixture.source.chmod(0o600)
        fixture.receipt.write_bytes(local._json_bytes({
            "version": 1, "source": str(fixture.source),
            "verifier_sha256": hashlib.sha256(fixture.source.read_bytes()).hexdigest(),
            "maintenance_operation_id": "b" * 32, "maintenance_binding_sha256": "c" * 64,
        }))
        fixture.receipt.chmod(0o600)
    return {
        path: (path.read_bytes() if path.exists() else None)
        for path in (fixture.source, fixture.receipt)
    }


def assert_password_files_unchanged(prior):
    for path, content in prior.items():
        assert (path.read_bytes() if path.exists() else None) == content
    assert not list(next(iter(prior)).parent.glob(".operator-reset-*"))


@pytest.mark.parametrize("existing_directory", [False, True])
@pytest.mark.parametrize("reset", [False, True])
def test_missing_journal_accepts_only_absent_or_empty_state(
    missing_journal, existing_directory, reset,
):
    fixture = missing_journal
    prior_password_files(fixture, reset)
    if existing_directory:
        fixture.state.mkdir(mode=0o700)
    assert fixture.guard() is None
    local.setup_password(fixture.source, reset=reset, stdin=io.StringIO(), stderr=io.StringIO())
    assert PasswordVerifier.parse(fixture.source.read_bytes()).verify("synthetic new operator password")
    receipt = json.loads(fixture.receipt.read_bytes())
    assert receipt["maintenance_operation_id"] is None
    assert receipt["maintenance_binding_sha256"] is None
    assert len(fixture.prompts) == 2
    assert not fixture.helpers.exists()
    assert not (fixture.state / "operation.json").exists()
    assert not fixture.state.exists() or list(fixture.state.iterdir()) == []


@pytest.mark.parametrize("name", ["candidate.env", ".staged", "cold-snapshot.db", "recovery"])
@pytest.mark.parametrize("reset", [False, True])
def test_missing_journal_nonempty_state_refuses_setup_and_reset_without_mutation(
    missing_journal, name, reset,
):
    fixture = missing_journal
    prior = prior_password_files(fixture, reset)
    fixture.state.mkdir(mode=0o700)
    evidence = fixture.state / name
    if name == "recovery":
        evidence.mkdir(mode=0o700)
    else:
        evidence.write_bytes(b"unresolved synthetic maintenance evidence")
        evidence.chmod(0o600)
    original_inode = evidence.stat().st_ino
    message = "maintenance state contains evidence without an operation journal"
    with pytest.raises(ConfigurationError, match=message):
        fixture.guard()
    with pytest.raises(ConfigurationError, match=message):
        local.setup_password(fixture.source, reset=reset, stdin=io.StringIO(), stderr=io.StringIO())
    assert fixture.prompts == []
    assert_password_files_unchanged(prior)
    assert list(fixture.state.iterdir()) == [evidence]
    assert evidence.stat().st_ino == original_inode
    assert evidence.is_dir() or evidence.read_bytes() == b"unresolved synthetic maintenance evidence"
    assert not fixture.helpers.exists()


@pytest.mark.parametrize("existing_directory", [False, True])
@pytest.mark.parametrize("reset", [False, True])
def test_missing_journal_evidence_appearing_during_prompt_prevents_publication(
    missing_journal, monkeypatch, existing_directory, reset,
):
    fixture = missing_journal
    prior = prior_password_files(fixture, reset)
    if existing_directory:
        fixture.state.mkdir(mode=0o700)
    evidence = fixture.state / "candidate.env"

    def prompt(*args, **kwargs):
        if not fixture.prompts:
            fixture.state.mkdir(mode=0o700, exist_ok=True)
            evidence.write_bytes(b"staged during human input")
            evidence.chmod(0o600)
        fixture.prompts.append(True)
        return "synthetic new operator password"

    monkeypatch.setattr(local.getpass, "getpass", prompt)
    with pytest.raises(
        ConfigurationError, match="maintenance state contains evidence without an operation journal",
    ):
        local.setup_password(fixture.source, reset=reset, stdin=io.StringIO(), stderr=io.StringIO())
    assert len(fixture.prompts) == 2
    assert_password_files_unchanged(prior)
    assert list(fixture.state.iterdir()) == [evidence]
    assert evidence.read_bytes() == b"staged during human input"
    assert not fixture.helpers.exists()


@pytest.fixture
def retained_reset(tmp_path, monkeypatch):
    state = tmp_path / "maintenance"
    state.mkdir(mode=0o700)
    source_directory = tmp_path / "source"
    source_directory.mkdir(mode=0o700)
    source = source_directory / "operator-password"
    original = create_password_verifier("synthetic previous operator password")
    source.write_bytes(original)
    source.chmod(0o600)
    production = (
        Path(__file__).resolve().parents[1] / "deploy" / "roles" / "guest_base"
        / "files" / "strugglebus-maintenance.py"
    ).read_bytes()
    assert 65_536 < len(production) < 1_048_576
    hashes = {name: "a" * 64 for name in local.MAINTENANCE_HELPERS}
    hashes["strugglebus-maintenance"] = hashlib.sha256(production).hexdigest()
    bundle = hashlib.sha256(
        "".join(hashes[name] for name in local.MAINTENANCE_HELPERS).encode("ascii"),
    ).hexdigest()
    helper_root = tmp_path / "helpers"
    directory = helper_root / bundle
    directory.mkdir(parents=True, mode=0o700)
    helper = directory / "strugglebus-maintenance"
    helper.write_bytes(production)
    helper.chmod(0o600)
    binding = {"helper_sha256": hashes, "helper_root": str(directory)}
    record = state / "operation.json"
    record.write_bytes(local._json_bytes({"operation_id": "1" * 32, "binding": binding}))
    record.chmod(0o600)
    stdout = local._json_bytes({
        "state": "complete", "provenance": "verified", "operation_id": "1" * 32,
    })
    observed = SimpleNamespace(
        state=state, source=source, original=original, helper=helper, record=record,
        binding=binding, stdout=stdout, calls=[], prompts=[],
    )
    original_lstat = Path.lstat
    simulated_root_paths = {helper, *helper.parents}

    def root_metadata(path, *args, **kwargs):
        value = original_lstat(path, *args, **kwargs)
        if path not in simulated_root_paths:
            return value
        # Non-root fixtures cannot own root-only ancestry. Preserve file type,
        # identity, length and link observations; simulate only UID/protected modes.
        fields = {name: getattr(value, name) for name in dir(value) if name.startswith("st_")}
        return SimpleNamespace(**{**fields, "st_uid": 0, "st_mode": value.st_mode & ~0o022})

    def status(command, **kwargs):
        assert command == [
            "/usr/bin/python3.13", "-I", str(helper), "status", "--verify",
            "--state-dir", str(state),
        ]
        assert kwargs == {
            "stdin": local.subprocess.DEVNULL, "capture_output": True, "timeout": 90,
            "check": False,
            "env": {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        }
        observed.calls.append(command)
        return SimpleNamespace(returncode=0, stdout=observed.stdout)

    def prompt(*args, **kwargs):
        observed.prompts.append(True)
        return "synthetic replacement operator password"

    actual_guard = local.require_resolved_maintenance
    monkeypatch.setattr(Path, "lstat", root_metadata)
    monkeypatch.setattr(local.subprocess, "run", status)
    monkeypatch.setattr(local, "require_root_terminal", lambda _: None)
    monkeypatch.setattr(local.getpass, "getpass", prompt)
    monkeypatch.setattr(local, "require_resolved_maintenance", lambda: actual_guard(
        state_directory=state, helper_root=helper_root,
    ))
    return observed


def test_password_reset_accepts_exact_retained_helper_larger_than_evidence_bound(retained_reset):
    fixture = retained_reset
    stderr = io.StringIO()
    local.setup_password(fixture.source, reset=True, stdin=io.StringIO(), stderr=stderr)
    assert len(fixture.calls) == 2
    assert len(fixture.prompts) == 2
    assert fixture.source.read_bytes() != fixture.original
    assert PasswordVerifier.parse(fixture.source.read_bytes()).verify(
        "synthetic replacement operator password",
    )
    receipt = json.loads(
        (fixture.source.parent / local.PASSWORD_AUTHORIZATION_FILE).read_bytes(),
    )
    assert receipt["maintenance_operation_id"] == "1" * 32
    assert receipt["maintenance_binding_sha256"] == hashlib.sha256(
        local._json_bytes(fixture.binding),
    ).hexdigest()
    assert "synthetic replacement operator password" not in stderr.getvalue()


@pytest.mark.parametrize("corruption,expected_status_calls", [
    ("helper_size", 0), ("helper_digest", 0), ("record_size", 0),
    ("status_size", 1), ("status_pending", 1), ("status_unverified", 1),
])
def test_retained_reset_keeps_evidence_bounds_and_refuses_before_password_write(
    retained_reset, corruption, expected_status_calls,
):
    fixture = retained_reset
    if corruption == "helper_size":
        fixture.helper.write_bytes(b"x" * 1_048_577)
    elif corruption == "helper_digest":
        fixture.helper.write_bytes(fixture.helper.read_bytes() + b"\n# changed\n")
    elif corruption == "record_size":
        fixture.record.write_bytes(fixture.record.read_bytes() + b" " * 65_537)
    elif corruption == "status_size":
        fixture.stdout += b" " * 65_537
    else:
        payload = json.loads(fixture.stdout)
        payload["state" if corruption == "status_pending" else "provenance"] = "unresolved"
        fixture.stdout = local._json_bytes(payload)
    expected_error = {
        "helper_size": "maintenance status helper is unsafe",
        "helper_digest": "maintenance status helper provenance changed",
        "record_size": "private input is too large or changed",
        "status_size": "maintenance status could not be established",
        "status_pending": "resolve pending maintenance before password setup or reset",
        "status_unverified": "maintenance status changed during password authorization",
    }[corruption]
    with pytest.raises(ConfigurationError, match=expected_error):
        local.setup_password(fixture.source, reset=True, stdin=io.StringIO(), stderr=io.StringIO())
    assert len(fixture.calls) == expected_status_calls
    assert fixture.prompts == []
    assert fixture.source.read_bytes() == fixture.original
    assert not (fixture.source.parent / local.PASSWORD_AUTHORIZATION_FILE).exists()
