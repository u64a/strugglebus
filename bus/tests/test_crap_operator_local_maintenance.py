"""Password-setup admission: retained maintenance evidence and private publication."""

import hashlib
import io
import json
import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from strugglebus import operator_local as local
from strugglebus.errors import ConfigurationError
from strugglebus.operator_auth import PasswordVerifier

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux private files and ownership")

OPERATION = "1f" * 16
HELPER_SOURCE = b"# synthetic retained maintenance helper\n"
FOREIGN_UID = 54_321


@pytest.fixture
def retained(tmp_path, monkeypatch):
    """A completed operation journal bound to a content-addressed helper.

    The helper tree must be root-owned, which an unprivileged test cannot
    create. Ownership is simulated per path; file types, modes, link counts
    and sizes stay real below the helper root.
    """
    # The code refuses a helper reached through a link; some hosts link /tmp.
    tmp_path = tmp_path.resolve()
    state = tmp_path / "maintenance"
    state.mkdir(mode=0o700)
    hashes = {name: "a" * 64 for name in local.MAINTENANCE_HELPERS}
    hashes["strugglebus-maintenance"] = hashlib.sha256(HELPER_SOURCE).hexdigest()
    bundle = hashlib.sha256(
        "".join(hashes[name] for name in local.MAINTENANCE_HELPERS).encode("ascii"),
    ).hexdigest()
    helper_root = tmp_path / "helpers"
    directory = helper_root / bundle
    directory.mkdir(parents=True, mode=0o755)
    # mkdir applies the mode only to the last directory; a umask of 002 would
    # leave the parent group-writable, which the code rightly refuses.
    helper_root.chmod(0o755)
    directory.chmod(0o755)
    helper = directory / "strugglebus-maintenance"
    helper.write_bytes(HELPER_SOURCE)
    helper.chmod(0o755)
    binding = {"helper_sha256": hashes, "helper_root": str(directory)}
    record = state / "operation.json"
    fixture = SimpleNamespace(
        state=state, helper_root=helper_root, directory=directory, helper=helper,
        record=record, binding=binding, calls=[], owners={},
        status={"state": "complete", "provenance": "verified", "operation_id": OPERATION},
        result=SimpleNamespace(returncode=0, stdout=None), during_status=lambda: None,
    )

    def write_record(value):
        content = value if isinstance(value, bytes) else local._json_bytes(value)
        record.write_bytes(content)
        record.chmod(0o600)

    fixture.write_record = write_record
    write_record({"operation_id": OPERATION, "binding": binding})
    actual_lstat = Path.lstat
    above_helpers = set(helper_root.parents)
    simulated = {helper, *helper.parents}

    def lstat(path, *args, **kwargs):
        value = actual_lstat(path, *args, **kwargs)
        if path not in simulated:
            return value
        fields = {name: getattr(value, name) for name in dir(value) if name.startswith("st_")}
        fields["st_uid"] = fixture.owners.get(path, 0)
        if path in above_helpers:
            # Shared temporary ancestors stand in for root-only system directories.
            fields["st_mode"] = value.st_mode & ~0o022
        return SimpleNamespace(**fields)

    def run(command, **kwargs):
        fixture.calls.append((command, kwargs))
        fixture.during_status()
        if isinstance(fixture.result, Exception):
            raise fixture.result
        if fixture.result.stdout is None:
            fixture.result.stdout = local._json_bytes(fixture.status)
        return fixture.result

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(local.subprocess, "run", run)
    fixture.resolve = lambda: local.require_resolved_maintenance(
        state_directory=state, helper_root=helper_root,
    )
    return fixture


def assert_refused(fixture, message, *, status_calls=0):
    with pytest.raises(ConfigurationError, match=message):
        fixture.resolve()
    assert len(fixture.calls) == status_calls


def test_completed_maintenance_is_bound_to_its_verified_helper(retained):
    assert retained.resolve() == {
        "operation_id": OPERATION,
        "binding_sha256": hashlib.sha256(local._json_bytes(retained.binding)).hexdigest(),
    }
    [(command, options)] = retained.calls
    assert command == [
        "/usr/bin/python3.13", "-I", str(retained.helper), "status", "--verify",
        "--state-dir", str(retained.state),
    ]
    assert options["env"] == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
    assert options["stdin"] is subprocess.DEVNULL and options["timeout"] == 90


def test_evidence_without_a_journal_is_never_treated_as_clean(retained):
    retained.record.unlink()
    assert retained.resolve() is None
    (retained.state / "backup.sqlite3").write_bytes(b"evidence")
    assert_refused(retained, "evidence without an operation journal")


def test_linked_state_directory_is_refused(retained, tmp_path):
    alias = tmp_path / "linked-maintenance"
    alias.symlink_to(retained.state, target_is_directory=True)
    with pytest.raises(ConfigurationError, match="private path"):
        local.require_resolved_maintenance(
            state_directory=alias, helper_root=retained.helper_root,
        )
    dangling = tmp_path / "dangling-maintenance"
    dangling.symlink_to(tmp_path / "absent", target_is_directory=True)
    with pytest.raises(ConfigurationError, match="private path"):
        local.require_resolved_maintenance(
            state_directory=dangling, helper_root=retained.helper_root,
        )
    assert retained.calls == []


@pytest.mark.parametrize("record,message", [
    (b"not json", "could not be established"),
    (b"[]", "maintenance binding is unavailable"),
    (b'{"binding": "helpers"}', "maintenance binding is unavailable"),
    (b'{"operation_id": "x"}', "maintenance binding is unavailable"),
    (b'{"binding": {}, "binding": {}}', "duplicate maintenance or authorization field"),
    (b'{"binding": {}}', "maintenance helper binding is invalid"),
    (b'{"binding": {"helper_sha256": []}}', "maintenance helper binding is invalid"),
    (b"[" * 5000, "could not be established"),
], ids=[
    "not-json", "list", "binding-text", "no-binding", "duplicate-field", "no-hashes",
    "hash-list", "too-deep",
])
def test_malformed_journal_is_refused_before_any_helper_runs(retained, record, message):
    retained.write_record(record)
    assert_refused(retained, message)


@pytest.mark.parametrize("change", [
    "missing-helper", "extra-helper", "uppercase-digest", "short-digest", "numeric-digest",
])
def test_helper_binding_must_name_exactly_the_known_helpers(retained, change):
    hashes = dict(retained.binding["helper_sha256"])
    if change == "missing-helper":
        del hashes["strugglebus-sqlite-backup"]
    elif change == "extra-helper":
        hashes["strugglebus-extra"] = "a" * 64
    elif change == "uppercase-digest":
        hashes["strugglebus-sqlite-backup"] = "A" * 64
    elif change == "short-digest":
        hashes["strugglebus-sqlite-backup"] = "a" * 63
    else:
        hashes["strugglebus-sqlite-backup"] = 7
    retained.write_record({
        "operation_id": OPERATION, "binding": {**retained.binding, "helper_sha256": hashes},
    })
    assert_refused(retained, "maintenance helper binding is invalid")


def test_helper_must_live_at_its_content_address(retained, tmp_path):
    elsewhere = tmp_path / "helpers" / ("0" * 64)
    retained.write_record({
        "operation_id": OPERATION, "binding": {**retained.binding, "helper_root": str(elsewhere)},
    })
    assert_refused(retained, "maintenance helper is not content-addressed")
    retained.write_record({
        "operation_id": OPERATION,
        "binding": {"helper_sha256": retained.binding["helper_sha256"]},
    })
    assert_refused(retained, "maintenance helper is not content-addressed")


@pytest.mark.parametrize("damage,message", [
    ("directory-group-writable", "maintenance helper directory is unsafe"),
    ("directory-foreign-owner", "maintenance helper directory is unsafe"),
    ("root-foreign-owner", "maintenance helper directory is unsafe"),
    ("directory-linked", "maintenance helper directory is unsafe"),
    ("helper-world-writable", "maintenance status helper is unsafe"),
    ("helper-foreign-owner", "maintenance status helper is unsafe"),
    ("helper-hard-linked", "maintenance status helper is unsafe"),
    ("helper-linked", "maintenance status helper is unsafe"),
    ("helper-oversized", "maintenance status helper is unsafe"),
    ("helper-edited", "maintenance status helper provenance changed"),
    ("helper-missing", "maintenance status could not be established"),
])
def test_unprotected_or_changed_helper_never_runs(retained, tmp_path, damage, message):
    if damage == "directory-group-writable":
        retained.directory.chmod(0o775)
    elif damage == "directory-foreign-owner":
        retained.owners[retained.directory] = FOREIGN_UID
    elif damage == "root-foreign-owner":
        retained.owners[retained.helper_root] = FOREIGN_UID
    elif damage == "directory-linked":
        moved = tmp_path / "moved-bundle"
        retained.directory.rename(moved)
        retained.directory.symlink_to(moved, target_is_directory=True)
    elif damage == "helper-world-writable":
        retained.helper.chmod(0o757)
    elif damage == "helper-foreign-owner":
        retained.owners[retained.helper] = FOREIGN_UID
    elif damage == "helper-hard-linked":
        os.link(retained.helper, retained.helper.with_name("second-name"))
    elif damage == "helper-linked":
        moved = retained.helper.with_name("moved-helper")
        retained.helper.rename(moved)
        retained.helper.symlink_to(moved)
    elif damage == "helper-oversized":
        retained.helper.write_bytes(b"#" * 1_048_577)
    elif damage == "helper-edited":
        retained.helper.write_bytes(HELPER_SOURCE + b"import os\n")
    else:
        retained.helper.unlink()
    assert_refused(retained, message)


@pytest.mark.parametrize("status,message", [
    ({"state": "pending"}, "resolve pending maintenance"),
    ({"state": None}, "resolve pending maintenance"),
    ({"provenance": "unverified"}, "maintenance status changed"),
    ({"operation_id": None}, "maintenance status changed"),
    ({"operation_id": "2e" * 16}, "maintenance status changed"),
    ({"operation_id": OPERATION.upper()}, "maintenance status changed"),
])
def test_status_must_be_the_verified_completed_retained_operation(retained, status, message):
    retained.status.update(status)
    assert_refused(retained, message, status_calls=1)


def test_operation_identity_must_be_canonical_even_when_the_journal_agrees(retained):
    retained.write_record({"operation_id": "not-hex", "binding": retained.binding})
    retained.status["operation_id"] = "not-hex"
    assert_refused(retained, "maintenance status changed", status_calls=1)


@pytest.mark.parametrize("stdout,message", [
    (b"[]", "resolve pending maintenance"),
    (b"not json", "maintenance status could not be established"),
    (b'{"state": "complete", "state": "complete"}', "duplicate maintenance"),
    (b" " * 65_537, "maintenance status could not be established"),
], ids=["list", "not-json", "duplicate-field", "oversized"])
def test_unreadable_status_output_is_refused(retained, stdout, message):
    retained.result.stdout = stdout
    assert_refused(retained, message, status_calls=1)


@pytest.mark.parametrize("failure", ["exit-status", "timeout", "cannot-execute"])
def test_failed_status_helper_is_refused(retained, failure):
    if failure == "exit-status":
        retained.result.returncode = 3
    elif failure == "timeout":
        retained.result = subprocess.TimeoutExpired("status", 90)
    else:
        retained.result = PermissionError("synthetic exec refusal")
    assert_refused(retained, "maintenance status could not be established", status_calls=1)


def test_journal_changed_while_status_ran_is_refused(retained):
    retained.during_status = lambda: retained.write_record({
        "operation_id": OPERATION, "binding": retained.binding, "note": "rewritten",
    })
    assert_refused(retained, "maintenance status changed", status_calls=1)


@pytest.fixture
def private_directory(tmp_path):
    tmp_path.chmod(0o700)
    return tmp_path


class OsProxy:
    """Stand in for the module's os with selected calls replaced."""

    def __init__(self, **replacements):
        self._replacements = replacements

    def __getattr__(self, name):
        return self._replacements.get(name) or getattr(os, name)


def test_publication_creates_a_private_file_and_tolerates_short_writes(
    private_directory, monkeypatch,
):
    sizes = []

    def one_byte(descriptor, view):
        sizes.append(len(view))
        return os.write(descriptor, view[:1])

    monkeypatch.setattr(local, "os", OsProxy(write=one_byte))
    path = private_directory / "credential"
    local._publish_private(path, b"abc", original=None)
    assert path.read_bytes() == b"abc"
    assert sizes == [3, 2, 1]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [item.name for item in private_directory.iterdir()] == ["credential"]


def test_publication_never_overwrites_an_unexpected_existing_file(private_directory):
    path = private_directory / "credential"
    path.write_bytes(b"already here")
    path.chmod(0o600)
    with pytest.raises(ConfigurationError):
        local._publish_private(path, b"new", original=None)
    assert path.read_bytes() == b"already here"


def test_publication_replaces_only_the_file_it_was_authorized_to_replace(private_directory):
    path = private_directory / "credential"
    path.write_bytes(b"old")
    path.chmod(0o600)
    original = path.lstat()
    local._publish_private(path, b"new", original=original)
    assert path.read_bytes() == b"new"
    assert [item.name for item in private_directory.iterdir()] == ["credential"]
    # The earlier observation is now stale: the path names a different file.
    with pytest.raises(ConfigurationError, match="changed during publication"):
        local._publish_private(path, b"newer", original=original)
    assert path.read_bytes() == b"new"
    assert [item.name for item in private_directory.iterdir()] == ["credential"]


def test_stalled_publication_removes_its_own_partial_file(private_directory, monkeypatch):
    monkeypatch.setattr(local, "os", OsProxy(write=lambda descriptor, view: 0))
    path = private_directory / "credential"
    with pytest.raises(OSError, match="did not progress"):
        local._publish_private(path, b"abc", original=None)
    assert list(private_directory.iterdir()) == []


def test_swapped_destination_is_refused_and_the_foreign_file_is_left_alone(
    private_directory, monkeypatch,
):
    path = private_directory / "credential"
    actual = local.require_private_path

    def swap_then_check(target, **options):
        if target == path:
            path.unlink()
            path.write_bytes(b"planted")
            path.chmod(0o600)
        return actual(target, **options)

    monkeypatch.setattr(local, "require_private_path", swap_then_check)
    with pytest.raises(ConfigurationError, match="destination changed"):
        local._publish_private(path, b"abc", original=None)
    assert path.read_bytes() == b"planted"


@pytest.fixture
def setup(private_directory, monkeypatch):
    fixture = SimpleNamespace(
        source=private_directory / "operator-password",
        receipt=private_directory / local.PASSWORD_AUTHORIZATION_FILE,
        answers=["synthetic operator password", "synthetic operator password"],
        stderr=io.StringIO(),
    )

    def prompt(text, stream=None):
        assert stream is fixture.stderr
        answer = fixture.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(local, "require_root_terminal", lambda stdin: None)
    monkeypatch.setattr(local, "require_resolved_maintenance", lambda: None)
    monkeypatch.setattr(local.getpass, "getpass", prompt)
    for name in (
        "STRUGGLEBUS_OPERATOR_PASSWORD", "STRUGGLEBUS_OPERATOR_PASSWORD_HASH",
        "STRUGGLEBUS_OPERATOR_SECRET",
    ):
        monkeypatch.delenv(name, raising=False)
    fixture.run = lambda *, reset=False: local.setup_password(
        fixture.source, reset=reset, stdin=io.StringIO(), stderr=fixture.stderr,
    )
    return fixture


def private_names(fixture):
    return sorted(
        item.name for item in fixture.source.parent.iterdir()
        if item.name != local.PASSWORD_CONTROL_FILE
    )


@pytest.mark.parametrize("name", [
    "STRUGGLEBUS_OPERATOR_PASSWORD", "STRUGGLEBUS_OPERATOR_PASSWORD_HASH",
    "STRUGGLEBUS_OPERATOR_SECRET",
])
def test_password_material_in_the_environment_is_refused_before_prompting(
    setup, monkeypatch, name,
):
    monkeypatch.setenv(name, "")
    with pytest.raises(ConfigurationError, match="must not be supplied through environment"):
        setup.run()
    assert len(setup.answers) == 2
    assert list(setup.source.parent.iterdir()) == []


def test_mismatched_confirmation_writes_nothing(setup):
    setup.answers[1] = "synthetic operator passw0rd"
    with pytest.raises(ConfigurationError, match="did not match"):
        setup.run()
    assert private_names(setup) == []
    assert "synthetic" not in setup.stderr.getvalue()


def test_closed_terminal_during_prompt_writes_nothing(setup):
    setup.answers[1] = EOFError()
    with pytest.raises(ConfigurationError, match="no-echo terminal"):
        setup.run()
    assert private_names(setup) == []


def test_reset_requires_an_existing_exact_mode_verifier(setup):
    with pytest.raises(ConfigurationError, match="private path is unavailable"):
        setup.run(reset=True)
    setup.run()
    first = setup.source.read_bytes()
    setup.source.chmod(0o400)
    setup.answers[:] = ["replacement operator password"] * 2
    with pytest.raises(ConfigurationError, match="verifier source must be root-owned 0600"):
        setup.run(reset=True)
    assert setup.source.read_bytes() == first
    assert len(setup.answers) == 2


def test_existing_receipt_must_be_exact_mode_before_prompting(setup):
    setup.receipt.write_bytes(b"{}")
    setup.receipt.chmod(0o400)
    with pytest.raises(ConfigurationError, match="authorization receipt must be root-owned 0600"):
        setup.run()
    assert len(setup.answers) == 2
    assert not setup.source.exists()
    setup.receipt.chmod(0o640)
    with pytest.raises(ConfigurationError, match="unsafe ownership or permissions"):
        setup.run()
    assert not setup.source.exists()


def test_reset_replaces_both_verifier_and_receipt(setup):
    setup.run()
    first = setup.source.read_bytes()
    setup.answers[:] = ["replacement operator password"] * 2
    setup.run(reset=True)
    assert setup.source.read_bytes() != first
    assert PasswordVerifier.parse(setup.source.read_bytes()).verify(
        "replacement operator password",
    )
    receipt = json.loads(setup.receipt.read_bytes())
    assert receipt["verifier_sha256"] == hashlib.sha256(setup.source.read_bytes()).hexdigest()
    assert private_names(setup) == sorted([local.PASSWORD_AUTHORIZATION_FILE, setup.source.name])
    assert "Operator verifier installed" in setup.stderr.getvalue()


@pytest.mark.parametrize("failure", [OSError("disk full"), ConfigurationError("unsafe")])
def test_receipt_failure_after_the_verifier_changed_demands_a_reset(setup, monkeypatch, failure):
    actual = local._publish_private

    def publish(path, content, *, original):
        if path == setup.receipt:
            raise failure
        return actual(path, content, original=original)

    monkeypatch.setattr(local, "_publish_private", publish)
    with pytest.raises(ConfigurationError, match="authorization receipt failed; rerun explicit"):
        setup.run()
    password = "synthetic operator password"
    assert PasswordVerifier.parse(setup.source.read_bytes()).verify(password)
    assert password not in setup.stderr.getvalue()
    assert "installed" not in setup.stderr.getvalue()
    assert not setup.receipt.exists()
