"""The delegated release fence, driven in-process with unprivileged temporary files.

The subprocess tests in test_operator_fence.py prove the real inherited
descriptors 3 and 4. These model the same delegation at other descriptor
numbers so each refusal is observed directly in this process.
"""

import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from strugglebus import operator_fence as fence
from strugglebus.errors import ConfigurationError

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="delegated descriptors require Linux flock and /proc",
)

NAMES = "operator-control:operator-metadata"
REFUSAL = "protected operator release delegation is unavailable"


def own_start_ticks():
    return int(Path("/proc/self/stat").read_bytes().rsplit(b")", 1)[1].split()[19])


def is_open(descriptor):
    try:
        os.fstat(descriptor)
    except OSError:
        return False
    return True


def free_descriptor_pair():
    # Well above the lowest free number, which is the one the next open() gets:
    # a worker late in a long run can already have a few hundred files open.
    probe = os.open(os.devnull, os.O_RDONLY)
    os.close(probe)
    start = max(200, probe + 64)
    for first in range(start, start + 600, 2):
        if not is_open(first) and not is_open(first + 1):
            return first
    raise AssertionError("no free descriptor pair")


def write_private(path, content):
    path.write_bytes(content)
    path.chmod(0o600)


@pytest.fixture
def delegation(tmp_path, monkeypatch):
    locks = tmp_path / "lock"
    locks.mkdir(mode=0o700)
    credentials = tmp_path / "credentials"
    credentials.mkdir(mode=0o700)
    lease = {
        "version": 1, "pid": os.getpid(), "start_ticks": own_start_ticks(),
        "token": "5a" * 32, "lease_seconds": 30, "heartbeat_ns": time.monotonic_ns(),
    }
    state = SimpleNamespace(
        control=locks / "control.lock", metadata=locks / "release.json",
        credential=credentials / fence.EXPECTED_CREDENTIAL, lease=lease,
        first=free_descriptor_pair(), credentials=credentials,
    )
    write_private(state.control, b"")
    state.write_lease = lambda **changes: write_private(
        state.metadata, json.dumps({**lease, **changes}).encode("ascii"),
    )
    state.write_binding = lambda **changes: write_private(
        state.credential, json.dumps({**lease, **changes}).encode("ascii"),
    )
    state.write_lease()
    state.write_binding()
    monkeypatch.setattr(fence, "CONTROL_PATH", state.control)
    monkeypatch.setattr(fence, "METADATA_PATH", state.metadata)
    # Model root-owned manager state with files this unprivileged user owns.
    monkeypatch.setattr(fence, "_ROOT_UID", os.geteuid())
    monkeypatch.setattr(fence, "_LISTEN_FDS_START", state.first)
    monkeypatch.setattr(fence, "_credential_directory", lambda: credentials)

    def delegate(*, names=NAMES, pid=None, count="2", control_flags=os.O_RDONLY,
                 control_path=None):
        sources = (
            (control_path or state.control, control_flags), (state.metadata, os.O_RDONLY),
        )
        for offset, (path, flags) in enumerate(sources):
            opened = os.open(path, flags)
            assert opened < state.first, "the reserved descriptors must stay clear of new files"
            os.dup2(opened, state.first + offset)
            os.close(opened)
        monkeypatch.setenv("LISTEN_PID", str(os.getpid() if pid is None else pid))
        monkeypatch.setenv("LISTEN_FDS", count)
        if names is None:
            monkeypatch.delenv("LISTEN_FDNAMES", raising=False)
        else:
            monkeypatch.setenv("LISTEN_FDNAMES", names)

    state.delegate = delegate
    state.descriptors = (state.first, state.first + 1)
    yield state
    for descriptor in state.descriptors:
        if is_open(descriptor):
            os.close(descriptor)


def lock_is_held(path):
    import fcntl

    probe = os.open(path, os.O_RDONLY)
    try:
        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    else:
        fcntl.flock(probe, fcntl.LOCK_UN)
        return False
    finally:
        os.close(probe)


def assert_refused(state, *, match=REFUSAL):
    with pytest.raises(ConfigurationError, match=match):
        with fence.delegated_release_fence():
            pytest.fail("a refused delegation must never run the mutation")
    assert not lock_is_held(state.control)
    assert not any(name in os.environ for name in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"))


def test_valid_delegation_holds_the_control_lock_until_exit(delegation):
    delegation.delegate()
    with fence.delegated_release_fence():
        assert lock_is_held(delegation.control)
        assert not any(os.get_inheritable(item) for item in delegation.descriptors)
        assert "LISTEN_FDS" not in os.environ and "LISTEN_FDNAMES" not in os.environ
    assert not lock_is_held(delegation.control)
    assert not any(is_open(item) for item in delegation.descriptors)


def test_descriptor_names_may_arrive_in_either_order(delegation, monkeypatch):
    delegation.delegate(names="operator-metadata:operator-control")
    # The second name is control, so the delegated files swap positions.
    first, second = delegation.descriptors
    spare = os.dup(first)
    os.dup2(second, first)
    os.dup2(spare, second)
    os.close(spare)
    with fence.delegated_release_fence():
        assert lock_is_held(delegation.control)


@pytest.mark.parametrize("activation", [
    {"pid": 1}, {"count": "3"}, {"count": ""}, {"names": None},
    {"names": "operator-control:operator-control"},
    {"names": "operator-control"},
    {"names": "operator-control:operator-metadata:operator-control"},
    {"names": "operator-control:another"},
])
def test_wrong_activation_is_refused_before_any_descriptor_is_touched(delegation, activation):
    delegation.delegate(**activation)
    assert_refused(delegation)
    assert all(os.get_inheritable(item) for item in delegation.descriptors)


def test_refused_on_other_platforms_before_reading_activation(delegation, monkeypatch):
    delegation.delegate()
    monkeypatch.setattr(fence.sys, "platform", "win32")
    with pytest.raises(ConfigurationError, match=REFUSAL):
        with fence.delegated_release_fence():
            pytest.fail("unsupported platform ran the mutation")
    assert os.environ["LISTEN_FDS"] == "2"


def test_missing_descriptor_is_refused(delegation):
    delegation.delegate()
    os.close(delegation.descriptors[1])
    assert_refused(delegation)


@pytest.mark.parametrize("damage", [
    "control-mode", "directory-mode", "writable-descriptor", "hard-link",
    "other-file", "other-owner", "path-descriptor", "linked-directory",
])
def test_unsafe_delegated_files_are_refused(delegation, monkeypatch, tmp_path, damage):
    options = {}
    if damage == "control-mode":
        delegation.control.chmod(0o640)
    elif damage == "directory-mode":
        delegation.control.parent.chmod(0o750)
    elif damage == "writable-descriptor":
        options["control_flags"] = os.O_RDWR
    elif damage == "hard-link":
        os.link(delegation.metadata, delegation.metadata.with_name("second-name"))
    elif damage == "other-file":
        other = delegation.control.with_name("other.lock")
        write_private(other, b"")
        options["control_path"] = other
    elif damage == "other-owner":
        monkeypatch.setattr(fence, "_ROOT_UID", os.geteuid() + 1)
    elif damage == "path-descriptor":
        options["control_flags"] = os.O_PATH
    elif damage == "linked-directory":
        alias = tmp_path / "alias"
        alias.symlink_to(delegation.control.parent, target_is_directory=True)
        monkeypatch.setattr(fence, "CONTROL_PATH", alias / "control.lock")
        monkeypatch.setattr(fence, "METADATA_PATH", alias / "release.json")
        options["control_path"] = alias / "control.lock"
        with pytest.raises(ConfigurationError, match=REFUSAL):
            fence._require_private_root_directory(alias)
    delegation.delegate(**options)
    assert_refused(delegation)
    assert not any(is_open(item) for item in delegation.descriptors)


@pytest.mark.parametrize("lease,binding", [
    ({}, {"token": "6b" * 32}),
    ({"lease_seconds": 31}, {}),
    ({"pid": os.getpid() + 1}, {}),
    ({"start_ticks": 1}, {"start_ticks": 1}),
    ({"pid": 2 ** 22 + 7}, {"pid": 2 ** 22 + 7}),
    ({"heartbeat_ns": 1, "lease_seconds": 1}, {"heartbeat_ns": 1, "lease_seconds": 1}),
    ({"heartbeat_ns": 2 ** 62}, {"heartbeat_ns": 2 ** 62}),
    ({"version": 2}, {}),
    ({"padding": "x" * fence.MAX_BINDING_BYTES}, {}),
], ids=[
    "token", "lease-seconds", "pid", "recycled-pid", "dead-pid",
    "stale-heartbeat", "future-heartbeat", "invalid-lease", "oversized-lease",
])
def test_lease_that_is_not_the_live_bound_manager_is_refused(delegation, lease, binding):
    delegation.write_lease(**lease)
    delegation.write_binding(**binding)
    delegation.delegate()
    assert_refused(delegation)
    assert not any(is_open(item) for item in delegation.descriptors)


def test_waits_for_a_busy_fence_then_holds_it(delegation, monkeypatch):
    import fcntl

    holder = os.open(delegation.control, os.O_RDONLY)
    fcntl.flock(holder, fcntl.LOCK_EX)
    waits = []

    def release_after_two_waits(seconds):
        waits.append(seconds)
        if len(waits) == 2:
            fcntl.flock(holder, fcntl.LOCK_UN)

    monkeypatch.setattr(fence, "time", SimpleNamespace(
        monotonic=time.monotonic, monotonic_ns=time.monotonic_ns,
        sleep=release_after_two_waits,
    ))
    delegation.delegate()
    try:
        with fence.delegated_release_fence():
            assert waits == [0.05, 0.05]
            assert lock_is_held(delegation.control)
    finally:
        os.close(holder)


def test_gives_up_when_the_fence_stays_busy(delegation, monkeypatch):
    import fcntl

    holder = os.open(delegation.control, os.O_RDONLY)
    fcntl.flock(holder, fcntl.LOCK_EX)
    clock = iter([100.0, 100.0, 129.9, 130.0])
    waits = []
    monkeypatch.setattr(fence, "time", SimpleNamespace(
        monotonic=lambda: next(clock), sleep=waits.append,
    ))
    delegation.delegate()
    try:
        with pytest.raises(ConfigurationError, match=REFUSAL):
            with fence.delegated_release_fence():
                pytest.fail("a busy fence ran the mutation")
        assert waits == [0.05, 0.05]
        assert lock_is_held(delegation.control)
    finally:
        os.close(holder)
    assert not any(is_open(item) for item in delegation.descriptors)


def test_lease_replaced_while_waiting_for_the_fence_is_refused(delegation, monkeypatch):
    actual = fence._expected_binding

    def replace_then_read():
        replacement = delegation.metadata.with_name("next-release.json")
        write_private(replacement, delegation.metadata.read_bytes())
        os.replace(replacement, delegation.metadata)
        return actual()

    monkeypatch.setattr(fence, "_expected_binding", replace_then_read)
    delegation.delegate()
    assert_refused(delegation)


def test_expected_binding_is_read_from_the_protected_credential(delegation):
    assert fence._expected_binding() == delegation.lease


@pytest.mark.parametrize("damage", [
    "shared-directory", "symbolic-link", "hard-link", "shared-mode", "oversized",
    "not-a-lease",
])
def test_unsafe_expected_binding_is_refused(delegation, damage):
    if damage == "shared-directory":
        delegation.credentials.chmod(0o755)
    elif damage == "symbolic-link":
        target = delegation.credential.with_name("real-lease")
        delegation.credential.rename(target)
        delegation.credential.symlink_to(target)
    elif damage == "hard-link":
        os.link(delegation.credential, delegation.credential.with_name("second-name"))
    elif damage == "shared-mode":
        delegation.credential.chmod(0o644)
    elif damage == "oversized":
        delegation.write_binding(padding="x" * fence.MAX_BINDING_BYTES)
    elif damage == "not-a-lease":
        write_private(delegation.credential, b"{}")
    with pytest.raises(ConfigurationError):
        fence._expected_binding()
    delegation.delegate()
    # A shared mode is reported by the common credential check in its own words.
    assert_refused(delegation, match="unsafe ownership" if damage == "shared-mode" else REFUSAL)
    assert not any(is_open(item) for item in delegation.descriptors)


def test_missing_expected_binding_is_refused(delegation):
    delegation.credential.unlink()
    with pytest.raises(FileNotFoundError):
        fence._expected_binding()
    delegation.delegate()
    assert_refused(delegation)


@pytest.mark.parametrize("change", ["appended", "replaced"])
def test_expected_binding_changed_while_read_is_refused(delegation, monkeypatch, change):
    actual_read = os.read

    def read_then_change(descriptor, count):
        data = actual_read(descriptor, count)
        if os.readlink(f"/proc/self/fd/{descriptor}") != str(delegation.credential):
            return data
        if change == "appended":
            with delegation.credential.open("ab") as stream:
                stream.write(b" ")
        else:
            replacement = delegation.credential.with_name("next-lease")
            write_private(replacement, data)
            os.replace(replacement, delegation.credential)
        return data

    monkeypatch.setattr(fence.os, "read", read_then_change)
    with pytest.raises(ConfigurationError, match=REFUSAL):
        fence._expected_binding()


def test_credential_directory_must_be_the_transient_operator_unit(monkeypatch):
    # The fixture above replaces this lookup; exercise the real one here.
    valid = "/run/credentials/strugglebus-operator-" + "0f" * 16 + ".service"
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", valid)
    assert fence._credential_directory() == Path(valid)
    for unsafe in (
        "", "/run/credentials/strugglebus.service", valid + "/..", valid.upper(),
        "/tmp/credentials/strugglebus-operator-" + "0f" * 16 + ".service",
    ):
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", unsafe)
        with pytest.raises(ConfigurationError, match=REFUSAL):
            fence._credential_directory()
    monkeypatch.delenv("CREDENTIALS_DIRECTORY")
    with pytest.raises(ConfigurationError, match=REFUSAL):
        fence._credential_directory()


def test_process_start_ticks_come_from_proc():
    assert fence._process_start_ticks(os.getpid()) == own_start_ticks()
    with pytest.raises(FileNotFoundError):
        fence._process_start_ticks(2 ** 22 + 7)
