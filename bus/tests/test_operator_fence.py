import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys

import pytest

from strugglebus import operator_fence
from test_release_lock import acquire, release, run_helper

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="delegated descriptors require Linux flock and /proc",
)

CHILD = r"""
import os, sys
from pathlib import Path
from strugglebus import operator_fence as fence
from strugglebus.errors import ConfigurationError

control, metadata = os.dup(int(sys.argv[1])), os.dup(int(sys.argv[2]))
os.dup2(control, 3)
os.dup2(metadata, 4)
for descriptor in {control, metadata, int(sys.argv[1]), int(sys.argv[2])} - {3, 4}:
    os.close(descriptor)
root = Path(sys.argv[3])
fence.CONTROL_PATH = root / "control.lock"
fence.METADATA_PATH = root / "release.json"
# Model manager delegation with non-root temporary files, not privileged systemd.
if sys.argv[6] != "production-owner":
    fence._ROOT_UID = os.geteuid()
def expected_binding():
    value = fence.parse_lease(Path(sys.argv[4]).read_bytes())
    if sys.argv[6] == "wait-replacement":
        print("PRECHECK", flush=True)
    return value
fence._expected_binding = expected_binding
os.environ["LISTEN_PID"] = str(os.getpid()) if sys.argv[6] != "wrong-pid" else "1"
os.environ["LISTEN_FDS"] = "2"
os.environ["LISTEN_FDNAMES"] = (
    "operator-control:operator-control" if sys.argv[6] == "wrong-names"
    else "operator-control:operator-metadata"
)
if sys.argv[6] == "missing-fd":
    os.close(4)
try:
    with fence.delegated_release_fence():
        assert not os.get_inheritable(3) and not os.get_inheritable(4)
        assert not any(name in os.environ for name in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"))
        Path(sys.argv[5]).write_text("mutation under fence")
        print("FENCED", flush=True)
        assert sys.stdin.readline() == "exit\n"
except ConfigurationError:
    print("DENIED", flush=True)
    raise SystemExit(2)
"""

RUNNER = r"""
import os, subprocess, sys, time
subprocess.Popen(
    [sys.executable, "-c", sys.argv[7], *sys.argv[1:7]],
    pass_fds=(int(sys.argv[1]), int(sys.argv[2])),
)
time.sleep(60)
"""


def start_mutator(root, binding, marker, *, mode="valid", descriptors=None):
    fds = descriptors or (
        os.open(root / "control.lock", os.O_RDONLY),
        os.open(root / "release.json", os.O_RDONLY),
    )
    environment = {
        **os.environ,
        "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        process = subprocess.Popen(
            [sys.executable, "-c", RUNNER if mode == "runner" else CHILD,
             *(str(fd) for fd in fds), str(root), str(binding), str(marker), mode,
             *([CHILD] if mode == "runner" else [])],
            pass_fds=fds, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=environment,
        )
    finally:
        for fd in fds:
            os.close(fd)
    return process


def read_line(process):
    ready, _, _ = select.select([process.stdout], [], [], 5)
    assert ready, "synthetic mutator did not report"
    return process.stdout.readline().strip()


def finish(process):
    text = "exit\n" if process.stdin is not None and not process.stdin.closed else None
    process.communicate(text, timeout=5)


@pytest.fixture
def lease(tmp_path):
    root = tmp_path / "locks"
    root.mkdir(mode=0o700)
    owner = acquire(root, lease=30)
    binding = tmp_path / "binding"
    binding.write_text(json.dumps(owner), encoding="ascii")
    binding.chmod(0o600)
    yield root, owner, binding, tmp_path / "mutation"
    if (root / "release.json").exists():
        current = json.loads((root / "release.json").read_text())
        release(root, current["token"])


@pytest.mark.parametrize("mode", ["wrong-pid", "wrong-names", "missing-fd", "production-owner"])
def test_invalid_delegation_fails_before_mutation(lease, mode):
    assert os.geteuid() != 0, "run delegated-fence evidence as an existing non-root account"
    root, _, binding, marker = lease
    process = start_mutator(root, binding, marker, mode=mode)
    try:
        assert read_line(process) == "DENIED"
        assert process.wait(timeout=5) == 2
        assert not marker.exists()
    finally:
        finish(process)


@pytest.mark.parametrize("replacement", ["unlink", "rename", "hardlink", "successor"])
def test_old_metadata_descriptor_or_binding_cannot_authorize_new_unit(lease, replacement):
    root, owner, binding, marker = lease
    fds = (
        os.open(root / "control.lock", os.O_RDONLY),
        os.open(root / "release.json", os.O_RDONLY),
    )
    original = (root / "release.json").read_bytes()
    if replacement == "hardlink":
        os.link(root / "release.json", root / "other")
    elif replacement == "rename":
        (root / "release.json").rename(root / "other")
        (root / "release.json").write_bytes(original)
        (root / "release.json").chmod(0o600)
    elif replacement == "unlink":
        (root / "release.json").unlink()
        (root / "release.json").write_bytes(original)
        (root / "release.json").chmod(0o600)
    else:
        for fd in fds:
            os.close(fd)
        release(root, owner["token"])
        acquire(root, lease=30)
        fds = None
    process = start_mutator(root, binding, marker, descriptors=fds)
    try:
        assert read_line(process) == "DENIED"
        assert process.wait(timeout=5) == 2
        assert not marker.exists()
    finally:
        finish(process)
        if replacement == "hardlink":
            (root / "other").unlink()


@pytest.mark.parametrize("action", ["release", "renew"])
def test_actual_mutator_fence_blocks_release_and_settles_normal_cleanup(lease, action):
    import fcntl

    root, owner, binding, marker = lease
    process = start_mutator(root, binding, marker)
    contender = None
    try:
        assert read_line(process) == "FENCED"
        assert marker.read_text() == "mutation under fence"
        with (root / "control.lock").open("rb") as probe:
            with pytest.raises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        contender = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve().parents[1] /
             "deploy/roles/guest_base/files/strugglebus-release-lock.py"),
             action, "--metadata-path", str(root / "release.json"), "--token", owner["token"],
             *(["--lease-seconds", "30"] if action == "renew" else [])],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        with pytest.raises(subprocess.TimeoutExpired):
            contender.wait(timeout=0.25)
        assert json.loads((root / "release.json").read_text()) == owner
        finish(process)
        assert process.returncode == 0
        assert contender.wait(timeout=6) == 0
    finally:
        finish(process)
        if contender is not None:
            contender.communicate(timeout=6)


def test_killed_keeper_cannot_publish_successor_until_mutator_exits(lease):
    root, owner, binding, marker = lease
    process = start_mutator(root, binding, marker)
    try:
        assert read_line(process) == "FENCED"
        os.kill(owner["pid"], signal.SIGKILL)
        result = run_helper(
            "acquire", "--lock-path", str(root / "release.lock"),
            "--metadata-path", str(root / "release.json"),
            "--wait-seconds", "1", "--lease-seconds", "30", check=False,
        )
        assert result.returncode == 1
        assert json.loads((root / "release.json").read_text()) == owner
        finish(process)
        assert process.returncode == 0
        successor = acquire(root, wait=2, lease=30)
        release(root, successor["token"])
    finally:
        finish(process)


def test_runner_loss_and_parent_descriptor_close_do_not_release_mutator_fence(lease):
    import fcntl

    root, owner, binding, marker = lease
    runner = start_mutator(root, binding, marker, mode="runner")
    try:
        assert read_line(runner) == "FENCED"
        os.kill(runner.pid, signal.SIGKILL)
        assert runner.wait(timeout=5) == -signal.SIGKILL
        with (root / "control.lock").open("rb") as probe:
            with pytest.raises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert json.loads((root / "release.json").read_text()) == owner
    finally:
        if runner.poll() is None:
            os.kill(runner.pid, signal.SIGKILL)
            runner.wait(timeout=5)
        finish(runner)


def test_expired_keeper_cannot_reclaim_lease_while_mutator_holds_control(tmp_path):
    root = tmp_path / "locks"
    root.mkdir(mode=0o700)
    owner = acquire(root, lease=2)
    binding = tmp_path / "binding"
    binding.write_text(json.dumps(owner), encoding="ascii")
    binding.chmod(0o600)
    process = start_mutator(root, binding, tmp_path / "mutation")
    try:
        assert read_line(process) == "FENCED"
        contender = run_helper(
            "acquire", "--lock-path", str(root / "release.lock"),
            "--metadata-path", str(root / "release.json"),
            "--wait-seconds", "3", "--lease-seconds", "30", check=False,
        )
        assert contender.returncode == 1
        assert json.loads((root / "release.json").read_text()) == owner
        finish(process)
        assert process.returncode == 0
        successor = acquire(root, wait=2, lease=30)
        release(root, successor["token"])
    finally:
        finish(process)
        if (root / "release.json").exists():
            current = json.loads((root / "release.json").read_text())
            release(root, current["token"])


def test_metadata_replacement_while_waiting_for_control_is_rechecked(lease):
    import fcntl

    root, _, binding, marker = lease
    with (root / "control.lock").open("rb") as control:
        fcntl.flock(control, fcntl.LOCK_EX)
        process = start_mutator(root, binding, marker, mode="wait-replacement")
        try:
            assert read_line(process) == "PRECHECK"
            replacement = root / "replacement"
            replacement.write_bytes((root / "release.json").read_bytes())
            replacement.chmod(0o600)
            replacement.replace(root / "release.json")
            fcntl.flock(control, fcntl.LOCK_UN)
            assert read_line(process) == "DENIED"
            assert process.wait(timeout=5) == 2
            assert not marker.exists()
        finally:
            fcntl.flock(control, fcntl.LOCK_UN)
            finish(process)


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("token", "f" * 64),
        ("pid", 999_999),
        ("start_ticks", 999_999),
        ("lease_seconds", 999_999),
        ("heartbeat_ns", 1),
    ],
)
def test_binding_from_different_original_lease_cannot_authorize_current_metadata(
    lease, field, replacement,
):
    root, owner, binding, marker = lease
    binding.write_text(json.dumps({**owner, field: replacement}), encoding="ascii")
    process = start_mutator(root, binding, marker)
    try:
        assert read_line(process) == "DENIED"
        assert process.wait(timeout=5) == 2
        assert not marker.exists()
    finally:
        finish(process)


@pytest.mark.parametrize("mode", ["private", "public", "hardlink", "symlink", "oversized"])
def test_expected_binding_projection_keeps_existing_private_credential_checks(
    lease, tmp_path, monkeypatch, mode,
):
    from strugglebus.errors import ConfigurationError

    _, owner, _, _ = lease
    directory = tmp_path / "synthetic-projection"
    directory.mkdir(mode=0o700)
    path = directory / operator_fence.EXPECTED_CREDENTIAL
    path.write_text(json.dumps(owner), encoding="ascii")
    path.chmod(0o400)
    # Only the namespace location is simulated; file/directory checks run normally.
    monkeypatch.setattr(operator_fence, "_credential_directory", lambda: directory)
    if mode == "public":
        path.chmod(0o644)
    elif mode == "hardlink":
        os.link(path, directory / "alias")
    elif mode == "symlink":
        path.rename(directory / "target")
        path.symlink_to(directory / "target")
    elif mode == "oversized":
        path.chmod(0o600)
        path.write_bytes(b"x" * 4097)
    if mode == "private":
        assert operator_fence._expected_binding() == owner
    else:
        with pytest.raises(ConfigurationError):
            operator_fence._expected_binding()


def test_descriptor_accepts_only_read_only_private_canonical_file(
    tmp_path, monkeypatch,
):
    from strugglebus.errors import ConfigurationError

    directory = tmp_path / "fence"
    directory.mkdir(mode=0o700)
    path = directory / "control.lock"
    path.write_bytes(b"")
    path.chmod(0o600)
    monkeypatch.setattr(operator_fence, "_ROOT_UID", os.geteuid())

    readable = os.open(path, os.O_RDONLY)
    try:
        assert operator_fence._descriptor(readable, path).st_ino == path.stat().st_ino
    finally:
        os.close(readable)

    writable = os.open(path, os.O_RDWR)
    try:
        with pytest.raises(ConfigurationError):
            operator_fence._descriptor(writable, path)
    finally:
        os.close(writable)


@pytest.mark.parametrize("directory", [None, "/tmp/credentials", "/run/credentials/strugglebus.service"])
def test_expected_binding_requires_exact_operator_projection_namespace(monkeypatch, directory):
    from strugglebus.errors import ConfigurationError

    if directory is None:
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    else:
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", directory)
    with pytest.raises(ConfigurationError):
        operator_fence._expected_binding()


@pytest.mark.parametrize("raw", [
    b"{}", b'{"version":1,"version":1}', b"[" * 1100, b"x" * 4097,
])
def test_binding_parser_is_strict_and_bounded(raw):
    from strugglebus.errors import ConfigurationError

    with pytest.raises(ConfigurationError):
        operator_fence.parse_lease(raw)
