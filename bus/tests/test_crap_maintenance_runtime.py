"""Protected configuration, file reads, child processes and updater polling."""

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace

import pytest

import strugglebus.maintenance_runtime as runtime
from strugglebus.maintenance_runtime import (
    BoardAnnouncer,
    PreparedReleaseGateway,
    active_application_version,
    config_from_json,
    load_config,
)
from strugglebus.maintenance_supervisor import PreparedRelease
from strugglebus.maintenance_types import MaintenanceError
from strugglebus.update_types import UpdateError
from test_maintenance_runtime import configuration

posix_only = pytest.mark.skipif(os.name != "posix", reason="requires POSIX ownership and modes")


# --- configuration ----------------------------------------------------------


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param({"version": 2}, id="future-version"),
        pytest.param({"application_uid": True}, id="boolean-uid"),
        pytest.param({"application_uid": "998"}, id="text-uid"),
        pytest.param({"release_lock_wait_seconds": 301}, id="wait-too-long"),
        pytest.param({"release_lock_wait_seconds": 1.5}, id="fractional-wait"),
        pytest.param({"release_lock_lease_seconds": 14401}, id="lease-too-long"),
        pytest.param({"release_lock_lease_seconds": "3600"}, id="text-lease"),
        pytest.param({"service_user": "Root"}, id="uppercase-user"),
        pytest.param({"service_user": ""}, id="empty-user"),
        pytest.param({"service_user": 998}, id="numeric-user"),
        pytest.param({"service_user": "a" * 33}, id="long-user"),
        pytest.param({"health_url": "https://bus.u64.lan/healthz?" + "x" * 512}, id="long-url"),
        pytest.param({"state_path": "/var/lib/../../etc/shadow"}, id="parent-traversal"),
        pytest.param({"python": ""}, id="empty-path"),
        pytest.param({"uv": None}, id="missing-path"),
        pytest.param({"ca_path": "/" + "c" * 4096}, id="long-path"),
    ],
)
def test_runtime_config_rejects_out_of_contract_values(changes):
    with pytest.raises(MaintenanceError) as caught:
        config_from_json(configuration(**changes))
    assert caught.value.code == "invalid_request"


@pytest.mark.parametrize("value", [None, [], "{}"])
def test_runtime_config_rejects_a_non_object(value):
    with pytest.raises(MaintenanceError, match="invalid_request"):
        config_from_json(value)


def test_runtime_config_accepts_the_bounds_of_each_number():
    low = config_from_json(configuration(
        application_uid=1, release_lock_wait_seconds=1, release_lock_lease_seconds=600,
    ))
    high = config_from_json(configuration(
        release_lock_wait_seconds=300, release_lock_lease_seconds=14400,
    ))
    assert (low.application_uid, low.release_lock_wait_seconds, low.release_lock_lease_seconds) == (
        1, 1, 600,
    )
    assert (high.release_lock_wait_seconds, high.release_lock_lease_seconds) == (300, 14400)


@pytest.fixture
def as_root_on_linux(monkeypatch):
    monkeypatch.setattr(runtime.sys, "platform", "linux")
    monkeypatch.setattr(runtime.os, "geteuid", lambda: 0, raising=False)


def test_load_config_reads_only_roots_private_file(as_root_on_linux, monkeypatch):
    reads = []

    def read(path, maximum, *, uid, mode):
        reads.append((path, maximum, uid, mode))
        return json.dumps(configuration()).encode("ascii")

    monkeypatch.setattr(runtime, "_read_regular", read)

    config = load_config(Path("/etc/strugglebus/maintenance.json"))

    assert config == config_from_json(configuration())
    assert reads == [(Path("/etc/strugglebus/maintenance.json"), 65536, 0, 0o600)]


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(b"\xff", id="not-ascii"),
        pytest.param(b"{", id="not-json"),
        pytest.param(b"[" * 100_000, id="unbounded-nesting"),
        pytest.param(b"{}", id="incomplete"),
    ],
)
def test_load_config_rejects_unparseable_content(as_root_on_linux, monkeypatch, raw):
    monkeypatch.setattr(runtime, "_read_regular", lambda path, maximum, **checks: raw)
    with pytest.raises(MaintenanceError) as caught:
        load_config(Path("/etc/strugglebus/maintenance.json"))
    assert caught.value.code == "invalid_request"


@pytest.mark.parametrize(("platform", "euid"), [("win32", 0), ("darwin", 0), ("linux", 998)])
def test_load_config_is_forbidden_unless_root_on_linux(monkeypatch, platform, euid):
    def unexpected(*args, **kwargs):
        raise AssertionError("the configuration must not be read")

    monkeypatch.setattr(runtime.sys, "platform", platform)
    monkeypatch.setattr(runtime.os, "geteuid", lambda: euid, raising=False)
    monkeypatch.setattr(runtime, "_read_regular", unexpected)
    with pytest.raises(MaintenanceError, match="forbidden"):
        load_config(Path("/etc/strugglebus/maintenance.json"))


# --- protected file reads ---------------------------------------------------


def test_read_regular_returns_bounded_content(tmp_path):
    path = tmp_path / "unit.service"
    path.write_bytes(b"[Service]\n")
    assert runtime._read_regular(path, 10) == b"[Service]\n"
    with pytest.raises(MaintenanceError, match="installation_failed"):
        runtime._read_regular(path, 9)


def test_read_regular_rejects_a_hard_linked_file(tmp_path):
    path = tmp_path / "unit.service"
    path.write_bytes(b"[Service]\n")
    os.link(path, tmp_path / "alias.service")
    with pytest.raises(MaintenanceError, match="installation_failed"):
        runtime._read_regular(path, 4096)


def test_read_regular_reports_a_missing_file_as_such(tmp_path):
    with pytest.raises(FileNotFoundError):
        runtime._read_regular(tmp_path / "missing", 4096)


def test_read_regular_rejects_a_file_that_grew_after_inspection(tmp_path, monkeypatch):
    path = tmp_path / "unit.service"
    path.write_bytes(b"x" * 64)
    real = os.fstat

    def stale(descriptor):
        info = real(descriptor)
        fields = {key: getattr(info, key) for key in dir(info) if key.startswith("st_")}
        return SimpleNamespace(**fields | {"st_size": 8})

    monkeypatch.setattr(runtime.os, "fstat", stale)
    with pytest.raises(MaintenanceError, match="installation_failed"):
        runtime._read_regular(path, 16)


def test_read_regular_rejects_a_path_replaced_after_opening(tmp_path, monkeypatch):
    path = tmp_path / "unit.service"
    path.write_bytes(b"[Service]\n")
    other = tmp_path / "other.service"
    other.write_bytes(b"[Service]\n")
    real = Path.lstat
    monkeypatch.setattr(Path, "lstat", lambda target: real(other if target == path else target))
    with pytest.raises(MaintenanceError, match="installation_failed"):
        runtime._read_regular(path, 4096)


def test_read_regular_rejects_a_path_removed_after_opening(tmp_path, monkeypatch):
    path = tmp_path / "unit.service"
    path.write_bytes(b"[Service]\n")

    def gone(target):
        raise FileNotFoundError(target)

    monkeypatch.setattr(Path, "lstat", gone)
    with pytest.raises(MaintenanceError, match="installation_failed"):
        runtime._read_regular(path, 4096)


@posix_only
def test_read_regular_enforces_the_expected_owner_and_mode(tmp_path):
    path = tmp_path / "maintenance.json"
    path.write_bytes(b"{}")
    path.chmod(0o600)
    owner = os.getuid()

    assert runtime._read_regular(path, 4096, uid=owner, mode=0o600) == b"{}"
    with pytest.raises(MaintenanceError, match="installation_failed"):
        runtime._read_regular(path, 4096, uid=owner + 1, mode=0o600)
    with pytest.raises(MaintenanceError, match="installation_failed"):
        runtime._read_regular(path, 4096, uid=owner, mode=0o644)
    path.chmod(0o644)
    assert runtime._read_regular(path, 4096, mode=0o644) == b"{}"


@posix_only
def test_read_regular_does_not_follow_a_symlink_or_read_a_directory(tmp_path):
    path = tmp_path / "unit.service"
    path.write_bytes(b"[Service]\n")
    link = tmp_path / "link.service"
    link.symlink_to(path)
    with pytest.raises(OSError):
        runtime._read_regular(link, 4096)
    with pytest.raises(MaintenanceError, match="installation_failed"):
        runtime._read_regular(tmp_path, 4096)


def test_sha256_hashes_a_file_larger_than_one_chunk(tmp_path):
    path = tmp_path / "helper"
    content = b"helper " * 200_000
    path.write_bytes(content)
    assert runtime._sha256(path) == hashlib.sha256(content).hexdigest()


def test_sha256_refuses_a_hard_linked_file(tmp_path):
    path = tmp_path / "helper"
    path.write_bytes(b"helper")
    os.link(path, tmp_path / "alias")
    with pytest.raises(MaintenanceError, match="installation_failed"):
        runtime._sha256(path)


@posix_only
def test_sha256_refuses_a_directory_or_symlink(tmp_path):
    path = tmp_path / "helper"
    path.write_bytes(b"helper")
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(MaintenanceError, match="installation_failed"):
        runtime._sha256(tmp_path)
    with pytest.raises(OSError):
        runtime._sha256(link)


# --- active application version ---------------------------------------------


@pytest.fixture
def current_release(monkeypatch, tmp_path):
    """A faked root-owned ``current`` link naming a release directory."""
    release_root = tmp_path / "releases"
    current = tmp_path / "current"
    state = SimpleNamespace(
        config=replace(
            config_from_json(configuration()), release_root=release_root, current_link=current,
        ),
        target=str(release_root / "0.2.29"),
        links=[],
        link=SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_nlink=1, st_dev=1, st_ino=2),
        directory=SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0),
        resolved={},
    )

    def lstat(path):
        if path != current:
            return state.directory
        return state.links.pop(0) if state.links else state.link

    monkeypatch.setattr(runtime.os, "readlink", lambda path: state.target)
    monkeypatch.setattr(
        Path, "resolve", lambda path, *, strict=False: state.resolved.get(path, path),
    )
    monkeypatch.setattr(Path, "lstat", lstat)
    return state


def test_active_version_is_the_name_of_the_linked_release(current_release):
    assert active_application_version(current_release.config) == "0.2.29"


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param({"st_mode": stat.S_IFDIR | 0o755}, id="directory-not-link"),
        pytest.param({"st_nlink": 2}, id="aliased-link"),
    ],
)
def test_active_version_rejects_an_unprotected_link(current_release, changes):
    for name, value in changes.items():
        setattr(current_release.link, name, value)
    with pytest.raises(MaintenanceError, match="installation_failed"):
        active_application_version(current_release.config)


def test_active_version_rejects_a_link_swapped_while_it_was_read(current_release):
    swapped = SimpleNamespace(**vars(current_release.link) | {"st_ino": 3})
    current_release.links = [current_release.link, swapped]
    with pytest.raises(MaintenanceError, match="installation_failed"):
        active_application_version(current_release.config)


def test_active_version_rejects_a_release_outside_the_release_root(current_release, tmp_path):
    current_release.target = str(tmp_path / "elsewhere" / "0.2.29")
    with pytest.raises(MaintenanceError, match="installation_failed"):
        active_application_version(current_release.config)


def test_active_version_rejects_a_symlinked_release_root(current_release, tmp_path):
    root = current_release.config.release_root
    current_release.resolved[root] = tmp_path / "moved"
    current_release.target = str(tmp_path / "moved" / "0.2.29")
    with pytest.raises(MaintenanceError, match="installation_failed"):
        active_application_version(current_release.config)


def test_active_version_rejects_a_release_that_is_itself_a_link(current_release):
    root = current_release.config.release_root
    current_release.resolved[root / "0.2.29"] = root / "0.2.28"
    with pytest.raises(MaintenanceError, match="installation_failed"):
        active_application_version(current_release.config)


@pytest.mark.parametrize(
    "directory",
    [
        pytest.param(SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0), id="not-a-directory"),
        pytest.param(SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=998), id="not-roots"),
        pytest.param(SimpleNamespace(st_mode=stat.S_IFDIR | 0o757, st_uid=0), id="world-writable"),
    ],
)
def test_active_version_rejects_an_unprotected_directory_chain(current_release, directory):
    current_release.directory = directory
    with pytest.raises(MaintenanceError, match="installation_failed"):
        active_application_version(current_release.config)


def test_active_version_rejects_a_release_not_named_by_a_version(current_release):
    current_release.target = str(current_release.config.release_root / "latest")
    with pytest.raises(MaintenanceError, match="installation_failed"):
        active_application_version(current_release.config)


def test_active_version_fails_closed_when_the_link_is_missing(tmp_path):
    config = replace(
        config_from_json(configuration()),
        release_root=tmp_path / "releases",
        current_link=tmp_path / "current",
    )
    with pytest.raises(MaintenanceError, match="installation_failed"):
        active_application_version(config)


# --- child processes --------------------------------------------------------


def _child(monkeypatch, outcome):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(runtime.subprocess, "run", run)
    return calls


def test_run_gives_the_child_a_hermetic_environment_and_discards_stderr(monkeypatch):
    calls = _child(monkeypatch, SimpleNamespace(returncode=0, stdout=b"out"))

    assert runtime._run(["/usr/bin/example", "arg"], input_bytes=b"in", timeout=7) == b"out"

    argv, kwargs = calls[0]
    assert argv == ["/usr/bin/example", "arg"]
    assert (kwargs["input"], kwargs["timeout"], kwargs["check"]) == (b"in", 7, False)
    assert kwargs["stdout"] == subprocess.PIPE
    assert kwargs["stderr"] == subprocess.DEVNULL
    assert kwargs["env"]["PATH"] == "/usr/local/bin:/usr/bin:/bin"
    assert kwargs["env"]["NO_PROXY"] == "*"
    assert kwargs["env"]["UV_PYTHON_DOWNLOADS"] == "never"
    assert not set(kwargs["env"]) & {"HOME", "PYTHONPATH", "LD_PRELOAD"}


def test_run_captures_stderr_only_to_classify_a_notice_failure(monkeypatch):
    calls = _child(monkeypatch, SimpleNamespace(returncode=0, stdout=b""))
    runtime._run(["/usr/bin/example"], report_failure=True)
    assert calls[0][1]["stderr"] == subprocess.PIPE


@pytest.mark.parametrize(
    "result",
    [
        pytest.param(SimpleNamespace(returncode=3, stdout=b"detail"), id="failed"),
        pytest.param(SimpleNamespace(returncode=0, stdout=b"x" * 65537), id="oversized-output"),
    ],
)
def test_run_fails_quietly_when_not_asked_to_report(monkeypatch, capsys, result):
    _child(monkeypatch, result)
    with pytest.raises(MaintenanceError, match="installation_failed"):
        runtime._run(["/usr/bin/example"])
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == ("", "")


@pytest.mark.parametrize(
    ("error", "report"),
    [
        (FileNotFoundError("/usr/bin/example"), "EXECUTION_ERROR"),
        (subprocess.TimeoutExpired("/usr/bin/example", 5), "TIMEOUT"),
        (subprocess.SubprocessError("secret"), "EXECUTION_ERROR"),
    ],
)
def test_run_reports_a_child_that_could_not_complete(monkeypatch, capsys, error, report):
    _child(monkeypatch, error)

    with pytest.raises(MaintenanceError, match="installation_failed"):
        runtime._run(["/usr/bin/example"])
    assert capsys.readouterr().err == ""

    with pytest.raises(MaintenanceError, match="installation_failed"):
        runtime._run(["/usr/bin/example"], report_failure=True)
    assert capsys.readouterr().err == f"maintenance_notice_failure={report}\n"


@pytest.mark.parametrize(
    ("stdout", "report"),
    [
        (b'{"cause":"NON_SQLITE_ERROR"}', "NON_SQLITE_ERROR"),
        (b'{"cause":"SQLITE_BUSY; rm -rf /"}', "INVALID_RESPONSE:rc=1"),
        (b'{"cause":7}', "INVALID_RESPONSE:rc=1"),
        (b'["cause"]', "INVALID_RESPONSE:rc=1"),
        (b"\xff\xfe", "INVALID_RESPONSE:rc=1"),
        (b"not json", "INVALID_RESPONSE:rc=1"),
    ],
)
def test_run_reports_only_a_recognised_cause_from_the_child(monkeypatch, capsys, stdout, report):
    _child(monkeypatch, SimpleNamespace(returncode=1, stdout=stdout, stderr=None))
    with pytest.raises(MaintenanceError, match="installation_failed"):
        runtime._run(["/usr/bin/example"], report_failure=True)
    assert capsys.readouterr().err == f"maintenance_notice_failure={report}\n"


def test_child_failure_detail_reads_only_the_tail_of_stderr():
    noise = b"ValueError: early\n" + b"x" * 5000 + b"\n"
    assert runtime._child_failure_detail(1, noise) == ":rc=1"
    assert runtime._child_failure_detail(1, noise + b"sqlite3.OperationalError: locked\n") == (
        ":exception=sqlite3.OperationalError"
    )
    assert runtime._child_failure_detail(1, b"KeyboardInterrupt\n") == ":exception=KeyboardInterrupt"


def test_command_as_root_is_unchanged():
    argv = ["/usr/bin/example"]
    assert runtime._command_as(argv, None) is argv


# --- updater polling --------------------------------------------------------


def _operation(**changes):
    values = {"operation_id": "c" * 32, "action": "check", "phase": "succeeded", "error": None}
    values.update(changes)
    return SimpleNamespace(operation=SimpleNamespace(**values))


class _Polled:
    def __init__(self, *statuses):
        self.statuses = list(statuses)
        self.asked = []

    async def status(self, operation_id):
        self.asked.append(operation_id)
        return self.statuses.pop(0)


@pytest.fixture
def no_sleep(monkeypatch):
    delays = []

    async def sleep(delay):
        delays.append(delay)

    monkeypatch.setattr(runtime.asyncio, "sleep", sleep)
    return delays


async def test_completed_update_polls_until_the_operation_succeeds(no_sleep):
    done = _operation()
    client = _Polled(
        SimpleNamespace(operation=None),
        _operation(operation_id="d" * 32),
        _operation(phase="running"),
        done,
    )

    result = await runtime._completed_update(
        client, SimpleNamespace(operation=None), "c" * 32, "check", 120,
    )

    assert result is done
    assert client.asked == ["c" * 32] * 4
    assert all(0 < delay <= 1 for delay in no_sleep)


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (_operation(action="prepare"), "invalid_response"),
        (_operation(phase="failed", error="verification_failed"), "verification_failed"),
        (_operation(phase="interrupted"), "unknown_outcome"),
        (_operation(phase="failed", error="not a public code"), "internal_error"),
    ],
)
async def test_completed_update_raises_once_the_operation_settles_badly(no_sleep, status, code):
    with pytest.raises(UpdateError) as caught:
        await runtime._completed_update(_Polled(), status, "c" * 32, "check", 120)
    assert caught.value.code == code
    assert no_sleep == []


async def test_completed_update_times_out_on_an_operation_that_never_settles(
    no_sleep, monkeypatch,
):
    clock = iter((0.0, 1.0, 121.0))
    # Only the module's own clock is replaced; the event loop keeps real time.
    monkeypatch.setattr(runtime, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    client = _Polled(_operation(phase="running"))

    with pytest.raises(UpdateError) as caught:
        await runtime._completed_update(client, _operation(phase="running"), "c" * 32, "check", 120)

    assert caught.value.code == "timeout"
    assert client.asked == ["c" * 32]
    assert no_sleep == [1]


# --- release gateway --------------------------------------------------------


def test_gateway_maps_any_updater_failure_to_updater_unavailable(monkeypatch):
    gateway = PreparedReleaseGateway(config_from_json(configuration()))
    release = PreparedRelease("0.2.50", Path("/prepared"))
    actors = []

    async def prepared(actor_id):
        actors.append(actor_id)
        return release

    async def failed(actor_id):
        raise UpdateError("authentication_failed")

    monkeypatch.setattr(gateway, "_prepare", prepared)
    assert gateway.prepare_latest(actor_id="operator:test") is release
    assert actors == ["operator:test"]

    monkeypatch.setattr(gateway, "_prepare", failed)
    with pytest.raises(MaintenanceError) as caught:
        gateway.prepare_latest(actor_id="operator:test")
    assert caught.value.code == "updater_unavailable"


@pytest.mark.parametrize("defect", ["nothing-prepared", "other-operation", "other-candidate"])
async def test_gateway_rejects_a_preparation_that_does_not_match_its_request(
    monkeypatch, tmp_path, defect,
):
    candidate = SimpleNamespace(version="0.2.50", digest="a" * 64)
    observation = SimpleNamespace(
        observation_id="d" * 32,
        application_version="0.2.49",
        application_release_id="release-7",
        discovery=SimpleNamespace(candidate=candidate),
        checked_at=0,
        expires_at=0,
    )
    release_ids = []

    class Client:
        def __init__(self, socket_path, *, allow_root_peer):
            pass

        async def status(self):
            return SimpleNamespace(observation=None, prepared=None)

        async def check(self, operation_id, actor_id, version, release_id):
            release_ids.append(release_id)
            return SimpleNamespace(
                operation=SimpleNamespace(
                    operation_id=operation_id, action="check", phase="succeeded", error=None,
                ),
                observation=observation,
                prepared=None,
            )

        async def prepare(self, operation_id, *arguments):
            prepared = {
                "nothing-prepared": None,
                "other-operation": SimpleNamespace(operation_id="e" * 32, candidate=candidate),
                "other-candidate": SimpleNamespace(
                    operation_id=operation_id,
                    candidate=SimpleNamespace(version="0.2.51", digest="f" * 64),
                ),
            }[defect]
            return SimpleNamespace(
                operation=SimpleNamespace(
                    operation_id=operation_id, action="prepare", phase="succeeded", error=None,
                ),
                prepared=prepared,
            )

    monkeypatch.setenv("STRUGGLEBUS_RELEASE_ID", "release-7")
    monkeypatch.setattr(runtime, "UpdateClient", Client)
    monkeypatch.setattr(runtime, "active_application_version", lambda config: "0.2.49")
    gateway = PreparedReleaseGateway(
        replace(config_from_json(configuration()), updater_cache_state=tmp_path),
    )

    with pytest.raises(MaintenanceError) as caught:
        await gateway._prepare("operator:test")

    assert caught.value.code == "preparation_failed"
    assert release_ids == ["release-7"]


# --- board announcer --------------------------------------------------------


def _announce(announcer, *, automatic):
    announcer.announce(
        PreparedRelease("0.2.50", Path("/prepared")),
        operation_id="a" * 32,
        scheduled_at=1_800_000_000,
        automatic=automatic,
    )


@pytest.mark.parametrize("automatic", [True, False])
def test_announcer_passes_the_notice_to_the_running_release(monkeypatch, automatic):
    calls = []
    monkeypatch.setattr(runtime, "_run", lambda argv, **kwargs: calls.append((argv, kwargs)) or b"")
    config = config_from_json(configuration())

    _announce(BoardAnnouncer(config), automatic=automatic)

    argv, kwargs = calls[0]
    assert argv[4:14] == [
        "--database", str(config.database),
        "--backup-dir", str(config.backup_dir),
        "--operation-id", "a" * 32,
        "--version", "0.2.50",
        "--scheduled-at", "1800000000",
    ]
    assert argv[14:] == (["--automatic"] if automatic else [])
    assert kwargs["user"] == "strugglebus"
    assert 1 <= kwargs["timeout"] <= 30


def test_announcer_does_not_retry_a_failure_that_is_not_the_notice_child(monkeypatch):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        raise MaintenanceError("forbidden")

    monkeypatch.setattr(runtime, "_run", run)
    monkeypatch.setattr(runtime.time, "sleep", lambda seconds: calls.append("sleep"))

    with pytest.raises(MaintenanceError, match="forbidden"):
        _announce(BoardAnnouncer(config_from_json(configuration())), automatic=False)
    assert len(calls) == 1
