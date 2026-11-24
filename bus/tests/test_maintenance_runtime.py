from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import json
import sqlite3
import stat
import sys

import time

import pytest

import strugglebus.maintenance_runtime as runtime_module
from strugglebus.maintenance_runtime import (
    ANNOUNCEMENT_SCRIPT,
    BoardAnnouncer,
    HELPERS,
    HostReleaseInstaller,
    PreparedReleaseGateway,
    active_application_version,
    config_from_json,
)
from strugglebus.maintenance_supervisor import PreparedRelease
from strugglebus.maintenance_types import MaintenanceError


def configuration(**changes):
    value = {
        "version": 1,
        "application_uid": 998,
        "service_user": "strugglebus",
        "updater_socket": "/run/strugglebus-updater/worker.sock",
        "updater_cache_state": "/var/lib/strugglebus-updater-cache/state",
        "state_path": "/var/lib/strugglebus-maintenance/supervisor.json",
        "database": "/var/lib/strugglebus/strugglebus.db",
        "backup_dir": "/var/backups/strugglebus",
        "release_root": "/opt/strugglebus/releases",
        "current_link": "/opt/strugglebus/current",
        "updater_release_root": "/opt/strugglebus-updater/releases",
        "updater_current_link": "/opt/strugglebus-updater/current",
        "service_unit": "/etc/systemd/system/strugglebus.service",
        "maintenance_root": "/var/lib/strugglebus-maintenance/runtime",
        "health_url": "https://bus.u64.lan/healthz",
        "ca_path": "/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt",
        "python": "/usr/bin/python3.13",
        "uv": "/usr/local/bin/uv",
        "systemctl": "/usr/bin/systemctl",
        "runuser": "/usr/sbin/runuser",
        "release_lock_wait_seconds": 30,
        "release_lock_lease_seconds": 3600,
    }
    value.update(changes)
    return value


def test_runtime_config_parses_complete_protected_contract():
    value = config_from_json(configuration())
    assert value.application_uid == 998
    assert value.state_path == Path("/var/lib/strugglebus-maintenance/supervisor.json")
    assert value.health_url == "https://bus.u64.lan/healthz"
    assert value.systemctl == Path("/usr/bin/systemctl")


@pytest.mark.parametrize(
    ("changes",),
    [
        ({"unexpected": "value"},),
        ({"health_url": "http://bus.u64.lan/healthz"},),
        ({"health_url": "https://bus.u64.lan/status"},),
        ({"application_uid": 0},),
        ({"release_lock_wait_seconds": 0},),
        ({"release_lock_lease_seconds": 599},),
        ({"database": "relative.db"},),
    ],
)
def test_runtime_config_rejects_incomplete_or_unsafe_values(changes):
    with pytest.raises(MaintenanceError, match="invalid_request"):
        config_from_json(configuration(**changes))


def test_runtime_helper_bundle_matches_maintenance_lifecycle():
    assert set(HELPERS.values()) == {
        "strugglebus-inspect-access-freeze",
        "strugglebus-maintenance",
        "strugglebus-release-lock",
        "strugglebus-sqlite-backup",
        "strugglebus-validate-maintenance-config",
    }


def test_self_update_helpers_use_the_operator_guard_bundle_identity():
    from strugglebus import operator_local

    assert runtime_module.HELPER_ROOT == operator_local.MAINTENANCE_HELPER_ROOT
    assert tuple(runtime_module.BUNDLE_HELPERS) == tuple(operator_local.MAINTENANCE_HELPERS)
    assert runtime_module.HostReleaseInstaller.helper_root == runtime_module.HELPER_ROOT


def test_renamed_environment_scripts_target_the_final_release(tmp_path):
    staging = tmp_path / ".0.2.45.maintenance-abc" / "venv"
    target = tmp_path / "0.2.45" / "venv"
    (staging / "bin").mkdir(parents=True)
    old = f"#!{staging}/bin/python\n".encode()
    (staging / "bin/strugglebus").write_bytes(old + b"import sys\n")
    (staging / "bin/activate").write_bytes(f"VIRTUAL_ENV='{staging}'\n".encode())
    (staging / "pyvenv.cfg").write_bytes(f"command = python -m venv {staging}\n".encode())
    large = b"\0" * (1024 * 1024) + str(staging).encode()
    (staging / "bin/python").write_bytes(large)

    runtime_module._retarget_scripts(staging, target)

    assert (staging / "bin/strugglebus").read_bytes() == (
        f"#!{target}/bin/python\nimport sys\n".encode()
    )
    assert str(staging).encode() not in (staging / "bin/activate").read_bytes()
    assert str(staging).encode() not in (staging / "pyvenv.cfg").read_bytes()
    assert (staging / "bin/python").read_bytes() == large


def test_run_uses_non_pam_setpriv_child_identity(monkeypatch):
    captured = {}

    def run(argv, **kwargs):
        captured.update(argv=argv, kwargs=kwargs)
        return SimpleNamespace(returncode=0, stdout=b"ok")

    account = SimpleNamespace(pw_uid=998, pw_gid=999)
    monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace(getpwnam=lambda user: account))
    monkeypatch.setattr(runtime_module.subprocess, "run", run)

    assert runtime_module._run(["/usr/bin/example"], user="strugglebus") == b"ok"
    assert captured["argv"] == [
        "/usr/bin/setpriv",
        "--reuid=998",
        "--regid=999",
        "--clear-groups",
        "--",
        "/usr/bin/example",
    ]
    assert "user" not in captured["kwargs"]


def test_announcement_shim_classifies_legacy_publish_failure(monkeypatch, capsys):
    import strugglebus.maintenance_notice as notice

    def fail(**kwargs):
        raise sqlite3.OperationalError("sensitive detail")

    monkeypatch.setattr(notice, "publish_notice", fail)
    monkeypatch.setattr(sys, "argv", [
        "notice",
        "--database", "/var/lib/strugglebus/strugglebus.db",
        "--backup-dir", "/var/backups/strugglebus",
        "--operation-id", "a" * 32,
        "--version", "0.2.45",
        "--scheduled-at", "1",
    ])

    with pytest.raises(SystemExit, match="1"):
        exec(ANNOUNCEMENT_SCRIPT, {})

    assert json.loads(capsys.readouterr().out) == {
        "cause": "SQLITE_ERROR",
        "error": "maintenance_notice_failed",
        "ok": False,
    }


def test_run_reports_only_bounded_maintenance_failure_code(monkeypatch, capsys):
    result = SimpleNamespace(
        returncode=1,
        stdout=b'{"cause":"SQLITE_BUSY","error":"maintenance_notice_failed","ok":false}',
    )
    monkeypatch.setattr(runtime_module.subprocess, "run", lambda argv, **kwargs: result)

    with pytest.raises(MaintenanceError, match="installation_failed"):
        runtime_module._run(["/usr/bin/example"], report_failure=True)

    assert capsys.readouterr().err == "maintenance_notice_failure=SQLITE_BUSY\n"


def test_run_reports_child_exception_type_without_message(monkeypatch, capsys):
    result = SimpleNamespace(
        returncode=1,
        stdout=b"",
        stderr=b'Traceback (most recent call last):\n  File "<string>", line 1\nPermissionError: [Errno 13] secret/path\n',
    )
    monkeypatch.setattr(runtime_module.subprocess, "run", lambda argv, **kwargs: result)

    with pytest.raises(MaintenanceError, match="installation_failed"):
        runtime_module._run(["/usr/bin/example"], report_failure=True)

    assert capsys.readouterr().err == (
        "maintenance_notice_failure=INVALID_RESPONSE:exception=PermissionError\n"
    )


@pytest.mark.parametrize(
    ("returncode", "stderr", "detail"),
    [(-9, b"", ":signal=9"), (2, b"usage: notice\nunreadable text\n", ":rc=2")],
)
def test_run_reports_signal_or_exit_code_for_unclassified_child(
    monkeypatch, capsys, returncode, stderr, detail,
):
    result = SimpleNamespace(returncode=returncode, stdout=b"", stderr=stderr)
    monkeypatch.setattr(runtime_module.subprocess, "run", lambda argv, **kwargs: result)

    with pytest.raises(MaintenanceError, match="installation_failed"):
        runtime_module._run(["/usr/bin/example"], report_failure=True)

    assert capsys.readouterr().err == f"maintenance_notice_failure=INVALID_RESPONSE{detail}\n"


def test_board_announcer_retries_bounded_application_notice_failure(monkeypatch):
    calls = []

    def run(argv, *, timeout, user, report_failure):
        calls.append((argv, timeout, user, report_failure))
        if len(calls) == 1:
            raise MaintenanceError("installation_failed")
        return b""

    monkeypatch.setattr(runtime_module, "_run", run)
    monkeypatch.setattr(runtime_module.time, "sleep", lambda seconds: None)
    announcer = BoardAnnouncer(config_from_json(configuration()))

    announcer.announce(
        PreparedRelease("0.2.37", Path("/prepared")),
        operation_id="a" * 32,
        scheduled_at=1,
        automatic=False,
    )

    assert len(calls) == 2
    assert Path(calls[0][0][0]) == Path("/opt/strugglebus/current/venv/bin/python")
    assert calls[0][0][1:3] == ["-I", "-c"]
    assert calls[0][0][3] == ANNOUNCEMENT_SCRIPT
    assert "busy_timeout_ms=30_000" in ANNOUNCEMENT_SCRIPT
    assert "notice.publish_notice" in ANNOUNCEMENT_SCRIPT
    assert "sqlite_errorname" in ANNOUNCEMENT_SCRIPT
    assert calls[0][1] <= 30
    assert calls[0][2] == "strugglebus"
    assert calls[0][3] is True


def test_board_announcer_fails_closed_after_bounded_deadline(monkeypatch):
    calls = []
    times = iter((0.0, 0.0, 31.0))

    def run(argv, *, timeout, user, report_failure):
        calls.append((timeout, report_failure))
        raise MaintenanceError("installation_failed")

    monkeypatch.setattr(runtime_module, "_run", run)
    monkeypatch.setattr(runtime_module.time, "monotonic", lambda: next(times))
    announcer = BoardAnnouncer(config_from_json(configuration()))

    with pytest.raises(MaintenanceError, match="installation_failed"):
        announcer.announce(
            PreparedRelease("0.2.37", Path("/prepared")),
            operation_id="a" * 32,
            scheduled_at=1,
            automatic=False,
        )
    assert len(calls) == 1


def test_active_application_version_uses_protected_application_link(monkeypatch, tmp_path):
    release_root = tmp_path / "releases"
    current = tmp_path / "current"
    target = release_root / "0.2.29"
    config = replace(
        config_from_json(configuration()),
        release_root=release_root,
        current_link=current,
    )
    link = SimpleNamespace(
        st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_nlink=1, st_dev=1, st_ino=2,
    )
    directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
    monkeypatch.setattr(runtime_module.os, "readlink", lambda path: str(target))
    monkeypatch.setattr(
        Path,
        "resolve",
        lambda path, *, strict=False: path,
    )
    monkeypatch.setattr(Path, "lstat", lambda path: link if path == current else directory)

    assert active_application_version(config) == "0.2.29"

    link.st_uid = 1
    with pytest.raises(MaintenanceError, match="installation_failed"):
        active_application_version(config)
    link.st_uid = 0

    monkeypatch.setattr(runtime_module.os, "readlink", lambda path: "0.2.29")
    with pytest.raises(MaintenanceError, match="installation_failed"):
        active_application_version(config)

    monkeypatch.setattr(runtime_module.os, "readlink", lambda path: str(target))
    directory.st_mode |= 0o020
    with pytest.raises(MaintenanceError, match="installation_failed"):
        active_application_version(config)


@pytest.mark.asyncio
async def test_release_gateway_checks_the_active_application_version(monkeypatch):
    calls = []

    class Client:
        def __init__(self, socket, *, allow_root_peer):
            assert allow_root_peer is True

        async def status(self):
            return SimpleNamespace(observation=None, prepared=None)

        async def check(self, *args):
            calls.append(args)
            return SimpleNamespace(
                operation=SimpleNamespace(
                    operation_id=args[0], action="check", phase="succeeded", error=None,
                ),
                observation=None,
            )

    monkeypatch.setattr(runtime_module, "UpdateClient", Client)
    monkeypatch.setattr(runtime_module, "active_application_version", lambda config: "0.2.29")
    gateway = PreparedReleaseGateway(config_from_json(configuration()))

    assert await gateway._prepare("operator:test") is None
    assert calls[0][2] == "0.2.29"


@pytest.mark.asyncio
async def test_release_gateway_reuses_exact_prepared_candidate(monkeypatch, tmp_path):
    candidate = SimpleNamespace(version="0.2.36", digest="a" * 64)
    now = int(time.time())
    observation = SimpleNamespace(
        application_version="0.2.29",
        application_release_id=None,
        discovery=SimpleNamespace(candidate=candidate),
        checked_at=now - 10,
        expires_at=now + 600,
    )
    prepared = SimpleNamespace(operation_id="b" * 32, candidate=candidate)

    class Client:
        def __init__(self, socket, *, allow_root_peer):
            assert allow_root_peer is True

        async def status(self):
            return SimpleNamespace(observation=observation, prepared=prepared)

        async def check(self, *args):
            raise AssertionError("an exact prepared candidate must not be rediscovered")

    monkeypatch.setattr(runtime_module, "UpdateClient", Client)
    monkeypatch.setattr(runtime_module, "active_application_version", lambda config: "0.2.29")
    directory = tmp_path / ("operation-" + "b" * 32)
    directory.mkdir()
    config = replace(
        config_from_json(configuration()),
        updater_cache_state=tmp_path,
    )
    gateway = PreparedReleaseGateway(config)

    release = await gateway._prepare("operator:test")

    assert release is not None
    assert release.version == "0.2.36"
    assert release.directory == directory


@pytest.mark.parametrize("mismatch", ["application", "candidate", "directory", "expired"])
@pytest.mark.asyncio
async def test_release_gateway_does_not_reuse_mismatched_prepared_candidate(
    monkeypatch,
    tmp_path,
    mismatch,
):
    candidate = SimpleNamespace(version="0.2.36", digest="a" * 64)
    observed_candidate = (
        SimpleNamespace(version="0.2.36", digest="c" * 64)
        if mismatch == "candidate"
        else candidate
    )
    now = int(time.time())
    observation = SimpleNamespace(
        application_version="0.2.28" if mismatch == "application" else "0.2.29",
        application_release_id=None,
        discovery=SimpleNamespace(candidate=observed_candidate),
        checked_at=now - 86400 if mismatch == "expired" else now - 10,
        expires_at=now - 85500 if mismatch == "expired" else now + 600,
    )
    prepared = SimpleNamespace(operation_id="b" * 32, candidate=candidate)
    calls = []

    class Client:
        def __init__(self, socket, *, allow_root_peer):
            pass

        async def status(self, operation_id=None):
            assert operation_id is None
            return SimpleNamespace(observation=observation, prepared=prepared)

        async def check(self, operation_id, *args):
            calls.append("check")
            return SimpleNamespace(
                operation=SimpleNamespace(
                    operation_id=operation_id,
                    action="check",
                    phase="succeeded",
                    error_code=None,
                ),
                observation=None,
            )

    monkeypatch.setattr(runtime_module, "UpdateClient", Client)
    monkeypatch.setattr(runtime_module, "active_application_version", lambda config: "0.2.29")
    config = replace(
        config_from_json(configuration()),
        updater_cache_state=tmp_path,
    )
    if mismatch != "directory":
        (tmp_path / ("operation-" + "b" * 32)).mkdir()
    gateway = PreparedReleaseGateway(config)

    assert await gateway._prepare("operator:test") is None
    assert calls == ["check"]


@pytest.mark.parametrize("newer", [False, True])
@pytest.mark.asyncio
async def test_release_gateway_rechecks_an_expired_observation_before_reuse(
    monkeypatch,
    tmp_path,
    newer,
):
    prepared_candidate = SimpleNamespace(version="0.2.36", digest="a" * 64)
    latest = SimpleNamespace(version="0.2.37", digest="c" * 64) if newer else prepared_candidate
    now = int(time.time())

    def observed(candidate, checked_at):
        return SimpleNamespace(
            observation_id="d" * 32,
            application_version="0.2.29",
            application_release_id=None,
            discovery=SimpleNamespace(candidate=candidate),
            checked_at=checked_at,
            expires_at=checked_at + 900,
        )

    prepared = SimpleNamespace(operation_id="b" * 32, candidate=prepared_candidate)
    stale = observed(prepared_candidate, now - 86400)
    fresh = observed(latest, now - 1)
    calls = []

    class Client:
        def __init__(self, socket, *, allow_root_peer):
            self.prepare_id = None

        async def status(self, operation_id=None):
            if operation_id is None:
                return SimpleNamespace(observation=stale, prepared=prepared)
            return SimpleNamespace(
                operation=SimpleNamespace(
                    operation_id=operation_id, action="prepare", phase="succeeded", error=None,
                ),
                prepared=SimpleNamespace(operation_id=operation_id, candidate=latest),
            )

        async def check(self, operation_id, *args):
            calls.append("check")
            return SimpleNamespace(
                operation=SimpleNamespace(
                    operation_id=operation_id, action="check", phase="succeeded", error=None,
                ),
                observation=fresh,
                prepared=prepared,
            )

        async def prepare(self, operation_id, *args):
            calls.append("prepare")
            return SimpleNamespace(
                operation=SimpleNamespace(
                    operation_id=operation_id, action="prepare", phase="succeeded", error=None,
                ),
                prepared=SimpleNamespace(operation_id=operation_id, candidate=latest),
            )

    monkeypatch.setattr(runtime_module, "UpdateClient", Client)
    monkeypatch.setattr(runtime_module, "active_application_version", lambda config: "0.2.29")
    (tmp_path / ("operation-" + "b" * 32)).mkdir()
    config = replace(config_from_json(configuration()), updater_cache_state=tmp_path)

    release = await PreparedReleaseGateway(config)._prepare("operator:test")

    assert release is not None
    assert release.version == latest.version
    if newer:
        assert calls == ["check", "prepare"]
        assert release.directory.name != "operation-" + "b" * 32
    else:
        assert calls == ["check"]
        assert release.directory == tmp_path / ("operation-" + "b" * 32)


@pytest.mark.asyncio
async def test_release_gateway_waits_for_check_and_prepare_completion(monkeypatch):
    calls = []
    candidate = SimpleNamespace(version="0.2.35", digest="a" * 64)
    observation = SimpleNamespace(
        observation_id="b" * 32,
        discovery=SimpleNamespace(candidate=candidate),
    )

    class Client:
        def __init__(self, socket, *, allow_root_peer):
            assert allow_root_peer is True
            self.check_id = None
            self.prepare_id = None

        async def check(self, *args):
            calls.append(("check", args))
            self.check_id = args[0]
            return SimpleNamespace(
                operation=SimpleNamespace(
                    operation_id=self.check_id, action="check", phase="accepted", error=None,
                ),
                observation=None,
            )

        async def prepare(self, *args):
            calls.append(("prepare", args))
            self.prepare_id = args[0]
            return SimpleNamespace(
                operation=SimpleNamespace(
                    operation_id=self.prepare_id, action="prepare", phase="accepted", error=None,
                ),
                prepared=None,
            )

        async def status(self, operation_id=None):
            calls.append(("status", operation_id))
            if operation_id is None:
                return SimpleNamespace(observation=None, prepared=None)
            if operation_id == self.check_id:
                return SimpleNamespace(
                    operation=SimpleNamespace(
                        operation_id=operation_id, action="check", phase="succeeded", error=None,
                    ),
                    observation=observation,
                    prepared=None,
                )
            return SimpleNamespace(
                operation=SimpleNamespace(
                    operation_id=operation_id, action="prepare", phase="succeeded", error=None,
                ),
                prepared=SimpleNamespace(operation_id=operation_id, candidate=candidate),
            )

    async def no_sleep(_delay):
        return None

    monkeypatch.setattr(runtime_module, "UpdateClient", Client)
    monkeypatch.setattr(runtime_module.asyncio, "sleep", no_sleep)
    monkeypatch.setattr(runtime_module, "active_application_version", lambda config: "0.2.29")
    gateway = PreparedReleaseGateway(config_from_json(configuration()))

    release = await gateway._prepare("operator:test")

    assert release is not None
    assert release.version == "0.2.35"
    assert release.directory.name.startswith("operation-")
    assert [call[0] for call in calls] == ["status", "check", "status", "prepare", "status"]
    assert calls[3][1][2] == "0.2.29"
    assert calls[3][1][4] == observation.observation_id
    assert calls[3][1][5] == candidate.digest

def _installed_target(tmp_path, marker: bytes):
    target = tmp_path / "0.2.48"
    target.mkdir()
    (target / ".installed").write_bytes(marker)
    return target


INSTALL_FACTS = {
    "wheel_src": "/prepared/strugglebus-0.2.48-py3-none-any.whl",
    "wheel_sha256": "a" * 64,
    "requirements_lock_sha256": "b" * 64,
}


def _bootstrap_marker(**changes) -> bytes:
    identity = {
        "version": 1, "package_version": "0.2.48", "source_commit": "c" * 40,
        "source_tree": "d" * 40, "manifest_sha256": "e" * 64,
        "wheel_sha256": "a" * 64, "requirements_lock_sha256": "b" * 64,
    }
    identity.update(changes)
    return json.dumps(identity).encode()


@pytest.mark.parametrize("marker", [
    pytest.param(
        b"wheel_filename=strugglebus-0.2.48-py3-none-any.whl\n"
        b"wheel_sha256=" + b"a" * 64 + b"\n"
        b"requirements_lock_sha256=" + b"b" * 64 + b"\n"
        b"agent_access_freeze=global-v1\n",
        id="self-update",
    ),
    pytest.param(_bootstrap_marker(), id="ansible-bootstrap"),
])
def test_existing_release_with_the_same_bytes_is_reused(tmp_path, marker):
    _installed_target(tmp_path, marker)
    installer = HostReleaseInstaller(config_from_json(configuration()))

    installer._materialize_environment(
        PreparedRelease("0.2.48", Path("/prepared")), INSTALL_FACTS, "f" * 32,
        tmp_path, group=None, private=False,
    )


@pytest.mark.parametrize("marker", [
    pytest.param(_bootstrap_marker(wheel_sha256="9" * 64), id="other-wheel"),
    pytest.param(_bootstrap_marker(requirements_lock_sha256="9" * 64), id="other-lock"),
    pytest.param(_bootstrap_marker(package_version="0.2.47"), id="other-version"),
    pytest.param(_bootstrap_marker(version=2), id="unknown-format"),
    pytest.param(_bootstrap_marker(extra="x"), id="extra-key"),
    pytest.param(b"[]", id="not-an-object"),
    pytest.param(b"\xff", id="not-ascii"),
])
def test_existing_release_with_different_provenance_fails_closed(tmp_path, marker):
    _installed_target(tmp_path, marker)
    installer = HostReleaseInstaller(config_from_json(configuration()))

    with pytest.raises(MaintenanceError, match="installation_failed"):
        installer._materialize_environment(
            PreparedRelease("0.2.48", Path("/prepared")), INSTALL_FACTS, "f" * 32,
            tmp_path, group=None, private=False,
        )


def test_installer_bundle_validation_allows_one_reviewed_forward_migration(monkeypatch):
    calls = []

    def validate(directory, **kwargs):
        calls.append(kwargs)
        return {"package_version": "0.2.50"}

    monkeypatch.setattr(runtime_module, "validate_bundle", validate)
    installer = HostReleaseInstaller(config_from_json(configuration()))
    installer._validate_bundle(PreparedRelease("0.2.50", Path("/prepared")))
    assert calls[0]["expected_current_schema"] == runtime_module.LATEST_SCHEMA_VERSION
    assert calls[0]["accept_newer_schema"] is True
