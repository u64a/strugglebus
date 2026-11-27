"""The host installer that materializes and activates a prepared release as root."""

from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
from types import SimpleNamespace

import pytest

import strugglebus.maintenance_runtime as runtime
from strugglebus.maintenance_runtime import (
    BUNDLE_HELPERS,
    HELPERS,
    HostReleaseInstaller,
    config_from_json,
)
from strugglebus.maintenance_supervisor import PreparedRelease
from strugglebus.maintenance_types import MaintenanceError
from test_maintenance_runtime import configuration

posix_only = pytest.mark.skipif(os.name != "posix", reason="requires POSIX ownership and modes")
VERSION = "0.2.50"
OPERATION = "f" * 32
TOKEN = "1" * 64
FREEZE_TOKEN = "2" * 64


@pytest.fixture
def config(tmp_path):
    return replace(
        config_from_json(configuration()),
        database=tmp_path / "data" / "strugglebus.db",
        backup_dir=tmp_path / "backups",
        release_root=tmp_path / "app" / "releases",
        current_link=tmp_path / "app" / "current",
        updater_release_root=tmp_path / "updater" / "releases",
        updater_current_link=tmp_path / "updater" / "current",
        service_unit=tmp_path / "strugglebus.service",
        maintenance_root=tmp_path / "maintenance",
    )


@pytest.fixture
def installer(config, tmp_path):
    value = HostReleaseInstaller(config)
    value.helper_root = tmp_path / "libexec"
    return value


@pytest.fixture
def root_owned(monkeypatch):
    """Report files the test user created as owned by root, as they are in production."""
    real = Path.lstat

    def lstat(path):
        info = real(path)
        fields = {key: getattr(info, key) for key in dir(info) if key.startswith("st_")}
        return SimpleNamespace(**fields | {"st_uid": 0})

    monkeypatch.setattr(Path, "lstat", lstat)


def _helper_bytes(name: str) -> bytes:
    return f"#!/usr/bin/python3\n# {name}\n".encode("ascii")


def _support_archive(directory: Path, *, omit=(), replace_with=None) -> PreparedRelease:
    directory.mkdir(exist_ok=True)
    archive = directory / f"strugglebus-deployment-support-{VERSION}.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        for source, name in HELPERS.items():
            if source in omit:
                continue
            member = tarfile.TarInfo(source)
            if replace_with is not None and source in replace_with:
                member.type = replace_with[source]
                bundle.addfile(member)
                continue
            content = _helper_bytes(name)
            member.size = len(content)
            bundle.addfile(member, io.BytesIO(content))
        extra = tarfile.TarInfo("README")
        bundle.addfile(extra, io.BytesIO(b""))
    return PreparedRelease(VERSION, directory)


def _identity() -> str:
    hashes = {name: hashlib.sha256(_helper_bytes(name)).hexdigest() for name in HELPERS.values()}
    return hashlib.sha256("".join(hashes[name] for name in BUNDLE_HELPERS).encode("ascii")).hexdigest()


# --- bundle validation ------------------------------------------------------


def test_bundle_that_fails_validation_is_a_preparation_failure(installer, monkeypatch):
    def invalid(directory, **expectations):
        raise ValueError("secret detail about the bundle")

    monkeypatch.setattr(runtime, "validate_bundle", invalid)
    with pytest.raises(MaintenanceError) as caught:
        installer._validate_bundle(PreparedRelease(VERSION, Path("/prepared")))
    assert caught.value.code == "preparation_failed"


def test_bundle_for_another_version_is_a_preparation_failure(installer, monkeypatch):
    received = {}

    def validate(directory, **expectations):
        received.update(expectations, directory=directory)
        return {"package_version": "0.2.51"}

    monkeypatch.setattr(runtime, "validate_bundle", validate)
    monkeypatch.setattr(runtime.HostReleaseInstaller, "_signed_digests", lambda self, release: {})
    with pytest.raises(MaintenanceError) as caught:
        installer._validate_bundle(PreparedRelease(VERSION, Path("/prepared")))
    assert caught.value.code == "preparation_failed"
    assert received["directory"] == Path("/prepared")
    assert received["expected_repository"] == "NZCypher819/strugglebus"
    assert received["minimum_package_version"] == VERSION


# --- helpers ----------------------------------------------------------------


@posix_only
def test_helpers_are_installed_under_their_bundle_identity(installer, tmp_path, root_owned):
    release = _support_archive(tmp_path / "prepared")

    target = installer._materialize_helpers(release, {})

    assert target == installer.helper_root / _identity()
    assert sorted(path.name for path in target.iterdir()) == sorted(HELPERS.values())
    for name in HELPERS.values():
        assert (target / name).read_bytes() == _helper_bytes(name)
        assert stat.S_IMODE((target / name).stat().st_mode) == 0o755
    assert stat.S_IMODE(target.stat().st_mode) == 0o755
    assert stat.S_IMODE(installer.helper_root.stat().st_mode) == 0o755


@posix_only
def test_installed_helpers_are_reused_and_traversal_is_restored(installer, tmp_path, root_owned):
    release = _support_archive(tmp_path / "prepared")
    target = installer._materialize_helpers(release, {})
    before = {path.name: path.stat().st_ino for path in target.iterdir()}
    target.chmod(0o700)

    assert installer._materialize_helpers(release, {}) == target

    assert {path.name: path.stat().st_ino for path in target.iterdir()} == before
    assert stat.S_IMODE(target.stat().st_mode) == 0o755


@posix_only
@pytest.mark.parametrize("defect", ["content", "mode", "hard-link", "symlink"])
def test_tampered_installed_helper_is_never_trusted_or_replaced(
    installer, tmp_path, root_owned, defect,
):
    release = _support_archive(tmp_path / "prepared")
    target = installer._materialize_helpers(release, {})
    helper = target / "strugglebus-maintenance"
    if defect == "content":
        helper.write_bytes(b"#!/bin/sh\nexit 0\n")
    elif defect == "mode":
        helper.chmod(0o775)
    elif defect == "hard-link":
        os.link(helper, tmp_path / "alias")
    else:
        genuine = tmp_path / "genuine"
        genuine.write_bytes(helper.read_bytes())
        genuine.chmod(0o755)
        helper.unlink()
        helper.symlink_to(genuine)
    tampered = helper.read_bytes()

    with pytest.raises(MaintenanceError) as caught:
        installer._materialize_helpers(release, {})

    assert caught.value.code == "installation_failed"
    assert helper.read_bytes() == tampered
    assert helper.is_symlink() is (defect == "symlink")


@posix_only
def test_helper_tree_not_owned_by_root_is_refused(installer, tmp_path):
    release = _support_archive(tmp_path / "prepared")
    with pytest.raises(MaintenanceError) as caught:
        installer._materialize_helpers(release, {})
    assert caught.value.code == "installation_failed"
    assert list(installer.helper_root.iterdir()) == []


def test_helper_root_that_is_not_a_directory_is_refused(installer, tmp_path):
    release = _support_archive(tmp_path / "prepared")
    installer.helper_root.write_bytes(b"")
    with pytest.raises(FileExistsError):
        installer._materialize_helpers(release, {})


def test_archive_without_every_helper_is_a_preparation_failure(installer, tmp_path):
    release = _support_archive(
        tmp_path / "prepared", omit={"helpers/strugglebus-release-lock.py"},
    )
    with pytest.raises(MaintenanceError) as caught:
        installer._materialize_helpers(release, {})
    assert caught.value.code == "preparation_failed"
    assert not installer.helper_root.exists()


@pytest.mark.parametrize("kind", [tarfile.DIRTYPE, tarfile.FIFOTYPE])
def test_archive_helper_that_is_not_a_regular_file_is_a_preparation_failure(
    installer, tmp_path, kind,
):
    release = _support_archive(
        tmp_path / "prepared", replace_with={"helpers/strugglebus-maintenance.py": kind},
    )
    with pytest.raises(MaintenanceError) as caught:
        installer._materialize_helpers(release, {})
    assert caught.value.code == "preparation_failed"
    assert not installer.helper_root.exists()


def test_oversized_archive_helper_is_a_preparation_failure(installer, tmp_path, monkeypatch):
    release = _support_archive(tmp_path / "prepared")
    monkeypatch.setattr(runtime, "FILE_BYTES", 8)
    with pytest.raises(MaintenanceError) as caught:
        installer._materialize_helpers(release, {})
    assert caught.value.code == "preparation_failed"


def test_archive_helper_shorter_than_its_header_is_a_preparation_failure():
    member = tarfile.TarInfo("helpers/strugglebus-maintenance.py")
    member.size = 64
    bundle = SimpleNamespace(extractfile=lambda entry: io.BytesIO(b"truncated"))
    with pytest.raises(MaintenanceError) as caught:
        runtime._helper_content(bundle, member)
    assert caught.value.code == "preparation_failed"


def test_missing_support_archive_is_reported_as_such(installer, tmp_path):
    with pytest.raises(FileNotFoundError):
        installer._materialize_helpers(PreparedRelease(VERSION, tmp_path), {})


@posix_only
def test_verify_helpers_without_hashes_still_checks_ownership_and_mode(tmp_path, root_owned):
    for name in HELPERS.values():
        (tmp_path / name).write_bytes(b"x")
        (tmp_path / name).chmod(0o755)
    HostReleaseInstaller._verify_helpers(tmp_path)

    (tmp_path / "strugglebus-sqlite-backup").chmod(0o700)
    with pytest.raises(MaintenanceError, match="installation_failed"):
        HostReleaseInstaller._verify_helpers(tmp_path)


@posix_only
def test_verify_helpers_rejects_helpers_not_owned_by_root(tmp_path):
    for name in HELPERS.values():
        (tmp_path / name).write_bytes(b"x")
        (tmp_path / name).chmod(0o755)
    with pytest.raises(MaintenanceError, match="installation_failed"):
        HostReleaseInstaller._verify_helpers(tmp_path)


def test_verify_helpers_reports_a_missing_helper_as_such(tmp_path):
    with pytest.raises(FileNotFoundError):
        HostReleaseInstaller._verify_helpers(tmp_path)


# --- release environments ---------------------------------------------------


@pytest.fixture
def build(monkeypatch, tmp_path):
    """Stand in for venv creation, uv and chown while a release is materialized."""
    wheel = tmp_path / "prepared" / f"strugglebus-{VERSION}-py3-none-any.whl"
    lock = tmp_path / "prepared" / "requirements.lock"
    wheel.parent.mkdir()
    wheel.write_bytes(b"wheel bytes")
    lock.write_bytes(b"dependency==1.0 --hash=sha256:00\n")
    state = SimpleNamespace(
        facts={
            "wheel_src": str(wheel),
            "wheel_sha256": "a" * 64,
            "requirements_lock_sha256": "b" * 64,
            "requirements_lock_src": str(lock),
        },
        release=PreparedRelease(VERSION, wheel.parent),
        commands=[],
        owners={},
        fail_on=None,
    )

    def run(argv, *, timeout=120, **kwargs):
        state.commands.append((argv, timeout, kwargs))
        step = "venv" if "venv" in argv else argv[3]
        if step == state.fail_on:
            raise MaintenanceError("installation_failed")
        if step == "venv":
            environment = Path(argv[-1])
            (environment / "bin").mkdir(parents=True)
            (environment / "lib").mkdir()
            (environment / "pyvenv.cfg").write_text(f"command = venv {environment}\n")
            (environment / "bin" / "python").write_bytes(b"\x7fELF")
            (environment / "lib" / "module.py").write_text("VALUE = 1\n")
        if step == "install":
            script = Path(argv[5]).parent / "strugglebus"
            script.write_text(f"#!{argv[5]}\nimport strugglebus\n")
        return b""

    def chown(path, uid, gid):
        state.owners[Path(path)] = (uid, gid)

    monkeypatch.setattr(runtime, "_run", run)
    monkeypatch.setattr(runtime.os, "chown", chown, raising=False)
    monkeypatch.setitem(
        sys.modules,
        "pwd",
        SimpleNamespace(getpwnam=lambda user: SimpleNamespace(pw_uid=998, pw_gid=997)),
    )
    return state


def _marker() -> bytes:
    return (
        f"wheel_filename=strugglebus-{VERSION}-py3-none-any.whl\n"
        f"wheel_sha256={'a' * 64}\n"
        f"requirements_lock_sha256={'b' * 64}\n"
        "agent_access_freeze=global-v1\n"
    ).encode("ascii")


def test_application_release_is_built_in_staging_then_renamed(installer, config, build):
    installer._materialize_application(build.release, build.facts, OPERATION)

    target = config.release_root / VERSION
    staging = config.release_root / f".{VERSION}.maintenance-{OPERATION}"
    assert not staging.exists()
    assert (target / ".installed").read_bytes() == _marker()
    assert (target / "release.env").read_bytes() == f"STRUGGLEBUS_RELEASE_ID={VERSION}\n".encode()
    assert (target / f"strugglebus-{VERSION}-py3-none-any.whl").read_bytes() == b"wheel bytes"
    assert (target / "requirements.lock").read_bytes().startswith(b"dependency==1.0")
    assert (target / "venv/bin/strugglebus").read_text() == (
        f"#!{target / 'venv/bin/python'}\nimport strugglebus\n"
    )
    assert str(staging) not in (target / "venv/pyvenv.cfg").read_text()

    python, uv = str(config.python), str(config.uv)
    venv_python = str(staging / "venv/bin/python")
    assert [(argv, timeout) for argv, timeout, _ in build.commands] == [
        ([python, "-I", "-m", "venv", "--copies", str(staging / "venv")], 120),
        ([
            uv, "--no-config", "pip", "sync", "--python", venv_python,
            "--require-hashes", "--only-binary", ":all:", str(staging / "requirements.lock"),
        ], 600),
        ([
            uv, "--no-config", "pip", "install", "--python", venv_python,
            "--no-deps", "--no-index", "--no-build", "--reinstall",
            str(staging / f"strugglebus-{VERSION}-py3-none-any.whl"),
        ], 180),
    ]
    assert all(kwargs == {} for _, _, kwargs in build.commands)
    # Every entry, including the staging root, goes to root and the service group.
    assert set(build.owners.values()) == {(0, 997)}
    assert staging in build.owners
    assert staging / "venv/lib/module.py" in build.owners


@posix_only
def test_application_release_is_closed_to_other_users(installer, config, build):
    installer._materialize_application(build.release, build.facts, OPERATION)

    target = config.release_root / VERSION
    assert stat.S_IMODE(target.stat().st_mode) == 0o750
    assert stat.S_IMODE((target / "venv/lib").stat().st_mode) == 0o750
    assert stat.S_IMODE((target / ".installed").stat().st_mode) == 0o640
    assert stat.S_IMODE((target / "venv/lib/module.py").stat().st_mode) == 0o640
    assert stat.S_IMODE((target / "venv/bin/python").stat().st_mode) == 0o750
    assert stat.S_IMODE((target / "venv/bin/strugglebus").stat().st_mode) == 0o750


def test_updater_release_belongs_to_root_alone(installer, config, build):
    installer._materialize_updater(build.release, build.facts, OPERATION)

    target = config.updater_release_root / VERSION
    assert (target / ".installed").read_bytes() == _marker()
    assert set(build.owners.values()) == {(0, 0)}
    assert not (config.release_root / VERSION).exists()
    if os.name == "posix":
        assert stat.S_IMODE(target.stat().st_mode) == 0o755
        assert stat.S_IMODE((target / ".installed").stat().st_mode) == 0o644
        assert stat.S_IMODE((target / "venv/bin/python").stat().st_mode) == 0o755


def test_leftover_staging_from_an_interrupted_attempt_is_discarded(installer, config, build):
    staging = config.release_root / f".{VERSION}.maintenance-{OPERATION}"
    (staging / "venv").mkdir(parents=True)
    (staging / "stale").write_bytes(b"left behind")

    installer._materialize_application(build.release, build.facts, OPERATION)

    assert not staging.exists()
    assert not (config.release_root / VERSION / "stale").exists()
    assert (config.release_root / VERSION / ".installed").read_bytes() == _marker()


@pytest.mark.parametrize("step", ["venv", "sync", "install"])
def test_failed_build_leaves_no_release_or_staging_behind(installer, config, build, step):
    build.fail_on = step

    with pytest.raises(MaintenanceError) as caught:
        installer._materialize_application(build.release, build.facts, OPERATION)

    assert caught.value.code == "installation_failed"
    assert list(config.release_root.iterdir()) == []
    assert build.owners == {}


def test_failed_ownership_change_leaves_no_release_behind(installer, config, build, monkeypatch):
    def refuse(path, uid, gid):
        raise PermissionError(path)

    monkeypatch.setattr(runtime.os, "chown", refuse, raising=False)
    with pytest.raises(PermissionError):
        installer._materialize_application(build.release, build.facts, OPERATION)
    assert list(config.release_root.iterdir()) == []


def test_installed_release_is_not_rebuilt(installer, config, build):
    installer._materialize_application(build.release, build.facts, OPERATION)
    build.commands.clear()

    installer._materialize_application(build.release, build.facts, "e" * 32)

    assert build.commands == []
    assert sorted(path.name for path in config.release_root.iterdir()) == [VERSION]


# --- release locks ----------------------------------------------------------


@pytest.fixture
def children(monkeypatch):
    """Record child commands and answer them from a queue of outputs or failures."""
    state = SimpleNamespace(calls=[], outputs=[])

    def run(argv, **kwargs):
        state.calls.append((argv, kwargs))
        output = state.outputs.pop(0) if state.outputs else b""
        if isinstance(output, BaseException):
            raise output
        return output

    monkeypatch.setattr(runtime, "_run", run)
    return state


def _lock_output(token=TOKEN) -> bytes:
    return json.dumps({"token": token, "expires_at": 1}).encode("ascii")


def test_release_lock_is_acquired_as_root_with_the_configured_wait_and_lease(
    installer, config, children, tmp_path,
):
    children.outputs = [_lock_output()]

    value = installer._acquire_release_lock(tmp_path)

    assert value == {"token": TOKEN, "expires_at": 1}
    argv, kwargs = children.calls[0]
    assert argv == [
        str(config.python), "-I", str(tmp_path / "strugglebus-release-lock"), "acquire",
        "--lock-path", str(Path("/run/lock/strugglebus/release.lock")),
        "--metadata-path", str(Path("/run/lock/strugglebus/release.json")),
        "--wait-seconds", "30",
        "--lease-seconds", "3600",
    ]
    assert kwargs == {"timeout": 35, "user": None}


def test_freeze_lock_is_acquired_as_the_service_user_beside_the_database(
    installer, config, children, tmp_path,
):
    children.outputs = [_lock_output(FREEZE_TOKEN)]

    assert installer._acquire_freeze_lock(tmp_path)["token"] == FREEZE_TOKEN

    argv, kwargs = children.calls[0]
    directory = config.database.parent / ".access-freeze-lock"
    assert argv[4:8] == [
        "--lock-path", str(directory / "transition.lock"),
        "--metadata-path", str(directory / "release.json"),
    ]
    assert kwargs == {"timeout": 35, "user": "strugglebus"}


@pytest.mark.parametrize(
    "output",
    [
        pytest.param(b"\xff", id="not-ascii"),
        pytest.param(b"token", id="not-json"),
        pytest.param(b'["' + b"1" * 64 + b'"]', id="not-an-object"),
        pytest.param(b"{}", id="no-token"),
        pytest.param(b'{"token": 7}', id="numeric-token"),
        pytest.param(_lock_output("1" * 63), id="short-token"),
        pytest.param(_lock_output("G" * 64), id="non-hex-token"),
    ],
)
def test_lock_helper_output_without_a_valid_token_fails(installer, children, tmp_path, output):
    children.outputs = [output]
    with pytest.raises(MaintenanceError) as caught:
        installer._acquire_release_lock(tmp_path)
    assert caught.value.code == "installation_failed"


def test_lock_is_released_by_token_and_a_failed_release_is_tolerated(
    installer, config, children, tmp_path,
):
    metadata = tmp_path / "release.json"
    installer._release_lock(tmp_path, metadata, TOKEN, user="strugglebus")
    children.outputs = [MaintenanceError("installation_failed")]
    installer._release_lock(tmp_path, metadata, TOKEN)

    argv, kwargs = children.calls[0]
    assert argv == [
        str(config.python), "-I", str(tmp_path / "strugglebus-release-lock"), "release",
        "--metadata-path", str(metadata), "--token", TOKEN,
    ]
    assert kwargs == {"timeout": 10, "user": "strugglebus"}
    assert children.calls[1][1] == {"timeout": 10, "user": None}


# --- maintenance request ----------------------------------------------------

UNIT = b"[Service]\nUser=strugglebus\n"
PROBE = {
    "candidate_schema": 12,
    "environment": {"STRUGGLEBUS_BIND_PORT": "8443", "STRUGGLEBUS_DATA_DIR": "/var/lib/strugglebus"},
}
FACTS = {
    "wheel_src": f"/prepared/strugglebus-{VERSION}-py3-none-any.whl",
    "wheel_sha256": "a" * 64,
    "requirements_lock_sha256": "b" * 64,
}


@pytest.fixture
def unit(monkeypatch):
    reads = []

    def read(path, maximum, *, uid, mode):
        reads.append((path, maximum, uid, mode))
        return UNIT

    monkeypatch.setattr(runtime, "_read_regular", read)
    monkeypatch.setattr(runtime, "_sha256", lambda path: "sha:" + path.name)
    return reads


def test_maintenance_request_binds_the_unit_helpers_and_candidate(
    installer, config, children, unit, tmp_path,
):
    children.outputs = [
        json.dumps(PROBE).encode("ascii"),
        json.dumps({"operator_credential": "credential-name"}).encode("ascii"),
    ]
    release = PreparedRelease(VERSION, Path("/prepared"))

    request, content = installer._maintenance_request(release, FACTS, tmp_path)

    assert unit == [(config.service_unit, 65536, 0, 0o644)]
    assert content == UNIT.decode("ascii")
    digest = hashlib.sha256(UNIT).hexdigest()
    assert request == {
        "release_root": str(config.release_root),
        "state_dir": str(config.maintenance_root),
        "backup_dir": str(config.backup_dir),
        "database": str(config.database),
        "unit": str(config.service_unit),
        "current": str(config.current_link),
        "candidate_config": str(config.maintenance_root / f"candidate-{digest}.service"),
        "helper_root": str(tmp_path),
        "helper_sha256": {
            name: "sha:" + name
            for name in HELPERS.values()
            if name != "strugglebus-release-lock"
        },
        "candidate": VERSION,
        "candidate_schema": 12,
        "config_sha256": digest,
        "marker": {
            "wheel_filename": f"strugglebus-{VERSION}-py3-none-any.whl",
            "wheel_sha256": "a" * 64,
            "requirements_lock_sha256": "b" * 64,
            "agent_access_freeze": "global-v1",
        },
        "environment": PROBE["environment"],
        "service_user": "strugglebus",
        "app_module": "strugglebus.app",
        "bind_port": 8443,
        "health_url": config.health_url,
        "ca_path": str(config.ca_path),
        "operator_credential": "credential-name",
    }

    probe, credential = children.calls
    assert probe[0] == [
        str(config.python), "-I", str(tmp_path / "strugglebus-validate-maintenance-config"),
        "--unit-stdin",
        "--candidate-python", str(config.release_root / VERSION / "venv/bin/python"),
        "--release-id", VERSION,
    ]
    assert probe[1] == {"input_bytes": UNIT, "timeout": 60, "user": "strugglebus"}
    assert credential[0] == [
        str(config.python), "-I", str(tmp_path / "strugglebus-maintenance"), "credential",
    ]
    assert json.loads(credential[1]["input_bytes"]) == {"unit_content": UNIT.decode("ascii")}
    assert "user" not in credential[1]


@pytest.mark.parametrize(
    "outputs",
    [
        pytest.param([b"not json", b"{}"], id="probe-not-json"),
        pytest.param([json.dumps(PROBE).encode(), b"\xff"], id="credential-not-ascii"),
    ],
)
def test_unparseable_helper_output_fails_the_request(installer, children, unit, tmp_path, outputs):
    children.outputs = outputs
    with pytest.raises(MaintenanceError) as caught:
        installer._maintenance_request(PreparedRelease(VERSION, Path("/prepared")), FACTS, tmp_path)
    assert caught.value.code == "installation_failed"


def test_rejected_candidate_configuration_fails_before_the_credential_is_read(
    installer, children, unit, tmp_path,
):
    children.outputs = [MaintenanceError("installation_failed")]
    with pytest.raises(MaintenanceError, match="installation_failed"):
        installer._maintenance_request(PreparedRelease(VERSION, Path("/prepared")), FACTS, tmp_path)
    assert len(children.calls) == 1


# --- updater activation -----------------------------------------------------


@pytest.fixture
def updater(config):
    previous = config.updater_release_root / "0.2.49"
    candidate = config.updater_release_root / VERSION
    previous.mkdir(parents=True)
    candidate.mkdir()
    config.updater_current_link.symlink_to(previous, target_is_directory=True)
    return SimpleNamespace(previous=previous, candidate=candidate, link=config.updater_current_link)


def _systemctl(config, *arguments):
    return [str(config.systemctl), *arguments]


@posix_only
def test_updater_link_is_switched_and_both_services_restarted(
    installer, config, children, updater,
):
    installer._activate_updater(VERSION)

    assert os.readlink(updater.link) == str(updater.candidate)
    assert sorted(path.name for path in updater.link.parent.iterdir()) == ["current", "releases"]
    assert children.calls == [
        (_systemctl(config, "restart", "strugglebus-updater.service"), {"timeout": 30}),
        (_systemctl(config, "restart", "strugglebus-maintenance.service"), {"timeout": 30}),
        (_systemctl(config, "is-active", "--quiet", "strugglebus-updater.service"), {"timeout": 10}),
    ]


@posix_only
@pytest.mark.parametrize("failing_call", [0, 1, 2])
def test_updater_link_is_rolled_back_when_the_new_updater_does_not_start(
    installer, config, children, updater, failing_call,
):
    children.outputs = [b""] * failing_call + [MaintenanceError("installation_failed")]

    with pytest.raises(MaintenanceError) as caught:
        installer._activate_updater(VERSION)

    assert caught.value.code == "installation_failed"
    assert os.readlink(updater.link) == str(updater.previous)
    assert sorted(path.name for path in updater.link.parent.iterdir()) == ["current", "releases"]
    assert [argv for argv, _ in children.calls[failing_call + 1:]] == [
        _systemctl(config, "restart", "strugglebus-updater.service"),
        _systemctl(config, "restart", "strugglebus-maintenance.service"),
    ]


@posix_only
def test_rollback_restarts_are_best_effort(installer, config, children, updater):
    children.outputs = [MaintenanceError("installation_failed")] * 3

    with pytest.raises(MaintenanceError, match="installation_failed"):
        installer._activate_updater(VERSION)

    assert os.readlink(updater.link) == str(updater.previous)
    assert len(children.calls) == 3


def test_updater_is_not_touched_without_a_current_release_to_fall_back_to(
    installer, config, children,
):
    config.updater_release_root.mkdir(parents=True)
    with pytest.raises(FileNotFoundError):
        installer._activate_updater(VERSION)
    assert children.calls == []
    assert sorted(path.name for path in config.updater_current_link.parent.iterdir()) == ["releases"]


# --- whole installation -----------------------------------------------------


@pytest.fixture
def installation(installer, config, monkeypatch, tmp_path):
    """Record the order of an installation whose individual steps are stubbed."""
    events = []
    helper_root = tmp_path / "libexec" / "identity"
    request = {"candidate": VERSION, "environment": {"STRUGGLEBUS_DATA_DIR": "/var/lib/strugglebus"}}
    state = SimpleNamespace(events=events, fail=None, helper_root=helper_root, request=request)

    def step(name, result=None):
        def record(*arguments, **keywords):
            events.append((name, arguments, keywords))
            if state.fail == name:
                raise MaintenanceError("installation_failed")
            return result

        return record

    def run(argv, *, input_bytes, timeout):
        events.append((argv[-1], (argv, json.loads(input_bytes)), {"timeout": timeout}))
        if state.fail == argv[-1]:
            raise MaintenanceError("installation_failed")
        return b""

    monkeypatch.setattr(installer, "_validate_bundle", step("validate", {"package_version": VERSION}))
    monkeypatch.setattr(installer, "_materialize_helpers", step("helpers", helper_root))
    monkeypatch.setattr(installer, "_materialize_application", step("application"))
    monkeypatch.setattr(installer, "_materialize_updater", step("updater"))
    monkeypatch.setattr(installer, "_acquire_release_lock", step("lock", {"token": TOKEN}))
    monkeypatch.setattr(installer, "_acquire_freeze_lock", step("freeze", {"token": FREEZE_TOKEN}))
    monkeypatch.setattr(installer, "_maintenance_request", step("request", (request, "[Service]\n")))
    monkeypatch.setattr(installer, "_activate_updater", step("activate"))
    monkeypatch.setattr(installer, "_release_lock", step("unlock"))
    monkeypatch.setattr(runtime, "_run", run)
    return state


def _names(events):
    return [name for name, _, _ in events]


def test_installation_stages_then_runs_under_both_locks(installer, config, installation):
    release = PreparedRelease(VERSION, Path("/prepared"))

    installer.install(release, operation_id=OPERATION)

    assert _names(installation.events) == [
        "validate", "helpers", "application", "updater", "lock", "freeze",
        "request", "stage", "run", "activate", "unlock", "unlock",
    ]
    events = {name: (arguments, keywords) for name, arguments, keywords in installation.events[:10]}
    facts = {"package_version": VERSION}
    assert events["application"][0] == (release, facts, OPERATION)
    assert events["updater"][0] == (release, facts, OPERATION)
    assert events["request"][0] == (release, facts, installation.helper_root)
    assert events["activate"][0] == (VERSION,)

    locks = [
        {"metadata": "/run/lock/strugglebus/release.json", "token": TOKEN},
        {
            "metadata": str(Path("/var/lib/strugglebus") / ".access-freeze-lock/release.json"),
            "token": FREEZE_TOKEN,
        },
    ]
    helper = str(installation.helper_root / "strugglebus-maintenance")
    (stage_argv, stage_input), stage_options = events["stage"]
    (run_argv, run_input), run_options = events["run"]
    assert stage_argv == [str(config.python), "-I", helper, "stage"]
    assert stage_input == {
        "request": installation.request, "unit_content": "[Service]\n", "locks": locks,
    }
    assert stage_options == {"timeout": 120}
    assert run_argv == [str(config.python), "-I", helper, "run"]
    assert run_input == {"request": installation.request, "locks": locks}
    assert run_options == {"timeout": 900}

    freeze_release, lock_release = installation.events[10:]
    assert freeze_release[1] == (
        installation.helper_root,
        config.database.parent / ".access-freeze-lock/release.json",
        FREEZE_TOKEN,
    )
    assert freeze_release[2] == {"user": "strugglebus"}
    assert lock_release[1] == (
        installation.helper_root, Path("/run/lock/strugglebus/release.json"), TOKEN,
    )
    assert lock_release[2] == {}


def test_run_deadline_stays_inside_a_short_lock_lease(installer, config, installation):
    installer.config = replace(config, release_lock_lease_seconds=600)

    installer.install(PreparedRelease(VERSION, Path("/prepared")), operation_id=OPERATION)

    timeouts = {
        name: keywords["timeout"]
        for name, _, keywords in installation.events
        if name in {"stage", "run"}
    }
    assert timeouts == {"stage": 120, "run": 540}


@pytest.mark.parametrize(
    ("failing", "completed"),
    [
        ("request", ["request"]),
        ("stage", ["request", "stage"]),
        ("run", ["request", "stage", "run"]),
        ("activate", ["request", "stage", "run", "activate"]),
    ],
)
def test_both_locks_are_released_when_a_locked_step_fails(
    installer, installation, failing, completed,
):
    installation.fail = failing

    with pytest.raises(MaintenanceError) as caught:
        installer.install(PreparedRelease(VERSION, Path("/prepared")), operation_id=OPERATION)

    assert caught.value.code == "installation_failed"
    assert _names(installation.events)[6:] == [*completed, "unlock", "unlock"]
    assert [event[1][2] for event in installation.events[-2:]] == [FREEZE_TOKEN, TOKEN]


@pytest.mark.parametrize("failing", ["validate", "helpers", "application", "updater", "lock"])
def test_failure_before_the_locks_are_held_changes_nothing_further(
    installer, installation, failing,
):
    installation.fail = failing

    with pytest.raises(MaintenanceError):
        installer.install(PreparedRelease(VERSION, Path("/prepared")), operation_id=OPERATION)

    names = _names(installation.events)
    assert names[-1] == failing
    assert not {"stage", "run", "activate", "unlock"} & set(names)


def test_release_lock_is_given_back_when_the_freeze_lock_cannot_be_taken(
    installer, installation,
):
    installation.fail = "freeze"

    with pytest.raises(MaintenanceError):
        installer.install(PreparedRelease(VERSION, Path("/prepared")), operation_id=OPERATION)

    assert _names(installation.events) == [
        "validate", "helpers", "application", "updater", "lock", "freeze", "unlock",
    ]
    unlock = installation.events[-1]
    assert unlock[1] == (
        installation.helper_root, Path("/run/lock/strugglebus/release.json"), TOKEN,
    )
    assert unlock[2] == {}
