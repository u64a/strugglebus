#!/usr/bin/python3.13
"""Fail closed unless a release directory is complete and immutable."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import time

from packaging.utils import InvalidWheelFilename, parse_wheel_filename


HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
RELEASE_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$")
MODULE_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,127}$")
LEGACY_MARKER_KEYS = (
    "wheel_filename",
    "wheel_sha256",
    "requirements_lock_sha256",
)
CAPABLE_MARKER_KEYS = LEGACY_MARKER_KEYS + ("agent_access_freeze",)
ACCESS_FREEZE_CAPABILITY = "global-v1"
ACCESS_PROBE_TIMEOUT_SECONDS = 5.0


class ReleaseValidationError(RuntimeError):
    pass


def require_regular(path: Path, *, executable: bool = False) -> None:
    try:
        file_stat = path.lstat()
    except FileNotFoundError as error:
        raise ReleaseValidationError(f"required release artifact is missing: {path.name}") from error
    if (
        not stat.S_ISREG(file_stat.st_mode)
        or file_stat.st_uid != os.geteuid()
        or stat.S_IMODE(file_stat.st_mode) & 0o022
        or file_stat.st_nlink != 1
    ):
        raise ReleaseValidationError(f"release artifact is not a regular file: {path.name}")
    if executable and not file_stat.st_mode & 0o111:
        raise ReleaseValidationError(f"release executable is not executable: {path.name}")


def require_directory(path: Path, name: str) -> None:
    try:
        file_stat = path.lstat()
    except FileNotFoundError as error:
        raise ReleaseValidationError(f"{name} is missing") from error
    if (
        not stat.S_ISDIR(file_stat.st_mode)
        or file_stat.st_uid != os.geteuid()
        or stat.S_IMODE(file_stat.st_mode) & 0o022
    ):
        raise ReleaseValidationError(f"{name} must be a non-symlink directory")


def require_trusted_executable(path: Path, name: str) -> None:
    try:
        file_stat = path.lstat()
    except FileNotFoundError as error:
        raise ReleaseValidationError(f"{name} is missing") from error
    if (
        not stat.S_ISREG(file_stat.st_mode)
        or file_stat.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(file_stat.st_mode) & 0o022
        or not file_stat.st_mode & 0o111
    ):
        raise ReleaseValidationError(f"{name} is not a trusted executable")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_marker(path: Path) -> dict[str, str]:
    require_regular(path)
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ReleaseValidationError("installed marker is not ASCII") from error
    values: dict[str, str] = {}
    for line in lines:
        if line.count("=") != 1:
            raise ReleaseValidationError("installed marker syntax is invalid")
        key, value = line.split("=", 1)
        if key not in CAPABLE_MARKER_KEYS or key in values or not value:
            raise ReleaseValidationError("installed marker schema is invalid")
        values[key] = value
    if tuple(values) not in {LEGACY_MARKER_KEYS, CAPABLE_MARKER_KEYS}:
        raise ReleaseValidationError("installed marker fields are missing or out of order")
    if not HASH_PATTERN.fullmatch(values["wheel_sha256"]) or not HASH_PATTERN.fullmatch(
        values["requirements_lock_sha256"]
    ):
        raise ReleaseValidationError("installed marker hash is invalid")
    if (
        "agent_access_freeze" in values
        and values["agent_access_freeze"] != ACCESS_FREEZE_CAPABILITY
    ):
        raise ReleaseValidationError("installed marker capability is invalid")
    return values


def service_identity(service_user: str) -> tuple[int, int, list[int]]:
    try:
        account = pwd.getpwnam(service_user)
    except KeyError as error:
        raise ReleaseValidationError("configured service user does not exist") from error
    return (
        account.pw_uid,
        account.pw_gid,
        os.getgrouplist(service_user, account.pw_gid),
    )


def probe_service_access(
    service_user: str,
    *,
    directories: tuple[Path, ...],
    readable_files: tuple[Path, ...],
    executable: Path,
    python: Path,
    app_module: str,
) -> str | None:
    if not hasattr(os, "fork"):
        raise ReleaseValidationError("service access validation requires POSIX")
    service_uid, service_gid, service_groups = service_identity(service_user)
    read_pipe, write_pipe = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_pipe)
        try:
            if os.geteuid() == 0:
                os.setgroups(service_groups)
                os.setgid(service_gid)
                os.setuid(service_uid)
            elif (
                os.geteuid() != service_uid
                or os.getegid() != service_gid
                or not set(service_groups).issubset(set(os.getgroups()) | {os.getegid()})
            ):
                raise PermissionError("validator cannot assume the service identity")

            for directory in directories:
                if not os.access(
                    directory,
                    os.R_OK | os.X_OK,
                    effective_ids=True,
                ):
                    raise PermissionError(f"service cannot access directory {directory}")
                descriptor = os.open(
                    directory,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                )
                os.close(descriptor)
            for path in readable_files:
                descriptor = os.open(
                    path,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                os.close(descriptor)
            if not os.access(
                executable,
                os.R_OK | os.X_OK,
                effective_ids=True,
            ):
                raise PermissionError("service cannot execute the release entry point")
            if not os.access(python, os.R_OK | os.X_OK, effective_ids=True):
                raise PermissionError("service cannot execute the release interpreter")
            os.dup2(write_pipe, 1)
            os.dup2(write_pipe, 2)
            # Fixed argv executes the validated interpreter after privilege drop.
            os.execve(  # nosec B606
                python,
                [
                    str(python),
                    "-I",
                    "-c",
                    (
                        "import importlib,sys;"
                        "module=importlib.import_module(sys.argv[1]);"
                        "value=getattr(module,'ACCESS_FREEZE_CAPABILITY',None);"
                        "print('' if value is None else value)"
                    ),
                    app_module,
                ],
                {
                    "LANG": "C",
                    "PATH": "/usr/bin:/bin",
                    "PYTHONNOUSERSITE": "1",
                },
            )
        except (OSError, PermissionError) as error:
            os.write(write_pipe, str(error).encode("utf-8", errors="replace")[:1024])
            os._exit(1)

    os.close(write_pipe)
    deadline = time.monotonic() + ACCESS_PROBE_TIMEOUT_SECONDS
    status: int | None = None
    while time.monotonic() < deadline:
        waited, child_status = os.waitpid(child, os.WNOHANG)
        if waited == child:
            status = child_status
            break
        time.sleep(0.01)
    if status is None:
        os.kill(child, 9)
        os.waitpid(child, 0)
        os.close(read_pipe)
        raise ReleaseValidationError("service access probe timed out")
    detail = os.read(read_pipe, 1024).decode("utf-8", errors="replace")
    os.close(read_pipe)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        message = "configured service identity cannot access the release"
        if detail:
            message = f"{message}: {detail}"
        raise ReleaseValidationError(message)
    capability = detail.strip()
    if capability and capability != ACCESS_FREEZE_CAPABILITY:
        raise ReleaseValidationError(
            "installed application exposes an unknown access-freeze capability"
        )
    return capability or None


def validate_release(
    root: Path,
    release: str,
    service_user: str | None = None,
    app_module: str = "json",
    *,
    require_release_id: bool = False,
) -> dict[str, str]:
    if not RELEASE_PATTERN.fullmatch(release):
        raise ReleaseValidationError("release name is invalid")
    if not MODULE_PATTERN.fullmatch(app_module):
        raise ReleaseValidationError("application module is invalid")
    require_directory(root, "release root")
    target = root / release
    require_directory(target, "release target")
    if target.parent.resolve(strict=True) != root.resolve(strict=True):
        raise ReleaseValidationError("release target escapes the release root")

    entries = {entry.name: entry for entry in os.scandir(target)}
    wheel_names = sorted(name for name in entries if name.endswith(".whl"))
    if len(wheel_names) != 1:
        raise ReleaseValidationError("release must contain exactly one wheel entry")
    allowed = {
        wheel_names[0],
        "requirements.lock",
        ".installed",
        "venv",
    }
    if "release.env" in entries:
        allowed.add("release.env")
    if set(entries) != allowed:
        raise ReleaseValidationError("release contains unexpected top-level entries")

    wheel = target / wheel_names[0]
    requirements = target / "requirements.lock"
    marker = parse_marker(target / ".installed")
    require_regular(wheel)
    require_regular(requirements)
    release_environment = target / "release.env"
    if "release.env" not in entries:
        if require_release_id:
            raise ReleaseValidationError("release environment is missing")
    else:
        require_regular(release_environment)
        try:
            release_environment_content = release_environment.read_text(encoding="ascii")
        except UnicodeDecodeError as error:
            raise ReleaseValidationError("release environment is not ASCII") from error
        if release_environment_content != f"STRUGGLEBUS_RELEASE_ID={release}\n":
            raise ReleaseValidationError("release environment identifier does not match")
    require_directory(target / "venv", "release virtual environment")
    require_directory(target / "venv" / "bin", "release virtual environment bin")
    service_entry_point = target / "venv" / "bin" / "strugglebus"
    require_regular(service_entry_point, executable=True)
    python = target / "venv" / "bin" / "python"
    try:
        python_target = python.resolve(strict=True)
    except (FileNotFoundError, RuntimeError) as error:
        raise ReleaseValidationError("release interpreter is missing or unsafe") from error
    require_trusted_executable(python_target, "release interpreter")

    if marker["wheel_filename"] != wheel.name:
        raise ReleaseValidationError("installed marker wheel filename does not match")
    try:
        distribution, _, _, _ = parse_wheel_filename(wheel.name)
    except InvalidWheelFilename as error:
        raise ReleaseValidationError("wheel filename is invalid") from error
    if distribution != "strugglebus":
        raise ReleaseValidationError("wheel distribution must be strugglebus")
    if sha256(wheel) != marker["wheel_sha256"]:
        raise ReleaseValidationError("wheel hash does not match installed marker")
    if sha256(requirements) != marker["requirements_lock_sha256"]:
        raise ReleaseValidationError("requirements hash does not match installed marker")
    runtime_capability = probe_service_access(
        service_user or pwd.getpwuid(os.geteuid()).pw_name,
        directories=(root, target, target / "venv", target / "venv" / "bin"),
        readable_files=(
            wheel,
            requirements,
            *((release_environment,) if release_environment.exists() else ()),
            target / ".installed",
        ),
        executable=service_entry_point,
        python=python,
        app_module=app_module,
    )
    marker_capability = marker.get("agent_access_freeze")
    if marker_capability is not None and marker_capability != runtime_capability:
        raise ReleaseValidationError(
            "installed marker access-freeze capability does not match the application"
        )
    return marker


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-release-id", action="store_true")
    parser.add_argument("release_root", type=Path)
    parser.add_argument("release")
    parser.add_argument("service_user")
    parser.add_argument("app_module")
    args = parser.parse_args()
    try:
        result = validate_release(
            args.release_root,
            args.release,
            args.service_user,
            args.app_module,
            require_release_id=args.require_release_id,
        )
    except ReleaseValidationError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
