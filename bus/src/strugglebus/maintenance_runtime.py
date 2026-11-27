"""Linux-only runtime for prepared-release installation on the Strugglebus VM."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess  # nosec B404
import sys
import tarfile
import time
from typing import Any
from uuid import uuid4

from strugglebus.maintenance_supervisor import (
    MaintenanceAnnouncer,
    PreparedRelease,
    ReleaseGateway,
    ReleaseInstaller,
)
from strugglebus.maintenance_types import MaintenanceError
from strugglebus.migrations import LATEST_SCHEMA_VERSION
from strugglebus.release_validation import (
    MAX_STATEMENT_BYTES,
    STATEMENT_NAME,
    SUPPORT_NAME_TEMPLATE,
    validate_bundle,
)
from strugglebus.release_signature import ReleaseSignatureError, signed_digests
from strugglebus.update_client import UpdateClient
from strugglebus.update_types import UpdateError, UpdateLimits, UpdateStatus, require_version

PATH_BYTES = 4096
FILE_BYTES = 512 * 1024 * 1024
ANNOUNCEMENT_SCRIPT = """\
import argparse
import json
from pathlib import Path
import re
import sqlite3
import strugglebus.maintenance_notice as notice
from strugglebus.store import SQLiteStore


def maintenance_store(database, *, backup_dir, **kwargs):
    return SQLiteStore(database, backup_dir=backup_dir, busy_timeout_ms=30_000)


def failure_code(error):
    current = error
    for _ in range(8):
        if isinstance(current, sqlite3.Error):
            name = getattr(current, "sqlite_errorname", None)
            if isinstance(name, str) and re.fullmatch(r"SQLITE_[A-Z0-9_]{1,56}", name):
                return name
            return "SQLITE_ERROR"
        current = current.__cause__ or current.__context__
        if current is None:
            break
    return "NON_SQLITE_ERROR"


parser = argparse.ArgumentParser()
parser.add_argument("--database", required=True, type=Path)
parser.add_argument("--backup-dir", required=True, type=Path)
parser.add_argument("--operation-id", required=True)
parser.add_argument("--version", required=True)
parser.add_argument("--scheduled-at", required=True, type=int)
parser.add_argument("--automatic", action="store_true")
args = parser.parse_args()
notice.SQLiteStore = maintenance_store
try:
    sequence = notice.publish_notice(
        database=args.database,
        backup_dir=args.backup_dir,
        operation_id=args.operation_id,
        version=args.version,
        scheduled_at=args.scheduled_at,
        automatic=args.automatic,
    )
except Exception as error:
    print(json.dumps({"cause": failure_code(error), "error": "maintenance_notice_failed", "ok": False}, sort_keys=True))
    raise SystemExit(1)
print(json.dumps({"ok": True, "sequence": sequence}, sort_keys=True))
"""

HELPERS = {
    "helpers/strugglebus-inspect-access-freeze.py": "strugglebus-inspect-access-freeze",
    "helpers/strugglebus-maintenance.py": "strugglebus-maintenance",
    "helpers/strugglebus-release-lock.py": "strugglebus-release-lock",
    "helpers/strugglebus-sqlite-backup.py": "strugglebus-sqlite-backup",
    "helpers/strugglebus-validate-maintenance-config.py": "strugglebus-validate-maintenance-config",
}
# Bundle identity shared with Ansible maintenance and the operator guard.
BUNDLE_HELPERS = (
    "strugglebus-maintenance", "strugglebus-validate-maintenance-config",
    "strugglebus-inspect-access-freeze", "strugglebus-sqlite-backup",
)
HELPER_ROOT = Path("/usr/local/libexec/strugglebus-maintenance")


def _absolute(value: object) -> Path:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > PATH_BYTES:
        raise MaintenanceError("invalid_request")
    portable = PurePosixPath(value)
    if not portable.is_absolute() or ".." in portable.parts:
        raise MaintenanceError("invalid_request")
    return Path(value)


def _text(value: object, pattern: str, maximum: int = 128) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or re.fullmatch(pattern, value) is None
    ):
        raise MaintenanceError("invalid_request")
    return value


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    application_uid: int
    service_user: str
    updater_socket: Path
    updater_cache_state: Path
    state_path: Path
    database: Path
    backup_dir: Path
    release_root: Path
    current_link: Path
    updater_release_root: Path
    updater_current_link: Path
    service_unit: Path
    maintenance_root: Path
    health_url: str
    ca_path: Path
    python: Path
    uv: Path
    systemctl: Path
    runuser: Path
    release_lock_wait_seconds: int
    release_lock_lease_seconds: int


def _config_numbers(value: dict[str, Any]) -> tuple[int, int, int]:
    """Return the validated application uid and release-lock wait and lease."""
    uid = value["application_uid"]
    wait = value["release_lock_wait_seconds"]
    lease = value["release_lock_lease_seconds"]
    if (
        type(uid) is not int or uid < 1 or type(wait) is not int or not 1 <= wait <= 300
        or type(lease) is not int or not 600 <= lease <= 14400
    ):
        raise MaintenanceError("invalid_request")
    return uid, wait, lease


def config_from_json(value: object) -> RuntimeConfig:
    keys = {
        "version", "application_uid", "service_user", "updater_socket",
        "updater_cache_state", "state_path", "database", "backup_dir",
        "release_root", "current_link", "updater_release_root",
        "updater_current_link", "service_unit", "maintenance_root", "health_url",
        "ca_path", "python", "uv", "systemctl", "runuser", "release_lock_wait_seconds",
        "release_lock_lease_seconds",
    }
    if not isinstance(value, dict) or set(value) != keys or value["version"] != 1:
        raise MaintenanceError("invalid_request")
    uid, wait, lease = _config_numbers(value)
    return RuntimeConfig(
        uid,
        _text(value["service_user"], r"[a-z_][a-z0-9_-]{0,31}"),
        *(
            _absolute(value[name])
            for name in (
                "updater_socket", "updater_cache_state", "state_path", "database",
                "backup_dir", "release_root", "current_link",
                "updater_release_root", "updater_current_link", "service_unit",
                "maintenance_root",
            )
        ),
        _text(value["health_url"], r"https://[A-Za-z0-9.-]+/healthz", 512),
        _absolute(value["ca_path"]),
        *(
            _absolute(value[name])
            for name in ("python", "uv", "systemctl", "runuser")
        ),
        wait,
        lease,
    )


def load_config(path: Path) -> RuntimeConfig:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise MaintenanceError("forbidden")
    raw = _read_regular(path, 65536, uid=0, mode=0o600)
    try:
        return config_from_json(json.loads(raw.decode("ascii")))
    except (UnicodeError, ValueError, RecursionError):
        raise MaintenanceError("invalid_request") from None


def _is_single_regular_file(
    metadata: os.stat_result, current: os.stat_result, maximum: int,
) -> bool:
    """The open descriptor is the bounded, unaliased regular file still at the path."""
    return not (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > maximum
        or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
    )


def _owner_and_mode_match(
    metadata: os.stat_result, uid: int | None, mode: int | None,
) -> bool:
    return not (
        (uid is not None and metadata.st_uid != uid)
        or (mode is not None and stat.S_IMODE(metadata.st_mode) != mode)
    )


def _read_regular(
    path: Path, maximum: int, *, uid: int | None = None, mode: int | None = None,
) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        current = path.lstat()
        if (
            not _is_single_regular_file(metadata, current, maximum)
            or not _owner_and_mode_match(metadata, uid, mode)
        ):
            raise MaintenanceError("installation_failed")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            value = stream.read(maximum + 1)
        if len(value) > maximum:
            raise MaintenanceError("installation_failed")
        return value
    except OSError:
        raise MaintenanceError("installation_failed") from None
    finally:
        os.close(descriptor)


_BOOTSTRAP_MARKER_KEYS = frozenset({
    "version", "package_version", "source_commit", "source_tree",
    "manifest_sha256", "wheel_sha256", "requirements_lock_sha256",
})


def _bootstrap_marker_matches(installed: bytes, version: str, facts: dict[str, Any]) -> bool:
    """Accept a release directory Ansible installed from the exact same bytes."""
    try:
        identity = json.loads(installed.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return False
    return (
        isinstance(identity, dict)
        and set(identity) == _BOOTSTRAP_MARKER_KEYS
        and identity["version"] == 1
        and identity["package_version"] == version
        and identity["wheel_sha256"] == facts["wheel_sha256"]
        and identity["requirements_lock_sha256"] == facts["requirements_lock_sha256"]
    )


def _retarget_scripts(staging: Path, target: Path) -> None:
    """Point a venv built under ``staging`` at its final ``target`` path.

    Installers embed the absolute interpreter path in console-script shebangs
    and activation scripts, so a venv renamed after installation would keep
    executing through the deleted staging path.
    """
    old = os.fsencode(staging)
    new = os.fsencode(target)
    candidates = [staging / "pyvenv.cfg", *sorted((staging / "bin").iterdir())]
    for path in candidates:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
            continue
        content = path.read_bytes()
        if old in content:
            path.write_bytes(content.replace(old, new))


def _is_stable_root_link(before: os.stat_result, after: os.stat_result) -> bool:
    """The current link is root's own unaliased symlink and was not swapped mid-read."""
    return not (
        not stat.S_ISLNK(before.st_mode)
        or before.st_uid != 0
        or before.st_nlink != 1
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
    )


def _is_direct_release(
    target: Path, resolved: Path, release_root: Path, config: RuntimeConfig,
) -> bool:
    """The link names a canonical directory directly inside the canonical release root."""
    return not (
        not target.is_absolute()
        or target.parent != release_root
        or release_root != config.release_root
        or resolved != target
    )


def _are_protected_directories(metadata: list[os.stat_result]) -> bool:
    return not any(
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
        for info in metadata
    )


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in require_version(version).split("."))


def _read_statement(path: Path) -> str:
    """Reads the saved statement without following a link or reading more than a statement holds."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_STATEMENT_BYTES:
            raise ValueError("not a statement")
        return stream.read(MAX_STATEMENT_BYTES).decode("utf-8")


def active_application_version(config: RuntimeConfig) -> str:
    try:
        before = config.current_link.lstat()
        target = Path(os.readlink(config.current_link))
        release_root = config.release_root.resolve(strict=True)
        resolved = target.resolve(strict=True)
        after = config.current_link.lstat()
        protected = [*reversed(release_root.parents), release_root, resolved]
        metadata = [path.lstat() for path in protected]
    except (OSError, RuntimeError, ValueError):
        raise MaintenanceError("installation_failed") from None
    if (
        not _is_stable_root_link(before, after)
        or not _is_direct_release(target, resolved, release_root, config)
        or not _are_protected_directories(metadata)
    ):
        raise MaintenanceError("installation_failed")
    try:
        return require_version(resolved.name)
    except UpdateError:
        raise MaintenanceError("installation_failed") from None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise MaintenanceError("installation_failed")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


_EXCEPTION_LINE = re.compile(rb"([A-Za-z_][A-Za-z0-9_.]{0,80}(?:Error|Exception|Exit|Interrupt))(?::|$)")


def _child_failure_detail(returncode: int, stderr: bytes | None) -> str:
    """Summarize a child failure by signal or exception type only, never message text."""
    if returncode < 0:
        return f":signal={-returncode}"
    for line in reversed((stderr or b"")[-4096:].splitlines()):
        match = _EXCEPTION_LINE.match(line.strip())
        if match is not None:
            return ":exception=" + match.group(1).decode("ascii")
    return f":rc={returncode}"


def _command_as(argv: list[str], user: str | None) -> list[str]:
    """Wrap ``argv`` so it runs as ``user`` without PAM; root runs it unchanged."""
    if user is None:
        return argv
    import pwd

    account = pwd.getpwnam(user)
    return [
        "/usr/bin/setpriv",
        f"--reuid={account.pw_uid}",
        f"--regid={account.pw_gid}",
        "--clear-groups",
        "--",
        *argv,
    ]


def _report_notice_failure(code: str) -> None:
    print(f"maintenance_notice_failure={code}", file=sys.stderr, flush=True)


def _notice_failure_code(result: subprocess.CompletedProcess[bytes]) -> str:
    """Classify a failed notice child by its bounded cause, else by how it died."""
    try:
        report = json.loads(result.stdout.decode("ascii"))
        observed = report.get("cause")
        if isinstance(observed, str) and re.fullmatch(
            r"(?:SQLITE_[A-Z0-9_]{1,56}|NON_SQLITE_ERROR)", observed,
        ):
            return observed
    except (UnicodeError, ValueError, AttributeError):
        pass
    return "INVALID_RESPONSE" + _child_failure_detail(result.returncode, result.stderr)


def _run(
    argv: list[str], *, input_bytes: bytes | None = None, timeout: int = 120,
    user: str | None = None, report_failure: bool = False,
) -> bytes:
    command = _command_as(argv, user)
    try:
        result = subprocess.run(  # nosec B603
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE if report_failure else subprocess.DEVNULL,
            check=False,
            timeout=timeout,
            env={
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "HTTP_PROXY": "",
                "HTTPS_PROXY": "",
                "ALL_PROXY": "",
                "NO_PROXY": "*",
                "PYTHONDONTWRITEBYTECODE": "1",
                "UV_LINK_MODE": "copy",
                "UV_NO_CACHE": "1",
                "UV_PYTHON_DOWNLOADS": "never",
            },
        )
    except (OSError, subprocess.SubprocessError) as error:
        if report_failure:
            _report_notice_failure(
                "TIMEOUT" if isinstance(error, subprocess.TimeoutExpired) else "EXECUTION_ERROR",
            )
        raise MaintenanceError("installation_failed") from None
    if result.returncode != 0 or len(result.stdout) > 65536:
        if report_failure:
            _report_notice_failure(_notice_failure_code(result))
        raise MaintenanceError("installation_failed")
    return result.stdout


def _operation_succeeded(status: UpdateStatus, operation_id: str, action: str) -> bool:
    """Whether the named operation has succeeded; raise once it settled any other way."""
    operation = status.operation
    if operation is None or operation.operation_id != operation_id:
        return False
    if operation.action != action:
        raise UpdateError("invalid_response")
    if operation.phase not in {"succeeded", "failed", "interrupted"}:
        return False
    if operation.phase != "succeeded":
        raise UpdateError(operation.error or "unknown_outcome")
    return True


async def _completed_update(
    client: UpdateClient,
    status: UpdateStatus,
    operation_id: str,
    action: str,
    timeout: int,
) -> UpdateStatus:
    deadline = time.monotonic() + timeout
    while True:
        if _operation_succeeded(status, operation_id, action):
            return status
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise UpdateError("timeout")
        await asyncio.sleep(min(1, remaining))
        status = await client.status(operation_id)


class PreparedReleaseGateway(ReleaseGateway):
    def __init__(self, config: RuntimeConfig):
        self.config = config

    def prepare_latest(self, *, actor_id: str) -> PreparedRelease | None:
        try:
            return asyncio.run(self._prepare(actor_id))
        except UpdateError:
            raise MaintenanceError("updater_unavailable") from None

    async def _prepare(self, actor_id: str) -> PreparedRelease | None:
        client = UpdateClient(
            self.config.updater_socket,
            allow_root_peer=True,
        )
        release_id = os.environ.get("STRUGGLEBUS_RELEASE_ID")
        running_version = active_application_version(self.config)
        reusable = self._reusable(await client.status(), running_version, release_id)
        if reusable is not None:
            return reusable
        limits = UpdateLimits()
        check_id = uuid4().hex
        checked = await _completed_update(
            client,
            await client.check(check_id, actor_id, running_version, release_id),
            check_id,
            "check",
            limits.check_timeout,
        )
        observation = checked.observation
        if observation is None or observation.discovery.candidate is None:
            return None
        reusable = self._reusable(checked, running_version, release_id)
        if reusable is not None:
            return reusable
        candidate = observation.discovery.candidate
        prepare_id = uuid4().hex
        prepared = await _completed_update(
            client,
            await client.prepare(
                prepare_id,
                actor_id,
                running_version,
                release_id,
                observation.observation_id,
                candidate.digest,
            ),
            prepare_id,
            "prepare",
            limits.prepare_timeout,
        )
        if (
            prepared.prepared is None
            or prepared.prepared.operation_id != prepare_id
            or prepared.prepared.candidate != candidate
        ):
            raise MaintenanceError("preparation_failed")
        directory = self.config.updater_cache_state / f"operation-{prepare_id}"
        return PreparedRelease(candidate.version, directory)

    def _reusable(
        self, status: UpdateStatus, running_version: str, release_id: str | None,
    ) -> PreparedRelease | None:
        # Prepared bytes are reused only for the candidate of a current,
        # unexpired observation; an old observation can predate a newer release.
        observation, prepared = status.observation, status.prepared
        if (
            observation is None
            or prepared is None
            or observation.application_version != running_version
            or observation.application_release_id != release_id
            or observation.discovery.candidate != prepared.candidate
            or not observation.checked_at <= int(time.time()) < observation.expires_at
        ):
            return None
        directory = self.config.updater_cache_state / f"operation-{prepared.operation_id}"
        if not directory.is_dir():
            return None
        return PreparedRelease(prepared.candidate.version, directory)


class BoardAnnouncer(MaintenanceAnnouncer):
    def __init__(self, config: RuntimeConfig):
        self.config = config

    def announce(
        self, release: PreparedRelease, *, operation_id: str,
        scheduled_at: int, automatic: bool,
    ) -> None:
        current_python = self.config.current_link / "venv/bin/python"
        argv = [
            str(current_python),
            "-I",
            "-c",
            ANNOUNCEMENT_SCRIPT,
            "--database",
            str(self.config.database),
            "--backup-dir",
            str(self.config.backup_dir),
            "--operation-id",
            operation_id,
            "--version",
            release.version,
            "--scheduled-at",
            str(scheduled_at),
        ]
        if automatic:
            argv.append("--automatic")
        deadline = time.monotonic() + 30
        while True:
            remaining = deadline - time.monotonic()
            try:
                _run(
                    argv,
                    timeout=max(1, min(30, int(remaining))),
                    user=self.config.service_user,
                    report_failure=True,
                )
                return
            except MaintenanceError as exc:
                remaining = deadline - time.monotonic()
                if exc.code != "installation_failed" or remaining <= 0:
                    raise
                time.sleep(min(1, remaining))


def _helper_content(bundle: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    stream = bundle.extractfile(member)
    if stream is None or not member.isfile() or member.size > FILE_BYTES:
        raise MaintenanceError("preparation_failed")
    content = stream.read(FILE_BYTES + 1)
    if len(content) != member.size:
        raise MaintenanceError("preparation_failed")
    return content


def _read_helpers(archive: Path) -> dict[str, bytes]:
    """Read every maintenance helper from the support archive, keyed by installed name."""
    contents: dict[str, bytes] = {}
    with tarfile.open(archive, "r:gz") as bundle:
        members = {member.name: member for member in bundle.getmembers()}
        if not set(HELPERS).issubset(members):
            raise MaintenanceError("preparation_failed")
        for source, name in HELPERS.items():
            contents[name] = _helper_content(bundle, members[source])
    return contents


def _ensure_root_directory(directory: Path) -> None:
    directory.mkdir(mode=0o755, exist_ok=True)
    metadata = directory.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0:
        raise MaintenanceError("installation_failed")
    directory.chmod(0o755)


def _write_missing_helpers(target: Path, contents: dict[str, bytes]) -> None:
    """Atomically add helpers not yet present; existing entries are verified, never replaced."""
    for name, content in contents.items():
        path = target / name
        if path.exists() or path.is_symlink():
            continue
        temporary = target / f".{name}.{uuid4().hex}"
        try:
            temporary.write_bytes(content)
            temporary.chmod(0o755)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def _install_marker(facts: dict[str, Any]) -> bytes:
    return (
        f"wheel_filename={Path(facts['wheel_src']).name}\n"
        f"wheel_sha256={facts['wheel_sha256']}\n"
        f"requirements_lock_sha256={facts['requirements_lock_sha256']}\n"
        "agent_access_freeze=global-v1\n"
    ).encode("ascii")


def _group_id(group: str | None) -> int:
    if group is None:
        return 0
    import pwd

    return pwd.getpwnam(group).pw_gid


def _apply_release_ownership(staging: Path, gid: int, *, private: bool) -> None:
    """Hand the staged tree to root and ``gid``, closed to other users when private."""
    directory_mode, file_mode = (0o750, 0o640) if private else (0o755, 0o644)
    executable_mode = directory_mode
    for path in [staging, *staging.rglob("*")]:
        os.chown(path, 0, gid)
        if path.is_dir():
            path.chmod(directory_mode)
        else:
            path.chmod(file_mode)
    for executable in (staging / "venv/bin").iterdir():
        if executable.is_file():
            executable.chmod(executable_mode)


class HostReleaseInstaller(ReleaseInstaller):
    helper_root = HELPER_ROOT

    def __init__(self, config: RuntimeConfig):
        self.config = config

    def install(self, release: PreparedRelease, *, operation_id: str) -> None:
        facts = self._validate_bundle(release)
        helper_root = self._materialize_helpers(release, facts)
        self._materialize_application(release, facts, operation_id)
        self._materialize_updater(release, facts, operation_id)
        release_lock = self._acquire_release_lock(helper_root)
        try:
            freeze_lock = self._acquire_freeze_lock(helper_root)
        except BaseException:
            # Do not leave the release lock held for its whole lease.
            self._release_lock(
                helper_root,
                Path("/run/lock/strugglebus/release.json"),
                str(release_lock["token"]),
            )
            raise
        try:
            request, unit = self._maintenance_request(
                release, facts, helper_root,
            )
            locks = [
                {
                    "metadata": "/run/lock/strugglebus/release.json",
                    "token": release_lock["token"],
                },
                {
                    "metadata": str(
                        Path(request["environment"]["STRUGGLEBUS_DATA_DIR"])
                        / ".access-freeze-lock/release.json"
                    ),
                    "token": freeze_lock["token"],
                },
            ]
            helper = helper_root / "strugglebus-maintenance"
            _run(
                [str(self.config.python), "-I", str(helper), "stage"],
                input_bytes=json.dumps(
                    {"request": request, "unit_content": unit, "locks": locks},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii"),
                timeout=120,
            )
            _run(
                [str(self.config.python), "-I", str(helper), "run"],
                input_bytes=json.dumps(
                    {"request": request, "locks": locks},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii"),
                timeout=min(900, self.config.release_lock_lease_seconds - 60),
            )
            self._activate_updater(release.version)
        finally:
            self._release_lock(
                helper_root,
                self.config.database.parent / ".access-freeze-lock/release.json",
                str(freeze_lock["token"]),
                user=self.config.service_user,
            )
            self._release_lock(
                helper_root,
                Path("/run/lock/strugglebus/release.json"),
                str(release_lock["token"]),
            )

    def _validate_bundle(self, release: PreparedRelease) -> dict[str, Any]:
        # Root does not take the updater worker's word that the release is the publisher's. It
        # reads the signed statement and checks the signature itself, before anything from the
        # release is written, run or imported.
        signed = self._signed_digests(release)
        try:
            facts = validate_bundle(
                release.directory,
                expected_repository="NZCypher819/strugglebus",
                expected_current_schema=LATEST_SCHEMA_VERSION,
                minimum_package_version=release.version,
                accept_newer_schema=True,
                statement_beside=True,
            )
        except Exception:
            raise MaintenanceError("preparation_failed") from None
        if facts["package_version"] != release.version:
            raise MaintenanceError("preparation_failed")
        # The hashes the validator just computed, which everything after this relies on, must be
        # the signed ones. So nothing later can use a file the publisher did not sign.
        if {asset["name"]: asset["sha256"] for asset in facts["release_assets"]} != signed:
            raise MaintenanceError("preparation_failed")
        return facts

    def _signed_digests(self, release: PreparedRelease) -> dict[str, str]:
        """The file hashes a pinned release key signed for this version, which must be a newer one."""
        try:
            statement = _read_statement(release.directory / STATEMENT_NAME)
            signed = signed_digests(statement, release.version)
        except (OSError, ValueError, ReleaseSignatureError):
            raise MaintenanceError("preparation_failed") from None
        # The signature ties these files to this version, so a version that is not newer than
        # the one running is an old release offered again.
        if _version_key(release.version) <= _version_key(active_application_version(self.config)):
            raise MaintenanceError("preparation_failed")
        return signed

    def _materialize_helpers(
        self, release: PreparedRelease, facts: dict[str, Any],
    ) -> Path:
        archive = release.directory / SUPPORT_NAME_TEMPLATE.format(version=release.version)
        contents = _read_helpers(archive)
        hashes = {name: hashlib.sha256(content).hexdigest() for name, content in contents.items()}
        identity = hashlib.sha256(
            "".join(hashes[name] for name in BUNDLE_HELPERS).encode("ascii"),
        ).hexdigest()
        target = self.helper_root / identity
        # The application's operator guard and the unprivileged lock helper read
        # this tree, so it must stay root-owned and traversable despite UMask=0077.
        for directory in (self.helper_root, target):
            _ensure_root_directory(directory)
        _write_missing_helpers(target, contents)
        self._verify_helpers(target, hashes)
        return target

    @staticmethod
    def _verify_helpers(
        directory: Path, hashes: dict[str, str] | None = None,
    ) -> None:
        for name in HELPERS.values():
            metadata = (directory / name).lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o755
                or (hashes is not None and _sha256(directory / name) != hashes[name])
            ):
                raise MaintenanceError("installation_failed")

    def _materialize_application(
        self, release: PreparedRelease, facts: dict[str, Any], operation_id: str,
    ) -> None:
        self._materialize_environment(
            release,
            facts,
            operation_id,
            self.config.release_root,
            group=self.config.service_user,
            private=True,
        )

    def _materialize_updater(
        self, release: PreparedRelease, facts: dict[str, Any], operation_id: str,
    ) -> None:
        self._materialize_environment(
            release,
            facts,
            operation_id,
            self.config.updater_release_root,
            group=None,
            private=False,
        )

    def _materialize_environment(
        self,
        release: PreparedRelease,
        facts: dict[str, Any],
        operation_id: str,
        root: Path,
        *,
        group: str | None,
        private: bool,
    ) -> None:
        target = root / release.version
        marker = _install_marker(facts)
        if target.exists():
            installed = _read_regular(target / ".installed", 4096)
            if installed != marker and not _bootstrap_marker_matches(installed, release.version, facts):
                raise MaintenanceError("installation_failed")
            return
        root.mkdir(mode=0o755, parents=True, exist_ok=True)
        staging = root / f".{release.version}.maintenance-{operation_id}"
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(mode=0o750 if private else 0o755)
        try:
            self._build_environment(staging, release, facts)
            (staging / ".installed").write_bytes(marker)
            _retarget_scripts(staging / "venv", target / "venv")
            _apply_release_ownership(staging, _group_id(group), private=private)
            os.replace(staging, target)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise

    def _build_environment(
        self, staging: Path, release: PreparedRelease, facts: dict[str, Any],
    ) -> None:
        """Populate ``staging`` with the pinned artifacts and their hash-locked venv."""
        wheel = Path(facts["wheel_src"])
        lock = Path(facts["requirements_lock_src"])
        shutil.copyfile(wheel, staging / wheel.name, follow_symlinks=False)
        shutil.copyfile(lock, staging / "requirements.lock", follow_symlinks=False)
        (staging / "release.env").write_text(
            f"STRUGGLEBUS_RELEASE_ID={release.version}\n",
            encoding="ascii",
            newline="\n",
        )
        _run([
            str(self.config.python), "-I", "-m", "venv", "--copies",
            str(staging / "venv"),
        ])
        _run([
            str(self.config.uv), "--no-config", "pip", "sync",
            "--python", str(staging / "venv/bin/python"),
            "--require-hashes", "--only-binary", ":all:",
            str(staging / "requirements.lock"),
        ], timeout=600)
        _run([
            str(self.config.uv), "--no-config", "pip", "install",
            "--python", str(staging / "venv/bin/python"),
            "--no-deps", "--no-index", "--no-build", "--reinstall",
            str(staging / wheel.name),
        ], timeout=180)

    def _acquire_release_lock(self, helper_root: Path) -> dict[str, Any]:
        return self._acquire_lock(
            helper_root,
            Path("/run/lock/strugglebus/release.lock"),
            Path("/run/lock/strugglebus/release.json"),
        )

    def _acquire_freeze_lock(self, helper_root: Path) -> dict[str, Any]:
        return self._acquire_lock(
            helper_root,
            self.config.database.parent / ".access-freeze-lock/transition.lock",
            self.config.database.parent / ".access-freeze-lock/release.json",
            user=self.config.service_user,
        )

    def _acquire_lock(
        self, helper_root: Path, lock: Path, metadata: Path, *,
        user: str | None = None,
    ) -> dict[str, Any]:
        output = _run([
            str(self.config.python),
            "-I",
            str(helper_root / "strugglebus-release-lock"),
            "acquire",
            "--lock-path",
            str(lock),
            "--metadata-path",
            str(metadata),
            "--wait-seconds",
            str(self.config.release_lock_wait_seconds),
            "--lease-seconds",
            str(self.config.release_lock_lease_seconds),
        ], timeout=self.config.release_lock_wait_seconds + 5, user=user)
        try:
            value = json.loads(output.decode("ascii"))
        except (UnicodeError, ValueError):
            raise MaintenanceError("installation_failed") from None
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("token"), str)
            or re.fullmatch(r"[0-9a-f]{64}", value["token"]) is None
        ):
            raise MaintenanceError("installation_failed")
        return value

    def _release_lock(
        self, helper_root: Path, metadata: Path, token: str, *,
        user: str | None = None,
    ) -> None:
        try:
            _run([
                str(self.config.python),
                "-I",
                str(helper_root / "strugglebus-release-lock"),
                "release",
                "--metadata-path",
                str(metadata),
                "--token",
                token,
            ], timeout=10, user=user)
        except MaintenanceError:
            pass

    def _maintenance_request(
        self,
        release: PreparedRelease,
        facts: dict[str, Any],
        helper_root: Path,
    ) -> tuple[dict[str, Any], str]:
        unit = _read_regular(self.config.service_unit, 65536, uid=0, mode=0o644)
        candidate_python = self.config.release_root / release.version / "venv/bin/python"
        validator = helper_root / "strugglebus-validate-maintenance-config"
        probe = _run([
            str(self.config.python),
            "-I",
            str(validator),
            "--unit-stdin",
            "--candidate-python",
            str(candidate_python),
            "--release-id",
            release.version,
        ], input_bytes=unit, timeout=60, user=self.config.service_user)
        credential = _run([
            str(self.config.python),
            "-I",
            str(helper_root / "strugglebus-maintenance"),
            "credential",
        ], input_bytes=json.dumps(
            {"unit_content": unit.decode("ascii")},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii"))
        try:
            candidate = json.loads(probe.decode("ascii"))
            operator = json.loads(credential.decode("ascii"))
        except (UnicodeError, ValueError):
            raise MaintenanceError("installation_failed") from None
        config_hash = hashlib.sha256(unit).hexdigest()
        request = {
            "release_root": str(self.config.release_root),
            "state_dir": str(self.config.maintenance_root),
            "backup_dir": str(self.config.backup_dir),
            "database": str(self.config.database),
            "unit": str(self.config.service_unit),
            "current": str(self.config.current_link),
            "candidate_config": str(
                self.config.maintenance_root / f"candidate-{config_hash}.service"
            ),
            "helper_root": str(helper_root),
            "helper_sha256": {
                name: _sha256(helper_root / name)
                for name in HELPERS.values()
                if name != "strugglebus-release-lock"
            },
            "candidate": release.version,
            "candidate_schema": candidate["candidate_schema"],
            "config_sha256": config_hash,
            "marker": {
                "wheel_filename": Path(facts["wheel_src"]).name,
                "wheel_sha256": facts["wheel_sha256"],
                "requirements_lock_sha256": facts["requirements_lock_sha256"],
                "agent_access_freeze": "global-v1",
            },
            "environment": candidate["environment"],
            "service_user": self.config.service_user,
            "app_module": "strugglebus.app",
            "bind_port": int(candidate["environment"]["STRUGGLEBUS_BIND_PORT"]),
            "health_url": self.config.health_url,
            "ca_path": str(self.config.ca_path),
            "operator_credential": operator["operator_credential"],
        }
        return request, unit.decode("ascii")

    def _activate_updater(self, version: str) -> None:
        target = self.config.updater_release_root / version
        previous = self.config.updater_current_link.resolve(strict=True)
        temporary = self.config.updater_current_link.with_name(
            f".{self.config.updater_current_link.name}.{uuid4().hex}",
        )
        temporary.symlink_to(target, target_is_directory=True)
        os.replace(temporary, self.config.updater_current_link)
        try:
            for unit in (
                "strugglebus-updater.service",
                "strugglebus-maintenance.service",
            ):
                _run([
                    str(self.config.systemctl),
                    "restart",
                    unit,
                ], timeout=30)
            _run([
                str(self.config.systemctl),
                "is-active",
                "--quiet",
                "strugglebus-updater.service",
            ], timeout=10)
        except MaintenanceError:
            rollback = self.config.updater_current_link.with_name(
                f".{self.config.updater_current_link.name}.{uuid4().hex}",
            )
            rollback.symlink_to(previous, target_is_directory=True)
            os.replace(rollback, self.config.updater_current_link)
            for unit in (
                "strugglebus-updater.service",
                "strugglebus-maintenance.service",
            ):
                try:
                    _run([
                        str(self.config.systemctl),
                        "restart",
                        unit,
                    ], timeout=30)
                except MaintenanceError:
                    pass
            raise
