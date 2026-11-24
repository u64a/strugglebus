"""Delegated, process-held fence for the protected operator launcher."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

from strugglebus.config import _systemd_credential_context, _validate_credential_metadata
from strugglebus.errors import ConfigurationError

CONTROL_PATH = Path("/run/lock/strugglebus/control.lock")
METADATA_PATH = Path("/run/lock/strugglebus/release.json")
DESCRIPTOR_NAMES = ("operator-control", "operator-metadata")
EXPECTED_CREDENTIAL = "operator-lease"
MAX_BINDING_BYTES = 4096
FENCE_WAIT_SECONDS = 30
_ROOT_UID = 0
# systemd hands over delegated descriptors starting here (SD_LISTEN_FDS_START).
_LISTEN_FDS_START = 3


def _error() -> ConfigurationError:
    return ConfigurationError("protected operator release delegation is unavailable")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _error()
        result[key] = value
    return result


_LEASE_FIELDS = frozenset({
    "version", "pid", "start_ticks", "token", "lease_seconds", "heartbeat_ns",
})
_POSITIVE_LEASE_FIELDS = ("pid", "start_ticks", "lease_seconds", "heartbeat_ns")


def _decode_lease(raw: bytes) -> object:
    try:
        return json.loads(raw.decode("ascii"), object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise _error() from None


def _is_version_one_lease(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == _LEASE_FIELDS
        and type(value["version"]) is int and value["version"] == 1
    )


def _lease_numbers_are_valid(value: dict) -> bool:
    for name in _POSITIVE_LEASE_FIELDS:
        if type(value[name]) is not int or value[name] <= 0:
            return False
    return value["pid"] > 1


def _lease_token_is_valid(value: dict) -> bool:
    token = value["token"]
    return isinstance(token, str) and re.fullmatch(r"[0-9a-f]{64}", token) is not None


def parse_lease(raw: bytes) -> dict:
    if len(raw) > MAX_BINDING_BYTES:
        raise _error()
    value = _decode_lease(raw)
    if (
        not _is_version_one_lease(value)
        or not _lease_numbers_are_valid(value)
        or not _lease_token_is_valid(value)
    ):
        raise _error()
    return value


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _is_private_root_file(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode) and info.st_uid == _ROOT_UID
        and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
    )


def _is_plain_read_only(flags: int) -> bool:
    return flags & os.O_ACCMODE == os.O_RDONLY and not flags & getattr(os, "O_PATH", 0)


def _require_private_root_directory(directory: Path) -> None:
    parent = directory.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode) or parent.st_uid != _ROOT_UID
        or stat.S_IMODE(parent.st_mode) != 0o700
        or directory.resolve(strict=True) != directory
    ):
        raise _error()


def _descriptor(descriptor: int, path: Path) -> os.stat_result:
    import fcntl

    info = os.fstat(descriptor)
    flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    if (
        not _is_private_root_file(info)
        or not _is_plain_read_only(flags)
        or os.readlink(f"/proc/self/fd/{descriptor}") != str(path)
    ):
        raise _error()
    _require_private_root_directory(path.parent)
    return info


def _credential_directory() -> Path:
    directory_text = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if re.fullmatch(
        r"/run/credentials/strugglebus-operator-[0-9a-f]{32}\.service",
        directory_text,
    ) is None:
        raise _error()
    return Path(directory_text)


def _expected_binding() -> dict:
    directory = _credential_directory()
    path = directory / EXPECTED_CREDENTIAL
    runtime_uid, projection = _systemd_credential_context(
        path, str(directory), runtime_uid=os.geteuid(),
    )
    if runtime_uid is None:
        raise _error()
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise _error()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        return parse_lease(_read_unchanged_binding(
            descriptor, path, before, runtime_uid=runtime_uid, projection=projection,
        ))
    finally:
        os.close(descriptor)


def _read_unchanged_binding(
    descriptor: int, path: Path, before: os.stat_result,
    *, runtime_uid: int, projection: bool,
) -> bytes:
    info = os.fstat(descriptor)
    _validate_credential_metadata(
        info, require_root_owner=True, runtime_uid=runtime_uid,
        protected_systemd_projection=projection,
    )
    if (
        _identity(info) != _identity(before) or info.st_nlink != 1
        or info.st_size > MAX_BINDING_BYTES or path.resolve(strict=True) != path
    ):
        raise _error()
    raw = os.read(descriptor, MAX_BINDING_BYTES + 1)
    after = os.fstat(descriptor)
    if (
        (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        or _identity(path.lstat()) != _identity(info)
    ):
        raise _error()
    return raw


def _start_ticks_from_stat(raw: bytes) -> int:
    if len(raw) > 4096:
        raise _error()
    tail = raw.rsplit(b")", 1)
    if len(tail) != 2:
        raise _error()
    fields = tail[1].split()
    if len(fields) < 20 or fields[0] in {b"Z", b"X"}:
        raise _error()
    return int(fields[19])


def _process_start_ticks(pid: int) -> int:
    with Path(f"/proc/{pid}/stat").open("rb") as source:
        raw = source.read(4097)
    return _start_ticks_from_stat(raw)


def _claim_activation() -> dict[str, int]:
    """Consume the systemd activation variables that name both descriptors."""
    activation = {
        name: os.environ.pop(name, None)
        for name in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES")
    }
    if (
        activation["LISTEN_PID"] != str(os.getpid()) or activation["LISTEN_FDS"] != "2"
        or activation["LISTEN_FDNAMES"] is None
    ):
        raise _error()
    names = activation["LISTEN_FDNAMES"].split(":")
    if len(names) != 2 or set(names) != set(DESCRIPTOR_NAMES):
        raise _error()
    return dict(zip(names, (_LISTEN_FDS_START, _LISTEN_FDS_START + 1), strict=True))


def _take_control_lock(control: int, cleanup: ExitStack) -> None:
    import fcntl

    deadline = time.monotonic() + FENCE_WAIT_SECONDS
    while True:
        try:
            fcntl.flock(control, fcntl.LOCK_EX | fcntl.LOCK_NB)
            cleanup.callback(fcntl.flock, control, fcntl.LOCK_UN)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise _error()
            time.sleep(0.05)


def _lease_matches_binding(current: dict, expected: dict) -> bool:
    if not hmac.compare_digest(current["token"], expected["token"]):
        return False
    return all(current[name] == expected[name] for name in current if name != "token")


def _heartbeat_is_fresh(current: dict) -> bool:
    age = time.monotonic_ns() - current["heartbeat_ns"]
    return 0 <= age < current["lease_seconds"] * 1_000_000_000


def _require_live_lease(control: int, metadata: int, cleanup: ExitStack) -> None:
    before_control = _descriptor(control, CONTROL_PATH)
    before_metadata = _descriptor(metadata, METADATA_PATH)
    expected = _expected_binding()
    _take_control_lock(control, cleanup)
    # A descriptor may still read an unlinked or renamed old lease. Check
    # its live kernel pathname and link count only after taking the fence.
    current_control = _descriptor(control, CONTROL_PATH)
    current_metadata = _descriptor(metadata, METADATA_PATH)
    if (
        _identity(before_control) != _identity(current_control)
        or _identity(before_metadata) != _identity(current_metadata)
        or current_metadata.st_size > MAX_BINDING_BYTES
    ):
        raise _error()
    os.lseek(metadata, 0, os.SEEK_SET)
    current = parse_lease(os.read(metadata, MAX_BINDING_BYTES + 1))
    if (
        not _lease_matches_binding(current, expected)
        or _process_start_ticks(current["pid"]) != current["start_ticks"]
        or not _heartbeat_is_fresh(current)
        or _identity(_descriptor(metadata, METADATA_PATH)) != _identity(current_metadata)
    ):
        raise _error()


@contextmanager
def delegated_release_fence():
    """Hold canonical control.lock in the mutator until synchronous cleanup ends."""
    if sys.platform != "linux":
        raise _error()
    descriptors = _claim_activation()
    with ExitStack() as cleanup:
        try:
            for descriptor in descriptors.values():
                os.set_inheritable(descriptor, False)
                cleanup.callback(os.close, descriptor)
            _require_live_lease(
                descriptors["operator-control"], descriptors["operator-metadata"], cleanup,
            )
        except (OSError, ValueError, RuntimeError):
            raise _error() from None
        yield
