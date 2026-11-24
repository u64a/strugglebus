"""Human-only verifier setup, independent of the running web credential."""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import re
import stat
# Only the checksum-verified retained helper runs, with fixed shell-free status argv.
import subprocess  # nosec B404
import warnings
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, TextIO
from uuid import uuid4

from strugglebus.errors import ConfigurationError
from strugglebus.operator_auth import create_password_verifier, password_bytes
from strugglebus.private_files import (
    open_private_output, read_private_file, require_private_path,
)

# Stable state filenames, not password material or authentication values.
PASSWORD_CONTROL_FILE = ".operator-password.control"  # nosec B105
PASSWORD_AUTHORIZATION_FILE = ".operator-password.authorization"  # nosec B105
MAINTENANCE_STATE_DIRECTORY = Path("/var/lib/strugglebus-maintenance")
MAINTENANCE_HELPER_ROOT = Path("/usr/local/libexec/strugglebus-maintenance")
MAINTENANCE_HELPERS = (
    "strugglebus-maintenance", "strugglebus-validate-maintenance-config",
    "strugglebus-inspect-access-freeze", "strugglebus-sqlite-backup",
)


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError("duplicate maintenance or authorization field")
        result[key] = value
    return result


def _json_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def require_terminal(stdin: TextIO) -> None:
    if not stdin.isatty():
        raise ConfigurationError("operator controls require a real interactive terminal")


def require_root_terminal(stdin: TextIO) -> None:
    require_terminal(stdin)
    if os.name != "posix" or os.geteuid() != 0:
        raise ConfigurationError("operator password setup requires the local Linux root operator")


def terminal_line(stdin: TextIO, stdout: TextIO, prompt: str, *, maximum: int) -> str:
    stdout.write(prompt)
    stdout.flush()
    value = stdin.readline(maximum + 2)
    if not value or not value.endswith("\n") or len(value.rstrip("\r\n")) > maximum:
        raise ConfigurationError("operator input ended or exceeded its limit")
    value = value.rstrip("\r\n")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ConfigurationError("operator input contains control characters")
    return value


@contextmanager
def password_source_lock(directory: Path) -> Iterator[None]:
    """The maintenance root helper uses this same stable source-directory lock."""
    import fcntl

    require_private_path(directory, directory=True, outside_repository=True)
    path = directory / PASSWORD_CONTROL_FILE
    descriptor = os.open(
        path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        0o600,
    )
    try:
        require_private_path(path, directory=False, outside_repository=True)
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            raise ConfigurationError("operator password control changed")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ConfigurationError("operator password source is in use") from None
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _is_absent(path: Path) -> bool:
    return not path.exists() and not path.is_symlink()


def _require_no_unjournaled_evidence(state_directory: Path) -> None:
    with os.scandir(state_directory) as entries:
        if next(entries, None) is not None:
            raise ConfigurationError(
                "maintenance state contains evidence without an operation journal"
            )


def _retained_binding(retained: object) -> dict:
    if not isinstance(retained, dict) or not isinstance(retained.get("binding"), dict):
        raise ConfigurationError("maintenance binding is unavailable")
    return retained["binding"]


def _is_sha256_hex(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _helper_hashes(binding: dict) -> dict:
    hashes = binding.get("helper_sha256")
    if (
        not isinstance(hashes, dict) or set(hashes) != set(MAINTENANCE_HELPERS)
        or not all(_is_sha256_hex(value) for value in hashes.values())
    ):
        raise ConfigurationError("maintenance helper binding is invalid")
    return hashes


def _content_addressed_helper(binding: dict, hashes: dict, helper_root: Path) -> Path:
    bundle = hashlib.sha256(
        "".join(hashes[name] for name in MAINTENANCE_HELPERS).encode("ascii"),
    ).hexdigest()
    directory = helper_root / bundle
    if binding.get("helper_root") != str(directory):
        raise ConfigurationError("maintenance helper is not content-addressed")
    return directory / "strugglebus-maintenance"


def _require_root_protected_ancestors(helper: Path) -> None:
    for ancestor in helper.parents:
        metadata = ancestor.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0 or metadata.st_mode & 0o022
            or ancestor.resolve(strict=True) != ancestor
        ):
            raise ConfigurationError("maintenance helper directory is unsafe")


def _require_root_protected_helper(helper: Path) -> None:
    metadata = helper.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0 or metadata.st_mode & 0o022
        or metadata.st_nlink != 1 or metadata.st_size > 1_048_576
        or helper.resolve(strict=True) != helper
    ):
        raise ConfigurationError("maintenance status helper is unsafe")


def _require_helper_provenance(helper: Path, expected_sha256: str) -> None:
    with helper.open("rb") as stream:
        source = stream.read(1_048_577)
    if hashlib.sha256(source).hexdigest() != expected_sha256:
        raise ConfigurationError("maintenance status helper provenance changed")


def _verified_status_helper(binding: dict, helper_root: Path) -> Path:
    hashes = _helper_hashes(binding)
    helper = _content_addressed_helper(binding, hashes, helper_root)
    _require_root_protected_ancestors(helper)
    _require_root_protected_helper(helper)
    _require_helper_provenance(helper, hashes["strugglebus-maintenance"])
    return helper


def _maintenance_status(helper: Path, state_directory: Path) -> object:
    # Root-protected canonical helper/hash checked above; fixed interpreter and subcommand.
    result = subprocess.run(  # nosec B603
        [
            "/usr/bin/python3.13", "-I", str(helper), "status", "--verify",
            "--state-dir", str(state_directory),
        ],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=90, check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )
    if result.returncode != 0 or len(result.stdout) > 65_536:
        raise ConfigurationError("maintenance status could not be established")
    return json.loads(result.stdout, object_pairs_hook=_unique_object)


def _verified_operation_id(payload: object, retained: dict) -> str | None:
    """The completed operation the status helper vouches for, if it is the retained one."""
    if not isinstance(payload, dict) or payload.get("state") != "complete":
        raise ConfigurationError("resolve pending maintenance before password setup or reset")
    operation_id = payload.get("operation_id")
    if (
        payload.get("provenance") != "verified"
        or not isinstance(operation_id, str)
        or not re.fullmatch(r"[0-9a-f]{32}", operation_id)
        or operation_id != retained.get("operation_id")
    ):
        return None
    return operation_id


def _completed_maintenance(
    record: Path, state_directory: Path, helper_root: Path,
) -> dict:
    retained_raw = read_private_file(record, maximum=65_536)
    retained = json.loads(retained_raw, object_pairs_hook=_unique_object)
    binding = _retained_binding(retained)
    helper = _verified_status_helper(binding, helper_root)
    payload = _maintenance_status(helper, state_directory)
    operation_id = _verified_operation_id(payload, retained)
    if operation_id is None or read_private_file(record, maximum=65_536) != retained_raw:
        raise ConfigurationError("maintenance status changed during password authorization")
    return {
        "operation_id": operation_id,
        "binding_sha256": hashlib.sha256(_json_bytes(binding)).hexdigest(),
    }


def require_resolved_maintenance(
    *, state_directory: Path = MAINTENANCE_STATE_DIRECTORY,
    helper_root: Path = MAINTENANCE_HELPER_ROOT,
) -> dict | None:
    if _is_absent(state_directory):
        return
    require_private_path(state_directory, directory=True)
    record = state_directory / "operation.json"
    try:
        if _is_absent(record):
            _require_no_unjournaled_evidence(state_directory)
            return
        return _completed_maintenance(record, state_directory, helper_root)
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError, RecursionError):
        raise ConfigurationError("maintenance status could not be established") from None


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("operator credential publication did not progress")
        view = view[written:]


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _fsync_directory(directory: Path) -> None:
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _discard_unpublished(destination: Path, opened: os.stat_result) -> None:
    if destination.exists() and _same_file(destination.lstat(), opened):
        destination.unlink()


def _publish_private(path: Path, content: bytes, *, original: os.stat_result | None) -> None:
    destination = path if original is None else path.with_name(f".operator-reset-{uuid4().hex}")
    descriptor = open_private_output(destination)
    opened = os.fstat(descriptor)
    replaced = False
    try:
        _write_all(descriptor, content)
        os.fsync(descriptor)
        require_private_path(destination, directory=False, outside_repository=True)
        if not _same_file(destination.lstat(), opened):
            raise ConfigurationError("operator credential destination changed")
        if original is not None:
            if not _same_file(path.lstat(), original):
                raise ConfigurationError("operator credential changed during publication")
            os.replace(destination, path)
        _fsync_directory(path.parent)
        replaced = True
    finally:
        os.close(descriptor)
        if not replaced:
            _discard_unpublished(destination, opened)


def _refuse_environment_passwords() -> None:
    if any(name in os.environ for name in (
        "STRUGGLEBUS_OPERATOR_PASSWORD", "STRUGGLEBUS_OPERATOR_PASSWORD_HASH",
        "STRUGGLEBUS_OPERATOR_SECRET",
    )):
        raise ConfigurationError("operator passwords must not be supplied through environment values")


def _existing_private_0600(path: Path, message: str) -> os.stat_result:
    require_private_path(path, directory=False, outside_repository=True)
    original = path.lstat()
    if stat.S_IMODE(original.st_mode) != 0o600:
        raise ConfigurationError(message)
    return original


def _existing_receipt(authorization_path: Path) -> os.stat_result | None:
    if _is_absent(authorization_path):
        return None
    return _existing_private_0600(
        authorization_path, "operator authorization receipt must be root-owned 0600",
    )


def _existing_verifier(path: Path, *, reset: bool) -> os.stat_result | None:
    if reset:
        return _existing_private_0600(path, "operator verifier source must be root-owned 0600")
    if not _is_absent(path):
        raise ConfigurationError("operator verifier already exists; use explicit reset")
    return None


def _prompt_new_verifier(stderr: TextIO) -> bytes:
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            password = getpass.getpass("New operator password: ", stream=stderr)
            confirmation = getpass.getpass("Confirm operator password: ", stream=stderr)
        except (getpass.GetPassWarning, EOFError):
            raise ConfigurationError("a working no-echo terminal is required") from None
    if not hmac.compare_digest(password_bytes(password), password_bytes(confirmation)):
        raise ConfigurationError("operator passwords did not match")
    return create_password_verifier(password)


def _publish_authorization(
    authorization_path: Path, authorization: dict, *, original: os.stat_result | None,
) -> None:
    try:
        _publish_private(authorization_path, _json_bytes(authorization), original=original)
    except (OSError, ConfigurationError):
        raise ConfigurationError(
            "operator verifier changed but authorization receipt failed; "
            "rerun explicit password reset before maintenance"
        ) from None


def setup_password(
    path: Path, *, reset: bool, stdin: TextIO, stderr: TextIO,
) -> None:
    require_root_terminal(stdin)
    _refuse_environment_passwords()
    if path.name in {PASSWORD_CONTROL_FILE, PASSWORD_AUTHORIZATION_FILE}:
        raise ConfigurationError("operator credential path is reserved for protected control state")
    with password_source_lock(path.parent):
        maintenance = require_resolved_maintenance()
        authorization_path = path.parent / PASSWORD_AUTHORIZATION_FILE
        authorization_original = _existing_receipt(authorization_path)
        original = _existing_verifier(path, reset=reset)
        verifier = _prompt_new_verifier(stderr)
        # Recheck after human input: a maintenance operation must not begin in
        # the gap before the new source-directory fence has been deployed.
        if require_resolved_maintenance() != maintenance:
            raise ConfigurationError("maintenance changed during password authorization")
        _publish_private(path, verifier, original=original)
        authorization = {
            "version": 1, "source": str(path),
            "verifier_sha256": hashlib.sha256(verifier).hexdigest(),
            "maintenance_operation_id": maintenance["operation_id"] if maintenance else None,
            "maintenance_binding_sha256": maintenance["binding_sha256"] if maintenance else None,
        }
        _publish_authorization(
            authorization_path, authorization, original=authorization_original,
        )
        stderr.write(
            "Operator verifier installed. Existing browser sessions and the old "
            "login password are invalidated only after the documented controlled "
            "service restart. No freeze or agent state was changed.\n"
        )
