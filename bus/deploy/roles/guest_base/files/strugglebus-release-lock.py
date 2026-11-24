#!/usr/bin/python3.13
"""Hold and release the process-owned Strugglebus deployment lock."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import select
import secrets
import signal
import stat
import sys
import time


METADATA_VERSION = 1
MAX_METADATA_BYTES = 4096
TOKEN_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class LockError(RuntimeError):
    pass


def process_start_ticks(pid: int) -> int | None:
    try:
        content = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except (FileNotFoundError, ProcessLookupError):
        return None
    close_paren = content.rfind(")")
    if close_paren < 0:
        raise LockError("malformed process stat data")
    fields = content[close_paren + 2 :].split()
    if len(fields) < 20:
        raise LockError("incomplete process stat data")
    return int(fields[19])


def parse_metadata(path: Path) -> dict[str, object] | None:
    require_private_directory(path.parent)
    try:
        file_stat = path.lstat()
    except FileNotFoundError:
        return None
    require_private_regular(file_stat, "lock metadata")
    if file_stat.st_size > MAX_METADATA_BYTES:
        raise LockError("lock metadata must be a bounded regular file")
    try:
        value = json.loads(path.read_text(encoding="ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LockError("lock metadata is malformed") from error
    if not isinstance(value, dict) or set(value) != {
        "version",
        "pid",
        "start_ticks",
        "token",
        "lease_seconds",
        "heartbeat_ns",
    }:
        raise LockError("lock metadata schema is invalid")
    if value["version"] != METADATA_VERSION:
        raise LockError("lock metadata version is unsupported")
    for name in ("pid", "start_ticks", "lease_seconds", "heartbeat_ns"):
        if not isinstance(value[name], int) or isinstance(value[name], bool):
            raise LockError(f"lock metadata {name} must be an integer")
    if (
        value["pid"] <= 1
        or value["start_ticks"] <= 0
        or value["heartbeat_ns"] <= 0
    ):
        raise LockError("lock metadata process identity is invalid")
    if not isinstance(value["token"], str) or not TOKEN_PATTERN.fullmatch(
        value["token"]
    ):
        raise LockError("lock metadata token is invalid")
    return value


def owner_is_live(metadata: dict[str, object]) -> bool:
    pid = int(metadata["pid"])
    return process_start_ticks(pid) == metadata["start_ticks"]


def write_metadata(path: Path, metadata: dict[str, object]) -> None:
    require_private_directory(path.parent)
    temporary = path.with_name(f".{path.name}.{metadata['token']}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        payload = json.dumps(metadata, sort_keys=True, separators=(",", ":"))
        with os.fdopen(descriptor, "w", encoding="ascii", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def require_private_directory(path: Path) -> None:
    try:
        directory_stat = path.lstat()
    except FileNotFoundError as error:
        raise LockError("release lock directory is missing") from error
    if (
        not stat.S_ISDIR(directory_stat.st_mode)
        or directory_stat.st_uid != os.geteuid()
        or stat.S_IMODE(directory_stat.st_mode) != 0o700
    ):
        raise LockError("release lock directory must be owner-only")


def require_private_regular(file_stat: os.stat_result, name: str) -> None:
    if (
        not stat.S_ISREG(file_stat.st_mode)
        or file_stat.st_uid != os.geteuid()
        or stat.S_IMODE(file_stat.st_mode) & 0o077
        or file_stat.st_nlink != 1
    ):
        raise LockError(f"{name} must be an owner-only regular file")


def remove_owned_metadata(path: Path, token: str) -> None:
    try:
        metadata = parse_metadata(path)
    except LockError:
        return
    if metadata is not None and metadata["token"] == token:
        path.unlink(missing_ok=True)


def open_lock(path: Path) -> int:
    require_private_directory(path.parent)
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
        0o600,
    )
    file_stat = os.fstat(descriptor)
    try:
        require_private_regular(file_stat, "release lock")
    except LockError:
        os.close(descriptor)
        raise
    return descriptor


def hold_lock(
    lock_path: Path,
    metadata_path: Path,
    token: str,
    wait_seconds: int,
    lease_seconds: int,
    status_fd: int,
) -> None:
    os.setsid()
    null_fd = os.open(os.devnull, os.O_RDWR)
    for descriptor in (0, 1, 2):
        os.dup2(null_fd, descriptor)
    if null_fd > 2:
        os.close(null_fd)

    lock_fd = -1
    control_fd = -1
    acquired = False
    try:
        lock_fd = open_lock(lock_path)
        control_fd = open_lock(metadata_path.with_name("control.lock"))
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise LockError("timed out waiting for the release lock")
                time.sleep(0.05)

        fcntl.flock(control_fd, fcntl.LOCK_EX)
        try:
            previous = parse_metadata(metadata_path)
            if previous is not None and owner_is_live(previous):
                raise LockError("live lock metadata exists without the kernel lock")

            pid = os.getpid()
            start_ticks = process_start_ticks(pid)
            if start_ticks is None:
                raise LockError("could not verify the lock holder process")
            metadata: dict[str, object] = {
                "version": METADATA_VERSION,
                "pid": pid,
                "start_ticks": start_ticks,
                "token": token,
                "lease_seconds": lease_seconds,
                "heartbeat_ns": time.monotonic_ns(),
            }
            write_metadata(metadata_path, metadata)
        finally:
            fcntl.flock(control_fd, fcntl.LOCK_UN)
        os.write(
            status_fd,
            ("OK " + json.dumps(metadata, separators=(",", ":"))).encode("ascii"),
        )
        os.close(status_fd)
        status_fd = -1

        stopping = False

        def stop_holder(_signum: int, _frame: object) -> None:
            nonlocal stopping
            stopping = True

        signal.signal(signal.SIGTERM, stop_holder)
        signal.signal(signal.SIGINT, stop_holder)
        while not stopping:
            fcntl.flock(control_fd, fcntl.LOCK_EX)
            try:
                current = parse_metadata(metadata_path)
                expired = (
                    current is None
                    or current["token"] != token
                    or current["pid"] != pid
                    or current["start_ticks"] != start_ticks
                    or time.monotonic_ns() - int(current["heartbeat_ns"])
                    >= lease_seconds * 1_000_000_000
                )
                if expired:
                    remove_owned_metadata(metadata_path, token)
            finally:
                fcntl.flock(control_fd, fcntl.LOCK_UN)
            if expired:
                break
            time.sleep(0.1)
    except (LockError, OSError, ValueError) as error:
        if status_fd >= 0:
            try:
                os.write(status_fd, f"ERROR {error}".encode("ascii", "replace"))
            except BrokenPipeError:
                pass
    finally:
        if control_fd >= 0:
            fcntl.flock(control_fd, fcntl.LOCK_EX)
            try:
                remove_owned_metadata(metadata_path, token)
            finally:
                fcntl.flock(control_fd, fcntl.LOCK_UN)
        if acquired:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        if lock_fd >= 0:
            os.close(lock_fd)
        if control_fd >= 0:
            os.close(control_fd)
        if status_fd >= 0:
            os.close(status_fd)


def acquire(
    lock_path: Path,
    metadata_path: Path,
    wait_seconds: int,
    lease_seconds: int,
) -> dict[str, object]:
    token = secrets.token_hex(32)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        hold_lock(
            lock_path,
            metadata_path,
            token,
            wait_seconds,
            lease_seconds,
            write_fd,
        )
        os._exit(0)

    os.close(write_fd)
    try:
        ready, _, _ = select.select([read_fd], [], [], wait_seconds + 2)
        if not ready:
            raise LockError("lock holder did not report acquisition")
        response = os.read(read_fd, MAX_METADATA_BYTES).decode("ascii")
    finally:
        os.close(read_fd)
    if not response.startswith("OK "):
        raise LockError(response.removeprefix("ERROR ") or "lock acquisition failed")
    metadata = json.loads(response[3:])
    if metadata["token"] != token or not owner_is_live(metadata):
        raise LockError("lock holder identity verification failed")
    return metadata


def release(metadata_path: Path, token: str) -> None:
    control_fd = open_lock(metadata_path.with_name("control.lock"))
    try:
        fcntl.flock(control_fd, fcntl.LOCK_EX)
        metadata = parse_metadata(metadata_path)
        if metadata is None:
            raise LockError("release lock metadata is missing")
        if metadata["token"] != token:
            raise LockError("refusing to release a lock owned by another operation")
        pid = int(metadata["pid"])
        if not owner_is_live(metadata):
            metadata_path.unlink(missing_ok=True)
            return
        os.kill(pid, signal.SIGTERM)
    finally:
        fcntl.flock(control_fd, fcntl.LOCK_UN)
        os.close(control_fd)
    deadline = time.monotonic() + 5
    while owner_is_live(metadata):
        if time.monotonic() >= deadline:
            raise LockError("lock holder did not terminate")
        time.sleep(0.05)


def renew(metadata_path: Path, token: str, lease_seconds: int) -> None:
    control_fd = open_lock(metadata_path.with_name("control.lock"))
    try:
        fcntl.flock(control_fd, fcntl.LOCK_EX)
        metadata = parse_metadata(metadata_path)
        if (
            metadata is None
            or metadata["token"] != token
            or metadata["lease_seconds"] != lease_seconds
            or not owner_is_live(metadata)
            or time.monotonic_ns() - int(metadata["heartbeat_ns"])
            >= lease_seconds * 1_000_000_000
        ):
            raise LockError("release lock ownership could not be renewed")
        metadata["heartbeat_ns"] = time.monotonic_ns()
        write_metadata(metadata_path, metadata)
    finally:
        fcntl.flock(control_fd, fcntl.LOCK_UN)
        os.close(control_fd)


def positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    acquire_parser = subparsers.add_parser("acquire")
    acquire_parser.add_argument("--lock-path", required=True, type=Path)
    acquire_parser.add_argument("--metadata-path", required=True, type=Path)
    acquire_parser.add_argument("--wait-seconds", required=True, type=positive_integer)
    acquire_parser.add_argument(
        "--lease-seconds", required=True, type=positive_integer
    )
    release_parser = subparsers.add_parser("release")
    release_parser.add_argument("--metadata-path", required=True, type=Path)
    release_parser.add_argument("--token", required=True)
    renew_parser = subparsers.add_parser("renew")
    renew_parser.add_argument("--metadata-path", required=True, type=Path)
    renew_parser.add_argument("--token", required=True)
    renew_parser.add_argument(
        "--lease-seconds", required=True, type=positive_integer
    )
    args = parser.parse_args()
    try:
        if args.action == "acquire":
            metadata = acquire(
                args.lock_path,
                args.metadata_path,
                args.wait_seconds,
                args.lease_seconds,
            )
            print(json.dumps(metadata, sort_keys=True, separators=(",", ":")))
        elif args.action == "release":
            if not TOKEN_PATTERN.fullmatch(args.token):
                raise LockError("release token is invalid")
            release(args.metadata_path, args.token)
        else:
            if not TOKEN_PATTERN.fullmatch(args.token):
                raise LockError("renewal token is invalid")
            renew(args.metadata_path, args.token, args.lease_seconds)
    except LockError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
