"""Confined Linux updater daemon; never installs, activates or executes candidates."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Callable
import ctypes
from dataclasses import dataclass
import errno
from importlib import metadata
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import sys
import time
from typing import Protocol

from strugglebus.update_state import Journal, UpdateState, journal_to_json
from strugglebus.update_storage import SecureCache, check_ancestry, read_protected_file
from strugglebus.update_types import (
    UPDATE_REPOSITORY, UPDATE_SOURCE_REPOSITORY, JsonObject, REQUEST_BYTES,
    RESPONSE_BYTES, UpdateCandidate, UpdateDiscovery, UpdateError, UpdateLimits,
    UpdateRequest, UpdateStatus, decode_frame, decode_json, discovery_from_json,
    discovery_to_json, encode_frame, encode_json, limits_from_json, request_from_json,
    require_bool, require_error, require_int, require_object, require_text,
    response_to_json, status_to_json,
)


class ReleaseSource(Protocol):
    policy_id: str

    def check(self, running_version: str, *, deadline: float) -> UpdateDiscovery:
        raise NotImplementedError

    def prepare(self, candidate: UpdateCandidate, directory: Path, *, deadline: float) -> None:
        raise NotImplementedError


class JobRunner(Protocol):
    async def run(
        self, request: UpdateRequest, candidate: UpdateCandidate | None,
        directory: Path | None, *, deadline: float,
    ) -> UpdateDiscovery | None:
        raise NotImplementedError


@dataclass(frozen=True)
class WorkerConfig:
    application_uid: int
    application_data_dir: Path
    cache_dir: Path
    release_repository: str
    source_repository: str
    limits: UpdateLimits


def _absolute_path(value: object) -> Path:
    if not isinstance(value, str):
        raise UpdateError("invalid_request")
    require_text(value, 4096)
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise UpdateError("storage_unsafe")
    return path


def config_from_json(value: object) -> WorkerConfig:
    if not isinstance(value, dict):
        raise UpdateError("invalid_request")
    obj = require_object(value, {
        "version", "application_uid", "application_data_dir", "cache_dir",
        "release_repository", "source_repository", "limits",
    })
    require_int(obj["version"], 2, 2)
    release_repository = require_text(obj["release_repository"], 128)
    source_repository = require_text(obj["source_repository"], 128)
    if (release_repository != UPDATE_REPOSITORY
            or source_repository != UPDATE_SOURCE_REPOSITORY):
        raise UpdateError("invalid_request")
    return WorkerConfig(
        require_int(obj["application_uid"], 2**31 - 1, 1),
        _absolute_path(obj["application_data_dir"]), _absolute_path(obj["cache_dir"]),
        release_repository, source_repository,
        limits_from_json(obj["limits"]),
    )


def load_config(path: Path) -> WorkerConfig:
    if sys.platform != "linux" or os.getuid() == 0:
        raise UpdateError("forbidden")
    _validate_runtime()
    config = config_from_json(decode_json(read_protected_file(path, 16384), 16384))
    if config.application_uid == os.getuid():
        raise UpdateError("forbidden")
    validate_topology(config)
    return config


def _resolve_current_release(alias: Path, current: Path) -> Path:
    """Follow the root-owned ``current`` link to this module inside one release."""
    check_ancestry(current)
    link = current.lstat()
    target = Path(os.readlink(current))
    if (
        not stat.S_ISLNK(link.st_mode)
        or link.st_uid != 0
        or not target.is_absolute()
        or target.parent != current.parent / "releases"
        or target.resolve(strict=True) != target
    ):
        raise UpdateError("forbidden")
    path = alias.resolve(strict=True)
    if path != target / alias.relative_to(current):
        raise UpdateError("forbidden")
    return path


def _resolve_runtime(alias: Path, current: Path) -> Path:
    try:
        if current in alias.parents:
            return _resolve_current_release(alias, current)
        path = alias.resolve(strict=True)
        if path != alias:
            raise UpdateError("forbidden")
        return path
    except (OSError, ValueError):
        raise UpdateError("forbidden") from None


def _validate_runtime_file(path: Path) -> None:
    if path.parent.name != "strugglebus" or path.parent.parent.name != "site-packages":
        raise UpdateError("forbidden")
    check_ancestry(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise UpdateError("forbidden")


def _validate_runtime() -> None:
    alias = Path(__file__).absolute()
    path = _resolve_runtime(alias, Path("/opt/strugglebus-updater/current"))
    _validate_runtime_file(path)
    installed = metadata.distribution("strugglebus").locate_file("strugglebus/update_worker.py")
    try:
        installed_path = Path(installed).resolve(strict=True)
    except OSError:
        raise UpdateError("forbidden") from None
    if installed_path != path:
        raise UpdateError("forbidden")


def _persistent_mount(path: Path, device: int) -> None:
    """Require an existing bounded persistent mount, never the root filesystem."""
    with open("/proc/self/mountinfo", encoding="utf-8") as stream:
        entries = stream.read(1024 * 1024 + 1)
    if len(entries) > 1024 * 1024:
        raise UpdateError("storage_unsafe")
    expected = f"{os.major(device)}:{os.minor(device)}"
    for line in entries.splitlines():
        fields = line.split()
        if len(fields) > 9 and fields[2] == expected and _cache_mount(path, fields[4]):
            separator = fields.index("-")
            if fields[separator + 1] in {"ext4", "xfs", "btrfs"}:
                return
    raise UpdateError("storage_unsafe")


def _cache_mount(cache: Path, raw_mount: str) -> bool:
    mount = Path(raw_mount)
    if not mount.is_absolute() or mount == Path(mount.anchor):
        return False
    return cache == mount or mount in cache.parents


def validate_topology(config: WorkerConfig) -> None:
    cache, data = config.cache_dir, config.application_data_dir
    check_ancestry(cache)
    check_ancestry(data)
    data_info, cache_info = data.lstat(), cache.lstat()
    _validate_data_directory(data_info, config.application_uid)
    _validate_data_acls(data)
    if not stat.S_ISDIR(cache_info.st_mode):
        raise UpdateError("storage_unsafe")
    if cache_info.st_uid != os.getuid():
        raise UpdateError("storage_unsafe")
    _validate_separation(cache, data, cache_info.st_dev, data_info.st_dev)
    _persistent_mount(cache, cache_info.st_dev)
    usage = os.statvfs(cache)
    capacity = usage.f_blocks * usage.f_frsize
    free = usage.f_bavail * usage.f_frsize
    required = config.limits.artifact_bytes + config.limits.journal_bytes + config.limits.reserve_bytes
    if not required <= capacity <= 1024 * 1024 * 1024 or free < config.limits.reserve_bytes:
        raise UpdateError("storage_full")


def _validate_data_directory(info: os.stat_result, application_uid: int) -> None:
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) not in {0o700, 0o750}:
        raise UpdateError("storage_unsafe")
    if info.st_uid != application_uid:
        raise UpdateError("storage_unsafe")
    if info.st_gid in {os.getgid(), *os.getgroups()}:
        raise UpdateError("storage_unsafe")


def _validate_data_acls(path: Path) -> None:
    for name in ("system.posix_acl_access", "system.posix_acl_default"):
        try:
            _require_absent_acl(path, name)
        except (AttributeError, NotImplementedError, TypeError):
            raise UpdateError("storage_unsafe") from None


def _require_absent_acl(path: Path, name: str) -> None:
    try:
        os.getxattr(path, name, follow_symlinks=False)
    except OSError as exc:
        if exc.errno == errno.ENODATA:
            return
        raise UpdateError("storage_unsafe") from None
    raise UpdateError("storage_unsafe")


def _validate_separation(cache: Path, data: Path, cache_device: int, data_device: int) -> None:
    if cache_device == data_device or cache == data:
        raise UpdateError("storage_unsafe")
    if cache in data.parents or data in cache.parents:
        raise UpdateError("storage_unsafe")
    if any(part.lower() in {"backup", "backups", "release", "releases"} for part in cache.parts):
        raise UpdateError("storage_unsafe")


def _validate_listener(listener: socket.socket) -> None:
    if listener.family != socket.AF_UNIX or listener.type != socket.SOCK_STREAM:
        raise UpdateError("forbidden")
    if not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
        raise UpdateError("forbidden")
    path = Path(listener.getsockname())
    check_ancestry(path)
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o660:
        raise UpdateError("forbidden")


def inherited_socket() -> socket.socket:
    if (os.environ.get("LISTEN_PID") != str(os.getpid())
            or os.environ.get("LISTEN_FDS") != "1"):
        raise UpdateError("forbidden")
    listener = socket.socket(fileno=3)
    try:
        _validate_listener(listener)
        listener.setblocking(False)
        return listener
    except BaseException:
        listener.close()
        raise


def _peer_allowed(writer: asyncio.StreamWriter, application_uid: int) -> bool:
    connection = writer.get_extra_info("socket")
    if connection is None:
        return False
    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _, uid, _ = struct.unpack("3i", raw)
        return uid in {0, application_uid}
    except OSError:
        return False


def _source_factory(config: WorkerConfig) -> ReleaseSource:
    from strugglebus.update_source import GitHubReleaseSource

    if (config.release_repository != UPDATE_REPOSITORY
            or config.source_repository != UPDATE_SOURCE_REPOSITORY):
        raise UpdateError("invalid_request")
    return GitHubReleaseSource(config.limits)


def _offline_verify(candidate: UpdateCandidate, directory: Path, limits: UpdateLimits) -> None:
    from strugglebus.update_source import verify_prepared

    verify_prepared(candidate, directory, limits)
    cache = SecureCache(directory.parent, limits)
    try:
        cache.validate_slot(directory.name.removeprefix("operation-"), candidate)
    finally:
        cache.close()


def _child_setup(keep_fd: int, parent_pid: int) -> None:
    import resource

    os.umask(0o077)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent_pid:
        raise UpdateError("interrupted")
    maximum = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    if maximum == resource.RLIM_INFINITY:
        maximum = 1048576
    os.closerange(3, keep_fd)
    os.closerange(keep_fd + 1, maximum)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _child_result(
    factory: Callable[[], ReleaseSource], verify: Callable[[UpdateCandidate, Path, UpdateLimits], None],
    request: UpdateRequest, candidate: UpdateCandidate | None, directory: Path | None,
    limits: UpdateLimits, deadline: float,
) -> JsonObject:
    source = factory()
    if request.action == "check" and request.application_version is not None:
        discovery = source.check(request.application_version, deadline=deadline)
        return {"ok": True, "error": None, "discovery": discovery_to_json(discovery)}
    if request.action != "prepare" or candidate is None or directory is None:
        raise UpdateError("invalid_request")
    if candidate.policy_id != source.policy_id:
        raise UpdateError("policy_mismatch")
    source.prepare(candidate, directory, deadline=deadline)
    verify(candidate, directory, limits)
    if time.monotonic() >= deadline:
        raise UpdateError("timeout")
    return {"ok": True, "error": None, "discovery": None}


def _child_main(
    channel: socket.socket, parent_pid: int, factory: Callable[[], ReleaseSource],
    verify: Callable[[UpdateCandidate, Path, UpdateLimits], None], request: UpdateRequest,
    candidate: UpdateCandidate | None, directory: Path | None, limits: UpdateLimits, deadline: float,
) -> None:
    try:
        _child_setup(channel.fileno(), parent_pid)
        result = _child_result(factory, verify, request, candidate, directory, limits, deadline)
    except UpdateError as exc:
        result = {"ok": False, "error": exc.code, "discovery": None}
    except BaseException:
        result = {"ok": False, "error": "internal_error", "discovery": None}
    try:
        channel.sendall(encode_frame(result, RESPONSE_BYTES))
    finally:
        channel.close()
        os._exit(0)


def _decode_job(data: bytes, action: str) -> UpdateDiscovery | None:
    obj = require_object(decode_frame(data, RESPONSE_BYTES), {"ok", "error", "discovery"})
    ok, error = require_bool(obj["ok"]), require_error(obj["error"])
    if not ok and error is not None and obj["discovery"] is None:
        raise UpdateError(error)
    if not ok or error is not None:
        raise UpdateError("invalid_response")
    if action == "check":
        return discovery_from_json(obj["discovery"])
    if obj["discovery"] is not None:
        raise UpdateError("invalid_response")
    return None


async def _read_job(channel: socket.socket) -> bytes:
    loop = asyncio.get_running_loop()
    data = bytearray()
    while len(data) <= RESPONSE_BYTES:
        part = await loop.sock_recv(channel, RESPONSE_BYTES + 1 - len(data))
        if not part:
            return bytes(data)
        data.extend(part)
    raise UpdateError("invalid_response")


class ProcessJobRunner:
    """One owned fork of installed trusted code; only bounded JSON crosses back."""

    def __init__(
        self, factory: Callable[[], ReleaseSource], limits: UpdateLimits,
        verify: Callable[[UpdateCandidate, Path, UpdateLimits], None] = _offline_verify,
    ):
        self.factory, self.limits, self.verify = factory, limits, verify
        self.pid: int | None = None

    async def run(
        self, request: UpdateRequest, candidate: UpdateCandidate | None,
        directory: Path | None, *, deadline: float,
    ) -> UpdateDiscovery | None:
        if self.pid is not None:
            raise UpdateError("busy")
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        parent_pid = os.getpid()
        try:
            pid = os.fork()
        except BaseException:
            parent.close()
            child.close()
            raise
        if pid == 0:
            parent.close()
            _child_main(child, parent_pid, self.factory, self.verify, request,
                        candidate, directory, self.limits, deadline)
            os._exit(1)
        child.close()
        parent.setblocking(False)
        self.pid = pid
        try:
            async with asyncio.timeout_at(deadline):
                result = _decode_job(await _read_job(parent), request.action)
                await self._reap(pid)
                return result
        except TimeoutError:
            raise UpdateError("timeout") from None
        finally:
            parent.close()
            await self._terminate(pid)

    async def _reap(self, pid: int) -> None:
        while True:
            exited, status = os.waitpid(pid, os.WNOHANG)
            if exited:
                self.pid = None
                if status != 0:
                    raise UpdateError("interrupted")
                return
            await asyncio.sleep(0.01)

    async def _terminate(self, pid: int) -> None:
        if self.pid != pid:
            return
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await asyncio.to_thread(os.waitpid, pid, 0)
        self.pid = None


class UpdateWorker:
    """The bound-socket and runner parameters are internal, non-CLI test seams."""

    def __init__(
        self, state: UpdateState, runner: JobRunner, application_uid: int,
        *, peer_check: Callable[[asyncio.StreamWriter, int], bool] = _peer_allowed,
    ):
        self.state, self.runner, self.application_uid = state, runner, application_uid
        self.peer_check = peer_check
        self.active_connections = 0
        self.job: asyncio.Task[None] | None = None
        self.connections: set[asyncio.Task[None]] = set()
        self.server: asyncio.Server | None = None
        self.closing = False

    async def serve(self, listener: socket.socket) -> None:
        self.state.reconcile(now=int(time.time()))
        prepared = self.state.journal.prepared
        if prepared is not None:
            _offline_verify(prepared.candidate,
                            self.state.storage.slot_path(prepared.operation_id), self.state.limits)
        self.server = await asyncio.start_unix_server(
            self._connected, sock=listener, limit=REQUEST_BYTES + 1,
        )

    def _connected(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self.closing or self.active_connections >= self.state.limits.connections:
            writer.close()
            return
        self.active_connections += 1
        task = asyncio.create_task(self._handle(reader, writer))
        self.connections.add(task)
        task.add_done_callback(self.connections.discard)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            async with asyncio.timeout(2):
                result = await self._response(reader, writer)
                writer.write(encode_frame(result, RESPONSE_BYTES))
                await writer.drain()
        except (OSError, TimeoutError, UpdateError):
            pass
        finally:
            writer.close()
            self.active_connections -= 1

    async def _response(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> JsonObject:
        try:
            if not self.peer_check(writer, self.application_uid):
                raise UpdateError("forbidden")
            request = request_from_json(decode_frame(await _read_request(reader), REQUEST_BYTES))
            return response_to_json(self.dispatch(request))
        except UpdateError as exc:
            return response_to_json(error=exc.code)
        except OSError:
            return response_to_json(error="storage_unsafe")

    def dispatch(self, request: UpdateRequest) -> UpdateStatus:
        if request.action == "status":
            return self.state.status(request.operation_id)
        accepted = self.state.accept(request)
        result = self.state.status(request.operation_id)
        if accepted:
            self.job = asyncio.create_task(self._execute())
        return result

    async def _execute(self) -> None:
        current = self.state.journal.current
        if current is None:
            return
        request = current.request
        limits = self.state.limits
        duration = limits.check_timeout if request.action == "check" else limits.prepare_timeout
        deadline = time.monotonic() + duration
        try:
            async with asyncio.timeout_at(deadline):
                candidate = None
                if request.action == "prepare":
                    candidate = self.state.candidate_for(request, now=int(time.time()))
                directory = self.state.start()
                result = await self.runner.run(request, candidate, directory, deadline=deadline)
                if time.monotonic() >= deadline:
                    raise UpdateError("timeout")
                self._finish(request, result)
        except asyncio.CancelledError:
            self._fail("interrupted", interrupted=True)
            raise
        except TimeoutError:
            self._fail("timeout")
        except UpdateError as exc:
            self._fail(exc.code)
        except Exception:
            self._fail("internal_error")

    def _finish(self, request: UpdateRequest, result: UpdateDiscovery | None) -> None:
        if request.action == "check" and result is not None:
            self.state.finish_check(result, now=int(time.time()))
        elif request.action == "prepare" and result is None:
            self.state._publish_prepared(now=int(time.time()))
        else:
            raise UpdateError("invalid_response")

    def _fail(self, code: str, *, interrupted: bool = False) -> None:
        if self.state.healthy and self.state.journal.current is not None:
            try:
                self.state.fail(code, now=int(time.time()), interrupted=interrupted)
            except (OSError, UpdateError):
                self.state.healthy = False

    async def close(self) -> None:
        self.closing = True
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
        if self.job is not None and not self.job.done():
            self.job.cancel()
            await asyncio.gather(self.job, return_exceptions=True)
        tasks = tuple(self.connections)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def _read_request(reader: asyncio.StreamReader) -> bytes:
    data = bytearray()
    while len(data) <= REQUEST_BYTES:
        part = await reader.read(REQUEST_BYTES + 1 - len(data))
        if not part:
            return bytes(data)
        data.extend(part)
    raise UpdateError("invalid_request")


async def _serve(config: WorkerConfig, storage: SecureCache, policy_id: str) -> None:
    state = UpdateState(storage, policy_id, config.limits, adopt_policy=True)
    runner = ProcessJobRunner(lambda: _source_factory(config), config.limits)
    worker = UpdateWorker(state, runner, config.application_uid)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    try:
        await worker.serve(inherited_socket())
        await stop.wait()
    finally:
        await worker.close()


def _run_command(command: str, config: WorkerConfig) -> None:
    from strugglebus.update_source import POLICY_ID

    storage = SecureCache(config.cache_dir, config.limits)
    try:
        if command == "status":
            state = UpdateState(storage, POLICY_ID, config.limits)
            print(encode_json(status_to_json(state.status()), RESPONSE_BYTES).decode("ascii"))
            return
        storage.acquire()
        if command == "init":
            storage.initialize(journal_to_json(Journal(POLICY_ID)))
        else:
            asyncio.run(_serve(config, storage, POLICY_ID))
    finally:
        storage.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Protected update preparation worker")
    parser.add_argument("command", choices=("init", "serve", "status"))
    parser.add_argument("--config", required=True)
    arguments = parser.parse_args(argv)
    try:
        _run_command(arguments.command, load_config(_absolute_path(arguments.config)))
    except UpdateError as exc:
        print(exc.code, file=sys.stderr)
        return 1
    except (OSError, ValueError, ImportError):
        print("unavailable", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
