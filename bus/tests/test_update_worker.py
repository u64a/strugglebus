import asyncio
from dataclasses import replace
import errno
import hashlib
import io
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import sys
import time
from types import SimpleNamespace

import pytest

from strugglebus import update_storage as storage_module
from strugglebus import update_worker as worker_module
from strugglebus.update_state import Journal, journal_to_json
from strugglebus.update_types import (
    REQUEST_BYTES, RESPONSE_BYTES, UpdateError, UpdateLimits, UpdateRequest,
    decode_frame, encode_frame, encode_json, request_to_json, response_from_json,
)
from test_update_client import Writer
from test_update_state import MemoryStorage, check_request, checked, make_state, prepared
from test_update_types import candidate, discovery


class Runner:
    def __init__(self, *, result=None, error=None, block=False):
        self.result, self.error, self.block = result, error, block
        self.calls = []
        self.cancelled = False
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def run(self, request, candidate, directory, *, deadline):
        self.calls.append((request, candidate, directory, deadline))
        self.entered.set()
        try:
            if self.block:
                await self.release.wait()
            if self.error:
                raise self.error
            return self.result
        except asyncio.CancelledError:
            self.cancelled = True
            raise


def worker(runner=None, *, limits=None, allowed=True):
    state, storage = make_state(limits)
    runner = runner or Runner(result=discovery())
    instance = worker_module.UpdateWorker(state, runner, 1000, peer_check=lambda w, uid: allowed)
    return instance, storage, runner


def reader_for(raw):
    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()
    return reader


async def test_worker_accept_status_remains_responsive_and_success():
    instance, storage, runner = worker(Runner(result=discovery(), block=True))
    accepted = instance.dispatch(check_request())
    assert accepted.operation.phase == "accepted"
    assert storage.saved[-1]["current"]["operation"]["phase"] == "accepted"
    await runner.entered.wait()
    assert instance.dispatch(UpdateRequest("status")).state == "checking"
    assert instance.dispatch(check_request()).operation.phase == "running"
    with pytest.raises(UpdateError, match="busy"):
        instance.dispatch(check_request("4" * 32))
    runner.release.set()
    await instance.job
    assert instance.state.status().operation.phase == "succeeded"
    assert runner.calls[0][3] <= time.monotonic() + 120
    assert len(runner.calls) == 1
    await instance.close()


@pytest.mark.parametrize("error,code", [
    (UpdateError("authentication_failed"), "authentication_failed"),
    (UpdateError("verification_failed"), "verification_failed"),
    (RuntimeError("TOKEN=secret signed URL"), "internal_error"),
])
async def test_worker_job_failures_static_and_durable(error, code):
    instance, _, _ = worker(Runner(error=error))
    instance.dispatch(check_request())
    await instance.job
    result = instance.state.status()
    assert result.state == "failed"
    assert result.operation.error == code
    assert "secret" not in str(result)


async def test_worker_prepare_uses_exact_observation_and_private_slot():
    instance, storage, runner = worker(Runner())
    request = checked(instance.state, now=int(time.time()) - 2)
    accepted = instance.dispatch(request)
    assert accepted.state == "preparing"
    await instance.job
    assert instance.state.status().state == "prepared"
    assert runner.calls[0][1] == candidate()
    assert runner.calls[0][2] == storage.slot_path(request.operation_id)
    assert storage.slots == {request.operation_id}


async def test_absolute_deadline_and_shutdown_cancel_owned_job():
    limits = UpdateLimits(check_timeout=1)
    instance, _, runner = worker(Runner(block=True), limits=limits)
    instance.dispatch(check_request())
    await instance.job
    assert runner.cancelled
    assert instance.state.status().operation.error == "timeout"
    second, _, second_runner = worker(Runner(block=True))
    second.dispatch(check_request())
    await second_runner.entered.wait()
    await second.close()
    assert second_runner.cancelled
    assert second.state.status().operation.phase == "interrupted"


async def test_job_invalid_result_and_storage_failure_remain_explicit():
    instance, _, _ = worker(Runner(result=None))
    instance.dispatch(check_request())
    await instance.job
    assert instance.state.status().operation.error == "invalid_response"
    instance, storage, runner = worker(Runner(result=discovery(), block=True))
    instance.dispatch(check_request())
    await runner.entered.wait()
    storage.fail_save = True
    runner.release.set()
    await instance.job
    with pytest.raises(UpdateError, match="state_corrupt"):
        instance.state.status()


@pytest.mark.parametrize("raw", [
    b'{}\n', b'{}\n{}\n', b'{}', b'{"action":"status","action":"check"}\n',
    b'x' * (REQUEST_BYTES + 1), b'{"version":1,"action":"install","operation_id":null}\n',
], ids=["empty", "extra", "truncated", "duplicate", "oversized", "forbidden-verb"])
async def test_worker_malformed_frames_refused(raw):
    instance, _, _ = worker()
    response = await instance._response(reader_for(raw), Writer())
    with pytest.raises(UpdateError, match="invalid_request"):
        response_from_json(response)
    assert instance.job is None


async def test_peer_refused_before_request_body_and_connection_bound():
    instance, _, _ = worker(allowed=False)
    class Unreadable:
        async def read(self, size):
            raise AssertionError("unauthorized body read")
    response = await instance._response(Unreadable(), Writer())
    assert response["error"] == "forbidden"
    instance.active_connections = 4
    extra = Writer()
    instance._connected(Unreadable(), extra)
    assert extra.closed
    assert instance.active_connections == 4


async def test_handler_closes_and_status_frame_roundtrip():
    instance, _, _ = worker()
    writer = Writer()
    reader = reader_for(encode_frame(request_to_json(UpdateRequest("status")), REQUEST_BYTES))
    instance._connected(reader, writer)
    await asyncio.gather(*tuple(instance.connections))
    assert writer.closed
    assert response_from_json(decode_frame(writer.data, RESPONSE_BYTES)).state == "idle"
    assert instance.active_connections == 0


async def test_shutdown_closes_open_admission_and_server(monkeypatch):
    instance, _, _ = worker()
    class Server:
        closed = False
        def close(self):
            self.closed = True
        async def wait_closed(self):
            pass
    server = Server()
    async def start(callback, *, sock, limit):
        assert limit == REQUEST_BYTES + 1
        return server
    monkeypatch.setattr(asyncio, "start_unix_server", start, raising=False)
    await instance.serve(object())
    writer = Writer()
    instance._connected(asyncio.StreamReader(), writer)
    await asyncio.sleep(0)
    await instance.close()
    assert server.closed and writer.closed and instance.active_connections == 0
    rejected = Writer()
    instance._connected(asyncio.StreamReader(), rejected)
    assert rejected.closed


def test_peer_uid_exact_and_no_socket(monkeypatch):
    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    assert not worker_module._peer_allowed(Writer(), 1000)
    for uid in [0, 1000, 1001]:
        peer = SimpleNamespace(getsockopt=lambda *args: struct.pack("3i", 1, uid, 0))
        assert worker_module._peer_allowed(Writer(peer=peer), 1000) == (uid in {0, 1000})
    def bad(*args):
        raise OSError("private")
    assert not worker_module._peer_allowed(Writer(peer=SimpleNamespace(getsockopt=bad)), 1000)


def config_json():
    return dict(
        version=2, application_uid=1000,
        application_data_dir=str(Path.cwd() / "synthetic-bus"),
        cache_dir=str(Path.cwd() / "synthetic-cache"),
        release_repository="NZCypher819/strugglebus-releases",
        source_repository="NZCypher819/strugglebus",
        limits={},
    )


@pytest.mark.parametrize("change", [
    {"version": 1}, {"version": True}, {"application_uid": 0}, {"application_uid": True},
    {"application_data_dir": "relative"}, {"cache_dir": "relative"},
    {"release_repository": "NZCypher819/strugglebus"},
    {"source_repository": "NZCypher819/strugglebus-releases"},
    {"limits": {"connections": 5}}, {"secret": "forbidden"}, {"quota_exists": True},
])
def test_config_exact_bounded_and_no_bypass(change):
    with pytest.raises(UpdateError):
        worker_module.config_from_json(config_json() | change)


def test_config_linux_nonroot_distinct_uid_protected_read(monkeypatch):
    raw = config_json()
    config = worker_module.config_from_json(raw)
    calls = []
    monkeypatch.setattr(worker_module, "read_protected_file", lambda path, limit: encode_json(raw, limit))
    monkeypatch.setattr(worker_module, "validate_topology", calls.append)
    monkeypatch.setattr(worker_module, "_validate_runtime", lambda: None)
    monkeypatch.setattr(worker_module.sys, "platform", "linux")
    monkeypatch.setattr(worker_module.os, "getuid", lambda: 1001, raising=False)
    assert worker_module.load_config(Path.cwd() / "config.json") == config
    assert calls == [config]
    for uid in [0, 1000]:
        monkeypatch.setattr(worker_module.os, "getuid", lambda: uid)
        with pytest.raises(UpdateError, match="forbidden"):
            worker_module.load_config(Path.cwd() / "config.json")
    monkeypatch.setattr(worker_module.sys, "platform", "win32")
    with pytest.raises(UpdateError, match="forbidden"):
        worker_module.load_config(Path.cwd() / "config.json")


@pytest.mark.parametrize("kind", ["same-device", "nested", "backup", "release"])
def test_cache_separation_rejects_unsafe_topology(kind):
    root = Path.cwd()
    data, cache, cache_device = root / "bus", root / "cache", 2
    if kind == "same-device":
        cache_device = 1
    elif kind == "nested":
        cache = data / "cache"
    elif kind == "backup":
        cache = root / "backups" / "cache"
    else:
        cache = root / "releases" / "cache"
    with pytest.raises(UpdateError, match="storage_unsafe"):
        worker_module._validate_separation(cache, data, cache_device, 1)


def test_cache_capacity_and_reserved_space_are_measured(monkeypatch):
    config = worker_module.config_from_json(config_json())
    monkeypatch.setattr(worker_module, "check_ancestry", lambda path: None)
    monkeypatch.setattr(worker_module, "_persistent_mount", lambda *args: None)
    monkeypatch.setattr(worker_module.os, "getuid", lambda: 1001, raising=False)
    monkeypatch.setattr(worker_module.os, "getgid", lambda: 1001, raising=False)
    monkeypatch.setattr(worker_module.os, "getgroups", lambda: [], raising=False)
    monkeypatch.setattr(worker_module.errno, "ENODATA", 61, raising=False)
    acl_calls = []
    acl_values = {}
    def read_acl(path, name, *, follow_symlinks):
        acl_calls.append((path, name, follow_symlinks))
        if name in acl_values:
            return acl_values[name]
        raise OSError(errno.ENODATA, "absent")
    monkeypatch.setattr(worker_module.os, "getxattr", read_acl, raising=False)
    infos = {
        config.cache_dir: SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1001, st_dev=2),
        config.application_data_dir: SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700, st_uid=1000, st_gid=1000, st_dev=1,
        ),
    }
    monkeypatch.setattr(Path, "lstat", lambda self: infos[self])
    usage = SimpleNamespace(f_blocks=1024**3, f_bavail=1024**3, f_frsize=1)
    monkeypatch.setattr(worker_module.os, "statvfs", lambda path: usage, raising=False)
    worker_module.validate_topology(config)
    assert acl_calls == [
        (config.application_data_dir, "system.posix_acl_access", False),
        (config.application_data_dir, "system.posix_acl_default", False),
    ]
    infos[config.application_data_dir].st_mode = stat.S_IFDIR | 0o750
    for name in ("system.posix_acl_access", "system.posix_acl_default"):
        acl_values[name] = named_worker_acl()
        with pytest.raises(UpdateError, match="storage_unsafe"):
            worker_module.validate_topology(config)
        acl_values.clear()
    for blocks, free in [(1024**3 + 1, 1024**3), (100, 100), (1024**3, 0)]:
        usage.f_blocks, usage.f_bavail = blocks, free
        with pytest.raises(UpdateError, match="storage_full"):
            worker_module.validate_topology(config)
    infos[config.cache_dir].st_uid = 0
    with pytest.raises(UpdateError, match="storage_unsafe"):
        worker_module.validate_topology(config)
    infos[config.cache_dir].st_mode = stat.S_IFREG | 0o600
    with pytest.raises(UpdateError, match="storage_unsafe"):
        worker_module.validate_topology(config)


def test_masked_data_metadata_or_bus_group_membership_cannot_attest_topology(monkeypatch):
    monkeypatch.setattr(worker_module.os, "getgid", lambda: 1001, raising=False)
    monkeypatch.setattr(worker_module.os, "getgroups", lambda: [], raising=False)
    info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o750, st_uid=1000, st_gid=1000)
    worker_module._validate_data_directory(info, 1000)
    for mode, uid in [(stat.S_IFDIR, 1000), (stat.S_IFDIR | 0o750, 0),
                      (stat.S_IFDIR | 0o777, 1000), (stat.S_IFREG | 0o700, 1000)]:
        info.st_mode, info.st_uid = mode, uid
        with pytest.raises(UpdateError, match="storage_unsafe"):
            worker_module._validate_data_directory(info, 1000)
    info.st_mode, info.st_uid = stat.S_IFDIR | 0o750, 1000
    monkeypatch.setattr(worker_module.os, "getgroups", lambda: [1000])
    with pytest.raises(UpdateError, match="storage_unsafe"):
        worker_module._validate_data_directory(info, 1000)


def named_worker_acl():
    entries = [(1, 7, 0xFFFFFFFF), (2, 5, 1001), (4, 5, 0xFFFFFFFF),
               (16, 5, 0xFFFFFFFF), (32, 0, 0xFFFFFFFF)]
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)


@pytest.mark.parametrize("name", ["system.posix_acl_access", "system.posix_acl_default"])
@pytest.mark.parametrize("value", [named_worker_acl(), b""])
def test_bus_root_acl_presence_is_rejected_without_parsing_or_repair(monkeypatch, name, value):
    monkeypatch.setattr(worker_module.errno, "ENODATA", 61, raising=False)
    observed = []
    def read_acl(path, attribute, *, follow_symlinks):
        observed.append(attribute)
        assert follow_symlinks is False
        if attribute == name:
            return value
        raise OSError(errno.ENODATA, "absent")
    monkeypatch.setattr(worker_module.os, "getxattr", read_acl, raising=False)
    with pytest.raises(UpdateError, match="storage_unsafe"):
        worker_module._validate_data_acls(Path("synthetic-bus"))
    assert name in observed


@pytest.mark.parametrize("name", ["system.posix_acl_access", "system.posix_acl_default"])
@pytest.mark.parametrize("failure", [errno.EACCES, errno.EIO, errno.ENOENT, errno.ENOTSUP, None])
def test_bus_root_acl_absence_requires_explicit_enodata(monkeypatch, failure, name):
    monkeypatch.setattr(worker_module.errno, "ENODATA", 61, raising=False)
    def unreadable(path, attribute, *, follow_symlinks):
        if attribute != name:
            raise OSError(errno.ENODATA, "absent")
        raise OSError(failure, "private filesystem details")
    monkeypatch.setattr(worker_module.os, "getxattr", unreadable, raising=False)
    with pytest.raises(UpdateError, match="storage_unsafe") as raised:
        worker_module._validate_data_acls(Path("synthetic-bus"))
    assert "private" not in str(raised.value)


@pytest.mark.parametrize("failure", [AttributeError, NotImplementedError, TypeError])
def test_bus_root_acl_unavailable_platform_proof_fails_closed(monkeypatch, failure):
    def unavailable(*args, **kwargs):
        raise failure("ACL inspection unavailable")
    monkeypatch.setattr(worker_module.os, "getxattr", unavailable, raising=False)
    with pytest.raises(UpdateError, match="storage_unsafe"):
        worker_module._validate_data_acls(Path("synthetic-bus"))


def test_bus_root_acl_missing_getxattr_fails_closed(monkeypatch):
    monkeypatch.delattr(worker_module.os, "getxattr", raising=False)
    with pytest.raises(UpdateError, match="storage_unsafe"):
        worker_module._validate_data_acls(Path("synthetic-bus"))


def test_child_job_results_and_no_candidate_execution():
    calls = []
    class Source:
        policy_id = "test-policy"
        def check(self, running_version, *, deadline):
            calls.append(("check", running_version, deadline))
            return discovery()
        def prepare(self, value, directory, *, deadline):
            calls.append(("prepare", value.digest, directory, deadline))
    def verify(value, directory, limits):
        calls.append(("offline", value.digest, directory))
    limits = UpdateLimits()
    deadline = time.monotonic() + 120
    result = worker_module._child_result(Source, verify, check_request(), None, None, limits, deadline)
    assert worker_module._decode_job(encode_frame(result, RESPONSE_BYTES), "check") == discovery()
    request = replace(check_request(), action="prepare")
    result = worker_module._child_result(Source, verify, request, candidate(), Path("synthetic"), limits, deadline)
    assert worker_module._decode_job(encode_frame(result, RESPONSE_BYTES), "prepare") is None
    assert [call[0] for call in calls] == ["check", "prepare", "offline"]
    with pytest.raises(UpdateError, match="policy_mismatch"):
        worker_module._child_result(Source, verify, request, candidate(policy="other"),
                                    Path("synthetic"), limits, deadline)
    with pytest.raises(UpdateError, match="timeout"):
        worker_module._child_result(Source, verify, request, candidate(), Path("synthetic"), limits, 0)
    with pytest.raises(UpdateError, match="invalid_request"):
        worker_module._child_result(Source, verify, request, None, None, limits, deadline)


@pytest.mark.parametrize("value", [
    {"ok": False, "error": None, "discovery": None},
    {"ok": True, "error": "busy", "discovery": None},
    {"ok": True, "error": None, "discovery": {}},
    {"ok": True, "error": None, "discovery": None, "extra": 1},
])
def test_job_pipe_exact_and_bounded(value):
    with pytest.raises(UpdateError):
        worker_module._decode_job(encode_frame(value, RESPONSE_BYTES), "prepare")
    with pytest.raises(UpdateError, match="source_unavailable"):
        worker_module._decode_job(
            encode_frame({"ok": False, "error": "source_unavailable", "discovery": None}, RESPONSE_BYTES),
            "check",
        )


class Channel:
    def __init__(self):
        self.closed = False
        self.data = b""
    def close(self):
        self.closed = True
    def setblocking(self, flag):
        assert flag is False
    def fileno(self):
        return 10
    def sendall(self, data):
        self.data += data


def install_process_adapter(monkeypatch, *, wait_status=(321, 0)):
    monkeypatch.setattr(signal, "SIGKILL", 9, raising=False)
    monkeypatch.setattr(socket, "AF_UNIX", 1, raising=False)
    channels = Channel(), Channel()
    signals = []
    fake_os = SimpleNamespace(
        getpid=lambda: 111, fork=lambda: 321,
        waitpid=lambda pid, flags: wait_status, WNOHANG=1,
        kill=lambda pid, sig: signals.append((pid, sig)),
    )
    monkeypatch.setattr(worker_module, "os", fake_os)
    monkeypatch.setattr(worker_module.socket, "socketpair", lambda *args: channels)
    return channels, signals


async def test_process_job_uses_bytes_reaps_own_child(monkeypatch):
    channels, signals = install_process_adapter(monkeypatch)
    async def read(channel):
        return encode_frame({"ok": True, "error": None, "discovery": None}, RESPONSE_BYTES)
    monkeypatch.setattr(worker_module, "_read_job", read)
    runner = worker_module.ProcessJobRunner(lambda: None, UpdateLimits())
    assert await runner.run(replace(check_request(), action="prepare"), candidate(), Path("synthetic"),
                            deadline=time.monotonic() + 1) is None
    assert runner.pid is None
    assert all(channel.closed for channel in channels)
    assert not signals


async def test_process_deadline_and_cancel_kill_only_owned_pid(monkeypatch):
    channels, signals = install_process_adapter(monkeypatch)
    async def read(channel):
        await asyncio.Event().wait()
    monkeypatch.setattr(worker_module, "_read_job", read)
    runner = worker_module.ProcessJobRunner(lambda: None, UpdateLimits())
    with pytest.raises(UpdateError, match="timeout"):
        await runner.run(check_request(), None, None, deadline=time.monotonic() + 0.01)
    assert signals == [(321, signal.SIGKILL)]
    assert runner.pid is None and channels[0].closed
    signals.clear()
    task = asyncio.create_task(runner.run(check_request(), None, None, deadline=time.monotonic() + 60))
    await asyncio.sleep(0)
    with pytest.raises(UpdateError, match="busy"):
        await runner.run(check_request(), None, None, deadline=time.monotonic() + 60)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert signals == [(321, signal.SIGKILL)]


async def test_nonzero_child_exit_and_fork_failure_explicit(monkeypatch):
    channels, signals = install_process_adapter(monkeypatch, wait_status=(321, 9))
    async def read(channel):
        return encode_frame({"ok": True, "error": None, "discovery": None}, RESPONSE_BYTES)
    monkeypatch.setattr(worker_module, "_read_job", read)
    runner = worker_module.ProcessJobRunner(lambda: None, UpdateLimits())
    with pytest.raises(UpdateError, match="interrupted"):
        await runner.run(replace(check_request(), action="prepare"), None, None,
                         deadline=time.monotonic() + 1)
    assert runner.pid is None and not signals
    def failure():
        raise OSError("process limit")
    monkeypatch.setattr(worker_module.os, "fork", failure)
    with pytest.raises(OSError):
        await runner.run(check_request(), None, None, deadline=time.monotonic() + 1)
    assert all(channel.closed for channel in channels)


def test_child_redacts_exceptions_and_never_pickles(monkeypatch):
    class Exited(BaseException):
        pass
    fake_os = SimpleNamespace(_exit=lambda code: (_ for _ in ()).throw(Exited()))
    monkeypatch.setattr(worker_module, "os", fake_os)
    monkeypatch.setattr(worker_module, "_child_setup", lambda *args: None)
    def factory():
        raise RuntimeError("private App token")
    channel = Channel()
    with pytest.raises(Exited):
        worker_module._child_main(channel, 1, factory, lambda *args: None,
                                 check_request(), None, None, UpdateLimits(), 10)
    assert channel.closed
    assert decode_frame(channel.data, RESPONSE_BYTES) == {
        "ok": False, "error": "internal_error", "discovery": None,
    }


def test_anonymous_public_source_factory_has_no_credential_dependency(monkeypatch):
    captured = []
    source_module = SimpleNamespace(
        GitHubReleaseSource=lambda limits: captured.append(limits) or limits,
    )
    monkeypatch.setitem(sys.modules, "strugglebus.update_source", source_module)
    config = worker_module.config_from_json(config_json())
    assert worker_module._source_factory(config) == config.limits
    assert captured == [config.limits]


def test_cli_only_fixed_commands_absolute_config_and_static_errors(monkeypatch, capsys):
    monkeypatch.setattr(worker_module, "load_config", lambda path: (_ for _ in ()).throw(UpdateError("forbidden")))
    assert worker_module.main(["status", "--config", str(Path.cwd() / "config")]) == 1
    assert capsys.readouterr().err == "forbidden\n"
    assert worker_module.main(["init", "--config", "relative"]) == 1
    assert capsys.readouterr().err == "storage_unsafe\n"
    with pytest.raises(SystemExit):
        worker_module.main(["install", "--config", str(Path.cwd() / "config")])
    with pytest.raises(SystemExit):
        worker_module.main(["serve", "--config", str(Path.cwd() / "config"), "--disable-verification"])


class PosixFiles:
    """A topology/UID adapter, not a production permission or mount bypass."""

    O_NOFOLLOW, O_CLOEXEC, O_DIRECTORY = 1 << 20, 1 << 21, 1 << 22
    O_RDONLY, O_RDWR, O_CREAT, O_EXCL = 0, 2, 1 << 10, 1 << 11

    def __init__(self, path, umask=0o022):
        self.path, self.umask = path, umask
        self.nodes = 0
        self.root = self.node(directory=True)
        self.handles = {}
        self.sequence = 20
        self.free = 1024**3
        self.synced = []
        self.fail_replace = False
        self.fail_sync = False

    def node(self, directory=False, data=b"", mode=None):
        self.nodes += 1
        return SimpleNamespace(
            directory=directory, data=data, children={}, uid=42, links=1,
            mode=(0o700 if directory else 0o600) if mode is None else mode,
            inode=self.nodes, device=2,
        )

    def getuid(self):
        return 42

    def info(self, node):
        return SimpleNamespace(
            st_mode=(stat.S_IFDIR if node.directory else stat.S_IFREG) | node.mode,
            st_uid=node.uid, st_nlink=node.links, st_dev=node.device, st_ino=node.inode,
            st_size=len(node.data),
        )

    def open(self, name, flags, mode=0o600, *, dir_fd=None):
        if dir_fd is None:
            assert Path(name) == self.path
            node = self.root
        else:
            parent = self.handles[dir_fd][0]
            if flags & self.O_CREAT:
                if name in parent.children and flags & self.O_EXCL:
                    raise FileExistsError(name)
                parent.children[name] = self.node(mode=mode & ~self.umask)
            if name not in parent.children:
                raise FileNotFoundError(name)
            node = parent.children[name]
        self.sequence += 1
        self.handles[self.sequence] = [node, 0]
        return self.sequence

    def close(self, fd):
        del self.handles[fd]

    def fstat(self, fd):
        return self.info(self.handles[fd][0])

    def stat(self, name, *, dir_fd, follow_symlinks):
        parent = self.handles[dir_fd][0]
        if name not in parent.children:
            raise FileNotFoundError(name)
        return self.info(parent.children[name])

    def fchmod(self, fd, mode):
        self.handles[fd][0].mode = mode

    def fsync(self, fd):
        if self.fail_sync:
            raise OSError("sync interrupted")
        self.synced.append(self.handles[fd][0].inode)

    def listdir(self, fd):
        return list(self.handles[fd][0].children)

    def read(self, fd, size):
        node, offset = self.handles[fd]
        data = node.data[offset:offset + size]
        self.handles[fd][1] += len(data)
        return data

    def write(self, fd, data):
        node, offset = self.handles[fd]
        node.data = node.data[:offset] + data
        self.handles[fd][1] += len(data)
        return len(data)

    def replace(self, source, target, *, src_dir_fd, dst_dir_fd):
        if self.fail_replace:
            raise OSError("rename interrupted")
        source_parent = self.handles[src_dir_fd][0]
        target_parent = self.handles[dst_dir_fd][0]
        target_parent.children[target] = source_parent.children.pop(source)

    def mkdir(self, name, mode, *, dir_fd):
        parent = self.handles[dir_fd][0]
        if name in parent.children:
            raise FileExistsError(name)
        parent.children[name] = self.node(directory=True, mode=mode & ~self.umask)

    def unlink(self, name, *, dir_fd):
        del self.handles[dir_fd][0].children[name]

    def rmdir(self, name, *, dir_fd):
        parent = self.handles[dir_fd][0]
        assert not parent.children[name].children
        del parent.children[name]

    def fstatvfs(self, fd):
        return SimpleNamespace(f_bavail=self.free, f_frsize=1)


def secure_cache(monkeypatch, *, umask=0o022):
    path = Path.cwd() / "synthetic-cache"
    files = PosixFiles(path, umask)
    monkeypatch.setattr(storage_module, "os", files)
    monkeypatch.setattr(storage_module, "check_ancestry", lambda path: None)
    monkeypatch.setattr(Path, "lstat", lambda self: files.info(files.root))
    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(
        LOCK_EX=1, LOCK_NB=2, flock=lambda *args: None,
    ))
    cache = storage_module.SecureCache(path, UpdateLimits())
    cache.acquire()
    cache.initialize(journal_to_json(Journal("test-policy")))
    return cache, files


@pytest.mark.parametrize("umask", [0o000, 0o002, 0o022])
def test_files_explicit_modes_durable_publication_under_umasks(monkeypatch, umask):
    cache, files = secure_cache(monkeypatch, umask=umask)
    assert files.root.children[storage_module.JOURNAL].mode == 0o600
    assert files.root.children[storage_module.LOCK].mode == 0o600
    assert cache.load() == journal_to_json(Journal("test-policy"))
    identity = "3" * 32
    path = cache.create_slot(identity)
    node = files.root.children[path.name]
    assert node.mode == 0o700
    value = candidate()
    value = replace(value, assets=tuple(replace(a, sha256=hashlib.sha256(b"x").hexdigest())
                                        for a in value.assets))
    node.children.update({a.name: files.node(data=b"x") for a in value.assets})
    cache.validate_slot(identity, value)
    cache.validate_inventory((identity,))
    cache.retire_slot(identity)
    assert path.name not in files.root.children
    assert files.root.inode in files.synced
    cache.retire_slot(identity)
    cache.close()
    assert not files.handles


@pytest.mark.parametrize("mutation", ["mode", "owner", "hardlink", "directory", "inode"])
def test_journal_unsafe_metadata_fails_without_repair(monkeypatch, mutation):
    cache, files = secure_cache(monkeypatch)
    node = files.root.children[storage_module.JOURNAL]
    if mutation == "mode":
        node.mode = 0o666
    elif mutation == "owner":
        node.uid = 0
    elif mutation == "hardlink":
        node.links = 2
    elif mutation == "directory":
        node.directory = True
    else:
        real_open = files.open
        def substitute(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            files.handles[fd][0] = files.node(data=b"{}")
            return fd
        monkeypatch.setattr(files, "open", substitute)
    before = node.mode, node.uid, node.links
    with pytest.raises(UpdateError, match="state_corrupt"):
        cache.load()
    assert before == (node.mode, node.uid, node.links)
    cache.close()


def test_no_unknown_inventory_or_more_than_two_artifact_slots(monkeypatch):
    cache, files = secure_cache(monkeypatch)
    first, second = "3" * 32, "4" * 32
    cache.create_slot(first)
    cache.create_slot(second)
    with pytest.raises(UpdateError, match="cleanup_pending"):
        cache.create_slot("5" * 32)
    with pytest.raises(UpdateError, match="state_corrupt"):
        cache.validate_inventory((first,))
    assert set(files.root.children) == {
        storage_module.JOURNAL, storage_module.LOCK,
        "operation-" + first, "operation-" + second,
    }
    cache.close()


def test_measured_free_reserve_and_no_unsafe_slot_repair(monkeypatch):
    cache, files = secure_cache(monkeypatch)
    files.free = cache.limits.reserve_bytes
    with pytest.raises(UpdateError, match="storage_full"):
        cache.create_slot("3" * 32)
    files.free = 1024**3
    path = cache.create_slot("3" * 32)
    files.root.children[path.name].mode = 0o777
    with pytest.raises(UpdateError, match="storage_unsafe"):
        cache.retire_slot("3" * 32)
    assert files.root.children[path.name].mode == 0o777
    cache.close()


@pytest.mark.parametrize("stage", ["replace", "sync"])
def test_crash_publication_retains_uncertain_journal_not_recreated(monkeypatch, stage):
    cache, files = secure_cache(monkeypatch)
    original = files.root.children[storage_module.JOURNAL].data
    setattr(files, "fail_" + stage, True)
    with pytest.raises(OSError):
        cache.save(journal_to_json(Journal("test-policy", last_check_at=10)))
    assert files.root.children[storage_module.JOURNAL].data == original
    assert storage_module.NEXT_JOURNAL in files.root.children
    with pytest.raises(UpdateError, match="state_corrupt"):
        cache.load()
    cache.close()


def test_cleanup_rejects_unknown_nested_files_hardlinks_and_changed_root(monkeypatch):
    cache, files = secure_cache(monkeypatch)
    identity = "3" * 32
    path = cache.create_slot(identity)
    slot = files.root.children[path.name]
    slot.children["do-not-delete"] = files.node(data=b"private")
    slot.children["do-not-delete"].links = 2
    with pytest.raises(UpdateError, match="storage_unsafe"):
        cache.retire_slot(identity)
    assert slot.children["do-not-delete"].data == b"private"
    files.root.inode += 1
    with pytest.raises(UpdateError, match="storage_unsafe"):
        cache.save(journal_to_json(Journal("test-policy")))
    cache.close()


def test_prepared_hashes_sizes_exact_files_and_no_extra_copy(monkeypatch):
    cache, files = secure_cache(monkeypatch)
    identity = "3" * 32
    slot = files.root.children[cache.create_slot(identity).name]
    value = candidate()
    with pytest.raises(UpdateError, match="verification_failed"):
        cache.validate_slot(identity, value)
    slot.children.update({a.name: files.node(data=b"x") for a in value.assets})
    with pytest.raises(UpdateError, match="verification_failed"):
        cache.validate_slot(identity, value)
    value = replace(value, assets=tuple(replace(a, sha256=hashlib.sha256(b"x").hexdigest())
                                        for a in value.assets))
    slot.children[value.assets[0].name].data = b"xx"
    with pytest.raises(UpdateError, match="verification_failed"):
        cache.validate_slot(identity, value)
    slot.children[value.assets[0].name].data = b"x"
    cache.validate_slot(identity, value)
    assert len(slot.children) == 5
    cache.close()


def test_low_level_bounded_file_reads_and_short_writes(monkeypatch):
    fake = SimpleNamespace(read=lambda fd, size: b"x" * size, write=lambda fd, data: 0)
    monkeypatch.setattr(storage_module, "os", fake)
    with pytest.raises(UpdateError, match="storage_full"):
        storage_module._read_bounded(1, 10)
    with pytest.raises(UpdateError, match="storage_full"):
        storage_module._write_all(1, b"x")


def test_root_ancestry_requires_nonwritable_real_directories(monkeypatch):
    path = Path.cwd() / "synthetic"
    records = {parent: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
               for parent in path.parents}
    monkeypatch.setattr(Path, "lstat", lambda self: records[self])
    storage_module.check_ancestry(path)
    for mode, uid in [(stat.S_IFDIR | 0o775, 0), (stat.S_IFLNK | 0o755, 0),
                      (stat.S_IFDIR | 0o755, 42)]:
        records[path.parent] = SimpleNamespace(st_mode=mode, st_uid=uid)
        with pytest.raises(UpdateError, match="storage_unsafe"):
            storage_module.check_ancestry(path)
    with pytest.raises(UpdateError, match="storage_unsafe"):
        storage_module.check_ancestry(Path("relative"))


@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644])
def test_root_config_read_only_protected_file_modes(monkeypatch, mode):
    path = Path.cwd() / "synthetic-config"
    files = PosixFiles(path)
    files.root = files.node(data=b"configuration", mode=mode)
    files.root.uid = 0
    monkeypatch.setattr(storage_module, "os", files)
    monkeypatch.setattr(storage_module, "check_ancestry", lambda path: None)
    monkeypatch.setattr(Path, "lstat", lambda self: files.info(files.root))
    assert storage_module.read_protected_file(path, 100) == b"configuration"
    files.root.mode = 0o666
    with pytest.raises(UpdateError, match="storage_unsafe"):
        storage_module.read_protected_file(path, 100)
    files.root.mode = mode
    files.root.links = 2
    with pytest.raises(UpdateError, match="storage_unsafe"):
        storage_module.read_protected_file(path, 100)
    assert not files.handles


def test_protected_file_inode_substitution_is_not_accepted(monkeypatch):
    path = Path.cwd() / "synthetic-config"
    files = PosixFiles(path)
    files.root = files.node(data=b"configuration", mode=0o644)
    files.root.uid = 0
    monkeypatch.setattr(storage_module, "os", files)
    monkeypatch.setattr(storage_module, "check_ancestry", lambda path: None)
    original = files.info(files.root)
    replacement = files.info(files.root)
    replacement.st_ino += 1
    calls = iter([original, replacement])
    monkeypatch.setattr(Path, "lstat", lambda self: next(calls))
    with pytest.raises(UpdateError, match="storage_unsafe"):
        storage_module.read_protected_file(path, 100)
    assert not files.handles


def test_bootstrap_refuses_nonempty_cache_or_busy_lock(monkeypatch):
    cache, files = secure_cache(monkeypatch)
    with pytest.raises(UpdateError, match="state_corrupt"):
        cache.initialize(journal_to_json(Journal("test-policy")))
    cache.close()
    restarted = storage_module.SecureCache(files.path, UpdateLimits())
    restarted.acquire()
    restarted.close()
    def locked(*args):
        raise OSError("already held")
    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=locked))
    restarted = storage_module.SecureCache(files.path, UpdateLimits())
    with pytest.raises(UpdateError, match="busy"):
        restarted.acquire()
    restarted.close()
    assert not files.handles


def test_artifact_aggregate_and_entry_count_bounded(monkeypatch):
    cache, files = secure_cache(monkeypatch)
    path = cache.create_slot("3" * 32)
    slot = files.root.children[path.name]
    slot.children.update({str(index): files.node() for index in range(6)})
    with pytest.raises(UpdateError, match="storage_unsafe"):
        cache.create_slot("4" * 32)
    with pytest.raises(UpdateError, match="storage_unsafe"):
        cache.retire_slot("3" * 32)
    slot.children.clear()
    slot.children["owned"] = files.node(data=b"x")
    cache.limits = UpdateLimits(artifact_bytes=UpdateLimits().candidate_bytes)
    with pytest.raises(UpdateError, match="storage_full"):
        cache.create_slot("4" * 32)
    cache.close()


def test_slot_device_and_inode_substitution_rejected(monkeypatch):
    cache, files = secure_cache(monkeypatch)
    path = cache.create_slot("3" * 32)
    slot = files.root.children[path.name]
    slot.device = 3
    with pytest.raises(UpdateError, match="storage_unsafe"):
        cache.retire_slot("3" * 32)
    slot.device = 2
    real_open = files.open
    def substitute(name, *args, **kwargs):
        fd = real_open(name, *args, **kwargs)
        if name == path.name:
            files.handles[fd][0] = files.node(directory=True)
        return fd
    monkeypatch.setattr(files, "open", substitute)
    with pytest.raises(UpdateError, match="storage_unsafe"):
        cache.retire_slot("3" * 32)
    assert path.name in files.root.children
    cache.close()


def test_mount_profile_only_measured_persistent_dedicated_mount(monkeypatch):
    path = Path.cwd() / "synthetic-cache"
    monkeypatch.setattr(worker_module.os, "major", lambda dev: 8, raising=False)
    monkeypatch.setattr(worker_module.os, "minor", lambda dev: 1, raising=False)
    def content(kind="ext4", mount=None):
        return f"20 1 8:1 / {mount or path} rw - {kind} device rw\n"
    monkeypatch.setattr(worker_module, "open", lambda *args, **kwargs: io.StringIO(content()), raising=False)
    worker_module._persistent_mount(path, 1)
    assert worker_module._cache_mount(path, str(path.parent))
    assert not worker_module._cache_mount(path, path.anchor)
    for raw in [content("tmpfs"), content(mount="wrong"), "x" * (1024 * 1024 + 1), "malformed"]:
        monkeypatch.setattr(worker_module, "open", lambda *args, **kwargs: io.StringIO(raw))
        with pytest.raises(UpdateError, match="storage_unsafe"):
            worker_module._persistent_mount(path, 1)


def test_inherited_socket_provenance_no_public_binding(monkeypatch):
    path = Path.cwd() / "synthetic.sock"
    monkeypatch.setattr(socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(worker_module.os, "getpid", lambda: 100)
    monkeypatch.setenv("LISTEN_PID", "100")
    monkeypatch.setenv("LISTEN_FDS", "1")
    monkeypatch.setattr(worker_module, "check_ancestry", lambda path: None)
    info = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0)
    monkeypatch.setattr(Path, "lstat", lambda self: info)
    listener = Channel()
    listener.family, listener.type = socket.AF_UNIX, socket.SOCK_STREAM
    listener.getsockopt = lambda *args: 1
    listener.getsockname = lambda: str(path)
    monkeypatch.setattr(worker_module.socket, "socket", lambda *, fileno: listener)
    assert worker_module.inherited_socket() is listener
    info.st_mode = stat.S_IFSOCK | 0o666
    with pytest.raises(UpdateError, match="forbidden"):
        worker_module.inherited_socket()
    assert listener.closed
    info.st_mode = stat.S_IFSOCK | 0o660
    listener.family = -1
    with pytest.raises(UpdateError, match="forbidden"):
        worker_module.inherited_socket()
    listener.family = socket.AF_UNIX
    listener.getsockopt = lambda *args: 0
    with pytest.raises(UpdateError, match="forbidden"):
        worker_module.inherited_socket()
    monkeypatch.setenv("LISTEN_FDS", "2")
    with pytest.raises(UpdateError, match="forbidden"):
        worker_module.inherited_socket()


def test_child_process_parent_death_and_fd_confinement(monkeypatch):
    closed, limits = [], []
    monkeypatch.setattr(signal, "SIGKILL", 9, raising=False)
    monkeypatch.setattr(signal, "signal", lambda *args: None)
    fake_os = SimpleNamespace(
        umask=lambda mask: None, getppid=lambda: 100,
        closerange=lambda low, high: closed.append((low, high)),
    )
    monkeypatch.setattr(worker_module, "os", fake_os)
    monkeypatch.setattr(worker_module.ctypes, "CDLL", lambda *args, **kwargs: SimpleNamespace(prctl=lambda *args: 0))
    monkeypatch.setitem(sys.modules, "resource", SimpleNamespace(
        RLIMIT_NOFILE=1, RLIMIT_CORE=2, RLIM_INFINITY=-1,
        getrlimit=lambda name: (1024, 1024),
        setrlimit=lambda name, bounds: limits.append((name, bounds)),
    ))
    worker_module._child_setup(10, 100)
    assert closed == [(3, 10), (11, 1024)] and limits == [(2, (0, 0))]
    sys.modules["resource"].getrlimit = lambda name: (-1, -1)
    worker_module._child_setup(10, 100)
    assert closed[-1] == (11, 1048576)
    fake_os.getppid = lambda: 200
    with pytest.raises(UpdateError, match="interrupted"):
        worker_module._child_setup(10, 100)


async def test_read_job_requires_eof_and_size_limit(monkeypatch):
    values = iter([b"abc", b"def", b""])
    async def receive(channel, size):
        return next(values)
    fake_loop = SimpleNamespace(sock_recv=receive)
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: fake_loop)
    assert await worker_module._read_job(Channel()) == b"abcdef"
    async def oversized(channel, size):
        return b"x" * size
    fake_loop.sock_recv = oversized
    with pytest.raises(UpdateError, match="invalid_response"):
        await worker_module._read_job(Channel())


def test_init_status_never_construct_public_source(monkeypatch, capsys):
    instances = []
    class Cache(MemoryStorage):
        def __init__(self, *args):
            super().__init__()
            self.locked = self.closed = self.initialized = False
            instances.append(self)
        def acquire(self):
            self.locked = True
        def initialize(self, value):
            self.initialized = True
            self.value = value
        def close(self):
            self.closed = True
    monkeypatch.setattr(worker_module, "SecureCache", Cache)
    monkeypatch.setitem(sys.modules, "strugglebus.update_source", SimpleNamespace(POLICY_ID="test-policy"))
    config = worker_module.config_from_json(config_json())
    worker_module._run_command("init", config)
    assert instances[-1].locked and instances[-1].initialized and instances[-1].closed
    worker_module._run_command("status", config)
    assert not instances[-1].locked and instances[-1].closed
    assert '"state":"idle"' in capsys.readouterr().out
    served = []
    async def serve(*args):
        served.append(args)
    monkeypatch.setattr(worker_module, "_serve", serve)
    worker_module._run_command("serve", config)
    assert served[0][0] == config and instances[-1].closed


def test_cli_success_and_os_error_redaction(monkeypatch, capsys):
    monkeypatch.setattr(worker_module, "load_config", lambda path: object())
    monkeypatch.setattr(worker_module, "_run_command", lambda *args: None)
    args = ["status", "--config", str(Path.cwd() / "config")]
    assert worker_module.main(args) == 0
    def failure(*args):
        raise OSError("root secret pathname")
    monkeypatch.setattr(worker_module, "_run_command", failure)
    assert worker_module.main(args) == 1
    assert capsys.readouterr().err == "unavailable\n"


def test_offline_reconciliation_verifies_source_and_owned_bytes(monkeypatch):
    calls = []
    monkeypatch.setitem(sys.modules, "strugglebus.update_source", SimpleNamespace(
        verify_prepared=lambda *args: calls.append(("offline", args)),
    ))
    class Cache:
        def __init__(self, *args):
            calls.append(("open", args))
        def validate_slot(self, *args):
            calls.append(("bytes", args))
        def close(self):
            calls.append(("close", ()))
    monkeypatch.setattr(worker_module, "SecureCache", Cache)
    path = Path("synthetic") / ("operation-" + "3" * 32)
    worker_module._offline_verify(candidate(), path, UpdateLimits())
    assert [call[0] for call in calls] == ["offline", "open", "bytes", "close"]
    assert calls[2][1] == ("3" * 32, candidate())


async def test_server_reconciles_prepared_offline_before_accepting(monkeypatch):
    instance, _, _ = worker()
    prepared(instance.state)
    calls = []
    monkeypatch.setattr(worker_module, "_offline_verify", lambda *args: calls.append(args))
    async def serve(callback, **kwargs):
        assert calls
        return SimpleNamespace()
    monkeypatch.setattr(asyncio, "start_unix_server", serve, raising=False)
    await instance.serve(object())
    assert calls[0][0] == candidate()


async def test_signal_server_lifecycle_and_storage_independence(monkeypatch):
    config = worker_module.config_from_json(config_json())
    storage = MemoryStorage()
    calls = []
    class Worker:
        def __init__(self, state, runner, uid):
            calls.append(("construct", uid))
        async def serve(self, listener):
            calls.append(("serve", listener))
        async def close(self):
            calls.append(("close",))
    monkeypatch.setattr(worker_module, "UpdateWorker", Worker)
    monkeypatch.setattr(worker_module, "inherited_socket", lambda: "inherited")
    actual_loop = asyncio.get_running_loop()
    def add_signal_handler(sig, callback):
        actual_loop.call_soon(callback)
    monkeypatch.setattr(actual_loop, "add_signal_handler", add_signal_handler)
    await worker_module._serve(config, storage, "test-policy")
    assert calls == [("construct", 1000), ("serve", "inherited"), ("close",)]


async def test_late_success_cannot_beat_absolute_deadline(monkeypatch):
    instance, _, runner = worker(Runner(result=discovery()))
    now = time.monotonic()
    times = iter([now, now + 121])
    monkeypatch.setattr(worker_module, "time", SimpleNamespace(monotonic=lambda: next(times), time=lambda: 100))
    instance.dispatch(check_request())
    await instance.job
    assert instance.state.status().operation.error == "timeout"


async def test_internal_dead_current_and_fail_publication_are_safe():
    instance, storage, _ = worker()
    await instance._execute()
    instance._fail("timeout")
    instance.state.accept(check_request(), now=100)
    storage.fail_save = True
    instance._fail("timeout")
    assert not instance.state.healthy
    assert instance.state.journal.current.operation.phase == "accepted"


async def test_handler_transport_exception_releases_admission():
    instance, _, _ = worker()
    writer = Writer()
    def broken(data):
        raise OSError("private")
    writer.write = broken
    instance._connected(reader_for(encode_frame(request_to_json(UpdateRequest("status")), REQUEST_BYTES)), writer)
    await asyncio.gather(*tuple(instance.connections))
    assert writer.closed and instance.active_connections == 0


async def test_response_storage_os_error_is_static(monkeypatch):
    instance, _, _ = worker()
    def broken(request):
        raise OSError("private")
    monkeypatch.setattr(instance, "dispatch", broken)
    result = await instance._response(
        reader_for(encode_frame(request_to_json(UpdateRequest("status")), REQUEST_BYTES)), Writer(),
    )
    assert result["error"] == "storage_unsafe"


async def test_reap_waits_without_blocking_status_and_missing_child_is_safe(monkeypatch):
    _, signals = install_process_adapter(monkeypatch)
    statuses = iter([(0, 0), (321, 0)])
    monkeypatch.setattr(worker_module.os, "waitpid", lambda pid, flags: next(statuses))
    runner = worker_module.ProcessJobRunner(lambda: None, UpdateLimits())
    runner.pid = 321
    await runner._reap(321)
    assert runner.pid is None
    runner.pid = 321
    def missing(*args):
        raise ProcessLookupError()
    monkeypatch.setattr(worker_module.os, "kill", missing)
    monkeypatch.setattr(worker_module.os, "waitpid", lambda *args: (321, 0))
    await runner._terminate(321)
    assert runner.pid is None


def test_new_file_failed_mode_verification_does_not_leak_fd(monkeypatch):
    cache, files = secure_cache(monkeypatch)
    handles = set(files.handles)
    monkeypatch.setattr(files, "fchmod", lambda *args: (_ for _ in ()).throw(OSError("cannot set mode")))
    with pytest.raises(OSError):
        cache._create_file("new-owned-file")
    assert set(files.handles) == handles
    cache.close()


def test_config_container_and_path_types_strict():
    with pytest.raises(UpdateError, match="invalid_request"):
        worker_module.config_from_json([])
    with pytest.raises(UpdateError, match="invalid_request"):
        worker_module._absolute_path(None)


def test_descriptor_entry_identity_revalidated_before_unlink(monkeypatch):
    cache, files = secure_cache(monkeypatch)
    fd = cache._open_file(storage_module.JOURNAL)
    files.root.children[storage_module.JOURNAL] = files.node(data=b"replacement")
    with pytest.raises(UpdateError, match="storage_unsafe"):
        cache._check_entry(cache.fd, storage_module.JOURNAL, fd)
    files.close(fd)
    cache.close()


async def test_fork_child_branch_never_returns_into_server(monkeypatch):
    class ChildExit(BaseException):
        pass
    channels, _ = install_process_adapter(monkeypatch)
    monkeypatch.setattr(worker_module.os, "fork", lambda: 0)
    calls = []
    def child(*args):
        calls.append(args)
        channels[1].close()
    def terminate(code):
        assert code == 1
        raise ChildExit()
    monkeypatch.setattr(worker_module, "_child_main", child)
    monkeypatch.setattr(worker_module.os, "_exit", terminate, raising=False)
    runner = worker_module.ProcessJobRunner(lambda: None, UpdateLimits())
    with pytest.raises(ChildExit):
        await runner.run(check_request(), None, None, deadline=time.monotonic() + 1)
    assert calls[0][1] == 111
    assert all(channel.closed for channel in channels)
    assert runner.pid is None


def test_cli_runtime_requires_protected_installed_distribution(monkeypatch):
    with pytest.raises(UpdateError, match="forbidden"):
        worker_module._validate_runtime()
    current = Path("/opt/strugglebus-updater/current")
    target = current.parent / "releases" / "0.2.33"
    relative = Path("venv/lib/site-packages/strugglebus/update_worker.py")
    alias, path = current / relative, target / relative
    monkeypatch.setattr(worker_module, "__file__", str(alias))
    monkeypatch.setattr(Path, "absolute", lambda self: alias)
    monkeypatch.setattr(Path, "is_absolute", lambda self: True)
    resolved = []

    def resolve(item, *, strict=False):
        resolved.append((item, strict))
        if item == current:
            return target
        if item == target:
            return target
        if item == alias:
            return path
        return item

    monkeypatch.setattr(Path, "resolve", resolve)
    monkeypatch.setattr(worker_module.os, "readlink", lambda item: os.fspath(target))
    ancestry = []
    monkeypatch.setattr(worker_module, "check_ancestry", ancestry.append)
    file_info = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)
    link_info = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda self: link_info if self == current else file_info,
    )
    monkeypatch.setattr(worker_module.metadata, "distribution",
                        lambda name: SimpleNamespace(locate_file=lambda relative: alias))
    worker_module._validate_runtime()
    assert ancestry == [current, path]
    assert all(strict is True for _, strict in resolved)
    link_info.st_uid = 1
    with pytest.raises(UpdateError, match="forbidden"):
        worker_module._validate_runtime()
    link_info.st_uid = 0
    file_info.st_mode |= 0o020
    with pytest.raises(UpdateError, match="forbidden"):
        worker_module._validate_runtime()
    file_info.st_mode = stat.S_IFREG | 0o644
    monkeypatch.setattr(worker_module.metadata, "distribution",
                        lambda name: SimpleNamespace(locate_file=lambda relative: path.parent / "other.py"))
    with pytest.raises(UpdateError, match="forbidden"):
        worker_module._validate_runtime()


@pytest.mark.parametrize("failed_alias_resolution", [1, 2])
def test_cli_runtime_rejects_unresolvable_runtime_identity(
    monkeypatch, failed_alias_resolution,
):
    current = Path("/opt/strugglebus-updater/current")
    target = current.parent / "releases" / "0.2.33"
    relative = Path("venv/lib/site-packages/strugglebus/update_worker.py")
    alias, path = current / relative, target / relative
    monkeypatch.setattr(worker_module, "__file__", str(alias))
    monkeypatch.setattr(Path, "absolute", lambda self: alias)
    monkeypatch.setattr(Path, "is_absolute", lambda self: True)
    alias_resolutions = 0

    def resolve(item, *, strict=False):
        nonlocal alias_resolutions
        assert strict is True
        if item == target:
            return target
        if item == alias:
            alias_resolutions += 1
            if alias_resolutions == failed_alias_resolution:
                raise OSError("unresolvable")
            return path
        return item

    monkeypatch.setattr(Path, "resolve", resolve)
    monkeypatch.setattr(worker_module.os, "readlink", lambda item: os.fspath(target))
    monkeypatch.setattr(worker_module, "check_ancestry", lambda item: None)
    file_info = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)
    link_info = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda self: link_info if self == current else file_info,
    )
    monkeypatch.setattr(
        worker_module.metadata,
        "distribution",
        lambda name: SimpleNamespace(locate_file=lambda relative: alias),
    )

    with pytest.raises(UpdateError, match="forbidden"):
        worker_module._validate_runtime()


async def test_incomplete_internal_adapters_cannot_succeed_silently():
    class IncompleteStorage(storage_module.StateStorage):
        pass
    class IncompleteSource(worker_module.ReleaseSource):
        policy_id = "test-policy"
    class IncompleteRunner(worker_module.JobRunner):
        pass
    store = IncompleteStorage()
    for method, args in [
        (store.load, ()), (store.save, ({},)), (store.create_slot, ("3" * 32,)),
        (store.slot_path, ("3" * 32,)), (store.retire_slot, ("3" * 32,)),
        (store.validate_slot, ("3" * 32, candidate())), (store.validate_inventory, ((),)),
    ]:
        with pytest.raises(NotImplementedError):
            method(*args)
    source = IncompleteSource()
    with pytest.raises(NotImplementedError):
        source.check("1.0.0", deadline=100)
    with pytest.raises(NotImplementedError):
        source.prepare(candidate(), Path("synthetic"), deadline=100)
    with pytest.raises(NotImplementedError):
        await IncompleteRunner().run(check_request(), None, None, deadline=100)


async def test_lost_client_ack_does_not_cancel_durable_exact_job():
    instance, _, runner = worker(Runner(result=discovery(), block=True))
    writer = Writer()
    def lost_reply(data):
        raise BrokenPipeError("caller vanished")
    writer.write = lost_reply
    instance._connected(
        reader_for(encode_frame(request_to_json(check_request()), REQUEST_BYTES)), writer,
    )
    await asyncio.gather(*tuple(instance.connections))
    await runner.entered.wait()
    assert instance.state.status("1" * 32).operation.phase == "running"
    runner.release.set()
    await instance.job
    assert instance.state.status("1" * 32).operation.phase == "succeeded"
    assert len(runner.calls) == 1


async def test_quarantine_creation_failure_never_starts_external_work():
    instance, storage, runner = worker(Runner())
    request = checked(instance.state, now=int(time.time()) - 2)
    storage.fail_create = True
    instance.dispatch(request)
    await instance.job
    assert instance.state.status(request.operation_id).operation.error == "storage_full"
    assert not runner.calls and not storage.slots


def test_protected_file_open_identity_rechecked_and_growth_refused(monkeypatch):
    path = Path.cwd() / "synthetic-config"
    files = PosixFiles(path)
    files.root = files.node(data=b"configuration", mode=0o644)
    files.root.uid = 0
    monkeypatch.setattr(storage_module, "os", files)
    monkeypatch.setattr(storage_module, "check_ancestry", lambda path: None)
    monkeypatch.setattr(Path, "lstat", lambda self: files.info(files.root))
    before = files.info(files.root)
    before.st_ino += 1
    monkeypatch.setattr(files, "fstat", lambda fd: before)
    with pytest.raises(UpdateError, match="storage_unsafe"):
        storage_module.read_protected_file(path, 100)
    before.st_size = 1
    monkeypatch.setattr(files, "read", lambda fd, size: b"x" * size)
    with pytest.raises(UpdateError, match="verification_failed"):
        storage_module._hash_file(1, 1)
