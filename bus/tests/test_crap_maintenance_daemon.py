"""The root-owned maintenance socket and timer entry point."""

import asyncio
from contextlib import contextmanager
from dataclasses import replace
import os
from pathlib import Path
import socket
import stat
import struct
import sys
from types import SimpleNamespace

import pytest

import strugglebus.maintenance_client as client_module
import strugglebus.maintenance_daemon as daemon
from strugglebus.maintenance_client import MaintenanceClient
from strugglebus.maintenance_runtime import config_from_json
from strugglebus.maintenance_state import MaintenanceState
from strugglebus.maintenance_types import (
    MAINTENANCE_REQUEST_BYTES,
    MAINTENANCE_RESPONSE_BYTES,
    MaintenanceError,
    MaintenanceRequest,
    request_to_json,
    response_from_json,
)
from strugglebus.update_types import decode_frame, encode_frame
from test_maintenance_runtime import configuration

OPERATION = "a" * 32
ACTOR = "operator:test"
linux_only = pytest.mark.skipif(sys.platform != "linux", reason="requires Linux sockets and flock")


@pytest.fixture
def config(tmp_path):
    return replace(
        config_from_json(configuration()),
        application_uid=998,
        state_path=tmp_path / "state" / "supervisor.json",
    )


def _as_root_owned(monkeypatch, function_owner, name):
    """Report files the test user created as owned by root, as they are in production."""
    real = getattr(function_owner, name)

    def owned_by_root(*args, **kwargs):
        info = real(*args, **kwargs)
        fields = {key: getattr(info, key) for key in dir(info) if key.startswith("st_")}
        fields["st_uid"] = 0
        return SimpleNamespace(**fields)

    monkeypatch.setattr(function_owner, name, owned_by_root)


# --- inherited socket -------------------------------------------------------


class _Listener:
    def __init__(self, path, *, family=None, kind=socket.SOCK_STREAM, accepting=1):
        self.family = getattr(socket, "AF_UNIX", 1) if family is None else family
        self.type = kind
        self.accepting = accepting
        self.path = path
        self.blocking = True
        self.closed = False

    def getsockopt(self, level, option):
        assert (level, option) == (socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        return self.accepting

    def getsockname(self):
        return str(self.path)

    def setblocking(self, flag):
        self.blocking = flag

    def close(self):
        self.closed = True


@pytest.fixture
def activation(monkeypatch, tmp_path):
    """Systemd socket activation handing over one protected listening socket."""
    monkeypatch.setattr(daemon.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setenv("LISTEN_PID", str(os.getpid()))
    monkeypatch.setenv("LISTEN_FDS", "1")
    path = tmp_path / "control.sock"
    info = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0)
    real_lstat = Path.lstat
    monkeypatch.setattr(
        Path, "lstat", lambda target: info if target == path else real_lstat(target),
    )
    state = SimpleNamespace(listener=_Listener(path), info=info, descriptors=[])

    def adopt(*, fileno):
        state.descriptors.append(fileno)
        return state.listener

    monkeypatch.setattr(daemon.socket, "socket", adopt)
    return state


def test_inherited_socket_adopts_descriptor_three_without_blocking(activation):
    assert daemon.inherited_socket() is activation.listener
    assert activation.descriptors == [3]
    assert activation.listener.blocking is False
    assert activation.listener.closed is False


@pytest.mark.parametrize(
    ("name", "value"),
    [("LISTEN_PID", "1"), ("LISTEN_FDS", "2"), ("LISTEN_FDS", "0")],
)
def test_socket_activation_for_another_process_is_forbidden(activation, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(MaintenanceError, match="forbidden"):
        daemon.inherited_socket()
    assert activation.descriptors == []


def test_missing_socket_activation_is_forbidden(activation, monkeypatch):
    monkeypatch.delenv("LISTEN_PID")
    with pytest.raises(MaintenanceError, match="forbidden"):
        daemon.inherited_socket()
    assert activation.descriptors == []


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param({"family": socket.AF_INET}, id="network-socket"),
        pytest.param({"kind": socket.SOCK_DGRAM}, id="datagram-socket"),
        pytest.param({"accepting": 0}, id="not-listening"),
    ],
)
def test_inherited_descriptor_of_the_wrong_kind_is_closed(activation, changes):
    activation.listener = _Listener(activation.listener.path, **changes)
    with pytest.raises(MaintenanceError, match="forbidden"):
        daemon.inherited_socket()
    assert activation.listener.closed is True
    assert activation.listener.blocking is True


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param({"st_mode": stat.S_IFREG | 0o660}, id="regular-file"),
        pytest.param({"st_uid": 998}, id="application-owned"),
        pytest.param({"st_mode": stat.S_IFSOCK | 0o666}, id="world-writable"),
    ],
)
def test_inherited_socket_at_an_unprotected_path_is_closed(activation, changes):
    for name, value in changes.items():
        setattr(activation.info, name, value)
    with pytest.raises(MaintenanceError, match="forbidden"):
        daemon.inherited_socket()
    assert activation.listener.closed is True


def test_inherited_socket_is_closed_when_its_path_is_gone(activation, tmp_path):
    activation.listener.path = tmp_path / "missing.sock"
    with pytest.raises(FileNotFoundError):
        daemon.inherited_socket()
    assert activation.listener.closed is True


# --- peer credentials -------------------------------------------------------


class _Connection:
    def __init__(self, uid=998, error=None):
        self.uid = uid
        self.error = error

    def getsockopt(self, level, option, size):
        assert (level, size) == (socket.SOL_SOCKET, 12)
        if self.error is not None:
            raise self.error
        return struct.pack("3i", 4242, self.uid, 0)


class _Writer:
    def __init__(self, connection=None, *, close_error=None):
        self.connection = connection
        self.sent = bytearray()
        self.closed = False
        self.close_error = close_error

    def get_extra_info(self, name):
        return self.connection if name == "socket" else None

    def write(self, data):
        self.sent.extend(data)

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        if self.close_error is not None:
            raise self.close_error

    def reply(self):
        return decode_frame(bytes(self.sent), MAINTENANCE_RESPONSE_BYTES)


@pytest.fixture
def peer_credentials(monkeypatch):
    monkeypatch.setattr(daemon.socket, "SO_PEERCRED", 17, raising=False)


def test_only_the_application_user_is_an_allowed_peer(peer_credentials):
    assert daemon._peer_allowed(_Writer(_Connection(998)), 998) is True
    assert daemon._peer_allowed(_Writer(_Connection(0)), 998) is False
    assert daemon._peer_allowed(_Writer(_Connection(1000)), 998) is False


def test_peer_without_readable_credentials_is_not_allowed(peer_credentials):
    assert daemon._peer_allowed(_Writer(None), 998) is False
    assert daemon._peer_allowed(_Writer(_Connection(error=OSError("no credentials"))), 998) is False


# --- state lock -------------------------------------------------------------


@linux_only
def test_state_lock_creates_a_private_lock_beside_the_state(config, monkeypatch):
    _as_root_owned(monkeypatch, daemon.os, "fstat")
    lock = config.state_path.with_suffix(".lock")

    with daemon._state_lock(config, blocking=False):
        assert stat.S_IMODE(lock.stat().st_mode) == 0o600
        assert stat.S_IMODE(lock.parent.stat().st_mode) == 0o700
        with pytest.raises(MaintenanceError, match="busy"):
            with daemon._state_lock(config, blocking=False):
                raise AssertionError("a held lock must not be granted twice")

    with daemon._state_lock(config, blocking=True):
        pass


@linux_only
def test_state_lock_is_released_when_the_guarded_work_fails(config, monkeypatch):
    _as_root_owned(monkeypatch, daemon.os, "fstat")
    with pytest.raises(RuntimeError, match="work failed"):
        with daemon._state_lock(config, blocking=False):
            raise RuntimeError("work failed")
    with daemon._state_lock(config, blocking=False):
        pass


@linux_only
def test_state_lock_not_owned_by_root_is_corrupt_state(config):
    with pytest.raises(MaintenanceError, match="state_corrupt"):
        with daemon._state_lock(config, blocking=False):
            raise AssertionError("an unprotected lock must not be granted")


@linux_only
@pytest.mark.parametrize("defect", ["shared-mode", "hard-link", "directory"])
def test_tampered_state_lock_is_corrupt_state(config, monkeypatch, defect):
    _as_root_owned(monkeypatch, daemon.os, "fstat")
    lock = config.state_path.with_suffix(".lock")
    lock.parent.mkdir(mode=0o700)
    if defect == "directory":
        lock.mkdir(mode=0o700)
        expected = IsADirectoryError
    else:
        lock.touch(mode=0o600)
        expected = MaintenanceError
        if defect == "shared-mode":
            lock.chmod(0o660)
        else:
            os.link(lock, lock.with_name("alias.lock"))

    with pytest.raises(expected):
        with daemon._state_lock(config, blocking=False):
            raise AssertionError("a tampered lock must not be granted")


@linux_only
def test_symlinked_state_lock_is_not_followed(config, tmp_path):
    lock = config.state_path.with_suffix(".lock")
    lock.parent.mkdir(mode=0o700)
    victim = tmp_path / "victim"
    victim.write_bytes(b"")
    lock.symlink_to(victim)
    with pytest.raises(OSError):
        with daemon._state_lock(config, blocking=False):
            raise AssertionError("a symlinked lock must not be granted")


# --- trigger ----------------------------------------------------------------


def test_trigger_starts_the_run_unit_without_waiting_for_it(config, monkeypatch):
    calls = []

    def spawn(mode, executable, argv):
        calls.append((mode, executable, argv))
        return 0

    monkeypatch.setattr(daemon.os, "spawnv", spawn)
    daemon._trigger(config)
    assert calls == [(
        os.P_WAIT,
        str(config.systemctl),
        [str(config.systemctl), "start", "--no-block", "strugglebus-maintenance-run.service"],
    )]


def test_trigger_reports_a_refused_or_unstartable_unit_as_unavailable(config, monkeypatch):
    monkeypatch.setattr(daemon.os, "spawnv", lambda *arguments: 1)
    with pytest.raises(MaintenanceError, match="unavailable"):
        daemon._trigger(config)

    def missing(*arguments):
        raise FileNotFoundError("systemctl")

    monkeypatch.setattr(daemon.os, "spawnv", missing)
    with pytest.raises(MaintenanceError, match="unavailable"):
        daemon._trigger(config)


# --- request handling -------------------------------------------------------


def _reader(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


def _frame(request: MaintenanceRequest) -> bytes:
    return encode_frame(request_to_json(request), MAINTENANCE_REQUEST_BYTES)


async def test_request_is_read_no_further_than_one_byte_past_the_ceiling():
    assert await daemon._read_request(_reader(b"abc\n")) == b"abc\n"
    oversized = await daemon._read_request(_reader(b"x" * (MAINTENANCE_REQUEST_BYTES + 500)))
    assert len(oversized) == MAINTENANCE_REQUEST_BYTES + 1


@pytest.fixture
def handler(config, monkeypatch, peer_credentials):
    """Drive ``_handle`` against real durable state with the root-only edges recorded."""
    events = []

    @contextmanager
    def lock(lock_config, *, blocking):
        events.append(("lock", blocking))
        if "busy" in events:
            raise MaintenanceError("busy")
        yield
        events.append("unlock")

    monkeypatch.setattr(daemon, "_state_lock", lock)
    monkeypatch.setattr(daemon, "active_application_version", lambda lock_config: "0.2.49")
    monkeypatch.setattr(daemon, "_trigger", lambda lock_config: events.append("trigger"))

    async def handle(data, *, uid=998, writer=None):
        writer = writer or _Writer(_Connection(uid))
        await daemon._handle(_reader(data), writer, config)
        return writer

    return SimpleNamespace(handle=handle, events=events, config=config)


async def test_status_request_is_answered_under_a_non_blocking_lock(handler):
    writer = await handler.handle(_frame(MaintenanceRequest("status")))

    status = response_from_json(writer.reply())
    assert status.current_version == "0.2.49"
    assert status.policy.enabled is True
    assert status.attempt is None
    assert handler.events == [("lock", False), "unlock"]
    assert writer.closed is True


async def test_configure_request_is_persisted(handler):
    writer = await handler.handle(
        _frame(MaintenanceRequest("configure", OPERATION, ACTOR, False, 4, 30)),
    )

    status = response_from_json(writer.reply())
    assert (status.policy.enabled, status.policy.hour, status.policy.minute) == (False, 4, 30)
    saved = MaintenanceState(handler.config.state_path, "0.2.49").journal.policy
    assert (saved.enabled, saved.hour, saved.minute) == (False, 4, 30)
    assert "trigger" not in handler.events


async def test_install_request_is_accepted_once_and_triggers_the_run_unit(handler):
    frame = _frame(MaintenanceRequest("install", OPERATION, ACTOR))

    first = response_from_json((await handler.handle(frame)).reply())
    assert (first.attempt.operation_id, first.attempt.phase, first.attempt.mode) == (
        OPERATION, "accepted", "manual",
    )
    assert handler.events.count("trigger") == 1

    other = _frame(MaintenanceRequest("install", "b" * 32, ACTOR))
    assert (await handler.handle(other)).reply()["error"] == "busy"
    assert handler.events.count("trigger") == 1


async def test_request_from_another_user_is_refused_before_it_is_read(handler):
    writer = await handler.handle(_frame(MaintenanceRequest("install", OPERATION, ACTOR)), uid=1000)

    assert writer.reply() == {"version": 1, "ok": False, "error": "forbidden", "status": None}
    assert handler.events == []
    assert not handler.config.state_path.exists()
    assert writer.closed is True


async def test_contended_state_is_reported_as_busy(handler):
    handler.events.append("busy")
    writer = await handler.handle(_frame(MaintenanceRequest("status")))
    assert writer.reply()["error"] == "busy"


@pytest.mark.parametrize(
    ("data", "error"),
    [
        pytest.param(b"", "internal_error", id="empty"),
        pytest.param(b"{}\n", "internal_error", id="wrong-keys"),
        pytest.param(
            b"x" * (MAINTENANCE_REQUEST_BYTES + 10), "internal_error", id="oversized",
        ),
        pytest.param(
            encode_frame(
                request_to_json(MaintenanceRequest("status")) | {"action": "reboot"},
                MAINTENANCE_REQUEST_BYTES,
            ),
            "invalid_request",
            id="unknown-action",
        ),
    ],
)
async def test_malformed_request_is_answered_without_touching_state(handler, data, error):
    writer = await handler.handle(data)

    assert writer.reply() == {"version": 1, "ok": False, "error": error, "status": None}
    assert handler.events == []
    assert writer.closed is True


async def test_unexpected_failure_is_answered_as_an_internal_error(handler, monkeypatch):
    def explode(lock_config):
        raise RuntimeError("secret detail")

    monkeypatch.setattr(daemon, "active_application_version", explode)
    writer = await handler.handle(_frame(MaintenanceRequest("status")))

    assert writer.reply() == {"version": 1, "ok": False, "error": "internal_error", "status": None}
    assert b"secret" not in writer.sent


async def test_reply_is_delivered_even_if_the_peer_resets_on_close(handler):
    writer = _Writer(_Connection(998), close_error=ConnectionResetError())
    await handler.handle(_frame(MaintenanceRequest("status")), writer=writer)
    assert writer.reply()["ok"] is True
    assert writer.closed is True


# --- serve and run ----------------------------------------------------------


async def test_serve_listens_on_the_inherited_socket_with_a_bounded_reader(config, monkeypatch):
    listener = object()
    started = {}
    handled = []

    class Server:
        async def __aenter__(self):
            started["entered"] = True
            return self

        async def __aexit__(self, *error):
            started["exited"] = True

        async def serve_forever(self):
            await started["callback"]("reader", "writer")

    async def start(callback, *, sock, limit):
        started.update(callback=callback, sock=sock, limit=limit)
        return Server()

    async def handle(reader, writer, handled_config):
        handled.append((reader, writer, handled_config))

    monkeypatch.setattr(daemon, "inherited_socket", lambda: listener)
    monkeypatch.setattr(daemon.asyncio, "start_unix_server", start, raising=False)
    monkeypatch.setattr(daemon, "_handle", handle)

    await daemon.serve(config)

    assert started["sock"] is listener
    assert started["limit"] == MAINTENANCE_REQUEST_BYTES + 1
    assert started["exited"] is True
    assert handled == [("reader", "writer", config)]


@linux_only
async def test_served_socket_answers_the_application_client(config, monkeypatch, tmp_path):
    path = tmp_path / "control.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(1)
    listener.setblocking(False)
    config = replace(config, application_uid=os.getuid())
    _as_root_owned(monkeypatch, daemon.os, "fstat")
    monkeypatch.setattr(daemon, "inherited_socket", lambda: listener)
    monkeypatch.setattr(daemon, "active_application_version", lambda served: "0.2.49")
    triggered = []
    monkeypatch.setattr(daemon, "_trigger", lambda served: triggered.append(served))
    # The test user is not root, so the client cannot see a root-owned supervisor.
    monkeypatch.setattr(client_module, "_verify_socket_path", lambda checked: (1, 1))
    monkeypatch.setattr(client_module, "_verify_root_peer", lambda writer: None)

    server = asyncio.ensure_future(daemon.serve(config))
    try:
        client = MaintenanceClient(path)
        assert (await client.status()).current_version == "0.2.49"
        installed = await client.install(OPERATION, ACTOR)
        assert installed.attempt.phase == "accepted"
        assert triggered == [config]
        with pytest.raises(MaintenanceError, match="unknown_outcome"):
            await client.install("b" * 32, ACTOR)
    finally:
        server.cancel()
        with pytest.raises(asyncio.CancelledError):
            await server


def test_run_drives_pending_maintenance_under_a_blocking_lock(config, monkeypatch):
    events = []

    @contextmanager
    def lock(lock_config, *, blocking):
        events.append(("lock", blocking))
        yield
        events.append("unlock")

    class Runner:
        def __init__(self, state, gateway, installer, announcer):
            events.append((
                state.current_version,
                type(gateway).__name__,
                type(installer).__name__,
                type(announcer).__name__,
                gateway.config is installer.config is announcer.config is config,
            ))

        def run_pending(self):
            events.append("run")
            return True

    monkeypatch.setattr(daemon, "_state_lock", lock)
    monkeypatch.setattr(daemon, "active_application_version", lambda lock_config: "0.2.49")
    monkeypatch.setattr(daemon, "MaintenanceRunner", Runner)

    assert daemon.run(config) is True
    assert events == [
        ("lock", True),
        ("0.2.49", "PreparedReleaseGateway", "HostReleaseInstaller", "BoardAnnouncer", True),
        "run",
        "unlock",
    ]


# --- command line -----------------------------------------------------------


@pytest.fixture
def command(config, monkeypatch):
    events = []

    @contextmanager
    def lock(lock_config, *, blocking):
        events.append(("lock", blocking))
        yield

    async def serve(served):
        events.append(("serve", served))

    def load(path):
        events.append(("load", path))
        return config

    monkeypatch.setattr(daemon, "load_config", load)
    monkeypatch.setattr(daemon, "_state_lock", lock)
    monkeypatch.setattr(daemon, "active_application_version", lambda lock_config: "0.2.49")
    monkeypatch.setattr(daemon, "serve", serve)
    monkeypatch.setattr(daemon, "run", lambda ran: events.append(("run", ran)))
    return SimpleNamespace(events=events, config=config)


def test_status_action_prints_the_policy(command, capsys):
    state = MaintenanceState(command.config.state_path, "0.2.49")
    state.configure(enabled=False, hour=3, minute=5)

    assert daemon.main(["status", "--config", "/etc/strugglebus/maintenance.json"]) == 0

    assert capsys.readouterr().out == "enabled=false window=03:05 timezone=Australia/Brisbane\n"
    assert command.events == [
        ("load", Path("/etc/strugglebus/maintenance.json")), ("lock", True),
    ]


def test_init_action_creates_default_state_silently(command, capsys):
    assert daemon.main(["init", "--config", "/etc/strugglebus/maintenance.json"]) == 0

    assert capsys.readouterr().out == ""
    journal = MaintenanceState(command.config.state_path, "0.2.49").journal
    assert journal.policy.enabled is True
    assert journal.attempt is None


def test_serve_and_run_actions_reach_their_entry_points(command):
    assert daemon.main(["serve", "--config", "/c.json"]) == 0
    assert daemon.main(["run", "--config", "/c.json"]) == 0
    assert [event[0] for event in command.events] == ["load", "serve", "load", "run"]
    assert command.events[1] == ("serve", command.config)
    assert command.events[3] == ("run", command.config)


def test_supervisor_failure_exits_one_with_only_its_code(command, monkeypatch, capsys):
    def refuse(path):
        raise MaintenanceError("forbidden")

    monkeypatch.setattr(daemon, "load_config", refuse)

    assert daemon.main(["run", "--config", "/c.json"]) == 1

    captured = capsys.readouterr()
    assert (captured.out, captured.err) == ("", "forbidden\n")


def test_interrupted_service_exits_cleanly(command, monkeypatch):
    def interrupt(config):
        raise KeyboardInterrupt

    monkeypatch.setattr(daemon, "run", interrupt)
    assert daemon.main(["run", "--config", "/c.json"]) == 0


def test_unknown_action_or_missing_config_is_a_usage_error(command):
    with pytest.raises(SystemExit) as caught:
        daemon.main(["restart", "--config", "/c.json"])
    assert caught.value.code == 2
    with pytest.raises(SystemExit):
        daemon.main(["status"])
    assert command.events == []
