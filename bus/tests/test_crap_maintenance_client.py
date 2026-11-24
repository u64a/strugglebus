"""The application-side client of the root-owned maintenance supervisor."""

import asyncio
from pathlib import Path
import socket
import stat
import struct
from types import SimpleNamespace

import pytest

import strugglebus.maintenance_client as client_module
from strugglebus.maintenance_client import MaintenanceClient
from strugglebus.maintenance_types import (
    MAINTENANCE_REQUEST_BYTES,
    MAINTENANCE_RESPONSE_BYTES,
    MaintenanceError,
    MaintenancePolicy,
    MaintenanceStatus,
    request_from_json,
    response_to_json,
)
from strugglebus.update_types import UpdateError, decode_frame, encode_frame

OPERATION = "a" * 32
ACTOR = "operator:test"
STATUS = MaintenanceStatus(MaintenancePolicy(), "0.2.49", None, 1_800_000_000, None)
SOCKET = Path("/run/strugglebus-maintenance/control.sock")
DIRECTORY = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)


def _socket_info(**changes):
    values = {"st_mode": stat.S_IFSOCK | 0o660, "st_uid": 0, "st_dev": 5, "st_ino": 9}
    values.update(changes)
    return SimpleNamespace(**values)


def _filesystem(monkeypatch, entries):
    """Present ``entries`` (path -> stat fields) as the whole filesystem."""
    monkeypatch.setattr(client_module.sys, "platform", "linux")

    def lstat(path):
        try:
            return entries[path.as_posix()]
        except KeyError:
            raise FileNotFoundError(path) from None

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(Path, "is_absolute", lambda path: path.as_posix().startswith("/"))


def _protected(socket_info=None):
    return {
        "/": DIRECTORY,
        "/run": DIRECTORY,
        "/run/strugglebus-maintenance": DIRECTORY,
        SOCKET.as_posix(): socket_info or _socket_info(),
    }


# --- construction -----------------------------------------------------------


@pytest.mark.parametrize("timeout", [0.01, 1, 2, 2.0])
def test_client_accepts_a_bounded_timeout(timeout):
    client = MaintenanceClient("/run/strugglebus-maintenance/control.sock", timeout)
    assert client.timeout == timeout
    assert client.socket_path == Path("/run/strugglebus-maintenance/control.sock")


@pytest.mark.parametrize(
    "timeout", [True, "1", None, 0, -1, 2.01, float("inf"), float("nan")],
)
def test_client_rejects_an_unbounded_timeout(timeout):
    with pytest.raises(ValueError, match="invalid maintenance timeout"):
        MaintenanceClient(SOCKET, timeout)


# --- socket path verification -----------------------------------------------


def test_socket_path_identity_is_its_device_and_inode(monkeypatch):
    _filesystem(monkeypatch, _protected())
    assert client_module._verify_socket_path(SOCKET) == (5, 9)


def test_socket_path_is_unavailable_off_linux(monkeypatch):
    _filesystem(monkeypatch, _protected())
    monkeypatch.setattr(client_module.sys, "platform", "win32")
    with pytest.raises(MaintenanceError, match="unavailable"):
        client_module._verify_socket_path(SOCKET)


def test_relative_socket_path_is_unavailable(monkeypatch):
    _filesystem(monkeypatch, _protected())
    with pytest.raises(MaintenanceError, match="unavailable"):
        client_module._verify_socket_path(Path("run/control.sock"))


@pytest.mark.parametrize(
    ("parent", "info"),
    [
        pytest.param(
            "/run/strugglebus-maintenance",
            SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0),
            id="symlinked-directory",
        ),
        pytest.param(
            "/run/strugglebus-maintenance",
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=998),
            id="application-owned-directory",
        ),
        pytest.param(
            "/run", SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0), id="group-writable",
        ),
        pytest.param(
            "/", SimpleNamespace(st_mode=stat.S_IFDIR | 0o757, st_uid=0), id="world-writable-root",
        ),
    ],
)
def test_socket_below_an_unprotected_directory_is_forbidden(monkeypatch, parent, info):
    entries = _protected()
    entries[parent] = info
    _filesystem(monkeypatch, entries)
    with pytest.raises(MaintenanceError, match="forbidden"):
        client_module._verify_socket_path(SOCKET)


@pytest.mark.parametrize(
    "info",
    [
        pytest.param(_socket_info(st_mode=stat.S_IFREG | 0o660), id="regular-file"),
        pytest.param(_socket_info(st_uid=998), id="application-owned"),
        pytest.param(_socket_info(st_mode=stat.S_IFSOCK | 0o666), id="world-writable"),
        pytest.param(_socket_info(st_mode=stat.S_IFSOCK | 0o600), id="root-only"),
    ],
)
def test_socket_that_is_not_roots_group_socket_is_forbidden(monkeypatch, info):
    _filesystem(monkeypatch, _protected(info))
    with pytest.raises(MaintenanceError, match="forbidden"):
        client_module._verify_socket_path(SOCKET)


# --- peer verification ------------------------------------------------------


class _Peer:
    def __init__(self, uid):
        self.uid = uid
        self.requested = None

    def getsockopt(self, level, option, size):
        self.requested = (level, option, size)
        return struct.pack("3i", 4242, self.uid, 0)


@pytest.fixture
def peer_credentials(monkeypatch):
    monkeypatch.setattr(client_module.socket, "SO_PEERCRED", 17, raising=False)


def test_root_peer_is_accepted(peer_credentials):
    peer = _Peer(0)
    writer = SimpleNamespace(get_extra_info=lambda name: peer if name == "socket" else None)
    client_module._verify_root_peer(writer)
    assert peer.requested == (socket.SOL_SOCKET, 17, 12)


def test_unprivileged_peer_is_forbidden(peer_credentials):
    peer = _Peer(998)
    writer = SimpleNamespace(get_extra_info=lambda name: peer)
    with pytest.raises(MaintenanceError, match="forbidden"):
        client_module._verify_root_peer(writer)


def test_connection_without_a_socket_is_forbidden():
    writer = SimpleNamespace(get_extra_info=lambda name: None)
    with pytest.raises(MaintenanceError, match="forbidden"):
        client_module._verify_root_peer(writer)


# --- exchange ---------------------------------------------------------------


class _Writer:
    def __init__(self, *, drain_error=None, close_error=None):
        self.sent = bytearray()
        self.eof = False
        self.closed = False
        self.drain_error = drain_error
        self.close_error = close_error

    def write(self, data):
        self.sent.extend(data)

    def write_eof(self):
        self.eof = True

    async def drain(self):
        if self.drain_error is not None:
            raise self.drain_error

    def close(self):
        self.closed = True

    async def wait_closed(self):
        if self.close_error is not None:
            raise self.close_error


class _Supervisor:
    """A scripted supervisor behind patched path, peer and connection primitives."""

    def __init__(self, monkeypatch, reply=b"", *, writer=None, connect_error=None):
        self.writer = writer or _Writer()
        self.reader = asyncio.StreamReader()
        self.reader.feed_data(reply)
        self.reader.feed_eof()
        self.connect_error = connect_error
        self.connections = []
        self.identities = [(5, 9), (5, 9)]
        self.peer_error = None
        self.events = []
        monkeypatch.setattr(client_module, "_verify_socket_path", self._verify_path)
        monkeypatch.setattr(client_module, "_verify_root_peer", self._verify_peer)
        monkeypatch.setattr(client_module.asyncio, "open_unix_connection", self._connect, raising=False)

    def _verify_path(self, path):
        self.events.append("path")
        identity = self.identities.pop(0)
        if isinstance(identity, BaseException):
            raise identity
        return identity

    def _verify_peer(self, writer):
        assert writer is self.writer
        self.events.append("peer")
        if self.peer_error is not None:
            raise self.peer_error

    async def _connect(self, path, *, limit):
        self.events.append("connect")
        self.connections.append((path, limit))
        if self.connect_error is not None:
            raise self.connect_error
        return self.reader, self.writer

    def request(self):
        return request_from_json(decode_frame(bytes(self.writer.sent), MAINTENANCE_REQUEST_BYTES))


def _reply(status=STATUS, error=None) -> bytes:
    return encode_frame(response_to_json(status, error), MAINTENANCE_RESPONSE_BYTES)


async def test_status_exchange_verifies_the_socket_before_and_after_connecting(monkeypatch):
    supervisor = _Supervisor(monkeypatch, _reply())

    status = await MaintenanceClient(SOCKET).status()

    assert status == STATUS
    assert supervisor.events == ["path", "connect", "peer", "path"]
    assert supervisor.connections == [(SOCKET, MAINTENANCE_RESPONSE_BYTES + 1)]
    assert supervisor.request().action == "status"
    assert supervisor.writer.eof is True
    assert supervisor.writer.closed is True


async def test_configure_and_install_send_their_complete_request(monkeypatch):
    supervisor = _Supervisor(monkeypatch, _reply())
    await MaintenanceClient(SOCKET).configure(
        OPERATION, ACTOR, enabled=False, hour=3, minute=30,
    )
    request = supervisor.request()
    assert (request.action, request.operation_id, request.actor_id) == (
        "configure", OPERATION, ACTOR,
    )
    assert (request.enabled, request.hour, request.minute) == (False, 3, 30)

    supervisor = _Supervisor(monkeypatch, _reply())
    await MaintenanceClient(SOCKET).install(OPERATION, ACTOR)
    request = supervisor.request()
    assert (request.action, request.operation_id, request.enabled) == ("install", OPERATION, None)


async def test_unverified_socket_is_never_connected(monkeypatch):
    supervisor = _Supervisor(monkeypatch, _reply())
    supervisor.identities = [MaintenanceError("forbidden")]

    with pytest.raises(MaintenanceError) as caught:
        await MaintenanceClient(SOCKET).install(OPERATION, ACTOR)

    assert caught.value.code == "forbidden"
    assert supervisor.events == ["path"]
    assert supervisor.writer.sent == b""
    assert supervisor.writer.closed is False


async def test_request_is_withheld_from_an_unprivileged_peer(monkeypatch):
    supervisor = _Supervisor(monkeypatch, _reply())
    supervisor.peer_error = MaintenanceError("forbidden")

    with pytest.raises(MaintenanceError) as caught:
        await MaintenanceClient(SOCKET).install(OPERATION, ACTOR)

    assert caught.value.code == "forbidden"
    assert supervisor.writer.sent == b""
    assert supervisor.writer.closed is True


async def test_request_is_withheld_when_the_socket_was_replaced(monkeypatch):
    supervisor = _Supervisor(monkeypatch, _reply())
    supervisor.identities = [(5, 9), (5, 10)]

    with pytest.raises(MaintenanceError) as caught:
        await MaintenanceClient(SOCKET).install(OPERATION, ACTOR)

    assert caught.value.code == "forbidden"
    assert supervisor.writer.sent == b""
    assert supervisor.writer.closed is True


@pytest.mark.parametrize(
    "error", [ConnectionRefusedError(), FileNotFoundError(), NotImplementedError(), TimeoutError()],
)
async def test_failure_before_dispatch_is_unavailable(monkeypatch, error):
    supervisor = _Supervisor(monkeypatch, connect_error=error)

    with pytest.raises(MaintenanceError) as caught:
        await MaintenanceClient(SOCKET).install(OPERATION, ACTOR)

    assert caught.value.code == "unavailable"
    assert supervisor.writer.sent == b""


async def test_send_failure_before_dispatch_is_unavailable(monkeypatch):
    supervisor = _Supervisor(monkeypatch, writer=_Writer(drain_error=BrokenPipeError()))

    with pytest.raises(MaintenanceError) as caught:
        await MaintenanceClient(SOCKET).install(OPERATION, ACTOR)

    assert caught.value.code == "unavailable"
    assert supervisor.writer.closed is True


async def test_supervisor_refusal_of_a_status_request_keeps_its_code(monkeypatch):
    _Supervisor(monkeypatch, _reply(None, "state_corrupt"))
    with pytest.raises(MaintenanceError) as caught:
        await MaintenanceClient(SOCKET).status()
    assert caught.value.code == "state_corrupt"


@pytest.mark.parametrize("action", ["configure", "install"])
async def test_supervisor_refusal_of_a_mutation_is_an_unknown_outcome(monkeypatch, action):
    _Supervisor(monkeypatch, _reply(None, "busy"))
    client = MaintenanceClient(SOCKET)

    with pytest.raises(MaintenanceError) as caught:
        if action == "install":
            await client.install(OPERATION, ACTOR)
        else:
            await client.configure(OPERATION, ACTOR, enabled=True, hour=1, minute=0)

    assert caught.value.code == "unknown_outcome"


async def test_read_failure_after_dispatch_is_an_unknown_outcome(monkeypatch):
    supervisor = _Supervisor(monkeypatch)
    supervisor.reader = asyncio.StreamReader()
    supervisor.reader.set_exception(ConnectionResetError())

    with pytest.raises(MaintenanceError) as caught:
        await MaintenanceClient(SOCKET).status()

    assert caught.value.code == "unknown_outcome"
    assert supervisor.writer.closed is True


async def test_silent_supervisor_times_out_as_an_unknown_outcome(monkeypatch):
    supervisor = _Supervisor(monkeypatch)
    supervisor.reader = asyncio.StreamReader()

    with pytest.raises(MaintenanceError) as caught:
        await MaintenanceClient(SOCKET, timeout=0.05).install(OPERATION, ACTOR)

    assert caught.value.code == "unknown_outcome"
    assert supervisor.writer.eof is True
    assert supervisor.writer.closed is True


@pytest.mark.parametrize(
    "reply",
    [
        pytest.param(b"", id="closed-without-reply"),
        pytest.param(_reply()[:-1], id="unterminated"),
        pytest.param(b"x" * (MAINTENANCE_RESPONSE_BYTES + 100) + b"\n", id="oversized"),
    ],
)
async def test_unframed_reply_is_rejected(monkeypatch, reply):
    supervisor = _Supervisor(monkeypatch, reply)
    with pytest.raises(UpdateError, match="invalid_request"):
        await MaintenanceClient(SOCKET).status()
    assert supervisor.writer.closed is True


async def test_reply_is_read_no_further_than_one_byte_past_the_ceiling():
    reader = asyncio.StreamReader()
    reader.feed_data(b"x" * (MAINTENANCE_RESPONSE_BYTES + 100))
    reader.feed_eof()
    assert len(await client_module._read_response(reader)) == MAINTENANCE_RESPONSE_BYTES + 1


async def test_reply_arriving_in_pieces_is_reassembled(monkeypatch):
    reply = _reply()
    supervisor = _Supervisor(monkeypatch)
    supervisor.reader = asyncio.StreamReader()

    async def trickle():
        for index in range(0, len(reply), 64):
            supervisor.reader.feed_data(reply[index:index + 64])
            await asyncio.sleep(0)
        supervisor.reader.feed_eof()

    task = asyncio.ensure_future(trickle())
    assert await MaintenanceClient(SOCKET).status() == STATUS
    await task


async def test_close_failure_does_not_mask_the_reply(monkeypatch):
    supervisor = _Supervisor(
        monkeypatch, _reply(), writer=_Writer(close_error=ConnectionResetError()),
    )
    assert await MaintenanceClient(SOCKET).status() == STATUS
    assert supervisor.writer.closed is True


# --- application identity ---------------------------------------------------


def test_application_uid_is_forbidden_off_linux(monkeypatch):
    monkeypatch.setattr(client_module.sys, "platform", "win32")
    with pytest.raises(MaintenanceError, match="forbidden"):
        client_module.application_uid()


def test_application_uid_is_the_process_uid_on_linux(monkeypatch):
    monkeypatch.setattr(client_module.sys, "platform", "linux")
    monkeypatch.setattr(client_module.os, "getuid", lambda: 998, raising=False)
    assert client_module.application_uid() == 998
