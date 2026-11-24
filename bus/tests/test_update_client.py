import asyncio
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import socket
import stat
import struct

import pytest

from strugglebus import update_client as client
from strugglebus.update_types import (
    REQUEST_BYTES, RESPONSE_BYTES, UpdateError, UpdateRequest, decode_frame, encode_frame,
    response_to_json,
)
from test_update_types import candidate, observation, operation, status


class Writer:
    def __init__(self, *, stall=False, peer=None):
        self.closed = False
        self.eof = False
        self.data = b""
        self.stall = stall
        self.peer = peer
        self.waited = False

    def write(self, raw):
        self.data += raw

    def write_eof(self):
        self.eof = True

    async def drain(self):
        if self.stall:
            await asyncio.Event().wait()

    def close(self):
        self.closed = True

    async def wait_closed(self):
        self.waited = True

    def get_extra_info(self, key):
        return self.peer


def install_transport(monkeypatch, raw, *, eof=True, stall=False):
    reader = asyncio.StreamReader()
    if raw is not None:
        reader.feed_data(raw)
    if eof:
        reader.feed_eof()
    writer = Writer(stall=stall)

    async def connect(path, **kwargs):
        assert kwargs["limit"] == RESPONSE_BYTES + 1
        return reader, writer

    monkeypatch.setattr(client, "_verify_socket_path", lambda path: (1, 2))
    monkeypatch.setattr(client, "_verify_server_peer", lambda writer: None)
    monkeypatch.setattr(asyncio, "open_unix_connection", connect, raising=False)
    return writer


async def test_status_roundtrip_and_half_close(monkeypatch):
    writer = install_transport(monkeypatch, encode_frame(response_to_json(status()), RESPONSE_BYTES))
    result = await client.UpdateClient("protected").status()
    assert result == status()
    assert writer.closed and writer.waited and writer.eof
    assert decode_frame(writer.data, REQUEST_BYTES) == {
        "version": 1, "action": "status", "operation_id": None,
    }


async def test_check_and_prepare_bind_request_and_response(monkeypatch):
    value = status()
    install_transport(monkeypatch, encode_frame(response_to_json(value), RESPONSE_BYTES))
    updater = client.UpdateClient("protected")
    assert await updater.check("1" * 32, "operator", "1.0.0", "release-one") == value
    value = replace(value, state="preparing", operation=operation("accepted", "prepare", "3" * 32))
    writer = install_transport(monkeypatch, encode_frame(response_to_json(value), RESPONSE_BYTES))
    assert await updater.prepare("3" * 32, "operator", "1.0.0", "release-one",
                                 observation().observation_id, candidate().digest) == value
    assert decode_frame(writer.data, REQUEST_BYTES)["candidate_digest"] == candidate().digest
    assert b"password" not in writer.data


@pytest.mark.parametrize("raw", [
    b'{}\n', b'{"version":1,"version":1,"ok":false,"error":"busy","status":null}\n',
    b"{}\n{}\n", b'{}', b"x" * (RESPONSE_BYTES + 1),
    b'{"version":1,"ok":true,"error":null,"status":null}\n',
], ids=["empty-object", "duplicate", "extra-frame", "truncated", "oversized", "missing-status"])
async def test_bad_responses_closed_and_redacted(monkeypatch, raw):
    writer = install_transport(monkeypatch, raw)
    with pytest.raises(UpdateError, match="invalid_response"):
        await client.UpdateClient("protected").status()
    assert writer.closed


async def test_static_error_survives_response(monkeypatch):
    install_transport(monkeypatch, encode_frame(response_to_json(error="busy"), RESPONSE_BYTES))
    with pytest.raises(UpdateError, match="busy"):
        await client.UpdateClient("protected").status()


@pytest.mark.parametrize("change", [
    {"operation": None},
    {"operation": operation(identity="9" * 32)},
    {"operation": replace(operation(), actor_id="other")},
    {"operation": operation(action="prepare")},
    {"history_available": False},
    {"observation": None},
    {"observation": replace(observation(), application_version="1.0.1")},
    {"observation": replace(observation(), application_release_id=None)},
])
async def test_check_response_binding_rejects_mismatch(monkeypatch, change):
    value = replace(status(), **change)
    install_transport(monkeypatch, encode_frame(response_to_json(value), RESPONSE_BYTES))
    with pytest.raises(UpdateError, match="unknown_outcome"):
        await client.UpdateClient("protected").check("1" * 32, "operator", "1.0.0", "release-one")


@pytest.mark.parametrize("field,value", [
    ("observation_id", "9" * 32), ("candidate_digest", "9" * 64),
    ("application_release_id", "other"),
])
async def test_prepare_response_binding_rejects_mismatch(monkeypatch, field, value):
    result = replace(status(), operation=operation("running", "prepare"))
    install_transport(monkeypatch, encode_frame(response_to_json(result), RESPONSE_BYTES))
    args = dict(operation_id="1" * 32, actor_id="operator", application_version="1.0.0",
                application_release_id="release-one", observation_id="2" * 32,
                candidate_digest=candidate().digest)
    args[field] = value
    with pytest.raises(UpdateError, match="unknown_outcome"):
        await client.UpdateClient("protected").prepare(**args)


async def test_absent_history_is_not_success_proof(monkeypatch):
    value = replace(status(), operation=None, history_available=False)
    install_transport(monkeypatch, encode_frame(response_to_json(value), RESPONSE_BYTES))
    result = await client.UpdateClient("protected").status("9" * 32)
    assert result.operation is None and not result.history_available


@pytest.mark.parametrize("stall", ["connect", "write", "read", "extra"])
async def test_one_absolute_deadline_and_safe_close(monkeypatch, stall):
    raw = encode_frame(response_to_json(status()), RESPONSE_BYTES) if stall == "extra" else None
    writer = install_transport(monkeypatch, raw, eof=False, stall=stall == "write")
    if stall == "connect":
        async def stalled(*args, **kwargs):
            await asyncio.Event().wait()
        monkeypatch.setattr(asyncio, "open_unix_connection", stalled)
    with pytest.raises(UpdateError, match="timeout"):
        await client.UpdateClient("protected", timeout=0.01).status()
    assert writer.closed or stall == "connect"


async def test_cancellation_closes_connection(monkeypatch):
    writer = install_transport(monkeypatch, None, eof=False)
    task = asyncio.create_task(client.UpdateClient("protected").status())
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert writer.closed


async def test_transport_errors_and_inode_change(monkeypatch):
    writer = install_transport(monkeypatch, None)
    identities = iter([(1, 2), (1, 3)])
    monkeypatch.setattr(client, "_verify_socket_path", lambda path: next(identities))
    with pytest.raises(UpdateError, match="forbidden"):
        await client.UpdateClient("protected").status()
    assert writer.closed
    monkeypatch.setattr(client, "_verify_socket_path", lambda path: (1, 2))
    async def fail(*args, **kwargs):
        raise OSError("private path")
    monkeypatch.setattr(asyncio, "open_unix_connection", fail)
    with pytest.raises(UpdateError, match="unavailable"):
        await client.UpdateClient("protected").status()


@pytest.mark.parametrize("timeout", [0, -1, 3, True, "2", float("nan"), float("inf")])
def test_client_timeout_cannot_expand_admission(timeout):
    with pytest.raises(ValueError):
        client.UpdateClient("protected", timeout)


def test_root_socket_provenance_and_safe_ancestry(monkeypatch):
    path = Path.cwd() / "synthetic.sock"
    monkeypatch.setattr(client.sys, "platform", "linux")
    infos = {parent: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
             for parent in path.parents}
    infos[path] = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0, st_dev=1, st_ino=2)
    monkeypatch.setattr(Path, "lstat", lambda self: infos[self])
    assert client._verify_socket_path(path) == (1, 2)
    for mode, uid in [(stat.S_IFSOCK | 0o666, 0), (stat.S_IFSOCK | 0o660, 1000),
                      (stat.S_IFLNK | 0o660, 0)]:
        infos[path] = SimpleNamespace(st_mode=mode, st_uid=uid)
        with pytest.raises(UpdateError, match="forbidden"):
            client._verify_socket_path(path)
    infos[path.parent].st_mode |= 0o020
    with pytest.raises(UpdateError, match="forbidden"):
        client._verify_socket_path(path)
    with pytest.raises(UpdateError, match="unavailable"):
        client._verify_socket_path(Path("relative"))


def test_server_peer_must_not_be_application_uid(monkeypatch):
    monkeypatch.setattr(client.os, "getuid", lambda: 1000, raising=False)
    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    for uid in [0, 1001]:
        peer = SimpleNamespace(getsockopt=lambda *args: struct.pack("3i", 1, uid, 100))
        client._verify_server_peer(Writer(peer=peer))
    for peer in [None, SimpleNamespace(getsockopt=lambda *args: struct.pack("3i", 1, 1000, 100))]:
        with pytest.raises(UpdateError, match="forbidden"):
            client._verify_server_peer(Writer(peer=peer))


async def test_close_errors_do_not_leak(monkeypatch):
    writer = Writer()
    async def broken():
        raise OSError("private")
    writer.wait_closed = broken
    await client._close(writer)
    assert writer.closed


def test_application_binding_never_accepts_missing_observation():
    with pytest.raises(UpdateError, match="invalid_response"):
        client._bind_application(UpdateRequest("check"), replace(status(), observation=None))


async def mutation(updater, action):
    if action == "check":
        return await updater.check("1" * 32, "operator", "1.0.0", "release-one")
    return await updater.prepare("1" * 32, "operator", "1.0.0", "release-one",
                                 "2" * 32, candidate().digest)


@pytest.mark.parametrize("action", ["check", "prepare"])
@pytest.mark.parametrize("raw", [
    b"", b"{", b"{}\n",
    b'{"version":1,"ok":false,"error":"busy","status":{}}\n',
    b'{"version":true,"ok":false,"error":"invalid_request","status":null}\n',
    b'{"version":2,"ok":false,"error":"invalid_request","status":null}\n',
    b'{"version":1,"ok":true,"error":"invalid_response","status":null}\n',
    b'{"version":1,"ok":false,"error":"private body","status":null}\n',
    b'{"version":1,"version":1,"ok":false,"error":"busy","status":null}\n',
    encode_frame(response_to_json(status()), RESPONSE_BYTES) + b"{}\n",
    b"x" * (RESPONSE_BYTES + 1),
], ids=["empty", "truncated", "missing-schema", "error-with-status", "bool-version",
        "unknown-version", "success-with-error", "nonstatic-error", "duplicate", "extra-frame",
        "oversized"])
async def test_post_dispatch_unconfirmed_acknowledgement_is_unknown(monkeypatch, action, raw):
    writer = install_transport(monkeypatch, raw)
    with pytest.raises(UpdateError, match="unknown_outcome") as raised:
        await mutation(client.UpdateClient("protected"), action)
    assert raised.value.code == "unknown_outcome"
    assert writer.data and writer.closed


@pytest.mark.parametrize("action", ["check", "prepare"])
@pytest.mark.parametrize("stage", ["write", "drain", "read"])
async def test_post_dispatch_transport_failure_is_unknown(monkeypatch, action, stage):
    writer = install_transport(monkeypatch, None, eof=False, stall=stage == "drain")
    if stage == "write":
        def lost_write(data):
            raise BrokenPipeError("private transport detail")
        writer.write = lost_write
    with pytest.raises(UpdateError, match="unknown_outcome"):
        await mutation(client.UpdateClient("protected", timeout=0.01), action)
    assert writer.closed


@pytest.mark.parametrize("code", [
    "busy", "cooldown", "invalid_request", "invalid_response",
    "timeout", "unavailable", "state_corrupt", "unknown_outcome",
])
async def test_valid_worker_refusal_is_not_misclassified_as_lost_ack(monkeypatch, code):
    install_transport(monkeypatch, encode_frame(response_to_json(error=code), RESPONSE_BYTES))
    with pytest.raises(UpdateError) as raised:
        await mutation(client.UpdateClient("protected"), "check")
    assert raised.value.code == code


@pytest.mark.parametrize("failure", ["timeout", "unavailable"])
async def test_failure_before_dispatch_does_not_claim_unknown_dispatch(monkeypatch, failure):
    writer = install_transport(monkeypatch, None)
    async def fail_before_send(*args, **kwargs):
        if failure == "timeout":
            await asyncio.Event().wait()
        raise OSError("private connection failure")
    monkeypatch.setattr(asyncio, "open_unix_connection", fail_before_send)
    with pytest.raises(UpdateError) as raised:
        await mutation(client.UpdateClient("protected", timeout=0.01), "check")
    assert raised.value.code == failure and writer.data == b""


async def test_unknown_outcome_reconciles_by_status_without_resubmission(monkeypatch):
    updater = client.UpdateClient("protected")
    first = install_transport(monkeypatch, b"")
    with pytest.raises(UpdateError, match="unknown_outcome"):
        await mutation(updater, "check")
    second = install_transport(monkeypatch, encode_frame(response_to_json(status()), RESPONSE_BYTES))
    result = await updater.status("1" * 32)
    assert result.operation.phase == "succeeded" and result.history_available
    assert decode_frame(first.data, REQUEST_BYTES)["action"] == "check"
    assert decode_frame(second.data, REQUEST_BYTES) == {
        "version": 1, "action": "status", "operation_id": "1" * 32,
    }


async def test_post_dispatch_cancellation_closes_without_claiming_nonexecution(monkeypatch):
    writer = install_transport(monkeypatch, None, eof=False)
    task = asyncio.create_task(mutation(client.UpdateClient("protected"), "check"))
    await asyncio.sleep(0)
    assert writer.data
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert writer.closed
