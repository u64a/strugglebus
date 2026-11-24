"""Asynchronous, bounded client for the protected local updater socket."""

from __future__ import annotations

import asyncio
import math
import os
from pathlib import Path
import socket
import stat
import struct
import sys

from strugglebus.update_types import (
    JsonValue, REQUEST_BYTES, RESPONSE_BYTES, UpdateError, UpdateOperation, UpdateRequest,
    UpdateStatus,
    decode_frame, encode_frame, request_to_json, response_from_json,
)


class _WorkerRefusal(UpdateError):
    """A validated negative acknowledgement, distinct from a lost acknowledgement."""


def _transport_failure(request: UpdateRequest, dispatched: bool, code: str) -> UpdateError:
    if dispatched and request.action in {"check", "prepare"}:
        return UpdateError("unknown_outcome")
    return UpdateError(code)


def _verify_socket_parent(parent: Path) -> None:
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise UpdateError("forbidden")


def _verify_socket_path(path: Path) -> tuple[int, int]:
    if sys.platform != "linux" or not path.is_absolute():
        raise UpdateError("unavailable")
    for parent in reversed(path.parents):
        _verify_socket_parent(parent)
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
        raise UpdateError("forbidden")
    if stat.S_IMODE(info.st_mode) != 0o660:
        raise UpdateError("forbidden")
    return info.st_dev, info.st_ino


def _verify_server_peer(writer: asyncio.StreamWriter, *, allow_root_peer: bool = False) -> None:
    peer = writer.get_extra_info("socket")
    if peer is None:
        raise UpdateError("forbidden")
    credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    _, uid, _ = struct.unpack("3i", credentials)
    # A systemd-owned listening socket can report root instead of the worker UID.
    if uid == os.getuid() and not (allow_root_peer and uid == 0):
        raise UpdateError("forbidden")


def _bind_response(request: UpdateRequest, result: UpdateStatus) -> None:
    if request.operation_id is None:
        return
    operation = result.operation
    if operation is None:
        if request.action == "status" and not result.history_available:
            return
        raise UpdateError("invalid_response")
    if operation.operation_id != request.operation_id or not result.history_available:
        raise UpdateError("invalid_response")
    if request.action != "status":
        _bind_mutation(request, result, operation)


def _bind_mutation(
    request: UpdateRequest, result: UpdateStatus, operation: UpdateOperation,
) -> None:
    if operation.action != request.action or operation.actor_id != request.actor_id:
        raise UpdateError("invalid_response")
    _bind_observation(request, result)


def _bind_observation(request: UpdateRequest, result: UpdateStatus) -> None:
    observation = result.observation
    if request.action == "check":
        if result.operation is not None and result.operation.phase == "succeeded":
            if observation is None:
                raise UpdateError("invalid_response")
            _bind_application(request, result)
        return
    if observation is None or observation.observation_id != request.observation_id:
        raise UpdateError("invalid_response")
    candidate = observation.discovery.candidate
    if candidate is None or candidate.digest != request.candidate_digest:
        raise UpdateError("invalid_response")
    _bind_application(request, result)


def _bind_application(request: UpdateRequest, result: UpdateStatus) -> None:
    observation = result.observation
    if observation is None:
        raise UpdateError("invalid_response")
    if (observation.application_version != request.application_version
            or observation.application_release_id != request.application_release_id):
        raise UpdateError("invalid_response")


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        async with asyncio.timeout(0.1):
            await writer.wait_closed()
    except (OSError, TimeoutError):
        pass


class UpdateClient:
    """Keep submitted IDs for status lookup, including after task cancellation.

    Closing a cancelled connection does not cancel a durably accepted worker job.
    Lost or invalid mutation acknowledgements are explicitly unknown outcomes.
    """

    def __init__(
        self, socket_path: str | Path, timeout: float = 2, *,
        allow_root_peer: bool = False,
    ):
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValueError("invalid updater timeout")
        if not math.isfinite(timeout) or not 0 < timeout <= 2:
            raise ValueError("invalid updater timeout")
        self.socket_path = Path(socket_path)
        self.timeout = timeout
        if allow_root_peer and (sys.platform != "linux" or os.geteuid() != 0):
            raise ValueError("root updater client requires Linux root")
        self.allow_root_peer = allow_root_peer

    async def status(self, operation_id: str | None = None) -> UpdateStatus:
        return await self._exchange(UpdateRequest("status", operation_id))

    async def check(
        self, operation_id: str, actor_id: str, application_version: str,
        application_release_id: str | None,
    ) -> UpdateStatus:
        return await self._exchange(UpdateRequest(
            "check", operation_id, actor_id, application_version, application_release_id,
        ))

    async def prepare(
        self, operation_id: str, actor_id: str, application_version: str,
        application_release_id: str | None, observation_id: str, candidate_digest: str,
    ) -> UpdateStatus:
        return await self._exchange(UpdateRequest(
            "prepare", operation_id, actor_id, application_version, application_release_id,
            observation_id, candidate_digest,
        ))

    async def _exchange(self, request: UpdateRequest) -> UpdateStatus:
        raw = encode_frame(request_to_json(request), REQUEST_BYTES)
        writer: asyncio.StreamWriter | None = None
        dispatched = False
        try:
            async with asyncio.timeout(self.timeout):
                identity = _verify_socket_path(self.socket_path)
                reader, writer = await asyncio.open_unix_connection(
                    self.socket_path, limit=RESPONSE_BYTES + 1,
                )
                if self.allow_root_peer:
                    _verify_server_peer(writer, allow_root_peer=True)
                else:
                    _verify_server_peer(writer)
                if _verify_socket_path(self.socket_path) != identity:
                    raise UpdateError("forbidden")
                dispatched = True
                writer.write(raw)
                writer.write_eof()
                await writer.drain()
                response = await _read_response(reader)
                _bind_response(request, response)
                return response
        except _WorkerRefusal as exc:
            raise UpdateError(exc.code) from None
        except UpdateError as exc:
            if exc.code == "invalid_response":
                raise _transport_failure(request, dispatched, exc.code) from None
            raise
        except TimeoutError:
            raise _transport_failure(request, dispatched, "timeout") from None
        except (OSError, NotImplementedError):
            raise _transport_failure(request, dispatched, "unavailable") from None
        finally:
            if writer is not None:
                await _close(writer)


async def _read_response(reader: asyncio.StreamReader) -> UpdateStatus:
    data = bytearray()
    while len(data) <= RESPONSE_BYTES:
        part = await reader.read(RESPONSE_BYTES + 1 - len(data))
        if not part:
            break
        data.extend(part)
    value: JsonValue = None
    try:
        value = decode_frame(bytes(data), RESPONSE_BYTES)
        return response_from_json(value)
    except UpdateError as exc:
        if _known_failure(value, exc.code):
            raise _WorkerRefusal(exc.code) from None
        raise UpdateError("invalid_response") from None


def _known_failure(value: JsonValue, code: str) -> bool:
    if not isinstance(value, dict) or set(value) != {"version", "ok", "error", "status"}:
        return False
    return (
        type(value["version"]) is int and value["version"] == 1
        and value["ok"] is False and value["error"] == code and value["status"] is None
    )
