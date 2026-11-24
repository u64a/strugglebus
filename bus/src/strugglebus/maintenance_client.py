"""Bounded application client for the root-owned maintenance supervisor."""

from __future__ import annotations

import asyncio
import math
import os
from pathlib import Path
import socket
import stat
import struct
import sys

from strugglebus.maintenance_types import (
    MAINTENANCE_REQUEST_BYTES,
    MAINTENANCE_RESPONSE_BYTES,
    MaintenanceError,
    MaintenanceRequest,
    MaintenanceStatus,
    request_to_json,
    response_from_json,
)
from strugglebus.update_types import decode_frame, encode_frame


def _verify_protected_parents(path: Path) -> None:
    """Every ancestor, from the filesystem root down, is root's unshared directory."""
    for parent in reversed(path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise MaintenanceError("forbidden")


def _verify_socket_path(path: Path) -> tuple[int, int]:
    if sys.platform != "linux" or not path.is_absolute():
        raise MaintenanceError("unavailable")
    _verify_protected_parents(path)
    info = path.lstat()
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o660
    ):
        raise MaintenanceError("forbidden")
    return info.st_dev, info.st_ino


def _verify_root_peer(writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("socket")
    if peer is None:
        raise MaintenanceError("forbidden")
    credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    _, uid, _ = struct.unpack("3i", credentials)
    if uid != 0:
        raise MaintenanceError("forbidden")


async def _read_response(reader: asyncio.StreamReader) -> bytes:
    """Read to end of stream, stopping one byte past the response ceiling."""
    data = bytearray()
    while len(data) <= MAINTENANCE_RESPONSE_BYTES:
        part = await reader.read(
            MAINTENANCE_RESPONSE_BYTES + 1 - len(data),
        )
        if not part:
            break
        data.extend(part)
    return bytes(data)


async def _close(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass


class MaintenanceClient:
    def __init__(self, socket_path: str | Path, timeout: float = 2):
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValueError("invalid maintenance timeout")
        if not math.isfinite(timeout) or not 0 < timeout <= 2:
            raise ValueError("invalid maintenance timeout")
        self.socket_path = Path(socket_path)
        self.timeout = timeout

    async def status(self) -> MaintenanceStatus:
        return await self._exchange(MaintenanceRequest("status"))

    async def configure(
        self, operation_id: str, actor_id: str, *,
        enabled: bool, hour: int, minute: int,
    ) -> MaintenanceStatus:
        return await self._exchange(MaintenanceRequest(
            "configure", operation_id, actor_id, enabled, hour, minute,
        ))

    async def install(self, operation_id: str, actor_id: str) -> MaintenanceStatus:
        return await self._exchange(MaintenanceRequest("install", operation_id, actor_id))

    async def _exchange(self, request: MaintenanceRequest) -> MaintenanceStatus:
        raw = encode_frame(request_to_json(request), MAINTENANCE_REQUEST_BYTES)
        writer: asyncio.StreamWriter | None = None
        dispatched = False
        try:
            async with asyncio.timeout(self.timeout):
                identity = _verify_socket_path(self.socket_path)
                reader, writer = await asyncio.open_unix_connection(
                    self.socket_path, limit=MAINTENANCE_RESPONSE_BYTES + 1,
                )
                _verify_root_peer(writer)
                if _verify_socket_path(self.socket_path) != identity:
                    raise MaintenanceError("forbidden")
                writer.write(raw)
                writer.write_eof()
                await writer.drain()
                dispatched = True
                return response_from_json(
                    decode_frame(await _read_response(reader), MAINTENANCE_RESPONSE_BYTES),
                )
        except MaintenanceError as error:
            if dispatched and request.action in {"configure", "install"}:
                raise MaintenanceError("unknown_outcome") from None
            raise
        except (TimeoutError, OSError, NotImplementedError):
            raise MaintenanceError("unknown_outcome" if dispatched else "unavailable") from None
        finally:
            await _close(writer)


def application_uid() -> int:
    if sys.platform != "linux":
        raise MaintenanceError("forbidden")
    return os.getuid()
