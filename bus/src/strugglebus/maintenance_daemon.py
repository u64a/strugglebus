"""Root-owned socket and timer entry point for self-updating maintenance."""

from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager
import os
from pathlib import Path
import socket
import stat
import struct
import sys

from strugglebus.maintenance_runtime import (
    active_application_version,
    BoardAnnouncer,
    HostReleaseInstaller,
    PreparedReleaseGateway,
    RuntimeConfig,
    load_config,
)
from strugglebus.maintenance_state import MaintenanceState
from strugglebus.maintenance_supervisor import (
    MaintenanceController,
    MaintenanceRunner,
)
from strugglebus.maintenance_types import (
    MAINTENANCE_REQUEST_BYTES,
    MAINTENANCE_RESPONSE_BYTES,
    MaintenanceError,
    request_from_json,
    response_to_json,
)
from strugglebus.update_types import decode_frame, encode_frame


def _require_listening_unix_stream(listener: socket.socket) -> None:
    if (
        listener.family != socket.AF_UNIX
        or listener.type != socket.SOCK_STREAM
        or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
    ):
        raise MaintenanceError("forbidden")


def _require_protected_socket_path(listener: socket.socket) -> None:
    path = Path(listener.getsockname())
    info = path.lstat()
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o660
    ):
        raise MaintenanceError("forbidden")


def inherited_socket() -> socket.socket:
    if (
        os.environ.get("LISTEN_PID") != str(os.getpid())
        or os.environ.get("LISTEN_FDS") != "1"
    ):
        raise MaintenanceError("forbidden")
    listener = socket.socket(fileno=3)
    try:
        _require_listening_unix_stream(listener)
        _require_protected_socket_path(listener)
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
        return uid == application_uid
    except OSError:
        return False


@contextmanager
def _state_lock(config: RuntimeConfig, *, blocking: bool):
    import fcntl

    path = config.state_path.with_suffix(".lock")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise MaintenanceError("state_corrupt")
        flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
        try:
            fcntl.flock(descriptor, flags)
        except BlockingIOError:
            raise MaintenanceError("busy") from None
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _trigger(config: RuntimeConfig) -> None:
    try:
        # The executable path and complete argument vector are validated constants.
        result = os.spawnv(  # nosec B606
            os.P_WAIT,
            str(config.systemctl),
            [
                str(config.systemctl),
                "start",
                "--no-block",
                "strugglebus-maintenance-run.service",
            ],
        )
    except OSError:
        raise MaintenanceError("unavailable") from None
    if result != 0:
        raise MaintenanceError("unavailable")


async def _read_request(reader: asyncio.StreamReader) -> bytes:
    data = bytearray()
    while len(data) <= MAINTENANCE_REQUEST_BYTES:
        part = await reader.read(MAINTENANCE_REQUEST_BYTES + 1 - len(data))
        if not part:
            break
        data.extend(part)
    return bytes(data)


async def _handle(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    config: RuntimeConfig,
) -> None:
    try:
        if not _peer_allowed(writer, config.application_uid):
            raise MaintenanceError("forbidden")
        request = request_from_json(
            decode_frame(await _read_request(reader), MAINTENANCE_REQUEST_BYTES),
        )
        with _state_lock(config, blocking=False):
            state = MaintenanceState(config.state_path, active_application_version(config))
            controller = MaintenanceController(
                state,
                trigger=lambda: _trigger(config),
            )
            result = controller.dispatch(request)
        response = response_to_json(result)
    except MaintenanceError as error:
        response = response_to_json(None, error.code)
    except BaseException:
        response = response_to_json(None, "internal_error")
    try:
        writer.write(encode_frame(response, MAINTENANCE_RESPONSE_BYTES))
        await writer.drain()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def serve(config: RuntimeConfig) -> None:
    listener = inherited_socket()
    server = await asyncio.start_unix_server(
        lambda reader, writer: _handle(reader, writer, config),
        sock=listener,
        limit=MAINTENANCE_REQUEST_BYTES + 1,
    )
    async with server:
        await server.serve_forever()


def run(config: RuntimeConfig) -> bool:
    with _state_lock(config, blocking=True):
        state = MaintenanceState(config.state_path, active_application_version(config))
        runner = MaintenanceRunner(
            state,
            PreparedReleaseGateway(config),
            HostReleaseInstaller(config),
            BoardAnnouncer(config),
        )
        return runner.run_pending()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("serve", "run", "init", "status"))
    parser.add_argument("--config", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        config = load_config(arguments.config)
        if arguments.action == "serve":
            asyncio.run(serve(config))
        elif arguments.action == "run":
            run(config)
        else:
            with _state_lock(config, blocking=True):
                status = MaintenanceState(
                    config.state_path, active_application_version(config),
                ).status()
            if arguments.action == "status":
                print(
                    f"enabled={str(status.policy.enabled).lower()} "
                    f"window={status.policy.hour:02d}:{status.policy.minute:02d} "
                    f"timezone={status.policy.timezone}"
                )
    except MaintenanceError as error:
        print(error.code, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
