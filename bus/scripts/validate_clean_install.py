"""Install release artifacts into a clean Python 3.13 venv and smoke test."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import sqlite3
# Subprocess runs only executables inside the newly created isolated venv.
import subprocess  # nosec B404
import sys
import tempfile
import time
import uuid
import venv
import zipfile
from contextlib import closing
from email.parser import BytesParser
from pathlib import Path

# The schema version a freshly installed wheel must report. Kept in step with
# strugglebus.migrations.LATEST_SCHEMA_VERSION and release_bundle.CURRENT_SCHEMA
# by tests/test_clean_install_validator.py.
EXPECTED_SCHEMA_VERSION = 24
# The guide version a freshly installed service must serve, kept in step with
# strugglebus.integration.GUIDE_VERSION by the same test.
EXPECTED_GUIDE_VERSION = "1.19.0"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument(
        "--expected-python",
        choices=("3.13",),
        required=True,
    )
    return parser


def _validate_python_version(expected_python: str) -> None:
    actual_python = f"{sys.version_info.major}.{sys.version_info.minor}"
    if actual_python != "3.13":
        raise RuntimeError("clean install validation requires Python 3.13")
    if expected_python != actual_python:
        raise RuntimeError(
            "clean install validation used the wrong Python version: "
            f"expected {expected_python}, found {actual_python}"
        )


def _venv_executable(environment: Path, name: str) -> Path:
    if os.name == "nt":
        return environment / "Scripts" / f"{name}.exe"
    return environment / "bin" / name


def _run(
    command: list[str],
    *,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # nosec B603
        command,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )


def _available_port() -> int:
    with socket.socket() as listening_socket:
        listening_socket.bind(("127.0.0.1", 0))
        return int(listening_socket.getsockname()[1])


def _request(
    port: int,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    body: bytes | None = None,
) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request(
            method,
            path,
            body=body,
            headers={} if headers is None else headers,
        )
        response = connection.getresponse()
        return response.status, response.read(64 * 1024)
    finally:
        connection.close()


def _wait_until_ready(process: subprocess.Popen[bytes], port: int) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("installed strugglebus server exited before readiness")
        try:
            status, body = _request(port, "/healthz")
            if status == 200 and json.loads(body) == {"status": "ok"}:
                return
        except (ConnectionError, OSError, TimeoutError, json.JSONDecodeError):
            pass
        time.sleep(0.05)
    raise RuntimeError("installed strugglebus server did not become ready")


def main() -> int:
    args = _parser().parse_args()
    _validate_python_version(args.expected_python)
    wheel = args.wheel.resolve(strict=True)
    requirements = args.requirements.resolve(strict=True)
    with zipfile.ZipFile(wheel) as archive:
        metadata_names = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_names) != 1:
            raise RuntimeError("wheel must contain exactly one METADATA file")
        metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
    package_version = metadata.get("Version")
    if package_version is None:
        raise RuntimeError("wheel metadata is missing its version")

    with tempfile.TemporaryDirectory(prefix="strugglebus-install-") as temporary:
        root = Path(temporary)
        environment_dir = root / "venv"
        venv.EnvBuilder(with_pip=True, clear=True).create(environment_dir)
        python = _venv_executable(environment_dir, "python")
        pip_environment = {
            **os.environ,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
        }
        _run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--no-cache-dir",
                "--only-binary=:all:",
                "--require-hashes",
                "--requirement",
                str(requirements),
            ],
            environment=pip_environment,
        )
        _run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--no-cache-dir",
                "--no-deps",
                str(wheel),
            ],
            environment=pip_environment,
        )

        command = _venv_executable(environment_dir, "strugglebus")
        version = _run([str(command), "--version"], environment=pip_environment)
        if version.stdout.strip() != f"strugglebus {package_version}":
            raise RuntimeError("installed CLI reported an unexpected version")
        schema_version = _run(
            [
                str(python),
                "-c",
                (
                    "from strugglebus.migrations import LATEST_SCHEMA_VERSION; "
                    "print(LATEST_SCHEMA_VERSION)"
                ),
            ],
            environment=pip_environment,
        )
        try:
            expected_schema_version = int(schema_version.stdout.strip())
        except ValueError as exc:
            raise RuntimeError(
                "installed package reported an invalid schema version"
            ) from exc
        if expected_schema_version != EXPECTED_SCHEMA_VERSION:
            raise RuntimeError("installed package reported an unsupported schema version")
        freeze_capability = _run(
            [
                str(python),
                "-c",
                (
                    "from strugglebus.access import ACCESS_FREEZE_CAPABILITY; "
                    "print(ACCESS_FREEZE_CAPABILITY)"
                ),
            ],
            environment=pip_environment,
        )
        if freeze_capability.stdout.strip() != "global-v1":
            raise RuntimeError("installed package lacks the required freeze capability")

        data_dir = root / "data"
        runtime_dir = root / "run"
        backup_dir = root / "backups"
        credential_dir = root / "credentials"
        for directory in (data_dir, runtime_dir, backup_dir, credential_dir):
            directory.mkdir()
        credential_dir.chmod(0o700)
        credential = credential_dir / "admin-token"
        credential.write_text("clean-install-admin-token", encoding="utf-8")
        credential.chmod(0o600)
        database = data_dir / "strugglebus.db"
        bind_host = "127.0.0.1"
        port = _available_port()
        application_environment = {
            **pip_environment,
            "CREDENTIALS_DIRECTORY": str(credential_dir),
            "STRUGGLEBUS_ADMIN_CREDENTIAL_PATH": str(credential),
            "STRUGGLEBUS_BACKUP_DIR": str(backup_dir),
            "STRUGGLEBUS_BIND_HOST": bind_host,
            "STRUGGLEBUS_BIND_PORT": str(port),
            "STRUGGLEBUS_DATA_DIR": str(data_dir),
            "STRUGGLEBUS_DATABASE_PATH": str(database),
            "STRUGGLEBUS_PUBLIC_BASE_URL": f"http://127.0.0.1:{port}",
            "STRUGGLEBUS_RELEASE_ID": "clean-install-test",
            "STRUGGLEBUS_RUNTIME_DIR": str(runtime_dir),
        }
        uvicorn = _venv_executable(environment_dir, "uvicorn")
        process = subprocess.Popen(  # nosec B603
            [
                str(uvicorn),
                "strugglebus.app:app",
                "--host",
                bind_host,
                "--port",
                str(port),
                "--no-access-log",
                "--no-proxy-headers",
                "--no-server-header",
            ],
            env=application_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait_until_ready(process, port)
            health = _run(
                [
                    str(command),
                    "health",
                    "--url",
                    f"http://127.0.0.1:{port}",
                    "--timeout",
                    "5",
                ],
                environment=application_environment,
            )
            if health.stdout.strip() != '{"status":"ok"}':
                raise RuntimeError("installed CLI health check returned unexpected output")

            credential_file = root / "clean-install-agent.credential"
            _run(
                [
                    str(command),
                    "agent",
                    "add",
                    "clean-install-agent",
                    "--credential-output",
                    str(credential_file),
                ],
                environment=application_environment,
            )
            api_key = credential_file.read_text(encoding="ascii").strip()
            if not api_key:
                raise RuntimeError("installed CLI did not write an agent credential")
            authorization = {"Authorization": f"Bearer {api_key}"}
            status, body = _request(
                port,
                "/api/whoami",
                headers=authorization,
            )
            identity = json.loads(body)
            if status != 200:
                raise RuntimeError("installed service did not return credential identity")
            proof = json.dumps(
                {
                    "request_id": str(uuid.uuid4()),
                    "expected_agent_id": identity["agent"]["id"],
                    "expected_agent_name": identity["agent"]["name"],
                    "expected_credential_epoch": identity["agent"]["credential_epoch"],
                    "expected_credential_version": identity["credential"]["version"],
                },
                separators=(",", ":"),
            ).encode("ascii")
            status, _ = _request(
                port,
                "/api/credentials/prove",
                headers={**authorization, "Content-Type": "application/json"},
                method="POST",
                body=proof,
            )
            if status != 200:
                raise RuntimeError("installed service did not prove agent credential")
            status, body = _request(
                port,
                "/api/channels",
                headers=authorization,
            )
            channels = json.loads(body)
            if status != 200 or [channel["name"] for channel in channels] != [
                "announce",
                "help",
                "humans",
                "status",
                "strugglebus-improvements",
            ]:
                raise RuntimeError("installed service failed the minimal database operation")
            status, body = _request(
                port,
                "/api/server-info",
                headers=authorization,
            )
            server_info = json.loads(body)
            if status != 200 or server_info != {
                "application_version": package_version,
                "release_id": "clean-install-test",
                "integration_guide_version": EXPECTED_GUIDE_VERSION,
                "coordination_protocol_version": 1,
            }:
                raise RuntimeError(
                    "installed service reported unexpected version identity: "
                    f"status={status}, body={server_info!r}"
                )
            with closing(sqlite3.connect(database)) as connection:
                if connection.execute("PRAGMA user_version").fetchone() != (
                    expected_schema_version,
                ):
                    raise RuntimeError("installed service did not apply packaged migrations")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
