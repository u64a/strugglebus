import socket
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Any

import hashlib

import pytest
import uvicorn

import strugglebus.operator_auth

from strugglebus.auth import AgentService
from strugglebus.config import AppConfig
from strugglebus.store import SQLiteStore


@contextmanager
def _run_uvicorn(application: Any) -> Iterator[str]:
    server = uvicorn.Server(
        uvicorn.Config(
            application,
            host="127.0.0.1",
            port=0,
            log_level="error",
            timeout_graceful_shutdown=1,
        )
    )
    listening_socket = socket.socket()
    listening_socket.bind(("127.0.0.1", 0))
    listening_socket.listen()
    port = listening_socket.getsockname()[1]
    thread = threading.Thread(
        target=server.run,
        kwargs={"sockets": [listening_socket]},
        daemon=True,
    )
    thread.start()

    deadline = time.monotonic() + 5
    while not server.started:
        if not thread.is_alive() or time.monotonic() >= deadline:
            pytest.fail("Uvicorn did not start")
        time.sleep(0.01)

    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=3)
        listening_socket.close()
        if thread.is_alive():
            pytest.fail("Uvicorn did not stop")


class _OneIterationHashlib:
    """Run operator password hashing with one PBKDF2 iteration.

    The stored ``sbop1$600000$`` format is unchanged; only the work factor is
    skipped. Tests marked ``real_password_hashing`` keep the production cost.
    """

    def __getattr__(self, name: str) -> Any:
        return getattr(hashlib, name)

    @staticmethod
    def pbkdf2_hmac(name: str, password: bytes, salt: bytes, iterations: int, dklen: int | None = None) -> bytes:
        return hashlib.pbkdf2_hmac(name, password, salt, 1, dklen)


@pytest.fixture(scope="session", autouse=True)
def _fast_operator_password_hashing() -> Iterator[None]:
    # Session scope, so module-scoped verifier fixtures are built the same way.
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(strugglebus.operator_auth, "hashlib", _OneIterationHashlib())
        yield


@pytest.fixture(autouse=True)
def _real_password_hashing_when_marked(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    if request.node.get_closest_marker("real_password_hashing") is not None:
        monkeypatch.setattr(strugglebus.operator_auth, "hashlib", hashlib)


@pytest.fixture
def uvicorn_server() -> Callable[[Any], AbstractContextManager[str]]:
    return _run_uvicorn


@pytest.fixture
def app_config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        database_path=tmp_path / "strugglebus.db",
        data_dir=tmp_path,
        runtime_dir=tmp_path / "run",
        backup_dir=tmp_path / "backups",
        admin_credential_path=None,
        admin_secret=b"test-only-admin-secret",
    )


@pytest.fixture
def agent_service(app_config: AppConfig) -> AgentService:
    service = AgentService(
        SQLiteStore(
            app_config.database_path,
            backup_dir=app_config.backup_dir,
            busy_timeout_ms=app_config.sqlite_busy_timeout_ms,
        )
    )
    service.initialize()
    return service
