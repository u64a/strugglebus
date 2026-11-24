from dataclasses import replace
from pathlib import Path

import pytest

from operator_test_support import PASSWORD, verifier
from strugglebus.config import AppConfig
from strugglebus.errors import ConfigurationError
from strugglebus.operator_auth import OperatorAuth, OperatorAuthError, OperatorCapacityError


def test_socket_setting_is_lazy_local_optional_and_outside_writable_paths(tmp_path):
    socket = Path(tmp_path.anchor) / "updater-fixture" / "control.sock"
    config = replace(AppConfig(), data_dir=tmp_path, runtime_dir=tmp_path / "run", backup_dir=tmp_path / "backups")
    assert config.updater_socket_path is None
    assert replace(config, updater_socket_path=socket).updater_socket_path == socket
    assert AppConfig.from_env({"STRUGGLEBUS_UPDATER_SOCKET_PATH": str(socket)}).updater_socket_path == socket
    assert AppConfig.from_env({"STRUGGLEBUS_UPDATER_SOCKET_PATH": ""}).updater_socket_path is None
    for path in (
        str(socket), Path("relative"), tmp_path / "socket", config.runtime_dir / "socket",
        config.backup_dir / "socket", Path(tmp_path.anchor),
        socket.parent / ".." / "control.sock", socket.parent / "bad\nsocket",
        socket.parent / "bad\x7fsocket", socket.parent / "bad\0socket",
        Path(r"\\synthetic-host\share\control.sock"),
    ):
        with pytest.raises(ConfigurationError, match="updater_socket_path"):
            replace(config, updater_socket_path=path)


def test_maintenance_socket_is_lazy_local_optional_and_outside_writable_paths(tmp_path):
    socket = Path(tmp_path.anchor) / "maintenance-fixture" / "control.sock"
    config = replace(
        AppConfig(),
        data_dir=tmp_path,
        runtime_dir=tmp_path / "run",
        backup_dir=tmp_path / "backups",
    )
    assert config.maintenance_socket_path is None
    assert replace(config, maintenance_socket_path=socket).maintenance_socket_path == socket
    assert AppConfig.from_env({
        "STRUGGLEBUS_MAINTENANCE_SOCKET_PATH": str(socket),
    }).maintenance_socket_path == socket
    assert AppConfig.from_env({
        "STRUGGLEBUS_MAINTENANCE_SOCKET_PATH": "",
    }).maintenance_socket_path is None
    for path in (
        str(socket), Path("relative"), tmp_path / "socket",
        config.runtime_dir / "socket", config.backup_dir / "socket",
        Path(tmp_path.anchor), socket.parent / ".." / "control.sock",
        socket.parent / "bad\nsocket", socket.parent / "bad\x7fsocket",
        socket.parent / "bad\0socket", Path(r"\\synthetic-host\share\control.sock"),
    ):
        with pytest.raises(ConfigurationError, match="maintenance_socket_path"):
            replace(config, maintenance_socket_path=path)


def test_socket_name_respects_unix_address_bound(tmp_path, monkeypatch):
    import strugglebus.config as configuration

    path = Path(tmp_path.anchor) / "updater-fixture" / ("x" * 107)
    monkeypatch.setattr(configuration, "os", type("PosixPaths", (), {
        "name": "posix", "fsencode": staticmethod(lambda path: str(path).encode()),
    }))
    with pytest.raises(ConfigurationError, match="socket path"):
        replace(AppConfig(), updater_socket_path=path)


async def _login(authority, source):
    challenge, csrf = authority.challenge(source)
    return (await authority.login(
        source=source, challenge=challenge, csrf=csrf, password=PASSWORD, guard=lambda: None,
    ))[1]


async def test_update_password_budget_is_separate_and_never_remembers_presence():
    config = replace(
        AppConfig(), updater_confirm_session_per_minute=1, updater_confirm_global_per_minute=1,
    )
    authority = OperatorAuth(config, verifier())
    try:
        context = await _login(authority, "caller")
        await authority.reauthenticate(context, PASSWORD, source="caller", family="updater-confirm")
        with pytest.raises(OperatorCapacityError):
            await authority.reauthenticate(context, PASSWORD, source="caller", family="updater-confirm")
        await authority.reauthenticate(context, PASSWORD, source="caller", family="device-enroll")
        authority.require_active(context)
    finally:
        authority.close()


@pytest.mark.parametrize("shared", ["session", "source", "global"])
async def test_update_password_admission_is_bounded_at_every_scope(shared):
    config = replace(
        AppConfig(), updater_confirm_session_per_minute=1,
        updater_confirm_global_per_minute=1 if shared == "global" else 6,
    )
    authority = OperatorAuth(config, verifier())
    try:
        first = await _login(authority, "first")
        second = first if shared == "session" else await _login(authority, "second")
        await authority.reauthenticate(first, PASSWORD, source="first", family="updater-confirm")
        with pytest.raises(OperatorCapacityError):
            await authority.reauthenticate(
                second, PASSWORD, source="first" if shared == "source" else "second", family="updater-confirm",
            )
    finally:
        authority.close()


async def test_revocation_during_update_password_work_is_rechecked(monkeypatch):
    authority = OperatorAuth(AppConfig(), verifier())
    try:
        context = await _login(authority, "caller")

        async def revoke(password):
            authority.logout(context)
            return True

        monkeypatch.setattr(authority, "_verify_password", revoke)
        with pytest.raises(OperatorAuthError, match="session"):
            await authority.reauthenticate(context, PASSWORD, source="caller", family="updater-confirm")
    finally:
        authority.close()
