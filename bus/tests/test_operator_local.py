import getpass
import hashlib
import io
import json
import os
import subprocess
import threading
import warnings
from contextlib import nullcontext
from dataclasses import replace

import pytest

from strugglebus.cli import EXIT_CONFIG, main
from strugglebus.config import AppConfig
from strugglebus.errors import ConfigurationError, StorageError
from strugglebus.operator_auth import PasswordVerifier
from strugglebus.operator_local import (
    PASSWORD_AUTHORIZATION_FILE, PASSWORD_CONTROL_FILE,
    require_resolved_maintenance, require_root_terminal, setup_password, terminal_line,
)


class SyntheticTerminal(io.StringIO):
    def isatty(self):
        return True


def test_emergency_menu_survives_invalid_web_verifier_and_needs_confirmations(
    app_config, tmp_path, monkeypatch,
):
    invalid = tmp_path / "invalid-web-verifier"
    invalid.write_bytes(b"not a verifier")
    config = replace(app_config, operator_credential_path=invalid)
    monkeypatch.setattr(AppConfig, "from_env", lambda: config)
    monkeypatch.setattr("strugglebus.operator_fence.delegated_release_fence", nullcontext)
    monkeypatch.setattr(
        "sys.stdin",
        SyntheticTerminal("1\n2\nsynthetic incident\nno\n2\nsynthetic incident\nFREEZE\n"
                          "1\n3\nsynthetic recovery\nUNFREEZE\n0\n"),
    )
    stdout, stderr = io.StringIO(), io.StringIO()
    assert main(["operator", "emergency"], stdout=stdout, stderr=stderr) == 0
    assert '"frozen":true' in stdout.getvalue()
    assert '"frozen":false' in stdout.getvalue()
    assert "Cancelled" in stderr.getvalue()
    assert "test-only-admin-secret" not in stdout.getvalue() + stderr.getvalue()


def test_emergency_menu_refuses_noninteractive_input_before_config(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("2\nreason\nFREEZE\n"))

    def unexpected():
        raise AssertionError("noninteractive caller loaded administrative configuration")

    monkeypatch.setattr(AppConfig, "from_env", unexpected)
    stderr = io.StringIO()
    assert main(["operator", "emergency"], stderr=stderr) == EXIT_CONFIG
    assert "interactive terminal" in stderr.getvalue()


def test_emergency_menu_refuses_missing_delegation_before_config(monkeypatch):
    monkeypatch.setattr("sys.stdin", SyntheticTerminal("1\n0\n"))
    for name in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
        monkeypatch.delenv(name, raising=False)

    def unexpected():
        raise AssertionError("unfenced caller loaded database configuration")

    monkeypatch.setattr(AppConfig, "from_env", unexpected)
    stderr = io.StringIO()
    assert main(["operator", "emergency"], stderr=stderr) == EXIT_CONFIG
    assert "delegation is unavailable" in stderr.getvalue()


@pytest.mark.parametrize("winner", ["maintenance", "operator"])
def test_transient_runtime_preserves_database_and_transition_lock_serialization(
    app_config, tmp_path, monkeypatch, winner,
):
    from strugglebus import access, cli

    baseline = cli._access_freeze(app_config)
    before = baseline.operator_status()
    canonical = app_config.data_dir / access.ACCESS_FREEZE_LOCK_DIRECTORY
    lock_path = canonical / access.ACCESS_FREEZE_LOCK_NAME
    lock_identity = lock_path.stat()
    config = replace(app_config, runtime_dir=tmp_path / "operator-transient-runtime")
    monkeypatch.setattr(AppConfig, "from_env", lambda: config)
    monkeypatch.setattr("strugglebus.operator_fence.delegated_release_fence", nullcontext)
    monkeypatch.setattr(access, "ACCESS_FREEZE_LOCK_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr("sys.stdin", SyntheticTerminal("2\nsynthetic containment\nFREEZE\n0\n"))
    actual_store = cli.SQLiteStore
    database_paths = []

    def observed_store(path, **kwargs):
        database_paths.append(path)
        return actual_store(path, **kwargs)

    monkeypatch.setattr(cli, "SQLiteStore", observed_store)
    stdout, stderr = io.StringIO(), io.StringIO()
    if winner == "maintenance":
        with access.access_freeze_transition_lock(canonical):
            assert main(["operator", "emergency"], stdout=stdout, stderr=stderr) != 0
        assert "timed out" in stderr.getvalue()
        assert baseline.status() == before
    else:
        entered, proceed = threading.Event(), threading.Event()
        original_transition = access.AccessFreezeService._transition

        def held_transition(self, **kwargs):
            entered.set()
            if not proceed.wait(5):
                raise AssertionError("synthetic transition was not released")
            return original_transition(self, **kwargs)

        monkeypatch.setattr(access.AccessFreezeService, "_transition", held_transition)
        results = []
        worker = threading.Thread(
            target=lambda: results.append(
                main(["operator", "emergency"], stdout=stdout, stderr=stderr),
            ),
        )
        worker.start()
        try:
            assert entered.wait(5), stderr.getvalue()
            with pytest.raises(StorageError, match="timed out"):
                with access.access_freeze_transition_lock(canonical):
                    pytest.fail("maintenance entered the operator-owned transition lock")
        finally:
            proceed.set()
            worker.join(timeout=5)
        assert not worker.is_alive()
        assert results == [0], stderr.getvalue()
        assert baseline.status().frozen
    assert database_paths == [app_config.database_path]
    assert baseline.transition_lock_directory == canonical
    after = lock_path.stat()
    assert (after.st_dev, after.st_ino) == (lock_identity.st_dev, lock_identity.st_ino)
    assert not (config.runtime_dir / access.ACCESS_FREEZE_LOCK_DIRECTORY).exists()
    assert not (config.runtime_dir / app_config.database_path.name).exists()


@pytest.mark.parametrize("value", ["", "12345\n", "a\x1bb\n", "unterminated"])
def test_local_input_is_bounded_and_rejects_control_bytes(value):
    with pytest.raises(ConfigurationError):
        terminal_line(io.StringIO(value), io.StringIO(), "Prompt: ", maximum=3)


@pytest.mark.parametrize("case", ["unknown_option", "positional", "reset_value", "help_value", "type"])
def test_password_command_never_echoes_unsupported_secret_arguments(
    tmp_path, capsys, monkeypatch, case,
):
    from strugglebus import cli
    import argparse

    secret = "synthetic-password-that-must-not-be-echoed"
    arguments = ["operator", "password", "--credential-file", str(tmp_path / "new")]
    if case == "type":
        def invalid_path(value):
            raise argparse.ArgumentTypeError(f"invalid path: {value}")
        monkeypatch.setattr(cli, "Path", invalid_path)
        arguments[-1] = secret
    else:
        arguments += {
            "unknown_option": ["--password", secret],
            "positional": [secret],
            "reset_value": [f"--reset={secret}"],
            "help_value": [f"--help={secret}"],
        }[case]

    def unexpected_handler(*args, **kwargs):
        pytest.fail("invalid arguments must not reach credential handling")

    monkeypatch.setattr(cli, "_operator_password", unexpected_handler)
    with pytest.raises(SystemExit) as error:
        main(arguments)
    assert error.value.code == 2
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err
    assert "invalid operator password arguments" in captured.err


def test_password_argument_help_remains_useful(capsys):
    with pytest.raises(SystemExit) as error:
        main(["operator", "password", "--help"])
    assert error.value.code == 0
    captured = capsys.readouterr()
    assert "--credential-file" in captured.out and "--reset" in captured.out
    assert "usage:" in captured.out and captured.err == ""


@pytest.mark.parametrize("reset", [False, True])
def test_password_valid_arguments_preserve_dispatch(tmp_path, monkeypatch, reset):
    from strugglebus import cli

    source = tmp_path / "operator-password"
    calls = []

    def handler(args, *, stdout, stderr):
        calls.append((args.credential_file, args.reset))
        return 0

    monkeypatch.setattr(cli, "_operator_password", handler)
    arguments = ["operator", "password", "--credential-file", str(source)]
    if reset:
        arguments.append("--reset")
    assert main(arguments, stdout=io.StringIO(), stderr=io.StringIO()) == 0
    assert calls == [(source, reset)]


def test_password_setup_requires_protected_linux_root_terminal():
    with pytest.raises(ConfigurationError):
        require_root_terminal(io.StringIO())
    if os.name != "posix" or os.geteuid() != 0:
        with pytest.raises(ConfigurationError, match="Linux root"):
            require_root_terminal(SyntheticTerminal())


@pytest.fixture
def synthetic_root(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX source-lock and atomic verifier contract")
    tmp_path.chmod(0o700)
    monkeypatch.setattr("strugglebus.operator_local.require_root_terminal", lambda stdin: None)
    monkeypatch.setattr("strugglebus.operator_local.require_resolved_maintenance", lambda: None)
    return tmp_path


def test_setup_and_reset_write_only_one_way_verifier(synthetic_root, monkeypatch):
    source = synthetic_root / "operator-password"
    password = "synthetic initial operator password"
    monkeypatch.setattr(getpass, "getpass", lambda *args, **kwargs: password)
    stderr = io.StringIO()
    setup_password(source, reset=False, stdin=SyntheticTerminal(), stderr=stderr)
    first = source.read_bytes()
    assert PasswordVerifier.parse(first).verify(password)
    assert password.encode() not in first
    assert password not in stderr.getvalue()
    with pytest.raises(ConfigurationError, match="already exists"):
        setup_password(source, reset=False, stdin=SyntheticTerminal(), stderr=stderr)
    password = "different synthetic operator password"
    setup_password(source, reset=True, stdin=SyntheticTerminal(), stderr=stderr)
    assert source.read_bytes() != first
    assert PasswordVerifier.parse(source.read_bytes()).verify(password)
    assert source.stat().st_mode & 0o777 == 0o600
    assert "only after" in stderr.getvalue()
    receipt = json.loads((source.parent / PASSWORD_AUTHORIZATION_FILE).read_bytes())
    assert receipt == {
        "version": 1, "source": str(source),
        "verifier_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "maintenance_operation_id": None, "maintenance_binding_sha256": None,
    }
    assert password not in json.dumps(receipt)


def test_setup_refuses_getpass_echo_fallback(synthetic_root, monkeypatch):
    def unsafe_getpass(*args, **kwargs):
        warnings.warn("unsafe terminal", getpass.GetPassWarning)
        raise AssertionError("echo fallback must never execute")

    monkeypatch.setattr(getpass, "getpass", unsafe_getpass)
    source = synthetic_root / "operator-password"
    with pytest.raises(ConfigurationError, match="no-echo"):
        setup_password(source, reset=False, stdin=SyntheticTerminal(), stderr=io.StringIO())
    assert not source.exists()


@pytest.mark.parametrize("name", [PASSWORD_AUTHORIZATION_FILE, PASSWORD_CONTROL_FILE])
def test_password_setup_cannot_replace_its_own_control_state(tmp_path, monkeypatch, name):
    monkeypatch.setattr("strugglebus.operator_local.require_root_terminal", lambda stdin: None)
    with pytest.raises(ConfigurationError, match="reserved"):
        setup_password(
            tmp_path / name, reset=True, stdin=SyntheticTerminal(), stderr=io.StringIO(),
        )


def test_setup_binds_completed_maintenance_authority(synthetic_root, monkeypatch):
    authority = {"operation_id": "a" * 32, "binding_sha256": "b" * 64}
    monkeypatch.setattr(
        "strugglebus.operator_local.require_resolved_maintenance", lambda: authority,
    )
    monkeypatch.setattr(getpass, "getpass", lambda *args, **kwargs: "synthetic bound password")
    source = synthetic_root / "operator-password"
    setup_password(source, reset=False, stdin=SyntheticTerminal(), stderr=io.StringIO())
    receipt = json.loads((source.parent / PASSWORD_AUTHORIZATION_FILE).read_bytes())
    assert receipt["maintenance_operation_id"] == authority["operation_id"]
    assert receipt["maintenance_binding_sha256"] == authority["binding_sha256"]


def test_setup_does_not_write_when_maintenance_changes_during_prompt(synthetic_root, monkeypatch):
    observations = iter([None, {"operation_id": "a" * 32, "binding_sha256": "b" * 64}])
    monkeypatch.setattr(
        "strugglebus.operator_local.require_resolved_maintenance", lambda: next(observations),
    )
    monkeypatch.setattr(getpass, "getpass", lambda *args, **kwargs: "synthetic bounded password")
    source = synthetic_root / "operator-password"
    with pytest.raises(ConfigurationError, match="maintenance changed"):
        setup_password(source, reset=False, stdin=SyntheticTerminal(), stderr=io.StringIO())
    assert not source.exists()


@pytest.mark.parametrize("existing_directory", [False, True])
def test_clean_install_needs_neither_prior_receipt_nor_old_helper(
    tmp_path, monkeypatch, existing_directory,
):
    state = tmp_path / "maintenance"
    if existing_directory:
        state.mkdir(mode=0o700)
    helper_root = tmp_path / "never-installed-old-helpers"
    original_run = subprocess.run

    def no_old_program(*args, **kwargs):
        if args[0][0] == "/usr/bin/python3.13":
            raise AssertionError("clean installation attempted to execute an older helper")
        return original_run(*args, **kwargs)

    monkeypatch.setattr("strugglebus.operator_local.subprocess.run", no_old_program)
    assert require_resolved_maintenance(
        state_directory=state, helper_root=helper_root,
    ) is None
    assert not (state / "operation.json").exists()
    assert not helper_root.exists()


@pytest.mark.skipif(os.name != "posix", reason="Linux root-terminal setup and source publication")
@pytest.mark.parametrize("existing_directory", [False, True])
def test_clean_install_password_setup_enables_real_projected_browser_login(
    app_config, tmp_path, monkeypatch, existing_directory,
):
    from fastapi.testclient import TestClient
    from strugglebus.app import create_app
    import re

    source_directory = tmp_path / "source"
    source_directory.mkdir(mode=0o700)
    source = source_directory / "operator-password"
    state = tmp_path / "maintenance"
    if existing_directory:
        state.mkdir(mode=0o700)
    helper_root = tmp_path / "never-installed-old-helpers"
    actual_guard = require_resolved_maintenance
    monkeypatch.setattr("strugglebus.operator_local.require_root_terminal", lambda stdin: None)
    monkeypatch.setattr(
        "strugglebus.operator_local.require_resolved_maintenance",
        lambda: actual_guard(state_directory=state, helper_root=helper_root),
    )
    password = "synthetic first-install operator password"
    monkeypatch.setattr(getpass, "getpass", lambda *args, **kwargs: password)
    with TestClient(
        create_app(config=app_config), base_url="https://bus.lan", follow_redirects=False,
    ) as browser:
        # Before any password exists the console offers only first-use setup.
        assert browser.get("/login").headers["location"] == "/setup"
        assert browser.get("/").headers["location"] == "/setup"
        assert browser.get("/healthz").status_code == 200

    setup_password(source, reset=False, stdin=SyntheticTerminal(), stderr=io.StringIO())
    receipt = json.loads((source_directory / PASSWORD_AUTHORIZATION_FILE).read_bytes())
    assert receipt["maintenance_operation_id"] is None
    assert receipt["maintenance_binding_sha256"] is None
    assert not (state / "operation.json").exists()
    assert not helper_root.exists()

    # A real private, runtime-owned projection exercises the loader without
    # invoking systemd or pretending that this test process is privileged.
    projection = tmp_path / "projection"
    projection.mkdir(mode=0o700)
    credential = projection / "operator-password"
    credential.write_bytes(source.read_bytes())
    credential.chmod(0o400)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(projection))
    config = replace(app_config, operator_credential_path=credential)
    with TestClient(
        create_app(config=config), base_url="https://bus.lan", follow_redirects=False,
    ) as browser:
        page = browser.get("/login")
        assert page.status_code == 200
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
        response = browser.post(
            "/login", data={"csrf": csrf, "password": password},
            headers={"Origin": "https://bus.lan"},
        )
        assert response.status_code == 303
        assert browser.get("/").status_code == 200
    assert not (state / "operation.json").exists()
