"""Operator and client command handlers that delegate to other modules."""

from __future__ import annotations

import io
import json
import sys
from email.message import Message
from pathlib import Path
from urllib.error import HTTPError

import pytest

import strugglebus.cli as cli
import strugglebus.operator_local as operator_local
import strugglebus.reconnect as reconnect
import strugglebus.satellite_client as satellite_client
from strugglebus.cli import (
    EXIT_AUTH,
    EXIT_CONFIG,
    EXIT_INTERRUPTED,
    EXIT_NETWORK,
    EXIT_OK,
    EXIT_SERVER,
    main,
)
from strugglebus.operator_auth import OperatorAuthError


class _Response(io.BytesIO):
    def __init__(self, body: bytes) -> None:
        super().__init__(body)
        self.headers = Message()
        self.headers["Content-Type"] = "application/json"

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


@pytest.fixture
def local(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point the CLI at a private data directory with a usable admin credential."""
    directory = tmp_path.resolve()
    directory.chmod(0o700)
    credential = directory / "admin-token"
    credential.write_text("test-admin-token", encoding="utf-8")
    credential.chmod(0o600)
    values = {
        "STRUGGLEBUS_DATA_DIR": str(directory),
        "STRUGGLEBUS_RUNTIME_DIR": str(directory / "run"),
        "STRUGGLEBUS_BACKUP_DIR": str(directory / "backups"),
        "STRUGGLEBUS_DATABASE_PATH": str(directory / "strugglebus.db"),
        "STRUGGLEBUS_ADMIN_CREDENTIAL_PATH": str(credential),
        "STRUGGLEBUS_PUBLIC_BASE_URL": "https://bus.lan",
        "CREDENTIALS_DIRECTORY": str(directory),
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    return directory


def _run(*arguments: str) -> tuple[int, str, str]:
    output, diagnostics = io.StringIO(), io.StringIO()
    code = main(list(arguments), stdout=output, stderr=diagnostics)
    return code, output.getvalue(), diagnostics.getvalue()


# --- Operator password --------------------------------------------------------


def test_operator_password_hands_the_terminal_to_the_verifier_setup(monkeypatch, tmp_path):
    calls = []

    def setup(path, **options):
        calls.append((path, options))

    monkeypatch.setattr(operator_local, "setup_password", setup)
    credential = tmp_path / "operator-verifier"
    diagnostics = io.StringIO()

    code = main(
        ["operator", "password", "--credential-file", str(credential), "--reset"],
        stdout=io.StringIO(),
        stderr=diagnostics,
    )

    assert code == EXIT_OK
    assert calls == [
        (credential, {"reset": True, "stdin": sys.stdin, "stderr": diagnostics}),
    ]


@pytest.mark.parametrize(
    "error", [PermissionError("synthetic"), OperatorAuthError("synthetic secret detail")],
    ids=["os", "verifier"],
)
def test_operator_password_failures_point_to_the_recovery_runbook(
    monkeypatch, tmp_path, error,
):
    def setup(path, **options):
        assert options["reset"] is False
        raise error

    monkeypatch.setattr(operator_local, "setup_password", setup)

    code, output, diagnostics = _run(
        "operator", "password", "--credential-file", str(tmp_path / "verifier"),
    )

    assert (code, output) == (EXIT_CONFIG, "")
    assert diagnostics == (
        "configuration error: operator verifier update did not complete safely; "
        "use the local recovery runbook\n"
    )


# --- Emergency menu -----------------------------------------------------------


def test_emergency_menu_confirms_each_change_and_reports_state(monkeypatch, local):
    answers = iter([
        "9",
        "1",
        "2", "  credential leaked  ", "freeze",
        "2", "credential leaked", "FREEZE",
        "3", "rotated", "UNFREEZE",
        "0",
    ])
    prompts = []

    def terminal_line(stdin, stdout, prompt, *, maximum):
        prompts.append((prompt, maximum))
        return next(answers)

    monkeypatch.setattr(operator_local, "terminal_line", terminal_line)
    output, diagnostics = io.StringIO(), io.StringIO()

    assert cli._operator_emergency_menu(stdout=output, stderr=diagnostics) == EXIT_OK

    assert diagnostics.getvalue() == (
        "Choose 1, 2, 3 or 0.\n"
        "Cancelled; access state was not changed.\n"
    )
    status, frozen, unfrozen = [json.loads(line) for line in output.getvalue().splitlines()]
    assert status["frozen"] is False and "changed" not in status
    assert (frozen["frozen"], frozen["changed"], frozen["reason"]) == (
        True, True, "credential leaked",
    )
    assert (unfrozen["frozen"], unfrozen["changed"], unfrozen["reason"]) == (
        False, True, "rotated",
    )
    assert ("Type FREEZE to confirm: ", 8) in prompts
    assert ("Type UNFREEZE to confirm: ", 8) in prompts
    assert ("Reason (no secrets): ", 256) in prompts
    assert next(answers, None) is None


# --- Enrollment ---------------------------------------------------------------


def test_enrollment_can_be_revoked_by_id_with_a_reason(local):
    token = local / "enrollment-token"
    code, _, diagnostics = _run(
        "agent", "enroll", "create", "builder", "--token-output", str(token),
    )
    assert code == EXIT_OK, diagnostics
    assert len(token.read_bytes()) == 72
    (listed,) = json.loads(_run("agent", "enroll", "list")[1])
    assert listed["status"] == "pending"

    code, output, diagnostics = _run(
        "agent", "enroll", "revoke", listed["id"], "--reason", "issued by mistake",
    )

    assert (code, output) == (EXIT_OK, "")
    assert diagnostics == f"revoked enrollment {listed['id']}\n"
    (after,) = json.loads(_run("agent", "enroll", "list")[1])
    assert after["status"] == "revoked"
    assert token.read_text(encoding="ascii").strip() not in json.dumps(after)

    code, _, diagnostics = _run(
        "agent", "enroll", "revoke", "enr_does-not-exist", "--reason", "cleanup",
    )
    assert code == EXIT_SERVER
    assert diagnostics == "server error: enrollment does not exist\n"


# --- Reconnect ----------------------------------------------------------------


def test_reconnect_redeem_reports_the_saved_pending_credential(monkeypatch, tmp_path):
    calls = []

    def redeem(package_file, credential_output):
        calls.append((package_file, credential_output))
        return type("Package", (), {"agent_id": "agent-1", "agent_name": "builder"})()

    monkeypatch.setattr(reconnect, "redeem_package", redeem)

    code, output, diagnostics = _run(
        "reconnect", "redeem",
        "--package-file", str(tmp_path / "package"),
        "--credential-output", str(tmp_path / "credential"),
    )

    assert code == EXIT_OK
    assert calls == [(tmp_path / "package", tmp_path / "credential")]
    assert json.loads(output) == {
        "agent_id": "agent-1",
        "agent_name": "builder",
        "credential_saved": True,
        "credential_status": "pending",
        "bootstrap_complete": False,
    }
    assert diagnostics.startswith("Pending credential saved privately.")


def test_interrupted_reconnect_warns_that_the_grant_may_be_spent(monkeypatch, tmp_path):
    def redeem(package_file, credential_output):
        raise KeyboardInterrupt

    monkeypatch.setattr(reconnect, "redeem_package", redeem)

    code, output, diagnostics = _run(
        "reconnect", "redeem",
        "--package-file", str(tmp_path / "package"),
        "--credential-output", str(tmp_path / "credential"),
    )

    assert (code, output) == (EXIT_INTERRUPTED, "")
    assert diagnostics == (
        "reconnect interrupted; the result may be uncertain; request an "
        "explicit operator reissue before retrying\n"
    )


# --- Satellite ----------------------------------------------------------------


@pytest.fixture
def satellite(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(satellite_client, "state_dir", lambda: tmp_path / "state")
    monkeypatch.setattr(
        satellite_client, "join", lambda directory: calls.append(("join", directory)),
    )
    monkeypatch.setattr(
        satellite_client,
        "install_task",
        lambda directory, port: calls.append(("install-task", directory, port)),
    )
    monkeypatch.setattr(
        satellite_client,
        "link_agent",
        lambda name, **options: calls.append(("link-agent", name, options)),
    )

    class _Satellite:
        def __init__(self, directory, port):
            calls.append(("run", directory, port))

        async def serve(self):
            return 7

    monkeypatch.setattr(satellite_client, "Satellite", _Satellite)
    return calls


def test_satellite_commands_use_the_site_state_directory_and_port(satellite, tmp_path):
    state = tmp_path / "state"

    assert _run("satellite", "join")[0] == EXIT_OK
    assert _run("satellite", "install-task")[0] == EXIT_OK
    assert _run("satellite", "install-task", "--port", "9001")[0] == EXIT_OK
    assert _run(
        "satellite", "link-agent", "builder", "--description", "CI", "--port", "9002",
        "--write", str(tmp_path / "mcp.json"),
    )[0] == EXIT_OK
    assert _run("satellite", "link-agent", "reviewer")[0] == EXIT_OK

    assert satellite == [
        ("join", state),
        ("install-task", state, 8765),
        ("install-task", state, 9001),
        ("link-agent", "builder",
         {"port": 9002, "description": "CI", "write": tmp_path / "mcp.json"}),
        ("link-agent", "reviewer", {"port": 8765, "description": "", "write": None}),
    ]


def test_satellite_run_returns_the_proxy_exit_status(satellite, tmp_path):
    assert _run("satellite", "run", "--port", "9100")[0] == 7
    assert satellite == [("run", tmp_path / "state", 9100)]


# --- Health -------------------------------------------------------------------


def _health(monkeypatch, local, outcome) -> tuple[int, str, str]:
    def open_request(request, **options):
        assert request.full_url == "https://bus.lan/healthz"
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(cli, "_ssl_context", lambda ca_file: "tls-context")
    monkeypatch.setattr(cli, "_open", open_request)
    return _run("health")


@pytest.mark.parametrize(
    ("body", "diagnostic"),
    [
        (b"x" * (cli.MAX_HEALTH_RESPONSE_BYTES + 1),
         "server error: health response exceeded the configured bound\n"),
        (b"<html>starting</html>", "server error: health endpoint returned invalid JSON\n"),
        (b"\xff\xfe", "server error: health endpoint returned invalid JSON\n"),
        (b'{"status":"starting"}', "server error: service is not ready\n"),
        (b'{"status":"ok","extra":1}', "server error: service is not ready\n"),
        (b"[]", "server error: service is not ready\n"),
    ],
    ids=["oversized", "html", "not-utf8", "starting", "extra-field", "not-object"],
)
def test_health_requires_exactly_the_ready_document(monkeypatch, local, body, diagnostic):
    code, output, diagnostics = _health(monkeypatch, local, _Response(body))

    assert (code, output, diagnostics) == (EXIT_SERVER, "", diagnostic)


@pytest.mark.parametrize(
    ("outcome", "code", "diagnostic"),
    [
        (HTTPError("https://bus.lan/healthz", 401, "x", Message(), None), EXIT_AUTH,
         "authentication error: health authentication failed\n"),
        (HTTPError("https://bus.lan/healthz", 503, "x", Message(), None), EXIT_SERVER,
         "server error: health endpoint returned an error\n"),
        (ConnectionResetError("synthetic detail"), EXIT_NETWORK,
         "network error: network request failed\n"),
    ],
    ids=["unauthorized", "unavailable", "reset"],
)
def test_health_failures_map_to_stable_exit_codes(
    monkeypatch, local, outcome, code, diagnostic,
):
    assert _health(monkeypatch, local, outcome) == (code, "", diagnostic)


def test_health_reports_ready_as_compact_json(monkeypatch, local):
    assert _health(monkeypatch, local, _Response(b'{ "status" : "ok" }')) == (
        EXIT_OK, '{"status":"ok"}\n', "",
    )


# --- Serve preflight ----------------------------------------------------------


def _preflight_config(tmp_path: Path, **overrides):
    values = {
        "data_dir": tmp_path,
        "admin_secret": b"x" * 40,
        "admin_credential_path": tmp_path / "admin-token",
        "public_base_url": "https://bus.lan",
    }
    values.update(overrides)
    return type("Config", (), values)()


def test_serve_preflight_names_a_missing_data_directory(tmp_path):
    config = _preflight_config(tmp_path, data_dir=tmp_path / "absent")

    with pytest.raises(cli.ConfigurationError, match="data directory does not exist") as raised:
        cli._serve_preflight(config, io.StringIO())
    assert str(tmp_path / "absent") in str(raised.value)
    assert "STRUGGLEBUS_DATA_DIR" in str(raised.value)


def test_serve_preflight_names_the_unusable_admin_credential(tmp_path):
    def load_admin_secret():
        raise cli.ConfigurationError("admin credential file is unavailable")

    config = _preflight_config(
        tmp_path, admin_secret=None, load_admin_secret=staticmethod(load_admin_secret),
    )

    with pytest.raises(cli.ConfigurationError) as raised:
        cli._serve_preflight(config, io.StringIO())
    message = str(raised.value)
    assert message.startswith(
        f"admin credential file is unavailable: {tmp_path / 'admin-token'}."
    )
    assert "STRUGGLEBUS_ADMIN_CREDENTIAL_PATH" in message
    assert raised.value.__cause__ is None


def test_serve_preflight_warns_about_short_tokens_and_plain_http(tmp_path):
    config = _preflight_config(
        tmp_path,
        admin_secret=None,
        load_admin_secret=staticmethod(lambda: b"short-token"),
        public_base_url="http://127.0.0.1:8080",
    )
    diagnostics = io.StringIO()

    cli._serve_preflight(config, diagnostics)

    first, second = diagnostics.getvalue().splitlines()
    assert first.startswith(
        f"warning: the admin token in {tmp_path / 'admin-token'} is only 11 characters long."
    )
    assert "short-token" not in diagnostics.getvalue()
    assert second.startswith("warning: STRUGGLEBUS_PUBLIC_BASE_URL is not an https:// address")


def test_serve_preflight_is_silent_for_a_sound_configuration(tmp_path):
    config = _preflight_config(
        tmp_path, admin_secret=None, load_admin_secret=staticmethod(lambda: b"t" * 32),
        public_base_url="HTTPS://bus.lan",
    )
    diagnostics = io.StringIO()

    cli._serve_preflight(config, diagnostics)
    cli._serve_preflight(_preflight_config(tmp_path), diagnostics)

    assert diagnostics.getvalue() == ""
