import json
import hashlib
import io
import os
import runpy
import subprocess
import sys
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "deploy" / "roles" / "systemd" / "templates" / "strugglebus-operator.py.j2"

from strugglebus import cli, operator_ssh
from strugglebus.config import AppConfig
from strugglebus.private_files import windows_directory


@pytest.fixture
def remote_helper():
    source = TEMPLATE.read_text(encoding="utf-8")
    replacements = {
        "strugglebus_service_user": "strugglebus",
        "strugglebus_service_group": "strugglebus",
        "strugglebus_data_dir": "/synthetic/data",
        "strugglebus_database_path": "/synthetic/data/board.db",
        "strugglebus_backup_dir": "/synthetic/backups",
        "strugglebus_runtime_dir": "/synthetic/run",
        "(strugglebus_config_dir ~ '/credentials/admin-token')": "/synthetic/credentials/admin-token",
        "(strugglebus_data_dir ~ ' ' ~ strugglebus_backup_dir)": "/synthetic/data /synthetic/backups",
        "(strugglebus_current_link ~ '/venv/bin/strugglebus')": "/synthetic/current/venv/bin/strugglebus",
    }
    for expression, value in replacements.items():
        source = source.replace("{{ " + expression + " | to_json }}", json.dumps(value))
    assert "{{" not in source
    namespace = {"__name__": "synthetic_operator_helper"}
    exec(compile(source, str(TEMPLATE), "exec"), namespace)
    return SimpleNamespace(**namespace)


def test_remote_entry_uses_only_fixed_local_service_command(remote_helper, monkeypatch):
    monkeypatch.setattr(remote_helper.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(sys, "argv", ["strugglebus-operator"])
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setenv("SYSTEMD_HOST", "synthetic-forbidden-remote")
    monkeypatch.setenv("DBUS_SYSTEM_BUS_ADDRESS", "synthetic-forbidden-bus")
    monkeypatch.setenv("STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH", "synthetic-forbidden-web-verifier")
    calls = []
    monkeypatch.setitem(
        remote_helper.main.__globals__, "private_binding",
        lambda owner: nullcontext(Path("/synthetic/private-binding")),
    )

    def run(arguments, **kwargs):
        calls.append((arguments, kwargs))
        if "--version" in arguments:
            return SimpleNamespace(returncode=0, stdout=b"systemd 257\n")
        if "acquire" in arguments:
            return SimpleNamespace(returncode=0, stdout=json.dumps({
                "version": 1, "pid": 123, "start_ticks": 1,
                "token": "a" * 64, "lease_seconds": 7200, "heartbeat_ns": 1,
            }).encode())
        return SimpleNamespace(
            returncode=0,
            stdout=b"LoadState=not-found\nActiveState=inactive\n" if "show" in arguments else b"",
        )

    monkeypatch.setattr(remote_helper.subprocess, "run", run)
    assert remote_helper.main() == 0
    arguments, options = calls[2]
    assert arguments[0] == "/usr/bin/systemd-run"
    assert arguments[-3:] == [
        "/synthetic/current/venv/bin/strugglebus", "operator", "emergency",
    ]
    assert "--property=User=strugglebus" in arguments
    assert "--property=LoadCredential=admin-token:/synthetic/credentials/admin-token" in arguments
    assert "--property=LoadCredential=operator-lease:" + str(Path("/synthetic/private-binding")) in arguments
    assert "--property=OpenFile=/run/lock/strugglebus/control.lock:operator-control:read-only" in arguments
    assert "--property=OpenFile=/run/lock/strugglebus/release.json:operator-metadata:read-only" in arguments
    assert "--property=RestrictAddressFamilies=AF_UNIX" in arguments
    runtime = next(value for value in arguments if value.startswith("--property=RuntimeDirectory="))
    name = runtime.split("=", 2)[-1]
    assert name.startswith("strugglebus-operator-")
    assert "--setenv=STRUGGLEBUS_RUNTIME_DIR=/run/" + name in arguments
    assert "--property=RuntimeDirectoryMode=0700" in arguments
    assert set(options["env"]) == {"PATH", "LANG", "TERM"}
    assert not options.get("shell", False)
    assert not any("OPERATOR_CREDENTIAL" in argument for argument in arguments)
    assert calls[1][0][3] == "acquire"
    assert calls[1][0][4:8] == [
        "--lock-path", "/run/lock/strugglebus/release.lock",
        "--metadata-path", "/run/lock/strugglebus/release.json",
    ]
    assert calls[-1][0][2] == "-c"
    assert json.loads(calls[-1][1]["input"]) == {"token": "a" * 64}
    assert not any("a" * 64 in argument for arguments, _ in calls for argument in arguments)
    assert ["stop", "show"] == [call[0][2] for call in calls[3:5]]
    assert options["timeout"] < remote_helper.RELEASE_LEASE_SECONDS
    assert "--setenv=STRUGGLEBUS_DATA_DIR=/synthetic/data" in arguments
    assert "--setenv=STRUGGLEBUS_DATABASE_PATH=/synthetic/data/board.db" in arguments
    assert "--setenv=STRUGGLEBUS_BACKUP_DIR=/synthetic/backups" in arguments


@pytest.mark.parametrize("failure", ["lease-busy", "timeout", "interrupted", "unit-active"])
def test_emergency_lease_failure_never_launches_or_releases_unsafe_authority(
    remote_helper, monkeypatch, failure, capsys,
):
    monkeypatch.setattr(remote_helper.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(sys, "argv", ["strugglebus-operator"])
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: True))
    calls = []
    monkeypatch.setitem(
        remote_helper.main.__globals__, "private_binding",
        lambda owner: nullcontext(Path("/synthetic/private-binding")),
    )

    def run(arguments, **kwargs):
        calls.append(arguments)
        if "--version" in arguments:
            return SimpleNamespace(returncode=0, stdout=b"systemd 257\n")
        if "acquire" in arguments:
            return SimpleNamespace(
                returncode=1 if failure == "lease-busy" else 0,
                stdout=json.dumps({
                    "version": 1, "pid": 123, "start_ticks": 1,
                    "token": "a" * 64, "lease_seconds": 7200, "heartbeat_ns": 1,
                }).encode(),
            )
        if arguments[0] == "/usr/bin/systemd-run":
            if failure == "timeout":
                raise subprocess.TimeoutExpired(arguments, 3700)
            if failure == "interrupted":
                raise KeyboardInterrupt
        return SimpleNamespace(
            returncode=0,
            stdout=b"LoadState=loaded\nActiveState=active\n" if "show" in arguments else b"",
        )

    monkeypatch.setattr(remote_helper.subprocess, "run", run)
    assert remote_helper.main() == 1
    assert not any("-c" in arguments for arguments in calls)
    if failure == "lease-busy":
        assert len(calls) == 2
    else:
        assert any("stop" in arguments for arguments in calls)
    output = capsys.readouterr()
    assert "a" * 64 not in output.out + output.err


@pytest.mark.skipif(sys.platform != "linux", reason="existing Linux process-owned release lock")
def test_operator_fence_contends_with_the_real_maintenance_release_lock(
    remote_helper, tmp_path, monkeypatch,
):
    helper = ROOT / "deploy" / "roles" / "guest_base" / "files" / "strugglebus-release-lock.py"
    directory = tmp_path / "release-lock"
    directory.mkdir(mode=0o700)
    lock_path, metadata_path = directory / "release.lock", directory / "release.json"
    namespace = remote_helper.main.__globals__
    monkeypatch.setitem(namespace, "RELEASE_LOCK_HELPER", str(helper))
    monkeypatch.setitem(namespace, "RELEASE_LOCK_PATH", str(lock_path))
    monkeypatch.setitem(namespace, "RELEASE_METADATA_PATH", str(metadata_path))
    monkeypatch.setitem(namespace, "RELEASE_LEASE_SECONDS", 10)
    monkeypatch.setattr(remote_helper.os, "geteuid", lambda: 0)
    monkeypatch.setattr(sys, "argv", ["strugglebus-operator"])
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: True))
    real_run = subprocess.run
    entered = []

    def run(arguments, **kwargs):
        if "--version" in arguments:
            return SimpleNamespace(returncode=0, stdout=b"systemd 257\n")
        if arguments[0] == "/usr/bin/python3.13":
            return real_run([sys.executable, *arguments[1:]], **kwargs)
        if arguments[0] == "/usr/bin/systemd-run":
            owned = json.loads(metadata_path.read_bytes())
            contender = real_run(
                [
                    sys.executable, str(helper), "acquire",
                    "--lock-path", str(lock_path), "--metadata-path", str(metadata_path),
                    "--wait-seconds", "1", "--lease-seconds", "5",
                ],
                capture_output=True, timeout=10, check=False,
            )
            assert contender.returncode == 1
            assert b"timed out" in contender.stderr
            assert json.loads(metadata_path.read_bytes()) == owned
            entered.append(True)
        return SimpleNamespace(
            returncode=0,
            stdout=b"LoadState=not-found\nActiveState=inactive\n" if "show" in arguments else b"",
        )

    monkeypatch.setattr(remote_helper.subprocess, "run", run)
    try:
        assert remote_helper.main() == 0
        assert entered == [True]
        assert not metadata_path.exists()
    finally:
        if metadata_path.exists():
            token = json.loads(metadata_path.read_bytes())["token"]
            real_run(
                [sys.executable, str(helper), "release",
                 "--metadata-path", str(metadata_path), "--token", token],
                capture_output=True, timeout=10, check=True,
            )


def test_root_entry_installation_pins_template_and_validates_rendered_python():
    tasks = (ROOT / "deploy" / "roles" / "systemd" / "tasks" / "operator_controls.yml").read_text()
    assert hashlib.sha256(TEMPLATE.read_bytes()).hexdigest() in tasks
    assert 'source: "{{ strugglebus_operator_rendered.path }}"' in tasks
    assert 'sha256: "{{ strugglebus_operator_rendered_identity.stat.checksum }}"' in tasks
    assert "validated_python_helper.yml" in tasks
    assert "callables: [main, command]" in tasks
    assert "destination: /usr/local/sbin/strugglebus-operator" in tasks
    assert "always:" in tasks
    assert 'path: "{{ strugglebus_operator_rendered.path }}"' in tasks
    assert "state: absent" in tasks
    for relative in [
        ("systemd", "main.yml"), ("release", "maintenance_configuration.yml"),
    ]:
        role, name = relative
        assert "operator_controls.yml" in (
            ROOT / "deploy" / "roles" / role / "tasks" / name
        ).read_text()


def test_operator_support_contains_reviewed_inputs_not_an_executable_template(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    support = runpy.run_path(str(ROOT / "scripts" / "release_bundle.py"))["SUPPORT_FILES"]
    expected = {
        "deploy/roles/systemd/templates/strugglebus-operator.py.j2",
        "deploy/roles/systemd/tasks/operator_controls.yml",
        "deploy/roles/systemd/tasks/operator_credential.yml",
    }
    actual = {entry.source: entry for entry in support if entry.source in expected}
    assert set(actual) == expected
    for source, entry in actual.items():
        assert entry.archive == entry.destination == source
        assert entry.mode == 0o644
    assert not any(entry.source.endswith(".ps1") for entry in support)


@pytest.mark.parametrize("root,terminal,arguments", [
    (False, True, ["helper"]), (True, False, ["helper"]),
    (True, True, ["helper", "arbitrary-command"]),
])
def test_remote_entry_refuses_unprivileged_nonterminal_or_arbitrary_commands(
    remote_helper, monkeypatch, root, terminal, arguments,
):
    monkeypatch.setattr(remote_helper.os, "geteuid", lambda: 0 if root else 123, raising=False)
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: terminal))
    monkeypatch.setattr(sys, "argv", arguments)

    def never_run(*args, **kwargs):
        raise AssertionError("unauthorized entry attempted a privileged operation")

    monkeypatch.setattr(remote_helper.subprocess, "run", never_run)
    assert remote_helper.main() == 2


@pytest.mark.parametrize("version", [b"systemd 252\n", b"unrecognized\n", b""])
def test_operator_requires_openfile_support_before_lease_or_unit(
    remote_helper, monkeypatch, version,
):
    calls = []
    monkeypatch.setattr(remote_helper.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(sys, "argv", ["strugglebus-operator"])
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: True))

    def run(arguments, **kwargs):
        calls.append(arguments)
        return SimpleNamespace(returncode=0, stdout=version)

    monkeypatch.setattr(remote_helper.subprocess, "run", run)
    assert remote_helper.main() == 1
    assert calls == [["/usr/bin/systemd-run", "--version"]]


def test_launcher_has_one_remote_command_and_no_trust_or_password_fallback(tmp_path):
    config = operator_ssh.SSHConfiguration(
        "synthetic.invalid", "root", "22", tmp_path / "identity", tmp_path / "hosts",
    )
    arguments = operator_ssh._ssh_arguments(Path("synthetic-system-ssh"), config)
    assert arguments.count("/usr/local/sbin/strugglebus-operator") == 1
    for argument in (
        "StrictHostKeyChecking=yes", "UpdateHostKeys=no",
        "ClearAllForwardings=yes", "ForwardAgent=no", "ProxyCommand=none",
        "ProxyJump=none", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
        "ControlMaster=no", "IdentityAgent=none",
    ):
        assert argument in arguments
    assert arguments[1:3] == ["-F", "NUL"]
    assert arguments[-2:] == [
        "strugglebus-operator", "/usr/local/sbin/strugglebus-operator",
    ]
    assert not any(".ps1" in argument for argument in arguments)


@pytest.fixture
def ssh_config(tmp_path):
    tmp_path.chmod(0o700)
    key, hosts = tmp_path / "synthetic-key", tmp_path / "synthetic-known-hosts"
    key.write_text("not a real key", encoding="ascii")
    hosts.write_text("not a real host pin", encoding="ascii")
    config = tmp_path / "synthetic-ssh-config"
    config.write_text(
        "Host strugglebus-operator\n"
        "  HostName synthetic.invalid\n"
        "  User root\n"
        f'  IdentityFile "{key}"\n'
        f'  UserKnownHostsFile "{hosts}"\n'
        "  IdentitiesOnly yes\n",
        encoding="utf-8",
    )
    for path in (key, hosts, config):
        path.chmod(0o600)
    return config


@pytest.fixture
def ssh_boundary(monkeypatch):
    monkeypatch.setattr(operator_ssh, "_ssh_program", lambda: Path("synthetic-system-ssh"))
    calls = []

    def invoke(arguments):
        calls.append(arguments)
        return 0

    def no_config():
        raise AssertionError("Windows operator client loaded server configuration")

    monkeypatch.setattr(operator_ssh, "_invoke_ssh", invoke)
    monkeypatch.setattr(AppConfig, "from_env", no_config)
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: True))
    return calls


def test_actual_installed_cli_connects_using_only_validated_argv(ssh_config, ssh_boundary):
    output, diagnostics = io.StringIO(), io.StringIO()
    assert cli.main(
        ["operator", "connect", "--ssh-config", str(ssh_config)],
        stdout=output, stderr=diagnostics,
    ) == 0
    assert len(ssh_boundary) == 1
    arguments = ssh_boundary[0]
    assert arguments[1:3] == ["-F", "NUL"]
    assert str(ssh_config) not in arguments
    assert arguments[-1] == "/usr/local/sbin/strugglebus-operator"
    assert "HostName=synthetic.invalid" in arguments
    assert "root" in arguments
    assert diagnostics.getvalue() == ""


def test_cli_validate_only_does_not_start_ssh(ssh_config, ssh_boundary):
    output = io.StringIO()
    assert cli.main(
        ["operator", "connect", "--ssh-config", str(ssh_config), "--validate-only"],
        stdout=output,
    ) == 0
    assert "no connection was made" in output.getvalue()
    assert not ssh_boundary


@pytest.mark.parametrize("extra", [
    "Include other.conf", "Match exec command", "ProxyCommand command",
    "RemoteCommand command", "LocalForward 8080 host:80", "Host *",
    "IdentityAgent agent", "IdentityFile %h", "User another",
])
def test_actual_cli_rejects_executable_duplicate_or_unapproved_config(
    ssh_config, ssh_boundary, extra,
):
    with ssh_config.open("a", encoding="utf-8") as stream:
        stream.write("  " + extra + "\n")
    diagnostics = io.StringIO()
    assert cli.main(
        ["operator", "connect", "--ssh-config", str(ssh_config)],
        stderr=diagnostics,
    ) == cli.EXIT_CONFIG
    assert not ssh_boundary
    assert extra not in diagnostics.getvalue()


def test_actual_cli_requires_human_terminal(ssh_config, ssh_boundary, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO())
    assert cli.main(
        ["operator", "connect", "--ssh-config", str(ssh_config)],
        stderr=io.StringIO(),
    ) == cli.EXIT_CONFIG
    assert not ssh_boundary


def test_cli_reports_failed_ssh_without_any_fallback(ssh_config, ssh_boundary, monkeypatch):
    monkeypatch.setattr(operator_ssh, "_invoke_ssh", lambda arguments: 255)
    diagnostics = io.StringIO()
    assert cli.main(
        ["operator", "connect", "--ssh-config", str(ssh_config)],
        stderr=diagnostics,
    ) != 0
    assert "no web fallback" in diagnostics.getvalue()


def test_ssh_process_drops_ambient_agent_and_askpass_overrides(monkeypatch):
    monkeypatch.setenv("SSH_ASKPASS", "synthetic-untrusted-program")
    monkeypatch.setenv("SSH_ASKPASS_REQUIRE", "force")
    monkeypatch.setenv("SSH_AUTH_SOCK", "synthetic-agent")
    monkeypatch.setenv("SSH_SK_PROVIDER", "synthetic-provider")
    calls = []

    def run(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(operator_ssh.subprocess, "run", run)
    assert operator_ssh._invoke_ssh(["synthetic-system-ssh"]) == 0
    arguments, options = calls[0]
    assert arguments == ["synthetic-system-ssh"]
    assert not any(name.upper().startswith("SSH_") for name in options["env"])
    assert not options.get("shell", False)
    assert options["timeout"] == 3660


@pytest.mark.skipif(os.name != "nt", reason="Windows file-sharing contract")
def test_actual_cli_pins_private_files_while_ssh_runs(ssh_config, ssh_boundary, monkeypatch):
    def invoke(arguments):
        with pytest.raises(PermissionError):
            ssh_config.write_text("Include unsafe.conf", encoding="utf-8")
        ssh_boundary.append(arguments)
        return 0

    monkeypatch.setattr(operator_ssh, "_invoke_ssh", invoke)
    assert cli.main(
        ["operator", "connect", "--ssh-config", str(ssh_config)],
        stdout=io.StringIO(), stderr=io.StringIO(),
    ) == 0
    assert len(ssh_boundary) == 1


@pytest.mark.skipif(os.name != "nt", reason="native Windows directory API")
def test_windows_program_location_ignores_ambient_systemroot(tmp_path, monkeypatch):
    actual = windows_directory()
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    assert windows_directory() == actual
