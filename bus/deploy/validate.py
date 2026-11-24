"""Validate deployment playbooks and templates without live infrastructure."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import grp
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pwd
import py_compile
import re
import shutil
import sqlite3
import ssl

# Subprocess is required only for the fixed offline validation commands below.
import subprocess  # nosec B404
import sys
import tempfile
import threading


DEPLOY_DIR = Path(__file__).resolve().parent
ANSIBLE_PLAYBOOK = shutil.which("ansible-playbook")
if ANSIBLE_PLAYBOOK is None:
    raise RuntimeError("ansible-playbook is required for deployment validation")
PLAYBOOKS = (
    "playbooks/provision.yml",
    "playbooks/bootstrap.yml",
    "playbooks/configure.yml",
    "playbooks/maintenance_deploy.yml",
    "playbooks/updater_bootstrap.yml",
    "playbooks/export_ca.yml",
    "playbooks/smoke.yml",
    "playbooks/satellite.yml",
    "tests/release_tasks_syntax.yml",
    "tests/lan_ca_check_mode.yml",
    "tests/lan_ca_activation_evidence.yml",
    "tests/systemd_development_check_mode.yml",
)


def run(*command: str) -> None:
    environment = os.environ.copy()
    environment["ANSIBLE_CONFIG"] = str(DEPLOY_DIR / "ansible.cfg")
    # Every caller below supplies fixed argv; shell expansion stays disabled.
    subprocess.run(  # nosec B603
        command,
        cwd=DEPLOY_DIR,
        env=environment,
        check=True,
    )


def run_expected_failure(
    *command: str,
    environment_overrides: dict[str, str],
) -> None:
    environment = os.environ.copy()
    environment["ANSIBLE_CONFIG"] = str(DEPLOY_DIR / "ansible.cfg")
    environment.update(environment_overrides)
    # The validator supplies fixed argv and deliberately disables shell parsing.
    result = subprocess.run(  # nosec B603
        command,
        cwd=DEPLOY_DIR,
        env=environment,
        check=False,
    )
    if result.returncode == 0:
        raise RuntimeError(
            f"command unexpectedly succeeded with unsafe environment: {command!r}"
        )


def run_caddy_activation_case(
    scenario: str,
    *,
    expected_success: bool,
    expected_events: list[str],
    expected_failed_predicate: str | None = None,
) -> None:
    with tempfile.TemporaryDirectory() as directory:
        log_path = Path(directory) / "events.log"
        environment = os.environ.copy()
        environment["ANSIBLE_CONFIG"] = str(DEPLOY_DIR / "ansible.cfg")
        environment["STRUGGLEBUS_CADDY_TEST_SCENARIO"] = scenario
        environment["STRUGGLEBUS_CADDY_TEST_LOG"] = str(log_path)
        result = subprocess.run(  # nosec B603
            [
                ANSIBLE_PLAYBOOK,
                "-i",
                "tests/inventory.yml",
                "tests/caddy_activation_order.yml",
            ],
            cwd=DEPLOY_DIR,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        if (result.returncode == 0) is not expected_success:
            raise RuntimeError(
                f"Caddy activation scenario {scenario!r} returned "
                f"{result.returncode}:\n{result.stdout}\n{result.stderr}"
            )
        events = (
            log_path.read_text(encoding="ascii").splitlines()
            if log_path.exists()
            else []
        )
        if events != expected_events:
            raise RuntimeError(
                f"Caddy activation scenario {scenario!r} recorded {events!r}"
            )
        if (
            expected_failed_predicate is not None
            and expected_failed_predicate not in result.stdout
        ):
            raise RuntimeError(
                f"Caddy activation scenario {scenario!r} did not attribute "
                f"{expected_failed_predicate!r}"
            )
        marker_path = Path(f"{log_path}.marker")
        if expected_success:
            if (
                marker_path.read_text(encoding="ascii")
                != "runtime_sha256=test\nconfig_sha256=test\n"
                or marker_path.stat().st_mode & 0o777 != 0o600
            ):
                raise RuntimeError(
                    f"Caddy activation scenario {scenario!r} marker is invalid"
                )
        elif marker_path.exists():
            raise RuntimeError(
                f"Caddy activation scenario {scenario!r} wrote a failure marker"
            )


def run_caddy_check_mode() -> None:
    environment = os.environ.copy()
    environment["ANSIBLE_CONFIG"] = str(DEPLOY_DIR / "ansible.cfg")
    result = subprocess.run(  # nosec B603
        [
            ANSIBLE_PLAYBOOK,
            "--check",
            "-i",
            "tests/inventory.yml",
            "tests/caddy_check_mode.yml",
        ],
        cwd=DEPLOY_DIR,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "Caddy check-mode scenario failed:\n"
            f"{result.stdout}\n{result.stderr}"
        )
    markers = (
        "TASK [caddy : Inspect the loaded Caddy systemd state]",
        "TASK [caddy : Derive the explicit Caddy activation plan]",
        "TASK [caddy : Record the Caddy activation requirements]",
        "TASK [caddy : Apply the validated Caddy activation plan before enablement]",
        "TASK [caddy : Report Caddy activation predicted by check mode]",
        "TASK [caddy : Enable Caddy after validated activation]",
        "TASK [caddy : Report Caddy enablement predicted by check mode]",
        "TASK [caddy : Install the proxy watchdog helper]",
        "TASK [caddy : Install the proxy watchdog units]",
    )
    positions = tuple(result.stdout.find(marker) for marker in markers)
    if -1 in positions or positions != tuple(sorted(positions)):
        raise RuntimeError(
            "the production Caddy role did not traverse the complete "
            f"state-driven check-mode sequence: {positions!r}"
        )
    recap = re.search(
        r"localhost\s+: ok=\d+\s+changed=(\d+)\s+unreachable=0\s+failed=0",
        result.stdout,
    )
    # Three managed Caddy files, the activation and enablement predictions, the
    # watchdog helper, and the watchdog unit template task - which loops over
    # two files but counts once in the recap.
    if recap is None or recap.group(1) != "7":
        raise RuntimeError(
            "Caddy check mode did not report the three files, activation, "
            "enablement, and proxy watchdog predictions; recap was "
            f"{recap.group(0) if recap else 'absent'}"
        )


def run_lan_ca_check_mode() -> None:
    environment = os.environ.copy()
    environment["ANSIBLE_CONFIG"] = str(DEPLOY_DIR / "ansible.cfg")
    result = subprocess.run(  # nosec B603
        [
            ANSIBLE_PLAYBOOK,
            "--check",
            "-i",
            "tests/inventory.yml",
            "tests/lan_ca_check_mode.yml",
        ],
        cwd=DEPLOY_DIR,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "LAN CA check-mode scenario failed:\n"
            f"{result.stdout}\n{result.stderr}"
        )
    if "A protected systemd credential would be staged during apply." not in (
        result.stdout
    ):
        raise RuntimeError("LAN CA check mode did not report inert secret staging")
    for forbidden in (
        "test-only-jwk-password",
        "wrong-test-only-password",
        "integration-issuer-test-only-passphrase",
    ):
        if forbidden in result.stdout + result.stderr:
            raise RuntimeError("LAN CA check mode disclosed a credential marker")


def run_inspector_contract_check_mode_case(
    scenario: str,
    *,
    expected_success: bool,
) -> None:
    environment = os.environ.copy()
    environment["ANSIBLE_CONFIG"] = str(DEPLOY_DIR / "ansible.cfg")
    result = subprocess.run(  # nosec B603
        [
            ANSIBLE_PLAYBOOK,
            "--check",
            "--diff",
            "-i",
            "tests/inventory.yml",
            "tests/inspector_contract_check_mode.yml",
            "--extra-vars",
            json.dumps(
                {"inspector_contract_test_scenario": scenario},
                separators=(",", ":"),
            ),
        ],
        cwd=DEPLOY_DIR,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if (result.returncode == 0) is not expected_success:
        raise RuntimeError(
            f"Inspector contract check-mode scenario {scenario!r} returned "
            f"{result.returncode}:\n{result.stdout}\n{result.stderr}"
        )


def _ansible_changed_count(output: str) -> int:
    match = re.search(
        r"localhost\s+: ok=\d+\s+changed=(\d+)\s+unreachable=0\s+failed=0",
        output,
    )
    if match is None:
        raise RuntimeError(f"Ansible output omitted a clean recap:\n{output}")
    return int(match.group(1))


def run_helper_bootstrap_case(scenario: str) -> None:
    expected_sha256 = {
        "strugglebus-maintenance.py":
            "b14ff2da4f13071fa75c511b5ca4acc35159897de230d22584a8e809f65b9834",
        "strugglebus-validate-maintenance-config.py":
            "3bda153a3b502b33452aa15d1a0ba01443592a4ee5ce0a3fd690b6b6de0fd58c",
        "strugglebus-release-lock.py":
            "9335ed5a2f5341dd2e5a96dffa529870cebb4d2d14f8503f8303c6529a5960bb",
        "strugglebus-validate-release.py":
            "5247e7b707412c76a6b0f27cbc66d13e52c8f6296ef9e5c9f4c1c1d52ab93972",
        "strugglebus-validate-backup.py":
            "aad645bf2ac983048b71cd6f973a2e3ee47e1ecdbb6b0571981050f1191a9150",
        "strugglebus-inspect-access-freeze.py":
            "6dc98305ef1326235803e79ea2b629ec5a3ac180159768d194fdf53c7e2ff9d9",
        "strugglebus_inspector_contract.py":
            "7f9cad75f66e14aee399867d0e64fcf821f127c37d6f08d7114ba39cd2de1459",
        "sqlite_backup.py.j2":
            "88f3d71550b147b3cdb26c201b5e60bd156d914a68687e75bb3d6cb85c4dd5b3",
    }
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source_root = root / "sources"
        destination_root = root / "helpers"
        source_root.mkdir(mode=0o700)
        destination_root.mkdir(mode=0o700)
        account = pwd.getpwuid(os.geteuid())
        group = grp.getgrgid(account.pw_gid)
        helper_cases = []
        definitions = (
            (
                DEPLOY_DIR / "roles/guest_base/files/strugglebus-maintenance.py",
                "strugglebus-maintenance",
                ("MaintenanceError", "Journal", "Host", "run", "main"),
                "",
                "0755",
            ),
            (
                DEPLOY_DIR / "roles/guest_base/files/strugglebus-validate-maintenance-config.py",
                "strugglebus-validate-maintenance-config",
                ("main",),
                "",
                "0755",
            ),
            (
                DEPLOY_DIR / "roles/guest_base/files/strugglebus-release-lock.py",
                "strugglebus-release-lock",
                ("LockError", "acquire", "release", "renew", "main"),
                "",
                "0755",
            ),
            (
                DEPLOY_DIR
                / "roles/guest_base/files/strugglebus-validate-release.py",
                "strugglebus-validate-release",
                ("ReleaseValidationError", "validate_release", "main"),
                "",
                "0755",
            ),
            (
                DEPLOY_DIR
                / "roles/guest_base/files/strugglebus-validate-backup.py",
                "strugglebus-validate-backup",
                ("BackupValidationError", "validate_backup", "main"),
                "",
                "0755",
            ),
            (
                DEPLOY_DIR
                / "roles/guest_base/files/strugglebus-inspect-access-freeze.py",
                "strugglebus-inspect-access-freeze",
                ("FreezeInspectionError", "inspect_access_freeze", "main"),
                DEPLOY_DIR / "files/strugglebus_inspector_contract.py",
                "0755",
            ),
            (
                DEPLOY_DIR / "files/strugglebus_inspector_contract.py",
                "strugglebus-inspector-contract",
                ("InspectorContractError", "verify_inspector_contract", "main"),
                "",
                "0755",
            ),
            (
                DEPLOY_DIR / "roles/systemd/templates/sqlite_backup.py.j2",
                "strugglebus-sqlite-backup",
                ("main",),
                "",
                "0755",
            ),
        )
        for (
            reviewed_source,
            destination_name,
            callables,
            contract,
            mode,
        ) in definitions:
            source = reviewed_source.resolve()
            source_name = source.name
            if scenario in {"malformed", "wrong-checksum"} and not helper_cases:
                fixture_source = source_root / source_name
                if scenario == "malformed":
                    fixture_source.write_text(
                        "#!/usr/bin/python3\nBROKEN_CONTRACT = True\n",
                        encoding="ascii",
                    )
                else:
                    shutil.copy2(source, fixture_source)
                fixture_source.chmod(0o700)
                source = fixture_source
            digest = expected_sha256[source_name]
            if scenario == "malformed" and not helper_cases:
                digest = file_digest(source)
            elif scenario == "wrong-checksum" and not helper_cases:
                digest = "0" * 64
            helper_cases.append(
                {
                    "source": str(source),
                    "destination": str(destination_root / destination_name),
                    "destination_python": sys.executable,
                    "sha256": digest,
                    "owner": account.pw_name,
                    "group": group.gr_name,
                    "mode": mode,
                    "install_task": f"Install fixture {destination_name}",
                    "callables": callables,
                    "contract": str(contract),
                }
            )
        if scenario == "invalid-destination":
            peer = root / "destination-peer"
            shutil.copy2(helper_cases[0]["source"], peer)
            peer.chmod(0o755)
            os.link(peer, helper_cases[0]["destination"])
        config_path = root / "vars.json"
        config_path.write_text(
            json.dumps(
                {"strugglebus_helper_cases": helper_cases},
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="ascii",
        )
        command = (
            ANSIBLE_PLAYBOOK,
            "-i",
            "tests/inventory.yml",
            "tests/helper_bootstrap.yml",
            "--extra-vars",
            f"@{config_path}",
        )
        environment = os.environ.copy()
        environment["ANSIBLE_CONFIG"] = str(DEPLOY_DIR / "ansible.cfg")
        before = snapshot_tree(root)
        first_check = subprocess.run(  # nosec B603
            [command[0], "--check", *command[1:]],
            cwd=DEPLOY_DIR,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        if scenario != "valid":
            if first_check.returncode == 0:
                raise RuntimeError(
                    f"Unsafe helper scenario {scenario!r} unexpectedly succeeded"
                )
            if snapshot_tree(root) != before:
                raise RuntimeError(
                    f"Unsafe helper scenario {scenario!r} mutated its fixture"
                )
            return
        if first_check.returncode != 0:
            raise RuntimeError(
                "First-install helper check failed:\n"
                f"{first_check.stdout}\n{first_check.stderr}"
            )
        if _ansible_changed_count(first_check.stdout) != len(helper_cases):
            raise RuntimeError(
                "First-install helper check did not predict every helper copy"
            )
        if snapshot_tree(root) != before:
            raise RuntimeError("First-install helper check mutated its fixture")

        apply = subprocess.run(  # nosec B603
            command,
            cwd=DEPLOY_DIR,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        if (
            apply.returncode != 0
            or _ansible_changed_count(apply.stdout) != len(helper_cases)
        ):
            raise RuntimeError(
                f"Helper configure apply failed:\n{apply.stdout}\n{apply.stderr}"
            )
        for helper_case in helper_cases:
            destination = Path(helper_case["destination"])
            if (
                file_digest(destination) != helper_case["sha256"]
                or destination.stat().st_mode & 0o777
                != int(str(helper_case["mode"]), 8)
            ):
                raise RuntimeError("Applied helper does not match reviewed source")

        zero_drift = subprocess.run(  # nosec B603
            [command[0], "--check", *command[1:]],
            cwd=DEPLOY_DIR,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        if (
            zero_drift.returncode != 0
            or _ansible_changed_count(zero_drift.stdout) != 0
        ):
            raise RuntimeError(
                "Post-apply helper check was not zero-drift:\n"
                f"{zero_drift.stdout}\n{zero_drift.stderr}"
            )


def run_release_case(
    scenario: str,
    *,
    expected_mutation: bool,
) -> None:
    with tempfile.TemporaryDirectory() as directory:
        log_path = Path(directory) / "mutations.log"
        environment = os.environ.copy()
        environment["ANSIBLE_CONFIG"] = str(DEPLOY_DIR / "ansible.cfg")
        environment["STRUGGLEBUS_RELEASE_TEST_SCENARIO"] = scenario
        environment["STRUGGLEBUS_RELEASE_TEST_LOG"] = str(log_path)
        subprocess.run(  # nosec B603
            [
                ANSIBLE_PLAYBOOK,
                "-i",
                "tests/inventory.yml",
                "tests/release_immutability.yml",
            ],
            cwd=DEPLOY_DIR,
            env=environment,
            check=True,
        )
        mutated = log_path.exists()
        if mutated is not expected_mutation:
            raise RuntimeError(
                f"Release scenario {scenario!r} mutation state was {mutated!r}"
            )


def run_service_user_execution_case(scenario: str) -> None:
    account = (
        pwd.getpwnam("nobody")
        if scenario == "real"
        else pwd.getpwuid(os.geteuid())
    )
    environment = os.environ.copy()
    environment["ANSIBLE_CONFIG"] = str(DEPLOY_DIR / "ansible.cfg")
    environment["STRUGGLEBUS_SERVICE_EXECUTION_SCENARIO"] = scenario
    environment["STRUGGLEBUS_SERVICE_EXECUTION_USER"] = account.pw_name
    environment["STRUGGLEBUS_SERVICE_EXECUTION_GROUP"] = grp.getgrgid(
        account.pw_gid
    ).gr_name
    environment["STRUGGLEBUS_SERVICE_EXECUTION_UID"] = str(account.pw_uid)
    environment["STRUGGLEBUS_SERVICE_EXECUTION_GID"] = str(account.pw_gid)
    result = subprocess.run(  # nosec B603
        [
            ANSIBLE_PLAYBOOK,
            "-i",
            "tests/inventory.yml",
            "tests/service_user_execution.yml",
        ],
        cwd=DEPLOY_DIR,
        env=environment,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Service-user execution scenario {scenario!r} returned "
            f"{result.returncode}"
        )


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_tree(root: Path) -> tuple[tuple[str, str, int, str], ...]:
    entries: list[tuple[str, str, int, str]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        mode = metadata.st_mode & 0o7777
        if path.is_symlink():
            entries.append((relative, "link", mode, os.readlink(path)))
        elif path.is_file():
            entries.append((relative, "file", mode, file_digest(path)))
        elif path.is_dir():
            entries.append((relative, "directory", mode, ""))
        else:
            entries.append((relative, "other", mode, ""))
    return tuple(entries)


def check_mode_python_interpreter(root: Path) -> Path:
    interpreter = Path(sys.executable).absolute()
    # The validator probes only the current fixed controller interpreter.
    isolated_probe = subprocess.run(  # nosec B603
        [str(interpreter), "-I", "-c", "import packaging"],
        check=False,
        capture_output=True,
    )
    if isolated_probe.returncode != 0:
        raise RuntimeError("release check-mode controller requires packaging in isolated mode")
    if not interpreter.is_symlink():
        return interpreter

    wrapper = root / "python3.13-test-wrapper"
    wrapper.write_text(
        "#!/usr/bin/python3\n"
        "import os\n"
        "import sys\n"
        "arguments = sys.argv[1:]\n"
        "if not arguments or arguments[0] != '-I':\n"
        "    raise SystemExit('expected isolated-mode argv')\n"
        f"interpreter = {ascii(str(interpreter))}\n"
        "os.execv(interpreter, [interpreter, *arguments])\n",
        encoding="ascii",
    )
    wrapper.chmod(0o750)
    return wrapper


def create_check_mode_release(
    release_root: Path,
    name: str,
    *,
    wheel_content: bytes,
    requirements_content: bytes,
    freeze_capable: bool = False,
) -> Path:
    release = release_root / name
    (release / "venv/bin").mkdir(parents=True)
    for directory in (release_root, release, release / "venv", release / "venv/bin"):
        directory.chmod(0o750)
    wheel_name = "strugglebus-0.2.0-py3-none-any.whl"
    wheel = release / wheel_name
    requirements = release / "requirements.lock"
    release_environment = release / "release.env"
    wheel.write_bytes(wheel_content)
    requirements.write_bytes(requirements_content)
    release_environment.write_text(
        f"STRUGGLEBUS_RELEASE_ID={name}\n",
        encoding="ascii",
    )
    wheel.chmod(0o640)
    requirements.chmod(0o640)
    release_environment.chmod(0o640)
    (release / "venv/bin/python").symlink_to(Path(sys.executable))
    (release / "venv/pyvenv.cfg").write_text(
        f"home = {Path(sys.executable).parent}\n"
        "include-system-site-packages = false\n"
        f"version = {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}\n",
        encoding="ascii",
    )
    package = (
        release
        / "venv/lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages/strugglebus"
    )
    package.mkdir(parents=True)
    package_init = package / "__init__.py"
    package_app = package / "app.py"
    package_init.write_text("", encoding="ascii")
    package_app.write_text(
        "ACCESS_FREEZE_CAPABILITY = 'global-v1'\n",
        encoding="ascii",
    )
    py_compile.compile(package_init, doraise=True)
    py_compile.compile(package_app, doraise=True)
    service_entry_point = release / "venv/bin/strugglebus"
    service_entry_point.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    service_entry_point.chmod(0o750)
    marker = release / ".installed"
    marker.write_text(
        f"wheel_filename={wheel_name}\n"
        f"wheel_sha256={hashlib.sha256(wheel_content).hexdigest()}\n"
        "requirements_lock_sha256="
        f"{hashlib.sha256(requirements_content).hexdigest()}\n"
        + ("agent_access_freeze=global-v1\n" if freeze_capable else ""),
        encoding="ascii",
    )
    marker.chmod(0o640)
    return release


def create_check_mode_database(path: Path, *, frozen: bool) -> None:
    with sqlite3.connect(path) as database:
        database.execute("PRAGMA user_version = 8")
        database.execute(
            """
            CREATE TABLE agent_access_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                frozen INTEGER NOT NULL CHECK (frozen IN (0, 1)),
                transition TEXT NOT NULL,
                changed_at TEXT,
                reason TEXT
            )
            """
        )
        database.execute(
            """
            INSERT INTO agent_access_state
                (singleton, frozen, transition, changed_at, reason)
            VALUES (1, ?, ?, '2026-01-02T03:04:05Z', ?)
            """,
            (
                int(frozen),
                "freeze" if frozen else "unfreeze",
                "offline frozen fixture" if frozen else "offline open fixture",
            ),
        )


class CheckModeHealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def run_release_check_mode_case(
    scenario: str,
    *,
    action: str,
    expected_success: bool,
) -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        release_root = root / "releases"
        backup_root = root / "backups"
        data_root = root / "data"
        artifacts = root / "artifacts"
        helpers = root / "helpers"
        staging = root / "staging"
        for path, mode in (
            (release_root, 0o750),
            (backup_root, 0o700),
            (data_root, 0o750),
            (data_root / ".access-freeze-lock", 0o700),
            (artifacts, 0o750),
            (helpers, 0o750),
            (staging, 0o700),
        ):
            path.mkdir()
            path.chmod(mode)

        wheel_name = "strugglebus-0.2.0-py3-none-any.whl"
        wheel_content = b"offline check-mode wheel"
        wheel = artifacts / wheel_name
        wheel.write_bytes(wheel_content)
        wheel.chmod(0o640)
        requirements = artifacts / "requirements.lock"
        requirements_content = (DEPLOY_DIR.parent / "requirements.lock").read_bytes()
        requirements.write_bytes(requirements_content)
        requirements.chmod(0o640)

        release_validator = helpers / "strugglebus-validate-release"
        access_freeze_inspector = helpers / "strugglebus-inspect-access-freeze"
        backup_validator = helpers / "strugglebus-validate-backup"
        backup_helper = helpers / "strugglebus-sqlite-backup"
        lock_helper = helpers / "strugglebus-release-lock"
        shutil.copy2(
            DEPLOY_DIR
            / "roles/guest_base/files/strugglebus-validate-release.py",
            release_validator,
        )
        shutil.copy2(
            DEPLOY_DIR
            / "roles/guest_base/files/strugglebus-inspect-access-freeze.py",
            access_freeze_inspector,
        )
        shutil.copy2(
            DEPLOY_DIR
            / "roles/guest_base/files/strugglebus-validate-backup.py",
            backup_validator,
        )
        backup_helper.write_text(
            "#!/usr/bin/python3.13\nraise SystemExit(0)\n",
            encoding="ascii",
        )
        shutil.copy2(
            DEPLOY_DIR / "roles/guest_base/files/strugglebus-release-lock.py",
            lock_helper,
        )
        release_validator.chmod(0o750)
        access_freeze_inspector.chmod(0o750)
        backup_validator.chmod(0o750)
        backup_helper.chmod(0o750)
        lock_helper.chmod(0o750)

        current_link = root / "current"
        frozen_scenario = scenario.startswith("frozen-")
        if action == "initial_install":
            if scenario in {"idempotent", "partial", "wrong-current"}:
                candidate = create_check_mode_release(
                    release_root,
                    "candidate",
                    wheel_content=wheel_content,
                    requirements_content=requirements_content,
                    freeze_capable=True,
                )
                if scenario == "partial":
                    (candidate / ".installed").unlink()
                if scenario == "idempotent":
                    current_link.symlink_to(candidate, target_is_directory=True)
                elif scenario == "wrong-current":
                    current_link.symlink_to(
                        create_check_mode_release(
                            release_root,
                            "other",
                            wheel_content=wheel_content,
                            requirements_content=requirements_content,
                            freeze_capable=True,
                        ),
                        target_is_directory=True,
                    )
            elif scenario == "dirty-database":
                create_check_mode_database(data_root / "strugglebus.db", frozen=False)
        elif action == "maintenance":
            active = create_check_mode_release(
                release_root,
                "active",
                wheel_content=wheel_content,
                requirements_content=requirements_content,
                freeze_capable=(
                    not frozen_scenario or scenario != "frozen-legacy-recovery"
                ),
            )
            current_link.symlink_to(active, target_is_directory=True)
            if scenario != "fresh":
                candidate = create_check_mode_release(
                    release_root,
                    "candidate",
                    wheel_content=wheel_content,
                    requirements_content=requirements_content,
                    freeze_capable=True,
                )
                if scenario == "partial":
                    (candidate / ".installed").unlink()
                elif scenario == "tampered":
                    with (candidate / ".installed").open("ab") as stream:
                        stream.write(b"tampered")
                if action == "maintenance" and scenario == "idempotent":
                    current_link.unlink()
                    current_link.symlink_to(candidate, target_is_directory=True)

        if frozen_scenario:
            create_check_mode_database(data_root / "strugglebus.db", frozen=True)
        backup = backup_root / "strugglebus-check-mode.db"
        if frozen_scenario:
            create_check_mode_database(
                backup,
                frozen=scenario != "frozen-unfrozen-backup",
            )
        else:
            with sqlite3.connect(backup) as database:
                database.execute("CREATE TABLE check_mode (value INTEGER NOT NULL)")
        backup.chmod(0o600)

        account = pwd.getpwuid(os.geteuid())
        default_ca_path = ssl.get_default_verify_paths().cafile
        if default_ca_path is None:
            raise RuntimeError("release check-mode tests require a default CA bundle")
        health_server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            CheckModeHealthHandler,
        )
        health_thread = threading.Thread(
            target=health_server.serve_forever,
            daemon=True,
        )
        health_thread.start()
        config: dict[str, object] = {
            "strugglebus_release_action": action,
            "strugglebus_maintenance_approval": "deploy-candidate",
            "strugglebus_service_user": account.pw_name,
            "strugglebus_service_group": grp.getgrgid(account.pw_gid).gr_name,
            "strugglebus_release_root": str(release_root),
            "strugglebus_current_link": str(current_link),
            "strugglebus_backup_dir": str(backup_root),
            "strugglebus_data_dir": str(data_root),
            "strugglebus_database_path": str(data_root / "strugglebus.db"),
            "strugglebus_release_validator_helper": str(release_validator),
            "strugglebus_access_freeze_inspector_helper": str(
                access_freeze_inspector
            ),
            "strugglebus_backup_validator_helper": str(backup_validator),
            "strugglebus_backup_helper": str(backup_helper),
            "strugglebus_release_lock_helper": str(lock_helper),
            "strugglebus_release_helper_owner": account.pw_name,
            "strugglebus_release_test_python_interpreter": str(
                check_mode_python_interpreter(root)
            ),
            "strugglebus_release_staging_dir": str(staging),
            "strugglebus_release_lock_wait_seconds": 1,
            "strugglebus_release_lock_lease_seconds": 7200,
            "strugglebus_app_target": "strugglebus.app:app",
            "strugglebus_health_url": (
                f"http://127.0.0.1:{health_server.server_port}/healthz"
            ),
            "strugglebus_caddy_ca_path": default_ca_path,
        }
        config.update(
            {
                "strugglebus_release_version": "candidate",
                "strugglebus_wheel_src": str(wheel),
                "strugglebus_wheel_sha256": hashlib.sha256(
                    wheel_content
                ).hexdigest(),
                "strugglebus_requirements_lock_src": str(requirements),
                "strugglebus_requirements_lock_sha256": hashlib.sha256(
                    requirements_content
                ).hexdigest(),
                "strugglebus_assert_external_vzdump": False,
                "strugglebus_owner_accepts_missing_weekly_vzdump_risk": True,
                "strugglebus_external_vzdump_retention": 4,
            }
        )
        config_path = root / "vars.json"
        config_path.write_text(
            json.dumps(config, sort_keys=True, separators=(",", ":")),
            encoding="ascii",
        )

        before = snapshot_tree(root)
        environment = os.environ.copy()
        environment["ANSIBLE_CONFIG"] = str(DEPLOY_DIR / "ansible.cfg")
        try:
            result = subprocess.run(  # nosec B603
                [
                    ANSIBLE_PLAYBOOK,
                    "--check",
                    "-i",
                    "tests/inventory.yml",
                    "tests/release_check_mode.yml",
                    "--extra-vars",
                    f"@{config_path}",
                ],
                cwd=DEPLOY_DIR,
                env=environment,
                check=False,
            )
        finally:
            health_server.shutdown()
            health_server.server_close()
            health_thread.join(timeout=5)
        if (result.returncode == 0) is not expected_success:
            raise RuntimeError(
                f"Release check-mode scenario {scenario!r} returned "
                f"{result.returncode}"
            )
        after = snapshot_tree(root)
        if after != before:
            raise RuntimeError(
                f"Release check-mode scenario {scenario!r} mutated its fixture"
            )


def backup_gate_command(values: dict[str, object]) -> tuple[str, ...]:
    return (
        ANSIBLE_PLAYBOOK,
        "-i",
        "tests/inventory.yml",
        "tests/release_backup_gate.yml",
        "--extra-vars",
        json.dumps(values, separators=(",", ":")),
    )


def main() -> int:
    run(sys.executable, "tests/contract.py")
    run(sys.executable, "tests/lan_ca_contract.py")
    run(sys.executable, "tests/script_execution.py")
    run(sys.executable, "tests/openssh_public_key_unit.py")
    run(sys.executable, "tests/smoke_unit.py")
    run(sys.executable, "tests/release_https_readiness_unit.py")
    with tempfile.TemporaryDirectory(prefix="maintenance-rehearsal-") as directory:
        run(sys.executable, "tests/maintenance_rehearsal.py", "--work-dir", directory)
    run(sys.executable, "tests/export_ca_unit.py")
    run(sys.executable, "tests/updater_bootstrap_unit.py")
    run(sys.executable, "tests/systemd_development_check_mode.py")
    run(
        "ansible-galaxy",
        "collection",
        "install",
        "--force",
        "-p",
        ".ansible/collections",
        "-r",
        "requirements.yml",
    )
    for playbook in PLAYBOOKS:
        run("ansible-playbook", "--syntax-check", playbook)
    run("ansible-playbook", "-i", "tests/inventory.yml", "tests/render.yml")
    run(
        "ansible-playbook",
        "-i",
        "tests/inventory.yml",
        "tests/deployment_profile.yml",
    )
    run(
        "ansible-playbook",
        "--check",
        "-i",
        "tests/inventory.yml",
        "tests/deployment_profile_consumers.yml",
    )
    run(
        "ansible-playbook",
        "--check",
        "-i",
        "tests/inventory.yml",
        "tests/systemd_development_check_mode.yml",
    )
    run(
        "ansible-playbook",
        "-i",
        "tests/inventory.yml",
        "tests/caddy_activation_plan.yml",
    )
    run_helper_bootstrap_case("valid")
    run_helper_bootstrap_case("malformed")
    run_helper_bootstrap_case("wrong-checksum")
    run_helper_bootstrap_case("invalid-destination")
    run_caddy_check_mode()
    run_lan_ca_check_mode()
    run(
        "ansible-playbook",
        "--check",
        "-i",
        "tests/inventory.yml",
        "tests/lan_ca_activation_evidence.yml",
    )
    for scenario, expected_success in (
        ("valid", True),
        ("skipped", False),
        ("empty", False),
        ("malformed", False),
        ("nonzero", False),
    ):
        run_inspector_contract_check_mode_case(
            scenario,
            expected_success=expected_success,
        )
    caddy_runtime_predicates = (
        "runtime_dir_exists",
        "runtime_dir_type",
        "runtime_dir_owner",
        "runtime_dir_group",
        "runtime_dir_mode",
        "runtime_dir_not_symlink",
        "admin_socket_exists",
        "admin_socket_type",
        "admin_socket_owner",
        "admin_socket_group",
        "admin_socket_mode",
        "admin_socket_not_symlink",
        "systemctl_active",
        "listener_probe_succeeded",
        "https_listener_present",
        "http_listener_absent",
    )
    caddy_activation_cases = [
        (
            "success",
            True,
            ["validate", "restart", "verify", "enable", "verify-unchanged"],
            None,
        ),
        ("validation-failure", False, ["validate", "stop"], None),
        ("restart-failure", False, ["validate", "restart", "stop"], None),
    ]
    caddy_activation_cases.extend(
        (
            f"mismatch-{predicate}",
            False,
            ["validate", "restart", "verify", "stop"],
            predicate,
        )
        for predicate in caddy_runtime_predicates
    )
    for scenario, success, events, predicate in caddy_activation_cases:
        run_caddy_activation_case(
            scenario,
            expected_success=success,
            expected_events=events,
            expected_failed_predicate=predicate,
        )
    run_service_user_execution_case("success")
    run_service_user_execution_case("failure")
    if os.geteuid() == 0:
        run_service_user_execution_case("real")
    run(
        *backup_gate_command(
            {
                "strugglebus_assert_external_vzdump": True,
                "strugglebus_owner_accepts_missing_weekly_vzdump_risk": False,
            }
        )
    )
    run_expected_failure(
        *backup_gate_command(
            {
                "strugglebus_assert_external_vzdump": True,
                "strugglebus_owner_accepts_missing_weekly_vzdump_risk": False,
                "strugglebus_wheel_src": "application.whl",
            }
        ),
        environment_overrides={},
    )
    run(
        *backup_gate_command(
            {
                "strugglebus_assert_external_vzdump": False,
                "strugglebus_owner_accepts_missing_weekly_vzdump_risk": True,
            }
        )
    )
    for rejected in (
        {},
        {
            "strugglebus_assert_external_vzdump": False,
            "strugglebus_owner_accepts_missing_weekly_vzdump_risk": False,
        },
        {
            "strugglebus_assert_external_vzdump": True,
            "strugglebus_owner_accepts_missing_weekly_vzdump_risk": True,
        },
    ):
        run_expected_failure(
            *backup_gate_command(rejected),
            environment_overrides={},
        )
    for invalid_value in ("true", "yes", "1", "false", "no", "0", 1, 0, None, []):
        for invalid_flag, other_flag in (
            (
                "strugglebus_assert_external_vzdump",
                "strugglebus_owner_accepts_missing_weekly_vzdump_risk",
            ),
            (
                "strugglebus_owner_accepts_missing_weekly_vzdump_risk",
                "strugglebus_assert_external_vzdump",
            ),
        ):
            run_expected_failure(
                *backup_gate_command(
                    {
                        invalid_flag: invalid_value,
                        other_flag: False,
                    }
                ),
                environment_overrides={},
            )
    for scenario, expected_mutation in (
        ("fresh", True),
        ("matching-installed", True),
        ("different-wheel", False),
        ("legacy-wheel", False),
        ("ambiguous-wheels", False),
        ("partial-empty", False),
        ("matching-unmarked", False),
        ("symlink-wheel", False),
        ("marker-mismatch", False),
        ("marker-hash-mismatch", False),
    ):
        run_release_case(scenario, expected_mutation=expected_mutation)
    for scenario, action, expected_success in (
        ("fresh", "initial_install", True),
        ("idempotent", "initial_install", True),
        ("partial", "initial_install", False),
        ("wrong-current", "initial_install", False),
        ("dirty-database", "initial_install", False),
        ("fresh", "maintenance", True),
        ("idempotent", "maintenance", True),
        ("partial", "maintenance", False),
        ("tampered", "maintenance", False),
    ):
        run_release_check_mode_case(
            scenario,
            action=action,
            expected_success=expected_success,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
