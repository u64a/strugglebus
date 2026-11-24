#!/usr/bin/env python3
"""Non-root recovery rehearsal using the real maintenance state machine.

Only systemd/process/TLS observations, release validation and the production
backup invocation are adapted. The small SQLite schema and its facts are
explicitly simulated; journal/config publication, selection, recovery and
snapshot retirement execute the installed helper's implementation.
Separate pytest cases exercise real loopback TLS and Linux process observations;
this standalone driver is not a systemd/Caddy production deployment rehearsal.
"""

from __future__ import annotations

import argparse
from contextlib import closing, nullcontext
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess  # nosec B404
import sys
import time
import uuid


ROOT = Path(__file__).resolve().parents[2]
HELPER_PATH = ROOT / "deploy" / "roles" / "guest_base" / "files" / "strugglebus-maintenance.py"
SPEC = importlib.util.spec_from_file_location("maintenance_under_test", HELPER_PATH)
if SPEC is None or SPEC.loader is None:
    raise ImportError("maintenance rehearsal helper is unavailable")
maintenance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(maintenance)

CRASH_EXIT = 73
MESSAGE_LIMITS = {"0.2.0": 1048576, "0.3.0": 524288, "0.4.0": 262144}
BASELINE_CHECKPOINTS = (
    "prepared", "stop-intent", "stopped", "snapshot-intent",
    "snapshot-published", "snapshot-ready", "activation-intent",
    "selection-replaced", "selected", "start-intent", "start-returned",
    "started", "ready", "timer-intent", "complete",
)
HANDOFF_CHECKPOINTS = (
    "prepared", "snapshot-intent", "snapshot-published", "snapshot-ready",
    "retire-intent", "previous-pin-removed", "activation-intent",
)


def require(condition: object, message: str) -> None:
    """Keep rehearsal invariants active even under python -O."""
    if not condition:
        raise AssertionError(message)


def read_json(path: Path) -> dict:
    return json.loads(path.read_bytes())


def write_json(path: Path, value: dict) -> None:
    maintenance.publish(path, json.dumps(value, sort_keys=True).encode("ascii"))


class RehearsalHost(maintenance.Host):
    """A persisted fake OS, never a replacement recovery algorithm."""

    def __init__(self, request: dict, checkpoint: str | None = None):
        super().__init__(request)
        self.os_state = self.state / "simulated-systemd.json"
        self.crash_checkpoint = checkpoint

    def checkpoint(self, phase: str) -> None:
        state = read_json(self.os_state)
        state["checkpoints"].append(phase)
        write_json(self.os_state, state)
        pause = state.get("pause")
        if pause is not None and phase == pause["phase"]:
            maintenance.publish(Path(pause["ready"]), b"checkpoint reached")
            deadline = time.monotonic() + 20
            while not Path(pause["release"]).exists():
                if time.monotonic() >= deadline:
                    raise maintenance.MaintenanceError("rehearsal checkpoint pause expired")
                time.sleep(0.02)
        if phase == self.crash_checkpoint:
            os._exit(CRASH_EXIT)

    def command(self, argv: list[str], *, timeout: int = 30,
                allowed: tuple[int, ...] = (0,)) -> str:
        state = read_json(self.os_state)
        state["commands"].append(argv)
        output, status = "", 0
        failure = state["failure"]
        if argv[0] == "ss":
            output = "LISTEN 0 128 127.0.0.1:8765" if failure == "occupied-port" else ""
        elif argv[0] != "systemctl":
            raise AssertionError(f"unexpected production command: {argv!r}")
        elif argv[1] == "stop":
            if failure == "stop":
                status = 1
            elif argv[2] == "strugglebus.service":
                state["active"] = False
            elif argv[2] == "strugglebus-backup.timer":
                state["timer_active"] = False
            elif argv[2] == "strugglebus-backup.service":
                state["backup_active"] = False
            else:
                raise AssertionError(argv)
        elif argv[1] == "is-active":
            key = {
                "strugglebus.service": "active",
                "strugglebus-backup.timer": "timer_active",
                "strugglebus-backup.service": "backup_active",
            }[argv[2]]
            output, status = ("active", 0) if state[key] else ("inactive", 3)
        elif argv[1] == "is-enabled":
            output, status = ("enabled", 0) if state["timer_enabled"] else ("disabled", 1)
        elif argv[1] == "show":
            if "--property=DropInPaths" in argv:
                output = ""
            elif "--property=FragmentPath" in argv:
                output = str(self.unit)
            else:
                raise AssertionError(argv)
        elif argv[1] == "daemon-reload":
            pass
        elif argv[1] == "enable":
            if "--now" in argv:
                if failure == "timer":
                    status = 1
                else:
                    state["timer_active"] = state["timer_enabled"] = True
        elif argv[1] == "start":
            require(argv[2] == "strugglebus.service", "unexpected service start")
            if not state["active"]:
                state["starts"].append(self.selected())
                state["running_release"] = self.selected()
                state["generation"] += 1
                with closing(sqlite3.connect(self.database)) as connection, connection:
                    connection.execute(f"PRAGMA user_version={self.expected_schema}")
                    connection.execute(
                        "INSERT INTO messages(body) VALUES (?)",
                        (f"written-by-{self.selected()}",),
                    )
            state["active"] = True
            if failure == "start":
                status = 1
        else:
            raise AssertionError(argv)
        write_json(self.os_state, state)
        if status not in allowed:
            raise maintenance.MaintenanceError("maintenance command failed")
        return output

    def release(self, name: str) -> dict:
        if not maintenance.RELEASE.fullmatch(name):
            raise maintenance.MaintenanceError("invalid release identity")
        return {"release": name, "marker": read_json(self.root / name / "marker.json")}

    def database_facts(self, path: Path) -> dict:
        # This intentionally models only schema/freeze/credential facts; schema
        # recognition and the real backup primitive have separate contract tests.
        with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)) as connection:
            if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise maintenance.MaintenanceError("simulated database integrity failed")
            schema = connection.execute("PRAGMA user_version").fetchone()[0]
            frozen, credentials = connection.execute(
                "SELECT frozen, credentials FROM simulated_safety"
            ).fetchone()
        if schema not in (10, 11, 12, 13) or schema > self.expected_schema:
            raise maintenance.MaintenanceError("simulated database schema unsupported")
        return {
            "schema": schema, "frozen": bool(frozen),
            "credential_state_sha256": maintenance.digest(credentials.encode()),
        }

    def snapshot(self, operation_id: str, *, create: bool) -> dict:
        path = self.snapshot_path(operation_id)
        if create and not os.path.lexists(path):
            # Real SQLite backup and durable, immutable pin files, not a dictionary
            # pretending that a snapshot exists. Production backup is tested apart.
            with closing(sqlite3.connect(f"{self.database.as_uri()}?mode=ro", uri=True)) as source:
                with closing(sqlite3.connect(path)) as destination, destination:
                    source.backup(destination)
            path.chmod(0o600)
            with path.open("r+b") as stream:
                os.fsync(stream.fileno())
            maintenance.sync_directory(path.parent)
            self.checkpoint("snapshot-published")
        return {
            "operation_id": operation_id,
            **self.snapshot_identity(operation_id),
            "database": self.database_facts(path),
        }

    def snapshot_identity(self, operation_id: str) -> dict:
        path = self.snapshot_path(operation_id)
        content = maintenance.read_regular(path, limit=8 * 1024 * 1024, private=True)
        with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)) as connection:
            if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise maintenance.MaintenanceError("simulated snapshot integrity failed")
        return {"sha256": maintenance.digest(content), "size": len(content)}

    def running(self) -> dict:
        state = read_json(self.os_state)
        if (
            not state["active"]
            or state["running_release"] != self.request["candidate"]
            or self.selected() != self.request["candidate"]
            or maintenance.digest(maintenance.read_regular(self.unit)) != self.request["config_sha256"]
            or state["failure"] == "identity"
        ):
            raise maintenance.MaintenanceError("simulated candidate identity mismatch")
        if state["failure"] == "identity-change":
            state["generation"] += 1
        state["observations"].append({"kind": "running", "generation": state["generation"]})
        write_json(self.os_state, state)
        return {"pid": 2000, "start_ticks": state["generation"], "release": state["running_release"]}

    def readiness(self) -> None:
        state = read_json(self.os_state)
        state["readiness_count"] += 1
        state["observations"].append({"kind": "readiness", "generation": state["generation"]})
        if state["failure"] == "identity-during-tls" and state["readiness_count"] % 2 == 0:
            state["generation"] += 1
        write_json(self.os_state, state)
        if state["failure"] == "readiness":
            raise maintenance.MaintenanceError("simulated TLS readiness failure")


class Scenario:
    def __init__(self, root: Path, *, selection: bool = True):
        self.root = root.resolve()
        self.root.mkdir(parents=True, mode=0o700)
        self.state = self.root / "state"
        self.backups = self.root / "backups"
        self.releases = self.root / "releases"
        self.helpers = self.root / "helpers"
        for directory in (self.state, self.backups, self.releases, self.helpers):
            directory.mkdir(mode=0o700)
        self.database = self.root / "live.db"
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.executescript(
                "PRAGMA user_version=10;"
                "CREATE TABLE simulated_safety(frozen INTEGER, credentials TEXT);"
                "INSERT INTO simulated_safety VALUES(1, 'revoked-credential-test-state');"
                "CREATE TABLE messages(id INTEGER PRIMARY KEY, body TEXT);"
                "INSERT INTO messages(body) VALUES('original-message');"
            )
        self.database.chmod(0o600)
        self.unit = self.root / "strugglebus.service"
        self.current = self.releases / "current"
        self.environment = {
            "STRUGGLEBUS_DATA_DIR": self.unit_path(self.root),
            "STRUGGLEBUS_RUNTIME_DIR": self.unit_path(self.root / "run"),
            "STRUGGLEBUS_BACKUP_DIR": self.unit_path(self.backups),
            "STRUGGLEBUS_DATABASE_PATH": self.unit_path(self.database),
            "STRUGGLEBUS_ADMIN_CREDENTIAL_PATH": "%d/admin-token",
            "STRUGGLEBUS_PUBLIC_BASE_URL": "https://bus.example.test",
            "STRUGGLEBUS_BIND_HOST": "127.0.0.1",
            "STRUGGLEBUS_BIND_PORT": "8765",
            "STRUGGLEBUS_ALLOWED_HOSTS": "bus.example.test,127.0.0.1:*,localhost:*,[::1]:*",
            "STRUGGLEBUS_ALLOWED_ORIGINS": "https://bus.example.test",
            "STRUGGLEBUS_TRUSTED_PROXY_SOURCES": "127.0.0.1",
        }
        for release in ("0.2.0", "0.3.0", "0.4.0"):
            directory = self.releases / release
            directory.mkdir()
            write_json(directory / "marker.json", {
                "agent_access_freeze": "global-v1",
                "wheel_sha256": hashlib.sha256(release.encode()).hexdigest(),
            })
            maintenance.publish(
                directory / "release.env", f"STRUGGLEBUS_RELEASE_ID={release}\n".encode(),
                mode=0o644,
            )
        maintenance.publish(self.unit, self.config("0.2.0"), mode=0o644)
        if selection:
            self.current.symlink_to(self.releases / "0.2.0", target_is_directory=True)
        # Executable fixtures are not bounded maintenance evidence records.
        helper = self.helpers / "strugglebus-maintenance"
        helper.write_bytes(HELPER_PATH.read_bytes())
        helper.chmod(0o600)
        self.os_state = self.state / "simulated-systemd.json"
        write_json(self.os_state, {
            "active": True, "backup_active": False, "timer_active": True,
            "timer_enabled": True, "running_release": "0.2.0", "generation": 1,
            "starts": [], "commands": [], "checkpoints": [], "failure": None,
            "observations": [], "readiness_count": 0,
        })
        self.request = self.prepare("0.3.0")

    def unit_path(self, path: Path) -> str:
        if os.name != "nt":
            return str(path)
        # The simulated Windows OS still renders Linux systemd grammar; these
        # inert unit paths are never opened or executed by the adapter.
        suffix = path.relative_to(self.root).as_posix()
        return "/maintenance-rehearsal" + (f"/{suffix}" if suffix != "." else "")

    def config(self, release: str) -> bytes:
        current = self.unit_path(self.current)
        lines = [
            "[Unit]", "Description=Strugglebus LAN message board",
            "After=network-online.target", "Wants=network-online.target",
            f"ConditionPathIsDirectory={current}",
            "[Service]", "Type=simple", "User=strugglebus", "Group=strugglebus",
            "LoadCredential=admin-token:/etc/strugglebus/credentials/admin-token",
            f"WorkingDirectory={current}",
            "RuntimeDirectory=strugglebus", "RuntimeDirectoryMode=0750",
            f"EnvironmentFile=-{current}/release.env",
            f"ExecStart={current}/venv/bin/strugglebus serve",
        ]
        lines.extend(f"Environment={key}={value}" for key, value in self.environment.items())
        lines.append(f"Environment=STRUGGLEBUS_MAX_MESSAGE_BYTES={MESSAGE_LIMITS[release]}")
        lines.extend((
            "Restart=always", "RestartSec=5s", "TimeoutStartSec=60s",
            "TimeoutStopSec=30s", "UMask=0027", "NoNewPrivileges=true",
            "PrivateTmp=true", "PrivateDevices=true", "ProtectSystem=strict",
            "ProtectHome=true", "ProtectKernelTunables=true", "ProtectKernelModules=true",
            "ProtectKernelLogs=true", "ProtectControlGroups=true", "ProtectClock=true",
            "ProtectHostname=true", "ProtectProc=invisible", "ProcSubset=pid",
            "RestrictSUIDSGID=true", "RestrictRealtime=true", "RestrictNamespaces=true",
            "LockPersonality=true", "MemoryDenyWriteExecute=true", "RemoveIPC=true",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "SystemCallArchitectures=native", "SystemCallFilter=@system-service",
            "SystemCallErrorNumber=EPERM",
            "ReadWritePaths=" + " ".join(
                self.environment["STRUGGLEBUS_" + key]
                for key in ("DATA_DIR", "RUNTIME_DIR", "BACKUP_DIR")
            ),
            "[Install]", "WantedBy=multi-user.target",
        ))
        return ("\n".join(lines) + "\n").encode("utf-8")

    def prepare(self, release: str) -> dict:
        content = self.config(release)
        sha = maintenance.digest(content)
        candidate_config = self.state / f"candidate-{sha}.service"
        maintenance.publish(candidate_config, content)
        request = {
            "release_root": str(self.releases), "state_dir": str(self.state),
            "backup_dir": str(self.backups), "database": str(self.database),
            "unit": str(self.unit), "current": str(self.current),
            "candidate_config": str(candidate_config), "helper_root": str(self.helpers),
            "candidate": release, "candidate_schema": 11, "config_sha256": sha,
            "marker": read_json(self.releases / release / "marker.json"),
            "environment": {
                **self.environment, "STRUGGLEBUS_MAX_MESSAGE_BYTES": str(MESSAGE_LIMITS[release]),
                "STRUGGLEBUS_ADMIN_CREDENTIAL_PATH": "/run/credentials/strugglebus.service/admin-token",
            },
            "service_user": "strugglebus",
            "app_module": "strugglebus.app", "bind_port": 8765,
            "health_url": "https://bus.example.test/healthz",
            "ca_path": str(self.root / "test-only-ca.crt"),
            "helper_sha256": {
                "strugglebus-maintenance": maintenance.digest(
                    maintenance.read_regular(
                        self.helpers / "strugglebus-maintenance", limit=1024 * 1024,
                    )
                ),
            },
        }
        write_json(self.root / f"request-{release}.json", request)
        return request

    def invoke(
        self, request: dict | None = None, *, checkpoint: str | None = None,
        status_verify: bool = False,
    ) -> subprocess.CompletedProcess:
        request = request or self.request
        path = self.root / f"request-{request['candidate']}.json"
        if not status_verify:
            write_json(path, request)
        command = [sys.executable, str(Path(__file__).resolve()), "--child", str(path)]
        if checkpoint is not None:
            command.extend(("--checkpoint", checkpoint))
        if status_verify:
            command.append("--status-verify")
        # This interpreter and this driver only; the request is a data-file argument, not code.
        return subprocess.run(  # nosec B603
            command, capture_output=True, text=True, timeout=30, check=False,
        )

    def success(self, request: dict | None = None) -> dict:
        result = self.invoke(request)
        require(result.returncode == 0, "maintenance child did not succeed")
        return json.loads(result.stdout)

    def crash(self, checkpoint: str, request: dict | None = None) -> None:
        result = self.invoke(request, checkpoint=checkpoint)
        require(result.returncode == CRASH_EXIT, "maintenance child did not reach crash checkpoint")

    def journal(self) -> dict:
        record = maintenance.Journal(self.state).read()
        require(record is not None, "maintenance journal is missing")
        return record

    def pins(self) -> list[Path]:
        return sorted(self.backups.glob("maintenance-*.db"))

    def failure(self, value: str | None) -> None:
        state = read_json(self.os_state)
        state["failure"] = value
        write_json(self.os_state, state)

    def assert_complete(self, request: dict | None = None) -> None:
        request = request or self.request
        record = self.journal()
        state = read_json(self.os_state)
        require(record["phase"] == "complete" and record["error"] is None, "journal is not complete")
        require(self.current.resolve() == self.releases / request["candidate"], "wrong release selected")
        require(self.unit.read_bytes() == self.config(request["candidate"]), "wrong configuration active")
        require(state["active"] and state["timer_active"] and state["timer_enabled"], "service or timer inactive")
        require(state["starts"] and "0.2.0" not in state["starts"], "predecessor started or candidate never started")
        require(len(self.pins()) == 1, "completed operation must retain exactly one pin")
        require(self.pins()[0].name == f"maintenance-{record['operation_id']}.db", "wrong pin retained")
        host = RehearsalHost(request)
        require(host.snapshot(record["operation_id"], create=False) == record["snapshot"], "snapshot changed")
        require(host.database_identity() == record["database_identity"], "database identity changed")
        require(host.database_facts(self.database)["schema"] == 11, "candidate schema not active")
        require(host.database_facts(self.database)["frozen"], "database freeze was lost")
        with closing(sqlite3.connect(self.database)) as connection:
            require(
                connection.execute("SELECT body FROM messages ORDER BY id LIMIT 1").fetchone() == ("original-message",),
                "original message was lost",
            )


def rehearse_baseline(root: Path | Scenario, checkpoint: str) -> None:
    scenario = root if isinstance(root, Scenario) else Scenario(root)
    scenario.crash(checkpoint)
    operation = scenario.journal()["operation_id"]
    require(len(scenario.pins()) <= 1, "baseline operation exceeded pin limit")
    scenario.success()
    require(scenario.journal()["operation_id"] == operation, "recovery changed operation identity")
    scenario.assert_complete()


def rehearse_handoff(root: Path | Scenario, checkpoint: str) -> None:
    scenario = root if isinstance(root, Scenario) else Scenario(root)
    scenario.success()
    previous = scenario.journal()
    old_pin = scenario.pins()[0]
    candidate = scenario.prepare("0.4.0")
    scenario.crash(checkpoint, candidate)
    handoff = scenario.journal()
    operation = handoff["operation_id"]
    require(operation != previous["operation_id"], "handoff reused previous operation identity")
    require(handoff["database_identity"] == previous["database_identity"], "handoff changed database identity")
    if checkpoint != "activation-intent":
        require(handoff["previous_config"] == previous["binding"]["config_sha256"], "previous config not retained")
        require(handoff["previous_operation"] == previous, "previous operation not retained")
    else:
        require(handoff["previous_config"] is None, "retired config still referenced")
        require(handoff["previous_operation"] is None, "retired operation still referenced")
    require(len(scenario.pins()) <= 2, "handoff exceeded two-pin limit")
    if checkpoint in ("prepared", "snapshot-intent"):
        require(scenario.pins() == [old_pin], "previous pin retired before new snapshot")
    elif checkpoint in ("snapshot-published", "snapshot-ready", "retire-intent"):
        require(len(scenario.pins()) == 2 and old_pin.exists(), "handoff must retain both pins")
    else:
        require(len(scenario.pins()) == 1 and not old_pin.exists(), "previous pin not retired")
    scenario.success(candidate)
    require(scenario.journal()["operation_id"] == operation, "handoff recovery changed operation identity")
    scenario.assert_complete(candidate)
    require(not old_pin.exists(), "previous pin not removed")
    require(
        not (scenario.state / f"predecessor-{previous['operation_id']}.service").exists(),
        "previous predecessor configuration not removed",
    )
    require(not Path(scenario.request["candidate_config"]).exists(), "previous candidate configuration not removed")


def rehearse_failure(root: Path | Scenario, failure: str) -> None:
    scenario = root if isinstance(root, Scenario) else Scenario(root)
    scenario.failure(failure)
    result = scenario.invoke()
    require(result.returncode == 1, "injected failure did not fail maintenance")
    record = scenario.journal()
    require(record["phase"] != "complete", "failed maintenance recorded complete")
    require(record["error"] in ("maintenance-failed", "cleanup-failed"), "failure not recorded")
    require(scenario.current.resolve() == scenario.releases / "0.3.0", "failure rolled back selection")
    require(len(scenario.pins()) == 1, "failure lost recovery pin")
    state = read_json(scenario.os_state)
    require(not state["active"] and "0.2.0" not in state["starts"], "failed candidate not stopped or predecessor started")
    with closing(sqlite3.connect(scenario.database)) as connection:
        require(connection.execute("PRAGMA user_version").fetchone() == (11,), "failure rolled back schema")
        require(
            connection.execute("SELECT count(*) FROM messages WHERE body='written-by-0.3.0'").fetchone()[0] >= 1,
            "failure rolled back candidate writes",
        )
    pin_digest = maintenance.digest(scenario.pins()[0].read_bytes())
    scenario.failure(None)
    scenario.success()
    scenario.assert_complete()
    require(maintenance.digest(scenario.pins()[0].read_bytes()) == pin_digest, "recovery replaced immutable pin")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--checkpoint")
    parser.add_argument("--fence-locks", type=Path)
    parser.add_argument("--status-verify", action="store_true")
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".maintenance-rehearsal")
    args = parser.parse_args()
    if args.child is not None:
        try:
            request = read_json(args.child)
            if args.status_verify:
                maintenance.Host = RehearsalHost
                sys.argv = [
                    str(HELPER_PATH), "status", "--verify", "--state-dir", request["state_dir"],
                ]
                return maintenance.main()
            fence = (
                maintenance.ownership_fence(read_json(args.fence_locks)["locks"])
                if args.fence_locks else nullcontext()
            )
            with fence:
                result = maintenance.run(request, RehearsalHost(request, args.checkpoint))
            print(json.dumps(result))
            return 0
        except (maintenance.MaintenanceError, OSError, ValueError, sqlite3.Error) as error:
            print(str(error), file=sys.stderr)
            return 1
    work = args.work_dir.resolve() / uuid.uuid4().hex
    work.mkdir(parents=True, mode=0o700)
    try:
        for phase in BASELINE_CHECKPOINTS:
            rehearse_baseline(work / f"baseline-{phase}", phase)
        for phase in HANDOFF_CHECKPOINTS:
            rehearse_handoff(work / f"handoff-{phase}", phase)
        for failure in ("start", "readiness", "identity", "identity-change", "timer"):
            rehearse_failure(work / f"failure-{failure}", failure)
        print("Maintenance rehearsal: 22 process-death recoveries and 5 forward-only failure recoveries passed.")
        return 0
    finally:
        shutil.rmtree(work)
        try:
            work.parent.rmdir()
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
