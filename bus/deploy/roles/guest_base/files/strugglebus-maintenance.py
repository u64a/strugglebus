#!/usr/bin/python3.13
"""Bounded, forward-only maintenance recovery on a protected guest."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import hmac
from itertools import islice
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import subprocess  # nosec B404
import sys
import time
from urllib.parse import urlsplit

VERSION = 1
MAX_BYTES = 65536
ID = re.compile(r"[0-9a-f]{32}")
SHA = re.compile(r"[0-9a-f]{64}")
RELEASE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
# Candidate schemas this reviewed helper understands. This is a fail-closed
# gate, so it lags deliberately: a new migration must be reviewed here before
# its candidate can be deployed. It is widened explicitly with each supported
# schema, never derived from the candidate's own claim, and a test asserts it
# keeps pace with the application's latest schema so it cannot lag silently.
# Schema 16 adds immutable keyed posts without changing the credential/freeze
# layouts observed here. This does not authorize restoring older history.
# Schema 19 adds a credential-less #humans author; no layout observed here changes.
# Schema 20 adds task message claims, schema 21 satellite site records and
# schema 22 SPN identity expiry;
# no layout observed here changes.
# Schema 23 adds the retention setting and lets keyed posts be deleted once
# older than the operator's period; no layout observed here changes.
# Schema 24 adds worker host enrolment codes and the site document store; no
# layout observed here changes.
# Schema 25 adds the host marks, host status and the stored event log; no
# layout observed here changes.
SUPPORTED_CANDIDATE_SCHEMAS = (10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25)
OPERATOR_CONTROL = ".operator-password.control"
OPERATOR_AUTHORIZATION = ".operator-password.authorization"
PROJECTED_CREDENTIAL_DIRECTORY = "/run/credentials/strugglebus.service"
PHASES = (
    "prepared", "stop-intent", "stopped", "snapshot-intent", "snapshot-ready",
    "retire-intent", "activation-intent", "selected", "start-intent", "started",
    "ready", "timer-intent", "complete",
)


class MaintenanceError(RuntimeError):
    """A sanitized failure that retains the operation's recovery evidence."""


def parse_json(raw: bytes) -> dict:
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise MaintenanceError("duplicate maintenance evidence field")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique_pairs)
    if not isinstance(value, dict):
        raise MaintenanceError("maintenance evidence must be an object")
    return value


def canonical_directory(path: Path, *, private: bool = False) -> None:
    metadata = path.lstat()
    if (
        not path.is_absolute() or not stat.S_ISDIR(metadata.st_mode)
        or path.resolve(strict=True) != path
        or (os.name == "posix" and (
            metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & (0o077 if private else 0o022)
        ))
    ):
        raise MaintenanceError("unsafe maintenance directory")


def read_regular(path: Path, *, limit: int = MAX_BYTES, private: bool = False) -> bytes:
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(current.st_mode)
            or metadata.st_nlink != 1 or metadata.st_size > limit
            or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
            or (os.name == "posix" and (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & (0o077 if private else 0o022)
            ))
        ):
            raise MaintenanceError("unsafe maintenance evidence file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            result = stream.read(limit + 1)
        if len(result) > limit:
            raise MaintenanceError("maintenance evidence exceeds its limit")
        return result
    finally:
        os.close(descriptor)


def sync_directory(path: Path) -> None:
    if os.name == "posix":
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def publish(
    path: Path, content: bytes, *, mode: int = 0o600,
    operation_id: str | None = None,
) -> None:
    if len(content) > MAX_BYTES:
        raise MaintenanceError("maintenance evidence exceeds its limit")
    if operation_id is None:
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}")
    else:
        if not ID.fullmatch(operation_id):
            raise MaintenanceError("invalid publication operation identity")
        temporary = path.with_name(f".{path.name}.maintenance-{operation_id}")
        if os.path.lexists(temporary):
            read_regular(temporary)
            temporary.unlink()
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            # The open() mode is filtered by the caller's umask (0077 under the
            # self-update run unit); published files need their exact mode.
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def require_same_topology(previous: bytes, candidate: bytes) -> None:
    import runpy

    helper = Path(__file__).with_name(
        "strugglebus-validate-maintenance-config" + Path(__file__).suffix
    )
    validator = runpy.run_path(str(helper))
    try:
        validator["validate_unit_scope"](previous.decode("ascii"), candidate.decode("ascii"))
    except validator["MaintenanceConfigError"]:
        raise MaintenanceError("maintenance does not change topology or credentials") from None


def credential_sources(content: bytes) -> dict[str, str]:
    import runpy

    helper = Path(__file__).with_name(
        "strugglebus-validate-maintenance-config" + Path(__file__).suffix
    )
    validator = runpy.run_path(str(helper))
    try:
        return validator["credential_sources"](content.decode("ascii"))
    except (UnicodeError, validator["MaintenanceConfigError"]):
        raise MaintenanceError("unsupported credential projection") from None


def operator_source(content: bytes) -> Path | None:
    source = credential_sources(content).get("operator-password")
    if source is None:
        return None
    path = Path(source)
    if path.name in {OPERATOR_CONTROL, OPERATOR_AUTHORIZATION}:
        raise MaintenanceError("operator source aliases protected control state")
    return path


@contextmanager
def operator_source_fence(source: Path | None):
    """Serialize source observations with the root-terminal password command."""
    if source is None:
        yield
        return
    import fcntl

    canonical_directory(source.parent, private=True)
    for ancestor in source.parent.parents:
        metadata = ancestor.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode) or ancestor.resolve(strict=True) != ancestor
            or (os.name == "posix" and (
                metadata.st_uid not in {0, os.geteuid()}
                or (metadata.st_mode & 0o022 and not (
                    metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX
                ))
            ))
        ):
            raise MaintenanceError("unsafe operator source ancestry")
    path = source.parent / OPERATOR_CONTROL
    # flock needs no write access. The self-update run unit mounts the
    # credential directory read-only, where an existing control file still
    # opens read-only; the password command always creates it first.
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        0o600,
    )
    try:
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            or opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise MaintenanceError("unsafe operator source control")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise MaintenanceError("operator credential source is in use") from None
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def validate_operator_observation(value: dict | None) -> None:
    if value is None:
        return
    required = {
        "version", "source", "sha256", "device", "inode", "size",
        "mtime_ns", "ctime_ns", "authorization",
    }
    if (
        not isinstance(value, dict) or set(value) != required
        or type(value["version"]) is not int or value["version"] != 1
        or not isinstance(value["source"], str) or not Path(value["source"]).is_absolute()
        or ".." in Path(value["source"]).parts
        or any(character in value["source"] for character in ("\x00", "\n", "\r"))
        or not isinstance(value["sha256"], str) or not SHA.fullmatch(value["sha256"])
        or any(type(value[field]) is not int or value[field] < 0 for field in (
            "device", "inode", "size", "mtime_ns", "ctime_ns",
        ))
        or value["size"] not in {110, 111}
    ):
        raise MaintenanceError("invalid operator credential provenance")
    authorization = value["authorization"]
    if authorization is None:
        return
    if (
        not isinstance(authorization, dict)
        or set(authorization) != {
            "version", "source", "verifier_sha256",
            "maintenance_operation_id", "maintenance_binding_sha256",
        }
        or type(authorization["version"]) is not int or authorization["version"] != 1
        or authorization["source"] != value["source"]
        or authorization["verifier_sha256"] != value["sha256"]
    ):
        raise MaintenanceError("invalid operator password authorization")
    operation = authorization["maintenance_operation_id"]
    binding = authorization["maintenance_binding_sha256"]
    if (
        (operation is None) != (binding is None)
        or (operation is not None and (
            not isinstance(operation, str) or not ID.fullmatch(operation)
            or not isinstance(binding, str) or not SHA.fullmatch(binding)
        ))
    ):
        raise MaintenanceError("invalid operator password maintenance authority")


def operator_observation(source: Path | None) -> dict | None:
    if source is None:
        return None
    canonical_directory(source.parent, private=True)
    before = source.lstat()
    raw = read_regular(source, limit=256, private=True)
    after = source.lstat()
    identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (
        any(getattr(before, field) != getattr(after, field) for field in identity)
        or (os.name == "posix" and stat.S_IMODE(after.st_mode) != 0o600)
        or not re.fullmatch(rb"sbop1\$600000\$[0-9a-f]{32}\$[0-9a-f]{64}\n?", raw)
    ):
        raise MaintenanceError("operator verifier is invalid or changed")
    authorization_path = source.parent / OPERATOR_AUTHORIZATION
    try:
        authorization_raw = read_regular(authorization_path, limit=4096, private=True)
    except FileNotFoundError:
        authorization = None
    else:
        if os.name == "posix" and stat.S_IMODE(authorization_path.lstat().st_mode) != 0o600:
            raise MaintenanceError("unsafe operator authorization mode")
        authorization = parse_json(authorization_raw)
    result = {
        "version": 1, "source": str(source), "sha256": digest(raw),
        "device": after.st_dev, "inode": after.st_ino, "size": after.st_size,
        "mtime_ns": after.st_mtime_ns, "ctime_ns": after.st_ctime_ns,
        "authorization": authorization,
    }
    validate_operator_observation(result)
    return result


def require_operator_binding(request: dict, content: bytes) -> None:
    source = operator_source(content)
    if "operator_credential" not in request:
        if source is not None:
            raise MaintenanceError("legacy maintenance cannot introduce an operator credential")
        return
    if operator_observation(source) != request["operator_credential"]:
        raise MaintenanceError("operator credential source changed from its maintenance binding")


def completed_operator_reset(record: dict, request: dict) -> bool:
    previous = record["binding"]
    if (
        record["phase"] != "complete"
        or "operator_credential" not in previous or "operator_credential" not in request
        or {key: value for key, value in previous.items() if key != "operator_credential"}
        != {key: value for key, value in request.items() if key != "operator_credential"}
    ):
        return False
    before, after = previous["operator_credential"], request["operator_credential"]
    if before is None or after is None or before["source"] != after["source"]:
        return False
    authorization = after["authorization"]
    return authorization is not None and (
        authorization["maintenance_operation_id"] == record["operation_id"]
        and authorization["maintenance_binding_sha256"] == digest(
            json.dumps(previous, sort_keys=True, separators=(",", ":")).encode("ascii"),
        )
    )


def process_ticks(pid: int) -> int:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    return int(raw[raw.rfind(")") + 2:].split()[19])


@contextmanager
def ownership_fence(locks: list[dict]):
    """Keep lease expiry/reacquisition outside the bounded remote operation."""
    import fcntl

    descriptors = []
    try:
        for lock in locks:
            path = Path(lock["metadata"])
            token = lock["token"]
            if not SHA.fullmatch(token):
                raise MaintenanceError("invalid maintenance lock token")
            control = path.with_name("control.lock")
            descriptor = os.open(control, os.O_RDWR | os.O_NOFOLLOW)
            descriptors.append(descriptor)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise MaintenanceError("unsafe maintenance lock control")
            deadline = time.monotonic() + 30
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise MaintenanceError("maintenance lock wait expired")
                    time.sleep(0.05)
            # Freeze lock metadata belongs to the service user; root may read it,
            # but its owner is checked against the already protected directory.
            info = path.lstat()
            parent = path.parent.lstat()
            if (
                not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != parent.st_uid or info.st_size > 4096
                or path.parent.resolve(strict=True) != path.parent
                or not stat.S_ISDIR(parent.st_mode)
                or stat.S_IMODE(parent.st_mode) != 0o700
                or metadata.st_uid != parent.st_uid
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise MaintenanceError("unsafe maintenance lock metadata")
            value = json.loads(path.read_bytes())
            if (
                value.get("version") != 1 or value.get("token") != token
                or process_ticks(value["pid"]) != value["start_ticks"]
                or time.monotonic_ns() - value["heartbeat_ns"]
                >= value["lease_seconds"] * 1_000_000_000
            ):
                raise MaintenanceError("maintenance lock ownership expired")
        yield
    finally:
        for descriptor in reversed(descriptors):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


FAILURE_FILENAME = "last-failure.json"


def record_failure(state_dir: str | None, reason: str) -> None:
    """Leave a readable, non-secret reason for a refusal.

    The Ansible task that invokes maintenance runs under no_log because its
    stdin carries release and freeze ownership tokens, which suppresses the
    curated stderr message along with them. Without this, a failure reports only
    that a phase did not complete, and the actual assertion has to be recovered
    by reading this file's source during an outage - which is exactly what
    happened to the v0.2.20 deployment.

    Only curated MaintenanceError text and a fixed generic sentence reach here,
    never process output, configuration or credential data. Best effort by
    design: a failure to record a failure must never mask the original one.

    Callers must not enable this before the ownership fence is held. A rejection
    that happens earlier has to leave the protected state directory untouched,
    or a refusal becomes a way for an unfenced caller to write into it.
    """

    if not state_dir:
        return
    try:
        directory = Path(state_dir)
        if not directory.is_dir():
            return
        payload = json.dumps(
            {
                "reason": reason[:512],
                "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        # Deliberately not publish(). That routine is for maintenance evidence
        # and configuration, and callers assert on exactly which artifacts it
        # emits; a diagnostic note is neither, and must not look like one.
        destination = directory / FAILURE_FILENAME
        temporary = destination.with_name(f".{FAILURE_FILENAME}.{secrets.token_hex(8)}")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, destination)
    except (OSError, ValueError):
        return


class Journal:
    def __init__(self, directory: Path):
        canonical_directory(directory, private=True)
        self.directory = directory
        self.path = directory / "operation.json"

    def read(self) -> dict | None:
        try:
            raw = read_regular(self.path, private=True)
        except FileNotFoundError:
            return None
        try:
            record = parse_json(raw)
        except (ValueError, UnicodeError) as error:
            raise MaintenanceError("invalid maintenance record") from error
        required = {
            "version", "revision", "operation_id", "phase", "binding", "predecessor",
            "predecessor_config", "database_before", "snapshot", "previous_pin",
            "error", "evidence", "previous_config", "database_identity", "previous_operation",
        }
        if (
            not isinstance(record, dict) or set(record) != required
            or type(record["version"]) is not int or record["version"] != VERSION
            or type(record["revision"]) is not int or record["revision"] < 1
            or not isinstance(record["operation_id"], str)
            or not ID.fullmatch(record["operation_id"])
            or record["phase"] not in PHASES
            or not isinstance(record["binding"], dict)
            or not isinstance(record["predecessor"], dict)
            or not isinstance(record["database_before"], dict)
            or not isinstance(record["database_identity"], dict)
            or set(record["database_identity"]) != {"device", "inode"}
            or any(type(value) is not int for value in record["database_identity"].values())
            or not isinstance(record["predecessor_config"], str)
            or not SHA.fullmatch(record["predecessor_config"])
            or record["error"] not in {None, "maintenance-failed", "cleanup-failed"}
            or not isinstance(record["evidence"], dict)
            or (record["previous_config"] is not None and (
                not isinstance(record["previous_config"], str)
                or not SHA.fullmatch(record["previous_config"])
            ))
        ):
            raise MaintenanceError("unsupported maintenance record")
        for field in ("snapshot", "previous_pin"):
            snapshot = record[field]
            if snapshot is not None:
                if (
                    not isinstance(snapshot, dict)
                    or set(snapshot) != {"operation_id", "sha256", "size", "database"}
                    or not isinstance(snapshot["operation_id"], str)
                    or not ID.fullmatch(snapshot["operation_id"])
                    or not isinstance(snapshot["sha256"], str)
                    or not SHA.fullmatch(snapshot["sha256"])
                    or type(snapshot["size"]) is not int or snapshot["size"] < 1
                    or not isinstance(snapshot["database"], dict)
                    or (field == "snapshot"
                        and snapshot["operation_id"] != record["operation_id"])
                ):
                    raise MaintenanceError("invalid maintenance snapshot provenance")
        previous = record["previous_operation"]
        if previous is not None and (
            not isinstance(previous, dict) or set(previous) != required
            or record["previous_pin"] is None
            or type(previous["version"]) is not int or previous["version"] != VERSION
            or previous["phase"] != "complete" or previous["previous_operation"] is not None
            or previous["previous_pin"] is not None
            or previous["snapshot"] != record["previous_pin"]
            or previous["operation_id"] != record["previous_pin"]["operation_id"]
            or previous["binding"]["config_sha256"] != record["previous_config"]
        ):
            raise MaintenanceError("previous recovery provenance is incomplete")
        if (previous is None) != (record["previous_pin"] is None):
            raise MaintenanceError("previous recovery receipt is missing")
        if PHASES.index(record["phase"]) >= PHASES.index("snapshot-ready") and record["snapshot"] is None:
            raise MaintenanceError("maintenance snapshot provenance is missing")
        return record

    def write(self, record: dict, phase: str | None = None) -> None:
        current = self.read()
        expected = record["revision"]
        if current is not None and (
            current["revision"] != expected
            or current["operation_id"] != record["operation_id"]
        ):
            raise MaintenanceError("maintenance record changed concurrently")
        if phase is not None:
            if phase not in PHASES or PHASES.index(phase) < PHASES.index(record["phase"]):
                raise MaintenanceError("invalid maintenance transition")
            record["phase"] = phase
        record["revision"] += 1
        publish(self.path, json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii"))

    def replace_completed(self, record: dict) -> None:
        current = self.read()
        if current is not None and current["phase"] != "complete":
            raise MaintenanceError("unresolved maintenance blocks a distinct upgrade")
        publish(self.path, json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii"))

    def reconcile_staging(self, record: dict | None, candidate: Path) -> None:
        retained = {"operation.json", candidate.name}
        for operation in (record, record["previous_operation"] if record else None):
            if operation is not None:
                retained.add(f"predecessor-{operation['operation_id']}.service")
                retained.add(f"candidate-{operation['binding']['config_sha256']}.service")
        with os.scandir(self.directory) as entries:
            names = [entry.name for entry in islice(entries, 129)]
        if len(names) > 128:
            raise MaintenanceError("maintenance staging exceeds its bounded recovery limit")
        for name in names:
            managed = re.fullmatch(
                r"(?:predecessor-[0-9a-f]{32}|candidate-[0-9a-f]{64})\.service"
                r"|\.(?:operation\.json|predecessor-[0-9a-f]{32}\.service"
                r"|candidate-[0-9a-f]{64}\.service)\.[0-9a-f]{16}",
                name,
            )
            if managed and name not in retained:
                path = self.directory / name
                content = read_regular(path, private=True)
                if name.startswith("candidate-") and digest(content) != name[10:-8]:
                    raise MaintenanceError("orphan candidate configuration is not content-bound")
                path.unlink()
        sync_directory(self.directory)


class Host:
    """Fixed production commands; tests substitute this boundary, not recovery."""

    def __init__(self, request: dict):
        self.request = request
        self.root = Path(request["release_root"])
        self.state = Path(request["state_dir"])
        self.backup_root = Path(request["backup_dir"])
        self.database = Path(request["database"])
        self.unit = Path(request["unit"])
        self.current = Path(request["current"])
        self.candidate_config = Path(request["candidate_config"])
        self.helper_root = Path(request["helper_root"])
        self.expected_schema = request["candidate_schema"]

    def command(self, argv: list[str], *, timeout: int = 30, allowed: tuple[int, ...] = (0,)) -> str:
        try:
            # Fixed internal commands and validated request fields; no shell or inherited PATH.
            result = subprocess.run(  # nosec B603
                argv, capture_output=True, timeout=timeout, check=False,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
            )
        except subprocess.TimeoutExpired as error:
            raise MaintenanceError("maintenance command timed out") from error
        if result.returncode not in allowed or len(result.stdout) > MAX_BYTES:
            raise MaintenanceError("maintenance command failed")
        return result.stdout.decode("utf-8").strip()

    def selected(self) -> str:
        value = self.current.resolve(strict=True)
        if value.parent != self.root or not RELEASE.fullmatch(value.name):
            raise MaintenanceError("selected release is not canonical")
        return value.name

    def release(self, name: str) -> dict:
        if not RELEASE.fullmatch(name):
            raise MaintenanceError("invalid release identity")
        output = self.command([
            "/usr/bin/python3.13", "-I", "/usr/local/libexec/strugglebus-validate-release",
            "--require-release-id", str(self.root), name,
            self.request["service_user"], self.request["app_module"],
        ])
        marker = json.loads(output)
        return {"release": name, "marker": marker}

    def database_facts(self, path: Path) -> dict:
        output = self.command([
            "/usr/bin/python3.13", "-I",
            str(self.helper_root / "strugglebus-inspect-access-freeze"), str(path),
        ])
        freeze = json.loads(output)
        if not freeze["schema_supported"]:
            raise MaintenanceError("maintenance requires a recognized freeze-capable database")
        with sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True) as connection:
            connection.execute("PRAGMA query_only=ON")
            deadline = time.monotonic() + 30
            connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            connection.execute("BEGIN")
            schema = connection.execute("PRAGMA user_version").fetchone()[0]
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            frozen = connection.execute(
                "SELECT frozen FROM agent_access_state WHERE singleton = 1"
            ).fetchone()
            if frozen is None or bool(frozen[0]) != freeze["frozen"]:
                raise MaintenanceError("database safety observation changed")
            credential_state = hashlib.sha256()
            # Preserve schema-10/11 receipt bytes exactly. Only schema 12 gains
            # additional, domain-separated containment/grant/audit observations.
            for query in (
                "SELECT id, credential_epoch, revoked_at FROM agents ORDER BY id",
                "SELECT id, agent_id, status, version, revoked_at, retired_at, expired_at "
                "FROM agent_credentials ORDER BY id",
                "SELECT singleton, frozen, transition, changed_at FROM agent_access_state",
            ):
                for row in connection.execute(query):
                    credential_state.update(json.dumps(row, separators=(",", ":")).encode("utf-8"))
                    credential_state.update(b"\n")
            if schema >= 12:
                for label, query in (
                    (
                        b"operator-agents-v1\n",
                        "SELECT id, name, blocked_at FROM agents ORDER BY id",
                    ),
                    (
                        b"operator-reconnect-v1\n",
                        "SELECT id, agent_id, secret_hash, issuance_request_id, intent_sha256, "
                        "bound_epoch, status, created_at, expires_at, actor_type, actor_id, reason, "
                        "redeemed_at, revoked_at, expired_at, redemption_request_id, "
                        "result_credential_id, version FROM agent_reconnect_grants ORDER BY id",
                    ),
                    (
                        b"operator-lifecycle-audit-v1\n",
                        "SELECT seq, id, request_id, intent_sha256, agent_id, action, "
                        "previous_state, resulting_state, previous_epoch, resulting_epoch, "
                        "actor_type, actor_id, occurred_at, reason, grant_id "
                        "FROM agent_lifecycle_audit ORDER BY seq",
                    ),
                ):
                    credential_state.update(label)
                    for row in connection.execute(query):
                        credential_state.update(
                            json.dumps(row, separators=(",", ":")).encode("utf-8")
                        )
                        credential_state.update(b"\n")
            if schema >= 13:
                # Schema 13 adds a second credential-bearing principal. A
                # monitor holds an operator-class read grant, so a device
                # revoked during the window is credential divergence and must
                # be observed here rather than only in the agent tables.
                for label, query in (
                    (
                        b"monitor-devices-v1\n",
                        "SELECT id, label, status, revoked_at, version "
                        "FROM mobile_devices ORDER BY id",
                    ),
                    (
                        b"monitor-credentials-v1\n",
                        "SELECT id, device_id, kind, secret_hash, status, "
                        "issuance_request_id, revoked_at, version "
                        "FROM mobile_device_credentials ORDER BY id",
                    ),
                ):
                    credential_state.update(label)
                    for row in connection.execute(query):
                        credential_state.update(
                            json.dumps(row, separators=(",", ":")).encode("utf-8")
                        )
                        credential_state.update(b"\n")
            if schema >= 14:
                # Schema 14 adds a device's second, write-bearing secret. A
                # grant revoked during the window is credential divergence in
                # exactly the same sense as a revoked read credential, and it
                # is the proof that authorises containment actions, so a
                # database restored behind our back must not be able to bring a
                # revoked write grant back unnoticed.
                credential_state.update(b"monitor-write-grants-v1\n")
                for row in connection.execute(
                    "SELECT id, device_id, kind, secret_hash, status, "
                    "issuance_request_id, revoked_at, version "
                    "FROM mobile_write_grants ORDER BY id"
                ):
                    credential_state.update(
                        json.dumps(row, separators=(",", ":")).encode("utf-8")
                    )
                    credential_state.update(b"\n")
            if schema >= 15:
                # Freeze decisions are containment authority. Actor attribution
                # is durable incident evidence and must be protected from a
                # rollback or database replacement during maintenance.
                credential_state.update(b"access-freeze-audit-v1\n")
                for row in connection.execute(
                    "SELECT seq, transition, changed_at, reason, actor_type, actor_id "
                    "FROM agent_access_audit ORDER BY seq"
                ):
                    credential_state.update(
                        json.dumps(row, separators=(",", ":")).encode("utf-8")
                    )
                    credential_state.update(b"\n")
        if integrity != ("ok",) or schema > self.expected_schema:
            raise MaintenanceError("database is incompatible with the candidate")
        return {
            "schema": schema, "frozen": freeze["frozen"],
            "credential_state_sha256": credential_state.hexdigest(),
        }

    def database_identity(self) -> dict:
        metadata = self.database.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or self.database.resolve(strict=True) != self.database
        ):
            raise MaintenanceError("unsafe live database identity")
        return {"device": metadata.st_dev, "inode": metadata.st_ino}

    def snapshot_path(self, operation_id: str) -> Path:
        if not ID.fullmatch(operation_id):
            raise MaintenanceError("invalid snapshot operation")
        return self.backup_root / f"maintenance-{operation_id}.db"

    def snapshot(self, operation_id: str, *, create: bool) -> dict:
        path = self.snapshot_path(operation_id)
        option = (
            "--maintenance-id"
            if create and not os.path.lexists(path)
            else "--verify-maintenance-id"
        )
        self.command([
            "/usr/sbin/runuser", "--user", self.request["service_user"], "--",
            "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LANG=C.UTF-8",
            "/usr/bin/python3.13", "-I", str(self.helper_root / "strugglebus-sqlite-backup"),
            str(self.database), str(self.backup_root), "7", option, operation_id,
        ], timeout=300)
        return {
            "operation_id": operation_id, **self.snapshot_identity(operation_id),
            "database": self.database_facts(path),
        }

    def snapshot_identity(self, operation_id: str) -> dict:
        import pwd

        path = self.snapshot_path(operation_id)
        uid = pwd.getpwnam(self.request["service_user"]).pw_uid
        directory = self.backup_root.lstat()
        if (
            not stat.S_ISDIR(directory.st_mode) or directory.st_uid != uid
            or stat.S_IMODE(directory.st_mode) != 0o700
            or self.backup_root.resolve(strict=True) != self.backup_root
        ):
            raise MaintenanceError("unsafe maintenance backup directory")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                or Path(f"/proc/self/fd/{descriptor}").resolve(strict=True) != path
            ):
                raise MaintenanceError("unsafe maintenance snapshot")
            hasher = hashlib.sha256()
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                while chunk := stream.read(1024 * 1024):
                    hasher.update(chunk)
            with sqlite3.connect(f"file:/proc/self/fd/{descriptor}?mode=ro&immutable=1", uri=True) as db:
                if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                    raise MaintenanceError("maintenance snapshot integrity failed")
        finally:
            os.close(descriptor)
        return {"sha256": hasher.hexdigest(), "size": info.st_size}

    def retire(self, snapshot: dict) -> None:
        path = self.snapshot_path(snapshot["operation_id"])
        if os.path.lexists(path):
            if self.snapshot(snapshot["operation_id"], create=False) != snapshot:
                raise MaintenanceError("previous snapshot provenance changed")
            path.unlink()
            sync_directory(path.parent)

    def stop(self) -> None:
        self.command(["systemctl", "stop", "strugglebus-backup.timer"])
        self.command(["systemctl", "stop", "strugglebus-backup.service"])
        if self.command(["systemctl", "is-active", "strugglebus-backup.service"], allowed=(3,)) != "inactive":
            raise MaintenanceError("backup oneshot did not stop")
        self.command(["systemctl", "stop", "strugglebus.service"], timeout=45)
        state = self.command(["systemctl", "is-active", "strugglebus.service"], allowed=(3,))
        if state == "failed":
            # A stop that exceeds TimeoutStopSec ends in SIGKILL and leaves the
            # unit failed rather than inactive. The processes are gone, which is
            # the quiescence this check exists to establish, but the residual
            # failed state is sticky: every later attempt reads "failed" again,
            # so the operation can never advance and no rerun can recover it.
            # Clear the latch, then prove quiescence from the unit state and the
            # listener rather than trusting the reset. Anything still running
            # keeps the original refusal.
            self.command(["systemctl", "reset-failed", "strugglebus.service"], allowed=(0, 1))
            state = self.command(["systemctl", "is-active", "strugglebus.service"], allowed=(3,))
        if state != "inactive":
            raise MaintenanceError("application did not stop")
        if self.command(["ss", "-H", "-ltn", f"sport = :{self.request['bind_port']}"]):
            raise MaintenanceError("application listener remains occupied")

    def activate(self, record: dict) -> None:
        current_hash = digest(read_regular(self.unit))
        if current_hash not in {record["predecessor_config"], self.request["config_sha256"]}:
            raise MaintenanceError("live service configuration changed")
        content = read_regular(self.candidate_config, private=True)
        if digest(content) != self.request["config_sha256"]:
            raise MaintenanceError("candidate configuration changed")
        publish(self.unit, content, mode=0o644, operation_id=record["operation_id"])
        temporary = self.root / f".maintenance-{record['operation_id']}"
        if os.path.lexists(temporary):
            if not temporary.is_symlink() or temporary.readlink() != self.root / self.request["candidate"]:
                raise MaintenanceError("unexpected maintenance selection link")
            temporary.unlink()
        temporary.symlink_to(self.root / self.request["candidate"], target_is_directory=True)
        os.replace(temporary, self.current)
        sync_directory(self.current.parent)
        self.command(["systemctl", "daemon-reload"])

    def start(self) -> None:
        require_operator_binding(self.request, read_regular(self.candidate_config, private=True))
        if (
            self.selected() != self.request["candidate"]
            or digest(read_regular(self.unit)) != self.request["config_sha256"]
        ):
            raise MaintenanceError("candidate code/configuration is not selected")
        if self.command(["systemctl", "show", "strugglebus.service", "--property=DropInPaths", "--value"]):
            raise MaintenanceError("untracked application unit overrides are not supported")
        if self.command(["systemctl", "show", "strugglebus.service", "--property=FragmentPath", "--value"]) != str(self.unit):
            raise MaintenanceError("application unit source is not the managed unit")
        self.command(["systemctl", "daemon-reload"])
        self.command(["systemctl", "enable", "strugglebus.service"])
        self.command(["systemctl", "start", "strugglebus.service"], timeout=75)

    def credential_projection(self, proc: Path, environment: dict[bytes, bytes]) -> dict:
        import pwd

        content = read_regular(self.candidate_config, private=True)
        require_operator_binding(self.request, content)
        sources = credential_sources(content)
        if environment.get(b"CREDENTIALS_DIRECTORY") != PROJECTED_CREDENTIAL_DIRECTORY.encode():
            raise MaintenanceError("running credential directory mismatch")
        user = pwd.getpwnam(self.request["service_user"])
        projection = proc / "root" / PROJECTED_CREDENTIAL_DIRECTORY.lstrip("/")
        directory = projection.lstat()
        if (
            not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid not in {0, user.pw_uid}
            or directory.st_gid not in {0, user.pw_gid}
            or directory.st_mode & 0o027
        ):
            raise MaintenanceError("unsafe running credential directory")
        for name, source in sources.items():
            field = (
                b"STRUGGLEBUS_ADMIN_CREDENTIAL_PATH" if name == "admin-token"
                else b"STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH"
            )
            expected_path = f"{PROJECTED_CREDENTIAL_DIRECTORY}/{name}".encode()
            if environment.get(field) != expected_path:
                raise MaintenanceError("running credential path mismatch")
            descriptor = os.open(
                projection / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            )
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or metadata.st_uid not in {0, user.pw_uid}
                    or metadata.st_gid not in {0, user.pw_gid}
                    or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o440, 0o600, 0o640}
                    or metadata.st_size > 4096
                ):
                    raise MaintenanceError("unsafe running credential projection")
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    raw = stream.read(4097)
                if len(raw) > 4096:
                    raise MaintenanceError("running credential exceeds observation limit")
            finally:
                os.close(descriptor)
            if name == "operator-password":
                expected = self.request["operator_credential"]["sha256"]
                if not hmac.compare_digest(digest(raw), expected):
                    raise MaintenanceError("running operator credential generation mismatch")
            else:
                source_path = Path(source)
                expected = read_regular(source_path, limit=4096, private=True)
                if (
                    stat.S_IMODE(source_path.lstat().st_mode) != 0o600
                    or not hmac.compare_digest(raw, expected)
                ):
                    raise MaintenanceError("running admin credential projection mismatch")
        if "operator-password" not in sources and b"STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH" in environment:
            raise MaintenanceError("unexpected running operator credential")
        require_operator_binding(self.request, content)
        operator = self.request["operator_credential"]
        return {
            "admin_credential_projected": True,
            "operator_credential_sha256": operator["sha256"] if operator else None,
        }

    def running(self) -> dict:
        import pwd

        if self.command(["systemctl", "is-active", "strugglebus.service"]) != "active":
            raise MaintenanceError("candidate is not active")
        raw = self.command(["systemctl", "show", "strugglebus.service", "--property=MainPID", "--value"])
        if not raw.isdecimal() or int(raw) < 2:
            raise MaintenanceError("candidate process identity is unavailable")
        pid = int(raw)
        ticks = process_ticks(pid)
        proc = Path(f"/proc/{pid}")
        if proc.stat().st_uid != pwd.getpwnam(self.request["service_user"]).pw_uid:
            raise MaintenanceError("running service identity mismatch")
        target = self.root / self.request["candidate"]
        if (proc / "cwd").resolve(strict=True) != target:
            raise MaintenanceError("running release identity mismatch")
        expected_python = (target / "venv/bin/python").resolve(strict=True)
        if (proc / "exe").resolve(strict=True) != expected_python:
            raise MaintenanceError("running interpreter identity mismatch")
        argv = (proc / "cmdline").read_bytes().split(b"\0")
        entry_point_paths = {
            str(target / "venv/bin/strugglebus").encode(),
            str(self.current / "venv/bin/strugglebus").encode(),
        }
        if not entry_point_paths.intersection(argv) or b"serve" not in argv:
            raise MaintenanceError("running entry point identity mismatch")
        with (proc / "environ").open("rb") as stream:
            environment_raw = stream.read(MAX_BYTES + 1)
        if len(environment_raw) > MAX_BYTES:
            raise MaintenanceError("running environment exceeds observation limit")
        environment = dict(
            item.split(b"=", 1) for item in environment_raw.split(b"\0") if b"=" in item
        )
        if environment.get(b"STRUGGLEBUS_RELEASE_ID") != self.request["candidate"].encode():
            raise MaintenanceError("running release environment mismatch")
        for key, value in self.request["environment"].items():
            if key in {
                "STRUGGLEBUS_ADMIN_CREDENTIAL_PATH", "STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH",
            }:
                continue
            if environment.get(key.encode()) != value.encode():
                raise MaintenanceError("running configuration mismatch")
        projection = (
            self.credential_projection(proc, environment)
            if "operator_credential" in self.request else {}
        )
        listeners = self.command([
            "ss", "-H", "-ltnp", f"sport = :{self.request['bind_port']}",
        ]).splitlines()
        address = self.request["environment"]["STRUGGLEBUS_BIND_HOST"]
        local = f"[{address}]" if ":" in address else address
        if (
            len(listeners) != 1
            or f"pid={pid}," not in listeners[0]
            or f"{local}:{self.request['bind_port']}" not in listeners[0].split()
        ):
            raise MaintenanceError("candidate does not own the configured loopback listener")
        if (
            process_ticks(pid) != ticks
            or self.selected() != self.request["candidate"]
            or digest(read_regular(self.unit)) != self.request["config_sha256"]
        ):
            raise MaintenanceError("candidate identity changed during observation")
        return {
            "pid": pid, "start_ticks": ticks, "release": self.request["candidate"], **projection,
        }

    def readiness(self) -> None:
        import ssl
        import urllib.request
        from urllib.error import HTTPError, URLError

        context = ssl.create_default_context(cafile=self.request["ca_path"])
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                raise MaintenanceError("candidate readiness redirects are forbidden")

        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context),
            NoRedirect(),
        )
        for attempt in range(20):
            try:
                with opener.open(self.request["health_url"], timeout=3) as response:
                    content = response.read(1025)
                    if (
                        response.status != 200 or response.url != self.request["health_url"]
                        or len(content) > 1024 or json.loads(content) != {"status": "ok"}
                    ):
                        raise MaintenanceError("candidate readiness response mismatch")
                return
            except (HTTPError, URLError, TimeoutError) as error:
                if attempt == 19:
                    raise MaintenanceError("TLS-verified candidate readiness failed") from error
                time.sleep(3)

    def timer(self) -> None:
        self.command(["systemctl", "enable", "--now", "strugglebus-backup.timer"])
        self.timer_ready()

    def timer_ready(self) -> None:
        for verb, expected in (("is-active", "active"), ("is-enabled", "enabled")):
            if self.command(["systemctl", verb, "strugglebus-backup.timer"]) != expected:
                raise MaintenanceError("backup timer recovery failed")

    def capacity(self) -> None:
        import shutil

        needed = self.database.stat().st_size + 64 * 1024 * 1024
        if shutil.disk_usage(self.backup_root).free < needed:
            raise MaintenanceError("insufficient maintenance snapshot capacity")

    def checkpoint(self, phase: str) -> None:
        """Observation seam for subprocess fault-injection tests."""


def validate_request(request: dict) -> None:
    required = {
        "release_root", "state_dir", "backup_dir", "database", "unit", "current",
        "candidate_config", "helper_root", "candidate", "candidate_schema",
        "config_sha256", "marker", "environment", "service_user", "app_module",
        "bind_port", "health_url", "ca_path", "helper_sha256",
    }
    if not isinstance(request, dict) or set(request) not in (
        required, required | {"operator_credential"},
    ):
        raise MaintenanceError("invalid maintenance request fields")
    if len(json.dumps(request).encode("ascii")) > MAX_BYTES // 4:
        raise MaintenanceError("maintenance bindings exceed their limit")
    for name in (
        "release_root", "state_dir", "backup_dir", "database", "unit", "current",
        "candidate_config", "helper_root", "ca_path",
    ):
        value = request[name]
        if (
            not isinstance(value, str) or not Path(value).is_absolute()
            or ".." in Path(value).parts or "\x00" in value or "\n" in value
        ):
            raise MaintenanceError("invalid maintenance path")
    if (
        not isinstance(request["candidate"], str) or not RELEASE.fullmatch(request["candidate"])
        or type(request["candidate_schema"]) is not int
        or request["candidate_schema"] not in SUPPORTED_CANDIDATE_SCHEMAS
        or type(request["bind_port"]) is not int or not 1 <= request["bind_port"] <= 65535
        or not isinstance(request["config_sha256"], str)
        or not SHA.fullmatch(request["config_sha256"])
        or not isinstance(request["marker"], dict)
        or not isinstance(request["environment"], dict)
        or not isinstance(request["helper_sha256"], dict)
        or request["service_user"] != "strugglebus"
        or request["app_module"] != "strugglebus.app"
    ):
        raise MaintenanceError("invalid maintenance identity")
    if request["candidate_schema"] >= 12 and "operator_credential" not in request:
        raise MaintenanceError("operator-capable maintenance requires explicit credential provenance")
    if "operator_credential" in request:
        validate_operator_observation(request["operator_credential"])
    configured_operator = "STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH" in request["environment"]
    if configured_operator != (request.get("operator_credential") is not None):
        raise MaintenanceError("operator credential projection and provenance differ")
    if configured_operator and (
        request["candidate_schema"] < 12
        or request["environment"]["STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH"]
        != f"{PROJECTED_CREDENTIAL_DIRECTORY}/operator-password"
    ):
        raise MaintenanceError("unsupported operator credential configuration")
    endpoint = urlsplit(request["health_url"])
    if endpoint.scheme != "https" or endpoint.path != "/healthz" or endpoint.query or endpoint.fragment or endpoint.username:
        raise MaintenanceError("maintenance requires the canonical HTTPS health endpoint")
    if Path(request["candidate_config"]).parent != Path(request["state_dir"]):
        raise MaintenanceError("candidate configuration is not confined")
    if Path(request["candidate_config"]).name != f"candidate-{request['config_sha256']}.service":
        raise MaintenanceError("candidate configuration name is not content-bound")
    if request["environment"].get("STRUGGLEBUS_BIND_HOST") not in {"127.0.0.1", "::1"}:
        raise MaintenanceError("maintenance requires a loopback application bind")
    for key, value in request["environment"].items():
        if (
            not isinstance(key, str) or not re.fullmatch(r"STRUGGLEBUS_[A-Z0-9_]+", key)
            or (key != "STRUGGLEBUS_OPERATOR_PASSWORD_WORKERS" and any(
                word in key for word in ("TOKEN", "SECRET", "PASSWORD", "AUTHORIZATION", "API_KEY")
            ))
            or not isinstance(value, str) or len(value) > 4096
            or any(character in value for character in ("\x00", "\n", "\r"))
        ):
            raise MaintenanceError("invalid maintenance environment")


def validate_helpers(request: dict) -> None:
    for name, expected in request["helper_sha256"].items():
        if (
            not isinstance(name, str) or not re.fullmatch(r"strugglebus-[a-z-]+", name)
            or not isinstance(expected, str) or not SHA.fullmatch(expected)
            or digest(read_regular(Path(request["helper_root"]) / name, limit=1024 * 1024)) != expected
        ):
            raise MaintenanceError("maintenance helper provenance mismatch")


def verify_provenance(record: dict, host: Host) -> None:
    for operation in (record, record["previous_operation"]):
        if operation is None:
            continue
        request = operation["binding"]
        validate_request(request)
        validate_helpers(request)
        if (
            host.release(request["candidate"])["marker"] != request["marker"]
            or host.release(operation["predecessor"]["release"]) != operation["predecessor"]
            or digest(read_regular(Path(request["candidate_config"]), private=True))
            != request["config_sha256"]
            or digest(read_regular(
                Path(request["state_dir"]) / f"predecessor-{operation['operation_id']}.service",
                private=True,
            )) != operation["predecessor_config"]
        ):
            raise MaintenanceError("maintenance artifact or configuration provenance changed")
        snapshot = operation["snapshot"]
        if snapshot is not None and host.snapshot_identity(snapshot["operation_id"]) != {
            "sha256": snapshot["sha256"], "size": snapshot["size"],
        }:
            raise MaintenanceError("maintenance snapshot provenance changed")


def run(request: dict, host: Host) -> dict:
    validate_request(request)
    validate_helpers(request)
    journal = Journal(Path(request["state_dir"]))
    binding = request.copy()
    record = journal.read()
    journal.reconcile_staging(record, host.candidate_config)
    candidate = host.release(request["candidate"])
    if candidate["marker"] != request["marker"] or candidate["marker"].get("agent_access_freeze") != "global-v1":
        raise MaintenanceError("candidate artifacts or freeze capability mismatch")
    config = read_regular(host.candidate_config, private=True)
    if digest(config) != request["config_sha256"]:
        raise MaintenanceError("staged candidate configuration mismatch")
    require_operator_binding(request, config)
    authorized_reset = record is not None and completed_operator_reset(record, request)
    if record is not None and record["binding"] != binding and record["phase"] != "complete":
        raise MaintenanceError("unresolved maintenance blocks changed inputs")
    selected = host.selected()
    if record is not None and record["phase"] == "complete" and (
        selected != record["binding"]["candidate"]
        or digest(read_regular(host.unit)) != record["binding"]["config_sha256"]
    ):
        raise MaintenanceError("completed deployment selection or configuration drifted")
    if record is None and selected == request["candidate"]:
        # A healthy legacy selection is observable, not fabricated provenance.
        identity = host.running()
        host.database_facts(host.database)
        host.readiness()
        host.timer_ready()
        if host.running() != identity:
            raise MaintenanceError("legacy process changed during readiness")
        return {"state": "verified-existing", "release": selected}
    if record is None or (record["binding"] != binding and not authorized_reset):
        if selected == request["candidate"]:
            raise MaintenanceError("selected candidate lacks matching configuration provenance")
        predecessor = host.release(selected)
        old_config = read_regular(host.unit)
        require_same_topology(old_config, config)
        before = host.database_facts(host.database)
        operation_id = secrets.token_hex(16)
        publish(journal.directory / f"predecessor-{operation_id}.service", old_config)
        record = {
            "version": VERSION, "revision": 1, "operation_id": operation_id,
            "phase": "prepared", "binding": binding, "predecessor": predecessor,
            "predecessor_config": digest(old_config), "database_before": before,
            "database_identity": host.database_identity(),
            "snapshot": None, "previous_pin": record["snapshot"] if record else None,
            "previous_config": record["binding"]["config_sha256"] if record else None,
            "previous_operation": record,
            "error": None, "evidence": {},
        }
        journal.replace_completed(record)
        host.checkpoint("prepared")
    if selected not in {record["predecessor"]["release"], request["candidate"]}:
        raise MaintenanceError("selected release drifted from maintenance provenance")
    if host.database_identity() != record["database_identity"]:
        raise MaintenanceError("live database identity changed")
    if host.release(record["predecessor"]["release"]) != record["predecessor"]:
        raise MaintenanceError("predecessor artifact provenance changed")
    saved = read_regular(journal.directory / f"predecessor-{record['operation_id']}.service", private=True)
    if digest(saved) != record["predecessor_config"]:
        raise MaintenanceError("predecessor configuration provenance changed")
    previous = record["previous_operation"]
    if previous is not None and PHASES.index(record["phase"]) < PHASES.index("retire-intent"):
        previous_config = read_regular(
            journal.directory / f"predecessor-{previous['operation_id']}.service",
            private=True,
        )
        if (
            host.release(previous["predecessor"]["release"]) != previous["predecessor"]
            or digest(previous_config) != previous["predecessor_config"]
            or host.snapshot(previous["operation_id"], create=False) != previous["snapshot"]
        ):
            raise MaintenanceError("previous completed recovery provenance changed")

    def advance(phase: str) -> None:
        journal.write(record, phase)
        host.checkpoint(phase)

    try:
        # A completed receipt must still reconcile actual app/timer state.
        if record["phase"] == "complete":
            if host.snapshot(record["operation_id"], create=False) != record["snapshot"]:
                raise MaintenanceError("maintenance snapshot provenance changed")
            facts = host.database_facts(host.database)
            if facts["schema"] != request["candidate_schema"]:
                raise MaintenanceError("completed deployment schema changed")
            host.start()
            host.readiness()
            identity = host.running()
            if (
                authorized_reset
                and record["evidence"].get("operator_credential_sha256")
                != request["operator_credential"]["sha256"]
                and (identity["pid"], identity["start_ticks"])
                == (record["evidence"].get("pid"), record["evidence"].get("start_ticks"))
            ):
                raise MaintenanceError("operator password reset requires proven service restart")
            host.readiness()
            host.timer()
            if host.running() != identity:
                raise MaintenanceError("candidate process changed during readiness")
            record["evidence"] = identity
            record["error"] = None
            journal.write(record)
            return {"state": "complete", "operation_id": record["operation_id"]}

        phase = PHASES.index(record["phase"])
        if phase < PHASES.index("start-intent"):
            if phase < PHASES.index("stop-intent"):
                advance("stop-intent")
            host.stop()
            if phase < PHASES.index("stopped"):
                advance("stopped")
            facts = host.database_facts(host.database)
            if PHASES.index(record["phase"]) < PHASES.index("snapshot-intent"):
                record["database_before"] = facts
                journal.write(record)
            elif facts != record["database_before"]:
                raise MaintenanceError("database safety state changed before candidate start")
            if record["snapshot"] is None:
                host.capacity()
                if PHASES.index(record["phase"]) < PHASES.index("snapshot-intent"):
                    advance("snapshot-intent")
                snapshot = host.snapshot(record["operation_id"], create=True)
                if snapshot["database"] != facts:
                    raise MaintenanceError("snapshot safety state differs from stopped database")
                record["snapshot"] = snapshot
                advance("snapshot-ready")
            if host.snapshot(record["operation_id"], create=False) != record["snapshot"]:
                raise MaintenanceError("maintenance snapshot provenance changed")
            if record["previous_pin"] is not None:
                if PHASES.index(record["phase"]) < PHASES.index("retire-intent"):
                    advance("retire-intent")
                host.retire(record["previous_pin"])
                host.checkpoint("previous-pin-removed")
                old_id = record["previous_pin"]["operation_id"]
                old_config_path = journal.directory / f"predecessor-{old_id}.service"
                if old_config_path.exists():
                    read_regular(old_config_path, private=True)
                    old_config_path.unlink()
                previous_config = record["previous_config"]
                if previous_config is not None and previous_config != request["config_sha256"]:
                    old_candidate_path = journal.directory / f"candidate-{previous_config}.service"
                    if old_candidate_path.exists():
                        if digest(read_regular(old_candidate_path, private=True)) != previous_config:
                            raise MaintenanceError("previous candidate configuration changed")
                        old_candidate_path.unlink()
                record["previous_pin"] = None
                record["previous_config"] = None
                record["previous_operation"] = None
                journal.write(record)
            if PHASES.index(record["phase"]) < PHASES.index("activation-intent"):
                advance("activation-intent")
            host.activate(record)
            host.checkpoint("selection-replaced")
            if PHASES.index(record["phase"]) < PHASES.index("selected"):
                advance("selected")
            advance("start-intent")
        else:
            if selected != request["candidate"]:
                raise MaintenanceError("possible candidate start forbids predecessor selection")
            if host.snapshot(record["operation_id"], create=False) != record["snapshot"]:
                raise MaintenanceError("maintenance snapshot provenance changed")
            host.database_facts(host.database)
        host.start()
        host.checkpoint("start-returned")
        if PHASES.index(record["phase"]) < PHASES.index("started"):
            advance("started")
        host.readiness()
        identity = host.running()
        host.readiness()
        facts = host.database_facts(host.database)
        if facts["schema"] != request["candidate_schema"]:
            raise MaintenanceError("candidate did not reach its supported schema")
        if record["database_before"]["frozen"] and not facts["frozen"]:
            raise MaintenanceError("candidate activation did not preserve the freeze")
        if PHASES.index(record["phase"]) < PHASES.index("ready"):
            advance("ready")
        if PHASES.index(record["phase"]) < PHASES.index("timer-intent"):
            advance("timer-intent")
        host.timer()
        if host.running() != identity:
            raise MaintenanceError("candidate process changed during readiness")
        record["evidence"] = identity
        record["error"] = None
        advance("complete")
        return {"state": "complete", "operation_id": record["operation_id"]}
    except (MaintenanceError, OSError, ValueError, sqlite3.Error) as error:
        record["error"] = "maintenance-failed"
        journal.write(record)
        # Do not restart a predecessor or roll back data. Retain a useful daily
        # backup schedule only after all application processes are quiescent.
        try:
            host.stop()
            host.database_facts(host.database)
            host.timer()
        except (MaintenanceError, OSError, ValueError, sqlite3.Error):
            record["error"] = "cleanup-failed"
            journal.write(record)
            raise MaintenanceError("maintenance failed; stopping or timer recovery also failed; recovery remains blocked") from error
        raise MaintenanceError("maintenance failed; application stopped, available recovery evidence retained; rerun the exact operation or use protected manual recovery") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("run", "stage", "status", "guard", "credential"))
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/strugglebus-maintenance"))
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    state_dir: str | None = None
    try:
        if args.verify and args.action != "status":
            raise MaintenanceError("provenance verification requires read-only status")
        if args.action in {"status", "guard"}:
            if not args.state_dir.exists():
                result = {"state": "absent"}
            else:
                record = Journal(args.state_dir).read()
                if args.action == "guard" and record is not None:
                    raise MaintenanceError("retained maintenance provenance requires the maintenance upgrade flow")
                result = {
                    "state": record["phase"], "operation_id": record["operation_id"],
                    "error": record["error"], "candidate": record["binding"]["candidate"],
                    "config_sha256": record["binding"]["config_sha256"],
                    "snapshot": record["snapshot"], "predecessor": record["predecessor"],
                } if record else {"state": "absent"}
                if args.verify and record is not None:
                    verify_provenance(record, Host(record["binding"]))
                    result["provenance"] = "verified"
                    result["runtime"] = "not-observed"
        else:
            if os.geteuid() != 0:
                raise MaintenanceError("production maintenance requires the protected local operator")
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise MaintenanceError("maintenance request exceeds its limit")
            value = parse_json(raw)
            if args.action == "credential":
                if set(value) != {"unit_content"} or not isinstance(value["unit_content"], str):
                    raise MaintenanceError("invalid operator credential observation request")
                source = operator_source(value["unit_content"].encode("ascii"))
                with operator_source_fence(source):
                    result = {"operator_credential": operator_observation(source)}
                print(json.dumps(result, sort_keys=True, separators=(",", ":")))
                return 0
            expected_fields = {"request", "locks"}
            if args.action == "stage":
                expected_fields.add("unit_content")
            if set(value) != expected_fields or len(value["locks"]) != 2:
                raise MaintenanceError("maintenance requires both release and freeze ownership")
            request = value["request"]
            validate_request(request)
            expected_helpers = {
                "strugglebus-maintenance", "strugglebus-validate-maintenance-config",
                "strugglebus-inspect-access-freeze", "strugglebus-sqlite-backup",
            }
            if set(request["helper_sha256"]) != expected_helpers:
                raise MaintenanceError("maintenance helper bundle is incomplete")
            if value["locks"][0]["metadata"] != "/run/lock/strugglebus/release.json" or value["locks"][1]["metadata"] != str(Path(request["environment"]["STRUGGLEBUS_DATA_DIR"]) / ".access-freeze-lock/release.json"):
                raise MaintenanceError("unexpected maintenance ownership paths")
            with ownership_fence(value["locks"]):
                # Only now may anything be written under the protected state
                # directory. A rejection before this point must leave no trace,
                # so an unfenced caller cannot use a refusal to write there.
                state_dir = request["state_dir"]
                content = (
                    value["unit_content"].encode("utf-8") if args.action == "stage"
                    else read_regular(Path(request["candidate_config"]), private=True)
                )
                if digest(content) != request["config_sha256"]:
                    raise MaintenanceError("candidate unit content differs from its binding")
                with operator_source_fence(operator_source(content)):
                    require_operator_binding(request, content)
                    if args.action == "stage":
                        validate_helpers(request)
                        journal = Journal(Path(request["state_dir"]))
                        record = journal.read()
                        if record is not None and record["phase"] != "complete" and record["binding"] != request:
                            raise MaintenanceError("unresolved maintenance blocks changed staging inputs")
                        candidate = Path(request["candidate_config"])
                        require_same_topology(read_regular(Path(request["unit"])), content)
                        journal.reconcile_staging(record, candidate)
                        if candidate.exists():
                            if digest(read_regular(candidate, private=True)) != request["config_sha256"]:
                                raise MaintenanceError("existing staged unit differs from its binding")
                        else:
                            publish(candidate, content)
                        Host(request).command(["systemd-analyze", "verify", str(candidate)])
                        result = {"state": "staged", "config_sha256": request["config_sha256"]}
                    else:
                        result = run(request, Host(request))
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except MaintenanceError as error:
        print(str(error), file=sys.stderr)
        record_failure(state_dir, str(error))
        return 1
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        # Never echo arbitrary process output, configuration or credential data.
        print("maintenance refused or failed; inspect protected operation status and deployment diagnostics", file=sys.stderr)
        record_failure(
            state_dir,
            "maintenance refused or failed; inspect protected operation status and deployment diagnostics",
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
