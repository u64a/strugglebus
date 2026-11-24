#!/usr/bin/python3.13
"""Validate staged settings without starting the application.

The caller verifies the candidate venv and unit ownership, runs systemd-analyze,
and invokes this helper as the service user. No credentials or release.env are
read: --release-id supplies the verified candidate's release identity.
For private staged units, the root caller uses validate_unit_scope(), then sends
its result to --environment-stdin after changing to the service identity, or
passes the already scope-checked unit bytes to --unit-stdin. Successful CLI output
contains candidate_schema and the validated non-secret environment mapping for
runtime comparison; the admin credential is represented only by its file path.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess  # nosec B404
import sys


MAX_UNIT_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 16 * 1024
MAX_SETTINGS = 128
MAX_VALUE_BYTES = 4096
PREFIX = "STRUGGLEBUS_"
PROJECTED_CREDENTIAL = "/run/credentials/strugglebus.service/admin-token"
PROJECTED_OPERATOR_CREDENTIAL = "/run/credentials/strugglebus.service/operator-password"
PROJECTED_SATELLITE_KEY = "/run/credentials/strugglebus.service/satellite-ca-key"
OPERATOR_DIRECTIVE = ("Service", "OperatorLoadCredential")
SATELLITE_DIRECTIVE = ("Service", "SatelliteLoadCredential")
PATH_SETTINGS = {
    "DATA_DIR", "RUNTIME_DIR", "BACKUP_DIR", "DATABASE_PATH",
    "ADMIN_CREDENTIAL_PATH", "OPERATOR_CREDENTIAL_PATH", "CA_BUNDLE_PATH",
}
TOPOLOGY_SETTINGS = PATH_SETTINGS - {"CA_BUNDLE_PATH", "OPERATOR_CREDENTIAL_PATH"} | {
    "PUBLIC_BASE_URL", "BIND_HOST", "BIND_PORT", "ALLOWED_HOSTS",
    "ALLOWED_ORIGINS", "TRUSTED_PROXY_SOURCES",
}
FIXED_DIRECTIVES = {
    "Unit": {
        "Description": "Strugglebus LAN message board",
        "After": "network-online.target",
        "Wants": "network-online.target",
    },
    "Service": {
        "Type": "simple",
        "RuntimeDirectory": "strugglebus",
        "RuntimeDirectoryMode": "0750",
        "Restart": "always",
        "RestartSec": "5s",
        "TimeoutStartSec": "60s",
        "TimeoutStopSec": "30s",
        "UMask": "0027",
        "NoNewPrivileges": "true",
        "PrivateTmp": "true",
        "PrivateDevices": "true",
        "ProtectSystem": "strict",
        "ProtectHome": "true",
        "ProtectKernelTunables": "true",
        "ProtectKernelModules": "true",
        "ProtectKernelLogs": "true",
        "ProtectControlGroups": "true",
        "ProtectClock": "true",
        "ProtectHostname": "true",
        "ProtectProc": "invisible",
        "ProcSubset": "pid",
        "RestrictSUIDSGID": "true",
        "RestrictRealtime": "true",
        "RestrictNamespaces": "true",
        "LockPersonality": "true",
        "MemoryDenyWriteExecute": "true",
        "RemoveIPC": "true",
        "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
        "SystemCallArchitectures": "native",
        "SystemCallFilter": "@system-service",
        "SystemCallErrorNumber": "EPERM",
    },
    "Install": {"WantedBy": "multi-user.target"},
}
DYNAMIC_DIRECTIVES = {
    "Unit": {"ConditionPathIsDirectory"},
    "Service": {
        "User", "Group", "WorkingDirectory", "LoadCredential",
        "EnvironmentFile", "ExecStart", "ReadWritePaths",
    },
    "Install": set(),
}
ASSIGNMENT = re.compile(
    r"""(?:[A-Z_][A-Z0-9_]*=[^\s"'\\]*|"[A-Z_][A-Z0-9_]*=[^"\\]*"|'[A-Z_][A-Z0-9_]*=[^'\\]*')(?: +|$)"""
)
UPDATER_BOUNDS = {
    "UPDATER_CONFIRM_SESSION_PER_MINUTE": 3,
    "UPDATER_CONFIRM_GLOBAL_PER_MINUTE": 6,
    "UPDATER_REVIEW_SECONDS": 300,
    "UPDATER_REVIEW_TICKETS": 8,
}


class MaintenanceConfigError(RuntimeError):
    """Only fixed, non-sensitive diagnostic messages cross this boundary."""


def _posix_path(value: str) -> bool:
    return (
        value.startswith("/")
        and str(PurePosixPath(value)) == value
        and ".." not in PurePosixPath(value).parts
        and re.fullmatch(r"/[A-Za-z0-9_./-]+", value) is not None
    )


def _validate_environment(environment: dict[str, str]) -> None:
    if not isinstance(environment, dict) or len(environment) > MAX_SETTINGS:
        raise MaintenanceConfigError("invalid environment")
    for name, value in environment.items():
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"STRUGGLEBUS_[A-Z][A-Z0-9_]{0,95}", name)
            or name in {
                "STRUGGLEBUS_ADMIN_SECRET", "STRUGGLEBUS_OPERATOR_PASSWORD",
                "STRUGGLEBUS_OPERATOR_PASSWORD_HASH", "STRUGGLEBUS_OPERATOR_SECRET",
            }
            or not isinstance(value, str)
            or len(value) > MAX_VALUE_BYTES
            or any(not 32 <= ord(character) < 127 for character in value)
            or "%" in value
        ):
            raise MaintenanceConfigError("invalid environment")
        if name.removeprefix(PREFIX) in PATH_SETTINGS:
            if not value and name == "STRUGGLEBUS_CA_BUNDLE_PATH":
                continue
            path = Path(value)
            if not path.is_absolute() or ".." in path.parts:
                raise MaintenanceConfigError("invalid configuration path")
    if len(json.dumps(environment).encode("ascii")) > MAX_UNIT_BYTES:
        raise MaintenanceConfigError("environment exceeds size limit")
    _validate_updater_settings(environment)


def _validate_updater_settings(environment: dict[str, str]) -> None:
    for name, maximum in UPDATER_BOUNDS.items():
        value = environment.get(PREFIX + name)
        if value is not None and (
            re.fullmatch(r"[1-9][0-9]{0,2}", value) is None
            or not 1 <= int(value) <= maximum
        ):
            raise MaintenanceConfigError("invalid updater limit")
    socket = environment.get(PREFIX + "UPDATER_SOCKET_PATH", "")
    if socket:
        _validate_updater_socket(socket, environment)


def _validate_updater_socket(socket: str, environment: dict[str, str]) -> None:
    if not _posix_path(socket) or len(socket) > 107:
        raise MaintenanceConfigError("invalid updater socket path")
    for name in ("DATA_DIR", "RUNTIME_DIR", "BACKUP_DIR"):
        directory = environment.get(PREFIX + name, "")
        if not directory or socket == directory or socket.startswith(directory + "/"):
            raise MaintenanceConfigError("updater socket overlaps application storage")


def _parse_unit(
    unit_text: str,
    *,
    allow_legacy_service_command: bool = False,
) -> tuple[dict[str, str], dict[tuple[str, str], str]]:
    if (
        not isinstance(unit_text, str)
        or len(unit_text) > MAX_UNIT_BYTES
        or any(
            character != "\n" and not 32 <= ord(character) < 127
            for character in unit_text
        )
        or "\\" in unit_text
    ):
        raise MaintenanceConfigError("invalid unit text")
    section = ""
    sections: list[str] = []
    directives: dict[tuple[str, str], str] = {}
    environment: dict[str, str] = {}
    for line in unit_text.split("\n"):
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            sections.append(section)
            if sections != ["Unit", "Service", "Install"][:len(sections)]:
                raise MaintenanceConfigError("invalid unit sections")
            continue
        name, separator, value = line.partition("=")
        if not separator or not section:
            raise MaintenanceConfigError("invalid unit directive")
        if section == "Service" and name == "Environment":
            position = 0
            while position < len(value):
                match = ASSIGNMENT.match(value, position)
                if match is None:
                    raise MaintenanceConfigError("invalid environment assignment")
                assignment = match.group().rstrip(" ")
                if assignment.startswith(("'", '"')):
                    assignment = assignment[1:-1]
                key, _, setting = assignment.partition("=")
                if (
                    not re.fullmatch(r"STRUGGLEBUS_[A-Z][A-Z0-9_]{0,95}", key)
                    or key in environment
                    or key in {
                        "STRUGGLEBUS_ADMIN_SECRET", "STRUGGLEBUS_OPERATOR_PASSWORD",
                        "STRUGGLEBUS_OPERATOR_PASSWORD_HASH", "STRUGGLEBUS_OPERATOR_SECRET",
                    }
                    or len(setting) > MAX_VALUE_BYTES
                    or "$" in setting
                    or "`" in setting
                    or (
                        "%" in setting
                        and (key, setting) not in {
                            ("STRUGGLEBUS_ADMIN_CREDENTIAL_PATH", "%d/admin-token"),
                            ("STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH", "%d/operator-password"),
                            ("STRUGGLEBUS_SATELLITE_CA_KEY_PATH", "%d/satellite-ca-key"),
                        }
                    )
                ):
                    raise MaintenanceConfigError("invalid environment assignment")
                environment[key] = setting
                position = match.end()
            if not value or len(environment) > MAX_SETTINGS:
                raise MaintenanceConfigError("invalid environment assignment")
            continue
        if section == "Service" and name == "LoadCredential" and value.startswith("operator-password:"):
            if OPERATOR_DIRECTIVE in directives:
                raise MaintenanceConfigError("duplicate operator credential")
            directives[OPERATOR_DIRECTIVE] = value
            continue
        if section == "Service" and name == "LoadCredential" and value.startswith("satellite-ca-key:"):
            if SATELLITE_DIRECTIVE in directives:
                raise MaintenanceConfigError("duplicate satellite credential")
            directives[SATELLITE_DIRECTIVE] = value
            continue
        if (
            name not in FIXED_DIRECTIVES[section]
            and name not in DYNAMIC_DIRECTIVES[section]
        ) or (section, name) in directives:
            raise MaintenanceConfigError("unsupported unit directive")
        if name in FIXED_DIRECTIVES[section] and value != FIXED_DIRECTIVES[section][name]:
            raise MaintenanceConfigError("unsupported unit directive")
        directives[section, name] = value
    expected = {
        (group, name)
        for group in FIXED_DIRECTIVES
        for name in FIXED_DIRECTIVES[group].keys() | DYNAMIC_DIRECTIVES[group]
    }
    expected |= {OPERATOR_DIRECTIVE, SATELLITE_DIRECTIVE} & set(directives)
    if sections != ["Unit", "Service", "Install"] or set(directives) != expected:
        raise MaintenanceConfigError("incomplete unit")
    required = PATH_SETTINGS - {"CA_BUNDLE_PATH", "OPERATOR_CREDENTIAL_PATH"} | {"BIND_HOST", "BIND_PORT"}
    if not {PREFIX + key for key in required}.issubset(environment):
        raise MaintenanceConfigError("incomplete service environment")
    for name in PATH_SETTINGS - {"ADMIN_CREDENTIAL_PATH", "OPERATOR_CREDENTIAL_PATH"}:
        setting = environment.get(PREFIX + name, "")
        if (setting or name != "CA_BUNDLE_PATH") and not _posix_path(setting):
            raise MaintenanceConfigError("invalid configuration path")
    if environment["STRUGGLEBUS_ADMIN_CREDENTIAL_PATH"] != "%d/admin-token":
        raise MaintenanceConfigError("unsupported credential reference")
    current = directives["Service", "WorkingDirectory"]
    credential = directives["Service", "LoadCredential"].removeprefix("admin-token:")
    operator_source = None
    if OPERATOR_DIRECTIVE in directives:
        operator_source = directives[OPERATOR_DIRECTIVE].removeprefix("operator-password:")
        if (
            not _posix_path(operator_source)
            or operator_source in {
                credential, environment["STRUGGLEBUS_DATABASE_PATH"],
                PROJECTED_CREDENTIAL, PROJECTED_OPERATOR_CREDENTIAL,
            }
            or environment.get("STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH") != "%d/operator-password"
        ):
            raise MaintenanceConfigError("unsupported operator credential reference")
    elif "STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH" in environment:
        raise MaintenanceConfigError("operator credential projection is missing")
    satellite_source = None
    if SATELLITE_DIRECTIVE in directives:
        satellite_source = directives[SATELLITE_DIRECTIVE].removeprefix("satellite-ca-key:")
        if (
            not _posix_path(satellite_source)
            or satellite_source in {
                credential, operator_source, environment["STRUGGLEBUS_DATABASE_PATH"],
                PROJECTED_CREDENTIAL, PROJECTED_OPERATOR_CREDENTIAL, PROJECTED_SATELLITE_KEY,
            }
            or environment.get("STRUGGLEBUS_SATELLITE_CA_KEY_PATH") != "%d/satellite-ca-key"
        ):
            raise MaintenanceConfigError("unsupported satellite credential reference")
    elif "STRUGGLEBUS_SATELLITE_CA_KEY_PATH" in environment:
        raise MaintenanceConfigError("satellite credential projection is missing")
    if (
        not _posix_path(current)
        or directives["Unit", "ConditionPathIsDirectory"] != current
        or directives["Service", "EnvironmentFile"] != f"-{current}/release.env"
        or not directives["Service", "LoadCredential"].startswith("admin-token:")
        or not _posix_path(credential)
        or any(
            not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", directives["Service", name])
            for name in ("User", "Group")
        )
        or directives["Service", "ReadWritePaths"] != " ".join(
            environment[PREFIX + name] for name in ("DATA_DIR", "RUNTIME_DIR", "BACKUP_DIR")
        )
    ):
        raise MaintenanceConfigError("invalid service references")
    try:
        loopback = ipaddress.ip_address(environment["STRUGGLEBUS_BIND_HOST"]).is_loopback
        port = environment["STRUGGLEBUS_BIND_PORT"]
        if not loopback or not re.fullmatch(r"[1-9][0-9]{0,4}", port) or int(port) > 65535:
            raise ValueError
    except ValueError:
        raise MaintenanceConfigError("invalid loopback binding") from None
    command = directives["Service", "ExecStart"].split(" ")
    service_command = [f"{current}/venv/bin/strugglebus", "serve"]
    legacy_command = [
        f"{current}/venv/bin/uvicorn",
        "strugglebus.app:app",
        "--host",
        environment["STRUGGLEBUS_BIND_HOST"],
        "--port",
        port,
        "--no-access-log",
        "--no-proxy-headers",
        "--no-server-header",
    ]
    if command != service_command and not (
        allow_legacy_service_command and command == legacy_command
    ):
        raise MaintenanceConfigError("unsupported service command")
    if environment.get("STRUGGLEBUS_CA_BUNDLE_PATH", "") in {
        credential, PROJECTED_CREDENTIAL, environment["STRUGGLEBUS_DATABASE_PATH"],
        operator_source, PROJECTED_OPERATOR_CREDENTIAL,
        satellite_source, PROJECTED_SATELLITE_KEY,
    }:
        raise MaintenanceConfigError("invalid public CA reference")
    environment["STRUGGLEBUS_ADMIN_CREDENTIAL_PATH"] = PROJECTED_CREDENTIAL
    if operator_source is not None:
        environment["STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH"] = PROJECTED_OPERATOR_CREDENTIAL
    if satellite_source is not None:
        environment["STRUGGLEBUS_SATELLITE_CA_KEY_PATH"] = PROJECTED_SATELLITE_KEY
    _validate_updater_settings(environment)
    return environment, directives


def parse_environment(unit_text: str) -> dict[str, str]:
    """Parse only the repository unit grammar; never evaluate shell/unit code.

    EnvironmentFile must reference current/release.env but is never opened.
    Only the fixed credential specifiers are expanded, to inert paths.
    Backslash escapes, continuation lines, other specifiers and overrides fail
    closed; quoted whole assignments and multiple assignments are supported.
    """
    return _parse_unit(unit_text)[0]


def validate_unit_scope(previous: str, candidate: str) -> dict[str, str]:
    """Permit reviewed one-way migrations without weakening candidate syntax."""
    old_environment, old_directives = _parse_unit(
        previous,
        allow_legacy_service_command=True,
    )
    environment, directives = _parse_unit(candidate)
    old_operator = old_directives.pop(OPERATOR_DIRECTIVE, None)
    operator = directives.pop(OPERATOR_DIRECTIVE, None)
    # Enabling or disabling satellites is an inventory choice, not topology.
    old_directives.pop(SATELLITE_DIRECTIVE, None)
    directives.pop(SATELLITE_DIRECTIVE, None)
    old_directives.pop(("Service", "ExecStart"))
    directives.pop(("Service", "ExecStart"))
    if (
        (old_operator is not None and operator != old_operator)
        or old_directives != directives or any(
        old_environment.get(PREFIX + name) != environment.get(PREFIX + name)
        for name in TOPOLOGY_SETTINGS
        )
    ):
        raise MaintenanceConfigError("unit changes protected topology")
    return environment


def credential_sources(unit_text: str) -> dict[str, str]:
    """Return named references only; this parser never reads credential files."""
    _, directives = _parse_unit(unit_text)
    sources = {
        "admin-token": directives["Service", "LoadCredential"].removeprefix("admin-token:")
    }
    if OPERATOR_DIRECTIVE in directives:
        sources["operator-password"] = directives[OPERATOR_DIRECTIVE].removeprefix("operator-password:")
    return sources


# Input is JSON on stdin, not executable source or the child's environment.
# Candidate imports and their diagnostics are silenced before importing config.
PROBE_CODE = r'''
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import time
from dataclasses import fields

sys.dont_write_bytecode = True
protocol = os.fdopen(os.dup(1), "w", encoding="ascii")
sink = os.open(os.devnull, os.O_WRONLY)
os.dup2(sink, 1)
os.dup2(sink, 2)
os.close(sink)
error = "invalid candidate configuration"
try:
    environment = json.loads(sys.stdin.buffer.read(65537))
    from strugglebus.config import AppConfig
    names = {item.name for item in fields(AppConfig)} - {"admin_secret"}
    requested = {key.removeprefix("STRUGGLEBUS_").lower() for key in environment}
    if not requested.issubset(names):
        error = "unsupported candidate setting"
        raise ValueError
    bundle = environment.get("STRUGGLEBUS_CA_BUNDLE_PATH", "")
    digest = environment.get("STRUGGLEBUS_CA_ROOT_SHA256", "")
    if bool(bundle) != bool(digest):
        error = "invalid public CA configuration"
        raise ValueError
    if bundle:
        error = "invalid public CA configuration"
        path = Path(bundle)
        blocked = {
            os.path.normcase(str(Path(environment[key])))
            for key in (
                "STRUGGLEBUS_DATABASE_PATH", "STRUGGLEBUS_ADMIN_CREDENTIAL_PATH",
                "STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH",
            )
            if key in environment
        }
        if (
            not path.is_absolute()
            or os.path.normcase(str(path)) in blocked
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or any(part.is_symlink() for part in (path, *path.parents))
        ):
            raise ValueError
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 256 * 1024:
            raise ValueError
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
                or opened.st_size > 256 * 1024
            ):
                raise ValueError
            pem = stream.read(256 * 1024 + 1)
        if len(pem) > 256 * 1024 or b"PRIVATE KEY" in pem:
            raise ValueError
        found = False
        pattern = rb"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----"
        for match in re.finditer(pattern, pem):
            try:
                der = base64.b64decode(re.sub(rb"\s", b"", match.group(1)), validate=True)
            except (binascii.Error, ValueError):
                continue
            if not der or hashlib.sha256(der).hexdigest() != digest:
                continue
            # Match the candidate trust-anchor loader without reopening the
            # protected path; older candidates only check the DER digest.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(der))
            certificates = context.get_ca_certs()
            if len(certificates) != 1:
                raise ValueError
            certificate = certificates[0]
            not_before = ssl.cert_time_to_seconds(certificate["notBefore"])
            not_after = ssl.cert_time_to_seconds(certificate["notAfter"])
            if not not_before <= time.time() < not_after:
                raise ValueError
            found = True
            break
        if not found:
            raise ValueError
    error = "invalid candidate configuration"
    AppConfig.from_env(environment)
    error = "invalid candidate migration package"
    from strugglebus.migrations import LATEST_SCHEMA_VERSION, load_packaged_migrations
    migrations = load_packaged_migrations()
    if (
        type(LATEST_SCHEMA_VERSION) is not int
        or not 1 <= LATEST_SCHEMA_VERSION <= 9999
        or len(migrations) != LATEST_SCHEMA_VERSION
        or tuple(item.version for item in migrations) != tuple(range(1, LATEST_SCHEMA_VERSION + 1))
    ):
        raise ValueError
    if "STRUGGLEBUS_OPERATOR_CREDENTIAL_PATH" in environment and LATEST_SCHEMA_VERSION < 12:
        raise ValueError
    result = {
        "schema_version": LATEST_SCHEMA_VERSION,
        "config_fields": sorted(names),
        "config_sha256": hashlib.sha256(
            json.dumps(environment, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest(),
    }
    encoded = json.dumps(result, sort_keys=True)
    if len(encoded) > 16384:
        raise ValueError
except BaseException:
    protocol.write(json.dumps({"error": error}) + "\n")
    protocol.close()
    sys.exit(1)
protocol.write(encoded + "\n")
protocol.close()
'''


def candidate_config_probe(
    candidate_python: str | Path,
    environment: dict[str, str],
    timeout: float = 30,
) -> dict[str, object]:
    """Run a verified candidate interpreter under the caller's service identity."""
    _validate_environment(environment)
    python = Path(candidate_python)
    if (
        not python.is_absolute()
        or ".." in python.parts
        or any(ord(character) < 32 for character in str(python))
        or isinstance(timeout, bool)
        or not isinstance(timeout, (float, int))
        or not math.isfinite(timeout)
        or not 0 < timeout <= 300
    ):
        raise MaintenanceConfigError("invalid candidate probe arguments")
    child_environment = {"LANG": "C", "PATH": os.defpath}
    if os.name == "nt" and "SystemRoot" in os.environ:
        child_environment["SystemRoot"] = os.environ["SystemRoot"]
    try:
        # Verified interpreter and fixed code; settings are data on stdin, never shell input.
        result = subprocess.run(  # nosec B603
            [str(python), "-I", "-c", PROBE_CODE],
            input=json.dumps(environment).encode("ascii"),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=child_environment,
            timeout=timeout,
            check=False,
        )
        if len(result.stdout) > MAX_OUTPUT_BYTES:
            raise ValueError
        payload = json.loads(result.stdout)
        if result.returncode:
            if payload in [
                {"error": message} for message in (
                    "invalid candidate configuration",
                    "unsupported candidate setting",
                    "invalid public CA configuration",
                    "invalid candidate migration package",
                )
            ]:
                raise MaintenanceConfigError(payload["error"])
            raise ValueError
        if (
            not isinstance(payload, dict)
            or set(payload) != {"schema_version", "config_fields", "config_sha256"}
            or type(payload["schema_version"]) is not int
            or not 1 <= payload["schema_version"] <= 9999
            or not isinstance(payload["config_fields"], list)
            or len(payload["config_fields"]) > MAX_SETTINGS
            or any(
                not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", name)
                for name in payload["config_fields"]
            )
            or "admin_secret" in payload["config_fields"]
            or payload["config_fields"] != sorted(set(payload["config_fields"]))
            or payload["config_sha256"] != hashlib.sha256(
                json.dumps(environment, sort_keys=True, separators=(",", ":")).encode("ascii")
            ).hexdigest()
        ):
            raise ValueError
        return payload
    except (OSError, ValueError, TypeError, RecursionError, subprocess.SubprocessError):
        raise MaintenanceConfigError("candidate configuration probe failed") from None


def _read_unit(filename: str) -> str:
    path = Path(filename)
    if not path.is_absolute() or path.is_symlink():
        raise MaintenanceConfigError("invalid unit path")
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_UNIT_BYTES:
            raise ValueError
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (
                opened.st_dev, opened.st_ino
            ) != (metadata.st_dev, metadata.st_ino):
                raise ValueError
            value = stream.read(MAX_UNIT_BYTES + 1)
        if len(value) > MAX_UNIT_BYTES:
            raise ValueError
        return value.decode("ascii")
    except (OSError, ValueError):
        raise MaintenanceConfigError("unit is unavailable or invalid") from None


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise MaintenanceConfigError("invalid helper arguments")


def _environment_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise MaintenanceConfigError("duplicate environment input")
        result[name] = value
    return result


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--unit")
    source.add_argument("--unit-stdin", action="store_true")
    source.add_argument("--environment-stdin", action="store_true")
    parser.add_argument("--current-unit")
    parser.add_argument("--candidate-python", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--timeout", type=float, default=30)
    try:
        arguments = parser.parse_args(argv)
        if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]{0,63}", arguments.release_id):
            raise MaintenanceConfigError("invalid candidate release identity")
        if arguments.environment_stdin or arguments.unit_stdin:
            if arguments.current_unit:
                raise MaintenanceConfigError("invalid helper arguments")
            try:
                raw = sys.stdin.buffer.read(MAX_UNIT_BYTES + 1)
                if len(raw) > MAX_UNIT_BYTES:
                    raise ValueError
                environment = (
                    parse_environment(raw.decode("ascii")) if arguments.unit_stdin
                    else json.loads(raw, object_pairs_hook=_environment_object)
                )
            except (OSError, ValueError, RecursionError):
                raise MaintenanceConfigError("invalid environment input") from None
            if arguments.environment_stdin:
                _validate_environment(environment)
        else:
            unit = _read_unit(arguments.unit)
            environment = (
                validate_unit_scope(_read_unit(arguments.current_unit), unit)
                if arguments.current_unit else parse_environment(unit)
            )
        if "STRUGGLEBUS_RELEASE_ID" in environment:
            raise MaintenanceConfigError("unit overrides candidate release identity")
        environment["STRUGGLEBUS_RELEASE_ID"] = arguments.release_id
        result = candidate_config_probe(
            arguments.candidate_python, environment, arguments.timeout
        )
    except MaintenanceConfigError as error:
        print(json.dumps({"error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps({
        "candidate_schema": result["schema_version"],
        "environment": environment,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
