"""Installed Windows operator client; SSH authority stays on the remote host."""

from __future__ import annotations

import re
import os
# Only trusted Windows OpenSSH receives the allowlisted, shell-free argv.
import subprocess  # nosec B404
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from strugglebus.errors import ConfigurationError, StrugglebusError
from strugglebus.operator_local import require_terminal
from strugglebus.private_files import (
    private_read_lease, read_private_file,
    require_trusted_windows_program, windows_directory,
)

SSH_ALIAS = "strugglebus-operator"
REMOTE_MENU = "/usr/local/sbin/strugglebus-operator"
_ENTRY = re.compile(r'\s*([A-Za-z][A-Za-z0-9]*)\s+(?:"([^"]+)"|([^\s#"]+))\s*')
_KEYS = {"hostname", "user", "port", "identityfile", "userknownhostsfile", "identitiesonly"}


class OperatorSSHError(StrugglebusError):
    """A protected SSH menu could not complete; never use a web fallback."""


@dataclass(frozen=True, slots=True)
class SSHConfiguration:
    hostname: str
    user: str
    port: str
    identity_file: Path
    known_hosts_file: Path


def _decode_ssh_configuration(raw: bytes) -> str:
    if len(raw) > 8192:
        raise ConfigurationError("operator SSH configuration is too large")
    try:
        return raw.decode("utf-8")
    except UnicodeError:
        raise ConfigurationError("operator SSH configuration must be UTF-8") from None


def _is_blank_or_comment(line: str) -> bool:
    return not line.strip() or line.lstrip().startswith("#")


def _has_expansion_or_control(value: str) -> bool:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return True
    return any(character in value for character in "%$`")


def _literal_entry(line: str) -> tuple[str, str]:
    match = _ENTRY.fullmatch(line)
    if match is None:
        raise ConfigurationError("operator SSH configuration needs simple literal entries")
    value = match[2] if match[2] is not None else match[3]
    if _has_expansion_or_control(value):
        raise ConfigurationError("operator SSH configuration expansions are forbidden")
    return match[1].lower(), value


def _require_single_leading_alias(
    value: str, seen_host: bool, settings: dict[str, str],
) -> None:
    if seen_host or settings or value != SSH_ALIAS:
        raise ConfigurationError("configure only the fixed operator SSH alias")


def _alias_settings(text: str) -> dict[str, str]:
    """Settings of the single fixed alias block; anything else is refused."""
    settings: dict[str, str] = {}
    seen_host = False
    for line in text.splitlines():
        if _is_blank_or_comment(line):
            continue
        key, value = _literal_entry(line)
        if key == "host":
            _require_single_leading_alias(value, seen_host, settings)
            seen_host = True
        elif not seen_host or key not in _KEYS or key in settings:
            raise ConfigurationError("unsupported or duplicate operator SSH setting")
        else:
            settings[key] = value
    return settings


def _require_identity_policy(settings: dict[str, str]) -> None:
    if (
        re.fullmatch(r"[A-Za-z0-9:\[][A-Za-z0-9:._\[\]-]{0,254}", settings["hostname"]) is None
        or re.fullmatch(r"[a-z_][a-z0-9_-]{0,63}", settings["user"]) is None
        or settings.get("identitiesonly", "yes") != "yes"
    ):
        raise ConfigurationError("operator SSH host, user or identity policy is invalid")


def _ssh_port(settings: dict[str, str]) -> str:
    port = settings.get("port", "22")
    if re.fullmatch(r"[1-9][0-9]{0,4}", port) is None or int(port) > 65_535:
        raise ConfigurationError("operator SSH port is invalid")
    return port


def _distinct_absolute_files(settings: dict[str, str]) -> tuple[Path, Path]:
    identity = Path(settings["identityfile"])
    known_hosts = Path(settings["userknownhostsfile"])
    if not identity.is_absolute() or not known_hosts.is_absolute() or identity == known_hosts:
        raise ConfigurationError("operator SSH files must have distinct absolute paths")
    return identity, known_hosts


def parse_ssh_configuration(raw: bytes) -> SSHConfiguration:
    settings = _alias_settings(_decode_ssh_configuration(raw))
    if not {"hostname", "user", "identityfile", "userknownhostsfile"} <= settings.keys():
        raise ConfigurationError("operator SSH configuration is incomplete")
    _require_identity_policy(settings)
    port = _ssh_port(settings)
    identity, known_hosts = _distinct_absolute_files(settings)
    return SSHConfiguration(settings["hostname"], settings["user"], port, identity, known_hosts)


def _ssh_program() -> Path:
    program = windows_directory() / "System32" / "OpenSSH" / "ssh.exe"
    require_trusted_windows_program(program)
    return program


def _ssh_arguments(program: Path, config: SSHConfiguration) -> list[str]:
    known_hosts = str(config.known_hosts_file).replace("\\", "\\\\")
    return [
        str(program), "-F", "NUL", "-tt", "-l", config.user, "-p", config.port,
        "-i", str(config.identity_file),
        "-o", f"HostName={config.hostname}",
        "-o", f'UserKnownHostsFile="{known_hosts}"',
        "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
        "-o", "GlobalKnownHostsFile=none", "-o", "VerifyHostKeyDNS=no",
        "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
        "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no", "-o", "ClearAllForwardings=yes",
        "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "Tunnel=no",
        "-o", "PermitLocalCommand=no", "-o", "ProxyCommand=none",
        "-o", "ProxyJump=none", "-o", "ControlMaster=no", "-o", "ControlPath=none",
        "-o", "ConnectTimeout=15", "-o", "ConnectionAttempts=1",
        SSH_ALIAS, REMOTE_MENU,
    ]


def _invoke_ssh(arguments: list[str]) -> int:
    try:
        environment = {
            name: value for name, value in os.environ.items()
            if not name.upper().startswith("SSH_") and name.upper() != "DISPLAY"
        }
        # connect_operator validates executable ACLs and builds literal argv; no shell/config execution.
        return subprocess.run(  # nosec B603
            arguments, timeout=3660, check=False, env=environment,
        ).returncode
    except (OSError, subprocess.TimeoutExpired):
        raise OperatorSSHError("protected SSH menu could not complete; no web fallback") from None


def connect_operator(
    config_file: Path, *, stdin: TextIO, validate_only: bool = False,
) -> None:
    if not validate_only:
        require_terminal(stdin)
    program = _ssh_program()
    with ExitStack() as leases:
        leases.enter_context(private_read_lease(config_file))
        config = parse_ssh_configuration(read_private_file(config_file, maximum=8192))
        if config_file in {config.identity_file, config.known_hosts_file}:
            raise ConfigurationError("operator SSH configuration must be a separate file")
        for path in (config.identity_file, config.known_hosts_file):
            leases.enter_context(private_read_lease(path))
        if validate_only:
            return
        # OpenSSH never parses the supplied config, so Match/Include cannot race
        # validation. Only reviewed literal values become separate argv entries.
        if _invoke_ssh(_ssh_arguments(program, config)) != 0:
            raise OperatorSSHError("protected SSH menu failed; no web fallback")
