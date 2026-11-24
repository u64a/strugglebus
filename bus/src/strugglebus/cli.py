"""Safe operational command-line interface for Strugglebus."""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import ssl
import stat
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, TextIO
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import (
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from strugglebus import __version__
from strugglebus.access import ACCESS_FREEZE_LOCK_DIRECTORY, AccessFreezeService, normalize_access_freeze_reason
from strugglebus.auth import (
    AgentService,
    parse_credential,
    parse_enrollment_token,
    parse_spn_credential,
)
from strugglebus.backup import DEFAULT_BACKUP_RETENTION, create_verified_backup
from strugglebus.config import AppConfig
from strugglebus.errors import (
    AgentNotFoundError,
    ConfigurationError,
    StrugglebusError,
)
from strugglebus.models import Agent, AgentCredential, LifecycleActor
from strugglebus.reconnect import NoRedirectHandler as _NoRedirectHandler
from strugglebus.service import MAX_SEQUENCE, BoardService
from strugglebus.store import SQLiteStore
from strugglebus.store import utc_now
from strugglebus.spn import ServicePrincipalService

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_CONFIG = 3
EXIT_AUTH = 4
EXIT_NETWORK = 5
EXIT_SERVER = 6
EXIT_INTERRUPTED = 130

DEFAULT_NETWORK_TIMEOUT = 30.0
MAX_NETWORK_TIMEOUT = 60.0
DEFAULT_TAIL_EVENTS = 100
DEFAULT_RECONNECT_ATTEMPTS = 8
MAX_SSE_LINE_BYTES = 2 * 1024 * 1024
MAX_HEALTH_RESPONSE_BYTES = 4096
MAX_IDENTITY_RESPONSE_BYTES = 32 * 1024
_OPERATION_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_CREDENTIAL_ID_PATTERN = re.compile(r"^cred_[A-Za-z0-9_-]{22}$")


class _AuthenticationFailure(Exception):
    pass


class _NetworkFailure(Exception):
    pass


class _ServerFailure(Exception):
    pass


class _OutputClosed(Exception):
    pass


class _ArgumentParser(argparse.ArgumentParser):
    redact_errors = False

    def error(self, message: str) -> None:
        super().error(
            "invalid operator password arguments" if self.redact_errors else message
        )


def _bounded_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if not 0.1 <= timeout <= MAX_NETWORK_TIMEOUT:
        raise argparse.ArgumentTypeError(
            f"must be between 0.1 and {MAX_NETWORK_TIMEOUT:g} seconds"
        )
    return timeout


def _non_negative_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def _positive_integer(value: str) -> int:
    parsed = _non_negative_integer(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def _sequence(value: str) -> int:
    parsed = _non_negative_integer(value)
    if parsed > MAX_SEQUENCE:
        raise argparse.ArgumentTypeError(
            f"must not exceed {MAX_SEQUENCE}"
        )
    return parsed


def _access_freeze_reason(value: str) -> str:
    try:
        return normalize_access_freeze_reason(value)
    except StrugglebusError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def _parser() -> _ArgumentParser:
    parser = _ArgumentParser(
        prog="strugglebus",
        description="LAN message board for AI agents.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    commands = parser.add_subparsers(dest="command")

    serve = commands.add_parser("serve", help="run the loopback ASGI service")
    serve.set_defaults(handler=_serve)

    operator = commands.add_parser("operator", help="protected local human controls")
    operator_commands = operator.add_subparsers(dest="operator_command", required=True)
    emergency = operator_commands.add_parser(
        "emergency", help="interactive local Status/Freeze/Unfreeze menu",
    )
    emergency.set_defaults(handler=_operator_emergency)
    connect = operator_commands.add_parser(
        "connect", help="open the protected SSH menu from the installed Windows client",
    )
    connect.add_argument("--ssh-config", required=True, type=Path)
    connect.add_argument("--validate-only", action="store_true")
    connect.set_defaults(handler=_operator_connect)
    password = operator_commands.add_parser(
        "password", help="set or reset the dedicated browser verifier at a root terminal",
    )
    password.redact_errors = True
    password.add_argument("--credential-file", required=True, type=Path)
    password.add_argument("--reset", action="store_true")
    password.set_defaults(handler=_operator_password)
    spn = operator_commands.add_parser(
        "spn", help="manage automated onboarding service principals",
    )
    spn_commands = spn.add_subparsers(dest="spn_command", required=True)
    spn_create = spn_commands.add_parser("create")
    spn_create.add_argument("name")
    spn_create.add_argument("agent_name_prefix")
    spn_create.add_argument("--request-id", default=None)
    spn_create.add_argument("--credential-output", required=True, type=Path)
    spn_create.set_defaults(handler=_operator_spn_create)
    spn_list = spn_commands.add_parser("list")
    spn_list.set_defaults(handler=_operator_spn_list)
    for action in ("block", "unblock", "revoke"):
        command = spn_commands.add_parser(action)
        command.add_argument("spn_id")
        command.add_argument("--expected-version", required=True, type=_non_negative_integer)
        command.add_argument("--request-id", default=None)
        command.add_argument("--reason", required=True)
        command.set_defaults(handler=_operator_spn_transition, spn_action=action)
    spn_rotate = spn_commands.add_parser("rotate")
    spn_rotate.add_argument("spn_id")
    spn_rotate.add_argument("--expected-version", required=True, type=_non_negative_integer)
    spn_rotate.add_argument("--request-id", default=None)
    spn_rotate.add_argument("--reason", required=True)
    spn_rotate.add_argument("--credential-output", required=True, type=Path)
    spn_rotate.set_defaults(handler=_operator_spn_rotate)

    reconnect = commands.add_parser(
        "reconnect", help="redeem a private computer-move package without server privileges",
    )
    reconnect_commands = reconnect.add_subparsers(
        dest="reconnect_command", required=True,
    )
    redeem = reconnect_commands.add_parser(
        "redeem", help="save a fresh pending credential from a single-use grant",
    )
    redeem.add_argument("--package-file", required=True, type=Path)
    redeem.add_argument("--credential-output", required=True, type=Path)
    redeem.set_defaults(handler=_reconnect_redeem)

    agent = commands.add_parser("agent", help="manage local agent identities")
    agent_commands = agent.add_subparsers(dest="agent_command", required=True)
    add = agent_commands.add_parser("add", help="register an agent locally")
    add.add_argument("name")
    add.add_argument("--description", default="")
    add.add_argument("--host", default="")
    add.add_argument(
        "--credential-output",
        required=True,
        type=Path,
        help="new absolute file path for the one-time credential (created 0600)",
    )
    add.set_defaults(handler=_agent_add)
    list_command = agent_commands.add_parser(
        "list", help="list active local agents as JSON"
    )
    list_command.set_defaults(handler=_agent_list)
    revoke = agent_commands.add_parser("revoke", help="revoke an agent by name")
    revoke.add_argument("name")
    revoke.set_defaults(handler=_agent_revoke)
    recover = agent_commands.add_parser(
        "recover",
        help="revoke all credentials and issue a pending replacement locally",
    )
    recover.add_argument("name")
    recover.add_argument("--expected-credential-epoch", required=True, type=_non_negative_integer)
    recover.add_argument("--reason", required=True)
    recover.add_argument(
        "--credential-output",
        required=True,
        type=Path,
        help="new absolute file path for the one-time credential (created 0600)",
    )
    recover.set_defaults(handler=_agent_recover)
    evidence = agent_commands.add_parser(
        "credential-evidence",
        help="create protected operation-bound credential evidence",
    )
    evidence_commands = evidence.add_subparsers(
        dest="credential_evidence_command",
        required=True,
    )
    evidence_verify = evidence_commands.add_parser(
        "verify",
        help="verify an exact active proved credential and write a receipt",
    )
    _add_credential_evidence_options(evidence_verify)
    evidence_verify.set_defaults(handler=_agent_credential_evidence_verify)
    evidence_revoke = evidence_commands.add_parser(
        "revoke",
        help="revoke an exact credential and write a verified receipt",
    )
    _add_credential_evidence_options(evidence_revoke)
    evidence_revoke.add_argument("--reason", required=True)
    evidence_revoke.set_defaults(handler=_agent_credential_evidence_revoke)

    enroll = agent_commands.add_parser(
        "enroll",
        help="mint a single-use, short-lived self-registration token",
    )
    enroll_commands = enroll.add_subparsers(dest="enroll_command", required=True)
    enroll_create = enroll_commands.add_parser(
        "create", help="mint one enrollment token bound to a name prefix"
    )
    enroll_create.add_argument(
        "name_prefix",
        help="agent names the holder may claim, e.g. adlab for adlab-cli-win",
    )
    enroll_create.add_argument("--description", default="")
    enroll_create.add_argument("--uses", default=1, type=_positive_integer)
    enroll_create.add_argument("--ttl-seconds", default=None, type=_positive_integer)
    enroll_create.add_argument("--reason", default="agent self-registration")
    enroll_create.add_argument(
        "--token-output",
        required=True,
        type=Path,
        help="new absolute file path for the one-time token (created 0600)",
    )
    enroll_create.set_defaults(handler=_agent_enroll_create)
    enroll_list = enroll_commands.add_parser(
        "list", help="list enrollments as JSON, never including tokens"
    )
    enroll_list.set_defaults(handler=_agent_enroll_list)
    enroll_revoke = enroll_commands.add_parser(
        "revoke", help="revoke a pending enrollment by ID"
    )
    enroll_revoke.add_argument("enrollment_id")
    enroll_revoke.add_argument("--reason", required=True)
    enroll_revoke.set_defaults(handler=_agent_enroll_revoke)

    access_freeze = commands.add_parser(
        "access-freeze",
        help="manage the persistent emergency agent-access freeze",
    )
    access_freeze_commands = access_freeze.add_subparsers(
        dest="access_freeze_command",
        required=True,
    )
    freeze_status = access_freeze_commands.add_parser(
        "status",
        help="show protected local freeze status",
    )
    freeze_status.set_defaults(handler=_access_freeze_status)
    freeze = access_freeze_commands.add_parser(
        "freeze",
        help="activate the emergency agent-access freeze",
    )
    freeze.add_argument("--reason", required=True, type=_access_freeze_reason)
    freeze.set_defaults(handler=_access_freeze_activate)
    unfreeze = access_freeze_commands.add_parser(
        "unfreeze",
        help="clear the emergency agent-access freeze",
    )
    unfreeze.add_argument("--reason", required=True, type=_access_freeze_reason)
    unfreeze.set_defaults(handler=_access_freeze_clear)

    health = commands.add_parser("health", help="check remote HTTPS readiness")
    _add_network_options(health)
    health.set_defaults(handler=_health)

    tail = commands.add_parser("tail", help="consume authenticated SSE messages")
    _add_network_options(tail)
    tail.add_argument("--since", type=_sequence, default=0)
    tail.add_argument(
        "--resume-file",
        type=Path,
        help="persist and resume the last emitted event sequence",
    )
    tail.add_argument("--expected-agent-id")
    tail.add_argument("--expected-agent-name")
    tail.add_argument(
        "--max-events",
        type=_positive_integer,
        default=DEFAULT_TAIL_EVENTS,
        help=f"stop after this many events (default: {DEFAULT_TAIL_EVENTS})",
    )
    tail.add_argument(
        "--retries",
        type=_non_negative_integer,
        default=DEFAULT_RECONNECT_ATTEMPTS,
        help="consecutive reconnect attempts before failing",
    )
    tail.set_defaults(handler=_tail)

    satellite = commands.add_parser(
        "satellite", help="join this machine to a bus through its gateway"
    )
    satellite_commands = satellite.add_subparsers(dest="satellite_command", required=True)
    satellite_join = satellite_commands.add_parser(
        "join", help="create this site's key and exchange it for a site bundle"
    )
    satellite_join.set_defaults(handler=_satellite_join)
    satellite_run = satellite_commands.add_parser(
        "run", help="run the local proxy, renewing and updating as needed"
    )
    satellite_link = satellite_commands.add_parser(
        "link-agent", help="enroll an agent through the proxy and print its MCP config"
    )
    satellite_link.add_argument("name")
    satellite_link.add_argument("--description", default="")
    satellite_link.add_argument(
        "--write", type=Path, help="write the MCP configuration to this new file"
    )
    satellite_task = satellite_commands.add_parser(
        "install-task", help="start the satellite at logon and restart it on exit"
    )
    for command in (satellite_run, satellite_link, satellite_task):
        command.add_argument("--port", type=_positive_integer, default=8765)
    satellite_run.set_defaults(handler=_satellite_run)
    satellite_link.set_defaults(handler=_satellite_link)
    satellite_task.set_defaults(handler=_satellite_install_task)

    backup = commands.add_parser(
        "backup", help="create an integrity-checked SQLite backup"
    )
    backup.add_argument("--database", type=Path)
    backup.add_argument("--destination", type=Path)
    backup.add_argument(
        "--retention",
        type=_positive_integer,
        default=DEFAULT_BACKUP_RETENTION,
    )
    backup.set_defaults(handler=_backup)

    selfhost = commands.add_parser(
        "selfhost", help="print or export the install guide and install files"
    )
    selfhost_commands = selfhost.add_subparsers(dest="selfhost_command", required=True)
    selfhost_guide = selfhost_commands.add_parser(
        "guide", help="print the install guide for your own network"
    )
    selfhost_guide.set_defaults(handler=_selfhost_guide)
    selfhost_export = selfhost_commands.add_parser(
        "export", help="copy the guide and the Docker and Debian install files"
    )
    selfhost_export.add_argument("directory", type=Path, help="new or empty folder")
    selfhost_export.set_defaults(handler=_selfhost_export)
    return parser


def _add_network_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--url",
        help="base URL (default: STRUGGLEBUS_PUBLIC_BASE_URL)",
    )
    parser.add_argument(
        "--ca-file",
        type=Path,
        help="explicit CA bundle; system trust is used by default",
    )
    parser.add_argument(
        "--timeout",
        type=_bounded_timeout,
        default=DEFAULT_NETWORK_TIMEOUT,
    )


def _operation_id(value: str) -> str:
    if _OPERATION_ID_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "must start with lowercase alphanumeric text and contain at most "
            "63 lowercase alphanumeric or hyphen characters"
        )
    return value


def _credential_id(value: str) -> str:
    if _CREDENTIAL_ID_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "must be cred_ followed by 22 URL-safe characters"
        )
    return value


def _add_credential_evidence_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("name")
    parser.add_argument("--credential-id", required=True, type=_credential_id)
    parser.add_argument("--operation-id", required=True, type=_operation_id)
    parser.add_argument(
        "--receipt-path",
        required=True,
        type=Path,
        help="new absolute file path for the operation-bound receipt (created 0600)",
    )


def _services(config: AppConfig) -> tuple[AgentService, BoardService]:
    store = SQLiteStore(
        config.database_path,
        backup_dir=config.backup_dir,
        busy_timeout_ms=config.sqlite_busy_timeout_ms,
    )
    return (
        AgentService(
            store,
            max_active_credentials=config.max_active_credentials_per_agent,
            max_pending_credentials=config.max_pending_credentials_per_agent,
            pending_seconds=config.credential_pending_seconds,
            rotations_per_window=config.self_rotations_per_window,
            rotation_window_seconds=config.self_rotation_window_seconds,
            enrollment_ttl_seconds=config.enrollment_ttl_seconds,
            max_enrollment_uses=config.max_enrollment_uses,
            reconnect_ttl_seconds=config.reconnect_grant_seconds,
            max_outstanding_reconnect_grants=config.reconnect_max_grants,
        ),
        BoardService(
            store,
            max_message_bytes=config.max_message_bytes,
            max_metadata_bytes=config.max_metadata_bytes,
            max_channels=config.max_channels,
        ),
    )


def _access_freeze(config: AppConfig) -> AccessFreezeService:
    store = SQLiteStore(
        config.database_path,
        backup_dir=config.backup_dir,
        busy_timeout_ms=config.sqlite_busy_timeout_ms,
    )
    return AccessFreezeService(
        store,
        clock=utc_now,
        transition_lock_directory=config.data_dir / ACCESS_FREEZE_LOCK_DIRECTORY,
    )


def _service_principals(config: AppConfig) -> ServicePrincipalService:
    store = SQLiteStore(
        config.database_path,
        backup_dir=config.backup_dir,
        busy_timeout_ms=config.sqlite_busy_timeout_ms,
    )
    store.initialize()
    return ServicePrincipalService(
        store,
        package_ttl_seconds=config.spn_package_ttl_seconds,
        max_outstanding_packages=config.spn_max_outstanding_packages,
    )


def _local_actor() -> LifecycleActor:
    return LifecycleActor("local-admin", "local-cli")


def _write_spn_credential(path: Path, secret: str) -> None:
    parsed = parse_spn_credential(secret)
    try:
        encoded = secret.encode("ascii")
    except UnicodeError as error:
        raise ConfigurationError("SPN credential has an invalid format") from error
    if parsed is None:
        raise ConfigurationError("SPN credential has an invalid format")
    _write_protected_file(
        path, encoded + b"\n", description="SPN credential output",
        strict_parent=True,
    )


def _operator_spn_create(
    args: argparse.Namespace, *, stdout: TextIO, stderr: TextIO,
) -> int:
    del stdout
    config = AppConfig.from_env()
    _authorize_local_admin(config)
    issued = _service_principals(config).create(
        name=args.name,
        agent_name_prefix=args.agent_name_prefix,
        request_id=args.request_id or str(uuid.uuid4()),
        actor=_local_actor(),
    )
    if not issued.secret_issued or issued.secret is None:
        raise ConfigurationError(
            "SPN creation already committed; credential secret is unavailable"
        )
    _write_spn_credential(args.credential_output, issued.secret)
    stderr.write(
        f"created SPN {issued.principal.id} ({issued.principal.name}) for "
        f"{issued.principal.agent_name_prefix!r}; the credential will not be shown again\n"
    )
    return EXIT_OK


def _operator_spn_list(
    args: argparse.Namespace, *, stdout: TextIO, stderr: TextIO,
) -> int:
    del args, stderr
    config = AppConfig.from_env()
    _authorize_local_admin(config)
    payload = [
        {
            "id": principal.id,
            "name": principal.name,
            "agent_name_prefix": principal.agent_name_prefix,
            "status": principal.status,
            "created_at": principal.created_at.isoformat(),
            "blocked_at": (
                principal.blocked_at.isoformat()
                if principal.blocked_at is not None else None
            ),
            "revoked_at": (
                principal.revoked_at.isoformat()
                if principal.revoked_at is not None else None
            ),
            "version": principal.version,
        }
        for principal in _service_principals(config).list()
    ]
    _write_json(stdout, payload)
    return EXIT_OK


def _operator_spn_transition(
    args: argparse.Namespace, *, stdout: TextIO, stderr: TextIO,
) -> int:
    del stdout
    config = AppConfig.from_env()
    _authorize_local_admin(config)
    principal = _service_principals(config).transition(
        args.spn_id,
        action=args.spn_action,
        expected_version=args.expected_version,
        request_id=args.request_id or str(uuid.uuid4()),
        reason=args.reason,
        actor=_local_actor(),
    )
    verb = {"block": "blocked", "unblock": "unblocked", "revoke": "revoked"}[
        args.spn_action
    ]
    stderr.write(
        f"{verb} SPN {principal.id}; state={principal.status}, "
        f"version={principal.version}\n"
    )
    return EXIT_OK


def _operator_spn_rotate(
    args: argparse.Namespace, *, stdout: TextIO, stderr: TextIO,
) -> int:
    del stdout
    config = AppConfig.from_env()
    _authorize_local_admin(config)
    issued = _service_principals(config).rotate(
        args.spn_id,
        expected_version=args.expected_version,
        request_id=args.request_id or str(uuid.uuid4()),
        reason=args.reason,
        actor=_local_actor(),
    )
    if not issued.secret_issued or issued.secret is None:
        raise ConfigurationError(
            "SPN rotation already committed; credential secret is unavailable"
        )
    _write_spn_credential(args.credential_output, issued.secret)
    stderr.write(
        f"rotated SPN {issued.principal.id}; version={issued.principal.version}; "
        "the credential will not be shown again\n"
    )
    return EXIT_OK


def _authorize_local_admin(config: AppConfig) -> int:
    """Prove the admin token is readable; return its length and nothing else."""
    secret = config.load_admin_secret()
    length = len(secret)
    del secret
    return length


def _serve_preflight(config: AppConfig, stderr: TextIO) -> None:
    """Fail before the server starts, in one line that names the file and the fix.

    The same faults are caught again during startup, but there they surface as
    a traceback; someone installing the bus for the first time needs the path.
    """

    if not config.data_dir.is_dir():
        raise ConfigurationError(
            f"data directory does not exist: {config.data_dir}. Create it, owned "
            "by the account that runs the bus, with mode 0700 "
            "(or set STRUGGLEBUS_DATA_DIR)"
        )
    if config.admin_secret is None:
        try:
            token_length = _authorize_local_admin(config)
        except ConfigurationError as error:
            raise ConfigurationError(
                f"{error}: {config.admin_credential_path}. It must be a file "
                "holding a long random token, mode 0600, either owned by root "
                "or owned by the bus account inside a mode-0700 directory named "
                "by CREDENTIALS_DIRECTORY (set STRUGGLEBUS_ADMIN_CREDENTIAL_PATH "
                "to move it). `strugglebus selfhost guide` prints the install guide"
            ) from None
        if token_length < 32:
            stderr.write(
                f"warning: the admin token in {config.admin_credential_path} is "
                f"only {token_length} characters long. Replace it with a long "
                "random one, for example the output of `openssl rand -hex 32`\n"
            )
    if not config.public_base_url.lower().startswith("https://"):
        stderr.write(
            "warning: STRUGGLEBUS_PUBLIC_BASE_URL is not an https:// address, so "
            "the operator console and first-run setup are disabled\n"
        )


def _serve(args: argparse.Namespace, *, stdout: TextIO, stderr: TextIO) -> int:
    del args, stdout
    import uvicorn

    from strugglebus.app import create_app
    from strugglebus.audit_feed import install_stdout_handler

    config = AppConfig.from_env()
    _serve_preflight(config, stderr)
    install_stdout_handler()
    application = create_app(config=config)
    server = uvicorn.Server(
        uvicorn.Config(
            application,
            host=config.bind_host,
            port=config.bind_port,
            access_log=False,
            server_header=False,
            proxy_headers=False,
            timeout_graceful_shutdown=config.shutdown_grace_seconds,
        )
    )
    # Live tails poll until their own connection deadline, which can be far
    # longer than a restart should take. Uvicorn raises this flag the moment a
    # stop signal arrives and only then waits for connections to drain, so
    # exposing it lets each stream end itself during that wait instead of
    # holding it open. timeout_graceful_shutdown is the backstop for anything
    # that does not observe the flag; without one, a stop can outlive the unit's
    # stop timeout, get killed, and leave the service in a failed state that
    # blocks the deployment from continuing.
    application.state.shutdown_requested = lambda: server.should_exit
    # After uvicorn.Config, which replaces the handlers on its own loggers.
    from strugglebus import server_log

    server_log.install()
    try:
        server.run()
    except SystemExit as error:
        if error.code in {None, EXIT_OK}:
            return EXIT_OK
        raise _ServerFailure("server did not start") from None
    if not server.started:
        raise _ServerFailure("server did not start")
    return EXIT_OK


def _agent_add(
    args: argparse.Namespace,
    *,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    config = AppConfig.from_env()
    _authorize_local_admin(config)
    agents, board = _services(config)
    board.initialize()
    created = agents.create_agent(
        args.name,
        description=args.description,
        host=args.host,
        request_id=str(uuid.uuid4()),
        creator_type="local-admin",
        creator_id="local-cli",
    )
    del stdout
    _write_credential_secret(args.credential_output, created.api_key)
    stderr.write(
        f"registered agent {created.agent.name} ({created.agent.id}); "
        "the API key will not be shown again\n"
    )
    return EXIT_OK


def _reconnect_redeem(
    args: argparse.Namespace, *, stdout: TextIO, stderr: TextIO,
) -> int:
    from strugglebus.reconnect import redeem_package

    try:
        package = redeem_package(args.package_file, args.credential_output)
    except KeyboardInterrupt:
        stderr.write(
            "reconnect interrupted; the result may be uncertain; request an "
            "explicit operator reissue before retrying\n"
        )
        return EXIT_INTERRUPTED
    _write_json(stdout, {
        "agent_id": package.agent_id, "agent_name": package.agent_name,
        "credential_saved": True, "credential_status": "pending",
        "bootstrap_complete": False,
    })
    stderr.write(
        "Pending credential saved privately. Complete normal pinned-identity "
        "proof, Rules of Engagement, orientation and catch-up. No backlog "
        "was consumed by this command.\n"
    )
    return EXIT_OK


def _operator_password(
    args: argparse.Namespace, *, stdout: TextIO, stderr: TextIO,
) -> int:
    del stdout
    from strugglebus.operator_local import setup_password
    from strugglebus.operator_auth import OperatorAuthError

    try:
        setup_password(
            args.credential_file, reset=args.reset, stdin=sys.stdin, stderr=stderr,
        )
    except (OSError, OperatorAuthError):
        raise ConfigurationError(
            "operator verifier update did not complete safely; use the local recovery runbook"
        ) from None
    return EXIT_OK


def _operator_emergency(
    args: argparse.Namespace, *, stdout: TextIO, stderr: TextIO,
) -> int:
    del args
    from strugglebus.operator_local import require_terminal
    from strugglebus.operator_fence import delegated_release_fence

    require_terminal(sys.stdin)
    with delegated_release_fence():
        return _operator_emergency_menu(stdout=stdout, stderr=stderr)


def _operator_emergency_menu(*, stdout: TextIO, stderr: TextIO) -> int:
    from strugglebus.operator_local import terminal_line

    config = AppConfig.from_env()
    _authorize_local_admin(config)
    access = _access_freeze(config)
    while True:
        choice = terminal_line(
            sys.stdin, stdout, "\n1 Status   2 Freeze   3 Unfreeze   0 Exit\nChoice: ",
            maximum=1,
        )
        if choice == "0":
            return EXIT_OK
        if choice == "1":
            _write_json(stdout, _access_freeze_payload(access.operator_status()))
            continue
        if choice not in {"2", "3"}:
            stderr.write("Choose 1, 2, 3 or 0.\n")
            continue
        action = "FREEZE" if choice == "2" else "UNFREEZE"
        reason = normalize_access_freeze_reason(terminal_line(
            sys.stdin, stdout, "Reason (no secrets): ", maximum=256,
        ))
        confirmation = terminal_line(
            sys.stdin, stdout, f"Type {action} to confirm: ", maximum=8,
        )
        if confirmation != action:
            stderr.write("Cancelled; access state was not changed.\n")
            continue
        state, changed = (
            access.operator_freeze(reason) if choice == "2"
            else access.operator_unfreeze(reason)
        )
        _write_json(stdout, _access_freeze_payload(state, changed=changed))


def _operator_connect(
    args: argparse.Namespace, *, stdout: TextIO, stderr: TextIO,
) -> int:
    del stderr
    from strugglebus.operator_ssh import connect_operator

    connect_operator(args.ssh_config, stdin=sys.stdin, validate_only=args.validate_only)
    if args.validate_only:
        stdout.write("Private operator SSH configuration is valid; no connection was made.\n")
    return EXIT_OK


def _write_enrollment_token(path: Path, token: str) -> None:
    parsed = parse_enrollment_token(token)
    try:
        encoded = token.encode("ascii")
    except UnicodeError as error:
        raise ConfigurationError("enrollment token has an invalid format") from error
    if parsed is None or len(encoded) != 71:
        raise ConfigurationError("enrollment token has an invalid format")
    _write_protected_file(
        path,
        encoded + b"\n",
        description="token output",
        strict_parent=True,
    )


def _agent_enroll_create(
    args: argparse.Namespace,
    *,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    config = AppConfig.from_env()
    _authorize_local_admin(config)
    agents, board = _services(config)
    board.initialize()
    issued = agents.create_enrollment(
        name_prefix=args.name_prefix,
        description=args.description,
        uses=args.uses,
        ttl_seconds=args.ttl_seconds,
        reason=args.reason,
    )
    del stdout
    if issued.token is None:
        raise ConfigurationError("enrollment token was not issued")
    _write_enrollment_token(args.token_output, issued.token)
    enrollment = issued.enrollment
    stderr.write(
        f"minted enrollment {enrollment.id} for names under "
        f"{enrollment.name_prefix!r}; {enrollment.uses_allowed} use(s), expires "
        f"{enrollment.expires_at.isoformat()}; the token will not be shown again\n"
    )
    return EXIT_OK


def _agent_enroll_list(
    args: argparse.Namespace,
    *,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    del args, stderr
    config = AppConfig.from_env()
    _authorize_local_admin(config)
    agents, board = _services(config)
    board.initialize()
    payload = [
        {
            "id": enrollment.id,
            "name_prefix": enrollment.name_prefix,
            "name_match": enrollment.name_match,
            "status": enrollment.status,
            "uses_allowed": enrollment.uses_allowed,
            "uses_remaining": enrollment.uses_remaining,
            "created_at": enrollment.created_at.isoformat(),
            "expires_at": enrollment.expires_at.isoformat(),
            "last_redeemed_at": (
                enrollment.last_redeemed_at.isoformat()
                if enrollment.last_redeemed_at is not None
                else None
            ),
        }
        for enrollment in agents.list_enrollments()
    ]
    stdout.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n")
    return EXIT_OK


def _agent_enroll_revoke(
    args: argparse.Namespace,
    *,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    del stdout
    config = AppConfig.from_env()
    _authorize_local_admin(config)
    agents, board = _services(config)
    board.initialize()
    enrollment = agents.revoke_enrollment(args.enrollment_id, reason=args.reason)
    stderr.write(f"revoked enrollment {enrollment.id}\n")
    return EXIT_OK


def _write_credential_secret(path: Path, secret: str) -> None:
    parsed = parse_credential(secret)
    try:
        encoded = secret.encode("ascii")
    except UnicodeError as error:
        raise ConfigurationError("credential secret has an invalid format") from error
    if (
        parsed is None
        or parsed[0] != "sb1"
        or parsed[1] is None
        or len(encoded) != 70
    ):
        raise ConfigurationError("credential secret has an invalid format")
    _write_protected_file(
        path,
        encoded + b"\n",
        description="credential output",
        strict_parent=True,
    )


def _effective_uid() -> int | None:
    return os.geteuid() if hasattr(os, "geteuid") else None


def _require_output_parent(
    path: Path,
    *,
    description: str,
    strict_parent: bool,
    effective_uid: int | None,
) -> None:
    try:
        parent_metadata = path.parent.stat(follow_symlinks=False)
    except OSError as error:
        raise ConfigurationError(f"{description} parent directory must exist") from error
    if not stat.S_ISDIR(parent_metadata.st_mode):
        raise ConfigurationError(f"{description} parent directory must exist")
    if strict_parent and effective_uid is not None and (
        parent_metadata.st_uid != effective_uid
        or (parent_metadata.st_mode & 0o022)
    ):
        raise ConfigurationError(f"{description} parent directory is not protected")


def _exclusive_create_flags() -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _require_fresh_output_descriptor(
    metadata: os.stat_result,
    effective_uid: int | None,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (effective_uid is not None and metadata.st_uid != effective_uid)
    ):
        raise OSError("created output descriptor is unsafe")


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("protected output write did not progress")
        view = view[written:]


def _require_unchanged_output(
    descriptor: int,
    path: Path,
    created_identity: tuple[int, int],
) -> None:
    metadata = os.fstat(descriptor)
    current = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (metadata.st_dev, metadata.st_ino) != created_identity
        or (current.st_dev, current.st_ino) != created_identity
    ):
        raise OSError("protected output changed during creation")


def _create_protected_content(
    path: Path,
    content: bytes,
    *,
    effective_uid: int | None,
) -> tuple[int, int]:
    """Exclusively create and fill the file; on failure remove only our own file."""
    descriptor = os.open(path, _exclusive_create_flags(), 0o600)
    created_identity: tuple[int, int] | None = None
    try:
        metadata = os.fstat(descriptor)
        created_identity = (metadata.st_dev, metadata.st_ino)
        _require_fresh_output_descriptor(metadata, effective_uid)
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        _write_all(descriptor, content)
        os.fsync(descriptor)
        _require_unchanged_output(descriptor, path, created_identity)
    except BaseException:
        os.close(descriptor)
        _unlink_if_same_file(path, created_identity)
        raise
    os.close(descriptor)
    return created_identity


def _write_protected_file(
    path: Path,
    content: bytes,
    *,
    description: str,
    strict_parent: bool,
) -> None:
    if not path.is_absolute():
        raise ConfigurationError(f"{description} path must be absolute")
    effective_uid = _effective_uid()
    _require_output_parent(
        path,
        description=description,
        strict_parent=strict_parent,
        effective_uid=effective_uid,
    )
    try:
        created_identity = _create_protected_content(
            path, content, effective_uid=effective_uid,
        )
        try:
            _fsync_directory(path.parent)
        except OSError:
            _unlink_if_same_file(path, created_identity)
            raise
    except FileExistsError as error:
        raise ConfigurationError(
            f"{description} path already exists"
        ) from error
    except (OSError, UnicodeError) as error:
        raise ConfigurationError(
            f"{description} could not be created safely"
        ) from error


def _unlink_if_same_file(path: Path, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    try:
        current = path.stat(follow_symlinks=False)
        if (current.st_dev, current.st_ino) != identity:
            return
        os.unlink(path)
    except (FileNotFoundError, OSError):
        return


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _agent_list(
    args: argparse.Namespace,
    *,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    del args, stderr
    config = AppConfig.from_env()
    _authorize_local_admin(config)
    agents, _ = _services(config)
    agents.initialize()
    payload = []
    after_name = None
    while True:
        page = agents.list_managed_agents(
            after_name=after_name, limit=200, require_access=False,
        )
        payload.extend(
            {**_agent_payload(agent), "state": agent.state,
             "blocked_at": None if agent.blocked_at is None else agent.blocked_at.isoformat()}
            for agent in page
        )
        if len(page) < 200:
            break
        after_name = page[-1].name
    stdout.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n")
    return EXIT_OK


def _agent_revoke(
    args: argparse.Namespace,
    *,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    del stderr
    config = AppConfig.from_env()
    _authorize_local_admin(config)
    agents, board = _services(config)
    board.initialize()
    revoked = agents.revoke_agent_by_name(
        args.name,
        actor_type="local-admin",
        actor_id="local-cli",
    )
    stdout.write(
        json.dumps(
            {"id": revoked.id, "name": revoked.name, "revoked": True},
            ensure_ascii=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    return EXIT_OK


def _agent_recover(
    args: argparse.Namespace,
    *,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    del stdout
    config = AppConfig.from_env()
    _authorize_local_admin(config)
    agents, board = _services(config)
    board.initialize()
    issued = agents.recover_agent(
        args.name,
        request_id=str(uuid.uuid4()),
        expected_credential_epoch=args.expected_credential_epoch,
        reason=args.reason,
        actor_type="local-admin",
        actor_id="local-cli",
    )
    if issued.secret is None:
        raise ConfigurationError("recovery credential secret is unavailable")
    _write_credential_secret(args.credential_output, issued.secret)
    stderr.write(
        f"recovered credentials for {args.name}; pending credential "
        f"{issued.credential.id} was written to the protected output file\n"
    )
    return EXIT_OK


def _agent_credential_evidence_verify(
    args: argparse.Namespace,
    *,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    del stdout
    config = AppConfig.from_env()
    _authorize_local_admin(config)
    agents, board = _services(config)
    board.initialize()
    agent = agents.get_active_agent_by_name(args.name)
    credential = agents.get_credential(agent.name, args.credential_id)
    if (
        credential.status != "active"
        or credential.activated_at is None
        or credential.identity_verified_at is None
    ):
        raise ConfigurationError("exact credential is not active and identity-proved")
    _write_credential_receipt(
        args.receipt_path,
        operation_id=args.operation_id,
        agent=agent,
        credential=credential,
    )
    stderr.write(
        f"verified credential {credential.id} for {agent.name}; "
        "operation-bound receipt created\n"
    )
    return EXIT_OK


def _agent_credential_evidence_revoke(
    args: argparse.Namespace,
    *,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    del stdout
    config = AppConfig.from_env()
    _authorize_local_admin(config)
    agents, board = _services(config)
    board.initialize()
    agent = agents.get_active_agent_by_name(args.name)
    target = agents.get_credential(agent.name, args.credential_id)
    if target.status != "revoked":
        agents.revoke_credential(
            agent.name,
            target.id,
            request_id=str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"strugglebus:credential-evidence:{args.operation_id}",
                )
            ),
            expected_credential_epoch=agent.credential_epoch,
            expected_credential_version=target.version,
            reason=args.reason,
            actor_type="local-admin",
            actor_id="local-cli",
        )
    verified = agents.get_credential(agent.name, target.id)
    if verified.status != "revoked" or verified.revoked_at is None:
        raise ConfigurationError("exact credential revocation could not be verified")
    _write_credential_receipt(
        args.receipt_path,
        operation_id=args.operation_id,
        agent=agents.get_active_agent_by_name(agent.name),
        credential=verified,
    )
    stderr.write(
        f"revoked credential {verified.id} for {agent.name}; "
        "operation-bound receipt created\n"
    )
    return EXIT_OK


def _write_credential_receipt(
    path: Path,
    *,
    operation_id: str,
    agent: Agent,
    credential: AgentCredential,
) -> None:
    if credential.version < 1:
        raise ConfigurationError("credential evidence version is stale")
    if credential.status == "active":
        outcome = "proved"
        observed = credential.identity_verified_at
    elif credential.status == "revoked":
        outcome = "revoked"
        observed = credential.revoked_at
    else:
        raise ConfigurationError("credential evidence state is invalid")
    if observed is None:
        raise ConfigurationError("credential evidence time is unavailable")
    payload = {
        "version": 1,
        "operation_id": operation_id,
        "agent_name": agent.name,
        "credential_id": credential.id,
        "outcome": outcome,
        "credential_status": credential.status,
        "credential_version": credential.version,
        "observed_at": _rfc3339_utc(observed),
    }
    encoded = (
        json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")
    _write_atomic_receipt(path, encoded)


def _rfc3339_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _link_receipt(temporary: Path, path: Path) -> None:
    try:
        os.link(temporary, path, follow_symlinks=False)
    except FileExistsError as error:
        raise ConfigurationError("receipt path already exists") from error


def _require_linked_receipt(path: Path, identity: tuple[int, int]) -> None:
    target = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(target.st_mode)
        or (target.st_dev, target.st_ino) != identity
    ):
        raise ConfigurationError("receipt could not be created safely")


def _require_published_receipt(path: Path, identity: tuple[int, int]) -> None:
    final = path.stat(follow_symlinks=False)
    effective_uid = _effective_uid()
    if (
        not stat.S_ISREG(final.st_mode)
        or final.st_nlink != 1
        or (final.st_dev, final.st_ino) != identity
        or (effective_uid is not None and final.st_uid != effective_uid)
        or (effective_uid is not None and final.st_mode & 0o077)
    ):
        raise ConfigurationError("receipt could not be created safely")


def _write_atomic_receipt(path: Path, content: bytes) -> None:
    if not path.is_absolute():
        raise ConfigurationError("receipt path must be absolute")
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    linked = False
    published = False
    temporary_identity: tuple[int, int] | None = None
    try:
        _write_protected_file(
            temporary,
            content,
            description="receipt",
            strict_parent=True,
        )
        temporary_identity = _file_identity(temporary)
        _link_receipt(temporary, path)
        linked = True
        _require_linked_receipt(path, temporary_identity)
        _unlink_if_same_file(temporary, temporary_identity)
        _require_published_receipt(path, temporary_identity)
        _fsync_directory(path.parent)
        published = True
    except OSError as error:
        raise ConfigurationError("receipt could not be created safely") from error
    finally:
        _unlink_if_same_file(temporary, _file_identity_or_none(temporary))
        if linked and not published:
            _unlink_if_same_file(path, temporary_identity)
        if linked:
            _fsync_directory(path.parent)


def _file_identity(path: Path) -> tuple[int, int]:
    metadata = path.stat(follow_symlinks=False)
    return metadata.st_dev, metadata.st_ino


def _file_identity_or_none(path: Path) -> tuple[int, int] | None:
    try:
        return _file_identity(path)
    except OSError:
        return None


def _agent_payload(agent: Agent) -> dict[str, object]:
    return {
        "id": agent.id,
        "name": agent.name,
        "credential_epoch": agent.credential_epoch,
        "description": agent.description,
        "host": agent.host,
        "created_at": agent.created_at.isoformat(),
        "last_seen_at": (
            None if agent.last_seen_at is None else agent.last_seen_at.isoformat()
        ),
    }


def _access_freeze_payload(
    state,
    *,
    changed: bool | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "frozen": state.frozen,
        "transition": state.transition,
        "changed_at": (
            None if state.changed_at is None else state.changed_at.isoformat()
        ),
        "reason": state.reason,
    }
    if changed is not None:
        payload["changed"] = changed
    return payload


def _write_json(stdout: TextIO, payload: object) -> None:
    stdout.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n")


def _access_freeze_status(
    args: argparse.Namespace,
    *,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    del args, stderr
    config = AppConfig.from_env()
    _authorize_local_admin(config)
    access = _access_freeze(config)
    _write_json(stdout, _access_freeze_payload(access.operator_status()))
    return EXIT_OK


def _access_freeze_activate(
    args: argparse.Namespace,
    *,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    del stderr
    config = AppConfig.from_env()
    _authorize_local_admin(config)
    access = _access_freeze(config)
    state, changed = access.operator_freeze(args.reason)
    _write_json(stdout, _access_freeze_payload(state, changed=changed))
    return EXIT_OK


def _access_freeze_clear(
    args: argparse.Namespace,
    *,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    del stderr
    config = AppConfig.from_env()
    _authorize_local_admin(config)
    access = _access_freeze(config)
    state, changed = access.operator_unfreeze(args.reason)
    _write_json(stdout, _access_freeze_payload(state, changed=changed))
    return EXIT_OK


def _is_safe_url_text(value: object) -> bool:
    return isinstance(value, str) and value.isascii() and not any(
        ord(character) < 33 or ord(character) == 127 for character in value
    )


def _has_credentials_or_resource(parsed) -> bool:
    """True when the URL carries more than scheme, host and port."""
    return bool(
        parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    )


def _is_bare_http_origin(parsed, hostname: str | None) -> bool:
    return not (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or hostname is None
        or _has_credentials_or_resource(parsed)
    )


def _split_url(value: str):
    try:
        parsed = urlsplit(value)
        return parsed, parsed.hostname, parsed.port
    except ValueError as error:
        raise ConfigurationError("URL must be a valid HTTP(S) origin") from error


def _base_url(config: AppConfig, override: str | None) -> str:
    value = config.public_base_url if override is None else override
    if not _is_safe_url_text(value):
        raise ConfigurationError("URL must be a safe ASCII HTTP(S) origin")
    parsed, hostname, port = _split_url(value)
    if not _is_bare_http_origin(parsed, hostname):
        raise ConfigurationError("URL must be an HTTP(S) origin without credentials")
    if port is not None and not 1 <= port <= 65_535:
        raise ConfigurationError("URL port must be between 1 and 65535")
    if parsed.scheme != "https" and hostname not in {
        "127.0.0.1",
        "::1",
        "localhost",
    }:
        raise ConfigurationError("remote URL must use HTTPS")
    return value.rstrip("/")


def _ssl_context(ca_file: Path | None) -> ssl.SSLContext:
    if ca_file is None:
        configured = os.environ.get("STRUGGLEBUS_CA_FILE")
        ca_file = None if configured is None else Path(configured)
    try:
        return ssl.create_default_context(
            cafile=None if ca_file is None else str(ca_file.resolve(strict=True))
        )
    except (OSError, ssl.SSLError) as error:
        raise ConfigurationError("CA file is unavailable or invalid") from error


def _open(request: Request, *, timeout: float, context: ssl.SSLContext):
    try:
        opener = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=context),
            _NoRedirectHandler(),
        )
        return opener.open(request, timeout=timeout)
    except HTTPError:
        raise
    except (OSError, TimeoutError, URLError, ssl.SSLError) as error:
        raise _NetworkFailure("network request failed") from error


def _health(
    args: argparse.Namespace,
    *,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    del stderr
    config = AppConfig.from_env()
    deadline = time.monotonic() + args.timeout
    request = Request(
        f"{_base_url(config, args.url)}/healthz",
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with _open(
            request,
            timeout=args.timeout,
            context=_ssl_context(args.ca_file),
        ) as response:
            body = _read_health_body(response, deadline)
    except HTTPError as error:
        if error.code in {401, 403}:
            raise _AuthenticationFailure("health authentication failed") from None
        raise _ServerFailure("health endpoint returned an error") from None
    except (OSError, TimeoutError, URLError, ssl.SSLError) as error:
        raise _NetworkFailure("network request failed") from error
    if len(body) > MAX_HEALTH_RESPONSE_BYTES:
        raise _ServerFailure("health response exceeded the configured bound")
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _ServerFailure("health endpoint returned invalid JSON") from error
    if payload != {"status": "ok"}:
        raise _ServerFailure("service is not ready")
    stdout.write('{"status":"ok"}\n')
    return EXIT_OK


def _read_health_body(response: BinaryIO, deadline: float) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total <= MAX_HEALTH_RESPONSE_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _NetworkFailure("health request timed out")
        fp = getattr(response, "fp", None)
        raw = getattr(fp, "raw", None)
        sock = getattr(raw, "_sock", None)
        if sock is not None:
            sock.settimeout(remaining)
        read = getattr(response, "read1", response.read)
        chunk = read(min(4096, MAX_HEALTH_RESPONSE_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _read_bounded(response: BinaryIO, limit: int) -> bytes:
    body = response.read(limit + 1)
    if len(body) > limit:
        raise _ServerFailure("server response exceeded the configured bound")
    return body


def _read_api_key_file(path: Path) -> bytes:
    """Read at most one byte beyond the limit from a safely owned regular file."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ConfigurationError("agent API key file is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ConfigurationError("agent API key path must be a regular file")
        if os.name == "posix" and (
            metadata.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
        ):
            raise ConfigurationError(
                "agent API key file has unsafe ownership or permissions"
            )
        return os.read(descriptor, 4097)
    except OSError as error:
        raise ConfigurationError("agent API key file is unreadable") from error
    finally:
        os.close(descriptor)


def _api_key_from_file(path: Path) -> str:
    if not path.is_absolute():
        raise ConfigurationError("agent API key file path must be absolute")
    key = _read_api_key_file(path).rstrip(b"\r\n")
    if not key or len(key) > 4096:
        raise ConfigurationError(
            "agent API key file must contain between 1 and 4096 bytes"
        )
    try:
        return _validate_api_key(key.decode("utf-8"))
    except UnicodeDecodeError as error:
        raise ConfigurationError("agent API key file must contain UTF-8 text") from error


def _read_api_key(environment: Mapping[str, str]) -> str:
    key_file = environment.get("STRUGGLEBUS_API_KEY_FILE")
    key_value = environment.get("STRUGGLEBUS_API_KEY")
    if key_file is not None and key_value is not None:
        raise ConfigurationError(
            "configure exactly one of STRUGGLEBUS_API_KEY_FILE or "
            "STRUGGLEBUS_API_KEY"
        )
    if key_file is None:
        if key_value is None or not key_value or len(key_value) > 4096:
            raise ConfigurationError("agent API key is not configured")
        return _validate_api_key(key_value)
    return _api_key_from_file(Path(key_file))


def _validate_api_key(value: str) -> str:
    if not value.isascii() or any(
        not (character.isalnum() or character in {"-", "_"})
        for character in value
    ):
        raise ConfigurationError("agent API key has an invalid format")
    return value


@dataclass(slots=True)
class _PendingSseEvent:
    """Fields accumulated for the SSE event currently being read."""

    event_id: str | None = None
    event_type: str = "message"
    data: list[str] = field(default_factory=list)
    data_bytes: int = 0

    def add_field(self, line: str, raw_length: int) -> None:
        name, separator, value = line.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if name == "id" and "\x00" not in value:
            self.event_id = value
        elif name == "event":
            self.event_type = value
        elif name == "data":
            self.data_bytes += raw_length
            if self.data_bytes > MAX_SSE_LINE_BYTES:
                raise _ServerFailure("SSE event exceeded the configured bound")
            self.data.append(value)


def _decode_sse_line(raw_line: bytes) -> str:
    try:
        return raw_line.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as error:
        raise _ServerFailure("SSE stream was not valid UTF-8") from error


def _iter_sse(response: BinaryIO) -> Iterator[tuple[str | None, str, str]]:
    event = _PendingSseEvent()
    while True:
        raw_line = response.readline(MAX_SSE_LINE_BYTES + 1)
        if len(raw_line) > MAX_SSE_LINE_BYTES:
            raise _ServerFailure("SSE line exceeded the configured bound")
        if not raw_line:
            return
        line = _decode_sse_line(raw_line)
        if not line:
            if event.data:
                yield event.event_id, event.event_type, "\n".join(event.data)
            event = _PendingSseEvent()
            continue
        if line.startswith(":"):
            yield None, "_comment", ""
            continue
        event.add_field(line, len(raw_line))


def _read_resume(path: Path | None) -> int:
    if path is None:
        return 0
    if not path.is_absolute():
        raise ConfigurationError("resume file path must be absolute")
    if not path.exists():
        return 0
    try:
        value = int(path.read_text(encoding="ascii").strip())
    except (OSError, UnicodeError, ValueError) as error:
        raise ConfigurationError("resume file does not contain a valid sequence") from error
    if not 0 <= value <= MAX_SEQUENCE:
        raise ConfigurationError("resume sequence is outside the supported range")
    return value


def _write_resume(path: Path | None, sequence: int) -> None:
    if path is None:
        return
    if not path.is_absolute():
        raise ConfigurationError("resume file path must be absolute")
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.tmp-",
            dir=path.parent,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="ascii") as handle:
                handle.write(f"{sequence}\n")
            temporary.chmod(0o600)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    except OSError as error:
        raise ConfigurationError("resume file could not be updated") from error


@dataclass(slots=True)
class _TailProgress:
    """Where the tail is in the stream and how reconnecting is going."""

    cursor: int
    emitted: int = 0
    failures: int = 0
    delay: float = 0.25

    def reset_backoff(self) -> None:
        self.failures = 0
        self.delay = 0.25


def _expected_tail_identity(args: argparse.Namespace) -> tuple[str, str]:
    expected_agent_id = (
        args.expected_agent_id
        or os.environ.get("STRUGGLEBUS_EXPECTED_AGENT_ID")
    )
    expected_agent_name = (
        args.expected_agent_name
        or os.environ.get("STRUGGLEBUS_EXPECTED_AGENT_NAME")
    )
    if not expected_agent_id or not expected_agent_name:
        raise ConfigurationError(
            "tail requires expected agent ID and name via flags or environment"
        )
    return expected_agent_id, expected_agent_name


def _stream_request(base_url: str, api_key: str, *, since: int, cursor: int) -> Request:
    query = urlencode({"since": since})
    headers = {
        "Accept": "text/event-stream",
        "Authorization": f"Bearer {api_key}",
    }
    if cursor:
        headers["Last-Event-ID"] = str(cursor)
    return Request(
        f"{base_url}/api/stream?{query}",
        headers=headers,
        method="GET",
    )


def _reject_access_event(event_type: str, data: str) -> None:
    """Stop the tail when the server reports that agent access has ended."""
    if event_type == "agent_access_frozen":
        if data != '{"detail":"agent access is frozen"}':
            raise _ServerFailure(
                "access-freeze event contained an invalid payload"
            )
        raise _AuthenticationFailure("agent access is frozen")
    if event_type == "agent_access_unavailable":
        raise _ServerFailure("agent access is unavailable")


def _message_sequence(event_id: str | None) -> int:
    if event_id is None:
        raise _ServerFailure("message event did not include an ID")
    try:
        sequence = int(event_id)
    except ValueError as error:
        raise _ServerFailure("message event ID was invalid") from error
    if not 0 <= sequence <= MAX_SEQUENCE:
        raise _ServerFailure("message event ID was outside the valid range")
    return sequence


def _message_payload(data: str, sequence: int) -> dict[str, object]:
    try:
        payload = json.loads(data)
    except json.JSONDecodeError as error:
        raise _ServerFailure("message event contained invalid JSON") from error
    if not isinstance(payload, dict):
        raise _ServerFailure("message event JSON was not an object")
    if payload.get("seq") != sequence:
        raise _ServerFailure(
            "message event ID did not match its payload"
        )
    return payload


def _emit_message(stdout: TextIO, payload: dict[str, object]) -> None:
    try:
        stdout.write(
            json.dumps(
                payload,
                ensure_ascii=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        stdout.flush()
    except BrokenPipeError:
        raise _OutputClosed from None


def _consume_stream(
    response,
    progress: _TailProgress,
    *,
    max_events: int,
    resume_file: Path | None,
    stdout: TextIO,
) -> None:
    """Emit new messages from one connection until it ends or the limit is met."""
    content_type = response.headers.get_content_type()
    if content_type != "text/event-stream":
        raise _ServerFailure(
            "stream endpoint did not return an SSE response"
        )
    for event_id, event_type, data in _iter_sse(response):
        if event_type == "_comment":
            progress.reset_backoff()
            continue
        _reject_access_event(event_type, data)
        if event_type != "message":
            continue
        sequence = _message_sequence(event_id)
        if sequence <= progress.cursor:
            continue
        _emit_message(stdout, _message_payload(data, sequence))
        progress.cursor = sequence
        _write_resume(resume_file, progress.cursor)
        progress.emitted += 1
        progress.reset_backoff()
        if progress.emitted >= max_events:
            return
    progress.reset_backoff()


def _tail(
    args: argparse.Namespace,
    *,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    del stderr
    config = AppConfig.from_env()
    base_url = _base_url(config, args.url)
    context = _ssl_context(args.ca_file)
    api_key = _read_api_key(os.environ)
    expected_agent_id, expected_agent_name = _expected_tail_identity(args)
    _assert_expected_identity(
        base_url=base_url,
        api_key=api_key,
        expected_agent_id=expected_agent_id,
        expected_agent_name=expected_agent_name,
        timeout=args.timeout,
        context=context,
    )
    progress = _TailProgress(cursor=max(args.since, _read_resume(args.resume_file)))

    while progress.emitted < args.max_events:
        request = _stream_request(
            base_url, api_key, since=args.since, cursor=progress.cursor,
        )
        try:
            with _open(request, timeout=args.timeout, context=context) as response:
                _consume_stream(
                    response,
                    progress,
                    max_events=args.max_events,
                    resume_file=args.resume_file,
                    stdout=stdout,
                )
            if progress.emitted >= args.max_events:
                return EXIT_OK
        except HTTPError as error:
            if error.code in {401, 403}:
                raise _AuthenticationFailure("agent authentication failed") from None
            raise _ServerFailure("stream endpoint returned an error") from None
        except _NetworkFailure:
            progress.failures += 1
        except (OSError, TimeoutError, URLError, ssl.SSLError):
            progress.failures += 1

        if progress.failures > args.retries:
            raise _NetworkFailure("SSE reconnect limit exceeded")
        time.sleep(progress.delay)
        progress.delay = min(progress.delay * 2, 5.0)
    return EXIT_OK


def _fetch_identity(
    base_url: str,
    headers: Mapping[str, str],
    *,
    timeout: float,
    context: ssl.SSLContext,
) -> tuple[object, object]:
    """Return the agent and credential objects the server reports for this key."""
    request = Request(
        f"{base_url}/api/whoami",
        headers=dict(headers),
        method="GET",
    )
    try:
        with _open(request, timeout=timeout, context=context) as response:
            raw = _read_bounded(response, MAX_IDENTITY_RESPONSE_BYTES)
    except HTTPError as error:
        if error.code in {401, 403}:
            raise _AuthenticationFailure("agent authentication failed") from None
        raise _ServerFailure("identity endpoint returned an error") from None
    except (OSError, TimeoutError, URLError, ssl.SSLError):
        raise _NetworkFailure("identity endpoint was unavailable") from None
    try:
        payload = json.loads(raw)
        return payload["agent"], payload["credential"]
    except (json.JSONDecodeError, KeyError, TypeError):
        raise _ServerFailure("identity endpoint returned an invalid response") from None


def _prove_pending_credential(
    base_url: str,
    headers: Mapping[str, str],
    proof: bytes,
    *,
    timeout: float,
    context: ssl.SSLContext,
) -> None:
    proof_request = Request(
        f"{base_url}/api/credentials/prove",
        data=proof,
        headers={**headers, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with _open(proof_request, timeout=timeout, context=context) as response:
            result = json.loads(
                _read_bounded(response, MAX_IDENTITY_RESPONSE_BYTES)
            )
    except HTTPError as error:
        if error.code in {401, 403, 409}:
            raise _AuthenticationFailure("credential identity proof failed") from None
        raise _ServerFailure("identity proof endpoint returned an error") from None
    except (OSError, TimeoutError, URLError, ssl.SSLError):
        raise _NetworkFailure("identity proof endpoint was unavailable") from None
    except json.JSONDecodeError:
        raise _ServerFailure("identity proof endpoint returned invalid JSON") from None
    if not isinstance(result, dict) or result.get("status") != "active":
        raise _AuthenticationFailure("credential identity proof failed")


def _require_plausible_expected_identity(
    expected_agent_id: str,
    expected_agent_name: str,
) -> None:
    if (
        len(expected_agent_id) > 128
        or len(expected_agent_name) > 128
        or "\x00" in expected_agent_id
        or "\x00" in expected_agent_name
    ):
        raise ConfigurationError("expected agent identity is invalid")


def _assert_expected_identity(
    *,
    base_url: str,
    api_key: str,
    expected_agent_id: str,
    expected_agent_name: str,
    timeout: float,
    context: ssl.SSLContext,
) -> None:
    _require_plausible_expected_identity(expected_agent_id, expected_agent_name)
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    agent, credential = _fetch_identity(
        base_url, headers, timeout=timeout, context=context,
    )
    if (
        not isinstance(agent, dict)
        or agent.get("id") != expected_agent_id
        or agent.get("name") != expected_agent_name
    ):
        raise _AuthenticationFailure("authenticated agent identity mismatch")
    status_value = credential.get("status") if isinstance(credential, dict) else None
    if status_value == "active":
        return
    if status_value != "pending":
        raise _AuthenticationFailure("authenticated credential is inactive")
    proof = json.dumps(
        {
            "request_id": str(uuid.uuid4()),
            "expected_agent_id": expected_agent_id,
            "expected_agent_name": expected_agent_name,
            "expected_credential_epoch": agent.get("credential_epoch"),
            "expected_credential_version": credential.get("version"),
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    _prove_pending_credential(
        base_url, headers, proof, timeout=timeout, context=context,
    )


def _backup(
    args: argparse.Namespace,
    *,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    del stderr
    config = AppConfig.from_env()
    database = config.database_path if args.database is None else args.database
    destination = config.backup_dir if args.destination is None else args.destination
    if not database.is_absolute() or not destination.is_absolute():
        raise ConfigurationError("backup paths must be absolute")
    backup_path = create_verified_backup(
        database,
        destination,
        retention=args.retention,
    )
    stdout.write(f"{backup_path}\n")
    return EXIT_OK


def _selfhost_files() -> Path:
    return Path(__file__).resolve().parent / "selfhost"


def _selfhost_guide(args: argparse.Namespace, *, stdout: TextIO, stderr: TextIO) -> int:
    del args, stderr
    stdout.write((_selfhost_files() / "INSTALL.md").read_text(encoding="utf-8"))
    return EXIT_OK


def _selfhost_export(args: argparse.Namespace, *, stdout: TextIO, stderr: TextIO) -> int:
    """Copy the install files out of the package, never over existing files."""

    del stderr
    import shutil

    target = args.directory.absolute()
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise ConfigurationError(f"export folder must be new or empty: {target}")
    shutil.copytree(
        _selfhost_files(), target, dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    stdout.write(f"{target}\n")
    return EXIT_OK


def _satellite_join(args: argparse.Namespace, *, stdout: TextIO, stderr: TextIO) -> int:
    from strugglebus import satellite_client

    satellite_client.join(satellite_client.state_dir())
    return EXIT_OK


def _satellite_run(args: argparse.Namespace, *, stdout: TextIO, stderr: TextIO) -> int:
    import asyncio

    from strugglebus import satellite_client

    proxy = satellite_client.Satellite(satellite_client.state_dir(), args.port)
    return asyncio.run(proxy.serve())


def _satellite_link(args: argparse.Namespace, *, stdout: TextIO, stderr: TextIO) -> int:
    from strugglebus import satellite_client

    satellite_client.link_agent(
        args.name, port=args.port, description=args.description, write=args.write,
    )
    return EXIT_OK


def _satellite_install_task(
    args: argparse.Namespace, *, stdout: TextIO, stderr: TextIO,
) -> int:
    from strugglebus import satellite_client

    satellite_client.install_task(satellite_client.state_dir(), args.port)
    return EXIT_OK


def _run_handler(
    handler,
    args: argparse.Namespace,
    *,
    output: TextIO,
    diagnostics: TextIO,
) -> int:
    """Run one command and turn each expected failure into its exit code."""
    try:
        return handler(args, stdout=output, stderr=diagnostics)
    except ConfigurationError as error:
        diagnostics.write(f"configuration error: {error}\n")
        return EXIT_CONFIG
    except _AuthenticationFailure as error:
        diagnostics.write(f"authentication error: {error}\n")
        return EXIT_AUTH
    except _NetworkFailure as error:
        diagnostics.write(f"network error: {error}\n")
        return EXIT_NETWORK
    except (AgentNotFoundError, StrugglebusError, _ServerFailure) as error:
        diagnostics.write(f"server error: {error}\n")
        return EXIT_SERVER
    except KeyboardInterrupt:
        diagnostics.write("interrupted\n")
        return EXIT_INTERRUPTED
    except _OutputClosed:
        _silence_broken_stdout(output)
        return EXIT_OK


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    output = sys.stdout if stdout is None else stdout
    diagnostics = sys.stderr if stderr is None else stderr
    parser = _parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser.redact_errors = arguments[:2] == ["operator", "password"]
    args = parser.parse_args(arguments)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help(output)
        return EXIT_OK
    return _run_handler(handler, args, output=output, diagnostics=diagnostics)


def _silence_broken_stdout(output: TextIO) -> None:
    if output is not sys.stdout:
        return
    try:
        descriptor = output.fileno()
        devnull = os.open(os.devnull, os.O_WRONLY)
    except (AttributeError, io.UnsupportedOperation, OSError):
        return
    try:
        os.dup2(devnull, descriptor)
    finally:
        os.close(devnull)
