#!/usr/bin/python3
"""Run a disposable production acceptance smoke with secret-safe diagnostics."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager, closing, contextmanager
from datetime import UTC, datetime
import html
import hashlib
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from importlib.metadata import version
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import ssl
import sys
import tempfile
import time
import uuid
import warnings
from typing import Any, TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    import httpx2 as httpx
    from mcp import ClientSession


PHASES = (
    "candidate_contract",
    "operator_authority",
    "enrollment",
    "credential_proof",
    "roe_receipt",
    "identity",
    "channel_subscription",
    "mcp_post_rest_read",
    "rest_reply_mcp_read",
    "sse_resume",
    "dashboard_safety",
    "revocation",
    "rest_denial",
    "mcp_denial",
)
CLEANUP_PHASES = ("helper_cleanup", "ansible_always_cleanup")
ALL_PHASES = PHASES + CLEANUP_PHASES
ERROR_CODES = {
    "none",
    "authentication",
    "operator_logout_failed",
    "cleanup_refused",
    "cleanup_failed",
    "artifact_cleanup_refused",
    "containment_unknown",
    "connection",
    "http_status",
    "injected_failure",
    "invalid_configuration",
    "invalid_response",
    "mcp_status",
    "phase_failed",
    "result_write_failed",
    "unexpected_error",
}
STATUS_CATEGORIES = {
    "cleanup_zero",
    "denied",
    "failed",
    "http_2xx",
    "ok",
    "not_applicable",
}
MARKER_VERSION = "strugglebus-disposable-smoke-v2"
HOST_MARKER = "disposable-smoke.invalid"
ENROLLMENT_REASON = "disposable smoke enrollment"
PHASE_TIMEOUT_SECONDS = 60
# Schema versions whose agent-table layout this smoke's containment and
# cleanup logic is known to handle. Schemas 13-15 leave every agent table
# untouched. Schema 16 retains keyed posts (schema 23: until the operator's
# retention period has passed): cleanup must refuse
# keyed artifacts before containment or artifact mutation, not bypass guards.
CLEANUP_SCHEMA_VERSIONS = {11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
SESSION_ROOT = Path("/run")
SESSION_COOKIE = "__Host-strugglebus-operator"
LOGIN_COOKIE = "__Host-strugglebus-login"
SESSION_FIELDS = {
    "version", "origin", "ca_path", "ca_sha256", "token", "csrf", "actor_id",
    "issued_at", "expires_at",
}
MAX_RESULT_BYTES = 16_384
DASHBOARD_CSP = (
    "default-src 'none'; style-src 'self'; script-src 'none'; "
    "connect-src 'none'; img-src 'none'; font-src 'none'; "
    "object-src 'none'; base-uri 'none'; form-action 'self'; "
    "frame-ancestors 'none'"
)


class SmokeError(Exception):
    """An expected, safely classified smoke failure."""

    def __init__(self, error_code: str, status_category: str = "failed") -> None:
        if error_code not in ERROR_CODES or status_category not in STATUS_CATEGORIES:
            raise ValueError("smoke error classification is not allowlisted")
        self.error_code = error_code
        self.status_category = status_category
        super().__init__(error_code)


def _atomic_json(path: Path, value: object) -> None:
    encoded = (
        json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    if len(encoded) > MAX_RESULT_BYTES:
        raise SmokeError("result_write_failed")
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        for attempt in range(5):
            try:
                os.replace(temporary, path)
                break
            except PermissionError:
                if os.name != "nt" or attempt == 4:
                    raise
                time.sleep(0.01 * (attempt + 1))
        path.chmod(0o600)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _result(
    phase: str,
    *,
    passed: bool,
    status_category: str,
    shape_matches: bool,
    count_matches: bool,
    error_code: str,
) -> dict[str, object]:
    if (
        phase not in ALL_PHASES
        or status_category not in STATUS_CATEGORIES
        or error_code not in ERROR_CODES
        or any(type(value) is not bool for value in (passed, shape_matches, count_matches))
    ):
        raise SmokeError("result_write_failed")
    return {
        "phase": phase,
        "passed": passed,
        "status_category": status_category,
        "shape_matches": shape_matches,
        "count_matches": count_matches,
        "error_code": error_code,
    }


def _read_input() -> dict[str, Any]:
    raw = sys.stdin.read(64 * 1024 + 1)
    if len(raw.encode("utf-8")) > 64 * 1024:
        raise SmokeError("invalid_configuration")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise SmokeError("invalid_configuration") from error
    if not isinstance(value, dict):
        raise SmokeError("invalid_configuration")
    return value


def _read_configuration(value: dict[str, Any]) -> dict[str, str]:
    expected = {
        "admin_credential_path",
        "base_url",
        "ca_path",
        "database_path",
        "expected_release_id",
        "release_environment_path",
        "work_dir",
    }
    if set(value) not in (expected, expected | {"operator_session_path"}):
        raise SmokeError("invalid_configuration")
    if not all(isinstance(value[key], str) and value[key] for key in expected):
        raise SmokeError("invalid_configuration")
    url = urlsplit(value["base_url"])
    if (
        url.scheme != "https" or not url.hostname or url.username or url.password
        or url.path not in {"", "/"} or url.query or url.fragment
        or re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", value["expected_release_id"]) is None
    ):
        raise SmokeError("invalid_configuration")
    if "operator_session_path" in value and not isinstance(value["operator_session_path"], str):
        raise SmokeError("invalid_configuration")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = {}
    for name, item in pairs:
        if name in value:
            raise SmokeError("invalid_configuration")
        value[name] = item
    return value


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        not value.isascii() or parsed.scheme != "https" or not parsed.hostname
        or parsed.username or parsed.password or parsed.path not in {"", "/"}
        or parsed.query or parsed.fragment
    ):
        raise SmokeError("invalid_configuration")
    return value.rstrip("/")


def _ca_bytes(path: Path) -> bytes:
    if os.name != "posix" or not path.is_absolute():
        raise SmokeError("authentication")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o022 or metadata.st_size > 256 * 1024
        ):
            raise SmokeError("authentication")
        raw = stream.read(256 * 1024 + 1)
    if not raw or len(raw) > 256 * 1024:
        raise SmokeError("authentication")
    return raw


def _ca_digest(path: Path) -> str:
    return hashlib.sha256(_ca_bytes(path)).hexdigest()


def _ca_context(path: Path, digest: str):
    raw = _ca_bytes(path)
    if hashlib.sha256(raw).hexdigest() != digest:
        raise SmokeError("authentication")
    return ssl.create_default_context(cadata=raw.decode("ascii"))


class _Form(HTMLParser):
    def __init__(self, text: str, action: str):
        super().__init__(convert_charrefs=True)
        self.action, self.active, self.found = action, False, False
        self.fields: dict[str, str] = {}
        if len(text.encode("utf-8")) > 512 * 1024:
            raise SmokeError("invalid_response")
        self.feed(text)
        if not self.found:
            raise SmokeError("invalid_response")

    def handle_starttag(self, tag: str, attrs) -> None:
        values = dict(attrs)
        if tag == "form":
            self.active = values.get("action") == self.action
            if self.active:
                if self.found:
                    raise SmokeError("invalid_response")
                self.found = True
        elif self.active and tag == "input" and "name" in values:
            name = values["name"]
            if name in self.fields:
                raise SmokeError("invalid_response")
            self.fields[name] = values.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self.active = False


def _session_page(response) -> tuple[str, str]:
    if response.status_code != 200:
        raise SmokeError("authentication")
    csrf = _Form(response.text, "/logout").fields.get("csrf", "")
    actors = re.findall(r'<code id="operator-identity">([^<]+)</code>', response.text)
    if (
        re.fullmatch(r"[A-Za-z0-9_-]{43}", csrf) is None or len(actors) != 1
        or re.fullmatch(r"operator:owner:[0-9a-f]{32}", actors[0]) is None
    ):
        raise SmokeError("invalid_response")
    return csrf, actors[0]


def _validate_session(value: Any, *, allow_expired: bool = False) -> dict[str, Any]:
    if (
        not isinstance(value, dict) or set(value) != SESSION_FIELDS
        or type(value["version"]) is not int or value["version"] != 1
        or any(not isinstance(value[key], str) for key in SESSION_FIELDS - {
            "version", "issued_at", "expires_at",
        })
        or any(type(value[key]) is not int for key in ("issued_at", "expires_at"))
        or not 0 < value["expires_at"] - value["issued_at"] <= 28_800
        or value["issued_at"] > time.time() + 5
        or (not allow_expired and value["expires_at"] <= time.time())
        or any(re.fullmatch(r"[A-Za-z0-9_-]{43}", value[key]) is None for key in ("token", "csrf"))
        or re.fullmatch(r"operator:owner:[0-9a-f]{32}", value["actor_id"]) is None
        or re.fullmatch(r"[0-9a-f]{64}", value["ca_sha256"]) is None
        or not Path(value["ca_path"]).is_absolute()
    ):
        raise SmokeError("authentication")
    if _origin(value["origin"]) != value["origin"]:
        raise SmokeError("authentication")
    return value


def _read_operator_session(path: Path, *, allow_expired: bool = False) -> dict[str, Any]:
    if os.name != "posix":
        raise SmokeError("authentication")
    parent = path.parent
    metadata = parent.lstat()
    if (
        parent.parent != SESSION_ROOT or parent.resolve(strict=True) != parent
        or not parent.name.startswith("strugglebus-smoke-")
        or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise SmokeError("authentication")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1
            or metadata.st_size > 8192 or _file_identity(path) != (metadata.st_dev, metadata.st_ino)
        ):
            raise SmokeError("authentication")
        raw = stream.read(8193)
    if len(raw) > 8192:
        raise SmokeError("authentication")
    return _validate_session(
        json.loads(raw.decode("ascii"), object_pairs_hook=_unique_object),
        allow_expired=allow_expired,
    )


def _operator_client(session: dict[str, Any]):
    import httpx2

    return httpx2.AsyncClient(
        base_url=session["origin"],
        verify=_ca_context(Path(session["ca_path"]), session["ca_sha256"]),
        timeout=10, follow_redirects=False, trust_env=False,
        headers={
            "Cookie": f"{SESSION_COOKIE}={session['token']}",
            "Origin": session["origin"],
        },
    )


async def _logout_operator(path: Path) -> None:
    if not path.exists():
        return
    session = _read_operator_session(path, allow_expired=True)
    identity = _file_identity(path)
    async with _operator_client(session) as client:
        response = await client.post("/logout", data={"csrf": session["csrf"]})
    # A 401 proves this credential no longer authorizes the route. Freeze,
    # transport failure and rate limits are not proof of session revocation.
    if (
        response.status_code not in {303, 401}
        or (response.status_code == 303 and response.headers.get("location") != "/login")
        or _file_identity(path) != identity
    ):
        raise SmokeError("operator_logout_failed")
    path.unlink()


def _operator_password() -> str:
    import getpass

    if os.name != "posix" or os.geteuid() != 0 or not sys.stderr.isatty():
        raise SmokeError("authentication")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass("Dedicated operator password (not the admin token): ")
        except (getpass.GetPassWarning, EOFError):
            raise SmokeError("authentication") from None


def _password_client(origin: str, ca_path: Path, ca_sha256: str):
    import httpx2

    return httpx2.AsyncClient(
        base_url=origin, verify=_ca_context(ca_path, ca_sha256),
        timeout=10, trust_env=False, follow_redirects=False,
    )


async def prepare_operator_session(value: dict[str, Any]) -> dict[str, Any]:
    from strugglebus.operator_auth import OperatorFormError, password_bytes

    if set(value) != {"base_url", "ca_path"} or any(
        not isinstance(item, str) for item in value.values()
    ):
        raise SmokeError("invalid_configuration")
    origin = _origin(value["base_url"])
    ca_path = Path(value["ca_path"])
    ca_sha256 = _ca_digest(ca_path)
    async with _password_client(origin, ca_path, ca_sha256) as client:
        challenge = await client.get("/login")
        if challenge.status_code != 200:
            raise SmokeError("authentication")
        csrf = _Form(challenge.text, "/login").fields.get("csrf", "")
        if re.fullmatch(r"[A-Za-z0-9_-]{43}", csrf) is None:
            raise SmokeError("authentication")
        password = _operator_password()
        issued_at = int(time.time())
        try:
            try:
                password_bytes(password)
            except OperatorFormError:
                raise SmokeError("authentication") from None
            response = await client.post(
                "/login", data={"csrf": csrf, "password": password},
                headers={"Origin": origin},
            )
        finally:
            del password
        if response.status_code != 303 or response.headers.get("location") != "/":
            raise SmokeError("authentication")
        cookies = SimpleCookie()
        for header in response.headers.get_list("set-cookie"):
            cookies.load(header)
        cookie = cookies.get(SESSION_COOKIE)
        if (
            cookie is None or not cookie["secure"] or not cookie["httponly"]
            or cookie["samesite"].lower() != "strict" or cookie["path"] != "/"
            or cookie["domain"] or not cookie["max-age"].isdecimal()
        ):
            raise SmokeError("authentication")
        csrf, actor_id = _session_page(await client.get("/operator/session"))
        session = _validate_session({
            "version": 1, "origin": origin, "ca_path": str(ca_path),
            "ca_sha256": ca_sha256, "token": cookie.value, "csrf": csrf,
            "actor_id": actor_id, "issued_at": issued_at,
            "expires_at": issued_at + int(cookie["max-age"]),
        })
        try:
            directory = Path(tempfile.mkdtemp(prefix="strugglebus-smoke-session-", dir=SESSION_ROOT))
            path = directory / "session.json"
            _atomic_json(path, session)
        except (OSError, SmokeError):
            logout = await client.post("/logout", data={"csrf": csrf}, headers={"Origin": origin})
            if logout.status_code != 303 or logout.headers.get("location") != "/login":
                raise SmokeError("operator_logout_failed") from None
            raise
    return {"operator_session_path": str(path), "expires_at": session["expires_at"]}


def _validate_response(model: Any, value: Any) -> Any:
    from pydantic import ValidationError

    try:
        return model.model_validate_json(json.dumps(value, allow_nan=False))
    except (ValidationError, ValueError, TypeError) as error:
        raise SmokeError("invalid_response") from error


def _candidate_contract(release_id: str) -> dict[str, Any]:
    from strugglebus import __version__
    from strugglebus.config import AppConfig
    from strugglebus.integration import (
        COORDINATION_PROTOCOL_VERSION, GUIDE_VERSION, build_server_info,
    )
    from strugglebus.migrations import LATEST_SCHEMA_VERSION

    if (
        re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", release_id) is None
        or version("strugglebus") != __version__ or release_id != __version__
        or re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", GUIDE_VERSION) is None
        or type(COORDINATION_PROTOCOL_VERSION) is not int
        or COORDINATION_PROTOCOL_VERSION < 1
        or type(LATEST_SCHEMA_VERSION) is not int
        or LATEST_SCHEMA_VERSION not in CLEANUP_SCHEMA_VERSIONS
    ):
        raise SmokeError("invalid_configuration")
    config = AppConfig(release_id=release_id)
    info = build_server_info(config).model_dump(mode="json")
    if (
        info["application_version"] != release_id
        or info["integration_guide_version"] != GUIDE_VERSION
        or info["coordination_protocol_version"] != COORDINATION_PROTOCOL_VERSION
    ):
        raise SmokeError("invalid_configuration")
    return {"info": info, "schema": LATEST_SCHEMA_VERSION}


def _database(path: Path) -> sqlite3.Connection:
    # Never create a missing database, including in the second cleanup process.
    return sqlite3.connect(path.resolve(strict=True).as_uri() + "?mode=rw",
                           uri=True, timeout=10)


def _file_identity(path: Path) -> tuple[int, int]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise SmokeError("cleanup_refused")
    return metadata.st_dev, metadata.st_ino


def _check_binding(
    path: Path, binding: tuple[int, int, int],
    database: sqlite3.Connection | None = None,
    *, error_code: str = "cleanup_refused",
) -> None:
    if (
        _file_identity(path) != binding[:2] or binding[2] not in CLEANUP_SCHEMA_VERSIONS
        or (
            database is not None
            and database.execute("PRAGMA user_version").fetchone()[0] != binding[2]
        )
    ):
        raise SmokeError(error_code)


@contextmanager
def _bound_transaction(
    path: Path, binding: tuple[int, int, int], *, error_code: str = "cleanup_refused",
) -> Iterator[sqlite3.Connection]:
    _check_binding(path, binding, error_code=error_code)
    with closing(_database(path)) as database:
        database.row_factory = sqlite3.Row
        database.execute("PRAGMA foreign_keys = ON")
        database.execute("BEGIN IMMEDIATE")
        try:
            _check_binding(path, binding, database, error_code=error_code)
            yield database
            _check_binding(path, binding, database, error_code=error_code)
            database.commit()
        except BaseException:
            database.rollback()
            raise


def _release_environment(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_mode & 0o022
        ):
            raise SmokeError("invalid_configuration")
        return stream.read(128)


def _read_secret(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_mode & 0o077
            ):
                raise SmokeError("authentication")
            value = stream.read(4097)
    except OSError as error:
        raise SmokeError("authentication") from error
    if not 1 <= len(value) <= 4096:
        raise SmokeError("authentication")
    try:
        return value.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise SmokeError("authentication") from error


class ResultStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.results: list[dict[str, object]] = []

    def load(self) -> None:
        if not self.path.exists():
            self.results = []
            return
        try:
            with self.path.open("rb") as stream:
                raw = stream.read(MAX_RESULT_BYTES + 1)
            if len(raw) > MAX_RESULT_BYTES:
                raise SmokeError("result_write_failed")
            value = json.loads(raw.decode("ascii"))
        except (json.JSONDecodeError, UnicodeError, OSError) as error:
            raise SmokeError("result_write_failed") from error
        if not isinstance(value, list):
            raise SmokeError("result_write_failed")
        phases = set()
        for item in value:
            if not isinstance(item, dict) or set(item) != {
                "phase", "passed", "status_category", "shape_matches",
                "count_matches", "error_code",
            }:
                raise SmokeError("result_write_failed")
            try:
                _result(**item)
                if item["phase"] in phases:
                    raise SmokeError("result_write_failed")
                phases.add(item["phase"])
            except (TypeError, ValueError) as error:
                raise SmokeError("result_write_failed") from error
        self.results = value

    def record(self, value: dict[str, object]) -> None:
        self.results = [
            item for item in self.results if item.get("phase") != value["phase"]
        ]
        self.results.append(value)
        _atomic_json(self.path, self.results)


def _dashboard_document_safe(response: httpx.Response, marker: str) -> bool:
    raw = f"{marker} <script>smoke</script> searchable-question"
    return (
        response.status_code == 200
        and raw not in response.text
        and html.escape(raw, quote=True) in response.text
        and '"marker"' not in response.text
        and '"run"' not in response.text
        and "<style" not in response.text.lower()
        and re.search(r"\sstyle\s*=", response.text, re.IGNORECASE) is None
        and response.headers.get("content-security-policy", "") == DASHBOARD_CSP
    )


def _dashboard_stylesheet_path(document: str) -> str:
    links = re.findall(r'<link rel="stylesheet" href="([^"]+)">', document)
    if len(links) != 1:
        raise SmokeError("invalid_response")
    if re.fullmatch(
        r"/assets/strugglebus-console\.[0-9a-f]{16}\.css",
        links[0],
    ) is None:
        raise SmokeError("invalid_response")
    return links[0]


def _dashboard_stylesheet_safe(response: httpx.Response) -> bool:
    return (
        response.status_code == 200
        and response.headers.get("content-type") == "text/css; charset=utf-8"
        and response.headers.get("x-content-type-options") == "nosniff"
        and "color-scheme: dark" in response.text
        and (
            ".site-header" in response.text
            or (".workspace" in response.text and ".rail" in response.text)
        )
    )


class RealSmokeBackend:
    def __init__(self, configuration: dict[str, str], state_path: Path) -> None:
        import httpx2 as httpx
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        self.httpx = httpx
        self.ClientSession = ClientSession
        self.streamable_http_client = streamable_http_client
        self.configuration = configuration
        self.state_path = state_path
        self.namespace = f"smoke-{secrets.token_hex(8)}"
        self.writer_name = f"{self.namespace}-writer"
        self.reader_name = f"{self.namespace}-reader"
        self.channel_name = self.namespace
        self.marker = f"{MARKER_VERSION}:{self.namespace}"
        self.writer: dict[str, Any] = {}
        self.reader: dict[str, Any] = {}
        self.question_seq = 0
        self.answer_seq = 0
        self.client: httpx.AsyncClient | None = None
        self.expected: dict[str, Any] = {}
        self.state_ready = False
        self.database_binding: tuple[int, int, int] | None = None
        self.database_path: Path | None = None
        self.operator: dict[str, Any] | None = None
        self.operator_client = None
        self.operator_session_path = state_path.parent / "operator-session.json"

    def _write_state(self) -> None:
        if self.database_path is None or self.database_binding is None:
            raise SmokeError("invalid_configuration")
        _atomic_json(
            self.state_path,
            {
                "database_path": str(self.database_path),
                "database_device": self.database_binding[0],
                "database_inode": self.database_binding[1],
                "schema_version": self.database_binding[2],
                "namespace": self.namespace,
                "containment": "not_started",
                "operator": (
                    {"actor_id": self.operator["actor_id"], "intents": []}
                    if self.operator is not None else None
                ),
            },
        )

    @property
    def metadata(self) -> dict[str, str]:
        return {"marker": MARKER_VERSION, "run": self.namespace}

    @property
    def writer_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.writer['api_key']}"}

    @property
    def reader_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.reader['api_key']}"}

    async def setup(self) -> None:
        self.client = self.httpx.AsyncClient(
            base_url=self.configuration["base_url"],
            verify=self.configuration["ca_path"],
            timeout=self.httpx.Timeout(10),
            trust_env=False, follow_redirects=False,
        )

    async def candidate_contract(self) -> tuple[str, bool, bool]:
        self.expected = _candidate_contract(self.configuration["expected_release_id"])
        path = Path(self.configuration["release_environment_path"])
        if (
            _release_environment(path) != (
                f"STRUGGLEBUS_RELEASE_ID={self.configuration['expected_release_id']}\n"
            ).encode("ascii")
        ):
            raise SmokeError("invalid_configuration")
        database_path = Path(self.configuration["database_path"]).resolve(strict=True)
        binding = (*_file_identity(database_path), self.expected["schema"])
        with _bound_transaction(
            database_path, binding, error_code="invalid_configuration"
        ) as database:
            # A state marker is armed only after the entire random namespace is absent.
            for query, values in (
                ("SELECT 1 FROM agents WHERE name IN (?, ?)",
                 (self.writer_name, self.reader_name)),
                ("SELECT 1 FROM channels WHERE name = ?", (self.namespace,)),
                ("SELECT 1 FROM agent_enrollments WHERE name_prefix IN (?, ?) OR actor_id = ?",
                 (self.writer_name, self.reader_name, self.namespace)),
            ):
                if database.execute(query, values).fetchone() is not None:
                    raise SmokeError("cleanup_refused")
            self.database_path, self.database_binding = database_path, binding
            self._write_state()
        self.state_ready = True
        return "ok", True, True

    async def operator_authority(self) -> tuple[str, bool, bool]:
        if self.expected["schema"] == 11:
            return "not_applicable", True, True
        raw_path = self.configuration.get("operator_session_path", "")
        if not raw_path:
            raise SmokeError("authentication")
        source = Path(raw_path)
        if (
            source.name != "session.json"
            or not source.parent.name.startswith("strugglebus-smoke-session-")
        ):
            raise SmokeError("authentication")
        identity = _file_identity(source)
        session = _read_operator_session(source)
        if (
            session["origin"] != _origin(self.configuration["base_url"])
            or _ca_digest(Path(self.configuration["ca_path"])) != session["ca_sha256"]
            or self.operator_session_path.exists()
        ):
            raise SmokeError("authentication")
        _atomic_json(self.operator_session_path, session)
        if _file_identity(source) != identity:
            raise SmokeError("authentication")
        source.unlink()
        source.parent.rmdir()
        self.operator = session
        self.operator_client = _operator_client(session)
        csrf, actor = _session_page(await self.operator_client.get("/operator/session"))
        if (csrf, actor) != (session["csrf"], session["actor_id"]):
            raise SmokeError("authentication")
        for path in ("/", "/activity", "/agents", "/channels", "/system", "/register"):
            response = await self._http_client().get(path)
            if response.status_code != 303 or response.headers.get("location") != "/login":
                raise SmokeError("authentication")
        self._write_state()
        return "http_2xx", True, True

    async def enrollment(self) -> tuple[str, bool, bool]:
        self.writer = await self._register(self.writer_name)
        self.reader = await self._register(self.reader_name)
        return "http_2xx", True, True

    def _http_client(self) -> httpx.AsyncClient:
        if self.client is None:
            raise SmokeError("phase_failed")
        return self.client

    async def _register(self, name: str) -> dict[str, Any]:
        from strugglebus.api import RedeemedEnrollmentResponse
        from strugglebus.auth import AgentService
        from strugglebus.store import SQLiteStore

        if not self.state_ready or name not in {self.writer_name, self.reader_name}:
            raise SmokeError("invalid_configuration")
        database_path, namespace, binding = _load_state(self.state_path)
        if (
            database_path != self.database_path or namespace != self.namespace
            or binding != self.database_binding
        ):
            raise SmokeError("cleanup_refused")

        class BoundEnrollmentStore(SQLiteStore):
            @contextmanager
            def _transaction(self) -> Iterator[sqlite3.Connection]:
                # Reuse domain minting and freeze checks, but never let its normal
                # connection opener create or mutate a replacement database.
                with _bound_transaction(database_path, binding) as database:
                    self._require_enforced_roe_receipt(database)
                    yield database

        service = AgentService(
            BoundEnrollmentStore(
                database_path,
                backup_dir=self.state_path.parent,
            )
        )
        issued = service.create_enrollment(
            name_prefix=name, name_match="exact", description=self.marker,
            uses=1, ttl_seconds=60, actor_type="local-admin",
            actor_id=self.namespace, reason=ENROLLMENT_REASON, require_access=True,
        )
        with _bound_transaction(database_path, binding):
            pass
        response = await self._http_client().post(
            "/api/enrollments/redeem",
            headers={"Authorization": f"Bearer {issued.token}"},
            json={
                "request_id": str(uuid.uuid4()), "name": name,
                "description": self.marker, "host": HOST_MARKER,
            },
        )
        del issued
        if response.status_code != 201:
            raise SmokeError("http_status")
        value = _validate_response(RedeemedEnrollmentResponse, response.json())
        agent = value.agent.model_dump(mode="json")
        credential = value.credential.model_dump(mode="json")
        if (
            agent["name"] != name or agent["description"] != self.marker
            or agent["host"] != HOST_MARKER or agent["credential_epoch"] != 1
            or credential["agent_id"] != agent["id"] or credential["kind"] != "sb1"
            or credential["status"] != "pending" or credential["version"] != 0
            or credential["creation_method"] != "enrollment"
            or not value.credential_secret
            or response.headers.get("cache-control") != "no-store"
        ):
            raise SmokeError("invalid_response")
        return {**agent, "api_key": value.credential_secret, "credential": credential}

    async def _orientation(
        self, agent: dict[str, Any], *, mcp: bool, actions: list[str]
    ) -> None:
        from strugglebus.api import OrientationResponse
        from strugglebus.app import OrientationResult

        if mcp:
            async with self.mcp(agent["api_key"]) as session:
                response = await session.call_tool("orientation")
            if response.is_error:
                raise SmokeError("mcp_status")
            raw = response.structured_content
        else:
            response = await self._http_client().get(
                "/api/orientation", headers={"Authorization": f"Bearer {agent['api_key']}"}
            )
            if response.status_code != 200:
                raise SmokeError("http_status")
            raw = response.json()
        value = _validate_response(OrientationResult if mcp else OrientationResponse, raw)
        if (
            value.agent.id != agent["id"] or value.agent.name != agent["name"]
            or value.credential.id != agent["credential"]["id"]
            or value.credential.status != agent["credential"]["status"]
            or value.agent.credential_epoch != agent["credential_epoch"]
            or value.roe_acknowledgement_status != (
                "missing" if "acknowledge_roe" in actions else "current"
            )
            or [item.action for item in value.required_actions] != actions
        ):
            raise SmokeError("invalid_response")

    async def credential_proof(self) -> tuple[str, bool, bool]:
        from strugglebus.api import CredentialResponse, WhoAmIResponse
        from strugglebus.app import MCPCredential

        for agent, use_mcp in ((self.writer, False), (self.reader, True)):
            await self._orientation(
                agent, mcp=use_mcp,
                actions=["prove_credential", "acknowledge_roe", "choose_subscriptions"],
            )
            identity = await self._http_client().get(
                "/api/whoami", headers={"Authorization": f"Bearer {agent['api_key']}"}
            )
            if identity.status_code != 200:
                raise SmokeError("authentication")
            pinned = _validate_response(WhoAmIResponse, identity.json())
            if (
                pinned.agent.id != agent["id"] or pinned.agent.name != agent["name"]
                or pinned.credential.id != agent["credential"]["id"]
                or pinned.credential.status != "pending"
                or pinned.subscriptions
            ):
                raise SmokeError("authentication")
            payload = {
                "request_id": str(uuid.uuid4()),
                "expected_agent_id": agent["id"], "expected_agent_name": agent["name"],
                "expected_credential_epoch": agent["credential_epoch"],
                "expected_credential_version": agent["credential"]["version"],
            }
            if use_mcp:
                async with self.mcp(agent["api_key"]) as session:
                    proof = await session.call_tool("prove_credential", payload)
                if proof.is_error:
                    raise SmokeError("authentication")
                raw = proof.structured_content
            else:
                proof = await self._http_client().post(
                    "/api/credentials/prove",
                    headers={"Authorization": f"Bearer {agent['api_key']}"},
                    json=payload,
                )
                if proof.status_code != 200:
                    raise SmokeError("authentication")
                raw = proof.json()
            credential = _validate_response(MCPCredential if use_mcp else CredentialResponse, raw)
            if (
                credential.id != agent["credential"]["id"]
                or credential.status != "active"
                or credential.version != 1 or credential.identity_verified_at is None
            ):
                raise SmokeError("authentication")
            identity = await self._http_client().get(
                "/api/whoami", headers={"Authorization": f"Bearer {agent['api_key']}"}
            )
            if identity.status_code != 200:
                raise SmokeError("authentication")
            proved = _validate_response(WhoAmIResponse, identity.json())
            if (
                proved.agent.id != agent["id"] or proved.agent.name != agent["name"]
                or proved.agent.credential_epoch != agent["credential_epoch"] + 1
                or proved.credential.agent_id != agent["id"]
                or any(
                    getattr(proved.credential, key) != getattr(credential, key)
                    for key in ("id", "status", "version", "identity_verified_at")
                )
            ):
                raise SmokeError("authentication")
            agent["credential"] = proved.credential.model_dump(mode="json")
            agent["credential_epoch"] = proved.agent.credential_epoch
            await self._orientation(
                agent, mcp=use_mcp, actions=["acknowledge_roe", "choose_subscriptions"],
            )
        return "ok", True, True

    async def roe_receipt(self) -> tuple[str, bool, bool]:
        from strugglebus.api import EffectiveRoeResponse, RoeAcknowledgementResponse
        from strugglebus.roe import composition_sha256, parse_policy

        for agent, use_mcp in ((self.writer, False), (self.reader, True)):
            headers = {"Authorization": f"Bearer {agent['api_key']}"}
            if use_mcp:
                async with self.mcp(agent["api_key"]) as session:
                    response = await session.call_tool("get_effective_roe")
                if response.is_error:
                    raise SmokeError("mcp_status")
                raw = response.structured_content
            else:
                response = await self._http_client().get("/api/roe/effective", headers=headers)
                if response.status_code != 200:
                    raise SmokeError("http_status")
                raw = response.json()
            effective = _validate_response(EffectiveRoeResponse, raw)
            for revision in (effective.global_revision, effective.agent_revision):
                if revision is not None:
                    _, _, digest = parse_policy(revision.content, scope=revision.scope)
                    if digest != revision.content_sha256:
                        raise SmokeError("invalid_response")
            if (
                effective.receipt_status != "missing"
                or effective.effective_sha256 != composition_sha256(
                    effective.global_revision, effective.agent_revision
                )
            ):
                raise SmokeError("invalid_response")
            payload = {
                "global_revision_id": effective.global_revision.id,
                "global_content_sha256": effective.global_revision.content_sha256,
                "agent_revision_id": (
                    effective.agent_revision.id if effective.agent_revision else None
                ),
                "agent_content_sha256": (
                    effective.agent_revision.content_sha256 if effective.agent_revision else None
                ),
                "effective_sha256": effective.effective_sha256,
            }
            if use_mcp:
                async with self.mcp(agent["api_key"]) as session:
                    response = await session.call_tool("acknowledge_roe", payload)
                if response.is_error:
                    raise SmokeError("mcp_status")
                raw = response.structured_content
            else:
                response = await self._http_client().post(
                    "/api/roe/acknowledgements", headers=headers, json=payload
                )
                if response.status_code != 201:
                    raise SmokeError("http_status")
                raw = response.json()
            receipt = _validate_response(RoeAcknowledgementResponse, raw)
            if (
                any(getattr(receipt, key) != expected for key, expected in payload.items())
                or receipt.agent_id != agent["id"]
                or receipt.credential_record_id != agent["credential"]["id"]
                or receipt.credential_id != agent["credential"]["id"]
                or receipt.credential_kind != "sb1"
            ):
                raise SmokeError("invalid_response")
            await self._orientation(agent, mcp=use_mcp, actions=["choose_subscriptions"])
        return "ok", True, True

    @asynccontextmanager
    async def mcp(
        self, api_key: str, *, statuses: list[int] | None = None,
    ) -> AsyncIterator[ClientSession]:
        async def observe_status(response: httpx.Response) -> None:
            if statuses is not None:
                statuses.append(response.status_code)

        async with self.httpx.AsyncClient(
            headers={"Authorization": f"Bearer {api_key}"},
            verify=self.configuration["ca_path"],
            timeout=self.httpx.Timeout(10),
            event_hooks={"response": [observe_status]},
            trust_env=False, follow_redirects=False,
        ) as http_client:
            async with self.streamable_http_client(
                f"{self.configuration['base_url']}/mcp",
                http_client=http_client,
            ) as (read_stream, write_stream):
                async with self.ClientSession(read_stream, write_stream) as session:
                    from mcp_types.version import LATEST_HANDSHAKE_VERSION

                    initialized = await session.initialize()
                    if (
                        initialized.protocol_version != LATEST_HANDSHAKE_VERSION
                        or initialized.capabilities.tools is None
                    ):
                        raise SmokeError("invalid_response")
                    yield session

    async def identity(self) -> tuple[str, bool, bool]:
        rest = await self._http_client().get(
            "/api/agents", headers=self.writer_headers
        )
        rest_info_response = await self._http_client().get(
            "/api/server-info", headers=self.writer_headers
        )
        values = rest.json() if rest.status_code == 200 else []
        rest_info = (
            rest_info_response.json()
            if rest_info_response.status_code == 200
            else {}
        )
        rest_match = (
            isinstance(values, list)
            and sum(
                item.get("name") in {self.writer_name, self.reader_name}
                for item in values
                if isinstance(item, dict)
            )
            == 2
        )
        async with self.mcp(self.writer["api_key"]) as session:
            mcp = await session.call_tool("whoami")
            mcp_info_response = await session.call_tool("server_info")
        value = mcp.structured_content or {}
        mcp_info = mcp_info_response.structured_content or {}
        mcp_match = (
            not mcp.is_error
            and isinstance(value.get("agent"), dict)
            and value["agent"].get("name") == self.writer_name
        )
        info_match = (
            rest.status_code == 200
            and rest_info_response.status_code == 200
            and not mcp_info_response.is_error
            and rest_info == mcp_info
            and rest_info == self.expected["info"]
            and type(rest_info.get("coordination_protocol_version")) is int
            and type(mcp_info.get("coordination_protocol_version")) is int
        )
        from strugglebus.integration import ServerInfo

        _validate_response(ServerInfo, rest_info)
        _validate_response(ServerInfo, mcp_info)
        if not rest_match or not mcp_match or not info_match:
            raise SmokeError("invalid_response")
        return "ok", True, True

    async def channel_subscription(self) -> tuple[str, bool, bool]:
        response = await self._http_client().post(
            "/api/channels",
            headers=self.writer_headers,
            json={"name": self.channel_name, "purpose": self.marker},
        )
        rest_match = (
            response.status_code == 201
            and response.json().get("name") == self.channel_name
        )
        async with self.mcp(self.reader["api_key"]) as session:
            subscribed = await session.call_tool(
                "subscribe", {"channel": self.channel_name}
            )
        value = subscribed.structured_content or {}
        mcp_match = not subscribed.is_error and value.get("subscribed") is True
        if not rest_match or not mcp_match:
            raise SmokeError("invalid_response")
        response = await self._http_client().get(
            "/api/subscriptions", headers=self.reader_headers
        )
        if (
            response.status_code != 200
            or [item.get("name") for item in response.json()] != [self.channel_name]
        ):
            raise SmokeError("invalid_response")
        return "ok", True, True

    async def mcp_post_rest_read(self) -> tuple[str, bool, bool]:
        body = f"{self.marker} <script>smoke</script> searchable-question"
        async with self.mcp(self.writer["api_key"]) as session:
            posted = await session.call_tool(
                "post",
                {
                    "channel": self.channel_name,
                    "body": body,
                    "kind": "question",
                    "metadata": self.metadata,
                },
            )
        value = posted.structured_content or {}
        self.question_seq = value.get("seq", 0)
        if posted.is_error or not isinstance(self.question_seq, int):
            raise SmokeError("mcp_status")
        read = await self._http_client().get(
            f"/api/channels/{self.channel_name}/messages",
            headers=self.reader_headers,
        )
        messages = read.json() if read.status_code == 200 else []
        matches = (
            isinstance(messages, list)
            and len(messages) == 1
            and messages[0].get("seq") == self.question_seq
        )
        if not matches:
            raise SmokeError("invalid_response")
        return "ok", True, True

    async def rest_reply_mcp_read(self) -> tuple[str, bool, bool]:
        response = await self._http_client().post(
            f"/api/channels/{self.channel_name}/messages",
            headers=self.reader_headers,
            json={
                "body": f"{self.marker} searchable-answer",
                "kind": "answer",
                "reply_to": self.question_seq,
                "metadata": self.metadata,
            },
        )
        value = response.json() if response.status_code == 201 else {}
        self.answer_seq = value.get("seq", 0)
        async with self.mcp(self.writer["api_key"]) as session:
            read = await session.call_tool(
                "read", {"channel": self.channel_name, "limit": 10}
            )
        messages = (read.structured_content or {}).get("messages", [])
        matches = (
            isinstance(self.answer_seq, int)
            and self.answer_seq > self.question_seq
            and [item.get("seq") for item in messages]
            == [self.question_seq, self.answer_seq]
            and messages[1].get("reply_to") == self.question_seq
        )
        if response.status_code != 201 or read.is_error or not matches:
            raise SmokeError("invalid_response")
        return "ok", True, True

    async def sse_resume(self) -> tuple[str, bool, bool]:
        found = False
        fields: dict[str, str] = {}
        async with self._http_client().stream(
            "GET",
            "/api/stream",
            headers={**self.reader_headers, "Last-Event-ID": str(self.question_seq)},
        ) as response:
            if response.status_code != 200:
                raise SmokeError("http_status")
            async with asyncio.timeout(10):
                async for line in response.aiter_lines():
                    if not line:
                        if (
                            fields.get("event") == "message"
                            and fields.get("id") == str(self.answer_seq)
                        ):
                            found = True
                            break
                        fields.clear()
                    elif not line.startswith(":"):
                        name, separator, value = line.partition(":")
                        if separator:
                            fields[name] = value.lstrip()
        if not found:
            raise SmokeError("invalid_response")
        return "http_2xx", True, True

    async def dashboard_safety(self) -> tuple[str, bool, bool]:
        client = self.operator_client if self.expected.get("schema", 0) >= 12 else self._http_client()
        if client is None:
            raise SmokeError("authentication")
        response = await client.get("/")
        if not _dashboard_document_safe(response, self.marker):
            raise SmokeError("invalid_response")
        stylesheet = await client.get(_dashboard_stylesheet_path(response.text))
        if not _dashboard_stylesheet_safe(stylesheet):
            raise SmokeError("invalid_response")
        return "http_2xx", True, True

    async def revocation(self) -> tuple[str, bool, bool]:
        admin_token = _read_secret(Path(self.configuration["admin_credential_path"]))
        try:
            response = await self._http_client().post(
                (
                    f"/api/admin/agents/{self.reader_name}/credentials/"
                    f"{self.reader['credential']['id']}/revoke"
                ),
                headers={"Authorization": f"Bearer {admin_token}"},
                json={
                    "request_id": str(uuid.uuid4()),
                    "expected_credential_epoch": self.reader["credential_epoch"],
                    "expected_credential_version": self.reader["credential"]["version"],
                    "reason": "disposable smoke revocation check",
                },
            )
        finally:
            del admin_token
        if response.status_code != 200:
            raise SmokeError("http_status")
        return "ok", True, True

    async def rest_denial(self) -> tuple[str, bool, bool]:
        response = await self._http_client().get(
            "/api/channels", headers=self.reader_headers
        )
        if response.status_code != 401:
            raise SmokeError("authentication")
        return "denied", True, True

    async def mcp_denial(self) -> tuple[str, bool, bool]:
        from mcp.shared.exceptions import MCPError

        denied = False
        statuses: list[int] = []
        try:
            async with self.mcp(self.reader["api_key"], statuses=statuses):
                pass
        except self.httpx.HTTPStatusError as error:
            denied = error.response.status_code == 401
        except MCPError:
            denied = bool(statuses) and all(status == 401 for status in statuses)
        except ExceptionGroup as error:
            leaves: list[BaseException] = []

            def collect(group: BaseExceptionGroup[BaseException]) -> None:
                for child in group.exceptions:
                    if isinstance(child, BaseExceptionGroup):
                        collect(child)
                    else:
                        leaves.append(child)

            collect(error)
            if not leaves or not all(
                isinstance(item, MCPError) or (
                    isinstance(item, self.httpx.HTTPStatusError)
                    and item.response.status_code == 401
                )
                for item in leaves
            ):
                raise
            # The SDK may erase HTTP status while wrapping an auth response.
            # Observe only status codes, never headers, bodies, or error text.
            denied = bool(statuses) and all(status == 401 for status in statuses)
        if not denied:
            raise SmokeError("authentication")
        return "denied", True, True

    async def close(self) -> None:
        try:
            await _logout_operator(self.operator_session_path)
        finally:
            if self.operator_client is not None:
                await self.operator_client.aclose()
            if self.client is not None:
                await self.client.aclose()

    def cleanup(self) -> None:
        if not self.state_ready:
            return
        if self.database_path is None or self.database_binding is None:
            raise SmokeError("invalid_configuration")
        _cleanup_state(
            self.state_path,
            expected=(self.database_path, self.namespace, self.database_binding),
        )


def _rows(database: sqlite3.Connection, query: str, values: tuple[Any, ...]):
    return database.execute(query, values).fetchall()


def cleanup_database(
    database_path: Path, *, namespace: str, binding: tuple[int, int, int],
) -> None:
    _cleanup_transaction(database_path, namespace=namespace, binding=binding, artifacts=False)
    _remove_contained_artifacts(database_path, namespace=namespace, binding=binding)


def _remove_contained_artifacts(
    database_path: Path, *, namespace: str, binding: tuple[int, int, int], operator=None,
) -> None:
    try:
        _cleanup_transaction(
            database_path, namespace=namespace, binding=binding, artifacts=True, operator=operator,
        )
    except (SmokeError, sqlite3.Error, OSError) as error:
        raise SmokeError("artifact_cleanup_refused") from error


def _cleanup_state(
    state_path: Path, *, expected: tuple[Path, str, tuple[int, int, int]] | None = None,
) -> None:
    value = _read_state(state_path)
    database_path = Path(value["database_path"])
    namespace = value["namespace"]
    binding = (value["database_device"], value["database_inode"], value["schema_version"])
    if expected is not None and (database_path, namespace, binding) != expected:
        raise SmokeError("cleanup_refused")
    if value["containment"] != "committed":
        def mark_attempt() -> None:
            # Persist uncertainty before mutation so interruption cannot claim
            # zero prior mutation. The receipt remains bound to the original DB.
            value["containment"] = "unknown"
            _atomic_json(state_path, value)

        try:
            _cleanup_transaction(
                database_path, namespace=namespace, binding=binding,
                artifacts=False, before_containment=mark_attempt,
                operator=value.get("operator"),
            )
        except (SmokeError, sqlite3.Error, OSError) as error:
            if value["containment"] == "unknown":
                raise SmokeError("containment_unknown") from error
            raise
        value["containment"] = "committed"
        try:
            _atomic_json(state_path, value)
        except (SmokeError, OSError) as error:
            # This attempt knows the commit succeeded; retries must conservatively
            # report unknown if the persisted marker could not be advanced.
            raise SmokeError("artifact_cleanup_refused") from error
    _remove_contained_artifacts(
        database_path, namespace=namespace, binding=binding, operator=value.get("operator"),
    )


def _operator_record(value, namespace):
    if value is None:
        return None, {}
    if (
        not isinstance(value, dict) or set(value) != {"actor_id", "intents"}
        or not isinstance(value["actor_id"], str)
        or re.fullmatch(r"operator:owner:[0-9a-f]{32}", value["actor_id"]) is None
        or not isinstance(value["intents"], list) or len(value["intents"]) > 8
    ):
        raise SmokeError("cleanup_refused")
    intents = {}
    for intent in value["intents"]:
        if (
            not isinstance(intent, dict)
            or set(intent) != {"agent_id", "name", "epoch", "action", "request_id"}
            or any(not isinstance(intent[key], str) for key in (
                "agent_id", "name", "action", "request_id",
            ))
            or not 1 <= len(intent["agent_id"]) <= 128
            or intent["name"] not in {f"{namespace}-writer", f"{namespace}-reader"}
            or intent["action"] not in {"block", "unblock", "retire", "reconnect", "redeem"}
            or type(intent["epoch"]) is not int or not 0 <= intent["epoch"] < 2**63 - 1
            or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", intent["request_id"]) is None
            or intent["request_id"] in intents
        ):
            raise SmokeError("cleanup_refused")
        intents[intent["request_id"]] = intent
    return value["actor_id"], intents


def _prove_operator_lineage(database, *, namespace, agents, agent_values, operator):
    actor, intents = _operator_record(operator, namespace)
    names = {row["id"]: row["name"] for row in agents}
    if any(names.get(item["agent_id"]) != item["name"] for item in intents.values()):
        raise SmokeError("cleanup_refused")
    grants = _rows(
        database, "SELECT * FROM agent_reconnect_grants WHERE agent_id IN (?, ?) LIMIT 9",
        agent_values,
    )
    if len(grants) > 8:
        raise SmokeError("cleanup_refused")
    proven = {}
    credential_ids = set()
    for grant in grants:
        intent = intents.get(grant["issuance_request_id"])
        if (
            intent is None or intent["action"] != "reconnect"
            or intent["agent_id"] != grant["agent_id"]
            or intent["epoch"] + 1 != grant["bound_epoch"]
            or grant["actor_type"] != "remote-admin" or grant["actor_id"] != actor
            or grant["reason"] != f"{MARKER_VERSION}:{namespace}"
        ):
            raise SmokeError("cleanup_refused")
        if grant["status"] == "redeemed":
            redemption = intents.get(grant["redemption_request_id"])
            credential = database.execute(
                "SELECT * FROM agent_credentials WHERE id=?", (grant["result_credential_id"],),
            ).fetchone()
            if (
                redemption is None or redemption["action"] != "redeem"
                or redemption["agent_id"] != grant["agent_id"]
                or redemption["epoch"] != grant["bound_epoch"]
                or credential is None or credential["agent_id"] != grant["agent_id"]
                or credential["issuance_request_id"] != grant["redemption_request_id"]
                or credential["creation_method"] != "reconnect"
                or credential["creation_reason"] != "single-use reconnect redemption"
            ):
                raise SmokeError("cleanup_refused")
            credential_ids.add(credential["id"])
        proven[grant["id"]] = grant
    events = _rows(
        database, "SELECT * FROM agent_lifecycle_audit WHERE agent_id IN (?, ?) LIMIT 65",
        agent_values,
    )
    if len(events) > 64:
        raise SmokeError("cleanup_refused")
    for event in events:
        if (
            event["actor_type"] == "local-admin" and event["actor_id"] == namespace
            and event["reason"] == "disposable smoke cleanup"
            and event["action"] in {"retire", "reconnect-invalidate", "reconnect-expire"}
        ):
            if event["grant_id"] is not None and event["grant_id"] not in proven:
                raise SmokeError("cleanup_refused")
            continue
        if event["action"] == "reconnect-expire":
            if event["actor_type"] != "system" or event["grant_id"] not in proven:
                raise SmokeError("cleanup_refused")
            continue
        intent = intents.get(event["request_id"])
        if intent is None:
            raise SmokeError("cleanup_refused")
        expected_action = {
            "reconnect": "reconnect-issue", "redeem": "reconnect-redeem",
        }.get(intent["action"], intent["action"])
        if (
            event["agent_id"] != intent["agent_id"] or event["action"] != expected_action
            or event["previous_epoch"] != intent["epoch"]
        ):
            raise SmokeError("cleanup_refused")
        if intent["action"] == "redeem":
            if (
                event["grant_id"] not in proven or event["actor_type"] != "reconnect-grant"
                or event["actor_id"] != f"reconnect:{event['grant_id']}"
                or event["reason"] != "single-use reconnect redemption"
            ):
                raise SmokeError("cleanup_refused")
        elif (
            event["actor_type"] != "remote-admin" or event["actor_id"] != actor
            or event["reason"] != f"{MARKER_VERSION}:{namespace}"
        ):
            raise SmokeError("cleanup_refused")
    return credential_ids


def _contain_operation(
    database: sqlite3.Connection, *, namespace: str,
    agents: list[sqlite3.Row], enrollments: list[sqlite3.Row],
    agent_values: tuple[Any, ...], schema: int,
) -> None:
    now = datetime.now(UTC).isoformat(timespec="microseconds")
    for enrollment in enrollments:
        if enrollment["status"] == "pending":
            database.execute(
                """
                UPDATE agent_enrollments
                SET status = 'revoked', revoked_at = ?,
                    revocation_reason = 'disposable smoke cleanup', version = version + 1
                WHERE id = ? AND status = 'pending'
                """,
                (now, enrollment["id"]),
            )
    if schema >= 12:
        from strugglebus.models import LifecycleActor
        from strugglebus.store import SQLiteStore

        class BoundCleanupStore(SQLiteStore):
            @contextmanager
            def _transaction(self):
                # The outer provenance transaction owns commit and rollback.
                yield database

        database_path = Path(database.execute("PRAGMA database_list").fetchone()[2])
        store = BoundCleanupStore(database_path, backup_dir=database_path.parent)
        for agent in agents:
            if agent["revoked_at"] is None:
                store.transition_agent(
                    agent["id"], action="retire", expected_credential_epoch=agent["credential_epoch"],
                    request_id=str(uuid.uuid4()), reason="disposable smoke cleanup",
                    actor=LifecycleActor("local-admin", namespace), changed_at=datetime.now(UTC),
                )
        if database.execute(
            "SELECT 1 FROM agent_reconnect_grants WHERE agent_id IN (?, ?) AND status='pending'",
            agent_values,
        ).fetchone() is not None or database.execute(
            "SELECT 1 FROM agent_credentials WHERE agent_id IN (?, ?) AND status IN ('pending','active')",
            agent_values,
        ).fetchone() is not None:
            raise SmokeError("cleanup_failed")
        return
    live_credentials = _rows(
        database,
        """
        SELECT id, agent_id FROM agent_credentials
        WHERE agent_id IN (?, ?) AND status IN ('pending', 'active')
        """,
        agent_values,
    )
    for credential in live_credentials:
        request_id = f"smoke-cleanup:{uuid.uuid4()}"
        cursor = database.execute(
            """
            UPDATE agent_credentials
            SET status = 'revoked', revoked_at = ?, version = version + 1
            WHERE id = ? AND status IN ('pending', 'active')
            """,
            (now, credential["id"]),
        )
        if cursor.rowcount != 1:
            raise SmokeError("cleanup_failed")
        database.execute(
            """
            INSERT INTO agent_credential_audit (
                id, event_type, agent_id, credential_id,
                related_credential_id, actor_type, actor_id, method,
                reason, request_id, occurred_at, details_json
            ) VALUES (?, 'revoke', ?, ?, NULL, 'local-admin',
                      ?, 'cleanup', 'disposable smoke cleanup', ?, ?, '{}')
            """,
            (
                f"audit:{uuid.uuid4()}", credential["agent_id"], credential["id"],
                namespace, request_id, now,
            ),
        )
    for agent in agents:
        if agent["revoked_at"] is not None:
            continue
        database.execute(
            """
            UPDATE agents SET revoked_at = ?, credential_epoch = credential_epoch + 1
            WHERE id = ? AND revoked_at IS NULL
            """,
            (now, agent["id"]),
        )
        database.execute(
            """
            INSERT INTO agent_credential_audit (
                id, event_type, agent_id, credential_id, actor_type, actor_id,
                method, reason, request_id, occurred_at, details_json
            ) VALUES (?, 'agent-revoke', ?, ?, 'local-admin', ?,
                      'agent-revocation', 'stable agent revoked', ?, ?, '{}')
            """,
            (
                str(uuid.uuid4()), agent["id"],
                database.execute(
                    "SELECT id FROM agent_credentials WHERE agent_id = ?", (agent["id"],)
                ).fetchone()["id"],
                namespace, str(uuid.uuid4()), now,
            ),
        )
    for query, values in (
        ("SELECT COUNT(*) FROM agents WHERE id IN (?, ?) AND revoked_at IS NULL", agent_values),
        ("SELECT COUNT(*) FROM agent_credentials WHERE agent_id IN (?, ?) "
         "AND status IN ('pending', 'active')", agent_values),
        ("SELECT COUNT(*) FROM agent_enrollments WHERE actor_id = ? AND status = 'pending'",
         (namespace,)),
    ):
        if database.execute(query, values).fetchone()[0]:
            raise SmokeError("cleanup_failed")


def _refuse_keyed_artifacts(
    database: sqlite3.Connection, *, namespace: str, agent_values: tuple[Any, ...],
) -> None:
    # Include external keyed replies and mentions whose retained relationships
    # would otherwise intersect cleanup. Legacy smoke posts never carry a key.
    if database.execute(
        """
        WITH artifacts AS (
            SELECT seq, post_request_id FROM messages
            WHERE agent_id IN (?, ?)
               OR channel_id = (SELECT id FROM channels WHERE name = ?)
        )
        SELECT 1 FROM artifacts WHERE post_request_id IS NOT NULL
        UNION ALL
        SELECT 1 FROM messages
        WHERE post_request_id IS NOT NULL
          AND reply_to IN (SELECT seq FROM artifacts)
        UNION ALL
        SELECT 1 FROM mentions
        JOIN messages ON messages.seq = mentions.message_seq
        WHERE mentions.agent_id IN (?, ?) AND messages.post_request_id IS NOT NULL
        LIMIT 1
        """,
        (*agent_values, namespace, *agent_values),
    ).fetchone() is not None:
        raise SmokeError("artifact_cleanup_refused")


def _cleanup_transaction(
    database_path: Path, *, namespace: str, binding: tuple[int, int, int],
    artifacts: bool,
    before_containment: Callable[[], None] | None = None,
    operator=None,
) -> None:
    if (
        len(namespace) != 22
        or not namespace.startswith("smoke-")
        or any(character not in "0123456789abcdef" for character in namespace[6:])
    ):
        raise SmokeError("cleanup_refused")
    _check_binding(database_path, binding)
    writer_name = f"{namespace}-writer"
    reader_name = f"{namespace}-reader"
    marker = f"{MARKER_VERSION}:{namespace}"
    database = _database(database_path)
    database.row_factory = sqlite3.Row
    try:
        database.execute("PRAGMA foreign_keys = ON")
        database.execute("BEGIN IMMEDIATE")
        _check_binding(database_path, binding, database)
        agents = _rows(
            database,
            """
            SELECT id, name, description, host, revoked_at, credential_epoch, blocked_at
            FROM agents
            WHERE name IN (?, ?)
            """ if binding[2] >= 12 else """
            SELECT id, name, description, host, revoked_at, credential_epoch
            FROM agents
            WHERE name IN (?, ?)
            """,
            (writer_name, reader_name),
        )
        for row in agents:
            if (
                row["name"] not in {writer_name, reader_name}
                or row["description"] != marker
                or row["host"] != HOST_MARKER
            ):
                raise SmokeError("cleanup_refused")
        agent_ids = {row["id"] for row in agents}
        enrollments = _rows(
            database,
            """
            SELECT * FROM agent_enrollments
            WHERE name_prefix IN (?, ?) OR actor_id = ?
            """,
            (writer_name, reader_name, namespace),
        )
        if (
            len(enrollments) > 2
            or len({row["name_prefix"] for row in enrollments}) != len(enrollments)
        ):
            raise SmokeError("cleanup_refused")
        redeemed_agents: set[str] = set()
        credential_ids: set[str] = set()
        for enrollment in enrollments:
            if (
                enrollment["name_prefix"] not in {writer_name, reader_name}
                or enrollment["name_match"] != "exact"
                or enrollment["description"] != marker
                or enrollment["actor_type"] != "local-admin"
                or enrollment["actor_id"] != namespace
                or enrollment["creation_reason"] != ENROLLMENT_REASON
                or enrollment["uses_allowed"] != 1
            ):
                raise SmokeError("cleanup_refused")
            redemptions = _rows(
                database,
                """
                SELECT redemption.agent_id, redemption.credential_id,
                       redemption.claimed_name, credential.creation_method
                FROM agent_enrollment_redemptions AS redemption
                JOIN agent_credentials AS credential
                  ON credential.id = redemption.credential_id
                 AND credential.agent_id = redemption.agent_id
                WHERE redemption.enrollment_id = ?
                """,
                (enrollment["id"],),
            )
            if len(redemptions) != (1 if enrollment["status"] == "exhausted" else 0):
                raise SmokeError("cleanup_refused")
            for redemption in redemptions:
                if (
                    redemption["agent_id"] not in agent_ids
                    or redemption["claimed_name"] != enrollment["name_prefix"]
                    or redemption["creation_method"] != "enrollment"
                    or not any(
                        row["id"] == redemption["agent_id"]
                        and row["name"] == redemption["claimed_name"] for row in agents
                    )
                ):
                    raise SmokeError("cleanup_refused")
                redeemed_agents.add(redemption["agent_id"])
                credential_ids.add(redemption["credential_id"])
        if redeemed_agents != agent_ids:
            raise SmokeError("cleanup_refused")
        if len(agent_ids) > 2:
            raise SmokeError("cleanup_refused")
        agent_values = (*agent_ids, *([None] * (2 - len(agent_ids))))
        credentials = _rows(
            database, "SELECT id FROM agent_credentials WHERE agent_id IN (?, ?)",
            agent_values,
        )
        if binding[2] >= 12:
            credential_ids.update(_prove_operator_lineage(
                database, namespace=namespace, agents=agents, agent_values=agent_values,
                operator=operator,
            ))
        if {row["id"] for row in credentials} != credential_ids:
            raise SmokeError("cleanup_refused")
        if binding[2] >= 16:
            _refuse_keyed_artifacts(database, namespace=namespace, agent_values=agent_values)
        if not artifacts:
            if before_containment is not None:
                before_containment()
            _contain_operation(
                database, namespace=namespace, agents=agents,
                enrollments=enrollments, agent_values=agent_values, schema=binding[2],
            )
            _check_binding(database_path, binding, database)
            database.commit()
            return
        channels = _rows(
            database,
            "SELECT id, name, purpose, created_by FROM channels WHERE name = ?",
            (namespace,),
        )
        if len(channels) > 1:
            raise SmokeError("artifact_cleanup_refused")
        channel_id = channels[0]["id"] if channels else None
        writer_id = next(
            (row["id"] for row in agents if row["name"] == writer_name), None
        )
        if channels and (
            channels[0]["purpose"] != marker
            or channels[0]["created_by"] != writer_id
        ):
            raise SmokeError("artifact_cleanup_refused")
        help_row = database.execute(
            "SELECT id FROM channels WHERE name = 'help'"
        ).fetchone()
        allowed_channels = {value for value in (channel_id,) if value is not None}
        if help_row is not None:
            allowed_channels.add(help_row["id"])
        messages = _rows(
            database,
            """
            SELECT seq, channel_id, agent_id, body, meta
            FROM messages
            WHERE agent_id IN (?, ?) OR channel_id = ?
            """,
            (*agent_values, channel_id),
        )
        if len(messages) > 3:
            raise SmokeError("artifact_cleanup_refused")
        message_seqs: set[int] = set()
        for row in messages:
            try:
                metadata = json.loads(row["meta"])
            except (json.JSONDecodeError, TypeError) as error:
                raise SmokeError("artifact_cleanup_refused") from error
            if (
                row["agent_id"] not in agent_ids
                or row["channel_id"] not in allowed_channels
                or not row["body"].startswith(marker)
                or metadata != {"marker": MARKER_VERSION, "run": namespace}
            ):
                raise SmokeError("artifact_cleanup_refused")
            message_seqs.add(row["seq"])
        for sequence in message_seqs:
            # ON DELETE SET NULL must not alter an unrelated reply.
            if any(
                row["seq"] not in message_seqs for row in _rows(
                    database, "SELECT seq FROM messages WHERE reply_to = ?", (sequence,)
                )
            ):
                raise SmokeError("artifact_cleanup_refused")
        if channel_id is not None:
            for table in ("subscriptions", "cursors"):
                if any(
                    row["agent_id"] not in agent_ids for row in _rows(
                        database,
                        f"SELECT agent_id FROM {table} WHERE channel_id = ?",
                        (channel_id,),
                    )
                ):
                    raise SmokeError("artifact_cleanup_refused")
        if agent_ids:
            sequence_values = (
                *message_seqs,
                *([None] * (3 - len(message_seqs))),
            )
            mention_rows = _rows(
                database,
                """
                SELECT message_seq, agent_id
                FROM mentions
                WHERE agent_id IN (?, ?) OR message_seq IN (?, ?, ?)
                """,
                (*agent_values, *sequence_values),
            )
            if any(
                row["message_seq"] not in message_seqs
                or row["agent_id"] not in agent_ids
                for row in mention_rows
            ):
                raise SmokeError("artifact_cleanup_refused")
            subscription_rows = _rows(
                database,
                "SELECT channel_id FROM subscriptions WHERE agent_id IN (?, ?)",
                agent_values,
            )
            cursor_rows = _rows(
                database,
                "SELECT channel_id FROM cursors WHERE agent_id IN (?, ?)",
                agent_values,
            )
            if any(
                row["channel_id"] != channel_id
                for row in subscription_rows + cursor_rows
            ):
                raise SmokeError("artifact_cleanup_refused")
            database.execute(
                """
                DELETE FROM mentions
                WHERE agent_id IN (?, ?) OR message_seq IN (?, ?, ?)
                """,
                (*agent_values, *sequence_values),
            )
            database.execute(
                "DELETE FROM mention_cursors WHERE agent_id IN (?, ?)",
                agent_values,
            )
            database.execute(
                "DELETE FROM cursors WHERE agent_id IN (?, ?)",
                agent_values,
            )
            database.execute(
                "DELETE FROM subscriptions WHERE agent_id IN (?, ?)",
                agent_values,
            )
        for sequence in sorted(message_seqs, reverse=True):
            database.execute("DELETE FROM messages WHERE seq = ?", (sequence,))
        if channel_id is not None:
            database.execute("DELETE FROM channels WHERE id = ?", (channel_id,))
        remaining = 0
        remaining += database.execute(
            "SELECT COUNT(*) FROM channels WHERE name = ?", (namespace,)
        ).fetchone()[0]
        if agent_ids:
            for query in (
                "SELECT COUNT(*) FROM agents WHERE id IN (?, ?) AND revoked_at IS NULL",
                "SELECT COUNT(*) FROM messages WHERE agent_id IN (?, ?)",
                "SELECT COUNT(*) FROM subscriptions WHERE agent_id IN (?, ?)",
                "SELECT COUNT(*) FROM cursors WHERE agent_id IN (?, ?)",
                "SELECT COUNT(*) FROM mention_cursors WHERE agent_id IN (?, ?)",
                "SELECT COUNT(*) FROM mentions WHERE agent_id IN (?, ?)",
                """
                SELECT COUNT(*) FROM agent_credentials
                WHERE agent_id IN (?, ?) AND status IN ('pending', 'active')
                """,
            ):
                remaining += database.execute(query, agent_values).fetchone()[0]
        if remaining:
            raise SmokeError("cleanup_failed")
        _check_binding(database_path, binding, database)
        database.commit()
    except BaseException:
        database.rollback()
        raise
    finally:
        database.close()


def _classify(error: BaseException) -> str:
    if isinstance(error, SmokeError):
        return error.error_code
    if isinstance(error, BaseExceptionGroup):
        codes = {_classify(child) for child in error.exceptions}
        return codes.pop() if len(codes) == 1 else "unexpected_error"
    import httpx2

    if isinstance(error, (httpx2.HTTPError, TimeoutError)):
        return "connection"
    return "unexpected_error"


async def run_smoke(
    backend: RealSmokeBackend,
    result_store: ResultStore,
    *,
    failure_phase: str | None = None,
) -> bool:
    passed = True
    try:
        await backend.setup()
        for phase in PHASES:
            try:
                if phase == failure_phase:
                    raise SmokeError("injected_failure")
                operation = getattr(backend, phase)
                async with asyncio.timeout(PHASE_TIMEOUT_SECONDS):
                    status_category, shape_matches, count_matches = await operation()
                if shape_matches is not True or count_matches is not True:
                    raise SmokeError("invalid_response")
                result_store.record(
                    _result(
                        phase,
                        passed=True,
                        status_category=status_category,
                        shape_matches=shape_matches,
                        count_matches=count_matches,
                        error_code="none",
                    )
                )
            except BaseException as error:
                result_store.record(
                    _result(
                        phase,
                        passed=False,
                        status_category="failed",
                        shape_matches=False,
                        count_matches=False,
                        error_code=_classify(error),
                    )
                )
                passed = False
                break
    except BaseException as error:
        result_store.record(
            _result(
                PHASES[0],
                passed=False,
                status_category="failed",
                shape_matches=False,
                count_matches=False,
                error_code=_classify(error),
            )
        )
        passed = False
    finally:
        cleanup_error = None
        try:
            backend.cleanup()
        except BaseException as error:
            cleanup_error = error
        try:
            await backend.close()
        except BaseException as error:
            if cleanup_error is None:
                cleanup_error = error
        if cleanup_error is None:
            cleanup_result = _result(
                "helper_cleanup",
                passed=True,
                status_category="cleanup_zero",
                shape_matches=True,
                count_matches=True,
                error_code="none",
            )
        else:
            cleanup_result = _result(
                "helper_cleanup",
                passed=False,
                status_category="failed",
                shape_matches=False,
                count_matches=False,
                error_code=_classify(cleanup_error),
            )
            passed = False
        result_store.record(cleanup_result)
    return passed


def _read_state(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="ascii") as stream:
            raw = stream.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise SmokeError("invalid_configuration")
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SmokeError("invalid_configuration") from error
    if (
        not isinstance(value, dict)
        or set(value) not in ({
            "database_path", "database_device", "database_inode", "schema_version",
            "namespace", "containment",
        }, {
            "database_path", "database_device", "database_inode", "schema_version",
            "namespace", "containment", "operator",
        })
        or not isinstance(value.get("containment"), str)
        or value["containment"] not in {"not_started", "unknown", "committed"}
        or not all(isinstance(value[key], str) for key in ("database_path", "namespace"))
        or not all(type(value[key]) is int for key in (
            "database_device", "database_inode", "schema_version"
        ))
    ):
        raise SmokeError("invalid_configuration")
    return value


def _load_state(path: Path) -> tuple[Path, str, tuple[int, int, int]]:
    value = _read_state(path)
    database_path = Path(value["database_path"])
    binding = (value["database_device"], value["database_inode"], value["schema_version"])
    if (
        _file_identity(database_path) != binding[:2]
        or binding[2] not in CLEANUP_SCHEMA_VERSIONS
    ):
        raise SmokeError("cleanup_refused")
    return database_path, value["namespace"], binding


def _paths(configuration: dict[str, str]) -> tuple[Path, Path]:
    work_dir = Path(configuration["work_dir"])
    metadata = work_dir.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o077
        or metadata.st_uid != 0 or work_dir.parent != Path("/run")
        or re.fullmatch(r"strugglebus-smoke-[A-Za-z0-9_.-]+", work_dir.name) is None
    ):
        raise SmokeError("invalid_configuration")
    return work_dir / "result.json", work_dir / "state.json"


def _configuration_for_action(
    action: str, input_value: dict[str, Any]
) -> dict[str, str]:
    if action == "run":
        return _read_configuration(input_value)
    if action == "cleanup" and set(input_value) == {"work_dir"} and isinstance(
        input_value["work_dir"], str
    ):
        return {"work_dir": input_value["work_dir"]}
    raise SmokeError("invalid_configuration")


def _execute(action: str, input_value: dict[str, Any]) -> int:
    configuration = _configuration_for_action(action, input_value)
    result_path, state_path = _paths(configuration)
    store = ResultStore(result_path)
    store.load()
    if action == "run":
        backend = RealSmokeBackend(configuration, state_path)
        success = asyncio.run(run_smoke(backend, store))
        return 0 if success else 1
    cleanup_error = None
    try:
        _cleanup_state(state_path)
    except BaseException as error:
        cleanup_error = error
    try:
        session_path = state_path.parent / "operator-session.json"
        if session_path.exists():
            asyncio.run(_logout_operator(session_path))
    except BaseException as error:
        if cleanup_error is None:
            cleanup_error = error
    if cleanup_error is None:
        value = _result(
            "ansible_always_cleanup",
            passed=True,
            status_category="cleanup_zero",
            shape_matches=True,
            count_matches=True,
            error_code="none",
        )
        success = True
    else:
        value = _result(
            "ansible_always_cleanup",
            passed=False,
            status_category="failed",
            shape_matches=False,
            count_matches=False,
            error_code=_classify(cleanup_error),
        )
        success = False
    store.record(value)
    print(json.dumps(store.results, ensure_ascii=True, separators=(",", ":")))
    return 0 if success else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("run", "cleanup", "prepare-operator"))
    arguments = parser.parse_args(argv)
    input_value: dict[str, Any] = {}
    try:
        input_value = _read_input()
        if arguments.action == "prepare-operator":
            print(json.dumps(asyncio.run(prepare_operator_session(input_value))))
            return 0
        return _execute(arguments.action, input_value)
    except Exception as error:
        if arguments.action == "prepare-operator":
            print(json.dumps({"operator_session_ready": False, "error_code": _classify(error)}))
            return 1
        phase = (
            PHASES[0]
            if arguments.action == "run"
            else "ansible_always_cleanup"
        )
        failure = _result(
            phase,
            passed=False,
            status_category="failed",
            shape_matches=False,
            count_matches=False,
            error_code=_classify(error),
        )
        results = [failure]
        work_dir = input_value.get("work_dir")
        if isinstance(work_dir, str):
            try:
                result_path, _ = _paths({"work_dir": work_dir})
                store = ResultStore(result_path)
                store.load()
                store.record(failure)
                results = store.results
            except Exception:
                results = [
                    _result(
                        phase,
                        passed=False,
                        status_category="failed",
                        shape_matches=False,
                        count_matches=False,
                        error_code="result_write_failed",
                    )
                ]
        print(json.dumps(results, ensure_ascii=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
