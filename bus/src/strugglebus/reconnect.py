"""Private recipient-side reconnect packages; no server configuration or storage."""

from __future__ import annotations

import json
import os
import re
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import SplitResult, urlsplit
from urllib.request import (
    HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener,
)
from uuid import UUID, uuid4

from strugglebus.auth import parse_credential
from strugglebus.ca import validate_trust_anchor
from strugglebus.errors import (
    ConfigurationError, DomainValidationError, StrugglebusError, TrustAnchorError,
)
from strugglebus.private_files import (
    open_private_output, read_private_file, require_private_path,
)
from strugglebus.service import normalize_name

MAX_PACKAGE_BYTES = 512 * 1024
MAX_REDEMPTION_RESPONSE_BYTES = 32 * 1024
REDEMPTION_TIMEOUT_SECONDS = 15
_GRANT = re.compile(r"sbr1_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{43}")
_FIELDS = {
    "version", "agent_id", "agent_name", "base_url",
    "ca_root", "ca_sha256", "expires_at", "grant",
}


class ReconnectError(StrugglebusError):
    """A reconnect failed; no returned secret is recoverable."""

    def __init__(
        self,
        message: str,
        *,
        outcome: str = "unknown",
        http_status: int | None = None,
    ) -> None:
        self.outcome = outcome
        self.http_status = http_status
        super().__init__(message)


_HTTP_REJECTIONS = {
    400: "request_rejected",
    401: "grant_rejected",
    403: "grant_rejected",
    404: "endpoint_unavailable",
    405: "method_rejected",
    409: "state_changed",
    413: "request_rejected",
    415: "media_type_rejected",
    422: "request_rejected",
    429: "rate_limited",
    503: "access_unavailable",
}


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True, slots=True)
class ReconnectPackage:
    agent_id: str
    agent_name: str
    base_url: str
    ca_root: bytes = field(repr=False)
    ca_sha256: str
    expires_at: datetime
    grant: str = field(repr=False)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _package_fields(raw: bytes) -> dict[str, object]:
    payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    if (
        not isinstance(payload, dict) or set(payload) != _FIELDS
        or type(payload["version"]) is not int or payload["version"] != 1
        or any(not isinstance(payload[key], str) for key in _FIELDS - {"version"})
    ):
        raise ValueError("invalid package")
    return payload


def _require_agent_identity(agent_id: str, name: str) -> None:
    if str(UUID(agent_id)) != agent_id:
        raise ValueError("invalid identity")
    if len(name) > 128 or normalize_name(name, agent=True) != name:
        raise ValueError("invalid name")


def _require_printable_ascii_origin(origin: str) -> None:
    if (
        len(origin) > 2048 or not origin.isascii()
        or any(ord(character) < 33 or ord(character) == 127 for character in origin)
    ):
        raise ValueError("invalid origin")


def _has_user_information(parsed: SplitResult) -> bool:
    return parsed.username is not None or parsed.password is not None


def _has_location(parsed: SplitResult) -> bool:
    return bool(parsed.path or parsed.query or parsed.fragment)


def _require_bare_https_origin(origin: str) -> None:
    _require_printable_ascii_origin(origin)
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https" or not parsed.hostname
        or _has_user_information(parsed) or _has_location(parsed)
        or (parsed.port is not None and not 1 <= parsed.port <= 65_535)
    ):
        raise ValueError("invalid origin")


def _unexpired_grant_expiry(expires_at: str, grant: str, now: datetime | None) -> datetime:
    expiry = datetime.fromisoformat(expires_at)
    instant = datetime.now(UTC) if now is None else now
    if (
        expiry.tzinfo is None or expiry.utcoffset() != timedelta(0)
        or not instant < expiry <= instant + timedelta(seconds=900)
        or _GRANT.fullmatch(grant) is None
    ):
        raise ValueError("expired or invalid grant")
    return expiry


def decode_package(raw: bytes, *, now: datetime | None = None) -> ReconnectPackage:
    if len(raw) > MAX_PACKAGE_BYTES:
        raise ConfigurationError("reconnect package is too large")
    try:
        payload = _package_fields(raw)
        name = payload["agent_name"]
        _require_agent_identity(payload["agent_id"], name)
        origin = payload["base_url"]
        _require_bare_https_origin(origin)
        expiry = _unexpired_grant_expiry(payload["expires_at"], payload["grant"], now)
        anchor = validate_trust_anchor(
            payload["ca_root"].encode("ascii"), payload["ca_sha256"],
        )
        return ReconnectPackage(
            agent_id=payload["agent_id"], agent_name=name, base_url=origin,
            ca_root=anchor, ca_sha256=payload["ca_sha256"],
            expires_at=expiry, grant=payload["grant"],
        )
    except (ValueError, UnicodeError, RecursionError, DomainValidationError, TrustAnchorError):
        raise ConfigurationError("reconnect package is invalid or expired") from None


def encode_package(
    *, agent_id: str, agent_name: str, base_url: str, ca_root: bytes,
    ca_sha256: str, expires_at: datetime, grant: str,
    now: datetime | None = None,
) -> bytes:
    try:
        raw = json.dumps({
            "version": 1, "agent_id": agent_id, "agent_name": agent_name,
            "base_url": base_url.rstrip("/"), "ca_root": ca_root.decode("ascii"),
            "ca_sha256": ca_sha256, "expires_at": expires_at.isoformat(), "grant": grant,
        }, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    except (UnicodeError, ValueError, TypeError):
        raise ConfigurationError("reconnect package could not be prepared") from None
    decode_package(raw, now=now)
    return raw


def _exchange(request: Request, context: ssl.SSLContext) -> bytes:
    opener = build_opener(
        ProxyHandler({}), HTTPSHandler(context=context), NoRedirectHandler(),
    )
    try:
        response = opener.open(request, timeout=REDEMPTION_TIMEOUT_SECONDS)
    except HTTPError as error:
        status = error.code
        error.close()
        reason = _HTTP_REJECTIONS.get(status)
        if reason is not None or 300 <= status < 500:
            raise ReconnectError(
                f"reconnect rejected by server: {reason or 'http_rejected'} "
                f"(HTTP {status}); do not retry this package; explicit operator "
                "reissue is required; old credentials remain revoked",
                outcome="rejected",
                http_status=status,
            ) from None
        raise ReconnectError(
            f"reconnect server response was inconclusive (HTTP {status}); the "
            "result is uncertain; do not retry this package; explicit operator "
            "reissue is required; old credentials remain revoked",
            outcome="unknown",
            http_status=status,
        ) from None
    with response:
        if response.status != 201:
            raise ReconnectError(
                "reconnect server response was inconclusive; the result is uncertain; "
                "do not retry this package; explicit operator reissue is required; "
                "old credentials remain revoked"
            )
        value = response.read(MAX_REDEMPTION_RESPONSE_BYTES + 1)
        if len(value) > MAX_REDEMPTION_RESPONSE_BYTES:
            raise ReconnectError(
                "reconnect response is invalid and the result is uncertain; do not "
                "retry this package; explicit operator reissue is required; old "
                "credentials remain revoked"
            )
        return value


def _names_packaged_agent(
    agent: object, credential: object, package: ReconnectPackage,
) -> bool:
    return (
        isinstance(agent, dict) and isinstance(credential, dict)
        and agent.get("id") == package.agent_id
        and agent.get("name") == package.agent_name
        and credential.get("agent_id") == package.agent_id
    )


def _is_pending_record_of(credential: dict, parsed: tuple | None) -> bool:
    return (
        credential.get("kind") == "sb1" and credential.get("status") == "pending"
        and parsed is not None and parsed[0] == "sb1"
        and credential.get("id") == parsed[1]
    )


def _credential_from_response(raw: bytes, package: ReconnectPackage) -> str:
    if len(raw) > MAX_REDEMPTION_RESPONSE_BYTES:
        raise ValueError("oversized response")
    payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(payload, dict):
        raise ValueError("invalid response")
    agent = payload.get("agent")
    credential = payload.get("credential")
    secret = payload.get("credential_secret")
    parsed = parse_credential(secret) if isinstance(secret, str) else None
    if (
        not _names_packaged_agent(agent, credential, package)
        or not _is_pending_record_of(credential, parsed)
    ):
        raise ValueError("identity or pending credential mismatch")
    return secret


def _remove_reserved_output(path: Path, identity: tuple[int, int]) -> None:
    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    if (current.st_dev, current.st_ino) != identity:
        raise ReconnectError(
            "private output changed; it was not removed; operator reissue is required"
        )
    path.unlink()


def _redemption_request(package: ReconnectPackage) -> Request:
    return Request(
        package.base_url + "/api/reconnect/redeem",
        data=json.dumps({
            "request_id": str(uuid4()), "expected_agent_id": package.agent_id,
            "expected_agent_name": package.agent_name,
        }, separators=(",", ":")).encode("ascii"),
        headers={
            "Authorization": f"Bearer {package.grant}",
            "Content-Type": "application/json", "Accept": "application/json",
        },
        method="POST",
    )


def _write_private_line(descriptor: int, secret: str) -> None:
    value = memoryview(secret.encode("ascii") + b"\n")
    while value:
        written = os.write(descriptor, value)
        if written <= 0:
            raise OSError("private write did not progress")
        value = value[written:]
    os.fsync(descriptor)


def _fsync_parent(path: Path) -> None:
    if os.name != "nt":
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)


def _store_credential(
    descriptor: int, credential_output: Path, identity: tuple[int, int], secret: str,
) -> None:
    require_private_path(credential_output, directory=False, outside_repository=True)
    current = credential_output.lstat()
    if (current.st_dev, current.st_ino) != identity:
        raise ValueError("private output changed")
    _write_private_line(descriptor, secret)
    current = credential_output.lstat()
    if (current.st_dev, current.st_ino) != identity or current.st_nlink != 1:
        raise ValueError("private output changed")
    require_private_path(credential_output, directory=False, outside_repository=True)
    _fsync_parent(credential_output)


def redeem_package(
    package_file: Path, credential_output: Path,
    *, exchange: Callable[[Request, ssl.SSLContext], bytes] = _exchange,
) -> ReconnectPackage:
    package = decode_package(read_private_file(package_file, maximum=MAX_PACKAGE_BYTES))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=package.ca_root.decode("ascii"))
    request = _redemption_request(package)
    descriptor = open_private_output(credential_output)
    metadata = os.fstat(descriptor)
    identity = metadata.st_dev, metadata.st_ino
    complete = False
    try:
        raw = exchange(request, context)
        secret = _credential_from_response(raw, package)
        _store_credential(descriptor, credential_output, identity, secret)
        complete = True
    except (OSError, URLError, ValueError, UnicodeError, RecursionError, TrustAnchorError,
            ConfigurationError):
        raise ReconnectError(
            "reconnect failed or its result is uncertain; explicit operator reissue "
            "is required; old credentials remain revoked"
        ) from None
    finally:
        os.close(descriptor)
        if not complete:
            try:
                _remove_reserved_output(credential_output, identity)
            except OSError:
                raise ReconnectError(
                    "private output cleanup failed; operator reissue is required"
                ) from None
    return package
