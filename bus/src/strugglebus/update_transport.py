"""Bounded anonymous read transport with no ambient credentials or proxies."""

from __future__ import annotations

from contextlib import contextmanager
from email.message import Message
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import socket
import stat
import time
from typing import Any, Iterator
import urllib.error
import urllib.request

from .release_transport import (
    ASSET_ACCEPT, GITHUB_API_HOST, GITHUB_ASSET_HOST, ReleasePublicationError,
    _AssetRedirects, _RejectRedirects, _exact_https_host, _response_media_type,
)
from .update_types import UpdateAsset, UpdateError, UpdateLimits

API = "https://api.github.com"
API_VERSION = "2022-11-28"
_CLOCK = time.monotonic
_SLEEP = time.sleep
# 429 is not here: asking again at once is what a limit is for stopping.
_TRANSIENT = frozenset({500, 502, 503, 504})


def _limited(code: int, headers: Any) -> bool:
    """
    Whether the source refused because of its request limit. GitHub answers 403 with no requests
    remaining, or 429. Known apart from other refusals so the operator is told the real cause,
    which no retry mends and which passes by itself.
    """
    if code == 429:
        return True
    return code == 403 and headers is not None and headers.get("x-ratelimit-remaining") == "0"
_NETWORK_ERRORS = (OSError, socket.timeout, http.client.HTTPException)


def remaining(deadline: float) -> float:
    if type(deadline) not in {int, float} or not math.isfinite(deadline):
        raise UpdateError("timeout")
    value = deadline - _CLOCK()
    if value <= 0:
        raise UpdateError("timeout")
    return value


def budget(deadline: float, seconds: int) -> float:
    return _CLOCK() + min(remaining(deadline), seconds)


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise UpdateError("invalid_metadata")
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise UpdateError("invalid_metadata")


def decode(payload: bytes) -> Any:
    try:
        value = json.loads(payload, object_pairs_hook=_pairs, parse_constant=_constant)
        _depth(value)
        return value
    except (UnicodeError, ValueError, RecursionError):
        raise UpdateError("invalid_metadata") from None


def _depth(value: Any, level: int = 0) -> None:
    if level > 16:
        raise UpdateError("invalid_metadata")
    if isinstance(value, dict):
        for item in value.values():
            _depth(item, level + 1)
    elif isinstance(value, list):
        for item in value:
            _depth(item, level + 1)


def _content_length(headers: Any) -> Any:
    """Return the single Content-Length header, refusing a repeated one."""
    values = headers.get_all("Content-Length") if hasattr(headers, "get_all") else None
    if values is not None and len(values) > 1:
        raise UpdateError("invalid_metadata")
    return headers.get("Content-Length")


def _size(headers: Any, maximum: int) -> int | None:
    value = _content_length(headers)
    if value is None:
        return None
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise UpdateError("invalid_metadata")
    if len(value) > 10 or int(value) > maximum:
        raise UpdateError("verification_failed")
    return int(value)


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def private_directory(path: Path, *, empty: bool = False) -> os.stat_result:
    absolute = path.absolute()
    info = absolute.lstat()
    if not stat.S_ISDIR(info.st_mode) or absolute.resolve(strict=True) != absolute:
        raise UpdateError("storage_unsafe")
    if os.name == "posix":
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise UpdateError("storage_unsafe")
    if empty and any(absolute.iterdir()):
        raise UpdateError("storage_unsafe")
    return info


@contextmanager
def exclusive_file(path: Path) -> Iterator[Any]:
    parent = private_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        else:
            os.chmod(path, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise UpdateError("storage_unsafe")
        if _identity(parent) != _identity(private_directory(path.parent)):
            raise UpdateError("storage_unsafe")
        with os.fdopen(fd, "wb", closefd=False) as stream:
            yield stream
            stream.flush()
            os.fsync(fd)
        if _identity(info) != _identity(path.lstat()):
            raise UpdateError("storage_unsafe")
    finally:
        os.close(fd)


class _HTTP:
    def __init__(self, limits: UpdateLimits, deadline: float):
        self.limits = limits
        self.deadline = deadline
        self._metadata = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _RejectRedirects(),
        )
        self._assets = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _DeadlineAssetRedirects(deadline),
        )

    def _timeout(self) -> float:
        return min(self.limits.request_timeout, remaining(self.deadline))

    def _request(self, path: str, *, asset: bool = False) -> urllib.request.Request:
        if not path.startswith("/") or path.startswith("//") or "#" in path:
            raise UpdateError("invalid_metadata")
        return urllib.request.Request(
            API + path,
            headers={
                "Accept": ASSET_ACCEPT if asset else "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "strugglebus-update-reader-v1",
            },
            method="GET",
        )

    def _open(self, request: urllib.request.Request, *, asset: bool = False) -> Any:
        opener = self._assets if asset else self._metadata
        try:
            return opener.open(request, timeout=self._timeout())
        except urllib.error.HTTPError as error:
            code = error.code
            limited = _limited(code, error.headers)
            error.close()
            if limited:
                raise UpdateError("rate_limited") from None
            if code in _TRANSIENT:
                raise _Retry() from None
            if code == 404:
                raise SourceMissing() from None
            raise UpdateError("source_unavailable") from None
        except ReleasePublicationError:
            raise UpdateError("invalid_metadata") from None
        except _NETWORK_ERRORS:
            raise _Retry() from None

    def _check_response(self, response: Any, *, asset: bool = False, status: int = 200) -> None:
        hosts = {GITHUB_API_HOST, GITHUB_ASSET_HOST} if asset else {GITHUB_API_HOST}
        try:
            _exact_https_host(response.geturl(), allowed_hosts=frozenset(hosts),
                              error_message="untrusted response")
        except ReleasePublicationError:
            raise UpdateError("invalid_metadata") from None
        if response.status != status or response.headers.get("Content-Encoding") not in {None, "identity"}:
            raise UpdateError("invalid_metadata")

    def _wait(self, attempt: int) -> None:
        delay = min(2 ** attempt, self.limits.retry_delay)
        if remaining(self.deadline) <= delay:
            raise UpdateError("timeout")
        _SLEEP(delay)

    def json(self, path: str) -> tuple[Any, bool]:
        request = self._request(path)
        attempt = 0
        while True:
            try:
                return self._json_once(request)
            except (_Retry, *_NETWORK_ERRORS):
                if attempt + 1 == self.limits.request_attempts:
                    raise UpdateError("source_unavailable") from None
                self._wait(attempt)
                attempt += 1

    def _json_once(self, request: urllib.request.Request) -> tuple[Any, bool]:
        with self._open(request) as response:
            self._check_response(response)
            if _response_media_type(response.headers) not in {"application/json", "application/vnd.github+json"}:
                raise UpdateError("invalid_metadata")
            maximum = self.limits.metadata_bytes
            expected = _size(response.headers, maximum)
            content = self._read(response, maximum)
            if expected is not None and expected != len(content):
                raise UpdateError("invalid_metadata")
            link = response.headers.get("Link", "")
            return decode(content), 'rel="next"' in link

    def _read(self, response: Any, maximum: int) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = self._chunk(response, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise UpdateError("verification_failed")

    def _chunk(self, response: Any, maximum: int) -> bytes:
        timeout = self._timeout()
        raw = getattr(getattr(response, "fp", None), "raw", None)
        connection = getattr(raw, "_sock", None)
        if connection is not None:
            connection.settimeout(timeout)
        # read1 performs at most one socket read, so drip-fed bodies cannot keep
        # read(n) internally looping past the next absolute-deadline check.
        read = getattr(response, "read1", response.read)
        return read(maximum)

    def download(self, path: str, asset: UpdateAsset, destination: Path) -> None:
        request = self._request(path, asset=True)
        # A failed partial transfer is not retried into or beside the quarantine.
        attempt = 0
        while True:
            try:
                response = self._open(request, asset=True)
                break
            except _Retry:
                if attempt + 1 == self.limits.request_attempts:
                    raise UpdateError("source_unavailable") from None
                self._wait(attempt)
                attempt += 1
        try:
            with response:
                self._download_response(response, asset, destination)
        except _NETWORK_ERRORS:
            raise UpdateError("source_unavailable") from None

    def _download_response(self, response: Any, asset: UpdateAsset, destination: Path) -> None:
        self._check_response(response, asset=True)
        if _response_media_type(response.headers) not in {ASSET_ACCEPT, asset.media_type}:
            raise UpdateError("invalid_metadata")
        if _size(response.headers, asset.size_bytes) != asset.size_bytes:
            raise UpdateError("invalid_metadata")
        _disposition(response.headers, asset.name)
        digest = hashlib.sha256()
        total = 0
        started = _CLOCK()
        with exclusive_file(destination) as output:
            while True:
                chunk = self._chunk(response, min(64 * 1024, asset.size_bytes + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > asset.size_bytes:
                    raise UpdateError("verification_failed")
                digest.update(chunk)
                output.write(chunk)
                self._throttle(total, started)
        if total != asset.size_bytes or digest.hexdigest() != asset.sha256:
            raise UpdateError("verification_failed")

    def _throttle(self, total: int, started: float) -> None:
        delay = total / self.limits.bytes_per_second - (_CLOCK() - started)
        if delay > 0:
            if delay >= remaining(self.deadline):
                raise UpdateError("timeout")
            _SLEEP(delay)


class SourceMissing(UpdateError):
    """
    The source answered that there is nothing at the address. To every caller that does not ask
    for it by name this is the same failure as before, the source being unavailable.
    """

    def __init__(self) -> None:
        super().__init__("source_unavailable")


class _Retry(Exception):
    """Internal, content-free transient failure."""


class _DeadlineAssetRedirects(_AssetRedirects):
    def __init__(self, deadline: float):
        self._deadline = deadline

    def redirect_request(self, request, file, code, message, headers, new_url):
        request.timeout = min(request.timeout, remaining(self._deadline))
        return super().redirect_request(request, file, code, message, headers, new_url)


def _disposition(headers: Any, expected_name: str) -> None:
    value = headers.get("Content-Disposition")
    if not isinstance(value, str):
        raise UpdateError("invalid_metadata")
    parsed = Message()
    parsed["Content-Disposition"] = value
    if parsed.get_content_disposition() != "attachment" or parsed.get_filename() != expected_name:
        raise UpdateError("invalid_metadata")
