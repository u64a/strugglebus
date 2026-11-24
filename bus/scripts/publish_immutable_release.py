"""Reconcile and publish one fully validated immutable GitHub Release."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from email.message import Message
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import tempfile
import time
from typing import Any, Callable, Protocol
import urllib.error
import urllib.parse
import urllib.request

from release_bundle import (
    CHECKSUMS_NAME,
    MANIFEST_NAME,
    MAX_ASSET_BYTES,
    REPOSITORY_ID,
    validate_bundle,
)
from release_qualification import (
    QualificationBinding,
    helper_digest,
    verify_qualified_release,
)
from validate_release_trigger import (
    APIClient,
    GITHUB_API_URL,
    validate_release_trigger,
)

from strugglebus.release_transport import (
    ASSET_ACCEPT,
    GITHUB_API_HOST,
    GITHUB_ASSET_HOST,
    ReleasePublicationError,
    USER_AGENT,
    _AssetRedirects,
    _RejectRedirects,
    _exact_https_host,
    _response_media_type,
)

from strugglebus.release_records import (
    LocalAsset,
    _asset_media_type,
    _positive_id,
    _release_body,
    _validate_asset_records,
    _validate_release_record,
)


MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_RELEASE_PAGES = 10
PAGE_SIZE = 100
REQUEST_TIMEOUT_SECONDS = 30
READ_ATTEMPTS = 3
MAX_RETRY_DELAY_SECONDS = 5
TRANSIENT_STATUSES = frozenset({429, 500, 502, 503, 504})
UPLOAD_API_URL = "https://uploads.github.com"


class ReleaseReadAPI(APIClient, Protocol):
    def find_release(
        self,
        repository: str,
        tag: str,
    ) -> dict[str, Any] | None: ...

    def list_assets(
        self,
        repository: str,
        release_id: int,
    ) -> list[dict[str, Any]]: ...

    def download_asset(
        self,
        repository: str,
        asset_id: int,
        destination: Path,
        *,
        expected_name: str,
        expected_size: int,
        expected_media_type: str,
        expected_sha256: str,
    ) -> None: ...


class ReleaseAPI(ReleaseReadAPI, Protocol):
    def create_draft(
        self,
        repository: str,
        tag: str,
        commit: str,
        body: str,
    ) -> dict[str, Any]: ...

    def upload_asset(
        self,
        repository: str,
        release_id: int,
        asset: LocalAsset,
    ) -> dict[str, Any]: ...

    def publish_release(
        self,
        repository: str,
        release_id: int,
    ) -> dict[str, Any]: ...


def _json_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleasePublicationError(f"{label} must be an object")
    return value


def _json_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReleasePublicationError(f"{label} must be an array")
    return value


class GitHubReleaseAPI:
    def __init__(
        self,
        api_url: str,
        token: str,
        *,
        sleep: Callable[[float], None] = time.sleep,
        json_opener: Any | None = None,
        asset_opener: Any | None = None,
    ) -> None:
        if api_url.rstrip("/") != GITHUB_API_URL:
            raise ReleasePublicationError("GitHub API origin is not the pinned origin")
        if (
            not token
            or len(token) > 4096
            or not token.isascii()
            or any(character.isspace() for character in token)
        ):
            raise ReleasePublicationError("GitHub API token has an invalid format")
        self.api_url = GITHUB_API_URL
        self._token = token
        self._sleep = sleep
        self._json_opener = json_opener or urllib.request.build_opener(
            _RejectRedirects()
        )
        self._asset_opener = asset_opener or urllib.request.build_opener(
            _AssetRedirects()
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(api_url={self.api_url!r})"

    def _headers(
        self,
        *,
        accept: str = "application/vnd.github+json",
        content_type: str | None = None,
    ) -> dict[str, str]:
        headers = {
            "Accept": accept,
            "Authorization": f"Bearer {self._token}",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if content_type is not None:
            headers["Content-Type"] = content_type
        return headers

    def _api_request_url(self, path: str) -> str:
        if (
            not path
            or "://" in path
            or path.startswith("//")
            or any(ord(character) < 32 for character in path)
        ):
            raise ReleasePublicationError("GitHub API path is invalid")
        return f"{self.api_url}/{path.lstrip('/')}"

    def _retry_delay(self, attempt: int, headers: Any | None) -> None:
        delay = min(0.25 * (2**attempt), MAX_RETRY_DELAY_SECONDS)
        if headers is not None:
            retry_after = headers.get("Retry-After")
            if isinstance(retry_after, str) and retry_after.isdecimal():
                delay = min(int(retry_after), MAX_RETRY_DELAY_SECONDS)
        self._sleep(delay)

    def _decode_json_response(
        self,
        response: Any,
        *,
        expected_status: int,
        expected_host: str,
    ) -> Any:
        if response.status != expected_status:
            raise ReleasePublicationError(
                f"GitHub API returned unexpected status {response.status}"
            )
        final_url = urllib.parse.urlsplit(response.geturl())
        try:
            final_port = final_url.port
        except ValueError as error:
            raise ReleasePublicationError(
                "GitHub API response origin has an invalid port"
            ) from error
        if (
            final_url.scheme != "https"
            or (final_url.hostname or "").casefold() != expected_host
            or final_url.username is not None
            or final_url.password is not None
            or final_port not in {None, 443}
        ):
            raise ReleasePublicationError("GitHub API response origin changed")
        if _response_media_type(response.headers) not in {
            "application/json",
            "application/vnd.github+json",
        }:
            raise ReleasePublicationError("GitHub API returned a non-JSON media type")
        content = response.read(MAX_RESPONSE_BYTES + 1)
        if len(content) > MAX_RESPONSE_BYTES:
            raise ReleasePublicationError("GitHub API response exceeds its size limit")
        try:
            value = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ReleasePublicationError(
                "GitHub API returned invalid JSON"
            ) from error
        if not isinstance(value, (dict, list)):
            raise ReleasePublicationError(
                "GitHub API response must be an object or array"
            )
        return value

    def _request_json(
        self,
        path: str,
        *,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
        expected_status: int = 200,
        allow_not_found: bool = False,
    ) -> Any | None:
        if method not in {"GET", "POST", "PATCH"}:
            raise ReleasePublicationError("GitHub API method is invalid")
        body = None
        if payload is not None:
            body = json.dumps(
                payload,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        attempts = READ_ATTEMPTS if method == "GET" else 1
        url = self._api_request_url(path)
        for attempt in range(attempts):
            request = urllib.request.Request(
                url,
                data=body,
                headers=self._headers(
                    content_type="application/json" if body is not None else None
                ),
                method=method,
            )
            try:
                # The request origin is fixed by _api_request_url.
                with self._json_opener.open(  # nosec B310
                    request,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                ) as response:
                    return self._decode_json_response(
                        response,
                        expected_status=expected_status,
                        expected_host="api.github.com",
                    )
            except urllib.error.HTTPError as error:
                status = error.code
                response_headers = error.headers
                error.close()
                if status == 404 and allow_not_found:
                    return None
                if method == "GET" and status in TRANSIENT_STATUSES:
                    if attempt + 1 < attempts:
                        self._retry_delay(attempt, response_headers)
                        continue
                if status in {401, 403}:
                    raise ReleasePublicationError(
                        "GitHub API authorization failed"
                    ) from None
                raise ReleasePublicationError(
                    f"GitHub API request failed with status {status}"
                ) from None
            except (urllib.error.URLError, socket.timeout, TimeoutError, OSError):
                if method == "GET" and attempt + 1 < attempts:
                    self._retry_delay(attempt, None)
                    continue
                raise ReleasePublicationError(
                    "GitHub API network request failed"
                ) from None
        raise ReleasePublicationError("GitHub API read retries were exhausted")

    def get(self, path: str) -> Any:
        value = self._request_json(path)
        if value is None:
            raise ReleasePublicationError("GitHub API unexpectedly returned no value")
        return value

    def find_release(
        self,
        repository: str,
        tag: str,
    ) -> dict[str, Any] | None:
        self._require_repository(repository)
        encoded_tag = urllib.parse.quote(tag, safe="")
        direct = self._request_json(
            f"repos/{repository}/releases/tags/{encoded_tag}",
            allow_not_found=True,
        )
        if direct is not None:
            direct = _json_object(direct, "release lookup")
            if direct.get("tag_name") != tag:
                raise ReleasePublicationError("release lookup returned the wrong tag")

        matches: dict[int, dict[str, Any]] = {}
        exhausted = False
        for page in range(1, MAX_RELEASE_PAGES + 1):
            query = urllib.parse.urlencode(
                {"page": str(page), "per_page": str(PAGE_SIZE)}
            )
            records = _json_list(
                self._request_json(f"repos/{repository}/releases?{query}"),
                "release list",
            )
            if len(records) > PAGE_SIZE:
                raise ReleasePublicationError("release list exceeds its page limit")
            for record_value in records:
                record = _json_object(record_value, "release list record")
                if record.get("tag_name") != tag:
                    continue
                release_id = _positive_id(record.get("id"), "release ID")
                existing = matches.get(release_id)
                if existing is not None and any(
                    existing.get(key) != record.get(key)
                    for key in (
                        "body",
                        "draft",
                        "immutable",
                        "name",
                        "prerelease",
                        "tag_name",
                        "target_commitish",
                    )
                ):
                    raise ReleasePublicationError(
                        "release changed during duplicate detection"
                    )
                matches[release_id] = record
            if len(records) < PAGE_SIZE:
                exhausted = True
                break
        if not exhausted:
            raise ReleasePublicationError(
                "release list is too large for complete duplicate detection"
            )
        if direct is not None:
            release_id = _positive_id(direct.get("id"), "release ID")
            listed = matches.get(release_id)
            if listed is not None and any(
                listed.get(key) != direct.get(key)
                for key in (
                    "body",
                    "draft",
                    "immutable",
                    "name",
                    "prerelease",
                    "tag_name",
                    "target_commitish",
                )
            ):
                raise ReleasePublicationError("release changed during lookup")
            matches[release_id] = direct
        if len(matches) > 1:
            raise ReleasePublicationError(
                "multiple releases use the candidate tag"
            )
        return next(iter(matches.values()), None)

    def create_draft(
        self,
        repository: str,
        tag: str,
        commit: str,
        body: str,
    ) -> dict[str, Any]:
        self._require_repository(repository)
        value = self._request_json(
            f"repos/{repository}/releases",
            method="POST",
            payload={
                "body": body,
                "draft": True,
                "make_latest": "false",
                "name": tag,
                "prerelease": False,
                "tag_name": tag,
                "target_commitish": commit,
            },
            expected_status=201,
        )
        return _json_object(value, "created release")

    def list_assets(
        self,
        repository: str,
        release_id: int,
    ) -> list[dict[str, Any]]:
        self._require_repository(repository)
        release_id = _positive_id(release_id, "release ID")
        query = urllib.parse.urlencode({"per_page": str(PAGE_SIZE)})
        records = _json_list(
            self._request_json(
                f"repos/{repository}/releases/{release_id}/assets?{query}"
            ),
            "release asset list",
        )
        if len(records) >= PAGE_SIZE:
            raise ReleasePublicationError(
                "release asset list is too large to reconcile safely"
            )
        return [
            _json_object(record, "release asset record")
            for record in records
        ]

    def upload_asset(
        self,
        repository: str,
        release_id: int,
        asset: LocalAsset,
    ) -> dict[str, Any]:
        self._require_repository(repository)
        release_id = _positive_id(release_id, "release ID")
        if asset.size <= 0 or asset.size > MAX_ASSET_BYTES:
            raise ReleasePublicationError("local release asset size is invalid")
        query = urllib.parse.urlencode({"name": asset.name})
        url = (
            f"{UPLOAD_API_URL}/repos/{repository}/releases/{release_id}/assets?"
            f"{query}"
        )
        headers = self._headers(content_type=asset.media_type)
        headers["Content-Length"] = str(asset.size)
        try:
            with asset.path.open("rb") as stream:
                request = urllib.request.Request(
                    url,
                    data=stream,
                    headers=headers,
                    method="POST",
                )
                # The upload origin is the fixed UPLOAD_API_URL.
                with self._json_opener.open(  # nosec B310
                    request,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                ) as response:
                    value = self._decode_json_response(
                        response,
                        expected_status=201,
                        expected_host="uploads.github.com",
                    )
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            if status in {401, 403}:
                raise ReleasePublicationError(
                    "GitHub asset upload authorization failed"
                ) from None
            raise ReleasePublicationError(
                f"GitHub asset upload failed with status {status}"
            ) from None
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError):
            raise ReleasePublicationError(
                "GitHub asset upload network request failed"
            ) from None
        return _json_object(value, "uploaded asset")

    def download_asset(
        self,
        repository: str,
        asset_id: int,
        destination: Path,
        *,
        expected_name: str,
        expected_size: int,
        expected_media_type: str,
        expected_sha256: str,
    ) -> None:
        self._require_repository(repository)
        asset_id = _positive_id(asset_id, "asset ID")
        if (
            destination.name != expected_name
            or expected_size <= 0
            or expected_size > MAX_ASSET_BYTES
            or destination.exists()
            or destination.is_symlink()
            or len(expected_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in expected_sha256
            )
        ):
            raise ReleasePublicationError("asset download destination is unsafe")
        url = self._api_request_url(
            f"repos/{repository}/releases/assets/{asset_id}"
        )
        for attempt in range(READ_ATTEMPTS):
            destination.unlink(missing_ok=True)
            request_headers = self._headers(accept=ASSET_ACCEPT)
            authorization = request_headers.pop("Authorization")
            request = urllib.request.Request(url, headers=request_headers, method="GET")
            request.add_unredirected_header("Authorization", authorization)
            try:
                # The handler creates a fresh target request after urllib injects Host.
                with self._asset_opener.open(  # nosec B310
                    request,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                ) as response:
                    self._write_asset_response(
                        response,
                        destination,
                        expected_name=expected_name,
                        expected_size=expected_size,
                        expected_media_type=expected_media_type,
                        expected_sha256=expected_sha256,
                    )
                return
            except ReleasePublicationError:
                destination.unlink(missing_ok=True)
                raise
            except urllib.error.HTTPError as error:
                status = error.code
                response_headers = error.headers
                response_url = error.geturl()
                error.close()
                destination.unlink(missing_ok=True)
                response_host = _exact_https_host(
                    response_url,
                    allowed_hosts=frozenset(
                        {GITHUB_API_HOST, GITHUB_ASSET_HOST}
                    ),
                    error_message="GitHub asset error response origin is not trusted",
                )
                if status in TRANSIENT_STATUSES and attempt + 1 < READ_ATTEMPTS:
                    self._retry_delay(attempt, response_headers)
                    continue
                if response_host == GITHUB_API_HOST and status in {401, 403}:
                    raise ReleasePublicationError(
                        "GitHub asset download authorization failed"
                    ) from None
                if response_host == GITHUB_API_HOST and status == 404:
                    raise ReleasePublicationError(
                        "GitHub release asset disappeared"
                    ) from None
                if response_host == GITHUB_ASSET_HOST:
                    raise ReleasePublicationError(
                        f"GitHub asset delivery failed with status {status}"
                    ) from None
                raise ReleasePublicationError(
                    f"GitHub asset API request failed with status {status}"
                ) from None
            except (urllib.error.URLError, socket.timeout, TimeoutError, OSError):
                destination.unlink(missing_ok=True)
                if attempt + 1 < READ_ATTEMPTS:
                    self._retry_delay(attempt, None)
                    continue
                raise ReleasePublicationError(
                    "GitHub asset download network request failed"
                ) from None
        raise ReleasePublicationError("GitHub asset download retries were exhausted")

    def _write_asset_response(
        self,
        response: Any,
        destination: Path,
        *,
        expected_name: str,
        expected_size: int,
        expected_media_type: str,
        expected_sha256: str,
    ) -> None:
        if response.status != 200:
            raise ReleasePublicationError(
                f"GitHub asset download returned status {response.status}"
            )
        _exact_https_host(
            response.geturl(),
            allowed_hosts=frozenset({GITHUB_API_HOST, GITHUB_ASSET_HOST}),
            error_message="GitHub asset response origin is not trusted",
        )
        media_type = _response_media_type(response.headers)
        if media_type not in {
            expected_media_type.casefold(),
            "application/octet-stream",
        }:
            raise ReleasePublicationError("GitHub asset media type is unexpected")
        disposition_value = response.headers.get("Content-Disposition")
        if not isinstance(disposition_value, str):
            raise ReleasePublicationError(
                "GitHub asset response lacks content disposition"
            )
        disposition = Message()
        disposition["Content-Disposition"] = disposition_value
        if (
            disposition.get_content_disposition() != "attachment"
            or disposition.get_filename() != expected_name
        ):
            raise ReleasePublicationError(
                "GitHub asset response filename is unexpected"
            )
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            if not content_length.isdecimal() or int(content_length) != expected_size:
                raise ReleasePublicationError(
                    "GitHub asset response length is unexpected"
                )
        written = 0
        downloaded_digest = hashlib.sha256()
        with destination.open("xb") as stream:
            while True:
                chunk = response.read(min(1024 * 1024, expected_size - written + 1))
                if not chunk:
                    break
                written += len(chunk)
                if written > expected_size:
                    raise ReleasePublicationError(
                        "GitHub asset response exceeds the expected size"
                    )
                stream.write(chunk)
                downloaded_digest.update(chunk)
        if written != expected_size:
            raise ReleasePublicationError(
                "GitHub asset response is shorter than expected"
            )
        if not hmac.compare_digest(
            downloaded_digest.hexdigest(),
            expected_sha256,
        ):
            raise ReleasePublicationError(
                "GitHub asset response digest is unexpected"
            )

    def publish_release(
        self,
        repository: str,
        release_id: int,
    ) -> dict[str, Any]:
        self._require_repository(repository)
        release_id = _positive_id(release_id, "release ID")
        value = self._request_json(
            f"repos/{repository}/releases/{release_id}",
            method="PATCH",
            payload={"draft": False, "make_latest": "false"},
        )
        return _json_object(value, "published release")

    @staticmethod
    def _require_repository(repository: str) -> None:
        if repository != REPOSITORY_ID:
            raise ReleasePublicationError("release repository identity mismatch")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _local_assets(directory: Path) -> dict[str, LocalAsset]:
    paths = sorted(directory.iterdir(), key=lambda path: path.name)
    names = {path.name for path in paths}
    wheels = {name for name in names if name.endswith(".whl")}
    support_archives = {name for name in names if name.endswith(".tar.gz")}
    expected = {
        MANIFEST_NAME,
        CHECKSUMS_NAME,
        "requirements.lock",
        *wheels,
        *support_archives,
    }
    if (
        names != expected
        or len(wheels) != 1
        or len(support_archives) != 1
        or len(names) != 5
    ):
        raise ReleasePublicationError("local release asset set is unexpected")
    assets: dict[str, LocalAsset] = {}
    for path in paths:
        metadata = path.stat()
        if (
            not path.is_file()
            or path.is_symlink()
            or metadata.st_size <= 0
            or metadata.st_size > MAX_ASSET_BYTES
        ):
            raise ReleasePublicationError(
                f"local release asset is unsafe: {path.name}"
            )
        assets[path.name] = LocalAsset(
            name=path.name,
            path=path,
            size=metadata.st_size,
            digest=_sha256(path),
            media_type=_asset_media_type(path.name),
        )
    return assets


def _files_equal(left: Path, right: Path) -> bool:
    if left.stat().st_size != right.stat().st_size:
        return False
    with left.open("rb") as left_stream, right.open("rb") as right_stream:
        while True:
            left_chunk = left_stream.read(1024 * 1024)
            right_chunk = right_stream.read(1024 * 1024)
            if left_chunk != right_chunk:
                return False
            if not left_chunk:
                return True


def _download_asset_copy(
    api: ReleaseReadAPI,
    repository: str,
    record: dict[str, Any],
    expected: LocalAsset,
    destination: Path,
) -> None:
    api.download_asset(
        repository,
        _positive_id(record.get("id"), "asset ID"),
        destination,
        expected_name=expected.name,
        expected_size=expected.size,
        expected_media_type=expected.media_type,
        expected_sha256=expected.digest,
    )
    if not _files_equal(expected.path, destination):
        raise ReleasePublicationError(
            f"downloaded release asset bytes differ: {expected.name}"
        )


def _validate_downloaded_bundle(
    directory: Path,
    local_assets: dict[str, LocalAsset],
    *,
    repository: str,
    tag: str,
    commit: str,
    tree: str,
) -> None:
    validate_bundle(
        directory,
        expected_repository=repository,
        expected_tag=tag,
        expected_commit=commit,
        expected_tree=tree,
    )
    if {path.name for path in directory.iterdir()} != set(local_assets):
        raise ReleasePublicationError("downloaded release asset set is unexpected")
    for name, expected in local_assets.items():
        if not _files_equal(expected.path, directory / name):
            raise ReleasePublicationError(
                f"downloaded release asset bytes differ: {name}"
            )


def _download_complete_release(
    api: ReleaseReadAPI,
    repository: str,
    release_assets: dict[str, dict[str, Any]],
    local_assets: dict[str, LocalAsset],
    destination: Path,
    *,
    tag: str,
    commit: str,
    tree: str,
) -> None:
    destination.mkdir()
    for name, expected in local_assets.items():
        _download_asset_copy(
            api,
            repository,
            release_assets[name],
            expected,
            destination / name,
        )
    _validate_downloaded_bundle(
        destination,
        local_assets,
        repository=repository,
        tag=tag,
        commit=commit,
        tree=tree,
    )


def _validate_trigger(
    api: ReleaseAPI,
    trigger_api: APIClient,
    *,
    repository: str,
    tag: str,
    commit: str,
    actor: str,
    workflow_sha: str,
) -> None:
    validate_release_trigger(
        trigger_api,
        repository=repository,
        tag=tag,
        event_sha=commit,
        event_ref=f"refs/tags/{tag}",
        ref_type="tag",
        actor=actor,
        workflow_sha=workflow_sha,
        immutable_client=api,
    )


def _require_release(
    api: ReleaseAPI,
    repository: str,
    tag: str,
) -> dict[str, Any]:
    release = api.find_release(repository, tag)
    if release is None:
        raise ReleasePublicationError("release disappeared during reconciliation")
    return release


def inspect_release_identity(
    api: ReleaseReadAPI,
    *,
    repository: str,
    tag: str,
    commit: str,
    assets: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Read metadata against previously verified assets without authorizing writes."""

    if repository != REPOSITORY_ID:
        raise ReleasePublicationError("release repository identity mismatch")
    release = api.find_release(repository, tag)
    if release is None:
        return None
    local_assets = {
        item["name"]: LocalAsset(
            name=item["name"],
            path=Path(item["name"]),
            size=item["size_bytes"],
            digest=item["sha256"],
            media_type=_asset_media_type(item["name"]),
        )
        for item in assets
    }
    if len(local_assets) != 5 or len(assets) != 5:
        raise ReleasePublicationError("expected release asset set is invalid")
    release_id, state = _validate_release_record(release, tag=tag, commit=commit)
    records = _validate_asset_records(
        api.list_assets(repository, release_id),
        local_assets,
        complete=state == "immutable",
    )
    return {"release": release, "state": state, "assets": records}


def verify_published_release(
    api: ReleaseReadAPI,
    directory: Path,
    *,
    repository: str,
    tag: str,
    commit: str,
    tree: str,
) -> dict[str, Any]:
    """Verify published bytes only; never dispatch, create, upload, or publish.

    Fresh-action gates belong to the caller. This deliberately does not require
    current main or an unexpired Actions artifact to inspect historical bytes.
    """

    validate_bundle(
        directory,
        expected_repository=repository,
        expected_tag=tag,
        expected_commit=commit,
        expected_tree=tree,
    )
    local_assets = _local_assets(directory)
    descriptions = [
        {"name": asset.name, "size_bytes": asset.size, "sha256": asset.digest}
        for asset in local_assets.values()
    ]
    before = inspect_release_identity(
        api, repository=repository, tag=tag, commit=commit, assets=descriptions
    )
    if before is None or before["state"] != "immutable":
        raise ReleasePublicationError("release is not yet immutable")
    with tempfile.TemporaryDirectory(
        prefix=".published-verification-", dir=directory.parent
    ) as temporary:
        _download_complete_release(
            api,
            repository,
            before["assets"],
            local_assets,
            Path(temporary) / "assets",
            tag=tag,
            commit=commit,
            tree=tree,
        )
    after = inspect_release_identity(
        api, repository=repository, tag=tag, commit=commit, assets=descriptions
    )
    if (
        after is None
        or after["state"] != "immutable"
        or after["release"]["id"] != before["release"]["id"]
        or after["assets"] != before["assets"]
    ):
        raise ReleasePublicationError("published release drifted during verification")
    return after["release"]


def publish_immutable_release(
    api: ReleaseAPI,
    directory: Path,
    *,
    repository: str,
    tag: str,
    commit: str,
    tree: str,
    actor: str,
    workflow_sha: str,
    qualification: QualificationBinding,
    trigger_api: APIClient | None = None,
) -> dict[str, Any]:
    validated = validate_bundle(
        directory,
        expected_repository=repository,
        expected_tag=tag,
        expected_commit=commit,
        expected_tree=tree,
    )
    directory = Path(validated["manifest"]).parent
    local_assets = _local_assets(directory)
    read_api = api if trigger_api is None else trigger_api
    _validate_trigger(
        api,
        read_api,
        repository=repository,
        tag=tag,
        commit=commit,
        actor=actor,
        workflow_sha=workflow_sha,
    )
    verify_qualified_release(
        read_api,
        directory,
        qualification,
        repository=repository,
        tag=tag,
        commit=commit,
        tree=tree,
    )

    with tempfile.TemporaryDirectory(
        prefix="strugglebus-release-publication-"
    ) as temporary:
        workspace = Path(temporary)
        release = api.find_release(repository, tag)
        if release is None:
            try:
                release = api.create_draft(
                    repository,
                    tag,
                    commit,
                    _release_body(tag),
                )
            except ReleasePublicationError as creation_error:
                release = api.find_release(repository, tag)
                if release is None:
                    raise creation_error

        release_id, state = _validate_release_record(
            release,
            tag=tag,
            commit=commit,
        )
        records = api.list_assets(repository, release_id)
        release_assets = _validate_asset_records(
            records,
            local_assets,
            complete=state == "immutable",
        )

        existing_directory = workspace / "existing-assets"
        existing_directory.mkdir()
        for name, record in release_assets.items():
            _download_asset_copy(
                api,
                repository,
                record,
                local_assets[name],
                existing_directory / name,
            )

        if state == "immutable":
            _validate_downloaded_bundle(
                existing_directory,
                local_assets,
                repository=repository,
                tag=tag,
                commit=commit,
                tree=tree,
            )
            _validate_trigger(
                api,
                read_api,
                repository=repository,
                tag=tag,
                commit=commit,
                actor=actor,
                workflow_sha=workflow_sha,
            )
            return release

        for name, asset in local_assets.items():
            if name in release_assets:
                continue
            try:
                api.upload_asset(repository, release_id, asset)
            except ReleasePublicationError as upload_error:
                current = _require_release(api, repository, tag)
                current_id, current_state = _validate_release_record(
                    current,
                    tag=tag,
                    commit=commit,
                )
                if current_id != release_id or current_state != "draft":
                    raise upload_error
                current_assets = _validate_asset_records(
                    api.list_assets(repository, release_id),
                    local_assets,
                    complete=False,
                )
                if name not in current_assets:
                    raise upload_error
            release = _require_release(api, repository, tag)
            current_id, current_state = _validate_release_record(
                release,
                tag=tag,
                commit=commit,
            )
            if current_id != release_id or current_state != "draft":
                raise ReleasePublicationError(
                    "release changed while assets were uploaded"
                )
            release_assets = _validate_asset_records(
                api.list_assets(repository, release_id),
                local_assets,
                complete=False,
            )
            if name not in release_assets:
                raise ReleasePublicationError(
                    f"uploaded release asset is missing: {name}"
                )
            _download_asset_copy(
                api,
                repository,
                release_assets[name],
                asset,
                existing_directory / name,
            )

        release = _require_release(api, repository, tag)
        current_id, current_state = _validate_release_record(
            release,
            tag=tag,
            commit=commit,
        )
        if current_id != release_id or current_state != "draft":
            raise ReleasePublicationError(
                "release changed before complete draft validation"
            )
        release_assets = _validate_asset_records(
            api.list_assets(repository, release_id),
            local_assets,
            complete=True,
        )
        _download_complete_release(
            api,
            repository,
            release_assets,
            local_assets,
            workspace / "complete-draft",
            tag=tag,
            commit=commit,
            tree=tree,
        )

        _validate_trigger(
            api,
            read_api,
            repository=repository,
            tag=tag,
            commit=commit,
            actor=actor,
            workflow_sha=workflow_sha,
        )
        release = _require_release(api, repository, tag)
        current_id, current_state = _validate_release_record(
            release,
            tag=tag,
            commit=commit,
        )
        if current_id != release_id or current_state != "draft":
            raise ReleasePublicationError(
                "release changed immediately before publication"
            )
        _validate_asset_records(
            api.list_assets(repository, release_id),
            local_assets,
            complete=True,
        )

        try:
            api.publish_release(repository, release_id)
        except ReleasePublicationError as publication_error:
            reconciled = api.find_release(repository, tag)
            if reconciled is None:
                raise publication_error
            reconciled_id, reconciled_state = _validate_release_record(
                reconciled,
                tag=tag,
                commit=commit,
            )
            if reconciled_id != release_id or reconciled_state != "immutable":
                raise publication_error

        published = _require_release(api, repository, tag)
        published_id, published_state = _validate_release_record(
            published,
            tag=tag,
            commit=commit,
        )
        if published_id != release_id or published_state != "immutable":
            raise ReleasePublicationError(
                "GitHub did not publish the exact immutable release"
            )
        published_assets = _validate_asset_records(
            api.list_assets(repository, release_id),
            local_assets,
            complete=True,
        )
        _validate_trigger(
            api,
            read_api,
            repository=repository,
            tag=tag,
            commit=commit,
            actor=actor,
            workflow_sha=workflow_sha,
        )
        _download_complete_release(
            api,
            repository,
            published_assets,
            local_assets,
            workspace / "published-release",
            tag=tag,
            commit=commit,
            tree=tree,
        )
        return published


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--repository", default=REPOSITORY_ID)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--qualification-run-id", type=int, required=True)
    parser.add_argument("--qualification-artifact-id", type=int, required=True)
    parser.add_argument("--qualification-artifact-name", required=True)
    parser.add_argument("--qualification-artifact-digest", required=True)
    parser.add_argument("--qualification-artifact-size", type=int, required=True)
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    parser.add_argument("--read-token-env", default="GITHUB_TOKEN")
    parser.add_argument("--publish-token-env", default="RELEASE_APP_TOKEN")
    args = parser.parse_args()
    read_token = os.environ.get(args.read_token_env)
    publish_token = os.environ.get(args.publish_token_env)
    if not read_token:
        raise ReleasePublicationError("read-only GitHub API token is unavailable")
    if not publish_token:
        raise ReleasePublicationError("GitHub App publication token is unavailable")
    qualification = QualificationBinding(
        receipt_path=args.receipt,
        run_id=args.qualification_run_id,
        artifact_id=args.qualification_artifact_id,
        artifact_name=args.qualification_artifact_name,
        artifact_digest=args.qualification_artifact_digest,
        artifact_size_bytes=args.qualification_artifact_size,
        helper_sha256=helper_digest(args.source_root),
        now=int(time.time()),
    )
    release_api = GitHubReleaseAPI(GITHUB_API_URL, publish_token)
    result = publish_immutable_release(
        release_api,
        args.directory,
        repository=args.repository,
        tag=args.tag,
        commit=args.commit,
        tree=args.tree,
        actor=args.actor,
        workflow_sha=args.workflow_sha,
        qualification=qualification,
        trigger_api=GitHubReleaseAPI(GITHUB_API_URL, read_token),
    )
    print(
        json.dumps(
            {
                "id": result["id"],
                "immutable": result["immutable"],
                "tag": result["tag_name"],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
