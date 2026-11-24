from __future__ import annotations

from email.message import Message
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
from typing import Any
import urllib.error
import urllib.request

import pytest


REPOSITORY = Path(__file__).resolve().parents[1]
SCRIPTS = REPOSITORY / "scripts"
sys.path.insert(0, str(SCRIPTS))


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_load("release_bundle", SCRIPTS / "release_bundle.py")
TRIGGER = _load("validate_release_trigger", SCRIPTS / "validate_release_trigger.py")
PUBLISHER = _load(
    "publish_immutable_release_http",
    SCRIPTS / "publish_immutable_release.py",
)


class FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        url: str,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status = status
        self._body = io.BytesIO(body)
        self._url = url
        self.headers = Message()
        for key, value in (headers or {"Content-Type": "application/json"}).items():
            self.headers[key] = value

    def read(self, size: int = -1) -> bytes:
        return self._body.read(size)

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class QueueOpener:
    def __init__(self, *items: Any) -> None:
        self.items = list(items)
        self.requests: list[urllib.request.Request] = []
        self.upload_bodies: list[bytes] = []

    def open(
        self,
        request: urllib.request.Request,
        *,
        timeout: int,
    ) -> FakeResponse:
        self.requests.append(request)
        if hasattr(request.data, "read"):
            self.upload_bodies.append(request.data.read())
        item = self.items.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def _http_error(status: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://api.github.com/test",
        status,
        "failure",
        Message(),
        io.BytesIO(b"not logged"),
    )


def _client(
    *,
    json_opener: QueueOpener | None = None,
    asset_opener: QueueOpener | None = None,
    delays: list[float] | None = None,
) -> Any:
    return PUBLISHER.GitHubReleaseAPI(
        TRIGGER.GITHUB_API_URL,
        "test-token",
        sleep=(delays.append if delays is not None else lambda delay: None),
        json_opener=json_opener,
        asset_opener=asset_opener,
    )


def test_json_reads_distinguish_404_from_authorization_failures() -> None:
    missing_opener = QueueOpener(_http_error(404))
    missing_client = _client(json_opener=missing_opener)

    assert (
        missing_client._request_json("repos/x/y/releases/tags/v1", allow_not_found=True)
        is None
    )
    assert (
        missing_opener.requests[0].get_header("Authorization")
        == "Bearer test-token"
    )

    denied_client = _client(json_opener=QueueOpener(_http_error(403)))
    with pytest.raises(
        PUBLISHER.ReleasePublicationError,
        match="authorization failed",
    ) as caught:
        denied_client._request_json(
            "repos/x/y/releases/tags/v1",
            allow_not_found=True,
        )
    assert "test-token" not in str(caught.value)
    assert caught.value.__cause__ is None


def test_safe_json_reads_retry_only_bounded_transient_failures() -> None:
    delays: list[float] = []
    response = FakeResponse(
        json.dumps({"ok": True}).encode(),
        url="https://api.github.com/test",
    )
    opener = QueueOpener(_http_error(503), response)
    client = _client(json_opener=opener, delays=delays)

    assert client.get("test") == {"ok": True}
    assert len(opener.requests) == 2
    assert delays == [0.25]


def test_mutating_requests_are_not_blindly_retried() -> None:
    opener = QueueOpener(_http_error(503))
    client = _client(json_opener=opener)

    with pytest.raises(PUBLISHER.ReleasePublicationError, match="status 503"):
        client._request_json("test", method="POST", payload={"draft": True})

    assert len(opener.requests) == 1


def test_api_origin_is_pinned_and_token_repr_is_redacted() -> None:
    client = _client(json_opener=QueueOpener())

    assert "test-token" not in repr(client)
    with pytest.raises(PUBLISHER.ReleasePublicationError, match="pinned origin"):
        PUBLISHER.GitHubReleaseAPI("https://example.invalid", "test-token")


@pytest.mark.parametrize(
    "token",
    ["", "has whitespace", "line\nbreak", "non-ascii-\N{SNOWMAN}", "x" * 4097],
)
def test_api_token_format_rejects_header_injection(
    token: str,
) -> None:
    with pytest.raises(PUBLISHER.ReleasePublicationError, match="invalid format"):
        PUBLISHER.GitHubReleaseAPI(TRIGGER.GITHUB_API_URL, token)


def test_json_redirect_handler_never_follows_a_redirect() -> None:
    handler = PUBLISHER._RejectRedirects()
    request = urllib.request.Request(
        "https://api.github.com/repos/NZCypher819/strugglebus/releases",
        headers={"Authorization": "Bearer test-token"},
        method="GET",
    )

    assert (
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            Message(),
            "https://example.invalid/stolen",
        )
        is None
    )


def test_asset_redirects_strip_authorization_and_reject_untrusted_hosts() -> None:
    handler = PUBLISHER._AssetRedirects()
    request = urllib.request.Request(
        "https://api.github.com/repos/NZCypher819/strugglebus/releases/assets/7",
        headers={
            "Accept": "application/octet-stream",
            "Authorization": "Bearer test-token",
        },
        method="GET",
    )

    redirected = handler.redirect_request(
        request,
        None,
        302,
        "Found",
        Message(),
        "https://release-assets.githubusercontent.com/github-production-release-asset/x",
    )

    assert redirected.get_header("Authorization") is None
    assert redirected.get_header("Accept") == "application/octet-stream"
    with pytest.raises(PUBLISHER.ReleasePublicationError, match="not trusted"):
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            Message(),
            "https://example.invalid/stolen",
        )


def test_asset_download_validates_origin_headers_name_type_size_and_bytes(
    tmp_path: Path,
) -> None:
    content = b"exact release bytes"
    response = FakeResponse(
        content,
        url="https://release-assets.githubusercontent.com/github-production-release-asset/x",
        headers={
            "Content-Disposition": 'attachment; filename="requirements.lock"',
            "Content-Length": str(len(content)),
            "Content-Type": "text/plain",
        },
    )
    opener = QueueOpener(response)
    client = _client(asset_opener=opener)
    destination = tmp_path / "requirements.lock"

    client.download_asset(
        PUBLISHER.REPOSITORY_ID,
        7,
        destination,
        expected_name="requirements.lock",
        expected_size=len(content),
        expected_media_type="text/plain",
        expected_sha256=hashlib.sha256(content).hexdigest(),
    )

    assert destination.read_bytes() == content
    assert (
        opener.requests[0].get_header("Authorization")
        == "Bearer test-token"
    )
    assert opener.requests[0].get_header("Accept") == "application/octet-stream"


@pytest.mark.parametrize(
    "headers",
    [
        {
            "Content-Disposition": 'attachment; filename="other.lock"',
            "Content-Length": "5",
            "Content-Type": "text/plain",
        },
        {
            "Content-Disposition": 'attachment; filename="requirements.lock"',
            "Content-Length": "4",
            "Content-Type": "text/plain",
        },
        {
            "Content-Disposition": 'attachment; filename="requirements.lock"',
            "Content-Length": "5",
            "Content-Type": "text/html",
        },
    ],
)
def test_asset_download_rejects_conflicting_response_metadata(
    tmp_path: Path,
    headers: dict[str, str],
) -> None:
    response = FakeResponse(
        b"exact",
        url="https://objects.githubusercontent.com/release",
        headers=headers,
    )
    client = _client(asset_opener=QueueOpener(response))
    destination = tmp_path / "requirements.lock"

    with pytest.raises(PUBLISHER.ReleasePublicationError):
        client.download_asset(
            PUBLISHER.REPOSITORY_ID,
            7,
            destination,
            expected_name="requirements.lock",
            expected_size=5,
            expected_media_type="text/plain",
            expected_sha256=hashlib.sha256(b"exact").hexdigest(),
        )

    assert not destination.exists()


def test_asset_upload_uses_derived_origin_exact_name_type_length_and_bytes(
    tmp_path: Path,
) -> None:
    content = b"locked requirements"
    path = tmp_path / "requirements.lock"
    path.write_bytes(content)
    response = FakeResponse(
        json.dumps({"id": 9}).encode(),
        url=(
            "https://uploads.github.com/repos/NZCypher819/strugglebus/"
            "releases/7/assets?name=requirements.lock"
        ),
        status=201,
    )
    opener = QueueOpener(response)
    client = _client(json_opener=opener)
    asset = PUBLISHER.LocalAsset(
        name=path.name,
        path=path,
        size=len(content),
        digest=hashlib.sha256(content).hexdigest(),
        media_type="text/plain",
    )

    assert client.upload_asset(PUBLISHER.REPOSITORY_ID, 7, asset) == {"id": 9}

    request = opener.requests[0]
    assert request.full_url == response.geturl()
    assert request.get_header("Content-type") == "text/plain"
    assert request.get_header("Content-length") == str(len(content))
    assert request.get_header("Authorization") == "Bearer test-token"
    assert opener.upload_bodies == [content]


def test_json_response_limits_and_media_type_are_enforced() -> None:
    oversized = FakeResponse(
        b"x" * (PUBLISHER.MAX_RESPONSE_BYTES + 1),
        url="https://api.github.com/test",
    )
    with pytest.raises(PUBLISHER.ReleasePublicationError, match="size limit"):
        _client(json_opener=QueueOpener(oversized)).get("test")

    html = FakeResponse(
        b"{}",
        url="https://api.github.com/test",
        headers={"Content-Type": "text/html"},
    )
    with pytest.raises(PUBLISHER.ReleasePublicationError, match="non-JSON"):
        _client(json_opener=QueueOpener(html)).get("test")
