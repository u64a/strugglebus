from __future__ import annotations

from email.message import Message
import hashlib
import importlib.util
import io
from pathlib import Path
import socket
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
    "publish_immutable_release_redirects",
    SCRIPTS / "publish_immutable_release.py",
)

CONTENT = b"exact release asset"
NAME = "SHA256SUMS"
MEDIA_TYPE = "text/plain"
API_ASSET_URL = (
    "https://api.github.com/repos/NZCypher819/strugglebus/releases/assets/7"
)
SIGNED_ASSET_URL = (
    "https://release-assets.githubusercontent.com/"
    "github-production-release-asset/7?sig=opaque-test-value"
)


class FakeResponse:
    def __init__(
        self,
        body: bytes = b"",
        *,
        url: str,
        status: int = 200,
        headers: dict[str, str] | Message | None = None,
    ) -> None:
        self.status = status
        self.code = status
        self.msg = "test response"
        self._body = io.BytesIO(body)
        self._url = url
        self.closed = False
        if isinstance(headers, Message):
            self.headers = headers
        else:
            self.headers = Message()
            for key, value in (headers or {}).items():
                self.headers[key] = value

    def read(self, size: int = -1) -> bytes:
        return self._body.read(size)

    def geturl(self) -> str:
        return self._url

    def info(self) -> Message:
        return self.headers

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class RecordingHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, *items: Any) -> None:
        super().__init__()
        self.items = list(items)
        self.requests: list[dict[str, Any]] = []

    def https_open(self, request: urllib.request.Request) -> FakeResponse:
        self.requests.append(
            {
                "url": request.full_url,
                "method": request.get_method(),
                "headers": {
                    key.casefold(): value
                    for key, value in request.header_items()
                },
                "unredirected": {
                    key.casefold(): value
                    for key, value in request.unredirected_hdrs.items()
                },
            }
        )
        if not self.items:
            raise AssertionError("unexpected HTTPS request")
        item = self.items.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def _asset_headers(
    *,
    name: str = NAME,
    size: int | None = len(CONTENT),
    media_type: str = MEDIA_TYPE,
) -> dict[str, str]:
    headers = {
        "Content-Disposition": f'attachment; filename="{name}"',
        "Content-Type": media_type,
    }
    if size is not None:
        headers["Content-Length"] = str(size)
    return headers


def _redirect(
    location: str,
    *,
    status: int = 302,
    headers: Message | None = None,
) -> FakeResponse:
    redirect_headers = Message() if headers is None else headers
    if headers is None:
        redirect_headers["Location"] = location
    return FakeResponse(
        url=API_ASSET_URL,
        status=status,
        headers=redirect_headers,
    )


def _opener(
    *items: Any,
) -> tuple[urllib.request.OpenerDirector, RecordingHTTPSHandler]:
    transport = RecordingHTTPSHandler(*items)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        PUBLISHER._AssetRedirects(),
        transport,
    )
    return opener, transport


def _client(
    *items: Any,
    delays: list[float] | None = None,
) -> tuple[Any, RecordingHTTPSHandler]:
    opener, transport = _opener(*items)
    client = PUBLISHER.GitHubReleaseAPI(
        TRIGGER.GITHUB_API_URL,
        "test-token",
        sleep=(delays.append if delays is not None else lambda delay: None),
        asset_opener=opener,
    )
    return client, transport


def _download(
    client: Any,
    destination: Path,
    *,
    content: bytes = CONTENT,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
) -> None:
    client.download_asset(
        PUBLISHER.REPOSITORY_ID,
        7,
        destination,
        expected_name=NAME,
        expected_size=len(content) if expected_size is None else expected_size,
        expected_media_type=MEDIA_TYPE,
        expected_sha256=(
            hashlib.sha256(content).hexdigest()
            if expected_sha256 is None
            else expected_sha256
        ),
    )


def test_direct_api_200_uses_unredirected_authorization(
    tmp_path: Path,
) -> None:
    response = FakeResponse(
        CONTENT,
        url=API_ASSET_URL,
        headers=_asset_headers(),
    )
    client, transport = _client(response)
    destination = tmp_path / NAME

    _download(client, destination)

    assert destination.read_bytes() == CONTENT
    assert len(transport.requests) == 1
    request = transport.requests[0]
    assert request["url"] == API_ASSET_URL
    assert request["method"] == "GET"
    assert request["headers"]["host"] == PUBLISHER.GITHUB_API_HOST
    assert "authorization" in request["unredirected"]


def test_exact_302_rebuilds_request_after_urllib_injects_source_host(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = FakeResponse(
        CONTENT,
        url=SIGNED_ASSET_URL,
        headers=_asset_headers(),
    )
    client, transport = _client(_redirect(SIGNED_ASSET_URL), target)
    original_headers = client._headers

    def source_headers(**kwargs: Any) -> dict[str, str]:
        return {
            **original_headers(**kwargs),
            "Cookie": "source-cookie",
            "Proxy-Authorization": "source-proxy-credential",
            "X-Source-Only": "source-value",
        }

    monkeypatch.setattr(client, "_headers", source_headers)
    destination = tmp_path / NAME

    _download(client, destination)

    assert destination.read_bytes() == CONTENT
    assert len(transport.requests) == 2
    source, redirected = transport.requests
    assert source["headers"]["host"] == PUBLISHER.GITHUB_API_HOST
    assert "authorization" in source["headers"]
    assert redirected["headers"] == {
        "accept": PUBLISHER.ASSET_ACCEPT,
        "host": PUBLISHER.GITHUB_ASSET_HOST,
        "user-agent": PUBLISHER.USER_AGENT,
    }
    for forbidden in (
        "authorization",
        "proxy-authorization",
        "cookie",
        "x-github-api-version",
        "x-source-only",
    ):
        assert forbidden not in redirected["headers"]


@pytest.mark.parametrize(
    "location",
    [
        "https://release-assets.githubusercontent.com.evil.example/asset",
        "https://sub.release-assets.githubusercontent.com/asset",
        "https://objects.githubusercontent.com/asset",
        "https://github-releases.githubusercontent.com/asset",
        "https://release-assets-githubusercontent.com/asset",
    ],
)
def test_redirect_rejects_suffix_wildcard_and_other_asset_hosts(
    tmp_path: Path,
    location: str,
) -> None:
    client, transport = _client(_redirect(location))
    destination = tmp_path / NAME

    with pytest.raises(PUBLISHER.ReleasePublicationError, match="target"):
        _download(client, destination)

    assert len(transport.requests) == 1
    assert not destination.exists()


@pytest.mark.parametrize(
    "location",
    [
        "http://release-assets.githubusercontent.com/asset",
        "https://u:p@release-assets.githubusercontent.com/asset",
        "https://release-assets.githubusercontent.com/asset#fragment",
        "https://release-assets.githubusercontent.com:444/asset",
        "https://release-assets.githubusercontent.com:invalid/asset",
        "/relative/asset",
        "//release-assets.githubusercontent.com/asset",
        "https://release-assets.githubusercontent.com/asset%zz",
        "https://release-assets.githubusercontent.com/asset with-space",
        "https://release-assets.githubusercontent.com\\asset",
        "https://release-assets.githubusercontent.com/asset\nnext",
        "https://release-assets.githubusercontent.com/asset\x00",
        "https://release-assets.githubusercontent.com",
    ],
)
def test_redirect_rejects_malformed_or_nonabsolute_locations(
    tmp_path: Path,
    location: str,
) -> None:
    client, transport = _client(_redirect(location))
    destination = tmp_path / NAME

    with pytest.raises(PUBLISHER.ReleasePublicationError):
        _download(client, destination)

    assert len(transport.requests) == 1
    assert not destination.exists()


def test_redirect_rejects_multiple_location_headers(tmp_path: Path) -> None:
    headers = Message()
    headers["Location"] = SIGNED_ASSET_URL
    headers["Location"] = SIGNED_ASSET_URL
    client, transport = _client(
        _redirect(SIGNED_ASSET_URL, headers=headers)
    )
    destination = tmp_path / NAME

    with pytest.raises(PUBLISHER.ReleasePublicationError, match="location"):
        _download(client, destination)

    assert len(transport.requests) == 1
    assert not destination.exists()


@pytest.mark.parametrize("status", [301, 303, 307, 308])
def test_alternate_redirect_statuses_are_rejected(
    tmp_path: Path,
    status: int,
) -> None:
    client, transport = _client(_redirect(SIGNED_ASSET_URL, status=status))
    destination = tmp_path / NAME

    with pytest.raises(PUBLISHER.ReleasePublicationError, match="status"):
        _download(client, destination)

    assert len(transport.requests) == 1
    assert not destination.exists()


@pytest.mark.parametrize(
    "second_location",
    [SIGNED_ASSET_URL, API_ASSET_URL],
)
def test_redirect_chains_and_loops_are_rejected_after_one_hop(
    tmp_path: Path,
    second_location: str,
) -> None:
    second = FakeResponse(
        url=SIGNED_ASSET_URL,
        status=302,
        headers={"Location": second_location},
    )
    client, transport = _client(_redirect(SIGNED_ASSET_URL), second)
    destination = tmp_path / NAME

    with pytest.raises(PUBLISHER.ReleasePublicationError, match="source"):
        _download(client, destination)

    assert len(transport.requests) == 2
    assert not destination.exists()


def test_api_and_delivery_target_404_have_distinct_sanitized_errors(
    tmp_path: Path,
) -> None:
    api_client, _ = _client(
        FakeResponse(url=API_ASSET_URL, status=404)
    )
    with pytest.raises(
        PUBLISHER.ReleasePublicationError,
        match="release asset disappeared",
    ):
        _download(api_client, tmp_path / NAME)

    target_client, _ = _client(
        _redirect(SIGNED_ASSET_URL),
        FakeResponse(url=SIGNED_ASSET_URL, status=404),
    )
    with pytest.raises(
        PUBLISHER.ReleasePublicationError,
        match="delivery failed with status 404",
    ) as caught:
        _download(target_client, tmp_path / NAME)
    assert "opaque-test-value" not in str(caught.value)


@pytest.mark.parametrize("status", [401, 403])
def test_api_and_delivery_authorization_errors_are_distinct(
    tmp_path: Path,
    status: int,
) -> None:
    api_client, _ = _client(
        FakeResponse(url=API_ASSET_URL, status=status)
    )
    with pytest.raises(
        PUBLISHER.ReleasePublicationError,
        match="authorization failed",
    ):
        _download(api_client, tmp_path / NAME)

    target_client, _ = _client(
        _redirect(SIGNED_ASSET_URL),
        FakeResponse(url=SIGNED_ASSET_URL, status=status),
    )
    with pytest.raises(
        PUBLISHER.ReleasePublicationError,
        match=f"delivery failed with status {status}",
    ):
        _download(target_client, tmp_path / NAME)


def test_transient_delivery_failure_retries_from_api_with_fresh_request(
    tmp_path: Path,
) -> None:
    delays: list[float] = []
    first_target = SIGNED_ASSET_URL.replace("opaque-test-value", "first")
    second_target = SIGNED_ASSET_URL.replace("opaque-test-value", "second")
    client, transport = _client(
        _redirect(first_target),
        FakeResponse(url=first_target, status=503),
        _redirect(second_target),
        FakeResponse(
            CONTENT,
            url=second_target,
            headers=_asset_headers(),
        ),
        delays=delays,
    )

    _download(client, tmp_path / NAME)

    assert [request["url"] for request in transport.requests] == [
        API_ASSET_URL,
        first_target,
        API_ASSET_URL,
        second_target,
    ]
    assert delays == [0.25]


def test_timeout_retries_are_bounded_and_leave_no_partial_file(
    tmp_path: Path,
) -> None:
    delays: list[float] = []
    client, transport = _client(
        socket.timeout(),
        socket.timeout(),
        socket.timeout(),
        delays=delays,
    )
    destination = tmp_path / NAME

    with pytest.raises(
        PUBLISHER.ReleasePublicationError,
        match="network request failed",
    ):
        _download(client, destination)

    assert len(transport.requests) == PUBLISHER.READ_ATTEMPTS
    assert delays == [0.25, 0.5]
    assert not destination.exists()


@pytest.mark.parametrize(
    ("headers", "message"),
    [
        (
            {
                "Content-Length": str(len(CONTENT)),
                "Content-Type": MEDIA_TYPE,
            },
            "content disposition",
        ),
        (
            _asset_headers(name="other"),
            "filename",
        ),
        (
            _asset_headers(media_type="text/html"),
            "media type",
        ),
        (
            {
                **_asset_headers(),
                "Content-Length": "not-a-number",
            },
            "length",
        ),
        (
            _asset_headers(size=len(CONTENT) + 1),
            "length",
        ),
    ],
)
def test_asset_metadata_validation_cleans_destination(
    tmp_path: Path,
    headers: dict[str, str],
    message: str,
) -> None:
    client, _ = _client(
        FakeResponse(CONTENT, url=API_ASSET_URL, headers=headers)
    )
    destination = tmp_path / NAME

    with pytest.raises(PUBLISHER.ReleasePublicationError, match=message):
        _download(client, destination)

    assert not destination.exists()


@pytest.mark.parametrize(
    ("body", "expected_size", "expected_sha256", "message"),
    [
        (
            CONTENT[:-1],
            len(CONTENT),
            hashlib.sha256(CONTENT).hexdigest(),
            "shorter",
        ),
        (
            CONTENT + b"x",
            len(CONTENT),
            hashlib.sha256(CONTENT).hexdigest(),
            "exceeds",
        ),
        (
            CONTENT,
            len(CONTENT),
            "0" * 64,
            "digest",
        ),
    ],
)
def test_short_oversize_and_digest_mismatch_remove_partial_file(
    tmp_path: Path,
    body: bytes,
    expected_size: int,
    expected_sha256: str,
    message: str,
) -> None:
    client, _ = _client(
        FakeResponse(
            body,
            url=API_ASSET_URL,
            headers=_asset_headers(size=None),
        )
    )
    destination = tmp_path / NAME

    with pytest.raises(PUBLISHER.ReleasePublicationError, match=message):
        _download(
            client,
            destination,
            content=CONTENT,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
        )

    assert not destination.exists()


@pytest.mark.parametrize(
    "final_url",
    [
        "https://objects.githubusercontent.com/asset?sig=opaque",
        "https://release-assets.githubusercontent.com.evil.example/asset",
        "http://release-assets.githubusercontent.com/asset",
        "https://u:p@release-assets.githubusercontent.com/asset",
        "https://release-assets.githubusercontent.com:444/asset",
        "https://release-assets.githubusercontent.com/asset#fragment",
        "https://release-assets.githubusercontent.com/asset%zz",
    ],
)
def test_final_response_origin_is_exact_and_errors_do_not_echo_url(
    tmp_path: Path,
    final_url: str,
) -> None:
    client, _ = _client(
        FakeResponse(CONTENT, url=final_url, headers=_asset_headers())
    )
    destination = tmp_path / NAME

    with pytest.raises(
        PUBLISHER.ReleasePublicationError,
        match="origin is not trusted",
    ) as caught:
        _download(client, destination)

    assert final_url not in str(caught.value)
    assert not destination.exists()


def test_download_is_no_clobber_and_rejects_invalid_digest(
    tmp_path: Path,
) -> None:
    client, transport = _client()
    destination = tmp_path / NAME
    destination.write_bytes(b"preserve")

    with pytest.raises(PUBLISHER.ReleasePublicationError, match="unsafe"):
        _download(client, destination)
    assert destination.read_bytes() == b"preserve"
    assert transport.requests == []

    destination.unlink()
    with pytest.raises(PUBLISHER.ReleasePublicationError, match="unsafe"):
        _download(client, destination, expected_sha256="A" * 64)
    assert not destination.exists()
    assert transport.requests == []
