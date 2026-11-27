from __future__ import annotations

from dataclasses import replace
from email.message import Message
import hashlib
import io
from pathlib import Path
import stat
from types import SimpleNamespace
import urllib.error

import pytest

from strugglebus import update_transport as transport
from strugglebus.release_transport import ReleasePublicationError, _AssetRedirects
from strugglebus.update_types import UpdateAsset, UpdateError, UpdateLimits
from test_update_source import Response


class Opener:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = 0

    def open(self, request, timeout):
        self.calls += 1
        value = next(self.responses)
        if isinstance(value, Exception):
            raise value
        return value


@pytest.fixture
def http(monkeypatch):
    monkeypatch.setattr(transport, "_CLOCK", lambda: 100.0)
    monkeypatch.setattr(transport, "_SLEEP", lambda delay: None)
    return transport._HTTP(UpdateLimits(), 200)


def test_reads_retry_only_three_times(http):
    http._metadata = Opener([OSError("sensitive-url")] * 3)
    with pytest.raises(UpdateError, match="source_unavailable") as error:
        http.json("/repos/NZCypher819/strugglebus-releases/releases")
    assert http._metadata.calls == 3 and "sensitive" not in str(error.value)


def test_retry_delay_never_exceeds_deadline(http):
    http.deadline = 100.5
    http._metadata = Opener([OSError("sensitive")])
    with pytest.raises(UpdateError, match="timeout"):
        http.json("/repos/NZCypher819/strugglebus-releases/releases")
    assert http._metadata.calls == 1


@pytest.mark.parametrize("code,expected,calls", [(401, "source_unavailable", 1),
                                               (403, "source_unavailable", 1),
                                               (404, "source_unavailable", 1),
                                               (302, "source_unavailable", 1),
                                               (429, "rate_limited", 1),
                                               (503, "source_unavailable", 3)])
def test_http_status_errors_are_sanitized_and_bounded(http, code, expected, calls):
    errors = [urllib.error.HTTPError("https://secret", code, "sensitive", {}, io.BytesIO(b"secret")) for _ in range(3)]
    http._metadata = Opener(errors)
    with pytest.raises(UpdateError, match=expected):
        http.json("/repos/NZCypher819/strugglebus-releases/releases")
    assert http._metadata.calls == calls


@pytest.mark.parametrize("code,headers,expected", [
    (403, {"x-ratelimit-remaining": "0"}, "rate_limited"),
    (403, {"x-ratelimit-remaining": "12"}, "source_unavailable"),
    (403, {}, "source_unavailable"),
    (403, None, "source_unavailable"),
    (429, {}, "rate_limited"),
    (404, {"x-ratelimit-remaining": "0"}, "source_unavailable"),
])
def test_the_sources_request_limit_is_told_apart_and_never_asked_again_at_once(http, code, headers, expected):
    """GitHub's limit passes by itself; asking again only uses more of it."""
    http._metadata = Opener([urllib.error.HTTPError("https://secret", code, "sensitive", headers, io.BytesIO(b"x"))] * 3)
    with pytest.raises(UpdateError, match=expected):
        http.json("/repos/u64a/strugglebus/releases")
    assert http._metadata.calls == 1


@pytest.mark.parametrize("url", ["http://api.github.com/app", "https://api.github.com.evil/app",
                                  "https://x@api.github.com/app", "https://api.github.com:444/app",
                                  "https://release-assets.githubusercontent.com/app"])
def test_metadata_response_cannot_change_origin(http, url):
    http._metadata = Opener([Response(b"{}", url)])
    with pytest.raises(UpdateError, match="invalid_metadata"):
        http.json("/repos/NZCypher819/strugglebus-releases/releases")


def test_metadata_type_encoding_length_depth_and_size_bounds(http):
    cases = [
        Response(b"{}", transport.API + "/app", media="text/html"),
        Response(b"{}", transport.API + "/app", Content_Encoding="gzip"),
        Response(b"{}", transport.API + "/app", status=201),
        Response(b"{}", transport.API + "/app", Content_Length="3"),
        Response(b"[" * 20 + b"]" * 20, transport.API + "/app"),
    ]
    for response in cases:
        http._metadata = Opener([response])
        with pytest.raises(UpdateError, match="invalid_metadata"):
            http.json("/repos/NZCypher819/strugglebus-releases/releases")
    http.limits = replace(http.limits, metadata_bytes=1)
    http._metadata = Opener([Response(b"{}", transport.API + "/app")])
    with pytest.raises(UpdateError, match="verification_failed"):
        http.json("/repos/NZCypher819/strugglebus-releases/releases")


def test_absent_length_is_bounded_and_link_only_marks_next(http):
    response = Response(b"{}", transport.API + "/app", Link='<https://evil/>; rel="next"')
    del response.headers["Content-Length"]
    http._metadata = Opener([response])
    assert http.json("/repos/NZCypher819/strugglebus-releases/releases") == ({}, True)
    assert http._metadata.calls == 1


@pytest.mark.parametrize("value", ["abc", "-1", "١", "10000000000", "99"])
def test_content_length_rejects_invalid_values(value):
    headers = Message()
    headers["Content-Length"] = value
    with pytest.raises(UpdateError):
        transport._size(headers, 5)


def test_request_rejects_mutations_and_omits_authorization(http):
    for path in ["https://evil", "//evil", "/app#fragment"]:
        with pytest.raises(UpdateError):
            http._request(path)
    request = http._request("/repos/NZCypher819/strugglebus-releases/releases")
    assert request.headers.get("Authorization") is None
    assert request.unredirected_hdrs.get("Authorization") is None
    redirect = _AssetRedirects().redirect_request(
        request, None, 302, "", {}, "https://release-assets.githubusercontent.com/opaque?signature=sensitive")
    assert redirect.get_header("Authorization") is None
    assert redirect.get_header("Host") is None
    assert redirect.get_header("X-github-api-version") is None


def test_redirect_failure_is_a_static_public_error(http):
    http._metadata = Opener([ReleasePublicationError("signed URL sensitive")])
    with pytest.raises(UpdateError, match="invalid_metadata") as error:
        http.json("/repos/NZCypher819/strugglebus-releases/releases")
    assert "sensitive" not in str(error.value)


def asset_response(payload=b"content"):
    asset = UpdateAsset(1, "requirements.lock", 7, hashlib.sha256(b"content").hexdigest(), "text/plain")
    response = Response(payload, transport.API + "/repos/NZCypher819/strugglebus-releases/releases/assets/1",
                        media="text/plain", Content_Disposition='attachment; filename="requirements.lock"')
    return asset, response


@pytest.mark.parametrize("mutation", [
    "type", "disposition", "filename", "length", "long", "short", "hash",
])
def test_download_validation_rejects_tampering(http, tmp_path, mutation):
    asset, response = asset_response()
    if mutation in {"long", "short", "hash"}:
        payload = {"long": b"too long", "short": b"short", "hash": b"tamper!"}[mutation]
        asset, response = asset_response(payload)
        response.headers.replace_header("Content-Length", "7")
    elif mutation == "type":
        response.headers.replace_header("Content-Type", "text/html")
    elif mutation == "disposition":
        del response.headers["Content-Disposition"]
    elif mutation == "filename":
        response.headers.replace_header("Content-Disposition", 'attachment; filename="../escape"')
    else:
        del response.headers["Content-Length"]
    http._assets = Opener([response])
    target = tmp_path / "owned"
    target.mkdir(mode=0o700)
    with pytest.raises(UpdateError):
        http.download("/repos/NZCypher819/strugglebus-releases/releases/assets/1",
                      asset, target / asset.name)


def test_github_asset_download_accepts_generic_transport_media_type(http, tmp_path):
    asset, response = asset_response()
    response.headers.replace_header("Content-Type", "application/octet-stream")
    http._assets = Opener([response])
    target = tmp_path / "owned"
    target.mkdir(mode=0o700)

    http.download(
        "/repos/NZCypher819/strugglebus-releases/releases/assets/1",
        asset,
        target / asset.name,
    )

    assert (target / asset.name).read_bytes() == b"content"


def test_stream_is_rate_limited_sequential_and_no_partial_retry(http, tmp_path, monkeypatch):
    asset, response = asset_response()
    sleeps = []
    monkeypatch.setattr(transport, "_SLEEP", sleeps.append)
    http._assets = Opener([response])
    target = tmp_path / "owned"
    target.mkdir(mode=0o700)
    http.download("/repos/NZCypher819/strugglebus-releases/releases/assets/1",
                  asset, target / asset.name)
    assert sleeps == [7 / UpdateLimits().bytes_per_second]
    assert (target / asset.name).read_bytes() == b"content"
    with pytest.raises(FileExistsError):
        with transport.exclusive_file(target / asset.name):
            pytest.fail("existing file opened")


def test_throttle_refuses_to_cross_deadline(http):
    http.deadline = 100.000001
    with pytest.raises(UpdateError, match="timeout"):
        http._throttle(1024, 100)


def test_private_directory_posix_owner_and_mode_checks(tmp_path, monkeypatch):
    actual = tmp_path.lstat()
    facade = SimpleNamespace(name="posix", geteuid=lambda: actual.st_uid)
    monkeypatch.setattr(transport, "os", facade)
    original = Path.lstat
    mode = [stat.S_IFDIR | 0o700]

    def metadata(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path == tmp_path:
            return SimpleNamespace(st_mode=mode[0], st_uid=info.st_uid, st_dev=info.st_dev, st_ino=info.st_ino)
        return info

    monkeypatch.setattr(Path, "lstat", metadata)
    transport.private_directory(tmp_path)
    mode[0] = stat.S_IFDIR | 0o777
    with pytest.raises(UpdateError, match="storage_unsafe"):
        transport.private_directory(tmp_path)
    mode[0] = stat.S_IFREG | 0o600
    with pytest.raises(UpdateError, match="storage_unsafe"):
        transport.private_directory(tmp_path)


def test_download_retries_only_before_open_and_not_after_partial_bytes(http, tmp_path):
    target = tmp_path / "owned"
    target.mkdir(mode=0o700)
    asset, response = asset_response()
    http._assets = Opener([OSError("sensitive"), response])
    http.download("/fixed", asset, target / asset.name)
    assert http._assets.calls == 2
    (target / asset.name).unlink()
    http._assets = Opener([OSError("sensitive")] * 3)
    with pytest.raises(UpdateError, match="source_unavailable"):
        http.download("/fixed", asset, target / asset.name)
    assert http._assets.calls == 3
    asset, response = asset_response()

    def fail_read(size):
        raise OSError("signed URL secret")

    response.read = fail_read
    response.read1 = fail_read
    http._assets = Opener([response])
    with pytest.raises(UpdateError, match="source_unavailable"):
        http.download("/fixed", asset, target / asset.name)
    assert http._assets.calls == 1


def test_redirect_and_each_socket_read_use_remaining_absolute_deadline(http):
    request = http._request(
        "/repos/NZCypher819/strugglebus-releases/releases/assets/1", asset=True,
    )
    request.timeout = 30
    handler = transport._DeadlineAssetRedirects(105)
    redirected = handler.redirect_request(
        request, None, 302, "", {}, "https://release-assets.githubusercontent.com/opaque?signature=synthetic")
    assert request.timeout == 5
    assert redirected.get_header("Authorization") is None
    timeouts = []
    response = Response(b"{}", transport.API + "/app")
    response.fp = SimpleNamespace(raw=SimpleNamespace(_sock=SimpleNamespace(settimeout=timeouts.append)))
    http.deadline = 104
    assert http._chunk(response, 2) == b"{}"
    assert timeouts == [4]
