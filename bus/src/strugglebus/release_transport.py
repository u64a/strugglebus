"""Shared exact-host, credential-stripping GitHub download transport policy."""
from __future__ import annotations
from typing import Any
import urllib.parse
import urllib.request

USER_AGENT = "strugglebus-immutable-release-v2"


GITHUB_API_HOST = "api.github.com"


GITHUB_ASSET_HOST = "release-assets.githubusercontent.com"


ASSET_ACCEPT = "application/octet-stream"


class ReleasePublicationError(RuntimeError):
    """The release state or GitHub API response is unsafe or conflicting."""


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


def _exact_https_host(
    url: Any,
    *,
    allowed_hosts: frozenset[str],
    error_message: str,
) -> str:
    _url_characters(url, error_message)
    _url_escapes(url, error_message)
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError:
        raise ReleasePublicationError(error_message) from None
    host = (parsed.hostname or "").casefold()
    if not _plain_https(parsed, port) or host not in allowed_hosts:
        raise ReleasePublicationError(error_message)
    return host


def _plain_https(parsed: urllib.parse.SplitResult, port: int | None) -> bool:
    """HTTPS on the default port with an absolute path and no embedded credentials."""
    return (
        parsed.scheme.casefold() == "https"
        and bool(parsed.netloc)
        and parsed.path.startswith("/")
        and parsed.username is None
        and parsed.password is None
        and port in {None, 443}
    )


def _url_characters(url: Any, error_message: str) -> None:
    if not isinstance(url, str) or not url or not url.isascii():
        raise ReleasePublicationError(error_message)
    if "#" in url or "\\" in url:
        raise ReleasePublicationError(error_message)
    if any(ord(character) <= 32 or ord(character) == 127 for character in url):
        raise ReleasePublicationError(error_message)


def _url_escapes(url: str, error_message: str) -> None:
    for index, character in enumerate(url):
        if character == "%" and (
            index + 2 >= len(url)
            or any(digit not in "0123456789abcdefABCDEF" for digit in url[index + 1:index + 3])
        ):
            raise ReleasePublicationError(error_message)


class _AssetRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> urllib.request.Request:
        if (
            code != 302
            or request.get_method() != "GET"
            or request.data is not None
        ):
            raise ReleasePublicationError("GitHub asset redirect is not trusted")
        _exact_https_host(
            request.full_url,
            allowed_hosts=frozenset({GITHUB_API_HOST}),
            error_message="GitHub asset redirect source is not trusted",
        )
        _exact_https_host(
            new_url,
            allowed_hosts=frozenset({GITHUB_ASSET_HOST}),
            error_message="GitHub asset redirect target is not trusted",
        )
        return urllib.request.Request(
            new_url,
            headers={
                "Accept": ASSET_ACCEPT,
                "User-Agent": USER_AGENT,
            },
            method="GET",
        )

    def http_error_302(
        self,
        request: urllib.request.Request,
        file: Any,
        code: int,
        message: str,
        headers: Any,
    ) -> Any:
        locations = (
            headers.get_all("Location")
            if hasattr(headers, "get_all")
            else [headers.get("Location")]
        )
        try:
            if (
                len(locations) != 1
                or not isinstance(locations[0], str)
                or headers.get("URI") is not None
            ):
                raise ReleasePublicationError(
                    "GitHub asset redirect location is invalid"
                )
            redirected = self.redirect_request(
                request,
                file,
                code,
                message,
                headers,
                locations[0],
            )
        finally:
            file.close()
        return self.parent.open(redirected, timeout=request.timeout)

    def _reject_alternate_redirect(
        self,
        request: urllib.request.Request,
        file: Any,
        code: int,
        message: str,
        headers: Any,
    ) -> None:
        file.close()
        raise ReleasePublicationError(
            "GitHub asset redirect status is not accepted"
        )

    http_error_301 = _reject_alternate_redirect
    http_error_303 = _reject_alternate_redirect
    http_error_307 = _reject_alternate_redirect
    http_error_308 = _reject_alternate_redirect


def _response_media_type(headers: Any) -> str:
    value = headers.get("Content-Type")
    if not isinstance(value, str):
        return ""
    return value.split(";", 1)[0].strip().casefold()
