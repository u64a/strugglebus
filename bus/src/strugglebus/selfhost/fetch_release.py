#!/usr/bin/env python3
"""Fetches the newest Strugglebus release when it is newer than the installed one.

Used by the automatic updaters in debian/ and docker/. Standard library only,
because it runs before anything of the new release is installed.

    fetch_release.py --installed 0.2.67 --into /some/new/folder

Prints one line and exits 0:

    current <latest version>            nothing newer; nothing was downloaded
    ready <latest version>              the release is in the folder, verified,
                                        with the install files under _wheel/

Exits 3 when the release page cannot be reached and 4 when the release does not
pass its checks. The reason goes to standard error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

REPOSITORY = "NZCypher819/strugglebus-releases"
API = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
DOWNLOAD_PREFIX = f"https://github.com/{REPOSITORY}/releases/download/"
MAXIMUM_BYTES = 64 * 1024 * 1024
UNREACHABLE = 3
INVALID = 4
_VERSION = re.compile(r"(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})")


class Problem(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


def parse_version(text: str) -> tuple[int, int, int]:
    match = _VERSION.fullmatch(text)
    if match is None:
        raise Problem(INVALID, f"'{text}' is not a release version such as 0.2.67")
    return int(match[1]), int(match[2]), int(match[3])


def _read(url: str, limit: int) -> bytes:
    if not url.startswith(("https://", "http://127.0.0.1:", "http://localhost:")):
        raise Problem(INVALID, f"refusing to download from {url}")
    request = urllib.request.Request(  # noqa: S310 - scheme checked above
        url, headers={"User-Agent": "strugglebus-update", "Accept": "application/json, */*"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310  # nosec B310
            data = response.read(limit + 1)
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise Problem(UNREACHABLE, f"could not download {url}: {error}") from None
    if len(data) > limit:
        raise Problem(INVALID, f"{url} is larger than expected")
    return data


def _newest_release(api: str) -> tuple[str, dict[str, object]]:
    """Returns the newest release's tag and its assets as name -> download URL."""
    try:
        release = json.loads(_read(api, 2 * 1024 * 1024))
        tag = release["tag_name"]
        assets = {asset["name"]: asset["browser_download_url"] for asset in release["assets"]}
    except (ValueError, KeyError, TypeError):
        raise Problem(INVALID, "the release page did not describe a release") from None
    if not isinstance(tag, str) or not tag.startswith("v"):
        raise Problem(INVALID, "the newest release has an unexpected name")
    return tag, assets


def _download(
    tag: str, assets: dict[str, object], needed: tuple[str, ...], into: Path,
    download_prefix: str,
) -> None:
    """Downloads the needed files, after checking that every one has a usable address."""
    for name in needed:
        url = assets.get(name)
        if not isinstance(url, str) or not url.startswith(download_prefix):
            raise Problem(INVALID, f"release {tag} has no usable {name}")
    into.mkdir(parents=True, exist_ok=False)
    for name in needed:
        (into / name).write_bytes(_read(assets[name], MAXIMUM_BYTES))


def _verify_checksums(tag: str, into: Path, names: tuple[str, ...]) -> None:
    listed: dict[str, str] = {}
    for line in (into / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        # "<digest>  <name>" (text) or "<digest> *<name>" (binary); both are in use.
        digest, _, name = line.strip().partition(" ")
        listed[name.strip().removeprefix("*")] = digest.lower()
    for name in names:
        actual = hashlib.sha256((into / name).read_bytes()).hexdigest()
        if listed.get(name) != actual:
            raise Problem(INVALID, f"{name} does not match SHA256SUMS in release {tag}")


def _unpack_install_files(tag: str, into: Path, wheel: str) -> None:
    kit = into / "_wheel"
    try:
        with zipfile.ZipFile(into / wheel) as archive:
            members = [
                name for name in archive.namelist() if name.startswith("strugglebus/selfhost/")
            ]
            archive.extractall(kit, members)
    except (zipfile.BadZipFile, OSError) as error:
        raise Problem(INVALID, f"{wheel} could not be opened: {error}") from None
    if not (kit / "strugglebus" / "selfhost" / "fetch_release.py").is_file():
        raise Problem(INVALID, f"release {tag} does not carry the install files")


def fetch(installed: str, into: Path, *, api: str, download_prefix: str) -> tuple[str, str]:
    current = parse_version(installed)
    tag, assets = _newest_release(api)
    version = tag[1:]
    if parse_version(version) <= current:
        return "current", version

    wheel = f"strugglebus-{version}-py3-none-any.whl"
    _download(tag, assets, ("SHA256SUMS", "requirements.lock", wheel), into, download_prefix)
    _verify_checksums(tag, into, ("requirements.lock", wheel))
    _unpack_install_files(tag, into, wheel)
    return "ready", version


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--installed", required=True, help="the version running now")
    parser.add_argument("--into", required=True, type=Path, help="a folder that does not exist yet")
    parser.add_argument("--api", default=API, help=argparse.SUPPRESS)
    parser.add_argument("--download-prefix", default=DOWNLOAD_PREFIX, help=argparse.SUPPRESS)
    options = parser.parse_args(arguments)
    try:
        word, version = fetch(
            options.installed, options.into,
            api=options.api, download_prefix=options.download_prefix,
        )
    except Problem as problem:
        print(f"fetch_release: {problem}", file=sys.stderr)
        return problem.code
    print(word, version)
    return 0


if __name__ == "__main__":
    sys.exit(main())
