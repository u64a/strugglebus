#!/usr/bin/env python3
"""Fetches the newest Strugglebus release when it is newer than the installed one.

Used by the automatic updaters in debian/ and docker/. Standard library only,
because it runs before anything of the new release is installed.

    fetch_release.py --installed 0.2.67 --into /some/new/folder

Prints one line and exits 0:

    current <latest version>            nothing newer; nothing was downloaded
    ready <latest version>              the release is in the folder, verified,
                                        with the install files under _wheel/

A release is used only if its files are the ones named in a statement signed by
one of the project's release keys (see RELEASE_KEYS). Publishing a release is
not enough.

Exits 3 when the release page cannot be reached and 4 when the release does not
pass its checks. The reason goes to standard error.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable, Iterable
from pathlib import Path

# Where releases are published: the project's own repository, which also holds the releases of
# its other parts. A bus release there is tagged bus/vX.Y.Z, and nothing else is a bus release.
REPOSITORY = "u64a/strugglebus"
TAG_PREFIX = "bus/v"
API = f"https://api.github.com/repos/{REPOSITORY}/releases?per_page=30"
DOWNLOAD_PREFIX = f"https://github.com/{REPOSITORY}/releases/download/"

# Where releases were published up to 0.2.73. It is still asked, after the place above, so a bus
# is never left without updates if it cannot use the new place. A release from either is taken
# only if a release key signed it, so asking two places trusts nobody new.
FORMER_REPOSITORY = "NZCypher819/strugglebus-releases"
FORMER_API = f"https://api.github.com/repos/{FORMER_REPOSITORY}/releases/latest"
FORMER_DOWNLOAD_PREFIX = f"https://github.com/{FORMER_REPOSITORY}/releases/download/"
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


# ---- The publisher's signature --------------------------------------------------------------
#
# A release's files are named, by SHA-256, in a short statement that the project owner signs
# with a hardware key. The statement and its signature travel in the release's annotated tag.
# Nothing from a release is installed, run or imported until its statement verifies here, in the
# updater that is already installed. So publishing a release is not enough to run code: the
# signature needs a key that is not held by GitHub.
#
# The check is done in Python, not with ssh-keygen, because this file also runs inside a plain
# Python container that has no ssh-keygen. It only verifies; it never handles a secret.

STATEMENT_HEADER = "strugglebus-bus-release 1"
SIGNATURE_NAMESPACE = "strugglebus-bus-release"
_SIGNATURE_BEGIN = "-----BEGIN SSH SIGNATURE-----"
_SIGNATURE_END = "-----END SSH SIGNATURE-----"
_KEY_TYPE = b"sk-ssh-ed25519@openssh.com"
# The hardware key must report both that it was touched and that its PIN was given. Requiring the
# PIN here is what makes a stolen key useless without it.
_TOUCHED_AND_PIN_VERIFIED = 0x05

# The keys allowed to sign a release: the owner's three hardware keys, as OpenSSH public key
# blobs. They are fixed in this file, which is installed root-owned. A different set arrives only
# in a release signed by one of these.
RELEASE_KEYS = (
    "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIN56hk/clV5r0XsK7JkOlTLz0Zyri/QEhaIqCnmd+5yO"
    "AAAAF3NzaDpzdHJ1Z2dsZWJ1cy1zaWduaW5n",
    "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIMLHD9G3fCyGMJ8RlHGYzaB7P3efJFqoQoQZ1AxivmUF"
    "AAAAF3NzaDpzdHJ1Z2dsZWJ1cy1zaWduaW5n",
    "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIMOObxkek5mGgpHJVUzS8mkKtGYyaazmUArYEWj3whC7"
    "AAAAF3NzaDpzdHJ1Z2dsZWJ1cy1zaWduaW5n",
)


def key_fingerprint(key_blob: bytes) -> str:
    """The fingerprint ssh-keygen prints for a public key, for messages."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(key_blob).digest()).decode().rstrip("=")


# Ed25519 verification, after the reference code in RFC 8032 section 6.

_P = 2**255 - 19
_ORDER = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_Point = tuple[int, int, int, int]


def _point_add(a: _Point, b: _Point) -> _Point:
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    first = (y1 - x1) * (y2 - x2) % _P
    second = (y1 + x1) * (y2 + x2) % _P
    third = 2 * t1 * t2 * _D % _P
    fourth = 2 * z1 * z2 % _P
    e, f, g, h = second - first, fourth - third, fourth + third, second + first
    return e * f % _P, g * h % _P, f * g % _P, e * h % _P


def _point_multiply(scalar: int, point: _Point) -> _Point:
    result: _Point = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _points_equal(a: _Point, b: _Point) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0 or (x == 0 and sign):
        return None
    return _P - x if (x & 1) != sign else x


def _point_decode(encoded: bytes) -> _Point | None:
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


_BASE_Y = 4 * pow(5, _P - 2, _P) % _P
_BASE: _Point = (_recover_x(_BASE_Y, 0) or 0, _BASE_Y, 1, (_recover_x(_BASE_Y, 0) or 0) * _BASE_Y % _P)


def ed25519_verifies(public: bytes, message: bytes, signature: bytes) -> bool:
    """True only when ``signature`` is the Ed25519 signature of ``message`` by ``public``."""
    key = _point_decode(public)
    commitment = _point_decode(signature[:32]) if len(signature) == 64 else None
    if key is None or commitment is None:
        return False
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= _ORDER:
        return False
    digest = hashlib.sha512(signature[:32] + public + message).digest()
    challenge = int.from_bytes(digest, "little") % _ORDER
    return _points_equal(
        _point_multiply(scalar, _BASE), _point_add(commitment, _point_multiply(challenge, key)),
    )


class _Reader:
    """Reads the length-prefixed fields OpenSSH writes."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._at = 0

    def take(self, count: int) -> bytes:
        if count < 0 or self._at + count > len(self._data):
            raise ValueError("truncated")
        value = self._data[self._at:self._at + count]
        self._at += count
        return value

    def string(self) -> bytes:
        return self.take(int.from_bytes(self.take(4), "big"))

    def finish(self) -> None:
        if self._at != len(self._data):
            raise ValueError("trailing data")


def _packed(*fields: bytes) -> bytes:
    return b"".join(len(field).to_bytes(4, "big") + field for field in fields)


def _armoured(signature: str) -> bytes:
    lines = [line.strip() for line in signature.strip().splitlines()]
    if len(lines) < 3 or lines[0] != _SIGNATURE_BEGIN or lines[-1] != _SIGNATURE_END:
        raise ValueError("not an SSH signature")
    return base64.b64decode("".join(lines[1:-1]), validate=True)


def _signature_fields(signature: str, namespace: str) -> tuple[bytes, bytes, bytes, bytes]:
    """The signer's key blob, the wrapper's reserved field, the raw signature, and flags + counter."""
    outer = _Reader(_armoured(signature))
    if outer.take(6) != b"SSHSIG" or outer.take(4) != (1).to_bytes(4, "big"):
        raise ValueError("unsupported signature format")
    key_blob, signed_namespace, reserved = outer.string(), outer.string(), outer.string()
    algorithm, signature_blob = outer.string(), outer.string()
    outer.finish()
    if signed_namespace != namespace.encode() or algorithm != b"sha512":
        raise ValueError("signed for another purpose, or with an unexpected hash")
    inner = _Reader(signature_blob)
    signature_type, raw, device = inner.string(), inner.string(), inner.take(5)
    inner.finish()
    if signature_type != _KEY_TYPE or device[0] & _TOUCHED_AND_PIN_VERIFIED != _TOUCHED_AND_PIN_VERIFIED:
        raise ValueError("not signed with a touched, PIN-verified hardware key")
    return key_blob, reserved, raw, device


def _hardware_key(key_blob: bytes) -> tuple[bytes, bytes]:
    """The Ed25519 public key and the application name inside a hardware key's public blob."""
    key = _Reader(key_blob)
    key_type, public, application = key.string(), key.string(), key.string()
    key.finish()
    if key_type != _KEY_TYPE:
        raise ValueError("not a hardware Ed25519 key")
    return public, application


def _hardware_signed_bytes(
    application: bytes, device: bytes, namespace: str, reserved: bytes, message: bytes,
) -> bytes:
    """
    What a hardware key actually signs. It is not the message: it is the hash of the key's
    application name, the device's flags and counter, and the hash of OpenSSH's wrapper around
    the message's hash.
    """
    wrapped = b"SSHSIG" + _packed(namespace.encode(), reserved, b"sha512", hashlib.sha512(message).digest())
    return hashlib.sha256(application).digest() + device + hashlib.sha256(wrapped).digest()


def signer_of(
    signature: str, message: bytes, namespace: str = SIGNATURE_NAMESPACE,
    keys: tuple[str, ...] | None = None,
    verifies: Callable[[bytes, bytes, bytes], bool] = ed25519_verifies,
) -> str | None:
    """
    The fingerprint of the release key that signed ``message``, or None when the signature is
    not a valid one by one of ``keys`` for ``namespace``. The key inside the signature only
    selects which pinned key to check against: it must equal one of them byte for byte, the
    application name included.
    """
    try:
        key_blob, reserved, raw, device = _signature_fields(signature, namespace)
        if key_blob not in {base64.b64decode(key) for key in (RELEASE_KEYS if keys is None else keys)}:
            return None
        public, application = _hardware_key(key_blob)
    except (ValueError, IndexError):
        return None
    signed = _hardware_signed_bytes(application, device, namespace, reserved, message)
    return key_fingerprint(key_blob) if verifies(public, signed, raw) else None


def release_statement(version: str, digests: dict[str, str]) -> str:
    """The exact text the owner signs for a release: its version and the hash of every file."""
    lines = [STATEMENT_HEADER, f"version {version}"]
    lines += [f"{digests[name].lower()}  {name}" for name in sorted(digests)]
    return "\n".join(lines) + "\n"


def _split_tag_message(message: str) -> tuple[str, str]:
    """Finds the statement and the signature in an annotated tag's message."""
    start = message.find(STATEMENT_HEADER + "\n")
    begin = message.find(_SIGNATURE_BEGIN)
    end = message.find(_SIGNATURE_END)
    if start < 0 or begin < start or end < begin or (start > 0 and message[start - 1] != "\n"):
        raise Problem(INVALID, "the release is not signed by its publisher")
    return message[start:begin], message[begin:end + len(_SIGNATURE_END)]


def signed_digests(
    message: str, version: str, *,
    keys: tuple[str, ...] | None = None,
    verifies: Callable[[bytes, bytes, bytes], bool] = ed25519_verifies,
) -> dict[str, str]:
    """
    The file hashes the publisher signed for ``version``, read from the release tag's message.
    Raises Problem unless a release key signed exactly that statement for exactly that version.
    """
    statement, signature = _split_tag_message(message)
    if signer_of(signature, statement.encode(), keys=keys, verifies=verifies) is None:
        raise Problem(INVALID, "the release's signature is not valid, or is not by a release key")
    return _statement_digests(statement, version)


def _statement_digests(statement: str, version: str) -> dict[str, str]:
    """Reads a verified statement strictly: exact lines, this version, one hash per name."""
    lines = statement.split("\n")
    if "\r" in statement or lines[-1] != "" or lines[:2] != [STATEMENT_HEADER, f"version {version}"]:
        raise Problem(INVALID, f"the signed statement is not for release {version}")
    digests: dict[str, str] = {}
    for line in lines[2:-1]:
        match = _STATEMENT_LINE.fullmatch(line)
        if match is None or match["name"] in digests:
            raise Problem(INVALID, "the signed statement is malformed")
        digests[match["name"]] = match["digest"]
    if not digests:
        raise Problem(INVALID, "the signed statement names no files")
    return digests


# One file: its SHA-256 in lower-case hexadecimal, two spaces, and a plain file name.
_STATEMENT_LINE = re.compile(r"(?P<digest>[0-9a-f]{64})  (?P<name>[A-Za-z0-9][A-Za-z0-9._+-]{0,199})")


def require_signed(digests: dict[str, str], name: str, data: bytes) -> None:
    """Refuses a file whose bytes are not the ones the publisher signed under that name."""
    if digests.get(name) != hashlib.sha256(data).hexdigest():
        raise Problem(INVALID, f"{name} is not the file the publisher signed")


def require_all_present(digests: dict[str, str], present: Iterable[str]) -> None:
    """Refuses a release that lacks a file its publisher signed."""
    missing = sorted(set(digests) - set(present))
    if missing:
        raise Problem(INVALID, f"the release is missing {missing[0]}, which its publisher signed")


def _tag_message(api: str, tag: str) -> str:
    """Reads the annotated tag's message for a release, from the same repository as the release."""
    root = api.split("/releases", 1)[0]
    try:
        ref = json.loads(_read(f"{root}/git/ref/tags/{tag}", 64 * 1024))
        target = ref["object"]
        if target["type"] != "tag":
            raise KeyError("type")
        record = json.loads(_read(f"{root}/git/tags/{target['sha']}", 64 * 1024))
        message = record["message"]
        if record["tag"] != tag or not isinstance(message, str):
            raise KeyError("tag")
    except (ValueError, KeyError, TypeError):
        raise Problem(INVALID, f"release {tag} is not signed by its publisher") from None
    return message


class _Release:
    """One published bus release: its tag, its version and where its files are."""

    def __init__(self, tag: str, version: str, assets: dict[str, object], api: str, prefix: str) -> None:
        self.tag = tag
        self.version = version
        self.assets = assets
        self.api = api
        self.download_prefix = prefix


def _version_of(tag: object, prefixes: tuple[str, ...]) -> str | None:
    """The version a release tag names, when it is a bus release's tag; otherwise None."""
    if not isinstance(tag, str):
        return None
    for prefix in prefixes:
        if tag.startswith(prefix) and _VERSION.fullmatch(tag[len(prefix):]):
            return tag[len(prefix):]
    return None


def _described(record: object, prefixes: tuple[str, ...], api: str, prefix: str) -> _Release | None:
    """A published bus release from one record of a release page, or None for anything else."""
    if not isinstance(record, dict) or record.get("draft") or record.get("prerelease"):
        return None
    version = _version_of(record.get("tag_name"), prefixes)
    if version is None:
        return None
    assets = {asset["name"]: asset["browser_download_url"] for asset in record["assets"]}
    return _Release(str(record["tag_name"]), version, assets, api, prefix)


def _only_release(page: object, api: str, download_prefix: str) -> list[_Release | None]:
    """The release a single-release page describes. Such a page may name it vX.Y.Z as well."""
    if not isinstance(page, dict) or "tag_name" not in page or "assets" not in page:
        raise KeyError("release")
    release = _described(page, (TAG_PREFIX, "v"), api, download_prefix)
    if release is None:
        raise Problem(INVALID, "the newest release has an unexpected name")
    return [release]


def _newest_release(api: str, download_prefix: str) -> _Release | None:
    """
    The newest bus release a place offers, or None when it has none.

    The project's repository answers with a list that also holds other parts' releases, so only
    tags starting bus/v count there. A page that describes a single release is the former place,
    or a mirror.
    """
    try:
        page = json.loads(_read(api, 2 * 1024 * 1024))
        if isinstance(page, list):
            found = [_described(record, (TAG_PREFIX,), api, download_prefix) for record in page]
        else:
            found = _only_release(page, api, download_prefix)
    except (ValueError, KeyError, TypeError, AttributeError):
        raise Problem(INVALID, "the release page did not describe a release") from None
    releases = [release for release in found if release is not None]
    return max(releases, key=lambda release: parse_version(release.version), default=None)


def _newest_anywhere(places: tuple[tuple[str, str], ...]) -> _Release | None:
    """
    The newest bus release across the places to ask. A place that cannot be reached or read is
    passed over while another answers; if none answers, the first problem is reported.
    """
    best: _Release | None = None
    answered = False
    problem: Problem | None = None
    for api, download_prefix in places:
        try:
            release = _newest_release(api, download_prefix)
        except Problem as error:
            problem = problem or error
            continue
        answered = True
        if release is not None and (best is None or parse_version(release.version) > parse_version(best.version)):
            best = release
    if not answered and problem is not None:
        raise problem
    return best


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


def _places(api: str, download_prefix: str) -> tuple[tuple[str, str], ...]:
    """Where to ask. A mirror set by the operator is asked alone; otherwise the former place is asked too."""
    if (api, download_prefix) != (API, DOWNLOAD_PREFIX):
        return ((api, download_prefix),)
    return ((API, DOWNLOAD_PREFIX), (FORMER_API, FORMER_DOWNLOAD_PREFIX))


def fetch(installed: str, into: Path, *, api: str, download_prefix: str) -> tuple[str, str]:
    current = parse_version(installed)
    release = _newest_anywhere(_places(api, download_prefix))
    if release is None:
        return "current", installed
    tag, version, assets = release.tag, release.version, release.assets
    if parse_version(version) <= current:
        return "current", version

    # The publisher's signature comes first: nothing below it is trusted without it.
    digests = signed_digests(_tag_message(release.api, tag), version)
    require_all_present(digests, assets)
    wheel = f"strugglebus-{version}-py3-none-any.whl"
    needed = ("SHA256SUMS", "requirements.lock", wheel)
    _download(tag, assets, needed, into, release.download_prefix)
    for name in needed:
        require_signed(digests, name, (into / name).read_bytes())
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
