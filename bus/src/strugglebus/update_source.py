"""Anonymous, bounded discovery and preparation of immutable release bytes.

The installed verifier never executes a release wheel or deployment helper.
Offline verification establishes integrity and policy, not publisher identity.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import zipfile
from typing import Any

from .release_records import LocalAsset, _asset_media_type, _validate_asset_records
from .release_transport import ReleasePublicationError
from . import release_validation as policy
from .release_signature import ReleaseSignatureError, signed_digests
from .update_transport import _HTTP, _identity, budget, exclusive_file, private_directory, remaining
from .update_types import (
    RELEASE_TAG_PREFIX, UPDATE_REPOSITORY, UPDATE_SOURCE_REPOSITORY, UpdateAsset, UpdateCandidate,
    UpdateDiscovery, UpdateError, UpdateLimits, require_version,
)

_ROOT = f"/repos/{UPDATE_REPOSITORY}"
_VERSION = re.compile(r"v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})")
_SHA = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"sha256:([0-9a-f]{64})")
_INVALID_BYTES = (OSError, ValueError, RuntimeError, KeyError, TypeError,
                  tarfile.TarError, zipfile.BadZipFile, EOFError)


def _policy_id() -> str:
    value = {
        "verifier": 2, "repository": UPDATE_REPOSITORY,
        "source_repository": UPDATE_SOURCE_REPOSITORY,
        "schema": policy.CURRENT_SCHEMA, "minimum_schema": policy.MINIMUM_UPGRADE_SCHEMA,
        "rollback_schema": policy.ROLLBACK_PREVIOUS_SCHEMA, "guide": policy.GUIDE_VERSION,
        "protocol": policy.COORDINATION_PROTOCOL_VERSION, "freeze": policy.ACCESS_FREEZE_CAPABILITY,
        "uv": policy.UV_VERSION, "uv_archive": policy.UV_ARCHIVE_SHA256,
        "python": ">=3.12,<3.14", "build_python": "3.13", "tested_python": ["3.12", "3.13"],
        "support": [(item.source, item.archive, item.destination, item.mode) for item in policy.SUPPORT_FILES],
    }
    return "prepare-v1:" + hashlib.sha256(policy._canonical_json(value)).hexdigest()


POLICY_ID = _policy_id()


def positive_id(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= 2**53 - 1:
        raise UpdateError("invalid_metadata")
    return value


def object_value(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise UpdateError("invalid_metadata")
    return value


class _Session:
    """One anonymous public-release job with no credential or auth state."""

    def __init__(self, http: _HTTP):
        remaining(http.deadline)
        self.http = http

    def get(self, path: str) -> tuple[Any, bool]:
        result = self.http.json(path)
        remaining(self.http.deadline)
        return result

    def download(self, asset: UpdateAsset, destination: Path) -> None:
        self.http.download(f"{_ROOT}/releases/assets/{asset.asset_id}", asset, destination)
        remaining(self.http.deadline)


def _tag_message(session: _Session, tag_sha: str) -> str:
    """The message of the release's annotated tag, which carries the publisher's signed statement."""
    message = _get_object(session, f"{_ROOT}/git/tags/{tag_sha}").get("message")
    if not isinstance(message, str) or len(message.encode()) > policy.MAX_STATEMENT_BYTES:
        raise UpdateError("verification_failed")
    return message


def _read_statement(directory: Path) -> str:
    path = directory / policy.STATEMENT_NAME
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > policy.MAX_STATEMENT_BYTES:
        raise UpdateError("storage_unsafe")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        return stream.read(policy.MAX_STATEMENT_BYTES + 1).decode("utf-8")


def _verify_signature(candidate: UpdateCandidate, directory: Path) -> None:
    """
    The publisher signed exactly this release: the statement saved beside the files is signed by
    a pinned release key, is for this version, and names each file with the hash it has.
    """
    try:
        signed = signed_digests(_read_statement(directory), candidate.version)
    except ReleaseSignatureError:
        raise UpdateError("verification_failed") from None
    if signed != {asset.name: asset.sha256 for asset in candidate.assets}:
        raise UpdateError("verification_failed")


def _names(version: str) -> set[str]:
    return {policy.MANIFEST_NAME, policy.CHECKSUMS_NAME, "requirements.lock",
            f"strugglebus-{version}-py3-none-any.whl",
            policy.SUPPORT_NAME_TEMPLATE.format(version=version)}


def _maximum(name: str) -> int:
    return {
        policy.MANIFEST_NAME: policy.MAX_MANIFEST_BYTES,
        policy.CHECKSUMS_NAME: policy.MAX_CHECKSUMS_BYTES,
        "requirements.lock": policy.MAX_LOCK_BYTES,
    }.get(name, policy.MAX_ASSET_BYTES)


def _asset(record: Any, names: set[str]) -> UpdateAsset:
    value = object_value(record)
    name = value.get("name")
    if not isinstance(name, str) or name not in names:
        raise UpdateError("invalid_metadata")
    size = positive_id(value.get("size"))
    digest = value.get("digest")
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise UpdateError("invalid_metadata")
    if size > _maximum(name) or value.get("content_type") != _asset_media_type(name):
        raise UpdateError("invalid_metadata")
    return UpdateAsset(positive_id(value.get("id")), name, size, digest[7:], value["content_type"])


def _assets(value: Any, version: str, limits: UpdateLimits) -> tuple[UpdateAsset, ...]:
    if not isinstance(value, list) or len(value) != 5:
        raise UpdateError("invalid_metadata")
    assets = tuple(sorted((_asset(item, _names(version)) for item in value), key=lambda asset: asset.name))
    local = {asset.name: LocalAsset(asset.name, Path(asset.name), asset.size_bytes,
                                   asset.sha256, asset.media_type) for asset in assets}
    if len(local) != 5 or sum(asset.size_bytes for asset in assets) > limits.candidate_bytes:
        raise UpdateError("invalid_metadata")
    try:
        _validate_asset_records(value, local, complete=True)
    except ReleasePublicationError:
        raise UpdateError("invalid_metadata") from None
    return assets


def _sha(value: Any) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise UpdateError("invalid_metadata")
    return value


def _get_object(session: _Session, path: str) -> dict[str, Any]:
    value, more = session.get(path)
    if more:
        raise UpdateError("invalid_metadata")
    return object_value(value)


def _published_tag(tag: str) -> str:
    """The name a release's tag has in the repository: bus/vX.Y.Z for the release vX.Y.Z."""
    return RELEASE_TAG_PREFIX + tag


def _tag_identity(session: _Session, tag: str) -> tuple[str, str, str]:
    published = _published_tag(tag)
    ref = _get_object(session, f"{_ROOT}/git/ref/tags/{published}")
    target = object_value(ref.get("object"))
    if ref.get("ref") != f"refs/tags/{published}" or target.get("type") != "tag":
        raise UpdateError("unsupported_release")
    tag_sha = _sha(target.get("sha"))
    annotated = _get_object(session, f"{_ROOT}/git/tags/{tag_sha}")
    target = object_value(annotated.get("object"))
    if annotated.get("sha") != tag_sha or annotated.get("tag") != published or target.get("type") != "commit":
        raise UpdateError("unsupported_release")
    commit = _sha(target.get("sha"))
    record = _get_object(session, f"{_ROOT}/git/commits/{commit}")
    if record.get("sha") != commit:
        raise UpdateError("invalid_metadata")
    tree = _sha(object_value(record.get("tree")).get("sha"))
    return tag_sha, commit, tree


def _metadata_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _source_metadata(body: Any) -> Any:
    """Parse the bounded release body; shape and canonical form are checked by the caller."""
    if not isinstance(body, str):
        raise UpdateError("unsupported_release")
    try:
        if len(body.encode("utf-8")) > 512:
            raise ValueError
        return json.loads(
            body, object_pairs_hook=_metadata_object,
            parse_constant=lambda item: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, ValueError, RecursionError):
        raise UpdateError("unsupported_release") from None


def _source_identity(body: Any) -> tuple[str, str]:
    value = _source_metadata(body)
    expected_keys = {"version", "source_repository", "source_commit", "source_tree"}
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise UpdateError("unsupported_release")
    if type(value["version"]) is not int or value["version"] != 1:
        raise UpdateError("unsupported_release")
    if value["source_repository"] != UPDATE_SOURCE_REPOSITORY:
        raise UpdateError("unsupported_release")
    try:
        commit, tree = _sha(value["source_commit"]), _sha(value["source_tree"])
    except UpdateError:
        raise UpdateError("unsupported_release") from None
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if body != canonical:
        raise UpdateError("unsupported_release")
    return commit, tree


def _release_identity(value: Any, tag: str, publication_commit: str) -> tuple[int, str, str]:
    record = object_value(value)
    expected = {
        "tag_name": _published_tag(tag),
        "target_commitish": publication_commit,
        "name": _published_tag(tag),
        "draft": False,
        "prerelease": False,
        "immutable": True,
    }
    scalar_keys = {"tag_name", "target_commitish", "name"}
    if (
        any(record.get(key) != expected[key] for key in scalar_keys)
        or record.get("draft") is not False
        or record.get("prerelease") is not False
        or record.get("immutable") is not True
    ):
        raise UpdateError("unsupported_release")
    source_commit, source_tree = _source_identity(record.get("body"))
    return positive_id(record.get("id")), source_commit, source_tree


def _resolve(session: _Session, release_id: int, version: str, limits: UpdateLimits) -> UpdateCandidate:
    tag = "v" + version
    record = _get_object(session, f"{_ROOT}/releases/{release_id}")
    tag_sha, publication_commit, _publication_tree = _tag_identity(session, tag)
    observed_id, source_commit, source_tree = _release_identity(
        record, tag, publication_commit,
    )
    if observed_id != release_id:
        raise UpdateError("publication_changed")
    assets, more = session.get(f"{_ROOT}/releases/{release_id}/assets?per_page=6")
    if more:
        raise UpdateError("invalid_metadata")
    return UpdateCandidate(version, release_id, tag, tag_sha, source_commit, source_tree, POLICY_ID,
                           _assets(assets, version, limits))


def _newer(record: Any, running: tuple[int, ...]) -> tuple[tuple[int, ...], int] | None:
    value = object_value(record)
    if value.get("draft") is True or value.get("prerelease") is True:
        return None
    # Only bus releases count. The repository's other releases, and a bare vX.Y.Z, are not ours.
    published = value.get("tag_name")
    if not isinstance(published, str) or not published.startswith(RELEASE_TAG_PREFIX):
        return None
    tag = published[len(RELEASE_TAG_PREFIX):]
    if _VERSION.fullmatch(tag) is None:
        return None
    version = tuple(int(part) for part in tag[1:].split("."))
    if version <= running:
        return None
    return version, positive_id(value.get("id"))


def _listing(
    session: _Session, running: str, limits: UpdateLimits,
) -> tuple[list[tuple[tuple[int, ...], int]], bool, int]:
    candidates: list[tuple[tuple[int, ...], int]] = []
    inspected = 0
    for page in range(1, limits.release_pages + 1):
        records, more = session.get(f"{_ROOT}/releases?per_page={limits.releases_per_page}&page={page}")
        if not isinstance(records, list) or len(records) > limits.releases_per_page:
            raise UpdateError("invalid_metadata")
        inspected += len(records)
        for record in records:
            candidate = _newer(record, tuple(int(part) for part in running.split(".")))
            if candidate is not None:
                candidates.append(candidate)
        if not more and len(records) < limits.releases_per_page:
            return candidates, True, inspected
    return candidates, False, inspected


def _discover(session: _Session, running: str, limits: UpdateLimits) -> UpdateDiscovery:
    candidates, complete, inspected = _listing(session, running, limits)
    if not candidates:
        return UpdateDiscovery(None, complete, inspected, None, None)
    # Offer the newest release. The installed verifier accepts any forward
    # schema, so a host several releases behind updates in one step, and a
    # broken release is superseded by publishing a fixed one.
    version, release_id = max(candidates)
    text = ".".join(str(part) for part in version)
    if sum(item[0] == version for item in candidates) != 1:
        return UpdateDiscovery(None, complete, inspected, text, "publication_changed")
    try:
        candidate = _resolve(session, release_id, text, limits)
    except UpdateError as error:
        if error.code not in {"unsupported_release", "invalid_metadata", "publication_changed"}:
            raise
        return UpdateDiscovery(None, complete, inspected, text, error.code)
    return UpdateDiscovery(candidate, complete, inspected, None, None)


def _candidate(candidate: UpdateCandidate, limits: UpdateLimits) -> None:
    if candidate.policy_id != POLICY_ID:
        raise UpdateError("policy_mismatch")
    if {asset.name for asset in candidate.assets} != _names(candidate.version):
        raise UpdateError("verification_failed")
    if sum(asset.size_bytes for asset in candidate.assets) > limits.candidate_bytes:
        raise UpdateError("verification_failed")
    for asset in candidate.assets:
        if asset.size_bytes > _maximum(asset.name) or asset.media_type != _asset_media_type(asset.name):
            raise UpdateError("verification_failed")


def _file_stamp(path: Path, asset: UpdateAsset) -> tuple[int, ...]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != asset.size_bytes:
        raise UpdateError("storage_unsafe")
    if os.name == "posix":
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise UpdateError("storage_unsafe")
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _verify_asset(path: Path, asset: UpdateAsset) -> tuple[int, ...]:
    before = _file_stamp(path, asset)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        if _identity(os.fstat(stream.fileno())) != before[:2]:
            raise UpdateError("storage_unsafe")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if before != _file_stamp(path, asset):
        raise UpdateError("storage_unsafe")
    if digest != asset.sha256:
        raise UpdateError("verification_failed")
    return before


def verify_prepared(candidate: UpdateCandidate, directory: Path, limits: UpdateLimits) -> None:
    """Verify already acquired bytes using only the trusted installed policy."""
    _candidate(candidate, limits)
    try:
        initial = private_directory(directory)
        if {path.name for path in directory.iterdir()} != _names(candidate.version) | {policy.STATEMENT_NAME}:
            raise UpdateError("verification_failed")
        _verify_signature(candidate, directory)
        stamps = {asset.name: _verify_asset(directory / asset.name, asset) for asset in candidate.assets}
        policy.validate_bundle(directory, expected_repository=UPDATE_SOURCE_REPOSITORY,
                               expected_tag=candidate.tag,
                               expected_commit=candidate.commit, expected_tree=candidate.tree,
                               accept_newer_schema=True, statement_beside=True)
        for asset in candidate.assets:
            if stamps[asset.name] != _file_stamp(directory / asset.name, asset):
                raise UpdateError("storage_unsafe")
        if _identity(initial) != _identity(private_directory(directory)):
            raise UpdateError("storage_unsafe")
    except _INVALID_BYTES:
        raise UpdateError("verification_failed") from None


class GitHubReleaseSource:
    policy_id = POLICY_ID

    def __init__(self, limits: UpdateLimits):
        self._limits = limits

    def check(self, running_version: str, *, deadline: float) -> UpdateDiscovery:
        require_version(running_version)
        deadline = budget(deadline, self._limits.check_timeout)
        session = _Session(_HTTP(self._limits, deadline))
        result = _discover(session, running_version, self._limits)
        remaining(deadline)
        return result

    def prepare(self, candidate: UpdateCandidate, directory: Path, *, deadline: float) -> None:
        _candidate(candidate, self._limits)
        deadline = budget(deadline, self._limits.prepare_timeout)
        try:
            initial = private_directory(directory, empty=True)
            session = _Session(_HTTP(self._limits, deadline))
            self._unchanged(session, candidate)
            for asset in candidate.assets:
                session.download(asset, directory / asset.name)
            with exclusive_file(directory / policy.STATEMENT_NAME) as statement:
                statement.write(_tag_message(session, candidate.tag_object_sha).encode())
            verify_prepared(candidate, directory, self._limits)
            self._unchanged(session, candidate)
            if _identity(initial) != _identity(private_directory(directory)):
                raise UpdateError("storage_unsafe")
            remaining(deadline)
        except OSError:
            raise UpdateError("storage_unsafe") from None

    def _unchanged(self, session: _Session, candidate: UpdateCandidate) -> None:
        observed = _resolve(session, candidate.release_id, candidate.version, self._limits)
        if observed != candidate:
            raise UpdateError("publication_changed")
