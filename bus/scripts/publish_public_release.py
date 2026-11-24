"""Publish an exact Strugglebus release bundle to the fixed public mirror."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
# Only the selected gh executable runs, with shell-free arguments and bounded I/O.
import subprocess  # nosec B404
import sys
import tempfile
import time
from typing import Any, Callable, Iterator, Protocol
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from promotion_common import PromotionError
from promotion_state import ReceiptStore
from release_bundle import MAX_ASSET_BYTES, REPOSITORY_ID, validate_bundle
from strugglebus.release_records import LocalAsset, _asset_media_type
from strugglebus.release_validation import ReleaseBundleError, SHA1_PATTERN, TAG_PATTERN


OWNER = "NZCypher819"
SOURCE_REPOSITORY = REPOSITORY_ID
PUBLIC_REPOSITORY = "NZCypher819/strugglebus-releases"
API_VERSION = "2022-11-28"
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_PAYLOAD_BYTES = 64 * 1024
MAX_REQUESTS = 200
REQUEST_SECONDS = 30
UPLOAD_SECONDS = 300
OPERATION_SECONDS = 900
MAX_PAGES = 10
PAGE_SIZE = 100
PHASES = frozenset(
    {
        "ready",
        "tag_object_intent",
        "tag_object_ready",
        "tag_ref_intent",
        "tag_ref_ready",
        "release_intent",
        "release_ready",
        "upload_intent",
        "assets_ready",
        "publish_intent",
        "complete",
    }
)


class PublicReleaseError(PromotionError):
    """A non-sensitive operator failure."""


class PublicReleaseAPI(Protocol):
    def owner(self) -> str: ...
    def repository(self, repository: str) -> dict[str, Any]: ...
    def immutable_releases(self, repository: str) -> bool: ...
    def branch_head(self, repository: str, branch: str) -> str: ...
    def commit_tree(self, repository: str, commit: str) -> str: ...
    def tag_ref(self, repository: str, tag: str) -> dict[str, Any] | None: ...
    def tag_object(self, repository: str, sha: str) -> dict[str, Any]: ...
    def optional_tag_object(
        self, repository: str, sha: str
    ) -> dict[str, Any] | None: ...
    def releases(self, repository: str, tag: str) -> list[dict[str, Any]]: ...
    def assets(self, repository: str, release_id: int) -> list[dict[str, Any]]: ...
    def create_tag_object(
        self, repository: str, payload: dict[str, Any]
    ) -> dict[str, Any]: ...
    def create_tag_ref(
        self, repository: str, tag: str, tag_sha: str
    ) -> dict[str, Any]: ...
    def create_release(
        self, repository: str, payload: dict[str, Any]
    ) -> dict[str, Any]: ...
    def upload_asset(
        self, repository: str, release_id: int, asset: LocalAsset
    ) -> dict[str, Any]: ...
    def publish_release(
        self, repository: str, release_id: int
    ) -> dict[str, Any]: ...


def approval_phrase(tag: str, commit: str) -> str:
    return f"publish-public-release-{tag}-{commit}"


def canonical_release_body(commit: str, tree: str) -> str:
    return json.dumps(
        {
            "source_commit": commit,
            "source_repository": SOURCE_REPOSITORY,
            "source_tree": tree,
            "version": 1,
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _integer(value: Any, label: str, maximum: int = 2**53 - 1) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise PublicReleaseError(f"{label} is invalid")
    return value


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PublicReleaseError(f"{label} is invalid")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA1_PATTERN.fullmatch(value) is None:
        raise PublicReleaseError(f"{label} is invalid")
    return value


def _tag(value: Any) -> str:
    if not isinstance(value, str) or TAG_PATTERN.fullmatch(value) is None:
        raise PublicReleaseError("release tag must be v<major>.<minor>.<patch>")
    return value


def _canonical_json(value: dict[str, Any]) -> bytes:
    try:
        payload = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise PublicReleaseError("GitHub mutation payload is invalid") from None
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise PublicReleaseError("GitHub mutation payload exceeds its size limit")
    return payload


def tag_object_sha(payload: dict[str, Any]) -> str:
    tagger = _object(payload.get("tagger"), "tagger")
    try:
        timestamp = int(
            datetime.strptime(
                str(tagger["date"]), "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc).timestamp()
        )
        content = (
            f"object {payload['object']}\ntype commit\ntag {payload['tag']}\n"
            f"tagger {tagger['name']} <{tagger['email']}> {timestamp} +0000\n\n"
            f"{payload['message']}"
        ).encode("ascii")
    except (KeyError, TypeError, ValueError, UnicodeError):
        raise PublicReleaseError("annotated tag payload is invalid") from None
    return hashlib.sha1(
        f"tag {len(content)}\0".encode("ascii") + content,
        usedforsecurity=False,
    ).hexdigest()


def _tag_payload(
    tag: str, anchor: str, body: str, created_at: int
) -> dict[str, Any]:
    return {
        "message": f"Strugglebus public release mirror v1\n{body}\n",
        "object": anchor,
        "tag": tag,
        "tagger": {
            "date": datetime.fromtimestamp(
                created_at, timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "email": f"{OWNER}@users.noreply.github.com",
            "name": OWNER,
        },
        "type": "commit",
    }


def _release_payload(tag: str, anchor: str, body: str) -> dict[str, Any]:
    return {
        "body": body,
        "draft": True,
        "name": tag,
        "prerelease": False,
        "tag_name": tag,
        "target_commitish": anchor,
    }


def _local_assets(
    directory: Path, tag: str, commit: str, tree: str
) -> dict[str, LocalAsset]:
    try:
        facts = validate_bundle(
            directory,
            expected_repository=SOURCE_REPOSITORY,
            expected_tag=tag,
            expected_commit=commit,
            expected_tree=tree,
        )
    except (OSError, ReleaseBundleError) as error:
        raise PublicReleaseError(f"source release bundle is invalid: {error}") from None
    records = facts.get("release_assets")
    if not isinstance(records, list) or len(records) != 5:
        raise PublicReleaseError("source release bundle must contain exactly five assets")
    assets: dict[str, LocalAsset] = {}
    for record in records:
        record = _object(record, "source asset")
        name = record.get("name")
        digest = record.get("sha256")
        size = record.get("size_bytes")
        if (
            not isinstance(name, str)
            or name in assets
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or type(size) is not int
            or not 1 <= size <= MAX_ASSET_BYTES
        ):
            raise PublicReleaseError("source release asset identity is invalid")
        path = directory / name
        metadata = path.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or metadata.st_nlink != 1
        ):
            raise PublicReleaseError("source release assets must be regular unlinked files")
        assets[name] = LocalAsset(
            name=name,
            path=path,
            size=size,
            digest=digest,
            media_type=_asset_media_type(name),
        )
    if len(assets) != 5:
        raise PublicReleaseError("source release bundle must contain exactly five assets")
    return dict(sorted(assets.items()))


def _validate_asset_records(
    records: list[dict[str, Any]],
    expected: dict[str, LocalAsset],
    *,
    complete: bool,
) -> dict[str, dict[str, Any]]:
    if len(records) > len(expected):
        raise PublicReleaseError("release has unexpected assets")
    result: dict[str, dict[str, Any]] = {}
    ids: set[int] = set()
    for value in records:
        record = _object(value, "release asset")
        asset_id = _integer(record.get("id"), "release asset ID")
        name = record.get("name")
        if (
            not isinstance(name, str)
            or name not in expected
            or name in result
            or asset_id in ids
        ):
            raise PublicReleaseError("release has duplicate or unexpected assets")
        asset = expected[name]
        if record.get("state") != "uploaded":
            raise PublicReleaseError(
                f"release asset upload is incomplete; delete the draft asset before resume: {name}"
            )
        digest = record.get("digest")
        if (
            record.get("label") not in {None, ""}
            or record.get("size") != asset.size
            or record.get("content_type") != asset.media_type
            or not isinstance(digest, str)
            or not hmac.compare_digest(digest, f"sha256:{asset.digest}")
        ):
            raise PublicReleaseError(f"release asset identity mismatch: {name}")
        ids.add(asset_id)
        result[name] = record
    if complete and set(result) != set(expected):
        raise PublicReleaseError("release asset set is incomplete")
    return result


def _validate_source(
    api: PublicReleaseAPI,
    tag: str,
    commit: str,
    tree: str,
    assets: dict[str, LocalAsset],
) -> None:
    if api.owner() != OWNER:
        raise PublicReleaseError("selected GitHub CLI authentication is not the owner")
    source = api.repository(SOURCE_REPOSITORY)
    if source.get("full_name") != SOURCE_REPOSITORY:
        raise PublicReleaseError("source repository identity is invalid")
    reference = api.tag_ref(SOURCE_REPOSITORY, tag)
    if reference is None:
        raise PublicReleaseError("source annotated tag does not exist")
    target = _object(reference.get("object"), "source tag reference")
    if target.get("type") != "tag":
        raise PublicReleaseError("source release tag is not annotated")
    tag_sha = _sha(target.get("sha"), "source tag object")
    tag_record = api.tag_object(SOURCE_REPOSITORY, tag_sha)
    tag_target = _object(tag_record.get("object"), "source annotated tag")
    if (
        tag_record.get("tag") != tag
        or tag_target.get("type") != "commit"
        or tag_target.get("sha") != commit
    ):
        raise PublicReleaseError("source annotated tag identity conflicts")
    if api.commit_tree(SOURCE_REPOSITORY, commit) != tree:
        raise PublicReleaseError("source commit tree conflicts")
    releases = api.releases(SOURCE_REPOSITORY, tag)
    if len(releases) != 1:
        raise PublicReleaseError("source release identity is missing or ambiguous")
    release = releases[0]
    release_id = _integer(release.get("id"), "source release ID")
    if (
        release.get("tag_name") != tag
        or release.get("target_commitish") != commit
        or release.get("name") != tag
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or release.get("immutable") is not True
    ):
        raise PublicReleaseError("source release identity conflicts")
    _validate_asset_records(
        api.assets(SOURCE_REPOSITORY, release_id), assets, complete=True
    )


def _validate_public_repository(
    api: PublicReleaseAPI, anchor: str, *, require_current_head: bool
) -> None:
    repository = api.repository(PUBLIC_REPOSITORY)
    branch = repository.get("default_branch")
    if (
        repository.get("full_name") != PUBLIC_REPOSITORY
        or repository.get("private") is not False
        or repository.get("visibility") != "public"
        or not isinstance(branch, str)
        or not branch
    ):
        raise PublicReleaseError("public mirror repository identity is invalid")
    if api.immutable_releases(PUBLIC_REPOSITORY) is not True:
        raise PublicReleaseError("public mirror immutable releases are not enabled")
    if require_current_head and api.branch_head(PUBLIC_REPOSITORY, branch) != anchor:
        raise PublicReleaseError("public mirror anchor is not the exact default-branch head")
    _sha(api.commit_tree(PUBLIC_REPOSITORY, anchor), "public anchor tree")


def _validate_public_tag_object(
    record: dict[str, Any], operation: dict[str, Any]
) -> None:
    payload = operation["tag_payload"]
    target = _object(record.get("object"), "public annotated tag")
    tagger = _object(record.get("tagger"), "public annotated tagger")
    if (
        record.get("sha") != operation["tag_sha"]
        or record.get("tag") != operation["tag"]
        or record.get("message") != payload["message"]
        or target.get("type") != "commit"
        or target.get("sha") != operation["public_anchor_commit"]
        or any(tagger.get(key) != payload["tagger"][key] for key in payload["tagger"])
    ):
        raise PublicReleaseError("public annotated tag conflicts with the receipt")


def _public_release(
    api: PublicReleaseAPI, operation: dict[str, Any]
) -> dict[str, Any] | None:
    releases = api.releases(PUBLIC_REPOSITORY, operation["tag"])
    if len(releases) > 1:
        raise PublicReleaseError("multiple public releases use the stable tag")
    if not releases:
        return None
    release = releases[0]
    release_id = _integer(release.get("id"), "public release ID")
    if (
        release.get("tag_name") != operation["tag"]
        or release.get("target_commitish") != operation["public_anchor_commit"]
        or release.get("name") != operation["tag"]
        or release.get("body") != operation["release_body"]
        or release.get("prerelease") is not False
        or not isinstance(release.get("draft"), bool)
        or not isinstance(release.get("immutable"), bool)
        or (release["draft"], release["immutable"])
        not in {(True, False), (False, True)}
    ):
        raise PublicReleaseError("public release conflicts with the receipt")
    recorded = operation.get("release_id")
    if recorded is not None and recorded != release_id:
        raise PublicReleaseError("public release ID conflicts with the receipt")
    return release


def _public_tag_ref(
    api: PublicReleaseAPI, operation: dict[str, Any]
) -> dict[str, Any] | None:
    reference = api.tag_ref(PUBLIC_REPOSITORY, operation["tag"])
    if reference is None:
        return None
    target = _object(reference.get("object"), "public tag reference")
    if (
        target.get("type") != "tag"
        or target.get("sha") != operation["tag_sha"]
    ):
        raise PublicReleaseError("public stable tag conflicts with the receipt")
    _validate_public_tag_object(
        api.tag_object(PUBLIC_REPOSITORY, operation["tag_sha"]), operation
    )
    return reference


def _new_operation(
    *,
    tag: str,
    commit: str,
    tree: str,
    anchor: str,
    approval: str,
    assets: dict[str, LocalAsset],
    created_at: int,
) -> dict[str, Any]:
    body = canonical_release_body(commit, tree)
    payload = _tag_payload(tag, anchor, body, created_at)
    return {
        "approval": approval,
        "assets": [
            {
                "media_type": asset.media_type,
                "name": asset.name,
                "sha256": asset.digest,
                "size_bytes": asset.size,
            }
            for asset in assets.values()
        ],
        "created_at": created_at,
        "phase": "ready",
        "public_anchor_commit": anchor,
        "public_repository": PUBLIC_REPOSITORY,
        "receipt_version": 1,
        "release_body": body,
        "release_id": None,
        "source_commit": commit,
        "source_repository": SOURCE_REPOSITORY,
        "source_tree": tree,
        "tag": tag,
        "tag_payload": payload,
        "tag_sha": tag_object_sha(payload),
        "uploading": None,
    }


def _validate_operation(
    value: Any,
    *,
    tag: str,
    commit: str,
    tree: str,
    anchor: str,
    approval: str,
    assets: dict[str, LocalAsset],
) -> dict[str, Any]:
    operation = _object(value, "public release receipt")
    expected_keys = {
        "approval",
        "assets",
        "created_at",
        "phase",
        "public_anchor_commit",
        "public_repository",
        "receipt_version",
        "release_body",
        "release_id",
        "source_commit",
        "source_repository",
        "source_tree",
        "tag",
        "tag_payload",
        "tag_sha",
        "uploading",
    }
    if set(operation) != expected_keys:
        raise PublicReleaseError("public release receipt shape is invalid")
    expected_assets = [
        {
            "media_type": asset.media_type,
            "name": asset.name,
            "sha256": asset.digest,
            "size_bytes": asset.size,
        }
        for asset in assets.values()
    ]
    if (
        operation["receipt_version"] != 1
        or operation["source_repository"] != SOURCE_REPOSITORY
        or operation["public_repository"] != PUBLIC_REPOSITORY
        or operation["tag"] != tag
        or operation["source_commit"] != commit
        or operation["source_tree"] != tree
        or operation["public_anchor_commit"] != anchor
        or operation["approval"] != approval
        or operation["release_body"] != canonical_release_body(commit, tree)
        or operation["assets"] != expected_assets
        or operation["phase"] not in PHASES
        or type(operation["created_at"]) is not int
        or not 0 < operation["created_at"] <= 4_102_444_799
        or operation["tag_payload"]
        != _tag_payload(tag, anchor, operation["release_body"], operation["created_at"])
        or operation["tag_sha"] != tag_object_sha(operation["tag_payload"])
        or (
            operation["release_id"] is not None
            and (
                type(operation["release_id"]) is not int
                or operation["release_id"] <= 0
            )
        )
        or (
            operation["uploading"] is not None
            and operation["uploading"] not in assets
        )
        or (
            operation["phase"] == "upload_intent"
            and operation["uploading"] is None
        )
        or (
            operation["phase"] != "upload_intent"
            and operation["uploading"] is not None
        )
    ):
        raise PublicReleaseError("public release receipt identity is invalid")
    return operation


def _save(
    store: Any,
    operation: dict[str, Any],
    phase: str,
    *,
    release_id: int | None = None,
    uploading: str | None = None,
) -> None:
    operation["phase"] = phase
    operation["uploading"] = uploading
    if release_id is not None:
        operation["release_id"] = release_id
    store.write(operation)


def _result(operation: dict[str, Any]) -> dict[str, Any]:
    return {
        "assets": [asset["name"] for asset in operation["assets"]],
        "deployment_performed": False,
        "phase": "complete",
        "public_anchor_commit": operation["public_anchor_commit"],
        "release_body": operation["release_body"],
        "release_id": operation["release_id"],
        "release_url": (
            f"https://github.com/{PUBLIC_REPOSITORY}/releases/tag/{operation['tag']}"
        ),
        "source_commit": operation["source_commit"],
        "source_repository": SOURCE_REPOSITORY,
        "source_tree": operation["source_tree"],
        "tag": operation["tag"],
    }


def publish_public_release(
    api: PublicReleaseAPI,
    store: Any,
    directory: Path,
    *,
    tag: str,
    commit: str,
    tree: str,
    public_anchor_commit: str,
    approval: str,
    resume: bool,
    now: Callable[[], float] = time.time,
) -> dict[str, Any]:
    tag = _tag(tag)
    commit = _sha(commit, "source commit")
    tree = _sha(tree, "source tree")
    anchor = _sha(public_anchor_commit, "public anchor commit")
    expected_approval = approval_phrase(tag, commit)
    if approval != expected_approval:
        raise PublicReleaseError(
            f"approval must exactly equal {expected_approval!r}", code=3
        )
    directory = directory.resolve(strict=True)
    assets = _local_assets(directory, tag, commit, tree)

    with store.locked():
        if resume:
            operation = _validate_operation(
                store.read(),
                tag=tag,
                commit=commit,
                tree=tree,
                anchor=anchor,
                approval=approval,
                assets=assets,
            )
        else:
            _validate_source(api, tag, commit, tree, assets)
            _validate_public_repository(api, anchor, require_current_head=True)
            created_at = int(now())
            operation = _new_operation(
                tag=tag,
                commit=commit,
                tree=tree,
                anchor=anchor,
                approval=approval,
                assets=assets,
                created_at=created_at,
            )
            if (
                api.optional_tag_object(
                    PUBLIC_REPOSITORY, operation["tag_sha"]
                )
                is not None
            ):
                raise PublicReleaseError("public annotated tag object already exists")
            if _public_tag_ref(api, operation) is not None:
                raise PublicReleaseError("public stable tag already exists")
            if _public_release(api, operation) is not None:
                raise PublicReleaseError("public release already exists")
            store.write(operation, create=True)

        _validate_source(api, tag, commit, tree, assets)
        _validate_public_repository(
            api, anchor, require_current_head=not resume
        )

        reference = _public_tag_ref(api, operation)
        release = _public_release(api, operation)
        if reference is None and release is not None:
            raise PublicReleaseError("public release exists without the recorded tag")

        if reference is None:
            _save(store, operation, "tag_object_intent")
            record = api.optional_tag_object(
                PUBLIC_REPOSITORY, operation["tag_sha"]
            )
            if record is None:
                record = api.create_tag_object(
                    PUBLIC_REPOSITORY, operation["tag_payload"]
                )
            _validate_public_tag_object(record, operation)
            _save(store, operation, "tag_object_ready")
            _save(store, operation, "tag_ref_intent")
            api.create_tag_ref(
                PUBLIC_REPOSITORY, operation["tag"], operation["tag_sha"]
            )
            reference = _public_tag_ref(api, operation)
            if reference is None:
                raise PublicReleaseError("public annotated tag creation was not observed")
            _save(store, operation, "tag_ref_ready")

        if release is None:
            _save(store, operation, "release_intent")
            api.create_release(
                PUBLIC_REPOSITORY,
                _release_payload(
                    operation["tag"],
                    operation["public_anchor_commit"],
                    operation["release_body"],
                ),
            )
            release = _public_release(api, operation)
            if release is None:
                raise PublicReleaseError("public draft release creation was not observed")
            _save(
                store,
                operation,
                "release_ready",
                release_id=_integer(release.get("id"), "public release ID"),
            )
        else:
            operation["release_id"] = _integer(
                release.get("id"), "public release ID"
            )

        release_id = operation["release_id"]
        if type(release_id) is not int:
            raise PublicReleaseError("public release ID is missing")
        remote_assets = _validate_asset_records(
            api.assets(PUBLIC_REPOSITORY, release_id),
            assets,
            complete=False,
        )
        for name, asset in assets.items():
            if name in remote_assets:
                continue
            _save(
                store,
                operation,
                "upload_intent",
                release_id=release_id,
                uploading=name,
            )
            api.upload_asset(PUBLIC_REPOSITORY, release_id, asset)
            remote_assets = _validate_asset_records(
                api.assets(PUBLIC_REPOSITORY, release_id),
                assets,
                complete=False,
            )
            if name not in remote_assets:
                raise PublicReleaseError(f"uploaded asset was not observed: {name}")
        _validate_asset_records(
            api.assets(PUBLIC_REPOSITORY, release_id),
            assets,
            complete=True,
        )
        _save(store, operation, "assets_ready", release_id=release_id)

        release = _public_release(api, operation)
        if release is None:
            raise PublicReleaseError("public release disappeared during publication")
        if release["draft"] is True:
            _save(store, operation, "publish_intent", release_id=release_id)
            api.publish_release(PUBLIC_REPOSITORY, release_id)
            release = _public_release(api, operation)
            if release is None:
                raise PublicReleaseError("published release was not observed")
        if release["draft"] is not False or release["immutable"] is not True:
            raise PublicReleaseError("public release is not immutable after publication")
        _validate_asset_records(
            api.assets(PUBLIC_REPOSITORY, release_id),
            assets,
            complete=True,
        )
        _save(store, operation, "complete", release_id=release_id)
        return _result(operation)


def _require_linux() -> None:
    if os.name != "posix" or sys.platform != "linux":
        raise PublicReleaseError("public release publication requires Linux or WSL", code=3)


@contextmanager
def _operation_deadline(seconds: int = OPERATION_SECONDS) -> Iterator[None]:
    _require_linux()
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_delay, previous_interval = signal.getitimer(signal.ITIMER_REAL)
    started = time.monotonic()

    def expired(signum: int, frame: Any) -> None:
        raise PublicReleaseError(
            "publication wall-clock deadline exceeded; resume with the same receipt",
            code=5,
        )

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(
        signal.ITIMER_REAL,
        min(float(seconds), previous_delay) if previous_delay else float(seconds),
    )
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_delay:
            remaining = max(
                previous_delay - (time.monotonic() - started),
                0.000001,
            )
            signal.setitimer(signal.ITIMER_REAL, remaining, previous_interval)


def _selected_gh(executable: str) -> str:
    if (
        not executable
        or any(ord(character) < 32 or ord(character) == 127 for character in executable)
    ):
        raise PublicReleaseError("selected GitHub CLI executable is invalid", code=3)
    selected = shutil.which("gh") if executable == "gh" else executable
    if selected is None or not Path(selected).is_absolute():
        raise PublicReleaseError(
            "select GitHub CLI by trusted absolute path or resolvable 'gh'", code=3
        )
    path = Path(selected).resolve(strict=True)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
        raise PublicReleaseError("selected GitHub CLI executable is not executable", code=3)
    return os.fspath(path)


def _gh_input_path(executable: str, path: Path) -> str:
    value = os.fspath(path)
    if sys.platform == "linux" and executable.casefold().endswith(".exe"):
        match = re.fullmatch(r"/mnt/([A-Za-z])/(.+)", value)
        if match is None:
            raise PublicReleaseError(
                "Windows GitHub CLI inputs must be on a /mnt/<drive> filesystem",
                code=3,
            )
        tail = match.group(2).replace("/", "\\")
        return f"{match.group(1).upper()}:\\{tail}"
    return value


def _gh_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for name in (
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
    ):
        environment.pop(name, None)
    fixed = {
        "BROWSER": "",
        "DEBUG": "",
        "GH_BROWSER": "",
        "GH_DEBUG": "",
        "GH_FORCE_TTY": "",
        "GH_HOST": "github.com",
        "GH_HTTP_UNIX_SOCKET": "",
        "GH_PAGER": "",
        "GH_PROMPT_DISABLED": "1",
        "GIT_ASKPASS": "",
        "GIT_TERMINAL_PROMPT": "0",
        "NO_COLOR": "1",
        "PAGER": "",
        "SSH_ASKPASS": "",
    }
    environment.update(fixed)
    environment["WSLENV"] = ":".join(sorted(fixed))
    return environment


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            process.kill()
    process.wait(timeout=1)


def _run_gh(
    executable: str,
    arguments: list[str],
    *,
    maximum: int,
    seconds: int,
    mutation: bool,
    allow_not_found: bool = False,
) -> bytes | None:
    process: subprocess.Popen[bytes] | None = None
    captured = bytearray()
    errors = bytearray()
    started = time.monotonic()
    try:
        process = subprocess.Popen(  # nosec B603
            [executable, *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_gh_environment(),
            shell=False,
        )
        if process.stdout is None or process.stderr is None:
            raise PublicReleaseError("GitHub CLI capture pipes are unavailable")
        with selectors.DefaultSelector() as selector:
            counts = {"stdout": 0, "stderr": 0}
            for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                if time.monotonic() - started > seconds:
                    raise PublicReleaseError(
                        "GitHub CLI mutation outcome is unknown; resume with the same receipt"
                        if mutation
                        else "GitHub CLI request timed out"
                    )
                for key, _ in selector.select(timeout=0.1):
                    name = key.data
                    bound = maximum if name == "stdout" else MAX_STDERR_BYTES
                    chunk = os.read(key.fd, min(64 * 1024, bound - counts[name] + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    counts[name] += len(chunk)
                    if counts[name] > bound:
                        raise PublicReleaseError("GitHub CLI output exceeded its limit")
                    if name == "stdout":
                        captured.extend(chunk)
                    else:
                        errors.extend(chunk)
            if process.wait(timeout=1) != 0:
                if allow_not_found and re.search(
                    rb"(?:HTTP|status(?: code)?)\s*404\b", errors, re.IGNORECASE
                ):
                    return None
                raise PublicReleaseError(
                    "GitHub CLI mutation outcome is unknown; resume with the same receipt"
                    if mutation
                    else "GitHub CLI request failed"
                )
        return bytes(captured)
    except (OSError, subprocess.SubprocessError):
        raise PublicReleaseError(
            "GitHub CLI mutation outcome is unknown; resume with the same receipt"
            if mutation
            else "GitHub CLI execution failed"
        ) from None
    finally:
        if process is not None:
            try:
                _stop_process(process)
            finally:
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()


@contextmanager
def _payload_file(
    payload: dict[str, Any], directory: Path | None = None
) -> Iterator[Path]:
    content = _canonical_json(payload)
    descriptor, name = tempfile.mkstemp(
        prefix="strugglebus-public-release-",
        suffix=".json",
        dir=directory,
    )
    path = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        yield path
    finally:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


class GitHubCLI:
    def __init__(
        self,
        executable: str,
        *,
        request_limit: int = MAX_REQUESTS,
        input_directory: Path | None = None,
    ) -> None:
        self.executable = _selected_gh(executable)
        if type(request_limit) is not int or not 1 <= request_limit <= MAX_REQUESTS:
            raise PublicReleaseError("GitHub request limit is invalid")
        self.input_directory = (
            None if input_directory is None else input_directory.resolve(strict=True)
        )
        self.remaining = request_limit

    def __repr__(self) -> str:
        return f"{type(self).__name__}(executable={self.executable!r})"

    def _consume(self) -> None:
        if self.remaining <= 0:
            raise PublicReleaseError("GitHub request budget exhausted")
        self.remaining -= 1

    def _api(
        self,
        endpoint: str,
        *,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
        input_path: Path | None = None,
        content_type: str | None = None,
        seconds: int = REQUEST_SECONDS,
        mutation: bool = False,
        allow_not_found: bool = False,
    ) -> Any:
        self._consume()
        arguments = [
            "api",
            "--hostname",
            "github.com",
            "--method",
            method,
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            f"X-GitHub-Api-Version: {API_VERSION}",
        ]
        if content_type is not None:
            arguments.extend(["-H", f"Content-Type: {content_type}"])
        if payload is not None and input_path is not None:
            raise PublicReleaseError("GitHub request input is ambiguous")
        if payload is not None:
            with _payload_file(payload, self.input_directory) as path:
                arguments.extend(
                    ["--input", _gh_input_path(self.executable, path), endpoint]
                )
                content = _run_gh(
                    self.executable,
                    arguments,
                    maximum=MAX_JSON_BYTES,
                    seconds=seconds,
                    mutation=mutation,
                    allow_not_found=allow_not_found,
                )
        else:
            if input_path is not None:
                arguments.extend(
                    ["--input", _gh_input_path(self.executable, input_path)]
                )
            arguments.append(endpoint)
            content = _run_gh(
                self.executable,
                arguments,
                maximum=MAX_JSON_BYTES,
                seconds=seconds,
                mutation=mutation,
                allow_not_found=allow_not_found,
            )
        if content is None:
            return None
        try:
            value = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise PublicReleaseError("GitHub CLI returned invalid JSON") from None
        if not isinstance(value, (dict, list)):
            raise PublicReleaseError("GitHub CLI returned an invalid JSON value")
        return value

    def _get_object(self, endpoint: str) -> dict[str, Any]:
        return _object(self._api(endpoint), "GitHub response")

    def _pages(self, endpoint: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for page in range(1, MAX_PAGES + 1):
            separator = "&" if "?" in endpoint else "?"
            value = self._api(
                f"{endpoint}{separator}per_page={PAGE_SIZE}&page={page}"
            )
            if not isinstance(value, list) or len(value) > PAGE_SIZE:
                raise PublicReleaseError("GitHub listing is invalid")
            records.extend(_object(item, "GitHub listing record") for item in value)
            if len(value) < PAGE_SIZE:
                return records
        raise PublicReleaseError("GitHub listing exceeds its complete bound")

    def owner(self) -> str:
        value = self._get_object("user").get("login")
        return value if isinstance(value, str) else ""

    def repository(self, repository: str) -> dict[str, Any]:
        return self._get_object(f"repos/{repository}")

    def immutable_releases(self, repository: str) -> bool:
        return self._get_object(f"repos/{repository}/immutable-releases").get(
            "enabled"
        ) is True

    def branch_head(self, repository: str, branch: str) -> str:
        encoded = urllib.parse.quote(branch, safe="")
        commit = _object(
            self._get_object(f"repos/{repository}/branches/{encoded}").get("commit"),
            "branch commit",
        )
        return _sha(commit.get("sha"), "branch commit")

    def commit_tree(self, repository: str, commit: str) -> str:
        tree = _object(
            self._get_object(f"repos/{repository}/git/commits/{commit}").get("tree"),
            "commit tree",
        )
        return _sha(tree.get("sha"), "commit tree")

    def tag_ref(self, repository: str, tag: str) -> dict[str, Any] | None:
        encoded = urllib.parse.quote(tag, safe="")
        value = self._api(f"repos/{repository}/git/matching-refs/tags/{encoded}")
        if not isinstance(value, list) or len(value) > PAGE_SIZE:
            raise PublicReleaseError("tag reference listing is invalid")
        matches = [
            _object(record, "tag reference")
            for record in value
            if isinstance(record, dict) and record.get("ref") == f"refs/tags/{tag}"
        ]
        if len(matches) > 1:
            raise PublicReleaseError("multiple exact tag references were returned")
        return matches[0] if matches else None

    def tag_object(self, repository: str, sha: str) -> dict[str, Any]:
        return self._get_object(f"repos/{repository}/git/tags/{sha}")

    def optional_tag_object(
        self, repository: str, sha: str
    ) -> dict[str, Any] | None:
        value = self._api(
            f"repos/{repository}/git/tags/{sha}", allow_not_found=True
        )
        return None if value is None else _object(value, "annotated tag object")

    def releases(self, repository: str, tag: str) -> list[dict[str, Any]]:
        return [
            release
            for release in self._pages(f"repos/{repository}/releases")
            if release.get("tag_name") == tag
        ]

    def assets(self, repository: str, release_id: int) -> list[dict[str, Any]]:
        return self._pages(f"repos/{repository}/releases/{release_id}/assets")

    def create_tag_object(
        self, repository: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        return _object(
            self._api(
                f"repos/{repository}/git/tags",
                method="POST",
                payload=payload,
                mutation=True,
            ),
            "created tag object",
        )

    def create_tag_ref(
        self, repository: str, tag: str, tag_sha: str
    ) -> dict[str, Any]:
        return _object(
            self._api(
                f"repos/{repository}/git/refs",
                method="POST",
                payload={"ref": f"refs/tags/{tag}", "sha": tag_sha},
                mutation=True,
            ),
            "created tag reference",
        )

    def create_release(
        self, repository: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        return _object(
            self._api(
                f"repos/{repository}/releases",
                method="POST",
                payload=payload,
                mutation=True,
            ),
            "created release",
        )

    def upload_asset(
        self, repository: str, release_id: int, asset: LocalAsset
    ) -> dict[str, Any]:
        name = urllib.parse.quote(asset.name, safe="")
        endpoint = (
            f"https://uploads.github.com/repos/{repository}/releases/"
            f"{release_id}/assets?name={name}"
        )
        return _object(
            self._api(
                endpoint,
                method="POST",
                input_path=asset.path,
                content_type=asset.media_type,
                seconds=UPLOAD_SECONDS,
                mutation=True,
            ),
            "uploaded release asset",
        )

    def publish_release(
        self, repository: str, release_id: int
    ) -> dict[str, Any]:
        return _object(
            self._api(
                f"repos/{repository}/releases/{release_id}",
                method="PATCH",
                payload={"draft": False},
                mutation=True,
            ),
            "published release",
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--public-anchor-commit", required=True)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--gh", required=True)
    parser.add_argument("--resume", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        _require_linux()
        args = _parser().parse_args(argv)
        with _operation_deadline():
            api = GitHubCLI(args.gh, input_directory=args.directory)
            result = publish_public_release(
                api,
                ReceiptStore(args.receipt),
                args.directory,
                tag=args.tag,
                commit=args.source_commit,
                tree=args.source_tree,
                public_anchor_commit=args.public_anchor_commit,
                approval=args.approval,
                resume=args.resume,
            )
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
        return 0
    except PublicReleaseError as error:
        print(f"error: {error}", file=sys.stderr)
        return error.code
    except (KeyboardInterrupt, OSError, ValueError):
        print(
            "error: publication stopped; reconcile with --resume and the same receipt",
            file=sys.stderr,
        )
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
