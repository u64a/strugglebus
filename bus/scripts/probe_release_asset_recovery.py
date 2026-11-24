"""Prove read-only recovery of the permanently partial v0.2.3 release asset."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, Protocol

from publish_immutable_release import (
    GITHUB_API_URL,
    GitHubReleaseAPI,
    ReleasePublicationError,
)


REPOSITORY = "NZCypher819/strugglebus"
OWNER = "NZCypher819"
DEFAULT_BRANCH = "main"
WORKFLOW_EVENT = "workflow_dispatch"
WORKFLOW_REF = "refs/heads/main"
PARTIAL_TAG = "v0.2.3"
PARTIAL_TAG_OBJECT = "139c4582880dedcd2926f9a7ba4b021e315e2d32"
PARTIAL_TAG_COMMIT = "cc3bcbe89d8c4408145fe87152d596d5de05142f"
PARTIAL_RELEASE_ID = 380577897
PARTIAL_ASSET_ID = 539668626
PARTIAL_ASSET_NAME = "SHA256SUMS"
PARTIAL_ASSET_SIZE = 398
PARTIAL_ASSET_MEDIA_TYPE = "text/plain"
PARTIAL_ASSET_SHA256 = (
    "549b4f80030d227062d948455f7fe758ddbd8344d399d2f693563e942f7a92de"
)
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")

EXPECTED_RELEASE = {
    "id": PARTIAL_RELEASE_ID,
    "tag_name": PARTIAL_TAG,
    "target_commitish": PARTIAL_TAG_COMMIT,
    "name": PARTIAL_TAG,
    "body": f"Canonical immutable Strugglebus release {PARTIAL_TAG}.",
    "draft": True,
    "prerelease": False,
    "immutable": False,
}
EXPECTED_ASSET = {
    "id": PARTIAL_ASSET_ID,
    "name": PARTIAL_ASSET_NAME,
    "label": "",
    "state": "uploaded",
    "size": PARTIAL_ASSET_SIZE,
    "content_type": PARTIAL_ASSET_MEDIA_TYPE,
    "digest": f"sha256:{PARTIAL_ASSET_SHA256}",
}


class RecoveryProofError(RuntimeError):
    """The hard-coded read-only recovery proof observed unexpected state."""


class RecoveryAPI(Protocol):
    def get(self, path: str) -> Any: ...

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


@dataclass(frozen=True)
class WorkflowIdentity:
    event_sha: str
    workflow_sha: str


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or not value.isascii()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise RecoveryProofError("recovery proof workflow identity is unavailable")
    return value


def workflow_identity_from_environment() -> WorkflowIdentity:
    if _required_environment("RECOVERY_REPOSITORY") != REPOSITORY:
        raise RecoveryProofError("recovery proof repository identity mismatch")
    if _required_environment("RECOVERY_ACTOR") != OWNER:
        raise RecoveryProofError("recovery proof actor identity mismatch")
    if _required_environment("RECOVERY_EVENT_NAME") != WORKFLOW_EVENT:
        raise RecoveryProofError("recovery proof event identity mismatch")
    if _required_environment("RECOVERY_REF") != WORKFLOW_REF:
        raise RecoveryProofError("recovery proof ref identity mismatch")
    event_sha = _required_environment("RECOVERY_EVENT_SHA")
    workflow_sha = _required_environment("RECOVERY_WORKFLOW_SHA")
    if (
        SHA_PATTERN.fullmatch(event_sha) is None
        or SHA_PATTERN.fullmatch(workflow_sha) is None
        or event_sha != workflow_sha
    ):
        raise RecoveryProofError("recovery proof workflow SHA identity mismatch")
    return WorkflowIdentity(event_sha=event_sha, workflow_sha=workflow_sha)


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RecoveryProofError(f"{label} response is invalid")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise RecoveryProofError(f"{label} response is invalid")
    return value


def _require_fields(
    value: dict[str, Any],
    expected: dict[str, Any],
    label: str,
) -> None:
    if any(value.get(key) != expected_value for key, expected_value in expected.items()):
        raise RecoveryProofError(f"{label} identity mismatch")


def _validate_asset(value: Any, label: str) -> dict[str, Any]:
    asset = _object(value, label)
    _require_fields(asset, EXPECTED_ASSET, label)
    return {key: asset[key] for key in EXPECTED_ASSET}


def _read_exact_state(
    api: RecoveryAPI,
    identity: WorkflowIdentity,
) -> dict[str, Any]:
    immutable = _object(
        api.get(f"repos/{REPOSITORY}/immutable-releases"),
        "immutable release setting",
    )
    if immutable.get("enabled") is not True:
        raise RecoveryProofError("immutable releases are not enabled")

    repository = _object(api.get(f"repos/{REPOSITORY}"), "repository")
    if repository.get("default_branch") != DEFAULT_BRANCH:
        raise RecoveryProofError("repository default branch identity mismatch")

    branch = _object(
        api.get(f"repos/{REPOSITORY}/branches/{DEFAULT_BRANCH}"),
        "default branch",
    )
    branch_commit = _object(branch.get("commit"), "default branch commit")
    if branch_commit.get("sha") != identity.event_sha:
        raise RecoveryProofError("workflow does not run on exact current main")

    tag_ref = _object(
        api.get(f"repos/{REPOSITORY}/git/ref/tags/{PARTIAL_TAG}"),
        "partial release tag ref",
    )
    tag_ref_object = _object(tag_ref.get("object"), "partial release tag ref object")
    if tag_ref_object.get("type") != "tag" or tag_ref_object.get(
        "sha"
    ) != PARTIAL_TAG_OBJECT:
        raise RecoveryProofError("partial release tag ref identity mismatch")

    tag = _object(
        api.get(f"repos/{REPOSITORY}/git/tags/{PARTIAL_TAG_OBJECT}"),
        "partial release annotated tag",
    )
    target = _object(tag.get("object"), "partial release tag target")
    if (
        tag.get("sha") != PARTIAL_TAG_OBJECT
        or tag.get("tag") != PARTIAL_TAG
        or target.get("type") != "commit"
        or target.get("sha") != PARTIAL_TAG_COMMIT
    ):
        raise RecoveryProofError("partial release annotated tag identity mismatch")

    release = _object(
        api.get(f"repos/{REPOSITORY}/releases/{PARTIAL_RELEASE_ID}"),
        "partial draft release",
    )
    _require_fields(release, EXPECTED_RELEASE, "partial draft release")
    embedded_assets = _array(release.get("assets"), "partial draft release assets")
    if len(embedded_assets) != 1:
        raise RecoveryProofError("partial draft release asset set mismatch")
    embedded_asset = _validate_asset(
        embedded_assets[0],
        "partial draft embedded asset",
    )

    listed_assets = _array(
        api.get(
            f"repos/{REPOSITORY}/releases/{PARTIAL_RELEASE_ID}/assets?per_page=100"
        ),
        "partial draft listed assets",
    )
    if len(listed_assets) != 1:
        raise RecoveryProofError("partial draft listed asset set mismatch")
    listed_asset = _validate_asset(
        listed_assets[0],
        "partial draft listed asset",
    )
    direct_asset = _validate_asset(
        api.get(f"repos/{REPOSITORY}/releases/assets/{PARTIAL_ASSET_ID}"),
        "partial draft direct asset",
    )
    if embedded_asset != listed_asset or listed_asset != direct_asset:
        raise RecoveryProofError("partial draft asset views disagree")

    return {
        "asset": direct_asset,
        "main": identity.event_sha,
        "release": {key: release[key] for key in EXPECTED_RELEASE},
        "tag_object": PARTIAL_TAG_OBJECT,
    }


def _validate_download(path: Path) -> None:
    try:
        if (
            not path.is_file()
            or path.is_symlink()
            or path.stat().st_size != PARTIAL_ASSET_SIZE
        ):
            raise RecoveryProofError("downloaded recovery asset size mismatch")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        raise RecoveryProofError("downloaded recovery asset is unreadable") from None
    if not hmac.compare_digest(digest.hexdigest(), PARTIAL_ASSET_SHA256):
        raise RecoveryProofError("downloaded recovery asset digest mismatch")


def run_recovery_proof(
    api: RecoveryAPI,
    identity: WorkflowIdentity,
) -> dict[str, Any]:
    before = _read_exact_state(api, identity)
    try:
        with tempfile.TemporaryDirectory(
            prefix="strugglebus-release-asset-recovery-proof-"
        ) as temporary:
            destination = Path(temporary) / PARTIAL_ASSET_NAME
            api.download_asset(
                REPOSITORY,
                PARTIAL_ASSET_ID,
                destination,
                expected_name=PARTIAL_ASSET_NAME,
                expected_size=PARTIAL_ASSET_SIZE,
                expected_media_type=PARTIAL_ASSET_MEDIA_TYPE,
                expected_sha256=PARTIAL_ASSET_SHA256,
            )
            _validate_download(destination)
    except OSError:
        raise RecoveryProofError("recovery proof workspace failed") from None
    after = _read_exact_state(api, identity)
    if before != after:
        raise RecoveryProofError("partial release state changed during recovery proof")
    return {
        "asset_id": PARTIAL_ASSET_ID,
        "release_id": PARTIAL_RELEASE_ID,
        "status": "verified-read-only",
        "tag": PARTIAL_TAG,
    }


def main() -> int:
    try:
        identity = workflow_identity_from_environment()
        token = _required_environment("RECOVERY_PROBE_TOKEN")
        result = run_recovery_proof(
            GitHubReleaseAPI(GITHUB_API_URL, token),
            identity,
        )
    except (RecoveryProofError, ReleasePublicationError) as error:
        print(f"release asset recovery proof failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
