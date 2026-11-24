"""Shared strict immutable release and asset identity validation."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import hmac
from .release_transport import ReleasePublicationError
from .release_validation import CHECKSUMS_NAME, MANIFEST_NAME

@dataclass(frozen=True)
class LocalAsset:
    name: str
    path: Path
    size: int
    digest: str
    media_type: str


def _positive_id(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ReleasePublicationError(f"{label} is invalid")
    return value


def _asset_media_type(name: str) -> str:
    if name.endswith(".whl"):
        return "application/vnd.python.wheel"
    if name.endswith(".tar.gz"):
        return "application/gzip"
    if name == MANIFEST_NAME:
        return "application/json"
    if name in {CHECKSUMS_NAME, "requirements.lock"}:
        return "text/plain"
    raise ReleasePublicationError(f"local release asset has no media type: {name}")


def _release_body(tag: str) -> str:
    return f"Canonical immutable Strugglebus release {tag}."


def _validate_release_record(
    release: dict[str, Any],
    *,
    tag: str,
    commit: str,
) -> tuple[int, str]:
    release_id = _positive_id(release.get("id"), "release ID")
    expected = {"tag_name": tag, "target_commitish": commit, "name": tag, "body": _release_body(tag)}
    if any(release.get(key) != value for key, value in expected.items()):
        raise ReleasePublicationError("release metadata conflicts with the candidate")
    _release_flags(release)
    if release["draft"] is True and release["immutable"] is False:
        return release_id, "draft"
    if release["draft"] is False and release["immutable"] is True:
        return release_id, "immutable"
    if release["draft"] is False and release["immutable"] is False:
        raise ReleasePublicationError("existing published release is mutable")
    raise ReleasePublicationError("release has an invalid draft/immutable state")


def _release_flags(release: dict[str, Any]) -> None:
    if (release.get("prerelease") is not False
            or not isinstance(release.get("draft"), bool)
            or not isinstance(release.get("immutable"), bool)):
        raise ReleasePublicationError("release metadata conflicts with the candidate")


def _validate_asset_records(
    records: list[dict[str, Any]],
    local_assets: dict[str, LocalAsset],
    *,
    complete: bool,
) -> dict[str, dict[str, Any]]:
    if len(records) > len(local_assets):
        raise ReleasePublicationError("release has unexpected assets")
    by_name: dict[str, dict[str, Any]] = {}
    seen_ids: set[int] = set()
    for record in records:
        asset_id = _positive_id(record.get("id"), "asset ID")
        name = record.get("name")
        if (
            not isinstance(name, str)
            or name in by_name
            or asset_id in seen_ids
            or name not in local_assets
        ):
            raise ReleasePublicationError(
                "release has a duplicate or unexpected asset"
            )
        _validate_asset_identity(record, local_assets[name])
        seen_ids.add(asset_id)
        by_name[name] = record
    if complete and set(by_name) != set(local_assets):
        raise ReleasePublicationError("release asset set is incomplete")
    return by_name


def _validate_asset_identity(record: dict[str, Any], expected: LocalAsset) -> None:
    digest = record.get("digest")
    label = record.get("label")
    if (
        record.get("state") != "uploaded"
        or (label is not None and label != "")
        or record.get("size") != expected.size
        or record.get("content_type") != expected.media_type
        or not isinstance(digest, str)
        or not hmac.compare_digest(digest, f"sha256:{expected.digest}")
    ):
        raise ReleasePublicationError(f"release asset identity mismatch: {expected.name}")
