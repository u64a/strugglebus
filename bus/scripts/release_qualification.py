"""Qualify one exact release asset set and bind it to an approved tag intent.

Qualification runs before any tag exists. It builds and validates the five
canonical release assets exactly once on the trusted default branch and uploads
them, together with a machine-readable canonical receipt, as exactly ONE
immutable Actions artifact. Publication never rebuilds anything: it resolves the
exact owner- and tag-bound qualification run through read-only GitHub API calls,
re-verifies every binding, and only then publishes the qualified bytes.

Technical boundary of the binding, stated precisely:

* An Actions artifact's live API ID, digest, and size only exist after the
  upload has completed, so an artifact can never contain its own digest. The
  receipt therefore does not, and cannot, carry those post-upload values.
* The canonical receipt is written before the upload and is part of the uploaded
  bytes. It binds every pre-upload value: repository, tag intent, package
  version, commit, tree, qualification run ID and attempt, workflow identity,
  the exact expected artifact name, the owner approval, the build tool
  identities, an expiry, and the exact five asset names, sizes, and SHA-256
  digests.
* Publication binds the immutable upload's live API identity - artifact ID,
  name, digest, size, owning run, and run head commit - to that receipt's run ID
  and expected artifact name, and to the SHA-256 of every file it downloaded
  from that artifact. Together those two directions prove that the bytes about
  to be published are the bytes the approved qualification run uploaded.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from release_bundle import (
    CHECKSUMS_NAME,
    MANIFEST_NAME,
    MAX_ASSET_BYTES,
    REPOSITORY_ID,
    SUPPORT_NAME_TEMPLATE,
    UV_VERSION,
    validate_bundle,
)
from validate_release_trigger import (
    APIClient,
    GITHUB_API_URL,
    GitHubClient,
    TriggerValidationError,
    validate_main_ci,
)


RECEIPT_VERSION = 1
RECEIPT_NAME = "strugglebus-qualification-receipt-v1.json"
RELEASE_ASSET_DIRECTORY = "release-assets"
QUALIFICATION_DIRECTORY = "qualification"
QUALIFICATION_WORKFLOW = "release-qualification.yml"
ASSET_ARTIFACT_TEMPLATE = "strugglebus-qualified-release-{tag}-{run_id}"
APPROVAL_PHRASE = "publish-exact-qualified-bytes"
BUILD_PYTHON = "3.13"
DEFAULT_VALIDITY_SECONDS = 7 * 24 * 60 * 60
MAX_VALIDITY_SECONDS = 14 * 24 * 60 * 60
MAX_RECEIPT_BYTES = 64 * 1024
MAX_RESOLUTION_BYTES = 16 * 1024
MAX_ARTIFACT_PAGES = 4
ARTIFACT_PAGE_SIZE = 100
MAX_RUN_RECORDS = 100
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024

SHA1_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
TAG_PATTERN = re.compile(r"^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
ARTIFACT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
ACTOR_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")


class QualificationError(RuntimeError):
    """The qualification receipt is missing, inconsistent, or expired."""


@dataclass(frozen=True)
class ArtifactIdentity:
    id: int
    name: str
    size_bytes: int
    digest: str


@dataclass(frozen=True)
class QualificationBinding:
    """Exact identities the publication event claims for the qualified bytes.

    Every value is resolved from the live read-only Actions API before the
    publisher performs any mutation, and each is re-read and compared against
    the live artifact record again inside ``verify_qualified_release``.
    """

    receipt_path: Path
    run_id: int
    artifact_id: int
    artifact_name: str
    artifact_digest: str
    artifact_size_bytes: int
    helper_sha256: str
    now: int


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise QualificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_canonical_json(path: Path, limit: int) -> tuple[dict[str, Any], bytes]:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise QualificationError(f"missing qualification document: {path.name}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise QualificationError(
            f"qualification document is not a regular file: {path.name}"
        )
    if metadata.st_size <= 0 or metadata.st_size > limit:
        raise QualificationError(
            f"qualification document exceeds its size limit: {path.name}"
        )
    content = path.read_bytes()
    try:
        value = json.loads(
            content,
            object_pairs_hook=_unique_object,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                QualificationError(f"non-finite JSON value: {constant}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError(
            f"qualification document is not valid JSON: {path.name}"
        ) from error
    if not isinstance(value, dict):
        raise QualificationError(
            f"qualification document must be one JSON object: {path.name}"
        )
    if _canonical_json(value) != content:
        raise QualificationError(
            f"qualification document is not canonically serialized: {path.name}"
        )
    return value, content


def _require_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise QualificationError(f"{label} must be an object")
    if set(value) != expected:
        raise QualificationError(f"{label} has unexpected or missing fields")
    return value


def _require_string(
    value: Any,
    label: str,
    *,
    pattern: re.Pattern[str] | None = None,
    maximum: int = 256,
) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise QualificationError(f"{label} is not a bounded non-empty string")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise QualificationError(f"{label} has an invalid format")
    return value


def _require_integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise QualificationError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise QualificationError(f"{label} is outside its allowed range")
    return value


def _require_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise QualificationError(f"{label} does not match the accepted value")


def _normalized_digest(value: Any, label: str) -> str:
    digest = _require_string(value, label, maximum=128)
    if digest.startswith("sha256:"):
        digest = digest[len("sha256:") :]
    digest = digest.casefold()
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise QualificationError(f"{label} is not a SHA-256 digest")
    return digest


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_regular_file(path: Path) -> int:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise QualificationError(f"missing qualified asset: {path.name}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise QualificationError(f"qualified asset is not a regular file: {path.name}")
    if metadata.st_size <= 0 or metadata.st_size > MAX_ASSET_BYTES:
        raise QualificationError(f"qualified asset size is invalid: {path.name}")
    return metadata.st_size


def expected_asset_names(version: str) -> list[str]:
    """Return the exact five release asset names for one package version."""

    _require_string(version, "package version", pattern=VERSION_PATTERN, maximum=32)
    return sorted(
        [
            f"strugglebus-{version}-py3-none-any.whl",
            "requirements.lock",
            SUPPORT_NAME_TEMPLATE.format(version=version),
            MANIFEST_NAME,
            CHECKSUMS_NAME,
        ]
    )


def asset_artifact_name(tag: str, run_id: int) -> str:
    return ASSET_ARTIFACT_TEMPLATE.format(tag=tag, run_id=run_id)


def _tag_version(tag: str) -> str:
    match = TAG_PATTERN.fullmatch(
        _require_string(tag, "intended release tag", maximum=64)
    )
    if match is None:
        raise QualificationError("intended release tag must be v<major>.<minor>.<patch>")
    return match.group("version")


def _describe_assets(directory: Path, version: str) -> list[dict[str, Any]]:
    names = sorted(entry.name for entry in directory.iterdir())
    expected = expected_asset_names(version)
    if names != expected:
        raise QualificationError("qualified asset set is incomplete or unexpected")
    return [
        {
            "name": name,
            "sha256": _sha256(directory / name),
            "size_bytes": _safe_regular_file(directory / name),
        }
        for name in expected
    ]


def validate_qualification_trigger(
    client: APIClient,
    *,
    repository: str,
    tag: str,
    commit: str,
    actor: str,
    workflow_sha: str,
    event_name: str,
    ref: str,
    approved_by: str,
    approval: str,
) -> dict[str, Any]:
    """Fail closed unless the owner dispatched qualification on exact main."""

    if repository != REPOSITORY_ID:
        raise QualificationError("qualification repository identity mismatch")
    version = _tag_version(tag)
    if SHA1_PATTERN.fullmatch(commit) is None:
        raise QualificationError("qualification commit is invalid")
    if SHA1_PATTERN.fullmatch(workflow_sha) is None:
        raise QualificationError("qualification workflow SHA is invalid")
    if commit != workflow_sha:
        raise QualificationError(
            "trusted default-branch workflow does not match the qualified commit"
        )
    if event_name != "workflow_dispatch":
        raise QualificationError("qualification must be an owner workflow dispatch")
    if ref != "refs/heads/main":
        raise QualificationError("qualification must run on the exact main ref")
    owner = repository.split("/", 1)[0]
    if actor.casefold() != owner.casefold():
        raise QualificationError("qualification must be dispatched by the repository owner")
    if approved_by.casefold() != owner.casefold():
        raise QualificationError("qualification approval must name the repository owner")
    if not hmac.compare_digest(approval, APPROVAL_PHRASE):
        raise QualificationError("qualification approval phrase is not the exact phrase")

    repository_record = client.get(f"repos/{repository}")
    if not isinstance(repository_record, dict):
        raise QualificationError("repository record must be an object")
    if repository_record.get("default_branch") != "main":
        raise QualificationError("qualification repository default branch must be main")
    main_branch = client.get(f"repos/{repository}/branches/main")
    if not isinstance(main_branch, dict):
        raise QualificationError("main branch record must be an object")
    main_commit = main_branch.get("commit")
    if not isinstance(main_commit, dict) or main_commit.get("sha") != commit:
        raise QualificationError(
            "qualification must run on the exact current main commit"
        )
    try:
        ci_run_id = validate_main_ci(client, repository=repository, commit=commit)
    except TriggerValidationError as error:
        raise QualificationError(f"qualification CI gate failed: {error}") from error
    return {
        "ci_run_id": ci_run_id,
        "commit": commit,
        "repository": repository,
        "tag": tag,
        "version": version,
    }


def build_receipt(
    directory: Path,
    *,
    repository: str,
    tag: str,
    commit: str,
    tree: str,
    version: str,
    run_id: int,
    run_attempt: int,
    actor: str,
    workflow_sha: str,
    approved_by: str,
    approval: str,
    uv_binary_sha256: str,
    helper_sha256: str,
    source_date_epoch: int,
    issued_at: int,
    validity_seconds: int = DEFAULT_VALIDITY_SECONDS,
) -> dict[str, Any]:
    """Build the pre-upload receipt that binds the exact qualified bytes."""

    if repository != REPOSITORY_ID:
        raise QualificationError("qualification repository identity mismatch")
    if _tag_version(tag) != version:
        raise QualificationError("intended release tag and package version differ")
    _require_string(commit, "qualified commit", pattern=SHA1_PATTERN, maximum=64)
    _require_string(tree, "qualified tree", pattern=SHA1_PATTERN, maximum=64)
    _require_integer(run_id, "qualification run ID", 1, 2**53 - 1)
    _require_integer(run_attempt, "qualification run attempt", 1, 1000)
    _require_string(actor, "qualification actor", pattern=ACTOR_PATTERN, maximum=64)
    _require_string(approved_by, "qualification approver", pattern=ACTOR_PATTERN, maximum=64)
    _require_string(workflow_sha, "qualification workflow SHA", pattern=SHA1_PATTERN, maximum=64)
    if not hmac.compare_digest(approval, APPROVAL_PHRASE):
        raise QualificationError("qualification approval phrase is not the exact phrase")
    _require_string(uv_binary_sha256, "uv binary digest", pattern=SHA256_PATTERN, maximum=64)
    _require_string(helper_sha256, "canonical wheel helper digest", pattern=SHA256_PATTERN, maximum=64)
    _require_integer(source_date_epoch, "source date epoch", 315532800, 4102444799)
    _require_integer(issued_at, "receipt issue time", 315532800, 4102444799)
    _require_integer(validity_seconds, "receipt validity", 3600, MAX_VALIDITY_SECONDS)
    receipt = {
        "approval": {
            "approved_by": approved_by,
            "intended_tag": tag,
            "phrase": APPROVAL_PHRASE,
        },
        "artifact": {
            "asset_directory": RELEASE_ASSET_DIRECTORY,
            "name": asset_artifact_name(tag, run_id),
            "receipt_directory": QUALIFICATION_DIRECTORY,
        },
        "assets": _describe_assets(directory, version),
        "expires_at": issued_at + validity_seconds,
        "issued_at": issued_at,
        "qualification": {
            "actor": actor,
            "event": "workflow_dispatch",
            "ref": "refs/heads/main",
            "repository": repository,
            "run_attempt": run_attempt,
            "run_id": run_id,
            "workflow": QUALIFICATION_WORKFLOW,
            "workflow_sha": workflow_sha,
        },
        "receipt_version": RECEIPT_VERSION,
        "release": {
            "commit": commit,
            "tag": tag,
            "tree": tree,
            "version": version,
        },
        "tools": {
            "build_python": BUILD_PYTHON,
            "canonical_wheel_sha256": helper_sha256,
            "source_date_epoch": source_date_epoch,
            "uv_binary_sha256": uv_binary_sha256,
            "uv_version": UV_VERSION,
        },
    }
    validated = validate_bundle(
        directory,
        expected_repository=repository,
        expected_tag=tag,
        expected_commit=commit,
        expected_tree=tree,
    )
    if not hmac.compare_digest(validated["uv_binary_sha256"], uv_binary_sha256):
        raise QualificationError("uv binary digest does not match the release manifest")
    return receipt


def validate_receipt(
    receipt: dict[str, Any],
    *,
    repository: str,
    tag: str,
    commit: str,
    tree: str,
    run_id: int,
    artifact_name: str,
    helper_sha256: str,
    now: int,
) -> dict[str, Any]:
    """Fail closed unless the receipt binds exactly the expected publication."""

    _require_keys(
        receipt,
        {
            "approval",
            "artifact",
            "assets",
            "expires_at",
            "issued_at",
            "qualification",
            "receipt_version",
            "release",
            "tools",
        },
        "qualification receipt",
    )
    if receipt["receipt_version"] != RECEIPT_VERSION:
        raise QualificationError("unsupported qualification receipt version")
    version = _tag_version(tag)

    release = _require_keys(
        receipt["release"], {"commit", "tag", "tree", "version"}, "receipt release"
    )
    _require_equal(release["tag"], tag, "receipt release tag")
    _require_equal(release["commit"], commit, "receipt release commit")
    _require_equal(release["tree"], tree, "receipt release tree")
    _require_equal(release["version"], version, "receipt release version")

    approval = _require_keys(
        receipt["approval"], {"approved_by", "intended_tag", "phrase"}, "receipt approval"
    )
    owner = repository.split("/", 1)[0]
    if approval["approved_by"] != owner:
        raise QualificationError("receipt approval does not name the repository owner")
    _require_equal(approval["intended_tag"], tag, "receipt approved tag intent")
    if not hmac.compare_digest(
        _require_string(approval["phrase"], "receipt approval phrase", maximum=64),
        APPROVAL_PHRASE,
    ):
        raise QualificationError("receipt approval phrase is not the exact phrase")

    qualification = _require_keys(
        receipt["qualification"],
        {
            "actor",
            "event",
            "ref",
            "repository",
            "run_attempt",
            "run_id",
            "workflow",
            "workflow_sha",
        },
        "receipt qualification",
    )
    _require_equal(qualification["repository"], repository, "receipt repository")
    _require_equal(qualification["event"], "workflow_dispatch", "receipt event")
    _require_equal(qualification["ref"], "refs/heads/main", "receipt ref")
    _require_equal(qualification["workflow"], QUALIFICATION_WORKFLOW, "receipt workflow")
    _require_equal(qualification["run_id"], run_id, "receipt qualification run")
    _require_integer(qualification["run_attempt"], "receipt run attempt", 1, 1000)
    _require_string(
        qualification["workflow_sha"],
        "receipt workflow SHA",
        pattern=SHA1_PATTERN,
        maximum=64,
    )
    _require_equal(qualification["workflow_sha"], commit, "receipt workflow identity")
    if qualification["actor"] != owner:
        raise QualificationError("receipt qualification actor is not the repository owner")

    artifact = _require_keys(
        receipt["artifact"],
        {"asset_directory", "name", "receipt_directory"},
        "receipt artifact",
    )
    _require_equal(artifact["name"], artifact_name, "receipt artifact name")
    _require_equal(
        artifact["name"], asset_artifact_name(tag, run_id), "receipt artifact identity"
    )
    _require_equal(
        artifact["asset_directory"], RELEASE_ASSET_DIRECTORY, "receipt asset directory"
    )
    _require_equal(
        artifact["receipt_directory"],
        QUALIFICATION_DIRECTORY,
        "receipt document directory",
    )

    tools = _require_keys(
        receipt["tools"],
        {
            "build_python",
            "canonical_wheel_sha256",
            "source_date_epoch",
            "uv_binary_sha256",
            "uv_version",
        },
        "receipt tools",
    )
    _require_equal(tools["build_python"], BUILD_PYTHON, "receipt build Python")
    _require_equal(tools["uv_version"], UV_VERSION, "receipt uv version")
    _require_string(
        tools["uv_binary_sha256"], "receipt uv digest", pattern=SHA256_PATTERN, maximum=64
    )
    _require_integer(
        tools["source_date_epoch"], "receipt source date epoch", 315532800, 4102444799
    )
    if not hmac.compare_digest(
        _require_string(
            tools["canonical_wheel_sha256"],
            "receipt canonical wheel helper digest",
            pattern=SHA256_PATTERN,
            maximum=64,
        ),
        helper_sha256,
    ):
        raise QualificationError(
            "receipt canonical wheel helper does not match the trusted controls"
        )

    issued_at = _require_integer(
        receipt["issued_at"], "receipt issue time", 315532800, 4102444799
    )
    expires_at = _require_integer(
        receipt["expires_at"], "receipt expiry", 315532800, 4102444799
    )
    _require_integer(now, "publication time", 315532800, 4102444799)
    if expires_at <= issued_at or expires_at - issued_at > MAX_VALIDITY_SECONDS:
        raise QualificationError("receipt validity window is invalid")
    if now < issued_at:
        raise QualificationError("receipt was issued in the future")
    if now >= expires_at:
        raise QualificationError("qualification receipt has expired")

    assets = receipt["assets"]
    expected = expected_asset_names(version)
    if not isinstance(assets, list) or len(assets) != len(expected):
        raise QualificationError("receipt asset list is incomplete or unexpected")
    described: dict[str, dict[str, Any]] = {}
    for entry in assets:
        _require_keys(entry, {"name", "sha256", "size_bytes"}, "receipt asset")
        name = _require_string(entry["name"], "receipt asset name", maximum=128)
        if name in described:
            raise QualificationError("receipt lists a duplicate asset")
        _require_string(
            entry["sha256"], "receipt asset digest", pattern=SHA256_PATTERN, maximum=64
        )
        _require_integer(entry["size_bytes"], "receipt asset size", 1, MAX_ASSET_BYTES)
        described[name] = entry
    if sorted(described) != expected or [item["name"] for item in assets] != expected:
        raise QualificationError("receipt asset set is incomplete or unexpected")
    return described


def _artifact_identity(record: Any, *, run_id: int, commit: str) -> ArtifactIdentity:
    if not isinstance(record, dict):
        raise QualificationError("artifact record must be an object")
    if record.get("expired") is not False:
        raise QualificationError("qualification artifact has expired")
    workflow_run = record.get("workflow_run")
    if not isinstance(workflow_run, dict):
        raise QualificationError("artifact record lacks its workflow run")
    if workflow_run.get("id") != run_id:
        raise QualificationError("artifact belongs to a different workflow run")
    if workflow_run.get("head_sha") != commit:
        raise QualificationError("artifact workflow run has the wrong head commit")
    if workflow_run.get("head_branch") != "main":
        raise QualificationError("artifact workflow run is not from main")
    return ArtifactIdentity(
        id=_require_integer(record.get("id"), "artifact ID", 1, 2**53 - 1),
        name=_require_string(
            record.get("name"), "artifact name", pattern=ARTIFACT_NAME_PATTERN
        ),
        size_bytes=_require_integer(
            record.get("size_in_bytes"), "artifact size", 1, MAX_ARTIFACT_BYTES
        ),
        digest=_normalized_digest(record.get("digest"), "artifact digest"),
    )


def _list_artifacts(client: APIClient, repository: str, run_id: int) -> list[Any]:
    records: list[Any] = []
    for page in range(1, MAX_ARTIFACT_PAGES + 1):
        query = urllib.parse.urlencode(
            {"page": str(page), "per_page": str(ARTIFACT_PAGE_SIZE)}
        )
        response = client.get(
            f"repos/{repository}/actions/runs/{run_id}/artifacts?{query}"
        )
        if not isinstance(response, dict):
            raise QualificationError("artifact listing must be an object")
        page_records = response.get("artifacts")
        if not isinstance(page_records, list) or len(page_records) > ARTIFACT_PAGE_SIZE:
            raise QualificationError("artifact listing is invalid")
        records.extend(page_records)
        if len(page_records) < ARTIFACT_PAGE_SIZE:
            return records
    raise QualificationError("qualification run has too many artifacts to reconcile")


def _select_artifact(
    records: list[Any],
    name: str,
    *,
    run_id: int,
    commit: str,
) -> ArtifactIdentity:
    matches = [
        record
        for record in records
        if isinstance(record, dict) and record.get("name") == name
    ]
    if len(matches) != 1:
        raise QualificationError(
            f"qualification run must expose exactly one {name} artifact"
        )
    return _artifact_identity(matches[0], run_id=run_id, commit=commit)


def resolve_qualification(
    client: APIClient,
    *,
    repository: str,
    tag: str,
    commit: str,
) -> dict[str, Any]:
    """Resolve the single owner- and tag-bound successful qualification run."""

    if repository != REPOSITORY_ID:
        raise QualificationError("qualification repository identity mismatch")
    _tag_version(tag)
    _require_string(commit, "qualified commit", pattern=SHA1_PATTERN, maximum=64)
    owner = repository.split("/", 1)[0]
    query = urllib.parse.urlencode(
        {
            "event": "workflow_dispatch",
            "head_sha": commit,
            "status": "completed",
            "per_page": str(MAX_RUN_RECORDS),
        }
    )
    response = client.get(
        f"repos/{repository}/actions/workflows/{QUALIFICATION_WORKFLOW}/runs?{query}"
    )
    if not isinstance(response, dict):
        raise QualificationError("qualification run listing must be an object")
    runs = response.get("workflow_runs")
    if not isinstance(runs, list) or len(runs) > MAX_RUN_RECORDS:
        raise QualificationError("qualification run listing is invalid")
    candidates: dict[int, dict[str, Any]] = {}
    for record in runs:
        if not isinstance(record, dict):
            raise QualificationError("qualification run record must be an object")
        actor = record.get("actor")
        triggering = record.get("triggering_actor")
        if (
            record.get("event") != "workflow_dispatch"
            or record.get("status") != "completed"
            or record.get("conclusion") != "success"
            or record.get("head_sha") != commit
            or record.get("head_branch") != "main"
            or not isinstance(actor, dict)
            or not isinstance(triggering, dict)
            or actor.get("login") != owner
            or triggering.get("login") != owner
        ):
            continue
        run_id = _require_integer(record.get("id"), "qualification run ID", 1, 2**53 - 1)
        candidates[run_id] = record
    if not candidates:
        raise QualificationError("no successful owner qualification run for this commit")

    resolved: list[dict[str, Any]] = []
    for run_id, record in sorted(candidates.items()):
        records = _list_artifacts(client, repository, run_id)
        names = {
            item.get("name")
            for item in records
            if isinstance(item, dict) and item.get("expired") is False
        }
        artifact_name = asset_artifact_name(tag, run_id)
        if artifact_name not in names:
            continue
        resolved.append(
            {
                "artifact": _select_artifact(
                    records, artifact_name, run_id=run_id, commit=commit
                ),
                "run": record,
                "run_attempt": _require_integer(
                    record.get("run_attempt"), "qualification run attempt", 1, 1000
                ),
                "run_id": run_id,
            }
        )
    if not resolved:
        raise QualificationError(
            "no unexpired qualification artifact matches this tag and commit"
        )
    if len(resolved) > 1:
        raise QualificationError(
            "multiple qualification runs claim this tag and commit"
        )
    return resolved[0]


def verify_qualified_release(
    client: APIClient,
    directory: Path,
    binding: QualificationBinding,
    *,
    repository: str,
    tag: str,
    commit: str,
    tree: str,
) -> dict[str, Any]:
    """Fail closed unless the local bytes are the exact qualified artifact.

    The live artifact record - ID, name, digest, size, owning run, and run head
    commit - is re-read from the read-only Actions API and compared against the
    identities the publication event claims. The receipt inside the downloaded
    artifact cannot carry those post-upload values, so it is joined to the live
    upload through its qualification run ID and its expected artifact name, and
    through the SHA-256 digest and size of every downloaded file.
    """

    resolved = resolve_qualification(
        client,
        repository=repository,
        tag=tag,
        commit=commit,
    )
    artifact: ArtifactIdentity = resolved["artifact"]
    _require_equal(resolved["run_id"], binding.run_id, "qualification run identity")
    _require_equal(artifact.id, binding.artifact_id, "qualification artifact ID")
    _require_equal(artifact.name, binding.artifact_name, "qualification artifact name")
    _require_equal(
        artifact.size_bytes, binding.artifact_size_bytes, "qualification artifact size"
    )
    if not hmac.compare_digest(
        artifact.digest,
        _normalized_digest(binding.artifact_digest, "claimed artifact digest"),
    ):
        raise QualificationError("qualification artifact digest drifted before publication")

    receipt, receipt_content = _read_canonical_json(
        binding.receipt_path, MAX_RECEIPT_BYTES
    )
    described = validate_receipt(
        receipt,
        repository=repository,
        tag=tag,
        commit=commit,
        tree=tree,
        run_id=binding.run_id,
        artifact_name=artifact.name,
        helper_sha256=binding.helper_sha256,
        now=binding.now,
    )
    _require_equal(
        receipt["qualification"]["run_attempt"],
        resolved["run_attempt"],
        "receipt run attempt",
    )

    names = sorted(entry.name for entry in directory.iterdir())
    if names != sorted(described):
        raise QualificationError("qualified asset set does not match the receipt")
    for name, entry in described.items():
        path = directory / name
        if _safe_regular_file(path) != entry["size_bytes"]:
            raise QualificationError(f"qualified asset size drifted: {name}")
        if not hmac.compare_digest(_sha256(path), entry["sha256"]):
            raise QualificationError(f"qualified asset digest drifted: {name}")
    validate_bundle(
        directory,
        expected_repository=repository,
        expected_tag=tag,
        expected_commit=commit,
        expected_tree=tree,
    )
    return {
        "artifact_digest": artifact.digest,
        "artifact_id": artifact.id,
        "artifact_name": artifact.name,
        "artifact_size_bytes": artifact.size_bytes,
        "expires_at": receipt["expires_at"],
        "qualification_run_id": resolved["run_id"],
        "receipt_sha256": hashlib.sha256(receipt_content).hexdigest(),
    }


def helper_digest(repository: Path) -> str:
    """Return the SHA-256 of the trusted canonical wheel helper."""

    return _sha256(repository / "scripts/canonical_wheel.py")


def _write_document(path: Path, value: dict[str, Any]) -> bytes:
    content = _canonical_json(value)
    if path.exists() or path.is_symlink():
        raise QualificationError(f"qualification document already exists: {path.name}")
    path.write_bytes(content)
    return content


def _client(token_env: str) -> GitHubClient:
    token = os.environ.get(token_env)
    if not token:
        raise QualificationError("read-only GitHub API token is unavailable")
    return GitHubClient(GITHUB_API_URL, token)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    gate = subparsers.add_parser("gate")
    gate.add_argument("--repository", default=REPOSITORY_ID)
    gate.add_argument("--tag", required=True)
    gate.add_argument("--commit", required=True)
    gate.add_argument("--actor", required=True)
    gate.add_argument("--workflow-sha", required=True)
    gate.add_argument("--event-name", required=True)
    gate.add_argument("--ref", required=True)
    gate.add_argument("--approved-by", required=True)
    gate.add_argument("--approval", required=True)
    gate.add_argument("--token-env", default="GITHUB_TOKEN")

    receipt = subparsers.add_parser("receipt")
    receipt.add_argument("directory", type=Path)
    receipt.add_argument("--output", type=Path, required=True)
    receipt.add_argument("--repository", default=REPOSITORY_ID)
    receipt.add_argument("--tag", required=True)
    receipt.add_argument("--commit", required=True)
    receipt.add_argument("--tree", required=True)
    receipt.add_argument("--version", required=True)
    receipt.add_argument("--run-id", type=int, required=True)
    receipt.add_argument("--run-attempt", type=int, required=True)
    receipt.add_argument("--actor", required=True)
    receipt.add_argument("--workflow-sha", required=True)
    receipt.add_argument("--approved-by", required=True)
    receipt.add_argument("--approval", required=True)
    receipt.add_argument("--uv-binary-sha256", required=True)
    receipt.add_argument("--source-date-epoch", type=int, required=True)
    receipt.add_argument("--source-root", type=Path, default=Path.cwd())
    receipt.add_argument(
        "--validity-seconds", type=int, default=DEFAULT_VALIDITY_SECONDS
    )

    resolve = subparsers.add_parser("resolve")
    resolve.add_argument("--repository", default=REPOSITORY_ID)
    resolve.add_argument("--tag", required=True)
    resolve.add_argument("--commit", required=True)
    resolve.add_argument("--token-env", default="GITHUB_TOKEN")

    outputs = subparsers.add_parser("outputs")
    outputs.add_argument("--resolution", type=Path, required=True)
    return parser


OUTPUT_KEYS = (
    "artifact_digest",
    "artifact_id",
    "artifact_name",
    "artifact_size_bytes",
    "run_id",
)


def render_outputs(resolution: dict[str, Any]) -> str:
    """Render resolved identities as bounded, injection-safe workflow outputs."""

    _require_keys(resolution, set(OUTPUT_KEYS), "qualification resolution")
    lines: list[str] = []
    for key in OUTPUT_KEYS:
        value = resolution[key]
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise QualificationError(f"resolved value is not renderable: {key}")
        text = str(value)
        if (
            not text
            or len(text) > 160
            or not text.isascii()
            or any(character in text for character in "\r\n\t\"'$`\\ =")
            or any(ord(character) <= 32 or ord(character) == 127 for character in text)
        ):
            raise QualificationError(f"resolved value is unsafe to render: {key}")
        lines.append(f"{key.replace('_', '-')}={text}")
    return "".join(f"{line}\n" for line in lines)


def main() -> int:
    args = _build_parser().parse_args()
    if args.command == "gate":
        result = validate_qualification_trigger(
            _client(args.token_env),
            repository=args.repository,
            tag=args.tag,
            commit=args.commit,
            actor=args.actor,
            workflow_sha=args.workflow_sha,
            event_name=args.event_name,
            ref=args.ref,
            approved_by=args.approved_by,
            approval=args.approval,
        )
    elif args.command == "receipt":
        receipt = build_receipt(
            args.directory,
            repository=args.repository,
            tag=args.tag,
            commit=args.commit,
            tree=args.tree,
            version=args.version,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            actor=args.actor,
            workflow_sha=args.workflow_sha,
            approved_by=args.approved_by,
            approval=args.approval,
            uv_binary_sha256=args.uv_binary_sha256,
            helper_sha256=helper_digest(args.source_root),
            source_date_epoch=args.source_date_epoch,
            issued_at=int(time.time()),
            validity_seconds=args.validity_seconds,
        )
        content = _write_document(args.output, receipt)
        result = {
            "artifact_name": receipt["artifact"]["name"],
            "expires_at": receipt["expires_at"],
            "receipt_sha256": hashlib.sha256(content).hexdigest(),
        }
    elif args.command == "outputs":
        resolution, _ = _read_canonical_json(args.resolution, MAX_RESOLUTION_BYTES)
        print(render_outputs(resolution), end="")
        return 0
    else:
        resolved = resolve_qualification(
            _client(args.token_env),
            repository=args.repository,
            tag=args.tag,
            commit=args.commit,
        )
        artifact: ArtifactIdentity = resolved["artifact"]
        result = {
            "artifact_digest": artifact.digest,
            "artifact_id": artifact.id,
            "artifact_name": artifact.name,
            "artifact_size_bytes": artifact.size_bytes,
            "run_id": resolved["run_id"],
        }
    print(_canonical_json(result).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
