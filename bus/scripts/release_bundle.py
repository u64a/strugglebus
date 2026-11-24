"""Build and validate the canonical immutable release bundle."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
# Subprocess is limited to fixed git commands and never invokes a shell.
import subprocess  # nosec B404
import tarfile
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any

from canonical_wheel import (
    CanonicalWheelError,
    normalize_wheel,
    verify_canonical_wheel,
)
from validate_requirements_lock import validate_requirements_lock

# Build/controller entry points use their qualified tree, not another install.
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from strugglebus.release_validation import (
    ACCESS_FREEZE_CAPABILITY,
    CHECKSUMS_NAME,
    COORDINATION_PROTOCOL_VERSION,
    CURRENT_SCHEMA,
    DISQUALIFIED_PRODUCTION_VERSIONS,
    GUIDE_VERSION,
    MANIFEST_NAME,
    MANIFEST_VERSION,
    MAX_ASSET_BYTES,
    MAX_CHECKSUMS_BYTES,
    MAX_LOCK_BYTES,
    MAX_MANIFEST_BYTES,
    MINIMUM_UPGRADE_SCHEMA,
    REPOSITORY_ID,
    ROLLBACK_PREVIOUS_SCHEMA,
    ReleaseBundleError,
    SHA1_PATTERN,
    SHA256_PATTERN,
    SUPPORT_FILES,
    SUPPORT_INDEX_NAME,
    SUPPORT_NAME_TEMPLATE,
    SupportFile,
    TAG_PATTERN,
    UV_ARCHIVE_SHA256,
    UV_VERSION,
    VERSION_PATTERN,
    _canonical_directory,
    _canonical_json,
    _read_json,
    _require_integer,
    _require_keys,
    _require_string,
    _safe_regular_file,
    _sha256,
    _sha256_bytes,
    _unique_object,
    _validate_checksums,
    _validate_support_archive,
    _version_tuple,
    _wheel_metadata,
    validate_bundle,
)


def _git(repository: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(  # nosec B603
            ("git", "-C", str(repository), *arguments),
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ReleaseBundleError(
            f"git command failed: {arguments[0] if arguments else 'git'}"
        ) from error
    return result.stdout.strip()


def _package_version(repository: Path) -> str:
    source = (repository / "src/strugglebus/__init__.py").read_text(encoding="utf-8")
    match = re.fullmatch(
        r'"""Strugglebus package\."""\n\n__version__ = "([0-9]+\.[0-9]+\.[0-9]+)"\n',
        source,
    )
    if match is None:
        raise ReleaseBundleError("package version source is not canonical")
    return match.group(1)


def resolve_release_identity(
    repository: Path,
    tag: str,
    *,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
    require_clean: bool = True,
    pre_tag: bool = False,
) -> tuple[str, str, int, str]:
    """Resolve the exact release identity for one intended annotated tag.

    The default mode is strict: the tag must already exist as an annotated tag
    and the identity is resolved from it. Pre-tag qualification mode is the only
    exception and exists solely for the owner-approved qualification workflow,
    which must produce the exact release bytes before the tag is created. That
    mode requires a caller-supplied exact commit and tree, resolves the identity
    from git, and compares every resolved value against them.
    """

    match = TAG_PATTERN.fullmatch(tag)
    if match is None:
        raise ReleaseBundleError("release tag must be v<major>.<minor>.<patch>")
    version = _package_version(repository)
    if match.group("version") != version:
        raise ReleaseBundleError("release tag version does not match the package")
    if pre_tag:
        if expected_commit is None or expected_tree is None:
            raise ReleaseBundleError(
                "pre-tag qualification requires the expected commit and tree"
            )
        if (
            SHA1_PATTERN.fullmatch(expected_commit) is None
            or SHA1_PATTERN.fullmatch(expected_tree) is None
        ):
            raise ReleaseBundleError(
                "pre-tag qualification requires exact 40-character identities"
            )
        revision = f"{expected_commit}^{{commit}}"
    else:
        if _git(repository, "cat-file", "-t", tag) != "tag":
            raise ReleaseBundleError("release tag must be an existing annotated tag")
        revision = f"{tag}^{{commit}}"
    commit = _git(repository, "rev-parse", revision)
    tree = _git(repository, "rev-parse", f"{commit}^{{tree}}")
    if SHA1_PATTERN.fullmatch(commit) is None or SHA1_PATTERN.fullmatch(tree) is None:
        raise ReleaseBundleError("git returned an invalid commit or tree identity")
    if expected_commit is not None and commit != expected_commit:
        raise ReleaseBundleError("release tag does not resolve to the expected commit")
    if expected_tree is not None and tree != expected_tree:
        raise ReleaseBundleError("release commit has the wrong tree")
    if require_clean and (
        _git(repository, "status", "--porcelain=v1", "--untracked-files=no")
        or _git(repository, "diff", "--cached", "--name-only")
    ):
        raise ReleaseBundleError("release source has tracked dirty state")
    timestamp_text = _git(repository, "show", "-s", "--format=%ct", commit)
    try:
        timestamp = int(timestamp_text)
    except ValueError as error:
        raise ReleaseBundleError("release commit has an invalid timestamp") from error
    return commit, tree, timestamp, version


def _support_index(repository: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for support in SUPPORT_FILES:
        source = repository / support.source
        metadata = _safe_regular_file(source, MAX_ASSET_BYTES)
        entries.append(
            {
                "archive_path": support.archive,
                "destination": support.destination,
                "mode": f"{support.mode:04o}",
                "sha256": _sha256(source),
                "size_bytes": metadata.st_size,
                "source_path": support.source,
            }
        )
    return sorted(entries, key=lambda entry: entry["archive_path"])


def _tar_info(name: str, size: int, mode: int, timestamp: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = mode
    info.mtime = timestamp
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    return info


def _write_support_archive(
    repository: Path,
    destination: Path,
    timestamp: int,
    support_index: list[dict[str, Any]],
) -> None:
    index_content = _canonical_json(
        {"files": support_index, "support_manifest_version": 1}
    )
    with destination.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=timestamp) as zipped:
            with tarfile.open(
                fileobj=zipped,
                mode="w",
                format=tarfile.USTAR_FORMAT,
            ) as archive:
                for support in sorted(SUPPORT_FILES, key=lambda item: item.archive):
                    source = repository / support.source
                    content = source.read_bytes()
                    archive.addfile(
                        _tar_info(support.archive, len(content), support.mode, timestamp),
                        fileobj=_BytesReader(content),
                    )
                archive.addfile(
                    _tar_info(
                        SUPPORT_INDEX_NAME,
                        len(index_content),
                        0o644,
                        timestamp,
                    ),
                    fileobj=_BytesReader(index_content),
                )


class _BytesReader:
    def __init__(self, content: bytes) -> None:
        self._content = content
        self._offset = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self._content) - self._offset
        result = self._content[self._offset : self._offset + size]
        self._offset += len(result)
        return result


def _asset(path: Path, purpose: str, media_type: str) -> dict[str, Any]:
    metadata = _safe_regular_file(path, MAX_ASSET_BYTES)
    return {
        "media_type": media_type,
        "name": path.name,
        "purpose": purpose,
        "sha256": _sha256(path),
        "size_bytes": metadata.st_size,
    }


def build_bundle(
    repository: Path,
    distribution_directory: Path,
    output_directory: Path,
    tag: str,
    *,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
    uv_binary: Path | None = None,
    pre_tag: bool = False,
) -> dict[str, Any]:
    repository = repository.resolve(strict=True)
    distribution_directory = distribution_directory.resolve(strict=True)
    output_directory.mkdir(parents=True, exist_ok=True)
    if output_directory.is_symlink() or any(output_directory.iterdir()):
        raise ReleaseBundleError("release output directory must be new and empty")
    commit, tree, timestamp, version = resolve_release_identity(
        repository,
        tag,
        expected_commit=expected_commit,
        expected_tree=expected_tree,
        pre_tag=pre_tag,
    )

    wheels = tuple(distribution_directory.glob("*.whl"))
    if len(wheels) != 1:
        raise ReleaseBundleError(f"expected one wheel, found {len(wheels)}")
    metadata = _wheel_metadata(wheels[0])
    if metadata["Version"] != version:
        raise ReleaseBundleError("wheel version does not match the release tag")
    wheel = output_directory / wheels[0].name
    lock = output_directory / "requirements.lock"
    try:
        normalize_wheel(wheels[0], wheel, timestamp=timestamp)
    except CanonicalWheelError as error:
        raise ReleaseBundleError(f"release wheel is not canonical: {error}") from error
    shutil.copyfile(repository / "requirements.lock", lock)
    validate_requirements_lock(lock)

    support_index = _support_index(repository)
    support = output_directory / SUPPORT_NAME_TEMPLATE.format(version=version)
    _write_support_archive(repository, support, timestamp, support_index)

    resolved_uv = uv_binary or Path(shutil.which("uv") or "")
    if not resolved_uv or not resolved_uv.is_file():
        raise ReleaseBundleError("the pinned uv executable is unavailable")
    uv_digest = _sha256(resolved_uv.resolve(strict=True))

    assets = [
        _asset(
            wheel,
            "application-wheel",
            "application/vnd.python.wheel",
        ),
        _asset(
            lock,
            "hash-locked-production-requirements",
            "text/plain",
        ),
        _asset(
            support,
            "reviewed-deployment-support",
            "application/gzip",
        ),
    ]
    assets.sort(key=lambda item: item["name"])
    manifest: dict[str, Any] = {
        "assets": assets,
        "build": {
            "build_python": "3.13",
            "tested_python": ["3.13"],
            "uv": {
                "archive_sha256": UV_ARCHIVE_SHA256,
                "binary_sha256": uv_digest,
                "platform": "x86_64-unknown-linux-gnu",
                "version": UV_VERSION,
            },
        },
        "compatibility": {
            "database": {
                "current_schema": CURRENT_SCHEMA,
                "downgrade_supported": False,
                "minimum_upgrade_schema": MINIMUM_UPGRADE_SCHEMA,
                "requires_verified_pre_migration_backup": True,
                "rollback_previous_schema": ROLLBACK_PREVIOUS_SCHEMA,
                "rollback_strategy": "restore-verified-backup-and-select-compatible-release",
            },
            "python_requires": ">=3.13,<3.14",
        },
        "consumption": {
            "authenticated_github_acquisition_required": True,
            "immutable_github_release_required": True,
            "offline_publisher_authenticity": False,
            "offline_verification": "sha256-integrity-only",
            "release_assets": sorted(
                [
                    wheel.name,
                    lock.name,
                    support.name,
                    MANIFEST_NAME,
                    CHECKSUMS_NAME,
                ]
            ),
        },
        "deployment_support": {
            "files": support_index,
            "support_manifest_version": 1,
        },
        "manifest_version": MANIFEST_VERSION,
        "package": {
            "name": "strugglebus",
            "version": version,
            "wheel_tag": "py3-none-any",
        },
        "protocol": {
            "capabilities": [f"agent-access-freeze:{ACCESS_FREEZE_CAPABILITY}"],
            "coordination_protocol_version": COORDINATION_PROTOCOL_VERSION,
            "integration_guide_version": GUIDE_VERSION,
        },
        "release": {
            "candidate_id": f"{REPOSITORY_ID}@{tag}:{commit}:{tree}",
            "repository": REPOSITORY_ID,
            "source_commit": commit,
            "source_tree": tree,
            "tag": tag,
        },
    }
    manifest_path = output_directory / MANIFEST_NAME
    manifest_path.write_bytes(_canonical_json(manifest))
    if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ReleaseBundleError("generated manifest exceeds its size limit")

    checksum_paths = sorted((wheel, lock, support, manifest_path), key=lambda p: p.name)
    checksums = "".join(f"{_sha256(path)}  {path.name}\n" for path in checksum_paths)
    (output_directory / CHECKSUMS_NAME).write_text(checksums, encoding="ascii")
    validate_bundle(
        output_directory,
        expected_repository=REPOSITORY_ID,
        expected_tag=tag,
        expected_commit=commit,
        expected_tree=tree,
        expected_current_schema=CURRENT_SCHEMA,
        required_protocol=COORDINATION_PROTOCOL_VERSION,
        required_capability=f"agent-access-freeze:{ACCESS_FREEZE_CAPABILITY}",
    )
    return manifest


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--repository", type=Path, default=Path.cwd())
    build.add_argument("--dist", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--tag", required=True)
    build.add_argument("--expected-commit")
    build.add_argument("--expected-tree")
    build.add_argument("--uv-binary", type=Path)
    build.add_argument(
        "--pre-tag",
        action="store_true",
        help=(
            "qualify the exact bytes before the annotated tag exists; requires "
            "--expected-commit and --expected-tree"
        ),
    )

    validate = subparsers.add_parser("validate")
    validate.add_argument("directory", type=Path)
    validate.add_argument("--expected-repository", default=REPOSITORY_ID)
    validate.add_argument("--expected-tag")
    validate.add_argument("--expected-commit")
    validate.add_argument("--expected-tree")
    validate.add_argument("--expected-current-schema", type=int, default=CURRENT_SCHEMA)
    validate.add_argument(
        "--required-protocol",
        type=int,
        default=COORDINATION_PROTOCOL_VERSION,
    )
    validate.add_argument(
        "--required-capability",
        default=f"agent-access-freeze:{ACCESS_FREEZE_CAPABILITY}",
    )
    validate.add_argument("--minimum-package-version")
    validate.add_argument("--format", choices=("summary", "ansible"), default="summary")
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    if args.command == "build":
        manifest = build_bundle(
            args.repository,
            args.dist,
            args.output,
            args.tag,
            expected_commit=args.expected_commit,
            expected_tree=args.expected_tree,
            uv_binary=args.uv_binary,
            pre_tag=args.pre_tag,
        )
        print(_canonical_json(manifest).decode("ascii"), end="")
        return 0
    result = validate_bundle(
        args.directory,
        expected_repository=args.expected_repository,
        expected_tag=args.expected_tag,
        expected_commit=args.expected_commit,
        expected_tree=args.expected_tree,
        expected_current_schema=args.expected_current_schema,
        required_protocol=args.required_protocol,
        required_capability=args.required_capability,
        minimum_package_version=args.minimum_package_version,
    )
    if args.format == "ansible":
        print(_canonical_json(result).decode("ascii"), end="")
    else:
        print(
            json.dumps(
                {
                    "authenticity": result["authenticity"],
                    "integrity": result["integrity"],
                    "source_commit": result["source_commit"],
                    "tag": result["tag"],
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
