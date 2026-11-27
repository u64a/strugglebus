"""Trusted read-only immutable bundle validation shared by release tools."""
from __future__ import annotations
import hashlib
import gzip
import json
import os
import re
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from email.message import Message
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any
from .release_wheel import CanonicalWheelError, verify_canonical_wheel
from .release_lock import validate_requirements_lock

MANIFEST_VERSION = 1


MANIFEST_NAME = "strugglebus-release-manifest-v1.json"


DISQUALIFIED_PRODUCTION_VERSIONS = frozenset(
    {
        "0.2.5",
        "0.2.6",
        "0.2.28",
        "0.2.31",
        "0.2.32",
        "0.2.33",
        "0.2.34",
        "0.2.35",
        "0.2.36",
        "0.2.37",
        "0.2.38",
        "0.2.39",
        "0.2.40",
        "0.2.41",
    }
)


CHECKSUMS_NAME = "SHA256SUMS"


SUPPORT_NAME_TEMPLATE = "strugglebus-deployment-support-{version}.tar.gz"


SUPPORT_INDEX_NAME = "deployment-support-files-v1.json"


REPOSITORY_ID = "NZCypher819/strugglebus"


CURRENT_SCHEMA = 24


MINIMUM_UPGRADE_SCHEMA = 1


ROLLBACK_PREVIOUS_SCHEMA = 23


# Upper bound on a candidate schema; matches the maintenance helper.
MAX_SCHEMA = 9999


GUIDE_VERSION = "1.19.0"


_GUIDE_VERSION_PATTERN = re.compile(r"(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})")


COORDINATION_PROTOCOL_VERSION = 1


ACCESS_FREEZE_CAPABILITY = "global-v1"


UV_VERSION = "0.12.7"


UV_ARCHIVE_SHA256 = (
    "788f18abea7c5f55d6216e4f5613fd89d4d59b631efeec117b2b07fe72f1da21"
)


MAX_MANIFEST_BYTES = 256 * 1024


MAX_CHECKSUMS_BYTES = 16 * 1024

# The publisher's signed statement, as an installed updater saves it beside the release's files.
# It is not a release asset: it comes from the release's tag, and it is what the assets are
# checked against. See release_signature.py.
STATEMENT_NAME = "release-statement.txt"
MAX_STATEMENT_BYTES = 8 * 1024


MAX_LOCK_BYTES = 10 * 1024 * 1024


MAX_ASSET_BYTES = 256 * 1024 * 1024


TAG_PATTERN = re.compile(r"^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$")


SHA1_PATTERN = re.compile(r"^[0-9a-f]{40}$")


SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


@dataclass(frozen=True)
class SupportFile:
    source: str
    archive: str
    destination: str
    mode: int = 0o755


SUPPORT_FILES = (
    SupportFile(
        "deploy/roles/systemd/templates/strugglebus-operator.py.j2",
        "deploy/roles/systemd/templates/strugglebus-operator.py.j2",
        "deploy/roles/systemd/templates/strugglebus-operator.py.j2",
        0o644,
    ),
    SupportFile(
        "deploy/roles/systemd/tasks/operator_controls.yml",
        "deploy/roles/systemd/tasks/operator_controls.yml",
        "deploy/roles/systemd/tasks/operator_controls.yml",
        0o644,
    ),
    SupportFile(
        "deploy/roles/systemd/tasks/operator_credential.yml",
        "deploy/roles/systemd/tasks/operator_credential.yml",
        "deploy/roles/systemd/tasks/operator_credential.yml",
        0o644,
    ),
    SupportFile(
        "deploy/roles/guest_base/files/strugglebus-release-lock.py",
        "helpers/strugglebus-release-lock.py",
        "/usr/local/libexec/strugglebus-release-lock",
    ),
    SupportFile(
        "deploy/roles/guest_base/files/strugglebus-validate-release.py",
        "helpers/strugglebus-validate-release.py",
        "/usr/local/libexec/strugglebus-validate-release",
    ),
    SupportFile(
        "deploy/roles/guest_base/files/strugglebus-validate-backup.py",
        "helpers/strugglebus-validate-backup.py",
        "/usr/local/libexec/strugglebus-validate-backup",
    ),
    SupportFile(
        "deploy/roles/guest_base/files/strugglebus-inspect-access-freeze.py",
        "helpers/strugglebus-inspect-access-freeze.py",
        "/usr/local/libexec/strugglebus-inspect-access-freeze",
    ),
    SupportFile(
        "deploy/roles/guest_base/files/strugglebus-maintenance.py",
        "helpers/strugglebus-maintenance.py",
        "/usr/local/libexec/strugglebus-maintenance",
    ),
    SupportFile(
        "deploy/roles/guest_base/files/strugglebus-validate-maintenance-config.py",
        "helpers/strugglebus-validate-maintenance-config.py",
        "/usr/local/libexec/strugglebus-validate-maintenance-config",
    ),
    SupportFile(
        "deploy/files/strugglebus_inspector_contract.py",
        "helpers/strugglebus-inspector-contract.py",
        "/usr/local/libexec/strugglebus-inspector-contract",
    ),
    SupportFile(
        "deploy/roles/systemd/templates/sqlite_backup.py.j2",
        "helpers/strugglebus-sqlite-backup.py",
        "/usr/local/libexec/strugglebus-sqlite-backup",
    ),
)


class ReleaseBundleError(RuntimeError):
    """The release bundle is unsafe, malformed, or incompatible."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


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
            raise ReleaseBundleError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path, limit: int) -> tuple[dict[str, Any], bytes]:
    _safe_regular_file(path, limit)
    content = path.read_bytes()
    try:
        value = json.loads(
            content,
            object_pairs_hook=_unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ReleaseBundleError(f"non-finite JSON value: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseBundleError(f"{path.name} is not valid canonical JSON") from error
    if not isinstance(value, dict):
        raise ReleaseBundleError(f"{path.name} must contain one JSON object")
    if _canonical_json(value) != content:
        raise ReleaseBundleError(f"{path.name} is not canonically serialized")
    return value, content


def _require_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ReleaseBundleError(f"{label} has unexpected or missing fields")


def _require_string(
    value: Any,
    label: str,
    *,
    pattern: re.Pattern[str] | None = None,
    maximum: int = 512,
) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ReleaseBundleError(f"{label} is not a bounded non-empty string")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ReleaseBundleError(f"{label} has an invalid format")
    return value


def _require_integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReleaseBundleError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise ReleaseBundleError(f"{label} is outside its allowed range")
    return value


def _safe_regular_file(path: Path, maximum: int) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ReleaseBundleError(f"missing release asset: {path.name}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ReleaseBundleError(f"release asset is not a regular file: {path.name}")
    if metadata.st_nlink != 1:
        raise ReleaseBundleError(f"release asset has multiple hard links: {path.name}")
    if metadata.st_size > maximum:
        raise ReleaseBundleError(f"release asset exceeds its size limit: {path.name}")
    return metadata


def _canonical_directory(path: Path) -> Path:
    absolute = path.absolute()
    try:
        metadata = absolute.lstat()
    except FileNotFoundError as error:
        raise ReleaseBundleError("release bundle directory is missing") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseBundleError("release bundle path must be a canonical directory")
    resolved = absolute.resolve(strict=True)
    if resolved != absolute:
        raise ReleaseBundleError("release bundle path traverses a symbolic link")
    return resolved


# Accepted Python contracts: manifest python_requires -> (wheel Requires-Python,
# manifest tested_python). The 3.13-only contract is accepted ahead of use so
# deployed updaters can verify a later release that drops Python 3.12.
PYTHON_CONTRACTS: dict[str, tuple[str, list[str]]] = {
    ">=3.12,<3.14": ("<3.14,>=3.12", ["3.12", "3.13"]),
    ">=3.13,<3.14": ("<3.14,>=3.13", ["3.13"]),
}


def _read_wheel_metadata(wheel: Path) -> Message:
    with zipfile.ZipFile(wheel) as archive:
        metadata_names = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_names) != 1:
            raise ReleaseBundleError("wheel must contain exactly one METADATA file")
        info = archive.getinfo(metadata_names[0])
        if info.file_size > MAX_MANIFEST_BYTES:
            raise ReleaseBundleError("wheel METADATA exceeds its size limit")
        with archive.open(info) as stream:
            return BytesParser().parsebytes(stream.read(MAX_MANIFEST_BYTES + 1))


def _expected_requires_python(metadata: Message, python_requires: str | None) -> str | None:
    """The wheel constraint the manifest demands, or any recognised one when it is silent."""
    if python_requires is not None:
        return PYTHON_CONTRACTS[python_requires][0]
    accepted = {wheel_value for wheel_value, _ in PYTHON_CONTRACTS.values()}
    requires = metadata.get("Requires-Python")
    return requires if requires in accepted else None


def _wheel_metadata(wheel: Path, python_requires: str | None = None) -> dict[str, str]:
    _safe_regular_file(wheel, MAX_ASSET_BYTES)
    metadata = _read_wheel_metadata(wheel)
    requires = _expected_requires_python(metadata, python_requires)
    required = {
        "Name": "strugglebus",
        "Version": wheel.name.split("-")[1],
        "Requires-Python": requires,
    }
    for key, expected in required.items():
        if expected is None or metadata.get(key) != expected:
            raise ReleaseBundleError(f"wheel metadata has unexpected {key}")
    expected_name = f"strugglebus-{required['Version']}-py3-none-any.whl"
    if wheel.name != expected_name:
        raise ReleaseBundleError("wheel filename is not the canonical pure-Python name")
    return required


def _validate_checksums(directory: Path, expected_names: set[str]) -> None:
    path = directory / CHECKSUMS_NAME
    _safe_regular_file(path, MAX_CHECKSUMS_BYTES)
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ReleaseBundleError("SHA256SUMS must be ASCII") from error
    entries: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,127})", line)
        if match is None:
            raise ReleaseBundleError("SHA256SUMS contains a malformed line")
        digest, name = match.groups()
        if name in entries:
            raise ReleaseBundleError("SHA256SUMS contains a duplicate asset")
        entries[name] = digest
    if set(entries) != expected_names:
        raise ReleaseBundleError("SHA256SUMS has unexpected or missing assets")
    if list(entries) != sorted(entries):
        raise ReleaseBundleError("SHA256SUMS is not sorted")
    for name, expected in entries.items():
        if _sha256(directory / name) != expected:
            raise ReleaseBundleError(f"checksum mismatch: {name}")


def _validate_support_archive(
    archive_path: Path,
    manifest_files: list[dict[str, Any]],
) -> None:
    _validate_support_expansion(archive_path)
    expected = {item.archive: item for item in SUPPORT_FILES}
    manifest_by_archive = {
        _require_string(entry.get("archive_path"), "helper archive path"): entry
        for entry in manifest_files
    }
    present = set(manifest_by_archive)
    if len(present) != len(manifest_files) or present != set(expected):
        raise ReleaseBundleError("manifest helper set is incomplete or unexpected")
    with tarfile.open(archive_path, mode="r:gz") as archive:
        members = _bounded_support_members(archive)
        _support_member_names(members, present)
        for member in members:
            _validate_support_header(member)
            if member.name == SUPPORT_INDEX_NAME:
                continue
            definition = expected[member.name]
            entry = manifest_by_archive[member.name]
            _validate_support_entry(entry, definition, member)
            _validate_support_payload(archive, member, entry)
        index_member = archive.getmember(SUPPORT_INDEX_NAME)
        index_stream = archive.extractfile(index_member)
        if index_stream is None:
            raise ReleaseBundleError("support archive index is unavailable")
        expected_index = _canonical_json(
            {
                "files": manifest_files,
                "support_manifest_version": 1,
            }
        )
        if index_stream.read(MAX_MANIFEST_BYTES + 1) != expected_index:
            raise ReleaseBundleError("support archive index does not match the manifest")


def _support_member_names(members: list[tarfile.TarInfo], expected: set[str]) -> None:
    names = [member.name for member in members]
    if len(names) != len(set(names)):
        raise ReleaseBundleError("support archive contains duplicate paths")
    if set(names) != {*expected, SUPPORT_INDEX_NAME}:
        raise ReleaseBundleError("support archive has unexpected or missing files")


def _validate_support_expansion(path: Path) -> None:
    # Bound decompression before tarfile parses extension headers or member sizes.
    maximum = MAX_ASSET_BYTES + (len(SUPPORT_FILES) + 1) * 1024 + 10240
    total = 0
    with gzip.open(path, "rb") as stream:
        while chunk := stream.read(64 * 1024):
            total += len(chunk)
            if total > maximum:
                raise ReleaseBundleError("support archive exceeds its expanded limits")


def _bounded_support_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members: list[tarfile.TarInfo] = []
    total = 0
    for member in archive:
        members.append(member)
        total += member.size
        if len(members) > len(SUPPORT_FILES) + 1 or total > MAX_ASSET_BYTES:
            raise ReleaseBundleError("support archive exceeds its expanded limits")
        if member.size < 0:
            raise ReleaseBundleError("support archive has an invalid member size")
        if member.name == SUPPORT_INDEX_NAME and member.size > MAX_MANIFEST_BYTES:
            raise ReleaseBundleError("support archive index exceeds its size limit")
    return members


def _version_tuple(version: str) -> tuple[int, int, int]:
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ReleaseBundleError("package version is not a numeric three-part version")
    return tuple(int(part) for part in version.split("."))  # type: ignore[return-value]


def validate_bundle(
    directory: Path,
    *,
    expected_repository: str = REPOSITORY_ID,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
    expected_current_schema: int = CURRENT_SCHEMA,
    required_protocol: int = COORDINATION_PROTOCOL_VERSION,
    required_capability: str = f"agent-access-freeze:{ACCESS_FREEZE_CAPABILITY}",
    minimum_package_version: str | None = None,
    accept_newer_schema: bool = False,
    statement_beside: bool = False,
) -> dict[str, Any]:
    directory = _canonical_directory(directory)
    manifest_path = directory / MANIFEST_NAME
    manifest, _ = _read_json(manifest_path, MAX_MANIFEST_BYTES)
    package, release, compatibility, protocol, build, consumption, deployment_support = _manifest_sections(manifest)

    version = _validate_package(package, minimum_package_version)

    tag, commit, tree = _validate_source(release, version, expected_repository, expected_tag, expected_commit, expected_tree)

    _validate_compatibility(compatibility, expected_current_schema, accept_newer_schema)
    python_requires = compatibility["python_requires"]

    _validate_protocol(protocol, required_protocol, required_capability, accept_newer_schema)

    uv = _validate_build(build, python_requires)

    _validate_consumption(consumption)

    asset_names, asset_map = _validate_manifest_assets(manifest, directory)

    expected_payloads, wheel_name, support_name = _validate_payloads(
        version, asset_names, asset_map, directory, python_requires,
    )

    _validate_support(deployment_support, directory, support_name)

    expected_release_assets = _validate_release_files(
        consumption, expected_payloads, directory, statement_beside,
    )

    release_asset_facts = _release_asset_facts(expected_release_assets, directory)

    return {
        "authenticity": "authenticated-github-acquisition-required",
        "integrity": "sha256-verified",
        "manifest": str(manifest_path),
        "package_version": version,
        "release_assets": release_asset_facts,
        "release_version": tag,
        "requirements_lock_sha256": asset_map["requirements.lock"]["sha256"],
        "requirements_lock_src": str(directory / "requirements.lock"),
        "source_commit": commit,
        "source_tree": tree,
        "tag": tag,
        "uv_binary_sha256": uv["binary_sha256"],
        "wheel_sha256": asset_map[wheel_name]["sha256"],
        "wheel_src": str(directory / wheel_name),
    }


def _manifest_sections(manifest: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    _require_keys(
        manifest,
        {
            "assets",
            "build",
            "compatibility",
            "consumption",
            "deployment_support",
            "manifest_version",
            "package",
            "protocol",
            "release",
        },
        "release manifest",
    )
    if type(manifest["manifest_version"]) is not int or manifest["manifest_version"] != MANIFEST_VERSION:
        raise ReleaseBundleError("unsupported release manifest version")

    package = manifest["package"]
    release = manifest["release"]
    compatibility = manifest["compatibility"]
    protocol = manifest["protocol"]
    build = manifest["build"]
    consumption = manifest["consumption"]
    deployment_support = manifest["deployment_support"]
    for value, label in (
        (package, "package"),
        (release, "release"),
        (compatibility, "compatibility"),
        (protocol, "protocol"),
        (build, "build"),
        (consumption, "consumption"),
        (deployment_support, "deployment support"),
    ):
        if not isinstance(value, dict):
            raise ReleaseBundleError(f"{label} must be an object")

    return package, release, compatibility, protocol, build, consumption, deployment_support


def _validate_package(package: dict[str, Any], minimum_package_version: str | None) -> str:
    _require_keys(package, {"name", "version", "wheel_tag"}, "package")
    version = _require_string(package["version"], "package version", pattern=VERSION_PATTERN)
    if version in DISQUALIFIED_PRODUCTION_VERSIONS:
        raise ReleaseBundleError(
            f"package version {version} is disqualified for production deployment"
        )
    if package != {
        "name": "strugglebus",
        "version": version,
        "wheel_tag": "py3-none-any",
    }:
        raise ReleaseBundleError("package identity is unsupported")
    if minimum_package_version is not None and (
        _version_tuple(version) < _version_tuple(minimum_package_version)
    ):
        raise ReleaseBundleError("release package version is a downgrade")

    return version


def _validate_source(
    release: dict[str, Any], version: str, expected_repository: str,
    expected_tag: str | None, expected_commit: str | None, expected_tree: str | None,
) -> tuple[str, str, str]:
    _require_keys(
        release,
        {"candidate_id", "repository", "source_commit", "source_tree", "tag"},
        "release",
    )
    repository = _require_string(release["repository"], "release repository")
    tag = _require_string(release["tag"], "release tag", pattern=TAG_PATTERN)
    commit = _require_string(release["source_commit"], "source commit", pattern=SHA1_PATTERN)
    tree = _require_string(release["source_tree"], "source tree", pattern=SHA1_PATTERN)
    expected_candidate = f"{repository}@{tag}:{commit}:{tree}"
    if (
        _require_string(release["candidate_id"], "release candidate", maximum=256)
        != expected_candidate
    ):
        raise ReleaseBundleError("release candidate identity is inconsistent")
    if repository != expected_repository:
        raise ReleaseBundleError("release repository identity mismatch")
    if TAG_PATTERN.fullmatch(tag).group("version") != version:  # type: ignore[union-attr]
        raise ReleaseBundleError("release tag and package version differ")
    _validate_expected_source(tag, commit, tree, expected_tag, expected_commit, expected_tree)
    return tag, commit, tree


def _validate_expected_source(
    tag: str, commit: str, tree: str,
    expected_tag: str | None, expected_commit: str | None, expected_tree: str | None,
) -> None:
    """Pin the release to whichever identities the caller already knows."""
    if expected_tag is not None and tag != expected_tag:
        raise ReleaseBundleError("release tag mismatch")
    if expected_commit is not None and commit != expected_commit:
        raise ReleaseBundleError("release source commit mismatch")
    if expected_tree is not None and tree != expected_tree:
        raise ReleaseBundleError("release source tree mismatch")


def _validate_compatibility(
    compatibility: dict[str, Any], expected_current_schema: int, accept_newer_schema: bool = False,
) -> None:
    _require_keys(compatibility, {"database", "python_requires"}, "compatibility")
    database = compatibility["database"]
    if not isinstance(database, dict):
        raise ReleaseBundleError("database compatibility must be an object")
    _require_keys(
        database,
        {
            "current_schema",
            "downgrade_supported",
            "minimum_upgrade_schema",
            "requires_verified_pre_migration_backup",
            "rollback_previous_schema",
            "rollback_strategy",
        },
        "database compatibility",
    )
    # An installed verifier may accept any number of forward migrations: the
    # candidate applies them in order at startup, after the maintenance helper
    # takes a verified snapshot at our schema, so rollback restores that
    # snapshot. Each release still declares its own predecessor schema.
    accepted = [(expected_current_schema, ROLLBACK_PREVIOUS_SCHEMA)]
    current = database.get("current_schema")
    if (
        accept_newer_schema and type(current) is int
        and expected_current_schema < current <= MAX_SCHEMA
    ):
        accepted.append((current, current - 1))
    if not any(_canonical_json(database) == _canonical_json({
        "current_schema": current,
        "downgrade_supported": False,
        "minimum_upgrade_schema": MINIMUM_UPGRADE_SCHEMA,
        "requires_verified_pre_migration_backup": True,
        "rollback_previous_schema": rollback,
        "rollback_strategy": "restore-verified-backup-and-select-compatible-release",
    }) for current, rollback in accepted):
        raise ReleaseBundleError("database schema compatibility is unsupported")
    if (type(compatibility["python_requires"]) is not str
            or compatibility["python_requires"] not in PYTHON_CONTRACTS):
        raise ReleaseBundleError("Python compatibility is unsupported")



def _guide_parts(value: Any) -> tuple[int, int, int] | None:
    if type(value) is not str or _GUIDE_VERSION_PATTERN.fullmatch(value) is None:
        return None
    major, minor, patch = (int(part) for part in value.split("."))
    return major, minor, patch


def _guide_accepted(value: Any, accept_additive: bool) -> bool:
    if value == GUIDE_VERSION:
        return True
    candidate, installed = _guide_parts(value), _guide_parts(GUIDE_VERSION)
    return (
        accept_additive and candidate is not None and installed is not None
        and candidate[0] == installed[0] and candidate > installed
    )


def _validate_protocol(
    protocol: dict[str, Any], required_protocol: int, required_capability: str,
    accept_additive_guide: bool = False,
) -> None:
    _require_keys(
        protocol,
        {
            "capabilities",
            "coordination_protocol_version",
            "integration_guide_version",
        },
        "protocol",
    )
    if (type(protocol["coordination_protocol_version"]) is not int
            or protocol["coordination_protocol_version"] != required_protocol):
        raise ReleaseBundleError("coordination protocol is incompatible")
    if not _guide_accepted(protocol["integration_guide_version"], accept_additive_guide):
        raise ReleaseBundleError("integration guide is incompatible")
    if protocol["capabilities"] != [required_capability]:
        raise ReleaseBundleError("required release capability is missing")



def _validate_build(build: dict[str, Any], python_requires: str) -> dict[str, Any]:
    _require_keys(build, {"build_python", "tested_python", "uv"}, "build")
    if (build["build_python"] != "3.13"
            or build["tested_python"] != PYTHON_CONTRACTS[python_requires][1]):
        raise ReleaseBundleError("build or test Python identity is incompatible")
    uv = build["uv"]
    if not isinstance(uv, dict):
        raise ReleaseBundleError("uv runtime identity must be an object")
    _require_keys(
        uv,
        {"archive_sha256", "binary_sha256", "platform", "version"},
        "uv runtime",
    )
    if (
        uv["version"] != UV_VERSION
        or uv["platform"] != "x86_64-unknown-linux-gnu"
        or uv["archive_sha256"] != UV_ARCHIVE_SHA256
        or not isinstance(uv["binary_sha256"], str)
        or SHA256_PATTERN.fullmatch(uv["binary_sha256"]) is None
    ):
        raise ReleaseBundleError("uv runtime identity is incompatible")

    return uv


def _validate_consumption(consumption: dict[str, Any]) -> None:
    _require_keys(
        consumption,
        {
            "authenticated_github_acquisition_required",
            "immutable_github_release_required",
            "offline_publisher_authenticity",
            "offline_verification",
            "release_assets",
        },
        "consumption",
    )
    if (
        consumption["authenticated_github_acquisition_required"] is not True
        or consumption["immutable_github_release_required"] is not True
        or consumption["offline_publisher_authenticity"] is not False
        or consumption["offline_verification"] != "sha256-integrity-only"
    ):
        raise ReleaseBundleError("release consumption policy is unsafe")



def _validate_manifest_assets(
    manifest: dict[str, Any], directory: Path,
) -> tuple[set[str], dict[str, dict[str, Any]]]:
    assets = manifest["assets"]
    if not isinstance(assets, list) or not 1 <= len(assets) <= 16:
        raise ReleaseBundleError("manifest assets must be a bounded list")
    asset_names: set[str] = set()
    asset_map: dict[str, dict[str, Any]] = {}
    for entry in assets:
        name = _manifest_asset_shape(entry)
        if name in asset_names:
            raise ReleaseBundleError("manifest contains duplicate assets")
        asset_names.add(name)
        asset_map[name] = entry
        digest = _require_string(entry["sha256"], "asset SHA-256", pattern=SHA256_PATTERN)
        size = _require_integer(entry["size_bytes"], "asset size", 1, MAX_ASSET_BYTES)
        path = directory / name
        metadata = _safe_regular_file(path, MAX_ASSET_BYTES)
        if metadata.st_size != size or _sha256(path) != digest:
            raise ReleaseBundleError(f"asset size or digest mismatch: {name}")
    if [entry["name"] for entry in assets] != sorted(asset_names):
        raise ReleaseBundleError("manifest assets are not sorted")

    return asset_names, asset_map


def _validate_payloads(
    version: str, asset_names: set[str], asset_map: dict[str, dict[str, Any]], directory: Path,
    python_requires: str,
) -> tuple[set[str], str, str]:
    wheel_name = f"strugglebus-{version}-py3-none-any.whl"
    support_name = SUPPORT_NAME_TEMPLATE.format(version=version)
    expected_payloads = {wheel_name, "requirements.lock", support_name}
    if asset_names != expected_payloads:
        raise ReleaseBundleError("manifest payload set is incomplete or unexpected")
    expected_asset_metadata = {
        wheel_name: (
            "application/vnd.python.wheel",
            "application-wheel",
        ),
        "requirements.lock": (
            "text/plain",
            "hash-locked-production-requirements",
        ),
        support_name: (
            "application/gzip",
            "reviewed-deployment-support",
        ),
    }
    for name, (media_type, purpose) in expected_asset_metadata.items():
        if (
            asset_map[name]["media_type"] != media_type
            or asset_map[name]["purpose"] != purpose
        ):
            raise ReleaseBundleError(f"manifest asset purpose is invalid: {name}")
    try:
        verify_canonical_wheel(directory / wheel_name)
    except CanonicalWheelError as error:
        raise ReleaseBundleError(f"release wheel is not canonical: {error}") from error
    _wheel_metadata(directory / wheel_name, python_requires)
    validate_requirements_lock(directory / "requirements.lock")

    return expected_payloads, wheel_name, support_name


def _validate_support(deployment_support: dict[str, Any], directory: Path, support_name: str) -> None:
    _require_keys(
        deployment_support,
        {"files", "support_manifest_version"},
        "deployment support",
    )
    if type(deployment_support["support_manifest_version"]) is not int or deployment_support["support_manifest_version"] != 1:
        raise ReleaseBundleError("unsupported deployment support manifest")
    helper_files = deployment_support["files"]
    if not isinstance(helper_files, list) or len(helper_files) != len(SUPPORT_FILES):
        raise ReleaseBundleError("deployment helper list is incomplete")
    _validate_support_archive(directory / support_name, helper_files)



def _names_beside(directory: Path, statement_beside: bool) -> set[str]:
    """What is in the release's folder, leaving out the signed statement where one is expected."""
    names = {entry.name for entry in directory.iterdir() if entry.name not in {".", ".."}}
    return names - {STATEMENT_NAME} if statement_beside else names


def _validate_release_files(
    consumption: dict[str, Any], expected_payloads: set[str], directory: Path,
    statement_beside: bool = False,
) -> list[str]:
    release_assets = consumption["release_assets"]
    expected_release_assets = sorted(
        {*expected_payloads, MANIFEST_NAME, CHECKSUMS_NAME}
    )
    if release_assets != expected_release_assets:
        raise ReleaseBundleError("release asset allowlist is inconsistent")
    actual_names = _names_beside(directory, statement_beside)
    if actual_names != set(expected_release_assets):
        raise ReleaseBundleError("release directory has missing or unexpected assets")
    for name in actual_names:
        maximum = (
            MAX_MANIFEST_BYTES
            if name == MANIFEST_NAME
            else MAX_CHECKSUMS_BYTES
            if name == CHECKSUMS_NAME
            else MAX_LOCK_BYTES
            if name == "requirements.lock"
            else MAX_ASSET_BYTES
        )
        _safe_regular_file(directory / name, maximum)
    _validate_checksums(directory, {*expected_payloads, MANIFEST_NAME})

    return expected_release_assets


def _release_asset_facts(expected_release_assets: list[str], directory: Path) -> list[dict[str, Any]]:
    release_asset_facts = []
    for name in sorted(expected_release_assets):
        path = directory / name
        release_asset_facts.append(
            {
                "name": name,
                "sha256": _sha256(path),
                "size_bytes": path.stat().st_size,
            }
        )

    return release_asset_facts


def _validate_support_header(member: tarfile.TarInfo) -> None:
    path = PurePosixPath(member.name)
    if path.is_absolute() or ".." in path.parts or "\\" in member.name:
        raise ReleaseBundleError("support archive contains an unsafe path")
    if not member.isfile() or member.islnk() or member.issym():
        raise ReleaseBundleError("support archive contains a non-regular member")
    if member.uid != 0 or member.gid != 0:
        raise ReleaseBundleError("support archive ownership is not normalized")


def _validate_support_entry(entry: dict[str, Any], definition: SupportFile, member: tarfile.TarInfo) -> None:
    _require_keys(
        entry,
        {
            "archive_path",
            "destination",
            "mode",
            "sha256",
            "size_bytes",
            "source_path",
        },
        "deployment helper",
    )
    if entry["source_path"] != definition.source:
        raise ReleaseBundleError("deployment helper source path mismatch")
    if entry["destination"] != definition.destination:
        raise ReleaseBundleError("deployment helper destination mismatch")
    if entry["mode"] != f"{definition.mode:04o}" or member.mode != definition.mode:
        raise ReleaseBundleError("deployment helper mode mismatch")
    _require_string(
        entry["sha256"],
        "deployment helper SHA-256",
        pattern=SHA256_PATTERN,
    )
    _require_integer(
        entry["size_bytes"],
        "deployment helper size",
        1,
        MAX_ASSET_BYTES,
    )


def _validate_support_payload(archive: tarfile.TarFile, member: tarfile.TarInfo, entry: dict[str, Any]) -> None:
    content = archive.extractfile(member)
    if content is None:
        raise ReleaseBundleError("deployment helper content is unavailable")
    payload = content.read(MAX_ASSET_BYTES + 1)
    if len(payload) != entry["size_bytes"] or member.size != entry["size_bytes"]:
        raise ReleaseBundleError("deployment helper size mismatch")
    if _sha256_bytes(payload) != entry["sha256"]:
        raise ReleaseBundleError("deployment helper digest mismatch")


def _manifest_asset_shape(entry: Any) -> str:
    if not isinstance(entry, dict):
        raise ReleaseBundleError("manifest asset must be an object")
    _require_keys(
        entry,
        {"media_type", "name", "purpose", "sha256", "size_bytes"},
        "manifest asset",
    )
    name = _require_string(entry["name"], "asset name", maximum=128)
    _require_string(entry["media_type"], "asset media type", maximum=128)
    _require_string(entry["purpose"], "asset purpose", maximum=128)
    if PurePosixPath(name).name != name or "\\" in name:
        raise ReleaseBundleError("asset name must be a safe basename")

    return name
