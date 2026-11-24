from __future__ import annotations

from copy import deepcopy
import io
import gzip
import json
from pathlib import Path
import stat
import tarfile
import zipfile

import pytest

from strugglebus import release_validation as bundle, release_wheel as wheel, release_lock as lock
from test_update_source import publication, VERSION, TAG, COMMIT, TREE


def rewrite(directory, transform):
    path = directory / bundle.MANIFEST_NAME
    manifest = json.loads(path.read_bytes())
    transform(manifest)
    path.write_bytes(bundle._canonical_json(manifest))


def set_nested(document, path, value):
    for key in path[:-1]:
        document = document[key]
    document[path[-1]] = value


@pytest.mark.parametrize("path,value,reason", [
    (("manifest_version",), 2, "manifest version"),
    (("manifest_version",), True, "manifest version"),
    (("package",), [], "package must"),
    (("package", "name"), "other", "package identity"),
    (("package", "version"), "0.2.5", "disqualified"),
    (("package", "version"), "0.2.28", "disqualified"),
    (("package", "version"), "0.2.31", "disqualified"),
    (("package", "version"), "0.2.32", "disqualified"),
    (("package", "version"), "0.2.33", "disqualified"),
    (("package", "version"), "0.2.34", "disqualified"),
    (("package", "version"), "not-a-version", "invalid format"),
    (("package", "version"), "", "bounded"),
    (("release", "repository"), "Other/repository", "candidate identity"),
    (("release", "candidate_id"), "unbound", "candidate identity"),
    (("compatibility", "database"), [], "must be an object"),
    (("compatibility", "database", "current_schema"), 25, "schema compatibility"),
    (("compatibility", "database", "minimum_upgrade_schema"), True, "schema compatibility"),
    (("protocol", "coordination_protocol_version"), True, "protocol"),
    (("build", "uv"), [], "must be an object"),
    (("build", "uv", "binary_sha256"), "invalid", "uv runtime"),
    (("build", "uv", "version"), "9.9.9", "uv runtime"),
    (("consumption", "authenticated_github_acquisition_required"), False, "consumption policy"),
    (("assets",), [], "bounded list"),
    (("assets", 0), "not-an-object", "must be an object"),
    (("assets", 0, "name"), "../unsafe", "safe basename"),
    (("assets", 0, "size_bytes"), True, "must be an integer"),
    (("assets", 0, "size_bytes"), 0, "allowed range"),
    (("deployment_support", "support_manifest_version"), 2, "support manifest"),
    (("deployment_support", "support_manifest_version"), True, "support manifest"),
    (("deployment_support", "files"), [], "helper list"),
    (("deployment_support", "files", 0, "source_path"), "wrong", "source path"),
    (("deployment_support", "files", 0, "destination"), "wrong", "destination"),
    (("deployment_support", "files", 0, "mode"), "0777", "mode mismatch"),
    (("deployment_support", "files", 0, "sha256"), "0" * 64, "digest mismatch"),
    (("deployment_support", "files", 0, "size_bytes"), 1, "size mismatch"),
    (("consumption", "release_assets"), [], "allowlist"),
])
def test_shared_manifest_validation_blocks_malformed_or_unknown_policy(publication, path, value, reason):
    rewrite(publication, lambda manifest: set_nested(manifest, path, value))
    with pytest.raises(bundle.ReleaseBundleError, match=reason):
        bundle.validate_bundle(publication)


@pytest.mark.parametrize("operation,reason", [
    (lambda manifest: manifest.pop("build"), "fields"),
    (lambda manifest: manifest["assets"].append(manifest["assets"][0]), "duplicate assets"),
    (lambda manifest: manifest["assets"].reverse(), "not sorted"),
    (lambda manifest: manifest["assets"].pop(), "payload set"),
    (lambda manifest: manifest["assets"][0].update(purpose="wrong"), "purpose"),
    (lambda manifest: manifest["deployment_support"]["files"][0].update(archive_path="unknown"), "helper set"),
])
def test_manifest_set_and_sort_contracts(publication, operation, reason):
    rewrite(publication, operation)
    with pytest.raises(bundle.ReleaseBundleError, match=reason):
        bundle.validate_bundle(publication)


def test_source_bindings_are_independently_checked(publication):
    for arguments in ({"expected_repository": "wrong"}, {"expected_tag": "v0.2.99"},
                      {"expected_commit": "9" * 40}, {"expected_tree": "9" * 40}):
        with pytest.raises(bundle.ReleaseBundleError):
            bundle.validate_bundle(publication, **arguments)


@pytest.mark.parametrize("python_requires,tested,reason", [
    (">=3.11,<3.14", ["3.12", "3.13"], "Python compatibility"),
    ([">=3.13,<3.14"], ["3.13"], "Python compatibility"),
    (">=3.13,<3.14", ["3.12", "3.13"], "test Python identity"),
    (">=3.12,<3.14", ["3.13"], "test Python identity"),
    # A consistent legacy 3.12 manifest still needs a matching wheel.
    (">=3.12,<3.14", ["3.12", "3.13"], "Requires-Python"),
])
def test_python_contract_must_be_one_consistent_accepted_pair(publication, python_requires, tested, reason):
    def transform(manifest):
        manifest["compatibility"]["python_requires"] = python_requires
        manifest["build"]["tested_python"] = tested
    rewrite(publication, transform)
    with pytest.raises(bundle.ReleaseBundleError, match=reason):
        bundle.validate_bundle(publication)


def test_json_and_checksum_parsers_fail_closed(publication):
    manifest = publication / bundle.MANIFEST_NAME
    for payload in (b"[]", b"{invalid", b'{"a":NaN}', b'{}'):
        manifest.write_bytes(payload)
        with pytest.raises(bundle.ReleaseBundleError):
            bundle._read_json(manifest, bundle.MAX_MANIFEST_BYTES)
    path = publication / bundle.CHECKSUMS_NAME
    for payload in (b"\xff", b"not a checksum", b"0" * 64 + b"  a\n" + b"0" * 64 + b"  a\n",
                    b"0" * 64 + b"  b\n" + b"0" * 64 + b"  a\n"):
        path.write_bytes(payload)
        with pytest.raises(bundle.ReleaseBundleError):
            bundle._validate_checksums(publication, {"a", "b"})


def test_file_and_directory_bounds(tmp_path):
    path = tmp_path / "file"
    with pytest.raises(bundle.ReleaseBundleError):
        bundle._safe_regular_file(path, 5)
    path.write_bytes(b"123456")
    with pytest.raises(bundle.ReleaseBundleError):
        bundle._safe_regular_file(path, 5)
    with pytest.raises(bundle.ReleaseBundleError):
        bundle._safe_regular_file(tmp_path, 5)
    with pytest.raises(bundle.ReleaseBundleError):
        bundle._canonical_directory(path)
    with pytest.raises(bundle.ReleaseBundleError):
        bundle._canonical_directory(tmp_path / "missing")
    with pytest.raises(bundle.ReleaseBundleError):
        bundle._version_tuple("invalid")


@pytest.mark.parametrize("name,kind,uid", [("../escape", tarfile.REGTYPE, 0),
                                         ("safe", tarfile.SYMTYPE, 0),
                                         ("safe", tarfile.LNKTYPE, 0),
                                         ("safe", tarfile.REGTYPE, 1)])
def test_archive_traversal_links_and_noncanonical_owner_are_rejected(name, kind, uid):
    info = tarfile.TarInfo(name)
    info.type, info.uid = kind, uid
    with pytest.raises(bundle.ReleaseBundleError):
        bundle._validate_support_header(info)


def test_archive_expansion_limits_are_enforced_before_payload_reads():
    cases = [
        [tarfile.TarInfo(str(i)) for i in range(len(bundle.SUPPORT_FILES) + 2)],
        [tarfile.TarInfo("giant")],
        [tarfile.TarInfo(bundle.SUPPORT_INDEX_NAME)],
        [tarfile.TarInfo("negative")],
    ]
    cases[1][0].size = bundle.MAX_ASSET_BYTES + 1
    cases[2][0].size = bundle.MAX_MANIFEST_BYTES + 1
    cases[3][0].size = -1
    for members in cases:
        with pytest.raises(bundle.ReleaseBundleError):
            bundle._bounded_support_members(members)
    with pytest.raises(bundle.ReleaseBundleError, match="duplicate"):
        bundle._support_member_names([tarfile.TarInfo("a"), tarfile.TarInfo("a")], {})
    with pytest.raises(bundle.ReleaseBundleError, match="unexpected"):
        bundle._support_member_names([], {})


def test_compressed_archive_bomb_is_rejected_before_tar_header_parsing(tmp_path, monkeypatch):
    path = tmp_path / "bomb.tar.gz"
    with gzip.open(path, "wb") as stream:
        stream.write(b"\0" * (100 * 1024))
    monkeypatch.setattr(bundle, "MAX_ASSET_BYTES", 1024)
    monkeypatch.setattr(bundle.tarfile, "open", lambda *args, **kwargs: pytest.fail("parsed oversized archive"))
    with pytest.raises(bundle.ReleaseBundleError, match="expanded limits"):
        bundle._validate_support_archive(path, [])


@pytest.mark.parametrize("field,value", [("create_system", 0), ("create_version", 1),
                                       ("extract_version", 1), ("flag_bits", 1),
                                       ("internal_attr", 1), ("extra", b"bad"),
                                       ("comment", b"bad"), ("compress_type", zipfile.ZIP_STORED)])
def test_canonical_wheel_metadata_cannot_be_weakened(field, value):
    info = wheel._canonical_info("safe.py", (2020, 1, 1, 0, 0, 0))
    setattr(info, field, value)
    with pytest.raises(wheel.CanonicalWheelError):
        wheel._verify_member_metadata(info)


def test_wheel_member_limits_and_header_types():
    for mutation in ({"file_size": wheel.MAX_MEMBER_BYTES + 1},
                     {"compress_type": 12}, {"external_attr": stat.S_IFDIR << 16},
                     {"create_system": 0, "external_attr": 0x10},
                     {"external_attr": (stat.S_IFREG | stat.S_ISUID) << 16}):
        info = wheel._canonical_info("safe.py", (2020, 1, 1, 0, 0, 0))
        for key, value in mutation.items():
            setattr(info, key, value)
        with pytest.raises(wheel.CanonicalWheelError):
            wheel._require_regular_member(info)
    with pytest.raises(wheel.CanonicalWheelError):
        wheel._date_time_epoch((2020,))
    with pytest.raises(wheel.CanonicalWheelError):
        wheel._date_time_epoch((2020, 99, 99, 0, 0, 0))


def test_wheel_file_failures_are_bounded(tmp_path):
    missing = tmp_path / "absent.whl"
    with pytest.raises(wheel.CanonicalWheelError):
        wheel._load(missing)
    missing.write_bytes(b"invalid zip")
    with pytest.raises(wheel.CanonicalWheelError):
        wheel._load(missing)
    missing.write_bytes(b"")
    with pytest.raises(wheel.CanonicalWheelError):
        wheel._safe_regular_file(missing)
    with pytest.raises(wheel.CanonicalWheelError):
        wheel._safe_regular_file(tmp_path)


def test_record_parser_rejects_overlong_nontext_and_malformed_rows():
    name = "strugglebus-1.0.0.dist-info/RECORD"
    for payload in (b"x" * (wheel.MAX_RECORD_BYTES + 1), b"\xff", b"\x00", b"only-one-column\n"):
        with pytest.raises(wheel.CanonicalWheelError):
            wheel._validate_record({name: payload}, [name])
    with pytest.raises(wheel.CanonicalWheelError):
        wheel._validate_record_hash("safe", "not-sha256", "1", b"x")
    with pytest.raises(wheel.CanonicalWheelError):
        wheel._record_name([])


def test_lock_size_nul_and_continuations(tmp_path, monkeypatch):
    path = tmp_path / "lock"
    for content in ("\x00", "  --hash=sha256:" + "0" * 64, "", "# only a comment"):
        path.write_text(content)
        with pytest.raises(RuntimeError):
            lock.validate_requirements_lock(path)
    monkeypatch.setattr(lock, "MAX_LOCK_BYTES", 1)
    path.write_text("too large")
    with pytest.raises(RuntimeError):
        lock.validate_requirements_lock(path)
