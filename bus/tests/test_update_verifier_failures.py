"""Focused adversarial failures across the installed read-side boundary."""

from __future__ import annotations

from dataclasses import replace
import io
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import urllib.request
import zipfile

import pytest

from release_fixtures import load_script, write_wheel
from strugglebus import release_records as records, release_transport as redirects
from strugglebus import release_validation as validation, release_wheel as wheel
from strugglebus import update_source as source, update_transport as transport
from strugglebus.update_types import UpdateError, UpdateLimits
from test_update_source import (
    COMMIT, TAG, VERSION, Response, fixture_api as fixture_api,
    publication as publication,
)
from test_update_transport import Opener, http as http


@pytest.mark.parametrize("value", [True, 0, -1, "1"])
def test_publisher_primitive_rejects_nonpositive_ids(value):
    with pytest.raises(records.ReleasePublicationError):
        records._positive_id(value, "synthetic")


def test_shared_release_records_reject_unknown_state_media_and_incomplete_set(tmp_path):
    with pytest.raises(records.ReleasePublicationError):
        records._asset_media_type("unexpected")
    release = {"id": 1, "tag_name": TAG, "target_commitish": COMMIT, "name": TAG,
               "body": records._release_body(TAG), "draft": True, "immutable": True, "prerelease": False}
    with pytest.raises(records.ReleasePublicationError, match="invalid draft/immutable"):
        records._validate_release_record(release, tag=TAG, commit=COMMIT)
    expected = records.LocalAsset("requirements.lock", tmp_path / "requirements.lock", 1, "0" * 64, "text/plain")
    with pytest.raises(records.ReleasePublicationError, match="incomplete"):
        records._validate_asset_records([], {expected.name: expected}, complete=True)


def test_shared_redirect_primitives_reject_controls_nonget_and_missing_media():
    with pytest.raises(redirects.ReleasePublicationError):
        redirects._url_characters(None, "static")
    with pytest.raises(redirects.ReleasePublicationError):
        redirects._exact_https_host("https://api.github.com/a b", allowed_hosts=frozenset({"api.github.com"}),
                                   error_message="static")
    request = urllib.request.Request("https://api.github.com/asset", data=b"not-a-read")
    with pytest.raises(redirects.ReleasePublicationError):
        redirects._AssetRedirects().redirect_request(
            request, None, 302, "", {}, "https://release-assets.githubusercontent.com/asset")
    assert redirects._response_media_type({}) == ""


def test_shared_regular_file_rejects_hardlinks(tmp_path):
    path = tmp_path / "file"
    path.write_bytes(b"safe")
    os.link(path, tmp_path / "second-link")
    with pytest.raises(validation.ReleaseBundleError, match="multiple hard links"):
        validation._safe_regular_file(path, 10)


def test_directory_resolution_cannot_traverse_replaced_ancestor(tmp_path, monkeypatch):
    original = Path.resolve
    monkeypatch.setattr(Path, "resolve", lambda path, **kwargs:
                        path / "changed" if path == tmp_path else original(path, **kwargs))
    with pytest.raises(validation.ReleaseBundleError, match="symbolic link"):
        validation._canonical_directory(tmp_path)


@pytest.mark.parametrize("kind", ["missing", "oversized", "identity", "filename"])
def test_wheel_metadata_presence_limit_identity_and_filename(tmp_path, kind):
    path = tmp_path / f"strugglebus-{VERSION}-{'wrong' if kind == 'filename' else 'py3-none-any'}.whl"
    content = (f"Name: {'other' if kind == 'identity' else 'strugglebus'}\nVersion: {VERSION}\n"
               "Requires-Python: <3.14,>=3.12\n").encode()
    with zipfile.ZipFile(path, "w") as archive:
        if kind != "missing":
            archive.writestr(f"strugglebus-{VERSION}.dist-info/METADATA",
                             b"x" * (validation.MAX_MANIFEST_BYTES + 1) if kind == "oversized" else content)
    with pytest.raises(validation.ReleaseBundleError):
        validation._wheel_metadata(path)


@pytest.mark.parametrize("contract,wheel_value,accepted", [
    (None, "<3.14,>=3.12", True),
    (None, "<3.14,>=3.13", True),
    (None, "<3.14,>=3.11", False),
    (">=3.12,<3.14", "<3.14,>=3.12", True),
    (">=3.12,<3.14", "<3.14,>=3.13", False),
    (">=3.13,<3.14", "<3.14,>=3.13", True),
    (">=3.13,<3.14", "<3.14,>=3.12", False),
])
def test_wheel_requires_python_must_match_the_manifest_contract(tmp_path, contract, wheel_value, accepted):
    path = tmp_path / f"strugglebus-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"strugglebus-{VERSION}.dist-info/METADATA",
                         f"Name: strugglebus\nVersion: {VERSION}\nRequires-Python: {wheel_value}\n")
    if accepted:
        assert validation._wheel_metadata(path, contract)["Requires-Python"] == wheel_value
    else:
        with pytest.raises(validation.ReleaseBundleError, match="Requires-Python"):
            validation._wheel_metadata(path, contract)


@pytest.mark.parametrize("kind", ["index-unavailable", "index-mismatch", "payload-unavailable"])
def test_support_extraction_failures_cannot_succeed(publication, monkeypatch, kind):
    manifest = json.loads((publication / validation.MANIFEST_NAME).read_bytes())
    original = validation.tarfile.TarFile.extractfile

    def unavailable(archive, member):
        if member.name == validation.SUPPORT_INDEX_NAME:
            if kind == "index-unavailable":
                return None
            if kind == "index-mismatch":
                return io.BytesIO(b"wrong index")
        elif kind == "payload-unavailable":
            return None
        return original(archive, member)

    monkeypatch.setattr(validation.tarfile.TarFile, "extractfile", unavailable)
    with pytest.raises(validation.ReleaseBundleError):
        validation._validate_support_archive(
            publication / validation.SUPPORT_NAME_TEMPLATE.format(version=VERSION),
            manifest["deployment_support"]["files"],
        )


def test_wheel_empty_members_and_archive_comment_are_forbidden(tmp_path):
    path = tmp_path / "empty.whl"
    with zipfile.ZipFile(path, "w"):
        pass
    with zipfile.ZipFile(path) as archive, pytest.raises(wheel.CanonicalWheelError, match="count"):
        wheel._read_members(archive)
    write_wheel(path, VERSION)
    with zipfile.ZipFile(path, "a") as archive:
        archive.comment = b"arbitrary"
    with zipfile.ZipFile(path) as archive, pytest.raises(wheel.CanonicalWheelError, match="comment"):
        wheel._read_members(archive)


def test_record_rows_reject_duplicate_and_missing_member():
    row = ["module.py", wheel._record_digest(b"x"), "1"]
    with pytest.raises(wheel.CanonicalWheelError, match="duplicate"):
        wheel._validate_record_row(row, {"module.py"}, {"module.py": b"x"}, "dist-info/RECORD")
    with pytest.raises(wheel.CanonicalWheelError, match="missing"):
        wheel._validate_record_row(row, set(), {}, "dist-info/RECORD")


def test_wheel_expanded_limits_and_truncated_member_reads(tmp_path, monkeypatch):
    path = tmp_path / "source.whl"
    write_wheel(path, VERSION)
    monkeypatch.setattr(wheel, "MAX_WHEEL_BYTES", 1)
    with pytest.raises(wheel.CanonicalWheelError, match="total limit"):
        wheel._load(path)
    monkeypatch.setattr(wheel, "MAX_WHEEL_BYTES", 256 * 1024 * 1024)
    original = zipfile.ZipFile.open

    def truncated(archive, member, *args, **kwargs):
        if not args and isinstance(member, zipfile.ZipInfo):
            return io.BytesIO(b"")
        return original(archive, member, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", truncated)
    with pytest.raises(wheel.CanonicalWheelError, match="payload is invalid"):
        wheel._load(path)


def test_canonical_wheel_requires_shared_and_zip_safe_timestamp(tmp_path, monkeypatch):
    path = tmp_path / "canonical.whl"
    raw = tmp_path / "raw.whl"
    write_wheel(raw, VERSION)
    load_script("canonical_wheel").normalize_wheel(raw, path, timestamp=1_700_000_000)
    members, payloads = wheel._load(path)
    original = members[0].date_time
    members[0].date_time = (2022, 1, 1, 0, 0, 0)
    monkeypatch.setattr(wheel, "_load", lambda path: (members, payloads))
    with pytest.raises(wheel.CanonicalWheelError, match="one fixed timestamp"):
        wheel.verify_canonical_wheel(path)
    members[0].date_time = original
    monkeypatch.setattr(wheel, "_date_time_epoch", lambda value: 315532799)
    with pytest.raises(wheel.CanonicalWheelError, match="ZIP-safe"):
        wheel.verify_canonical_wheel(path)


def test_draft_release_identity_is_not_immutable():
    release = {
        "id": 1, "tag_name": TAG, "target_commitish": COMMIT, "name": TAG,
        "body": json.dumps({
            "source_commit": COMMIT,
            "source_repository": "NZCypher819/strugglebus",
            "source_tree": "2" * 40,
            "version": 1,
        }, sort_keys=True, separators=(",", ":")),
        "draft": True, "immutable": False, "prerelease": False,
    }
    with pytest.raises(UpdateError, match="unsupported_release"):
        source._release_identity(release, TAG, COMMIT)


def test_asset_pagination_is_rejected_during_exact_resolution(fixture_api, monkeypatch):
    session = source._Session(transport._HTTP(UpdateLimits(), 220))
    original = session.get
    monkeypatch.setattr(session, "get", lambda path:
                        ([], True) if "/assets?" in path else original(path))
    with pytest.raises(UpdateError, match="invalid_metadata"):
        source._resolve(session, 81, VERSION, UpdateLimits())


def test_safe_posix_asset_stamp_accepts_exact_owner_mode(fixture_api, monkeypatch):
    api, reader = fixture_api
    candidate = reader.check("0.2.27", deadline=220).candidate
    asset = candidate.assets[0]
    path = api.directory / asset.name
    real = path.lstat()
    info = SimpleNamespace(**{name: getattr(real, name) for name in (
        "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")},
        st_uid=1001, st_mode=stat.S_IFREG | 0o600)
    monkeypatch.setattr(source, "os", SimpleNamespace(name="posix", geteuid=lambda: 1001))
    monkeypatch.setattr(Path, "lstat", lambda selected: info)
    assert source._file_stamp(path, asset)[:2] == (real.st_dev, real.st_ino)


def test_opened_asset_must_be_same_inode(fixture_api, monkeypatch):
    api, reader = fixture_api
    asset = reader.check("0.2.27", deadline=220).candidate.assets[0]
    facade = SimpleNamespace(**{name: getattr(os, name) for name in dir(os) if not name.startswith("__")})
    real = os.fstat
    facade.fstat = lambda fd: SimpleNamespace(st_dev=real(fd).st_dev, st_ino=real(fd).st_ino + 1)
    monkeypatch.setattr(source, "os", facade)
    with pytest.raises(UpdateError, match="storage_unsafe"):
        source._verify_asset(api.directory / asset.name, asset)


@pytest.mark.parametrize("kind", ["asset", "directory"])
def test_offline_validation_rechecks_paths_after_canonical_validation(fixture_api, monkeypatch, kind):
    api, reader = fixture_api
    candidate = reader.check("0.2.27", deadline=220).candidate
    completed = [False]
    original = validation.validate_bundle

    def validate(*args, **kwargs):
        result = original(*args, **kwargs)
        completed[0] = True
        return result

    monkeypatch.setattr(validation, "validate_bundle", validate)
    if kind == "asset":
        original_stamp = source._file_stamp

        def stamp(path, asset):
            result = original_stamp(path, asset)
            return (result[0], result[1] + 1, *result[2:]) if completed[0] else result

        monkeypatch.setattr(source, "_file_stamp", stamp)
    else:
        original_directory = source.private_directory

        def directory(path, **kwargs):
            info = original_directory(path, **kwargs)
            return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino + int(completed[0]))

        monkeypatch.setattr(source, "private_directory", directory)
    with pytest.raises(UpdateError, match="storage_unsafe"):
        source.verify_prepared(candidate, api.directory, UpdateLimits())


def test_prepare_rechecks_owned_directory_after_second_publication_observation(fixture_api, tmp_path, monkeypatch):
    _, reader = fixture_api
    candidate = reader.check("0.2.27", deadline=220).candidate
    target = tmp_path / "quarantine"
    target.mkdir(mode=0o700)
    original = reader._unchanged
    observed = [0]

    def unchanged(*args):
        original(*args)
        observed[0] += 1

    original_directory = source.private_directory

    def directory(path, **kwargs):
        info = original_directory(path, **kwargs)
        return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino + (observed[0] == 2))

    monkeypatch.setattr(reader, "_unchanged", unchanged)
    monkeypatch.setattr(source, "private_directory", directory)
    with pytest.raises(UpdateError, match="storage_unsafe"):
        reader.prepare(candidate, target, deadline=700)


@pytest.mark.parametrize("kind", ["nonregular", "parent", "file"])
def test_exclusive_download_rejects_path_substitution(tmp_path, monkeypatch, kind):
    parent = tmp_path / "owned"
    parent.mkdir(mode=0o700)
    path = parent / "asset"
    facade = SimpleNamespace(**{name: getattr(os, name) for name in dir(os) if not name.startswith("__")})
    if kind == "nonregular":
        facade.fstat = lambda fd: SimpleNamespace(st_mode=stat.S_IFDIR, st_nlink=1)
    elif kind == "parent":
        original = transport.private_directory
        calls = [0]

        def directory(path, **kwargs):
            calls[0] += 1
            info = original(path, **kwargs)
            return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino + (calls[0] > 1))

        monkeypatch.setattr(transport, "private_directory", directory)
    else:
        original_lstat = Path.lstat

        def lstat(selected, *args, **kwargs):
            result = original_lstat(selected, *args, **kwargs)
            if selected == path:
                return SimpleNamespace(st_dev=result.st_dev, st_ino=result.st_ino + 1)
            return result

        monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(transport, "os", facade)
    with pytest.raises(UpdateError, match="storage_unsafe"):
        with transport.exclusive_file(path) as stream:
            stream.write(b"synthetic")


def test_exclusive_download_explicitly_sets_fd_mode_on_posix(tmp_path, monkeypatch):
    parent = tmp_path / "owned"
    parent.mkdir(mode=0o700)
    path = parent / "asset"
    facade = SimpleNamespace(**{name: getattr(os, name) for name in dir(os) if not name.startswith("__")})
    modes = []
    facade.fchmod = lambda fd, mode: modes.append((fd, mode))
    monkeypatch.setattr(transport, "os", facade)
    with transport.exclusive_file(path) as stream:
        stream.write(b"safe")
    assert len(modes) == 1 and modes[0][1] == 0o600


def test_exclusive_download_mode_fallback_remains_explicit(tmp_path, monkeypatch):
    parent = tmp_path / "owned"
    parent.mkdir(mode=0o700)
    path = parent / "asset"
    facade = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)
                              if not name.startswith("__") and name != "fchmod"})
    modes = []
    original = os.chmod

    def chmod(path, mode):
        modes.append(mode)
        original(path, mode)

    facade.chmod = chmod
    monkeypatch.setattr(transport, "os", facade)
    with transport.exclusive_file(path) as stream:
        stream.write(b"safe")
    assert modes == [0o600]


def test_metadata_body_length_and_actual_stream_limit_are_checked(http):
    response = Response(b"{}", transport.API + "/app")
    response.headers.replace_header("Content-Length", "3")
    http._metadata = Opener([response])
    with pytest.raises(UpdateError, match="invalid_metadata"):
        http.json("/repos/NZCypher819/strugglebus-releases/releases")
    response = Response(b"{}", transport.API + "/app")
    del response.headers["Content-Length"]
    http._metadata = Opener([response])
    http.limits = replace(http.limits, metadata_bytes=1)
    with pytest.raises(UpdateError, match="verification_failed"):
        http.json("/repos/NZCypher819/strugglebus-releases/releases")


def test_slow_transfer_does_not_sleep_again(http, monkeypatch):
    monkeypatch.setattr(transport, "_SLEEP", lambda delay: pytest.fail("already under rate"))
    http._throttle(1, 90)
