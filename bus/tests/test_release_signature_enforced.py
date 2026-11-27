"""Publishing a release is not enough to run code: the server's own update path needs the
publisher's signature, in the updater worker and again, independently, in the root installer."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import strugglebus.maintenance_runtime as runtime
from release_signing import TEST_KEY, ReleaseKey, statement_for
from strugglebus import release_signature
from strugglebus import release_validation as validation
from strugglebus import update_source as source
from strugglebus.maintenance_runtime import HostReleaseInstaller, config_from_json
from strugglebus.maintenance_supervisor import PreparedRelease
from strugglebus.maintenance_types import MaintenanceError
from strugglebus.update_types import UpdateError, UpdateLimits
from test_maintenance_runtime import configuration
from test_update_source import (
    TAG, TAG_SHA, VERSION, _refresh_assets, _rehash, fixture_api as fixture_api,
    publication as publication,
)

STATEMENT = validation.STATEMENT_NAME
NOT_THE_OWNER = ReleaseKey()


def served_tag(api) -> dict:
    return api.routes[f"{source._ROOT}/git/tags/{TAG_SHA}"]


def prepare(reader, folder: Path):
    candidate = reader.check("0.2.27", deadline=220).candidate
    folder.mkdir(mode=0o700)
    reader.prepare(candidate, folder, deadline=700)
    return candidate


def files_of(directory: Path) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in directory.iterdir() if path.name != STATEMENT}


# ---- The updater worker ----------------------------------------------------------------------

def test_a_signed_release_is_prepared_with_its_statement_saved_beside_the_files(fixture_api, tmp_path):
    api, reader = fixture_api

    candidate = prepare(reader, tmp_path / "slot")

    saved = (tmp_path / "slot" / STATEMENT).read_text(encoding="utf-8")
    assert saved == served_tag(api)["message"]
    assert release_signature.signed_digests(saved, VERSION) == {
        asset.name: asset.sha256 for asset in candidate.assets
    }
    assert (tmp_path / "slot" / STATEMENT).stat().st_mode & 0o777 == 0o600


def test_someone_who_can_publish_but_cannot_sign_gets_nowhere(fixture_api, tmp_path):
    """
    The attack this exists for. Write access to the releases repository lets someone replace a
    file and make every GitHub-side fact agree: the manifest, the checksums, the asset digests.
    It does not let them sign, so the statement still names the owner's files.
    """
    api, reader = fixture_api
    genuine = served_tag(api)["message"]
    lock = api.directory / "requirements.lock"
    lock.write_bytes(lock.read_bytes() + b"malicious==6.6.6 --hash=sha256:" + b"0" * 64 + b"\n")
    lock.chmod(0o600)
    _rehash(api.directory)
    _refresh_assets(api)
    served_tag(api)["message"] = genuine

    with pytest.raises(UpdateError, match="verification_failed"):
        prepare(reader, tmp_path / "slot")


@pytest.mark.parametrize("message", [
    lambda api: "Strugglebus public release mirror v1\n{}\n",
    lambda api: NOT_THE_OWNER.tag_message(statement_for(VERSION, files_of(api.directory))),
    lambda api: TEST_KEY.tag_message(statement_for("9.9.9", files_of(api.directory))),
    lambda api: TEST_KEY.tag_message(statement_for(VERSION, files_of(api.directory)), flags=0x01),
    lambda api: TEST_KEY.tag_message(
        statement_for(VERSION, files_of(api.directory)), namespace="strugglebus-release",
    ),
    lambda api: TEST_KEY.tag_message(statement_for(VERSION, files_of(api.directory) | {"extra.sh": b""})),
    lambda api: TEST_KEY.tag_message(statement_for(
        VERSION, {name: data for name, data in files_of(api.directory).items() if name != "requirements.lock"},
    )),
    lambda api: None,
    lambda api: "x" * (validation.MAX_STATEMENT_BYTES + 1),
], ids=[
    "no statement", "signed by someone else", "a statement for another version", "touched but no PIN",
    "signed as a worker host release", "names a file the release lacks", "leaves a file out",
    "no message at all", "an oversized message",
])
def test_the_worker_refuses_a_release_that_is_not_the_one_the_owner_signed(fixture_api, tmp_path, message):
    api, reader = fixture_api
    served_tag(api)["message"] = message(api)

    with pytest.raises(UpdateError, match="verification_failed"):
        prepare(reader, tmp_path / "slot")


def test_prepared_files_are_refused_without_their_statement_or_with_a_changed_one(fixture_api, tmp_path):
    api, reader = fixture_api
    candidate = prepare(reader, tmp_path / "slot")
    saved = tmp_path / "slot" / STATEMENT
    genuine = saved.read_bytes()
    limits = UpdateLimits()

    source.verify_prepared(candidate, tmp_path / "slot", limits)
    saved.write_bytes(genuine.replace(b"version ", b"Version "))
    with pytest.raises(UpdateError, match="verification_failed"):
        source.verify_prepared(candidate, tmp_path / "slot", limits)
    saved.unlink()
    with pytest.raises(UpdateError, match="verification_failed"):
        source.verify_prepared(candidate, tmp_path / "slot", limits)
    saved.write_bytes(b"\xff\xfe not text")
    saved.chmod(0o600)
    with pytest.raises(UpdateError, match="verification_failed"):
        source.verify_prepared(candidate, tmp_path / "slot", limits)


@pytest.mark.skipif(not hasattr(Path, "hardlink_to"), reason="needs hard links")
def test_the_saved_statement_must_be_a_plain_file_of_its_own(fixture_api, tmp_path):
    api, reader = fixture_api
    candidate = prepare(reader, tmp_path / "slot")
    saved = tmp_path / "slot" / STATEMENT
    (tmp_path / "elsewhere").hardlink_to(saved)

    with pytest.raises(UpdateError, match="storage_unsafe"):
        source.verify_prepared(candidate, tmp_path / "slot", UpdateLimits())


# ---- The root installer ----------------------------------------------------------------------

@pytest.fixture
def installer(monkeypatch):
    monkeypatch.setattr(runtime, "active_application_version", lambda config: "0.2.49")
    return HostReleaseInstaller(config_from_json(configuration()))


FILES = {"requirements.lock": b"lock\n", "strugglebus-0.2.50-py3-none-any.whl": b"wheel"}


def release(tmp_path: Path, message: str | None, version: str = "0.2.50") -> PreparedRelease:
    folder = tmp_path / "prepared"
    folder.mkdir(exist_ok=True)
    if message is not None:
        (folder / STATEMENT).write_text(message, encoding="utf-8", newline="")
    return PreparedRelease(version, folder)


def signed(version: str = "0.2.50", key: ReleaseKey = TEST_KEY, **options) -> str:
    return key.tag_message(statement_for(version, FILES), **options)


def facts(files: dict[str, bytes] = FILES, version: str = "0.2.50") -> dict:
    return {"package_version": version, "release_assets": [
        {"name": name, "sha256": hashlib.sha256(data).hexdigest()} for name, data in sorted(files.items())
    ]}


def test_root_checks_the_signature_itself_and_takes_the_hashes_from_it(installer, tmp_path, monkeypatch):
    seen = {}

    def validate(directory, **expectations):
        seen.update(expectations)
        return facts()

    monkeypatch.setattr(runtime, "validate_bundle", validate)

    assert installer._validate_bundle(release(tmp_path, signed())) == facts()
    assert seen["statement_beside"] is True
    assert installer._signed_digests(release(tmp_path, signed())) == {
        name: hashlib.sha256(data).hexdigest() for name, data in FILES.items()
    }


@pytest.mark.parametrize("message", [
    None,
    "Strugglebus public release mirror v1\n{}\n",
    signed(key=NOT_THE_OWNER),
    signed(version="0.2.51"),
    signed(flags=0x01),
    signed(namespace="strugglebus-release"),
    signed().replace("version 0.2.50", "version 0.2.5O"),
    "x" * (validation.MAX_STATEMENT_BYTES + 1),
], ids=[
    "no statement saved", "no statement in it", "signed by someone else", "for another version",
    "touched but no PIN", "signed as a worker host release", "changed after signing", "oversized",
])
def test_root_refuses_before_it_looks_at_a_single_release_file(installer, tmp_path, monkeypatch, message):
    monkeypatch.setattr(runtime, "validate_bundle", lambda *args, **kwargs: pytest.fail("the release was read"))

    with pytest.raises(MaintenanceError) as caught:
        installer._validate_bundle(release(tmp_path, message))

    assert caught.value.code == "preparation_failed"


def test_root_refuses_files_whose_hashes_are_not_the_signed_ones(installer, tmp_path, monkeypatch):
    """Whatever the worker left in the folder, the hashes root goes on to use must be signed."""
    swapped = FILES | {"requirements.lock": b"malicious\n"}
    monkeypatch.setattr(runtime, "validate_bundle", lambda *args, **kwargs: facts(swapped))
    with pytest.raises(MaintenanceError) as caught:
        installer._validate_bundle(release(tmp_path, signed()))
    assert caught.value.code == "preparation_failed"

    monkeypatch.setattr(runtime, "validate_bundle", lambda *args, **kwargs: facts(FILES | {"extra.sh": b""}))
    with pytest.raises(MaintenanceError):
        installer._validate_bundle(release(tmp_path, signed()))


@pytest.mark.parametrize("running", ["0.2.50", "0.2.51", "1.0.0"])
def test_root_refuses_a_signed_release_that_is_not_newer_than_the_one_running(tmp_path, monkeypatch, running):
    """An old release is genuinely signed. Offered again as an update, it is still refused."""
    monkeypatch.setattr(runtime, "active_application_version", lambda config: running)
    monkeypatch.setattr(runtime, "validate_bundle", lambda *args, **kwargs: pytest.fail("the release was read"))
    installer = HostReleaseInstaller(config_from_json(configuration()))

    with pytest.raises(MaintenanceError) as caught:
        installer._validate_bundle(release(tmp_path, signed()))

    assert caught.value.code == "preparation_failed"


def test_root_does_not_follow_a_link_to_a_statement(installer, tmp_path):
    folder = tmp_path / "prepared"
    folder.mkdir()
    (tmp_path / "real").write_text(signed(), encoding="utf-8", newline="")
    try:
        (folder / STATEMENT).symlink_to(tmp_path / "real")
    except OSError:
        pytest.skip("symbolic links are not available here")

    with pytest.raises(MaintenanceError) as caught:
        installer._signed_digests(PreparedRelease("0.2.50", folder))

    assert caught.value.code == "preparation_failed"


def test_versions_are_compared_as_numbers():
    assert runtime._version_key("0.10.0") > runtime._version_key("0.9.9")
    assert runtime._version_key("1.0.0") > runtime._version_key("0.99.99")
