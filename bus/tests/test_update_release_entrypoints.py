"""Compatibility contracts for release entry points using shared read helpers."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from release_fixtures import load_script, write_wheel
from strugglebus.update_types import UPDATE_SOURCE_REPOSITORY
from test_update_source import publication, fixture_api, VERSION, TAG, COMMIT, TREE, ROOT


@pytest.mark.parametrize("format", ["summary", "ansible"])
def test_bundle_validation_cli_stdout_contract(publication, monkeypatch, capsys, format):
    bundle = load_script("release_bundle")
    monkeypatch.setattr(sys, "argv", ["release_bundle.py", "validate", str(publication),
                                     "--format", format, "--expected-tag", TAG,
                                     "--expected-commit", COMMIT, "--expected-tree", TREE])
    assert bundle.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["tag"] == TAG and result["integrity"] == "sha256-verified"
    assert result["authenticity"] == "authenticated-github-acquisition-required"
    if format == "summary":
        assert set(result) == {"authenticity", "integrity", "source_commit", "tag"}
    else:
        assert len(result["release_assets"]) == 5


def test_bundle_build_cli_dispatch_contract(tmp_path, monkeypatch, capsys):
    bundle = load_script("release_bundle")
    calls = []

    def build(*args, **kwargs):
        calls.append((args, kwargs))
        return {"manifest_version": 1}

    monkeypatch.setattr(bundle, "build_bundle", build)
    monkeypatch.setattr(sys, "argv", ["release_bundle.py", "build", "--repository", str(ROOT),
                                     "--dist", str(tmp_path / "dist"), "--output", str(tmp_path / "output"),
                                     "--tag", TAG, "--expected-commit", COMMIT, "--expected-tree", TREE,
                                     "--uv-binary", str(tmp_path / "uv"), "--pre-tag"])
    assert bundle.main() == 0
    assert capsys.readouterr().out == '{"manifest_version":1}\n'
    assert calls == [((ROOT, tmp_path / "dist", tmp_path / "output", TAG),
                     {"expected_commit": COMMIT, "expected_tree": TREE,
                      "uv_binary": tmp_path / "uv", "pre_tag": True, "source_repository": None})]


def test_lock_cli_uses_shared_verifier(tmp_path, monkeypatch):
    module = load_script("validate_requirements_lock")
    path = tmp_path / "requirements.lock"
    path.write_text("package==1.0 \\\n    --hash=sha256:" + "0" * 64 + "\n")
    monkeypatch.setattr(sys, "argv", ["validate_requirements_lock.py", str(path)])
    assert module.main() == 0


def test_canonical_cli_verify_without_timestamp(tmp_path, monkeypatch, capsys):
    module = load_script("canonical_wheel")
    raw, canonical = tmp_path / "raw.whl", tmp_path / "canonical.whl"
    write_wheel(raw, VERSION)
    module.normalize_wheel(raw, canonical, timestamp=1_700_000_000)
    monkeypatch.setattr(sys, "argv", ["canonical_wheel.py", "verify", str(canonical)])
    assert module.main() == 0
    assert json.loads(capsys.readouterr().out)["source_date_epoch"] == 1_700_000_000


@pytest.mark.parametrize("text", ["invalid", "9999999999999"])
def test_canonical_cli_timestamp_parsing_is_strict(text):
    module = load_script("canonical_wheel")
    with pytest.raises(module.CanonicalWheelError, match="decimal UTC"):
        module.resolve_source_date_epoch(text)


@pytest.mark.parametrize("kind", ["order", "payload"])
def test_normalization_rechecks_read_helper_results(tmp_path, monkeypatch, kind):
    module = load_script("canonical_wheel")
    raw, canonical = tmp_path / "raw.whl", tmp_path / "canonical.whl"
    write_wheel(raw, VERSION)
    if kind == "order":
        verify = module.verify_canonical_wheel

        def reordered(path, **kwargs):
            return {**verify(path, **kwargs), "members": ["unexpected"]}

        monkeypatch.setattr(module, "verify_canonical_wheel", reordered)
    else:
        read = module._load
        count = [0]

        def changed(path):
            count[0] += 1
            members, payloads = read(path)
            if count[0] == 2:
                payloads = {**payloads, "unexpected": b"bytes"}
            return members, payloads

        monkeypatch.setattr(module, "_load", changed)
    with pytest.raises(module.CanonicalWheelError, match="changed"):
        module.normalize_wheel(raw, canonical, timestamp=1_700_000_000)


@pytest.mark.parametrize("available", ["none", "read", "both"])
def test_publisher_cli_dispatch_uses_separate_synthetic_tokens(tmp_path, monkeypatch, capsys, available):
    module = load_script("publish_immutable_release")
    monkeypatch.delenv("SYNTHETIC_UPDATER_READ", raising=False)
    monkeypatch.delenv("SYNTHETIC_UPDATER_PUBLISH", raising=False)
    if available != "none":
        monkeypatch.setenv("SYNTHETIC_UPDATER_READ", "synthetic-read")
    if available == "both":
        monkeypatch.setenv("SYNTHETIC_UPDATER_PUBLISH", "synthetic-publish")
    constructed = []
    received = []

    def api(url, token):
        constructed.append((url, token))
        return ("synthetic-client", token)

    def publish(client, directory, **kwargs):
        received.append((client, directory, kwargs))
        return {"id": 1, "immutable": True, "tag_name": TAG}

    monkeypatch.setattr(module, "GitHubReleaseAPI", api)
    monkeypatch.setattr(module, "publish_immutable_release", publish)
    monkeypatch.setattr(sys, "argv", [
        "publish_immutable_release.py", str(tmp_path),
        "--tag", TAG, "--commit", COMMIT, "--tree", TREE, "--actor", "synthetic-owner",
        "--workflow-sha", COMMIT, "--receipt", str(tmp_path / "receipt.json"),
        "--qualification-run-id", "1", "--qualification-artifact-id", "2",
        "--qualification-artifact-name", "synthetic-artifact",
        "--qualification-artifact-digest", "sha256:" + "0" * 64,
        "--qualification-artifact-size", "1", "--source-root", str(ROOT),
        "--read-token-env", "SYNTHETIC_UPDATER_READ", "--publish-token-env", "SYNTHETIC_UPDATER_PUBLISH",
    ])
    if available != "both":
        with pytest.raises(module.ReleasePublicationError, match="unavailable"):
            module.main()
        assert not constructed
        return
    assert module.main() == 0
    assert capsys.readouterr().out == '{"id":1,"immutable":true,"tag":"' + TAG + '"}\n'
    assert constructed == [(module.GITHUB_API_URL, "synthetic-publish"), (module.GITHUB_API_URL, "synthetic-read")]
    assert received[0][0] == ("synthetic-client", "synthetic-publish")
    assert received[0][2]["trigger_api"] == ("synthetic-client", "synthetic-read")


def test_metadata_inspection_rejects_wrong_repository_missing_release_or_asset_contract(fixture_api):
    fixture, _ = fixture_api
    publisher = load_script("publish_immutable_release")
    descriptions = [{"name": item["name"], "size_bytes": item["size"], "sha256": item["digest"][7:]}
                    for item in fixture.assets]
    api = SimpleNamespace(find_release=lambda *args: None)
    with pytest.raises(publisher.ReleasePublicationError, match="repository identity"):
        publisher.inspect_release_identity(api, repository="other/repository", tag=TAG,
                                           commit=COMMIT, assets=descriptions)
    assert publisher.inspect_release_identity(api, repository=publisher.REPOSITORY_ID, tag=TAG,
                                              commit=COMMIT, assets=descriptions) is None
    # In the private repository this publisher writes to, a release's tag has no prefix.
    api.find_release = lambda *args: {**fixture.release, "tag_name": TAG, "name": TAG}
    with pytest.raises(publisher.ReleasePublicationError, match="asset set"):
        publisher.inspect_release_identity(api, repository=publisher.REPOSITORY_ID, tag=TAG,
                                           commit=COMMIT, assets=descriptions[:-1])


def test_historical_published_byte_wrapper_rechecks_identity_after_one_full_copy(fixture_api, monkeypatch):
    fixture, _ = fixture_api
    # The pretend release was built in the project's own repository, so the publisher is told so.
    monkeypatch.setattr(load_script("publish_immutable_release"), "REPOSITORY_ID", UPDATE_SOURCE_REPOSITORY)
    # The publisher's own folder holds only the release's files; the signed statement is added
    # beside them later, by an updater that has fetched it from the tag.
    (fixture.directory / "release-statement.txt").unlink()
    publisher = load_script("publish_immutable_release")
    downloads = []
    private_release = {
        **fixture.release,
        "tag_name": TAG,
        "name": TAG,
        "target_commitish": COMMIT,
        "body": publisher._release_body(TAG),
    }

    def find(*args):
        return {**private_release, "id": 82} if downloads else private_release

    def download(repository, asset_id, destination, **expected):
        record = next(item for item in fixture.assets if item["id"] == asset_id)
        destination.write_bytes((fixture.directory / record["name"]).read_bytes())
        downloads.append(asset_id)

    api = SimpleNamespace(find_release=find, list_assets=lambda *args: fixture.assets,
                          download_asset=download)
    with pytest.raises(publisher.ReleasePublicationError, match="drifted"):
        publisher.verify_published_release(api, fixture.directory, repository=UPDATE_SOURCE_REPOSITORY,
                                           tag=TAG, commit=COMMIT, tree=TREE)
    assert sorted(downloads) == [100, 101, 102, 103, 104]


def test_published_copy_rejects_same_length_tamper_and_conflicting_asset_set(publication, tmp_path, monkeypatch):
    publisher = load_script("publish_immutable_release")
    monkeypatch.setattr(publisher, "REPOSITORY_ID", UPDATE_SOURCE_REPOSITORY)
    local = publisher._local_assets(publication)
    left, right = tmp_path / "left", tmp_path / "right"
    left.write_bytes(b"original")
    right.write_bytes(b"tampered")
    assert not publisher._files_equal(left, right)
    incomplete = dict(local)
    incomplete.pop(next(iter(incomplete)))
    with pytest.raises(publisher.ReleasePublicationError, match="asset set"):
        publisher._validate_downloaded_bundle(publication, incomplete, repository=UPDATE_SOURCE_REPOSITORY,
                                              tag=TAG, commit=COMMIT, tree=TREE)
    name = "requirements.lock"
    original = local[name]
    right.write_bytes(b"!" * original.size)
    local[name] = publisher.LocalAsset(name, right, original.size, original.digest, original.media_type)
    with pytest.raises(publisher.ReleasePublicationError, match="bytes differ"):
        publisher._validate_downloaded_bundle(publication, local, repository=UPDATE_SOURCE_REPOSITORY,
                                              tag=TAG, commit=COMMIT, tree=TREE)
