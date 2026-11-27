from __future__ import annotations

from dataclasses import replace
from email.message import Message
import hashlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import urllib.error
import urllib.request

import pytest

from release_fixtures import load_script, write_wheel, wheel_members, _record_hash
from strugglebus import __version__
from strugglebus import update_source as source, update_transport as transport
from strugglebus import release_validation as validation
from release_signing import TEST_KEY, statement_for
from strugglebus.update_types import (
    UPDATE_REPOSITORY, UPDATE_SOURCE_REPOSITORY, UpdateError, UpdateLimits,
)

ROOT = Path(__file__).resolve().parents[1]
# The fixture release is always the one after the running package version.
_MAJOR, _MINOR, _PATCH = (int(part) for part in __version__.split("."))
VERSION = f"{_MAJOR}.{_MINOR}.{_PATCH + 1}"
TAG = "v" + VERSION
# The release's tag as the repository has it. Inside the release it is still TAG.
PUBLISHED_TAG = "bus/" + TAG
COMMIT, TREE, TAG_SHA = "1" * 40, "2" * 40, "3" * 40
PUBLIC_COMMIT, PUBLIC_TREE = "4" * 40, "5" * 40


class Response(io.BytesIO):
    def __init__(self, payload, url, media="application/json", status=200, **headers):
        super().__init__(payload)
        self.url = url
        self.status = status
        self.headers = Message()
        self.headers["Content-Type"] = media
        self.headers["Content-Length"] = str(len(payload))
        for name, value in headers.items():
            self.headers[name.replace("_", "-")] = value

    def geturl(self):
        return self.url


@pytest.fixture
def publication(tmp_path, monkeypatch):
    bundle = load_script("release_bundle")
    dist = tmp_path / "dist"
    dist.mkdir()
    write_wheel(dist / f"strugglebus-{VERSION}-py3-none-any.whl", VERSION)
    uv = tmp_path / "uv"
    uv.write_bytes(b"synthetic uv")
    monkeypatch.setattr(bundle, "resolve_release_identity",
                        lambda *args, **kwargs: (COMMIT, TREE, 1_700_000_000, VERSION))
    # A release as the pipeline in the project's own repository builds it, which is what an
    # installed updater expects from now on. The publisher script copies the name when it is
    # first loaded, so it is loaded before the name is changed and never keeps the changed one.
    load_script("publish_immutable_release")
    monkeypatch.setattr(bundle, "REPOSITORY_ID", UPDATE_SOURCE_REPOSITORY)
    directory = tmp_path / "published"
    bundle.build_bundle(ROOT, dist, directory, TAG, uv_binary=uv)
    directory.chmod(0o700)
    for path in directory.iterdir():
        path.chmod(0o600)
    return directory


def tag_answer(number: int = 1) -> str:
    """The address of one answer to the question for the repository's bus tags."""
    return f"{source._TAG_REFS}?per_page=100&page={number}"


def tag_refs(*tags: str) -> list[dict]:
    return [{"ref": f"refs/tags/{tag}", "object": {"type": "tag", "sha": TAG_SHA}} for tag in tags]


def release_for(tag: str) -> str:
    """The address that answers with the release published for a tag."""
    return f"{source._ROOT}/releases/tags/{tag}"


class FixtureAPI:
    def __init__(self, directory):
        self.directory = directory
        self.requests = []
        self.downloads = []
        self.routes = {}
        self.handlers = []
        self.assets = [
            {"id": index, "name": path.name, "size": path.stat().st_size,
             "digest": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
             "content_type": source._asset_media_type(path.name), "state": "uploaded", "label": None}
            for index, path in enumerate(sorted(directory.iterdir()), start=100)
        ]
        body = json.dumps({
            "source_commit": COMMIT,
            "source_repository": UPDATE_SOURCE_REPOSITORY,
            "source_tree": TREE,
            "version": 1,
        }, sort_keys=True, separators=(",", ":"))
        self.release = {
            "id": 81, "tag_name": PUBLISHED_TAG, "target_commitish": PUBLIC_COMMIT,
            "name": PUBLISHED_TAG, "body": body,
            "draft": False, "prerelease": False, "immutable": True,
        }
        self.routes = {
            tag_answer(): tag_refs(PUBLISHED_TAG),
            release_for(PUBLISHED_TAG): self.release,
            f"{source._ROOT}/releases/81": self.release,
            f"{source._ROOT}/git/ref/tags/{PUBLISHED_TAG}": {
                "ref": f"refs/tags/{PUBLISHED_TAG}", "object": {"type": "tag", "sha": TAG_SHA},
            },
            f"{source._ROOT}/git/tags/{TAG_SHA}": {
                "sha": TAG_SHA, "tag": PUBLISHED_TAG,
                "object": {"type": "commit", "sha": PUBLIC_COMMIT},
            },
            f"{source._ROOT}/git/commits/{PUBLIC_COMMIT}": {
                "sha": PUBLIC_COMMIT, "tree": {"sha": PUBLIC_TREE},
            },
            f"{source._ROOT}/releases/81/assets?per_page=6": self.assets,
        }
        self.sign()

    def sign(self):
        """
        The publisher signs exactly the files as they are now. The signed statement is served in
        the release's tag, and also saved beside the files, as a prepared release has it, for the
        tests that check this folder directly.
        """
        saved = self.directory / source.policy.STATEMENT_NAME
        saved.unlink(missing_ok=True)
        statement = TEST_KEY.tag_message(statement_for(
            TAG.removeprefix("v"), {path.name: path.read_bytes() for path in self.directory.iterdir()},
        ))
        self.routes[f"{source._ROOT}/git/tags/{TAG_SHA}"]["message"] = statement
        saved.write_text(statement, encoding="utf-8", newline="")
        saved.chmod(0o600)

    def opener(self, *handlers):
        self.handlers.extend(handlers)
        return self

    def open(self, request, timeout):
        assert request.full_url.startswith(transport.API + "/")
        assert 0 < timeout <= 30
        path = request.full_url[len(transport.API):]
        self.requests.append((request.get_method(), path))
        assert request.get_header("Authorization") is None
        assert request.get_header("Host") is None
        assert request.get_method() == "GET" and request.data is None
        if "/releases/assets/" in path:
            return self.asset_response(request, int(path.rsplit("/", 1)[1]))
        if path not in self.routes and "/releases/tags/" in path:
            # A tag that has no published release.
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", Message(), None)
        value = self.routes[path]
        if callable(value):
            value = value()
        if isinstance(value, Exception):
            raise value
        return Response(json.dumps(value).encode(), request.full_url,
                        status=201 if request.get_method() == "POST" else 200)

    def asset_response(self, request, asset_id):
        asset = next(asset for asset in self.assets if asset["id"] == asset_id)
        self.downloads.append(asset_id)
        payload = (self.directory / asset["name"]).read_bytes()
        return Response(payload, request.full_url, media=asset["content_type"],
                        Content_Disposition=f'attachment; filename="{asset["name"]}"')


@pytest.fixture
def fixture_api(publication, monkeypatch):
    api = FixtureAPI(publication)
    monkeypatch.setattr(urllib.request, "build_opener", api.opener)
    monkeypatch.setattr(transport, "_CLOCK", lambda: 100.0)
    monkeypatch.setattr(transport, "_SLEEP", lambda delay: None)
    return api, source.GitHubReleaseSource(UpdateLimits())


def test_anonymous_check_prepare_and_trusted_offline_verify(fixture_api, tmp_path, monkeypatch):
    api, reader = fixture_api
    discovery = reader.check("0.2.27", deadline=220)
    assert discovery.complete and discovery.inspected == 1
    assert discovery.blocked_reason is None
    candidate = discovery.candidate
    assert candidate.commit == COMMIT and candidate.tree == TREE
    assert candidate.tag_object_sha == TAG_SHA and candidate.policy_id == reader.policy_id
    target = tmp_path / "quarantine"
    target.mkdir(mode=0o700)
    reader.prepare(candidate, target, deadline=700)
    assert sorted(api.downloads) == [100, 101, 102, 103, 104]
    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: pytest.fail("offline network"))
    source.verify_prepared(candidate, target, UpdateLimits())
    assert all(method == "GET" for method, _ in api.requests)
    assert not any("actions" in path or "latest" in path or "/contents/" in path for _, path in api.requests)
    assert all(handler.proxies == {} for handler in api.handlers if isinstance(handler, urllib.request.ProxyHandler))
    assert source._ROOT == f"/repos/{UPDATE_REPOSITORY}"


def test_constructor_never_contacts_network(monkeypatch):
    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: pytest.fail("network"))
    assert source.GitHubReleaseSource(UpdateLimits()).policy_id == source.POLICY_ID


@pytest.mark.parametrize("mutation", [
    lambda value: value | {"source_repository": "other/private"},
    lambda value: value | {"source_commit": "invalid"},
    lambda value: value | {"source_tree": "invalid"},
    lambda value: value | {"version": 2},
    lambda value: value | {"extra": True},
])
def test_public_metadata_source_binding_fail_closed(fixture_api, mutation):
    api, reader = fixture_api
    value = json.loads(api.release["body"])
    api.routes[f"{source._ROOT}/releases/81"] = {
        **api.release,
        "body": json.dumps(mutation(value), sort_keys=True, separators=(",", ":")),
    }
    result = reader.check("0.2.27", deadline=220)
    assert result.candidate is None
    assert result.blocked_reason == "unsupported_release"


@pytest.mark.parametrize("body", [
    '{"source_commit":"' + COMMIT + '","source_repository":"' + UPDATE_SOURCE_REPOSITORY
    + '","source_tree":"' + TREE + '","version":1}\n',
    '{"version":1,"source_tree":"' + TREE + '","source_repository":"'
    + UPDATE_SOURCE_REPOSITORY + '","source_commit":"' + COMMIT + '"}',
    '{"source_commit":"' + COMMIT + '","source_commit":"' + COMMIT
    + '","source_repository":"' + UPDATE_SOURCE_REPOSITORY
    + '","source_tree":"' + TREE + '","version":1}',
    "[]",
])
def test_public_metadata_requires_one_exact_canonical_json_object(fixture_api, body):
    api, reader = fixture_api
    api.routes[f"{source._ROOT}/releases/81"] = {**api.release, "body": body}
    result = reader.check("0.2.27", deadline=220)
    assert result.candidate is None
    assert result.blocked_reason == "unsupported_release"


def test_public_metadata_binds_private_source_independently_of_public_tag(
    fixture_api, publication,
):
    api, reader = fixture_api
    source_commit, source_tree = "8" * 40, "9" * 40
    api.routes[f"{source._ROOT}/releases/81"] = {
        **api.release,
        "body": json.dumps({
            "source_commit": source_commit,
            "source_repository": UPDATE_SOURCE_REPOSITORY,
            "source_tree": source_tree,
            "version": 1,
        }, sort_keys=True, separators=(",", ":")),
    }
    candidate = reader.check("0.2.27", deadline=220).candidate
    assert candidate.commit == source_commit and candidate.tree == source_tree
    assert candidate.tag_object_sha == TAG_SHA
    with pytest.raises(UpdateError, match="verification_failed"):
        source.verify_prepared(candidate, publication, UpdateLimits())


@pytest.mark.parametrize("field,value", [
    ("immutable", False), ("immutable", None), ("immutable", "true"), ("immutable", 1),
    ("target_commitish", "main"), ("body", "<script>untrusted</script>"),
    ("draft", None), ("draft", 0), ("prerelease", None), ("prerelease", 0),
    ("name", "anything"),
])
def test_blocked_publication_is_not_hidden_by_older_release(fixture_api, field, value):
    api, reader = fixture_api
    api.routes[f"{source._ROOT}/releases/81"] = {**api.release, field: value}
    result = reader.check("0.2.27", deadline=220)
    assert result.candidate is None
    assert result.blocked_version == VERSION and result.blocked_reason == "unsupported_release"


def test_every_answer_of_tags_is_read_and_only_the_newest_release_is_resolved(fixture_api):
    """Tags come in name order, so the newest can be anywhere."""
    api, reader = fixture_api
    older = {**api.release, "id": 80, "tag_name": "bus/v0.2.28", "name": "bus/v0.2.28"}
    api.routes[tag_answer(1)] = tag_refs(*(f"bus/v0.1.{i}" for i in range(100)))
    api.routes[tag_answer(2)] = tag_refs("bus/v0.2.28", PUBLISHED_TAG)
    api.routes[release_for("bus/v0.2.28")] = older
    result = reader.check("0.2.27", deadline=220)
    assert result.candidate.version == VERSION and result.complete and result.inspected == 40
    assert ("GET", release_for("bus/v0.2.28")) not in api.requests
    assert ("GET", f"{source._ROOT}/releases/80") not in api.requests
    assert not any("page=3" in path for _, path in api.requests)


def test_other_releases_cannot_bury_a_bus_release(fixture_api):
    """The shared list of releases is never read, so nothing published after a bus release hides it."""
    api, reader = fixture_api
    api.routes[f"{source._ROOT}/releases?per_page=20&page=1"] = [
        {**api.release, "id": 200 + i, "tag_name": f"windows/v9.9.{i}"} for i in range(20)]
    api.routes[f"{source._ROOT}/releases?per_page=20&page=2"] = [
        {**api.release, "id": 300 + i, "tag_name": f"windows/v9.8.{i}"} for i in range(20)]
    result = reader.check("0.2.27", deadline=220)
    assert result.candidate.version == VERSION and result.complete
    assert not any("/releases?" in path for _, path in api.requests)


def test_more_tags_than_can_be_read_with_no_update_among_them_fails_the_check(fixture_api):
    """It is never reported as nothing newer."""
    api, reader = fixture_api
    for answer in range(1, source._TAG_ANSWERS + 1):
        api.routes[tag_answer(answer)] = tag_refs(*(f"bus/v0.1.{i}" for i in range(100)))
    with pytest.raises(UpdateError, match="invalid_metadata"):
        reader.check("0.2.27", deadline=220)
    assert not any(f"page={source._TAG_ANSWERS + 1}" in path for _, path in api.requests)


def test_more_tags_than_can_be_read_still_offers_an_update_found_among_them(fixture_api):
    api, reader = fixture_api
    for answer in range(1, source._TAG_ANSWERS + 1):
        api.routes[tag_answer(answer)] = tag_refs(*(f"bus/v0.1.{i}" for i in range(99)), PUBLISHED_TAG)
    result = reader.check("0.2.27", deadline=220)
    assert result.candidate.version == VERSION and not result.complete and result.inspected == 40


def test_blocked_newest_release_does_not_fall_back_to_an_older_one(fixture_api):
    api, reader = fixture_api
    older = {**api.release, "id": 80, "tag_name": "bus/v0.2.28"}
    api.routes[tag_answer()] = tag_refs(PUBLISHED_TAG, "bus/v0.2.28")
    api.routes[release_for("bus/v0.2.28")] = older
    api.routes[f"{source._ROOT}/releases/81"] = {**api.release, "immutable": False}
    result = reader.check("0.2.27", deadline=220)
    assert result.candidate is None
    assert result.blocked_version == VERSION and result.blocked_reason == "unsupported_release"
    assert ("GET", f"{source._ROOT}/releases/80") not in api.requests


@pytest.mark.parametrize("tag", ["bus/v0.3.0rc1", "bus/v00.3.0", TAG, "windows/" + TAG, "bus/" + VERSION])
def test_tags_that_are_not_bus_release_tags_are_not_candidates(fixture_api, tag):
    api, reader = fixture_api
    api.routes[tag_answer()] = tag_refs(tag)
    api.routes[release_for(tag)] = api.release
    result = reader.check("0.2.27", deadline=220)
    assert result.candidate is None and result.blocked_reason is None and result.complete


@pytest.mark.parametrize("field", ["draft", "prerelease"])
def test_a_tag_whose_release_is_not_published_is_not_a_candidate(fixture_api, field):
    api, reader = fixture_api
    api.routes[release_for(PUBLISHED_TAG)] = {**api.release, field: True}
    result = reader.check("0.2.27", deadline=220)
    assert result.candidate is None and result.blocked_reason is None


def test_a_newer_tag_with_no_release_does_not_hide_a_real_update(fixture_api):
    """Anyone who can push can make a tag. Only a published release counts."""
    api, reader = fixture_api
    api.routes[tag_answer()] = tag_refs("bus/v9.9.9", "bus/v9.9.8", PUBLISHED_TAG)
    api.routes[release_for("bus/v9.9.8")] = {**api.release, "id": 90, "draft": True}
    result = reader.check("0.2.27", deadline=220)
    assert result.candidate.version == VERSION
    assert ("GET", release_for("bus/v9.9.9")) in api.requests


def test_only_the_newest_few_tags_are_tried(fixture_api):
    api, reader = fixture_api
    stray = [f"bus/v9.9.{n}" for n in range(source._TAGS_TRIED)]
    api.routes[tag_answer()] = tag_refs(PUBLISHED_TAG, *stray)
    result = reader.check("0.2.27", deadline=220)
    assert result.candidate is None and result.blocked_reason is None
    assert ("GET", release_for(PUBLISHED_TAG)) not in api.requests


def test_a_release_that_cannot_be_reached_is_not_taken_for_a_missing_one(fixture_api):
    api, reader = fixture_api
    api.routes[release_for(PUBLISHED_TAG)] = urllib.error.HTTPError("https://x", 403, "no", Message(), None)
    with pytest.raises(UpdateError, match="source_unavailable"):
        reader.check("0.2.27", deadline=220)


@pytest.mark.parametrize("endpoint,field,value", [
    (f"/git/ref/tags/{PUBLISHED_TAG}", "object", {"type": "commit", "sha": PUBLIC_COMMIT}),
    (f"/git/ref/tags/{PUBLISHED_TAG}", "ref", "refs/heads/main"),
    (f"/git/tags/{TAG_SHA}", "object", {"type": "tag", "sha": TAG_SHA}),
    (f"/git/tags/{TAG_SHA}", "sha", "6" * 40),
    (f"/git/commits/{PUBLIC_COMMIT}", "sha", "6" * 40),
    (f"/git/commits/{PUBLIC_COMMIT}", "tree", {"sha": "main"}),
])
def test_direct_annotated_tag_commit_tree_is_required(fixture_api, endpoint, field, value):
    api, reader = fixture_api
    api.routes[source._ROOT + endpoint] = {**api.routes[source._ROOT + endpoint], field: value}
    assert reader.check("0.2.27", deadline=220).blocked_reason in {"unsupported_release", "invalid_metadata"}


@pytest.mark.parametrize("field,value", [
    ("digest", None), ("digest", "sha256:" + "z" * 64), ("name", "../escape"),
    ("id", True), ("size", 0), ("size", True), ("size", 256 * 1024 * 1024 + 1),
    ("content_type", "text/html"), ("content_type", "application/octet-stream"),
    ("state", "new"), ("label", "arbitrary"),
])
def test_asset_metadata_is_exact_and_bounded(fixture_api, field, value):
    api, reader = fixture_api
    api.assets[0] = {**api.assets[0], field: value}
    assert reader.check("0.2.27", deadline=220).blocked_reason == "invalid_metadata"


def test_release_drift_after_download_is_rejected(fixture_api, tmp_path):
    api, reader = fixture_api
    candidate = reader.check("0.2.27", deadline=220).candidate
    api.routes[f"{source._ROOT}/releases/81/assets?per_page=6"] = lambda: (
        [{**asset, "id": asset["id"] + 1} for asset in api.assets] if api.downloads else api.assets)
    target = tmp_path / "quarantine"
    target.mkdir(mode=0o700)
    with pytest.raises(UpdateError, match="publication_changed"):
        reader.prepare(candidate, target, deadline=700)
    assert len(api.downloads) == 5


def test_candidate_policy_and_existing_destination_rejected_before_network(fixture_api, tmp_path):
    api, reader = fixture_api
    candidate = reader.check("0.2.27", deadline=220).candidate
    calls = len(api.requests)
    with pytest.raises(UpdateError, match="policy_mismatch"):
        reader.prepare(replace(candidate, policy_id="unknown"), tmp_path, deadline=700)
    with pytest.raises(UpdateError, match="storage_unsafe"):
        reader.prepare(candidate, tmp_path, deadline=700)
    assert len(api.requests) == calls


def test_offline_tamper_and_unexpected_files_are_rejected(fixture_api, publication):
    _, reader = fixture_api
    candidate = reader.check("0.2.27", deadline=220).candidate
    (publication / "unexpected").write_bytes(b"not allowed")
    with pytest.raises(UpdateError, match="verification_failed"):
        source.verify_prepared(candidate, publication, UpdateLimits())
    (publication / "unexpected").unlink()
    path = publication / candidate.assets[0].name
    path.write_bytes(b"!" * path.stat().st_size)
    with pytest.raises(UpdateError, match="verification_failed"):
        source.verify_prepared(candidate, publication, UpdateLimits())


@pytest.mark.parametrize("payload", [b'{"a":1,"a":2}', b'{"a":NaN}', b"[]garbage", b"\xff",
                                     b"[" * 2000 + b"]" * 2000])
def test_network_json_is_strict_and_sanitized(payload):
    with pytest.raises(UpdateError, match="invalid_metadata"):
        transport.decode(payload)


@pytest.mark.parametrize("deadline", [0, float("nan"), float("inf"), "later"])
def test_invalid_or_expired_deadline_never_contacts_source(fixture_api, deadline):
    api, reader = fixture_api
    with pytest.raises(UpdateError, match="timeout"):
        reader.check("0.2.27", deadline=deadline)
    assert not api.requests
def _rehash(directory):
    manifest_path = directory / validation.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_bytes())
    for asset in manifest["assets"]:
        path = directory / asset["name"]
        asset.update(size_bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    manifest_path.write_bytes(validation._canonical_json(manifest))
    files = sorted(
        path for path in directory.iterdir()
        if path.name not in (validation.CHECKSUMS_NAME, validation.STATEMENT_NAME)
    )
    (directory / validation.CHECKSUMS_NAME).write_text(
        "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files),
        encoding="ascii",
    )


def _refresh_assets(api):
    for asset in api.assets:
        path = api.directory / asset["name"]
        asset["digest"] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        asset["size"] = path.stat().st_size
    api.sign()


@pytest.mark.parametrize("section,field,value", [
    ("protocol", "integration_guide_version", "2.0.0"),
    ("protocol", "integration_guide_version", "1.16.9"),
    ("protocol", "integration_guide_version", "1.18"),
    ("protocol", "coordination_protocol_version", 2),
    ("protocol", "capabilities", []),
    ("compatibility", "python_requires", ">=3.14"),
    ("build", "build_python", "3.14"),
    ("release", "source_commit", "9" * 40),
    ("release", "source_tree", "9" * 40),
])
def test_installed_exact_policy_blocks_unknown_compatibility(fixture_api, section, field, value):
    api, reader = fixture_api
    manifest_path = api.directory / validation.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_bytes())
    manifest[section][field] = value
    manifest_path.write_bytes(validation._canonical_json(manifest))
    _rehash(api.directory)
    _refresh_assets(api)
    candidate = reader.check("0.2.27", deadline=220).candidate
    with pytest.raises(UpdateError, match="verification_failed"):
        source.verify_prepared(candidate, api.directory, UpdateLimits())


def _with_database(api, *, current, rollback, guide=None):
    manifest_path = api.directory / validation.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_bytes())
    manifest["compatibility"]["database"].update(current_schema=current, rollback_previous_schema=rollback)
    if guide is not None:
        manifest["protocol"]["integration_guide_version"] = guide
    manifest_path.write_bytes(validation._canonical_json(manifest))
    _rehash(api.directory)
    _refresh_assets(api)


@pytest.mark.parametrize("ahead", [1, 2, 5])
def test_installed_policy_accepts_any_forward_migration(fixture_api, ahead):
    api, reader = fixture_api
    current = validation.CURRENT_SCHEMA + ahead
    _with_database(api, current=current, rollback=current - 1, guide="1.19.0")
    candidate = reader.check("0.2.27", deadline=220).candidate
    source.verify_prepared(candidate, api.directory, UpdateLimits())
    with pytest.raises(validation.ReleaseBundleError, match="schema compatibility"):
        validation.validate_bundle(api.directory, expected_repository=source.UPDATE_SOURCE_REPOSITORY)


@pytest.mark.parametrize("current,rollback", [
    (validation.CURRENT_SCHEMA + 2, validation.CURRENT_SCHEMA),
    (validation.CURRENT_SCHEMA + 1, validation.ROLLBACK_PREVIOUS_SCHEMA),
    (validation.MAX_SCHEMA + 1, validation.MAX_SCHEMA),
    (validation.CURRENT_SCHEMA - 1, validation.ROLLBACK_PREVIOUS_SCHEMA - 1),
    (validation.CURRENT_SCHEMA, validation.CURRENT_SCHEMA),
])
def test_installed_policy_blocks_other_schema_transitions(fixture_api, current, rollback):
    api, reader = fixture_api
    _with_database(api, current=current, rollback=rollback)
    candidate = reader.check("0.2.27", deadline=220).candidate
    with pytest.raises(UpdateError, match="verification_failed"):
        source.verify_prepared(candidate, api.directory, UpdateLimits())


def test_canonical_candidate_code_is_never_imported_or_executed(fixture_api, tmp_path):
    api, reader = fixture_api
    sentinel = tmp_path / "candidate-executed"
    members = wheel_members(VERSION)
    members["strugglebus/__init__.py"] = (
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('executed')\n"
        "raise RuntimeError('candidate must never execute')\n"
    ).encode()
    record = f"strugglebus-{VERSION}.dist-info/RECORD"
    members[record] = ("\n".join(
        f"{name},{_record_hash(payload)},{len(payload)}" for name, payload in sorted(members.items()) if name != record
    ) + f"\n{record},,\n").encode()
    raw = tmp_path / "untrusted.whl"
    write_wheel(raw, VERSION, members=members)
    wheel = api.directory / f"strugglebus-{VERSION}-py3-none-any.whl"
    wheel.unlink()
    load_script("canonical_wheel").normalize_wheel(raw, wheel, timestamp=1_700_000_000)
    wheel.chmod(0o600)
    _rehash(api.directory)
    _refresh_assets(api)
    candidate = reader.check("0.2.27", deadline=220).candidate
    source.verify_prepared(candidate, api.directory, UpdateLimits())
    assert not sentinel.exists()


def test_publisher_and_installed_reader_share_the_same_verifier():
    publisher = load_script("publish_immutable_release")
    bundle = load_script("release_bundle")
    canonical = load_script("canonical_wheel")
    from strugglebus import release_records, release_wheel
    assert bundle.validate_bundle is validation.validate_bundle
    assert canonical.verify_canonical_wheel is release_wheel.verify_canonical_wheel
    assert publisher._validate_asset_records is release_records._validate_asset_records
    assert publisher._validate_release_record is release_records._validate_release_record


@pytest.mark.parametrize("change", ["count", "duplicates", "total", "extra_page", "release_id"])
def test_candidate_resolution_rejects_incomplete_or_overbudget_identity(fixture_api, change):
    api, reader = fixture_api
    if change == "count":
        api.assets.pop()
    elif change == "duplicates":
        api.assets[-1] = api.assets[0]
    elif change == "total":
        reader._limits = replace(reader._limits, candidate_bytes=1)
    elif change == "release_id":
        api.routes[f"{source._ROOT}/releases/81"] = {**api.release, "id": 82}
    else:
        api.routes[tag_answer()] = tag_refs(*(f"bus/v0.1.{i}" for i in range(101)))
        with pytest.raises(UpdateError, match="invalid_metadata"):
            reader.check("0.2.27", deadline=220)
        return
    result = reader.check("0.2.27", deadline=220)
    assert result.candidate is None and result.blocked_reason is not None


def test_partial_resolution_links_are_not_silently_ignored():
    session = SimpleNamespace(get=lambda path: ({}, True))
    with pytest.raises(UpdateError, match="invalid_metadata"):
        source._get_object(session, "/fixed")
    session.get = lambda path: ([], True)
    with pytest.raises(UpdateError, match="invalid_metadata"):
        source._resolve(session, 1, VERSION, UpdateLimits())


def test_read_errors_are_not_reported_as_no_update(fixture_api):
    api, reader = fixture_api
    api.routes[f"{source._ROOT}/releases/81"] = OSError("secret upstream")
    with pytest.raises(UpdateError, match="source_unavailable"):
        reader.check("0.2.27", deadline=220)


def test_candidate_offline_limits_and_file_links(fixture_api, publication):
    _, reader = fixture_api
    candidate = reader.check("0.2.27", deadline=220).candidate
    with pytest.raises(UpdateError, match="verification_failed"):
        source.verify_prepared(candidate, publication, replace(UpdateLimits(), candidate_bytes=1))
    bad_asset = replace(candidate.assets[0], name="other")
    with pytest.raises(UpdateError, match="verification_failed"):
        source.verify_prepared(replace(candidate, assets=(bad_asset, *candidate.assets[1:])), publication, UpdateLimits())
    bad_asset = replace(candidate.assets[0], media_type="text/html")
    with pytest.raises(UpdateError, match="verification_failed"):
        source.verify_prepared(replace(candidate, assets=(bad_asset, *candidate.assets[1:])), publication, UpdateLimits())
    asset = candidate.assets[0]
    path = publication / asset.name
    link = publication.parent / "extra-hardlink"
    os.link(path, link)
    with pytest.raises(UpdateError, match="storage_unsafe"):
        source.verify_prepared(candidate, publication, UpdateLimits())
    link.unlink()


def test_offline_inode_substitution_is_rejected(fixture_api, publication, monkeypatch):
    _, reader = fixture_api
    candidate = reader.check("0.2.27", deadline=220).candidate
    actual = source._file_stamp
    counts = {}

    def substituted(path, asset):
        result = actual(path, asset)
        counts[path] = counts.get(path, 0) + 1
        if counts[path] > 1:
            return result[0], result[1] + 1, *result[2:]
        return result

    monkeypatch.setattr(source, "_file_stamp", substituted)
    with pytest.raises(UpdateError, match="storage_unsafe"):
        source.verify_prepared(candidate, publication, UpdateLimits())


def test_posix_offline_ownership_is_fail_closed(fixture_api, publication, monkeypatch):
    _, reader = fixture_api
    candidate = reader.check("0.2.27", deadline=220).candidate
    facade = SimpleNamespace(name="posix", geteuid=lambda: 987654321)
    monkeypatch.setattr(source, "os", facade)
    with pytest.raises(UpdateError, match="storage_unsafe"):
        source._file_stamp(publication / candidate.assets[0].name, candidate.assets[0])


def test_prepare_missing_directory_is_static_storage_failure(fixture_api, tmp_path):
    _, reader = fixture_api
    candidate = reader.check("0.2.27", deadline=220).candidate
    with pytest.raises(UpdateError, match="storage_unsafe"):
        reader.prepare(candidate, tmp_path / "missing", deadline=700)
