from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any, Callable

import pytest

from release_fixtures import (
    ARTIFACT_ID,
    ARTIFACT_SIZE,
    QUALIFICATION_RUN_ID,
    qualification_responses,
    write_qualification_receipt,
    write_wheel,
)


REPOSITORY = Path(__file__).resolve().parents[1]
SCRIPTS = REPOSITORY / "scripts"
sys.path.insert(0, str(SCRIPTS))


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


BUNDLE = _load("release_bundle", SCRIPTS / "release_bundle.py")
TRIGGER = _load("validate_release_trigger", SCRIPTS / "validate_release_trigger.py")
QUALIFICATION = _load(
    "release_qualification",
    SCRIPTS / "release_qualification.py",
)
PUBLISHER = _load(
    "publish_immutable_release",
    SCRIPTS / "publish_immutable_release.py",
)

COMMIT = "1" * 40
TREE = "2" * 40
TAG_OBJECT = "3" * 40
TAG = "v0.2.0"


def _write_wheel(path: Path) -> None:
    write_wheel(path, "0.2.0")


def _bundle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist / "strugglebus-0.2.0-py3-none-any.whl")
    uv = tmp_path / "uv"
    uv.write_bytes(b"pinned uv")
    output = tmp_path / "release"
    monkeypatch.setattr(
        BUNDLE,
        "resolve_release_identity",
        lambda *args, **kwargs: (COMMIT, TREE, 1_700_000_000, "0.2.0"),
    )
    BUNDLE.build_bundle(REPOSITORY, dist, output, TAG, uv_binary=uv)
    return output


def _trigger_responses() -> dict[str, dict[str, Any]]:
    responses: dict[str, Any] = {
        f"repos/{BUNDLE.REPOSITORY_ID}/git/ref/tags/{TAG}": {
            "object": {"type": "tag", "sha": TAG_OBJECT}
        },
        f"repos/{BUNDLE.REPOSITORY_ID}/git/tags/{TAG_OBJECT}": {
            "tag": TAG,
            "object": {"type": "commit", "sha": COMMIT},
        },
        f"repos/{BUNDLE.REPOSITORY_ID}": {
            "default_branch": "main",
        },
        f"repos/{BUNDLE.REPOSITORY_ID}/immutable-releases": {"enabled": True},
        f"repos/{BUNDLE.REPOSITORY_ID}/branches/main": {
            "commit": {"sha": COMMIT}
        },
        (
            f"repos/{BUNDLE.REPOSITORY_ID}/actions/workflows/ci.yml/runs?"
            f"event=push&head_sha={COMMIT}&status=completed&per_page=100"
        ): {
            "workflow_runs": [
                {
                    "id": 42,
                    "event": "push",
                    "head_sha": COMMIT,
                    "head_branch": "main",
                    "status": "completed",
                    "conclusion": "success",
                }
            ]
        },
        f"repos/{BUNDLE.REPOSITORY_ID}/actions/runs/42/jobs?per_page=100": {
            "jobs": [
                {
                    "name": name,
                    "status": "completed",
                    "conclusion": "success",
                }
                for name in TRIGGER.REQUIRED_CI_JOBS
            ]
        },
    }
    responses.update(
        qualification_responses(
            repository=BUNDLE.REPOSITORY_ID,
            tag=TAG,
            commit=COMMIT,
        )
    )
    return responses


class FakeAPI:
    def __init__(
        self,
        directory: Path,
        *,
        state: str = "absent",
        existing_names: set[str] | None = None,
    ) -> None:
        self.directory = directory
        self.events: list[tuple[Any, ...]] = []
        self.responses = _trigger_responses()
        self.release: dict[str, Any] | None = None
        self.stored: dict[str, bytes] = {}
        self.asset_ids: dict[str, int] = {}
        self.metadata_overrides: dict[str, dict[str, Any]] = {}
        self.records_transform: (
            Callable[[list[dict[str, Any]]], list[dict[str, Any]]] | None
        ) = None
        self.create_error_after_mutation = False
        self.upload_error_after_mutation: str | None = None
        self.publish_error_after_mutation = False
        self.corrupt_download_number: dict[str, int] = {}
        self.download_counts: dict[str, int] = {}
        if state not in {"absent", "draft", "immutable"}:
            raise ValueError(state)
        if state != "absent":
            self.release = self._release_record(immutable=state == "immutable")
            selected = (
                {path.name for path in directory.iterdir()}
                if existing_names is None
                else existing_names
            )
            for name in sorted(selected):
                self._store(name, (directory / name).read_bytes())

    @staticmethod
    def _release_record(*, immutable: bool) -> dict[str, Any]:
        return {
            "id": 7,
            "tag_name": TAG,
            "target_commitish": COMMIT,
            "name": TAG,
            "body": f"Canonical immutable Strugglebus release {TAG}.",
            "prerelease": False,
            "draft": not immutable,
            "immutable": immutable,
        }

    def _store(self, name: str, content: bytes) -> None:
        self.stored[name] = content
        self.asset_ids.setdefault(name, len(self.asset_ids) + 100)

    def _asset_record(self, name: str) -> dict[str, Any]:
        content = self.stored[name]
        record = {
            "id": self.asset_ids[name],
            "name": name,
            "label": None,
            "state": "uploaded",
            "size": len(content),
            "digest": f"sha256:{hashlib.sha256(content).hexdigest()}",
            "content_type": PUBLISHER._asset_media_type(name),
        }
        record.update(self.metadata_overrides.get(name, {}))
        return record

    def get(self, path: str) -> Any:
        self.events.append(("get", path))
        return json.loads(json.dumps(self.responses[path]))

    def find_release(
        self,
        repository: str,
        tag: str,
    ) -> dict[str, Any] | None:
        self.events.append(("find_release", repository, tag))
        if self.release is None:
            return None
        return json.loads(json.dumps(self.release))

    def create_draft(
        self,
        repository: str,
        tag: str,
        commit: str,
        body: str,
    ) -> dict[str, Any]:
        self.events.append(("create_draft", repository, tag, commit, body))
        if self.release is not None:
            raise AssertionError("duplicate draft creation")
        self.release = self._release_record(immutable=False)
        if self.create_error_after_mutation:
            raise PUBLISHER.ReleasePublicationError("ambiguous create failure")
        return json.loads(json.dumps(self.release))

    def list_assets(
        self,
        repository: str,
        release_id: int,
    ) -> list[dict[str, Any]]:
        self.events.append(("list_assets", repository, release_id))
        records = [
            self._asset_record(name)
            for name in sorted(self.stored)
        ]
        if self.records_transform is not None:
            records = self.records_transform(records)
        return json.loads(json.dumps(records))

    def upload_asset(
        self,
        repository: str,
        release_id: int,
        asset: Any,
    ) -> dict[str, Any]:
        self.events.append(
            ("upload_asset", repository, release_id, asset.name, asset.media_type)
        )
        if asset.name in self.stored:
            raise AssertionError("duplicate asset upload")
        self._store(asset.name, asset.path.read_bytes())
        if self.upload_error_after_mutation == asset.name:
            raise PUBLISHER.ReleasePublicationError("ambiguous upload failure")
        return self._asset_record(asset.name)

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
    ) -> None:
        self.events.append(
            (
                "download_asset",
                repository,
                asset_id,
                expected_name,
                expected_size,
                expected_media_type,
                expected_sha256,
            )
        )
        if self.asset_ids.get(expected_name) != asset_id:
            raise AssertionError("asset ID/name mismatch")
        if (
            hashlib.sha256(self.directory.joinpath(expected_name).read_bytes()).hexdigest()
            != expected_sha256
        ):
            raise AssertionError("asset digest mismatch")
        content = self.stored[expected_name]
        self.download_counts[expected_name] = (
            self.download_counts.get(expected_name, 0) + 1
        )
        if (
            self.corrupt_download_number.get(expected_name)
            == self.download_counts[expected_name]
        ):
            content = bytes([content[0] ^ 1]) + content[1:]
        destination.write_bytes(content)

    def publish_release(
        self,
        repository: str,
        release_id: int,
    ) -> dict[str, Any]:
        self.events.append(("publish_release", repository, release_id))
        if self.release is None:
            raise AssertionError("release is absent")
        self.release["draft"] = False
        self.release["immutable"] = True
        if self.publish_error_after_mutation:
            raise PUBLISHER.ReleasePublicationError("ambiguous publish failure")
        return json.loads(json.dumps(self.release))


def _publish(
    api: FakeAPI,
    directory: Path,
    *,
    trigger_api: FakeAPI | None = None,
    binding: Any | None = None,
) -> dict[str, Any]:
    return PUBLISHER.publish_immutable_release(
        api,
        directory,
        repository=BUNDLE.REPOSITORY_ID,
        tag=TAG,
        commit=COMMIT,
        tree=TREE,
        actor="NZCypher819",
        workflow_sha=COMMIT,
        qualification=_binding(directory) if binding is None else binding,
        trigger_api=trigger_api,
    )


def _binding(directory: Path, **overrides: Any) -> Any:
    return write_qualification_receipt(
        directory,
        directory.parent / "qualification",
        repository=BUNDLE.REPOSITORY_ID,
        tag=TAG,
        commit=COMMIT,
        tree=TREE,
        version="0.2.0",
        **overrides,
    )


def _event_names(api: FakeAPI) -> list[str]:
    return [str(event[0]) for event in api.events]


def _mutations(api: FakeAPI) -> list[str]:
    """Return every release-mutating call the publisher attempted."""

    mutating = {
        "create_draft",
        "upload_asset",
        "publish_release",
        "delete_release",
        "delete_asset",
        "update_release",
    }
    return [name for name in _event_names(api) if name in mutating]


def test_absent_release_reaches_exact_immutable_state_without_gh(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    empty_path = tmp_path / "empty-path"
    empty_path.mkdir()
    monkeypatch.setenv("PATH", os.fspath(empty_path))
    assert shutil.which("gh") is None
    api = FakeAPI(directory)

    result = _publish(api, directory)

    names = _event_names(api)
    expected_assets = {path.name for path in directory.iterdir()}
    uploaded = {
        str(event[3])
        for event in api.events
        if event[0] == "upload_asset"
    }
    assert result["immutable"] is True
    assert result["draft"] is False
    assert uploaded == expected_assets
    assert names.count("create_draft") == 1
    assert names.count("upload_asset") == 5
    assert names.count("publish_release") == 1
    publish_index = names.index("publish_release")
    assert names.index("create_draft") < publish_index
    assert max(
        index
        for index, name in enumerate(names)
        if name == "upload_asset"
    ) < publish_index
    assert {
        str(event[3])
        for event in api.events[:publish_index]
        if event[0] == "download_asset"
    } == expected_assets
    assert {
        str(event[3])
        for event in api.events[publish_index + 1 :]
        if event[0] == "download_asset"
    } == expected_assets


def test_workflow_cli_executes_fixture_with_no_gh_on_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    empty_path = tmp_path / "workflow-path"
    empty_path.mkdir()
    monkeypatch.setenv("PATH", os.fspath(empty_path))
    monkeypatch.setenv("GITHUB_TOKEN", "read-token")
    monkeypatch.setenv("RELEASE_APP_TOKEN", "app-token")
    release_api = FakeAPI(directory)
    trigger_api = FakeAPI(directory)
    clients = {"app-token": release_api, "read-token": trigger_api}
    binding = _binding(directory)
    monkeypatch.setattr(
        PUBLISHER,
        "GitHubReleaseAPI",
        lambda api_url, token: clients[token],
    )
    monkeypatch.setattr(PUBLISHER.time, "time", lambda: float(binding.now))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "publish_immutable_release.py",
            os.fspath(directory),
            "--repository",
            BUNDLE.REPOSITORY_ID,
            "--tag",
            TAG,
            "--commit",
            COMMIT,
            "--tree",
            TREE,
            "--actor",
            "NZCypher819",
            "--workflow-sha",
            COMMIT,
            "--receipt",
            os.fspath(binding.receipt_path),
            "--qualification-run-id",
            str(binding.run_id),
            "--qualification-artifact-id",
            str(binding.artifact_id),
            "--qualification-artifact-name",
            binding.artifact_name,
            "--qualification-artifact-digest",
            binding.artifact_digest,
            "--qualification-artifact-size",
            str(binding.artifact_size_bytes),
            "--source-root",
            os.fspath(REPOSITORY),
        ],
    )

    assert shutil.which("gh") is None
    assert PUBLISHER.main() == 0
    assert json.loads(capsys.readouterr().out) == {
        "id": 7,
        "immutable": True,
        "tag": TAG,
    }


def test_partial_exact_draft_is_resumed_without_reupload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    names = sorted(path.name for path in directory.iterdir())
    existing = set(names[:2])
    api = FakeAPI(directory, state="draft", existing_names=existing)

    result = _publish(api, directory)

    uploaded = {
        str(event[3])
        for event in api.events
        if event[0] == "upload_asset"
    }
    assert result["immutable"] is True
    assert uploaded == set(names) - existing
    assert "create_draft" not in _event_names(api)


def test_exact_immutable_release_is_a_byte_verified_idempotent_noop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    api = FakeAPI(directory, state="immutable")

    result = _publish(api, directory)

    assert result["immutable"] is True
    assert "create_draft" not in _event_names(api)
    assert "upload_asset" not in _event_names(api)
    assert "publish_release" not in _event_names(api)
    assert {
        str(event[3])
        for event in api.events
        if event[0] == "download_asset"
    } == {path.name for path in directory.iterdir()}


def test_app_token_is_used_only_for_setting_and_release_operations(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    release_api = FakeAPI(directory)
    trigger_api = FakeAPI(directory)
    immutable_path = f"repos/{BUNDLE.REPOSITORY_ID}/immutable-releases"
    del trigger_api.responses[immutable_path]
    for path in tuple(release_api.responses):
        if path != immutable_path:
            del release_api.responses[path]

    result = _publish(release_api, directory, trigger_api=trigger_api)

    assert result["immutable"] is True
    release_gets = [
        event[1] for event in release_api.events if event[0] == "get"
    ]
    trigger_gets = [
        event[1] for event in trigger_api.events if event[0] == "get"
    ]
    assert release_gets == [immutable_path, immutable_path, immutable_path]
    assert immutable_path not in trigger_gets


@pytest.mark.parametrize(
    "mutation",
    [
        lambda api: api.release.update(body="conflicting"),
        lambda api: api.release.update(target_commitish="4" * 40),
        lambda api: api.release.update(prerelease=True),
        lambda api: api.release.update(draft=False, immutable=False),
    ],
)
def test_conflicting_release_metadata_is_rejected_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation: Callable[[FakeAPI], None],
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    api = FakeAPI(directory, state="draft")
    assert api.release is not None
    mutation(api)

    with pytest.raises(PUBLISHER.ReleasePublicationError):
        _publish(api, directory)

    assert "upload_asset" not in _event_names(api)
    assert "publish_release" not in _event_names(api)


@pytest.mark.parametrize(
    "transform",
    [
        lambda records: records + [dict(records[0])],
        lambda records: [dict(records[0], id=records[1]["id"]), *records[1:]],
        lambda records: [dict(records[0], name="unexpected"), *records[1:]],
        lambda records: [dict(records[0], content_type="text/html"), *records[1:]],
        lambda records: [
            dict(records[0], digest="sha256:" + "0" * 64),
            *records[1:],
        ],
    ],
)
def test_duplicate_unexpected_or_mismatched_assets_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    transform: Callable[[list[dict[str, Any]]], list[dict[str, Any]]],
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    api = FakeAPI(directory, state="draft")
    api.records_transform = transform

    with pytest.raises(PUBLISHER.ReleasePublicationError):
        _publish(api, directory)

    assert "publish_release" not in _event_names(api)


def test_remote_bytes_are_compared_even_when_metadata_claims_the_local_digest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    api = FakeAPI(directory, state="draft")
    name = sorted(api.stored)[0]
    original = api.stored[name]
    api.stored[name] = bytes([original[0] ^ 1]) + original[1:]
    local = directory / name
    api.metadata_overrides[name] = {
        "size": local.stat().st_size,
        "digest": f"sha256:{hashlib.sha256(local.read_bytes()).hexdigest()}",
    }

    with pytest.raises(
        PUBLISHER.ReleasePublicationError,
        match="downloaded release asset bytes differ",
    ):
        _publish(api, directory)

    assert "publish_release" not in _event_names(api)


def test_complete_draft_redownload_must_pass_before_publish(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    api = FakeAPI(directory)
    name = sorted(path.name for path in directory.iterdir())[0]
    api.corrupt_download_number[name] = 2

    with pytest.raises(
        PUBLISHER.ReleasePublicationError,
        match="downloaded release asset bytes differ",
    ):
        _publish(api, directory)

    assert "publish_release" not in _event_names(api)


def test_published_assets_are_redownloaded_after_irreversible_publish(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    api = FakeAPI(directory)
    name = sorted(path.name for path in directory.iterdir())[0]
    api.corrupt_download_number[name] = 3

    with pytest.raises(
        PUBLISHER.ReleasePublicationError,
        match="downloaded release asset bytes differ",
    ):
        _publish(api, directory)

    assert "publish_release" in _event_names(api)


@pytest.mark.parametrize(
    "failure",
    ["create", "upload", "publish"],
)
def test_ambiguous_mutation_failures_reconcile_only_exact_observed_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: str,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    api = FakeAPI(directory)
    if failure == "create":
        api.create_error_after_mutation = True
    elif failure == "upload":
        api.upload_error_after_mutation = sorted(
            path.name for path in directory.iterdir()
        )[0]
    else:
        api.publish_error_after_mutation = True

    result = _publish(api, directory)

    assert result["immutable"] is True
    assert result["draft"] is False


def test_disabled_immutable_setting_refuses_all_release_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    api = FakeAPI(directory)
    api.responses[
        f"repos/{BUNDLE.REPOSITORY_ID}/immutable-releases"
    ]["enabled"] = False

    with pytest.raises(TRIGGER.TriggerValidationError, match="must be enabled"):
        _publish(api, directory)

    assert "create_draft" not in _event_names(api)
    assert "upload_asset" not in _event_names(api)
    assert "publish_release" not in _event_names(api)


def test_temporary_downloads_are_cleaned_after_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    temporary_root = tmp_path / "publisher-temporary"
    temporary_root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", os.fspath(temporary_root))
    api = FakeAPI(directory)
    name = sorted(path.name for path in directory.iterdir())[0]
    api.corrupt_download_number[name] = 2

    with pytest.raises(PUBLISHER.ReleasePublicationError):
        _publish(api, directory)

    assert list(temporary_root.iterdir()) == []


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"run_id": QUALIFICATION_RUN_ID + 5}, "qualification run"),
        ({"artifact_id": ARTIFACT_ID + 5}, "artifact ID"),
        ({"artifact_size": ARTIFACT_SIZE + 5}, "artifact size"),
        ({"artifact_digest": "f" * 64}, "digest drifted"),
        ({"issued_at": 1_600_000_000, "validity_seconds": 3600}, "has expired"),
    ],
)
def test_qualification_drift_refuses_every_release_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    overrides: dict[str, Any],
    message: str,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    api = FakeAPI(directory)
    binding = _binding(directory, **overrides)

    with pytest.raises(QUALIFICATION.QualificationError, match=message):
        _publish(api, directory, binding=binding)

    names = _event_names(api)
    assert "create_draft" not in names
    assert "upload_asset" not in names
    assert "publish_release" not in names


def test_missing_or_tampered_qualification_receipt_refuses_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    api = FakeAPI(directory)
    binding = _binding(directory)
    binding.receipt_path.unlink()

    with pytest.raises(
        QUALIFICATION.QualificationError,
        match="missing qualification document",
    ):
        _publish(api, directory, binding=binding)
    assert _event_names(api).count("create_draft") == 0

    tampered = FakeAPI(directory)
    binding = _binding(directory)
    receipt = json.loads(binding.receipt_path.read_text(encoding="ascii"))
    receipt["assets"][0]["sha256"] = "0" * 64
    binding.receipt_path.write_bytes(QUALIFICATION._canonical_json(receipt))

    with pytest.raises(QUALIFICATION.QualificationError, match="digest drifted"):
        _publish(tampered, directory, binding=binding)
    assert "upload_asset" not in _event_names(tampered)

    drifted = FakeAPI(directory)
    binding = _binding(directory)
    receipt = json.loads(binding.receipt_path.read_text(encoding="ascii"))
    receipt["artifact"]["name"] = "strugglebus-qualified-release-other"
    binding.receipt_path.write_bytes(QUALIFICATION._canonical_json(receipt))

    with pytest.raises(QUALIFICATION.QualificationError, match="artifact name"):
        _publish(drifted, directory, binding=binding)
    assert "create_draft" not in _event_names(drifted)


def test_local_asset_tampering_refuses_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    api = FakeAPI(directory)
    binding = _binding(directory)
    wheel = directory / "strugglebus-0.2.0-py3-none-any.whl"
    wheel.write_bytes(wheel.read_bytes() + b"tampered")

    with pytest.raises(
        (BUNDLE.ReleaseBundleError, QUALIFICATION.QualificationError),
        match="size or digest mismatch|size drifted|digest drifted",
    ):
        _publish(api, directory, binding=binding)
    assert _mutations(api) == []

    extra = FakeAPI(directory)
    second_root = tmp_path / "second"
    second_root.mkdir()
    second = _bundle(monkeypatch, second_root)
    binding = write_qualification_receipt(
        second,
        tmp_path / "second-qualification",
        repository=BUNDLE.REPOSITORY_ID,
        tag=TAG,
        commit=COMMIT,
        tree=TREE,
        version="0.2.0",
    )
    (second / "unexpected-asset").write_text("extra", encoding="ascii")

    with pytest.raises(
        (BUNDLE.ReleaseBundleError, QUALIFICATION.QualificationError),
        match="unexpected|does not match the receipt",
    ):
        _publish(extra, second, binding=binding)
    assert _mutations(extra) == []


def test_missing_qualification_run_refuses_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    api = FakeAPI(directory)
    runs_path = next(
        path for path in api.responses if "release-qualification.yml" in path
    )
    api.responses[runs_path] = {"workflow_runs": []}

    with pytest.raises(
        QUALIFICATION.QualificationError,
        match="no successful owner qualification run",
    ):
        _publish(api, directory)

    assert _mutations(api) == []


def test_expired_or_duplicate_qualification_artifacts_refuse_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    artifacts_path = (
        f"repos/{BUNDLE.REPOSITORY_ID}/actions/runs/"
        f"{QUALIFICATION_RUN_ID}/artifacts?page=1&per_page=100"
    )

    expired = FakeAPI(directory)
    expired.responses[artifacts_path]["artifacts"][0]["expired"] = True
    with pytest.raises(
        QUALIFICATION.QualificationError,
        match="no unexpired qualification artifact",
    ):
        _publish(expired, directory)
    assert _mutations(expired) == []

    duplicate = FakeAPI(directory)
    records = duplicate.responses[artifacts_path]["artifacts"]
    records.append(dict(records[0], id=ARTIFACT_ID + 1))
    with pytest.raises(QUALIFICATION.QualificationError, match="exactly one"):
        _publish(duplicate, directory)
    assert _mutations(duplicate) == []


def test_publisher_performs_no_build_and_publishes_only_qualified_bytes() -> None:
    source = (SCRIPTS / "publish_immutable_release.py").read_text(encoding="utf-8")

    for forbidden in (
        "uv build",
        "subprocess",
        "shutil.which",
        "build_bundle(",
        "evidence",
    ):
        assert forbidden not in source
    assert "verify_qualified_release(" in source
    state_machine = source.split("def publish_immutable_release(", 1)[1]
    verification = state_machine.index("verify_qualified_release(")
    first_mutation = min(
        state_machine.index("api.create_draft("),
        state_machine.index("api.upload_asset("),
        state_machine.index("api.publish_release("),
    )
    assert verification < first_mutation
