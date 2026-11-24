"""Local promotion doubles that retain the real release trust gates."""

from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import Path
import stat
from typing import Any, Callable, Iterator
import zipfile

from release_fixtures import (
    ARTIFACT_ID,
    OWNER,
    PUBLISHED_AT,
    QUALIFICATION_RUN_ID,
    REPOSITORY,
    build_pre_tag_bundle,
    canonical_json,
    load_script,
    qualification_responses,
    write_qualification_receipt,
)


VERSION = load_script("release_bundle")._package_version(REPOSITORY)
REPO = f"{OWNER}/strugglebus"
ROOT = f"repos/{REPO}"
CI_RUN_ID = 42
RELEASE_ID = 7
PUBLISHER_RUN_ID = 5151


def copy_json(value: Any) -> Any:
    return json.loads(canonical_json(value))


@dataclass(frozen=True)
class QualifiedBundle:
    directory: Path
    commit: str
    tree: str
    tag: str
    assets: dict[str, bytes]
    receipt: bytes
    archive: bytes


def qualification_zip(
    assets: dict[str, bytes],
    receipt: bytes,
    *,
    extra: tuple[str, bytes] | None = None,
    link: str | None = None,
) -> bytes:
    qualification = load_script("release_qualification")
    output = io.BytesIO()
    members = [(f"release-assets/{name}", data) for name, data in sorted(assets.items())]
    members.append((f"qualification/{qualification.RECEIPT_NAME}", receipt))
    if extra is not None:
        members.append(extra)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members:
            member = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.external_attr = (
                (stat.S_IFLNK if name == link else stat.S_IFREG) | 0o600
            ) << 16
            member.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(member, data)
    return output.getvalue()


def build_qualified_bundle(directory: Path) -> QualifiedBundle:
    assets_directory, commit, tree, version = build_pre_tag_bundle(directory)
    assert version == VERSION
    tag = f"v{version}"
    binding = write_qualification_receipt(
        assets_directory,
        directory / "qualification",
        repository=REPO,
        tag=tag,
        commit=commit,
        tree=tree,
        version=version,
    )
    assets = {path.name: path.read_bytes() for path in assets_directory.iterdir()}
    receipt = binding.receipt_path.read_bytes()
    return QualifiedBundle(
        directory=assets_directory,
        commit=commit,
        tree=tree,
        tag=tag,
        assets=assets,
        receipt=receipt,
        archive=qualification_zip(assets, receipt),
    )


class MemoryReceiptStore:
    """Protocol double: immutable snapshots, exclusive create, and writer locking."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.content: bytes | None = None
        self.snapshots: list[dict[str, Any]] = []
        self.reads = 0
        self.locks = 0
        self._locked = False
        self.after_write: Callable[[dict[str, Any]], None] | None = None

    @contextmanager
    def locked(self) -> Iterator[None]:
        assert not self._locked, "promotion must not recursively acquire its lock"
        self._locked = True
        self.locks += 1
        try:
            yield
        finally:
            self._locked = False

    def read(self) -> dict[str, Any]:
        self.reads += 1
        if self.content is None:
            raise load_script("promotion_common").PromotionError("receipt does not exist")
        return json.loads(self.content)

    def write(self, operation: dict[str, Any], *, create: bool = False) -> None:
        assert self._locked, "receipt intent must be saved under the stable writer lock"
        if create == (self.content is not None):
            raise load_script("promotion_common").PromotionError(
                "receipt already exists" if create else "receipt does not exist"
            )
        self.content = canonical_json(operation)
        self.snapshots.append(json.loads(self.content))
        if self.after_write is not None:
            self.after_write(copy_json(operation))


class FakePromotionAPI:
    """Only three mutations exist; publishing is an independently observed event."""

    def __init__(self, bundle: QualifiedBundle, store: MemoryReceiptStore) -> None:
        self.bundle = bundle
        self.store = store
        self.events: list[tuple[Any, ...]] = []
        self.mutations: list[tuple[str, Any]] = []
        self.intent_snapshots: list[dict[str, Any]] = []
        self.responses: dict[str, Any] = {}
        self.runs: list[dict[str, Any]] = []
        self.publisher_runs: list[dict[str, Any]] = []
        self.tag_objects: dict[str, dict[str, Any]] = {}
        self.tag_ref: dict[str, Any] | None = None
        self.release: dict[str, Any] | None = None
        self.stored_assets: dict[str, bytes] = {}
        self.asset_overrides: dict[str, dict[str, Any]] = {}
        self.asset_download_override: dict[str, bytes] = {}
        self.archive = bundle.archive
        self.loss_once: set[str] = set()
        self.visible_dispatch = True
        self.publish_on_ref: str | None = "immutable"
        self.unexpected_tag_sha = False
        self.before_get: Callable[[str], None] | None = None
        self.after_mutation: Callable[[str], None] | None = None
        self.source_version = VERSION
        self._install_gate_responses()
        self.install_qualification(visible=False)

    @property
    def all_runs_path(self) -> str:
        qualification = load_script("release_qualification")
        return (
            f"{ROOT}/actions/workflows/{qualification.QUALIFICATION_WORKFLOW}/runs?"
            f"event=workflow_dispatch&head_sha={self.bundle.commit}&per_page=100"
        )

    @property
    def resolved_runs_path(self) -> str:
        return self.all_runs_path.replace("&per_page=", "&status=completed&per_page=")

    @property
    def publication_runs_path(self) -> str:
        return (
            f"{ROOT}/actions/workflows/release.yml/runs?"
            f"event=create&head_sha={self.bundle.commit}&per_page=100"
        )

    def _install_gate_responses(self) -> None:
        trigger = load_script("validate_release_trigger")
        commit = self.bundle.commit
        self.responses.update(
            {
                "user": {"login": OWNER},
                ROOT: {"full_name": REPO, "default_branch": "main"},
                f"{ROOT}/immutable-releases": {"enabled": True},
                f"{ROOT}/branches/main": {"commit": {"sha": commit}},
                f"{ROOT}/git/commits/{commit}": {
                    "sha": commit, "tree": {"sha": self.bundle.tree}
                },
                (
                    f"{ROOT}/actions/workflows/ci.yml/runs?"
                    f"event=push&head_sha={commit}&status=completed&per_page=100"
                ): {
                    "total_count": 1,
                    "workflow_runs": [
                        {
                            "id": CI_RUN_ID, "event": "push", "head_sha": commit,
                            "head_branch": "main", "status": "completed",
                            "conclusion": "success",
                        }
                    ],
                },
                f"{ROOT}/actions/runs/{CI_RUN_ID}/jobs?per_page=100": {
                    "total_count": len(trigger.REQUIRED_CI_JOBS),
                    "jobs": [
                        {"name": name, "status": "completed", "conclusion": "success"}
                        for name in sorted(trigger.REQUIRED_CI_JOBS)
                    ],
                },
            }
        )

    def install_qualification(
        self, *, visible: bool = True, run_id: int = QUALIFICATION_RUN_ID
    ) -> dict[str, Any]:
        responses = qualification_responses(
            repository=REPO,
            tag=self.bundle.tag,
            commit=self.bundle.commit,
            run_id=run_id,
            artifact_id=ARTIFACT_ID + run_id - QUALIFICATION_RUN_ID,
            artifact_digest=hashlib.sha256(self.archive).hexdigest(),
            artifact_size=len(self.archive),
        )
        run = responses.pop(self.resolved_runs_path)["workflow_runs"][0]
        for response in responses.values():
            response["total_count"] = len(response["artifacts"])
        self.responses.update(responses)
        if visible:
            self.runs.append(run)
        return run

    def replace_archive(self, payload: bytes) -> None:
        self.archive = payload
        for path, response in self.responses.items():
            if "/artifacts?" in path:
                for artifact in response["artifacts"]:
                    artifact["size_in_bytes"] = len(payload)
                    artifact["digest"] = hashlib.sha256(payload).hexdigest()

    def artifact_record(self, run_id: int = QUALIFICATION_RUN_ID) -> dict[str, Any]:
        path = f"{ROOT}/actions/runs/{run_id}/artifacts?page=1&per_page=100"
        return self.responses[path]["artifacts"][0]

    def _source(self, path: str) -> dict[str, Any]:
        if path == "src/strugglebus/__init__.py":
            content = (REPOSITORY / path).read_bytes()
            if self.source_version != VERSION:
                content = content.replace(
                    f'__version__ = "{VERSION}"'.encode(),
                    f'__version__ = "{self.source_version}"'.encode(),
                )
        else:
            assert path == "scripts/canonical_wheel.py", path
            content = (REPOSITORY / path).read_bytes()
        return {
            "type": "file", "encoding": "base64", "path": path,
            "size": len(content), "content": base64.b64encode(content).decode("ascii"),
        }

    def _lookup(self, path: str, *, optional: bool) -> Any:
        if self.before_get is not None:
            self.before_get(path)
        if path in self.responses:
            return copy_json(self.responses[path])
        if path in {self.all_runs_path, self.resolved_runs_path}:
            runs = self.runs
            if path == self.resolved_runs_path:
                runs = [run for run in runs if run["status"] == "completed"]
            return copy_json({"total_count": len(runs), "workflow_runs": runs})
        if path == self.publication_runs_path:
            return copy_json({
                "total_count": len(self.publisher_runs),
                "workflow_runs": self.publisher_runs,
            })
        if path == f"{ROOT}/git/ref/tags/{self.bundle.tag}":
            if not optional:
                assert self.tag_ref is not None
            return copy_json(self.tag_ref)
        if path.startswith(f"{ROOT}/git/tags/"):
            record = self.tag_objects.get(path.rsplit("/", 1)[1])
            if not optional:
                assert record is not None, path
            return copy_json(record)
        if path.startswith(f"{ROOT}/contents/"):
            source, query = path.removeprefix(f"{ROOT}/contents/").split("?", 1)
            assert query == f"ref={self.bundle.commit}"
            return self._source(source)
        raise AssertionError(f"unexpected GitHub read: {path}")

    def get(self, path: str) -> Any:
        self.events.append(("get", path))
        return self._lookup(path, optional=False)

    def optional_get(self, path: str) -> Any:
        self.events.append(("optional_get", path))
        return self._lookup(path, optional=True)

    def _intent(self, mutation: str, payload: Any, phase: str) -> None:
        assert self.store._locked
        assert self.store.content is not None, "remote mutation preceded durable receipt"
        snapshot = json.loads(self.store.content)
        assert snapshot["phase"] == phase, "remote mutation preceded its exact durable intent"
        assert snapshot["commit"] == self.bundle.commit
        assert snapshot["tag"] == self.bundle.tag
        assert mutation not in [name for name, _ in self.mutations], "mutation was repeated"
        self.intent_snapshots.append(snapshot)
        self.mutations.append((mutation, copy_json(payload)))
        self.events.append((mutation,))

    def _accepted(self, mutation: str) -> None:
        if self.after_mutation is not None:
            self.after_mutation(mutation)
        if mutation in self.loss_once:
            self.loss_once.remove(mutation)
            raise load_script("promotion_common").PromotionError(
                "GitHub request failed; accepted outcome is unknown", code=5
            )

    def dispatch(self, tag: str, commit: str) -> None:
        assert (tag, commit) == (self.bundle.tag, self.bundle.commit)
        self._intent("dispatch", {"tag": tag, "commit": commit}, "dispatch_intent")
        assert self.intent_snapshots[-1]["dispatch"] == {
            "acknowledged": False, "baseline_ids": []
        }
        if self.visible_dispatch:
            self.install_qualification()
        self._accepted("dispatch")

    def create_tag(self, payload: dict[str, Any]) -> dict[str, Any]:
        module = load_script("promote_release")
        self._intent("create_tag", payload, "tag_object_intent")
        assert self.intent_snapshots[-1]["tag_intent"]["payload"] == payload
        sha = module.tag_object_sha(payload)
        if self.unexpected_tag_sha:
            sha = "f" * 40
        record = {
            "sha": sha, "tag": payload["tag"], "message": payload["message"],
            "tagger": copy_json(payload["tagger"]),
            "object": {"type": payload["type"], "sha": payload["object"]},
        }
        self.tag_objects[sha] = record
        self._accepted("create_tag")
        return copy_json(record)

    def create_ref(self, tag: str, sha: str) -> dict[str, Any]:
        self._intent("create_ref", {"tag": tag, "sha": sha}, "tag_ref_intent")
        assert sha == self.intent_snapshots[-1]["tag_intent"]["expected_sha"]
        assert self.tag_ref is None, "tag refs must only ever be created once"
        self.tag_ref = {"ref": f"refs/tags/{tag}", "object": {"type": "tag", "sha": sha}}
        self.publisher_runs = [
            {
                "actor": {"login": OWNER}, "triggering_actor": {"login": OWNER},
                "id": PUBLISHER_RUN_ID, "run_attempt": 1, "event": "create",
                "head_sha": self.bundle.commit, "head_branch": tag,
                "status": "in_progress", "conclusion": None,
            }
        ]
        if self.publish_on_ref is not None:
            names = None if self.publish_on_ref == "immutable" else {"requirements.lock"}
            self.publish(self.publish_on_ref, names=names)
        self._accepted("create_ref")
        return copy_json(self.tag_ref)

    def publish(self, state: str = "immutable", *, names: set[str] | None = None) -> None:
        assert state in {"draft", "immutable"}
        self.release = {
            "id": RELEASE_ID, "tag_name": self.bundle.tag,
            "target_commitish": self.bundle.commit, "name": self.bundle.tag,
            "body": f"Canonical immutable Strugglebus release {self.bundle.tag}.",
            "prerelease": False, "draft": state == "draft", "immutable": state == "immutable",
        }
        selected = set(self.bundle.assets) if names is None else names
        self.stored_assets = {name: self.bundle.assets[name] for name in selected}

    def find_release(self, repository: str, tag: str) -> Any:
        assert (repository, tag) == (REPO, self.bundle.tag)
        self.events.append(("find_release", repository, tag))
        return copy_json(self.release)

    def list_assets(self, repository: str, release_id: int) -> list[dict[str, Any]]:
        assert (repository, release_id) == (REPO, RELEASE_ID)
        publisher = load_script("publish_immutable_release")
        self.events.append(("list_assets", repository, release_id))
        records = []
        for asset_id, name in enumerate(sorted(self.bundle.assets), 100):
            if name not in self.stored_assets:
                continue
            content = self.stored_assets[name]
            record = {
                "id": asset_id, "name": name, "label": None, "state": "uploaded",
                "size": len(content), "digest": f"sha256:{hashlib.sha256(content).hexdigest()}",
                "content_type": publisher._asset_media_type(name),
            }
            record.update(self.asset_overrides.get(name, {}))
            records.append(record)
        return copy_json(records)

    def download_artifact(self, artifact: Any, destination: Path) -> None:
        self.events.append(("download_artifact", artifact.id))
        assert artifact.id == ARTIFACT_ID
        assert artifact.size_bytes == len(self.archive)
        assert artifact.digest == hashlib.sha256(self.archive).hexdigest()
        destination.write_bytes(self.archive)

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
        assert repository == REPO
        assert asset_id == sorted(self.bundle.assets).index(expected_name) + 100
        content = self.stored_assets[expected_name]
        assert expected_size == len(content)
        assert expected_sha256 == hashlib.sha256(content).hexdigest()
        assert expected_media_type == load_script("publish_immutable_release")._asset_media_type(
            expected_name
        )
        self.events.append(("download_asset", expected_name))
        destination.write_bytes(self.asset_download_override.get(expected_name, content))


def no_wait(_: float) -> None:
    pass


def deadline_sleep(_: float) -> None:
    raise load_script("promotion_common").PromotionError("invocation deadline reached", code=5)


def deadline_after_one_poll() -> Callable[[float], None]:
    polls = 0

    def sleep(seconds: float) -> None:
        nonlocal polls
        polls += 1
        if polls > 1:
            deadline_sleep(seconds)

    return sleep


def run_promotion(api: FakePromotionAPI, *, resume: bool = False, **kwargs: Any) -> Any:
    promotion = load_script("promote_release")
    return promotion.promote(
        api, api.store, tag=api.bundle.tag, commit=api.bundle.commit,
        approval=promotion.APPROVAL_PHRASE, resume=resume,
        now=lambda: PUBLISHED_AT, sleep=kwargs.pop("sleep", no_wait), **kwargs,
    )
