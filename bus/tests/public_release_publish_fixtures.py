"""Dedicated fixtures for the public release mirror publisher."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Iterator

from release_fixtures import build_pre_tag_bundle, load_script
from release_signing import TEST_KEY
from strugglebus import release_signature


PUBLISHER = load_script("publish_public_release")
ANCHOR = "a" * 40
SOURCE_TAG_OBJECT = "b" * 40
RELEASE_ID = 71


class MemoryReceiptStore:
    def __init__(self) -> None:
        self.content: dict[str, Any] | None = None
        self.snapshots: list[dict[str, Any]] = []
        self.locked_now = False

    @contextmanager
    def locked(self) -> Iterator[None]:
        assert not self.locked_now
        self.locked_now = True
        try:
            yield
        finally:
            self.locked_now = False

    def read(self) -> dict[str, Any]:
        if self.content is None:
            raise PUBLISHER.PublicReleaseError("receipt does not exist")
        return json.loads(json.dumps(self.content))

    def write(self, value: dict[str, Any], *, create: bool = False) -> None:
        assert self.locked_now
        if create == (self.content is not None):
            raise PUBLISHER.PublicReleaseError("receipt state conflict")
        self.content = json.loads(json.dumps(value))
        self.snapshots.append(json.loads(json.dumps(value)))


class FakePublicReleaseAPI:
    def __init__(
        self,
        directory: Path,
        *,
        tag: str,
        commit: str,
        tree: str,
    ) -> None:
        self.directory = directory
        self.tag = tag
        self.commit = commit
        self.tree = tree
        self.events: list[tuple[Any, ...]] = []
        self.mutations: list[str] = []
        self.public_ref: dict[str, Any] | None = None
        self.public_tag_object: dict[str, Any] | None = None
        self.public_release: dict[str, Any] | None = None
        self.public_assets: dict[str, bytes] = {}
        self.asset_overrides: dict[str, dict[str, Any]] = {}
        self.source_release_overrides: dict[str, Any] = {}
        self.source_asset_overrides: dict[str, dict[str, Any]] = {}
        self.owner_login = PUBLISHER.OWNER
        self.public_immutable = True
        self.public_visibility = "public"
        self.public_private = False
        self.public_head = ANCHOR
        self.loss_once: set[str] = set()
        self.after_mutation: Callable[[str], None] | None = None
        self._source_assets = {
            path.name: path.read_bytes() for path in directory.iterdir()
        }

    def _event(self, name: str, *values: Any) -> None:
        self.events.append((name, *values))

    def _mutate(self, name: str) -> None:
        self.mutations.append(name)
        self._event(name)
        if self.after_mutation is not None:
            self.after_mutation(name)
        if name in self.loss_once:
            self.loss_once.remove(name)
            raise PUBLISHER.PublicReleaseError("ambiguous mutation")

    def owner(self) -> str:
        self._event("owner")
        return self.owner_login

    def repository(self, repository: str) -> dict[str, Any]:
        self._event("repository", repository)
        if repository == PUBLISHER.SOURCE_REPOSITORY:
            return {
                "default_branch": "main",
                "full_name": repository,
                "private": True,
                "visibility": "private",
            }
        assert repository == PUBLISHER.PUBLIC_REPOSITORY
        return {
            "default_branch": "main",
            "full_name": repository,
            "private": self.public_private,
            "visibility": self.public_visibility,
        }

    def immutable_releases(self, repository: str) -> bool:
        self._event("immutable_releases", repository)
        assert repository == PUBLISHER.PUBLIC_REPOSITORY
        return self.public_immutable

    def branch_head(self, repository: str, branch: str) -> str:
        self._event("branch_head", repository, branch)
        assert repository == PUBLISHER.PUBLIC_REPOSITORY
        assert branch == "main"
        return self.public_head

    def commit_tree(self, repository: str, commit: str) -> str:
        self._event("commit_tree", repository, commit)
        if repository == PUBLISHER.SOURCE_REPOSITORY:
            assert commit == self.commit
            return self.tree
        assert repository == PUBLISHER.PUBLIC_REPOSITORY
        assert commit == ANCHOR
        return "c" * 40

    def tag_ref(self, repository: str, tag: str) -> dict[str, Any] | None:
        self._event("tag_ref", repository, tag)
        assert tag == self.tag
        if repository == PUBLISHER.SOURCE_REPOSITORY:
            return {
                "ref": f"refs/tags/{tag}",
                "object": {"type": "tag", "sha": SOURCE_TAG_OBJECT},
            }
        assert repository == PUBLISHER.PUBLIC_REPOSITORY
        return json.loads(json.dumps(self.public_ref))

    def tag_object(self, repository: str, sha: str) -> dict[str, Any]:
        self._event("tag_object", repository, sha)
        if repository == PUBLISHER.SOURCE_REPOSITORY:
            assert sha == SOURCE_TAG_OBJECT
            return {
                "sha": sha,
                "tag": self.tag,
                "object": {"type": "commit", "sha": self.commit},
            }
        assert repository == PUBLISHER.PUBLIC_REPOSITORY
        assert self.public_tag_object is not None
        return json.loads(json.dumps(self.public_tag_object))

    def optional_tag_object(
        self, repository: str, sha: str
    ) -> dict[str, Any] | None:
        self._event("optional_tag_object", repository, sha)
        assert repository == PUBLISHER.PUBLIC_REPOSITORY
        if self.public_tag_object is None:
            return None
        assert self.public_tag_object["sha"] == sha
        return json.loads(json.dumps(self.public_tag_object))

    def releases(self, repository: str, tag: str) -> list[dict[str, Any]]:
        self._event("releases", repository, tag)
        assert tag == self.tag
        if repository == PUBLISHER.SOURCE_REPOSITORY:
            record = {
                "draft": False,
                "id": 41,
                "immutable": True,
                "name": tag,
                "prerelease": False,
                "tag_name": tag,
                "target_commitish": self.commit,
            }
            record.update(self.source_release_overrides)
            return [record]
        assert repository == PUBLISHER.PUBLIC_REPOSITORY
        return (
            []
            if self.public_release is None
            else [json.loads(json.dumps(self.public_release))]
        )

    @staticmethod
    def _asset_record(
        asset_id: int,
        name: str,
        content: bytes,
        *,
        overrides: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        record = {
            "content_type": PUBLISHER._asset_media_type(name),
            "digest": f"sha256:{hashlib.sha256(content).hexdigest()}",
            "id": asset_id,
            "label": None,
            "name": name,
            "size": len(content),
            "state": "uploaded",
        }
        record.update(overrides or {})
        return record

    def assets(self, repository: str, release_id: int) -> list[dict[str, Any]]:
        self._event("assets", repository, release_id)
        if repository == PUBLISHER.SOURCE_REPOSITORY:
            assert release_id == 41
            return [
                self._asset_record(
                    index,
                    name,
                    content,
                    overrides=self.source_asset_overrides.get(name),
                )
                for index, (name, content) in enumerate(
                    sorted(self._source_assets.items()), 100
                )
            ]
        assert repository == PUBLISHER.PUBLIC_REPOSITORY
        assert release_id == RELEASE_ID
        return [
            self._asset_record(
                index,
                name,
                content,
                overrides=self.asset_overrides.get(name),
            )
            for index, (name, content) in enumerate(
                sorted(self.public_assets.items()), 200
            )
        ]

    def create_tag_object(
        self, repository: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        assert repository == PUBLISHER.PUBLIC_REPOSITORY
        record = {
            "message": payload["message"],
            "object": {
                "type": "commit",
                "sha": payload["object"],
                "url": f"https://api.github.test/commits/{payload['object']}",
            },
            "sha": PUBLISHER.tag_object_sha(payload),
            "tag": payload["tag"],
            "tagger": json.loads(json.dumps(payload["tagger"])),
        }
        self.public_tag_object = record
        self._mutate("create_tag_object")
        return json.loads(json.dumps(record))

    def create_tag_ref(
        self, repository: str, tag: str, tag_sha: str
    ) -> dict[str, Any]:
        assert repository == PUBLISHER.PUBLIC_REPOSITORY
        self.public_ref = {
            "ref": f"refs/tags/{tag}",
            "object": {
                "type": "tag",
                "sha": tag_sha,
                "url": f"https://api.github.test/tags/{tag_sha}",
            },
        }
        self._mutate("create_tag_ref")
        return json.loads(json.dumps(self.public_ref))

    def create_release(
        self, repository: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        assert repository == PUBLISHER.PUBLIC_REPOSITORY
        self.public_release = {
            **json.loads(json.dumps(payload)),
            "id": RELEASE_ID,
            "immutable": False,
        }
        self._mutate("create_release")
        return json.loads(json.dumps(self.public_release))

    def upload_asset(
        self, repository: str, release_id: int, asset: Any
    ) -> dict[str, Any]:
        assert repository == PUBLISHER.PUBLIC_REPOSITORY
        assert release_id == RELEASE_ID
        assert asset.media_type != "application/octet-stream"
        self.public_assets[asset.name] = asset.path.read_bytes()
        self._mutate(f"upload:{asset.name}")
        return self._asset_record(299, asset.name, self.public_assets[asset.name])

    def publish_release(
        self, repository: str, release_id: int
    ) -> dict[str, Any]:
        assert repository == PUBLISHER.PUBLIC_REPOSITORY
        assert release_id == RELEASE_ID
        assert self.public_release is not None
        self.public_release["draft"] = False
        self.public_release["immutable"] = True
        self._mutate("publish_release")
        return json.loads(json.dumps(self.public_release))


def bundle(tmp_path: Path) -> tuple[Path, str, str, str]:
    return build_pre_tag_bundle(tmp_path)


# The publisher refuses a release whose statement is not signed by a pinned release key. Tests
# cannot touch the owner's hardware keys, so here it trusts the stand-in key instead.
PUBLISHER.signer_of = lambda signature, statement: release_signature.signer_of(  # noqa: E731
    signature, statement, keys=(TEST_KEY.blob,),
)


def signature_for(directory: Path, *, commit: str, tree: str, tag: str) -> str:
    """The owner's signature of the statement for this bundle, made with the stand-in key."""
    assets = PUBLISHER._local_assets(directory, tag, commit, tree)
    statement = release_signature.release_statement(
        tag.removeprefix("v"), {name: asset.digest for name, asset in assets.items()},
    )
    return TEST_KEY.sign(statement.encode())


def signed_for(directory: Path, *, commit: str, tree: str, tag: str) -> str:
    """The statement and signature as the tag carries them."""
    return PUBLISHER.signed_statement(
        tag, PUBLISHER._local_assets(directory, tag, commit, tree),
        signature_for(directory, commit=commit, tree=tree, tag=tag),
    )


def invoke(
    api: FakePublicReleaseAPI,
    store: MemoryReceiptStore,
    directory: Path,
    *,
    commit: str,
    tree: str,
    tag: str,
    resume: bool = False,
) -> dict[str, Any]:
    return PUBLISHER.publish_public_release(
        api,
        store,
        directory,
        tag=tag,
        commit=commit,
        tree=tree,
        public_anchor_commit=ANCHOR,
        approval=PUBLISHER.approval_phrase(tag, commit),
        resume=resume,
        signature=signature_for(directory, commit=commit, tree=tree, tag=tag),
        now=lambda: 1_700_000_000,
    )
