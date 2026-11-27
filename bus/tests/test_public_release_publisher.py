from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from public_release_publish_fixtures import (
    ANCHOR,
    FakePublicReleaseAPI,
    MemoryReceiptStore,
    PUBLISHER,
    bundle,
    invoke,
    signature_for,
    signed_for,
)


def _prepared(
    tmp_path: Path,
) -> tuple[Path, str, str, str, FakePublicReleaseAPI, MemoryReceiptStore]:
    directory, commit, tree, version = bundle(tmp_path)
    tag = f"v{version}"
    return (
        directory,
        commit,
        tree,
        tag,
        FakePublicReleaseAPI(directory, tag=tag, commit=commit, tree=tree),
        MemoryReceiptStore(),
    )


def test_publishes_exact_five_assets_and_canonical_public_identity(
    tmp_path: Path,
) -> None:
    directory, commit, tree, tag, api, store = _prepared(tmp_path)

    result = invoke(
        api, store, directory, commit=commit, tree=tree, tag=tag
    )

    assert result["phase"] == "complete"
    assert result["deployment_performed"] is False
    assert result["public_anchor_commit"] == ANCHOR
    assert result["assets"] == sorted(path.name for path in directory.iterdir())
    assert len(result["assets"]) == 5
    assert api.public_release is not None
    assert api.public_release["body"] == json.dumps(
        {
            "source_commit": commit,
            "source_repository": PUBLISHER.SOURCE_REPOSITORY,
            "source_tree": tree,
            "version": 1,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    assert api.public_release["draft"] is False
    assert api.public_release["immutable"] is True
    assert api.public_tag_object is not None
    assert api.public_tag_object["object"]["type"] == "commit"
    assert api.public_tag_object["object"]["sha"] == ANCHOR
    assert "url" in api.public_tag_object["object"]
    assert api.mutations[0:3] == [
        "create_tag_object",
        "create_tag_ref",
        "create_release",
    ]
    assert api.mutations[-1] == "publish_release"
    assert len([name for name in api.mutations if name.startswith("upload:")]) == 5
    assert store.content is not None
    assert store.content["phase"] == "complete"


@pytest.mark.parametrize(
    ("conflict", "message"),
    [
        ("tag", "tag object already exists"),
        ("release", "release already exists"),
    ],
)
def test_existing_public_state_fails_closed_before_mutation(
    tmp_path: Path,
    conflict: str,
    message: str,
) -> None:
    directory, commit, tree, tag, api, store = _prepared(tmp_path)
    operation = PUBLISHER._new_operation(
        tag=tag,
        commit=commit,
        tree=tree,
        anchor=ANCHOR,
        approval=PUBLISHER.approval_phrase(tag, commit),
        assets=PUBLISHER._local_assets(directory, tag, commit, tree),
        created_at=1_700_000_000,
        signed=signed_for(directory, commit=commit, tree=tree, tag=tag),
    )
    if conflict == "tag":
        api.public_tag_object = {
            "message": operation["tag_payload"]["message"],
            "object": {"type": "commit", "sha": ANCHOR},
            "sha": operation["tag_sha"],
            "tag": tag,
            "tagger": operation["tag_payload"]["tagger"],
        }
        api.public_ref = {
            "ref": f"refs/tags/{tag}",
            "object": {"type": "tag", "sha": operation["tag_sha"]},
        }
    else:
        api.public_release = {
            **PUBLISHER._release_payload(
                tag, ANCHOR, operation["release_body"]
            ),
            "id": 71,
            "immutable": False,
        }

    with pytest.raises(PUBLISHER.PublicReleaseError, match=message):
        invoke(api, store, directory, commit=commit, tree=tree, tag=tag)

    assert api.mutations == []
    assert store.content is None


@pytest.mark.parametrize(
    "failure",
    [
        "owner",
        "source-tag",
        "source-tree",
        "source-release",
        "source-media",
        "public-private",
        "immutable-disabled",
        "anchor",
        "approval",
    ],
)
def test_identity_and_policy_failures_never_mutate(
    tmp_path: Path,
    failure: str,
) -> None:
    directory, commit, tree, tag, api, store = _prepared(tmp_path)
    approval = PUBLISHER.approval_phrase(tag, commit)
    if failure == "owner":
        api.owner_login = "someone-else"
    elif failure == "source-tag":
        api.commit = "d" * 40
    elif failure == "source-tree":
        api.tree = "e" * 40
    elif failure == "source-release":
        api.source_release_overrides["immutable"] = False
    elif failure == "source-media":
        first = sorted(api._source_assets)[0]
        api.source_asset_overrides[first] = {
            "content_type": "application/octet-stream"
        }
    elif failure == "public-private":
        api.public_private = True
        api.public_visibility = "private"
    elif failure == "immutable-disabled":
        api.public_immutable = False
    elif failure == "anchor":
        api.public_head = "f" * 40
    elif failure == "approval":
        approval = "publish-public-release"

    with pytest.raises(PUBLISHER.PublicReleaseError):
        PUBLISHER.publish_public_release(
            api,
            store,
            directory,
            tag=tag,
            commit=commit,
            tree=tree,
            public_anchor_commit=ANCHOR,
            approval=approval,
            signature=signature_for(directory, commit=commit, tree=tree, tag=tag),
            resume=False,
            now=lambda: 1_700_000_000,
        )

    assert api.mutations == []
    assert store.content is None


def test_tampered_local_checksums_fail_before_remote_reads_or_mutation(
    tmp_path: Path,
) -> None:
    directory, commit, tree, tag, api, store = _prepared(tmp_path)
    target = directory / "requirements.lock"
    target.write_bytes(target.read_bytes() + b"tampered")

    with pytest.raises(PUBLISHER.PublicReleaseError, match="bundle is invalid"):
        invoke(api, store, directory, commit=commit, tree=tree, tag=tag)

    assert api.events == []
    assert api.mutations == []
    assert store.content is None


@pytest.mark.parametrize(
    "lost_mutation",
    [
        "create_tag_object",
        "create_tag_ref",
        "create_release",
        "upload:SHA256SUMS",
        "publish_release",
    ],
)
def test_interruption_reconciles_without_repeating_accepted_mutations(
    tmp_path: Path,
    lost_mutation: str,
) -> None:
    directory, commit, tree, tag, api, store = _prepared(tmp_path)
    api.loss_once.add(lost_mutation)

    with pytest.raises(PUBLISHER.PublicReleaseError, match="ambiguous mutation"):
        invoke(api, store, directory, commit=commit, tree=tree, tag=tag)

    assert store.content is not None
    before = list(api.mutations)
    result = invoke(
        api,
        store,
        directory,
        commit=commit,
        tree=tree,
        tag=tag,
        resume=True,
    )

    assert result["phase"] == "complete"
    assert api.mutations.count(lost_mutation) == 1
    assert api.mutations[: len(before)] == before


def test_resume_reports_incomplete_draft_asset_recovery(
    tmp_path: Path,
) -> None:
    directory, commit, tree, tag, api, store = _prepared(tmp_path)
    api.loss_once.add("upload:SHA256SUMS")
    with pytest.raises(PUBLISHER.PublicReleaseError):
        invoke(api, store, directory, commit=commit, tree=tree, tag=tag)
    api.asset_overrides["SHA256SUMS"] = {"state": "starter"}
    mutation_count = len(api.mutations)

    with pytest.raises(
        PUBLISHER.PublicReleaseError,
        match="delete the draft asset before resume: SHA256SUMS",
    ):
        invoke(
            api,
            store,
            directory,
            commit=commit,
            tree=tree,
            tag=tag,
            resume=True,
        )

    assert len(api.mutations) == mutation_count


def test_resume_allows_public_default_branch_to_advance(
    tmp_path: Path,
) -> None:
    directory, commit, tree, tag, api, store = _prepared(tmp_path)
    api.loss_once.add("create_tag_object")
    with pytest.raises(PUBLISHER.PublicReleaseError):
        invoke(api, store, directory, commit=commit, tree=tree, tag=tag)
    api.public_head = "f" * 40

    result = invoke(
        api,
        store,
        directory,
        commit=commit,
        tree=tree,
        tag=tag,
        resume=True,
    )

    assert result["phase"] == "complete"


def test_resume_rejects_conflicting_asset_media_type_without_mutation(
    tmp_path: Path,
) -> None:
    directory, commit, tree, tag, api, store = _prepared(tmp_path)
    api.loss_once.add("upload:SHA256SUMS")
    with pytest.raises(PUBLISHER.PublicReleaseError):
        invoke(api, store, directory, commit=commit, tree=tree, tag=tag)
    api.asset_overrides["SHA256SUMS"] = {
        "content_type": "application/octet-stream"
    }
    mutation_count = len(api.mutations)

    with pytest.raises(PUBLISHER.PublicReleaseError, match="identity mismatch"):
        invoke(
            api,
            store,
            directory,
            commit=commit,
            tree=tree,
            tag=tag,
            resume=True,
        )

    assert len(api.mutations) == mutation_count


def test_resume_rejects_conflicting_release_body_without_mutation(
    tmp_path: Path,
) -> None:
    directory, commit, tree, tag, api, store = _prepared(tmp_path)
    api.loss_once.add("create_release")
    with pytest.raises(PUBLISHER.PublicReleaseError):
        invoke(api, store, directory, commit=commit, tree=tree, tag=tag)
    assert api.public_release is not None
    api.public_release["body"] = "{}"
    mutation_count = len(api.mutations)

    with pytest.raises(PUBLISHER.PublicReleaseError, match="release conflicts"):
        invoke(
            api,
            store,
            directory,
            commit=commit,
            tree=tree,
            tag=tag,
            resume=True,
        )

    assert len(api.mutations) == mutation_count


def test_resume_requires_exact_receipt_identity_and_approval(
    tmp_path: Path,
) -> None:
    directory, commit, tree, tag, api, store = _prepared(tmp_path)
    api.loss_once.add("create_tag_ref")
    with pytest.raises(PUBLISHER.PublicReleaseError):
        invoke(api, store, directory, commit=commit, tree=tree, tag=tag)
    mutation_count = len(api.mutations)

    with pytest.raises(PUBLISHER.PublicReleaseError, match="approval must exactly"):
        PUBLISHER.publish_public_release(
            api,
            store,
            directory,
            tag=tag,
            commit=commit,
            tree=tree,
            public_anchor_commit=ANCHOR,
            approval="wrong",
            resume=True,
            signature=signature_for(directory, commit=commit, tree=tree, tag=tag),
        )

    assert len(api.mutations) == mutation_count


def test_public_asset_conflict_fails_closed(
    tmp_path: Path,
) -> None:
    directory, commit, tree, tag, api, store = _prepared(tmp_path)
    api.loss_once.add("upload:SHA256SUMS")
    with pytest.raises(PUBLISHER.PublicReleaseError):
        invoke(api, store, directory, commit=commit, tree=tree, tag=tag)
    api.public_assets["SHA256SUMS"] += b"conflict"
    mutation_count = len(api.mutations)

    with pytest.raises(PUBLISHER.PublicReleaseError, match="identity mismatch"):
        invoke(
            api,
            store,
            directory,
            commit=commit,
            tree=tree,
            tag=tag,
            resume=True,
        )

    assert len(api.mutations) == mutation_count


def test_upload_transport_passes_each_strict_media_type(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    executable = tmp_path / "gh"
    executable.write_text("#!/bin/sh\n", encoding="ascii")
    executable.chmod(0o755)
    client = PUBLISHER.GitHubCLI(str(executable))
    asset_path = tmp_path / "release-manifest.json"
    asset_path.write_bytes(b"{}")
    asset = PUBLISHER.LocalAsset(
        name=asset_path.name,
        path=asset_path,
        size=2,
        digest="4" * 64,
        media_type="application/json",
    )
    observed: dict[str, Any] = {}

    def fake_run(
        executable_value: str,
        arguments: list[str],
        *,
        maximum: int,
        seconds: int,
        mutation: bool,
        allow_not_found: bool,
    ) -> bytes:
        observed.update(
            executable=executable_value,
            arguments=arguments,
            maximum=maximum,
            seconds=seconds,
            mutation=mutation,
            allow_not_found=allow_not_found,
        )
        return b'{"id":9}'

    monkeypatch.setattr(PUBLISHER, "_run_gh", fake_run)

    assert client.upload_asset(PUBLISHER.PUBLIC_REPOSITORY, 7, asset) == {"id": 9}
    assert "Content-Type: application/json" in observed["arguments"]
    assert "Content-Type: application/octet-stream" not in observed["arguments"]
    assert observed["mutation"] is True
    assert observed["seconds"] == PUBLISHER.UPLOAD_SECONDS


def test_windows_gh_inputs_use_windows_paths_from_wsl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(PUBLISHER.sys, "platform", "linux")

    assert PUBLISHER._gh_input_path(
        "/mnt/c/Program Files/GitHub CLI/gh.exe",
        PurePosixPath("/mnt/d/releases/v0.2.31/release-manifest.json"),
    ) == "D:\\releases\\v0.2.31\\release-manifest.json"
    with pytest.raises(PUBLISHER.PublicReleaseError, match="/mnt/<drive>"):
        PUBLISHER._gh_input_path(
            "/mnt/c/Program Files/GitHub CLI/gh.exe",
            PurePosixPath("/root/release-manifest.json"),
        )


def test_environment_removes_token_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GH_TOKEN", "secret")
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    monkeypatch.setenv("GH_ENTERPRISE_TOKEN", "secret")
    monkeypatch.setenv("GITHUB_ENTERPRISE_TOKEN", "secret")

    environment = PUBLISHER._gh_environment()

    assert all(
        name not in environment
        for name in (
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "GH_ENTERPRISE_TOKEN",
            "GITHUB_ENTERPRISE_TOKEN",
        )
    )
    assert environment["GH_PROMPT_DISABLED"] == "1"
    assert "TOKEN" not in environment["WSLENV"]
