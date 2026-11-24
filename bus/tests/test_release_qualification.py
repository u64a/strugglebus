from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

import pytest

from release_fixtures import (
    ARTIFACT_ID,
    ARTIFACT_SIZE,
    OWNER,
    PUBLISHED_AT,
    QUALIFICATION_RUN_ID,
    build_pre_tag_bundle,
    load_script,
    qualification_responses,
    write_qualification_receipt,
    write_wheel,
)


BUNDLE = load_script("release_bundle")
TRIGGER = load_script("validate_release_trigger")
MODULE = load_script("release_qualification")
QualificationError = MODULE.QualificationError

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ID = BUNDLE.REPOSITORY_ID
COMMIT = "1" * 40
TREE = "2" * 40
TAG = "v0.2.0"
VERSION = "0.2.0"


class FakeClient:
    def __init__(self, *, commit: str = COMMIT, tag: str = TAG, **overrides: Any) -> None:
        self.responses: dict[str, Any] = {
            f"repos/{REPOSITORY_ID}": {"default_branch": "main"},
            f"repos/{REPOSITORY_ID}/branches/main": {"commit": {"sha": commit}},
            (
                f"repos/{REPOSITORY_ID}/actions/workflows/ci.yml/runs?"
                f"event=push&head_sha={commit}&status=completed&per_page=100"
            ): {
                "workflow_runs": [
                    {
                        "id": 42,
                        "event": "push",
                        "head_sha": commit,
                        "head_branch": "main",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ]
            },
            f"repos/{REPOSITORY_ID}/actions/runs/42/jobs?per_page=100": {
                "jobs": [
                    {"name": name, "status": "completed", "conclusion": "success"}
                    for name in TRIGGER.REQUIRED_CI_JOBS
                ]
            },
        }
        self.responses.update(
            qualification_responses(
                repository=REPOSITORY_ID,
                tag=tag,
                commit=commit,
                **overrides,
            )
        )
        self.reads: list[str] = []

    def get(self, path: str) -> Any:
        self.reads.append(path)
        return json.loads(json.dumps(self.responses[path]))

    def runs(self) -> dict[str, Any]:
        key = next(key for key in self.responses if "release-qualification.yml" in key)
        return self.responses[key]

    def artifacts(self, run_id: int = QUALIFICATION_RUN_ID) -> dict[str, Any]:
        key = f"repos/{REPOSITORY_ID}/actions/runs/{run_id}/artifacts?page=1&per_page=100"
        return self.responses[key]


def _bundle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    dist = tmp_path / "dist"
    dist.mkdir()
    write_wheel(dist / f"strugglebus-{VERSION}-py3-none-any.whl", VERSION)
    uv = tmp_path / "uv"
    uv.write_bytes(b"pinned uv")
    output = tmp_path / "release-assets"
    monkeypatch.setattr(
        BUNDLE,
        "resolve_release_identity",
        lambda *args, **kwargs: (COMMIT, TREE, 1_700_000_000, VERSION),
    )
    BUNDLE.build_bundle(REPOSITORY_ROOT, dist, output, TAG, uv_binary=uv)
    return output


def _documents(tmp_path: Path, directory: Path, **overrides: Any) -> Any:
    return write_qualification_receipt(
        directory,
        tmp_path / "qualification",
        repository=REPOSITORY_ID,
        tag=TAG,
        commit=COMMIT,
        tree=TREE,
        version=VERSION,
        **overrides,
    )


def _gate(client: FakeClient, **overrides: Any) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "repository": REPOSITORY_ID,
        "tag": TAG,
        "commit": COMMIT,
        "actor": OWNER,
        "workflow_sha": COMMIT,
        "event_name": "workflow_dispatch",
        "ref": "refs/heads/main",
        "approved_by": OWNER,
        "approval": MODULE.APPROVAL_PHRASE,
    }
    arguments.update(overrides)
    return MODULE.validate_qualification_trigger(client, **arguments)


def test_gate_accepts_the_approved_owner_dispatch_on_exact_main() -> None:
    assert _gate(FakeClient()) == {
        "ci_run_id": 42,
        "commit": COMMIT,
        "repository": REPOSITORY_ID,
        "tag": TAG,
        "version": VERSION,
    }


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"actor": "collaborator"}, "repository owner"),
        ({"approved_by": "collaborator"}, "name the repository owner"),
        ({"approval": "publish"}, "approval phrase"),
        ({"event_name": "push"}, "owner workflow dispatch"),
        ({"ref": "refs/heads/topic"}, "exact main ref"),
        ({"repository": "NZCypher819/other"}, "repository identity"),
        ({"tag": "latest"}, "release tag must be"),
        ({"workflow_sha": "9" * 40}, "does not match the qualified commit"),
        ({"commit": "9" * 40}, "workflow does not match"),
    ],
)
def test_gate_rejects_untrusted_or_inexact_dispatch(
    overrides: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(QualificationError, match=message):
        _gate(FakeClient(), **overrides)


def test_gate_requires_current_main_and_successful_main_ci() -> None:
    stale = FakeClient()
    stale.responses[f"repos/{REPOSITORY_ID}/branches/main"]["commit"]["sha"] = "9" * 40
    with pytest.raises(QualificationError, match="exact current main commit"):
        _gate(stale)

    failed = FakeClient()
    failed.responses[
        f"repos/{REPOSITORY_ID}/actions/runs/42/jobs?per_page=100"
    ]["jobs"].pop()
    with pytest.raises(QualificationError, match="missing or unsuccessful"):
        _gate(failed)


def test_receipt_binds_the_exact_five_assets_and_tool_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    binding = _documents(tmp_path, directory)
    receipt = json.loads(binding.receipt_path.read_text(encoding="ascii"))

    assert [asset["name"] for asset in receipt["assets"]] == MODULE.expected_asset_names(
        VERSION
    )
    assert len(receipt["assets"]) == 5
    assert receipt["release"] == {
        "commit": COMMIT,
        "tag": TAG,
        "tree": TREE,
        "version": VERSION,
    }
    assert receipt["approval"]["approved_by"] == OWNER
    assert receipt["approval"]["phrase"] == MODULE.APPROVAL_PHRASE
    assert receipt["tools"]["canonical_wheel_sha256"] == MODULE.helper_digest(
        REPOSITORY_ROOT
    )
    assert receipt["tools"]["uv_version"] == BUNDLE.UV_VERSION
    assert receipt["expires_at"] > receipt["issued_at"]
    assert receipt["artifact"]["name"] == MODULE.asset_artifact_name(
        TAG, QUALIFICATION_RUN_ID
    )
    for asset in receipt["assets"]:
        path = directory / asset["name"]
        assert path.stat().st_size == asset["size_bytes"]
    for forbidden in ("token", "authorization", "private-key", "inventory"):
        assert forbidden not in binding.receipt_path.read_text(encoding="ascii").lower()


def test_evidence_is_not_part_of_the_qualification_architecture() -> None:
    source = (REPOSITORY_ROOT / "scripts/release_qualification.py").read_text(
        encoding="utf-8"
    )
    lowered = source.lower()

    assert not hasattr(MODULE, "build_evidence")
    assert not hasattr(MODULE, "validate_evidence")
    assert not hasattr(MODULE, "evidence_artifact_name")
    assert "evidence" not in lowered
    assert MODULE.OUTPUT_KEYS == (
        "artifact_digest",
        "artifact_id",
        "artifact_name",
        "artifact_size_bytes",
        "run_id",
    )
    assert set(MODULE.QualificationBinding.__dataclass_fields__) == {
        "receipt_path",
        "run_id",
        "artifact_id",
        "artifact_name",
        "artifact_digest",
        "artifact_size_bytes",
        "helper_sha256",
        "now",
    }


def test_receipt_documents_the_post_upload_binding_boundary() -> None:
    docstring = MODULE.__doc__ or ""
    verification = MODULE.verify_qualified_release.__doc__ or ""

    assert "only exist after the" in docstring
    assert "can never contain its own digest" in docstring
    assert "does not, and cannot, carry those post-upload values" in docstring
    assert "exactly ONE" in docstring
    assert "qualification run ID" in docstring and "expected artifact name" in docstring
    assert "cannot carry those post-upload values" in verification
    assert "run ID" in verification and "expected artifact name" in verification


def test_verification_accepts_the_exact_qualified_artifact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    binding = _documents(tmp_path, directory)
    client = FakeClient()

    result = MODULE.verify_qualified_release(
        client,
        directory,
        binding,
        repository=REPOSITORY_ID,
        tag=TAG,
        commit=COMMIT,
        tree=TREE,
    )

    assert result["qualification_run_id"] == QUALIFICATION_RUN_ID
    assert result["artifact_id"] == binding.artifact_id
    assert result["artifact_name"] == binding.artifact_name
    assert result["artifact_size_bytes"] == binding.artifact_size_bytes
    assert result["receipt_sha256"] == hashlib.sha256(
        binding.receipt_path.read_bytes()
    ).hexdigest()


def test_pre_tag_qualification_verifies_real_untagged_source_end_to_end(
    tmp_path: Path,
) -> None:
    directory, commit, tree, version = build_pre_tag_bundle(tmp_path)
    tag = f"v{version}"
    binding = write_qualification_receipt(
        directory,
        tmp_path / "qualification",
        repository=REPOSITORY_ID,
        tag=tag,
        commit=commit,
        tree=tree,
        version=version,
    )
    client = FakeClient(commit=commit, tag=tag)

    result = MODULE.verify_qualified_release(
        client,
        directory,
        binding,
        repository=REPOSITORY_ID,
        tag=tag,
        commit=commit,
        tree=tree,
    )

    receipt = json.loads(binding.receipt_path.read_text(encoding="ascii"))
    assert result["artifact_name"] == MODULE.asset_artifact_name(
        tag, QUALIFICATION_RUN_ID
    )
    assert receipt["release"] == {
        "commit": commit,
        "tag": tag,
        "tree": tree,
        "version": version,
    }
    assert [asset["name"] for asset in receipt["assets"]] == MODULE.expected_asset_names(
        version
    )


def _replace(binding: Any, **overrides: Any) -> Any:
    return dataclasses.replace(binding, **overrides)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda binding: _replace(binding, run_id=binding.run_id + 1),
            "qualification run",
        ),
        (
            lambda binding: _replace(binding, artifact_id=binding.artifact_id + 1),
            "artifact ID",
        ),
        (
            lambda binding: _replace(binding, artifact_digest="f" * 64),
            "digest drifted",
        ),
        (
            lambda binding: _replace(
                binding, artifact_size_bytes=binding.artifact_size_bytes + 1
            ),
            "artifact size",
        ),
        (
            lambda binding: _replace(binding, helper_sha256="e" * 64),
            "canonical wheel helper",
        ),
        (
            lambda binding: _replace(binding, now=PUBLISHED_AT + 30 * 24 * 60 * 60),
            "has expired",
        ),
        (
            lambda binding: _replace(binding, now=1_600_000_000),
            "issued in the future",
        ),
        (
            lambda binding: _replace(
                binding, artifact_name="strugglebus-qualified-release-wrong"
            ),
            "artifact name",
        ),
    ],
)
def test_verification_rejects_binding_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutate: Callable[[Any], Any],
    message: str,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    binding = mutate(_documents(tmp_path, directory))

    with pytest.raises(QualificationError, match=message):
        MODULE.verify_qualified_release(
            FakeClient(),
            directory,
            binding,
            repository=REPOSITORY_ID,
            tag=TAG,
            commit=COMMIT,
            tree=TREE,
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda receipt: receipt["release"].update(tree="9" * 40), "release tree"),
        (lambda receipt: receipt["release"].update(commit="9" * 40), "release commit"),
        (
            lambda receipt: receipt["qualification"].update(run_id=99),
            "qualification run",
        ),
        (
            lambda receipt: receipt["qualification"].update(run_attempt=7),
            "receipt run attempt",
        ),
        (
            lambda receipt: receipt["artifact"].update(name="strugglebus-other"),
            "artifact name",
        ),
        (
            lambda receipt: receipt["approval"].update(approved_by="collaborator"),
            "repository owner",
        ),
        (
            lambda receipt: receipt["approval"].update(phrase="publish"),
            "approval phrase",
        ),
        (
            lambda receipt: receipt["tools"].update(uv_version="0.0.1"),
            "receipt uv version",
        ),
        (
            lambda receipt: receipt["tools"].update(canonical_wheel_sha256="c" * 64),
            "canonical wheel helper",
        ),
        (
            lambda receipt: receipt["assets"][0].update(sha256="0" * 64),
            "digest drifted",
        ),
        (
            lambda receipt: receipt["assets"].pop(),
            "asset list is incomplete",
        ),
    ],
)
def test_verification_rejects_receipt_document_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutate: Callable[[dict[str, Any]], None],
    message: str,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    binding = _documents(tmp_path, directory)
    receipt = json.loads(binding.receipt_path.read_text(encoding="ascii"))
    mutate(receipt)
    binding.receipt_path.write_bytes(MODULE._canonical_json(receipt))

    with pytest.raises(QualificationError, match=message):
        MODULE.verify_qualified_release(
            FakeClient(),
            directory,
            binding,
            repository=REPOSITORY_ID,
            tag=TAG,
            commit=COMMIT,
            tree=TREE,
        )


def test_verification_rejects_a_missing_or_non_canonical_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    binding = _documents(tmp_path, directory)
    original = binding.receipt_path.read_bytes()
    binding.receipt_path.unlink()

    with pytest.raises(QualificationError, match="missing qualification document"):
        MODULE.verify_qualified_release(
            FakeClient(),
            directory,
            binding,
            repository=REPOSITORY_ID,
            tag=TAG,
            commit=COMMIT,
            tree=TREE,
        )

    binding.receipt_path.write_bytes(b"  " + original)
    with pytest.raises(QualificationError, match="not valid JSON|not canonically"):
        MODULE.verify_qualified_release(
            FakeClient(),
            directory,
            binding,
            repository=REPOSITORY_ID,
            tag=TAG,
            commit=COMMIT,
            tree=TREE,
        )


def test_verification_rejects_asset_hash_and_file_set_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = _bundle(monkeypatch, tmp_path)
    binding = _documents(tmp_path, directory)
    receipt = json.loads(binding.receipt_path.read_text(encoding="ascii"))
    tampered = receipt["assets"][0]["name"]
    (directory / tampered).write_bytes(
        (directory / tampered).read_bytes() + b"tampered"
    )
    with pytest.raises(QualificationError, match="size drifted|digest drifted"):
        MODULE.verify_qualified_release(
            FakeClient(),
            directory,
            binding,
            repository=REPOSITORY_ID,
            tag=TAG,
            commit=COMMIT,
            tree=TREE,
        )

    second_root = tmp_path / "second"
    second_root.mkdir()
    second = _bundle(monkeypatch, second_root)
    binding = _documents(second_root, second)
    (second / "unexpected-asset").write_text("extra", encoding="ascii")
    with pytest.raises(QualificationError, match="does not match the receipt"):
        MODULE.verify_qualified_release(
            FakeClient(),
            second,
            binding,
            repository=REPOSITORY_ID,
            tag=TAG,
            commit=COMMIT,
            tree=TREE,
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda client: client.runs().update(workflow_runs=[]), "no successful owner"),
        (
            lambda client: client.runs()["workflow_runs"][0].update(
                conclusion="failure"
            ),
            "no successful owner",
        ),
        (
            lambda client: client.runs()["workflow_runs"][0].update(
                actor={"login": "collaborator"}
            ),
            "no successful owner",
        ),
        (
            lambda client: client.runs()["workflow_runs"][0].update(
                head_branch="topic"
            ),
            "no successful owner",
        ),
        (
            lambda client: client.artifacts()["artifacts"][0].update(expired=True),
            "no unexpired qualification artifact",
        ),
        (
            lambda client: client.artifacts()["artifacts"].append(
                dict(client.artifacts()["artifacts"][0], id=9999)
            ),
            "exactly one",
        ),
        (
            lambda client: client.artifacts()["artifacts"].clear(),
            "no unexpired qualification artifact",
        ),
        (
            lambda client: client.artifacts()["artifacts"][0].update(
                name="strugglebus-qualified-release-v9.9.9-1"
            ),
            "no unexpired qualification artifact",
        ),
        (
            lambda client: client.artifacts()["artifacts"][0].update(
                workflow_run={
                    "head_branch": "main",
                    "head_sha": "9" * 40,
                    "id": QUALIFICATION_RUN_ID,
                }
            ),
            "wrong head commit",
        ),
        (
            lambda client: client.artifacts()["artifacts"][0].update(
                workflow_run={
                    "head_branch": "main",
                    "head_sha": COMMIT,
                    "id": QUALIFICATION_RUN_ID + 77,
                }
            ),
            "different workflow run",
        ),
    ],
)
def test_resolution_fails_closed_on_missing_or_ambiguous_runs(
    mutate: Callable[[FakeClient], None],
    message: str,
) -> None:
    client = FakeClient()
    mutate(client)

    with pytest.raises(QualificationError, match=message):
        MODULE.resolve_qualification(
            client,
            repository=REPOSITORY_ID,
            tag=TAG,
            commit=COMMIT,
        )


def test_resolution_binds_the_live_artifact_identity() -> None:
    client = FakeClient()

    resolved = MODULE.resolve_qualification(
        client,
        repository=REPOSITORY_ID,
        tag=TAG,
        commit=COMMIT,
    )

    assert set(resolved) == {"artifact", "run", "run_attempt", "run_id"}
    assert resolved["artifact"].id == ARTIFACT_ID
    assert resolved["artifact"].size_bytes == ARTIFACT_SIZE
    assert resolved["artifact"].name == MODULE.asset_artifact_name(
        TAG, QUALIFICATION_RUN_ID
    )
    assert resolved["run"]["head_sha"] == COMMIT
    assert resolved["run"]["head_branch"] == "main"


def test_resolution_rejects_duplicate_qualification_runs() -> None:
    client = FakeClient()
    second = qualification_responses(
        repository=REPOSITORY_ID,
        tag=TAG,
        commit=COMMIT,
        run_id=QUALIFICATION_RUN_ID + 1,
        artifact_id=9101,
    )
    runs_key = next(key for key in second if "release-qualification.yml" in key)
    client.responses[runs_key]["workflow_runs"].extend(
        second[runs_key]["workflow_runs"]
    )
    for key, value in second.items():
        if key != runs_key:
            client.responses[key] = value

    with pytest.raises(QualificationError, match="multiple qualification runs"):
        MODULE.resolve_qualification(
            client,
            repository=REPOSITORY_ID,
            tag=TAG,
            commit=COMMIT,
        )


def test_resolved_workflow_outputs_are_bounded_and_injection_safe() -> None:
    client = FakeClient()
    resolved = MODULE.resolve_qualification(
        client,
        repository=REPOSITORY_ID,
        tag=TAG,
        commit=COMMIT,
    )
    artifact = resolved["artifact"]
    rendered = MODULE.render_outputs(
        {
            "artifact_digest": artifact.digest,
            "artifact_id": artifact.id,
            "artifact_name": artifact.name,
            "artifact_size_bytes": artifact.size_bytes,
            "run_id": resolved["run_id"],
        }
    )

    assert rendered.splitlines() == [
        f"artifact-digest={artifact.digest}",
        f"artifact-id={artifact.id}",
        f"artifact-name={artifact.name}",
        f"artifact-size-bytes={artifact.size_bytes}",
        f"run-id={resolved['run_id']}",
    ]
    with pytest.raises(QualificationError, match="unsafe to render"):
        MODULE.render_outputs(
            {
                "artifact_digest": "a" * 64,
                "artifact_id": 1,
                "artifact_name": "name\nrun-id=99",
                "artifact_size_bytes": 4096,
                "run_id": 3,
            }
        )
    with pytest.raises(QualificationError, match="qualification resolution"):
        MODULE.render_outputs(
            {
                "artifact_digest": "a" * 64,
                "artifact_id": 1,
                "artifact_name": "name",
                "artifact_size_bytes": 4096,
                "evidence_artifact_id": 2,
                "run_id": 3,
            }
        )
