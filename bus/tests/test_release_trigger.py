from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from typing import Any

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_release_trigger",
    REPOSITORY_ROOT / "scripts/validate_release_trigger.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load release trigger validator")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

TriggerValidationError = MODULE.TriggerValidationError
validate_release_trigger = MODULE.validate_release_trigger

COMMIT = "1" * 40
TAG_OBJECT = "2" * 40
TAG = "v0.2.0"


class FakeClient:
    def __init__(self) -> None:
        self.responses: dict[str, Any] = {
            f"repos/{MODULE.REPOSITORY}/git/ref/tags/{TAG}": {
                "object": {"type": "tag", "sha": TAG_OBJECT}
            },
            f"repos/{MODULE.REPOSITORY}/git/tags/{TAG_OBJECT}": {
                "tag": TAG,
                "object": {"type": "commit", "sha": COMMIT},
            },
            f"repos/{MODULE.REPOSITORY}": {
                "default_branch": "main",
            },
            f"repos/{MODULE.REPOSITORY}/immutable-releases": {"enabled": True},
            f"repos/{MODULE.REPOSITORY}/branches/main": {
                "commit": {"sha": COMMIT}
            },
            (
                f"repos/{MODULE.REPOSITORY}/actions/workflows/ci.yml/runs?"
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
            f"repos/{MODULE.REPOSITORY}/actions/runs/42/jobs?per_page=100": {
                "jobs": [
                    {
                        "name": name,
                        "status": "completed",
                        "conclusion": "success",
                    }
                    for name in MODULE.REQUIRED_CI_JOBS
                ]
            },
        }

    def get(self, path: str) -> Any:
        return self.responses[path]


def _validate(client: FakeClient) -> dict[str, Any]:
    return validate_release_trigger(
        client,
        repository=MODULE.REPOSITORY,
        tag=TAG,
        event_sha=COMMIT,
        event_ref=f"refs/tags/{TAG}",
        ref_type="tag",
        actor="NZCypher819",
        workflow_sha=COMMIT,
    )


def test_release_trigger_accepts_exact_owner_tagged_main_commit() -> None:
    assert _validate(FakeClient()) == {
        "ci_run_id": 42,
        "commit": COMMIT,
        "repository": MODULE.REPOSITORY,
        "tag": TAG,
        "tag_object": TAG_OBJECT,
    }


def test_candidate_gate_can_defer_admin_only_immutable_setting_check() -> None:
    client = FakeClient()
    del client.responses[f"repos/{MODULE.REPOSITORY}/immutable-releases"]

    result = validate_release_trigger(
        client,
        repository=MODULE.REPOSITORY,
        tag=TAG,
        event_sha=COMMIT,
        event_ref=f"refs/tags/{TAG}",
        ref_type="tag",
        actor="NZCypher819",
        workflow_sha=COMMIT,
        require_immutable_releases=False,
    )

    assert result["commit"] == COMMIT


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda client: client.responses[
                f"repos/{MODULE.REPOSITORY}/git/ref/tags/{TAG}"
            ]["object"].update(type="commit"),
            "annotated",
        ),
        (
            lambda client: client.responses[
                f"repos/{MODULE.REPOSITORY}/git/tags/{TAG_OBJECT}"
            ]["object"].update(sha="3" * 40),
            "event commit",
        ),
        (
            lambda client: client.responses[
                f"repos/{MODULE.REPOSITORY}/immutable-releases"
            ].update(enabled=False),
            "immutable releases",
        ),
        (
            lambda client: client.responses[
                f"repos/{MODULE.REPOSITORY}/branches/main"
            ]["commit"].update(sha="3" * 40),
            "current main",
        ),
        (
            lambda client: client.responses[
                f"repos/{MODULE.REPOSITORY}/actions/workflows/ci.yml/runs?"
                f"event=push&head_sha={COMMIT}&status=completed&per_page=100"
            ].update(workflow_runs=[]),
            "successful main CI",
        ),
        (
            lambda client: client.responses[
                f"repos/{MODULE.REPOSITORY}/actions/runs/42/jobs?per_page=100"
            ]["jobs"].pop(),
            "missing or unsuccessful",
        ),
    ],
)
def test_release_trigger_rejects_unsafe_or_incomplete_state(
    mutation: object,
    message: str,
) -> None:
    client = FakeClient()
    assert callable(mutation)
    mutation(client)
    with pytest.raises(TriggerValidationError, match=message):
        _validate(client)


@pytest.mark.parametrize(
    "overrides",
    [
        {"tag": "latest", "event_ref": "refs/tags/latest"},
        {"event_ref": "refs/heads/main", "ref_type": "branch"},
        {"actor": "collaborator"},
        {"repository": "NZCypher819/other"},
        {"workflow_sha": "3" * 40},
    ],
)
def test_release_trigger_rejects_ref_actor_and_repository_confusion(
    overrides: dict[str, str],
) -> None:
    arguments = {
        "repository": MODULE.REPOSITORY,
        "tag": TAG,
        "event_sha": COMMIT,
        "event_ref": f"refs/tags/{TAG}",
        "ref_type": "tag",
        "actor": "NZCypher819",
        "workflow_sha": COMMIT,
    }
    arguments.update(overrides)
    with pytest.raises(TriggerValidationError):
        validate_release_trigger(FakeClient(), **arguments)
