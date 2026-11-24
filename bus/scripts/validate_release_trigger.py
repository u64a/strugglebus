"""Validate the immutable-release tag and exact-main CI gate."""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol


REPOSITORY = "NZCypher819/strugglebus"
GITHUB_API_URL = "https://api.github.com"
REQUIRED_CI_JOBS = frozenset(
    {
        # Python 3.13 is the only supported interpreter; the qualification
        # workflow also clean-installs the exact published wheel on it before a
        # release can proceed.
        "Python 3.13",
        "Deployment validation",
        "Isolated LAN CA integration",
        "Security",
    }
)
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
TAG_PATTERN = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")


class TriggerValidationError(RuntimeError):
    """The release trigger does not identify an accepted immutable candidate."""


class APIClient(Protocol):
    def get(self, path: str) -> Any: ...


@dataclass(frozen=True)
class GitHubClient:
    api_url: str
    token: str

    def get(self, path: str) -> Any:
        request = urllib.request.Request(
            f"{self.api_url.rstrip('/')}/{path.lstrip('/')}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "strugglebus-release-trigger-v1",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
                if response.status != 200:
                    raise TriggerValidationError(
                        f"GitHub API returned status {response.status}"
                    )
                content = response.read(2 * 1024 * 1024 + 1)
        except (urllib.error.HTTPError, urllib.error.URLError) as error:
            raise TriggerValidationError("GitHub API request failed") from error
        if len(content) > 2 * 1024 * 1024:
            raise TriggerValidationError("GitHub API response exceeds the size limit")
        try:
            value = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise TriggerValidationError("GitHub API returned invalid JSON") from error
        if not isinstance(value, (dict, list)):
            raise TriggerValidationError("GitHub API response must be an object or array")
        return value


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TriggerValidationError(f"{label} must be an object")
    return value


def _string(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise TriggerValidationError(f"{label} must be a bounded string")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise TriggerValidationError(f"{label} has an invalid format")
    return value


def validate_main_ci(
    client: APIClient,
    *,
    repository: str,
    commit: str,
) -> int:
    """Return the newest successful exact-main CI run ID for one commit."""

    query = urllib.parse.urlencode(
        {
            "event": "push",
            "head_sha": commit,
            "status": "completed",
            "per_page": "100",
        }
    )
    runs = _object(
        client.get(f"repos/{repository}/actions/workflows/ci.yml/runs?{query}"),
        "CI workflow runs",
    )
    workflow_runs = runs.get("workflow_runs")
    if not isinstance(workflow_runs, list) or len(workflow_runs) > 100:
        raise TriggerValidationError("CI workflow run response is invalid")
    successful = [
        run
        for run in workflow_runs
        if isinstance(run, dict)
        and run.get("event") == "push"
        and run.get("head_sha") == commit
        and run.get("head_branch") == "main"
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and isinstance(run.get("id"), int)
    ]
    if not successful:
        raise TriggerValidationError("exact release commit lacks successful main CI")
    selected = max(successful, key=lambda run: int(run["id"]))
    jobs = _object(
        client.get(
            f"repos/{repository}/actions/runs/{selected['id']}/jobs?per_page=100"
        ),
        "CI jobs",
    )
    job_records = jobs.get("jobs")
    if not isinstance(job_records, list) or len(job_records) > 100:
        raise TriggerValidationError("CI jobs response is invalid")
    successful_job_names = {
        job.get("name")
        for job in job_records
        if isinstance(job, dict)
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
        and isinstance(job.get("name"), str)
    }
    if not REQUIRED_CI_JOBS.issubset(successful_job_names):
        missing = sorted(REQUIRED_CI_JOBS - successful_job_names)
        raise TriggerValidationError(f"release CI jobs are missing or unsuccessful: {missing}")
    return int(selected["id"])


def validate_release_trigger(
    client: APIClient,
    *,
    repository: str,
    tag: str,
    event_sha: str,
    event_ref: str,
    ref_type: str,
    actor: str,
    workflow_sha: str,
    immutable_client: APIClient | None = None,
    require_immutable_releases: bool = True,
) -> dict[str, Any]:
    if repository != REPOSITORY:
        raise TriggerValidationError("release repository identity mismatch")
    if TAG_PATTERN.fullmatch(tag) is None:
        raise TriggerValidationError("release tag must be v<major>.<minor>.<patch>")
    if SHA_PATTERN.fullmatch(event_sha) is None:
        raise TriggerValidationError("release event SHA is invalid")
    if SHA_PATTERN.fullmatch(workflow_sha) is None:
        raise TriggerValidationError("release workflow SHA is invalid")
    if ref_type != "tag" or event_ref != f"refs/tags/{tag}":
        raise TriggerValidationError("release event is not the exact tag ref")
    owner = repository.split("/", 1)[0]
    if actor.casefold() != owner.casefold():
        raise TriggerValidationError("release tag must be pushed by the repository owner")

    encoded_tag = urllib.parse.quote(tag, safe="")
    tag_ref = _object(
        client.get(f"repos/{repository}/git/ref/tags/{encoded_tag}"),
        "tag ref",
    )
    tag_object = _object(tag_ref.get("object"), "tag ref object")
    if tag_object.get("type") != "tag":
        raise TriggerValidationError("release tag must be annotated")
    tag_object_sha = _string(tag_object.get("sha"), "tag object SHA", SHA_PATTERN)

    annotated_tag = _object(
        client.get(f"repos/{repository}/git/tags/{tag_object_sha}"),
        "annotated tag",
    )
    if annotated_tag.get("tag") != tag:
        raise TriggerValidationError("annotated tag name mismatch")
    target = _object(annotated_tag.get("object"), "annotated tag target")
    if target.get("type") != "commit":
        raise TriggerValidationError("annotated tag must directly target a commit")
    commit = _string(target.get("sha"), "tag commit", SHA_PATTERN)
    if commit != event_sha:
        raise TriggerValidationError("tag target does not match the event commit")
    if commit != workflow_sha:
        raise TriggerValidationError(
            "trusted default-branch workflow does not match the release commit"
        )

    repository_record = _object(
        client.get(f"repos/{repository}"),
        "repository",
    )
    if repository_record.get("default_branch") != "main":
        raise TriggerValidationError("release repository default branch must be main")
    if require_immutable_releases:
        settings_client = client if immutable_client is None else immutable_client
        immutable_releases = _object(
            settings_client.get(f"repos/{repository}/immutable-releases"),
            "immutable release settings",
        )
        if immutable_releases.get("enabled") is not True:
            raise TriggerValidationError(
                "GitHub immutable releases must be enabled before publication"
            )

    main_branch = _object(
        client.get(f"repos/{repository}/branches/main"),
        "main branch",
    )
    main_commit = _object(main_branch.get("commit"), "main branch commit")
    if main_commit.get("sha") != commit:
        raise TriggerValidationError("release tag must target the exact current main commit")

    ci_run_id = validate_main_ci(client, repository=repository, commit=commit)

    return {
        "ci_run_id": ci_run_id,
        "commit": commit,
        "repository": repository,
        "tag": tag,
        "tag_object": tag_object_sha,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--event-sha", required=True)
    parser.add_argument("--event-ref", required=True)
    parser.add_argument("--ref-type", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    parser.add_argument("--immutable-token-env", default="RELEASE_APP_TOKEN")
    parser.add_argument("--defer-immutable-setting-check", action="store_true")
    args = parser.parse_args()
    token = os.environ.get(args.token_env)
    if not token:
        raise TriggerValidationError("GitHub API token is unavailable")
    immutable_client = None
    if not args.defer_immutable_setting_check:
        immutable_token = os.environ.get(args.immutable_token_env)
        if not immutable_token:
            raise TriggerValidationError(
                "GitHub App token for immutable release settings is unavailable"
            )
        immutable_client = GitHubClient(GITHUB_API_URL, immutable_token)
    result = validate_release_trigger(
        GitHubClient(GITHUB_API_URL, token),
        repository=args.repository,
        tag=args.tag,
        event_sha=args.event_sha,
        event_ref=args.event_ref,
        ref_type=args.ref_type,
        actor=args.actor,
        workflow_sha=args.workflow_sha,
        immutable_client=immutable_client,
        require_immutable_releases=not args.defer_immutable_setting_check,
    )
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
