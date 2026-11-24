from pathlib import Path
import re

from release_fixtures import load_script


REPOSITORY = Path(__file__).resolve().parents[1]
WORKFLOW = REPOSITORY / ".github/workflows/release.yml"
QUALIFICATION_WORKFLOW = REPOSITORY / ".github/workflows/release-qualification.yml"
PUBLISHER = REPOSITORY / "scripts/publish_immutable_release.py"
QUALIFICATION = load_script("release_qualification")


def _release() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _qualification() -> str:
    return QUALIFICATION_WORKFLOW.read_text(encoding="utf-8")


def test_release_workflow_has_only_the_annotated_tag_trigger() -> None:
    content = _release()
    trigger = content.split("permissions:", 1)[0]

    assert "create:" in trigger
    assert "github.workflow_sha" in content
    assert "github.event.ref_type == 'tag'" in content
    for forbidden in (
        "workflow_dispatch:",
        "pull_request:",
        "pull_request_target:",
        "release:",
        "branches:",
    ):
        assert forbidden not in trigger
    assert "validate_release_trigger.py" in content
    assert "--ref-type" in content
    assert "--actor" in content
    assert "--workflow-sha" in content
    assert "group: immutable-release-publication" in content


def test_publication_never_builds_or_rebuilds_any_asset() -> None:
    content = _release()

    for forbidden in (
        "uv build",
        "uv sync",
        "release_bundle.py build",
        "validate_clean_install.py",
        "check_requirements_lock.py",
        "validate_release_artifacts.py",
        "actions/upload-artifact@",
        "setup-uv@",
    ):
        assert forbidden not in content
    assert content.count("actions/download-artifact@") == 1
    assert content.count("publish_immutable_release.py") == 1


def test_publication_retrieves_exactly_one_qualification_artifact() -> None:
    content = _release()

    assert "release_qualification.py resolve" in content
    assert "release_qualification.py outputs" in content
    assert content.count("run-id: ${{ steps.qualification.outputs.run-id }}") == 1
    assert content.count("name: ${{ steps.qualification.outputs.artifact-name }}") == 1
    for argument in (
        "--qualification-run-id",
        "--qualification-artifact-id",
        "--qualification-artifact-name",
        "--qualification-artifact-digest",
        "--qualification-artifact-size",
        "--receipt",
    ):
        assert argument in content
    assert "publish_immutable_release.py qualified/release-assets" in content
    assert (
        "--receipt \"qualified/qualification/"
        "strugglebus-qualification-receipt-v1.json\"" in content
    )


def test_neither_release_workflow_keeps_a_second_evidence_artifact() -> None:
    qualification_source = (
        REPOSITORY / "scripts/release_qualification.py"
    ).read_text(encoding="utf-8")
    publisher = PUBLISHER.read_text(encoding="utf-8")

    for content in (_release(), _qualification(), qualification_source, publisher):
        assert "evidence" not in content.lower()
    assert _qualification().count("actions/upload-artifact@") == 1
    assert _release().count("actions/download-artifact@") == 1


def test_publication_consumes_exactly_the_rendered_resolver_outputs() -> None:
    content = _release()
    rendered = {key.replace("_", "-") for key in QUALIFICATION.OUTPUT_KEYS}
    referenced = set(
        re.findall(r"steps\.qualification\.outputs\.([a-z0-9-]+)", content)
    )

    assert referenced == rendered
    assert rendered == {
        "artifact-digest",
        "artifact-id",
        "artifact-name",
        "artifact-size-bytes",
        "run-id",
    }


def test_qualification_workflow_is_owner_bound_and_read_only() -> None:
    content = _qualification()
    header = content.split("jobs:", 1)[0]

    assert "workflow_dispatch:" in header
    assert "actions: read" in header
    assert "contents: read" in header
    assert "write" not in header
    assert "group: immutable-release-publication" in header
    assert "github.actor == 'NZCypher819'" in content
    assert "inputs.approved_by == 'NZCypher819'" in content
    assert "inputs.approval == 'publish-exact-qualified-bytes'" in content
    assert "github.ref == 'refs/heads/main'" in content
    assert "github.repository == 'NZCypher819/strugglebus'" in content
    assert "release_qualification.py gate" in content
    for forbidden in (
        "create-github-app-token",
        "RELEASE_APP_TOKEN",
        "STRUGGLEBUS_RELEASE_APP_ID",
        "publish_immutable_release.py",
        "contents: write",
        "id-token:",
        "attestations:",
    ):
        assert forbidden not in content
    assert re.search(r"^\s+contents:\s+write\s*$", content, re.MULTILINE) is None


def test_qualification_builds_the_five_assets_once_into_one_artifact() -> None:
    content = _qualification()

    assert content.count("uv build --wheel --out-dir dist") == 1
    assert content.count("release_bundle.py build") == 1
    assert content.count("--pre-tag") == 1
    assert content.count("canonical_wheel.py normalize") == 1
    assert content.count("canonical_wheel.py verify") == 1
    assert content.count("validate_clean_install.py") == 1
    assert "for python_version in 3.13; do" in content
    assert "uv python install 3.13" in content
    assert content.count("actions/upload-artifact@") == 1
    assert content.count("if-no-files-found: error") == 1
    assert content.count("release-assets/*") == 1
    assert content.count("qualification/*") == 1
    assert content.count("release_qualification.py receipt") == 1
    assert "retention-days: 7" in content
    assert "SOURCE_DATE_EPOCH" in content
    assert (
        "name: strugglebus-qualified-release-"
        "${{ inputs.release_tag }}-${{ github.run_id }}" in content
    )


def test_qualification_refuses_missing_or_invalid_selected_interpreter() -> None:
    content = _qualification()

    assert (
        'if ! selected_python="$(uv python find --no-project '
        '"$python_version")"; then'
    ) in content
    assert '[ -z "$selected_python" ] || [ ! -x "$selected_python" ]' in content
    assert "No Python $python_version interpreter is available" in content
    assert "Selected Python $python_version interpreter is not executable" in content
    assert content.count("exit 1") >= 2
    assert "--managed-python" not in content
    assert '"$selected_python" scripts/validate_clean_install.py' in content
    assert "python scripts/validate_clean_install.py" not in content


def test_release_workflow_scopes_write_access_only_to_publish() -> None:
    content = _release()
    global_permissions = content.split("concurrency:", 1)[0]
    assert "contents: read" in global_permissions
    assert "actions: read" in global_permissions
    assert "write" not in global_permissions
    assert re.search(r"^\s+contents:\s+write\s*$", content, re.MULTILINE) is None
    assert "permission-administration: read" in content
    assert "permission-contents: write" in content
    assert "repositories: strugglebus" in content
    assert "owner: NZCypher819" in content
    assert "STRUGGLEBUS_RELEASE_APP_ID" in content
    assert "STRUGGLEBUS_RELEASE_APP_PRIVATE_KEY" in content
    assert "RELEASE_APP_TOKEN" in content
    assert "skip-token-revoke: false" in content
    assert content.count("--defer-immutable-setting-check") == 1
    assert (
        content.count("RELEASE_APP_TOKEN: ${{ steps.release-app-token.outputs.token }}")
        == 1
    )
    assert "GH_TOKEN:" not in content
    for forbidden in (
        "attestations:",
        "id-token:",
        "packages: write",
        "pull-requests: write",
    ):
        assert forbidden not in content


def test_both_release_workflows_are_fork_blocked_pinned_and_time_bounded() -> None:
    for content in (_release(), _qualification()):
        assert content.count("github.repository == 'NZCypher819/strugglebus'") == 1
        assert content.count("runs-on: [self-hosted, prox-runner]") == 1
        assert content.count("timeout-minutes:") == 1
        assert content.count("persist-credentials: false") == 1
        uses = re.findall(r"uses:\s+([^@\s]+)@([^\s]+)", content)
        assert uses
        assert all(re.fullmatch(r"[0-9a-f]{40}", revision) for _, revision in uses)
    assert "actions/create-github-app-token@" in _release()


def test_release_workflow_uses_only_the_python_rest_state_machine() -> None:
    content = _release()
    publisher = PUBLISHER.read_text(encoding="utf-8")
    publish_step = content.split("Verify every binding and publish", 1)[1]

    assert content.count("publish_immutable_release.py") == 1
    assert '--commit "$RELEASE_COMMIT"' in publish_step
    assert '--tree "$SOURCE_TREE"' in publish_step
    assert "GITHUB_TOKEN: ${{ github.token }}" in publish_step
    assert (
        "RELEASE_APP_TOKEN: ${{ steps.release-app-token.outputs.token }}"
        in publish_step
    )
    assert re.search(r"(?m)(?:^|[;&|]\s*)gh(?:\s|$)", content) is None
    assert re.search(r"(?m)(?:^|[;&|]\s*)gh(?:\s|$)", publisher) is None
    assert re.search(r"(?m)(?:^|[;&|]\s*)gh(?:\s|$)", _qualification()) is None
    assert "subprocess" not in publisher
    assert "shutil.which" not in publisher
    assert "/tmp/" not in publish_step


def test_publisher_validates_qualification_and_draft_before_publish() -> None:
    content = PUBLISHER.read_text(encoding="utf-8")
    state_machine = content.split("def publish_immutable_release(", 1)[1]
    qualification = state_machine.index("verify_qualified_release(")
    complete_draft = state_machine.index('workspace / "complete-draft"')
    revalidate = state_machine.index("_validate_trigger(", complete_draft)
    publish = state_machine.index("api.publish_release(", revalidate)
    immutable = state_machine.index('published_state != "immutable"', publish)
    published_copy = state_machine.index('workspace / "published-release"', immutable)
    first_mutation = min(
        state_machine.index("api.create_draft("),
        state_machine.index("api.upload_asset("),
        state_machine.index("api.publish_release("),
    )

    assert qualification < first_mutation
    assert qualification < complete_draft < revalidate < publish < immutable
    assert immutable < published_copy
