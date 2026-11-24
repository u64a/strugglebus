from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
from pathlib import Path
import re
import sys
from typing import Any, Callable

import pytest


REPOSITORY = Path(__file__).resolve().parents[1]
SCRIPTS = REPOSITORY / "scripts"
WORKFLOW = REPOSITORY / ".github/workflows/release-asset-recovery-proof.yml"
PROBE_PATH = SCRIPTS / "probe_release_asset_recovery.py"
sys.path.insert(0, str(SCRIPTS))


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_load("release_bundle", SCRIPTS / "release_bundle.py")
_load("validate_release_trigger", SCRIPTS / "validate_release_trigger.py")
_load("publish_immutable_release", SCRIPTS / "publish_immutable_release.py")
PROBE = _load(
    "probe_release_asset_recovery_tests",
    PROBE_PATH,
)

CURRENT_MAIN = "a" * 40
DUMMY_CONTENT = b"test recovery bytes"


def _responses() -> dict[str, Any]:
    asset = dict(PROBE.EXPECTED_ASSET)
    return {
        f"repos/{PROBE.REPOSITORY}/immutable-releases": {"enabled": True},
        f"repos/{PROBE.REPOSITORY}": {"default_branch": "main"},
        f"repos/{PROBE.REPOSITORY}/branches/main": {
            "commit": {"sha": CURRENT_MAIN}
        },
        f"repos/{PROBE.REPOSITORY}/git/ref/tags/{PROBE.PARTIAL_TAG}": {
            "object": {
                "type": "tag",
                "sha": PROBE.PARTIAL_TAG_OBJECT,
            }
        },
        f"repos/{PROBE.REPOSITORY}/git/tags/{PROBE.PARTIAL_TAG_OBJECT}": {
            "sha": PROBE.PARTIAL_TAG_OBJECT,
            "tag": PROBE.PARTIAL_TAG,
            "object": {
                "type": "commit",
                "sha": PROBE.PARTIAL_TAG_COMMIT,
            },
        },
        f"repos/{PROBE.REPOSITORY}/releases/{PROBE.PARTIAL_RELEASE_ID}": {
            **PROBE.EXPECTED_RELEASE,
            "assets": [dict(asset)],
        },
        (
            f"repos/{PROBE.REPOSITORY}/releases/"
            f"{PROBE.PARTIAL_RELEASE_ID}/assets?per_page=100"
        ): [dict(asset)],
        (
            f"repos/{PROBE.REPOSITORY}/releases/assets/"
            f"{PROBE.PARTIAL_ASSET_ID}"
        ): dict(asset),
    }


class FakeAPI:
    def __init__(self) -> None:
        self.responses = _responses()
        self.events: list[tuple[Any, ...]] = []
        self.after_first_read: Callable[[FakeAPI], None] | None = None
        self.download_parent: Path | None = None

    def get(self, path: str) -> Any:
        get_count = sum(event[0] == "get" for event in self.events)
        if get_count == len(self.responses) and self.after_first_read is not None:
            mutation = self.after_first_read
            self.after_first_read = None
            mutation(self)
        self.events.append(("get", path))
        return copy.deepcopy(self.responses[path])

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
        self.download_parent = destination.parent
        destination.write_bytes(DUMMY_CONTENT)


def _identity() -> Any:
    return PROBE.WorkflowIdentity(
        event_sha=CURRENT_MAIN,
        workflow_sha=CURRENT_MAIN,
    )


def test_recovery_proof_reads_exact_state_before_and_after_download(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = FakeAPI()
    validated: list[bytes] = []
    monkeypatch.setattr(
        PROBE,
        "_validate_download",
        lambda path: validated.append(path.read_bytes()),
    )

    result = PROBE.run_recovery_proof(api, _identity())

    assert result == {
        "asset_id": PROBE.PARTIAL_ASSET_ID,
        "release_id": PROBE.PARTIAL_RELEASE_ID,
        "status": "verified-read-only",
        "tag": PROBE.PARTIAL_TAG,
    }
    assert validated == [DUMMY_CONTENT]
    event_names = [event[0] for event in api.events]
    assert event_names == [
        *(["get"] * len(api.responses)),
        "download_asset",
        *(["get"] * len(api.responses)),
    ]
    download = api.events[len(api.responses)]
    assert download == (
        "download_asset",
        PROBE.REPOSITORY,
        PROBE.PARTIAL_ASSET_ID,
        PROBE.PARTIAL_ASSET_NAME,
        PROBE.PARTIAL_ASSET_SIZE,
        PROBE.PARTIAL_ASSET_MEDIA_TYPE,
        PROBE.PARTIAL_ASSET_SHA256,
    )
    assert api.download_parent is not None
    assert not api.download_parent.exists()


def _mutate_embedded_asset(api: FakeAPI) -> None:
    release_path = f"repos/{PROBE.REPOSITORY}/releases/{PROBE.PARTIAL_RELEASE_ID}"
    api.responses[release_path]["assets"].append(dict(PROBE.EXPECTED_ASSET))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda api: api.responses[
            f"repos/{PROBE.REPOSITORY}/immutable-releases"
        ].update(enabled=False),
        lambda api: api.responses[
            f"repos/{PROBE.REPOSITORY}/branches/main"
        ]["commit"].update(sha="b" * 40),
        lambda api: api.responses[
            f"repos/{PROBE.REPOSITORY}/git/ref/tags/{PROBE.PARTIAL_TAG}"
        ]["object"].update(sha="b" * 40),
        lambda api: api.responses[
            f"repos/{PROBE.REPOSITORY}/git/tags/{PROBE.PARTIAL_TAG_OBJECT}"
        ]["object"].update(sha="b" * 40),
        lambda api: api.responses[
            f"repos/{PROBE.REPOSITORY}/releases/{PROBE.PARTIAL_RELEASE_ID}"
        ].update(draft=False),
        _mutate_embedded_asset,
        lambda api: api.responses[
            (
                f"repos/{PROBE.REPOSITORY}/releases/"
                f"{PROBE.PARTIAL_RELEASE_ID}/assets?per_page=100"
            )
        ][0].update(size=397),
        lambda api: api.responses[
            (
                f"repos/{PROBE.REPOSITORY}/releases/assets/"
                f"{PROBE.PARTIAL_ASSET_ID}"
            )
        ].update(digest="sha256:" + "0" * 64),
    ],
)
def test_recovery_proof_refuses_exact_state_mismatches_before_download(
    mutation: Callable[[FakeAPI], None],
) -> None:
    api = FakeAPI()
    mutation(api)

    with pytest.raises(PROBE.RecoveryProofError):
        PROBE.run_recovery_proof(api, _identity())

    assert all(event[0] != "download_asset" for event in api.events)


def test_recovery_proof_revalidates_state_after_download(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = FakeAPI()
    api.after_first_read = lambda current: current.responses[
        f"repos/{PROBE.REPOSITORY}/releases/{PROBE.PARTIAL_RELEASE_ID}"
    ].update(draft=False)
    monkeypatch.setattr(PROBE, "_validate_download", lambda path: None)

    with pytest.raises(PROBE.RecoveryProofError, match="draft release"):
        PROBE.run_recovery_proof(api, _identity())

    assert any(event[0] == "download_asset" for event in api.events)
    immutable_path = f"repos/{PROBE.REPOSITORY}/immutable-releases"
    assert api.events.count(("get", immutable_path)) == 2


def test_download_validation_checks_exact_size_and_digest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    content = b"locally verified recovery content"
    path = tmp_path / PROBE.PARTIAL_ASSET_NAME
    path.write_bytes(content)
    monkeypatch.setattr(PROBE, "PARTIAL_ASSET_SIZE", len(content))
    monkeypatch.setattr(
        PROBE,
        "PARTIAL_ASSET_SHA256",
        hashlib.sha256(content).hexdigest(),
    )

    PROBE._validate_download(path)

    path.write_bytes(content[:-1] + b"x")
    with pytest.raises(PROBE.RecoveryProofError, match="digest"):
        PROBE._validate_download(path)


def _workflow_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "RECOVERY_REPOSITORY": PROBE.REPOSITORY,
        "RECOVERY_ACTOR": PROBE.OWNER,
        "RECOVERY_EVENT_NAME": PROBE.WORKFLOW_EVENT,
        "RECOVERY_REF": PROBE.WORKFLOW_REF,
        "RECOVERY_EVENT_SHA": CURRENT_MAIN,
        "RECOVERY_WORKFLOW_SHA": CURRENT_MAIN,
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("RECOVERY_REPOSITORY", "NZCypher819/other"),
        ("RECOVERY_ACTOR", "collaborator"),
        ("RECOVERY_EVENT_NAME", "push"),
        ("RECOVERY_REF", "refs/heads/other"),
        ("RECOVERY_EVENT_SHA", "invalid"),
        ("RECOVERY_WORKFLOW_SHA", "b" * 40),
    ],
)
def test_workflow_identity_refuses_nonowner_or_noncurrent_main_context(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: str,
) -> None:
    _workflow_environment(monkeypatch)
    monkeypatch.setenv(name, value)

    with pytest.raises(PROBE.RecoveryProofError):
        PROBE.workflow_identity_from_environment()


def test_main_error_is_bounded_and_does_not_echo_token(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _workflow_environment(monkeypatch)
    monkeypatch.setenv("RECOVERY_ACTOR", "wrong")
    monkeypatch.setenv("RECOVERY_PROBE_TOKEN", "sensitive-test-token")

    assert PROBE.main() == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert len(captured.err) < 256
    assert "sensitive-test-token" not in captured.err


def test_recovery_workflow_is_input_free_owner_only_and_current_main_gated() -> None:
    content = WORKFLOW.read_text(encoding="utf-8")
    trigger = content.split("permissions:", 1)[0]

    assert "workflow_dispatch:" in trigger
    assert "inputs:" not in trigger
    assert "push:" not in trigger
    assert "pull_request:" not in trigger
    assert "github.repository == 'NZCypher819/strugglebus'" in content
    assert "github.actor == 'NZCypher819'" in content
    assert "github.event_name == 'workflow_dispatch'" in content
    assert "github.ref == 'refs/heads/main'" in content
    assert "github.sha == github.workflow_sha" in content
    assert "ref: ${{ github.workflow_sha }}" in content
    assert "group: immutable-release-publication" in content
    assert "runs-on: [self-hosted, prox-runner]" in content
    assert "timeout-minutes: 5" in content
    assert 'test "$(id -u)" -ne 0' in content


def test_recovery_workflow_pins_actions_and_scopes_token_to_probe() -> None:
    content = WORKFLOW.read_text(encoding="utf-8")
    uses = re.findall(r"uses:\s+([^@\s]+)@([^\s]+)", content)

    assert uses
    assert all(re.fullmatch(r"[0-9a-f]{40}", revision) for _, revision in uses)
    assert "persist-credentials: false" in content
    assert "permissions:\n  contents: read" in content
    assert "permission-administration: read" in content
    assert "permission-contents: write" in content
    assert "owner: NZCypher819" in content
    assert "repositories: strugglebus" in content
    assert "skip-token-revoke: false" in content
    token_reference = "${{ steps.recovery-app-token.outputs.token }}"
    assert content.count(token_reference) == 1
    assert f"RECOVERY_PROBE_TOKEN: {token_reference}" in content
    assert "GH_TOKEN:" not in content
    assert "GITHUB_TOKEN:" not in content
    assert re.search(r"(?m)(?:^|[;&|]\s*)gh(?:\s|$)", content) is None


def test_probe_is_get_only_hard_coded_and_not_a_generic_release_tool() -> None:
    content = PROBE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(content)
    api_methods = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "api"
    }

    assert api_methods == {"get", "download_asset"}
    for method in ("create_draft", "upload_asset", "publish_release"):
        assert method not in content
    assert "argparse" not in content
    assert "subprocess" not in content
    assert "urllib.request" not in content
    for exact_fact in (
        PROBE.REPOSITORY,
        PROBE.PARTIAL_TAG,
        PROBE.PARTIAL_TAG_OBJECT,
        PROBE.PARTIAL_TAG_COMMIT,
        str(PROBE.PARTIAL_RELEASE_ID),
        str(PROBE.PARTIAL_ASSET_ID),
        str(PROBE.PARTIAL_ASSET_SIZE),
        PROBE.PARTIAL_ASSET_MEDIA_TYPE,
        PROBE.PARTIAL_ASSET_SHA256,
    ):
        assert exact_fact in content
    before = content.index("before = _read_exact_state")
    download = content.index("api.download_asset(", before)
    after = content.index("after = _read_exact_state", download)
    assert before < download < after
