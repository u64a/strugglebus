from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
from typing import Any
import zipfile

import pytest

from promotion_fixtures import (
    CI_RUN_ID,
    REPO,
    ROOT,
    VERSION,
    FakePromotionAPI,
    MemoryReceiptStore,
    QualifiedBundle,
    build_qualified_bundle,
    copy_json,
    deadline_after_one_poll,
    deadline_sleep,
    qualification_zip,
    run_promotion,
)
from release_fixtures import (
    ARTIFACT_ID,
    OWNER,
    PUBLISHED_AT,
    QUALIFICATION_RUN_ID,
    canonical_json,
    load_script,
    run_git,
)


@pytest.fixture(scope="session")
def qualified_bundle(tmp_path_factory: pytest.TempPathFactory) -> QualifiedBundle:
    return build_qualified_bundle(tmp_path_factory.mktemp("promotion-bundle"))


@pytest.fixture
def promotion() -> Any:
    return load_script("promote_release")


@pytest.fixture
def api(qualified_bundle: QualifiedBundle, tmp_path: Path) -> FakePromotionAPI:
    return FakePromotionAPI(
        qualified_bundle, MemoryReceiptStore(tmp_path / "promotion-receipt.json")
    )


def assert_read_only(api: FakePromotionAPI, snapshots: int = 0) -> None:
    assert api.mutations == []
    assert len(api.store.snapshots) == snapshots
    assert not [event for event in api.events if event[0].startswith("download")]


def trust_errors(promotion: Any) -> tuple[type[Exception], ...]:
    return (
        promotion.PromotionError,
        promotion.QualificationError,
        promotion.TriggerValidationError,
        promotion.ReleaseBundleError,
        promotion.ReleasePublicationError,
    )


def pause_after(api: FakePromotionAPI, phase: str) -> None:
    def stop(operation: dict[str, Any]) -> None:
        if operation["phase"] == phase:
            raise load_script("promotion_common").PromotionError("test interruption", code=5)

    api.store.after_write = stop


def test_one_entrypoint_dispatches_then_verifies_exact_immutable_bytes(
    promotion: Any, api: FakePromotionAPI
) -> None:
    result = run_promotion(api)
    assert result["phase"] == "complete"
    assert result["deployment_performed"] is False
    assert result["commit"] == api.bundle.commit
    assert result["tree"] == api.bundle.tree
    assert result["qualification_run_id"] == QUALIFICATION_RUN_ID
    assert result["qualification_artifact_id"] == ARTIFACT_ID
    assert result["qualification_artifact_digest"] == hashlib.sha256(api.archive).hexdigest()
    assert result["release_url"] == f"https://github.com/{REPO}/releases/tag/v{VERSION}"
    assert result["next_action"] == "docs/DEPLOYMENT.md#maintenance-window-upgrade"
    assert [name for name, _ in api.mutations] == ["dispatch", "create_tag", "create_ref"]
    assert [state["phase"] for state in api.intent_snapshots] == [
        "dispatch_intent", "tag_object_intent", "tag_ref_intent"
    ]
    assert sorted(event[1] for event in api.events if event[0] == "download_asset") == sorted(
        api.bundle.assets
    )
    operation = api.store.read()
    assert promotion.validate_operation(operation) == operation
    assert operation["qualification"]["run_attempt"] == 1
    assert operation["release"]["verified_at"] == PUBLISHED_AT
    assert api.store.snapshots[0]["phase"] == "created"
    assert api.store.snapshots[0]["qualification"] is None
    assert api.store.snapshots[1]["dispatch"]["acknowledged"] is False
    assert not list(api.store.path.parent.glob(".promotion-*"))


def test_valid_existing_qualification_is_reused_without_dispatch(
    promotion: Any, api: FakePromotionAPI
) -> None:
    api.install_qualification()
    assert run_promotion(api)["phase"] == "complete"
    assert [name for name, _ in api.mutations] == ["create_tag", "create_ref"]
    assert api.store.read()["dispatch"] is None


@pytest.mark.skipif(sys.platform != "linux", reason="real protected Linux receipt storage")
@pytest.mark.parametrize("lost_response", [None, "dispatch", "create_tag", "create_ref"])
def test_operator_flow_with_real_durable_receipts(
    promotion: Any, api: FakePromotionAPI, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch, lost_response: str | None,
) -> None:
    private = tmp_path / "private-state"
    private.mkdir(mode=0o700)
    state = load_script("promotion_state")
    receipt_path = private / "promotion.json"
    api.store = state.ReceiptStore(receipt_path)

    def intent(mutation: str, payload: Any, phase: str) -> None:
        snapshot = api.store.read()
        assert snapshot["phase"] == phase
        assert snapshot["tag"] == api.bundle.tag
        assert snapshot["commit"] == api.bundle.commit
        assert os.stat(receipt_path).st_mode & 0o777 == 0o600
        assert mutation not in [name for name, _ in api.mutations]
        api.intent_snapshots.append(snapshot)
        api.mutations.append((mutation, copy_json(payload)))

    monkeypatch.setattr(api, "_intent", intent)
    if lost_response is not None:
        api.loss_once.add(lost_response)
        with pytest.raises(promotion.PromotionError):
            run_promotion(api)
        api.store = state.ReceiptStore(receipt_path)
    result = run_promotion(api, resume=lost_response is not None)
    assert result["phase"] == "complete"
    completed = state.ReceiptStore(receipt_path).read()
    assert completed["release"]["id"] == result["release_id"]
    assert [name for name, _ in api.mutations] == ["dispatch", "create_tag", "create_ref"]
    assert sorted(path.name for path in private.iterdir()) == [
        "promotion.json", "promotion.json.lock"
    ]


@pytest.mark.parametrize("state", ["absent", "pending", "ready"])
def test_plan_is_read_only_even_with_existing_qualification(
    promotion: Any, api: FakePromotionAPI, state: str
) -> None:
    if state != "absent":
        run = api.install_qualification()
        if state == "pending":
            run.update(status="in_progress", conclusion=None)
    before = set(api.store.path.parent.iterdir())
    result = promotion.plan(api, api.bundle.tag, api.bundle.commit)
    assert result["read_only"] is True
    assert result["qualification"] == state
    assert result["tree"] == api.bundle.tree
    assert api.store.content is None
    assert api.store.locks == 0
    assert set(api.store.path.parent.iterdir()) == before
    assert_read_only(api)


def test_status_preserves_unknown_intent_without_download_or_repair(
    promotion: Any, api: FakePromotionAPI
) -> None:
    api.visible_dispatch = False
    api.loss_once.add("dispatch")
    with pytest.raises(promotion.PromotionError, match="outcome is unknown"):
        run_promotion(api)
    operation = api.store.read()
    before = api.store.content
    snapshots = len(api.store.snapshots)
    locks = api.store.locks
    api.events.clear()
    api.mutations.clear()
    result = promotion.status(api, operation)
    assert result["recorded_phase"] == "dispatch_intent"
    assert result["observed_run_ids"] == []
    assert "unknown" in result["dispatch_outcome"]
    assert result["verification"].startswith("metadata-only")
    assert api.store.content == before
    assert api.store.locks == locks
    assert_read_only(api, snapshots)


@pytest.mark.parametrize(
    "case",
    ["owner", "main", "default-branch", "immutable", "version", "ci-missing", "ci-failed",
     "ci-job", "commit-response"],
)
def test_preflight_failures_never_write_or_mutate(
    promotion: Any, api: FakePromotionAPI, case: str
) -> None:
    if case == "owner":
        api.responses["user"]["login"] = "not-the-owner"
    elif case == "main":
        api.responses[f"{ROOT}/branches/main"]["commit"]["sha"] = "9" * 40
    elif case == "default-branch":
        api.responses[ROOT]["default_branch"] = "other"
    elif case == "immutable":
        api.responses[f"{ROOT}/immutable-releases"]["enabled"] = False
    elif case == "version":
        api.source_version = VERSION + "0"
    elif case.startswith("ci-"):
        path = next(path for path in api.responses if "/workflows/ci.yml/" in path)
        if case == "ci-missing":
            api.responses[path]["workflow_runs"] = []
            api.responses[path]["total_count"] = 0
        elif case == "ci-failed":
            api.responses[path]["workflow_runs"][0]["conclusion"] = "failure"
        else:
            api.responses[f"{ROOT}/actions/runs/{CI_RUN_ID}/jobs?per_page=100"]["jobs"][0][
                "conclusion"
            ] = "failure"
    else:
        api.responses[f"{ROOT}/git/commits/{api.bundle.commit}"]["sha"] = "9" * 40
    with pytest.raises(trust_errors(promotion)):
        run_promotion(api)
    assert_read_only(api)
    assert api.store.content is None


@pytest.mark.parametrize("tag", [
    "v0.2.0", "v0.2.1", "v0.2.2", "v0.2.3", "v0.2.5", "v0.2.6", "v0.2.28", "v0.2.31", "v0.2.32",
    "v0.2.12/../../main", "v0.2.12\n", "0.2.12", "v0.2.12-rc1",
])
def test_disqualified_or_malformed_tag_is_rejected_before_api(
    promotion: Any, api: FakePromotionAPI, tag: str
) -> None:
    with pytest.raises(promotion.PromotionError):
        promotion.promote(
            api, api.store, tag=tag, commit=api.bundle.commit,
            approval=promotion.APPROVAL_PHRASE,
        )
    assert api.events == []
    assert_read_only(api)


@pytest.mark.parametrize("commit", ["main", "A" * 40, "a" * 39, "a" * 41, "a" * 40 + "\n"])
def test_malformed_commit_is_rejected_before_api(
    promotion: Any, api: FakePromotionAPI, commit: str
) -> None:
    with pytest.raises(promotion.PromotionError):
        promotion.promote(
            api, api.store, tag=api.bundle.tag, commit=commit,
            approval=promotion.APPROVAL_PHRASE,
        )
    assert api.events == []


def test_exact_approval_is_required_before_receipt_lock(
    promotion: Any, api: FakePromotionAPI
) -> None:
    with pytest.raises(promotion.PromotionError) as error:
        promotion.promote(
            api, api.store, tag=api.bundle.tag, commit=api.bundle.commit,
            approval="publish-exact-qualified-bytes ",
        )
    assert error.value.code == 2
    assert api.store.locks == 0
    assert api.events == []


@pytest.mark.parametrize("case", ["two-successes", "two-pending", "success-and-pending", "failed"])
def test_ambiguous_or_failed_qualification_never_dispatches_replacement(
    promotion: Any, api: FakePromotionAPI, case: str
) -> None:
    first = api.install_qualification()
    if case != "failed":
        second = api.install_qualification(run_id=QUALIFICATION_RUN_ID + 1)
        if case in {"two-pending", "success-and-pending"}:
            second.update(status="in_progress", conclusion=None)
        if case == "two-pending":
            first.update(status="queued", conclusion=None)
    else:
        first["conclusion"] = "failure"
    with pytest.raises(trust_errors(promotion)):
        run_promotion(api, sleep=deadline_sleep)
    assert api.mutations == []
    assert not [event for event in api.events if event[0].startswith("download")]


def test_single_unattributed_pending_run_is_observed_never_redispatched(
    promotion: Any, api: FakePromotionAPI
) -> None:
    run = api.install_qualification()
    run.update(status="in_progress", conclusion=None)
    with pytest.raises(promotion.PromotionError) as error:
        run_promotion(api, sleep=deadline_sleep)
    assert error.value.code == 5
    assert api.store.read()["phase"] == "qualifying"
    assert api.store.read()["dispatch"] is None
    assert api.mutations == []
    run.update(status="completed", conclusion="success")
    assert run_promotion(api, resume=True)["phase"] == "complete"
    assert [name for name, _ in api.mutations] == ["create_tag", "create_ref"]


@pytest.mark.parametrize("case", ["overflow", "exact-page", "duplicate-id"])
def test_unprovable_run_listing_completeness_fails_closed(
    promotion: Any, api: FakePromotionAPI, case: str
) -> None:
    run = api.install_qualification()
    if case == "overflow":
        response = {"total_count": 101, "workflow_runs": [run]}
    elif case == "exact-page":
        runs = [dict(run, id=10000 + index) for index in range(100)]
        response = {"total_count": 100, "workflow_runs": runs}
    else:
        response = {"total_count": 2, "workflow_runs": [run, run]}
    api.responses[api.all_runs_path] = response
    with pytest.raises(promotion.PromotionError):
        run_promotion(api)
    assert api.mutations == []
    assert not [event for event in api.events if event[0].startswith("download")]


@pytest.mark.parametrize("case", ["artifact-expired", "receipt-expired", "run-attempt"])
def test_expired_or_changed_qualification_never_tags(
    promotion: Any, api: FakePromotionAPI, case: str
) -> None:
    run = api.install_qualification()
    if case == "artifact-expired":
        api.artifact_record()["expired"] = True
    elif case == "run-attempt":
        run["run_attempt"] = 2
    kwargs = {}
    if case == "receipt-expired":
        receipt = json.loads(api.bundle.receipt)
        expires = receipt["expires_at"]
        kwargs["now"] = lambda: expires
    if kwargs:
        with pytest.raises(trust_errors(promotion)):
            promotion.promote(
                api, api.store, tag=api.bundle.tag, commit=api.bundle.commit,
                approval=promotion.APPROVAL_PHRASE, sleep=deadline_sleep, **kwargs,
            )
    else:
        with pytest.raises(trust_errors(promotion)):
            run_promotion(api)
    assert api.mutations == []
    assert api.store.read()["qualification"] is None


@pytest.mark.parametrize("case", [
    "noncanonical", "duplicate", "wrong-owner", "wrong-repository", "wrong-commit", "asset-digest",
])
def test_strict_qualification_receipt_is_enforced_by_real_validator(
    promotion: Any, api: FakePromotionAPI, case: str
) -> None:
    api.install_qualification()
    receipt = json.loads(api.bundle.receipt)
    if case == "noncanonical":
        payload = json.dumps(receipt, indent=2).encode()
    elif case == "duplicate":
        payload = b'{"receipt_version":1,' + api.bundle.receipt[1:]
    else:
        if case == "wrong-owner":
            receipt["approval"]["approved_by"] = "other-owner"
        elif case == "wrong-repository":
            receipt["qualification"]["repository"] = "other/strugglebus"
        elif case == "wrong-commit":
            receipt["release"]["commit"] = "9" * 40
        else:
            receipt["assets"][0]["sha256"] = "0" * 64
        payload = canonical_json(receipt)
    api.replace_archive(qualification_zip(api.bundle.assets, payload))
    with pytest.raises(trust_errors(promotion)):
        run_promotion(api)
    assert api.mutations == []


@pytest.mark.parametrize("mutation,phase", [
    ("dispatch", "dispatch_intent"),
    ("create_tag", "tag_object_intent"),
    ("create_ref", "tag_ref_intent"),
])
def test_lost_accepted_mutation_response_resumes_without_repeating(
    promotion: Any, api: FakePromotionAPI, mutation: str, phase: str
) -> None:
    api.loss_once.add(mutation)
    with pytest.raises(promotion.PromotionError) as error:
        run_promotion(api)
    assert error.value.code == 5
    assert api.store.read()["phase"] == phase
    assert [name for name, _ in api.mutations].count(mutation) == 1
    result = run_promotion(api, resume=True)
    assert result["phase"] == "complete"
    assert [name for name, _ in api.mutations] == ["dispatch", "create_tag", "create_ref"]


@pytest.mark.parametrize("accepted", [False, True])
def test_no_visible_dispatch_event_never_authorizes_another_dispatch(
    promotion: Any, api: FakePromotionAPI, accepted: bool
) -> None:
    api.visible_dispatch = False
    if not accepted:
        api.loss_once.add("dispatch")
    with pytest.raises(promotion.PromotionError) as first:
        run_promotion(api, sleep=deadline_sleep)
    assert first.value.code == 5
    with pytest.raises(promotion.PromotionError) as resumed:
        run_promotion(api, resume=True, sleep=deadline_sleep)
    assert resumed.value.code == 5
    assert [name for name, _ in api.mutations] == ["dispatch"]
    assert api.store.read()["dispatch"]["acknowledged"] is accepted
    assert api.store.read()["qualification"] is None


@pytest.mark.parametrize("mutation", ["create_tag", "create_ref"])
def test_unknown_tag_mutation_with_no_visible_object_or_ref_is_not_repeated(
    promotion: Any, api: FakePromotionAPI, mutation: str
) -> None:
    api.loss_once.add(mutation)
    with pytest.raises(promotion.PromotionError):
        run_promotion(api)
    if mutation == "create_tag":
        api.tag_objects.clear()
    else:
        api.tag_ref = None
        api.release = None
    before = copy_json(api.mutations)
    with pytest.raises(promotion.PromotionError) as error:
        run_promotion(api, resume=True, sleep=deadline_sleep)
    assert error.value.code == 5
    assert copy_json(api.mutations) == before


def test_unexpected_github_tag_hash_never_creates_ref(
    promotion: Any, api: FakePromotionAPI
) -> None:
    api.unexpected_tag_sha = True
    with pytest.raises(promotion.PromotionError, match="tag object conflicts"):
        run_promotion(api)
    assert [name for name, _ in api.mutations] == ["dispatch", "create_tag"]
    assert api.tag_ref is None
    with pytest.raises(promotion.PromotionError) as error:
        run_promotion(api, resume=True, sleep=deadline_sleep)
    assert error.value.code == 5
    assert api.tag_ref is None


@pytest.mark.parametrize("conflict", ["object-message", "object-target", "ref-object", "lightweight-ref"])
def test_resume_rejects_conflicting_tag_provenance_without_repair(
    promotion: Any, api: FakePromotionAPI, conflict: str
) -> None:
    api.loss_once.add("create_ref" if "ref" in conflict else "create_tag")
    with pytest.raises(promotion.PromotionError):
        run_promotion(api)
    expected = api.store.read()["tag_intent"]["expected_sha"]
    if conflict == "object-message":
        api.tag_objects[expected]["message"] = "same commit but different operation"
    elif conflict == "object-target":
        api.tag_objects[expected]["object"]["sha"] = "8" * 40
    elif conflict == "ref-object":
        api.tag_ref["object"]["sha"] = "8" * 40
    else:
        api.tag_ref["object"] = {"type": "commit", "sha": api.bundle.commit}
    before = copy_json(api.mutations)
    with pytest.raises(promotion.PromotionError):
        run_promotion(api, resume=True)
    assert copy_json(api.mutations) == before


@pytest.mark.parametrize("state", ["tag", "draft", "immutable"])
def test_consumed_tag_or_release_cannot_start_new_operation(
    promotion: Any, api: FakePromotionAPI, state: str
) -> None:
    if state == "tag":
        api.tag_ref = {
            "ref": f"refs/tags/{api.bundle.tag}",
            "object": {"type": "tag", "sha": "3" * 40},
        }
    else:
        api.publish(state)
    with pytest.raises(promotion.PromotionError, match="consumed"):
        run_promotion(api)
    assert_read_only(api)
    assert api.store.content is None


@pytest.mark.parametrize("stage,mutations", [
    ("dispatch_intent", []),
    ("qualified", ["dispatch"]),
    ("tag_object_intent", ["dispatch"]),
    ("tag_object_ready", ["dispatch", "create_tag"]),
    ("tag_ref_intent", ["dispatch", "create_tag"]),
])
def test_main_advancement_before_each_mutation_stops_advancement(
    promotion: Any, api: FakePromotionAPI, stage: str, mutations: list[str]
) -> None:
    def advance(operation: dict[str, Any]) -> None:
        if operation["phase"] == stage:
            api.responses[f"{ROOT}/branches/main"]["commit"]["sha"] = "9" * 40

    api.store.after_write = advance
    with pytest.raises(trust_errors(promotion)):
        run_promotion(api)
    assert [name for name, _ in api.mutations] == mutations
    assert api.tag_ref is None


@pytest.mark.parametrize("completed", [False, True])
def test_partial_draft_waits_only_while_publisher_is_active(
    promotion: Any, api: FakePromotionAPI, completed: bool
) -> None:
    api.publish_on_ref = "draft"

    def finish(mutation: str) -> None:
        if mutation == "create_ref" and completed:
            api.publisher_runs[0].update(status="completed", conclusion="failure")

    api.after_mutation = finish
    with pytest.raises(promotion.PromotionError) as error:
        run_promotion(api, sleep=deadline_after_one_poll())
    assert error.value.code == (6 if completed else 5)
    if completed:
        assert "consumed" in str(error.value)
    assert api.store.read()["phase"] == "publishing"
    assert api.store.read()["release"] is None
    assert set(api.stored_assets) == {"requirements.lock"}
    assert not [event for event in api.events if event[0] == "download_asset"]
    if not completed:
        api.publish()
        assert run_promotion(api, resume=True)["phase"] == "complete"


def test_failed_workflow_after_actual_immutable_publication_succeeds(
    promotion: Any, api: FakePromotionAPI
) -> None:
    def failed_cleanup(mutation: str) -> None:
        if mutation == "create_ref":
            api.publisher_runs[0].update(status="completed", conclusion="failure")

    api.after_mutation = failed_cleanup
    assert run_promotion(api)["phase"] == "complete"
    assert len([event for event in api.events if event[0] == "download_asset"]) == 5


def test_main_advance_after_tag_observation_does_not_block_resume_verification(
    promotion: Any, api: FakePromotionAPI
) -> None:
    api.publish_on_ref = None
    with pytest.raises(promotion.PromotionError) as error:
        run_promotion(api, sleep=deadline_after_one_poll())
    assert error.value.code == 5
    assert api.store.read()["phase"] == "publishing"
    api.responses[f"{ROOT}/branches/main"]["commit"]["sha"] = "9" * 40
    api.publish()
    assert run_promotion(api, resume=True)["phase"] == "complete"
    assert [name for name, _ in api.mutations] == ["dispatch", "create_tag", "create_ref"]


def test_lost_ref_response_reconciles_owned_ref_after_main_advances(
    promotion: Any, api: FakePromotionAPI
) -> None:
    api.loss_once.add("create_ref")
    with pytest.raises(promotion.PromotionError):
        run_promotion(api)
    assert api.store.read()["phase"] == "tag_ref_intent"
    api.responses[f"{ROOT}/branches/main"]["commit"]["sha"] = "9" * 40
    assert run_promotion(api, resume=True)["phase"] == "complete"
    assert [name for name, _ in api.mutations] == ["dispatch", "create_tag", "create_ref"]


def test_completed_historical_status_is_metadata_only_after_main_and_artifact_change(
    promotion: Any, api: FakePromotionAPI
) -> None:
    run_promotion(api)
    operation = api.store.read()
    api.responses[f"{ROOT}/branches/main"]["commit"]["sha"] = "9" * 40
    api.artifact_record()["expired"] = True
    api.runs.clear()
    api.events.clear()
    api.mutations.clear()
    before = api.store.content
    snapshots = len(api.store.snapshots)
    result = promotion.status(api, operation)
    assert result["recorded_phase"] == "complete"
    assert result["release_state"] == "immutable"
    assert result["prior_verification_at"] == PUBLISHED_AT
    assert "no new byte or qualification verification" in result["verification"]
    assert api.store.content == before
    assert_read_only(api, snapshots)
    assert not [event for event in api.events if "/actions/" in str(event)]
    assert run_promotion(api, resume=True)["recorded_phase"] == "complete"
    assert_read_only(api, snapshots)


@pytest.mark.parametrize("field,value", [
    ("repository", "other/strugglebus"), ("owner", "other"),
    ("receipt_version", True), ("receipt_version", 2), ("operation_id", "../bad"),
    ("commit", "not-a-sha"), ("tree", "F" * 40), ("created_at", True),
    ("ci_run_id", 0), ("phase", "deploying"), ("unknown", "not permitted"),
])
def test_tampered_operation_is_rejected_before_live_reads(
    promotion: Any, api: FakePromotionAPI, field: str, value: Any
) -> None:
    pause_after(api, "created")
    with pytest.raises(promotion.PromotionError, match="test interruption"):
        run_promotion(api)
    operation = api.store.read()
    operation[field] = value
    api.store.content = canonical_json(operation)
    api.store.after_write = None
    api.events.clear()
    with pytest.raises(promotion.PromotionError):
        run_promotion(api, resume=True)
    assert api.events == []
    assert api.mutations == []


@pytest.mark.parametrize("field", ["artifact-name", "asset-name", "tag-payload", "tag-sha", "release-expiry"])
def test_cross_bound_receipt_fields_cannot_be_tampered(
    promotion: Any, api: FakePromotionAPI, field: str
) -> None:
    run_promotion(api)
    operation = api.store.read()
    if field == "artifact-name":
        operation["qualification"]["artifact_name"] += "-other"
    elif field == "asset-name":
        operation["qualification"]["assets"][0]["name"] = "../../escape"
    elif field == "tag-payload":
        operation["tag_intent"]["payload"]["message"] += "modified"
    elif field == "tag-sha":
        operation["tag_intent"]["expected_sha"] = "8" * 40
    else:
        operation["release"]["verified_at"] = operation["qualification"]["expires_at"]
    api.events.clear()
    with pytest.raises(promotion.PromotionError):
        promotion.status(api, operation)
    assert api.events == []


def test_resume_requires_existing_exact_identity_and_never_replaces_receipt(
    promotion: Any, api: FakePromotionAPI
) -> None:
    with pytest.raises(promotion.PromotionError, match="does not exist"):
        run_promotion(api, resume=True)
    pause_after(api, "created")
    with pytest.raises(promotion.PromotionError, match="test interruption"):
        run_promotion(api)
    before = api.store.content
    api.store.after_write = None
    with pytest.raises(promotion.PromotionError, match="already exists"):
        run_promotion(api)
    with pytest.raises(promotion.PromotionError, match="identity"):
        promotion.promote(
            api, api.store, tag=f"v{VERSION}0", commit=api.bundle.commit,
            approval=promotion.APPROVAL_PHRASE, resume=True,
        )
    assert api.store.content == before
    assert api.mutations == []


def test_receipt_run_attempt_drift_on_resume_stops_before_tag(
    promotion: Any, api: FakePromotionAPI
) -> None:
    pause_after(api, "qualified")
    with pytest.raises(promotion.PromotionError, match="test interruption"):
        run_promotion(api)
    api.store.after_write = None
    api.runs[0]["run_attempt"] = 2
    with pytest.raises(trust_errors(promotion)):
        run_promotion(api, resume=True)
    assert [name for name, _ in api.mutations] == ["dispatch"]


@pytest.mark.parametrize("field,value", [
    ("artifact_id", ARTIFACT_ID + 1), ("run_attempt", 2),
    ("receipt_sha256", "0" * 64), ("helper_sha256", "0" * 64),
    ("artifact_digest", "0" * 64),
])
def test_well_formed_qualification_tampering_is_detected_by_live_reverification(
    promotion: Any, api: FakePromotionAPI, field: str, value: Any
) -> None:
    pause_after(api, "qualified")
    with pytest.raises(promotion.PromotionError, match="test interruption"):
        run_promotion(api)
    operation = api.store.read()
    operation["qualification"][field] = value
    promotion.validate_operation(operation)
    api.store.content = canonical_json(operation)
    api.store.after_write = None
    with pytest.raises(trust_errors(promotion)):
        run_promotion(api, resume=True)
    assert [name for name, _ in api.mutations] == ["dispatch"]
    assert api.tag_ref is None


def test_expired_protected_qualification_cannot_resume_even_with_present_artifact(
    promotion: Any, api: FakePromotionAPI
) -> None:
    pause_after(api, "qualified")
    with pytest.raises(promotion.PromotionError, match="test interruption"):
        run_promotion(api)
    api.store.after_write = None
    expires = api.store.read()["qualification"]["expires_at"]
    api.events.clear()
    with pytest.raises(promotion.PromotionError, match="expired"):
        promotion.promote(
            api, api.store, tag=api.bundle.tag, commit=api.bundle.commit,
            approval=promotion.APPROVAL_PHRASE, resume=True,
            now=lambda: expires, sleep=deadline_sleep,
        )
    assert [name for name, _ in api.mutations] == ["dispatch"]
    assert not [event for event in api.events if event[0].startswith("download")]


def test_status_wrong_owner_fails_without_reconciliation_or_writes(
    promotion: Any, api: FakePromotionAPI
) -> None:
    pause_after(api, "created")
    with pytest.raises(promotion.PromotionError, match="test interruption"):
        run_promotion(api)
    before = api.store.content
    api.responses["user"]["login"] = "not-the-owner"
    api.events.clear()
    with pytest.raises(promotion.PromotionError) as error:
        promotion.status(api, api.store.read())
    assert error.value.code == 4
    assert api.events == [("get", "user")]
    assert api.store.content == before
    assert_read_only(api, snapshots=1)


def test_tag_object_hash_matches_real_git_serialization(
    promotion: Any, api: FakePromotionAPI, tmp_path: Path
) -> None:
    pause_after(api, "tag_object_intent")
    with pytest.raises(promotion.PromotionError, match="test interruption"):
        run_promotion(api)
    operation = api.store.read()
    payload = operation["tag_intent"]["payload"]
    root = tmp_path / "tag-hash"
    root.mkdir()
    run_git(root, "init")
    tag_file = root / "tag-object"
    tag_file.write_bytes(
        (
            f"object {api.bundle.commit}\ntype commit\ntag {api.bundle.tag}\n"
            f"tagger {OWNER} <{OWNER}@users.noreply.github.com> {PUBLISHED_AT} +0000\n\n"
            f"{payload['message']}"
        ).encode("ascii")
    )
    expected = run_git(root, "hash-object", "-t", "tag", str(tag_file))
    assert expected == operation["tag_intent"]["expected_sha"]
    assert promotion.tag_object_sha(payload) == expected


@pytest.mark.parametrize(
    "case",
    ["extra", "duplicate", "traversal", "link", "directory-link", "oversize", "footer-bomb"],
)
def test_qualification_zip_rejects_unsafe_members_and_bounded_expansion(
    promotion: Any, api: FakePromotionAPI, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    assets = api.bundle.assets
    receipt = api.bundle.receipt
    if case == "extra":
        payload = qualification_zip(assets, receipt, extra=("extra.txt", b"untrusted"))
    elif case == "duplicate":
        with pytest.warns(UserWarning, match="Duplicate name"):
            payload = qualification_zip(
                assets, receipt, extra=("release-assets/requirements.lock", b"duplicate")
            )
    elif case == "traversal":
        payload = qualification_zip(assets, receipt, extra=("../escape", b"escape"))
    elif case == "link":
        payload = qualification_zip(assets, receipt, link="release-assets/requirements.lock")
    elif case == "directory-link":
        payload = qualification_zip(
            assets, receipt, extra=("release-assets/", b""), link="release-assets/"
        )
    elif case == "oversize":
        monkeypatch.setattr(promotion, "MAX_ASSET_BYTES", 64)
        payload = api.bundle.archive
    else:
        payload_array = bytearray(api.bundle.archive)
        footer = payload_array.rfind(b"PK\x05\x06")
        struct.pack_into("<HH", payload_array, footer + 8, 65535, 65535)
        struct.pack_into("<L", payload_array, footer + 12, 0xFFFFFFFF)
        payload = bytes(payload_array)
    archive = tmp_path / "unsafe.zip"
    archive.write_bytes(payload)
    destination = tmp_path / "extracted"
    with pytest.raises(promotion.PromotionError):
        promotion.extract_qualification(archive, destination, VERSION)
    assert not destination.exists()
    assert not (tmp_path / "escape").exists()


def test_valid_qualification_zip_extracts_only_six_exact_regular_files(
    promotion: Any, api: FakePromotionAPI, tmp_path: Path
) -> None:
    archive = tmp_path / "qualified.zip"
    archive.write_bytes(api.archive)
    destination = tmp_path / "extracted"
    promotion.extract_qualification(archive, destination, VERSION)
    extracted = {
        path.relative_to(destination).as_posix(): path.read_bytes()
        for path in destination.rglob("*") if path.is_file()
    }
    expected = {f"release-assets/{name}": data for name, data in api.bundle.assets.items()}
    expected[f"qualification/{promotion.RECEIPT_NAME}"] = api.bundle.receipt
    assert extracted == expected


@pytest.mark.parametrize("comment_size", [0, 65535])
def test_zip64_cannot_override_checked_directory_bounds(
    promotion: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    comment_size: int,
) -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for index in range(32):
            archive.writestr(f"entry-{index:03}", b"")
    original = output.getvalue()
    ordinary = original[-22:]
    _, _, _, _, count, central_size, central_offset, _ = struct.unpack(
        "<4s4H2LH", ordinary
    )
    prefix = original[:-22]
    zip64 = struct.pack(
        "<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0,
        count, count, central_size, central_offset,
    )
    locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, len(prefix), 1)
    # This ordinary footer claims a tiny six-entry directory covering only the
    # ZIP64 records. ZipFile would instead parse the larger real directory.
    false_footer = struct.pack(
        "<4s4H2LH", b"PK\x05\x06", 0, 0, 6, 6,
        len(zip64) + len(locator), len(prefix), comment_size,
    )
    path = tmp_path / "zip64.zip"
    path.write_bytes(prefix + zip64 + locator + false_footer + b"x" * comment_size)

    def forbidden_parser(*args: Any, **kwargs: Any) -> None:
        pytest.fail("ZIP64 must be rejected before ZipFile allocates member objects")

    monkeypatch.setattr(promotion.zipfile, "ZipFile", forbidden_parser)
    destination = tmp_path / "extracted"
    with pytest.raises(promotion.PromotionError, match="ZIP64"):
        promotion.extract_qualification(path, destination, VERSION)
    assert not destination.exists()


def test_changed_bundle_bytes_in_an_otherwise_valid_archive_fail_before_tagging(
    promotion: Any, api: FakePromotionAPI
) -> None:
    api.install_qualification()
    assets = dict(api.bundle.assets)
    assets["requirements.lock"] += b"\n# substituted after qualification\n"
    api.replace_archive(qualification_zip(assets, api.bundle.receipt))
    with pytest.raises(trust_errors(promotion)):
        run_promotion(api)
    assert api.mutations == []
    assert api.store.read()["qualification"] is None


def test_publisher_verifier_is_genuinely_read_only_and_reads_every_asset(
    promotion: Any, api: FakePromotionAPI
) -> None:
    api.publish()
    api.responses[f"{ROOT}/branches/main"]["commit"]["sha"] = "9" * 40
    api.artifact_record()["expired"] = True
    result = promotion.verify_published_release(
        api, api.bundle.directory, repository=REPO, tag=api.bundle.tag,
        commit=api.bundle.commit, tree=api.bundle.tree,
    )
    assert result["id"] == 7
    assert result["immutable"] is True
    assert api.mutations == []
    assert api.store.snapshots == []
    assert sorted(event[1] for event in api.events if event[0] == "download_asset") == sorted(
        api.bundle.assets
    )
    assert not [event for event in api.events if event[0] in {"get", "download_artifact"}]


def test_publisher_verifier_rejects_corrupt_bytes_despite_matching_metadata(
    promotion: Any, api: FakePromotionAPI
) -> None:
    api.publish()
    api.asset_download_override["requirements.lock"] = b"substituted bytes"
    with pytest.raises(promotion.ReleasePublicationError, match="bytes differ"):
        promotion.verify_published_release(
            api, api.bundle.directory, repository=REPO, tag=api.bundle.tag,
            commit=api.bundle.commit, tree=api.bundle.tree,
        )
    assert api.mutations == []
    assert api.store.snapshots == []


@pytest.mark.parametrize("case", ["draft", "partial", "digest", "foreign-commit"])
def test_publisher_verifier_rejects_invalid_release_without_mutations(
    promotion: Any, api: FakePromotionAPI, case: str
) -> None:
    api.publish("draft" if case == "draft" else "immutable")
    if case == "partial":
        api.stored_assets.pop("requirements.lock")
    elif case == "digest":
        api.asset_overrides["requirements.lock"] = {"digest": "sha256:" + "0" * 64}
    elif case == "foreign-commit":
        api.release["target_commitish"] = "9" * 40
    with pytest.raises(promotion.ReleasePublicationError):
        promotion.verify_published_release(
            api, api.bundle.directory, repository=REPO, tag=api.bundle.tag,
            commit=api.bundle.commit, tree=api.bundle.tree,
        )
    assert_read_only(api)


@pytest.mark.parametrize("command", ["plan", "status", "promote"])
def test_native_windows_cli_refuses_before_authentication(
    promotion: Any, api: FakePromotionAPI, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], command: str
) -> None:
    monkeypatch.setattr(promotion, "os", SimpleNamespace(name="nt"))

    def forbidden_auth(*args: Any, **kwargs: Any) -> None:
        pytest.fail("native Windows must be refused before credential acquisition")

    monkeypatch.setattr(promotion.PromotionAPI, "from_gh", forbidden_auth)
    arguments = [command]
    if command != "status":
        arguments += ["--tag", api.bundle.tag, "--commit", api.bundle.commit]
    if command != "plan":
        arguments += ["--receipt", str(api.store.path)]
    if command == "promote":
        arguments += ["--approval", promotion.APPROVAL_PHRASE]
    assert promotion.main(arguments) == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "native Windows is unsupported" in json.loads(captured.err)["error"]
    assert api.store.content is None


@pytest.mark.parametrize("option,value", [
    ("--timeout-seconds", "59"), ("--timeout-seconds", "3601"),
    ("--poll-seconds", "1"), ("--poll-seconds", "61"),
    ("--approval", "incorrect"),
])
def test_cli_invalid_bounds_and_approval_fail_before_authentication(
    promotion: Any, api: FakePromotionAPI, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str], option: str, value: str
) -> None:
    monkeypatch.setattr(promotion, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(promotion, "sys", SimpleNamespace(platform="linux", stderr=sys.stderr))

    def forbidden_auth(*args: Any, **kwargs: Any) -> None:
        pytest.fail("invalid arguments must be rejected before credential acquisition")

    monkeypatch.setattr(promotion.PromotionAPI, "from_gh", forbidden_auth)
    arguments = [
        "promote", "--tag", api.bundle.tag, "--commit", api.bundle.commit,
        "--receipt", str(api.store.path), "--approval", promotion.APPROVAL_PHRASE,
        option, value,
    ]
    assert promotion.main(arguments) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert isinstance(json.loads(captured.err)["error"], str)
    assert api.store.content is None


def test_cli_trust_validation_error_does_not_echo_untrusted_secret(
    promotion: Any, api: FakePromotionAPI, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str]
) -> None:
    from contextlib import nullcontext
    secret = "ghp_local_test_secret_never_output"
    monkeypatch.setattr(promotion, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(promotion, "sys", SimpleNamespace(platform="linux", stderr=sys.stderr))
    monkeypatch.setattr(promotion, "deadline", lambda seconds: nullcontext())

    def authentication_failure(*args: Any, **kwargs: Any) -> None:
        raise promotion.ReleasePublicationError("Authorization: Bearer " + secret + "\x1b[2J")

    monkeypatch.setattr(promotion.PromotionAPI, "from_gh", authentication_failure)
    assert promotion.main([
        "plan", "--tag", api.bundle.tag, "--commit", api.bundle.commit
    ]) == 6
    captured = capsys.readouterr()
    assert captured.out == ""
    assert secret not in captured.err
    assert "Authorization" not in captured.err
    assert "\x1b" not in captured.err
    assert json.loads(captured.err) == {
        "error": "release trust validation failed; inspect read-only state"
    }
