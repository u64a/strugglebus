from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from strugglebus.update_state import Journal, UpdateState, journal_from_json, journal_to_json
from strugglebus.update_types import UpdateDiscovery, UpdateError, UpdateLimits, UpdateRequest
from test_update_types import candidate, discovery


class MemoryStorage:
    def __init__(self):
        self.value = journal_to_json(Journal("test-policy"))
        self.saved = []
        self.slots = set()
        self.retired = []
        self.fail_save = False
        self.fail_cleanup = False
        self.fail_create = False
        self.fail_verify = False

    def load(self):
        return deepcopy(self.value)

    def save(self, value):
        if self.fail_save:
            raise OSError("private disk details")
        self.value = deepcopy(value)
        self.saved.append(deepcopy(value))

    def slot_path(self, identity):
        return Path("synthetic-cache") / ("operation-" + identity)

    def create_slot(self, identity):
        if self.fail_create:
            raise UpdateError("storage_full")
        assert identity not in self.slots
        self.slots.add(identity)
        return self.slot_path(identity)

    def retire_slot(self, identity):
        if self.fail_cleanup:
            raise OSError("private disk details")
        self.retired.append(identity)
        self.slots.discard(identity)

    def validate_slot(self, identity, candidate):
        if self.fail_verify or identity not in self.slots:
            raise UpdateError("verification_failed")

    def validate_inventory(self, identities):
        if self.slots - set(identities):
            raise UpdateError("state_corrupt")


def check_request(identity="1" * 32, application_version="1.0.0"):
    return UpdateRequest("check", identity, "operator", application_version, "release-one")


def make_state(limits=None):
    storage = MemoryStorage()
    return UpdateState(storage, "test-policy", limits or UpdateLimits()), storage


def checked(state, identity="1" * 32, now=100, application_version="1.0.0"):
    state.accept(check_request(identity, application_version), now=now)
    state.start()
    state.finish_check(discovery(), now=now + 1)
    observed = state.journal.observation
    return UpdateRequest("prepare", "3" * 32, "operator", application_version, "release-one",
                         observed.observation_id, candidate().digest)


def prepared(state, now=100):
    request = checked(state, now=now)
    state.accept(request, now=now + 2)
    state.start()
    state.finish_prepare(now=now + 3)
    return request


def test_empty_history_and_durable_acceptance_before_work():
    state, storage = make_state()
    assert state.status().state == "idle"
    assert state.status("1" * 32).history_available is False
    assert state.accept(check_request(), now=100)
    assert storage.saved[-1]["current"]["operation"]["phase"] == "accepted"
    assert state.status().state == "checking"
    assert state.status().operation.actor_id == "operator"
    assert state.start() is None
    assert storage.saved[-1]["current"]["operation"]["phase"] == "running"
    state.finish_check(discovery(), now=101)
    assert state.status().state == "observed"
    assert state.status().observation.expires_at == 1001
    assert not state.accept(check_request(), now=102)


def test_replay_conflict_busy_and_cooldown():
    state, _ = make_state()
    request = check_request()
    state.accept(request, now=100)
    assert not state.accept(request, now=100)
    with pytest.raises(UpdateError, match="conflict"):
        state.accept(replace(request, actor_id="other"), now=100)
    with pytest.raises(UpdateError, match="busy"):
        state.accept(check_request("4" * 32), now=100)
    state.fail("timeout", now=101)
    with pytest.raises(UpdateError, match="cooldown"):
        state.accept(check_request("4" * 32), now=159)
    assert state.accept(check_request("4" * 32), now=160)


@pytest.mark.parametrize("change,now,error", [
    ({"observation_id": "4" * 32}, 102, "observation_mismatch"),
    ({"candidate_digest": "4" * 64}, 102, "observation_mismatch"),
    ({"application_version": "1.0.1"}, 102, "observation_mismatch"),
    ({"application_release_id": None}, 102, "observation_mismatch"),
    ({}, 100, "observation_expired"), ({}, 1001, "observation_expired"),
])
def test_prepare_exact_observation_binding(change, now, error):
    state, storage = make_state()
    request = checked(state)
    with pytest.raises(UpdateError, match=error):
        state.accept(replace(request, **change), now=now)
    assert not storage.slots


def test_prepare_accepts_exact_legacy_repository_digest_only_before_public_transition():
    state, _ = make_state()
    request = checked(state, application_version="0.2.29")
    legacy = replace(request, candidate_digest=candidate().legacy_private_repository_digest)
    assert state.accept(legacy, now=102)

    state, _ = make_state()
    request = checked(state, application_version="0.2.29")
    with pytest.raises(UpdateError, match="observation_mismatch"):
        state.accept(replace(request, candidate_digest="4" * 64), now=102)

    state, _ = make_state()
    request = checked(state, application_version="0.2.31")
    legacy = replace(request, candidate_digest=candidate().legacy_private_repository_digest)
    with pytest.raises(UpdateError, match="observation_mismatch"):
        state.accept(legacy, now=102)


def test_prepare_publish_then_old_retirement_and_replay_snapshot():
    state, storage = make_state()
    first = prepared(state)
    assert state.status().state == "prepared"
    assert storage.slots == {first.operation_id}
    assert not state.accept(first, now=104)
    second = checked(state, identity="5" * 32, now=200)
    second = replace(second, operation_id="6" * 32)
    state.accept(second, now=202)
    state.start()
    assert storage.slots == {first.operation_id, second.operation_id}
    state.finish_prepare(now=203)
    publication = [entry for entry in storage.saved if entry["cleanup"] == first.operation_id]
    assert publication[-1]["prepared"]["operation_id"] == second.operation_id
    assert storage.slots == {second.operation_id}
    assert state.status(first.operation_id).observation.observation_id == first.observation_id
    assert state.status(first.operation_id).operation.phase == "succeeded"
    assert state.status(first.operation_id).prepared.operation_id == second.operation_id


def test_cleanup_failure_blocks_third_slot_and_survives_restart():
    state, storage = make_state()
    first = prepared(state)
    second = replace(checked(state, identity="5" * 32, now=200), operation_id="6" * 32)
    state.accept(second, now=202)
    state.start()
    storage.fail_cleanup = True
    state.finish_prepare(now=203)
    assert state.journal.cleanup == first.operation_id
    with pytest.raises(UpdateError, match="cleanup_pending"):
        state.accept(check_request("7" * 32), now=300)
    restarted = UpdateState(storage, "test-policy", UpdateLimits())
    restarted.reconcile(now=301)
    assert restarted.journal.cleanup == first.operation_id
    storage.fail_cleanup = False
    restarted.cleanup()
    assert restarted.journal.cleanup is None
    assert storage.slots == {second.operation_id}


@pytest.mark.parametrize("started", [False, True])
def test_restart_interrupts_intent_and_never_retries(started):
    state, storage = make_state()
    state.accept(check_request(), now=100)
    if started:
        state.start()
    restarted = UpdateState(storage, "test-policy", UpdateLimits())
    restarted.reconcile(now=102)
    receipt = restarted.status("1" * 32)
    assert receipt.state == "interrupted"
    assert receipt.operation.phase == "interrupted"
    assert receipt.operation.error == "interrupted"
    assert not restarted.accept(check_request(), now=104)


def test_failed_prepare_retains_old_good_preparation():
    state, storage = make_state()
    first = prepared(state)
    second = replace(checked(state, identity="5" * 32, now=200), operation_id="6" * 32)
    state.accept(second, now=202)
    state.start()
    state.fail("verification_failed", now=203)
    assert state.status().state == "failed"
    assert state.status().prepared.operation_id == first.operation_id
    assert storage.slots == {first.operation_id}


def test_restart_unfinished_prepare_cleans_only_owned_quarantine():
    state, storage = make_state()
    request = checked(state)
    state.accept(request, now=102)
    state.start()
    restarted = UpdateState(storage, "test-policy", UpdateLimits())
    restarted.reconcile(now=103)
    assert storage.retired == [request.operation_id]
    assert restarted.status().operation.error == "interrupted"


def test_unknown_corrupt_version_and_policy_are_fail_closed():
    state, storage = make_state()
    for replacement in [{}, storage.value | {"version": 2},
                        storage.value | {"version": True}, storage.value | {"extra": 1}]:
        with pytest.raises(UpdateError, match="state_corrupt"):
            journal_from_json(replacement, UpdateLimits())
    with pytest.raises(UpdateError, match="policy_mismatch"):
        UpdateState(storage, "other-policy", UpdateLimits())
    storage.fail_save = True
    with pytest.raises(UpdateError, match="state_corrupt"):
        state.accept(check_request(), now=100)
    with pytest.raises(UpdateError, match="state_corrupt"):
        state.status()
    assert not storage.saved


def test_new_verifier_adopts_quiescent_journal_and_retires_old_candidate():
    state, storage = make_state()
    request = prepared(state)
    adopted = UpdateState(storage, "next-policy", UpdateLimits(), adopt_policy=True)
    assert storage.value["policy_id"] == "next-policy"
    assert adopted.journal.prepared is None and adopted.journal.observation is None
    assert adopted.journal.receipts == ()
    assert adopted.journal.last_check_at == 100
    assert adopted.journal.cleanup == request.operation_id
    adopted.reconcile(now=200)
    assert storage.retired == [request.operation_id] and not storage.slots
    assert adopted.status().state == "idle"
    with pytest.raises(UpdateError, match="cooldown"):
        adopted.accept(check_request("5" * 32), now=150)
    with pytest.raises(UpdateError, match="policy_mismatch"):
        UpdateState(storage, "test-policy", UpdateLimits())


def test_new_verifier_refuses_to_adopt_an_active_or_unsettled_journal():
    state, storage = make_state()
    state.accept(check_request(), now=100)
    before = deepcopy(storage.value)
    with pytest.raises(UpdateError, match="policy_mismatch"):
        UpdateState(storage, "next-policy", UpdateLimits(), adopt_policy=True)
    assert storage.value == before
    state, storage = make_state()
    state.accept(check_request(), now=100)
    state.start()
    state.finish_check(discovery(), now=101)
    storage.value["cleanup"] = "6" * 32
    with pytest.raises(UpdateError, match="policy_mismatch"):
        UpdateState(storage, "next-policy", UpdateLimits(), adopt_policy=True)
    assert storage.value["policy_id"] == "test-policy"

def test_receipts_bounded_and_evicted_lookup_explicit():
    state, _ = make_state()
    for index in range(18):
        state.accept(check_request(f"{index:032x}"), now=100 + index * 60)
        state.fail("source_unavailable", now=101 + index * 60)
    assert len(state.journal.receipts) == 16
    assert not state.status("0" * 32).history_available
    assert state.status(f"{17:032x}").history_available
    assert journal_from_json(journal_to_json(state.journal), UpdateLimits()) == state.journal


def test_prepared_reconciliation_checks_bytes_and_never_repairs():
    state, storage = make_state()
    prepared(state)
    storage.fail_verify = True
    restarted = UpdateState(storage, "test-policy", UpdateLimits())
    with pytest.raises(UpdateError, match="verification_failed"):
        restarted.reconcile(now=200)
    assert len(storage.slots) == 1


def test_corrupt_journal_receipt_binding_and_slot_relationships():
    state, _ = make_state()
    request = checked(state)
    raw = journal_to_json(state.journal)
    invalid = deepcopy(raw)
    invalid["receipts"][0]["request"]["actor_id"] = "other"
    with pytest.raises(UpdateError, match="state_corrupt"):
        journal_from_json(invalid, UpdateLimits())
    invalid = deepcopy(raw)
    invalid["receipts"] *= 2
    with pytest.raises(UpdateError, match="state_corrupt"):
        journal_from_json(invalid, UpdateLimits())
    for changed in [{"quarantine": "4" * 32}, {"cleanup": "bad"}, {"receipts": None}]:
        with pytest.raises(UpdateError, match="state_corrupt"):
            journal_from_json(raw | changed, UpdateLimits())
    state.accept(request, now=102)
    raw = journal_to_json(state.journal)
    with pytest.raises(UpdateError, match="state_corrupt"):
        journal_from_json(raw | {"cleanup": "4" * 32}, UpdateLimits())


def test_receipt_and_current_terminal_phase_corruption_refused():
    state, _ = make_state()
    checked(state)
    raw = journal_to_json(state.journal)
    bad = deepcopy(raw)
    bad["receipts"][0]["operation"].update(phase="accepted", finished_at=None, error=None)
    with pytest.raises(UpdateError, match="state_corrupt"):
        journal_from_json(bad, UpdateLimits())
    bad = deepcopy(raw)
    bad["current"] = bad["receipts"].pop()
    with pytest.raises(UpdateError, match="state_corrupt"):
        journal_from_json(bad, UpdateLimits())


def test_slot_collision_and_wrong_pending_operation_refused():
    state, _ = make_state()
    prepared(state)
    raw = journal_to_json(state.journal)
    with pytest.raises(UpdateError, match="state_corrupt"):
        journal_from_json(raw | {"cleanup": state.journal.prepared.operation_id}, UpdateLimits())
    state, _ = make_state()
    request = checked(state)
    state.accept(request, now=102)
    raw = journal_to_json(state.journal)
    with pytest.raises(UpdateError, match="state_corrupt"):
        journal_from_json(raw | {"quarantine": "4" * 32}, UpdateLimits())


def test_no_candidate_policy_drift_and_narrow_artifact_limit_refused():
    state, _ = make_state()
    request = checked(state)
    original = state.journal
    empty = replace(original.observation, discovery=UpdateDiscovery(None, True, 1, None, None))
    state.journal = replace(original, observation=empty)
    with pytest.raises(UpdateError, match="no_candidate"):
        state.candidate_for(request, now=102)
    state.journal = replace(original, policy_id="other")
    with pytest.raises(UpdateError, match="policy_mismatch"):
        state.candidate_for(request, now=102)
    state.journal = original
    state.limits = UpdateLimits(candidate_bytes=4)
    with pytest.raises(UpdateError, match="storage_full"):
        state.candidate_for(request, now=102)


def test_wrong_completion_cannot_publish_unverified_success():
    state, _ = make_state()
    with pytest.raises(UpdateError, match="state_corrupt"):
        state.start()
    with pytest.raises(UpdateError, match="invalid_request"):
        state.accept(UpdateRequest("status"), now=100)
    state.accept(check_request(), now=100)
    for complete in [state.finish_prepare, state._publish_prepared]:
        with pytest.raises(UpdateError, match="state_corrupt"):
            complete(now=101)
    with pytest.raises(UpdateError, match="policy_mismatch"):
        state.finish_check(replace(discovery(), candidate=candidate(policy="other")), now=101)
    state.finish_check(discovery(), now=101)
    observed = state.journal.observation
    request = UpdateRequest("prepare", "3" * 32, "operator", "1.0.0", "release-one",
                            observed.observation_id, candidate().digest)
    state.accept(request, now=102)
    with pytest.raises(UpdateError, match="state_corrupt"):
        state.finish_check(discovery(), now=103)
    with pytest.raises(UpdateError, match="state_corrupt"):
        state._publish_prepared(now=103)


def test_lost_durable_acceptance_ack_reconciles_without_reexecution(monkeypatch):
    state, storage = make_state()
    save = storage.save
    def save_then_lose_ack(value):
        save(value)
        raise OSError("acknowledgement lost")
    monkeypatch.setattr(storage, "save", save_then_lose_ack)
    with pytest.raises(UpdateError, match="state_corrupt"):
        state.accept(check_request(), now=100)
    monkeypatch.setattr(storage, "save", save)
    restarted = UpdateState(storage, "test-policy", UpdateLimits())
    restarted.reconcile(now=101)
    assert restarted.status("1" * 32).operation.phase == "interrupted"
    assert not restarted.accept(check_request(), now=102)
    assert not storage.slots


def test_lost_prepared_publication_ack_preserves_verified_outcome(monkeypatch):
    state, storage = make_state()
    first = prepared(state)
    second = replace(checked(state, identity="5" * 32, now=200), operation_id="6" * 32)
    state.accept(second, now=202)
    state.start()
    save = storage.save
    def save_then_lose_ack(value):
        save(value)
        raise OSError("acknowledgement lost")
    monkeypatch.setattr(storage, "save", save_then_lose_ack)
    with pytest.raises(UpdateError, match="state_corrupt"):
        state.finish_prepare(now=203)
    assert storage.slots == {first.operation_id, second.operation_id}
    monkeypatch.setattr(storage, "save", save)
    restarted = UpdateState(storage, "test-policy", UpdateLimits())
    restarted.reconcile(now=204)
    assert restarted.status(second.operation_id).operation.phase == "succeeded"
    assert restarted.status().prepared.operation_id == second.operation_id
    assert storage.slots == {second.operation_id}
    assert not restarted.accept(second, now=205)


def test_new_explicit_check_after_interruption_still_obeys_cooldown():
    state, storage = make_state()
    state.accept(check_request(), now=100)
    state.start()
    restarted = UpdateState(storage, "test-policy", UpdateLimits())
    restarted.reconcile(now=101)
    replacement = check_request("4" * 32)
    with pytest.raises(UpdateError, match="cooldown"):
        restarted.accept(replacement, now=159)
    assert restarted.accept(replacement, now=160)
    assert restarted.status("1" * 32).operation.phase == "interrupted"
    assert restarted.status(replacement.operation_id).operation.phase == "accepted"


def test_interrupted_prepare_blocks_new_check_until_owned_cleanup_finishes():
    state, storage = make_state()
    request = checked(state)
    state.accept(request, now=102)
    state.start()
    storage.fail_cleanup = True
    restarted = UpdateState(storage, "test-policy", UpdateLimits())
    restarted.reconcile(now=103)
    assert restarted.status(request.operation_id).operation.phase == "interrupted"
    replacement = check_request("4" * 32)
    with pytest.raises(UpdateError, match="cleanup_pending"):
        restarted.accept(replacement, now=200)
    storage.fail_cleanup = False
    restarted.cleanup()
    assert restarted.accept(replacement, now=200)
