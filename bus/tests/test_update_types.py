from dataclasses import FrozenInstanceError, replace
import json

import pytest

from strugglebus import update_types

from strugglebus import __version__
from strugglebus.update_types import (
    ERROR_CODES, ERROR_MESSAGES, LEGACY_UPDATE_REPOSITORY, MAX_TIMESTAMP,
    REQUEST_BYTES, RESPONSE_BYTES,
    UPDATE_REPOSITORY, UPDATE_SOURCE_REPOSITORY, UpdateAsset, UpdateCandidate,
    UpdateDiscovery, UpdateError, UpdateLimits, UpdateObservation, UpdateOperation,
    UpdatePrepared, UpdateRequest, UpdateStatus, asset_from_json, asset_to_json,
    candidate_from_json, candidate_to_json, decode_frame, decode_json,
    discovery_from_json, discovery_to_json, encode_frame, encode_json, limits_from_json,
    limits_to_json, observation_from_json, observation_to_json, operation_from_json,
    operation_to_json, prepared_from_json, prepared_to_json, request_from_json,
    request_to_json, response_from_json, response_to_json, status_from_json, status_to_json,
)


def candidate(version="2.0.0", policy="test-policy"):
    return UpdateCandidate(
        version, 10, "v" + version, "a" * 40, "b" * 40, "c" * 40, policy,
        tuple(UpdateAsset(index, f"asset-{index}", 1, "d" * 64, "application/octet-stream")
              for index in range(1, 6)),
    )


def discovery():
    return UpdateDiscovery(candidate(), True, 1, None, None)


def observation():
    return UpdateObservation("2" * 32, 100, 1000, "1.0.0", "release-one", discovery())


def operation(phase="succeeded", action="check", identity="1" * 32):
    terminal = phase in {"succeeded", "failed", "interrupted"}
    error = "interrupted" if phase == "interrupted" else ("timeout" if phase == "failed" else None)
    return UpdateOperation(identity, action, "operator", phase, 100, 101 if terminal else None, error)


def status():
    return UpdateStatus("observed", __version__, "test-policy", operation(), observation(), None, True)


@pytest.mark.parametrize("instance,encoder,decoder", [
    (candidate().assets[0], asset_to_json, asset_from_json),
    (candidate(), candidate_to_json, candidate_from_json),
    (discovery(), discovery_to_json, discovery_from_json),
    (operation(), operation_to_json, operation_from_json),
    (observation(), observation_to_json, observation_from_json),
    (UpdatePrepared(candidate(), 110, "3" * 32), prepared_to_json, prepared_from_json),
    (status(), status_to_json, status_from_json),
])
def test_strict_round_trip_and_frozen(instance, encoder, decoder):
    raw = encode_json(encoder(instance), RESPONSE_BYTES)
    assert decoder(decode_json(raw, RESPONSE_BYTES)) == instance
    with pytest.raises(FrozenInstanceError):
        instance.untrusted = "change"
    extra = encoder(instance) | {"unexpected": True}
    with pytest.raises(UpdateError):
        decoder(extra)
    missing = encoder(instance)
    missing.pop(next(iter(missing)))
    with pytest.raises(UpdateError):
        decoder(missing)


def test_digest_binds_every_candidate_and_asset_field():
    value = candidate()
    changes = dict(version="2.0.1", release_id=11, tag="v2.0.1", tag_object_sha="e" * 40,
                   commit="e" * 40, tree="e" * 40, policy_id="other")
    for key, changed in changes.items():
        kwargs = {key: changed}
        if key in {"version", "tag"}:
            kwargs.update(version="2.0.1", tag="v2.0.1")
        assert replace(value, **kwargs).digest != value.digest
    for key, changed in dict(asset_id=42, name="other", size_bytes=2, sha256="e" * 64,
                             media_type="text/plain").items():
        asset = replace(value.assets[0], **{key: changed})
        assert replace(value, assets=(asset,) + value.assets[1:]).digest != value.digest
    assert len(value.digest) == 64
    assert value.legacy_private_repository_digest != value.digest
    assert len(value.legacy_private_repository_digest) == 64


def test_releases_come_from_the_projects_repository_under_a_tag_prefix_of_their_own():
    assert UPDATE_REPOSITORY == "u64a/strugglebus"
    assert UPDATE_SOURCE_REPOSITORY == "u64a/strugglebus"
    assert update_types.RELEASE_TAG_PREFIX == "bus/"
    # The digest older applications confirmed is still worked out from where they were built.
    assert LEGACY_UPDATE_REPOSITORY == "NZCypher819/strugglebus"


def test_an_updater_configuration_may_name_the_present_place_or_the_former_one():
    names = update_types.names_the_release_source
    assert names("u64a/strugglebus", "u64a/strugglebus")
    # Written before the move: still accepted, so the file need not change at the same moment.
    assert names("NZCypher819/strugglebus-releases", "NZCypher819/strugglebus")
    assert not names("u64a/strugglebus", "NZCypher819/strugglebus")
    assert not names("NZCypher819/strugglebus-releases", "u64a/strugglebus")
    assert not names("someone/else", "someone/else")


@pytest.mark.parametrize("data", [
    b'{"a":1,"a":2}', b'{"a":{"b":1,"b":2}}', b'NaN', b'Infinity', b'-Infinity',
    b'1.5', b'{"a":"\\u0000"}', b'{"a":"\\ud800"}', b'\xff', b'[] []',
    b'[' * 18 + b'0' + b']' * 18,
])
def test_json_rejects_malformed_control_duplicate_and_float(data):
    with pytest.raises(UpdateError, match="invalid_request"):
        decode_json(data, RESPONSE_BYTES)


@pytest.mark.parametrize("data", [b'{}\n{}\n', b'{}', b'{}\n ', b'\n{}\n', b'{}\r\n', b' ' * REQUEST_BYTES + b'\n'])
def test_wire_exact_one_lf_frame(data):
    with pytest.raises(UpdateError):
        decode_frame(data, REQUEST_BYTES)


def test_wire_roundtrip_and_size_boundary():
    raw = encode_frame({"a": "b"}, REQUEST_BYTES)
    assert decode_frame(raw, REQUEST_BYTES) == {"a": "b"}
    with pytest.raises(UpdateError):
        encode_frame({"a": "x" * REQUEST_BYTES}, REQUEST_BYTES)
    with pytest.raises(UpdateError):
        decode_json(b"{} ", 2)
    with pytest.raises(UpdateError):
        encode_json(1.5, 100)


@pytest.mark.parametrize("field,value", [
    ("asset_id", True), ("asset_id", 0), ("asset_id", 2**63),
    ("name", "../escape"), ("name", "/escape"), ("name", "bad\\name"),
    ("name", "x" * 193), ("size_bytes", False), ("size_bytes", 0),
    ("size_bytes", 256 * 1024 * 1024 + 1), ("sha256", "A" * 64),
    ("sha256", "a" * 63), ("media_type", "text/plain\nsecret"),
    ("media_type", "\ud800"),
])
def test_asset_bounds(field, value):
    with pytest.raises(UpdateError):
        asset_from_json(asset_to_json(candidate().assets[0]) | {field: value})


@pytest.mark.parametrize("field,value", [
    ("version", "01.2.3"), ("version", "1.2.3-rc1"), ("version", "1.2"),
    ("release_id", True), ("tag", "other"), ("tag_object_sha", "x" * 40),
    ("commit", "a" * 64), ("tree", None), ("policy_id", "bad value"),
    ("assets", []), ("assets", None),
])
def test_candidate_bounds(field, value):
    with pytest.raises(UpdateError):
        candidate_from_json(candidate_to_json(candidate()) | {field: value})


def test_assets_unique_and_aggregate_bounded():
    value = candidate()
    with pytest.raises(UpdateError):
        replace(value, assets=(value.assets[0],) * 5)
    with pytest.raises(UpdateError):
        replace(value, assets=tuple(replace(a, size_bytes=64 * 1024 * 1024) for a in value.assets))
    with pytest.raises(UpdateError):
        replace(value, assets=list(value.assets))


@pytest.mark.parametrize("change", [
    {"complete": 1}, {"inspected": True}, {"inspected": 41}, {"blocked_version": "2.0.0"},
    {"blocked_reason": "raw signed secret"}, {"blocked_version": "2.0.0", "blocked_reason": "verification_failed"},
])
def test_discovery_bounds(change):
    with pytest.raises(UpdateError):
        discovery_from_json(discovery_to_json(discovery()) | change)


def test_blocked_and_empty_discovery_are_explicit():
    for value in [UpdateDiscovery(None, False, 40, None, None),
                  UpdateDiscovery(None, True, 1, "2.0.0", "verification_failed")]:
        assert discovery_from_json(discovery_to_json(value)) == value


@pytest.mark.parametrize("change", [
    {"operation_id": "A" * 32}, {"actor_id": "x" * 129}, {"actor_id": "x\nsecret"},
    {"action": "install"}, {"phase": "queued"}, {"started_at": -1},
    {"started_at": MAX_TIMESTAMP + 1}, {"finished_at": True}, {"finished_at": 99},
    {"phase": "running"}, {"error": "timeout"}, {"error": "upstream private body"},
])
def test_operation_bounds(change):
    with pytest.raises(UpdateError):
        operation_from_json(operation_to_json(operation()) | change)


@pytest.mark.parametrize("change", [
    {"observation_id": "abc"}, {"checked_at": True}, {"expires_at": 100},
    {"expires_at": 1001}, {"application_version": "latest"}, {"application_release_id": "\n"},
])
def test_observation_bounds(change):
    with pytest.raises(UpdateError):
        observation_from_json(observation_to_json(observation()) | change)


def test_status_policy_and_types_are_strict():
    for change in [{"history_available": 1}, {"state": []}, {"policy_id": "other"},
                   {"worker_version": "latest"}]:
        with pytest.raises(UpdateError):
            status_from_json(status_to_json(status()) | change)
    prepared = UpdatePrepared(candidate(), 101, "3" * 32)
    value = replace(status(), prepared=prepared)
    assert status_from_json(status_to_json(value)) == value
    assert UpdateError("signed-url?secret").code == "internal_error"


@pytest.mark.parametrize("action", ["status", "check", "prepare"])
def test_exact_requests(action):
    value = UpdateRequest(action, None if action == "status" else "1" * 32)
    if action != "status":
        value = replace(value, actor_id="operator", application_version="1.0.0")
    if action == "prepare":
        value = replace(value, observation_id="2" * 32, candidate_digest="3" * 64)
    raw = request_to_json(value)
    assert request_from_json(raw) == value
    for change in [{"version": True}, {"password": "not allowed"}, {"operation_id": "bad"},
                   {"action": []}, {"action": "install"}]:
        with pytest.raises(UpdateError):
            request_from_json(raw | change)
    assert request_from_json(request_to_json(UpdateRequest("status", "1" * 32))).operation_id == "1" * 32


@pytest.mark.parametrize("error", sorted(ERROR_CODES))
def test_response_static_errors(error):
    value = response_to_json(error=error)
    with pytest.raises(UpdateError) as raised:
        response_from_json(value)
    assert raised.value.code == error


def test_response_success_and_invalid_pairings():
    assert response_from_json(response_to_json(status())) == status()
    for value in [
        {"version": True, "ok": True, "error": None, "status": status_to_json(status())},
        {"version": 1, "ok": True, "error": "busy", "status": status_to_json(status())},
        {"version": 1, "ok": False, "error": None, "status": None},
        {"version": 1, "ok": True, "error": None, "status": None},
    ]:
        with pytest.raises(UpdateError):
            response_from_json(value)
    for args in [{}, {"status": status(), "error": "busy"}]:
        with pytest.raises(UpdateError):
            response_to_json(**args)


def test_limits_only_narrow_reviewed_defaults():
    defaults = UpdateLimits()
    assert limits_from_json({}) == defaults
    assert limits_from_json(limits_to_json(defaults)) == defaults
    for field, value in limits_to_json(defaults).items():
        with pytest.raises(UpdateError):
            limits_from_json({field: False})
        invalid = value - 1 if field in {"reserve_bytes", "check_cooldown"} else value + 1
        with pytest.raises(UpdateError):
            limits_from_json({field: invalid})
    for value in [[], {"unchecked_quota": True}, {"connections": 0}]:
        with pytest.raises(UpdateError):
            limits_from_json(value)
    assert limits_from_json({"connections": 1}).connections == 1
    assert json.loads(encode_json(limits_to_json(defaults), RESPONSE_BYTES))["receipt_count"] == 16


@pytest.mark.parametrize("field,minimum", [
    ("check_cooldown", 60), ("reserve_bytes", 256 * 1024 * 1024),
])
def test_safety_floors_reject_one_and_just_below_minimum(field, minimum):
    for lowered in (1, minimum - 1):
        with pytest.raises(UpdateError, match="invalid_request"):
            UpdateLimits(**{field: lowered})
        with pytest.raises(UpdateError, match="invalid_request"):
            limits_from_json({field: lowered})
    assert limits_from_json({field: minimum}) == UpdateLimits()


def test_direct_typed_construction_rejects_wrong_nested_objects():
    actions = [
        lambda: replace(candidate(), assets=(object(),) + candidate().assets[1:]),
        lambda: replace(observation(), discovery=None),
        lambda: UpdatePrepared(None, 100, "3" * 32),
        lambda: replace(status(), operation=object()),
        lambda: replace(status(), state="installing"),
    ]
    for action in actions:
        with pytest.raises(UpdateError, match="invalid_request"):
            action()


def test_unknown_outcome_remains_explicit_and_never_success_shaped():
    error = UpdateError("unknown_outcome")
    assert error.code == str(error) == "unknown_outcome"
    assert "may have started or completed" in error.message
    assert "same operation ID" in error.message
    response = response_to_json(error=error.code)
    assert response["ok"] is False and response["status"] is None
    with pytest.raises(UpdateError, match="unknown_outcome"):
        response_from_json(response)


def test_human_error_messages_are_static_complete_and_not_wire_metadata():
    assert set(ERROR_MESSAGES) == ERROR_CODES
    for code in ERROR_CODES:
        error = UpdateError(code)
        assert error.message == ERROR_MESSAGES[code]
        assert error.message and str(error) == code
        assert response_to_json(error=code)["error"] == code
    private = "private credential signed URL"
    error = UpdateError(private)
    assert private not in str(error) and private not in error.message
    assert error.message == ERROR_MESSAGES["internal_error"]
    with pytest.raises(TypeError):
        ERROR_MESSAGES["unknown_outcome"] = private
