from __future__ import annotations

import copy
import json
import re

import pytest
from pydantic import ValidationError

from strugglebus.config import AppConfig
from strugglebus.integration import (
    MAX_GUIDE_RESPONSE_BYTES,
    TestRequestV1 as RequestContractV1,
    TestStatusV1 as StatusContractV1,
    build_integration_guide,
)


def test_guide_contract_examples_validate_and_response_is_bounded(
    app_config: AppConfig,
) -> None:
    guide = build_integration_guide(app_config)
    request = RequestContractV1.model_validate_json(
        json.dumps(guide.contracts.test_request_example)
    )
    status = StatusContractV1.model_validate_json(
        json.dumps(guide.contracts.test_status_example)
    )
    encoded = guide.model_dump_json().encode("utf-8")

    assert request.protocol_version == status.protocol_version == 1
    assert request.message_type == "test_request"
    assert status.state == "succeeded"
    assert len(encoded) <= MAX_GUIDE_RESPONSE_BYTES
    assert guide.contracts.test_request_schema["additionalProperties"] is False
    assert guide.contracts.test_status_schema["additionalProperties"] is False
    assert guide.contracts.test_request_schema["properties"]["files"]["maxItems"] == 256
    assert guide.contracts.test_status_schema["properties"]["artifacts"]["maxItems"] == 8
    assert guide.guide_version == "1.19.0"
    tools = {tool.name: tool for tool in guide.tools}
    assert tools["server_info"].mutates_state is False
    assert tools["read_replies"].mutates_state is False
    assert tools["get_effective_roe"].mutates_state is False
    assert tools["acknowledge_roe"].mutates_state is True
    assert tools["prove_credential"].mutates_state is True
    assert tools["retire_predecessor_credential"].mutates_state is True
    assert guide.limits.roe_enforcement_mode == "observe"
    assert "receipt, not agreement" in guide.onboarding_prompt
    assert "orientation first on every connection" in guide.onboarding_prompt
    assert "Persist each page before" in guide.onboarding_prompt
    assert "non-consuming reads" in guide.onboarding_prompt
    assert "supervised durable SSE client" in guide.onboarding_prompt
    assert "never substitute recurring model prompts" in guide.onboarding_prompt
    assert "abort on any mismatch" in guide.onboarding_prompt
    assert "when present" in tools["get_effective_roe"].usage
    assert "Persist every page" in tools["catch_up"].usage
    assert "recover catch-up history" in tools["read"].usage
    surfaces = next(section for section in guide.sections if section.id == "surfaces")
    surfaces_text = " ".join(surfaces.instructions)
    assert "Call server_info on connection" in surfaces_text
    assert "event: server_stopping" in surfaces_text
    # The two terminal events demand opposite responses, so the guide must not
    # let a reader treat a restart as a freeze or a freeze as a restart.
    assert "not a freeze and not an error" in surfaces_text
    assert "Last-Event-ID" in surfaces_text
    assert "orientation and a complete catch_up drain" in surfaces_text
    assert "application_version" in surfaces_text
    assert "release_id" in surfaces_text
    assert "integration_guide_version" in surfaces_text
    freeze = next(
        section for section in guide.sections if section.id == "emergency-access-freeze"
    )
    freeze_text = " ".join(freeze.instructions)
    assert "Do not retry" in freeze_text
    assert "local human operator" in freeze_text
    assert "coordination_protocol_version" in surfaces_text
    assert "not an authorization boundary" in surfaces_text
    assert "every board channel" in surfaces_text
    assert "authorized task scope locally" in surfaces_text
    onboarding = next(
        section for section in guide.sections if section.id == "onboarding"
    )
    onboarding_text = " ".join(onboarding.instructions)
    assert "Pin the expected stable agent ID and name" in onboarding_text
    assert "wrong process" in onboarding_text
    lifecycle = next(
        section for section in guide.sections if section.id == "credential-lifecycle"
    )
    lifecycle_text = " ".join(lifecycle.instructions)
    assert "exactly once" in lifecycle_text
    assert "zero-downtime overlap" in lifecycle_text
    assert "MCP intentionally provides no issuance" in lifecycle_text
    coordination = next(
        section for section in guide.sections if section.id == "coordination"
    )
    coordination_text = " ".join(coordination.instructions)
    assert "Deduplicate by global seq" in coordination_text
    assert "two-hour replay overlap" in coordination_text
    assert "catch_up(start_drain=true)" in coordination_text
    assert "empty" in coordination_text
    assert "complete=true" in coordination_text
    assert "cannot guarantee progress" in coordination_text
    assert "Catch-Up-Continuation" in coordination_text
    assert "Deliberate mention-only use is valid" in onboarding_text
    assert tools["list_subscriptions"].mutates_state is False
    assert "catch_up(start_drain=true)" in guide.onboarding_prompt
    assert "only direct replies" in coordination_text
    assert "strugglebus-improvements" in coordination_text
    assert "must contain no secrets" in coordination_text
    assert "do not authorize implementation" in coordination_text
    assert "operator should post an announce" in coordination_text
    assert "never posts messages automatically" in coordination_text
    monitoring = next(
        section for section in guide.sections if section.id == "monitoring"
    )
    monitoring_text = " ".join(monitoring.instructions)
    assert "Separate five stages" in monitoring_text
    assert "owner-managed supervisor" in monitoring_text
    assert "healthy collector proves transport only" in monitoring_text
    assert "Terminal control events" in monitoring_text
    assert "Last-Event-ID" in monitoring_text
    assert "session-attached blocking waiter" in monitoring_text
    assert "one bounded scheduled prompt" in monitoring_text
    assert "never polls Strugglebus" in monitoring_text
    assert "correlated, model-authored response" in monitoring_text
    assert "receiving or queueing is not acceptance" in monitoring_text
    assert "agent_access_frozen" in monitoring_text
    definitions = guide.contracts.test_request_schema["$defs"]
    file_pattern = definitions["ReferencedFile"]["properties"]["path"]["pattern"]
    entrypoint_pattern = guide.contracts.test_request_schema["properties"]["entrypoint"][
        "pattern"
    ]
    assert re.fullmatch(file_pattern, ".github/workflows/ci.yml")
    assert re.fullmatch(entrypoint_pattern, "tests/integration/test_contract.py")
    assert re.fullmatch(file_pattern, "../secret") is None
    assert re.fullmatch(entrypoint_pattern, "tests/../secret") is None
    repository_pattern = guide.contracts.test_request_schema["properties"][
        "repository"
    ]["pattern"]
    assert re.fullmatch(repository_pattern, "example-org/example-project")
    assert re.fullmatch(repository_pattern, "../secret") is None
    assert re.fullmatch(repository_pattern, "owner/..") is None


def test_guide_advertises_optional_post_retry_without_changing_protocol(
    app_config: AppConfig,
) -> None:
    guide = build_integration_guide(app_config)
    sections = [section for section in guide.sections if section.id == "post-retry-v1"]
    assert len(sections) == 1
    instructions = " ".join(sections[0].instructions)
    assert "request_id" in instructions
    assert "metadata.request_id" in instructions
    assert "REST" in instructions and "MCP" in instructions
    assert "post request_id conflicts with previously accepted input" in instructions
    assert guide.contracts.test_request_example["protocol_version"] == 1
    assert guide.contracts.test_status_example["protocol_version"] == 1


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.update(unexpected=True),
        lambda payload: payload.update(commit_sha="A" * 40),
        lambda payload: payload.update(repository="../secret"),
        lambda payload: payload.update(entrypoint="../outside"),
        lambda payload: payload.update(files=payload["files"] * 257),
        lambda payload: payload.update(safety_assertions=[]),
        lambda payload: payload.update(timeout_seconds=86_401),
    ],
)
def test_request_contract_rejects_unsafe_or_unbounded_values(
    app_config: AppConfig,
    mutation,
) -> None:
    payload = copy.deepcopy(
        build_integration_guide(app_config).contracts.test_request_example
    )
    mutation(payload)

    with pytest.raises(ValidationError):
        RequestContractV1.model_validate_json(json.dumps(payload))


def test_status_contract_rejects_unknown_state_and_excess_artifacts(
    app_config: AppConfig,
) -> None:
    example = build_integration_guide(app_config).contracts.test_status_example
    bad_state = copy.deepcopy(example)
    bad_state["state"] = "complete"
    too_many_artifacts = copy.deepcopy(example)
    too_many_artifacts["artifacts"] *= 9

    with pytest.raises(ValidationError):
        StatusContractV1.model_validate_json(json.dumps(bad_state))
    with pytest.raises(ValidationError):
        StatusContractV1.model_validate_json(json.dumps(too_many_artifacts))


def test_contract_runtime_accepts_json_schema_integral_numbers(
    app_config: AppConfig,
) -> None:
    guide = build_integration_guide(app_config)
    request = copy.deepcopy(guide.contracts.test_request_example)
    request["protocol_version"] = 1.0
    request["timeout_seconds"] = 900.0
    request["output_policy"]["maximum_artifacts"] = 8.0
    status = copy.deepcopy(guide.contracts.test_status_example)
    status["protocol_version"] = 1.0
    status["artifacts"][0]["size_bytes"] = 2048.0

    validated_request = RequestContractV1.model_validate_json(json.dumps(request))
    validated_status = StatusContractV1.model_validate_json(json.dumps(status))

    assert validated_request.timeout_seconds == 900
    assert validated_request.output_policy.maximum_artifacts == 8
    assert validated_status.artifacts[0].size_bytes == 2048


def test_onboarding_prompt_uses_configured_public_endpoint(
    app_config: AppConfig,
) -> None:
    configured = AppConfig(
        database_path=app_config.database_path,
        data_dir=app_config.data_dir,
        runtime_dir=app_config.runtime_dir,
        backup_dir=app_config.backup_dir,
        admin_credential_path=None,
        admin_secret=b"test-only-admin-secret",
        public_base_url="https://coordination.example/",
    )

    guide = build_integration_guide(configured)

    assert guide.mcp_endpoint == "https://coordination.example/mcp"
    assert guide.rest_endpoint == "https://coordination.example/api/integration-guide"
    assert "https://coordination.example/mcp" in guide.onboarding_prompt
    assert "server_info" in guide.onboarding_prompt
    assert all(
        "https://bus.lan" not in instruction
        for section in guide.sections
        for instruction in section.instructions
    )
