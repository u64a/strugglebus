from __future__ import annotations

import json

from strugglebus.audit_feed import PREFIX, AuditFeed
from strugglebus.auth import AgentService

ALLOWED_KEYS = {
    "ts", "table", "event", "agent_id", "agent_name", "credential_id", "spn_id",
    "actor_type", "actor_id", "request_id", "identity_expires_at",
    "remote_address", "outcome", "status", "request_bytes",
    "host_prefix", "document", "serial", "signer_fingerprint",
}


def _feed(agent_service: AgentService) -> tuple[AuditFeed, list[str]]:
    lines: list[str] = []
    feed = AuditFeed(agent_service.store, emit=lines.append)
    feed.start_at_end()
    return feed, lines


def test_new_audit_rows_are_emitted_as_allow_listed_json(
    agent_service: AgentService,
) -> None:
    feed, lines = _feed(agent_service)
    created = agent_service.create_agent("feed-copilot")
    pending = agent_service.verify_credential(created.api_key)
    assert pending is not None

    feed.poll_once()

    assert lines
    records = []
    for line in lines:
        assert line.startswith(PREFIX)
        assert "sb1_" not in line and "sbsp1_" not in line
        assert "reason" not in line and "details" not in line and "secret" not in line
        record = json.loads(line[len(PREFIX):])
        assert set(record) == ALLOWED_KEYS
        records.append(record)
    issued = [r for r in records if r["table"] == "agent_credential_audit"]
    assert issued and issued[0]["event"]
    assert issued[0]["agent_id"] == created.agent.id
    assert issued[0]["agent_name"] == "feed-copilot"

    # A second pass emits nothing new.
    count = len(lines)
    feed.poll_once()
    assert len(lines) == count


def test_feed_does_not_replay_rows_that_existed_at_start(
    agent_service: AgentService,
) -> None:
    agent_service.create_agent("before-feed")
    feed, lines = _feed(agent_service)

    feed.poll_once()
    assert lines == []

    agent_service.create_agent("after-feed")
    feed.poll_once()
    assert lines
    assert all(json.loads(line[len(PREFIX):])["agent_name"] == "after-feed" for line in lines)


def test_worker_host_events_reach_the_feed_with_their_own_keys(
    agent_service: AgentService,
) -> None:
    from datetime import UTC, datetime

    from strugglebus.host_enrollment import HostEnrollmentService
    from strugglebus.models import LifecycleActor
    from strugglebus.site_documents import SiteDocumentService

    feed, lines = _feed(agent_service)
    actor = LifecycleActor(actor_type="local-admin", actor_id="local-service")
    store = agent_service.store
    issued = HostEnrollmentService(store).mint(
        host_prefix="host-office1", request_id="11111111-2222-4333-8444-555555555555",
        reason="new worker host", actor=actor,
    )
    signature = "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"
    SiteDocumentService(store, clock=lambda: datetime.now(UTC)).publish(
        name="fleet", serial=7, body=b"signed bytes", signature=signature,
        signer_fingerprint="SHA256:" + "A" * 43, reason="add a host", actor=actor,
    )

    feed.poll_once()

    records = [json.loads(line[len(PREFIX):]) for line in lines]
    assert all(set(record) == ALLOWED_KEYS for record in records)
    minted = next(r for r in records if r["table"] == "host_enrollments")
    assert (minted["event"], minted["host_prefix"], minted["request_id"]) == (
        "host-code-minted", "host-office1", "11111111-2222-4333-8444-555555555555",
    )
    assert (minted["actor_type"], minted["actor_id"], minted["document"]) == (
        "local-admin", "local-service", None,
    )
    stored = next(r for r in records if r["table"] == "site_document_audit")
    assert (stored["event"], stored["document"], stored["serial"], stored["signer_fingerprint"]) == (
        "site-document-stored", "fleet", 7, "SHA256:" + "A" * 43,
    )
    # Neither the code nor the signed bytes ever reach the feed.
    assert all(issued.code not in line and "signed bytes" not in line for line in lines)

    from strugglebus import audit_feed

    recent = audit_feed.recent(store, 10)
    assert {row["table"] for row in recent} >= {"host_enrollments", "site_document_audit"}
    assert all(set(row) == ALLOWED_KEYS - {"remote_address", "outcome", "status", "request_bytes"} for row in recent)
