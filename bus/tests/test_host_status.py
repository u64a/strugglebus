"""Worker hosts report what they are doing; the App's Hosts page reads it."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from strugglebus import host_status
from strugglebus.errors import AgentNotFoundError, CredentialConflictError, DomainValidationError
from strugglebus.migrations import LATEST_SCHEMA_VERSION
from strugglebus.models import LifecycleActor
from test_mobile_write_path import _auth, _grant, surface  # noqa: F401
from test_site_documents import _agent_key
from test_spn_onboarding import _actor, _create_spn, spn_client  # noqa: F401
from test_spn_worker_lifecycle import _worker

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts" / "host-status"
#: The contract files, pinned: one changed by accident fails here, not by quietly agreeing with itself.
PINNED = {
    "snapshot-v2.json": "dfdd19e0aa5ae9e4a02ce41eb192067c1df17030894f7beca9388eb352d55555",
    "snapshot-v2-device.json": "4ede2b330023e0179b2a62ebbf577d8dcacd8ef025f19ea354a7755faaee0e3a",
    "sample-v2.json": "f0377cc9142d2c9a2382d18ae9d9c5eaeb2d89a5815077964f45b238fa1e3ca3",
}
STATUS = "/api/hosts/status"
HOSTS = "/api/mobile/hosts/status"
ADMIN_HOSTS = "/api/mobile/admin/hosts/status"
HOST = "host-box1-host"
START = datetime(2026, 11, 27, 4, 0, 0, tzinfo=UTC)


def contract(name: str) -> dict:
    data = (CONTRACTS / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == PINNED[name], f"{name} changed: {hashlib.sha256(data).hexdigest()}"
    return json.loads(data)


def snapshot(**changed) -> dict:
    return {**contract("snapshot-v2.json"), **changed}


class Clock:
    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        return self.now

    def forward(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def agent_id(store, name: str) -> str:
    with sqlite3.connect(store.database_path) as connection:
        return connection.execute("SELECT id FROM agents WHERE name = ?", (name,)).fetchone()[0]


def mark(client, secret, grant, target: str, name: str, action: str = "mark", **changed):
    body = {
        "request_id": str(uuid.uuid4()), "action": action, "expected_name": name,
        "reason": "enrolled before host codes", "grant_secret": grant, **changed,
    }
    return client.post(f"/api/mobile/admin/agents/{target}/host", json=body, headers=_auth(secret))


@pytest.fixture
def hosts(surface):  # noqa: F811
    """A bus with one marked host, a clock the test moves, and the device's grant."""
    client, secret, agents, store = surface
    clock = Clock()
    client.app.state.host_status_service = host_status.HostStatusService(store, clock=clock)
    key = _agent_key(agents, HOST)
    grant = _grant(client, secret)
    target = agent_id(store, HOST)
    assert mark(client, secret, grant, target, HOST).status_code == 200
    return client, secret, grant, key, target, clock, store, agents


def report(client, key: str, body: object = None, **changed):
    payload = snapshot(**changed) if body is None else body
    data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return client.post(STATUS, content=data, headers={**_auth(key), "Content-Type": "application/json"})


# ---- the schema -------------------------------------------------------------------------------


def test_schema_twenty_five_adds_the_host_and_event_tables(surface) -> None:  # noqa: F811
    _, _, _, store = surface
    assert LATEST_SCHEMA_VERSION == 25
    with sqlite3.connect(store.database_path) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type = 'table'")}
        assert {"host_agents", "host_agent_audit", "host_status", "host_status_samples", "bus_events"} <= tables
        connection.execute(
            "INSERT INTO bus_events (event_id, received_at, source, level, type, subject, fields) "
            "VALUES (?, 'now', 'bus', 'info', 'started', '', '{}')", (str(uuid.uuid4()),),
        )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute("UPDATE bus_events SET level = 'error'")
        connection.execute("DELETE FROM bus_events")


# ---- the check of a snapshot ------------------------------------------------------------------


def test_the_contract_snapshot_is_accepted_and_its_filter_and_sample_match_the_contract() -> None:
    whole = contract("snapshot-v2.json")

    assert host_status.refusal(whole, HOST) is None
    assert host_status.for_device(whole) == contract("snapshot-v2-device.json")
    assert host_status.sample(whole, "2026-11-27T04:00:00Z") == contract("sample-v2.json")
    # The filter works on a copy.
    assert whole["account"] == "sbworker" and whole["bus"]["channel"] == "worker-hosts"


@pytest.mark.parametrize("change,reason", [
    ({"agent": "host-other-host"}, "wrong-agent"),
    ({"v": 1}, "bad-value:v"),
    ({"v": 2.0}, "bad-value:v"),
    ({"v": True}, "bad-value:v"),
    ({"state": "sleeping"}, "bad-value:state"),
    ({"host": "x" * 32}, "bad-value:host"),
    ({"serial": -1}, "bad-value:serial"),
    ({"serial": True}, "bad-value:serial"),
    ({"dedicated": 1}, "bad-value:dedicated"),
    ({"outbox": "0"}, "bad-value:outbox"),
    ({"warnings": ["x"] * 9}, "bad-value:warnings"),
    ({"warnings": [7]}, "bad-value:warnings"),
    ({"warnings": "isolation-weak"}, "bad-value:warnings"),
    ({"problem": {"code": "disk-low"}}, "missing-field:problem"),
    ({"problem": {"code": "disk-low", "text": "Low.", "path": "C:\\\\x"}}, "unknown-field:problem"),
    ({"update": "soon"}, "bad-value:update"),
    ({"task_id": "abc"}, "unknown-field"),
    ({"machine": {"cpu_pct": 1.0}}, "missing-field:machine"),
    ({"machine": {"cpu_pct": float("inf"), "ram_free_gb": 1, "disk_free_gb": 1, "commit_pct": 1}}, "bad-value:machine.cpu_pct"),
    ({"machine": {"cpu_pct": "37", "ram_free_gb": 1, "disk_free_gb": 1, "commit_pct": 1}}, "bad-value:machine.cpu_pct"),
    ({"bus": {"state": "ok", "channel": "c", "channel_state": "lost"}}, "bad-value:bus.channel_state"),
    ({"engines": [{"name": "ghcp"}]}, "missing-field:engines"),
    ({"workers": {"busy": 0, "max": 1, "claiming": 0, "running": [{"slot": "w", "engine": "e", "model": "m", "minutes": 1, "task": "t"}]}},
     "unknown-field:workers.running"),
])
def test_a_snapshot_that_does_not_fit_is_refused_with_the_place_and_never_its_text(change, reason) -> None:
    assert host_status.refusal(snapshot(**change), HOST) == reason


@pytest.mark.parametrize("value", [None, [], "text", 7])
def test_something_that_is_not_a_snapshot_is_refused(value) -> None:
    assert host_status.refusal(value, HOST) == "bad-snapshot"


def test_a_missing_top_level_field_is_refused() -> None:
    short = snapshot()
    del short["tasks"]
    assert host_status.refusal(short, HOST) == "missing-field"


@pytest.mark.parametrize("pwsh", ["7.5.4", None])
def test_a_field_added_later_is_accepted_with_or_without_it_and_checked_when_sent(hosts, pwsh) -> None:
    """A host and its bus are not updated at the same moment: neither order may break reporting."""
    client, secret, grant, key, *_ = hosts

    assert host_status.refusal(snapshot(), HOST) is None
    assert report(client, key, pwsh=pwsh).status_code == 201

    shown = client.get(HOSTS, headers=_auth(secret)).json()["hosts"][0]["snapshot"]
    assert shown["pwsh"] == pwsh
    assert host_status.refusal(snapshot(pwsh=7), HOST) == "bad-value:pwsh"
    assert host_status.refusal(snapshot(pwsh="x" * 33), HOST) == "bad-value:pwsh"


FINGERPRINT = "SHA256:" + "A" * 43
NEWER = {
    "signers": [{"fingerprint": FINGERPRINT, "key_type": "sk-ssh-ed25519@openssh.com", "namespaces": "strugglebus-fleet,strugglebus-host-command"}],
    "signers_total": 3,
    "sign_in": {"nonce": "n-1", "tool": "gh", "state": "code", "code": "AB12-CD34", "expires_at": "2026-11-28T05:00:00Z"},
    "sign_in_key": {"x25519": "B" * 43 + "=", "fingerprint": FINGERPRINT},
    "claude_token_since": "2026-11-28",
}


def test_the_newer_admin_only_fields_are_accepted_together_or_not_at_all_and_hidden_from_devices(hosts) -> None:
    """What a host trusts and how it is signed in: sent by newer hosts, never required, never shown without the grant."""
    client, secret, grant, key, *_ = hosts

    assert host_status.refusal(snapshot(), HOST) is None
    assert host_status.refusal(snapshot(**NEWER), HOST) is None
    assert report(client, key, **NEWER).status_code == 201

    shown = client.get(HOSTS, headers=_auth(secret)).json()["hosts"][0]["snapshot"]
    assert not set(NEWER) & set(shown)
    whole = client.post(ADMIN_HOSTS, json={"grant_secret": grant}, headers=_auth(secret)).json()["hosts"][0]["snapshot"]
    assert {name: whole[name] for name in NEWER} == NEWER


@pytest.mark.parametrize(
    ("changed", "reason"),
    [
        ({"signers": "none"}, "bad-value:signers"),
        ({"signers": [{"fingerprint": FINGERPRINT, "key_type": "ssh-ed25519"}]}, "missing-field:signers"),
        ({"signers": [{"fingerprint": "MD5:abc", "key_type": "ssh-ed25519", "namespaces": ""}]}, "bad-value:signers.fingerprint"),
        ({"signers": [{"fingerprint": FINGERPRINT, "key_type": "ssh-ed25519", "namespaces": "a b"}]}, "bad-value:signers.namespaces"),
        ({"signers": [{"fingerprint": FINGERPRINT, "key_type": "ssh-ed25519", "namespaces": "", "key": "AAAA"}]}, "unknown-field:signers"),
        ({"signers": [NEWER["signers"][0]] * 17}, "bad-value:signers"),
        ({"signers_total": -1}, "bad-value:signers_total"),
        ({"signers_total": 1001}, "bad-value:signers_total"),
        ({"sign_in": {"nonce": "n", "tool": "gh"}}, "missing-field:sign_in"),
        ({"sign_in": {"nonce": "n", "tool": "gh", "state": "waiting"}}, "bad-value:sign_in.state"),
        ({"sign_in": {"nonce": "n", "tool": "gh", "state": "code", "code": "a token, not a code"}}, "bad-value:sign_in.code"),
        ({"sign_in": {"nonce": "n", "tool": "gh", "state": "done", "token": "x"}}, "unknown-field:sign_in"),
        ({"sign_in_key": {"x25519": "short", "fingerprint": FINGERPRINT}}, "bad-value:sign_in_key.x25519"),
        ({"claude_token_since": "yesterday"}, "bad-value:claude_token_since"),
        ({"claude_token_since": "2026-11-28\n"}, "bad-value:claude_token_since"),
    ],
)
def test_a_newer_field_that_is_sent_is_checked_as_hard_as_any_other(changed, reason) -> None:
    assert host_status.refusal(snapshot(**changed), HOST) == reason


def test_a_failed_sign_in_may_say_why_and_one_with_no_code_carries_none() -> None:
    assert host_status.refusal(snapshot(sign_in={"nonce": "n", "tool": "claude", "state": "failed", "reason": None}), HOST) is None
    assert host_status.refusal(snapshot(sign_in={"nonce": "n", "tool": "claude", "state": "failed", "reason": "timed out"}), HOST) is None
    assert host_status.refusal(snapshot(sign_in={"nonce": "n", "tool": "gh", "state": "starting"}), HOST) is None


def test_fields_that_may_be_empty_are_accepted_empty() -> None:
    quiet = snapshot(
        update=None, last_command=None, problem=None, model=None, ghcp_ok=None, warnings=[],
        machine=dict.fromkeys(host_status.MACHINE), engines=[],
        fleet={"source": None, "serial": None, "coordinators": None, "state": None},
    )
    assert host_status.refusal(quiet, HOST) is None
    assert host_status.for_device({**quiet, "bus": None})["bus"] is None


# ---- a host reports ---------------------------------------------------------------------------


def test_a_marked_host_reports_and_the_bus_stamps_its_own_time(hosts) -> None:
    client, secret, grant, key, target, clock, *_ = hosts

    stored = report(client, key, started_at="1999-01-01T00:00:00Z")

    assert stored.status_code == 201, stored.text
    assert stored.json() == {"received_at": "2026-11-27T04:00:00Z"}
    clock.forward(30)
    listed = client.get(HOSTS, headers=_auth(secret)).json()
    assert listed["now"] == "2026-11-27T04:00:30Z"
    [host] = listed["hosts"]
    assert (host["agent_id"], host["agent"], host["received_at"]) == (target, HOST, "2026-11-27T04:00:00Z")
    assert host["snapshot"] == {**contract("snapshot-v2-device.json"), "started_at": "1999-01-01T00:00:00Z"}


def test_only_an_administrator_gets_the_account_the_warnings_and_the_channel(hosts) -> None:
    client, secret, grant, key, *_ = hosts
    report(client, key)

    device = client.get(HOSTS, headers=_auth(secret)).json()["hosts"][0]["snapshot"]
    admin = client.post(ADMIN_HOSTS, json={"grant_secret": grant}, headers=_auth(secret))

    assert admin.status_code == 200 and admin.headers["cache-control"] == "no-store"
    assert admin.json()["hosts"][0]["snapshot"] == contract("snapshot-v2.json")
    for hidden in ("account", "dedicated", "warnings"):
        assert hidden not in device
    assert device["bus"] == {"state": "ok"}
    assert client.post(ADMIN_HOSTS, json={"grant_secret": "wrong"}, headers=_auth(secret)).status_code == 401
    assert client.post(ADMIN_HOSTS, json={"grant_secret": grant}).status_code == 401
    assert client.get(HOSTS).status_code == 401


def test_an_agent_that_is_not_marked_may_not_report_whatever_its_name(hosts) -> None:
    client, *_, agents = hosts
    lookalike = _agent_key(agents, "host-fake-host")

    refused = report(client, lookalike, agent="host-fake-host")

    assert refused.status_code == 403 and refused.json() == {"detail": "not-a-host"}
    assert report(client, "sb1_not-a-credential").status_code == 401


def test_a_report_under_another_hosts_name_is_refused(hosts) -> None:
    client, secret, grant, key, *_ = hosts

    refused = report(client, key, agent="host-other-host")

    assert refused.status_code == 400 and refused.json() == {"detail": "wrong-agent"}
    assert client.get(HOSTS, headers=_auth(secret)).json()["hosts"][0]["snapshot"] is None


@pytest.mark.parametrize("body,status,detail", [
    (b"{not json", 400, "bad-json"),
    (b"[" * 100_0 + b"]" * 100_0, 400, "bad-snapshot"),
    (b"[]", 400, "bad-snapshot"),
    (b" " * (16 * 1024 + 1), 413, "too-large"),
])
def test_a_report_that_cannot_be_read_is_refused(hosts, body, status, detail) -> None:
    client, _, _, key, *_ = hosts

    refused = report(client, key, body)

    assert (refused.status_code, refused.json()) == (status, {"detail": detail})


def test_a_report_exactly_at_the_size_limit_is_read(hosts) -> None:
    client, _, _, key, *_ = hosts
    body = json.dumps(snapshot()).encode()

    assert report(client, key, body + b" " * (16 * 1024 - len(body))).status_code == 201


def test_a_host_may_report_once_every_ten_seconds(hosts) -> None:
    client, _, _, key, _, clock, *_ = hosts
    assert report(client, key).status_code == 201

    clock.forward(4)
    early = report(client, key)
    clock.forward(6)
    on_time = report(client, key)

    assert (early.status_code, early.json(), early.headers["retry-after"]) == (429, {"detail": "too-soon"}, "7")
    assert on_time.status_code == 201


def test_a_clock_set_back_does_not_shut_a_host_out_for_long(hosts) -> None:
    client, _, _, key, _, clock, *_ = hosts
    report(client, key)

    clock.forward(-3600)
    refused = report(client, key)

    assert refused.status_code == 429 and refused.headers["retry-after"] == "10"


def test_storage_trouble_is_unavailable(hosts, monkeypatch) -> None:
    from strugglebus.errors import StorageError

    client, secret, _, key, target, *_ = hosts

    def broken(*args, **kwargs):
        raise StorageError("disk")

    service = client.app.state.host_status_service
    monkeypatch.setattr(service._store, "record_host_status", broken)
    monkeypatch.setattr(service._store, "host_statuses", broken)
    monkeypatch.setattr(service._store, "host_status_samples", broken)

    assert report(client, key).status_code == 503
    assert client.get(HOSTS, headers=_auth(secret)).status_code == 503
    assert client.get(f"/api/mobile/hosts/{target}/status/history", headers=_auth(secret)).status_code == 503


# ---- history ----------------------------------------------------------------------------------


def history(client, secret, target, **query):
    return client.get(f"/api/mobile/hosts/{target}/status/history", params=query, headers=_auth(secret))


def test_history_is_a_sample_of_each_report_oldest_first(hosts) -> None:
    client, secret, _, key, target, clock, *_ = hosts
    for busy in (1, 2, 3):
        workers = {**snapshot()["workers"], "busy": busy}
        assert report(client, key, workers=workers).status_code == 201
        clock.forward(60)

    answer = history(client, secret, target).json()

    assert answer["agent_id"] == target and answer["now"] == "2026-11-27T04:03:00Z"
    assert [(s["received_at"], s["workers"]["busy"]) for s in answer["samples"]] == [
        ("2026-11-27T04:00:00Z", 1), ("2026-11-27T04:01:00Z", 2), ("2026-11-27T04:02:00Z", 3),
    ]
    assert answer["samples"][1] == {**contract("sample-v2.json"), "received_at": "2026-11-27T04:01:00Z"}
    later = history(client, secret, target, since="2026-11-27T04:01:30Z").json()
    assert [s["workers"]["busy"] for s in later["samples"]] == [3]


def test_history_keeps_twelve_hours_and_no_more(hosts) -> None:
    client, secret, _, key, target, clock, *_ = hosts
    report(client, key)
    clock.forward(11 * 3600)
    report(client, key)
    clock.forward(3600 + 1)
    report(client, key)

    kept = [s["received_at"] for s in history(client, secret, target, since="2020-01-01T00:00:00Z").json()["samples"]]

    assert kept == ["2026-11-27T15:00:00Z", "2026-11-27T16:00:01Z"]


def test_history_is_only_for_a_marked_host_and_needs_a_time_zone(hosts) -> None:
    client, secret, _, _, target, *_, agents = hosts
    _agent_key(agents, "plain-agent")
    plain = agent_id(hosts[6], "plain-agent")

    assert history(client, secret, plain).status_code == 404
    assert history(client, secret, str(uuid.uuid4())).status_code == 404
    assert history(client, secret, target, since="2026-11-27T04:00:00").status_code == 422
    assert client.get(f"/api/mobile/hosts/{target}/status/history").status_code == 401


def test_samples_of_a_host_that_stopped_reporting_are_removed_by_the_sweep(hosts) -> None:
    client, secret, _, key, target, clock, store, _ = hosts
    report(client, key)
    clock.forward(60)
    report(client, key)

    assert store.remove_expired_host_status_samples(now=clock.now, keep=host_status.HISTORY, batch_size=10) == 0
    clock.forward(12 * 3600)
    assert store.remove_expired_host_status_samples(now=clock.now, keep=host_status.HISTORY, batch_size=1) == 1
    assert store.remove_expired_host_status_samples(now=clock.now, keep=host_status.HISTORY, batch_size=10) == 0
    assert len(history(client, secret, target).json()["samples"]) == 1


# ---- the mark ---------------------------------------------------------------------------------


def test_a_hosts_own_enrolment_marks_its_host_agent_and_not_its_workers(spn_client) -> None:  # noqa: F811
    store = spn_client.app.state.agent_service.store
    enrolment = spn_client.app.state.host_enrollment_service
    issued = enrolment.mint(
        host_prefix="host-office1", request_id=str(uuid.uuid4()), reason="new host", actor=_actor(),
    )
    principal = enrolment.redeem(issued.code, request_id=str(uuid.uuid4()), source="test").credential

    _worker(spn_client, principal, "host-office1-host")
    _worker(spn_client, principal, "host-office1-w01")

    assert store.is_host(agent_id(store, "host-office1-host"))
    assert not store.is_host(agent_id(store, "host-office1-w01"))
    with sqlite3.connect(store.database_path) as connection:
        [record] = connection.execute(
            "SELECT agent_name, action, actor_type, actor_id, reason, request_id FROM host_agent_audit",
        ).fetchall()
        [(enrolment_id,)] = connection.execute("SELECT id FROM host_enrollments").fetchall()
        [(marked_by,)] = connection.execute("SELECT marked_by FROM host_agents").fetchall()
    assert record == (
        "host-office1-host", "marked", "host-enrolment", f"host-enrolment:{enrolment_id}",
        "registered by the service principal of its host enrolment", None,
    )
    assert marked_by == "enrolment"


def test_a_name_that_looks_like_a_hosts_is_not_marked_without_a_host_enrolment(spn_client) -> None:  # noqa: F811
    """An ordinary service principal whose prefix happens to fit registers an ordinary agent."""
    store = spn_client.app.state.agent_service.store
    _, secret = _create_spn(spn_client, prefix="host-office1")

    _worker(spn_client, secret, "host-office1-host")

    assert not store.is_host(agent_id(store, "host-office1-host"))


def test_an_administrator_marks_and_unmarks_a_host_and_both_are_recorded(hosts) -> None:
    client, secret, grant, key, target, _, store, _ = hosts
    report(client, key)

    again = mark(client, secret, grant, target, HOST)
    removed = mark(client, secret, grant, target, HOST, "unmark", reason="retired")

    assert again.json() == {
        "action": "mark", "target_id": target, "target_label": HOST, "applied": False,
        "state": "a worker host", "detail": "Nothing changed. Agent is a worker host.",
        "secret": None, "secret_kind": None,
    }
    assert removed.json()["applied"] is True and removed.json()["detail"] == "Agent is now not a worker host."
    assert client.get(HOSTS, headers=_auth(secret)).json()["hosts"] == []
    assert report(client, key).status_code == 403
    with sqlite3.connect(store.database_path) as connection:
        records = connection.execute(
            "SELECT action, actor_type, actor_id, reason FROM host_agent_audit ORDER BY seq",
        ).fetchall()
        left = [connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608
                for table in ("host_agents", "host_status", "host_status_samples")]
    assert records == [
        ("marked", "remote-admin", "device:phone-one", "enrolled before host codes"),
        ("unmarked", "remote-admin", "device:phone-one", "retired"),
    ]
    assert left == [0, 0, 0]


def test_a_repeated_request_changes_nothing(hosts) -> None:
    client, secret, grant, _, target, *_ = hosts
    request_id = str(uuid.uuid4())

    first = mark(client, secret, grant, target, HOST, "unmark", request_id=request_id)
    marked_again = mark(client, secret, grant, target, HOST)
    replayed = mark(client, secret, grant, target, HOST, "unmark", request_id=request_id)

    assert (first.json()["applied"], marked_again.json()["applied"], replayed.json()["applied"]) == (True, True, False)
    assert client.get(HOSTS, headers=_auth(secret)).json()["hosts"][0]["agent"] == HOST


def test_marking_needs_the_grant_the_right_agent_and_a_reason(hosts) -> None:
    client, secret, grant, _, target, *_ = hosts

    assert mark(client, secret, "wrong", target, HOST).status_code == 401
    assert mark(client, secret, grant, target, "another-name").status_code == 409
    assert mark(client, secret, grant, str(uuid.uuid4()), HOST).status_code == 404
    assert mark(client, secret, grant, target, HOST, reason="").status_code == 422
    assert mark(client, secret, grant, target, HOST, action="promote").status_code == 422
    assert mark(client, secret, grant, target, HOST, request_id="not-a-uuid").status_code == 422


def test_the_store_checks_the_mark_request_itself(hosts) -> None:
    *_, target, _, store, _ = hosts
    actor = LifecycleActor(actor_type="local-admin", actor_id="console")
    fine = {"marked": True, "expected_name": HOST, "reason": "r", "request_id": str(uuid.uuid4()),
            "actor": actor, "changed_at": START}

    with pytest.raises(DomainValidationError):
        store.set_host_mark(target, **{**fine, "request_id": "x"})
    with pytest.raises(DomainValidationError):
        store.set_host_mark(target, **{**fine, "reason": " padded "})
    with pytest.raises(DomainValidationError):
        store.set_host_mark(target, **{**fine, "actor": "someone"})
    with pytest.raises(AgentNotFoundError):
        store.set_host_mark(str(uuid.uuid4()), **fine)
    with pytest.raises(CredentialConflictError):
        store.set_host_mark(target, **{**fine, "expected_name": "other"})


# ---- the audit feed ---------------------------------------------------------------------------


def test_every_report_stored_or_refused_reaches_the_audit_feed_with_who_and_how_large(hosts, monkeypatch) -> None:
    client, _, _, key, target, clock, *_ = hosts
    emitted: list[str] = []
    monkeypatch.setattr("strugglebus.api.emit_audit", emitted.append)
    body = json.dumps(snapshot()).encode()

    report(client, key, body)
    report(client, key, body)
    client.get("/api/whoami", headers=_auth(key))

    lines = [json.loads(line.removeprefix("strugglebus-audit ")) for line in emitted]
    assert [(l["event"], l["status"], l["outcome"], l["agent_name"], l["agent_id"], l["request_bytes"]) for l in lines] == [
        ("POST /api/hosts/status", 201, "ok", HOST, target, len(body)),
        ("POST /api/hosts/status", 429, "refused", HOST, target, len(body)),
    ]


def test_marks_reach_the_audit_feed_and_the_devices_log(hosts) -> None:
    from strugglebus import audit_feed

    client, secret, grant, _, target, _, store, _ = hosts
    feed_lines: list[str] = []
    feed = audit_feed.AuditFeed(store, feed_lines.append)
    feed.start_at_end()

    mark(client, secret, grant, target, HOST, "unmark", reason="retired")
    feed.poll_once()

    [line] = [json.loads(text.removeprefix("strugglebus-audit ")) for text in feed_lines if "host_agent_audit" in text]
    assert (line["event"], line["agent_name"], line["agent_id"], line["actor_id"], line["request_bytes"]) == (
        "host-unmarked", HOST, target, "device:phone-one", None,
    )
    assert "retired" not in json.dumps(line)
    shown = client.get("/api/mobile/admin/logs", headers=_auth(secret)).json()["entries"]
    assert [(e["event"], e["subject"]) for e in shown if e["event"].startswith("host-")] == [
        ("host-unmarked", HOST), ("host-marked", HOST),
    ]


def test_reports_that_worked_stay_out_of_the_devices_short_log_and_refusals_stay_in() -> None:
    from strugglebus import audit_feed, server_log

    def line(event: str, status: int) -> str:
        return audit_feed.request_line(ts="2026-11-27T04:00:00.000000Z", event=event, status=status, remote_address="a")

    assert server_log._request_entry(line("POST /api/hosts/status", 201)) is None
    assert server_log._request_entry(line("POST /api/hosts/events", 201)) is None
    assert server_log._request_entry(line("POST /api/hosts/status", 403))["level"] == "warning"
    assert server_log._request_entry(line("POST /api/enrollments/redeem", 201))["level"] == "info"
