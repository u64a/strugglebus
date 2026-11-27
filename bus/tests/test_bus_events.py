"""The stored event log: what worker hosts report, and what the bus records about itself."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from strugglebus import audit_feed, bus_events
from strugglebus.retention import RetentionSweeper
from test_host_status import HOST, START, Clock, agent_id, hosts, mark  # noqa: F401
from test_mobile_write_path import _auth, surface  # noqa: F401
from test_site_documents import _agent_key

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts" / "host-events"
PINNED = {
    "batch-21-events.json": "fd6829da23ad0ef0b08dcbe31b3e4892552cbd5098c274392d892e20a8a7dac6",
    "batch-free-text.json": "57c7d53c20999b248d6bcd54e7c176d02f7e3b6b588d88490201e66a460cf4d7",
    "batch-good.json": "5c44f56c43fecdef291402af215d66b2ba271a66bddc07561181634c935080ce",
    "batch-unknown-field.json": "1d18126b7320e48773ade472911b546e87ce6f74a7dc6eff2e0791b8c1a24554",
    "batch-unknown-type.json": "0635459985075b2b1347a8bde778a99f2be11f493ce5b1a47a4436e276b46bc5",
    "batch-wrong-agent.json": "7d28fc908d328aabd9b7d19c1940436dd279071a4d9ed79efc3575a8b72b3c9a",
    "expected.json": "fdded42ff4c8d4eee4654a8917cc5c143edf23c577ec7400cff0d3389be5fa55",
}
EVENTS = "/api/hosts/events"
LOG = "/api/mobile/admin/logs"
FULL = "/api/mobile/admin/logs/full"


def contract_bytes(name: str) -> bytes:
    data = (CONTRACTS / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == PINNED[name], name
    return data


def contract(name: str) -> dict:
    return json.loads(contract_bytes(name))


def event(type_name: str = "started", **fields) -> dict:
    return {"id": str(uuid.uuid4()), "type": type_name, "at": "2026-11-27T04:01:00Z", **fields}


def batch(*events: dict, agent: str = HOST) -> dict:
    return {"v": 1, "agent": agent, "events": list(events) or [event()]}


def send(client, key: str, body: object):
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    return client.post(EVENTS, content=data, headers={**_auth(key), "Content-Type": "application/json"})


@pytest.fixture
def log(hosts):  # noqa: F811
    """The marked host of ``hosts``, with the event log on the same clock."""
    client, secret, grant, key, target, clock, store, agents = hosts
    client.app.state.event_log = bus_events.BusEventLog(store, clock=clock)
    with sqlite3.connect(store.database_path) as connection:
        # The bus noted its own start; these tests count what they store themselves.
        connection.execute("DELETE FROM bus_events")
    return client, secret, grant, key, target, clock, store, agents


def full(client, secret, grant, **more) -> list[dict]:
    answer = client.post(FULL, json={"grant_secret": grant, **more}, headers=_auth(secret))
    assert answer.status_code == 200, answer.text
    return answer.json()["entries"]


def host_rows(entries: list[dict]) -> list[dict]:
    return [entry for entry in entries if entry["source"] == "host"]


# ---- the host contract ------------------------------------------------------------------------


def test_every_contract_batch_gets_the_answer_the_contract_gives(log) -> None:
    client, _, _, key, _, clock, *_ = log
    expected = contract("expected.json")
    assert expected["caller_agent"] == HOST

    for name, result in expected["results"].items():
        answer = send(client, key, contract_bytes(name))
        assert answer.status_code == result["status"], (name, answer.text)
        if result["reason"] is not None:
            assert answer.json() == {"detail": result["reason"]}, name
        clock.forward(5)


def test_the_good_batch_is_stored_with_the_bus_own_levels_and_time(log) -> None:
    client, secret, grant, key, _, clock, *_ = log

    assert send(client, key, contract_bytes("batch-good.json")).json() == {"stored": 8}

    rows = host_rows(full(client, secret, grant))
    assert [(row["event"], row["level"], row["detail"]) for row in reversed(rows)] == [
        ("started", "info", "at=2026-11-27T04:01:00Z"),
        ("update-found", "info", "version=2026.11.28 at=2026-11-27T04:02:00Z"),
        ("update-failed", "error", "reason=selftest-failed version=2026.11.28 at=2026-11-27T04:03:00Z"),
        ("restarted-after-crash", "warning", "attempt=2 exit_code=1 at=2026-11-27T04:04:00Z"),
        ("fatal", "error", "error=KeyError at=2026-11-27T04:05:00Z"),
        ("task-refused", "warning", "reason=memory-high at=2026-11-27T04:06:00Z"),
        ("problem-raised", "warning", "code=disk-low at=2026-11-27T04:07:00Z"),
        ("stopped", "info", "reason=drain at=2026-11-27T04:08:00Z"),
    ]
    assert {(row["subject"], row["ts"]) for row in rows} == {(HOST, "2026-11-27T04:00:00Z")}


def test_the_bus_and_the_host_agree_on_every_type() -> None:
    """The host's list is the contract; the bus gives each a level and nothing more."""
    import ast

    path = Path(__file__).resolve().parents[2] / "worker-host" / "workerhost" / "hostevents.py"
    if not path.exists():
        pytest.skip("the worker host's source is not beside the bus here")
    # Read, not imported: the host's module belongs to its own package.
    assigned = {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in ast.parse(path.read_text(encoding="utf-8")).body
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in {"TYPES", "FIELDS"}
    }

    assert {name: fields for name, (fields, _) in bus_events.HOST_TYPES.items()} == assigned["TYPES"]
    assert bus_events.HOST_FIELDS == assigned["FIELDS"]
    assert {level for _, level in bus_events.HOST_TYPES.values()} == {"info", "warning", "error"}


@pytest.mark.parametrize("body,reason", [
    ([], "bad-batch"),
    ({"v": 1, "agent": HOST}, "bad-batch"),
    ({"v": 2, "agent": HOST, "events": [event()]}, "bad-batch"),
    ({"v": True, "agent": HOST, "events": [event()]}, "bad-batch"),
    ({"v": 1, "agent": HOST, "events": [event()], "more": 1}, "bad-batch"),
    (batch(agent="host-other-host"), "wrong-agent"),
    ({"v": 1, "agent": HOST, "events": []}, "bad-batch"),
    ({"v": 1, "agent": HOST, "events": "started"}, "bad-batch"),
    ({"v": 1, "agent": HOST, "events": ["started"]}, "duplicate-id"),
    ({"v": 1, "agent": HOST, "events": [event(), "started"]}, "duplicate-id"),
    ({"v": 1, "agent": HOST, "events": [event()] * 2}, "duplicate-id"),
    (batch({**event(), "type": ["x"]}), "unknown-type"),
    (batch({**event(), "id": "not-a-uuid"}), "bad-id"),
    (batch({**event(), "id": 7}), "bad-id"),
    (batch({**event(), "at": "yesterday"}), "bad-at"),
    (batch({"id": str(uuid.uuid4()), "type": "started"}), "bad-at"),
    (batch(event("update-found", version="v1")), "bad-value"),
    (batch(event("restarted-after-crash", exit_code=True)), "bad-value"),
    (batch(event("restarted-after-crash", exit_code=10_000_000)), "bad-value"),
    (batch(event("fatal", error="KeyError: 'secret'")), "bad-value"),
    (batch(event("task-refused", reason="x" * 65)), "bad-value"),
    (batch(event("started", reason="drain")), "unknown-field"),
])
def test_a_batch_that_does_not_fit_is_refused_whole(body, reason) -> None:
    assert bus_events.host_batch_refusal(body, HOST) == reason


def test_an_event_that_is_not_an_object_is_refused() -> None:
    assert bus_events._host_event_fault("started") == "bad-batch"
    assert bus_events._host_event_fault({"id": "x"}) == "unknown-type"


def test_one_bad_event_refuses_the_whole_batch_and_stores_none(log) -> None:
    client, secret, grant, key, *_ = log

    refused = send(client, key, batch(event(), event("fatal", error="a b")))

    assert (refused.status_code, refused.json()) == (400, {"detail": "bad-value"})
    assert host_rows(full(client, secret, grant)) == []


def test_a_batch_sent_again_makes_no_duplicate(log) -> None:
    client, secret, grant, key, _, clock, *_ = log
    first, second = event(), event("stopped", reason="drain")

    assert send(client, key, batch(first)).json() == {"stored": 1}
    clock.forward(5)
    assert send(client, key, batch(first, second)).json() == {"stored": 1}

    assert [row["event"] for row in host_rows(full(client, secret, grant))] == ["stopped", "started"]


def test_events_are_only_from_a_marked_host_at_most_every_five_seconds_and_not_too_large(log) -> None:
    client, _, _, key, _, clock, _, agents = log
    other = _agent_key(agents, "host-fake-host")

    assert send(client, other, batch(agent="host-fake-host")).json() == {"detail": "not-a-host"}
    assert send(client, key, batch()).status_code == 201
    clock.forward(2)
    early = send(client, key, batch())
    assert (early.status_code, early.headers["retry-after"]) == (429, "4")
    clock.forward(3)
    assert send(client, key, batch()).status_code == 201
    assert send(client, key, b" " * (16 * 1024 + 1)).status_code == 413
    assert send(client, key, b"{").json() == {"detail": "bad-json"}
    assert send(client, "sb1_nothing", batch()).status_code == 401


# ---- limits -----------------------------------------------------------------------------------


def stored_event(subject: str, source: str = "host") -> bus_events.Event:
    return bus_events.Event(str(uuid.uuid4()), source, "info", "started", subject, {})


def count(store, where: str = "1=1") -> int:
    with sqlite3.connect(store.database_path) as connection:
        return connection.execute(f"SELECT COUNT(*) FROM bus_events WHERE {where}").fetchone()[0]  # noqa: S608


def test_one_noisy_host_cannot_push_out_anothers_events_nor_the_buses_own(log) -> None:
    *_, target, clock, store, agents = log
    _agent_key(agents, "host-quiet-host")
    quiet = agent_id(store, "host-quiet-host")
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "INSERT INTO host_agents (agent_id, marked_at, marked_by) VALUES (?, ?, 'admin')", (quiet, "x"),
        )
    limits = {"minimum_gap": timedelta(0), "per_host": 3, "cap": 5}
    store.record_bus_event(stored_event("", "update"), received_at=clock.now, cap=10)

    store.record_host_events(quiet, [stored_event("host-quiet-host")] * 1, received_at=clock.now, **limits)
    for _ in range(4):
        store.record_host_events(target, [stored_event(HOST), stored_event(HOST)], received_at=clock.now, **limits)

    assert count(store, f"subject = '{HOST}'") == 3
    assert count(store, "subject = 'host-quiet-host'") == 1
    assert count(store, "source = 'update'") == 1


def test_all_hosts_together_keep_to_the_host_sources_share(log) -> None:
    *_, target, clock, store, _ = log

    for index in range(4):
        store.record_host_events(
            target, [stored_event(f"host-{index}"), stored_event(f"host-{index}")], received_at=clock.now,
            minimum_gap=timedelta(0), per_host=10, cap=5,
        )

    assert count(store) == 5
    assert count(store, "subject = 'host-0'") == 0


def test_a_source_of_the_buses_own_keeps_to_its_share(log) -> None:
    *_, clock, store, _ = log

    results = [store.record_bus_event(stored_event("", "update"), received_at=clock.now, cap=3) for _ in range(5)]
    again = bus_events.Event("11111111-1111-4111-8111-111111111111", "bus", "info", "started", "", {})

    assert results == [True] * 5 and count(store, "source = 'update'") == 3
    assert store.record_bus_event(again, received_at=clock.now, cap=3) is True
    assert store.record_bus_event(again, received_at=clock.now, cap=3) is False


def test_events_are_kept_thirty_days_and_never_removed_during_a_freeze(log) -> None:
    client, secret, grant, key, _, clock, store, _ = log
    send(client, key, batch())
    clock.forward(29 * 86400)
    send(client, key, batch())
    clock.forward(86400 + 1)
    sweep = {"now": clock.now, "keep": bus_events.KEEP}

    client.app.state.access_freeze_service.freeze("incident")
    assert store.remove_expired_bus_events(batch_size=10, **sweep) == 0
    client.app.state.access_freeze_service.unfreeze("over")

    assert store.remove_expired_bus_events(batch_size=10, **sweep) == 1
    assert store.remove_expired_bus_events(batch_size=10, **sweep) == 0
    assert count(store) == 1


def test_the_hourly_sweep_removes_old_events_and_old_samples(log) -> None:
    *_, target, clock, store, _ = log
    store.record_bus_event(stored_event("", "bus"), received_at=clock.now, cap=10)
    emitted: list[str] = []
    clock.forward(31 * 86400)

    RetentionSweeper(store, clock=clock, emit=emitted.append, batch_size=1).run_once()

    assert count(store) == 0


# ---- the bus's own events ---------------------------------------------------------------------


def test_the_bus_records_its_own_events_and_keeps_only_values_that_fit(log) -> None:
    client, secret, grant, *_ = log
    events = client.app.state.event_log

    assert events.record("update", "update-check-failed", reason="rate-limited") is True
    events.record("update", "update-failed", "0.2.75", version="0.2.75", previous="0.2.74",
                  reason="HTTP 500: <html>upstream said things</html>")
    events.record("security", "release-signature-refused", "0.2.75", version="0.2.75", extra="ignored")
    events.record("bus", "started", version="0.2.74", schema=25)

    rows = [row for row in full(client, secret, grant) if row["source"] != "host" and row["source"] in bus_events.ALL_SOURCES]
    assert [(row["source"], row["event"], row["level"], row["subject"], row["detail"]) for row in reversed(rows)] == [
        ("update", "update-check-failed", "warning", None, "reason=rate-limited"),
        # A reason that is not one of the bus's own short codes is left out, not stored.
        ("update", "update-failed", "error", "0.2.75", "previous=0.2.74 version=0.2.75"),
        ("security", "release-signature-refused", "error", "0.2.75", "version=0.2.75"),
        ("bus", "started", "info", None, "schema=25 version=0.2.74"),
    ]
    with pytest.raises(KeyError):
        events.record("update", "not-a-type")


def test_every_type_name_fits_the_tables_rule() -> None:
    names = set(bus_events.HOST_TYPES) | {name for types in bus_events.BUS_TYPES.values() for name in types}

    assert all(bus_events._KINDS["code"].fullmatch(name) and len(name) <= 64 for name in names)
    assert set(bus_events.BUS_TYPES) | {"host"} == set(bus_events.ALL_SOURCES) == set(bus_events.CAPS)
    assert set(bus_events.OPEN_SOURCES) < set(bus_events.ALL_SOURCES)


# ---- who reads what ---------------------------------------------------------------------------


def test_any_device_reads_update_and_bus_events_but_only_an_administrator_the_rest(log) -> None:
    client, secret, grant, key, *_ = log
    events = client.app.state.event_log
    send(client, key, batch())
    events.record("update", "update-found", "0.2.75", version="0.2.75")
    events.record("security", "release-signature-refused", "0.2.75", version="0.2.75")
    events.record("bus", "started", version="0.2.74", schema=25)

    device = client.get(LOG, headers=_auth(secret)).json()["entries"]
    admin = full(client, secret, grant)

    def stored(entries):
        return sorted((e["source"], e["event"]) for e in entries if e["source"] in bus_events.ALL_SOURCES)

    assert stored(device) == [("bus", "started"), ("update", "update-found")]
    assert stored(admin) == [
        ("bus", "started"), ("host", "started"), ("security", "release-signature-refused"), ("update", "update-found"),
    ]
    refused = client.post(FULL, json={"grant_secret": "wrong"}, headers=_auth(secret))
    assert refused.status_code == 401
    assert client.post(FULL, json={"grant_secret": grant}).status_code == 401
    assert client.post(FULL, json={"grant_secret": grant, "limit": 501}, headers=_auth(secret)).status_code == 422


def test_the_full_log_is_newest_first_keeps_to_its_limit_and_is_not_cached(log) -> None:
    client, secret, grant, key, _, clock, *_ = log
    for name in ("started", "pressure", "stopped"):
        send(client, key, batch(event(name)))
        clock.forward(5)

    answer = client.post(FULL, json={"grant_secret": grant, "limit": 2}, headers=_auth(secret))

    assert answer.headers["cache-control"] == "no-store"
    assert len(answer.json()["entries"]) == 2
    times = [entry["ts"] for entry in answer.json()["entries"]]
    assert times == sorted(times, reverse=True)


# ---- the audit feed ---------------------------------------------------------------------------


def test_every_stored_event_reaches_the_audit_feed_once(log) -> None:
    client, _, _, key, _, clock, store, _ = log
    lines: list[str] = []
    feed = audit_feed.AuditFeed(store, lines.append)
    send(client, key, batch(event("pressure")))
    feed.start_at_end()

    clock.forward(5)
    send(client, key, batch(event("fatal", error="KeyError")))
    client.app.state.event_log.record("update", "update-check-failed", reason="rate-limited")
    feed.poll_once()
    feed.poll_once()

    records = [json.loads(line.removeprefix("strugglebus-audit ")) for line in lines if '"bus_events"' in line]
    assert [(r["source"], r["event"], r["level"], r["subject"], r["fields"]) for r in records] == [
        ("host", "fatal", "error", HOST, {"error": "KeyError", "at": "2026-11-27T04:01:00Z"}),
        ("update", "update-check-failed", "warning", "", {"reason": "rate-limited"}),
    ]
    assert all(r["outcome"] == "ok" and r["ts"].startswith("2026-11-27T04:00:05") for r in records)
    plain = json.loads(audit_feed.request_line(ts="t", event="e", status=200, remote_address="a").removeprefix("strugglebus-audit "))
    assert set(records[0]) == set(plain)
    assert (plain["source"], plain["level"], plain["subject"], plain["fields"]) == (None, None, None, None)
