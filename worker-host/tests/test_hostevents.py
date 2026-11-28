"""Host events for the bus's event log (workerhost/hostevents.py; docs/app-host-integration.md section 1b)."""
from __future__ import annotations

import json

import pytest

from workerhost import hostevents

CALLER = "host-box1-host"


def ev(n: int, etype: str, **fields) -> dict:
    """An event with a fixed id and time, so the contract files are the same on every run."""
    return {"id": f"00000000-0000-4000-8000-{n:012d}", "type": etype, "at": f"2026-11-27T04:{n % 60:02d}:00Z", **fields}


GOOD_EVENTS = [
    ev(1, "started"),
    ev(2, "update-found", version="2026.11.28"),
    ev(3, "update-failed", version="2026.11.28", reason="selftest-failed"),
    ev(4, "restarted-after-crash", exit_code=1, attempt=2),
    ev(5, "fatal", error="KeyError"),
    ev(6, "task-refused", reason="memory-high"),
    ev(7, "problem-raised", code="disk-low"),
    ev(8, "stopped", reason="drain"),
]


def batch(events, agent=CALLER) -> dict:
    return hostevents.body(agent, events)


# The contract files (contracts/host-events/): one good batch, one of each refusal bus-dev asked for (28850).
VECTORS = {
    "batch-good.json": (batch(GOOD_EVENTS), None),
    "batch-unknown-type.json": (batch([ev(1, "started"), ev(2, "host-hacked")]), "unknown-type"),
    "batch-unknown-field.json": (batch([ev(1, "update-applied", version="2026.11.28", note="x")]), "unknown-field"),
    "batch-free-text.json": (batch([ev(1, "task-refused", reason="refused: disk full on D:")]), "bad-value"),
    "batch-wrong-agent.json": (batch([ev(1, "started")], agent="host-other-host"), "wrong-agent"),
    "batch-21-events.json": (batch([ev(n, "pressure") for n in range(1, 22)]), "too-many-events"),
}


def vector_bytes(data) -> bytes:
    return (json.dumps(data, indent=1, ensure_ascii=True) + "\n").encode("ascii")


def expected() -> dict:
    return {"caller_agent": CALLER,
            "results": {name: {"status": 201 if reason is None else 400, "reason": reason}
                        for name, (_, reason) in VECTORS.items()}}


def contract(name: str) -> bytes:
    from vectors import path

    return path("host-events", name).read_bytes()


@pytest.mark.parametrize("name", list(VECTORS) + ["expected.json"])
def test_the_contract_files_are_what_this_test_makes(name):
    want = expected() if name == "expected.json" else VECTORS[name][0]
    assert contract(name) == vector_bytes(want)


@pytest.mark.parametrize("name", list(VECTORS))
def test_the_reference_check_gives_each_vector_its_expected_answer(name):
    data, reason = VECTORS[name]
    assert hostevents.validate_batch(data, CALLER) == reason


def test_every_type_and_field_is_in_the_fixed_lists():
    # 22 agreed in 1b, plus section 4a's 4 device-code sign-in types and claude-token-stored, plus the machine's
    # engine updater's tool-updated and tool-update-failed (#humans 29444).
    assert len(hostevents.TYPES) == 29
    assert all(f in hostevents.FIELDS for fields in hostevents.TYPES.values() for f in fields)


@pytest.mark.parametrize("name, value, ok", [
    ("version", "2026.11.27.3", True), ("version", "manual", True), ("version", "v1; rm", False),
    ("reason", "memory-high", True), ("reason", "Memory High", False), ("reason", "a" * 65, False),
    ("error", "KeyError", True), ("error", "json.JSONDecodeError", True), ("error", "C:\\x", False),
    ("exit_code", -1, True), ("exit_code", "1", False), ("exit_code", True, False),
    ("unknown", "x", False),
])
def test_values_are_of_fixed_kinds_never_free_text(name, value, ok):
    assert hostevents.value_ok(name, value) is ok


def test_make_leaves_out_what_does_not_fit_rather_than_sending_a_refusable_event():
    e = hostevents.make("task-refused", at=1_800_000_000, reason="refused because of C:\\secret", task_id="abc")
    assert set(e) == {"id", "type", "at"} and e["type"] == "task-refused" and e["at"].endswith("Z")
    assert hostevents.make("not-a-type") is None
    assert hostevents.event_problem(e) is None


def test_other_refusals():
    assert hostevents.validate_batch({"v": 1, "agent": CALLER, "events": []}, CALLER) == "bad-batch"
    assert hostevents.validate_batch({"v": 2, "agent": CALLER, "events": [ev(1, "started")]}, CALLER) == "bad-batch"
    assert hostevents.validate_batch(batch([ev(1, "started"), ev(1, "stopped")]), CALLER) == "duplicate-id"
    bad_id = dict(ev(1, "started"), id="not-a-uuid")
    assert hostevents.validate_batch(batch([bad_id]), CALLER) == "bad-id"
    # 20 valid events stay under 4 KB, so only a body padded with something else can pass 16 KB: refused for size.
    padded = dict(ev(1, "started"), note="x" * 17000)
    assert hostevents.validate_batch(batch([padded]), CALLER) == "too-large"
    assert hostevents.validate_batch(batch(GOOD_EVENTS), "host-other-host") == "wrong-agent"


# --- the queue and the tap ---------------------------------------------------------------------------------------

def test_the_queue_is_bounded_and_keeps_update_failures_longest(tmp_path):
    q = hostevents.Queue(tmp_path)
    q.add(hostevents.make("update-failed", version="2026.11.28", reason="selftest-failed"))
    for _ in range(hostevents.QUEUE_MAX + 5):
        q.add(hostevents.make("pressure"))
    events = q.load()
    assert len(events) == hostevents.QUEUE_MAX and events[0]["type"] == "update-failed"


def test_the_queue_gives_at_most_20_per_call_and_removes_what_was_stored(tmp_path):
    q = hostevents.Queue(tmp_path)
    for _ in range(25):
        q.add(hostevents.make("pressure"))
    first = q.first(CALLER)
    assert len(first) == hostevents.MAX_EVENTS and hostevents.validate_batch(batch(first), CALLER) is None
    q.remove({e["id"] for e in first})
    assert len(q.load()) == 5


def test_a_broken_queue_file_never_breaks_logging(tmp_path):
    (tmp_path / hostevents.QUEUE_FILE).write_text("{not json", encoding="utf-8")
    q = hostevents.Queue(tmp_path)
    assert q.load() == []
    q.add(hostevents.make("started"))
    assert [e["type"] for e in q.load()] == ["started"]


def test_the_log_writes_its_line_first_and_queues_only_mapped_events(tmp_path):
    log = hostevents.EventLog(tmp_path / "logs", tmp_path / "state")
    log("host-start", host="box1", channel="worker-hosts", ghcp="1.0.116")
    log("poll", n=3)  # not in the table: a line only
    log("update-failed", version="2026.11.28", reason="selftest-failed", detail="C:\\long\\path")
    log("task-refused", reason="memory-high")
    lines = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "logs").glob("*.log"))
    assert "host-start" in lines and "poll" in lines and "detail=" in lines  # the local log keeps everything
    events = log.events.load()
    assert [e["type"] for e in events] == ["started", "update-failed", "task-refused"]
    assert events[1] == {**events[1], "version": "2026.11.28", "reason": "selftest-failed"} and "detail" not in events[1]


def test_repeating_lines_become_one_event_per_change(tmp_path):
    log = hostevents.EventLog(tmp_path / "logs", tmp_path / "state")
    for _ in range(3):
        log("bus-unreachable")
    log("bus-back")
    log("bus-error", status=503)
    for _ in range(2):
        log("leaf-renew-failed", status=0)
    log("leaf-renewed")
    log("leaf-renew-failed", status=0)
    for _ in range(2):
        log("update-check", status="ok", release="2026.11.28", serial=9, installed="2026.11.27.3", newer=True)
    log("update-check", status="ok", release="2026.11.28", serial=9, installed="2026.11.28", newer=False)
    assert [e["type"] for e in log.events.load()] == [
        "bus-lost", "bus-back", "bus-lost", "leaf-renew-failed", "leaf-renew-failed", "update-found"]


def test_the_supervisor_lines_a_crash_and_a_rollback_but_not_a_planned_restart(tmp_path):
    log = hostevents.EventLog(tmp_path / "logs", tmp_path / "state")
    log("supervisor-restart", reason="updated", exit_code=75, delay=0)
    log("supervisor-restart", exit_code=1, ran_seconds=12, delay=30, attempt=2)
    log("supervisor-rollback", version="2026.11.28", restored=True, failures=3)
    log("ghcp-update", ok=True, before="1.0.1", after="1.0.2")
    log("ghcp-update", ok=False, before="1.0.1", after="1.0.1")
    types = [(e["type"], e.get("exit_code"), e.get("attempt"), e.get("version")) for e in log.events.load()]
    assert types == [("restarted-after-crash", 1, 2, None), ("update-rolled-back", None, None, "2026.11.28"),
                     ("copilot-update-failed", None, None, None)]


def test_an_error_line_becomes_a_fatal_with_the_type_only(tmp_path):
    log = hostevents.EventLog(tmp_path / "logs", tmp_path / "state")
    try:
        raise KeyError("C:\\Users\\me\\secret.txt")
    except KeyError as e:
        log.error("fatal", e)
    (event,) = log.events.load()
    assert event["type"] == "fatal" and event["error"] == "KeyError" and "secret" not in json.dumps(event)
