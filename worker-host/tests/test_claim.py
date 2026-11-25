"""Claim protocol (design section 4) with two simulated hosts on one in-memory channel."""
from __future__ import annotations

import json

from conftest import COORD, HOST_A, HOST_B, STRANGER, task_body
from workerhost.claim import ClaimSession, reply_text
from workerhost.validate import digest_of

TASK = task_body()
DIGEST = digest_of(TASK)


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def post_task(bus) -> int:
    return bus.append(COORD, "question", json.dumps(TASK))


def session(bus, me, name, task_seq, clock, hosts=(HOST_A, HOST_B), digest=DIGEST):
    return ClaimSession(bus.client(me), "worker-hosts", name, task_seq, TASK["task_id"], digest, list(hosts), COORD,
                        settle_seconds=20, clock=clock)


def test_lowest_seq_wins_and_the_loser_yields(shared_bus):
    clock = Clock()
    t = post_task(shared_bus)
    a, b = session(shared_bus, HOST_A, "alpha", t, clock), session(shared_bus, HOST_B, "bravo", t, clock)
    assert b.post_claim() and a.post_claim()  # bravo claims first: lower seq
    assert not a.ready() and not b.ready()  # settle window
    clock.t = 21
    assert a.ready() and b.ready()
    assert b.decide() == "win"
    assert a.decide() == "lose"
    a.yield_("lose")
    yields = [m for m in shared_bus.messages if m["body"].startswith("{") and json.loads(m["body"])["type"] == "yield"]
    assert len(yields) == 1 and yields[0]["agent_name"] == HOST_A.agent_name and yields[0]["reply_to"] == t
    assert json.loads(yields[0]["body"])["digest"] == DIGEST


def test_claims_are_replies_carrying_task_id_and_digest(shared_bus):
    clock = Clock()
    t = post_task(shared_bus)
    a = session(shared_bus, HOST_A, "alpha", t, clock)
    a.post_claim()
    m = shared_bus.messages[-1]
    body = json.loads(m["body"])
    assert (m["kind"], m["reply_to"], body["type"], body["task_id"], body["digest"]) == (
        "answer", t, "claim", TASK["task_id"], DIGEST)


def test_stray_identity_or_wrong_digest_cannot_take_a_task(shared_bus):
    clock = Clock()
    t = post_task(shared_bus)
    # An unpinned identity claims first, and a pinned host claims with a different body digest.
    shared_bus.append(STRANGER, "answer", reply_text("claim", TASK["task_id"], DIGEST, "evil"), reply_to=t)
    shared_bus.append(HOST_B, "answer", reply_text("claim", TASK["task_id"], "f" * 64, "bravo"), reply_to=t)
    shared_bus.append(HOST_B, "status", reply_text("claim", TASK["task_id"], DIGEST, "bravo"), reply_to=t)
    a = session(shared_bus, HOST_A, "alpha", t, clock)
    a.post_claim()
    clock.t = 25
    assert a.decide() == "win"


def test_reread_failure_fails_closed(shared_bus):
    clock = Clock()
    t = post_task(shared_bus)
    a = session(shared_bus, HOST_A, "alpha", t, clock)
    a.post_claim()
    clock.t = 25
    shared_bus.fail_reads_for.add(HOST_A.agent_name)
    assert a.decide() == "unreadable"  # never "win": the host does not start


def test_own_claim_not_visible_fails_closed(shared_bus):
    clock = Clock()
    t = post_task(shared_bus)
    a = session(shared_bus, HOST_A, "alpha", t, clock, hosts=[HOST_B])  # misconfigured: own pin missing
    a.post_claim()
    clock.t = 25
    assert a.decide() == "lost-claim"


def test_cancel_before_start_stops_the_winner(shared_bus):
    clock = Clock()
    t = post_task(shared_bus)
    a, b = session(shared_bus, HOST_A, "alpha", t, clock), session(shared_bus, HOST_B, "bravo", t, clock)
    a.post_claim()
    b.post_claim()
    shared_bus.append(COORD, "question", json.dumps({"v": 1, "type": "cancel", "task": t}))
    clock.t = 25
    assert a.decide() == "cancelled"
    assert b.decide() == "cancelled"


def test_cancel_from_a_stranger_is_ignored(shared_bus):
    clock = Clock()
    t = post_task(shared_bus)
    a = session(shared_bus, HOST_A, "alpha", t, clock)
    a.post_claim()
    shared_bus.append(STRANGER, "question", json.dumps({"v": 1, "type": "cancel", "task": t}))
    clock.t = 25
    assert a.decide() == "win"


def test_claim_post_failure_means_no_claim(shared_bus):
    clock = Clock()
    t = post_task(shared_bus)
    a = session(shared_bus, HOST_A, "alpha", t, clock)

    def boom(*args, **kw):
        raise OSError("down")

    a.bus.post = boom
    assert a.post_claim() is False
    assert a.outcome == "claim-failed" and not a.ready()


def test_two_hosts_end_to_end_through_the_host_loop(tmp_path, shared_bus, monkeypatch):
    """Both hosts validate the same task; exactly one posts `started`, the other `yield`."""
    import time

    from conftest import FakeVault
    from workerhost import config as config_mod
    from workerhost import resources
    from workerhost.host import Host, save_pins

    monkeypatch.setattr(resources, "sample", lambda root: resources.Sample(100 * resources.GB, 10 * resources.GB,
                                                                           100 * resources.GB, 128 * resources.GB,
                                                                           500 * resources.GB))
    hosts, started = [], []
    for me, name in ((HOST_A, "alpha"), (HOST_B, "bravo")):
        home = tmp_path / name
        cfg = config_mod.Config(host_name=name, agent_prefix=f"host-{name}", poll_seconds=0, settle_seconds=0,
                                workers_root=tmp_path / f"w-{name}",
                                repos={"app-core": "acme/app-core"},
                                allowed_models=["claude-opus-5.5"], home=home,
                                hosts=[{"agent_name": HOST_A.agent_name, "agent_id": HOST_A.agent_id},
                                       {"agent_name": HOST_B.agent_name, "agent_id": HOST_B.agent_id}])
        h = Host(cfg, bus=shared_bus.client(me), vault=FakeVault())
        save_pins(cfg, coordinator=COORD, host=me)
        h.pins = {"coordinator": COORD, "host": me}
        h.st.data["cursor"] = 0
        h.start = lambda p, session_id=None, n=name: (started.append(n), p.session.post("started"))
        hosts.append(h)
    shared_bus.append(COORD, "question", json.dumps(task_body()))
    shared_bus.messages[-1]["created_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for h in hosts:
        h.poll()
    for h in hosts:
        h.advance_claims()  # post claims
    for h in reversed(hosts):
        h.next_poll = 0
        h.advance_claims()  # settle elapsed: decide
    assert started == ["alpha"]
    kinds = [json.loads(m["body"])["type"] for m in shared_bus.messages if m["kind"] == "answer"]
    assert kinds.count("claim") == 2 and kinds.count("yield") == 1 and kinds.count("started") == 1
