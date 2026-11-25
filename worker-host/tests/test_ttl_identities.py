"""Phase 2 (bus 0.2.61): one TTL identity per task attempt, retired by the SPN when the task ends."""
from __future__ import annotations

import json
from datetime import datetime

import pytest

from conftest import COORD, HOST_A, FakeVault, SharedBus
from test_openbao import SPN, FakeBao, client
from workerhost import busclient, resources
from workerhost.config import Config, OpenBao, Runtime
from workerhost.host import Host

DAY = datetime.now().strftime("%y%m%d")


def make(tmp_path, monkeypatch, ttl=True, hours=6.0):
    monkeypatch.setattr(resources, "sample", lambda root: None)
    bao = FakeBao()
    monkeypatch.setattr("workerhost.host.openbao_client", lambda c: client(bao))
    cfg = Config(host_name="alpha", agent_prefix="host-alpha", home=tmp_path / "home", workers_root=tmp_path / "w",
                 runtime=Runtime(max_runtime_hours=hours), openbao=OpenBao(enabled=True, ttl_identities=ttl))
    h = Host(cfg, bus=SharedBus().client(HOST_A), vault=FakeVault())
    h.pins = {"host": HOST_A, "coordinator": COORD}
    h.store.save_spn(SPN)
    return h, bao


def test_each_attempt_gets_a_new_dated_name(tmp_path, monkeypatch):
    h, _ = make(tmp_path, monkeypatch)
    monkeypatch.setattr(h, "release_identity", lambda agent: None)
    a = h.task_agent("t1", "core14")
    b = h.task_agent("t2", "core14")
    c = h.task_agent("t3", "core15")
    assert (a, b, c) == (f"host-alpha-core14-{DAY}1", f"host-alpha-core14-{DAY}2", f"host-alpha-core15-{DAY}1")


def test_phase_1_keeps_the_durable_name(tmp_path, monkeypatch):
    h, _ = make(tmp_path, monkeypatch, ttl=False)
    assert h.task_agent("t1", "core14") == "host-alpha-core14" and not h.ttl_identities


@pytest.mark.parametrize("hours,ttl", [(6.0, 7 * 3600), (2.0, 3 * 3600), (11.5, 43200), (20.0, 43200)])
def test_ttl_is_runtime_plus_an_hour_capped_at_12(tmp_path, monkeypatch, hours, ttl):
    h, _ = make(tmp_path, monkeypatch, hours=hours)
    assert h.identity_ttl() == ttl


def test_mint_asks_for_the_ttl(tmp_path, monkeypatch):
    h, bao = make(tmp_path, monkeypatch)
    seen = {}

    def fake_onboard(bus, spn, agent, description, identity_ttl_seconds=None):
        seen.update(agent=agent, ttl=identity_ttl_seconds)
        return {"agent_id": "id", "agent_name": agent, "secret": "sb1_x", "identity_expires_at": "2026-11-04T20:00:00Z"}

    monkeypatch.setattr("workerhost.host.onboard", fake_onboard)
    monkeypatch.setattr("workerhost.host.bootstrap", lambda bus, rec, ch: [])
    agent = h.task_agent("t1", "core14")
    rec = h.ensure_identity(agent, h.identity_ttl())
    assert seen == {"agent": f"host-alpha-core14-{DAY}1", "ttl": 7 * 3600} and rec["secret"] == "sb1_x"
    assert f"host-alpha/workers/host-alpha-core14-{DAY}1" in bao.kv


def test_release_retires_with_the_spn_and_destroys_the_entry(tmp_path, monkeypatch):
    h, bao = make(tmp_path, monkeypatch)
    agent = f"host-alpha-core14-{DAY}1"
    h.store.save(agent, {"agent_name": agent, "secret": "sb1_x"})
    h.st.data.setdefault("worker_channels", {})[agent] = ["Notes"]
    calls = []
    monkeypatch.setattr("workerhost.host.retire_identity", lambda bus, spn, name: calls.append((spn, name)) or 200)
    h.st.set_task("t1", status="finished", bus_agent=agent)
    h.release_task_identity("t1")
    assert calls == [(SPN, agent)]
    assert f"host-alpha/workers/{agent}" not in bao.kv and agent not in h.st.data["worker_channels"]


@pytest.mark.parametrize("agent", ["host-alpha-core14", "host-alpha-host", "someone-else-core14-2611041", ""])
def test_durable_host_and_foreign_names_are_never_retired(tmp_path, monkeypatch, agent):
    h, _ = make(tmp_path, monkeypatch)
    monkeypatch.setattr("workerhost.host.retire_identity", lambda *a: pytest.fail("must not retire " + agent))
    h.release_identity(agent)


def test_a_failed_retire_is_logged_and_not_fatal(tmp_path, monkeypatch):
    h, bao = make(tmp_path, monkeypatch)
    agent = f"host-alpha-core14-{DAY}1"
    h.store.save(agent, {"secret": "sb1_x"})

    def down(*a):
        raise OSError("bus down")

    monkeypatch.setattr("workerhost.host.retire_identity", down)
    h.release_identity(agent)  # no raise; the TTL retires it anyway
    log = "".join(p.read_text(encoding="utf-8") for p in h.cfg.logs_dir.glob("host-*.log"))
    assert "identity-retire-failed" in log


def test_a_resume_retires_the_previous_attempt(tmp_path, monkeypatch):
    h, _ = make(tmp_path, monkeypatch)
    released = []
    monkeypatch.setattr(h, "release_identity", lambda agent: released.append(agent))
    first = h.task_agent("t1", "core14")
    h.st.set_task("t1", status="interrupted", bus_agent=first)
    second = h.task_agent("t1", "core14")
    assert released == [first] and second != first


def test_retire_call_shape():
    class B:
        def call(self, method, path, body=None, query=None, token=None):
            self.seen = (method, path, sorted(body), token)
            return 200, {"state": "retired"}

    b = B()
    assert busclient.retire(b, SPN, "host-alpha-core14-2611041") == 200
    assert b.seen == ("POST", "/api/spn/agents/host-alpha-core14-2611041/retire", ["request_id"], SPN)


def test_onboard_sends_the_ttl_only_when_asked():
    class B:
        base = "https://bus"

        def __init__(self):
            self.bodies = []

        def call(self, method, path, body=None, query=None, token=None):
            self.bodies.append(body)
            if path.endswith("onboarding-packages"):
                return 201, {"package": {"enrollment_token": "sbse1_t", "identity_expires_at": "2026-11-04T20:00:00Z"}}
            return 201, {"agent": {"id": "i", "name": body["name"]}, "credential": {"id": "c"},
                         "credential_secret": "sb1_s"}

    b = B()
    rec = busclient.onboard(b, SPN, "host-alpha-x-2611041", "d", identity_ttl_seconds=25200)
    assert b.bodies[0]["identity_ttl_seconds"] == 25200 and rec["identity_expires_at"] == "2026-11-04T20:00:00Z"
    b2 = B()
    busclient.onboard(b2, SPN, "host-alpha-x", "d")
    assert "identity_ttl_seconds" not in b2.bodies[0]


def test_notes_addressed_to_the_stable_name_reach_a_ttl_worker():
    msgs = [{"seq": 10, "agent_id": COORD.agent_id, "agent_name": COORD.agent_name, "kind": "chat",
             "body": "@host-alpha-core14 please also update the README"},
            {"seq": 11, "agent_id": COORD.agent_id, "agent_name": COORD.agent_name, "kind": "chat",
             "body": f"@host-alpha-core14-{DAY}1 and the changelog"}]
    notes, other, quoted = busclient.select_notes(msgs, f"host-alpha-core14-{DAY}1", 5, COORD.agent_id,
                                                  COORD.agent_name, also=("host-alpha-core14",))
    assert [n["seq"] for n in notes] == [10, 11]
    only_ttl, _, _ = busclient.select_notes(msgs, f"host-alpha-core14-{DAY}1", 5, COORD.agent_id, COORD.agent_name)
    assert [n["seq"] for n in only_ttl] == [11]


def test_worker_env_carries_the_stable_notes_name(tmp_path):
    from workerhost import launcher

    env = launcher.worker_env({"SB_NOTES_NAME": "stale"}, bus_ca="ca", bus_url="u", store=None, token="sb1_x",
                              temp=tmp_path, gh_exe="gh", wait_timeout=60, notes_name="host-alpha-core14")
    assert env["SB_NOTES_NAME"] == "host-alpha-core14"
    plain = launcher.worker_env({"SB_NOTES_NAME": "stale"}, bus_ca="ca", bus_url="u", store=None, token="sb1_x",
                                temp=tmp_path, gh_exe="gh", wait_timeout=60)
    assert "SB_NOTES_NAME" not in plain


# --- SPN self-rotation -------------------------------------------------------------------------------------------
NEW_SPN = "sbsp1_successor-secret-value"


def test_rotation_stores_the_successor_and_reads_it_back(tmp_path, monkeypatch):
    from workerhost.host import rotate_spn_now

    h, bao = make(tmp_path, monkeypatch)
    monkeypatch.setattr(busclient, "rotate_spn", lambda bus, spn, rid: NEW_SPN if spn == SPN else pytest.fail("old"))
    events = []
    assert rotate_spn_now(h.cfg, h.store, lambda e, **kw: events.append(e)) == "rotated"
    assert bao.kv["host-alpha/strugglebus-spn"]["secret"] == NEW_SPN and "rotated_at" in bao.kv["host-alpha/strugglebus-spn"]
    assert events == ["spn-rotated"]


def test_rotation_retries_inside_the_overlap_then_reports_lost(tmp_path, monkeypatch):
    from workerhost.host import rotate_spn_now

    h, bao = make(tmp_path, monkeypatch)
    monkeypatch.setattr(busclient, "rotate_spn", lambda bus, spn, rid: NEW_SPN)
    real_save = h.store.save_spn
    fails = {"n": 3}

    def flaky(secret, rotated_at=None):
        if fails["n"]:
            fails["n"] -= 1
            raise OSError("vault blip")
        real_save(secret, rotated_at)

    monkeypatch.setattr(h.store, "save_spn", flaky)
    t = {"now": 0.0}
    assert rotate_spn_now(h.cfg, h.store, lambda e, **kw: None, sleep=lambda s: t.update(now=t["now"] + s),
                          clock=lambda: t["now"]) == "rotated"
    assert bao.kv["host-alpha/strugglebus-spn"]["secret"] == NEW_SPN
    fails["n"] = 99
    events = []
    assert rotate_spn_now(h.cfg, h.store, lambda e, **kw: events.append(e), sleep=lambda s: t.update(now=t["now"] + s),
                          clock=lambda: t["now"]) == "lost"
    assert events[-1] == "spn-rotate-lost"


def test_rotation_runs_only_in_the_window_and_when_due(tmp_path, monkeypatch):
    import workerhost.host as host_mod

    h, bao = make(tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(host_mod, "rotate_spn_now", lambda cfg, store, log: calls.append(1) or "rotated")
    now = 1_800_000_000.0
    h.spn_rotate_tick(now)  # no clock yet: started, not rotated
    assert calls == [] and h.store.spn_rotated_at() == pytest.approx(now)

    class Clock(datetime):
        hour_ = 3

        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 11, 5, cls.hour_, 10)

    monkeypatch.setattr(host_mod, "datetime", Clock)
    h.next_spn_check = 0
    h.spn_rotate_tick(now + 10 * 86400)  # in the window, not due
    assert calls == []
    h.next_spn_check = 0
    Clock.hour_ = 14
    h.spn_rotate_tick(now + 31 * 86400)  # due, outside the window
    assert calls == []
    h.next_spn_check = 0
    Clock.hour_ = 3
    h.spn_rotate_tick(now + 31 * 86400)  # due and in the window
    assert calls == [1]


def test_rotate_answer_parsing():
    class B:
        def __init__(self, status, body):
            self.r = (status, body)

        def call(self, *a, **k):
            return self.r

    assert busclient.rotate_spn(B(201, {"credential_secret": NEW_SPN}), SPN, "r") == NEW_SPN
    assert busclient.rotate_spn(B(201, {"credential": {"secret": NEW_SPN}}), SPN, "r") == NEW_SPN
    assert busclient.rotate_spn(B(200, {}), SPN, "r") is None
    with pytest.raises(busclient.BusError):
        busclient.rotate_spn(B(201, {"nothing": "here"}), SPN, "r")
    with pytest.raises(busclient.BusError):
        busclient.rotate_spn(B(429, {"detail": "limit"}), SPN, "r")
