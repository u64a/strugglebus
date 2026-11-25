"""Signed host commands arriving at the host (workerhost/host.py handle_command; docs/app-host-integration.md
section 4): the verbs map to the existing control paths, a remote drain leaves the host running and paused, a
command for another host is only logged, and the result is in the status's last_command. The signature rules
themselves are tests/test_commands.py; here the verifier is a stand-in."""
from __future__ import annotations

import base64
import datetime as dt
import json
import time
from types import SimpleNamespace as NS

import pytest

from conftest import COORD, HOST_A, HOST_B
from workerhost import commands, hoststatus


@pytest.fixture
def host(tmp_path, monkeypatch):
    from conftest import FakeVault
    from workerhost import resources
    from workerhost.config import Config
    from workerhost.host import Host

    monkeypatch.setattr(resources, "sample", lambda root: None)
    cfg = Config(host_name="alpha", agent_prefix="host-alpha", poll_seconds=0, settle_seconds=0,
                 workers_root=tmp_path / "w", home=tmp_path / "home",
                 hosts=[{"agent_name": HOST_B.agent_name, "agent_id": HOST_B.agent_id}])
    h = Host(cfg, vault=FakeVault(), signers=tmp_path / "allowed_signers")
    h.pins = {"coordinator": COORD, "host": HOST_A}
    h.posts = []
    h.post = lambda kind, text, reply_to=None, queue=True, metadata=None: h.posts.append(text)
    h.verified = True
    monkeypatch.setattr(commands, "verifier", lambda *a: lambda doc, sig: NS(
        ok=h.verified, fingerprint="SHA256:test", reason="" if h.verified else "bad-signature"))
    return h


def stamp(t: float) -> str:
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


SEQ = iter(range(100, 10_000))


def message(host, verb="pause", target=None, nonce=None):
    now = time.time()
    doc = json.dumps({"v": 1, "type": "sb-host-command", "host": target or host.cfg.host_agent, "verb": verb,
                      "nonce": nonce or f"{next(SEQ):032x}", "issued_at": stamp(now - 5),
                      "expires_at": stamp(now + 295)}).encode()
    return {"seq": next(SEQ), "kind": "question", "agent_name": "human:operator", "agent_id": "op",
            "body": "signed host command; see metadata",
            "metadata": {"sb_host_command": {"doc": base64.b64encode(doc).decode(), "sig": "armored"}}}


def test_pause_and_resume(host):
    host.handle(message(host, "pause"))
    assert host.st.data["paused"] is True
    assert host.st.data["last_command"]["verb"] == "pause" and host.st.data["last_command"]["result"] == "done"
    host.handle(message(host, "resume"))
    assert host.st.data["paused"] is False


def test_a_remote_drain_ends_running_and_paused(host, monkeypatch):
    host.runs["t1"] = object()  # a worker still running
    host.handle(message(host, "drain"))
    assert host.reported_state() == "draining" and host.st.data["paused"] is True
    host.runs.clear()
    monkeypatch.setattr(host, "poll", lambda: None)
    for step in ("reload_models", "refresh_sample", "do_resumes", "advance_claims", "supervise", "flush_outbox", "heartbeat_if_due",
                 "status_if_changed", "maintain"):
        monkeypatch.setattr(host, step, lambda *a, **k: None)
    host.tick()
    assert host.st.data["drain_to_pause"] is False and host.st.data["paused"] is True
    assert host.exit_code is None  # still running: the App can resume it
    assert host.reported_state().startswith("paused")


def test_update_asks_for_the_newest_signed_release(host, monkeypatch):
    asked = []
    monkeypatch.setattr(host, "update_check", lambda announce=True: asked.append(announce))
    host.handle(message(host, "update"))
    assert host.update_now is True and asked == [True]


def test_a_command_for_another_host_is_only_logged(host):
    host.handle(message(host, "pause", target="host-beta-host"))
    assert host.st.data["paused"] is False and host.st.data.get("last_command") is None


def test_a_refusal_is_shown_and_does_nothing(host):
    host.verified = False
    host.handle(message(host, "pause"))
    assert host.st.data["paused"] is False
    assert host.st.data["last_command"] == {"nonce": None, "verb": None, "result": "refused",
                                            "reason": "bad-signature"}


def test_a_replay_is_refused(host):
    m = message(host, "pause", nonce="b" * 32)
    host.handle(m)
    host.st.data["paused"] = False
    host.handle({**m, "seq": next(SEQ)})
    assert host.st.data["paused"] is False and host.st.data["last_command"]["reason"] == "replayed"


def test_a_command_message_is_never_read_as_a_task(host, monkeypatch):
    seen = []
    monkeypatch.setattr(host, "consider", lambda m, ctx: seen.append(m))
    host.handle(message(host, "pause"))
    assert seen == []


def test_the_status_carries_the_last_command(host):
    host.handle(message(host, "pause", nonce="c" * 32))
    status = hoststatus.build(host.status_facts())
    assert status["last_command"] == {"nonce": "c" * 32, "verb": "pause", "result": "done", "reason": None}
