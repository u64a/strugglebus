"""The cost record: usage.read_usage and the credits on the finished/failed envelopes."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from conftest import COORD, HOST_A, FakeVault
from test_restart import TASK_ID, cfg, make_host, replies, running  # noqa: F401  (cfg is a fixture)
from workerhost import usage

DATA = Path(__file__).parent / "data" / "events.jsonl"
SID = "11111111-2222-4333-8444-555555555555"


def put_log(home: Path, sid: str = SID) -> None:
    d = home / ".copilot" / "session-state" / sid
    d.mkdir(parents=True)
    shutil.copy(DATA, d / "events.jsonl")


def test_read_usage_sums_models_and_skips_torn_and_unknown_lines(tmp_path):
    put_log(tmp_path)
    assert usage.read_usage(SID, home=tmp_path) == {
        "aic": 10.5, "calls": 5, "input_tokens": 3810, "output_tokens": 385,
        "by_model": {"model-a": 4.5, "model-b": 6.0}, "model_observed": "model-b"}


def test_read_usage_missing_log_is_none(tmp_path):
    assert usage.read_usage(SID, home=tmp_path) is None


def test_read_usage_empty_log_has_no_observed_model(tmp_path):
    d = tmp_path / ".copilot" / "session-state" / SID
    d.mkdir(parents=True)
    (d / "events.jsonl").write_text('{"type":"session.start","data":{}}\n', encoding="utf-8")
    got = usage.read_usage(SID, home=tmp_path)
    assert got["aic"] == 0.0 and got["calls"] == 0 and got["model_observed"] is None


@pytest.mark.parametrize("code,kind", [(0, "finished"), (1, "failed")])
def test_finish_posts_credits(cfg, shared_bus, tmp_path, monkeypatch, code, kind):  # noqa: F811
    put_log(tmp_path / "u")
    real = usage.read_usage
    monkeypatch.setattr(usage, "read_usage", lambda sid: real(sid, home=tmp_path / "u"))
    h = make_host(cfg, shared_bus)
    run = running(h, tmp_path)
    h.st.set_task(TASK_ID, session_id=SID)
    h.finish(TASK_ID, run, code)
    body = replies(h)[0]
    assert body["type"] == kind and body["model"] == "claude-opus-5.5"
    assert (body["aic"], body["calls"], body["model_observed"]) == (10.5, 5, "model-b")
    assert body["by_model"] == {"model-a": 4.5, "model-b": 6.0}
    assert "aic=10.5" in "".join(p.read_text(encoding="utf-8") for p in h.cfg.logs_dir.glob("host-*.log"))


def test_finish_without_a_log_posts_the_old_envelope(cfg, shared_bus, tmp_path, monkeypatch):  # noqa: F811
    real = usage.read_usage
    monkeypatch.setattr(usage, "read_usage", lambda sid: real(sid, home=tmp_path / "none"))
    h = make_host(cfg, shared_bus)
    run = running(h, tmp_path)
    h.st.set_task(TASK_ID, session_id=SID)
    h.finish(TASK_ID, run, 0)
    body = replies(h)[0]
    assert not {"aic", "calls", "by_model", "model_observed"} & body.keys()
    assert "usage-missing" in "".join(p.read_text(encoding="utf-8") for p in h.cfg.logs_dir.glob("host-*.log"))
