"""Resources (design section 5): refusals carry a reason code and this host's numbers, never a message value."""
from __future__ import annotations

import json

from conftest import message, task_body
from workerhost.config import Resources
from workerhost.resources import GB, Guard, Sample, check, game_running
from workerhost.validate import validate_task

R = Resources(max_workers=6, max_commit_pct=80, min_free_ram_gb=6, worker_commit_gb=8, min_free_disk_gb=40)


def sample(commit_limit=200, committed=50, free_phys=100, free_disk=500, procs=()):
    return Sample(commit_limit * GB, committed * GB, free_phys * GB, 128 * GB, free_disk * GB, set(procs))


def test_room_means_no_refusal():
    assert check(sample(), R, active=0) is None


def test_each_rule_refuses_with_its_reason_code():
    assert check(sample(), R, active=6) == ("workers", {"workers": 6, "limit": 6})
    reason, numbers = check(sample(committed=155), R, active=0)  # (155+8)/200 = 81.5 %
    assert (reason, numbers) == ("commit", {"commit_pct": 81.5, "limit": 80})
    assert check(sample(free_phys=13), R, active=0) == ("ram", {"ram_free_gb": 5.0, "limit": 6})
    assert check(sample(free_disk=39), R, active=0) == ("disk", {"disk_free_gb": 39.0, "limit": 40})


def test_resource_refusal_through_the_validator_echoes_no_message_value(ctx):
    marker = "core-zz9-plural-z-alpha"
    ctx.resources = lambda: check(sample(committed=190), R, active=0)
    d = validate_task(message(task_body(worker="core14", branch=f"feature/{marker}")), ctx)
    assert (d.action, d.reason) == ("refuse", "commit")
    refusal = json.dumps({"reason": d.reason, **d.numbers})
    assert marker not in refusal and "core14" not in refusal
    assert set(d.numbers) == {"commit_pct", "limit"}


def test_game_process_detection_is_case_insensitive_and_exe_optional():
    s = sample(procs={"eldenring.exe", "steam.exe"})
    assert game_running(s, ["EldenRing"])
    assert game_running(s, ["eldenring.exe"])
    assert not game_running(s, ["cyberpunk2077"])
    assert not game_running(s, [])


def test_guard_trips_on_two_samples_a_minute_apart_and_resets():
    t = [0.0]
    g = Guard(Resources(guard_commit_pct=85, guard_free_gb=6), clock=lambda: t[0])
    hot = sample(committed=180)  # 90 %
    assert not g.update(hot)
    t[0] = 30
    assert not g.update(hot)
    t[0] = 61
    assert g.update(hot)
    assert not g.update(sample())
