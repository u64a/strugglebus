"""docs/coordinator-guide.md and tools/post-task.py stay true to the code: the guide's example task passes the hosts'
own rules, every reason a host can give is explained, and the helper refuses locally what a host would refuse."""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GUIDE = (ROOT / "docs" / "coordinator-guide.md").read_text(encoding="utf-8")
SPEC = importlib.util.spec_from_file_location("post_task", ROOT / "tools" / "post-task.py")
post_task = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(post_task)

COMMIT = "3251a85e528772e7594b5f17f8e98f3e3d72930e"
BASE = ["--as", "sb-test-coordinator", "--channel", "worker-hosts-test", "--worker", "test1",
        "--repo", "https://github.com/acme/strugglebus-sandbox.git", "--branch", "test/x",
        "--brief", "tooling/briefs/hello.md", "--commit", COMMIT, "--dry-run"]


def test_the_guides_example_task_passes_the_hosts_rules():
    example = re.search(r"```json\n(\{.*?\})\n```", GUIDE, re.S).group(1)
    example = (example.replace("<new uuid>", "6f1c2b9e-4d3a-4b8e-9f20-1a2b3c4d5e6f").replace("<40-hex>", COMMIT)
               .replace("<owner>/<repo>", "acme/app-core"))
    assert post_task.check(json.loads(example), ["claude-opus-5.5"]) is None


def test_every_reason_a_host_gives_is_explained_in_the_guide():
    code = "".join((ROOT / "workerhost" / f).read_text(encoding="utf-8") for f in ("launcher.py", "host.py", "validate.py"))
    launch = set(re.findall(r'LaunchError\("([a-z-]+)"\)', code)) - {"copilot-wrapper", "copilot-missing", "stop-here"}
    refuse = set(re.findall(r'Decision\("refuse", "([a-z_]+)"', code))
    resources = set(re.findall(r'return "([a-z]+)", \{', (ROOT / "workerhost" / "resources.py").read_text(encoding="utf-8")))
    states = set(re.findall(r'return "([a-z]+)", \{', code))
    for reason in sorted(launch | refuse | resources | states):
        assert f"`{reason}`" in GUIDE, reason
    for reply in ("claim", "yield", "refuse", "started", "warning", "stalled", "finished", "failed", "timed-out",
                  "interrupted"):
        assert f"`{reply}`" in GUIDE, reply


def test_post_task_builds_the_envelope_and_canonicalises_the_url(capsys):
    assert post_task.main(BASE + ["--repo-instructions", "false", "--needs", "sshdrop", "--model", "gpt-5.5"]) == 0
    task = json.loads(capsys.readouterr().out)
    assert task["repo"] == "https://github.com/acme/strugglebus-sandbox"  # .git dropped
    assert task["repo_instructions"] is False and task["needs"] == ["sshdrop"] and task["model"] == "gpt-5.5"
    assert task["type"] == "task" and task["v"] == 1 and task["host"] == "any" and len(task["task_id"]) == 36


@pytest.mark.parametrize("over, field", [
    (["--branch", "main"], "branch"),
    (["--worker", "host"], "worker"),
    (["--worker", "con"], "worker"),
    (["--brief", "briefs/x.md"], "brief"),
    (["--brief", "tooling/briefs/../x.md"], "brief"),
    (["--commit", "3251a85"], "vault_commit"),
    (["--repo", "git@github.com:acme/x.git"], "repo"),
    (["--repo", "https://gitlab.com/someone-else/x"], "repo"),  # outside the default fence (GitHub)
    (["--model", "auto"], "model"),
    (["--host", "Alpha"], "host"),
])
def test_post_task_refuses_locally_what_a_host_would_refuse(capsys, over, field):
    args = list(BASE)
    for i in range(0, len(over), 2):
        args[args.index(over[i]) + 1] = over[i + 1] if over[i] in args else args.extend(over[i:i + 2])
    if over[0] not in BASE:
        args += over
    assert post_task.main(args) == 2
    assert f"field {field}" in capsys.readouterr().out


# --- posting and following (no real bus) ------------------------------------------------------------------------------

def args_for(**over):
    from types import SimpleNamespace

    a = dict(store="", agent="sb-test-coordinator", bus="", ca="")
    a.update(over)
    return SimpleNamespace(**a)


def test_connect_says_what_is_missing(tmp_path, monkeypatch):
    for k in ("SB_BUS_STORE", "SB_BUS_URL", "SB_BUS_CA"):
        monkeypatch.delenv(k, raising=False)
    assert post_task.connect(args_for()) == "no credential store: --store, or SB_BUS_STORE"

    class Store:
        def __init__(self, folder):
            pass

        def load(self, agent):
            if agent != "sb-test-coordinator":
                raise LookupError(agent)
            return {"secret": "s"}

    monkeypatch.setattr(post_task.creds, "Store", Store)
    assert post_task.connect(args_for(store=str(tmp_path), agent="someone")) == "no identity someone in that store"
    assert post_task.connect(args_for(store=str(tmp_path))).startswith("which bus?")  # no URL anywhere: no default
    bus = post_task.connect(args_for(store=str(tmp_path), bus="https://bus.example.lan", ca="ca.crt"))
    assert not isinstance(bus, str)


def reply(seq, to, kind, **body):
    return {"seq": seq, "reply_to": to, "agent_name": "host-a-host", "created_at": "2026-11-24T08:00:00Z",
            "body": json.dumps({"type": kind, **body})}


class ReplyBus:
    def __init__(self, pages):
        self.pages = list(pages)

    def read(self, channel, since, limit):
        return self.pages.pop(0) if self.pages else []


@pytest.mark.parametrize("last, code", [("finished", 0), ("failed", 1), ("timed-out", 1)])
def test_follow_prints_the_replies_and_ends_on_the_terminal_one(capsys, last, code):
    bus = ReplyBus([[reply(11, 10, "claim"), reply(12, 99, "started")],  # 12 answers another task: skipped
                    [reply(13, 10, "started", worker="test1"), reply(14, 10, last, exit_code=0)]])
    assert post_task.follow(bus, "worker-hosts-test", 10, 5, sleep=lambda s: None) == code
    out = capsys.readouterr().out
    assert "[11]" in out and "[12]" not in out and f"[14] 08:00:00 host-a-host: {last}" in out


def test_follow_gives_up_at_the_time_limit(capsys, monkeypatch):
    clock = iter([0, 0, 1000, 1000])
    monkeypatch.setattr(post_task.time, "time", lambda: next(clock))
    assert post_task.follow(ReplyBus([[reply(11, 10, "started")]]), "c", 10, 1, sleep=lambda s: None) == 0
    assert "stopped following" in capsys.readouterr().out
