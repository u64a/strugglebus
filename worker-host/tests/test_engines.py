"""Worker engines (docs/agent-host-build.md 7.6): Copilot (`ghcp`) and Claude Code (`claude`) - config, the task's
`engine` field, the Claude Code command line, resume and usage."""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from conftest import BRIEF, message, task_body
from workerhost import engines
from workerhost.validate import validate_task

CLAUDE = engines.Claude()


# --- config --------------------------------------------------------------------------------------------------

def test_no_engines_table_is_copilot_only():
    assert engines.parse(None) == engines.Engines("ghcp", None)


def test_claude_table_with_defaults():
    e = engines.parse({"default": "ghcp", "claude": {}})
    assert e.default == "ghcp" and e.claude == engines.Claude()
    assert e.claude.allows("opus") and e.claude.allows("claude-opus-5-5") and not e.claude.allows("gpt-6.1-sol")


@pytest.mark.parametrize("table,needle", [
    ({"default": "codex"}, "engines.default"),
    ({"default": "claude"}, "needs an \\[engines.claude\\]"),
    ({"extra": 1}, "unknown keys in \\[engines\\]"),
    ({"claude": {"model": "opus"}}, "unknown keys in \\[engines.claude\\]"),
    ({"claude": {"allowed": ["*"]}}, "engines.claude"),
    ({"claude": {"default_model": "gpt-5", "allowed": ["claude-*"]}}, "engines.claude"),
    ({"claude": {"exe": ""}}, "exe"),
    ({"claude": "yes"}, "must be a table"),
])
def test_bad_engine_tables_are_refused(table, needle):
    with pytest.raises(ValueError, match=needle):
        engines.parse(table)


def test_the_template_ships_copilot_as_default_with_claude_configured():
    import re
    import tomllib
    from workerhost import sitefile
    root = Path(__file__).resolve().parent.parent
    text = (root / "config.template.toml").read_text(encoding="utf-8")
    for k, v in sitefile.load(root / "site.example.toml").items():
        text = text.replace(k, v)
    raw = tomllib.loads(re.sub(r"@[A-Z_]+@", "1", text).replace('default = "1"', 'default = "ghcp"'))
    e = engines.parse(raw["engines"])
    assert e.default == "ghcp" and e.claude is not None


# --- the Claude Code command ---------------------------------------------------------------------------------

def test_the_claude_command_line():
    cmd = engines.claude_command(r"C:\bin\claude.exe", "opus", "0" * 8 + "-0000-0000-0000-" + "0" * 12, False,
                                 r"C:\wh\app", r"C:\wh\vault-export\abc")
    assert cmd[:2] == [r"C:\bin\claude.exe", "-p"]
    assert cmd[cmd.index("--output-format") + 1] == "stream-json" and "--verbose" in cmd
    assert cmd[cmd.index("--model") + 1] == "opus"
    assert cmd[cmd.index("--permission-mode") + 1] == "acceptEdits"
    assert cmd[cmd.index("--allowedTools") + 1] == "Bash,WebFetch,WebSearch"
    # No settings source at all: a repository's .claude/settings*.json must never act (sec-agent, PR #91 review;
    # proven live: "project,local" let a planted settings.local.json env value into the worker's shell).
    assert cmd[cmd.index("--setting-sources") + 1] == "" and "--strict-mcp-config" in cmd
    assert "--settings" not in cmd
    assert [cmd[i + 1] for i, a in enumerate(cmd) if a == "--add-dir"] == [r"C:\wh\app", r"C:\wh\vault-export\abc"]
    assert cmd[-2:] == ["--session-id", "0" * 8 + "-0000-0000-0000-" + "0" * 12]


def test_never_bypasses_permissions_and_never_carries_the_prompt():
    for resume in (False, True):
        cmd = engines.claude_command("claude.exe", "sonnet", "s", resume, "app")
        joined = " ".join(cmd).lower()
        assert "dangerously" not in joined and "bypasspermissions" not in joined
        assert "task follows" not in joined
    assert engines.claude_command("claude.exe", "opus", "sid", True, "app")[-2:] == ["--resume", "sid"]


def test_build_claude_puts_the_prompt_on_stdin_with_the_repo_note(monkeypatch, tmp_path):
    from workerhost import launcher
    exe = tmp_path / "claude.exe"
    exe.write_bytes(b"")
    cmd, prompt = launcher.build_claude(str(exe), "Do it.\n", "bus.py", "opus", "sid", False, None, True)
    assert prompt.endswith("Task follows.\n----\nDo it.\n") and engines.CLAUDE_REPO_NOTE in prompt
    assert "Do it." not in " ".join(cmd)
    _, prompt_off = launcher.build_claude(str(exe), "Do it.\n", "bus.py", "opus", "sid", False, None, False)
    assert engines.CLAUDE_REPO_NOTE not in prompt_off
    with pytest.raises(launcher.LaunchError, match="claude-missing"):
        launcher.build_claude(str(tmp_path / "nope.exe"), "x", "b", "opus", "s", False)


def test_a_cmd_wrapper_is_never_an_engine(tmp_path):
    wrapper = tmp_path / "claude.cmd"
    wrapper.write_text("@echo off")
    assert engines.resolve(str(wrapper)) is None


# --- availability --------------------------------------------------------------------------------------------

def test_available_needs_claude_configured_installed_and_signed_in(tmp_path):
    copilot = tmp_path / "copilot.exe"
    claude = tmp_path / "claude.exe"
    copilot.write_bytes(b"")
    claude.write_bytes(b"")
    home = tmp_path / "home"
    eng = engines.Engines("ghcp", engines.Claude(exe=str(claude)))
    assert engines.available(str(copilot), eng, home) == ["ghcp"]           # not signed in
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / ".credentials.json").write_text("{}")
    assert engines.available(str(copilot), eng, home) == ["ghcp", "claude"]
    assert engines.available(str(copilot), engines.Engines(), home) == ["ghcp"]  # not configured
    assert engines.available(str(tmp_path / "gone.exe"), eng, home) == ["claude"]


# --- resume --------------------------------------------------------------------------------------------------

def test_a_claude_session_resumes_only_in_its_own_clone(tmp_path):
    home, clone = tmp_path / "home", tmp_path / "w" / "core14"
    clone.mkdir(parents=True)
    sid = "11111111-2222-3333-4444-555555555555"
    folder = home / ".claude" / "projects" / "C--w-core14"
    folder.mkdir(parents=True)
    (folder / f"{sid}.jsonl").write_text(json.dumps({"type": "summary"}) + "\n"
                                         + json.dumps({"type": "user", "cwd": str(clone)}) + "\n")
    assert engines.claude_session_ok(sid, clone, home)
    assert not engines.claude_session_ok(sid, tmp_path / "w" / "core15", home)
    assert not engines.claude_session_ok("99999999-2222-3333-4444-555555555555", clone, home)


# --- usage ---------------------------------------------------------------------------------------------------

def result(usd, turns=3, model="claude-opus-5-5"):
    return json.dumps({"type": "result", "subtype": "success", "total_cost_usd": usd, "num_turns": turns,
                       "usage": {"input_tokens": 10, "cache_read_input_tokens": 90, "output_tokens": 5},
                       "modelUsage": {model: {"costUSD": usd}}}) + "\n"


def test_usage_is_read_from_this_tasks_part_of_the_log_only(tmp_path):
    from workerhost import launcher
    log = tmp_path / "core14.log"
    log.write_text(launcher.header({"seq": 1, "task_id": "A", "engine": "claude"}) + result(9.0)
                   + launcher.header({"seq": 2, "task_id": "B", "engine": "claude"}) + '{"type":"assistant"}\n'
                   + result(1.25, 7) + launcher.header({"seq": 3, "task_id": "C", "engine": "ghcp"}) + "text\n",
                   encoding="utf-8")
    u = engines.read_claude_usage(log, "B")
    assert u == {"usd": 1.25, "calls": 7, "input_tokens": 100, "output_tokens": 5,
                 "by_model_usd": {"claude-opus-5-5": 1.25}, "model_observed": "claude-opus-5-5"}
    assert engines.read_claude_usage(log, "A")["usd"] == 9.0
    assert engines.read_claude_usage(log, "C") is None
    assert engines.read_claude_usage(tmp_path / "missing.log", "B") is None


# --- the host launches the right engine ----------------------------------------------------------------------

def start_host(tmp_path, monkeypatch, task_engine, default_engine="ghcp"):
    """Drive Host.start with fakes up to the launch; return what was launched and posted."""
    from types import SimpleNamespace
    from workerhost import host as host_mod, launcher
    exe = tmp_path / "claude.exe"
    exe.write_bytes(b"")
    seen, posts, state = {}, [], {}
    monkeypatch.setattr(launcher, "prepare_clone", lambda root, worker, repo, *a, **k: tmp_path)
    monkeypatch.setattr(launcher, "write_meta", lambda clone, meta: None)
    monkeypatch.setattr(launcher, "build", lambda *a: seen.setdefault("ghcp", ["copilot.exe", "-p", "PROMPT"]))

    def fake_launch(cmd, clone, env, log, temp, worker, task_id, head, job=None, stdin_text=None):
        seen.update(cmd=cmd, env=env, stdin=stdin_text, head=head)
        raise launcher.LaunchError("stop-here")
    monkeypatch.setattr(launcher, "launch", fake_launch)
    h = object.__new__(host_mod.Host)
    h.cfg = SimpleNamespace(workers_root=tmp_path, worker_agent=lambda w: "p-" + w, repos={}, gh_exe="gh",
                            git_exe="git", export_dir=tmp_path / "x", copilot_exe="copilot", bus_ca="ca",
                            bus_url="u", creds_dir=tmp_path, busclient_path=tmp_path / "bus.py", host_name="alpha",
                            runtime=SimpleNamespace(task_wait_timeout_seconds=1), default_engine=default_engine,
                            claude=engines.Claude(exe=str(exe)))
    h.vault = SimpleNamespace(referenced_files=lambda *a: [])
    h.ensure_identity = lambda agent: None
    h.ensure_channel = lambda agent, channel, record=None: None
    h.default_model = lambda: "claude-opus-5.5"
    h.log = lambda *a, **k: None
    h.ghcp_version = "1.0"
    h.openbao = None
    h.st = SimpleNamespace(data={"tasks": {}}, set_task=lambda tid, **k: state.update(k),
                           mark_terminal=lambda *a, **k: None)
    task = {"worker": "w1", "task_id": "t1", "repo": "https://github.com/o/r", "branch": "b", "vault_commit": "d" * 40,
            "brief": BRIEF}
    if task_engine:
        task["engine"] = task_engine
    h.start(SimpleNamespace(task=task, session=SimpleNamespace(post=lambda kind, **k: posts.append((kind, k))),
                            resume=False, brief=SimpleNamespace(text="Do the thing.\n", blob_sha="c" * 40),
                            msg_seq=9, coordinator=None, policy=None, repo_url="https://github.com/o/r"))
    return seen, dict(posts), state


def test_a_claude_task_launches_claude_code_with_the_prompt_on_stdin(tmp_path, monkeypatch):
    seen, posts, state = start_host(tmp_path, monkeypatch, "claude")
    assert seen["cmd"][0].endswith("claude.exe") and seen["cmd"][1] == "-p"
    assert seen["cmd"][seen["cmd"].index("--model") + 1] == "opus"        # Claude Code's own default model
    assert seen["stdin"].endswith("Task follows.\n----\nDo the thing.\n")
    assert "Do the thing." not in " ".join(seen["cmd"])
    assert seen["env"]["DISABLE_AUTOUPDATER"] == "1"
    assert "engine=claude" in seen["head"]
    assert posts["started"]["engine"] == "claude" and posts["started"]["model"] == "opus"
    assert state["engine"] == "claude"


def test_the_host_default_engine_applies_and_copilot_is_unchanged(tmp_path, monkeypatch):
    seen, posts, _ = start_host(tmp_path, monkeypatch, None, default_engine="claude")
    assert seen["cmd"][0].endswith("claude.exe") and posts["started"]["engine"] == "claude"
    seen, posts, _ = start_host(tmp_path, monkeypatch, None)
    assert seen["cmd"] == ["copilot.exe", "-p", "PROMPT"] and seen["stdin"] is None
    assert "DISABLE_AUTOUPDATER" not in seen["env"] and posts["started"]["engine"] == "ghcp"


def test_claude_usage_reaches_the_finished_envelope(tmp_path):
    from types import SimpleNamespace
    from workerhost import host as host_mod, launcher
    log = tmp_path / "w1.log"
    log.write_text(launcher.header({"seq": 9, "task_id": "t1", "engine": "claude"}) + result(2.5, 4), encoding="utf-8")
    h = object.__new__(host_mod.Host)
    h.st = SimpleNamespace(data={"tasks": {"t1": {"engine": "claude", "log": str(log), "session_id": "s"}}})
    h.log = lambda *a, **k: None
    spent = h.read_spent("t1")
    assert spent == {"usd": 2.5, "calls": 4, "by_model_usd": {"claude-opus-5-5": 2.5},
                     "model_observed": "claude-opus-5-5"}
    assert "aic" not in spent


def test_the_heartbeat_names_the_account_the_host_runs_as(tmp_path, monkeypatch, shared_bus):
    from conftest import COORD, HOST_A, FakeVault
    from workerhost import resources
    from workerhost.config import Config
    from workerhost.host import Host
    monkeypatch.setattr(resources, "sample", lambda root: None)
    monkeypatch.setenv("USERNAME", "sbworker")
    cfg = Config(host_name="alpha", agent_prefix="host-alpha", workers_root=tmp_path / "w", home=tmp_path / "home",
                 allowed_models=["claude-opus-5.5"])
    h = Host(cfg, bus=shared_bus.client(HOST_A), vault=FakeVault())
    line = h.heartbeat_line()
    assert line.startswith("host=alpha state=") and " release=manual user=sbworker" in line


# --- the task's engine field ---------------------------------------------------------------------------------

@pytest.fixture
def both(ctx):
    return dataclasses.replace(ctx, engines=("ghcp", "claude"), claude=CLAUDE)


def test_no_engine_field_uses_the_host_default(both):
    d = validate_task(message(task_body()), both)
    assert d.accepted and d.task["engine"] == "ghcp"
    d = validate_task(message(task_body(model=...)), dataclasses.replace(both, default_engine="claude"))
    assert d.accepted and d.task["engine"] == "claude"


def test_a_claude_task_is_checked_against_claude_models(both):
    assert validate_task(message(task_body(engine="claude", model="opus")), both).accepted
    assert validate_task(message(task_body(engine="claude", model="claude-opus-5-5")), both).accepted
    d = validate_task(message(task_body(engine="claude", model="gpt-6.1-sol")), both)
    assert (d.action, d.reason, d.field) == ("refuse", "shape", "model")
    d = validate_task(message(task_body(engine="ghcp", model="opus")), both)   # not a Copilot id
    assert (d.action, d.field) == ("refuse", "model")


@pytest.mark.parametrize("engine", ["codex", "", "CLAUDE", 1, None, ["claude"]])
def test_a_bad_engine_value_is_a_shape_error(both, engine):
    d = validate_task(message(task_body(engine=engine)), both)
    assert (d.action, d.reason, d.field) == ("refuse", "shape", "engine")


def test_an_engine_this_host_lacks_is_refused_as_engine(ctx):
    d = validate_task(message(task_body(engine="claude", model="opus")), ctx)  # ctx: Copilot only
    assert (d.action, d.reason, d.field) == ("refuse", "engine", "engine")
    no_copilot = dataclasses.replace(ctx, engines=("claude",), claude=CLAUDE)
    d = validate_task(message(task_body()), no_copilot)  # default ghcp, which is gone
    assert (d.action, d.reason) == ("refuse", "engine")


def test_claude_is_not_held_to_the_command_line_limit(both):
    tight = dataclasses.replace(both, fits_command_line=lambda text, policy=None: False)
    assert validate_task(message(task_body(engine="claude", model="opus")), tight).accepted
    d = validate_task(message(task_body()), tight)
    assert (d.action, d.reason) == ("refuse", "brief")
