"""Model families (config.toml [models]): exact ids or '*' patterns, a denied list checked first, and a hot reload of
that table only. A bad edit keeps the previous models; nothing ever widens to "anything"."""
from __future__ import annotations

import json
import os
import time

import pytest

from conftest import COORD, HOST_A, FakeVault, task_body
from workerhost import models, resources
from workerhost.config import Config
from workerhost.host import Host

FAMILIES = ["claude-*", "gpt-*", "gemini-*", "grok-*", "mai-code-*", "hydrafusion*"]


# --- the rule --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("model", [
    "claude-opus-5.5", "claude-fable-5.2", "claude-haiku-5.5",   # a family covers models released after the edit
    "gpt-6.2-astra", "gpt-6.1-sol", "gpt-5.3-codex",
    "gemini-4-argon", "grok-4.7", "mai-code-2-flash", "hydrafusion", "hydrafusion-max",
])
def test_a_family_allows_its_members(model):
    assert models.is_allowed(model, FAMILIES)


@pytest.mark.parametrize("model", [
    "qwen2.5-32b",              # local self-hosted: no family covers it
    "llama-4",
    "claude",                   # "claude-*" needs the dash
    "Claude-Opus-5.5",          # ids are lowercase
    "--yolo", "-claude-opus",   # a flag is never a model
    "claude-opus-5.5 --yolo", "claude-*", "claude-opus;rm", "",
    None, 5, ["claude-opus-5.5"],
])
def test_anything_else_is_refused(model):
    assert not models.is_allowed(model, FAMILIES)


def test_denied_wins_over_allowed():
    assert not models.is_allowed("hydrafusion-max", FAMILIES, denied=["hydrafusion*"])
    assert not models.is_allowed("gpt-5.5", FAMILIES, denied=["gpt-5.5"])
    assert models.is_allowed("gpt-5.6-sol", FAMILIES, denied=["gpt-5.5"])


def test_an_exact_list_still_works():
    assert models.is_allowed("gpt-5.5", ["claude-opus-5.5", "gpt-5.5"])
    assert not models.is_allowed("gpt-5.6", ["claude-opus-5.5", "gpt-5.5"])


# --- the table -------------------------------------------------------------------------------------------------

def test_parse_defaults_and_families():
    m = models.parse({"default": "claude-opus-5.5", "allowed": FAMILIES, "denied": ["hydrafusion*"]})
    assert m.default == "claude-opus-5.5" and m.allowed == tuple(FAMILIES) and m.denied == ("hydrafusion*",)
    assert models.parse(None) == models.Models("claude-opus-5.5", ("claude-opus-5.5",))


@pytest.mark.parametrize("pattern", ["claude-*", "gpt-*", "gemini-*", "mai-code-*", "hydrafusion*", "gro*",
                                     "claude-opus-5.5", "gpt-6.2-astra", "o3"])
def test_good_patterns(pattern):
    assert models.pattern_ok(pattern)


@pytest.mark.parametrize("pattern", [
    "*", "c*", "g*", "0*", "gp*",          # near-universal: a family needs a 3+ character prefix (sec-agent, 26475)
    "cla*de", "claude-*-5", "*-opus-*",    # one TRAILING '*' only
    "claude-**", "claude-?", "claude-[a-z]*", "Claude-*", "claude-* ", "-claude-*", "",
])
def test_bad_patterns(pattern):
    assert not models.pattern_ok(pattern)


@pytest.mark.parametrize("table,needle", [
    ({"allowed": ["*"]}, "allowed"),                               # everything, local models included: no
    ({"allowed": ["c*"]}, "allowed"),                              # near-universal
    ({"allowed": ["*-opus-*"]}, "allowed"),                        # must start with a letter or digit
    ({"allowed": ["claude-?"]}, "allowed"),                        # '*' is the only wildcard
    ({"allowed": ["claude-[a-z]*"]}, "allowed"),
    ({"allowed": ["Claude-*"]}, "allowed"),
    ({"allowed": "claude-*"}, "allowed"),                          # a list, not a string
    ({"allowed": []}, "allowed"),
    ({"allowed": ["claude-*"], "denied": ["--yolo"]}, "denied"),
    ({"default": "claude-*", "allowed": ["claude-*"]}, "default"),  # the default is one exact id
    ({"default": "gpt-6", "allowed": ["claude-*"]}, "default"),
    ({"default": "claude-opus-5.5", "allowed": ["claude-*"], "denied": ["claude-opus-*"]}, "default"),
    ({"allowed": ["claude-*"], "extra": 1}, "unknown"),
])
def test_bad_tables_are_refused(table, needle):
    with pytest.raises(ValueError, match=needle):
        models.parse(table)


# --- the host --------------------------------------------------------------------------------------------------

def write_config(home, models_toml: str) -> None:
    home.mkdir(parents=True, exist_ok=True)
    path = home / "config.toml"
    path.write_text('host_name = "alpha"\nagent_prefix = "host-alpha"\n\n[models]\n' + models_toml, encoding="utf-8")
    # A distinct mtime per write, even on a coarse clock: the reload compares (mtime_ns, size).
    t = time.time() + write_config.n
    write_config.n += 1
    os.utime(path, (t, t))


write_config.n = 0


@pytest.fixture
def host(tmp_path, shared_bus, monkeypatch):
    monkeypatch.setattr(resources, "sample", lambda root: resources.Sample(
        100 * resources.GB, 10 * resources.GB, 100 * resources.GB, 128 * resources.GB, 500 * resources.GB, set()))
    home = tmp_path / "home"
    write_config(home, 'default = "claude-opus-5.5"\nallowed = ["claude-opus-5.5"]\n')
    cfg = Config(host_name="alpha", agent_prefix="host-alpha", poll_seconds=0, settle_seconds=0,
                 workers_root=tmp_path / "w", repos={"app-core": "acme/app-core"},
                 allowed_models=["claude-opus-5.5"], home=home,
                 hosts=[{"agent_name": HOST_A.agent_name, "agent_id": HOST_A.agent_id}])
    h = Host(cfg, bus=shared_bus.client(HOST_A), vault=FakeVault())
    h.bus.calls = []
    h.bus.call = lambda method, path, body=None: h.bus.calls.append((method, path)) or {}
    h.pins = {"coordinator": COORD, "host": HOST_A}
    h.st.data["cursor"] = 0
    h.started = []
    h.start = lambda p, session_id=None: h.started.append(p.task["task_id"])
    return h


def host_log(h) -> str:
    return "".join(p.read_text(encoding="utf-8") for p in h.cfg.logs_dir.glob("host-*.log"))


def refused_field(h, shared_bus, model) -> str | None:
    """Post a task asking for `model`; the refusal's field, or None when the host claimed it."""
    shared_bus.append(COORD, "question", json.dumps(task_body(model=model)))
    shared_bus.messages[-1]["created_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    h.poll()
    body = h.bus.posts[-1]["body"]
    h.bus.posts.clear()
    return body.get("field") if body.get("type") == "refuse" else None


def test_a_new_model_is_refused_then_allowed_after_a_reload_with_no_restart(host, shared_bus):
    assert refused_field(host, shared_bus, "claude-fable-5.2") == "model"
    write_config(host.cfg.home, f'default = "claude-opus-5.5"\nallowed = {json.dumps(FAMILIES)}\n')
    host.reload_models()
    assert host.cfg.allowed_models == FAMILIES
    assert "models-reloaded" in host_log(host)
    assert any("models=claude-*,gpt-*" in str(p["body"]) for p in host.bus.posts)  # the heartbeat carries the list
    host.bus.posts.clear()
    body = dict(task_body(model="claude-fable-5.2"), task_id="7a2d3c0f-5e4b-4c9f-8a31-2b3c4d5e6f70", worker="core15")
    shared_bus.append(COORD, "question", json.dumps(body))
    shared_bus.messages[-1]["created_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    host.poll()
    assert [p["body"].get("type") for p in host.bus.posts] != ["refuse"]
    assert "7a2d3c0f-5e4b-4c9f-8a31-2b3c4d5e6f70" in host.pending


def test_a_bad_edit_keeps_the_previous_models(host):
    write_config(host.cfg.home, 'default = "claude-opus-5.5"\nallowed = ["c*"]\n')
    host.reload_models()
    assert host.cfg.allowed_models == ["claude-opus-5.5"]
    write_config(host.cfg.home, 'default = "claude-opus-5.5"\nallowed = ["claude-*"\n')   # broken TOML
    host.reload_models()
    assert host.cfg.allowed_models == ["claude-opus-5.5"]
    assert host_log(host).count("models-reload-failed") == 2


def test_only_models_is_reloaded(host):
    write_config(host.cfg.home, 'default = "claude-opus-5.5"\nallowed = ["claude-*"]\n')
    (host.cfg.home / "config.toml").write_text(
        'host_name = "changed"\nagent_prefix = "host-alpha"\nmax_task_age_hours = 99\n\n[models]\nallowed = ["claude-*"]\n',
        encoding="utf-8")
    os.utime(host.cfg.home / "config.toml", (time.time() + 100, time.time() + 100))
    host.reload_models()
    assert host.cfg.allowed_models == ["claude-*"]
    assert host.cfg.host_name == "alpha" and host.cfg.max_task_age_hours == 2.0


def test_an_unchanged_file_is_not_reread(host, monkeypatch):
    calls = []
    monkeypatch.setattr(models, "read", lambda p: calls.append(p))
    host.reload_models()
    host.reload_models()
    assert calls == []


def test_a_narrowed_list_drops_a_set_model_choice(host):
    write_config(host.cfg.home, f'default = "claude-opus-5.5"\nallowed = {json.dumps(FAMILIES)}\n')
    host.reload_models()
    host.st.data["default_model"] = "gpt-6.2-astra"
    assert host.default_model() == "gpt-6.2-astra"
    write_config(host.cfg.home, 'default = "claude-opus-5.5"\nallowed = ["claude-*"]\ndenied = ["gpt-*"]\n')
    host.reload_models()
    assert host.default_model() == "claude-opus-5.5"


def audits(h) -> list[str]:
    return [text for channel, kind, text in h.bus.channel_posts if channel == models.AUDIT_CHANNEL]


def test_a_reload_is_audited_on_the_security_channel(host):
    write_config(host.cfg.home, 'default = "claude-opus-5.5"\nallowed = ["claude-*", "gpt-*"]\n')
    host.reload_models()
    [text] = audits(host)
    sha = models.file_sha256(host.cfg.home / "config.toml")
    assert text.startswith("models-reloaded host=alpha sha256=" + sha)
    assert "old: default=claude-opus-5.5 allowed=claude-opus-5.5 denied=-" in text
    assert "new: default=claude-opus-5.5 allowed=claude-*,gpt-* denied=-" in text
    assert ("PUT", "/api/subscriptions/security") in host.bus.calls


def test_a_failed_reload_is_audited_too(host):
    write_config(host.cfg.home, 'default = "claude-opus-5.5"\nallowed = ["c*"]\n')
    host.reload_models()
    [text] = audits(host)
    assert text.startswith("models-reload-failed host=alpha") and "kept: default=claude-opus-5.5" in text


def test_an_unaudited_change_is_never_silent(host):
    host.bus.fail_channels.add(models.AUDIT_CHANNEL)
    write_config(host.cfg.home, 'default = "claude-opus-5.5"\nallowed = ["claude-*"]\n')
    host.reload_models()
    assert audits(host) == []
    assert any(c == host.cfg.channel and t.startswith("models-reloaded") for c, k, t in host.bus.channel_posts)
    assert "models-audit-failed" in host_log(host)


def test_a_list_changed_while_stopped_is_audited_at_start(host):
    host.check_models_at_start()                      # the first start with this code records the list
    assert audits(host)[-1].startswith("models-loaded host=alpha")
    host.check_models_at_start()                      # unchanged: nothing more
    assert len(audits(host)) == 1
    host.cfg.allowed_models = ["claude-*", "grok-*"]  # as if config.toml was edited and the host restarted
    host.check_models_at_start()
    assert audits(host)[-1].startswith("models-changed-at-start host=alpha")
    assert "new: default=claude-opus-5.5 allowed=claude-*,grok-*" in audits(host)[-1]


def test_the_template_defaults_are_the_three_relied_on_providers():
    import re
    import tomllib
    from pathlib import Path
    from workerhost import sitefile
    root = Path(__file__).resolve().parent.parent
    text = (root / "config.template.toml").read_text(encoding="utf-8")
    for k, v in sitefile.load(root / "site.example.toml").items():
        text = text.replace(k, v)
    m = models.parse(tomllib.loads(re.sub(r"@[A-Z_]+@", "1", text))["models"])
    assert m.allowed == ("claude-*", "gpt-*", "gemini-*") and m.denied == ()


def test_denied_refuses_a_task(host, shared_bus):
    write_config(host.cfg.home, f'default = "claude-opus-5.5"\nallowed = {json.dumps(FAMILIES)}\n'
                                f'denied = ["hydrafusion*"]\n')
    host.reload_models()
    host.bus.posts.clear()
    assert refused_field(host, shared_bus, "hydrafusion-max") == "model"
