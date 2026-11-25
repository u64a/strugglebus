"""The shipped config template loads once install.ps1 has filled it in, with the agreed defaults."""
from __future__ import annotations

from pathlib import Path

import pytest

from workerhost import config

TEMPLATE = Path(__file__).resolve().parent.parent / "config.template.toml"


SITE = Path(__file__).resolve().parent / "data" / "site.toml"


def fill(tmp_path: Path, max_workers: int = 12, extra: str = "", commit_gb: int = 8) -> Path:
    """The template as install.ps1 fills it for a new host, with the test site (tests/data/site.toml)."""
    from workerhost import sitefile

    text = TEMPLATE.read_text(encoding="utf-8")
    values = {"@HOST_NAME@": "dev128", "@AGENT_PREFIX@": "host-box1", "@WORKERS_ROOT@": str(tmp_path / "w"),
              "@BUS_CA@": "C:\\ca.crt",
              "@COPILOT_EXE@": "C:\\copilot.exe", "@GH_EXE@": "gh", "@GIT_EXE@": "git",
              "@PYTHON_EXE@": "C:\\py\\python.exe", "@MAX_WORKERS@": str(max_workers),
              "@WORKER_COMMIT_GB@": str(commit_gb), "@DEFAULT_ENGINE@": "ghcp"}
    for key, value in {**values, **sitefile.load(SITE)}.items():
        text = text.replace(key, value)
    path = tmp_path / "config.toml"
    path.write_text(text + extra, encoding="utf-8")
    return path


def test_template_has_no_unfilled_placeholders_after_install(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKERHOST_HOME", str(tmp_path))
    import re

    assert re.findall(r"@[A-Z_]+@", fill(tmp_path).read_text(encoding="utf-8")) == []


def test_template_defaults(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKERHOST_HOME", str(tmp_path))
    cfg = config.load(fill(tmp_path))
    assert cfg.channel == "worker-hosts" and cfg.messages_mutable is False and cfg.logon_type == "Password"
    assert (cfg.resources.max_workers, cfg.resources.worker_commit_gb) == (12, 8)
    assert (cfg.heartbeat_running_minutes, cfg.heartbeat_idle_minutes) == (10, 60)
    assert cfg.pause_while_running == [] and cfg.coordinator_name == "coord-main"
    assert cfg.repos["app-core"] == "acme/app-core"
    assert cfg.home == tmp_path
    assert cfg.default_engine == "ghcp" and cfg.claude is not None and cfg.claude.default_model == "opus"


def test_an_older_config_without_engines_is_copilot_only(tmp_path, monkeypatch):
    import re
    monkeypatch.setenv("WORKERHOST_HOME", str(tmp_path))
    path = fill(tmp_path)
    text = path.read_text(encoding="utf-8")
    path.write_text(re.sub(r"(?ms)^\[engines\]\n.*?(?=^\[remotes\])", "", text), encoding="utf-8")
    cfg = config.load(path)
    assert cfg.default_engine == "ghcp" and cfg.claude is None


def test_a_claude_default_without_the_claude_table_is_refused(tmp_path, monkeypatch):
    import re
    monkeypatch.setenv("WORKERHOST_HOME", str(tmp_path))
    path = fill(tmp_path)
    text = path.read_text(encoding="utf-8").replace('default = "ghcp"', 'default = "claude"')
    path.write_text(re.sub(r"(?ms)^\[engines\.claude\]\n.*?(?=^\[remotes\])", "", text), encoding="utf-8")
    with pytest.raises(ValueError, match="engines.claude"):
        config.load(path)


def test_64gb_profile(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKERHOST_HOME", str(tmp_path))
    cfg = config.load(fill(tmp_path, max_workers=2))
    assert (cfg.resources.max_workers, cfg.resources.worker_commit_gb) == (2, 8)


@pytest.mark.parametrize("extra,message", [
    ('\nsurprise = 1\n', "unknown"),
])
def test_unknown_top_level_key_is_an_error(tmp_path, monkeypatch, extra, message):
    monkeypatch.setenv("WORKERHOST_HOME", str(tmp_path))
    text = fill(tmp_path).read_text(encoding="utf-8")
    (tmp_path / "config.toml").write_text(extra + text, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        config.load(tmp_path / "config.toml")


def test_settle_window_must_cover_two_polls(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKERHOST_HOME", str(tmp_path))
    text = fill(tmp_path).read_text(encoding="utf-8").replace("settle_seconds = 20", "settle_seconds = 5")
    (tmp_path / "config.toml").write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="settle_seconds"):
        config.load(tmp_path / "config.toml")


def test_loader_defaults_messages_immutable_when_the_key_is_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKERHOST_HOME", str(tmp_path))
    text = fill(tmp_path).read_text(encoding="utf-8").replace("messages_mutable = false\n", "")
    assert "\nmessages_mutable" not in text
    (tmp_path / "config.toml").write_text(text, encoding="utf-8")
    assert config.load(tmp_path / "config.toml").messages_mutable is False


@pytest.mark.parametrize("mode", ["Password", "Interactive"])
def test_both_logon_modes_load(tmp_path, monkeypatch, mode):
    monkeypatch.setenv("WORKERHOST_HOME", str(tmp_path))
    text = fill(tmp_path).read_text(encoding="utf-8").replace('logon_type = "Password"', f'logon_type = "{mode}"')
    (tmp_path / "config.toml").write_text(text, encoding="utf-8")
    assert config.load(tmp_path / "config.toml").logon_type == mode


def test_wh_status_shows_the_logon_mode(tmp_path, monkeypatch, capsys):
    from workerhost import cli

    monkeypatch.setenv("WORKERHOST_HOME", str(tmp_path))
    text = fill(tmp_path).read_text(encoding="utf-8").replace('logon_type = "Password"', 'logon_type = "Interactive"')
    (tmp_path / "config.toml").write_text(text, encoding="utf-8")
    cfg = config.load(tmp_path / "config.toml")
    assert cli.cmd_status(cfg, None) == 1  # not running
    assert "logon=Interactive task=StrugglebusWorkerHost" in capsys.readouterr().out


def test_agent_prefix_is_loaded_and_names_derive_from_it(tmp_path, monkeypatch):
    """The dev machine: SPN host-box1, host host-box1-host, worker core5 host-box1-core5."""
    monkeypatch.setenv("WORKERHOST_HOME", str(tmp_path))
    cfg = config.load(fill(tmp_path))
    assert cfg.agent_prefix == "host-box1"
    assert cfg.host_agent == "host-box1-host"
    assert cfg.worker_agent("core5") == "host-box1-core5"
    assert config.agent_name("coord", "core5") == "coord-core5"


def test_worker_named_host_cannot_take_the_host_identity():
    cfg = config.Config(host_name="x", agent_prefix="host-box1")
    with pytest.raises(ValueError, match="reserved"):
        cfg.worker_agent("host")


def test_longest_prefix_and_worker_fit_the_credential_store(tmp_path):
    from workerhost import creds

    agent = config.Config(host_name="x", agent_prefix="p" * 31).worker_agent("w" * 31)
    assert len(agent) == 63
    creds.Store(tmp_path)._path(agent)  # raises ValueError("bad identity name") if the store refuses it


@pytest.mark.parametrize("prefix", ["", "a", "Host-box1", "-box1", "host_box1", "host box1",
                                    "h" * 32, "host-box1\n"])
def test_bad_agent_prefix_is_refused(tmp_path, monkeypatch, prefix):
    monkeypatch.setenv("WORKERHOST_HOME", str(tmp_path))
    text = fill(tmp_path).read_text(encoding="utf-8").replace('agent_prefix = "host-box1"',
                                                             f"agent_prefix = {prefix!r}".replace("'", '"'))
    (tmp_path / "config.toml").write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="agent_prefix"):
        config.load(tmp_path / "config.toml")


def test_missing_agent_prefix_is_refused_not_defaulted(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKERHOST_HOME", str(tmp_path))
    text = fill(tmp_path).read_text(encoding="utf-8").replace('agent_prefix = "host-box1"\n', "")
    assert "\nagent_prefix" not in text
    (tmp_path / "config.toml").write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="agent_prefix missing"):
        config.load(tmp_path / "config.toml")


def test_host_launch_derives_the_worker_name_from_the_config():
    """host.py names a worker through Config.worker_agent and nowhere else."""
    source = (Path(__file__).resolve().parent.parent / "workerhost" / "host.py").read_text(encoding="utf-8")
    # Phase 2 adds a per-attempt suffix in Host.task_agent, still on top of Config.worker_agent.
    assert "stable = self.cfg.worker_agent(worker)" in source and "agent = self.task_agent(task_id, worker)" in source
    assert "coord-" not in source and "sb-host-" not in source
