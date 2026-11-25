"""Multi-project hosts, part 2 (docs/agent-host-build.md 7.1, 7.3, 7.4).

A task's repository may be a full clone URL, checked against its coordinator's signed `repos` AND this host's own
[remotes] fence. Briefs come from the sending coordinator's notes repository. The worker's preamble names its project,
coordinator and notes channel and carries the project's signed rules; notes are read from that channel; every
variable is SB_*. Before the first signed fleet, nothing changes.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import BRIEF, COORD, FakeVault, message, task_body

from workerhost import config, fleet, launcher, prompt, urls
from workerhost.config import INSTALL_DIR
from workerhost.validate import Pin, Policy, validate_task

SANDBOX = "https://github.com/acme/strugglebus-sandbox"
TEST = Pin("ed917e32-a978-490b-abfa-ac71e8cf0423", "sb-test-coordinator")


class Untouchable:
    """The legacy vault, for a fleet coordinator: reading it would mean the brief came from the wrong repository."""

    def __getattr__(self, name):
        raise AssertionError(f"the legacy vault was used ({name})")


def fleet_policy(**over) -> Policy:
    values = dict(vault=FakeVault(), project="test", coordinator_name=TEST.agent_name, notes_channel="worker-hosts-test",
                  repos=(SANDBOX,), legacy=False)
    values.update(over)
    return Policy(**values)


def from_fleet(ctx, **policies):
    """ctx with the given coordinators (by agent_name) as fleet.toml coordinators."""
    pins = {COORD.agent_name: COORD, TEST.agent_name: TEST}
    ctx.coordinators = [pins[name] for name in policies]
    ctx.policy = lambda pin: policies.get(pin.agent_name)
    ctx.vault = Untouchable()
    return ctx


# --- 7.1 / 7.3: the repository -------------------------------------------------------------------------------

def test_before_the_first_signed_fleet_short_names_work_and_urls_are_refused(ctx):
    d = validate_task(message(task_body()), ctx)
    assert d.accepted and d.repo_url == "https://github.com/acme/app-core"
    assert d.policy.legacy and d.policy.project == "default" and d.policy.notes_channel == "worker-hosts"
    d = validate_task(message(task_body(repo="https://github.com/acme/app-core")), ctx)
    assert (d.action, d.field) == ("refuse", "repo")


def test_a_fleet_coordinator_names_its_repository_by_url(ctx):
    pol = fleet_policy()
    from_fleet(ctx, **{TEST.agent_name: pol})
    d = validate_task(message(task_body(repo=SANDBOX + ".git"), sender=TEST), ctx)
    assert d.accepted, (d.reason, d.field)
    assert d.repo_url == SANDBOX and d.policy is pol and d.coordinator == TEST
    assert "fetch" in pol.vault.calls  # the brief came from this coordinator's notes repository


@pytest.mark.parametrize("repo", [
    "https://github.com/acme/app-core",          # a real repository, but not one this coordinator may use
    "http://github.com/acme/strugglebus-sandbox",      # not https
    "https://github.com/acme/strugglebus-sandbox/x",   # not exactly /<owner>/<repo>
    "https://user@github.com/acme/strugglebus-sandbox",
    "https://github.com:443/acme/strugglebus-sandbox",
    "https://GitHub.com/acme/strugglebus-sandbox",
    "https://github.com/acme/strugglebus-sandbox?x=1",
    "https://github.com/acme/strugglebus-sandbox#x",
    "git@github.com:acme/strugglebus-sandbox.git",
    "ssh://git@github.com/acme/strugglebus-sandbox",
    "file:///C:/repos/strugglebus-sandbox",
    "ext::sh -c calc",
    "https://github.com/acme/..",
    "https://github.com/acme/strugglebus-sandbox ",
    "app-core",                                          # a short name outside this coordinator's repos
    42,
])
def test_a_repository_outside_the_rules_is_refused(ctx, repo):
    from_fleet(ctx, **{TEST.agent_name: fleet_policy()})
    d = validate_task(message(task_body(repo=repo), sender=TEST), ctx)
    assert (d.action, d.reason, d.field) == ("refuse", "shape", "repo")


def test_the_hosts_own_fence_wins_over_a_signed_mistake(ctx):
    vault = FakeVault()
    from_fleet(ctx, **{TEST.agent_name: fleet_policy(vault=vault, repos=("https://evil.example/", "https://github.com/"))})
    ctx.remotes = ["https://github.com/acme-labs/"]
    for repo in ("https://evil.example/o/r", "https://github.com/acme-labs-evil/r", "https://github.com/acme/r"):
        d = validate_task(message(task_body(repo=repo), sender=TEST), ctx)
        assert (d.action, d.field) == ("refuse", "repo"), repo
    d = validate_task(message(task_body(repo="https://github.com/acme-labs/r"), sender=TEST), ctx)
    assert d.accepted and d.repo_url == "https://github.com/acme-labs/r"


def test_a_short_name_from_a_fleet_coordinator_must_be_inside_its_repos(ctx):
    app = fleet_policy(project="app", coordinator_name=COORD.agent_name, notes_channel="Notes",
                            repos=("https://github.com/acme/",))
    from_fleet(ctx, **{COORD.agent_name: app, TEST.agent_name: fleet_policy()})
    d = validate_task(message(task_body()), ctx)
    assert d.accepted and d.repo_url == "https://github.com/acme/app-core"
    d = validate_task(message(task_body(task_id="7f1c2b9e-4d3a-4b8e-9f20-1a2b3c4d5e6f"), sender=TEST), ctx)
    assert (d.action, d.field) == ("refuse", "repo")


def test_each_coordinators_briefs_come_from_its_own_notes_repository(ctx):
    no_brief = FakeVault(files={})
    from_fleet(ctx, **{TEST.agent_name: fleet_policy(vault=no_brief)})
    d = validate_task(message(task_body(repo=SANDBOX), sender=TEST), ctx)
    assert (d.action, d.reason, d.field) == ("refuse", "brief", "brief")
    assert no_brief.calls[0] == "fetch"


@pytest.mark.parametrize("project_default, given, expected", [
    (True, None, True), (False, None, False), (False, True, True), (True, False, False)])
def test_repo_instructions_default_comes_from_the_project(ctx, project_default, given, expected):
    from_fleet(ctx, **{TEST.agent_name: fleet_policy(repo_instructions=project_default)})
    body = task_body(repo=SANDBOX) if given is None else task_body(repo=SANDBOX, repo_instructions=given)
    d = validate_task(message(body, sender=TEST), ctx)
    assert d.accepted and d.task["repo_instructions"] is expected


def test_a_coordinator_with_no_policy_is_ignored_like_a_stranger(ctx):
    ctx.coordinators = [TEST]
    ctx.policy = lambda pin: None
    assert validate_task(message(task_body(repo=SANDBOX), sender=TEST), ctx).reason == "sender"


# --- 7.4: the worker's preamble -----------------------------------------------------------------------------

def test_a_fleet_projects_preamble_names_it_and_carries_its_signed_rules():
    rules = "Only touch files under hello/.\nThe text {busclient} here stays literal."
    text = prompt.build_prompt("BRIEF", r"C:\wh\bus.py", None, fleet_policy(worker_rules=rules, vault=None))
    assert text.startswith("You are a worker for the test project, run by sb-test-coordinator for the owner")
    assert 'post <agent> worker-hosts-test status' in text and "@sb-test-coordinator" in text
    assert "SB_BUS_CA and SB_BUS_STORE" in text and "Notes" not in text
    assert "Project rules (test, from the signed fleet list" in text
    assert "The text {busclient} here stays literal." in text  # rules are substituted last, never expanded
    assert "Your brief is your whole task" in text and "never push to develop, main or master" in text
    assert text.index("Project rules") < text.index("Task follows.") and text.endswith("----\nBRIEF")
    bare = prompt.build_prompt("BRIEF", "b", None, fleet_policy(vault=None))
    assert "Project rules" not in bare


def test_the_legacy_coordinator_gets_the_same_preamble_from_config_values():
    # No separate Notes preamble any more: a coordinator pinned in config.toml gets the one preamble, filled from
    # [coordinator] project, notes_channel and owner.
    legacy = Policy(vault=None, project="tools", coordinator_name="coord-a", notes_channel="tools-notes", owner="Sam")
    text = prompt.build_prompt("BRIEF", "b", None, legacy)
    assert text.startswith("You are a worker for the tools project, run by coord-a for Sam")
    assert "post <agent> tools-notes status" in text and "Notes" not in text


def test_a_brief_is_measured_with_its_projects_rules():
    export = str(Path(INSTALL_DIR.parent / "vault-export") / ("0" * 40))
    plain = fleet_policy(vault=None)
    base = len(subprocess.list2cmdline(prompt.command("copilot.exe", prompt.build_prompt("", "b", export, plain),
                                                      "x" * 64, "0" * 36, False, export, False)))
    brief = "y" * (prompt.MAX_COMMAND_LINE - base - 100)
    assert prompt.fits(brief, "b", project=plain)
    assert not prompt.fits(brief, "b", project=fleet_policy(vault=None, worker_rules="r" * fleet.MAX_RULES))


# --- fleet.toml: the two new keys -----------------------------------------------------------------------------

COORD_TOML = """serial = 3

[[coordinator]]
agent_name = "sb-test-coordinator"
agent_id = "ed917e32-a978-490b-abfa-ac71e8cf0423"
project = "test"
notes_repo = "https://github.com/acme/strugglebus-sandbox"
notes_channel = "worker-hosts-test"
repos = ["https://github.com/acme/strugglebus-sandbox"]
"""


def test_fleet_entries_carry_repo_instructions_and_worker_rules():
    c = fleet.parse(COORD_TOML.encode()).coordinators[0]
    assert c.repo_instructions is True and c.worker_rules == ""
    f = fleet.parse((COORD_TOML + 'repo_instructions = false\nworker_rules = """\nRule one.\nRule two.\n"""\n').encode())
    c = f.coordinators[0]
    assert c.repo_instructions is False and c.worker_rules == "Rule one.\nRule two." and f.ignored_keys == ()


@pytest.mark.parametrize("extra, where", [
    ('repo_instructions = "false"', "repo_instructions"),
    ("repo_instructions = 0", "repo_instructions"),
    ("worker_rules = 5", "worker_rules"),
    ('worker_rules = "' + "r" * (4000 + 1) + '"', "worker_rules"),
    ('worker_rules = "bell \\u0007 here"', "worker_rules"),
    ('worker_rules = "escape \\u001b[31m"', "worker_rules"),
])
def test_bad_new_keys_make_the_file_invalid(extra, where):
    with pytest.raises(fleet.FleetError) as e:
        fleet.parse((COORD_TOML + extra + "\n").encode())
    assert e.value.reason == "fleet-invalid" and e.value.detail.endswith(where)


# --- config.toml: [remotes] -----------------------------------------------------------------------------------

def test_remotes_come_from_the_site_file_and_are_checked(tmp_path, monkeypatch):
    import tomllib

    from test_config import SITE, fill

    monkeypatch.setenv("WORKERHOST_HOME", str(tmp_path))
    cfg = config.load(fill(tmp_path))
    assert cfg.remotes == tomllib.loads(SITE.read_text(encoding="utf-8"))["remotes"]
    text = (tmp_path / "config.toml").read_text(encoding="utf-8")
    start, end = text.index("[remotes]"), text.index("[repos]")
    for bad in ('allowed = ["https://github.com/acme/app-core"]',  # a repository, not a prefix
                'allowed = ["http://github.com/acme-labs/"]', "allowed = []", 'other = ["https://github.com/"]'):
        (tmp_path / "config.toml").write_text(text[:start] + "[remotes]\n" + bad + "\n\n" + text[end:], encoding="utf-8")
        with pytest.raises(ValueError):
            config.load(tmp_path / "config.toml")
    good = 'allowed = ["https://git.example.lan/"]'
    (tmp_path / "config.toml").write_text(text[:start] + "[remotes]\n" + good + "\n\n" + text[end:], encoding="utf-8")
    assert config.load(tmp_path / "config.toml").remotes == ["https://git.example.lan/"]


def test_each_notes_repository_has_its_own_mirror_and_app_keeps_the_old_one(tmp_path):
    cfg = config.Config(host_name="h", agent_prefix="p-x", home=tmp_path, vault_repo="acme/team-notes")
    assert cfg.notes_vault_dir("https://github.com/acme/team-notes") == cfg.vault_dir
    assert cfg.notes_vault_dir(SANDBOX + ".git") == tmp_path / "vaults" / "github.com--acme--strugglebus-sandbox.git"


# --- launching -------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("url, tool", [(SANDBOX, "gh"), ("https://git.example.lan/alice/tool", "git")])
def test_a_new_clone_uses_gh_for_github_and_git_elsewhere(tmp_path, monkeypatch, url, tool):
    calls = []

    def run(cmd, **kw):
        calls.append((cmd, kw.get("env", {})))
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    monkeypatch.setattr(launcher.subprocess, "run", run)
    launcher.prepare_clone(tmp_path, "w1", url, "test/x", "gh", "git")
    cmd, env = calls[0]
    clone = str(tmp_path / "w1")
    if tool == "gh":
        assert cmd == ["gh", "repo", "clone", url, clone, "--", "-q"]
    else:
        assert cmd == ["git", "clone", "-q", "--", url, clone]  # "--": a URL can never be read as an option
    assert env["GIT_TERMINAL_PROMPT"] == "0"


@pytest.mark.parametrize("origin, repo, same", [
    ("https://github.com/acme/strugglebus-sandbox.git\n", SANDBOX, True),
    ("https://github.com/ACME/strugglebus-sandbox/", SANDBOX, True),
    ("https://github.com/acme/strugglebus-sandbox.git", "acme/strugglebus-sandbox", True),
    ("https://github.com/acme/app-core.git", SANDBOX, False),
    ("https://github.com/acme/strugglebus-sandbox-2.git", SANDBOX, False),
    ("https://git.example.lan/acme/strugglebus-sandbox", SANDBOX, False),
])
def test_an_existing_clone_must_be_of_the_same_repository(origin, repo, same):
    assert launcher._origin_matches(origin, repo) is same


def test_worker_variables_are_set_as_sb_names_only_and_never_inherited(tmp_path):
    base = {"PATH": "p", "SB_NOTES_CHANNEL": "Notes", "SB_TASK_SEQ": "1", "SB_PROJECT": "other"}
    env = launcher.worker_env(base, bus_ca="ca", bus_url="u", store=tmp_path, temp=tmp_path, gh_exe="gh",
                              wait_timeout=1, task_seq=77, coordinator=TEST, notes_channel="worker-hosts-test",
                              project="test")
    for name, value in (("BUS_CA", "ca"), ("BUS_URL", "u"), ("TASK_SEQ", "77"), ("COORDINATOR_ID", TEST.agent_id),
                        ("COORDINATOR_NAME", TEST.agent_name), ("NOTES_CHANNEL", "worker-hosts-test"),
                        ("PROJECT", "test")):
        assert env["SB_" + name] == value
    bare = launcher.worker_env(base, bus_ca="ca", bus_url="u", store=tmp_path, temp=tmp_path, gh_exe="gh",
                               wait_timeout=1)
    assert not {"SB_NOTES_CHANNEL", "SB_TASK_SEQ", "SB_PROJECT"} & set(bare)


# --- the host -------------------------------------------------------------------------------------------------

def make_host(tmp_path, fleet_obj=None, required=False):
    from workerhost import host as host_mod

    h = object.__new__(host_mod.Host)
    h.cfg = config.Config(host_name="h", agent_prefix="p-x", home=tmp_path, vault_repo="acme/team-notes")
    h.vault = SimpleNamespace(name="legacy")
    h.vaults = {}
    h.fleet, h.fleet_required = fleet_obj, required
    return h


def test_the_host_gives_each_coordinator_its_own_project(tmp_path):
    entry = "\n" + 'repo_instructions = false\nworker_rules = "Sandbox only."\n'
    f = fleet.parse((COORD_TOML + entry).encode())
    h = make_host(tmp_path, f, required=True)
    pol = h.policy_for(TEST)
    assert (pol.project, pol.coordinator_name, pol.notes_channel, pol.repos, pol.repo_instructions, pol.worker_rules,
            pol.legacy) == ("test", TEST.agent_name, "worker-hosts-test", (SANDBOX,), False, "Sandbox only.", False)
    assert pol.vault is h.policy_for(TEST).vault and pol.vault is not h.vault  # one mirror per notes repository
    assert pol.vault.path == tmp_path / "vaults" / "github.com--acme--strugglebus-sandbox.git"
    assert h.policy_for(COORD) is None  # not in this fleet
    assert make_host(tmp_path, None, required=True).policy_for(COORD) is None  # fail closed
    legacy = make_host(tmp_path).policy_for(COORD)
    assert legacy.legacy and legacy.vault is not None and legacy.vault.name == "legacy"
    assert (legacy.project, legacy.notes_channel, legacy.owner) == ("default", "worker-hosts", "")


def test_the_fleets_owner_reaches_every_coordinators_policy(tmp_path):
    f = fleet.parse(('owner = "Sam O\'Neil"\n' + COORD_TOML).encode())
    assert f.owner == "Sam O'Neil" and "owner" not in f.ignored_keys
    assert make_host(tmp_path, f, required=True).policy_for(TEST).owner == "Sam O'Neil"


@pytest.mark.parametrize("owner", ['"{rules}"', '"a\\nb"', '"-x"', "3", '"' + "a" * 41 + '"'])
def test_an_owner_that_is_not_a_plain_name_makes_the_fleet_invalid(owner):
    with pytest.raises(fleet.FleetError, match="owner"):
        fleet.parse((f"owner = {owner}\n" + COORD_TOML).encode())


def test_a_app_fleet_entry_reuses_the_existing_app_notes_mirror(tmp_path):
    text = COORD_TOML.replace("strugglebus-sandbox", "team-notes", 1)
    h = make_host(tmp_path, fleet.parse(text.encode()), required=True)
    assert h.policy_for(TEST).vault is h.vault


def test_host_start_runs_a_fleet_task_as_its_project(tmp_path, monkeypatch):
    from workerhost import host as host_mod

    calls, posts, channels = {}, [], []

    def fake_build(*args):
        calls["build"] = args
        return ["copilot"]

    def fake_env(base, **kw):
        calls["env"] = kw
        raise launcher.LaunchError("stop-here")

    def fake_clone(root, worker, repo, *a, **k):
        calls["repo"] = repo
        return tmp_path

    monkeypatch.setattr(launcher, "prepare_clone", fake_clone)
    monkeypatch.setattr(launcher, "write_meta", lambda clone, meta: calls.setdefault("meta", meta))
    monkeypatch.setattr(launcher, "build", fake_build)
    monkeypatch.setattr(launcher, "worker_env", fake_env)
    h = object.__new__(host_mod.Host)
    h.cfg = SimpleNamespace(workers_root=tmp_path, worker_agent=lambda w: "p-" + w, repos={}, gh_exe="gh",
                            git_exe="git", export_dir=tmp_path / "x", copilot_exe="copilot", bus_ca="ca",
                            bus_url="u", creds_dir=tmp_path, busclient_path=tmp_path / "bus.py",
                            runtime=SimpleNamespace(task_wait_timeout_seconds=1))
    h.vault = Untouchable()
    h.ensure_identity = lambda agent: None
    h.ensure_channel = lambda agent, channel, record=None: channels.append((agent, channel))
    h.default_model = lambda: "m"
    h.log = lambda *a, **k: None
    h.st = SimpleNamespace(data={"tasks": {}}, set_task=lambda *a, **k: None, mark_terminal=lambda *a, **k: None)
    pol = fleet_policy(vault=SimpleNamespace(referenced_files=lambda *a: []), worker_rules="Sandbox only.")
    task = {"worker": "w1", "task_id": "t1", "repo": SANDBOX, "branch": "b", "vault_commit": "d" * 40, "brief": BRIEF}
    session = SimpleNamespace(post=lambda kind, **k: posts.append((kind, k)))
    h.start(SimpleNamespace(task=task, session=session, resume=False, brief=SimpleNamespace(text="B", blob_sha="c" * 40),
                            msg_seq=9, coordinator=TEST, policy=pol, repo_url=SANDBOX))
    assert calls["repo"] == SANDBOX and calls["meta"]["project"] == "test" and calls["meta"]["repo"] == SANDBOX
    assert calls["build"][8] is pol  # the preamble is this project's
    assert calls["env"]["notes_channel"] == "worker-hosts-test" and calls["env"]["project"] == "test"
    assert channels == [("p-w1", "worker-hosts-test")]  # subscribed before it is told to post there
    kinds = {kind: k for kind, k in posts}
    assert kinds["started"]["project"] == "test" and kinds["failed"]["project"] == "test"
