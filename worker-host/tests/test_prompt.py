"""The prompt builder never interpolates a message field (design section 3, last paragraph)."""
from __future__ import annotations

import inspect
import re

import pytest

from workerhost import prompt
from workerhost.config import INSTALL_DIR


def test_build_prompt_takes_no_task_or_message():
    # `project` is the sending coordinator's policy from the signed fleet.toml, never a message field.
    # `extra_note` is fixed text from the install (engines.CLAUDE_REPO_NOTE), passed only by launcher.build_claude.
    params = list(inspect.signature(prompt.build_prompt).parameters)
    assert params == ["brief_text", "busclient", "vault_export", "project", "extra_note"]


def test_the_extra_note_is_only_ever_the_fixed_claude_repo_note():
    from pathlib import Path
    from workerhost import launcher
    root = Path(__file__).resolve().parent.parent / "workerhost"
    sites = {f.name: f.read_text(encoding="utf-8").count("build_prompt(") for f in root.glob("*.py")}
    # prompt.py: its docstring, the definition and fits(); launcher.py: build() (no note) and build_claude() (the
    # fixed note). A new call site anywhere fails here and gets looked at.
    assert {k: v for k, v in sites.items() if v} == {"prompt.py": 3, "launcher.py": 2}
    assert "extra_note" not in inspect.getsource(launcher.build)
    src = inspect.getsource(launcher.build_claude)
    assert 'engines.CLAUDE_REPO_NOTE if repo_instructions else ""' in src


def expected(busclient: str, note: str = "", owner: str = "the owner") -> str:
    """The one preamble, filled for a prompt built with no policy."""
    return (prompt.PROJECT_PREAMBLE.replace("{project}", "default").replace("{coordinator}", "the coordinator")
            .replace("{owner_s}", owner + "'s").replace("{owner}", owner).replace("{channel}", "worker-hosts")
            .replace("{busclient}", busclient).replace("{vault_export}", note).replace("{rules}", ""))


def test_prompt_is_exactly_fixed_preamble_plus_brief():
    brief = "Do the export.\n"
    p = prompt.build_prompt(brief, r"C:\wh\workerhost\busclient.py")
    assert p.endswith("Task follows.\n----\n" + brief)
    assert p == expected(r"C:\wh\workerhost\busclient.py") + brief
    assert "vault_export" not in p and "vault-export" not in p


def test_preamble_is_identical_for_every_task_and_holds_only_the_known_placeholders():
    a = prompt.build_prompt("", "B")
    b = prompt.build_prompt("", "B")
    assert a == b
    import re
    assert sorted(set(re.findall(r"\{[a-z_]+\}", prompt.PROJECT_PREAMBLE))) == [
        "{busclient}", "{channel}", "{coordinator}", "{owner_s}", "{owner}", "{project}", "{rules}", "{vault_export}"]


def test_there_is_one_preamble_and_it_names_no_one_built_in():
    # There used to be a second, single-project preamble; now every worker gets the project preamble, and the owner,
    # project, coordinator and channel come from the signed fleet (or config.toml before one), never from the code.
    assert not hasattr(prompt, "PREAMBLE")
    for placeholder in ("{owner}", "{owner_s}", "{project}", "{coordinator}", "{channel}"):
        assert placeholder in prompt.PROJECT_PREAMBLE
    assert "SB_" in prompt.PROJECT_PREAMBLE  # workers are told the SB_* names
    text = prompt.build_prompt("", "b")
    assert not re.search(r"\b[A-Z][a-z]+'s decision", text.replace("the owner's decision", ""))  # no name built in


def test_the_owner_is_named_where_merging_is_decided():
    from workerhost.validate import Policy
    p = prompt.build_prompt("B", "b", None, Policy(vault=None, project="tools", coordinator_name="coord-a",
                                                   notes_channel="tools", legacy=False, owner="Sam"))
    assert "run by coord-a for Sam and started" in p and "merging is Sam's decision alone" in p
    assert "for the owner and started" in prompt.build_prompt("B", "b")
    assert "merging is the owner's decision alone" in prompt.build_prompt("B", "b")


def test_prompt_names_the_export_folder_only_when_there_is_one():
    export = "C:\\wh\\vault-export\\" + "a" * 40
    p = prompt.build_prompt("BRIEF", "B", export)
    assert f'"{export}"' in p and "read-only" in p
    assert p == expected("B", prompt.EXPORT_NOTE.replace("{path}", export)) + "BRIEF"
    assert "{" not in p
    assert export not in prompt.build_prompt("BRIEF", "B")
    assert prompt.build_prompt("BRIEF", "B", None) == prompt.build_prompt("BRIEF", "B", "")


@pytest.fixture
def copilot(tmp_path):
    exe = tmp_path / "bin" / "copilot.exe"
    exe.parent.mkdir()
    exe.write_bytes(b"MZ")
    return str(exe)


def test_message_fields_never_reach_the_prompt(copilot):
    """Feed the whole launch path with sentinel task fields: only the brief text can appear."""
    from workerhost import launcher

    task = {"worker": "sentinel-worker", "repo": "sentinel-repo", "branch": "feature/sentinel-branch",
            "task_id": "5e471e1e-0000-4000-8000-000000000000", "brief": "tooling/briefs/sentinel-brief.txt",
            "vault_commit": "5" * 40, "host": "sentinel-host"}
    cmd = launcher.build(copilot, "BRIEF BODY", "C:/bus.py", "claude-opus-5.5",
                         "0cb916db-26aa-40f2-86b5-1ba81b225fd2", False)
    text = cmd[cmd.index("-p") + 1]
    for value in task.values():
        assert value not in text
        assert all(value not in arg for arg in cmd)
    assert text.endswith("BRIEF BODY")


def test_command_is_an_argument_list_without_a_shell_wrapper(monkeypatch, copilot):
    from workerhost import launcher

    cmd = launcher.build(copilot, "x", "b", "claude-opus-5.5", "0cb916db-26aa-40f2-86b5-1ba81b225fd2", True)
    assert cmd[1:3] == ["-p", prompt.build_prompt("x", "b")]
    assert cmd[3:9] == ["--allow-all-tools", "--no-auto-update", "--add-dir", str(INSTALL_DIR), "--model",
                        "claude-opus-5.5"]
    assert cmd[9] == "--resume=0cb916db-26aa-40f2-86b5-1ba81b225fd2"
    monkeypatch.setattr(launcher.shutil, "which", lambda name: r"C:\tools\copilot.cmd")
    try:
        launcher.build("copilot", "x", "b", "m", "0cb916db-26aa-40f2-86b5-1ba81b225fd2", False)
    except launcher.LaunchError as e:
        assert e.reason == "copilot-wrapper"  # a .cmd would put the prompt through cmd.exe
    else:
        raise AssertionError("a .cmd wrapper must be refused")


@pytest.mark.parametrize("resume", [False, True])
def test_command_adds_only_the_app_folder_for_the_bus_client(resume):
    """The bus client lives under <home>\\app, outside the clone: allow that folder, never every path."""
    cmd = prompt.command(r"C:\bin\copilot.exe", "p", "claude-opus-5.5", "0cb916db-26aa-40f2-86b5-1ba81b225fd2",
                         resume)
    i = cmd.index("--add-dir")
    assert cmd[i + 1] == str(INSTALL_DIR)
    assert cmd.count("--add-dir") == 1
    assert "--allow-all-tools" in cmd
    assert cmd[cmd.index("--model") + 1] == "claude-opus-5.5"
    assert "--allow-all" not in cmd and "--allow-all-paths" not in cmd
    assert not any(a.startswith(("--allow-all=", "--allow-all-paths", "--yolo")) for a in cmd)
    from workerhost.config import Config
    assert Config.busclient_path.fget(None).is_relative_to(INSTALL_DIR)


EXPORT = "C:\\wh\\vault-export\\" + "b" * 40
SID = "0cb916db-26aa-40f2-86b5-1ba81b225fd2"


@pytest.mark.parametrize("resume", [False, True])
@pytest.mark.parametrize("export", [None, EXPORT])
def test_a_worker_never_updates_the_cli_itself(resume, export):
    """The host owns the Copilot CLI version (winget, in its window, when no worker runs); a worker must not
    download a new one mid-task and change the version under the other workers."""
    cmd = prompt.command(r"C:\bin\copilot.exe", "p", "m", SID, resume, export)
    assert cmd.count("--no-auto-update") == 1
    assert cmd.index("--no-auto-update") > cmd.index("-p") + 1  # a flag of its own, not inside the prompt


@pytest.mark.parametrize("resume", [False, True])
@pytest.mark.parametrize("export", [None, EXPORT])
def test_repository_instructions_load_unless_the_task_turns_them_off(resume, export):
    """The coordinator decides per task ("repo_instructions"). Default: loaded (Notes's repositories hold rules
    the preamble does not, such as never writing to an assessed tenant). False: --no-custom-instructions."""
    default = prompt.command(r"C:\bin\copilot.exe", "p", "m", SID, resume, export)
    assert "--no-custom-instructions" not in default
    assert prompt.command(r"C:\bin\copilot.exe", "p", "m", SID, resume, export, True) == default
    off = prompt.command(r"C:\bin\copilot.exe", "p", "m", SID, resume, export, False)
    assert off.count("--no-custom-instructions") == 1
    assert off.index("--no-custom-instructions") > off.index("-p") + 1  # a flag of its own, not inside the prompt
    assert [a for a in off if a != "--no-custom-instructions"] == default  # nothing else changes


def test_the_preamble_keeps_a_worker_to_its_brief():
    """Some repository instructions say "take the next task in NOW.md; do not wait for the owner": not for a worker."""
    text = prompt.build_prompt("BRIEF", "b")
    assert "Your brief is your whole task" in text and "NOW.md" in text
    assert text.index("Your brief is your whole task") < text.index("Task follows.")


@pytest.mark.parametrize("resume", [False, True])
def test_command_adds_the_export_folder_exactly_when_there_is_one(resume):
    with_export = prompt.command(r"C:\bin\copilot.exe", "p", "m", SID, resume, EXPORT)
    assert with_export[3:10] == ["--allow-all-tools", "--no-auto-update", "--add-dir", str(INSTALL_DIR),
                                 "--add-dir", EXPORT, "--model"]
    assert with_export.count("--add-dir") == 2
    for none in (None, ""):
        without = prompt.command(r"C:\bin\copilot.exe", "p", "m", SID, resume, none)
        assert without == prompt.command(r"C:\bin\copilot.exe", "p", "m", SID, resume)
        assert without.count("--add-dir") == 1 and EXPORT not in without
    for cmd in (with_export, without):
        assert "--allow-all" not in cmd and "--allow-all-paths" not in cmd
        assert not any(a.startswith(("--allow-all=", "--allow-all-paths", "--yolo")) for a in cmd)


def test_launcher_build_passes_the_export_to_command_and_prompt(copilot):
    from workerhost import launcher

    cmd = launcher.build(copilot, "x", "b", "m", SID, False, EXPORT)
    assert cmd[1:3] == ["-p", prompt.build_prompt("x", "b", EXPORT)]
    assert cmd[3:] == ["--allow-all-tools", "--no-auto-update", "--add-dir", str(INSTALL_DIR), "--add-dir",
                       EXPORT, "--model", "m", f"--session-id={SID}"]
    off = launcher.build(copilot, "x", "b", "m", SID, False, EXPORT, False)
    assert off[3:6] == ["--allow-all-tools", "--no-auto-update", "--no-custom-instructions"]
    plain = launcher.build(copilot, "x", "b", "m", SID, False)
    assert plain.count("--add-dir") == 1 and all(EXPORT not in a for a in plain)


class _Brief:
    text = "See research/other.md.\n"
    blob_sha = "c" * 40


@pytest.mark.parametrize("referenced", [False, True])
def test_host_start_adds_the_export_only_when_the_task_has_one(tmp_path, monkeypatch, referenced):
    """host.start exports the pinned commit only when the brief names other vault files, and only then
    does the command get the second --add-dir (pointing at that export)."""
    from types import SimpleNamespace

    from workerhost import host as host_mod, launcher

    export = tmp_path / "vault-export" / ("d" * 40)
    calls = {}

    class Vault:
        def referenced_files(self, commit, text, brief):
            return ["research/other.md"] if referenced else []

        def export(self, commit, root):
            calls["export"] = (commit, root)
            return export

    def fake_build(*args):
        calls["build"] = args
        raise launcher.LaunchError("stop-here")

    monkeypatch.setattr(launcher, "prepare_clone", lambda *a, **k: tmp_path)
    monkeypatch.setattr(launcher, "write_meta", lambda clone, meta: calls.setdefault("meta", meta))
    monkeypatch.setattr(launcher, "build", fake_build)
    h = object.__new__(host_mod.Host)
    h.cfg = SimpleNamespace(workers_root=tmp_path, worker_agent=lambda w: "p-" + w, repos={"r": "o/r"}, gh_exe="gh",
                            git_exe="git", export_dir=tmp_path / "vault-export", copilot_exe="copilot",
                            busclient_path=tmp_path / "bus.py")
    h.vault = Vault()
    h.ensure_identity = lambda agent: None
    h.default_model = lambda: "m"
    h.log = lambda *a, **k: None
    h.st = SimpleNamespace(data={"tasks": {}}, set_task=lambda *a, **k: None, mark_terminal=lambda *a, **k: None)
    task = {"worker": "w1", "task_id": "t1", "repo": "r", "branch": "b", "vault_commit": "d" * 40,
            "brief": "tooling/briefs/x.txt"}
    session = SimpleNamespace(post=lambda *a, **k: None)
    h.start(SimpleNamespace(task=task, session=session, resume=False, brief=_Brief(), msg_seq=1))
    vault_export = calls["build"][6]
    if referenced:
        assert calls["export"] == ("d" * 40, tmp_path / "vault-export")
        assert vault_export == str(export) == calls["meta"]["vault_export"]
    else:
        assert "export" not in calls and vault_export is None and "vault_export" not in calls["meta"]


@pytest.mark.parametrize("given,expected", [(None, True), (True, True), (False, False)])
def test_host_start_passes_the_tasks_repo_instructions_choice_and_reports_it(tmp_path, monkeypatch, given, expected):
    from types import SimpleNamespace

    from workerhost import host as host_mod, launcher

    calls, posts = {}, []

    def fake_build(*args):
        calls["build"] = args
        raise launcher.LaunchError("stop-here")

    monkeypatch.setattr(launcher, "prepare_clone", lambda *a, **k: tmp_path)
    monkeypatch.setattr(launcher, "write_meta", lambda clone, meta: None)
    monkeypatch.setattr(launcher, "build", fake_build)
    h = object.__new__(host_mod.Host)
    h.cfg = SimpleNamespace(workers_root=tmp_path, worker_agent=lambda w: "p-" + w, repos={"r": "o/r"}, gh_exe="gh",
                            git_exe="git", export_dir=tmp_path / "x", copilot_exe="copilot",
                            busclient_path=tmp_path / "bus.py")
    h.vault = SimpleNamespace(referenced_files=lambda *a: [])
    h.ensure_identity = lambda agent: None
    h.default_model = lambda: "m"
    h.log = lambda *a, **k: None
    h.st = SimpleNamespace(data={"tasks": {}}, set_task=lambda *a, **k: None, mark_terminal=lambda *a, **k: None)
    task = {"worker": "w1", "task_id": "t1", "repo": "r", "branch": "b", "vault_commit": "d" * 40,
            "brief": "tooling/briefs/x.txt"}
    if given is not None:
        task["repo_instructions"] = given
    session = SimpleNamespace(post=lambda kind, **k: posts.append((kind, k)))
    h.start(SimpleNamespace(task=task, session=session, resume=False, brief=_Brief(), msg_seq=1))
    assert calls["build"][7] is expected
    started = [k for kind, k in posts if kind == "started"]
    assert started and started[0]["repo_instructions"] is expected  # the coordinator sees which way it ran


def test_oversized_brief_does_not_fit_the_command_line():
    assert prompt.fits("x" * 1000, "b")
    assert not prompt.fits("x" * 40000, "b")
    assert not prompt.fits('"' * 16000, "b")  # quoting doubles it


def test_resume_only_uses_a_session_recorded_in_this_clone(tmp_path):
    from workerhost.launcher import session_ok

    sid = "0cb916db-26aa-40f2-86b5-1ba81b225fd2"
    ws = tmp_path / ".copilot" / "session-state" / sid
    ws.mkdir(parents=True)
    clone = tmp_path / "workers" / "core14"
    (ws / "workspace.yaml").write_text(f"id: {sid}\ncwd: {clone}\n", encoding="utf-8")
    assert session_ok(sid, clone, home=tmp_path)
    assert not session_ok(sid, tmp_path / "workers" / "core9", home=tmp_path)
    assert not session_ok("../../etc", clone, home=tmp_path)


def test_copilot_is_never_a_bare_name_a_clone_could_shadow(monkeypatch, tmp_path):
    """A repository may contain copilot.exe; an unresolved name must fail, not run from the clone."""
    from workerhost import launcher

    monkeypatch.setattr(launcher.shutil, "which", lambda name: None)
    with pytest.raises(launcher.LaunchError) as e:
        launcher.build("copilot", "x", "b", "m", "0cb916db-26aa-40f2-86b5-1ba81b225fd2", False)
    assert e.value.reason == "copilot-missing"
    with pytest.raises(launcher.LaunchError):
        launcher.build(str(tmp_path / "nope" / "copilot.exe"), "x", "b", "m", "0cb916db-26aa-40f2-86b5-1ba81b225fd2",
                       False)
    monkeypatch.setattr(launcher.shutil, "which", lambda name: "copilot.exe")  # relative: refused too
    with pytest.raises(launcher.LaunchError):
        launcher.build("copilot", "x", "b", "m", "0cb916db-26aa-40f2-86b5-1ba81b225fd2", False)