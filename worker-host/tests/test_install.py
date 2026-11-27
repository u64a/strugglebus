"""install.ps1, without installing anything: the capacity it picks and the task each logon mode defines.

The script is dot-sourced, which defines its pure functions and stops before any action; the task
definition is checked as the Task Scheduler XML it would register. Nothing is registered.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
INSTALL = ROOT / "install.ps1"
NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
PWSH = shutil.which("pwsh")

pytestmark = pytest.mark.skipif(PWSH is None, reason="PowerShell 7 (pwsh) is not installed")

APP = r"C:\Users\alice\AppData\Local\strugglebus-worker-host\app"
ARGS = rf'"{APP}\wh.py" --home "C:\Users\alice\AppData\Local\strugglebus-worker-host" supervise'

DRIVER = r"""
$ErrorActionPreference = 'Stop'
. '@INSTALL@'
$out = [ordered]@{
  capacity = [ordered]@{}
  logon = Set-LogonLine (Get-Content -Raw '@TEMPLATE@') 'Interactive'
  logon_missing = Set-LogonLine "host_name = 'a'`nchannel = 'worker-hosts'`n`n[models]`ndefault = 'x'`n" 'Interactive'
  pyver = [ordered]@{}
  copilot_alias = Select-CopilotExe 'C:\Users\x\AppData\Local\Microsoft\WindowsApps\copilot.exe' 'C:\Users\x\AppData\Local\Microsoft\WinGet\Links\copilot.exe' $true
  copilot_alias_nolink = Select-CopilotExe 'C:\Users\x\AppData\Local\Microsoft\WindowsApps\copilot.exe' 'C:\Users\x\AppData\Local\Microsoft\WinGet\Links\copilot.exe' $false
  copilot_plain = Select-CopilotExe 'C:\Tools\copilot.exe' 'C:\Users\x\AppData\Local\Microsoft\WinGet\Links\copilot.exe' $true
  copilot_line = Set-CopilotLine (Get-Content -Raw '@TEMPLATE@') 'C:\Users\x\AppData\Local\Microsoft\WinGet\Links\copilot.exe'
  prefix_line = Set-AgentPrefixLine ((Get-Content -Raw '@TEMPLATE@').Replace('@AGENT_PREFIX@', 'sb-host-dev128')) 'host-box1'
  prefix_missing = Set-AgentPrefixLine "host_name = 'a'`nchannel = 'worker-hosts'`n`n[models]`ndefault = 'x'`n" 'host-box1'
  prefix_single = Set-AgentPrefixLine "host_name = 'a'`nagent_prefix = 'old-prefix'`n`n[models]`ndefault = 'x'`n" 'host-box1'
  prefix_default = [ordered]@{}
  prefix_bad_throws = $false
  task_args = Get-HostTaskArguments 'C:\Users\x\AppData\Local\strugglebus-worker-host\app' 'C:\Users\x\AppData\Local\strugglebus-worker-host'
  password = New-HostTaskXml -Mode Password -UserId 'DEV128\alice' -Command 'C:\Py & Co\python.exe' -Arguments '@ARGS@' -WorkingDirectory '@APP@'
  interactive = New-HostTaskXml -Mode Interactive -UserId 'S-1-12-1-1-2-3-4' -Command 'C:\Py & Co\python.exe' -Arguments '@ARGS@' -WorkingDirectory '@APP@'
}
foreach ($gb in 128, 96, 64, 63.7, 32) { $out.capacity["$gb"] = Get-Capacity $gb }
foreach ($v in 'Python 3.11.9', 'Python 3.12.1', 'Python 4.0.0', 'Python 3.10.11', 'Python 2.7.18', '', 'python: not found') { $out.pyver[$v] = [bool](Test-PythonVersion $v) }
foreach ($h in 'box1', 'dev128', 'a-very-long-machine-name-indeed-x') { $out.prefix_default[$h] = Get-DefaultAgentPrefix $h }
$out.prefix_ok = @(foreach ($p in 'host-box1', 'coord', 'Host-box1', 'a', '-x', 'host_box1', "host-box1`n", ('h' * 32)) { [bool](Test-AgentPrefix $p) })
try { Set-AgentPrefixLine "agent_prefix = `"x`"`n" 'Bad Prefix' | Out-Null } catch { $out.prefix_bad_throws = $true }
$out.signers = @(Get-SignerList (Get-Content -Raw '@SIGNERS@'))
$out.pinned_path = Get-PinnedSignersPath
$tpl = Get-Content -Raw '@TEMPLATE@'
$out.engines_block = Get-EnginesBlock $tpl
$out.engine_added = Set-EngineDefault "host_name = 'a'`n`n[models]`ndefault = 'x'`n`n[remotes]`nallowed = []`n" 'claude' $tpl
$out.engine_changed = Set-EngineDefault "host_name = 'a'`n`n[engines]`ndefault = `"ghcp`"`n`n[engines.claude]`nexe = `"claude`"`ndefault = `"keep`"`n" 'claude' $tpl
$out.engine_nodefault = Set-EngineDefault "[engines]`n`n[engines.claude]`nexe = `"c`"`n" 'ghcp' $tpl
$out.task_line = Set-TaskNameLine $tpl 'StrugglebusWorkerHost-sbworker'
$out.task_line_missing = Set-TaskNameLine "host_name = 'a'`n`n[models]`ndefault = 'x'`n" 'StrugglebusWorkerHost-sbworker'
$out.panel = Get-PanelLaunch 'C:\Nowhere\python.exe' 'C:\h\app' 'C:\h'
$out.panel_lnk = Get-PanelShortcutPath
$out | ConvertTo-Json -Depth 4
"""


SIGNERS = ROOT / "tests" / "data" / "allowed_signers"  # throwaway test keys; a site's own list is its deployment's


@pytest.fixture(scope="module")
def ps(tmp_path_factory):
    script = tmp_path_factory.mktemp("install") / "driver.ps1"
    text = (DRIVER.replace("@INSTALL@", str(INSTALL)).replace("@TEMPLATE@", str(ROOT / "config.template.toml"))
            .replace("@ARGS@", ARGS.replace("'", "''")).replace("@APP@", APP)
            .replace("@SIGNERS@", str(SIGNERS)))
    script.write_text(text, encoding="utf-8")
    r = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(script)], capture_output=True,
                       text=True, timeout=120, stdin=subprocess.DEVNULL)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def task(xml: str) -> ET.Element:
    return ET.fromstring(xml.split("?>", 1)[1])


def text(root: ET.Element, path: str) -> str | None:
    node = root.find(path, NS)
    return None if node is None else node.text


@pytest.mark.parametrize("gb,workers,commit", [("128", 12, 8), ("96", 12, 8), ("64", 6, 8), ("63.7", 6, 8)])
def test_capacity_for_alice_machines(ps, gb, workers, commit):
    cap = ps["capacity"][gb]
    assert (cap["MaxWorkers"], cap["WorkerCommitGb"]) == (workers, commit)


def test_other_memory_sizes_fall_back_to_editing_the_config(ps):
    assert ps["capacity"]["32"]["Profile"] == "other" and ps["capacity"]["32"]["MaxWorkers"] == 2


def test_logon_mode_is_written_to_the_config(ps):
    assert '\nlogon_type = "Interactive"' in ps["logon"] and '\nlogon_type = "Password"' not in ps["logon"]


def test_logon_mode_is_added_to_an_older_config_as_a_top_level_key(ps):
    import tomllib

    raw = tomllib.loads(ps["logon_missing"])
    assert raw["logon_type"] == "Interactive" and "logon_type" not in raw["models"]


def test_a_second_hosts_task_name_goes_into_its_config_at_the_top_level(ps):
    """The DevBox's sbworker host beside devhost01's: wh start/stop and the status use scheduled_task."""
    import tomllib

    assert tomllib.loads(ps["task_line_missing"])["scheduled_task"] == "StrugglebusWorkerHost-sbworker"
    tpl = ps["task_line"].replace("\r\n", "\n")  # the template, placeholders and all: not TOML until filled in
    assert tpl.count("scheduled_task =") == 1 and '\nscheduled_task = "StrugglebusWorkerHost-sbworker"\n' in tpl
    assert tpl.index("scheduled_task =") < tpl.index("\n[")  # top level, before the first table


def test_agent_prefix_line_replaces_or_adds_a_top_level_key(ps):
    """A re-run with -AgentPrefix changes an existing config; an older config gets the key at the top level."""
    import tomllib

    line = ps["prefix_line"].replace("\r\n", "\n")
    assert '\nagent_prefix = "host-box1"\n' in line and "sb-host-dev128" not in line
    raw = tomllib.loads(ps["prefix_missing"])
    assert raw["agent_prefix"] == "host-box1" and "agent_prefix" not in raw["models"]
    assert tomllib.loads(ps["prefix_single"])["agent_prefix"] == "host-box1"  # replaced, not duplicated
    assert ps["prefix_bad_throws"] is True


def test_engines_block_comes_from_the_template(ps):
    block = ps["engines_block"]
    assert block.startswith("[engines]\n") or block.startswith("[engines]\r\n")
    assert "[engines.claude]" in block and 'default = "@DEFAULT_ENGINE@"' in block and "[remotes]" not in block


def test_default_engine_is_added_to_an_older_config(ps):
    import tomllib
    from workerhost import engines
    raw = tomllib.loads(ps["engine_added"])
    assert raw["engines"]["default"] == "claude" and raw["remotes"] == {"allowed": []}
    assert engines.parse(raw["engines"]).claude is not None


def test_default_engine_changes_only_the_engines_table(ps):
    import tomllib
    raw = tomllib.loads(ps["engine_changed"])
    assert raw["engines"]["default"] == "claude"
    assert raw["engines"]["claude"]["default"] == "keep"  # a key of the same name in [engines.claude] is untouched
    assert tomllib.loads(ps["engine_nodefault"])["engines"]["default"] == "ghcp"


def test_agent_prefix_default_and_pattern(ps):
    assert ps["prefix_default"] == {"box1": "sb-host-box1", "dev128": "sb-host-dev128",
                                    "a-very-long-machine-name-indeed-x": "sb-host-a-very-long-machine-nam"}
    # host-box1, coord, Host-box1, a, -x, host_box1, "host-box1\n", 32 x h
    assert ps["prefix_ok"] == [True, True, False, False, False, False, False, False]


def test_installer_says_the_prefix_must_be_the_spn_name():
    source = INSTALL.read_text(encoding="utf-8")
    assert "[string]$AgentPrefix = ''" in source
    assert "MUST equal the name of the SPN" in source
    assert "'@AGENT_PREFIX@' = $AgentPrefix" in source


def common(root: ET.Element) -> None:
    s = "t:Settings/t:"
    assert text(root, s + "RestartOnFailure/t:Interval") == "PT1M"
    assert text(root, s + "RestartOnFailure/t:Count") == "999"
    assert text(root, s + "ExecutionTimeLimit") == "PT0S"
    assert text(root, s + "MultipleInstancesPolicy") == "IgnoreNew"
    # Never true: Windows would stop the host on any network drop and not start it again until a reboot.
    assert text(root, s + "RunOnlyIfNetworkAvailable") == "false"
    assert text(root, s + "DisallowStartIfOnBatteries") == "false"
    assert text(root, s + "Enabled") == "false"  # disabled until `wh start`
    assert text(root, "t:Principals/t:Principal/t:RunLevel") == "LeastPrivilege"
    assert text(root, "t:Actions/t:Exec/t:Command") == r"C:\Py & Co\python.exe"
    assert text(root, "t:Actions/t:Exec/t:Arguments") == ARGS
    assert text(root, "t:Actions/t:Exec/t:WorkingDirectory") == APP
    assert root.find(".//t:Password", NS) is None


def test_password_mode_task(ps):
    root = task(ps["password"])
    common(root)
    assert text(root, "t:Principals/t:Principal/t:LogonType") == "Password"
    assert text(root, "t:Principals/t:Principal/t:UserId") == r"DEV128\alice"
    assert text(root, "t:Triggers/t:BootTrigger/t:Delay") == "PT2M"
    assert root.find("t:Triggers/t:LogonTrigger", NS) is None


def test_interactive_mode_task(ps):
    root = task(ps["interactive"])
    common(root)
    assert text(root, "t:Principals/t:Principal/t:LogonType") == "InteractiveToken"
    assert text(root, "t:Principals/t:Principal/t:UserId") == "S-1-12-1-1-2-3-4"
    assert text(root, "t:Triggers/t:LogonTrigger/t:UserId") == "S-1-12-1-1-2-3-4"
    assert root.find("t:Triggers/t:BootTrigger", NS) is None


def test_interactive_registration_stores_no_password():
    source = INSTALL.read_text(encoding="utf-8")
    interactive = source.split("if ($Logon -eq 'Interactive') {", 1)[1].split("\n}\n", 1)[0]
    assert "Register-ScheduledTask -TaskName $TaskName -Xml $xml -Force" in interactive
    assert "Get-TaskCredential" not in interactive and "-Password" not in interactive
    assert "Invoke-Wh @('probe')" in interactive  # the probe runs in this session


def test_copilot_prefers_the_winget_link_over_the_windowsapps_alias(ps):
    """The app-execution alias refuses to run under a scheduled task or SSH ("Access is denied")."""
    link = r"C:\Users\x\AppData\Local\Microsoft\WinGet\Links\copilot.exe"
    assert ps["copilot_alias"] == link
    assert ps["copilot_alias_nolink"] == r"C:\Users\x\AppData\Local\Microsoft\WindowsApps\copilot.exe"
    assert ps["copilot_plain"] == r"C:\Tools\copilot.exe"
    assert f"\ncopilot_exe = '{link}'\n" in ps["copilot_line"] and "@COPILOT_EXE@" not in ps["copilot_line"]


def test_task_account_is_the_identity_name_not_userdomain():
    """WORKGROUP\\user (from $env:USERDOMAIN on a workgroup machine) has no SID; the identity's own
    name does. Seen on the first dev-machine install."""
    source = INSTALL.read_text(encoding="utf-8")
    body = source.split("function Get-TaskCredential {", 1)[1].split("\n}\n", 1)[0]
    code = [l for l in body.splitlines() if not l.strip().startswith("#")]
    assert any("WindowsIdentity]::GetCurrent().Name" in l for l in code)
    assert not any("USERDOMAIN" in l for l in code)


def test_owner_only_acl_is_granted_on_the_folder_and_inherited_by_its_contents():
    """icacls /grant (OI)(CI) with /T gives files an inherit-only entry, which is no access at all:
    the second install on the dev machine could not overwrite its own files."""
    source = INSTALL.read_text(encoding="utf-8")
    grants = [l for l in source.splitlines() if "icacls" in l and "/grant:r" in l]
    assert grants and all("/T" not in l for l in grants)
    assert any("icacls" in l and "/reset /T" in l for l in source.splitlines())


def test_python_version_is_read_from_the_banner_only(ps):
    """Get-Python runs `python --version` and nothing else: the first install hung with python
    reading a script from stdin. The banner check is the pure part."""
    assert ps["pyver"] == {"Python 3.11.9": True, "Python 3.12.1": True, "Python 4.0.0": True,
                           "Python 3.10.11": False, "Python 2.7.18": False, "": False, "python: not found": False}
    source = INSTALL.read_text(encoding="utf-8")
    body = source.split("function Get-Python {", 1)[1].split("\n}\n", 1)[0]
    assert "--version" in body and "-c" not in body and "import" not in body
    native = [l for l in body.splitlines() if "--version" in l and not l.strip().startswith("#")]
    assert native and all("|" not in l for l in native)  # a -First stage after python leaves $LASTEXITCODE stale

def test_scheduled_task_runs_the_supervisor(ps):
    """Issue #16: the task action is `wh.py supervise`, which restarts a crashed host; Task Scheduler's
    own RestartOnFailure only covers a task that fails to launch."""
    app = r"C:\Users\x\AppData\Local\strugglebus-worker-host\app"
    home = r"C:\Users\x\AppData\Local\strugglebus-worker-host"
    assert ps["task_args"] == f'"{app}\\wh.py" --home "{home}" supervise'
    source = INSTALL.read_text(encoding="utf-8")
    assert "$runArgs = Get-HostTaskArguments $App $HostHome" in source


def test_pin_signers_shows_the_same_fingerprints_as_the_host(ps):
    from workerhost import signing

    # install.ps1 -PinSigners and the host read the same file the same way (tests/data/allowed_signers: throwaway keys).
    expected = [(s.fingerprint, s.comment) for s in signing.read_signers(SIGNERS)]
    assert [(s["Fingerprint"], s["Comment"]) for s in ps["signers"]] == expected and len(expected) == 2
    assert all(s["Namespaces"] == "strugglebus-fleet,strugglebus-baseline,strugglebus-release" for s in ps["signers"])
    assert ps["pinned_path"].lower().endswith(r"\strugglebus\allowed_signers")


def test_pin_signers_needs_elevation_and_a_typed_yes():
    text = INSTALL.read_text(encoding="utf-8")
    block = text[text.index("if ($PinSigners) {"):text.index("# --- install ---")]
    assert "IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)" in block
    assert "-cne 'yes'" in block and "WriteAllBytes" in block
    assert "*S-1-5-32-545:(OI)(CI)RX" in block and "/setowner '*S-1-5-32-544'" in block  # users read only


def test_the_status_window_starts_at_sign_in_without_a_console(ps):
    # no pythonw.exe beside a python.exe that does not exist: falls back to python.exe itself
    assert ps["panel"]["Exe"] == r"C:\Nowhere\python.exe"
    assert ps["panel"]["Arguments"] == r'"C:\h\app\wh.py" --home "C:\h" panel'
    assert ps["panel_lnk"].endswith(r"\Startup\Strugglebus host.lnk")
    text = INSTALL.read_text(encoding="utf-8")
    assert "if (-not $NoPanel) {" in text and "Remove-Item -Force $lnk" in text
