"""setup\\Update-Engines.ps1: the SYSTEM task that updates the machine-wide agent programs for dedicated hosts
(#humans 29443; u64-security's conditions 29444; prox-manager's admission rule 29445). Its pure parts run in both
PowerShells; its structure is read as text, so the conditions can't quietly go."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "setup" / "Update-Engines.ps1"
BOOTSTRAP = ROOT / "tools" / "bootstrap.ps1"
PWSH, WINPS = shutil.which("pwsh"), shutil.which("powershell")
SHELLS = [s for s in (PWSH, WINPS) if s]
pytestmark = pytest.mark.skipif(not SHELLS, reason="no PowerShell")
TEXT = SCRIPT.read_text(encoding="ascii")


def run(body: str, shell: str):
    env = dict(os.environ)
    head = ""
    if shell == WINPS:
        env.pop("PSModulePath", None)  # as test_bootstrap_verify.clean_env: 5.1 started from 7
        # ...and its own security module by path: started from a PowerShell 7 process it can't autoload it (the SYSTEM
        # task starts 5.1 directly, where it loads as usual: proved on the test VM, 29 Nov).
        head = "Import-Module (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1')\n"
    driver = f"$ErrorActionPreference = 'Stop'\n{head}. '{SCRIPT}'\n{body}"
    r = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", driver], capture_output=True, text=True,
                       timeout=120, stdin=subprocess.DEVNULL, env=env)
    assert r.returncode == 0, r.stderr + r.stdout
    return json.loads(r.stdout)


@pytest.mark.parametrize("shell", SHELLS)
def test_the_window_is_the_hosts_and_fixed_in_the_script(shell):
    got = run("ConvertTo-Json @((Test-InWindow ([datetime]'2026-11-29 03:59')), (Test-InWindow ([datetime]'2026-11-29 04:00')),"
              " (Test-InWindow ([datetime]'2026-11-29 05:59')), (Test-InWindow ([datetime]'2026-11-29 06:00')))", shell)
    assert got == [False, True, True, False]
    assert "$WindowStart, $WindowEnd = '04:00', '06:00'" in TEXT and "config.toml" not in TEXT  # never a host's config


@pytest.mark.parametrize("shell", SHELLS)
def test_only_the_pinned_publisher_passes(shell):
    github = 'CN="GitHub, Inc.", O="GitHub, Inc.", L=San Francisco, S=California, C=US'
    anthropic = ('CN="Anthropic, PBC", O="Anthropic, PBC", L=San Francisco, S=California, C=US, SERIALNUMBER=4860621, '
                 'OID.2.5.4.15=Private Organization')
    got = run(f"ConvertTo-Json @((Get-PublisherProblem 'Valid' '{github}' 'GitHub, Inc.'), "
              f"(Get-PublisherProblem 'Valid' '{anthropic}' 'Anthropic, PBC'), "
              f"(Get-PublisherProblem 'Valid' '{github}' 'Anthropic, PBC'), "
              f"(Get-PublisherProblem 'Valid' 'CN=\"GitHub, Inc.\", O=\"github, inc.\"' 'GitHub, Inc.'), "
              f"(Get-PublisherProblem 'NotSigned' '{github}' 'GitHub, Inc.'), "
              f"(Get-PublisherProblem 'HashMismatch' '{github}' 'GitHub, Inc.'), "
              f"(Get-PublisherProblem 'Valid' 'CN=GitHub, Inc.' 'GitHub, Inc.'))", shell)
    assert got == [None, None, "publisher-mismatch", "publisher-mismatch", "signature-invalid", "signature-invalid",
                   "publisher-mismatch"]  # case counts; a CN without an O is no publisher
    # the pins themselves, read from the installed copies on the DevBox (28 Nov)
    assert "id = 'GitHub.Copilot'; exe = 'copilot.exe'; org = 'GitHub, Inc.'" in TEXT
    assert "id = 'Anthropic.ClaudeCode'; exe = 'claude.exe'; org = 'Anthropic, PBC'" in TEXT


# What `winget show --id GitHub.Copilot --exact --source winget` printed as SYSTEM on the test VM (29 Nov).
SHOW = """Found GitHub Copilot CLI [GitHub.Copilot]
Version: 1.0.117
Publisher: GitHub, Inc.
Publisher Url: https://github.com/home/
Moniker: copilot
"""


@pytest.mark.parametrize("shell", SHELLS)
def test_the_newest_version_comes_from_winget_show(shell, tmp_path):
    (tmp_path / "show.txt").write_text(SHOW, encoding="utf-8")
    got = run(f"ConvertTo-Json @((Get-ShowVersion (Get-Content -Raw '{tmp_path / 'show.txt'}')), "
              "(Get-ShowVersion 'No package found matching input criteria.'), (Get-ShowVersion 'Version: 1.0.117; x'))", shell)
    assert got == ["1.0.117", None, None]


@pytest.mark.parametrize("shell", SHELLS)
def test_only_a_higher_version_is_newer(shell):
    pairs = [("1.0.117", "1.0.116"), ("1.0.116", "1.0.117"), ("1.0.117", "1.0.117"), ("1.0.118-2", "1.0.118"),
             ("1.0.118", "1.0.118-2"), ("2.1.332", "2.1.40"), ("1.1", "1.0.9"), ("x", "1.0.0"), ("1.0.1", "")]
    got = run("ConvertTo-Json @(" + ", ".join(f"(Test-Newer '{a}' '{b}')" for a, b in pairs) + ")", shell)
    assert got == [True, False, False, True, False, True, True, False, False]


@pytest.mark.parametrize("shell", SHELLS)
def test_a_host_is_busy_with_a_worker_or_a_claim_and_unreadable_means_busy(shell, tmp_path):
    now = time.time()

    def host(name, status=None, raw=None, age=0):
        d = tmp_path / name / "state"
        d.mkdir(parents=True)
        f = d / "status.json"
        f.write_text(raw if raw is not None else json.dumps({"updated": now - age, **status}), encoding="utf-8")
        os.utime(f, (now - age, now - age))

    host("idle", {"workers": [], "claims": []})
    host("working", {"workers": [{"slot": "a"}], "claims": []})
    host("claimed", {"workers": [], "claims": ["t1"]})
    host("stale", {"workers": [{"slot": "a"}], "claims": []}, age=3600)  # a stopped host's last word
    host("garbled", raw="{not json")                                    # written just now, unreadable
    host("garbled-old", raw="{not json", age=3600)
    got = run(f"$b = Get-BusyHosts '{tmp_path}' {now}; ConvertTo-Json -InputObject @($b)", shell)
    assert sorted(got) == ["claimed", "garbled", "working"]


@pytest.mark.parametrize("shell", SHELLS)
def test_only_a_folder_under_the_winget_packages_root_is_touched(shell):
    got = run("ConvertTo-Json @((Get-PackageDir 'C:\\Program Files\\WinGet\\Packages\\GitHub.Copilot_x\\copilot.exe' "
              "'C:\\Program Files\\WinGet\\Packages'), (Get-PackageDir 'C:\\Users\\bob\\copilot.exe' 'C:\\Program Files\\WinGet\\Packages'), "
              "(Get-PackageDir 'C:\\Program Files\\WinGet\\Packages\\..\\x.exe' 'C:\\Program Files\\WinGet\\Packages'))", shell)
    assert got == ["C:\\Program Files\\WinGet\\Packages\\GitHub.Copilot_x", None, None]


def _function(text: str, name: str) -> str:
    start = text.index(f"function {name}")
    return text[start:text.index("\n}\n", start) + 3]


def test_the_winget_root_check_is_the_bootstraps_own():
    """Condition: the same safety check before the permission reset. Two copies, so a test keeps them identical."""
    boot = BOOTSTRAP.read_text(encoding="ascii")
    for name in ("Get-AclProblem", "Assert-WingetRootSafe"):
        assert _function(TEXT, name) == _function(boot, name), name
    for line in ("$TrustedSids = ", "$CreatorOwner = ", "$WriteRights = "):
        pick = lambda t: next(ln for ln in t.splitlines() if ln.startswith(line))  # noqa: E731
        assert pick(TEXT) == pick(boot)


def test_winget_is_called_by_full_path_with_fixed_ids_at_machine_scope():
    upgrade = _function(TEXT, "Update-OneEngine")
    assert "Invoke-Winget $winget $upArgs" in upgrade and "'--scope', 'machine'" in upgrade and "'--exact'" in upgrade
    assert "'--source', 'winget'" in upgrade  # never the msstore source
    assert "'--skip-dependencies'" in upgrade  # never a stray PowerShell MSIX beside the pinned one (the VM, 29 Nov)
    assert "'--id', $engine.id" in upgrade  # the id comes from the script's own $Engines, nothing else
    system = _function(TEXT, "Get-SystemWinget")
    assert "-AllUsers" in system and "'WindowsApps'" in system and "'Microsoft Corporation'" in system
    assert "Microsoft.VCLibs.140.00.UWPDesktop" in system  # its runtime, from WindowsApps too
    assert "$env:PATH = $vc.InstallLocation" in system and "SetEnvironmentVariable" not in TEXT  # this process only
    installed = _function(TEXT, "Get-InstalledVersion")
    assert "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" in installed  # admin-written, not the host's


def test_the_publisher_is_checked_before_the_permission_reset_and_a_failure_restores():
    upgrade = _function(TEXT, "Update-OneEngine")
    assert upgrade.index("Invoke-Robocopy $dir $backup") < upgrade.index("Invoke-Winget $winget $upArgs")
    assert upgrade.index("Get-EngineProblem $engine") < upgrade.index("Assert-WingetRootSafe") < upgrade.index("/reset")
    check = upgrade[upgrade.index("if ($problem)"):upgrade.index("Assert-WingetRootSafe")]
    assert "Restore-Engine $engine $dir" in check and "return $r" in check
    restore = _function(TEXT, "Restore-Engine")
    assert restore.index("Invoke-Robocopy $backup $dir") < restore.index("Get-EngineProblem $engine")  # checked again
    # unsafe from the first touch until checked, so an error in between leaves the marker
    assert upgrade.index("$r.safe = $false") < upgrade.index("Invoke-Winget $winget $upArgs") < upgrade.index("$r.safe = $true")


def test_admission_closes_first_and_only_a_safely_finished_run_reopens_it():
    """Fail closed (prox-manager #humans 29445/29449/29453, u64-security 29455)."""
    main = TEXT[TEXT.index("if ($MyInvocation.InvocationName -eq '.') { return }"):]
    # 1. a marker left by a dead run is recovered before anything else, at any hour
    assert main.index("if (Test-Path -LiteralPath $Marker)") < main.index("Test-InWindow")
    recovery = main[main.index("if (Test-Path -LiteralPath $Marker)"):main.index("Test-InWindow")]
    assert "Repair-AfterInterruption" in recovery and "if ($rec.safe) { Remove-Item -LiteralPath $Marker" in recovery
    # 2. the update: the marker before the idle check, and removed only when nothing was touched or all is safe
    update = main[main.index("Test-InWindow"):]
    assert update.index("Set-Marker 'waiting'") < update.index("Get-BusyHosts")
    removals = [m.start() for m in re.finditer(r"Remove-Item -LiteralPath \$Marker", update)]
    first_touch = update.index("Update-OneEngine")
    assert len(removals) == 2
    assert removals[0] < first_touch  # busy: nothing was touched
    assert update[removals[1] - 20:removals[1]].endswith("if ($safe) { ")  # every tool checked or restored
    assert "finally" not in update  # nothing reopens admission just because the run ends


def test_one_run_at_a_time_and_nothing_the_account_writes_decides():
    main = TEXT[TEXT.index("if ($MyInvocation.InvocationName -eq '.') { return }"):]
    assert main.index("'Global\\StrugglebusEngineUpdate'") < main.index("if (Test-Path -LiteralPath $Marker)")
    assert "if (-not $mutex.WaitOne(0)) { exit 0 }" in main
    # the only host file read is the busy check; never a host's config, state or control
    assert "config.toml" not in TEXT and "state\\control" not in TEXT and "state.json" not in TEXT
    boot = BOOTSTRAP.read_text(encoding="ascii")
    install = _function(boot, "Install-EngineUpdateTask")
    assert "SetSecurityDescriptor" not in install and "GRGX" not in install  # the account gets no start right


@pytest.mark.parametrize("shell", SHELLS)
def test_a_start_outside_the_window_with_no_interrupted_marker_does_nothing(shell, tmp_path):
    here = tmp_path / "engine-update"
    here.mkdir()
    script = tmp_path / "copy.ps1"
    # the real script, pointed at a scratch folder and a window that has already closed
    text = TEXT.replace("$Here = Join-Path $SbRoot 'engine-update'", f"$Here = '{here}'") \
               .replace("$WindowStart, $WindowEnd = '04:00', '06:00'", "$WindowStart, $WindowEnd = '00:00', '00:00'") \
               .replace("'Global\\StrugglebusEngineUpdate'", "'Global\\StrugglebusEngineUpdateTest'")
    script.write_text(text, encoding="ascii")
    r = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-File", str(script)], capture_output=True, text=True,
                       timeout=120)
    assert r.returncode == 0, r.stderr
    assert list(here.iterdir()) == []  # wrote nothing


def test_recovery_waits_for_installers_and_checks_every_tool():
    rec = _function(TEXT, "Repair-AfterInterruption")
    assert "Get-Process -Name $InstallerProcesses" in rec and "safe = $false" in rec  # still installing: later
    assert "foreach ($e in $Engines)" in rec and "Get-EngineProblem $e" in rec and "Restore-Engine $e $dir" in rec
    assert "$InstallerProcesses = @('winget', 'WindowsPackageManagerServer')" in TEXT


@pytest.mark.parametrize("shell", SHELLS)
def test_a_winget_call_that_overruns_is_killed_and_the_heartbeat_beats_meanwhile(shell, tmp_path):
    marker = tmp_path / "updating.json"
    ping = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "PING.EXE")
    got = run(f"$Marker = '{marker}'; $BeatSeconds = 1; $t0 = Get-Date; "
              f"$r = Invoke-Winget '{ping}' @('-n', '60', '127.0.0.1') 3; "
              "ConvertTo-Json @($r.timedOut, [int]((Get-Date) - $t0).TotalSeconds)", shell)
    assert got[0] is True and got[1] < 30  # killed after ~3 s, not left running for 60
    beat = json.loads(marker.read_text(encoding="utf-8"))
    assert beat["phase"] == "updating" and abs(time.time() - beat["beat_at"]) < 60


@pytest.mark.parametrize("shell", SHELLS)
def test_recovery_restores_a_broken_tool_from_its_backup_and_checks_it(shell, tmp_path):
    """A real Microsoft-signed file (Windows' whoami.exe, catalog-signed) stands in for a tool: the "installed" copy
    is broken, as a run killed mid-replacement could leave it; recovery puts the backup back and verifies it."""
    whoami = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "whoami.exe")
    pkgs, links, here = tmp_path / "Packages", tmp_path / "Links", tmp_path / "engine-update"
    pkg = pkgs / "Test.Tool_x"
    pkg.mkdir(parents=True)
    links.mkdir()
    (here / "backup" / "Test.Tool").mkdir(parents=True)
    shutil.copy2(whoami, here / "backup" / "Test.Tool" / "tool.exe")
    (pkg / "tool.exe").write_bytes(b"MZ half-written")  # broken
    (links / "tool.exe").write_bytes(b"")  # not a symlink here: Get-LinkTarget falls back to the file itself
    # the link must point INTO the package folder, so test with the package's own file as the "link"
    got = run(f"$WingetPackages = '{pkgs}'; $WingetLinks = '{pkg}'; $Here = '{here}'; $Marker = '{here / 'updating.json'}'; "
              "$InstallerProcesses = @('no-such-process-xyz'); "
              "$Engines = @(@{ tool = 'ghcp'; id = 'Test.Tool'; exe = 'tool.exe'; org = 'Microsoft Corporation' }); "
              "function Get-InstalledVersion([string]$id) { '1.0.0' }; "
              "$rec = Repair-AfterInterruption; ConvertTo-Json -Depth 4 @($rec.safe, $rec.results[0].outcome, $rec.results[0].reason)", shell)
    assert got == [True, "failed", "restored-after-signature-invalid"]
    assert (pkg / "tool.exe").read_bytes() == (here / "backup" / "Test.Tool" / "tool.exe").read_bytes()


def test_the_bootstrap_registers_one_fixed_action_from_the_admin_only_copy():
    boot = BOOTSTRAP.read_text(encoding="ascii")
    action = _function(boot, "Get-EngineUpdateAction")
    assert "System32\\WindowsPowerShell\\v1.0\\powershell.exe" in action
    assert '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$script`"' in action
    install = _function(boot, "Install-EngineUpdateTask")
    assert "Join-Path $stage 'setup\\Update-Engines.ps1'" in install  # from the verified stage
    assert "Test-UserWritable $dir" in install and "'S-1-5-18'" in install
    main = boot[boot.index("if ($MyInvocation.InvocationName -eq '.') { return }"):]
    assert main.index("Install-EngineUpdateTask") < main.index("Invoke-IsolationCheck")
