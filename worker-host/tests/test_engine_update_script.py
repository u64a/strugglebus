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
    if shell == WINPS:
        env.pop("PSModulePath", None)  # as test_bootstrap_verify.clean_env: 5.1 started from 7
    driver = f"$ErrorActionPreference = 'Stop'\n. '{SCRIPT}'\n{body}"
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
    assert "& $winget @upArgs" in upgrade and "'--scope', 'machine'" in upgrade and "'--exact'" in upgrade
    assert "'--source', 'winget'" in upgrade  # never the msstore source
    assert "'--skip-dependencies'" in upgrade  # never a stray PowerShell MSIX beside the pinned one (the VM, 29 Nov)
    assert "'--id', $engine.id" in upgrade  # the id comes from the script's own $Engines, nothing else
    system = _function(TEXT, "Get-SystemWinget")
    assert "-AllUsers" in system and "'WindowsApps'" in system and "'Microsoft Corporation'" in system
    assert "Microsoft.VCLibs.140.00.UWPDesktop" in system  # its runtime, from WindowsApps too
    installed = _function(TEXT, "Get-InstalledVersion")
    assert "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" in installed  # admin-written, not the host's


def test_the_publisher_is_checked_before_the_permission_reset_and_a_failure_restores():
    upgrade = _function(TEXT, "Update-OneEngine")
    assert upgrade.index("Get-PublisherProblem") < upgrade.index("Assert-WingetRootSafe") < upgrade.index("/reset")
    check = upgrade[upgrade.index("if ($problem)"):upgrade.index("Assert-WingetRootSafe")]
    assert "Invoke-Robocopy $backup $dir" in check and "return $r" in check
    assert upgrade.index("Invoke-Robocopy $dir $backup") < upgrade.index("& $winget @upArgs")


def test_admission_is_closed_before_the_idle_check_and_opened_only_in_a_finally():
    main = TEXT[TEXT.index("if ($MyInvocation.InvocationName -eq '.') { return }"):]
    assert main.index("WriteAllText($Marker") < main.index("Get-BusyHosts")
    body = main[main.index("WriteAllText($Marker"):]
    assert body.index("try {") < body.index("Start-Sleep -Seconds $SettleSeconds") < body.index("Update-OneEngine")
    final = body[body.rindex("} finally {"):]
    assert "Remove-Item -LiteralPath $Marker" in final
    assert "exit" not in body[:body.rindex("} finally {")]  # nothing leaves before the finally


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
