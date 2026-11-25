"""setup/10-debloat.ps1: the list's rules, the plan it makes from a machine snapshot, and the real debloat.txt.

Only the pure functions are exercised (dot-sourced): nothing here removes an app or writes the registry. They are
run in PowerShell 7 and in Windows PowerShell 5.1, where the script really runs (it re-launches itself there).
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "setup" / "10-debloat.ps1"
LIST = ROOT / "setup" / "debloat.txt"
SHELLS = [s for s in ("pwsh", "powershell") if shutil.which(s)]

pytestmark = pytest.mark.skipif(not SHELLS, reason="no PowerShell")


def ps(shell: str, body: str):
    # A file, not -Command -: stdin is read line by line, which breaks here-strings and multi-line hashtables.
    script = "$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest; . '" + str(SCRIPT) + "'\n" + body
    with tempfile.TemporaryDirectory() as d:
        driver = Path(d) / "driver.ps1"
        driver.write_bytes(b"\xef\xbb\xbf" + script.encode("utf-8"))  # BOM: Windows PowerShell reads it as UTF-8
        r = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(driver)],
                           capture_output=True, timeout=120)
    out = r.stdout.decode("utf-8", "replace").strip()
    assert r.returncode == 0, (out, r.stderr.decode("utf-8", "replace"))
    return json.loads(out)


def parse_error(shell: str, text: str) -> str:
    body = ("try { Read-DebloatList @'\n" + text + "\n'@ | Out-Null; ConvertTo-Json 'parsed' } "
            "catch { ConvertTo-Json $_.Exception.Message }")
    return ps(shell, body)


@pytest.fixture(params=SHELLS)
def shell(request):
    return request.param


def test_the_real_list_parses_and_never_removes_what_section_6_keeps(shell):
    got = ps(shell, """
$l = Read-DebloatList ([IO.File]::ReadAllText('@LIST@'))
[ordered]@{
  kinds = [ordered]@{ app = @($l.Entries | Where-Object Kind -eq 'app').Count; policy = @($l.Entries | Where-Object Kind -eq 'policy').Count
                      user = @($l.Entries | Where-Object Kind -eq 'user').Count; feature = @($l.Entries | Where-Object Kind -eq 'feature').Count
                      onedrive = @($l.Entries | Where-Object Kind -eq 'onedrive').Count }
  apps = @($l.Entries | Where-Object Kind -eq 'app' | ForEach-Object Name)
  keep = @($l.Keep)
  search = @($l.Entries | Where-Object { $_.Kind -eq 'policy' -and $_.Value -eq 'DisableWebSearch' } | ForEach-Object { $_.Path + '|' + $_.Data })
} | ConvertTo-Json -Depth 4
""".replace("@LIST@", str(LIST)))
    assert got["kinds"]["onedrive"] == 1 and got["kinds"]["feature"] == 1
    assert got["kinds"]["app"] >= 25 and got["kinds"]["policy"] >= 10 and got["kinds"]["user"] >= 20
    # Section 6 "Remove": a sample from each group, and Quick Assist by name.
    for name in ("MicrosoftWindows.Client.WebExperience", "Microsoft.GamingApp", "Microsoft.BingNews", "MSTeams",
                 "Microsoft.OutlookForWindows", "Microsoft.YourPhone", "MicrosoftCorporationII.QuickAssist"):
        assert name in got["apps"]
    # Section 6 "Keep": Store and App Installer (winget), Edge, Terminal, Windows Security, the codecs.
    for name in ("Microsoft.WindowsStore", "Microsoft.DesktopAppInstaller", "Microsoft.MicrosoftEdge.Stable",
                 "Microsoft.WindowsTerminal", "Microsoft.SecHealthUI", "Microsoft.HEVCVideoExtension"):
        assert name in got["keep"] and name not in got["apps"]
    assert got["search"] == ["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search|1"]  # a path with a space


@pytest.mark.parametrize("text, message", [
    ("remove Microsoft.BingNews", "unknown entry 'remove'"),
    ("app Microsoft.Xbox*", "no wildcards"),
    ("app Microsoft.WindowsStore", "is protected"),                 # built in: no keep line needed
    ("app Microsoft.VCLibs.140.00", "is protected"),                # a framework, by pattern
    ("keep Contoso.Thing*\napp Contoso.Thing.Two", "is protected"),  # a keep family wins over a removal
    ("app A.B extra", "exactly one name"),
    ("policy HKLM\\SOFTWARE\\Policies\\X Value 4294967296", "not a DWORD"),
    ("policy HKLM\\SOFTWARE\\Policies\\X Value -1", "not a DWORD"),
    ("policy HKCU\\Software\\X Value 1", "policy path starts HKLM"),
    ("user HKLM\\SOFTWARE\\X Value 1", "user path starts Software"),
    ("user Software\\X\\\\Y Value 1", "not a plain registry path"),
    ("policy HKLM\\SOFTWARE\\X Value", "takes <path> <value name> <dword>"),
    ("onedrive now", "takes nothing"),
])
def test_a_line_it_does_not_understand_stops_the_run_with_its_line_number(shell, text, message):
    got = parse_error(shell, "# header\n\n" + text)
    assert message in got
    assert got.startswith("line ")


SNAPSHOT = r"""
$l = Read-DebloatList @'
app     Contoso.Game
app     Contoso.Absent
keep    Contoso.Notes
feature Recall
feature Contoso.Feature
policy  HKLM\SOFTWARE\Policies\Contoso\Windows Search  DisableWebSearch 1
policy  HKLM\SOFTWARE\Policies\Contoso  Already 1
user    Software\Contoso\Advanced ShowTaskViewButton 0
onedrive
'@
function Snapshot([bool]$done) {
  $reg = @{ 'HKLM\SOFTWARE\Policies\Contoso|Already' = [uint32]1; 'HKCU\Software\Contoso\Advanced|ShowTaskViewButton' = [uint32]0 }
  if ($done) { $reg['HKLM\SOFTWARE\Policies\Contoso\Windows Search|DisableWebSearch'] = [uint32]1; $reg['Default\Software\Contoso\Advanced|ShowTaskViewButton'] = [uint32]0 }
  else { $reg['Default\Software\Contoso\Advanced|ShowTaskViewButton'] = [uint32]1 }
  [pscustomobject]@{
    Installed = $(if ($done) { @{ 'Contoso.Notes' = 1 } } else { @{ 'Contoso.Game' = 2; 'Contoso.Notes' = 1 } })
    Visible = @('Contoso.Notes', 'Contoso.Calendar') + $(if ($done) { @() } else { @('Contoso.Game') })
    Provisioned = $(if ($done) { @('Contoso.Codec') } else { @('Contoso.Game', 'Contoso.Codec') })
    Features = @{ 'Recall' = 'DisabledWithPayloadRemoved'; 'Contoso.Feature' = $(if ($done) { 'Disabled' } else { 'Enabled' }) }
    Registry = $reg
    OneDrive = -not $done
  }
}
[ordered]@{
  todo = @(Get-DebloatPlan $l (Snapshot $false) | ForEach-Object Text)
  done = @(Get-DebloatPlan $l (Snapshot $true) | ForEach-Object Text)
  unlisted = @(Get-Unlisted $l (Snapshot $false))
} | ConvertTo-Json -Depth 4
"""


def test_the_plan_is_only_what_still_differs_and_is_empty_once_applied(shell):
    got = ps(shell, SNAPSHOT)
    assert got["todo"] == [
        "remove app Contoso.Game: installed (2), provisioned",
        "disable feature Contoso.Feature (Enabled)",  # Recall is already DisabledWithPayloadRemoved
        "policy HKLM\\SOFTWARE\\Policies\\Contoso\\Windows Search\\DisableWebSearch = 1 (now unset)",
        "user (Default) Software\\Contoso\\Advanced\\ShowTaskViewButton = 0 (now 1)",  # HKCU is already 0
        "uninstall OneDrive (this user) and stop new profiles installing it",
    ]
    assert got["done"] == []  # idempotent: what setup.ps1's Test- step relies on
    # Contoso.Calendar and Contoso.Codec are neither removed nor kept: listed for review, not touched.
    assert got["unlisted"] == ["Contoso.Calendar", "Contoso.Codec"]


def test_the_list_and_the_script_ship_with_crlf_safe_text():
    # The script is read by Windows PowerShell 5.1: plain ASCII, so no BOM question and no mojibake.
    for f in (SCRIPT, LIST):
        assert all(b < 128 for b in f.read_bytes()), f.name
