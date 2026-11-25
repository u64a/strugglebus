"""setup/20-policy.ps1: a host never sleeps on mains (the screen still turns off), and the plan is idempotent.

Only the pure plan is exercised (dot-sourced), in PowerShell 7 and Windows PowerShell 5.1: nothing here touches
the power settings or the registry of the machine running the tests.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from test_debloat import SHELLS, ps as run_ps

SCRIPT = Path(__file__).resolve().parent.parent / "setup" / "20-policy.ps1"
pytestmark = pytest.mark.skipif(not SHELLS, reason="no PowerShell")


def ps(shell: str, body: str):
    import test_debloat

    old = test_debloat.SCRIPT
    test_debloat.SCRIPT = SCRIPT
    try:
        return run_ps(shell, body)
    finally:
        test_debloat.SCRIPT = old


@pytest.fixture(params=SHELLS)
def shell(request):
    return request.param


SNAPSHOT = r"""
function Snapshot([bool]$done) {
  $ac = @{}
  foreach ($i in @($Items | Where-Object Kind -eq 'ac')) { $ac[$i.Setting] = [uint32]$i.Value }
  if (-not $done) {
    $ac['29f6c1db-86da-48c5-9fdb-f2b67b1f44da'] = [uint32]600   # sleep after 10 minutes (a test laptop, as shipped)
    $ac['7bc4a2f9-d8fc-4469-b07b-33eb785aaca0'] = [uint32]120   # unattended sleep after 2 minutes
    $ac['5ca83367-6e45-459f-a27b-476b1d01c936'] = $null         # no lid on this machine: nothing to set
  }
  [pscustomobject]@{
    Ac = $ac
    Overlay = $(if ($done) { 'ded574b5-45a0-4f42-8737-46345c09c238' } else { $null })
    Hibernate = -not $done
    Registry = $(if ($done) { $r = @{}; foreach ($i in @($Items | Where-Object Kind -eq 'registry')) { $r["$($i.Path)|$($i.ValueName)"] = $i.Value }; $r } else { @{} })
  }
}
[ordered]@{
  todo = @(Get-PolicyPlan $Items (Snapshot $false) | ForEach-Object Text)
  done = @(Get-PolicyPlan $Items (Snapshot $true) | ForEach-Object Text)
  rows = @($Items | ForEach-Object { $_.Name + '=' + $_.Value })
} | ConvertTo-Json -Depth 4
"""


def test_the_plan_is_what_differs_and_empty_once_applied(shell):
    got = ps(shell, SNAPSHOT)
    assert got["todo"] == [
        "sleep after (mains) = 0 (now 600)",
        "unattended sleep timeout (mains) = 0 (now 120)",
        "power mode (mains) = Best performance (now default)",
        "hibernation and Fast Startup = off (now on)",
        "long paths: LongPathsEnabled = 1 (now unset)",
        "Windows Update: use active hours: SetActiveHours = 1 (now unset)",
        "Windows Update: active hours start (no restarts from): ActiveHoursStart = 8 (now unset)",
        "Windows Update: active hours end (restarts allowed from): ActiveHoursEnd = 2 (now unset)",
        "Windows Update: automatic updates on: NoAutoUpdate = 0 (now unset)",
        "Windows Update: download, then install at the scheduled time: AUOptions = 4 (now unset)",
        "Windows Update: install every day: ScheduledInstallDay = 0 (now unset)",
        "Windows Update: install (and restart) at 03:00: ScheduledInstallTime = 3 (now unset)",
    ]
    assert got["done"] == []  # idempotent: setup.ps1's Test- step relies on it


def test_update_restarts_fall_in_the_maintenance_window(shell):
    rows = dict(r.rsplit("=", 1) for r in ps(shell, SNAPSHOT)["rows"])
    start = int(rows["Windows Update: active hours start (no restarts from)"])
    end = int(rows["Windows Update: active hours end (restarts allowed from)"])
    assert (end - start) % 24 == 18  # Windows' maximum span; anything longer is refused
    install = int(rows["Windows Update: install (and restart) at 03:00"])
    assert 2 <= install < 6  # agent-host-build.md 9.3: the 02:00-06:00 maintenance window
    assert end < start  # active hours run past midnight
    assert end <= install < start  # the install hour is outside active hours, so its restart is allowed


def test_mains_never_sleeps_but_the_screen_still_turns_off(shell):
    rows = dict(r.rsplit("=", 1) for r in ps(shell, SNAPSHOT)["rows"])
    assert rows["sleep after (mains)"] == "0" and rows["hibernate after (mains)"] == "0"
    assert rows["unattended sleep timeout (mains)"] == "0"
    assert rows["turn off the screen after (mains, seconds)"] == "600"  # screen off, machine awake
    assert rows["closing the lid (mains: 0 = do nothing)"] == "0"
    assert rows["power mode (mains)"] == "ded574b5-45a0-4f42-8737-46345c09c238"  # Best performance


def test_the_script_is_plain_ascii_for_windows_powershell():
    assert all(b < 128 for b in SCRIPT.read_bytes())
