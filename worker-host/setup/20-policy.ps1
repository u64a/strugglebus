<#
.SYNOPSIS
  Machine policy for a host (agent-host-build.md section 2, 20-policy): power so it never sleeps, long paths, and
  Windows Update restarts only in the nightly maintenance window. Idempotent: a second run changes nothing. Time,
  diagnostic data and the rest of Windows Update (deferrals) join it later.

.DESCRIPTION
  Power, on mains (AC) only. The screen still turns off; the machine does not:
    - sleep after                 never      (a sleeping host drops off the bus and its workers stop)
    - hibernate after             never
    - unattended sleep timeout    never      (after a wake-up nobody is at, e.g. for updates)
    - turn off the screen after   10 minutes
    - closing the lid             do nothing (laptops)
    - power mode                  Best performance
  On battery Windows' own settings stay, so a host that loses mains power sleeps rather than running flat.
  Hibernation is turned off (powercfg /hibernate off), which also turns off Fast Startup: every restart is a real
  one, the state hosts and their scheduled tasks expect, and the hibernation file's disk space comes back.

  Long paths: LongPathsEnabled = 1 (worker trees go past 260 characters).

  Windows Update (policy values under HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate):
    - active hours 08:00-02:00 (18 hours, Windows' maximum): no update restart then
    - updates download by themselves and install every day at 03:00, restarting then if they need to
  So an update restart falls in the 02:00-06:00 maintenance window, not at 18:00 as with the defaults.

  Settings are read and written through Windows' power API (powrprof.dll) by GUID, so settings powercfg hides on
  a given machine (a laptop's lid) are handled the same way. The active plan is changed in place; on
  modern-standby machines (most laptops) Balanced is the only plan, and "Best performance" is its power mode.

  Needs an elevated PowerShell.

.PARAMETER WhatIf
  Print what would change, change nothing.

.PARAMETER Check
  Change nothing; exit 0 if everything is in place, 1 if not (setup.ps1's Test- step).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File setup\20-policy.ps1 -WhatIf
#>
[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$Check
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SubSleep = '238c9fa8-0aad-41ed-83f4-97be242c8f20'
$SubVideo = '7516b95f-f776-4464-8c53-06167f40cc99'
$SubButtons = '4f971e89-eebd-4455-a8de-9e59040e7347'
$BestPerformance = 'ded574b5-45a0-4f42-8737-46345c09c238'
$WuPolicy = 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'

# One row per setting. Kind: ac (a value of the active power plan, on mains), overlay (the mains power mode),
# hibernate (on/off), registry (an HKLM DWORD).
$Items = @(
    [pscustomobject]@{ Kind = 'ac'; Name = 'sleep after (mains)'; Sub = $SubSleep; Setting = '29f6c1db-86da-48c5-9fdb-f2b67b1f44da'; Value = 0 }
    [pscustomobject]@{ Kind = 'ac'; Name = 'hibernate after (mains)'; Sub = $SubSleep; Setting = '9d7815a6-7ee4-497e-8888-515a05f02364'; Value = 0 }
    [pscustomobject]@{ Kind = 'ac'; Name = 'unattended sleep timeout (mains)'; Sub = $SubSleep; Setting = '7bc4a2f9-d8fc-4469-b07b-33eb785aaca0'; Value = 0 }
    [pscustomobject]@{ Kind = 'ac'; Name = 'turn off the screen after (mains, seconds)'; Sub = $SubVideo; Setting = '3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e'; Value = 600 }
    [pscustomobject]@{ Kind = 'ac'; Name = 'closing the lid (mains: 0 = do nothing)'; Sub = $SubButtons; Setting = '5ca83367-6e45-459f-a27b-476b1d01c936'; Value = 0 }
    [pscustomobject]@{ Kind = 'overlay'; Name = 'power mode (mains)'; Value = $BestPerformance }
    [pscustomobject]@{ Kind = 'hibernate'; Name = 'hibernation and Fast Startup'; Value = 0 }
    [pscustomobject]@{ Kind = 'registry'; Name = 'long paths'; Path = 'SYSTEM\CurrentControlSet\Control\FileSystem'; Value = 1; ValueName = 'LongPathsEnabled' }
    # Windows Update restarts only in the maintenance window (agent-host-build.md 9.2). Without this, Windows restarts
    # as soon as its default active hours (8:00-17:00) end: a host restarted at 18:00, mid-task. Active hours
    # are capped at 18 hours, so 08:00-02:00 leaves 02:00-08:00 for restarts, and updates install daily at 03:00
    # (restart_time), inside the 02:00-06:00 window. "No auto-restart with users signed in" is deliberately NOT set:
    # The owner stays signed in on the hosts, so updates would never finish.
    [pscustomobject]@{ Kind = 'registry'; Name = 'Windows Update: use active hours'; Path = $WuPolicy; Value = 1; ValueName = 'SetActiveHours' }
    [pscustomobject]@{ Kind = 'registry'; Name = 'Windows Update: active hours start (no restarts from)'; Path = $WuPolicy; Value = 8; ValueName = 'ActiveHoursStart' }
    [pscustomobject]@{ Kind = 'registry'; Name = 'Windows Update: active hours end (restarts allowed from)'; Path = $WuPolicy; Value = 2; ValueName = 'ActiveHoursEnd' }
    [pscustomobject]@{ Kind = 'registry'; Name = 'Windows Update: automatic updates on'; Path = "$WuPolicy\AU"; Value = 0; ValueName = 'NoAutoUpdate' }
    [pscustomobject]@{ Kind = 'registry'; Name = 'Windows Update: download, then install at the scheduled time'; Path = "$WuPolicy\AU"; Value = 4; ValueName = 'AUOptions' }
    [pscustomobject]@{ Kind = 'registry'; Name = 'Windows Update: install every day'; Path = "$WuPolicy\AU"; Value = 0; ValueName = 'ScheduledInstallDay' }
    [pscustomobject]@{ Kind = 'registry'; Name = 'Windows Update: install (and restart) at 03:00'; Path = "$WuPolicy\AU"; Value = 3; ValueName = 'ScheduledInstallTime' }
)

function Get-PolicyPlan($items, $state) {
    # Pure: the rows and a snapshot (state.Ac: Setting -> value or $null, state.Overlay, state.Hibernate,
    # state.Registry: 'path|name' -> value) -> the changes still to make.
    $plan = New-Object System.Collections.Generic.List[object]
    foreach ($i in $items) {
        switch ($i.Kind) {
            'ac' {
                $now = if ($state.Ac.ContainsKey($i.Setting)) { $state.Ac[$i.Setting] } else { $null }
                if ($null -ne $now -and [int64]$now -ne [int64]$i.Value) {
                    $plan.Add([pscustomobject]@{ Item = $i; Text = "$($i.Name) = $($i.Value) (now $now)" })
                }
            }
            'overlay' {
                if ("$($state.Overlay)" -ne $i.Value) {
                    $plan.Add([pscustomobject]@{ Item = $i; Text = "$($i.Name) = Best performance (now $(if ($state.Overlay) { $state.Overlay } else { 'default' }))" })
                }
            }
            'hibernate' {
                if ($state.Hibernate) { $plan.Add([pscustomobject]@{ Item = $i; Text = "$($i.Name) = off (now on)" }) }
            }
            'registry' {
                $k = "$($i.Path)|$($i.ValueName)"
                $now = if ($state.Registry.ContainsKey($k)) { $state.Registry[$k] } else { $null }
                if ($now -ne $i.Value) {
                    $plan.Add([pscustomobject]@{ Item = $i; Text = "$($i.Name): $($i.ValueName) = $($i.Value) (now $(if ($null -eq $now) { 'unset' } else { $now }))" })
                }
            }
        }
    }
    return $plan.ToArray()
}

# Dot-sourced (the tests do this): define the above and stop here.
if ($MyInvocation.InvocationName -eq '.') { return }

function Say([string]$text) { Write-Host "[policy] $text" }

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'run this from an elevated PowerShell (Run as administrator)'
}

if (-not ('StrugglebusPower' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class StrugglebusPower {
    [DllImport("powrprof.dll")] static extern uint PowerGetActiveScheme(IntPtr root, out IntPtr scheme);
    [DllImport("powrprof.dll")] static extern uint PowerReadACValueIndex(IntPtr root, ref Guid scheme, ref Guid sub, ref Guid setting, out uint value);
    [DllImport("powrprof.dll")] static extern uint PowerWriteACValueIndex(IntPtr root, ref Guid scheme, ref Guid sub, ref Guid setting, uint value);
    [DllImport("powrprof.dll")] static extern uint PowerSetActiveScheme(IntPtr root, ref Guid scheme);
    [DllImport("powrprof.dll", EntryPoint = "PowerSetActiveOverlayScheme")] static extern uint SetOverlay(Guid overlay);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr mem);
    public static Guid Active() {
        IntPtr p;
        uint rc = PowerGetActiveScheme(IntPtr.Zero, out p);
        if (rc != 0) throw new System.ComponentModel.Win32Exception((int)rc);
        Guid g = (Guid)Marshal.PtrToStructure(p, typeof(Guid));
        LocalFree(p);
        return g;
    }
    // null when this machine has no such setting (e.g. no lid)
    public static uint? ReadAc(Guid sub, Guid setting) {
        Guid s = Active(); uint v;
        return PowerReadACValueIndex(IntPtr.Zero, ref s, ref sub, ref setting, out v) == 0 ? (uint?)v : null;
    }
    public static void WriteAc(Guid sub, Guid setting, uint value) {
        Guid s = Active();
        uint rc = PowerWriteACValueIndex(IntPtr.Zero, ref s, ref sub, ref setting, value);
        if (rc != 0) throw new System.ComponentModel.Win32Exception((int)rc);
        rc = PowerSetActiveScheme(IntPtr.Zero, ref s);  // re-apply so the change takes effect now
        if (rc != 0) throw new System.ComponentModel.Win32Exception((int)rc);
    }
    public static void SetOverlayScheme(Guid overlay) {
        uint rc = SetOverlay(overlay);
        if (rc != 0) throw new System.ComponentModel.Win32Exception((int)rc);
    }
}
'@
}

$schemesKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes'

function Get-RegValue([string]$path, [string]$name) {
    # The value, or $null when the key or value is absent.
    try { return (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name } catch { return $null }
}

function Get-PolicyState {
    $ac = @{}
    foreach ($i in @($Items | Where-Object Kind -eq 'ac')) {
        $ac[$i.Setting] = [StrugglebusPower]::ReadAc([guid]$i.Sub, [guid]$i.Setting)
    }
    $overlay = Get-RegValue $schemesKey 'ActiveOverlayAcPowerScheme'
    $hib = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabled'
    $hibernate = if ($null -ne $hib) { [int]$hib -ne 0 } else { $true }  # unset: Windows' default, on
    $registry = @{}
    foreach ($i in @($Items | Where-Object Kind -eq 'registry')) {
        $v = Get-RegValue "HKLM:\$($i.Path)" $i.ValueName
        if ($null -ne $v) { $registry["$($i.Path)|$($i.ValueName)"] = [int]$v }
    }
    return [pscustomobject]@{ Ac = $ac; Overlay = $overlay; Hibernate = $hibernate; Registry = $registry }
}

function Test-OnBattery {
    # A desktop has no battery: never on battery.
    $b = @(Get-CimInstance -Namespace root\wmi -ClassName BatteryStatus -ErrorAction SilentlyContinue)
    return [bool]($b.Count -and -not $b[0].PowerOnline)
}

function Invoke-Step($step) {
    $i = $step.Item
    switch ($i.Kind) {
        'ac' { [StrugglebusPower]::WriteAc([guid]$i.Sub, [guid]$i.Setting, [uint32]$i.Value) }
        'overlay' {
            # The power mode, through the API only (the registry key is protected, as it is for Settings). The API
            # sets the mode for the power source in use, so this is done on mains; on battery it waits for a later
            # run (the nightly maintenance re-runs this step).
            if (Test-OnBattery) { Say '  on battery now: the mains power mode is set on a later run'; return }
            [StrugglebusPower]::SetOverlayScheme([guid]$i.Value)
        }
        'hibernate' {
            & powercfg.exe /hibernate off
            if ($LASTEXITCODE -ne 0) { throw 'powercfg /hibernate off failed' }
        }
        'registry' {
            $path = "HKLM:\$($i.Path)"
            if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
            New-ItemProperty -Path $path -Name $i.ValueName -PropertyType DWord -Value $i.Value -Force | Out-Null
        }
    }
}

$plan = @(Get-PolicyPlan $Items (Get-PolicyState))
if ($Check) { exit $(if ($plan.Count) { 1 } else { 0 }) }
if (-not $plan.Count) { Say 'nothing to do: every setting is already in place'; exit 0 }
Say "$($plan.Count) change(s)$(if ($WhatIf) { ' (WhatIf: nothing is changed)' })"
foreach ($step in $plan) {
    Say "  $($step.Text)"
    if (-not $WhatIf) { Invoke-Step $step }
}
if ($WhatIf) { exit 0 }
$left = @(Get-PolicyPlan $Items (Get-PolicyState))
if ($left.Count) {
    Say "NOT done ($($left.Count)):"
    foreach ($step in $left) { Say "  still: $($step.Text)" }
    exit 1
}
Say 'done. The screen still turns off after 10 minutes on mains; the machine no longer sleeps; update restarts only 02:00-08:00 (install at 03:00).'
exit 0
