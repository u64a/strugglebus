<#
.SYNOPSIS
  Removes the consumer apps and sets the policies and per-user settings in setup/debloat.txt (agent-host-build.md
  section 6). For DEDICATED hosts only. Idempotent: a second run changes nothing.

.DESCRIPTION
  Reads setup/debloat.txt, looks at this machine, and prints the plan: one line per thing it would change.
    - app      removed for every user and as a provisioned package, so new profiles do not get it
    - feature  optional feature disabled (no restart)
    - policy   HKLM policy value, so Windows does not put things back
    - user     per-user value, written to the user running this AND to the Default profile (new profiles)
    - onedrive OneDrive uninstalled for this user; new profiles never get the OneDrive installer
  Packages the list does not name are left alone and listed at the end ("not in the list"), so anything a feature
  update adds shows up for review. A `keep` line, or the built-in protected set (Store, App Installer, Edge, WebView2,
  Windows Security and the frameworks), can never be removed, whatever the list says.

  It never touches user files, worker clones or the strugglebus host. Other existing profiles keep their own
  per-user settings (only the running user and the Default profile are written).

  Needs an elevated Windows PowerShell (Run as administrator). Started from PowerShell 7 it re-runs itself in
  Windows PowerShell 5.1, where the Appx cmdlets work natively.

.PARAMETER WhatIf
  Print the plan and change nothing.

.PARAMETER Check
  Change nothing; exit 0 if there is nothing to do, 1 if there is (setup.ps1's Test- step).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File setup\10-debloat.ps1 -WhatIf
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File setup\10-debloat.ps1
#>
[CmdletBinding()]
param(
    [string]$List = '',   # default: debloat.txt next to this script
    [switch]$WhatIf,
    [switch]$Check
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Never removed, whatever debloat.txt says (section 6 "Keep"): winget needs the Store and App Installer, and the
# rest is the browser engine, Windows Security and the frameworks other apps are built on.
$Protected = @(
    'Microsoft.WindowsStore', 'Microsoft.StorePurchaseApp', 'Microsoft.DesktopAppInstaller', 'Microsoft.Winget.Source',
    'Microsoft.MicrosoftEdge*', 'Microsoft.WebView2*', 'Microsoft.Win32WebViewHost', 'Microsoft.SecHealthUI',
    'Microsoft.VCLibs*', 'Microsoft.UI.Xaml*', 'Microsoft.NET.Native*', 'Microsoft.WindowsAppRuntime*',
    'Microsoft.Services.Store.Engagement', 'Microsoft.WindowsTerminal', 'Microsoft.PowerShell'
)
$DefaultHive = 'HKEY_USERS\strugglebus-default'
$NamePattern = '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'

function Test-Protected([string]$name, [string[]]$keep = @()) {
    foreach ($p in @($Protected) + @($keep)) { if ($name -like $p) { return $true } }
    return $false
}

function Read-DebloatList([string]$text) {
    # Pure: debloat.txt text -> entries. Throws "line <n>: ..." on anything it does not understand.
    $entries = New-Object System.Collections.Generic.List[object]
    $keep = New-Object System.Collections.Generic.List[string]
    $n = 0
    foreach ($raw in ($text -split "`r?`n")) {
        $n++
        $line = ($raw -replace '#.*$', '').Trim()
        if (-not $line) { continue }
        $tokens = @($line -split '\s+')
        $kind = $tokens[0].ToLowerInvariant()
        switch ($kind) {
            { $_ -in 'app', 'keep', 'feature' } {
                if ($tokens.Count -ne 2) { throw "line ${n}: '$kind' takes exactly one name" }
                # Only a keep may end in * (a family such as the per-language handwriting packs); removals are exact.
                $pattern = if ($kind -eq 'keep') { $NamePattern -replace '\$$', '\*?$' } else { $NamePattern }
                if ($tokens[1] -notmatch $pattern) { throw "line ${n}: '$($tokens[1])' is not a package or feature name (no wildcards)" }
                if ($kind -eq 'keep') { $keep.Add($tokens[1]) }
                else { $entries.Add([pscustomobject]@{ Kind = $kind; Name = $tokens[1]; Line = $n }) }
            }
            { $_ -in 'policy', 'user' } {
                # The path may hold spaces ("Windows Search"): it is everything between the kind and the last two words.
                $m = [regex]::Match($line, '^\S+\s+(.+?)\s+(\S+)\s+(\S+)$')
                if (-not $m.Success) { throw "line ${n}: '$kind' takes <path> <value name> <dword>" }
                $path = $m.Groups[1].Value; $value = $m.Groups[2].Value; $data = $m.Groups[3].Value
                if ($data -notmatch '^\d{1,10}$' -or [uint64]$data -gt [uint32]::MaxValue) { throw "line ${n}: '$data' is not a DWORD" }
                if ($value -notmatch $NamePattern) { throw "line ${n}: '$value' is not a value name" }
                if ($kind -eq 'policy' -and $path -notmatch '^HKLM\\SOFTWARE\\[^\\]') { throw "line ${n}: a policy path starts HKLM\SOFTWARE\" }
                if ($kind -eq 'user' -and $path -notmatch '^Software\\[^\\]') { throw "line ${n}: a user path starts Software\ (it is written under each profile)" }
                if ($path -match '\\\\|\\$|[*?"]') { throw "line ${n}: '$path' is not a plain registry path" }
                $entries.Add([pscustomobject]@{ Kind = $kind; Path = $path; Value = $value; Data = [uint32]$data; Line = $n })
            }
            'onedrive' {
                if ($tokens.Count -ne 1) { throw "line ${n}: 'onedrive' takes nothing" }
                $entries.Add([pscustomobject]@{ Kind = 'onedrive'; Line = $n })
            }
            default { throw "line ${n}: unknown entry '$kind' (app, keep, feature, policy, user, onedrive)" }
        }
    }
    foreach ($e in $entries) {
        if ($e.Kind -eq 'app' -and (Test-Protected $e.Name $keep)) { throw "line $($e.Line): $($e.Name) is protected (keep); it is never removed" }
    }
    return [pscustomobject]@{ Entries = $entries.ToArray(); Keep = $keep.ToArray() }
}

function Get-RegKey([string]$hive, [string]$path, [string]$value) { "$hive\$path|$value" }

function Get-DebloatPlan($list, $state) {
    # Pure: the entries and a snapshot of the machine -> the changes still to make, in list order.
    # $state: Installed (name -> users), Provisioned (names), Features (name -> state), Registry (key -> dword),
    # OneDrive (bool: installed for this user or the Default profile still installs it).
    $plan = New-Object System.Collections.Generic.List[object]
    foreach ($e in $list.Entries) {
        switch ($e.Kind) {
            'app' {
                $users = if ($state.Installed.ContainsKey($e.Name)) { $state.Installed[$e.Name] } else { 0 }
                $prov = @($state.Provisioned) -contains $e.Name
                if ($users -or $prov) {
                    $what = @(); if ($users) { $what += "installed ($users)" }; if ($prov) { $what += 'provisioned' }
                    $plan.Add([pscustomobject]@{ Entry = $e; Text = "remove app $($e.Name): $($what -join ', ')" })
                }
            }
            'feature' {
                $s = if ($state.Features.ContainsKey($e.Name)) { $state.Features[$e.Name] } else { $null }
                if ($s -and $s -notlike 'Disabled*') { $plan.Add([pscustomobject]@{ Entry = $e; Text = "disable feature $($e.Name) ($s)" }) }
            }
            'policy' {
                $k = Get-RegKey 'HKLM' ($e.Path -replace '^HKLM\\', '') $e.Value
                $now = if ($state.Registry.ContainsKey($k)) { $state.Registry[$k] } else { $null }
                if ($now -ne $e.Data) { $plan.Add([pscustomobject]@{ Entry = $e; Hive = 'HKLM'; Text = "policy $($e.Path)\$($e.Value) = $($e.Data) (now $(if ($null -eq $now) { 'unset' } else { $now }))" }) }
            }
            'user' {
                foreach ($hive in 'HKCU', 'Default') {
                    $k = Get-RegKey $hive $e.Path $e.Value
                    $now = if ($state.Registry.ContainsKey($k)) { $state.Registry[$k] } else { $null }
                    if ($now -ne $e.Data) { $plan.Add([pscustomobject]@{ Entry = $e; Hive = $hive; Text = "user ($hive) $($e.Path)\$($e.Value) = $($e.Data) (now $(if ($null -eq $now) { 'unset' } else { $now }))" }) }
                }
            }
            'onedrive' {
                if ($state.OneDrive) { $plan.Add([pscustomobject]@{ Entry = $e; Text = 'uninstall OneDrive (this user) and stop new profiles installing it' }) }
            }
        }
    }
    return $plan.ToArray()
}

function Get-Unlisted($list, $state) {
    # Pure: removable packages (installed apps that are not part of Windows itself or a framework, and provisioned
    # packages) that the list neither removes nor keeps and that are not protected.
    $named = @($list.Entries | Where-Object Kind -eq 'app' | ForEach-Object Name)
    $all = @($state.Visible) + @($state.Provisioned) | Sort-Object -Unique
    return @($all | Where-Object { $_ -and $named -notcontains $_ -and -not (Test-Protected $_ $list.Keep) })
}

# Dot-sourced (the tests do this): define the functions above and stop here.
if ($MyInvocation.InvocationName -eq '.') { return }
if (-not $List) { $List = Join-Path $PSScriptRoot 'debloat.txt' }
$List = [IO.Path]::GetFullPath($List)

if ($PSVersionTable.PSEdition -eq 'Core') {
    # The Appx cmdlets are Windows PowerShell's; run the whole script there, with the same arguments.
    $argv = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-List', $List)
    if ($WhatIf) { $argv += '-WhatIf' }
    if ($Check) { $argv += '-Check' }
    & (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') @argv
    exit $LASTEXITCODE
}

function Say([string]$text) { Write-Host "[debloat] $text"; if ($script:Log) { Add-Content -Path $script:Log -Value "$(Get-Date -Format s) $text" } }

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'run this from an elevated PowerShell (Run as administrator)'
}
$debloat = Read-DebloatList ([IO.File]::ReadAllText($List))

function Get-RegDword([string]$psPath, [string]$value) {
    try { $v = (Get-ItemProperty -Path $psPath -Name $value -ErrorAction Stop).$value } catch { return $null }
    if ($v -is [int] -or $v -is [uint32] -or $v -is [long]) { return [uint32]([int64]$v -band 0xFFFFFFFF) }
    return $null
}

function Get-HivePath([string]$hive, [string]$path) {
    switch ($hive) {
        'HKLM' { "Registry::HKEY_LOCAL_MACHINE\$path" }
        'HKCU' { "Registry::HKEY_CURRENT_USER\$path" }
        'Default' { "Registry::$DefaultHive\$path" }
    }
}

function Get-DebloatState($list) {
    $installed = @{}
    $all = @(Get-AppxPackage -AllUsers)
    $visible = @($all | Where-Object { -not $_.IsFramework -and "$($_.SignatureKind)" -ne 'System' } | ForEach-Object Name | Sort-Object -Unique)
    foreach ($p in $all) {
        $users = @($p.PackageUserInformation | Where-Object { "$($_.InstallState)" -eq 'Installed' }).Count
        if ($users) { $installed[$p.Name] = [Math]::Max($users, $(if ($installed.ContainsKey($p.Name)) { $installed[$p.Name] } else { 0 })) }
    }
    $provisioned = @(Get-AppxProvisionedPackage -Online | ForEach-Object DisplayName)
    $features = @{}
    foreach ($e in @($list.Entries | Where-Object Kind -eq 'feature')) {
        $f = Get-WindowsOptionalFeature -Online -FeatureName $e.Name -ErrorAction SilentlyContinue
        if ($f) { $features[$e.Name] = "$($f.State)" }
    }
    $registry = @{}
    foreach ($e in @($list.Entries | Where-Object { $_.Kind -in 'policy', 'user' })) {
        $hives = if ($e.Kind -eq 'policy') { @('HKLM') } else { @('HKCU', 'Default') }
        foreach ($hive in $hives) {
            $path = if ($hive -eq 'HKLM') { $e.Path -replace '^HKLM\\', '' } else { $e.Path }
            $v = Get-RegDword (Get-HivePath $hive $path) $e.Value
            if ($null -ne $v) { $registry[(Get-RegKey $hive $path $e.Value)] = $v }
        }
    }
    $oneDrive = (Test-Path (Join-Path $env:LOCALAPPDATA 'Microsoft\OneDrive\OneDrive.exe')) -or
        ($null -ne (Get-OneDriveUninstall)) -or
        ($null -ne (Get-ItemProperty -Path "Registry::$DefaultHive\Software\Microsoft\Windows\CurrentVersion\Run" -Name 'OneDriveSetup' -ErrorAction SilentlyContinue))
    return [pscustomobject]@{ Installed = $installed; Visible = $visible; Provisioned = $provisioned; Features = $features
        Registry = $registry; OneDrive = $oneDrive }
}

function Get-OneDriveUninstall {
    $u = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe' -Name UninstallString -ErrorAction SilentlyContinue
    if ($u) { return $u.UninstallString }
    return $null
}

function Invoke-Step($step) {
    $e = $step.Entry
    switch ($e.Kind) {
        'app' {
            foreach ($p in @(Get-AppxPackage -AllUsers -Name $e.Name)) {
                try { Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction Stop }
                catch { Say "  $($p.PackageFullName): $($_.Exception.Message.Trim())" }
            }
            foreach ($p in @(Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq $e.Name)) {
                Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -ErrorAction Stop | Out-Null
            }
        }
        'feature' { Disable-WindowsOptionalFeature -Online -FeatureName $e.Name -NoRestart -ErrorAction Stop | Out-Null }
        { $_ -in 'policy', 'user' } {
            $path = if ($step.Hive -eq 'HKLM') { $e.Path -replace '^HKLM\\', '' } else { $e.Path }
            $ps = Get-HivePath $step.Hive $path
            if (-not (Test-Path $ps)) { New-Item -Path $ps -Force | Out-Null }
            New-ItemProperty -Path $ps -Name $e.Value -PropertyType DWord -Value ([int]([int64]$e.Data -band 0xFFFFFFFF)) -Force | Out-Null
        }
        'onedrive' {
            Get-Process OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            $cmd = Get-OneDriveUninstall
            if ($cmd) {
                # "C:\...\OneDriveSetup.exe  /uninstall" (per-user install): run that exe with its own arguments.
                $m = [regex]::Match($cmd, '^\s*"?([^"]+?\.exe)"?\s*(.*)$')
                $exe = $m.Groups[1].Value; $rest = $m.Groups[2].Value.Trim()
                if (-not $rest) { $rest = '/uninstall' }
                Start-Process -FilePath $exe -ArgumentList $rest -Wait
            } elseif (Test-Path (Join-Path $env:LOCALAPPDATA 'Microsoft\OneDrive\OneDrive.exe')) {
                Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\OneDriveSetup.exe') -ArgumentList '/uninstall' -Wait
            }
            Remove-ItemProperty -Path "Registry::$DefaultHive\Software\Microsoft\Windows\CurrentVersion\Run" -Name 'OneDriveSetup' -ErrorAction SilentlyContinue
        }
    }
}

$script:Log = $null
if (-not $WhatIf -and -not $Check) {
    $logDir = Join-Path $env:ProgramData 'strugglebus\logs'
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    $script:Log = Join-Path $logDir 'debloat.log'
}

# The Default profile's hive, loaded for the run and always unloaded again.
$defaultFile = Join-Path (Split-Path $env:PUBLIC) 'Default\NTUSER.DAT'
& reg.exe load $DefaultHive $defaultFile 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "could not load the Default profile hive ($defaultFile)" }
$exit = 0
try {
    $state = Get-DebloatState $debloat
    $plan = @(Get-DebloatPlan $debloat $state)
    if ($Check) { $exit = if ($plan.Count) { 1 } else { 0 } }
    elseif (-not $plan.Count) { Say 'nothing to do: every entry in the list is already in place' }
    else {
        Say "$($plan.Count) change(s)$(if ($WhatIf) { ' (WhatIf: nothing is changed)' })"
        foreach ($step in $plan) {
            Say "  $($step.Text)"
            # One refused step (a value Windows protects, an app that will not go) must not stop the rest: say it and
            # carry on. The re-read below lists whatever is still not in place and makes the exit code 1.
            if (-not $WhatIf) {
                try { Invoke-Step $step } catch { Say "    failed: $($_.Exception.Message.Trim())" }
            }
        }
        if (-not $WhatIf) {
            $left = @(Get-DebloatPlan $debloat (Get-DebloatState $debloat))
            if ($left.Count) {
                Say "NOT done ($($left.Count)): run again, and check the lines above"
                foreach ($step in $left) { Say "  still: $($step.Text)" }
                $exit = 1
            } else {
                Say 'done. Sign out and in (or restart) for taskbar and Start changes to show.'
            }
        }
    }
    if (-not $Check) {
        $unlisted = @(Get-Unlisted $debloat (Get-DebloatState $debloat))
        if ($unlisted.Count) { Say "not in the list (left alone; add app or keep lines to decide): $($unlisted -join ', ')" }
    }
} finally {
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    & reg.exe unload $DefaultHive 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning "the Default profile hive is still loaded as $DefaultHive; it unloads at the next restart (its changes are saved)" }
}
exit $exit
