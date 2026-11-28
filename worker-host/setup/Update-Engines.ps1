# Updates the machine-wide agent programs (GitHub Copilot CLI, Claude Code) that worker hosts on dedicated accounts
# run. Run as SYSTEM by the scheduled task StrugglebusEngineUpdate, which the bootstrap registers (elevated), from an
# admin-only copy in C:\ProgramData\strugglebus\engine-update. Windows PowerShell 5.1.
#
# Why the machine and not the host (#humans 29443): a dedicated host's account is a standard user and the tools are in
# Program Files, so it can't update them, and it mustn't be able to change its own tools. u64-security's conditions
# (#humans 29444), each kept here:
#   1. winget by full path, Microsoft-signed, fixed ids, machine scope; NOTHING read from files the account can write,
#      apart from whether each host is busy (a host that lies only swaps a tool under its own worker).
#   2. After the upgrade, before the permission reset and before anything runs it: the new exe must carry a valid
#      Authenticode signature from the pinned organisation. If not, the package folder is restored from the copy taken
#      before, and the failure is reported as publisher-mismatch (or signature-invalid).
#   3. The result goes to engine-update\result.json, which only administrators and SYSTEM can write; hosts read it.
#   4. Only inside the window, and only when no host on this PC is running or holding a task. Admission stays CLOSED
#      from before the idle check until every tool is checked or restored (prox-manager, #humans 29445-29453;
#      u64-security 29455): the marker engine-update\updating.json is written first and kept fresh as a heartbeat,
#      and hosts take no new task while it EXISTS. Only a run that finishes safely removes it. A run that dies
#      leaves it, the hosts report engine-update-interrupted, and the next run (the window, or the hourly trigger)
#      recovers first: no installer left running, every tool checked, any failure restored from its backup.
#      One run at a time (a global mutex), and the host account can't start the task (#humans 29458/29459).
#   5. Each outcome becomes a host event (the host logs it from the result): tool-updated or tool-update-failed.
#   6. The task: SYSTEM, one fixed action, no arguments.
$ErrorActionPreference = 'Stop'

$SbRoot = Join-Path $env:ProgramData 'strugglebus'
$Here = Join-Path $SbRoot 'engine-update'
$ResultFile = Join-Path $Here 'result.json'
$WingetPackages = Join-Path $env:ProgramFiles 'WinGet\Packages'
$WingetLinks = Join-Path $env:ProgramFiles 'WinGet\Links'
$WindowStart, $WindowEnd = '04:00', '06:00'   # the hosts' [ghcp] window; fixed here, never read from a host's config
$Marker = Join-Path $Here 'updating.json'
$BusyFreshSeconds = 900                       # a host's status.json older than this has no live workers
$SettleSeconds = 30                           # longer than a host's loop (poll_seconds 10) plus a claim in flight
$WaitIdleSeconds = 600                        # how long the marker is held waiting for hosts to empty
$BeatSeconds = 30                             # the marker's heartbeat while a run is alive
$WingetTimeoutSeconds = 900                   # one winget call; then it is killed with its children
$WaitInstallersSeconds = 900                  # recovery waits this long for a dead run's installers to stop
$InstallerProcesses = @('winget', 'WindowsPackageManagerServer')
$Engines = @(
    @{ tool = 'ghcp'; id = 'GitHub.Copilot'; exe = 'copilot.exe'; org = 'GitHub, Inc.' },
    @{ tool = 'claude'; id = 'Anthropic.ClaudeCode'; exe = 'claude.exe'; org = 'Anthropic, PBC' }
)

function Test-InWindow([datetime]$now, [string]$start = $WindowStart, [string]$end = $WindowEnd) {
    # Pure: is the local time inside [start, end)?
    $t = $now.ToString('HH:mm')
    return ($start -le $t) -and ($t -lt $end)
}

function Get-OrgFromSubject([string]$subject) {
    # Pure: the O= of a certificate subject, quoted or not; $null if absent.
    $m = [regex]::Match($subject, '(?:^|,\s*)O=(?:"((?:[^"]|"")*)"|([^,]*))')
    if (-not $m.Success) { return $null }
    if ($m.Groups[1].Success) { return $m.Groups[1].Value.Replace('""', '"') }
    return $m.Groups[2].Value.Trim()
}

function Get-PublisherProblem($status, [string]$subject, [string]$org) {
    # Pure: why a signature isn't the pinned publisher's, as a host event reason, or $null.
    if ("$status" -ne 'Valid') { return 'signature-invalid' }
    if ((Get-OrgFromSubject $subject) -cne $org) { return 'publisher-mismatch' }
    return $null
}

$ToolVersionRe = '^[0-9]+(\.[0-9]+){1,3}(-[0-9A-Za-z.]+)?$'

function Get-ShowVersion([string]$showOutput) {
    # Pure: the "Version:" line of `winget show --id <id> --exact --source winget`, the newest the source offers.
    # (As SYSTEM, `winget list` can't see a portable install made by an administrator; `show` works, 29 Nov.)
    foreach ($ln in [regex]::Split("$showOutput", '[\r\n]+')) {
        if ($ln -notmatch '^\s*Version:\s*v?(\S+)\s*$') { continue }
        $v = $Matches[1]   # kept before the next -match, which replaces $Matches
        if ($v -match $ToolVersionRe) { return $v }
    }
    return $null
}

function Test-Newer([string]$candidate, [string]$installed) {
    # Pure: is $candidate a higher version than $installed? By the numeric parts; a suffix (-2) breaks a tie upward.
    function Split-V([string]$v) { $n, $s = $v -split '-', 2; return @(([version]($n + ('.0' * (3 - ($n -split '\.').Count)))), "$s") }
    if ($candidate -notmatch $ToolVersionRe -or $installed -notmatch $ToolVersionRe) { return $false }
    $c, $i = (Split-V $candidate), (Split-V $installed)
    if ($c[0] -ne $i[0]) { return $c[0] -gt $i[0] }
    return [string]::CompareOrdinal($c[1], $i[1]) -gt 0
}

function Get-InstalledVersion([string]$id) {
    # The version winget recorded at install, in HKLM's uninstall entry: only administrators and SYSTEM can write it.
    $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($id)_Microsoft.Winget.Source_8wekyb3d8bbwe"
    $v = (Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue).DisplayVersion
    if ("$v" -match $ToolVersionRe) { return "$v" }
    return $null
}

function Get-BusyHosts([string]$hostRoot, [double]$nowEpoch, [int]$freshSeconds = $BusyFreshSeconds) {
    # The hosts on this PC with a running worker, by folder name. Each host's status.json is READ only: it is the
    # account's file, so a host can lie, but only about itself. Unreadable and fresh means busy: never guess idle.
    $busy = @()
    foreach ($dir in @(Get-ChildItem -LiteralPath $hostRoot -Directory -ErrorAction SilentlyContinue)) {
        $file = Join-Path $dir.FullName 'state\status.json'
        if (-not (Test-Path -LiteralPath $file)) { continue }
        try {
            $s = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json
        } catch {
            $age = $nowEpoch - ([DateTimeOffset](Get-Item -LiteralPath $file).LastWriteTimeUtc).ToUnixTimeSeconds()
            if ($age -lt $freshSeconds) { $busy += $dir.Name }
            continue
        }
        $updated = 0.0
        [void][double]::TryParse("$($s.updated)", [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$updated)
        # A worker running, or a task claimed and about to start one.
        $holding = @($s.workers).Count + @($s.claims | Where-Object { $_ }).Count
        if (($nowEpoch - $updated) -lt $freshSeconds -and $holding -gt 0) { $busy += $dir.Name }
    }
    return , $busy
}

# --- the winget root's safety: the SAME functions as tools\bootstrap.ps1 (a test keeps them identical) ---------------
$TrustedSids = @('S-1-5-32-544', 'S-1-5-18', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')  # Administrators, SYSTEM, TrustedInstaller
$CreatorOwner = 'S-1-3-0'
$WriteRights = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'

function Get-AclProblem([string]$ownerSid, $aces) {
    # Pure: why this folder is NOT safe to inherit from, or $null. Owner Administrators, SYSTEM or TrustedInstaller;
    # write (any of $WriteRights) allowed to nobody else. CREATOR OWNER as an inherit-only entry is what Program Files
    # itself has: it grants nothing on the folder, only the creator of something inside (here, an administrator).
    # $aces: @{ sid; rights (int); allow (bool); inheritOnly (bool) }.
    if ($TrustedSids -notcontains $ownerSid) { return "owned by $ownerSid" }
    foreach ($a in @($aces)) {
        if (-not $a.allow -or ($a.rights -band [int]$WriteRights) -eq 0) { continue }
        if ($TrustedSids -contains $a.sid) { continue }
        if ($a.sid -eq $CreatorOwner -and $a.inheritOnly) { continue }
        return "$($a.sid) may write to it"
    }
    return $null
}

function Assert-WingetRootSafe([string]$root = $WingetPackages) {
    # u64-security (#humans 29070): a reset package folder inherits from the root, which winget created; so the root
    # must be right first, or the reset would hand its flaw down. Refused, not fixed: an administrator looks at it.
    # PowerShell 7 (.NET Core) has no DirectoryInfo.GetAccessControl (the DevBox, 28 Nov); and not Get-Acl, whose
    # module Windows PowerShell 5.1 can't load when started from a PowerShell 7 window. As at Get-AclProblem's caller.
    $info, $sections = (Get-Item -LiteralPath $root), [Security.AccessControl.AccessControlSections]'Owner, Access'
    $acl = if ($PSVersionTable.PSVersion.Major -ge 6) { [IO.FileSystemAclExtensions]::GetAccessControl($info, $sections) } else { $info.GetAccessControl($sections) }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $aces = foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        @{ sid = $r.IdentityReference.Value; rights = [int]$r.FileSystemRights
           allow = ($r.AccessControlType -eq 'Allow'); inheritOnly = [bool]($r.PropagationFlags -band 'InheritOnly') }
    }
    $problem = Get-AclProblem $owner $aces
    if ($problem) { throw "$root is not safe to inherit from ($problem): fix its permissions, then run this again" }
}
# --- end of the shared functions --------------------------------------------------------------------------------------

function Get-SystemWinget {
    # The real winget.exe by full path from App Installer's admin-protected folder, Microsoft-signed; as the
    # bootstrap's Get-Winget, but -AllUsers, since SYSTEM has no package registration of its own.
    $pkg = Get-AppxPackage -AllUsers -Name 'Microsoft.DesktopAppInstaller' -ErrorAction SilentlyContinue |
        Sort-Object { [version]$_.Version } -Descending | Select-Object -First 1
    if (-not $pkg) { throw 'winget-missing' }
    $exe = Join-Path $pkg.InstallLocation 'winget.exe'
    $apps = Join-Path $env:ProgramFiles 'WindowsApps'
    if (-not $exe.StartsWith($apps + '\', [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $exe)) { throw 'winget-missing' }
    $s = Get-AuthenticodeSignature -LiteralPath $exe
    if ($s.Status -ne 'Valid' -or (Get-OrgFromSubject $s.SignerCertificate.Subject) -ne 'Microsoft Corporation') { throw 'winget-untrusted' }
    # SYSTEM has no registration of App Installer's runtime dependency, so winget fails with 0xC0000135 (a DLL not
    # found; seen on the test VM, 29 Nov). Its folder goes first on this process's PATH: also in the admin-protected
    # WindowsApps, and Microsoft's.
    $vc = Get-AppxPackage -AllUsers -Name 'Microsoft.VCLibs.140.00.UWPDesktop' -ErrorAction SilentlyContinue |
        Where-Object { "$($_.Architecture)" -eq "$($pkg.Architecture)" } | Sort-Object { [version]$_.Version } -Descending |
        Select-Object -First 1
    if (-not $vc -or -not "$($vc.InstallLocation)".StartsWith($apps + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'winget-runtime-missing' }
    $env:PATH = $vc.InstallLocation + ';' + $env:PATH
    return $exe
}

function Get-LinkTarget([string]$link) {
    $item = Get-Item -LiteralPath $link -ErrorAction SilentlyContinue
    if (-not $item) { return $null }
    if ($item.LinkType -eq 'SymbolicLink') { return [string](@($item.Target)[0]) }
    return $item.FullName
}

function Get-PackageDir([string]$target, [string]$root = $WingetPackages) {
    # Pure: the winget package folder (root\<package>) holding this file, or $null if it isn't under the root.
    $r = $root.TrimEnd('\') + '\'
    if (-not $target -or -not $target.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)) { return $null }
    $package = $target.Substring($r.Length).Split('\')[0]
    if (-not $package -or $package -eq '..' -or $package -eq '.') { return $null }
    return $r + $package
}

function Invoke-Robocopy([string]$from, [string]$to) {
    $rc = Join-Path $env:SystemRoot 'System32\robocopy.exe'
    & $rc $from $to /MIR /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
    return ($LASTEXITCODE -lt 8)
}

function Set-Marker([string]$phase) {
    # The marker is also the heartbeat: rewritten at least every $BeatSeconds while a run is alive. Hosts stay closed
    # while it exists, and call it interrupted when it is older than their limit (engineupdate.STALE_SECONDS).
    $m = @{ v = 1; phase = $phase; beat_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
    [IO.File]::WriteAllText($Marker, ($m | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
}

function Wait-Beating([int]$seconds, [string]$phase) {
    # Sleep, keeping the heartbeat fresh.
    $end = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $end) { Set-Marker $phase; Start-Sleep -Seconds ([Math]::Min($BeatSeconds, [Math]::Max(1, ($end - (Get-Date)).TotalSeconds))) }
}

function Invoke-Winget([string]$winget, [string[]]$wingetArgs, [int]$timeoutSeconds = $WingetTimeoutSeconds) {
    # winget as a child process, the heartbeat kept fresh while it runs; killed with its children after the timeout.
    # The arguments are the script's own fixed words (no spaces, no quotes), so joining them is safe in 5.1.
    $psi = New-Object Diagnostics.ProcessStartInfo $winget, ($wingetArgs -join ' ')
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi)
    $out, $err = $p.StandardOutput.ReadToEndAsync(), $p.StandardError.ReadToEndAsync()
    $end = (Get-Date).AddSeconds($timeoutSeconds)
    while (-not $p.WaitForExit($BeatSeconds * 1000)) {
        Set-Marker 'updating'
        if ((Get-Date) -gt $end) {
            & (Join-Path $env:SystemRoot 'System32\taskkill.exe') /PID $p.Id /T /F 2>&1 | Out-Null
            [void]$p.WaitForExit(30000)
            return @{ code = $null; timedOut = $true; out = '' }
        }
    }
    return @{ code = $p.ExitCode; timedOut = $false; out = $out.Result + "`n" + $err.Result }
}

function Get-EngineProblem($engine) {
    # Is this tool, as installed now, the pinned publisher's? $null when it is (or isn't installed at all).
    $target = Get-LinkTarget (Join-Path $WingetLinks $engine.exe)
    if (-not $target) { return $null }
    if (-not (Test-Path -LiteralPath $target)) { return 'signature-invalid' }
    $sig = Get-AuthenticodeSignature -LiteralPath $target
    return Get-PublisherProblem $sig.Status $sig.SignerCertificate.Subject $engine.org
}

function Restore-Engine($engine, [string]$dir) {
    # The package folder back from the copy taken before this run touched it, then checked again. $null when the
    # restored tool passes; otherwise why not.
    $backup = Join-Path $Here ('backup\' + $engine.id)
    if (-not (Test-Path -LiteralPath $backup)) { return 'no-backup' }
    if (-not (Invoke-Robocopy $backup $dir)) { return 'restore-failed' }
    return Get-EngineProblem $engine
}

function Update-OneEngine($engine, [string]$winget) {
    # One tool: @{tool; outcome = updated | current | failed | not-installed; before; after; reason; safe}. `safe` is
    # false only when the tool may be left half-replaced or unverified: then the marker stays (fail closed).
    $r = @{ tool = $engine.tool; outcome = 'failed'; before = $null; after = $null; reason = $null; safe = $true }
    $link = Join-Path $WingetLinks $engine.exe
    $dir = Get-PackageDir (Get-LinkTarget $link)
    if (-not $dir -or -not (Test-Path -LiteralPath $dir)) { $r.outcome = 'not-installed'; return $r }
    $r.before = Get-InstalledVersion $engine.id
    if (-not $r.before) { $r.reason = 'version-unreadable'; return $r }
    $showArgs = @('show', '--id', $engine.id, '--exact', '--source', 'winget', '--disable-interactivity', '--accept-source-agreements')
    $show = Invoke-Winget $winget $showArgs 120
    $latest = Get-ShowVersion $show.out
    if (-not $latest) { $r.reason = 'source-unreadable'; return $r }
    if (-not (Test-Newer $latest $r.before)) { $r.outcome = 'current'; $r.after = $r.before; return $r }
    $backup = Join-Path $Here ('backup\' + $engine.id)
    if (-not (Invoke-Robocopy $dir $backup)) { $r.reason = 'backup-failed'; return $r }
    # From here the tool may change: it is safe again only once checked, or restored and checked.
    $r.safe = $false
    $script:Touching = $engine.tool
    # `install --force`, not `upgrade`: as SYSTEM, winget can't see the portable install to upgrade it (29 Nov); the
    # same command the bootstrap uses (--scope machine --force), from the winget source only.
    # --skip-dependencies: Copilot's manifest declares Microsoft.PowerShell, which winget otherwise installs (as an
    # MSIX, for SYSTEM: seen on the test VM, 29 Nov). The hosts use the pinned PowerShell 7, as the bootstrap does.
    $upArgs = @('install', '--id', $engine.id, '--exact', '--scope', 'machine', '--force', '--source', 'winget', '--silent',
                '--skip-dependencies', '--disable-interactivity', '--accept-source-agreements', '--accept-package-agreements')
    $run = Invoke-Winget $winget $upArgs
    $problem = Get-EngineProblem $engine
    if ($problem) {
        # Condition 2: never leave an unverified program in place. Put the old package back, exactly, and check it.
        $after = Restore-Engine $engine $dir
        $r.reason, $r.safe = $(if ($after) { 'restore-failed' } else { $problem }), (-not $after)
        if ($r.safe) { $script:Touching = $null }
        return $r
    }
    Assert-WingetRootSafe
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    & $icacls $dir /reset /T /C /Q | Out-Null
    $r.safe = $true   # checked: the pinned publisher's program, whatever its version
    $script:Touching = $null
    if ($LASTEXITCODE -ne 0) { $r.reason = 'acl-reset-failed'; return $r }
    $r.after = Get-InstalledVersion $engine.id
    if ($run.timedOut) { $r.reason = 'winget-timeout'; return $r }
    if ($run.code -ne 0 -or -not $r.after -or $r.after -eq $r.before) { $r.reason = 'winget-failed'; return $r }
    $r.outcome = 'updated'
    return $r
}

function Repair-AfterInterruption {
    # A marker left by a run that died: wait for anything it started to stop, then check every tool, restoring any
    # that fails from its backup. Returns @{ safe; results }.
    $deadline = (Get-Date).AddSeconds($WaitInstallersSeconds)
    while (@(Get-Process -Name $InstallerProcesses -ErrorAction SilentlyContinue).Count) {
        if ((Get-Date) -gt $deadline) { return @{ safe = $false; results = @() } }   # still running: later
        Wait-Beating 15 'recovering'
    }
    $results = @(foreach ($e in $Engines) {
            $r = @{ tool = $e.tool; outcome = 'current'; before = $null; after = $null; reason = $null; safe = $true }
            $dir = Get-PackageDir (Get-LinkTarget (Join-Path $WingetLinks $e.exe))
            if (-not $dir) { $r.outcome = 'not-installed' }
            elseif ($problem = Get-EngineProblem $e) {
                $after = Restore-Engine $e $dir
                $r.outcome, $r.reason, $r.safe = 'failed', $(if ($after) { 'restore-failed' } else { "restored-after-$problem" }), (-not $after)
            }
            $r.before = $r.after = Get-InstalledVersion $e.id
            $r
        })
    return @{ safe = -not ($results | Where-Object { -not $_.safe }); results = $results }
}

function Write-Result([hashtable]$result) {
    # Atomic: a temp file in the same admin-only folder, then a move over the old one.
    $tmp = Join-Path $Here ('result-' + [guid]::NewGuid().ToString('n') + '.tmp')
    [IO.File]::WriteAllText($tmp, ($result | ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $tmp -Destination $ResultFile -Force
}

function Read-LastResult {
    try { return Get-Content -LiteralPath $ResultFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return $null }
}

function New-Result([string]$state, $results, $busy = @(), [string]$mode = 'update') {
    return @{ v = 1; day = (Get-Date).ToString('yyyy-MM-dd'); state = $state; mode = $mode; busy = @($busy)
              written_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
              results = @($results | ForEach-Object { @{ tool = $_.tool; outcome = $_.outcome; before = $_.before; after = $_.after; reason = $_.reason } }) }
}

if ($MyInvocation.InvocationName -eq '.') { return }

# --- 0. One run at a time on this PC (u64-security, #humans 29459): a second start exits at once. A holder that died
#        leaves the mutex abandoned, which is ours to take. Released when this process ends.
$mutex = New-Object Threading.Mutex($false, 'Global\StrugglebusEngineUpdate')
try { if (-not $mutex.WaitOne(0)) { exit 0 } } catch [Threading.AbandonedMutexException] { }
# Nothing the host account can write decides what happens from here: the window is the script's own, and the marker
# and result are admin-only. The account has no right to start this task at all (29459): it runs from its own triggers.

# --- 1. A marker left by a run that died: recover first, at any hour (the hourly trigger). Only a run that FINISHES
#        removes the marker; until then every host stays closed (fail closed; #humans 29453-29455).
if (Test-Path -LiteralPath $Marker) {
    $beat = (Get-Item -LiteralPath $Marker).LastWriteTimeUtc
    if (([DateTime]::UtcNow - $beat).TotalSeconds -lt 3 * $BeatSeconds) { exit 0 }   # a live run holds it
    Set-Marker 'recovering'
    $rec = Repair-AfterInterruption
    if ($rec.results.Count) { Write-Result (New-Result $(if ($rec.safe) { 'done' } else { 'interrupted' }) $rec.results @() 'recovery') }
    if ($rec.safe) { Remove-Item -LiteralPath $Marker -Force }
    exit 0
}

# --- 2. The nightly update: inside the window, once a night, only when no host on this PC is busy.
if (-not (Test-InWindow (Get-Date))) { exit 0 }
$last = Read-LastResult
if ($last -and $last.day -eq (Get-Date).ToString('yyyy-MM-dd') -and $last.state -eq 'done' -and $last.mode -eq 'update') { exit 0 }
$hostRoot = Join-Path $SbRoot 'host'
Set-Marker 'waiting'   # admission closed FIRST (condition 4): from here, no host takes a new task
Wait-Beating $SettleSeconds 'waiting'   # every host's loop sees the marker; a claim already in flight lands
$deadline = (Get-Date).AddSeconds($WaitIdleSeconds)
$busy = Get-BusyHosts $hostRoot ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
while ($busy.Count -and (Get-Date) -lt $deadline) {
    Wait-Beating 20 'waiting'
    $busy = Get-BusyHosts $hostRoot ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
}
if ($busy.Count) {
    # Nothing was touched: open again, and try on the next run inside the window.
    Write-Result (New-Result 'waiting' @() $busy)
    Remove-Item -LiteralPath $Marker -Force
    exit 0
}
$results = @()
$script:Touching = $null
try {
    $winget = Get-SystemWinget
    foreach ($e in $Engines) {
        Set-Marker 'updating'
        $results += Update-OneEngine $e $winget
    }
} catch {
    # An unexpected error: what wasn't reached is reported as failed and untouched; anything mid-replacement is
    # unsafe, so the marker stays and the next run recovers.
    $reason = if ("$($_.Exception.Message)" -match '^[a-z]+(-[a-z]+)*$') { $_.Exception.Message } else { 'error' }
    $done = @($results | ForEach-Object { $_.tool })
    $results += @(foreach ($e in $Engines) { if ($done -notcontains $e.tool) { @{ tool = $e.tool; outcome = 'failed'; reason = $reason; safe = ($e.tool -ne $script:Touching) } } })
}
$safe = -not ($results | Where-Object { -not $_.safe })
Write-Result (New-Result $(if ($safe) { 'done' } else { 'interrupted' }) $results)
if ($safe) { Remove-Item -LiteralPath $Marker -Force }   # admission open again only when every tool is checked
exit 0
