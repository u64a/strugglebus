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
#      from before the idle check until after the publisher check or rollback (prox-manager, #humans 29445): the
#      marker engine-update\updating.json is written first, hosts take no new task while it is fresh, and it is
#      removed in a finally. A marker older than the hosts' limit (45 min) is ignored, so a crash never blocks work.
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

function Update-OneEngine($engine, [string]$winget) {
    # One tool: its outcome as @{tool; outcome = updated | current | failed | not-installed; before; after; reason}.
    $r = @{ tool = $engine.tool; outcome = 'failed'; before = $null; after = $null; reason = $null }
    $link = Join-Path $WingetLinks $engine.exe
    $target = Get-LinkTarget $link
    $dir = Get-PackageDir $target
    if (-not $dir -or -not (Test-Path -LiteralPath $dir)) { $r.outcome = 'not-installed'; return $r }
    $r.before = Get-InstalledVersion $engine.id
    if (-not $r.before) { $r.reason = 'version-unreadable'; return $r }
    $showArgs = @('show', '--id', $engine.id, '--exact', '--source', 'winget', '--disable-interactivity', '--accept-source-agreements')
    $latest = Get-ShowVersion ((& $winget @showArgs 2>&1) -join "`n")
    if (-not $latest) { $r.reason = 'source-unreadable'; return $r }
    if (-not (Test-Newer $latest $r.before)) { $r.outcome = 'current'; $r.after = $r.before; return $r }
    $backup = Join-Path $Here ('backup\' + $engine.id)
    if (-not (Invoke-Robocopy $dir $backup)) { $r.reason = 'backup-failed'; return $r }
    # `install --force`, not `upgrade`: as SYSTEM, winget can't see the portable install to upgrade it (29 Nov); the
    # same command the bootstrap uses (--scope machine --force), from the winget source only.
    # --skip-dependencies: Copilot's manifest declares Microsoft.PowerShell, which winget otherwise installs (as an
    # MSIX, for SYSTEM: seen on the test VM, 29 Nov). The hosts use the pinned PowerShell 7, as the bootstrap does.
    $upArgs = @('install', '--id', $engine.id, '--exact', '--scope', 'machine', '--force', '--source', 'winget', '--silent',
                '--skip-dependencies', '--disable-interactivity', '--accept-source-agreements', '--accept-package-agreements')
    & $winget @upArgs 2>&1 | Out-Null
    $code = $LASTEXITCODE
    $target = Get-LinkTarget $link   # the upgrade may have replaced the link
    $sig = if ($target -and (Test-Path -LiteralPath $target)) { Get-AuthenticodeSignature -LiteralPath $target } else { $null }
    $problem = if ($sig) { Get-PublisherProblem $sig.Status $sig.SignerCertificate.Subject $engine.org } else { 'signature-invalid' }
    if ($problem) {
        # Condition 2: never leave an unverified program in place. Put the old package back, exactly.
        $r.reason = if (Invoke-Robocopy $backup $dir) { $problem } else { 'restore-failed' }
        return $r
    }
    Assert-WingetRootSafe
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    & $icacls $dir /reset /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { $r.reason = 'acl-reset-failed'; return $r }
    $r.after = Get-InstalledVersion $engine.id
    if ($code -ne 0 -or -not $r.after -or $r.after -eq $r.before) { $r.reason = 'winget-failed'; return $r }
    $r.outcome = 'updated'
    return $r
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

if ($MyInvocation.InvocationName -eq '.') { return }

$now = Get-Date
if (-not (Test-InWindow $now)) { exit 0 }
$today = $now.ToString('yyyy-MM-dd')
$last = Read-LastResult
if ($last -and $last.day -eq $today -and $last.state -eq 'done') { exit 0 }   # once a night
$hostRoot = Join-Path $SbRoot 'host'
# Admission closed FIRST (condition 4): from here until the finally, no host takes a new task.
[IO.File]::WriteAllText($Marker, (@{ v = 1; started_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() } | ConvertTo-Json),
    [Text.UTF8Encoding]::new($false))
try {
    Start-Sleep -Seconds $SettleSeconds   # every host's loop sees the marker; a claim already in flight lands
    $deadline = (Get-Date).AddSeconds($WaitIdleSeconds)
    $busy = Get-BusyHosts $hostRoot ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    while ($busy.Count -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 20
        $busy = Get-BusyHosts $hostRoot ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    }
    if ($busy.Count) {
        # Still busy after the wait: try again on the task's next run inside the window.
        Write-Result @{ v = 1; day = $today; state = 'waiting'; written_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); busy = $busy; results = @() }
    } else {
        try {
            $winget = Get-SystemWinget
            $results = @(foreach ($e in $Engines) { Update-OneEngine $e $winget })
        } catch {
            $reason = if ("$($_.Exception.Message)" -match '^[a-z]+(-[a-z]+)*$') { $_.Exception.Message } else { 'error' }
            $results = @(foreach ($e in $Engines) { @{ tool = $e.tool; outcome = 'failed'; before = $null; after = $null; reason = $reason } })
        }
        Write-Result @{ v = 1; day = $today; state = 'done'; written_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); busy = @(); results = $results }
    }
} finally {
    Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue   # admission open again
}
exit 0
