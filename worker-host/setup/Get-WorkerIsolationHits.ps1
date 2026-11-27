<#
.SYNOPSIS
  Generic worker-account isolation check: can the worker account change anything that ANOTHER account (or the system)
  runs automatically? Each such path is a way for a worker job to take over that account.

.DESCRIPTION
  Written by u64-security for the worker-host bootstrap (strugglebus-improvements 28470/28471, condition Q5): the
  lesson of the DevBox account split, where C:\repos and D:\ inherited "Authenticated Users: Modify" and every agent's
  Startup scripts and scheduled tasks ran from there.

  Dot-source this file and call:   Get-WorkerIsolationHits -Account sbworker [-Exclude D:\workers]

  It looks at what runs automatically as someone other than the worker:
    - scheduled tasks (every folder; their program, script paths in the arguments, and working directory);
    - Startup folders (all users' and the common one) and each shortcut's target and arguments;
    - Run / RunOnce registry keys (HKLM, WOW6432Node, and every loaded user hive);
    - services (their program path);
  and, as a lower-severity finding, top-level folders on each fixed drive and in ProgramData that the worker can write.

  "Can write" is decided from the ACLs (no need to log on as the worker): allow ACEs minus deny ACEs for the worker's
  SID, its local groups, and the groups every standard account has (Everyone, Authenticated Users, Users, BATCH,
  INTERACTIVE, Local account, LOCAL). Ownership by any of those counts as write (an owner can change the ACL).
  For a file: write data, append, change permissions or take ownership. For a folder: add a file or subfolder (plant
  a module or DLL next to a script), change permissions or take ownership. For a registry key: set value, create
  subkey, change permissions or take ownership.

  Run it ELEVATED: without elevation, other users' tasks and Startup folders are partly invisible and the result says
  "incomplete". It reads only; it changes nothing.

  Output: one object per hit, with Severity (exec = something runs from it; info = writable top-level folder),
  Kind, Source (the task, shortcut, value or service), Path and Why. An empty result means no hit was found, not
  that the machine is proven safe: relative paths inside scripts, and code loaded by the programs themselves, are
  not followed.

.LIMITATIONS
  - Group membership comes from local groups and well-known SIDs. A domain account's domain groups aren't expanded.
  - Mandatory integrity labels and conditional ACEs are ignored (conservative: they can only remove access).
  - Paths are taken from absolute paths in the command line. Relative paths and paths built at run time aren't seen.
#>

function Get-WorkerIsolationHits {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Account,   # the worker's local account name, e.g. sbworker
        [string[]]$Exclude = @()                  # folders the worker is meant to own (its home, its work dir)
    )

    $hits = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)

    # ---- the worker's SIDs -------------------------------------------------------------------------------------------
    $sids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($s in 'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-3', 'S-1-5-4', 'S-1-5-113', 'S-1-2-0') { [void]$sids.Add($s) }
    $workerSid = $null
    try {
        $workerSid = ([Security.Principal.NTAccount]$Account).Translate([Security.Principal.SecurityIdentifier]).Value
        [void]$sids.Add($workerSid)
        foreach ($g in Get-LocalGroup) {
            $members = @(Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue)
            if ($members | Where-Object { $_.SID.Value -eq $workerSid }) {
                [void]$sids.Add($g.SID.Value)
                if ($g.SID.Value -eq 'S-1-5-32-544') {
                    $hits.Add([pscustomobject]@{ Severity = 'exec'; Kind = 'account'; Source = $Account; Path = ''
                                                 Why = 'the worker account is a member of Administrators' })
                }
            }
        }
    }
    catch { Write-Warning "Account '$Account' not found; checking with the standard groups only." }

    $profileDir = if ($workerSid) {
        (Get-CimInstance Win32_UserProfile -Filter "SID='$workerSid'" -ErrorAction SilentlyContinue).LocalPath } else { $null }
    $excl = @($Exclude + @($profileDir) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') + '\' })

    # ---- ACL evaluation --------------------------------------------------------------------------------------------
    $FILE_MASK = 0x2 -bor 0x4 -bor 0x40000 -bor 0x80000 -bor 0x40000000 -bor 0x10000000
    $DIR_MASK  = 0x2 -bor 0x4 -bor 0x40000 -bor 0x80000 -bor 0x40000000 -bor 0x10000000
    $REG_MASK  = 0x2 -bor 0x4 -bor 0x40000 -bor 0x80000 -bor 0x40000000 -bor 0x10000000

    function Test-AclWrite($acl, [int]$mask, [bool]$isContainer) {
        if (-not $acl) { return $null }
        $owner = try { $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { $null }
        if ($owner -and $sids.Contains($owner)) { return "owned by $owner" }
        $allow = 0; $deny = 0; $who = @()
        foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if (-not $sids.Contains($ace.IdentityReference.Value)) { continue }
            # an inherit-only ACE on a container applies to its children, not to the container itself
            if ($isContainer -and ($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
            $bits = [int64]$ace.($(if ($ace -is [Security.AccessControl.RegistryAccessRule]) { 'RegistryRights' } else { 'FileSystemRights' }))
            $bits = $bits -band 0xFFFFFFFF
            if ($ace.AccessControlType -eq 'Deny') { $deny = $deny -bor $bits }
            else { $allow = $allow -bor $bits; if ($bits -band $mask) { $who += $ace.IdentityReference.Translate([Security.Principal.NTAccount]).Value } }
        }
        $eff = $allow -band (-bnot $deny) -band $mask
        if ($eff) { return ('writable by ' + (($who | Select-Object -Unique) -join ', ')) }
        return $null
    }

    function Get-AclSafe([string]$path) {
        # Get-Acl throws "unauthorized" on some protected folders even with -ErrorAction SilentlyContinue
        try { return Get-Acl -LiteralPath $path -ErrorAction Stop } catch { return $null }
    }

    function Test-PathWrite([string]$path) {
        # returns the reason or $null; checks the file itself and the folder it sits in
        if (-not $path) { return $null }
        $p = [Environment]::ExpandEnvironmentVariables($path.Trim('"', "'", ' '))
        foreach ($e in $excl) { if (($p.TrimEnd('\') + '\').StartsWith($e, [StringComparison]::OrdinalIgnoreCase)) { return $null } }
        if (Test-Path -LiteralPath $p -PathType Leaf) {
            $r = Test-AclWrite (Get-AclSafe $p) $FILE_MASK $false
            if ($r) { return "file $r" }
            $d = [IO.Path]::GetDirectoryName($p)
            $r = Test-AclWrite (Get-AclSafe $d) $DIR_MASK $true
            if ($r) { return "its folder $d is $r (a file can be planted beside it)" }
        }
        elseif (Test-Path -LiteralPath $p -PathType Container) {
            $r = Test-AclWrite (Get-AclSafe $p) $DIR_MASK $true
            if ($r) { return "folder $r" }
        }
        return $null
    }

    function Get-CommandPaths([string]$exe, [string]$cmdArgs, [string]$workDir) {
        # absolute paths in a program + argument string: quoted, then unquoted tokens
        $all = @()
        $text = (@($exe, $cmdArgs) -join ' ')
        $text = [Environment]::ExpandEnvironmentVariables($text)
        foreach ($m in [regex]::Matches($text, '["'']([A-Za-z]:\\[^"'']+)["'']')) { $all += $m.Groups[1].Value }
        $unq = [regex]::Replace($text, '["''][^"'']*["'']', ' ')
        foreach ($m in [regex]::Matches($unq, '(?<![\w\\])([A-Za-z]:\\[^\s;|&<>]+)')) { $all += $m.Groups[1].Value }
        if ($exe -and -not ($exe -match '^[A-Za-z]:\\') -and -not ($exe -match '[\\/]')) {
            $c = Get-Command $exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($c) { $all += $c.Source }
        }
        if ($workDir) { $all += [Environment]::ExpandEnvironmentVariables($workDir) }
        return $all | ForEach-Object { $_.TrimEnd(',', '.') } | Select-Object -Unique
    }

    function Add-Hit($severity, $kind, $source, $path, $why) {
        $key = "$kind|$path"
        if ($seen.ContainsKey($key)) { return }; $seen[$key] = $true
        $hits.Add([pscustomobject]@{ Severity = $severity; Kind = $kind; Source = $source; Path = $path; Why = $why })
    }

    function Check-Command($kind, $source, $exe, $cmdArgs, $workDir) {
        foreach ($p in Get-CommandPaths $exe $cmdArgs $workDir) {
            $r = Test-PathWrite $p
            if ($r) { Add-Hit 'exec' $kind $source $p $r }
        }
    }

    # ---- scheduled tasks ----------------------------------------------------------------------------------------------
    foreach ($t in Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $uid = "$($t.Principal.UserId)"
        if ($workerSid -and ($uid -match "(^|\\)$([regex]::Escape($Account))$" -or $uid -eq $workerSid)) { continue }  # the worker's own
        foreach ($a in $t.Actions) {
            if ($a.CimClass.CimClassName -ne 'MSFT_TaskExecAction') { continue }
            Check-Command 'scheduled-task' "$($t.TaskPath)$($t.TaskName) (runs as $(if ($uid) { $uid } else { $t.Principal.GroupId }))" $a.Execute $a.Arguments $a.WorkingDirectory
        }
    }

    # ---- Startup folders and shortcuts --------------------------------------------------------------------------------
    $shell = New-Object -ComObject WScript.Shell
    $startups = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
    foreach ($u in Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { -not $_.Special }) {
        if ($workerSid -and $u.SID -eq $workerSid) { continue }
        $startups += Join-Path $u.LocalPath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    }
    foreach ($sf in $startups) {
        if (-not (Test-Path -LiteralPath $sf)) { continue }
        $r = Test-AclWrite (Get-AclSafe $sf) $DIR_MASK $true
        if ($r) { Add-Hit 'exec' 'startup-folder' $sf $sf "folder $r (anything added runs at that user's logon)" }
        foreach ($item in Get-ChildItem -LiteralPath $sf -File -ErrorAction SilentlyContinue) {
            $r = Test-AclWrite (Get-AclSafe $item.FullName) $FILE_MASK $false
            if ($r) { Add-Hit 'exec' 'startup-item' $item.FullName $item.FullName "file $r" }
            if ($item.Extension -eq '.lnk') {
                $lnk = $shell.CreateShortcut($item.FullName)
                Check-Command 'startup-item' $item.FullName $lnk.TargetPath $lnk.Arguments $lnk.WorkingDirectory
            }
            else { Check-Command 'startup-item' $item.FullName $item.FullName '' '' }
        }
    }

    # ---- Run / RunOnce keys ------------------------------------------------------------------------------------------
    $runKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce')
    if (-not (Get-PSDrive HKU -ErrorAction SilentlyContinue)) { [void](New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Script) }
    foreach ($hive in Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' }) {
        if ($workerSid -and $hive.PSChildName -eq $workerSid) { continue }
        $runKeys += "HKU:\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run", "HKU:\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    foreach ($k in $runKeys) {
        try {
            if (-not (Test-Path $k -ErrorAction Stop)) { continue }
            $r = Test-AclWrite (Get-Acl -Path $k -ErrorAction Stop) $REG_MASK $true
            if ($r) { Add-Hit 'exec' 'run-key' $k $k "registry key $r" }
            $item = Get-Item -Path $k -ErrorAction Stop
            foreach ($name in $item.GetValueNames()) {
                $cmd = [string]$item.GetValue($name)
                Check-Command 'run-key' "$k\$name" '' $cmd ''
            }
        }
        catch { Write-Warning "Could not read $k ($($_.Exception.Message)); run elevated for a complete result." }
    }

    # ---- services -----------------------------------------------------------------------------------------------------
    foreach ($svc in Get-CimInstance Win32_Service -ErrorAction SilentlyContinue) {
        if (-not $svc.PathName) { continue }
        if ($workerSid -and $svc.StartName -match "(^|\\)$([regex]::Escape($Account))$") { continue }
        $pn = $svc.PathName
        if ($pn -notmatch '^\s*"' -and $pn -match '^\s*([A-Za-z]:\\[^"]*?\.exe)') { $pn = '"' + $Matches[1] + '"' + $pn.Substring($Matches[0].Length) }
        Check-Command 'service' "$($svc.Name) (runs as $($svc.StartName))" '' $pn ''
    }

    # ---- writable top-level folders (info) ------------------------------------------------------------------------------
    $tops = @()
    foreach ($d in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue) {
        $root = "$($d.DeviceID)\"
        $tops += $root
        $tops += Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin 'Windows', '$Recycle.Bin', 'System Volume Information', 'Recovery', 'Config.Msi' } |
            ForEach-Object FullName
    }
    $tops += Get-ChildItem -LiteralPath $env:ProgramData -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object FullName
    foreach ($p in $tops) {
        $skip = $false
        foreach ($e in $excl) { if (($p.TrimEnd('\') + '\').StartsWith($e, [StringComparison]::OrdinalIgnoreCase)) { $skip = $true } }
        if ($skip) { continue }
        $r = Test-AclWrite (Get-AclSafe $p) $DIR_MASK $true
        if ($r) { Add-Hit 'info' 'writable-folder' $p $p "folder $r; new folders created under it inherit that" }
    }

    if (-not $elevated) { Write-Warning 'Not elevated: other accounts'' tasks, Startup folders and hives may be missing. Result is INCOMPLETE.' }
    return $hits
}
