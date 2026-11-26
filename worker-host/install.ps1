<#
.SYNOPSIS
  Installs, updates or removes the strugglebus worker host on this machine.

.DESCRIPTION
  Copies the host code to <home>\app, writes <home>\config.toml from config.template.toml (only if
  there is none yet; capacity is picked from the installed memory), makes <home> owner-only, puts
  `wh` on the user PATH, registers the scheduled task and runs `wh probe` the way the host will run.
  The task is left disabled: `wh enrol`, then `wh start`.

  Two logon modes (-Logon):
    Password     (default) At startup, 2-minute delay, run whether logged on or not, logon type
                 Password. For a local account with a password. Your Windows password is asked for
                 once, handed to Task Scheduler and not kept anywhere by this script. The probe runs
                 through a scheduled task with the same logon, so it sees what the host will see.
    Interactive  At log on of the installing user, 1-minute delay, run only when the user is logged
                 on, no stored password. For Entra ID accounts that sign in with Windows Hello for
                 Business (no password to give Task Scheduler). After a reboot the host comes back
                 once you sign in. The probe runs here, in your signed-in session, which is where
                 the task runs.
  Both: network required, restart on failure every minute (999 times, the Task Scheduler maximum),
  no execution time limit, one instance, least privilege. The action is `wh.py supervise`, which
  runs the host as a child process and restarts it after a crash (10 s, 30 s, 60 s, then every
  5 minutes); Task Scheduler's own restart only covers a task that fails to launch. Re-running
  this script updates the action of an existing install.

  Nothing here reads, prints or stores a bus credential; that is `wh enrol`.

.PARAMETER Home
  Host home folder. Default %LOCALAPPDATA%\strugglebus-worker-host.
.PARAMETER WorkersRoot
  Where worker clones go (written to a new config only). Default C:\sb-workers.
.PARAMETER HostName
  This machine's short name (new config only). Default: the computer name, lower-cased.
.PARAMETER AgentPrefix
  The bus name prefix for every identity this host uses: the host is <AgentPrefix>-host, a worker
  <AgentPrefix>-<worker>. It MUST equal the name of the SPN whose credential `wh enrol` is given:
  the bus refuses any other name (HTTP 422 "agent name is outside the SPN prefix"). Default
  sb-host-<host_name>. Given on a re-run, it replaces agent_prefix in the existing config.
.PARAMETER SiteFile
  Your site's values for a NEW config: the bus URL, fleet repository, coordinator, allowed remotes and OpenBao
  (copy site.example.toml and fill it in). Checked by workerhost\sitefile.py before anything is written. Required when
  there is no config.toml yet; ignored (and an existing config left as it is) otherwise.
.PARAMETER BusCa
  The bus LAN root certificate file (new config only). Required when there is no config.toml yet.
.PARAMETER Logon
  Password (default) or Interactive, see above. Recorded as logon_type in config.toml.
.PARAMETER DefaultEngine
  ghcp (GitHub Copilot CLI) or claude (Claude Code): the engine for a task that names none (config.toml
  [engines] default; docs/agent-host-build.md 7.6). A new config without it: you are asked (ghcp if nobody can
  answer). Given on a re-run, it sets the default in the existing config, adding the [engines] block if missing.
  Claude Code must also be installed and signed in (`claude`, then /login) for tasks to use it.
.PARAMETER NoScheduledTask
  Do not register a scheduled task (dry runs; the config gets scheduled_task = "").
.PARAMETER NoPath
  Do not add the app folder to the user PATH.
.PARAMETER NoPanel
  Do not put the status window ("Strugglebus host", `wh panel`) in your Startup folder. By default it is
  added, so it opens at every sign-in (RDP included), and it is started at the end of the install.
.PARAMETER UpdatePassword
  Only re-enter the Windows password for the existing task (Password mode, after a password change).
.PARAMETER PinSigners
  Only pin the signing keys: copy keys\allowed_signers (your site's file, kept with your deployment) to
  C:\ProgramData\strugglebus\allowed_signers, writable by administrators only, after showing every
  fingerprint and asking you to confirm them against your own copy (docs/signing-keys.md section 7).
  Needs an elevated PowerShell. Run it once per host, and again by hand whenever the key list changes:
  the repository can never change what a host trusts by itself. (setup.ps1 -Only signers, later, does
  the same with a YubiKey check added.)
.PARAMETER Uninstall
  Stop the host (workers are killed: drain first), remove the scheduled task, the app folder and
  the PATH entry. Config, credentials, state and logs stay unless -Purge. Worker clones are never touched.
.PARAMETER Purge
  With -Uninstall: also delete the whole home folder, including the DPAPI credentials.

.EXAMPLE
  pwsh -File install.ps1 -SiteFile ..\my-site.toml -BusCa C:\certs\lan-root.crt -AgentPrefix host-box1
.EXAMPLE
  pwsh -File install.ps1   (an existing install: update the code, keep config.toml)
.EXAMPLE
  pwsh -File install.ps1 -Logon Interactive
.EXAMPLE
  pwsh -File install.ps1 -Home $env:TEMP\wh-dry -NoScheduledTask -NoPath
#>
[CmdletBinding()]
param(
    [Alias('Home')][string]$HostHome = (Join-Path $env:LOCALAPPDATA 'strugglebus-worker-host'),
    [string]$WorkersRoot = 'C:\sb-workers',
    [string]$HostName = '',
    [string]$AgentPrefix = '',
    [string]$BusCa = '',
    [string]$SiteFile = '',
    [ValidateSet('Password', 'Interactive')][string]$Logon = 'Password',
    [ValidateSet('', 'ghcp', 'claude')][string]$DefaultEngine = '',
    [switch]$NoScheduledTask,
    [switch]$NoPath,
    [switch]$UpdatePassword,
    [switch]$PinSigners,
    [switch]$NoPanel,
    [switch]$Uninstall,
    [switch]$Purge
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TaskName = 'StrugglebusWorkerHost'
$ProbeTask = 'StrugglebusWorkerHost-Probe'
$Source = $PSScriptRoot
$HostHome = [IO.Path]::GetFullPath($HostHome)
$App = Join-Path $HostHome 'app'
$Config = Join-Path $HostHome 'config.toml'

function Say([string]$text) { Write-Host "[install] $text" }

function Get-Capacity([double]$RamGb) {
    # Starting points: a 128 GB machine runs 12 workers at 8 GB, a 64 GB machine 6. Anything else gets
    # a cautious 2, and the installer says to edit the config.
    if ($RamGb -ge 96) { return [pscustomobject]@{ MaxWorkers = 12; WorkerCommitGb = 8; Profile = '128gb' } }
    if ($RamGb -ge 60) { return [pscustomobject]@{ MaxWorkers = 6; WorkerCommitGb = 8; Profile = '64gb' } }
    return [pscustomobject]@{ MaxWorkers = 2; WorkerCommitGb = 8; Profile = 'other' }
}

function Get-InstalledMemoryGb {
    $sticks = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue | Where-Object { $_.Capacity })
    $bytes = if ($sticks.Count) { ($sticks | Measure-Object -Property Capacity -Sum).Sum } else {
        (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory }
    return [math]::Round($bytes / 1GB)
}

function Set-LogonLine([string]$text, [string]$mode) {
    $line = "logon_type = `"$mode`""
    $pattern = '(?m)^logon_type\s*=\s*"[^"]*"'
    if ([regex]::IsMatch($text, $pattern)) { return [regex]::Replace($text, $pattern, $line) }
    # A top-level key must come before the first [table], or TOML would put it inside that table.
    $table = [regex]::Match($text, '(?m)^\[')
    if ($table.Success) { return $text.Insert($table.Index, "$line`n`n") }
    return $text.TrimEnd() + "`n$line`n"
}

function New-HostTaskXml {
    # The definition of the host task, as Task Scheduler XML. Pure: registers nothing.
    param(
        [Parameter(Mandatory)][ValidateSet('Password', 'Interactive')][string]$Mode,
        [Parameter(Mandatory)][string]$UserId,
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][string]$Arguments,
        [Parameter(Mandatory)][string]$WorkingDirectory
    )
    $e = { param($s) [Security.SecurityElement]::Escape($s) }
    $user = & $e $UserId
    if ($Mode -eq 'Password') {
        $trigger = "<BootTrigger><Enabled>true</Enabled><Delay>PT2M</Delay></BootTrigger>"
        $logonType = 'Password'
    } else {
        $trigger = "<LogonTrigger><Enabled>true</Enabled><UserId>$user</UserId><Delay>PT1M</Delay></LogonTrigger>"
        $logonType = 'InteractiveToken'
    }
    # RunOnlyIfNetworkAvailable is false on purpose: with true, Windows STOPS the host the moment the network drops
    # (a Wi-Fi blip, a router reboot) and nothing starts it again until the next boot. The host itself rides out an
    # unreachable bus and retries (seen on a laptop host, 26 Nov 2026: stopped by a 2-minute gateway reboot).
    return @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>strugglebus worker host ($Mode logon). Disabled until 'wh start'.</Description>
  </RegistrationInfo>
  <Triggers>$trigger</Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$user</UserId>
      <LogonType>$logonType</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
    <Enabled>false</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$(& $e $Command)</Command>
      <Arguments>$(& $e $Arguments)</Arguments>
      <WorkingDirectory>$(& $e $WorkingDirectory)</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@
}

function Get-HostTaskArguments([string]$App, [string]$HostHome) {
    # The scheduled task runs the supervisor, which runs and restarts the host after a crash. Pure, for the tests.
    return "`"$App\wh.py`" --home `"$HostHome`" supervise"
}

function Test-PythonVersion([string]$line) {
    # "Python 3.11.9" -> $true when 3.11 or later. Pure, for the tests.
    $m = [regex]::Match($line, 'Python (\d+)\.(\d+)')
    return $m.Success -and ([int]$m.Groups[1].Value -gt 3 -or ([int]$m.Groups[1].Value -eq 3 -and [int]$m.Groups[2].Value -ge 11))
}

function Select-CopilotExe([string]$found, [string]$wingetLink, [bool]$linkExists) {
    # The WindowsApps app-execution alias for copilot refuses to run outside an interactive session
    # ("Access is denied" under a scheduled task or SSH), so when PATH resolves to it and the winget
    # link exists, the host uses the link. Pure, for the tests.
    if ($found -match '\\Microsoft\\WindowsApps\\' -and $linkExists) { return [IO.Path]::GetFullPath($wingetLink) }
    return $found
}

function Set-CopilotLine([string]$text, [string]$exe) {
    # Refresh copilot_exe in an existing config to what this run found (the paths are the installer's).
    if ($exe.Contains("'")) { throw "path $exe contains a quote" }
    return [regex]::Replace($text, "(?m)^copilot_exe\s*=\s*'[^']*'", "copilot_exe = '$exe'")
}

function Get-EnginesBlock([string]$template) {
    # The template's [engines] and [engines.claude] tables, verbatim (comments included), up to the next other table.
    $m = [regex]::Match($template, '(?ms)^\[engines\]\r?\n.*?(?=^\[(?!engines)[^\]]+\]|\z)')
    if (-not $m.Success) { throw 'config.template.toml has no [engines] table' }
    return $m.Value.TrimEnd() + "`n"
}

function Set-EngineDefault([string]$text, [string]$engine, [string]$template) {
    # Sets `default = "<engine>"` inside [engines]; a config from before engines gets the template's block appended.
    if ($text -notmatch '(?m)^\[engines\]\s*$') {
        $block = (Get-EnginesBlock $template).Replace('@DEFAULT_ENGINE@', $engine)
        return $text.TrimEnd() + "`n`n" + $block
    }
    $m = [regex]::Match($text, '(?ms)^\[engines\]\s*\r?\n(.*?)(?=^\[|\z)')
    $body = $m.Groups[1].Value
    if ($body -match '(?m)^default\s*=') {
        $new = [regex]::Replace($body, '(?m)^default\s*=.*$', "default = `"$engine`"")
    } else {
        $new = "default = `"$engine`"`n" + $body
    }
    return $text.Substring(0, $m.Groups[1].Index) + $new + $text.Substring($m.Groups[1].Index + $body.Length)
}

function Read-DefaultEngine {
    # Asked once for a new config. Nobody to answer (a non-interactive install): ghcp, and say so.
    Say 'Default engine for tasks that do not name one: ghcp (GitHub Copilot CLI) or claude (Claude Code)?'
    try {
        $a = (Read-Host 'ghcp or claude [ghcp]').Trim().ToLower()
    } catch { $a = '' }
    if ($a -in @('ghcp', 'claude')) { return $a }
    if ($a) { Say "'$a' is neither: using ghcp" }
    return 'ghcp'
}

function Test-AgentPrefix([string]$prefix) {
    return $prefix -cmatch '^[a-z0-9][a-z0-9-]{1,30}\z'
}

function Get-DefaultAgentPrefix([string]$hostName) {
    # sb-host-<host_name>, cut to the 31 characters the bus pattern allows. Right only when the SPN
    # has exactly this name; the installer says so.
    $p = "sb-host-$hostName"
    if ($p.Length -gt 31) { $p = $p.Substring(0, 31) }
    return $p.TrimEnd('-')
}

function Set-AgentPrefixLine([string]$text, [string]$prefix) {
    # As Set-LogonLine: replace agent_prefix, or add it as a top-level key before the first [table].
    if (-not (Test-AgentPrefix $prefix)) { throw ("agent prefix '$prefix' must be the SPN's name: " + '^[a-z0-9][a-z0-9-]{1,30}$') }
    $line = "agent_prefix = `"$prefix`""
    $pattern = '(?m)^agent_prefix\s*=\s*("[^"]*"|''[^'']*'')'
    if ([regex]::IsMatch($text, $pattern)) { return [regex]::Replace($text, $pattern, $line) }
    $table = [regex]::Match($text, '(?m)^\[')
    if ($table.Success) { return $text.Insert($table.Index, "$line`n`n") }
    return $text.TrimEnd() + "`n$line`n"
}

function Get-SignerList([string]$text) {
    # Each allowed_signers line as principal, namespaces, key type, SHA256 fingerprint (the same string
    # ssh-keygen -lf prints) and comment. Pure: for showing what is about to be pinned.
    $types = @('ssh-ed25519', 'sk-ssh-ed25519@openssh.com', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp521', 'sk-ecdsa-sha2-nistp256@openssh.com', 'ssh-rsa')
    $sha = [Security.Cryptography.SHA256]::Create()
    foreach ($line in ($text -split "`r?`n")) {
        $tokens = @($line.Trim() -split '\s+' | Where-Object { $_ })
        if (-not $tokens.Count -or $tokens[0].StartsWith('#')) { continue }
        $i = [array]::FindIndex([string[]]$tokens, [Predicate[string]] { param($t) $types -contains $t })
        if ($i -lt 1 -or $i + 1 -ge $tokens.Count) { throw "not an allowed_signers line: $line" }
        $fp = 'SHA256:' + [Convert]::ToBase64String($sha.ComputeHash([Convert]::FromBase64String($tokens[$i + 1]))).TrimEnd('=')
        $ns = [regex]::Match(($tokens[1..($i - 1)] -join ' '), 'namespaces="([^"]*)"').Groups[1].Value
        [pscustomobject]@{
            Principal = $tokens[0]; Namespaces = $ns; KeyType = $tokens[$i]; Fingerprint = $fp
            Comment = ($tokens | Select-Object -Skip ($i + 2)) -join ' '
        }
    }
}

function Get-PinnedSignersPath {
    return Join-Path $env:ProgramData 'strugglebus\allowed_signers'
}

function Get-PanelLaunch([string]$python, [string]$App, [string]$HostHome) {
    # pythonw.exe (no console window) beside python.exe when there is one.
    $w = Join-Path (Split-Path $python) 'pythonw.exe'
    $exe = if (Test-Path $w) { $w } else { $python }
    return [pscustomobject]@{ Exe = $exe; Arguments = "`"$App\wh.py`" --home `"$HostHome`" panel" }
}

function Get-PanelShortcutPath {
    return Join-Path ([Environment]::GetFolderPath('Startup')) 'Strugglebus host.lnk'
}

# Dot-sourced (the tests do this): define the functions above and stop here.
function Get-SiteValues([string]$python, [string]$source, [string]$siteFile) {
    # The template's site placeholders from a site.toml, checked by workerhost\sitefile.py (stdlib only, run
    # isolated): each value is already a TOML literal. Throws with the checker's message on a bad file.
    $out = & $python -I (Join-Path $source 'workerhost\sitefile.py') $siteFile
    if ($LASTEXITCODE -ne 0) { throw "$($out -join ' ')" }
    $values = @{}
    foreach ($p in (($out -join '') | ConvertFrom-Json).PSObject.Properties) { $values[$p.Name] = [string]$p.Value }
    return $values
}

if ($MyInvocation.InvocationName -eq '.') { return }

function Find-Exe([string]$name, [string[]]$extra = @()) {
    $cmd = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    $path = if ($cmd) { $cmd.Source } else { $extra | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1 }
    if (-not $path) { throw "$name not found on PATH; install it and sign in first" }
    return [IO.Path]::GetFullPath($path)
}

function Get-Python {
    # Only "--version" is run: python never reads stdin here. The first install on the dev machine
    # hung in this function with python waiting for a script on stdin (its argument list arrived as
    # "- c"), so the version is read from the banner and the executable is the one on PATH.
    $cmd = Get-Command python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) {
        # Captured whole, not piped through a -First stage: that stops the pipeline early and
        # leaves $LASTEXITCODE stale (seen on the dev machine: version printed, exit code from the
        # previous command, "python not found").
        $out = & $cmd.Source --version 2>&1
        if ($LASTEXITCODE -eq 0 -and (Test-PythonVersion "$out")) { return [IO.Path]::GetFullPath($cmd.Source) }
    }
    throw 'python 3.11 or later not found on PATH (the host needs tomllib); the WindowsApps python stub does not count'
}

function Get-TaskCredential {
    # The identity's own name (MACHINE\user for a local account, DOMAIN\user otherwise). On a
    # workgroup machine $env:USERDOMAIN is "WORKGROUP", which Task Scheduler cannot map to a SID.
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    Say "Task Scheduler needs your Windows password once to run the host while you are logged off."
    Say "This is the account password, not a PIN. It is not stored by this script."
    Say "No password (Windows Hello for Business)? Cancel and run: install.ps1 -Logon Interactive"
    return Get-Credential -UserName $user -Message 'Windows password for the worker host scheduled task'
}

function Invoke-Wh([string[]]$whArgs) {
    $py = Get-Python
    & $py (Join-Path $App 'wh.py') --home $HostHome @whArgs
}

function Set-UserPath([switch]$Remove) {
    $current = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @($current -split ';' | Where-Object { $_ -and ($_.TrimEnd('\') -ne $App.TrimEnd('\')) })
    if (-not $Remove) { $parts += $App }
    [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User')
}

# ------------------------------------------------------------------------------------------------
if ($Uninstall) {
    if (Test-Path (Join-Path $App 'wh.py')) {
        Say 'stopping the host (wh stop)'
        Invoke-Wh @('stop') | Out-Host
    }
    foreach ($t in @($TaskName, $ProbeTask)) {
        if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $t -Confirm:$false
            Say "removed scheduled task $t"
        }
    }
    Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*$App\wh.py*panel*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    $lnk = Get-PanelShortcutPath
    if (Test-Path $lnk) { Remove-Item -Force $lnk; Say "removed the status window from Startup" }
    if (Test-Path $App) { Remove-Item -Recurse -Force $App; Say "removed $App" }
    if (-not $NoPath) { Set-UserPath -Remove }
    if ($Purge) {
        if (Test-Path $HostHome) { Remove-Item -Recurse -Force $HostHome; Say "purged $HostHome (credentials included)" }
    } else {
        Say "kept $HostHome (config, DPAPI credentials, state, logs); -Uninstall -Purge removes it"
    }
    Say 'worker clones under the workers root were not touched'
    return
}

if ($UpdatePassword) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $existing) { throw "no task $TaskName" }
    if ("$($existing.Principal.LogonType)" -ne 'Password') {
        Say 'this task runs in your signed-in session (Interactive) and stores no password: nothing to update'
        return
    }
    $cred = Get-TaskCredential
    Set-ScheduledTask -TaskName $TaskName -User $cred.UserName -Password $cred.GetNetworkCredential().Password | Out-Null
    $cred = $null
    Say 'scheduled task password updated'
    return
}

if ($PinSigners) {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'pinning the signers needs an elevated PowerShell (Run as administrator)'
    }
    $from = Join-Path $Source 'keys\allowed_signers'
    $to = Get-PinnedSignersPath
    $bytes = [IO.File]::ReadAllBytes($from)
    $new = @(Get-SignerList ([Text.Encoding]::UTF8.GetString($bytes)))
    if (-not $new.Count) { throw "no keys in $from" }
    if (Test-Path $to) {
        Say "currently pinned in ${to}:"
        foreach ($s in @(Get-SignerList ([IO.File]::ReadAllText($to)))) { Say "    $($s.Fingerprint)  $($s.Comment)  [$($s.Namespaces)]" }
    } else {
        Say "nothing pinned yet at $to"
    }
    Say "about to pin, from ${from}:"
    foreach ($s in $new) { Say "    $($s.Fingerprint)  $($s.Comment)  [$($s.Namespaces)]  ($($s.Principal), $($s.KeyType))" }
    Say 'Compare every fingerprint with YOUR OWN copy, kept outside this repository (signing-keys.md 4.5).'
    Say 'The repository alone could have been changed; this is the check that it was not.'
    if ((Read-Host 'Type yes if every fingerprint matches') -cne 'yes') { Say 'not pinned: nothing changed'; return }
    $dir = Split-Path $to
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    # Owned by Administrators; Administrators and SYSTEM full control, Users read only, nothing inherited.
    # The host and its workers run unelevated, so nothing they run can add a key.
    & icacls $dir /setowner '*S-1-5-32-544' /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "could not set the owner of $dir" }
    & icacls $dir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "could not lock down $dir" }
    [IO.File]::WriteAllBytes($to, $bytes)
    & icacls $to /reset /Q | Out-Null
    & icacls $to /setowner '*S-1-5-32-544' /Q | Out-Null
    $written = [IO.File]::ReadAllBytes($to)
    if ([Convert]::ToBase64String($written) -ne [Convert]::ToBase64String($bytes)) { throw "$to does not read back as written" }
    Say "pinned $($new.Count) key(s) in $to (administrators write, users read). 'wh fleet status' shows them."
    return
}

# --- install -------------------------------------------------------------------------------------
if ($AgentPrefix -and -not (Test-AgentPrefix $AgentPrefix)) {
    throw ("-AgentPrefix '$AgentPrefix' must be the SPN's name: " + '^[a-z0-9][a-z0-9-]{1,30}$')
}
$python = Get-Python
$copilotDefault = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Links\copilot.exe'
$copilot = Select-CopilotExe (Find-Exe 'copilot' @($copilotDefault)) $copilotDefault (Test-Path $copilotDefault)
if ([IO.Path]::GetExtension($copilot) -ne '.exe') {
    throw "copilot resolves to $copilot; the host needs the .exe (a .cmd/.ps1 wrapper would route the prompt through a shell)"
}
$gh = Find-Exe 'gh'
$git = Find-Exe 'git'
Say "python  $python"
Say "copilot $copilot"
Say "gh      $gh"
Say "git     $git"

New-Item -ItemType Directory -Force -Path $HostHome, $App, (Join-Path $App 'workerhost') | Out-Null
# Owner-only: the current user, inheritance removed (credentials, state and saved briefs live here).
# The grant goes on the home folder only; everything under it is reset to inherit from it. Granting
# (OI)(CI) on files with /T leaves each file an inherit-only entry, which is no access at all (the
# second install on the dev machine could not overwrite its own files).
& icacls $HostHome /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'could not make the home folder owner-only' }
if (Get-ChildItem -Force $HostHome | Select-Object -First 1) {
    & icacls (Join-Path $HostHome '*') /reset /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'could not reset the home folder contents to inherit' }
}

Copy-Item -Force (Join-Path $Source 'workerhost\*.py') (Join-Path $App 'workerhost')
Copy-Item -Force (Join-Path $Source 'wh.py'), (Join-Path $Source 'config.template.toml'), (Join-Path $Source 'README.md') $App
$whCmd = "@echo off`r`n`"$python`" `"$App\wh.py`" --home `"$HostHome`" %*`r`nexit /b %ERRORLEVEL%`r`n"
[IO.File]::WriteAllText((Join-Path $App 'wh.cmd'), $whCmd, [Text.Encoding]::ASCII)
Say "code installed in $App"
# What is installed, for self-update (workerhost/update.py): a hand install is "manual", serial 0, so the next signed
# release is applied (unless it is this very commit).
$sourceCommit = ''
if (Test-Path (Join-Path $Source '.git')) {
    $sourceCommit = (& git -C $Source rev-parse HEAD 2>$null | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0 -or "$sourceCommit" -notmatch '^[0-9a-f]{40}$') { $sourceCommit = '' }
}
$releaseJson = [ordered]@{ version = 'manual'; serial = 0; commit = "$sourceCommit" } | ConvertTo-Json
[IO.File]::WriteAllText((Join-Path $App 'RELEASE.json'), $releaseJson + "`n", (New-Object Text.UTF8Encoding($false)))

$useTask = -not $NoScheduledTask
$utf8 = New-Object Text.UTF8Encoding($false)
if (Test-Path $Config) {
    $text = [IO.File]::ReadAllText($Config)
    $updated = Set-CopilotLine (Set-LogonLine $text $Logon) $copilot
    if ($AgentPrefix) {
        $updated = Set-AgentPrefixLine $updated $AgentPrefix
    } elseif ($updated -notmatch '(?m)^agent_prefix\s*=') {
        # A config from before agent_prefix: add the default so the host loads, and say so below.
        $hn = [regex]::Match($updated, '(?m)^host_name\s*=\s*["'']([^"'']*)').Groups[1].Value
        $updated = Set-AgentPrefixLine $updated (Get-DefaultAgentPrefix $hn)
    }
    if ($DefaultEngine) {
        $updated = Set-EngineDefault $updated $DefaultEngine (Get-Content -Raw (Join-Path $Source 'config.template.toml'))
        Say "default engine set to $DefaultEngine ([engines] in $Config)"
    }
    if ($updated -ne $text) { [IO.File]::WriteAllText($Config, $updated, $utf8) }
    $AgentPrefix = [regex]::Match($updated, '(?m)^agent_prefix\s*=\s*["'']([^"'']*)').Groups[1].Value
    Say "kept the existing $Config (logon_type = `"$Logon`", copilot_exe refreshed)"
} else {
    if (-not $HostName) { $HostName = ($env:COMPUTERNAME.ToLower() -replace '[^a-z0-9-]', '-').Trim('-') }
    if ($HostName.Length -gt 31) { $HostName = $HostName.Substring(0, 31).Trim('-') }
    if (-not $AgentPrefix) { $AgentPrefix = Get-DefaultAgentPrefix $HostName }
    $ramGb = Get-InstalledMemoryGb
    $cap = Get-Capacity $ramGb
    if (-not $SiteFile) { throw 'a new install needs -SiteFile <your site.toml> (copy site.example.toml and fill it in)' }
    if (-not $BusCa) { throw 'a new install needs -BusCa <the bus LAN root certificate file>' }
    $site = Get-SiteValues $python $Source $SiteFile
    if (-not $DefaultEngine) { $DefaultEngine = Read-DefaultEngine }
    $text = Get-Content -Raw (Join-Path $Source 'config.template.toml')
    $values = @{
        '@HOST_NAME@' = $HostName; '@AGENT_PREFIX@' = $AgentPrefix; '@WORKERS_ROOT@' = $WorkersRoot; '@BUS_CA@' = $BusCa
        '@COPILOT_EXE@' = $copilot; '@GH_EXE@' = $gh; '@GIT_EXE@' = $git; '@PYTHON_EXE@' = $python
        '@MAX_WORKERS@' = "$($cap.MaxWorkers)"; '@WORKER_COMMIT_GB@' = "$($cap.WorkerCommitGb)"
        '@DEFAULT_ENGINE@' = $DefaultEngine
    }
    foreach ($k in $values.Keys) {
        if ($values[$k].Contains("'")) { throw "path $($values[$k]) contains a quote" }
        $text = $text.Replace($k, $values[$k])
    }
    foreach ($k in $site.Keys) { $text = $text.Replace($k, $site[$k]) }  # TOML literals, checked by sitefile.py
    $text = Set-LogonLine $text $Logon
    if (-not $useTask) { $text = $text.Replace('scheduled_task = "StrugglebusWorkerHost"', 'scheduled_task = ""') }
    [IO.File]::WriteAllText($Config, $text, $utf8)
    Say ("wrote $Config (host_name=$HostName, logon_type=$Logon, default engine $DefaultEngine, ${ramGb} GB " +
        "installed -> max_workers=$($cap.MaxWorkers), worker_commit_gb=$($cap.WorkerCommitGb)); review it now")
    if ($cap.Profile -eq 'other') {
        Say "${ramGb} GB is neither the 128 GB nor the 64 GB profile: set max_workers in the config yourself"
    }
}
Say ("agent_prefix = `"${AgentPrefix}`": it MUST equal the name of the SPN you give 'wh enrol' (the bus refuses " +
    "any other name). Host identity ${AgentPrefix}-host, workers ${AgentPrefix}-<worker>. " +
    "Wrong? Re-run with -AgentPrefix <SPN name>.")

if (-not $NoPath) {
    Set-UserPath
    Say "added $App to your user PATH (open a new terminal for 'wh')"
}

if (-not $NoPanel) {
    $launch = Get-PanelLaunch $python $App $HostHome
    $shell = New-Object -ComObject WScript.Shell
    $lnk = $shell.CreateShortcut((Get-PanelShortcutPath))
    $lnk.TargetPath = $launch.Exe
    $lnk.Arguments = $launch.Arguments
    $lnk.WorkingDirectory = $App
    $lnk.Description = 'Strugglebus worker host: status window'
    $lnk.Save()
    # The new code is in place: close a panel still running the old code, then start it again.
    Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*$App\wh.py*panel*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Process -FilePath $launch.Exe -ArgumentList $launch.Arguments -WorkingDirectory $App
    Say 'status window: opened now, and at every sign-in (Startup folder, "Strugglebus host"; -NoPanel to skip)'
}

if (-not $useTask) {
    Say 'no scheduled task (-NoScheduledTask): start the host with "wh start" (runs detached) or "wh run"'
    Invoke-Wh @('probe') | Out-Host
    return
}

# --- scheduled task --------------------------------------------------------------------------------
$runArgs = Get-HostTaskArguments $App $HostHome
if ($Logon -eq 'Interactive') {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $xml = New-HostTaskXml -Mode Interactive -UserId $sid -Command $python -Arguments $runArgs -WorkingDirectory $App
    Register-ScheduledTask -TaskName $TaskName -Xml $xml -Force -ErrorAction Stop | Out-Null
    Disable-ScheduledTask -TaskName $TaskName -ErrorAction Stop | Out-Null
    Say "registered scheduled task $TaskName (Interactive: at your sign-in, no stored password; disabled until 'wh start')"

    # The task runs in this signed-in session, so the probe runs here.
    Say 'probe (run in this session, where the task will run):'
    Invoke-Wh @('probe') | ForEach-Object { Write-Host "    $_" }
    Say 'next: "wh enrol" (SPN credential, once), then "wh start"'
    return
}

$cred = Get-TaskCredential
$user = $cred.UserName
$password = $cred.GetNetworkCredential().Password
$xml = New-HostTaskXml -Mode Password -UserId $user -Command $python -Arguments $runArgs -WorkingDirectory $App
# The ScheduledTasks cmdlets do not always honour $ErrorActionPreference, so each call says Stop.
Register-ScheduledTask -TaskName $TaskName -Xml $xml -User $user -Password $password -Force -ErrorAction Stop | Out-Null
Disable-ScheduledTask -TaskName $TaskName -ErrorAction Stop | Out-Null
Say "registered scheduled task $TaskName (Password: at startup, logged on or not; disabled until 'wh start')"

# Probe through a task with the same logon, so it runs as the host will (no interactive session).
$probeOut = Join-Path $HostHome 'state\probe.txt'
New-Item -ItemType Directory -Force -Path (Split-Path $probeOut) | Out-Null
Remove-Item -Force $probeOut -ErrorAction SilentlyContinue
$probeAction = New-ScheduledTaskAction -Execute $python `
    -Argument "`"$App\wh.py`" --home `"$HostHome`" probe --out `"$probeOut`"" -WorkingDirectory $App
Register-ScheduledTask -TaskName $ProbeTask -Action $probeAction -Settings (New-ScheduledTaskSettingsSet) `
    -User $user -Password $password -RunLevel Limited -Force -ErrorAction Stop | Out-Null
$password = $null; $cred = $null
try {
    Start-ScheduledTask -TaskName $ProbeTask -ErrorAction Stop
    $deadline = (Get-Date).AddMinutes(4)
    do {
        Start-Sleep -Seconds 3
        $state = (Get-ScheduledTask -TaskName $ProbeTask).State
    } while ($state -eq 'Running' -and (Get-Date) -lt $deadline)
    if (Test-Path $probeOut) {
        Say 'probe (run through Task Scheduler as you, logged off):'
        Get-Content $probeOut | ForEach-Object { Write-Host "    $_" }
    } else {
        Say 'probe produced no output: check the password and that Python is installed for all sessions'
    }
} finally {
    Unregister-ScheduledTask -TaskName $ProbeTask -Confirm:$false
}
Say 'next: "wh enrol" (SPN credential, once), then "wh start"'
