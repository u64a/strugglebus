<#
.SYNOPSIS
  Run on YOUR computer (gaming PC, work laptop, ...): lets a public key sign in to a host over SSH as an administrator.

.DESCRIPTION
  Connects to the host with ssh, adds the public key to C:\ProgramData\ssh\administrators_authorized_keys (once; a
  key already there is left alone), keeps that file's permissions as sshd requires (Administrators and SYSTEM only),
  and turns password sign-in off. Then it checks the key works, when the key is this computer's own.

  On a freshly built host no key is authorised yet, so ssh asks for the host account's Windows PASSWORD: you type
  it into ssh's own prompt, in this terminal. This script never sees it, keeps it or passes it anywhere. That works
  only until the first key is on the host (setup\25-access.ps1 allows password sign-in exactly while there is none).
  Later grants use a key you already have on the host.

  Agent keys (e.g. an agent on another PC): pass its .pub file with -PublicKey. It is added as an
  administrator, as on a host today (a drop-folder-only account is a later enhancement).

.PARAMETER Target
  user@host, e.g. devtest@host-a.example.lan. The user must be an administrator on the host.

.PARAMETER PublicKey
  The public key file to add. Default: this computer's ~\.ssh\id_ed25519.pub.

.PARAMETER KeepPassword
  Leave password sign-in on (only if you still need it, e.g. to add another computer's key with a password).

.EXAMPLE
  pwsh -File tools\grant-ssh.ps1 -Target devtest@host-a.example.lan
.EXAMPLE
  pwsh -File tools\grant-ssh.ps1 -Target devuser@host-b.example.lan -PublicKey C:\keys\agent-access.pub
#>
[CmdletBinding()]
param(
    [string]$Target = '',
    [string]$PublicKey = (Join-Path $HOME '.ssh\id_ed25519.pub'),
    [switch]$KeepPassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$KeyPattern = '^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com|ssh-rsa) [A-Za-z0-9+/=]+( [ -~]{0,200})?$'

function Test-PublicKey([string]$line) {
    # Pure: one OpenSSH public key line, with an optional printable comment; never a private key.
    return [bool]($line -match $KeyPattern) -and $line -notmatch 'PRIVATE KEY'
}

function New-RemoteScript([string]$key, [bool]$keepPassword) {
    # Pure: the PowerShell the host runs. The public key is not a secret; it travels inside the script text.
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($key))
    $keep = if ($keepPassword) { '$true' } else { '$false' }
    return @"
`$ErrorActionPreference = 'Stop'
`$ProgressPreference = 'SilentlyContinue'
`$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not `$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'this account is not an administrator on the host' }
`$key = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$b64'))
`$blob = (`$key -split ' ')[1]
`$file = Join-Path `$env:ProgramData 'ssh\administrators_authorized_keys'
`$lines = @(if (Test-Path `$file) { Get-Content `$file })
if (`$lines | Where-Object { (`$_ -split ' ') -contains `$blob }) { 'key: already there' } else {
    [IO.File]::WriteAllLines(`$file, [string[]](@(`$lines | Where-Object { `$_ -match '\S' }) + `$key), (New-Object Text.ASCIIEncoding))
    'key: added'
}
& icacls `$file /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' /Q | Out-Null
if ($keep) { 'password sign-in: left as it is (-KeepPassword)' } else {
    `$conf = Join-Path `$env:ProgramData 'ssh\sshd_config'
    `$text = [IO.File]::ReadAllText(`$conf)
    `$out = New-Object System.Collections.Generic.List[string]; `$inMatch = `$false; `$set = `$false
    foreach (`$l in (`$text -split "``r?``n")) {
        if (`$l -match '^\s*Match\s') { if (-not `$set) { `$out.Add('PasswordAuthentication no'); `$set = `$true }; `$inMatch = `$true }
        if (-not `$inMatch -and `$l -match '^\s*#?\s*PasswordAuthentication\s') { if (-not `$set) { `$out.Add('PasswordAuthentication no'); `$set = `$true }; continue }
        `$out.Add(`$l)
    }
    if (-not `$set) { `$out.Add('PasswordAuthentication no') }
    `$new = `$out -join "``r``n"
    if (`$new -ne `$text) {
        [IO.File]::WriteAllText(`$conf, `$new, (New-Object Text.UTF8Encoding(`$false)))
        'password sign-in: off (sshd restarts in a few seconds)'
        Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-Command','Start-Sleep 3; Restart-Service sshd'
    } else { 'password sign-in: already off' }
}
"@
}

# Dot-sourced (the tests do this): define the above and stop here.
if ($MyInvocation.InvocationName -eq '.') { return }

if ($Target -notmatch '^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+$') { throw '-Target must be user@host, e.g. devtest@host-a.example.lan' }
if (-not (Test-Path $PublicKey)) { throw "no public key at $PublicKey (create one with: ssh-keygen -t ed25519)" }
$key = (Get-Content -Raw $PublicKey).Trim()
if (-not (Test-PublicKey $key)) { throw "$PublicKey is not one OpenSSH public key line (a .pub file)" }

$script = New-RemoteScript $key $KeepPassword.IsPresent
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
Write-Host "[grant-ssh] adding $((($key -split ' ') | Select-Object -Last 1)) to $Target as an administrator key"
Write-Host '[grant-ssh] if ssh asks for a password, it is the Windows password of that account on the host'
& ssh -o StrictHostKeyChecking=accept-new $Target "powershell -NoProfile -NonInteractive -EncodedCommand $encoded"
if ($LASTEXITCODE -ne 0) { throw "ssh to $Target failed (exit $LASTEXITCODE)" }

$own = Join-Path $HOME '.ssh\id_ed25519.pub'
if ((Test-Path $own) -and ((Get-Content -Raw $own).Trim() -eq $key)) {
    Start-Sleep -Seconds 6  # sshd restarting
    & ssh -o BatchMode=yes -o PasswordAuthentication=no -o ConnectTimeout=15 $Target 'echo key-sign-in-ok' | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'the key was added but signing in with it failed: check the host (setup\25-access.ps1 -WhatIf)' }
    Write-Host "[grant-ssh] done: this computer signs in to $Target with its key; password sign-in is off"
} else {
    Write-Host "[grant-ssh] done: that key can now sign in to $Target (not checked from here: it is not this computer's key)"
}
