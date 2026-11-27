<#
.SYNOPSIS
  Puts a StruggleBus worker host on this PC from the App's data file (docs/app-host-integration.md section 2).

.DESCRIPTION
  Code and data are separate (security review). This file is a fixed release file that the App ships
  unchanged and never edits. Check it before running it: its Authenticode signature once releases are signed, until
  then its SHA-256 with `Get-FileHash -Algorithm SHA256 .\bootstrap.ps1` against what the App shows. The App's output
  is a data file (sbhost-enrol.json) that is never executed: this script reads it, refuses anything that is not
  exactly the canonical form (tests/data/vectors/sbhost-enrol.json), and prints its digest and every signer
  fingerprint to compare with the App (M2).

  STATUS: the checks are built and tested; the install steps that change the machine are not wired yet and stop
  with "not built yet". Run nothing from this file on a real host until it says otherwise.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1 -DataFile .\sbhost-enrol.json
#>
[CmdletBinding()]
param(
    [string]$DataFile = '',
    [switch]$Yes,
    [switch]$SingleSigner
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The data file's keys, in their canonical order.
$Keys = 'v', 'written_at', 'device', 'bus_url', 'bus_ca_pem', 'host_prefix', 'enrol_code', 'engines', 'dedicated',
        'signers', 'fleet_source', 'remotes'
$MaxDataBytes = 65536

$Patterns = @{
  written_at  = '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}Z$'
  device      = '^(?=.{1,63}$)[a-z0-9]+(?:-[a-z0-9]+)*$'
  bus_url     = '^https://[a-z0-9][a-z0-9.-]{0,252}(:[0-9]{1,5})?/?$'
  host_prefix = '^(?=.{2,31}$)[a-z0-9]+(?:-[a-z0-9]+)*$'
  enrol_code  = '^(sbhe1_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{43})?$'   # empty once redeemed
  engine      = '^(ghcp|claude)$'
  remote      = '^https://[a-z0-9][a-z0-9.-]{0,252}/([A-Za-z0-9_.-]{1,100}/)?$'
  base64      = '^[A-Za-z0-9+/]+={0,2}$'
  signer      = '^[A-Za-z0-9][A-Za-z0-9._@-]{0,63} namespaces="(strugglebus-fleet|strugglebus-host-command)(,(strugglebus-fleet|strugglebus-host-command))?" (ssh-ed25519|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp256|sk-ecdsa-sha2-nistp256@openssh\.com|ssh-rsa) [A-Za-z0-9+/]+={0,2}( [A-Za-z0-9._@-]{1,64})?$'
}

function Format-SbJsonValue($v) {
    # Values have passed their patterns, so the only character JSON must escape is the signer lines' double quote.
    if ($v -is [bool]) { if ($v) { return 'true' } else { return 'false' } }
    if ($v -is [int] -or $v -is [long]) { return "$v" }
    if ($v -is [array]) { return '[' + ((@($v) | ForEach-Object { Format-SbJsonValue $_ }) -join ',') + ']' }
    return '"' + "$v".Replace('"', '\"') + '"'
}

function Format-SbData($data) {
    # Pure: the canonical bytes of the data file as text: one line of JSON, the keys in $Keys order, no spaces,
    # ASCII only, then one LF. The same as Python's json.dumps(obj, separators=(",", ":"), ensure_ascii=True) + "\n".
    return '{' + (($Keys | ForEach-Object { '"' + $_ + '":' + (Format-SbJsonValue $data[$_]) }) -join ',') + "}`n"
}

function ConvertFrom-SbJson([string]$text) {
    # The data file's JSON as a hashtable (ConvertFrom-Json gives an object; Windows PowerShell 5.1 has no -AsHashtable).
    $o = $text | ConvertFrom-Json
    $h = @{}
    foreach ($p in $o.PSObject.Properties) {
        $h[$p.Name] = if ($p.Value -is [array]) { , @($p.Value) } else { $p.Value }
    }
    return $h
}

function Test-SbData($data, [switch]$SingleSigner) {
    # Pure: the list of problems with the data (empty = good). Every value must match its pattern; site keys may only
    # sign the fleet and host commands, never releases.
    $bad = [System.Collections.Generic.List[string]]::new()
    foreach ($k in $data.Keys) { if ($k -cnotin $Keys) { $bad.Add("unknown key $k") } }
    foreach ($k in $Keys) { if (-not $data.ContainsKey($k)) { $bad.Add("missing $k") } }
    if ($bad.Count) { return , $bad.ToArray() }
    if (-not (($data.v -is [int] -or $data.v -is [long]) -and $data.v -eq 1)) { $bad.Add('v') }
    foreach ($k in 'written_at', 'device', 'bus_url', 'host_prefix', 'enrol_code') {
        if ($data[$k] -isnot [string] -or $data[$k] -cnotmatch $Patterns[$k]) { $bad.Add($k) }
    }
    $pem = $data.bus_ca_pem
    if ($pem -isnot [string] -or $pem -cnotmatch $Patterns.base64 -or $pem.Length -gt 16384) { $bad.Add('bus_ca_pem') }
    else {
        try {
            if ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($pem)) -notmatch '^-----BEGIN CERTIFICATE-----') {
                $bad.Add('bus_ca_pem')
            }
        } catch { $bad.Add('bus_ca_pem') }
    }
    $engines = @($data.engines)
    if ($engines.Count -lt 1 -or $engines.Count -gt 2 -or @($engines | Where-Object { $_ -isnot [string] -or $_ -cnotmatch $Patterns.engine }).Count -or
        @($engines | Select-Object -Unique).Count -ne $engines.Count) { $bad.Add('engines') }
    if ($data.dedicated -isnot [bool]) { $bad.Add('dedicated') }
    if ($data.fleet_source -isnot [string] -or $data.fleet_source -cnotin 'bus', 'git', 'either') { $bad.Add('fleet_source') }
    $remotes = @($data.remotes)
    if ($remotes.Count -lt 1 -or @($remotes | Where-Object { $_ -isnot [string] -or $_ -cnotmatch $Patterns.remote }).Count) { $bad.Add('remotes') }
    $signers = @($data.signers)
    if (@($signers | Where-Object { $_ -isnot [string] -or $_ -cnotmatch $Patterns.signer }).Count) { $bad.Add('signers') }
    elseif ($signers.Count -lt 2 -and -not $SingleSigner) { $bad.Add('signers: at least two (or -SingleSigner, for testing)') }
    elseif ($signers.Count -lt 1) { $bad.Add('signers') }
    return , $bad.ToArray()
}

function Read-SbData([byte[]]$bytes, [switch]$SingleSigner) {
    # The data file's values, or a throw naming what is wrong. The bytes must be exactly Format-SbData of the values
    # read from them, so a repeated key, a comment, spacing, CRLF, a BOM or anything else is refused.
    if ($bytes.Length -gt $MaxDataBytes) { throw 'the data file is too large' }
    if (@($bytes | Where-Object { $_ -gt 127 }).Count) { throw 'the data file is not ASCII' }
    $text = [Text.Encoding]::ASCII.GetString($bytes)
    try { $data = ConvertFrom-SbJson $text } catch { throw 'the data file is not JSON' }
    $bad = Test-SbData $data -SingleSigner:$SingleSigner
    if ($bad.Count) { throw "the data file's values are not valid ($($bad -join ', '))" }
    if ((Format-SbData $data) -cne $text) { throw 'the data file is not in the canonical form' }
    return $data
}

function Get-FileDigest([byte[]]$bytes) {
    # Pure: the first 16 hex of SHA-256 over the bytes, as four groups of four (M2).
    $hex = -join ([Security.Cryptography.SHA256]::Create().ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
    return ($hex.Substring(0, 16) -split '(.{4})' | Where-Object { $_ }) -join ' '
}

function Get-SignerFingerprint([string]$line) {
    # Pure: the SHA256:... fingerprint of an allowed_signers line's key, as ssh-keygen -lf prints it.
    $blob = ($line -split ' ')[3]
    $hash = [Security.Cryptography.SHA256]::Create().ComputeHash([Convert]::FromBase64String($blob))
    return 'SHA256:' + [Convert]::ToBase64String($hash).TrimEnd('=')
}

function Clear-EnrolCode($data) {
    # Pure: the data file's canonical text with the one-time code blanked (Q1), to write back once it is redeemed.
    $copy = @{} + $data
    $copy.enrol_code = ''
    return Format-SbData $copy
}

# --- verifying the host code before any of it runs (2.2 step 3) ---------------------------------------------------

# The project's release keys: YubiKeys A, B and C, the keys tools\sign-bootstrap.ps1 pins by fingerprint. Only
# these may sign the host code this script installs, whatever the data file says (its signers may sign only the
# fleet and host commands). Public keys: nothing secret here.
$ReleaseKeys = @(
    'sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIN56hk/clV5r0XsK7JkOlTLz0Zyri/QEhaIqCnmd+5yOAAAAF3NzaDpzdHJ1Z2dsZWJ1cy1zaWduaW5n',
    'sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIMLHD9G3fCyGMJ8RlHGYzaB7P3efJFqoQoQZ1AxivmUFAAAAF3NzaDpzdHJ1Z2dsZWJ1cy1zaWduaW5n',
    'sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIMOObxkek5mGgpHJVUzS8mkKtGYyaazmUArYEWj3whC7AAAAF3NzaDpzdHJ1Z2dsZWJ1cy1zaWduaW5n'
)

# The oldest release this script installs (prox-manager, #humans 28901: an older signed release must be refused). A
# new PC has no installed serial to compare with, so this floor stands in for it: raise it when this file changes.
$MinReleaseSerial = 9

function Test-ReleaseFloor($release) {
    # Pure: the release is not older than this script allows, and carries installer_sha256 (needed for step 6).
    return [int]$release.serial -ge $MinReleaseSerial -and $release.ContainsKey('installer_sha256')
}

function Get-ReleaseSigners {
    # Pure: an allowed_signers file for ssh-keygen: the release keys, principal "release", release namespace only.
    return (($ReleaseKeys | ForEach-Object { 'release namespaces="strugglebus-release" ' + $_ }) -join "`n") + "`n"
}

function Read-SshField([byte[]]$buf, [int]$at) {
    # Pure: one SSH wire string at $at: @(bytes, the next offset). Throws past the end.
    if ($at + 4 -gt $buf.Length) { throw 'signature too short' }
    $n = ([int]$buf[$at] -shl 24) -bor ([int]$buf[$at + 1] -shl 16) -bor ([int]$buf[$at + 2] -shl 8) -bor [int]$buf[$at + 3]
    if ($n -lt 0 -or $at + 4 + $n -gt $buf.Length) { throw 'signature too short' }
    $out = New-Object byte[] $n
    [Array]::Copy($buf, $at + 4, $out, 0, $n)
    return @(, $out), ($at + 4 + $n)
}

function Get-SkFlags([string]$armoured) {
    # Pure: a security-key SSHSIG signature's flags byte (0x01 touch, 0x04 PIN), or -1 for any other key type. The
    # flags are part of what the key signs, so they are genuine once ssh-keygen has verified the signature.
    $b64 = (($armoured -split "`n") | Where-Object { $_ -and $_ -notmatch '^-----' } | ForEach-Object { $_.Trim() }) -join ''
    $blob = [Convert]::FromBase64String($b64)
    if ($blob.Length -lt 10 -or [Text.Encoding]::ASCII.GetString($blob, 0, 6) -cne 'SSHSIG') { throw 'not an SSH signature' }
    $at = 10
    foreach ($skip in 1..4) { $f, $at = Read-SshField $blob $at }  # public key, namespace, reserved, hash
    $inner, $at = Read-SshField $blob $at
    $type, $j = Read-SshField $inner[0] 0
    if (-not [Text.Encoding]::ASCII.GetString($type[0]).StartsWith('sk-')) { return -1 }
    $sig, $j = Read-SshField $inner[0] $j
    if ($j -ge $inner[0].Length) { throw 'no flags in the signature' }
    return [int]$inner[0][$j]
}

function Test-InstalledPath([string]$path) {
    # Pure: the host's own rule (workerhost/update.py wanted): the files a host runs, which tree_sha256 covers.
    if ($path -cin 'wh.py', 'config.template.toml', 'README.md') { return $true }
    return $path -cmatch '^workerhost/[A-Za-z0-9_]+\.py$'
}

function Test-InstallerPath([string]$path) {
    # Pure: what this script runs as administrator, which installer_sha256 covers (tools/make-release.py INSTALLER_RE).
    return $path -ceq 'install.ps1' -or $path -cmatch '^setup/[A-Za-z0-9_.-]+\.(ps1|txt)$'
}

function Get-TreeSha256($files) {
    # Pure: the host's tree_sha256 (workerhost/update.py): SHA-256 over "<sha256 of the file>  <path>`n" for each
    # file, sorted by path ORDINALLY (as Python sorts; PowerShell's own sort ignores case).
    $paths = [string[]]@($files.Keys)
    [Array]::Sort($paths, [StringComparer]::Ordinal)
    $sha = [Security.Cryptography.SHA256]::Create()
    $lines = ($paths | ForEach-Object {
            (-join ($sha.ComputeHash([byte[]]$files[$_]) | ForEach-Object { $_.ToString('x2') })) + '  ' + $_ + "`n"
        }) -join ''
    return -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($lines)) | ForEach-Object { $_.ToString('x2') })
}

function Read-ReleaseText([string]$text) {
    # Pure: the top-level keys of a signed release.toml this script needs, each checked strictly, or a throw. Only
    # the part before the first [table] counts (moved_to is a table, and not used here).
    $head = ($text -split '(?m)^\s*\[', 2)[0]
    $want = [ordered]@{
        serial = '^serial = ([0-9]{1,9})$'; version = '^version = "([0-9][0-9A-Za-z.+-]{0,31})"$'
        commit = '^commit = "([0-9a-f]{40})"$'; tree_sha256 = '^tree_sha256 = "([0-9a-f]{64})"$'
        installer_sha256 = '^installer_sha256 = "([0-9a-f]{64})"$'
    }
    $out = @{}
    foreach ($k in $want.Keys) {
        $m = [regex]::Matches($head, '(?m)' + $want[$k].TrimEnd('$') + '\r?$')
        if ($m.Count -gt 1) { throw "release.toml: $k twice" }
        if ($m.Count -eq 1) { $out[$k] = $m[0].Groups[1].Value }
    }
    foreach ($k in 'serial', 'version', 'commit', 'tree_sha256') { if (-not $out.ContainsKey($k)) { throw "release.toml: no $k" } }
    $out.serial = [int]$out.serial
    return $out
}

function Test-ReleaseSignature([byte[]]$data, [string]$sig, [string]$keygen, [string]$work) {
    # The release's signature by one of the built-in release keys, namespace strugglebus-release, with the PIN
    # (0x05): @(ok, why). Runs Windows' own ssh-keygen with the signed bytes as a FILE on stdin (a pipe changes them).
    $signers = Join-Path $work 'release_signers'
    $dataFile = Join-Path $work 'release.toml'
    $sigFile = Join-Path $work 'release.toml.sig'
    [IO.File]::WriteAllText($signers, (Get-ReleaseSigners), [Text.Encoding]::ASCII)
    [IO.File]::WriteAllBytes($dataFile, $data)
    [IO.File]::WriteAllText($sigFile, $sig, [Text.Encoding]::ASCII)
    $out = & cmd.exe /d /c "`"$keygen`" -Y verify -f `"$signers`" -I release -n strugglebus-release -s `"$sigFile`" < `"$dataFile`" 2>&1"
    $line = ($out | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0 -or "$line" -notlike 'Good "strugglebus-release" signature for release with *') { return $false, 'bad-signature' }
    try { $flags = Get-SkFlags $sig } catch { return $false, 'sig-shape' }
    if ($flags -ne -1 -and ($flags -band 5) -ne 5) { return $false, 'no-pin' }
    return $true, 'good'
}

function Say([string]$text) { Write-Host "[bootstrap] $text" }

# --- the machine: checks, prerequisites (2.2 steps 1 and 2) -----------------------------------------------------

# Where the host code comes from, built in (like the release keys): the data file can't point the install elsewhere.
$ReleaseRepo = 'https://github.com/u64a/strugglebus'
$ReleaseFolder = 'worker-host'
$Keygen = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'   # Windows' own, never another on PATH

# What step 2 installs, only where missing, with winget (signed packages only), machine-wide so the host's account
# sees them too. The first existing path wins.
$Prereqs = [ordered]@{
    python = @{ id = 'Python.Python.3.13'; paths = @('C:\Program Files\Python313\python.exe', 'C:\Program Files\Python312\python.exe') }
    git    = @{ id = 'Git.Git'; paths = @('C:\Program Files\Git\cmd\git.exe') }
    pwsh   = @{ id = 'Microsoft.PowerShell'; paths = @('C:\Program Files\PowerShell\7\pwsh.exe') }
    gh     = @{ id = 'GitHub.cli'; paths = @('C:\Program Files\GitHub CLI\gh.exe') }
    ghcp   = @{ id = 'GitHub.Copilot'; paths = @('C:\Program Files\WinGet\Links\copilot.exe') }
    claude = @{ id = 'Anthropic.ClaudeCode'; paths = @('C:\Program Files\WinGet\Links\claude.exe') }
}

function Get-NeededPrereqs($engines) {
    # Pure: the tools this host needs: the four always, plus each chosen engine.
    return @('python', 'git', 'pwsh', 'gh') + @(@($engines) | Where-Object { $_ -cin 'ghcp', 'claude' })
}

function Test-Windows11 { return [Environment]::OSVersion.Version.Build -ge 22000 }

function Test-Elevated {
    $p = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-Prereq([string]$name) {
    foreach ($p in $Prereqs[$name].paths) { if (Test-Path -LiteralPath $p -PathType Leaf) { return $p } }
    return $null
}

function Install-Prereqs($engines) {
    # Step 2: each missing tool from winget, machine-wide. Returns name -> path; throws if one is still missing.
    $found = [ordered]@{}
    foreach ($name in (Get-NeededPrereqs $engines)) {
        $path = Find-Prereq $name
        if (-not $path) {
            $id = $Prereqs[$name].id
            Say "installing $id (winget, machine-wide)"
            & winget install --id $id --exact --scope machine --silent --accept-package-agreements --accept-source-agreements --disable-interactivity | Out-Host
            $path = Find-Prereq $name
            if (-not $path) { throw "$id did not install where expected ($($Prereqs[$name].paths -join ', '))" }
        }
        Say "$name`: $path"
        $found[$name] = $path
    }
    return $found
}

# --- the host code: fetched, verified, staged (2.2 step 3) -------------------------------------------------------

function Invoke-GitBytes([string]$git, [string[]]$arguments) {
    # git's stdout as exact bytes (PowerShell's own capture would decode and re-encode it). Throws on failure.
    $psi = New-Object Diagnostics.ProcessStartInfo $git
    $psi.Arguments = ($arguments | ForEach-Object { if ($_ -match '[\s"]') { '"' + $_.Replace('"', '\"') + '"' } else { $_ } }) -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [Diagnostics.Process]::Start($psi)
    $err = $p.StandardError.ReadToEndAsync()
    $ms = New-Object IO.MemoryStream
    $p.StandardOutput.BaseStream.CopyTo($ms)
    $p.WaitForExit()
    if ($p.ExitCode -ne 0) { throw "git $($arguments[0]) failed: $($err.Result.Trim())" }
    return , $ms.ToArray()
}

function Get-VerifiedRelease([string]$git, [string]$work, [string]$repo = $ReleaseRepo, [string]$folder = $ReleaseFolder) {
    # Step 3: the newest release on main, checked before ANY of it runs: the signature by a built-in release key with
    # touch and PIN, not older than $MinReleaseSerial, then tree_sha256 and installer_sha256 over the exact bytes.
    # Returns @{ release; stage } with the staged files (the host's and the installer's) under $work\stage.
    $mirror = Join-Path $work 'release.git'
    Invoke-GitBytes $git @('clone', '--quiet', '--bare', '--filter=blob:none', '--single-branch', '--branch', 'main', $repo, $mirror) | Out-Null
    $g = { param([string[]]$a) Invoke-GitBytes $git (@('--git-dir', $mirror) + $a) }
    $data = & $g @('cat-file', 'blob', "main:$folder/release.toml")
    $sig = [Text.Encoding]::ASCII.GetString((& $g @('cat-file', 'blob', "main:$folder/release.toml.sig")))
    $ok, $why = Test-ReleaseSignature $data $sig $Keygen $work
    if (-not $ok) { throw "the release is not signed by a project release key with touch and PIN ($why): nothing installed" }
    $release = Read-ReleaseText ([Text.Encoding]::UTF8.GetString($data))
    if (-not (Test-ReleaseFloor $release)) { throw "release serial $($release.serial) is older than this bootstrap allows ($MinReleaseSerial), or has no installer_sha256" }
    $listing = [Text.Encoding]::UTF8.GetString((& $g @('ls-tree', '-r', '-z', '--full-tree', $release.commit, '--', $folder)))
    $hostFiles = @{}; $installerFiles = @{}
    foreach ($entry in ($listing -split "`0")) {
        if (-not $entry) { continue }
        $meta, $full = $entry -split "`t", 2
        if (($meta -split ' ')[1] -ne 'blob' -or -not $full.StartsWith("$folder/")) { continue }
        $rel = $full.Substring($folder.Length + 1)
        if (Test-InstalledPath $rel) { $hostFiles[$rel] = & $g @('cat-file', 'blob', "$($release.commit):$full") }
        elseif (Test-InstallerPath $rel) { $installerFiles[$rel] = & $g @('cat-file', 'blob', "$($release.commit):$full") }
    }
    if ((Get-TreeSha256 $hostFiles) -cne $release.tree_sha256) { throw 'the host files do not match the signed tree_sha256: nothing installed' }
    if ((Get-TreeSha256 $installerFiles) -cne $release.installer_sha256) { throw 'install.ps1 or setup\ does not match the signed installer_sha256: nothing installed' }
    $stage = Join-Path $work 'stage'
    foreach ($set in $hostFiles, $installerFiles) {
        foreach ($rel in $set.Keys) {
            $to = Join-Path $stage ($rel -replace '/', '\')
            New-Item -ItemType Directory -Force (Split-Path $to) | Out-Null
            [IO.File]::WriteAllBytes($to, [byte[]]$set[$rel])
        }
    }
    Say "release $($release.version) (serial $($release.serial), $($release.commit.Substring(0, 12))): signature, PIN, tree and installer hashes all good"
    return @{ release = $release; stage = $stage }
}

if ($MyInvocation.InvocationName -eq '.') { return }

if (-not $DataFile) { throw 'give the App''s data file: bootstrap.ps1 -DataFile .\sbhost-enrol.json' }
if (-not (Test-Windows11)) { throw 'this needs Windows 11' }
if (-not (Test-Elevated)) { throw 'run this as administrator (right-click PowerShell, Run as administrator)' }
if (-not (Test-Path -LiteralPath $Keygen -PathType Leaf)) { throw "Windows' own ssh-keygen is missing ($Keygen): add the optional feature OpenSSH Client" }
$bytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $DataFile).Path)
$SB = Read-SbData $bytes -SingleSigner:$SingleSigner
Say "data file from device $($SB.device), $($SB.written_at), for host $($SB.host_prefix) on $($SB.bus_url)"
Say "data file digest: $(Get-FileDigest $bytes)"
foreach ($line in $SB.signers) { Say "signer: $(Get-SignerFingerprint $line)" }
Say 'compare these with what the App shows for this host.'
if (-not $Yes) { Read-Host '[bootstrap] press Enter to continue, or close this window to stop' | Out-Null }

$work = Join-Path $env:TEMP ('sbhost-bootstrap-' + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $work | Out-Null
$tools = Install-Prereqs $SB.engines                    # step 2
$verified = Get-VerifiedRelease $tools.git $work        # step 3
Say "verified host code staged at $($verified.stage)"
throw 'not built yet: the install steps after the verified fetch (2.2 steps 4 to 12) come in a later change'
