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
  powershell -NoProfile -ExecutionPolicy Bypass -File .\bootstrap.ps1 -DataFile .\sbhost-enrol.json
  (-NoProfile: otherwise the operator's own profile.ps1, which any program they run can write, runs elevated first.)
#>
[CmdletBinding()]
param(
    [string]$DataFile = '',
    [switch]$Yes,
    [switch]$SingleSigner,
    [ValidateSet('', 'device', 'browser')][string]$SignIn = ''   # how the sign-ins are approved; asked if not given
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
    pwsh   = @{ id = ''; paths = @('C:\Program Files\PowerShell\7\pwsh.exe') }   # not winget: see $PwshZip
    gh     = @{ id = 'GitHub.cli'; paths = @('C:\Program Files\GitHub CLI\gh.exe') }
    # Copilot CLI's package declares a dependency on the PowerShell MSIX, which won't install machine-wide (the test
    # VM): skipped, because PowerShell 7 is already in place from its pinned, checked zip by then.
    ghcp   = @{ id = 'GitHub.Copilot'; paths = @('C:\Program Files\WinGet\Links\copilot.exe'); skipDeps = $true }
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

# PowerShell 7 is the one tool not from winget: winget has only an MSIX for it, which won't install machine-wide, and
# the host's own account needs pwsh. So: PowerShell's own release zip, the LTS line, pinned by size and SHA-256 (three
# independent sources agreed, #humans 28927-28929), every program and script file in it Authenticode-signed by
# Microsoft. Updating it means a new pin here, in a signed host release.
$PwshZip = @{
    version = '7.6.10'; line = 'LTS'; file = 'PowerShell-7.6.10-win-x64.zip'; size = 109626781
    sha256 = '7D871531806EB1646264E4BBABD9F0C30C23355591BC756BB9909448C29AE166'
    url = 'https://github.com/PowerShell/PowerShell/releases/download/v7.6.10/PowerShell-7.6.10-win-x64.zip'
}
$PwshHome = 'C:\Program Files\PowerShell\7'
$SignedExtensions = '.exe', '.dll', '.ps1', '.psm1', '.psd1'

function Test-MicrosoftName([string]$dn) {
    # Pure: an X.500 name whose organisation (O=) is exactly Microsoft Corporation (not text found anywhere in it).
    return $dn -cmatch '(^|,\s*)O=Microsoft Corporation(,|$)'
}

function Get-UnsignedByMicrosoft([string]$dir) {
    # Every file under $dir with a signable extension whose signature is not Valid with a Microsoft signer AND
    # issuer. Empty means all good.
    $bad = @()
    foreach ($f in (Get-ChildItem -LiteralPath $dir -Recurse -File | Where-Object { $SignedExtensions -contains $_.Extension.ToLowerInvariant() })) {
        $s = Get-AuthenticodeSignature -LiteralPath $f.FullName
        $c = $s.SignerCertificate
        if ($s.Status -ne 'Valid' -or -not $c -or -not (Test-MicrosoftName $c.Subject) -or -not (Test-MicrosoftName $c.Issuer)) {
            $bad += "$($f.FullName.Substring($dir.Length).TrimStart('\')) ($($s.Status))"
        }
    }
    return , $bad
}

$UserSids = 'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4'   # Everyone, Authenticated Users, Users, Interactive

function Test-UserWritable([string]$dir) {
    # True if an ordinary user could add or change files in $dir (a folder that doesn't exist counts as writable:
    # whoever creates it decides).
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { return $true }
    $write = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, ChangePermissions, TakeOwnership'
    # .NET directly, not Get-Acl: the same in Windows PowerShell 5.1 (.NET Framework) and PowerShell 7 (.NET).
    $info = New-Object IO.DirectoryInfo $dir
    $acl = if ($PSVersionTable.PSVersion.Major -ge 6) { [IO.FileSystemAclExtensions]::GetAccessControl($info) } else { $info.GetAccessControl() }
    foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($r.AccessControlType -ne 'Allow' -or ($r.FileSystemRights -band $write) -eq 0) { continue }
        if ($UserSids -contains $r.IdentityReference.Value) { return $true }
    }
    return $false
}

function Install-Pwsh([string]$work) {
    # Step 2, PowerShell 7 (u64-security's conditions, #humans 28927): download into the admin-only stage, check
    # size and SHA-256, extract there, check every signature, then move into Program Files with an ACL of
    # Administrators and SYSTEM full, Users read and execute; the machine PATH only if no user-writable folder
    # comes before it.
    $exe = Join-Path $PwshHome 'pwsh.exe'
    if (Test-Path -LiteralPath $exe) {
        $have = (& $exe -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>$null | Select-Object -First 1)
        if ("$have" -eq $PwshZip.version) { Say "pwsh $have already at $PwshHome"; return $exe }
        throw "a different PowerShell ($have) is already at ${PwshHome}: remove it first, or update this bootstrap's pin"
    }
    $zip = Join-Path $work $PwshZip.file
    Say "downloading PowerShell $($PwshZip.version) ($($PwshZip.line)), pinned by SHA-256"
    $old = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
    try { Invoke-WebRequest -UseBasicParsing -Uri $PwshZip.url -OutFile $zip } finally { $ProgressPreference = $old }
    if ((Get-Item -LiteralPath $zip).Length -ne $PwshZip.size) { throw 'the PowerShell zip is not the pinned size: refused' }
    if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -cne $PwshZip.sha256) { throw 'the PowerShell zip does not match the pinned SHA-256: refused' }
    $unpacked = Join-Path $work 'pwsh'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($zip, $unpacked)
    $bad = Get-UnsignedByMicrosoft $unpacked
    if ($bad.Count) { throw "PowerShell files not signed by Microsoft: $(($bad | Select-Object -First 5) -join ', '): refused" }
    New-Item -ItemType Directory -Path (Split-Path $PwshHome) -Force | Out-Null
    Move-Item -LiteralPath $unpacked -Destination $PwshHome
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    & $icacls $PwshHome /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0 -or (Test-UserWritable $PwshHome)) { throw "could not make $PwshHome writable by administrators only" }
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $before = @($machine -split ';' | Where-Object { $_ })
    $writable = @($before | Where-Object { Test-UserWritable ([Environment]::ExpandEnvironmentVariables($_)) })
    if ($writable.Count) {
        Say "NOT adding $PwshHome to the machine PATH: these folders before it are user-writable: $($writable -join '; ')"
    } elseif ($before -notcontains $PwshHome) {
        [Environment]::SetEnvironmentVariable('Path', (($before + $PwshHome) -join ';'), 'Machine')
        Say "added $PwshHome to the machine PATH"
    }
    Say "PowerShell $($PwshZip.version) installed at ${PwshHome}: size, SHA-256 and every signature checked"
    return $exe
}

$WingetExe = $null   # set by Get-Winget once found and checked

function Get-Winget {
    # The real winget.exe by full path, never the PATH alias: that lives in the user-writable
    # %LOCALAPPDATA%\Microsoft\WindowsApps, which any unelevated program of the operator's can replace (u64-security,
    # #humans 28966). The App Installer package's own folder under Program Files\WindowsApps is admin-protected; the
    # file must also carry a valid Microsoft signature. Found once, then remembered.
    if ($script:WingetExe) { return $script:WingetExe }
    $pkg = Get-AppxPackage -Name 'Microsoft.DesktopAppInstaller' -ErrorAction SilentlyContinue |
        Sort-Object { [version]$_.Version } -Descending | Select-Object -First 1
    if (-not $pkg) { throw 'App Installer (winget) is not installed: get "App Installer" from the Microsoft Store, then run this again' }
    $exe = Join-Path $pkg.InstallLocation 'winget.exe'
    $programFilesApps = Join-Path $env:ProgramFiles 'WindowsApps'
    if (-not $exe.StartsWith($programFilesApps + '\', [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $exe)) {
        throw "winget.exe is not where App Installer keeps it ($exe): refused"
    }
    $s = Get-AuthenticodeSignature -LiteralPath $exe
    if ($s.Status -ne 'Valid' -or -not $s.SignerCertificate -or -not (Test-MicrosoftName $s.SignerCertificate.Subject) -or
        -not (Test-MicrosoftName $s.SignerCertificate.Issuer)) { throw "winget.exe is not signed by Microsoft ($($s.Status)): refused" }
    $script:WingetExe = $exe
    return $exe
}

$WingetPackages = Join-Path $env:ProgramFiles 'WinGet\Packages'

function Get-WingetPackageDir([string]$target, [string]$root = $WingetPackages) {
    # Pure: the winget package folder (root\<package>) holding this file, or $null if it isn't under the root.
    $r = $root.TrimEnd('\') + '\'
    if (-not $target.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)) { return $null }
    $package = $target.Substring($r.Length).Split('\')[0]
    if (-not $package -or $package -eq '..' -or $package -eq '.') { return $null }
    return $r + $package
}

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
    $acl = (Get-Item -LiteralPath $root).GetAccessControl('Owner, Access')
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $aces = foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        @{ sid = $r.IdentityReference.Value; rights = [int]$r.FileSystemRights
           allow = ($r.AccessControlType -eq 'Allow'); inheritOnly = [bool]($r.PropagationFlags -band 'InheritOnly') }
    }
    $problem = Get-AclProblem $owner $aces
    if ($problem) { throw "$root is not safe to inherit from ($problem): fix its permissions, then run this again" }
}

function Repair-WingetPackageAcl([string]$path) {
    # winget unpacks a portable package in the installing user's TEMP and moves it, so its files keep that folder's
    # ACL: the installer has full control and other users (the host's account) get "Access is denied" (seen on the
    # test VM, copilot.exe and claude.exe). Reset to what Program Files gives: Users read and run, nobody else writes.
    $item = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $target = if ($item.LinkType -eq 'SymbolicLink') { @($item.Target)[0] } else { $item.FullName }
    $dir = Get-WingetPackageDir $target
    if (-not $dir -or -not (Test-Path -LiteralPath $dir)) { return }
    Assert-WingetRootSafe
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    & $icacls $dir /reset /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "could not reset the permissions of $dir" }
    Say "permissions of $dir reset to Program Files' (users read and run, administrators write)"
}

function Install-Prereqs($engines, [string]$work) {
    # Step 2: each missing tool from winget, machine-wide (PowerShell 7 from its pinned zip). Returns name -> path;
    # throws if one is still missing.
    $found = [ordered]@{}
    foreach ($name in (Get-NeededPrereqs $engines)) {
        $path = Find-Prereq $name
        if ($name -eq 'pwsh') { $path = Install-Pwsh $work }
        if (-not $path) {
            $id = $Prereqs[$name].id
            Say "installing $id (winget, machine-wide)"
            $wingetArgs = @('install', '--id', $id, '--exact', '--scope', 'machine', '--silent', '--accept-package-agreements',
                            '--accept-source-agreements', '--disable-interactivity')
            if ($Prereqs[$name].ContainsKey('skipDeps') -and $Prereqs[$name].skipDeps) { $wingetArgs += '--skip-dependencies' }
            & (Get-Winget) @wingetArgs | Out-Host
            $path = Find-Prereq $name
            if (-not $path) { throw "$id did not install where expected ($($Prereqs[$name].paths -join ', '))" }
        }
        Repair-WingetPackageAcl $path
        Say "$name`: $path"
        $found[$name] = $path
    }
    return $found
}

# --- the host code: fetched, verified, staged (2.2 step 3) -------------------------------------------------------

function New-AdminOnlyFolder([string]$path) {
    # A new folder only Administrators and SYSTEM can write (inheritance cut, a fresh ACL), so nothing running as the
    # operator unelevated can swap a file between the check and the run (u64-security, #humans 28905). Throws if it
    # exists already: a fresh folder every run.
    if (Test-Path -LiteralPath $path) { throw "$path exists already" }
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    & $icacls $path /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "could not restrict $path to Administrators and SYSTEM" }
    return $path
}

# Git runs ELEVATED here, but reads the operator's own ~/.gitconfig (and XDG config), which any unelevated program of
# theirs can write: `url.<ext::cmd>.insteadOf` would run a command as administrator at the clone (u64-security, #humans
# 28966). So no system or user config at all, HOME pointed at the admin-only work folder, only https, no credential
# helper, no prompts. $GitTestAllow is for the tests' local clone only and is empty in real use.
$GitSafeConfig = @('-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always', '-c', 'credential.helper=',
                   '-c', 'core.askPass=')
$GitTestAllow = @()

function Invoke-GitBytes([string]$git, [string[]]$arguments, [string]$isolatedHome) {
    # git's stdout as exact bytes (PowerShell's own capture would decode and re-encode it), with a clean environment
    # (above): $isolatedHome is the admin-only work folder, holding an empty config file and an empty hooks folder.
    # Throws on failure.
    if (-not $isolatedHome) { throw 'git needs the admin-only work folder' }
    $emptyConfig = Join-Path $isolatedHome 'empty.gitconfig'
    $noHooks = Join-Path $isolatedHome 'no-hooks'
    if (-not (Test-Path -LiteralPath $emptyConfig)) { [IO.File]::WriteAllText($emptyConfig, '') }
    if (-not (Test-Path -LiteralPath $noHooks)) { New-Item -ItemType Directory -Path $noHooks | Out-Null }
    $psi = New-Object Diagnostics.ProcessStartInfo $git
    $all = @($GitSafeConfig) + @('-c', "core.hooksPath=$noHooks") + @($GitTestAllow) + @($arguments)
    $psi.Arguments = ($all | ForEach-Object { if ($_ -match '[\s"]' -or $_ -eq '') { '"' + $_.Replace('"', '\"') + '"' } else { $_ } }) -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    foreach ($kv in @{ GIT_CONFIG_NOSYSTEM = '1'; GIT_CONFIG_GLOBAL = $emptyConfig; GIT_TERMINAL_PROMPT = '0'; GIT_ASKPASS = '';
                        HOME = $isolatedHome; XDG_CONFIG_HOME = $isolatedHome; GCM_INTERACTIVE = 'never' }.GetEnumerator()) {
        $psi.EnvironmentVariables[$kv.Key] = $kv.Value
    }
    foreach ($name in 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_CONFIG', 'GIT_CONFIG_PARAMETERS', 'GIT_CONFIG_COUNT', 'GIT_EXEC_PATH',
                      'GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_PROXY_COMMAND', 'GIT_TEMPLATE_DIR', 'HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY') {
        $psi.EnvironmentVariables.Remove($name)
    }
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
    Invoke-GitBytes $git @('clone', '--quiet', '--bare', '--filter=blob:none', '--single-branch', '--branch', 'main', $repo, $mirror) $work | Out-Null
    $g = { param([string[]]$a) Invoke-GitBytes $git (@('--git-dir', $mirror) + $a) $work }
    $data = & $g @('cat-file', 'blob', "main:$folder/release.toml")
    $sig = [Text.Encoding]::ASCII.GetString((& $g @('cat-file', 'blob', "main:$folder/release.toml.sig")))
    $ok, $why = Test-ReleaseSignature $data $sig $Keygen $work
    if (-not $ok) { throw "the release is not signed by a project release key with touch and PIN ($why): nothing installed" }
    $release = Read-ReleaseText ([Text.Encoding]::UTF8.GetString($data))
    if (-not (Test-ReleaseFloor $release)) {
        if (-not $release.ContainsKey('installer_sha256')) { throw "release serial $($release.serial) has no installer_sha256 (it predates what this bootstrap needs): nothing installed" }
        throw "release serial $($release.serial) is older than this bootstrap allows (at least $MinReleaseSerial): nothing installed"
    }
    $listing = [Text.Encoding]::UTF8.GetString((& $g @('ls-tree', '-r', '-z', '--full-tree', $release.commit, '--', $folder)))
    $hostFiles = @{}; $installerFiles = @{}
    foreach ($entry in ($listing -split "`0")) {
        if (-not $entry) { continue }
        $meta, $full = $entry -split "`t", 2
        if (($meta -split ' ')[1] -ne 'blob' -or -not $full.StartsWith("$folder/")) { continue }
        $rel = $full.Substring($folder.Length + 1)
        if (Test-InstalledPath $rel) { $hostFiles[$rel] = & $g @('cat-file', 'blob', "$($release.commit):$full") }
        elseif (Test-InstallerPath $rel) { $installerFiles[$rel] = & $g @('cat-file', 'blob', "$($release.commit):$full") }
        elseif ($rel.StartsWith('setup/')) {
            # Anything else in setup\ could be loaded by a script run as administrator without being hashed: refused
            # (u64-security, #humans 28905), so a new helper needs installer_sha256 to cover it first.
            throw "setup\ holds $rel, which installer_sha256 does not cover: nothing installed"
        }
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

# --- the host's own account, the pinned keys, the install (2.2 steps 4 to 6) ---------------------------------------
# u64-security's review of the design, #humans 28966: a standard account with a random password held in memory only;
# recorded so offboarding deletes only an account made here; hidden from the sign-in screen, kept out of the remote
# groups, and (after the engine sign-in, step 7) denied every logon but the scheduled task's.

$SbRoot = Join-Path $env:ProgramData 'strugglebus'
function Get-AccountRecordPath([string]$account, [string]$root = $SbRoot) {
    # Pure: one offboarding record PER ACCOUNT. One shared host-account.json was overwritten by a second host's install
    # on the same PC (seen on the test VM, 28 Nov), losing the first host's record.
    return Join-Path $root "host-account-$account.json"
}
$PinnedSigners = Join-Path $SbRoot 'allowed_signers'
$PinnedCa = Join-Path $SbRoot 'bus-ca.crt'

function Protect-SbRoot {
    # C:\ProgramData\strugglebus: ProgramData lets Users create files and folders by default, so inheritance is cut and
    # the folder owned by Administrators: Administrators and SYSTEM full, Users read and execute, nothing else.
    New-Item -ItemType Directory -Force -Path $SbRoot | Out-Null
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    & $icacls $SbRoot /setowner '*S-1-5-32-544' /Q | Out-Null
    & $icacls $SbRoot /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /Q | Out-Null
    if ($LASTEXITCODE -ne 0 -or (Test-UserWritable $SbRoot)) { throw "could not lock down $SbRoot" }
}

function New-RandomPassword([int]$length = 32) {
    # A SecureString of random characters (upper, lower, digit and symbol, so any password policy accepts it). It never
    # exists as a plain string here; the bytes are cleared after use.
    $sets = 'ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!#%+-.:=?@^_~'
    $all = -join $sets
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] ($length * 2)
    $rng.GetBytes($bytes)
    $secure = New-Object Security.SecureString
    for ($i = 0; $i -lt $length; $i++) {
        $pool = if ($i -lt $sets.Count) { $sets[$i] } else { $all }   # one of each set first, then any
        $secure.AppendChar($pool[(([int]$bytes[2 * $i] -shl 8) -bor $bytes[2 * $i + 1]) % $pool.Length])
    }
    [Array]::Clear($bytes, 0, $bytes.Length)
    $secure.MakeReadOnly()
    return $secure
}

function Get-FreeAccountName([string]$base = 'sbworker') {
    # Pure on its input: sbworker, else sbworker2, sbworker3 ... (Get-LocalUser decides what exists).
    for ($n = 1; $n -lt 100; $n++) {
        $name = if ($n -eq 1) { $base } else { "$base$n" }
        if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) { return $name }
    }
    throw 'no free sbworker account name'
}

function New-HostAccount([string]$hostPrefix, $password) {
    # Step 4: a standard local user, not an administrator, recorded in host-account-<name>.json for offboarding.
    $name = Get-FreeAccountName
    $user = New-LocalUser -Name $name -Password $password -PasswordNeverExpires -UserMayNotChangePassword `
        -AccountNeverExpires -Description "StruggleBus worker host $hostPrefix" -ErrorAction Stop
    $users = Get-LocalGroup -SID 'S-1-5-32-545'
    if (-not (Get-LocalGroupMember -Group $users -ErrorAction SilentlyContinue | Where-Object { $_.SID -eq $user.SID })) {
        Add-LocalGroupMember -Group $users -Member $user -ErrorAction Stop
    }
    foreach ($remote in 'S-1-5-32-555', 'S-1-5-32-580', 'S-1-5-32-544') {   # Remote Desktop Users, Remote Management Users, Administrators
        $g = Get-LocalGroup -SID $remote -ErrorAction SilentlyContinue
        if ($g -and (Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue | Where-Object { $_.SID -eq $user.SID })) {
            Remove-LocalGroupMember -Group $g -Member $user -ErrorAction Stop
        }
    }
    # Hidden from the sign-in screen.
    $list = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
    New-Item -Path $list -Force | Out-Null
    New-ItemProperty -Path $list -Name $name -Value 0 -PropertyType DWord -Force | Out-Null
    $record = [ordered]@{ account = $name; sid = $user.SID.Value; created_by_bootstrap = $true; host_prefix = $hostPrefix
                          created_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    [IO.File]::WriteAllText((Get-AccountRecordPath $name), ((ConvertTo-Json $record) + "`n"), (New-Object Text.UTF8Encoding($false)))
    Say "created the host's account $name (standard user, hidden from sign-in, password random and never stored)"
    return $user
}

function Get-PinnedSignersText($signerLines) {
    # Pure: the site's keys (fleet and host commands only, as the data file's patterns allow) and the built-in release
    # keys (releases only).
    $site = @($signerLines)
    return (($site + @($ReleaseKeys | ForEach-Object { 'release namespaces="strugglebus-release" ' + $_ })) -join "`n") + "`n"
}

function Save-IfDifferent([string]$file, [byte[]]$new, [string]$stamp) {
    # This machine's trust root may already be there (a host installed before, beside the new one: the DevBox): a
    # different one is kept as <file>.before-<stamp>, with the folder's ACL, and said, never replaced silently
    # (u64-security, #humans 29129). Returns the copy's path, or $null.
    if (-not (Test-Path -LiteralPath $file)) { return $null }
    $old = [IO.File]::ReadAllBytes($file)
    if ([Linq.Enumerable]::SequenceEqual($old, $new)) { return $null }
    $copy = "$file.before-$stamp"
    [IO.File]::WriteAllBytes($copy, $old)
    Say "KEPT the previous $(Split-Path $file -Leaf) as ${copy}: this machine trusted it before this install"
    return $copy
}

function Write-PinnedFiles($data) {
    # Step 5: allowed_signers and the bus CA in the locked-down folder (inherited: Administrators write, Users read).
    $signers = [Text.Encoding]::ASCII.GetBytes((Get-PinnedSignersText $data.signers))
    $ca = [Convert]::FromBase64String($data.bus_ca_pem)
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $kept = @(Save-IfDifferent $PinnedSigners $signers $stamp) + @(Save-IfDifferent $PinnedCa $ca $stamp) | Where-Object { $_ }
    [IO.File]::WriteAllBytes($PinnedSigners, $signers)
    [IO.File]::WriteAllBytes($PinnedCa, $ca)
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    foreach ($f in @($PinnedSigners, $PinnedCa) + @($kept)) {
        & $icacls $f /reset /Q | Out-Null
        & $icacls $f /setowner '*S-1-5-32-544' /Q | Out-Null
    }
    Say "pinned $(@($data.signers).Count) site key(s) and the 3 release keys in $PinnedSigners"
}

function Get-HostTaskName([string[]]$existing, [string]$account) {
    # Pure: the scheduled task's name. The usual one, unless another host on this PC has it (the DevBox's devhost01
    # host while the sbworker one is set up beside it): then one named for the account, so neither replaces the other.
    $default = 'StrugglebusWorkerHost'
    if (@($existing) -notcontains $default) { return $default }
    $name = "$default-$account"
    if (@($existing) -contains $name) { throw "a task named $name already exists: remove that host first" }
    return $name
}

function Get-SiteText($data) {
    # Pure: the site file install.ps1 reads (workerhost/sitefile.py), from the checked data file.
    $remotes = (@($data.remotes) | ForEach-Object { '"' + $_ + '"' }) -join ', '
    return "bus_url = `"$($data.bus_url)`"`nfleet_source = `"$($data.fleet_source)`"`nremotes = [$remotes]`n"
}

function Get-ReleaseRecordText($release, [string]$repo = $ReleaseRepo, [string]$folder = $ReleaseFolder) {
    # Pure: app\RELEASE.json for the release step 3 verified, in workerhost/update.py's own form (what apply() writes),
    # with where it came from as the source for its updates. install.ps1 on its own writes "manual", serial 0, and no
    # source; a host from this script would then never update itself (it has no fleet repository to fall back on).
    $record = [ordered]@{ version = $release.version; serial = [int]$release.serial; commit = $release.commit
                          tree_sha256 = $release.tree_sha256; moved_to = [ordered]@{ repo = $repo; path = $folder } }
    return (ConvertTo-Json $record -Depth 3) + "`n"
}

function Write-ReleaseRecord([string]$hostHome, $release) {
    $file = Join-Path $hostHome 'app\RELEASE.json'
    [IO.File]::WriteAllText($file, (Get-ReleaseRecordText $release), (New-Object Text.UTF8Encoding($false)))
    Say "recorded release $($release.version) (serial $($release.serial)) from $ReleaseRepo, $ReleaseFolder as installed: the host updates from there"
}

function Invoke-Install([string]$pwsh, [string]$stage, [string]$work, $data, [string]$account, $password, $tools) {
    # Step 6: the staged, verified install.ps1, by full path, without the operator's profile, for the account; its
    # password goes on stdin and nowhere else.
    $site = Join-Path $work 'site.toml'
    [IO.File]::WriteAllText($site, (Get-SiteText $data), [Text.Encoding]::ASCII)
    $installer = Join-Path $stage 'install.ps1'
    $psi = New-Object Diagnostics.ProcessStartInfo $pwsh
    $taskName = Get-HostTaskName @(Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object TaskName) $account
    if ($taskName -ne 'StrugglebusWorkerHost') { Say "another host on this PC has the usual task name: this one's task is $taskName" }
    $parts = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $installer, '-Account', $account,
               '-PasswordStdin', '-SiteFile', $site, '-BusCa', $PinnedCa, '-AgentPrefix', $data.host_prefix,
               '-DefaultEngine', @($data.engines)[0], '-TaskName', $taskName)
    $psi.Arguments = ($parts | ForEach-Object { if ($_ -match '[\s"]') { '"' + $_ + '"' } else { $_ } }) -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.WorkingDirectory = $stage
    # A fresh PATH: this process started before step 2 installed the tools, so its own PATH is stale. The machine's
    # PATH plus the tools' own folders, never the user's PATH (folders the operator can write, run elevated here).
    $toolDirs = @($tools.Values | ForEach-Object { Split-Path $_ } | Select-Object -Unique)
    $psi.EnvironmentVariables['Path'] = (@($toolDirs) + @([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';' |
        Where-Object { $_ })) -join ';'
    $p = [Diagnostics.Process]::Start($psi)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    try { $p.StandardInput.WriteLine([Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr); $p.StandardInput.Close() }
    $p.WaitForExit()
    if ($p.ExitCode -ne 0) { throw "install.ps1 failed (exit $($p.ExitCode)): see its output above" }
}

# --- sign-in, logon rights, enrolment, start (2.2 steps 7 to 9 and 12) ---------------------------------------------

function New-AccountCredential([string]$account, $password) {
    return New-Object Management.Automation.PSCredential("$env:COMPUTERNAME\$account", $password)
}

function Stop-AccountProcesses([string]$account) {
    # Whatever a sign-in left running as the host's account (a browser, mostly): closed, so nothing interactive keeps
    # running under it. Its scheduled task isn't started yet.
    $left = @(Get-Process -IncludeUserName -ErrorAction SilentlyContinue |
        Where-Object { $_.UserName -eq "$env:COMPUTERNAME\$account" })
    if ($left.Count) {
        Say "closing what the sign-in left running as ${account}: $(($left.ProcessName | Sort-Object -Unique) -join ', ')"
        $left | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

function Get-SignInCommand([string]$engine, [string]$exe, [string]$mode) {
    # Pure: the command a sign-in window runs, and what to tell the operator. 'device': a code shown here, approved
    # in a browser on ANY PC (a passkey or a signed-in browser elsewhere works; nothing opens here). 'browser': a
    # browser opens on THIS PC (Copilot's needs the passkey or sign-in to reach this PC).
    $device = $mode -ne 'browser'
    switch ($engine) {
        'gh' {
            # gh shows the code either way; in device mode GH_BROWSER only prints the link instead of opening it.
            $quiet = if ($device) { 'set "GH_BROWSER=cmd /c echo Open on any PC:" && ' } else { '' }
            return @{ cmd = "$quiet`"$exe`" auth login --hostname github.com --git-protocol https --web && `"$exe`" auth setup-git"
                      hint = 'copy the one-time code, open https://github.com/login/device, approve, then close this window' }
        }
        'ghcp' {
            if ($device) {
                return @{ cmd = "`"$exe`" login --device-code"
                          hint = 'open https://github.com/login/device on any PC, enter the code shown, then close this window' }
            }
            return @{ cmd = "`"$exe`" login"; hint = 'approve in the browser that opens here, then close this window' }
        }
        default {
            # Claude Code's /login shows a link and takes the code back by paste, so it works from any PC either way.
            return @{ cmd = "`"$exe`""; hint = 'type /login, open the link it shows, paste the code back, then /exit and close this window' }
        }
    }
}

function Read-SignInMode([string]$given, [bool]$yes) {
    if ($given) { return $given }
    if ($yes) { return 'device' }
    Say 'How will you approve the sign-ins (GitHub, and each engine)?'
    Say '  1 = a device code: approve on any PC or phone where you are already signed in (recommended; works for VMs)'
    Say '  2 = a browser on this PC'
    $a = Read-Host '[bootstrap] 1 or 2 (Enter = 1)'
    if ($a -eq '2') { return 'browser' }
    return 'device'
}

function Invoke-SignIn([string]$account, $password, $engines, $tools, [string]$mode = 'device') {
    # Step 7: each sign-in must run AS the host's account (its tokens are stored in that profile), so a window opens
    # under it; the operator approves it (Get-SignInCommand), then closes the window.
    # Skipped or failed: the host shows needs-sign-in, and `wh signin <engine>` finishes it later.
    $cred = New-AccountCredential $account $password
    # gh first: the host uses it (whether a worker's branch was merged before its clone is deleted; the probe checks
    # `gh auth status`), and `gh auth setup-git` makes it git's GitHub credential for this account.
    foreach ($engine in @('gh') + @($engines)) {
        $exe = $tools[$engine]
        $how = Get-SignInCommand $engine $exe $mode
        $cmd = $how.cmd
        $hint = $how.hint
        Say "signing $engine in as $account in a new window: $hint"
        try {
            # HOME: git takes its home from HOME, then HOMEDRIVE+HOMEPATH, which a window opened this way leaves at
            # C:\Windows (seen on the test VM: gh auth setup-git could not lock C:/WINDOWS/.gitconfig).
            # Wait for the window only: -Wait also waits for everything it started, and a browser the sign-in opened
            # as the account keeps running after the window closes (seen on the test VM: the script hung).
            $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\cmd.exe') `
                -ArgumentList '/k', "title Sign in $engine as $account && set `"HOME=%USERPROFILE%`" && $cmd" `
                -Credential $cred -LoadUserProfile -WorkingDirectory $env:SystemRoot -PassThru -ErrorAction Stop
            $p.WaitForExit()
            Stop-AccountProcesses $account
        } catch {
            Say "the $engine sign-in window could not open ($($_.Exception.Message)): finish later with 'wh signin $engine'"
        }
    }
}

$DeniedRights = 'SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeDenyNetworkLogonRight', 'SeDenyServiceLogonRight'

function Update-UserRightsInf([string]$inf, [string]$sid, [string[]]$rights) {
    # Pure: a secedit export (its [Privilege Rights] section) with *SID added to each right, once; a missing right is
    # added. Other rights and other holders are left exactly as they were.
    $entry = "*$sid"
    $lines = [Collections.Generic.List[string]]($inf -split "`r?`n")
    $start = $lines.FindIndex([Predicate[string]] { param($l) $l.Trim() -eq '[Privilege Rights]' })
    if ($start -lt 0) { $lines.Add('[Privilege Rights]'); $start = $lines.Count - 1 }
    $end = $start + 1
    while ($end -lt $lines.Count -and -not $lines[$end].TrimStart().StartsWith('[')) { $end++ }
    foreach ($right in $rights) {
        $found = $false
        for ($i = $start + 1; $i -lt $end; $i++) {
            if ($lines[$i] -match "^\s*$right\s*=\s*(.*)$") {
                $holders = @($Matches[1].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                if ($holders -notcontains $entry) { $holders += $entry }
                $lines[$i] = "$right = " + ($holders -join ',')
                $found = $true
            }
        }
        if (-not $found) { $lines.Insert($end, "$right = $entry"); $end++ }
    }
    return ($lines -join "`r`n")
}

function Add-UserRights([string]$sid, [string[]]$rights) {
    # Adds the SID to these user rights (secedit export, Update-UserRightsInf, import); other holders are kept.
    $secedit = Join-Path $env:SystemRoot 'System32\secedit.exe'
    $tag = [guid]::NewGuid().ToString('n')
    $infFile = Join-Path $work "rights-$tag.inf"
    $db = Join-Path $work "rights-$tag.sdb"
    & $secedit /export /cfg $infFile /areas USER_RIGHTS /quiet | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'could not read the user rights (secedit /export)' }
    $updated = Update-UserRightsInf ([IO.File]::ReadAllText($infFile)) $sid $rights
    [IO.File]::WriteAllText($infFile, $updated, [Text.Encoding]::Unicode)
    & $secedit /configure /db $db /cfg $infFile /areas USER_RIGHTS /quiet | Out-Null
    $code = $LASTEXITCODE
    Remove-Item -LiteralPath $infFile, $db, ([IO.Path]::ChangeExtension($db, '.jfm')) -Force -ErrorAction SilentlyContinue
    if ($code -ne 0) { throw "could not set $($rights -join ', ') (secedit /configure)" }
}

function Grant-BatchLogon([string]$sid) {
    # Step 4: a standard user doesn't hold "log on as a batch job", and registering a task doesn't grant it: without it
    # the scheduled task's logon is refused (0xC000015B, seen on the test VM). The existing hosts run as administrators,
    # who hold it already.
    Add-UserRights $sid @('SeBatchLogonRight')
    Say "the host's account may log on as a batch job (its scheduled task)"
}

function Set-HostLogonRights([string]$sid) {
    # After the sign-in and the enrolment: the account may run its scheduled task and nothing else: no sign-in at the
    # PC, no Remote Desktop, no network logon (SMB, WinRM), no services (u64-security, #humans 28966).
    Add-UserRights $sid $DeniedRights
    Say "the host's account is now denied sign-in at the PC, Remote Desktop, network and service logon"
}

function Invoke-AsAccount([string]$exe, [string[]]$arguments, [string]$account, $password, [string]$stdinLine = '') {
    # Runs a program as the host's account (its profile loaded), with an optional stdin line; returns its output.
    $psi = New-Object Diagnostics.ProcessStartInfo $exe
    $psi.Arguments = ($arguments | ForEach-Object { if ($_ -match '[\s"]') { '"' + $_ + '"' } else { $_ } }) -join ' '
    $psi.UserName = $account
    $psi.Domain = $env:COMPUTERNAME
    $psi.Password = $password
    $psi.LoadUserProfile = $true
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = $env:SystemRoot
    $p = [Diagnostics.Process]::Start($psi)
    $err = $p.StandardError.ReadToEndAsync()
    if ($stdinLine) { $p.StandardInput.WriteLine($stdinLine) }
    $p.StandardInput.Close()
    $out = $p.StandardOutput.ReadToEnd()
    $p.WaitForExit()
    return @{ code = $p.ExitCode; out = $out; err = $err.Result }
}

function Invoke-Enrol([string]$python, [string]$hostHome, [string]$account, $password, [byte[]]$bytes, [string]$dataFile) {
    # Step 8: `wh enrol --code-stdin` as the account (its credentials are stored as that account): the one-time code
    # goes on stdin, never on a command line or in a log, and is blanked in the data file straight after (Q1).
    $data = Read-SbData $bytes -SingleSigner:$SingleSigner
    if (-not $data.enrol_code) { throw 'the data file has no enrolment code left (already used): get a new one from the App' }
    $wh = Join-Path $hostHome 'app\wh.py'
    $r = Invoke-AsAccount $python @('-I', $wh, '--home', $hostHome, 'enrol', '--code-stdin') $account $password $data.enrol_code
    [IO.File]::WriteAllText((Resolve-Path -LiteralPath $dataFile).Path, (Clear-EnrolCode $data), [Text.Encoding]::ASCII)
    Say 'the one-time code is blanked in the data file'
    $r.out -split "`r?`n" | Where-Object { $_ } | ForEach-Object { Say "  $_" }
    if ($r.code -ne 0) { throw "enrolment failed (exit $($r.code)): get a new code from the App and run this again" }
    $m = [regex]::Match($r.out, 'CONFIRMATION CODE ([0-9a-f]{8})')
    $id = [regex]::Match($r.out, 'host identity (\S+)')
    if (-not $m.Success) { throw 'enrolment printed no confirmation code' }
    return @{ code = $m.Groups[1].Value; identity = $id.Groups[1].Value }
}

function Start-Host([string]$python, [string]$hostHome) {
    # Step 9: `wh start` (enables and starts the scheduled task), then wait for the host's first status.
    & $python -I (Join-Path $hostHome 'app\wh.py') --home $hostHome start | ForEach-Object { Say "  $_" }
    $status = Join-Path $hostHome 'state\status.json'
    $deadline = (Get-Date).AddMinutes(3)
    while ((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath $status)) { Start-Sleep -Seconds 5 }
    if (Test-Path -LiteralPath $status) { Say 'the host is running and reporting' }
    else { Say 'the host has not reported within 3 minutes: check Task Scheduler and its log under the home folder' }
}

function Invoke-IsolationCheck([string]$stage, [string]$account, [string]$hostHome, [string]$workersRoot) {
    # Step 11 (u64-security's check, vendored as setup\Get-WorkerIsolationHits.ps1, so it arrives in the verified stage
    # under installer_sha256): anything the host's account could change that runs as someone else. The paths are shown
    # here only; the host gets the counts (state\isolation.json), which raise its standing "isolation-weak" warning.
    $check = Join-Path $stage 'setup\Get-WorkerIsolationHits.ps1'
    if (-not (Test-Path -LiteralPath $check)) { Say 'this release has no isolation check: skipped'; return }
    $execCount = -1; $info = @()
    try {
        . $check   # strict-mode safe from u64-security 08662d3; if it still throws, the catch counts it as weak
        $hits = @(Get-WorkerIsolationHits -Account $account -Exclude @($hostHome, $workersRoot))
        $exec = @($hits | Where-Object { $_.Severity -eq 'exec' })
        $info = @($hits | Where-Object { $_.Severity -ne 'exec' })
        $execCount = $exec.Count
    } catch {
        # Unknown is not clean: the host shows isolation-weak (exec_hits -1) until the check is run again.
        Say "ISOLATION CHECK FAILED ($($_.Exception.Message)): the host will show the isolation-weak warning"
    }
    if ($execCount -lt 0) {
    } elseif ($exec.Count) {
        Say "ISOLATION: $($exec.Count) thing(s) the host's account can change would run as someone else:"
        foreach ($h in $exec) { Say "  [$($h.Kind)] $($h.Source): $($h.Path) ($($h.Why))" }
        Say 'Fix their permissions; until then the host shows the isolation-weak warning.'
    } else {
        Say 'isolation check: nothing the host''s account can change runs as anyone else'
    }
    if ($info.Count) { Say "  (and $($info.Count) writable top-level folder(s), lower severity)" }
    $record = [ordered]@{ exec_hits = $execCount; info_hits = $info.Count
                          checked_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    $state = Join-Path $hostHome 'state'
    New-Item -ItemType Directory -Force -Path $state | Out-Null
    [IO.File]::WriteAllText((Join-Path $state 'isolation.json'), ((ConvertTo-Json $record) + "`n"), (New-Object Text.UTF8Encoding($false)))
}

$StrayGitConfig = Join-Path $env:SystemRoot '.gitconfig'

function Test-StrayGitConfig([switch]$Remove) {
    # Any git run with no HOME and no profile (SYSTEM, a service, another account's batch job) takes
    # C:\Windows\.gitconfig as its global config, so a file there quietly steers git for them (u64-security, 29049).
    # Before the install: refuse (someone else's file; an administrator decides). After the sign-ins: ours, removed.
    if (-not (Test-Path -LiteralPath $StrayGitConfig)) { Say "checked: no $StrayGitConfig"; return }
    if (-not $Remove) {
        throw "$StrayGitConfig exists: git run without a profile (SYSTEM, services) reads it. Look at it, remove it, then run this again."
    }
    Remove-Item -LiteralPath $StrayGitConfig -Force
    Say "removed $StrayGitConfig (left by a sign-in; git without a profile would read it)"
}

function Show-SignInKey([string]$python, [string]$hostHome, [string]$account, $password) {
    # Spec 4a (u64-security, #humans 29120): the host's key for a sealed Claude token, made now as the account (its
    # private half is DPAPI, so only that account can make or use it), and its fingerprint printed here, so the App's
    # first pin is compared with what the machine itself showed, not trusted on first use.
    try {
        $r = Invoke-AsAccount $python @('-I', (Join-Path $hostHome 'app\wh.py'), '--home', $hostHome, 'sign-in-key') $account $password
        $m = [regex]::Match($r.out, 'sign-in key: (SHA256:[A-Za-z0-9+/]{43})')
        if ($r.code -eq 0 -and $m.Success) {
            Say "this host's sign-in key: $($m.Groups[1].Value)"
            Say '  (the App shows this the first time it signs Claude Code in here: check they match)'
        } else {
            Say "could not make the sign-in key (exit $($r.code)): 'wh sign-in-key', as the host's account, makes it later"
        }
    } catch {
        Say "could not make the sign-in key ($($_.Exception.Message))"
    }
}

function Show-SignInResult([string]$python, [string]$hostHome, [string]$account, $password) {
    # After the sign-ins, still able to run as the account: its probe, so a skipped or failed sign-in shows now
    # (on the test VM a cancelled Claude sign-in otherwise went unnoticed).
    try {
        $r = Invoke-AsAccount $python @('-I', (Join-Path $hostHome 'app\wh.py'), '--home', $hostHome, 'probe') $account $password
        $lines = @($r.out -split "`r?`n" | Where-Object { $_ -match 'signed in|gh auth|copilot' })
        Say 'sign-ins, as the host sees them:'
        foreach ($l in $lines) { Say "  $($l.Trim())" }
        if ($lines -match '^\s*FAIL') { Say 'A sign-in is missing: the host runs without it (that engine is not offered) until it is added.' }
    } catch {
        Say "could not check the sign-ins ($($_.Exception.Message))"
    }
}

function Remove-DataFileOffer([string]$dataFile, [bool]$yes) {
    # Step 12: the data file's code is spent and blanked; offer to delete it.
    if ($yes) { Say "the data file $dataFile is no longer needed (its code is spent); delete it when you like"; return }
    if ((Read-Host '[bootstrap] delete the data file now? (yes/no)') -ceq 'yes') {
        Remove-Item -LiteralPath $dataFile -Force
        Say 'data file deleted'
    }
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
$mode = Read-SignInMode $SignIn $Yes                    # asked now, so the rest runs unattended up to the sign-ins
Test-StrayGitConfig

$work = New-AdminOnlyFolder (Join-Path $env:ProgramData ('strugglebus\bootstrap-' + [guid]::NewGuid().ToString('n')))
$tools = Install-Prereqs $SB.engines $work              # step 2
$verified = Get-VerifiedRelease $tools.git $work        # step 3
Say "verified host code staged at $($verified.stage)"
Protect-SbRoot
$password = New-RandomPassword
$account = New-HostAccount $SB.host_prefix $password    # step 4
Grant-BatchLogon $account.SID.Value
Write-PinnedFiles $SB                                    # step 5
Invoke-Install $tools.pwsh $verified.stage $work $SB $account.Name $password $tools   # step 6
$hostHome = Join-Path $SbRoot "host\$($account.Name)"
Write-ReleaseRecord $hostHome $verified.release
Invoke-IsolationCheck $verified.stage $account.Name $hostHome 'C:\sb-workers'   # step 11, straight after the install
# Steps 8 and 7 run AS the account, which is an interactive logon (CreateProcessWithLogonW), so they come before the
# denials; the finally applies the denials even when the enrolment or a sign-in fails. Enrolment first: the App's
# code lasts 15 minutes, and the sign-ins take as long as the operator needs (on the test VM they outlasted it).
try {
    $enrolled = Invoke-Enrol $tools.python $hostHome $account.Name $password $bytes $DataFile   # step 8
    Show-SignInKey $tools.python $hostHome $account.Name $password               # spec 4a
    Invoke-SignIn $account.Name $password $SB.engines $tools $mode               # step 7
    Show-SignInResult $tools.python $hostHome $account.Name $password
    Test-StrayGitConfig -Remove
} finally {
    $password = $null
    Set-HostLogonRights $account.SID.Value                                       # step 7's denials
}
Start-Host $tools.python $hostHome                                                  # step 9
Say "enrolled as $($enrolled.identity). CONFIRMATION CODE: $($enrolled.code)"
Say 'In the App, compare this code with the one it shows for this host, then approve the host into the fleet.'
Say 'Until then the host waits in "needs-fleet" and takes no work (step 10).'
Say 'Note: this account''s password exists nowhere. A reinstall sets a new one, which makes the saved sign-ins and'
Say 'secrets unreadable (DPAPI): a reinstall means signing in to the engines and enrolling again.'
Remove-DataFileOffer $DataFile $Yes                                              # step 12
