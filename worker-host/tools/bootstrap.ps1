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

if ($MyInvocation.InvocationName -eq '.') { return }

function Say([string]$text) { Write-Host "[bootstrap] $text" }

if (-not $DataFile) { throw 'give the App''s data file: bootstrap.ps1 -DataFile .\sbhost-enrol.json' }
$bytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $DataFile).Path)
$SB = Read-SbData $bytes -SingleSigner:$SingleSigner
Say "data file from device $($SB.device), $($SB.written_at), for host $($SB.host_prefix) on $($SB.bus_url)"
Say "data file digest: $(Get-FileDigest $bytes)"
foreach ($line in $SB.signers) { Say "signer: $(Get-SignerFingerprint $line)" }
Say 'compare these with what the App shows for this host.'
if (-not $Yes) { Read-Host '[bootstrap] press Enter to continue, or close this window to stop' | Out-Null }
throw 'not built yet: the install steps (2.2 steps 2 to 12) come in a later change'
