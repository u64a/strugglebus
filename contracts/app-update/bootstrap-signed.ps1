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

# SIG # Begin signature block
# MIIniwYJKoZIhvcNAQcCoIInfDCCJ3gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBh5sZAclnDblvS
# J6jan4LBvg5H0l6SELFyQuJJw5ktIqCCID8wggXJMIIEsaADAgECAhAbtY8lKt8j
# AEkoya49fu0nMA0GCSqGSIb3DQEBDAUAMH4xCzAJBgNVBAYTAlBMMSIwIAYDVQQK
# ExlVbml6ZXRvIFRlY2hub2xvZ2llcyBTLkEuMScwJQYDVQQLEx5DZXJ0dW0gQ2Vy
# dGlmaWNhdGlvbiBBdXRob3JpdHkxIjAgBgNVBAMTGUNlcnR1bSBUcnVzdGVkIE5l
# dHdvcmsgQ0EwHhcNMjEwNTMxMDY0MzA2WhcNMjkwOTE3MDY0MzA2WjCBgDELMAkG
# A1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVzIFMuQS4xJzAl
# BgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEkMCIGA1UEAxMb
# Q2VydHVtIFRydXN0ZWQgTmV0d29yayBDQSAyMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAvfl4+ObVgAxknYYblmRnPyI6HnUBfe/7XGeMycxca6mR5rlC
# 5SBLm9qbe7mZXdmbgEvXhEArJ9PoujC7Pgkap0mV7ytAJMKXx6fumyXvqAoAl4Va
# qp3cKcniNQfrcE1K1sGzVrihQTib0fsxf4/gX+GxPw+OFklg1waNGPmqJhCrKtPQ
# 0WeNG0a+RzDVLnLRxWPa52N5RH5LYySJhi40PylMUosqp8DikSiJucBb+R3Z5yet
# /5oCl8HGUJKbAiy9qbk0WQq/hEr/3/6zn+vZnuCYI+yma3cWKtvMrTscpIfcRnNe
# GWJoRVfkkIJCu0LW8GHgwaM9ZqNd9BjuiMmNF0UpmTJ1AjHuKSbIawLmtWJFfzcV
# WiNoidQ+3k4nsPBADLxNF8tNorMe0AZa3faTz1d1mfX6hhpneLO/lv403L3nUlbl
# s+V1e9dBkQXcXWnjlQ1DufyDljmVe2yAWk8TcsbXfSl6RLpSpCrVQUYJIP4ioLZb
# MI28iQzV13D4h1L92u+sUS4Hs07+0AnacO+Y+lbmbdu1V0vc5SwlFcieLnhO+Nqc
# noYsylfzGuXIkosagpZ6w7xQEmnYDlpGizrrJvojybawgb5CAKT41v4wLsfSRvbl
# jnX98sy50IdbzAYQYLuDNbdeZ95H7JlI8aShFf6tjGKOOVVPORa5sWOd/7cCAwEA
# AaOCAT4wggE6MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLahVDkCw6A/joq8
# +tT4HKbROg79MB8GA1UdIwQYMBaAFAh2zcsH/yT2xc3tu5C84oQ3RnX3MA4GA1Ud
# DwEB/wQEAwIBBjAvBgNVHR8EKDAmMCSgIqAghh5odHRwOi8vY3JsLmNlcnR1bS5w
# bC9jdG5jYS5jcmwwawYIKwYBBQUHAQEEXzBdMCgGCCsGAQUFBzABhhxodHRwOi8v
# c3ViY2Eub2NzcC1jZXJ0dW0uY29tMDEGCCsGAQUFBzAChiVodHRwOi8vcmVwb3Np
# dG9yeS5jZXJ0dW0ucGwvY3RuY2EuY2VyMDkGA1UdIAQyMDAwLgYEVR0gADAmMCQG
# CCsGAQUFBwIBFhhodHRwOi8vd3d3LmNlcnR1bS5wbC9DUFMwDQYJKoZIhvcNAQEM
# BQADggEBAFHCoVgWIhCL/IYx1MIy01z4S6Ivaj5N+KsIHu3V6PrnCA3st8YeDrJ1
# BXqxC/rXdGoABh+kzqrya33YEcARCNQOTWHFOqj6seHjmOriY/1B9ZN9DbxdkjuR
# mmW60F9MvkyNaAMQFtXx0ASKhTP5N+dbLiZpQjy6zbzUeulNndrnQ/tjUoCFBMQl
# lVXwfqefAcVbKPjgzoZwpic7Ofs4LphTZSJ1Ldf23SIikZbr3WjtP6MZl9M7JYjs
# NhI9qX7OAo0FmpKnJ25FspxihjcNpDOO16hO0EoXQ0zF8ads0h5YbBRRfopUofbv
# n3l6XYGaFpAP4bvxSgD5+d2+7arszgowggZuMIIEVqADAgECAhBN2plxRehW7d8i
# 84MUmE69MA0GCSqGSIb3DQEBCwUAMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhB
# c3NlY28gRGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNp
# Z25pbmcgMjAyMSBDQTAeFw0yNjExMjYyMDQ0MzNaFw0yNzExMjYyMDQ0MzJaMIGT
# MQswCQYDVQQGEwJBVTEYMBYGA1UECAwPTmV3IFNvdXRoIFdhbGVzMRMwEQYDVQQH
# DApTaGVsbCBDb3ZlMR4wHAYDVQQKDBVPcGVuIFNvdXJjZSBEZXZlbG9wZXIxNTAz
# BgNVBAMMLE9wZW4gU291cmNlIERldmVsb3BlciBDaHJpc3RvcGhlciBDdW5uaW5n
# aGFtMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAxyrJOkPCpXPPwVdY
# +PjHnhHXCU/p96M9rhkM3B3smPm9smUA2BtgB9tbV1W2gIfYrxsyaQYIH6Nj4VNf
# yZ4S4E/gvV0qVgmMOEZ+sUA4xZlq/aL+1upXXSI80ltAtI8ZPq4ODprw8TQr2TyJ
# XDNzqSPh2SuL0pP+3dEISMIXo9o1D/UJUjykxWjlI2SUbzzuiK+Zd4u2lODNplUw
# 7Q+91mdwvRZR9Spov8CxQk+t0h5ZoqK3vHxu1sBm9Nx83bed54mVRBDlLOXPOmXO
# WRYednwFGPwLLzE8xshulX9oomITY7n8K2NTC9NpZgbgXtDjTWu6Q52kIrB2uBKj
# M2v1Ge5oYuwREkXSQr/YFVlB3jBcGtXOQUQW/IXK3vt9+7U2hx9ZKZkizVjd1i34
# vnlw5bPeGHFllvfHz6W0g8rP31K8XYsYx9Q6BgvIt4a+ITYyx6pLE7rEAnbOoaak
# i/ZX6jDzRaKEU58PZJnsV1yqBXfRfumvObqXIR+xZA/gGuPLAgMBAAGjggF4MIIB
# dDAMBgNVHRMBAf8EAjAAMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jY3NjYTIw
# MjEuY3JsLmNlcnR1bS5wbC9jY3NjYTIwMjEuY3JsMHMGCCsGAQUFBwEBBGcwZTAs
# BggrBgEFBQcwAYYgaHR0cDovL2Njc2NhMjAyMS5vY3NwLWNlcnR1bS5jb20wNQYI
# KwYBBQUHMAKGKWh0dHA6Ly9yZXBvc2l0b3J5LmNlcnR1bS5wbC9jY3NjYTIwMjEu
# Y2VyMB8GA1UdIwQYMBaAFN10XUwA23ufoHTKsW73PMAywHDNMB0GA1UdDgQWBBQg
# y4InGH4k6zcwAVavIP2DaHW/VDBLBgNVHSAERDBCMAgGBmeBDAEEATA2BgsqhGgB
# hvZ3AgUBBDAnMCUGCCsGAQUFBwIBFhlodHRwczovL3d3dy5jZXJ0dW0ucGwvQ1BT
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0B
# AQsFAAOCAgEAYA8dgYbN0y5LaSTTk5S909iFeTDiOq7MG7Fg3AGtqZ680qIf6iV8
# n3gYB9y5uSa4/josUHMWj/wfZab7d3XrhXnpKTshti0VKoW3fnTbzIk6actckucs
# M2PY2vDz1HGV+StoqW8oVntpUVCYD9FFl/JdA6f67ISG/yY/uuKjXIebDBA55L7Y
# EgVCEu7obQODMpYwjYmzHTsII0rOoEienRmkXp5bWIgJkoZVlGIRSemHZxYoclIv
# w7fV9++hbK+HEV8Vfwtjr+mUgBJW+20i5b7DUeF89c7WZjplhLh2ZwfBLFD2PJ7P
# gZGsJEnabuwYjyM+KJlqw68v/tPl0KuxkkN5b8swxV/MbXfGxaf8ZBsV1Meir+lA
# D64P1s3ieZuqzXd0flacVrCQdBpm3A4S0HqUZw0BAgU5fPMbFpeuOWSJohhlXALI
# v/M9pw8XPYoFQq44ylNLKQQ5MxKtIa5Q2wHvkx6/Cdl407TeSmkv3LBEo4Rf8yOD
# jOeEw/ve0bwCOU6gV2ipgMRFJYW0LpN4apamMgGOjcQYTK8LFD4PcNEDapXLYjS5
# 40XUHUVdPYWQt18cBZ4xBAaNPaw6Ro6YdKQEG7Zu1fQc6KBEJhin2BV6eDjcO39H
# nHqIodvKmk1pCw1rd7psK6alQc+L6VaZAC9MCxrE1jpYod9BRG72HwAwggaCMIIE
# aqADAgECAhAo8HfBHDa9/l90MkdwJy4DMA0GCSqGSIb3DQEBDAUAMFYxCzAJBgNV
# BAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNV
# BAMTG0NlcnR1bSBUaW1lc3RhbXBpbmcgMjAyMSBDQTAeFw0yNjAzMTEwNzM0NTRa
# Fw0zNjAyMjcwNzM0NTRaMFAxCzAJBgNVBAYTAlBMMSEwHwYDVQQKDBhBc3NlY28g
# RGF0YSBTeXN0ZW1zIFMuQS4xHjAcBgNVBAMMFUNlcnR1bSBUaW1lc3RhbXAgMjAy
# NjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALi9zfBw+xI12hi2F9uN
# QBNOSTkTIi13fuh3DiWybI5392bBfJw6tO7zDs7UqP/rejVf4xFTU3XNOPsuOFkP
# 5SPFsnWwn3VJL+NhNhsuujvYsQtaQnvNo1wk46reTgws1L8OFEdKaxgyqT4zOQx8
# 1mLwNZSqXNU9Rrb9oAJWJF4Mydz+C1ebu0D0+vgM3tqAQ8TU203fqgKCPqIdHloa
# FqH9eyR+8tnpmy2hnnN59ZOtmsuHeRwf5iTOhlhf0d/qqquLOSIGPgGVL1Hj5XBU
# ox2OE7tQRr+l/xxNbL6OuwBO4Aa2EbuxYg37cpXv5i2/lTL4NASB/duf9W4fjA3R
# o+GP+bC54n2OYiM3Cq8z92ejx8F5HWO2e4/75eC95B9tMw/eq7109GDyW2+2ut5B
# n0o8MXJTERkyystWbqcnUkomA97qfiDCwvpWuOMdfTOksXe9S+xDxOJaCbiyTivg
# PulxcT+tfQTRXBr5UwtPvc+INnafOEilzVHA11tv+pHcylryxBc08cUihf/ttqkZ
# S0bmx3VxQay8uohaTp0//ECA9vYGW51SKdJMJhXvKyIdBLy8WYNchTt8yRITv9Ad
# xg9JqGujh+TnP1bW3aQjFtlEl7SzgNeI8OVA/CJAWWUuRT3Au9ToOpHy/flrrknh
# N4heEw7/6ILMv4HSsj0YZ4otAgMBAAGjggFQMIIBTDB1BggrBgEFBQcBAQRpMGcw
# OwYIKwYBBQUHMAKGL2h0dHA6Ly9zdWJjYS5yZXBvc2l0b3J5LmNlcnR1bS5wbC9j
# dHNjYTIwMjEuY2VyMCgGCCsGAQUFBzABhhxodHRwOi8vc3ViY2Eub2NzcC1jZXJ0
# dW0uY29tMB8GA1UdIwQYMBaAFL5UAi+/QGxzQ86sCSVOnkNEGu7gMAwGA1UdEwEB
# /wQCMAAwOQYDVR0fBDIwMDAuoCygKoYoaHR0cDovL3N1YmNhLmNybC5jZXJ0dW0u
# cGwvY3RzY2EyMDIxLmNybDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8B
# Af8EBAMCB4AwIgYDVR0gBBswGTAIBgZngQwBBAIwDQYLKoRoAYb2dwIFAQswHQYD
# VR0OBBYEFCM5aiirmhKnpKfyH/lFmr+N/oIDMA0GCSqGSIb3DQEBDAUAA4ICAQBm
# /pObrAveTqYFPCSthxNVwBHTW4TfuBQY2KGCdMlH6ALjVPYf2XARNGMTXScR0JQ2
# /c2LxLpoHHhRwxFf3d933DhFS165rYj6iPSQKm41rc9AMpTCjMdmai1aK9o870pO
# zTzLRhWFVIxm+5Qf+t4V5z14tPoUsAWdfRKD1Zzvzfe5AHlE9rxOZcGROiULxs3E
# df7ZJ8RZI0jzD9juj2oEX2XS7BVKuNCK1W0h1mjapv028yqo8UtZh5/1Ib48Yyp8
# 8BDYShh5PSGUUuS5tYXVfcduIPBe3PdNTYRYdT5VNxkwLgjMzIcr/6SH2fejFJDj
# nCxjvXLuarErJg/IdI+hXdGIBDVOGv1zrkF4ktoQvFZIp5DIAYh0GwyUhc87qqn5
# UaYTj2+iyiBDSNh7aGCrkuAnqg7Qh7frhX+QhMGeJ9SpLpnG76qN85hLyjvYR6gR
# YiLTj8G4fxjqV400/buPw0rBo9yJZyq/8cGdCOLPOYf9qpefTcrZKeO9pg+UJHx8
# UABbaTqizRxm8sUSEycccCCFhIit3AI/3wGuSOADeiA676NcQ7+dsP04YvzvdN7p
# TZNyg672WpBDJdg0eItHl4yomvNeIOWh1qs4QqOW6TI8Ocsi4uSDTLorxLUDnBTw
# KQzzpxd1YUctEgRh32R0J9FkFkeEruJU94RljFr1uDCCBrkwggShoAMCAQICEQCZ
# o4AKJlU7ZavcboSms+o5MA0GCSqGSIb3DQEBDAUAMIGAMQswCQYDVQQGEwJQTDEi
# MCAGA1UEChMZVW5pemV0byBUZWNobm9sb2dpZXMgUy5BLjEnMCUGA1UECxMeQ2Vy
# dHVtIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MSQwIgYDVQQDExtDZXJ0dW0gVHJ1
# c3RlZCBOZXR3b3JrIENBIDIwHhcNMjEwNTE5MDUzMjE4WhcNMzYwNTE4MDUzMjE4
# WjBWMQswCQYDVQQGEwJQTDEhMB8GA1UEChMYQXNzZWNvIERhdGEgU3lzdGVtcyBT
# LkEuMSQwIgYDVQQDExtDZXJ0dW0gQ29kZSBTaWduaW5nIDIwMjEgQ0EwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCdI88EMCM7wUYs5zNzPmNdenW6vlxN
# ur3rLfi+5OZ+U3iZIB+AspO+CC/bj+taJUbMbFP1gQBJUzDUCPx7BNLgid1TyztV
# Ln52NKgxxu8gpyTr6EjWyGzKU/gnIu+bHAse1LCitX3CaOE13rbuHbtrxF2tPU8f
# 253QgX6eO8yTbGps1Mg+yda3DcTsOYOhSYNCJiL+5wnjZ9weoGRtvFgMHtJg6i67
# 1OPXIciiHO4Lwo2p9xh/tnj+JmCQEn5QU0NxzrOiRna4kjFaA9ZcwSaG7WAxeC/x
# oZSxF1oK1UPZtKVt+yrsGKqWONoK6f5EmBOAVEK2y4ATDSkb34UD7JA32f+Rm0ws
# r5ajzftDhA5mBipVZDjHpwzv8bTKzCDUSUuUmPo1govD0RwFcTtMXcfJtm1i+P2U
# NXadPyYVKRxKQATHN3imsfBiNRdN5kiVVeqP55piqgxOkyt+HkwIA4gbmSc3hD8k
# e66t9MjlcNg73rZZlrLHsAIV/nJ0mmgSjBI/TthoGJDydekOQ2tQD2Dup/+sKQpt
# alDlui59SerVSJg8gAeV7N/ia4mrGoiez+SqV3olVfxyLFt3o/OQOnBmjhKUANoK
# LYlKmUpKEFI0PfoT8Q1W/y6s9LTI6ekbi0igEbFUIBE8KDUGfIwnisEkBw5KcBZ3
# XwnHmfznwlKo8QIDAQABo4IBVTCCAVEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
# FgQU3XRdTADbe5+gdMqxbvc8wDLAcM0wHwYDVR0jBBgwFoAUtqFUOQLDoD+Oirz6
# 1PgcptE6Dv0wDgYDVR0PAQH/BAQDAgEGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMDAG
# A1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9jcmwuY2VydHVtLnBsL2N0bmNhMi5jcmww
# bAYIKwYBBQUHAQEEYDBeMCgGCCsGAQUFBzABhhxodHRwOi8vc3ViY2Eub2NzcC1j
# ZXJ0dW0uY29tMDIGCCsGAQUFBzAChiZodHRwOi8vcmVwb3NpdG9yeS5jZXJ0dW0u
# cGwvY3RuY2EyLmNlcjA5BgNVHSAEMjAwMC4GBFUdIAAwJjAkBggrBgEFBQcCARYY
# aHR0cDovL3d3dy5jZXJ0dW0ucGwvQ1BTMA0GCSqGSIb3DQEBDAUAA4ICAQB1iFgP
# 5Y9QKJpTnxDsQ/z0O23JmoZifZdEOEmQvo/79PQg9nLF/GJe6ZiUBEyDBHMtFRK0
# mXj3Qv3gL0sYXe+PPMfwmreJHvgFGWQ7XwnfMh2YIpBrkvJnjwh8gIlNlUl4KENT
# K5DLqsYPEtRQCw7R6p4s2EtWyDDr/M58iY2UBEqfUU/ujR9NuPyKk0bEcEi62JGx
# auFYzZ/yld13fHaZskIoq2XazjaD0pQkcQiIueL0HKiohS6XgZuUtCKA7S6CHttZ
# EsObQJ1j2s0urIDdqF7xaXFVaTHKtAuMfwi0jXtF3JJphrJfc+FFILgCbX/uYBPB
# lbBIP4Ht4xxk2GmfzMn7oxPITpigQFJFWuzTMUUgdRHTxaTSKRJ/6Uh7ki/pFjf9
# sUASWgxT69QF9Ki4JF5nBIujxZ2sOU9e1HSCJwOfK07t5nnzbs1LbHuAIGJsRJiQ
# 6HX/DW1XFOlXY1rc9HufFhWU+7Uk+hFkJsfzqBz3pRO+5aI6u5abI4Qws4YaeJH7
# H7M8X/YNoaArZbV4Ql+jarKsE0+8XvC4DJB+IVcvC9Ydqahi09mjQse4fxfef0L7
# E3hho2O3bLDM6v60rIRUCi2fJT2/IRU5ohgyTch4GuYWefSBsp5NPJh4QRTP9DC3
# gc5QEKtbrTY0Ka87Web7/zScvLmvQBm8JDFpDjCCBrkwggShoAMCAQICEQDn/2nH
# OzXOS5Em2HR8aKWHMA0GCSqGSIb3DQEBDAUAMIGAMQswCQYDVQQGEwJQTDEiMCAG
# A1UEChMZVW5pemV0byBUZWNobm9sb2dpZXMgUy5BLjEnMCUGA1UECxMeQ2VydHVt
# IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MSQwIgYDVQQDExtDZXJ0dW0gVHJ1c3Rl
# ZCBOZXR3b3JrIENBIDIwHhcNMjEwNTE5MDUzMjA3WhcNMzYwNTE4MDUzMjA3WjBW
# MQswCQYDVQQGEwJQTDEhMB8GA1UEChMYQXNzZWNvIERhdGEgU3lzdGVtcyBTLkEu
# MSQwIgYDVQQDExtDZXJ0dW0gVGltZXN0YW1waW5nIDIwMjEgQ0EwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQDpEh8ENe25XXrFppVBvoplf0530W0lddNm
# jtv4YSh/f7eDQKFaIqc7tHj7ox+u8vIsJZlroakUeMS3i3T8aJRC+eQs4FF0Gqvk
# M6+WZO8kmzZfxmZaBYmMLs8FktgFYCzywmXeQ1fEExflee2OpbHVk665eXRHjH7M
# YZIzNnjl2m8Hy8ulB9mR8wL/W0v0pjKNT6G0sfrx1kk+3OGosFUb7yWNnVkWKU4q
# SxLv16kJ6oVJ4BSbZ4xMak6JLeB8szrK9vwGDpvGDnKCUMYL3NuviwH1x4gZG0JA
# XU3x2pOAz91JWKJSAmRy/l0s0l5bEYKolg+DMqVhlOANd8Yh5mkQWaMEvBRE/kAG
# zIqgWhwzN2OsKIVtO8mf5sPWSrvyplSABAYa13rMYnzwfg08nljZHghquCJYCa/x
# HK9acev9UD7Y+usr15d7mrszzxhF1JOr1Mpup2chNSBlyOObhlSO16rwrffVrg/S
# zaKfSndS5swRhr8bnDqNJY9TNyEYvBYpgF95K7p0g4LguR4A++Z1nFIHWVY5v0fN
# VZmgzxD9uVo/gta3onGOQj3JCxgYx0KrCXu4yc9QiVwTFLWbNdHFSjBCt5/8Q9pL
# uRhVocdCunhcHudMS1CGQ/Rn0+7P+fzMgWdRKfEOh/hjLrnQ8BdJiYrZNxvIOhM2
# aa3zEDHNwwIDAQABo4IBVTCCAVEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU
# vlQCL79AbHNDzqwJJU6eQ0Qa7uAwHwYDVR0jBBgwFoAUtqFUOQLDoD+Oirz61Pgc
# ptE6Dv0wDgYDVR0PAQH/BAQDAgEGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMDAGA1Ud
# HwQpMCcwJaAjoCGGH2h0dHA6Ly9jcmwuY2VydHVtLnBsL2N0bmNhMi5jcmwwbAYI
# KwYBBQUHAQEEYDBeMCgGCCsGAQUFBzABhhxodHRwOi8vc3ViY2Eub2NzcC1jZXJ0
# dW0uY29tMDIGCCsGAQUFBzAChiZodHRwOi8vcmVwb3NpdG9yeS5jZXJ0dW0ucGwv
# Y3RuY2EyLmNlcjA5BgNVHSAEMjAwMC4GBFUdIAAwJjAkBggrBgEFBQcCARYYaHR0
# cDovL3d3dy5jZXJ0dW0ucGwvQ1BTMA0GCSqGSIb3DQEBDAUAA4ICAQC4k1l3yUwV
# /ZQHCKCneqAs8EGTnwEUJLdDpokN/dMhKjK0rR5qX8nIIHzxpQR3TAw2IRw1Uxsr
# 2PliG3bCFqSdQTUbfaTq6V3vBzEebDru9QFjqlKnxCF2h1jhLNFFplbPJiW+JSnJ
# Th1fKEqEdKdxgl9rVTvlxfEJ7exOn25MGbd/wGPwuSmMxRJVO0wnqgS7kmoJjNF9
# zqeehFSDDP8ZVkWg4EZ2tIS0M3uZmByRr+1Lkwjjt8AtW83mVnZTyTsOb+FNfwJY
# 7DS4FmWhkRbgcHRetreoTirPOr/ozyDKhT8MTSTf6Lttg6s6T/u08mDWw6HK04ZR
# DfQ9sb77QV8mKgO44WGP31vXnVKoWVJpFBjPvjL8/Zck/5wXX2iqjOaLStFOR/IQ
# ki+Ehn4zlcgVm22ZVCBPF+l8nAwUUShCtKuSU7GmZLKCmmxQMkSiWILTm8EtVD6A
# xnJhoq8EnhjEEyUoflkeRF2WhFiVQOmWTwZRr44IxWGkNJC6tTorW5rl2Zl+2e9J
# LPYf3pStAPMDoPKIjVXd6NW2+fZrNUBeDo2eOa5Fn7Brs/HLQff5Xgris5MeUbdV
# gDrF8uxO6cLPvZPo63j62SsNg55pTWk9fUIF9iPoRbb4QurjoY/woI1RAOKtYtTi
# c6aAJq3u83RIPpGXBSJKwx4KJAOZnCDCtTGCBqIwggaeAgEBMGowVjELMAkGA1UE
# BhMCUEwxITAfBgNVBAoTGEFzc2VjbyBEYXRhIFN5c3RlbXMgUy5BLjEkMCIGA1UE
# AxMbQ2VydHVtIENvZGUgU2lnbmluZyAyMDIxIENBAhBN2plxRehW7d8i84MUmE69
# MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJ
# KoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQB
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIBMQBbqEFQEuggbCCpIhnpX+NeIzKXeRXQ5p
# kLtV2ojxMA0GCSqGSIb3DQEBAQUABIIBgDO1SGvxBGpd2HUGIbdnNTgwBAezEpMC
# LlGhc39P8Joj84BYWGdL8faTh+8vKD/BgGusUP7aSfZat7X25MmJlj3RLdAscoT3
# z6RDJl4CsMy35msCvG6OQRoln2jQLAeI2jvDVgQVCBWplqQgzObKnq3Sp2kUcM8R
# um5WL6uZCBvgepMdndeWvqEAg2+bMdKBZQRhR2hbC9Jp/3/asNqGBbt1on+cY/pT
# 6db+cZMz2S4rwjXvr0Y6GlunhKHAppyhHbRjdIL3PK7OHT6yUSYCmWl/zG5rBhkw
# Mslp8lNWkRl57e+m07/qjmc/0BDYs8vNd82BA4eD/PrEQogdaY+EqWpY0szlsKTW
# TLN76HAH/s3K62HoppLn0rwWgmFw6y8laSBorDvnAw4cpwjVhKjmA7zK8j+mCoNs
# icBSHfYmaUk9aTuoGnE5F/xQ1/zlYe8nV67xvpqhp6L/3S2yT+ujauk7SylsR61a
# JDwrjSWJ6tYI2ZD0NE+Vhy+OhAPLb9J8OKGCBAIwggP+BgkqhkiG9w0BCQYxggPv
# MIID6wIBATBqMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0YSBT
# eXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBUaW1lc3RhbXBpbmcgMjAyMSBD
# QQIQKPB3wRw2vf5fdDJHcCcuAzANBglghkgBZQMEAgIFAKCCAVYwGgYJKoZIhvcN
# AQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNjExMjYyMzE4NDda
# MDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIEIIW+kOEK0kONfMkotq9IsJqyCBd87Piw
# EmxY05EFJcQ8MD8GCSqGSIb3DQEJBDEyBDAnAmvSorANSO5m3J+YVoQ5+E2HDErH
# iPgnCqGZGRU0HlgmTi3/JHRBD61iu4as7sQwgZ8GCyqGSIb3DQEJEAIMMYGPMIGM
# MIGJMIGGBBRXFGhBDKha80JO+RZKUTYQ9NONmDBuMFqkWDBWMQswCQYDVQQGEwJQ
# TDEhMB8GA1UEChMYQXNzZWNvIERhdGEgU3lzdGVtcyBTLkEuMSQwIgYDVQQDExtD
# ZXJ0dW0gVGltZXN0YW1waW5nIDIwMjEgQ0ECECjwd8EcNr3+X3QyR3AnLgMwDQYJ
# KoZIhvcNAQEBBQAEggIAnjiMYQztfSeCKKVUNOe8GR7F7+A0Ru+00oeqajTuGW4t
# TGZLpY6HPyg/aR2lf8joPQVdnCzbwhFWXvhM4slyDEpG1y+eAFz2/r1sEuVB4wuA
# O4DhSp6PMKEJ3eDqRjsAHLiWYfQbIU1WvveWE7T8xIJq+Q1JcIRxQuJrv6PYUtks
# wACsG6hqqVgSTatflg1x8ADOPEhYbCe/CnN0wRHSlVzbuNzhwbBARFExN2Vn3CRr
# bw4OjZVq2WGSjbllQhPjmmaKIZaOTX/YBIxam2p3F/Ew/3ogcoPotBdUvqcE40nf
# 8QJ4LWbChA/9xfoewiUTqxEUEOulwA7I5kotUgaD1VXASkQQYS2yLQTDwMgTLiNh
# 1vKe0PdiU1NJXUnOnkzINKRPl2o38LgIXUjVT6BizX7rjwXZf5BVWt/RqIEMoH5x
# w8VjqxxVA/5PdrxYw4xED1okpgPugGZMaJHPo1G6mAAhunzZtKS/yB7nI/ak08hR
# r1XiNSCCmeCX561ea/kxi4TWhW78pZj9q1V+NCZfRBq1H0RYR2iYG+yXqpRbq+Qa
# m+EYkKI7ZsSsqDea2vKhNBLitnpzx4SpEsh3RXCSRCdpxEsz7N7nAGyX98h8SukK
# QlczlvWpjWb8eL2OladsnPn/e+n220wsAXUHDvsmP4q5BS6QS9Fl/ZrbCU5qvpw=
# SIG # End signature block
