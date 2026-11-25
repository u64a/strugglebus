<#
.SYNOPSIS
  The host's leaf certificate for OpenBao (docs/openbao-design.md section 2.5): an EC P-256 key and a CSR made
  on this machine, the leaf issued by step-ca with a one-time token from the site's token minter, then checked.
  Idempotent: with a valid leaf for the right name, a second run changes nothing.

.DESCRIPTION
  Run it AS THE HOST'S USER (the account the scheduled task runs as), not elevated: the leaf folder is owner-only
  to whoever runs this, and the host must be able to read it. Run it after install.ps1 (it calls the installed wh)
  and before `wh openbao seed-spn` / `wh enrol`.

  1. <home>\leaf, owner-only (inheritance removed, this user only).
  2. leaf.key (PKCS#8 PEM) and leaf.csr for <agent_prefix>.<san_domain>, made here; the key never leaves this machine.
  3. `wh openbao enrol`: asks for the one-time token at a hidden prompt and sends it to step-ca in the request
     body over the pinned LAN root. The token is never on a command line (the step CLI only takes it as a flag,
     which is why this does not use the step CLI). The leaf lasts 72 h; the host renews it hourly over mTLS, so
     the token is needed only again after a rebuild or a leaf left to expire (host off for 3 days).
  4. Prints the folder's ACL (icacls), so who can read the key is shown, not assumed.
  5. `wh openbao status`: login, own-prefix write/read/destroy, what is stored.

  Needs PowerShell 7 (.NET's PKCS#8 export).

.PARAMETER San
  The leaf's name. Default: <agent_prefix>.<san_domain> from config.toml ([openbao] san_domain), e.g.
  host-box1.home.lan.

.PARAMETER HostHome
  The host home folder. Default %LOCALAPPDATA%\strugglebus-worker-host.

.PARAMETER Force
  Make a new key and leaf even if a valid one is there.

.PARAMETER WhatIf
  Print what would change, change nothing.

.PARAMETER Check
  Change nothing; exit 0 if a valid leaf for the right name is in place with an owner-only folder, 1 if not.
#>
[CmdletBinding()]
param(
    [string]$San,
    [string]$HostHome = (Join-Path $env:LOCALAPPDATA 'strugglebus-worker-host'),
    [switch]$Force,
    [switch]$WhatIf,
    [switch]$Check
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-Pem([string]$label, [byte[]]$der) {
    # Pure: DER bytes as PEM with 64-character lines.
    $b64 = [Convert]::ToBase64String($der)
    $lines = for ($i = 0; $i -lt $b64.Length; $i += 64) { $b64.Substring($i, [Math]::Min(64, $b64.Length - $i)) }
    return "-----BEGIN $label-----`n" + ($lines -join "`n") + "`n-----END $label-----`n"
}

function New-LeafRequest([string]$san) {
    # An EC P-256 key and a CSR whose CN and only DNS SAN are $san (the step-ca template: CN = the only SAN).
    $ec = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=$san", $ec, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $sans = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $sans.AddDnsName($san)
    $req.CertificateExtensions.Add($sans.Build($false))
    $csr = ConvertTo-Pem 'CERTIFICATE REQUEST' $req.CreateSigningRequest()
    $key = ConvertTo-Pem 'PRIVATE KEY' $ec.ExportPkcs8PrivateKey()
    return [pscustomobject]@{ Key = $key; Csr = $csr; Ec = $ec; Request = $req }
}

function Test-SanName([string]$san) {
    # Pure: a lowercase DNS name of two labels or more (the host's own name, then its LAN domain).
    return $san -cmatch '^[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9][a-z0-9-]{0,62})+$'
}

function Get-DefaultSan([string]$configText) {
    # Pure: <agent_prefix>.<san_domain> from config.toml's text, or $null if either is missing.
    if ($configText -notmatch '(?m)^\s*agent_prefix\s*=\s*"([a-z0-9-]+)"') { return $null }
    $prefix = $Matches[1]
    if ($configText -notmatch '(?ms)^\[openbao\][^\[]*?^\s*san_domain\s*=\s*"([a-z0-9.-]+)"') { return $null }
    return "$prefix.$($Matches[1])"
}

function Get-LeafPlan($s, [string]$san, [bool]$force) {
    # Pure: a snapshot of the leaf folder -> the changes still to make, in order.
    $plan = New-Object System.Collections.Generic.List[object]
    function Add([string]$id, [string]$text) { $plan.Add([pscustomobject]@{ Id = $id; Text = $text }) }
    if (-not $s.FolderOwnerOnly) { Add 'folder' "make $($s.Folder) owner-only (this user only)" }
    $valid = $s.LeafSans -contains $san -and $s.HoursLeft -gt 2
    if ($force -or -not $valid) {
        Add 'key' "make a new EC P-256 key and a CSR for $san"
        Add 'enrol' "issue the leaf: wh openbao enrol (asks for the one-time token, hidden)"
    }
    return $plan.ToArray()
}

if ($MyInvocation.InvocationName -eq '.') { return }

function Say([string]$text) { Write-Host "[openbao] $text" }

if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Run this with PowerShell 7 (pwsh): it needs .NET PKCS#8 export.' }
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -and -not $Check -and -not $WhatIf) {
    Say 'warning: this window is elevated. Run it as the host user, not elevated, unless that is the same account.'
}

# By SID: in an SSH session a local account's USERDOMAIN is WORKGROUP, which icacls cannot map.
$Me = [Security.Principal.WindowsIdentity]::GetCurrent()
$Wh = Join-Path $HostHome 'app\wh.cmd'
if (-not (Test-Path $Wh)) { throw "no installed host at ${Wh}: run install.ps1 first" }
$Leaf = Join-Path $HostHome 'leaf'
if (-not $San) {
    $San = Get-DefaultSan (Get-Content (Join-Path $HostHome 'config.toml') -Raw)
    if (-not $San) { throw 'config.toml has no agent_prefix or no [openbao] san_domain: set it, or pass -San <name>.<domain>' }
}
if (-not (Test-SanName $San)) { throw "-San must be a lowercase DNS name, <name>.<domain>, got '$San'" }

function Get-LeafState {
    $ownerOnly = $false
    if (Test-Path $Leaf) {
        $acl = Get-Acl $Leaf
        $rules = @($acl.Access)
        $ownerOnly = $acl.AreAccessRulesProtected -and $rules.Count -ge 1 -and
            -not ($rules | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -ne $Me.User.Value })
    }
    $sans = @(); $hours = 0
    $crt = Join-Path $Leaf 'leaf.crt'
    if (Test-Path $crt) {
        try {
            $c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($crt)
            $hours = ($c.NotAfter.ToUniversalTime() - [DateTime]::UtcNow).TotalHours
            $ext = $c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
            if ($ext) {
                $sans = @([System.Security.Cryptography.X509Certificates.X509SubjectAlternativeNameExtension]::new(
                    @($ext)[0].RawData).EnumerateDnsNames())
            }
        } catch { $sans = @(); $hours = 0 }
    }
    return [pscustomobject]@{ Folder = $Leaf; FolderOwnerOnly = $ownerOnly; LeafSans = $sans; HoursLeft = $hours }
}

$state = Get-LeafState
$plan = @(Get-LeafPlan $state $San ([bool]$Force))
if ($Check) { exit $(if ($plan.Count) { 1 } else { 0 }) }
if (-not $plan.Count) {
    Say "nothing to do: leaf $San valid for $([int]$state.HoursLeft) h, folder owner-only"
} else {
    $plan | ForEach-Object { Say "$(if ($WhatIf) { 'would ' })$($_.Text)" }
    if ($WhatIf) { exit 0 }
    foreach ($step in $plan) {
        switch ($step.Id) {
            'folder' {
                New-Item -ItemType Directory -Force -Path $Leaf | Out-Null
                & icacls $Leaf /inheritance:r /grant:r "*$($Me.User.Value):(OI)(CI)F" | Out-Null
                if ($LASTEXITCODE) { throw "icacls failed on $Leaf" }
            }
            'key' {
                $r = New-LeafRequest $San
                $keyPath = Join-Path $Leaf 'leaf.key'
                [IO.File]::WriteAllText($keyPath, $r.Key, [Text.Encoding]::ASCII)
                & icacls $keyPath /inheritance:r /grant:r "*$($Me.User.Value):F" | Out-Null
                if ($LASTEXITCODE) { throw "icacls failed on $keyPath" }
                [IO.File]::WriteAllText((Join-Path $Leaf 'leaf.csr'), $r.Csr, [Text.Encoding]::ASCII)
                Remove-Item (Join-Path $Leaf 'leaf.crt') -ErrorAction SilentlyContinue
                $r.Ec.Dispose()
            }
            'enrol' {
                & $Wh openbao enrol
                if ($LASTEXITCODE) { throw 'wh openbao enrol failed (nothing secret was printed); a new token is needed' }
            }
        }
    }
}

Say 'who can read the leaf folder (icacls):'
& icacls $Leaf | Where-Object { $_ -and $_ -notmatch 'Successfully processed' } | ForEach-Object { Say "  $_" }
Say 'checking OpenBao (login, own-prefix write/read/destroy):'
& $Wh openbao status
exit $LASTEXITCODE
