<#
.SYNOPSIS
  Authenticode-sign the worker host's bootstrap.ps1 for a release, or check a signed copy, against that release.

.DESCRIPTION
  The repository keeps bootstrap.ps1 UNSIGNED. Its SHA-256 is release.toml's bootstrap_sha256, signed by the project
  release key (YubiKey). Signing appends one Authenticode signature block and changes nothing before it, so a signed
  copy is "the released bytes + one block" and can be checked exactly (docs/app-host-integration.md 2.1).

  -Sign (on the owner's PC, with the code-signing certificate available, e.g. through SimplySign):
    1. verifies release.toml's signature with the pinned release signers, namespace strugglebus-release;
    2. REFUSES unless bootstrap.ps1's SHA-256 equals that release's bootstrap_sha256, so only what the release key
       already approved is ever signed (a doctored file handed over for signing is refused);
    3. signs a COPY (-Out; the repository file is never touched) with the certificate whose thumbprint is in the
       release's authenticode_thumbprints, with an RFC 3161 timestamp;
    4. runs the check below on the copy.

  Without -Sign: checks a signed copy (-Out) and lists every problem. It passes only if:
    - the bytes before the signature block hash to bootstrap_sha256 from the verified release.toml;
    - exactly one signature block follows, and nothing after it;
    - Get-AuthenticodeSignature says Valid;
    - the signer's thumbprint is one of the release's authenticode_thumbprints (a name can be shared, a thumbprint
      cannot);
    - the signature carries a timestamp, so it stays checkable after the certificate expires.

.EXAMPLE
  pwsh -File tools\sign-bootstrap.ps1 -Release release.toml -Bootstrap tools\bootstrap.ps1 -Out C:\out\bootstrap.ps1 -Sign
.EXAMPLE
  pwsh -File tools\sign-bootstrap.ps1 -Release release.toml -Out C:\out\bootstrap.ps1
#>
[CmdletBinding()]
param(
    [string]$Release = '',
    [string]$ReleaseSig = '',
    [string]$Signers = 'C:\ProgramData\strugglebus\allowed_signers',
    [string]$Bootstrap = '',
    [string]$Out = '',
    [switch]$Sign,
    [string]$TimestampServer = 'http://time.certum.pl'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The project release keys (the owner's YubiKeys A, B and C), by SSH key fingerprint. release.toml must verify with
# one of THESE, whatever the -Signers file says: that file comes from a repository an agent could push to, and an
# added key there must never get a doctored bootstrap.ps1 signed. Changing this list needs a reviewed pull request
# (CODEOWNERS: /worker-host/). Cross-checked against the hosts' administrator-only pin on 27 Nov 2026.
$ReleaseKeyFingerprints = @(
    'SHA256:xh5bC1DWKRzjLykESi8D5Qha6izhRNwkMJUyVMC2q2A',
    'SHA256:I621GOi+pKy3XIbahS6mmqKCn7pVnQaubqPigdMTzus',
    'SHA256:3bgt5AEYlZ4vvVtI9aVzPOTqBgwqyf0IYLEmNta9FpM'
)
$BlockStart = "`r`n# SIG # Begin signature block`r`n"
$BlockEnd = "# SIG # End signature block`r`n"
$NamespaceRelease = 'strugglebus-release'

function Get-Sha256Hex([byte[]]$bytes) {
    return -join ([Security.Cryptography.SHA256]::Create().ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
}

function Get-ReleaseFacts([string]$text) {
    # Pure: bootstrap_sha256 and authenticode_thumbprints from release.toml's text (as make-release writes them).
    $sha = [regex]::Match($text, '(?m)^bootstrap_sha256 = "([0-9a-f]{64})"\r?$')
    $list = [regex]::Match($text, '(?m)^authenticode_thumbprints = \[([^\]\r\n]*)\]\r?$')
    $thumbs = @()
    if ($list.Success) {
        $thumbs = @([regex]::Matches($list.Groups[1].Value, '"([0-9A-F]{40})"') | ForEach-Object { $_.Groups[1].Value })
    }
    return @{ bootstrap_sha256 = $(if ($sha.Success) { $sha.Groups[1].Value } else { '' }); thumbprints = $thumbs }
}

function Split-SignedScript([byte[]]$bytes) {
    # Pure: @{ Content; Block } for "content + exactly one signature block, nothing after it", else a throw naming why.
    $text = [Text.Encoding]::ASCII.GetString($bytes)
    if (@($bytes | Where-Object { $_ -gt 127 }).Count) { throw 'not ASCII' }
    $at = $text.IndexOf($BlockStart)
    if ($at -lt 0) { throw 'no signature block' }
    if ($text.IndexOf($BlockStart, $at + 1) -ge 0) { throw 'more than one signature block' }
    $block = $text.Substring($at)
    if (-not $block.EndsWith($BlockEnd)) { throw 'something follows the signature block' }
    $lines = $block.Substring(2, $block.Length - 4) -split "`r`n"
    foreach ($l in $lines[1..($lines.Count - 2)]) {
        if ($l -cnotmatch '^# [A-Za-z0-9+/=]+$') { throw 'the signature block holds a line that is not signature data' }
    }
    return @{ Content = [byte[]]$bytes[0..($at - 1)]; Block = $block }
}

function Test-UnsignedBootstrap([byte[]]$bytes, $facts) {
    # Pure: the problems with signing these bytes for this release (empty = sign).
    $bad = [Collections.Generic.List[string]]::new()
    if (-not $facts.bootstrap_sha256) { $bad.Add('the release names no bootstrap_sha256') }
    elseif ((Get-Sha256Hex $bytes) -ne $facts.bootstrap_sha256) { $bad.Add('bootstrap.ps1 is not the file this release approved (SHA-256 differs)') }
    if ([Text.Encoding]::ASCII.GetString($bytes).Contains('# SIG # Begin signature block')) { $bad.Add('bootstrap.ps1 is already signed') }
    if (-not $facts.thumbprints) { $bad.Add('the release names no authenticode_thumbprints') }
    return , $bad.ToArray()
}

function Test-SignedBootstrap([byte[]]$bytes, $facts, $signature) {
    # Pure (the signature is Get-AuthenticodeSignature's result, passed in): every problem with this signed copy.
    $bad = [Collections.Generic.List[string]]::new()
    try {
        $parts = Split-SignedScript $bytes
        if ((Get-Sha256Hex $parts.Content) -ne $facts.bootstrap_sha256) { $bad.Add('the bytes before the signature are not the released bootstrap.ps1') }
    } catch { $bad.Add("shape: $($_.Exception.Message)") }
    if ($null -eq $signature -or "$($signature.Status)" -ne 'Valid') { $bad.Add("signature status: $(if ($signature) { $signature.Status } else { 'none' })") }
    $thumb = if ($signature -and $signature.SignerCertificate) { "$($signature.SignerCertificate.Thumbprint)".ToUpperInvariant() } else { '' }
    if (-not $thumb -or $thumb -notin $facts.thumbprints) { $bad.Add("signer thumbprint $thumb is not one the release names") }
    if ($null -eq $signature -or $null -eq $signature.TimeStamperCertificate) { $bad.Add('no timestamp') }
    return , $bad.ToArray()
}

function Get-SignerPrincipals([string]$signersText) {
    # Pure: the plain principals in an allowed_signers file, in order, each once (as sign-config.ps1).
    $out = [Collections.Generic.List[string]]::new()
    foreach ($line in ($signersText -split "`r?`n")) {
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        foreach ($p in (($t -split '\s+')[0] -split ',')) {
            if ($p -cmatch '^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$' -and -not $out.Contains($p)) { $out.Add($p) }
        }
    }
    return , $out.ToArray()
}

function Invoke-Native([string]$exe, [string[]]$arguments, [byte[]]$stdin = $null) {
    # Exact bytes in: PowerShell's own pipes re-encode text and would change the signed bytes.
    $psi = [Diagnostics.ProcessStartInfo]::new($exe)
    foreach ($a in $arguments) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $null -ne $stdin
    $p = [Diagnostics.Process]::Start($psi)
    $err = $p.StandardError.ReadToEndAsync()
    $out = $p.StandardOutput.ReadToEndAsync()
    if ($null -ne $stdin) { $p.StandardInput.BaseStream.Write($stdin, 0, $stdin.Length); $p.StandardInput.Close() }
    $p.WaitForExit()
    return [pscustomobject]@{ Code = $p.ExitCode; Out = $out.Result; Err = $err.Result }
}

function Test-ReleaseSignature([string]$keygen, [string]$signers, [byte[]]$data, [string]$sigPath,
                               [string[]]$pinned = $ReleaseKeyFingerprints) {
    # The fingerprint of the key that made a good release signature, if that key is one of the PINNED release keys;
    # '' otherwise (no good signature, or a good one by a key the -Signers file has but this script does not pin).
    foreach ($principal in (Get-SignerPrincipals ([IO.File]::ReadAllText($signers)))) {
        $r = Invoke-Native $keygen @('-Y', 'verify', '-f', $signers, '-I', $principal, '-n', $NamespaceRelease, '-s', $sigPath) $data
        $line = $r.Out.Trim()
        if ($r.Code -eq 0 -and $line.StartsWith("Good `"$NamespaceRelease`" signature for $principal ")) {
            $fp = [regex]::Match($line, '(SHA256:[A-Za-z0-9+/]{43})').Groups[1].Value
            if ($fp -and $fp -cin $pinned) { return $fp }
        }
    }
    return ''
}

function Find-SshKeygen {
    foreach ($c in @('C:\Program Files\OpenSSH\ssh-keygen.exe', (Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'))) {
        if (Test-Path $c) { return $c }
    }
    $found = Get-Command ssh-keygen -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }
    throw 'ssh-keygen not found (Win32-OpenSSH)'
}

if ($MyInvocation.InvocationName -eq '.') { return }

function Say([string]$text) { Write-Host "[sign-bootstrap] $text" }

if (-not $Release -or -not $Out) { throw 'give -Release <release.toml> and -Out <signed copy>' }
if (-not $ReleaseSig) { $ReleaseSig = "$Release.sig" }
$releaseBytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Release).Path)
$releaseKey = Test-ReleaseSignature (Find-SshKeygen) $Signers $releaseBytes (Resolve-Path -LiteralPath $ReleaseSig).Path
if (-not $releaseKey) {
    throw "release.toml is not signed by one of the pinned project release keys ($NamespaceRelease): nothing is signed or passed"
}
$facts = Get-ReleaseFacts ([Text.Encoding]::UTF8.GetString($releaseBytes))
Say "release verified by $releaseKey; bootstrap_sha256 $($facts.bootstrap_sha256); thumbprints $($facts.thumbprints -join ', ')"

if ($Sign) {
    if (-not $Bootstrap) { throw 'give -Bootstrap <the unsigned bootstrap.ps1>' }
    $plain = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Bootstrap).Path)
    $bad = Test-UnsignedBootstrap $plain $facts
    if ($bad.Count) { throw "refusing to sign: $($bad -join '; ')" }
    $cert = @(Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Thumbprint -in $facts.thumbprints })
    if ($cert.Count -ne 1) { throw "need exactly one code-signing certificate named by the release in CurrentUser\My; found $($cert.Count)" }
    [IO.File]::WriteAllBytes($Out, $plain)
    $r = Set-AuthenticodeSignature -LiteralPath $Out -Certificate $cert[0] -HashAlgorithm SHA256 -TimestampServer $TimestampServer
    Say "signed: $($r.Status)"
}

$signed = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Out).Path)
$bad = Test-SignedBootstrap $signed $facts (Get-AuthenticodeSignature -LiteralPath $Out)
if ($bad.Count) { throw "the signed bootstrap is not acceptable: $($bad -join '; ')" }
Say "OK: $Out is bootstrap.ps1 as approved by release key $releaseKey + one timestamped signature by certificate $(((Get-AuthenticodeSignature -LiteralPath $Out).SignerCertificate).Thumbprint)"
