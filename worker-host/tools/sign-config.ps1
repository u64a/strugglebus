<#
.SYNOPSIS
  Signs a fleet.toml / baseline.toml / release.toml change with your YubiKey and merges it (docs/signing-keys.md
  section 6; releases: docs/design.md section 10a).

.DESCRIPTION
  Run on a signing PC (signing-keys.md section 5), from a clone of this repository, in PowerShell 7.

  -Pr <n>, step by step:
    1. Refuses a PR that changes anything but fleet.toml, baseline.toml, release.toml and their .sig files.
    2. Shows each changed file's diff against main and checks its serial is exactly main's + 1.
    3. Asks "sign?": read the change, this is the moment that counts.
    4. Signs the file's exact bytes as git stores them in the PR (never a working copy) with
       ssh-keygen -Y sign. The YubiKey asks for its PIN and blinks: touch it.
    5. Verifies the signature against keys/allowed_signers from main, as a host would.
    6. Commits the .sig to the PR branch and pushes it (a push fails if the branch moved meanwhile).
    7. Waits for the checks, then squash-merges.
    8. Fetches main and verifies the merged file and signature once more, then prints the commit.
       Hosts pick up fleet.toml within fleet_refresh_minutes (15); `wh fleet status --refresh` on a
       host does it at once.
    9. For a release.toml: creates the GitHub Release v<version> at the released commit (for people to
       read; hosts read the signed release.toml, never the release page). Hosts announce it at their next
       check_at (01:00) and apply it in their window (03:00); `wh update now` on a host applies it sooner.

  In a shared repository (u64a/strugglebus) the host's signed files sit in its folder: give -Path worker-host.
  Then the files are <folder>/release.toml and so on, no GitHub Release page is made (that repository's releases
  belong to other products, and the App's updater reads them), and the check is against -Signers, since that
  repository carries no signer list. The first release at a new place starts at -FirstSerial: the old place's
  serial + 1, as make-release.py --continue-from prints.

  -Test: signs a throwaway text and verifies it, to check this PC can sign (after a rebuild).

  Nothing secret passes through this script: the private key never leaves the YubiKey, and the PIN
  goes from you to ssh-keygen directly.

.PARAMETER Pr
  The pull request number.
.PARAMETER Test
  Only check that this PC can sign.
.PARAMETER KeyFile
  The key handle file read back off the YubiKey (signing-keys.md 5.2). Default: ~\.ssh\id_ed25519_sk_strugglebus,
  else the one id_ed25519_sk_rk_strugglebus-signing_* file in ~\.ssh.
.PARAMETER NoMerge
  Sign and push the signature, but leave the merge to you.
.PARAMETER Path
  The host's folder in a shared repository (e.g. worker-host). Default: the repository's top level.
.PARAMETER FirstSerial
  Only when the PR adds a signed file that main does not have yet: the serial it must start at (default 1).
.PARAMETER Signers
  The allowed_signers file to check the new signature against. Default: keys/allowed_signers on main (under -Path).

.EXAMPLE
  pwsh -File tools\sign-config.ps1 -Pr 31
.EXAMPLE
  pwsh -File worker-host\tools\sign-config.ps1 -Pr 21 -Path worker-host -FirstSerial 8 -Signers <file> -KeyFile <file>
.EXAMPLE
  pwsh -File tools\sign-config.ps1 -Test
#>
[CmdletBinding()]
param(
    [int]$Pr = 0,
    [switch]$Test,
    [string]$KeyFile = '',
    [switch]$NoMerge,
    [string]$Path = '',
    [int]$FirstSerial = 0,
    [string]$Signers = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Signed = [ordered]@{ 'fleet.toml' = 'strugglebus-fleet'; 'baseline.toml' = 'strugglebus-baseline'; 'release.toml' = 'strugglebus-release' }

function Say([string]$text) { Write-Host "[sign] $text" }

function Get-Prefix([string]$folder) {
    # Pure: "worker-host/" for -Path worker-host (either slash, no leading or trailing one), "" for the top level.
    $f = $folder.Replace('\', '/').Trim('/')
    if (-not $f) { return '' }
    if ($f -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$' -or $f -match '(^|/)\.\.?(/|$)') {
        throw "-Path $folder is not a plain folder name"
    }
    return "$f/"
}

function Test-PrFiles([string[]]$files, [string]$prefix = '') {
    # Only the signed files and their signatures may change in a signing PR: code never rides in on a config signature.
    $allowed = @('fleet.toml', 'fleet.toml.sig', 'baseline.toml', 'baseline.toml.sig', 'release.toml', 'release.toml.sig') |
        ForEach-Object { "$prefix$_" }
    return @($files | Where-Object { $allowed -notcontains $_ })
}

function Get-Serial([string]$text) {
    # The top-level `serial = <n>` (before the first [table]); $null if there is none.
    $head = ($text -split '(?m)^\s*\[', 2)[0]
    $m = [regex]::Match($head, '(?m)^\s*serial\s*=\s*(\d+)\s*(#.*)?$')
    if ($m.Success) { return [int]$m.Groups[1].Value }
    return $null
}

function Test-SerialStep($mainSerial, $prSerial, [int]$first = 0) {
    # A new file starts at 1, or at -FirstSerial when it continues another place's numbering; every change after that
    # is exactly one more than main (signing-keys.md 8). -FirstSerial never applies to a file main already has.
    if ($null -eq $prSerial) { return $false }
    if ($null -eq $mainSerial) { return $prSerial -eq $(if ($first -gt 0) { $first } else { 1 }) }
    return $prSerial -eq ($mainSerial + 1)
}

function Find-SshKeygen {
    $candidates = @('C:\Program Files\OpenSSH\ssh-keygen.exe', (Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'))
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    throw 'ssh-keygen not found: install Win32-OpenSSH (signing-keys.md 4.1). Git''s ssh-keygen cannot use the YubiKey.'
}

# Dot-sourced (the tests do this): define the functions above and stop here.
function Get-SignerPrincipals([string]$signersText) {
    # Pure: the principals named in an allowed_signers file (first field, comma-separated), in order, each once.
    # Wildcard patterns are skipped: the hosts (workerhost/signing.py) try only plain names.
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($line in ($signersText -split "`r?`n")) {
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        foreach ($p in (($t -split '\s+')[0] -split ',')) {
            if ($p -cmatch '^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$' -and -not $out.Contains($p)) { $out.Add($p) }
        }
    }
    return , $out.ToArray()
}

if ($MyInvocation.InvocationName -eq '.') { return }
if ($Test -eq ($Pr -gt 0)) { throw 'give either -Pr <number> or -Test' }
$prefix = Get-Prefix $Path
if ($Signers -and -not (Test-Path -LiteralPath $Signers -PathType Leaf)) { throw "no signers file $Signers" }

function Invoke-Native([string]$exe, [string[]]$arguments, [byte[]]$stdin = $null, [string]$cwd = (Get-Location).Path) {
    # Runs a program with exact bytes in and out. PowerShell's own pipes and > re-encode text, which
    # would change the signed bytes (signing-keys.md 6.1).
    $psi = [Diagnostics.ProcessStartInfo]::new($exe)
    foreach ($a in $arguments) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $null -ne $stdin
    $psi.WorkingDirectory = $cwd
    $p = [Diagnostics.Process]::Start($psi)
    $err = $p.StandardError.ReadToEndAsync()
    $out = [IO.MemoryStream]::new()
    $copy = $p.StandardOutput.BaseStream.CopyToAsync($out)
    if ($null -ne $stdin) {
        $p.StandardInput.BaseStream.Write($stdin, 0, $stdin.Length)
        $p.StandardInput.Close()
    }
    $copy.Wait()
    $p.WaitForExit()
    return [pscustomobject]@{ Code = $p.ExitCode; Out = $out.ToArray(); Err = $err.Result }
}

function Invoke-Git([string[]]$arguments, [switch]$Bytes) {
    $r = Invoke-Native 'git' $arguments
    if ($r.Code -ne 0) { throw "git $($arguments -join ' ') failed: $($r.Err.Trim())" }
    if ($Bytes) { return , $r.Out }
    return [Text.Encoding]::UTF8.GetString($r.Out).Trim()
}

function Get-Blob([string]$ref, [string]$name) {
    $r = Invoke-Native 'git' @('cat-file', 'blob', "${ref}:$name")
    if ($r.Code -ne 0) { return $null }
    return , $r.Out
}

function Resolve-KeyFile {
    if ($KeyFile) { if (Test-Path $KeyFile) { return (Resolve-Path $KeyFile).Path }; throw "no key file $KeyFile" }
    $ssh = Join-Path $HOME '.ssh'
    $short = Join-Path $ssh 'id_ed25519_sk_strugglebus'
    if (Test-Path $short) { return $short }
    $found = @(Get-ChildItem $ssh -Filter 'id_ed25519_sk_rk_strugglebus-signing_*' -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -ne '.pub' })
    if ($found.Count -eq 1) { return $found[0].FullName }
    throw "no key handle in $ssh (read it back off the YubiKey: signing-keys.md 5.2), or pass -KeyFile"
}

function Invoke-Sign([string]$keygen, [string]$key, [string]$namespace, [byte[]]$data, [string]$work) {
    $file = Join-Path $work ([guid]::NewGuid().ToString('n'))
    [IO.File]::WriteAllBytes($file, $data)
    Say "signing ($namespace): enter the YubiKey PIN when asked, then touch the key when it blinks"
    # Interactive on purpose: ssh-keygen talks to you for the PIN, not to this script.
    & $keygen -Y sign -f $key -n $namespace $file
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path "$file.sig")) { throw 'ssh-keygen -Y sign failed (wrong PIN, no touch, or the wrong key handle)' }
    return , [IO.File]::ReadAllBytes("$file.sig")
}

function Test-Signature([string]$keygen, [string]$signers, [string]$namespace, [byte[]]$data, [byte[]]$sig, [string]$work) {
    # As the hosts check it: good for one of the principals in the pinned list.
    $sigFile = Join-Path $work ([guid]::NewGuid().ToString('n') + '.sig')
    [IO.File]::WriteAllBytes($sigFile, $sig)
    $text = ''
    foreach ($principal in (Get-SignerPrincipals (Get-Content $signers -Raw))) {
        $r = Invoke-Native $keygen @('-Y', 'verify', '-f', $signers, '-I', $principal, '-n', $namespace, '-s', $sigFile) $data
        $text = [Text.Encoding]::UTF8.GetString($r.Out).Trim()
        if ($r.Code -eq 0 -and $text.StartsWith("Good `"$namespace`" signature for $principal ")) { return $text }
    }
    throw "the signature does not verify against $signers ($namespace): $text"
}

$keygen = Find-SshKeygen
$key = Resolve-KeyFile
$work = Join-Path ([IO.Path]::GetTempPath()) ("sign-config-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $work | Out-Null
$root = Invoke-Git @('rev-parse', '--show-toplevel')
Set-Location $root

try {
    if ($Test) {
        $signers = if ($Signers) { (Resolve-Path -LiteralPath $Signers).Path } else { Join-Path $root "${prefix}keys\allowed_signers" }
        $data = [Text.Encoding]::UTF8.GetBytes("strugglebus sign-config test $(Get-Date -Format o) on $env:COMPUTERNAME`n")
        $sig = Invoke-Sign $keygen $key 'strugglebus-fleet' $data $work
        Say (Test-Signature $keygen $signers 'strugglebus-fleet' $data $sig $work)
        Say 'this PC can sign. Compare the SHA256 above with signing-keys.md 2.1 to see which YubiKey it was.'
        return
    }

    $info = gh pr view $Pr --json files,headRefName,headRepositoryOwner,state,isCrossRepository,title | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw "gh pr view $Pr failed" }
    if ($info.state -ne 'OPEN') { throw "PR #$Pr is $($info.state)" }
    if ($info.isCrossRepository) { throw "PR #$Pr comes from a fork: refused" }
    $files = @($info.files | ForEach-Object { $_.path })
    $extra = @(Test-PrFiles $files $prefix)  # @(): an empty result must stay an empty list under StrictMode
    if ($extra.Count) { throw "PR #$Pr changes more than the signed files: $($extra -join ', '). Refused: code never rides in on a config signature." }
    $toSign = @($Signed.Keys | ForEach-Object { "$prefix$_" } | Where-Object { $files -contains $_ })
    if (-not $toSign.Count) { throw "PR #$Pr changes none of ${prefix}fleet.toml, ${prefix}baseline.toml, ${prefix}release.toml" }

    $branch = $info.headRefName
    Invoke-Git @('fetch', '-q', 'origin', "+refs/heads/main:refs/remotes/origin/main", "+refs/pull/$Pr/head:refs/remotes/origin/pr/$Pr") | Out-Null
    $head = Invoke-Git @('rev-parse', "refs/remotes/origin/pr/$Pr")
    $signers = Join-Path $work 'allowed_signers'
    if ($Signers) {
        Copy-Item -LiteralPath $Signers -Destination $signers
    } else {
        $listed = Get-Blob 'refs/remotes/origin/main' "${prefix}keys/allowed_signers"
        if ($null -eq $listed) { throw "main has no ${prefix}keys/allowed_signers: give -Signers <your allowed_signers file>" }
        [IO.File]::WriteAllBytes($signers, $listed)
    }
    Say "PR #$Pr '$($info.title)' at $($head.Substring(0, 12)) (branch $branch)"

    $plan = @()
    foreach ($name in $toSign) {
        $data = Get-Blob $head $name
        if ($null -eq $data) { throw "$name is deleted in PR #${Pr}: deleting a signed file is not done through this script" }
        $mainData = Get-Blob 'refs/remotes/origin/main' $name
        $mainSerial = if ($null -ne $mainData) { Get-Serial ([Text.Encoding]::UTF8.GetString($mainData)) } else { $null }
        $prSerial = Get-Serial ([Text.Encoding]::UTF8.GetString($data))
        if (-not (Test-SerialStep $mainSerial $prSerial $FirstSerial)) {
            $start = if ($FirstSerial -gt 0) { $FirstSerial } else { 1 }
            throw "$name serial is $prSerial; main has $(if ($null -eq $mainSerial) { "no file (so it must be $start)" } else { "$mainSerial. It must be exactly one more" })."
        }
        Write-Host ''
        Write-Host "=== ${name}: serial $(if ($null -eq $mainSerial) { "(new here, starting at $prSerial)" } else { $mainSerial }) -> $prSerial ==="
        git --no-pager diff --no-color refs/remotes/origin/main $head -- ":(top)$name" | Out-Host
        $plan += [pscustomobject]@{ Name = $name; Namespace = $Signed[$name.Substring($prefix.Length)]; Data = $data; Serial = $prSerial }
    }
    Write-Host ''
    if ((Read-Host "Sign $($plan.Name -join ' and ')? Type yes") -cne 'yes') { Say 'not signed: nothing changed'; return }

    $tree = Join-Path $work 'tree'
    Invoke-Git @('worktree', 'add', '-q', '--detach', $tree, $head) | Out-Null
    try {
        foreach ($item in $plan) {
            $sig = Invoke-Sign $keygen $key $item.Namespace $item.Data $work
            Say (Test-Signature $keygen $signers $item.Namespace $item.Data $sig $work)
            [IO.File]::WriteAllBytes((Join-Path $tree "$($item.Name).sig"), $sig)
        }
        $names = @($plan | ForEach-Object { "$($_.Name).sig" })
        Invoke-Git (@('-C', $tree, 'add', '--') + $names) | Out-Null
        $msg = "sign " + (($plan | ForEach-Object { "$($_.Name) (serial $($_.Serial))" }) -join ', ')
        Invoke-Git @('-C', $tree, 'commit', '-q', '-m', $msg) | Out-Null
        Invoke-Git @('-C', $tree, 'push', '-q', 'origin', "HEAD:refs/heads/$branch") | Out-Null
        Say "pushed the signature to $branch"
    } finally {
        Invoke-Native 'git' @('worktree', 'remove', '--force', $tree) | Out-Null
    }

    if ($NoMerge) { Say "not merged (-NoMerge): merge PR #$Pr when its checks pass"; return }
    Say 'waiting for the checks'
    Start-Sleep -Seconds 10
    gh pr checks $Pr --watch --fail-fast | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "checks did not pass on PR #${Pr}: not merged" }
    gh pr merge $Pr --squash --delete-branch | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "merge of PR #$Pr failed" }

    Invoke-Git @('fetch', '-q', 'origin', '+refs/heads/main:refs/remotes/origin/main') | Out-Null
    $merged = Invoke-Git @('rev-parse', 'refs/remotes/origin/main')
    foreach ($item in $plan) {
        $data = Get-Blob $merged $item.Name
        $sig = Get-Blob $merged "$($item.Name).sig"
        if ($null -eq $data -or $null -eq $sig) { throw "$($item.Name) or its signature is missing on main after the merge" }
        Test-Signature $keygen $signers $item.Namespace $data $sig $work | Out-Null
    }
    Say "merged as $($merged.Substring(0, 12)); main verifies."
    if ($plan.Name -contains "${prefix}fleet.toml") {
        Say 'Hosts apply fleet.toml within 15 minutes (or at once: wh fleet status --refresh on a host).'
    }
    $rel = $plan | Where-Object Name -eq "${prefix}release.toml" | Select-Object -First 1
    if ($rel) {
        $text = [Text.Encoding]::UTF8.GetString($rel.Data)
        $version = [regex]::Match($text, '(?m)^version\s*=\s*"([^"]+)"').Groups[1].Value
        $commit = [regex]::Match($text, '(?m)^commit\s*=\s*"([0-9a-f]{40})"').Groups[1].Value
        $notes = [regex]::Match($text, '(?m)^notes\s*=\s*"([^"]*)"').Groups[1].Value
        if ($prefix) {
            # A shared repository: its releases page belongs to the other products (the App's updater reads it).
            Say 'no GitHub Release page in a shared repository (hosts never read one)'
        } elseif ($version -and $commit) {
            gh release create "v$version" --target $commit --title "Worker host $version" --notes "$notes`n`nSigned release.toml serial $($rel.Serial). Hosts announce it at check_at and apply it in their maintenance window." | Out-Host
            if ($LASTEXITCODE -ne 0) { Say "the GitHub Release page was not created (hosts do not need it): gh release create v$version --target $commit" }
        }
        Say "Release $version is signed: hosts announce it at their next check (01:00) and apply it in the window (03:00)."
    }
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
