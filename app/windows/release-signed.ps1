# Signs, packages and publishes a StruggleBus Monitor release.
#
# The code-signing key lives in the certificate authority's cloud and only
# works on a PC where the owner is logged in to it (SimplySign Desktop, with
# a one-time code from their phone). GitHub's runners cannot sign. So the
# release is made in two halves:
#
#   1. Pushing the tag windows/vX.Y.Z makes GitHub test and build the app,
#      unsigned, and keep the build as an artifact of that run.
#   2. This script, run on the signing PC, downloads that build, signs the
#      app and its installer, packages them and publishes the release to the
#      repository the installed app updates from.
#
#   pwsh app/windows/release-signed.ps1 -Version 1.7.2
#
# Nothing secret is stored or printed: signing uses the certificate from the
# Windows store, and publishing uses the GitHub login 'gh' already holds.
[CmdletBinding()]
param(
    # The release to make, as in the tag windows/vX.Y.Z.
    [Parameter(Mandatory)][string]$Version,
    # Publish without asking. Without it the script asks before uploading.
    [switch]$Yes,
    # Sign and package but do not upload. For trying the signing step.
    [switch]$SkipUpload,
    # Use builds already on disk (folders publish-win-x64 and publish-win-arm64)
    # instead of downloading the tag's build. Only allowed with -SkipUpload.
    [string]$ArtifactsDir,
    [string[]]$Runtimes = @('win-x64', 'win-arm64')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$SourceRepository = 'u64a/strugglebus'
$DestinationRepository = 'NZCypher819/StruggleApp-Privacy'
$Workflow = 'windows-release.yml'
$PackId = 'NZCypher819.StruggleBusMonitor'
$VpkVersion = '1.2.161'
$TimestampServer = 'http://time.certum.pl'
# The certificates allowed to sign a release, by thumbprint. A name is not
# enough: someone else with the same name could hold their own certificate.
# When the certificate is renewed, add the new thumbprint here before the old
# one expires. The publisher name is checked as well.
$Thumbprints = @(
    '3FF059FA28ED74ACB229CBA2E670CEA565015238'   # valid to 26 Nov 2027
)
$Publisher = 'CN=Open Source Developer Christopher Cunningham, O=Open Source Developer, L=Shell Cove, S=New South Wales, C=AU'

function Invoke-Checked {
    # Runs a program and stops if it fails. Output goes to the console.
    param([Parameter(Mandatory)][string]$Program, [string[]]$Arguments = @())
    & $Program @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "'$Program $($Arguments -join ' ')' failed with exit code $LASTEXITCODE." }
}

function Invoke-Capture {
    # Runs a program, stops if it fails, and returns what it printed.
    param([Parameter(Mandatory)][string]$Program, [string[]]$Arguments = @())
    $output = & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "'$Program $($Arguments -join ' ')' failed with exit code $LASTEXITCODE." }
    return ($output -join "`n").Trim()
}

function Get-SigningCertificate {
    $found = @(Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
        Where-Object { $_.Thumbprint -in $Thumbprints -and $_.Subject -eq $Publisher -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) })
    if ($found.Count -eq 0) {
        throw "The signing certificate is not available. Log in to SimplySign Desktop with a one-time code from your phone, then run this again."
    }
    if ($found.Count -gt 1) { throw "More than one allowed signing certificate is in the store. Remove the old one first." }
    return $found[0]
}

function Get-Vpk {
    # The packaging tool, at the pinned version, kept in its own folder.
    $folder = Join-Path $env:LOCALAPPDATA "StruggleBus\release-tools\vpk-$VpkVersion"
    $vpk = Join-Path $folder 'vpk.exe'
    if (-not (Test-Path $vpk)) {
        Invoke-Checked dotnet @('tool', 'install', 'vpk', '--version', $VpkVersion, '--tool-path', $folder)
    }
    return $vpk
}

function Get-TagBuild {
    # Downloads the build GitHub made for the tag, after checking the tag is a
    # commit on main and that its run passed.
    param([string]$Tag, [string]$Into)
    $commit = Invoke-Capture gh @('api', "repos/$SourceRepository/commits/tags/$Tag", '--jq', '.sha')
    $position = Invoke-Capture gh @('api', "repos/$SourceRepository/compare/main...$commit", '--jq', '.status')
    if ($position -notin @('identical', 'behind')) {
        throw "Tag $Tag ($commit) is not a commit on main (GitHub says '$position'). Refusing to release it."
    }
    $runs = Invoke-Capture gh @('run', 'list', '-R', $SourceRepository, '--workflow', $Workflow, '--commit', $commit,
        '--json', 'databaseId,headBranch,status,conclusion') | ConvertFrom-Json
    $run = @($runs | Where-Object { $_.headBranch -eq $Tag }) | Select-Object -First 1
    if (-not $run) { throw "No '$Workflow' run was found for tag $Tag. Push the tag first and let it finish." }
    if ($run.status -ne 'completed') {
        Write-Host "Waiting for GitHub to finish building $Tag ..."
        Invoke-Checked gh @('run', 'watch', "$($run.databaseId)", '-R', $SourceRepository, '--exit-status', '--interval', '20')
    }
    elseif ($run.conclusion -ne 'success') {
        throw "The build for $Tag finished as '$($run.conclusion)'. Fix it and tag again."
    }
    Invoke-Checked gh @('run', 'download', "$($run.databaseId)", '-R', $SourceRepository, '-D', $Into)
    Write-Host "Using the build from run $($run.databaseId), commit $commit."
}

function Assert-Signed {
    # Every installer and the app itself must carry a valid, timestamped
    # signature from an allowed certificate before anything is uploaded.
    param([string[]]$Files)
    foreach ($file in $Files) {
        $signature = Get-AuthenticodeSignature -LiteralPath $file
        $signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { '(none)' }
        if ($signature.Status -ne 'Valid' -or $signer -notin $Thumbprints -or -not $signature.TimeStamperCertificate) {
            throw "'$file' is not correctly signed: status $($signature.Status), signer $signer."
        }
        Write-Host "signed: $(Split-Path $file -Leaf)"
    }
}

function Test-Program {
    # True for a Windows program file (an .exe or .dll, whatever it is named):
    # they all start with the two bytes 'MZ'.
    param([string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    try { return $stream.ReadByte() -eq 0x4D -and $stream.ReadByte() -eq 0x5A }
    finally { $stream.Dispose() }
}

function Assert-EveryProgramSigned {
    # No program file may ship unsigned. Each one in the package must be
    # validly signed either by an allowed certificate (the app's own files) or
    # by Microsoft (the .NET runtime that ships with it).
    param([string]$Folder)
    $ours = 0; $microsoft = 0; $bad = @()
    foreach ($file in Get-ChildItem -LiteralPath $Folder -Recurse -File) {
        if (-not (Test-Program $file.FullName)) { continue }
        $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
        $signer = $signature.SignerCertificate
        if ($signature.Status -eq 'Valid' -and $signer.Thumbprint -in $Thumbprints -and $signature.TimeStamperCertificate) { $ours++ }
        elseif ($signature.Status -eq 'Valid' -and $signer.Subject -match '(^|, )O=Microsoft Corporation(,|$)' -and $signer.Issuer -match '(^|, )O=Microsoft Corporation(,|$)') { $microsoft++ }
        else { $bad += "$($file.FullName.Substring($Folder.Length + 1)) ($($signature.Status))" }
    }
    if ($bad.Count -gt 0) { throw "These program files are not signed by this project or by Microsoft:`n  $($bad -join "`n  ")" }
    if ($ours -eq 0) { throw "No file in '$Folder' is signed by this project." }
    Write-Host "every program file is signed: $ours by this project, $microsoft by Microsoft"
}

if ($Version -notmatch '^\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?$') { throw "'$Version' is not a version like 1.7.2." }
if ($ArtifactsDir -and -not $SkipUpload) { throw '-ArtifactsDir is for trying the signing step and needs -SkipUpload. A published release is always made from the build GitHub made for the tag.' }

$tag = "windows/v$Version"
$certificate = Get-SigningCertificate
$vpk = Get-Vpk
$icon = Join-Path $PSScriptRoot 'StruggleBusMonitor\icon.ico'
$work = Join-Path ([IO.Path]::GetTempPath()) "strugglebus-release-$Version-$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
New-Item -ItemType Directory -Path $work | Out-Null
Write-Host "Signing as: $($certificate.Subject)"
Write-Host "Working in: $work"

try {
    $builds = $ArtifactsDir
    if (-not $builds) {
        $builds = Join-Path $work 'builds'
        Get-TagBuild -Tag $tag -Into $builds
    }

    $signParams = "/fd SHA256 /td SHA256 /tr $TimestampServer /sha1 $($certificate.Thumbprint)"
    $outputs = @{}
    foreach ($runtime in $Runtimes) {
        $build = Join-Path $builds "publish-$runtime"
        if (-not (Test-Path (Join-Path $build 'StruggleBusMonitor.exe'))) { throw "The $runtime build is missing from '$builds'." }
        $releases = Join-Path $work "Releases-$runtime"

        # The previous release lets the tool make a small update package. The
        # first release on a channel has none, so a failure here is not fatal.
        & $vpk download github --repoUrl "https://github.com/$DestinationRepository" --channel $runtime --outputDir $releases | Out-Host
        if ($LASTEXITCODE -ne 0) { Write-Warning "No previous $runtime release was downloaded; this one will have no small update package." }

        Invoke-Checked $vpk @('pack',
            '--packId', $PackId,
            '--packVersion', $Version,
            '--packDir', $build,
            '--runtime', $runtime,
            '--channel', $runtime,
            '--mainExe', 'StruggleBusMonitor.exe',
            '--packTitle', 'StruggleBus Monitor',
            '--icon', $icon,
            '--signParams', $signParams,
            '--outputDir', $releases)

        Assert-Signed @(Get-ChildItem -Path $releases -Filter '*Setup.exe' | ForEach-Object FullName)
        # The tool signs a copy, not the build folder, so the app is checked
        # where a user gets it: inside the portable package.
        $portable = Get-ChildItem -Path $releases -Filter '*Portable.zip' | Select-Object -First 1
        $unpacked = Join-Path $work "portable-$runtime"
        Expand-Archive -LiteralPath $portable.FullName -DestinationPath $unpacked
        Assert-Signed @(Get-ChildItem -Path $unpacked -Recurse -Filter 'StruggleBusMonitor.exe' | ForEach-Object FullName)
        Assert-EveryProgramSigned $unpacked
        $outputs[$runtime] = $releases
    }

    if ($SkipUpload) {
        Write-Host "Signed and packaged $Version. Nothing was uploaded (-SkipUpload). The packages are in $work."
        return
    }
    if (-not $Yes) {
        $answer = Read-Host "Publish StruggleBus Monitor v$Version to $DestinationRepository? Type 'publish' to go ahead"
        if ($answer -ne 'publish') { Write-Host 'Stopped. Nothing was uploaded.'; return }
    }

    # The packaging tool reads the token from the environment, so it never
    # appears on a command line or in this script's output.
    $env:VPK_TOKEN = Invoke-Capture gh @('auth', 'token')
    try {
        # One runtime at a time: both upload into the same GitHub release.
        foreach ($runtime in $Runtimes) {
            Invoke-Checked $vpk @('upload', 'github',
                '--repoUrl', "https://github.com/$DestinationRepository",
                '--channel', $runtime,
                '--outputDir', $outputs[$runtime],
                '--tag', "v$Version",
                '--releaseName', "StruggleBus Monitor v$Version",
                '--publish',
                '--merge')
        }
    }
    finally {
        Remove-Item Env:VPK_TOKEN -ErrorAction SilentlyContinue
    }
    Write-Host "Published StruggleBus Monitor v$Version, signed by $($certificate.Subject)."
}
finally {
    if (-not $SkipUpload) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}
