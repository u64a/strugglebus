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
    [string[]]$Runtimes = @('win-x64', 'win-arm64'),
    # A checkout of the worker host's signed release: release.toml, its .sig and
    # keys\allowed_signers. The installer is signed only if that release names it.
    [string]$HostRelease = 'C:\repos\strugglebus-worker-host'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$SourceRepository = 'u64a/strugglebus'
$DestinationRepository = 'NZCypher819/StruggleApp-Privacy'
$Workflow = 'windows-release.yml'
$PackId = 'NZCypher819.StruggleBusMonitor'
$RepositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$SignInstallerTool = Join-Path $RepositoryRoot 'worker-host\tools\sign-bootstrap.ps1'
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
    Assert-CheckoutIsTheTag $commit
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

function Assert-CheckoutIsTheTag {
    # This script, and the installer-signing tool it calls (which holds the
    # pinned release keys), run from the checkout on this PC. They are only the
    # reviewed ones if the checkout is exactly the tagged commit with nothing
    # changed. The same goes for the installer that gets signed, which the app
    # built from that commit has inside it.
    param([string]$Commit)
    $head = Invoke-Capture git @('-C', $RepositoryRoot, 'rev-parse', 'HEAD')
    $changes = Invoke-Capture git @('-C', $RepositoryRoot, 'status', '--porcelain')
    if ($head -ne $Commit) { throw "This checkout is at $head, but the tag is $Commit. Check out the tag first, so the scripts that run are the reviewed ones." }
    if ($changes) { throw "This checkout has changes that are not in the tag:`n$changes`nRemove them first, so the scripts that run are the reviewed ones." }
    Write-Host "This checkout is the tagged commit, unchanged."
}

function Get-SignedInstaller {
    # The worker host's installer (bootstrap.ps1), signed, for Add a host to
    # hand over. The app has the unsigned file built in and uses a signed copy
    # only if it is exactly that file plus one signature block. This checkout
    # is the commit the app was built from (see Assert-CheckoutIsTheTag), so
    # the file here is that file.
    #
    # worker-host/tools/sign-bootstrap.ps1 does the signing. It refuses unless
    # the file's hash is the one in a worker host release that verifies with the
    # project's release keys, so only an installer that release approved is
    # ever signed, and it checks the signed copy afterwards.
    param([string]$Into)
    $unsigned = Join-Path $RepositoryRoot 'worker-host\tools\bootstrap.ps1'
    $signed = Join-Path $Into 'bootstrap.ps1'
    Invoke-Checked pwsh (@('-NoProfile', '-File', $SignInstallerTool) + (Get-HostReleaseArguments) + @('-Bootstrap', $unsigned, '-Out', $signed, '-Sign'))
    return $signed
}

function Get-HostReleaseArguments {
    return @('-Release', (Join-Path $HostRelease 'release.toml'), '-Signers', (Join-Path $HostRelease 'keys\allowed_signers'))
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

function New-SignedFileList {
    # The app checks an update before installing it. Signatures on the program
    # files are not enough by themselves: the text files beside them tell .NET
    # which libraries to load, and a library could be swapped for an older one
    # that Microsoft also signed. So the hash of every file goes in a list, the
    # list is signed, and the app refuses an update whose files do not match it.
    #
    # The project's own program files are signed first, here, so that the list
    # holds the hashes of the files as they ship. The packaging tool then finds
    # them signed and leaves them alone.
    #
    # The list is a PowerShell data file only because Windows can sign and
    # check those. It is read as text and never run.
    param([string]$Build, [string]$Version, $Certificate)
    $root = (Resolve-Path -LiteralPath $Build).Path
    $list = Join-Path $root 'signed-files.psd1'
    Remove-Item -LiteralPath $list -ErrorAction SilentlyContinue
    $lines = @('# StruggleBus Monitor signed file list. Data only; never run.', "# version $(($Version -split '[-+]')[0])")
    # The packaging tool leaves this Microsoft crash-dump helper out of the
    # package, so it must not be on the list. The app would refuse it anyway: a
    # program that can be started has to be signed by this project.
    Remove-Item -LiteralPath (Join-Path $root 'createdump.exe') -ErrorAction SilentlyContinue
    $files = Get-ChildItem -LiteralPath $root -Recurse -File | Sort-Object FullName
    foreach ($file in $files) {
        if (-not (Test-Program $file.FullName) -or (Get-AuthenticodeSignature -LiteralPath $file.FullName).Status -ne 'NotSigned') { continue }
        $signed = Set-AuthenticodeSignature -FilePath $file.FullName -Certificate $Certificate -HashAlgorithm SHA256 -TimestampServer $TimestampServer
        if ($signed.Status -ne 'Valid') { throw "'$($file.Name)' could not be signed: $($signed.StatusMessage)" }
        Write-Host "signed before listing: $($file.Name)"
    }
    foreach ($file in $files) {
        $name = $file.FullName.Substring($root.Length + 1).Replace('\', '/')
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $lines += "# sha256 $hash  $name"
    }
    $lines += '@{}'
    [IO.File]::WriteAllText($list, ($lines -join "`n") + "`n")
    $signed = Set-AuthenticodeSignature -FilePath $list -Certificate $Certificate -HashAlgorithm SHA256 -TimestampServer $TimestampServer
    if ($signed.Status -ne 'Valid') { throw "The file list could not be signed: $($signed.StatusMessage)" }
    Write-Host "listed $($lines.Count - 3) file(s) beside the app in signed-files.psd1"
}

function Assert-ListMatches {
    # The same comparison the app makes before installing an update, made here
    # on the packaged files, so a release whose list and contents disagree is
    # never published. Anything the packaging tool adds, drops or changes after
    # the list was signed shows up here, not on users' PCs.
    param([string]$Folder)
    $addedByPackager = @('sq.version', 'Squirrel.exe', 'StruggleBus Monitor_ExecutionStub.exe', 'signed-files.psd1')
    $listed = @{}
    foreach ($line in Get-Content -LiteralPath (Join-Path $Folder 'signed-files.psd1')) {
        if ($line.StartsWith('# SIG # Begin signature block')) { break }
        if ($line -match '^# sha256 ([0-9a-f]{64})  (.+)$') { $listed[$Matches[2]] = $Matches[1] }
    }
    $problems = @()
    foreach ($file in Get-ChildItem -LiteralPath $Folder -Recurse -File) {
        $name = $file.FullName.Substring($Folder.Length + 1).Replace('\', '/')
        if ($name -in $addedByPackager) { continue }
        if (-not $listed.ContainsKey($name)) { $problems += "$name is in the package but not on the list"; continue }
        if ($listed[$name] -ne (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()) { $problems += "$name is not the file that was listed" }
        $listed.Remove($name)
    }
    $problems += $listed.Keys | ForEach-Object { "$_ is on the list but not in the package" }
    if ($problems.Count -gt 0) { throw "The package does not match its signed list of files:`n  $($problems -join "`n  ")" }
    Write-Host 'the package matches its signed list of files'
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
    $installer = Get-SignedInstaller -Into $work

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

        # Beside the app, and so on the signed list of files below.
        Copy-Item -LiteralPath $installer -Destination (Join-Path $build 'bootstrap.ps1') -Force
        New-SignedFileList -Build $build -Version $Version -Certificate $certificate

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
        $shippedList = Get-ChildItem -Path $unpacked -Recurse -Filter 'signed-files.psd1' | Select-Object -First 1
        if (-not $shippedList) { throw "The signed list of files is missing from the $runtime package." }
        Assert-Signed @($shippedList.FullName)
        Assert-ListMatches $shippedList.Directory.FullName
        # The installer as a user gets it, checked again by the worker host's own tool.
        $shipped = Get-ChildItem -Path $unpacked -Recurse -Filter 'bootstrap.ps1' | Select-Object -First 1
        if (-not $shipped) { throw "The signed installer is missing from the $runtime package." }
        Invoke-Checked pwsh (@('-NoProfile', '-File', $SignInstallerTool) + (Get-HostReleaseArguments) + @('-Out', $shipped.FullName))
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
