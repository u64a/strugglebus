# The GitHub half of a StruggleBus Monitor release: fetching the previous
# release's package, and publishing the new release.
#
# It is apart from release-signed.ps1 so that it can be rehearsed against a
# scratch repository without the signing key:
#
#   pwsh app/windows/release-github.ps1 -Action publish -Version 0.0.2 `
#       -Packages C:\some\folder -Repository u64a/something-release-test
#
# Releases here are published under the tag GitHub built from, windows/vX.Y.Z.
# The repository also holds the bus's releases, under bus/ tags, so nothing in
# this script goes by "the newest release": it goes by tag.
#
# A published release in this repository can never be changed (GitHub's
# immutable releases). So the release is made as a draft, every file in the
# draft is compared with the file on this PC, and only then is it published.
#
# Nothing secret is stored or printed: everything uses the login 'gh' holds.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('previous', 'publish')][string]$Action,
    # The release being made, as in the tag windows/vX.Y.Z.
    [Parameter(Mandatory)][string]$Version,
    [string]$Repository = 'u64a/strugglebus',
    [string]$PackId = 'NZCypher819.StruggleBusMonitor',
    # previous: the runtime wanted and the folder to put its package in.
    [string]$Runtime,
    [string]$Into,
    # publish: the folder holding one Releases-<runtime> folder per runtime.
    [string]$Packages,
    [string[]]$Runtimes = @('win-x64', 'win-arm64')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Home_ = 'u64a/strugglebus'
# Where releases before 1.7.6 were published, as tags vX.Y.Z. Read only for the
# previous package, until this repository has a release of its own to offer.
$Former = 'NZCypher819/StruggleApp-Privacy'
$PreviousTried = 5

if ($Version -notmatch '^\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?$') { throw "'$Version' is not a version like 1.7.2." }
if ($Repository -ne $Home_ -and $Repository -notmatch '^u64a/[A-Za-z0-9._-]+-release-test$') {
    throw "'$Repository' is neither $Home_ nor a scratch repository named u64a/...-release-test."
}
$Tag = "windows/v$Version"
# Started with -File, a list arrives as one text with commas in it.
$Runtimes = @($Runtimes | ForEach-Object { $_ -split ',' } | Where-Object { $_ })

function Invoke-Gh {
    # Runs gh, stops if it fails, and returns what it printed.
    param([string[]]$Arguments)
    $output = & gh @Arguments
    if ($LASTEXITCODE -ne 0) { throw "'gh $($Arguments -join ' ')' failed with exit code $LASTEXITCODE." }
    return ($output -join "`n").Trim()
}

function Test-Gh {
    # Runs gh quietly and says whether it succeeded.
    param([string[]]$Arguments)
    $null = & gh @Arguments 2>&1
    return $LASTEXITCODE -eq 0
}

function Get-EarlierReleases {
    # Every release tag older than the one being made, newest first: this
    # repository's windows/vX.Y.Z tags, then the former repository's vX.Y.Z.
    $this = [version](($Version -split '[-+]')[0])
    $found = @()
    foreach ($ref in (Invoke-Gh @('api', "repos/$Repository/git/matching-refs/tags/windows/v", '--paginate', '--jq', '.[].ref')) -split "`n") {
        if ($ref -match '^refs/tags/(windows/v(\d+\.\d+\.\d+))$') {
            $found += [pscustomobject]@{ Repository = $Repository; Tag = $Matches[1]; Version = [version]$Matches[2]; Order = 0 }
        }
    }
    if ($Repository -eq $Home_) {
        foreach ($name in (Invoke-Gh @('api', "repos/$Former/releases?per_page=100", '--jq', '.[] | select(.draft | not) | .tag_name')) -split "`n") {
            if ($name -match '^v(\d+\.\d+\.\d+)$') {
                $found += [pscustomobject]@{ Repository = $Former; Tag = $name; Version = [version]$Matches[1]; Order = 1 }
            }
        }
    }
    return @($found | Where-Object { $_.Version -lt $this } |
        Sort-Object @{ Expression = 'Version'; Descending = $true }, @{ Expression = 'Order'; Descending = $false })
}

function Get-PreviousPackage {
    # Puts the newest earlier release's full package in $Into, so the packaging
    # tool can make a small update package from it. A tag with no published
    # release, or without this runtime, is passed over. The first release on a
    # channel has no previous one, so finding none is not fatal.
    #
    # The package is not checked here. A wrong one could only make a small
    # update package that does not apply: the app compares the result with the
    # full package's hash, falls back to the full package, and checks that
    # against the signed list of files before installing anything.
    if (-not $Runtime -or -not $Into) { throw '-Action previous needs -Runtime and -Into.' }
    New-Item -ItemType Directory -Force -Path $Into | Out-Null
    foreach ($earlier in (Get-EarlierReleases | Select-Object -First $PreviousTried)) {
        $file = "$PackId-$($earlier.Version)-$Runtime-full.nupkg"
        if (Test-Gh @('release', 'download', $earlier.Tag, '-R', $earlier.Repository, '-p', $file, '-D', $Into)) {
            Write-Host "Previous $Runtime release: $($earlier.Tag) in $($earlier.Repository)."
            return
        }
    }
    Write-Warning "No previous $Runtime release was found; this one will have no small update package."
}

function Get-ReleaseFiles {
    # The files one runtime's release is made of, and its list of packages cut
    # down to this version. The packaging tool's own list also names the
    # previous release's package, which is not part of this release.
    param([string]$ForRuntime, [string]$Staging)
    $folder = Join-Path $Packages "Releases-$ForRuntime"
    $full = "$PackId-$Version-$ForRuntime-full.nupkg"
    $delta = "$PackId-$Version-$ForRuntime-delta.nupkg"
    $names = @($full, "$PackId-$ForRuntime-Portable.zip", "$PackId-$ForRuntime-Setup.exe")
    if (Test-Path -LiteralPath (Join-Path $folder $delta)) { $names += $delta }
    $files = @()
    foreach ($name in $names) {
        $path = Join-Path $folder $name
        if (-not (Test-Path -LiteralPath $path)) { throw "'$name' is missing from '$folder'." }
        $files += $path
    }

    $list = "releases.$ForRuntime.json"
    $listed = @((Get-Content -LiteralPath (Join-Path $folder $list) -Raw | ConvertFrom-Json).Assets | Where-Object { "$($_.Version)" -eq $Version })
    if (@($listed | Where-Object { $_.FileName -eq $full -and $_.Type -eq 'Full' }).Count -ne 1) { throw "'$list' does not list $full exactly once." }
    foreach ($entry in $listed) {
        if ($entry.FileName -notin $names) { throw "'$list' lists $($entry.FileName), which is not part of this release." }
        $hash = (Get-FileHash -LiteralPath (Join-Path $folder $entry.FileName) -Algorithm SHA256).Hash
        if ($hash -ne $entry.SHA256) { throw "'$list' gives a hash for $($entry.FileName) that is not the file's." }
    }
    $cut = Join-Path $Staging $list
    [IO.File]::WriteAllText($cut, ([pscustomobject]@{ Assets = @($listed) } | ConvertTo-Json -Compress -Depth 5))
    return $files + $cut
}

function Remove-EarlierDraft {
    # A run that stopped part way leaves a draft. It is removed and made again,
    # because every run signs afresh. A published release is never touched.
    if (-not (Test-Gh @('release', 'view', $Tag, '-R', $Repository, '--json', 'isDraft'))) { return }
    $draft = (Invoke-Gh @('release', 'view', $Tag, '-R', $Repository, '--json', 'isDraft') | ConvertFrom-Json).isDraft
    if (-not $draft) { throw "$Tag is already published in $Repository. A published release cannot be changed; release a new version." }
    Invoke-Gh @('release', 'delete', $Tag, '-R', $Repository, '--yes') | Out-Null
    Write-Host "Removed the draft an earlier run left for $Tag."
}

function Assert-ReleaseHolds {
    # Compares what GitHub holds for the release with the files on this PC:
    # the same names, each the same size and, where GitHub gives one, the same
    # hash.
    param([string]$ReleaseId, [string[]]$Files)
    $held = @{}
    foreach ($asset in @(Invoke-Gh @('api', "repos/$Repository/releases/$ReleaseId/assets?per_page=100") | ConvertFrom-Json)) { $held[$asset.name] = $asset }
    $problems = @()
    foreach ($file in $Files) {
        $name = Split-Path $file -Leaf
        if (-not $held.ContainsKey($name)) { $problems += "$name was not uploaded"; continue }
        $asset = $held[$name]
        $held.Remove($name)
        if ($asset.state -ne 'uploaded') { $problems += "$name is '$($asset.state)'" }
        if ([long]$asset.size -ne (Get-Item -LiteralPath $file).Length) { $problems += "$name is not the size of the file here" }
        $digest = if ($asset.PSObject.Properties['digest']) { $asset.digest } else { $null }
        if ($digest -and $digest -ne "sha256:$((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant())") { $problems += "$name does not have the hash of the file here" }
    }
    $problems += $held.Keys | ForEach-Object { "$_ is in the release but is not one of this release's files" }
    if ($problems.Count -gt 0) { throw "The release on GitHub does not match the files here:`n  $($problems -join "`n  ")" }
    Write-Host "GitHub holds all $($Files.Count) files, each matching the file here."
}

function Publish-Release {
    if (-not $Packages) { throw '-Action publish needs -Packages.' }
    $staging = Join-Path $Packages 'release-lists'
    Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $staging | Out-Null
    $files = @()
    foreach ($one in $Runtimes) { $files += Get-ReleaseFiles -ForRuntime $one -Staging $staging }

    Remove-EarlierDraft
    $notes = "StruggleBus Monitor $Version for Windows. GitHub built it from the tag $Tag; it was signed and published from the owner's PC. An installed copy updates itself."
    # --verify-tag: the release goes on the tag GitHub built from, and is never
    # allowed to make a tag of its own.
    Invoke-Gh (@('release', 'create', $Tag, '-R', $Repository, '--verify-tag', '--draft',
            '--title', "StruggleBus Monitor v$Version", '--notes', $notes) + $files) | Out-Null
    $id = (Invoke-Gh @('release', 'view', $Tag, '-R', $Repository, '--json', 'databaseId') | ConvertFrom-Json).databaseId
    Assert-ReleaseHolds -ReleaseId "$id" -Files $files

    Invoke-Gh @('release', 'edit', $Tag, '-R', $Repository, '--draft=false', '--latest') | Out-Null
    $published = Invoke-Gh @('api', "repos/$Repository/releases/$id") | ConvertFrom-Json
    if ($published.draft -or $published.tag_name -ne $Tag -or @($published.assets).Count -ne $files.Count) {
        throw "GitHub does not show $Tag as published with its $($files.Count) files. Look at the release before doing anything else."
    }
    if (-not ($published.PSObject.Properties['immutable'] -and $published.immutable)) {
        throw "$Tag is published, but $Repository is not keeping it from being changed. Turn on immutable releases for the repository."
    }
    Write-Host "Published $Tag in ${Repository}: $($files.Count) files, and it can no longer be changed."
}

if ($Action -eq 'previous') { Get-PreviousPackage } else { Publish-Release }
