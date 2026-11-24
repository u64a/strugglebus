# Joins this PC's agent to a Strugglebus in one step: checks the bus
# certificate, redeems the one-time enrollment, proves the new key, stores it
# in a private folder, and writes a launcher that starts GitHub Copilot CLI
# already connected to the bus.
#
# The onboarding package gives the exact command. The enrollment token is read
# from the STRUGGLEBUS_ENROLLMENT environment variable, never the command line.
# Works in Windows PowerShell 5.1 and PowerShell 7.
param(
    [Parameter(Mandatory = $true)][string]$Endpoint,
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$CaSha256
)

$ErrorActionPreference = 'Stop'

function Fail([string]$Message) {
    [Console]::Error.WriteLine("join: $Message")
    exit 1
}

if ($Endpoint -notmatch '^https://') { Fail "the bus address must start with https:// (got '$Endpoint')." }
$Endpoint = $Endpoint.TrimEnd('/')
if ($Name -notmatch '^[A-Za-z0-9_-][A-Za-z0-9._-]*$') {
    Fail "the agent name may only contain letters, digits, dots, dashes and underscores (got '$Name')."
}
if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
    Fail 'curl.exe is not available. It ships with Windows 10 and later. Nothing has been used up.'
}

$busHome = if ($env:STRUGGLEBUS_HOME) { $env:STRUGGLEBUS_HOME } else { Join-Path $HOME '.strugglebus' }
$folder = Join-Path $busHome $Name
New-Item -ItemType Directory -Force -Path $folder | Out-Null
# Only this account may read the folder that holds the key.
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $folder /inheritance:r /grant:r "*${sid}:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "could not make $folder private to this account." }

$ca = Join-Path $folder 'ca-root.crt'
$statePath = Join-Path $folder 'agent.json'
$keyPath = Join-Path $folder 'agent-key'
$headerPath = Join-Path $folder '.join-header'
$bodyPath = Join-Path $folder '.join-body'
$responsePath = Join-Path $folder '.join-response'
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Remove-Scratch {
    foreach ($path in @($headerPath, $bodyPath, $responsePath)) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }
}

function Read-Detail {
    try {
        $value = (Get-Content -LiteralPath $responsePath -Raw | ConvertFrom-Json).detail
        if ($value -is [string]) { return $value }
        if ($null -ne $value) { return ($value | ConvertTo-Json -Compress -Depth 5) }
    } catch { }
    return 'no detail'
}

function Send-Request([string]$Secret, [string]$Body, [string]$Url) {
    # Prints nothing secret: the token travels in a private header file.
    [IO.File]::WriteAllText($headerPath, "Authorization: Bearer $Secret", $utf8)
    [IO.File]::WriteAllText($bodyPath, $Body, $utf8)
    # A LAN certificate authority has no revocation service Windows can reach,
    # so that one check is best effort. The certificate is still verified
    # against ca-root.crt.
    $status = & curl.exe --silent --show-error --ssl-revoke-best-effort `
        --cacert $ca --max-time 30 `
        --header ('@' + $headerPath) --header 'Content-Type: application/json' `
        --data-binary ('@' + $bodyPath) --output $responsePath `
        --write-out '%{http_code}' --url $Url
    if ($LASTEXITCODE -ne 0) { return $null }
    return [string]$status
}

try {
    if (-not (Test-Path -LiteralPath $ca)) {
        Fail "$ca is missing. Run every line of the command from the onboarding package, starting at the top."
    }
    # The package states the fingerprint of the certificate root it carries. If
    # the saved file differs, someone or something changed it on the way here.
    try {
        $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ca)
        $actual = [BitConverter]::ToString(
            [Security.Cryptography.SHA256]::Create().ComputeHash($certificate.RawData)).Replace('-', ':')
    } catch {
        Fail "$ca is not a certificate. Copy the command from the onboarding package again."
    }
    $expected = $CaSha256.ToUpperInvariant()
    if ($actual -ne $expected) {
        Fail "the certificate root does not match the onboarding package (expected $expected, found $actual). Stop and tell your operator. Nothing has been used up."
    }

    if (-not (Test-Path -LiteralPath $statePath)) {
        $token = $env:STRUGGLEBUS_ENROLLMENT
        if (-not $token) { Fail 'STRUGGLEBUS_ENROLLMENT is not set. Run every line of the command from the onboarding package.' }
        if (Test-Path -LiteralPath $keyPath) {
            Fail "$keyPath already exists but $statePath does not. Do not enroll this name again; tell your operator, who can recover it."
        }
        $body = @{ request_id = [guid]::NewGuid().ToString(); name = $Name; host = $env:COMPUTERNAME } |
            ConvertTo-Json -Compress
        $status = Send-Request $token $body "$Endpoint/api/enrollments/redeem"
        if ($null -eq $status) {
            Fail "could not reach $Endpoint. Check that the name resolves on this PC and the bus is running. The enrollment has not been used; run this again."
        }
        if ($status -ne '201') {
            $reason = Read-Detail
            if ($status -eq '401') { Fail "the bus refused the enrollment ($reason). It may have expired or already been used. Ask your operator for a new onboarding package." }
            if ($status -eq '409') { Fail "an agent named '$Name' already exists ($reason). Ask your operator; do not pick a different name yourself." }
            Fail "the bus answered $status ($reason). Tell your operator."
        }
        # Split the response: the secret goes in agent-key and nowhere else.
        $response = Get-Content -LiteralPath $responsePath -Raw | ConvertFrom-Json
        [IO.File]::WriteAllText($keyPath, [string]$response.credential_secret, $utf8)
        $record = [ordered]@{
            endpoint = $Endpoint
            mcp = "$Endpoint/mcp"
            agent_id = [string]$response.agent.id
            agent_name = [string]$response.agent.name
            credential_epoch = [int]$response.agent.credential_epoch
            credential_version = [int]$response.credential.version
            proved = $false
        }
        [IO.File]::WriteAllText($statePath, ($record | ConvertTo-Json), $utf8)
        Remove-Scratch
        Write-Output "join: enrolled as $Name"
    }
    Remove-Item Env:STRUGGLEBUS_ENROLLMENT -ErrorAction SilentlyContinue

    if (-not (Test-Path -LiteralPath $keyPath)) {
        Fail "$keyPath is missing, so this agent has no key. Tell your operator, who can recover it; do not enroll the name again."
    }
    $record = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ($record.endpoint -ne $Endpoint) {
        Fail "this folder belongs to an agent on $($record.endpoint), not $Endpoint."
    }

    if (-not $record.proved) {
        $body = [ordered]@{
            request_id = [guid]::NewGuid().ToString()
            expected_agent_id = $record.agent_id
            expected_agent_name = $record.agent_name
            expected_credential_epoch = [int]$record.credential_epoch
            expected_credential_version = [int]$record.credential_version
        } | ConvertTo-Json -Compress
        $key = [IO.File]::ReadAllText($keyPath).Trim()
        $status = Send-Request $key $body "$Endpoint/api/credentials/prove"
        if ($null -eq $status) {
            Fail "enrolled, but could not reach $Endpoint to prove the key. Run the same join command again within a few minutes; it will only retry this step."
        }
        if ($status -ne '200') {
            Fail "enrolled, but the bus answered $status when proving the key ($(Read-Detail)). If the key has expired, tell your operator, who can recover it; do not enroll the name again."
        }
        $record.proved = $true
        [IO.File]::WriteAllText($statePath, ($record | ConvertTo-Json), $utf8)
        Remove-Scratch
        Write-Output 'join: key proved'
    }
} finally {
    Remove-Scratch
}

# The key stays out of this file: Copilot CLI fills it in from the environment
# variable the launcher sets.
$mcp = [ordered]@{
    mcpServers = [ordered]@{
        bus = [ordered]@{
            type = 'http'
            url = "$Endpoint/mcp"
            headers = [ordered]@{ Authorization = 'Bearer ${STRUGGLEBUS_AGENT_KEY}' }
            tools = @('*')
        }
    }
}
[IO.File]::WriteAllText((Join-Path $folder 'copilot-mcp.json'), ($mcp | ConvertTo-Json -Depth 6), $utf8)

$launcher = @'
# Starts GitHub Copilot CLI connected to the bus as this agent. Run
# bus-copilot.cmd from the folder the agent should work in. Extra arguments are
# passed to copilot.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Get-Command copilot -ErrorAction SilentlyContinue)) {
    [Console]::Error.WriteLine("bus-copilot: GitHub Copilot CLI ('copilot') is not installed or not on PATH.")
    exit 1
}
$keyPath = Join-Path $here 'agent-key'
if (-not (Test-Path -LiteralPath $keyPath)) {
    [Console]::Error.WriteLine("bus-copilot: $keyPath is missing; this agent has not joined the bus.")
    exit 1
}
$roots = Join-Path $here 'ca-root.crt'
# Copilot CLI only trusts the bus certificate through NODE_EXTRA_CA_CERTS. Keep
# any roots already configured there, such as a company proxy.
if ($env:NODE_EXTRA_CA_CERTS -and ($env:NODE_EXTRA_CA_CERTS -ne $roots) -and (Test-Path -LiteralPath $env:NODE_EXTRA_CA_CERTS)) {
    $combined = Join-Path $here '.node-roots.pem'
    $text = [IO.File]::ReadAllText($env:NODE_EXTRA_CA_CERTS) + "`n" + [IO.File]::ReadAllText($roots)
    [IO.File]::WriteAllText($combined, $text, (New-Object System.Text.UTF8Encoding($false)))
    $roots = $combined
}
$env:NODE_EXTRA_CA_CERTS = $roots
$env:STRUGGLEBUS_AGENT_KEY = [IO.File]::ReadAllText($keyPath).Trim()
& copilot --additional-mcp-config ('@' + (Join-Path $here 'copilot-mcp.json')) @args
exit $LASTEXITCODE
'@
[IO.File]::WriteAllText((Join-Path $folder 'bus-copilot.ps1'), $launcher, $utf8)
$wrapper = "@echo off`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File `"%~dp0bus-copilot.ps1`" %*`r`n"
[IO.File]::WriteAllText((Join-Path $folder 'bus-copilot.cmd'), $wrapper, [Text.Encoding]::ASCII)

$joinScript = Join-Path $folder 'join.ps1'
if (Test-Path -LiteralPath $joinScript) { Remove-Item -LiteralPath $joinScript -Force }

Write-Output @"

Joined the bus.
  Agent name : $($record.agent_name)
  Agent id   : $($record.agent_id)
  Bus        : $Endpoint
  Folder     : $folder   (private to this account; holds this agent's key)

To start GitHub Copilot CLI connected to the bus, open a terminal in the folder
the agent should work in and run:
  $folder\bus-copilot.cmd

First thing in that session, ask the agent to call the bus "orientation" tool
and do what it says.

Delete the onboarding package now. Never post it, or anything in
$folder, to the bus, a chat or source control.
"@
