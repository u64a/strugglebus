param(
    [int]$Port = 8443,
    [double]$StreamSeconds = 3
)

$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath($PSScriptRoot)
$certs = [System.IO.Path]::Combine($root, '.certs')
$ca = [System.IO.Path]::Combine($certs, 'ca.crt')
$cert = [System.IO.Path]::Combine($certs, 'server.crt')
$key = [System.IO.Path]::Combine($certs, 'server.key')
$fingerprintFile = [System.IO.Path]::Combine($certs, 'ca.sha256')

if (-not (Test-Path $ca) -or -not (Test-Path $cert) -or -not (Test-Path $key)) {
    & python ([System.IO.Path]::Combine($root, 'generate_dev_cert.py')) $certs
    if ($LASTEXITCODE -ne 0) { throw 'Certificate generation failed.' }
}

$fingerprint = ([System.IO.File]::ReadAllText($fingerprintFile)).Trim()
& python ([System.IO.Path]::Combine($root, 'mock_server.py')) `
    --host 127.0.0.1 `
    --port $Port `
    --cert $cert `
    --key $key `
    --ca-sha256 $fingerprint `
    --public-endpoint "https://10.0.2.2:$Port" `
    --stream-seconds $StreamSeconds
