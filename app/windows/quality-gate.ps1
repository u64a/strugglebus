# CI gate: every hand-written method under CRAP 10, line coverage at least 85%.
#
# CRAP = complexity^2 * (1 - coverage)^3 + complexity, per method, from the
# Cobertura report that 'dotnet test --collect:"XPlat Code Coverage"' writes.
# A method passes by being simple, by being tested, or both. Code generated
# from XAML is left out.
#
#   pwsh windows/quality-gate.ps1 -Results windows/.metrics
param(
    [Parameter(Mandatory)][string]$Results,
    [double]$MaxCrap = 10,
    [double]$MinCoverage = 85
)
$ErrorActionPreference = 'Stop'

$report = Get-ChildItem -Path $Results -Recurse -Filter 'coverage.cobertura.xml' | Select-Object -First 1
if (-not $report) { throw "No coverage.cobertura.xml was found under '$Results'." }
[xml]$coverage = Get-Content -LiteralPath $report.FullName -Raw

$rows = [System.Collections.Generic.List[object]]::new()
$lines = @{}
foreach ($class in $coverage.SelectNodes('//class')) {
    $file = ($class.GetAttribute('filename') -replace '\\', '/').Split('/')[-1]
    if ($file -match '\.(g|g\.i)\.cs$' -or $file -match '\.xaml$') { continue }
    foreach ($line in $class.SelectNodes('lines/line')) {
        $key = "$file`:$($line.GetAttribute('number'))"
        $lines[$key] = $lines[$key] -or ([int]$line.GetAttribute('hits') -gt 0)
    }
    foreach ($method in $class.SelectNodes('methods/method')) {
        $own = $method.SelectNodes('lines/line')
        if ($own.Count -eq 0) { continue }
        $hit = @($own | Where-Object { [int]$_.GetAttribute('hits') -gt 0 }).Count
        $covered = $hit / $own.Count
        $complexity = [Math]::Max(1, [int][double]$method.GetAttribute('complexity'))
        $owner = $class.GetAttribute('name')
        $name = $method.GetAttribute('name')
        # An async method is compiled to a nested class; report it under its own name.
        if ($name -eq 'MoveNext' -and $owner -match '/<(\w+)>d__') {
            $name = $Matches[1]
            $owner = $owner.Split('/')[0]
        }
        $rows.Add([pscustomobject]@{
            Crap       = $complexity * $complexity * [Math]::Pow(1 - $covered, 3) + $complexity
            Complexity = $complexity
            Coverage   = $covered
            Where      = "$file $($owner.Split('.')[-1]).$name"
        })
    }
}
if ($rows.Count -eq 0 -or $lines.Count -eq 0) { throw 'The coverage report measured no hand-written code.' }

$lineCoverage = 100 * @($lines.Values | Where-Object { $_ }).Count / $lines.Count
$worst = $rows | Sort-Object Crap -Descending | Select-Object -First 1
'quality gate: {0} methods, line coverage {1:N1}%, highest CRAP {2:N1} ({3})' -f $rows.Count, $lineCoverage, $worst.Crap, $worst.Where

$problems = @($rows | Where-Object { $_.Crap -ge $MaxCrap } | Sort-Object Crap -Descending | ForEach-Object {
    '{0}: CRAP {1:N1} (complexity {2}, coverage {3:P0})' -f $_.Where, $_.Crap, $_.Complexity, $_.Coverage
})
if ($lineCoverage -lt $MinCoverage) { $problems += 'line coverage is {0:N1}%, below {1}%' -f $lineCoverage, $MinCoverage }

if ($problems.Count -eq 0) {
    "passed: every method is under CRAP $MaxCrap and coverage is at least $MinCoverage%"
    exit 0
}
"FAILED: $($problems.Count) problem(s). Simplify the method or test more of it."
$problems | ForEach-Object { "  $_" }
exit 1
