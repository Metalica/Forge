$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$testRoot = Join-Path $workspaceRoot (".tmp\trust_zone_approval_matrix_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    $reportPath = Join-Path $testRoot "trust_zone_approval_matrix_report.json"
    & "$PSScriptRoot\trust_zone_approval_matrix_check.ps1" -ReportPath $reportPath

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "trust-zone approval-matrix report was not generated."
    }
    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$parsed.passed) {
        throw "trust-zone approval-matrix report indicates failure."
    }
    if ($parsed.check -ne "trust_zone_approval_matrix_check") {
        throw "Unexpected check id in trust-zone approval-matrix report."
    }
    if ($null -eq $parsed.trust_zones -or @($parsed.trust_zones).Count -lt 4) {
        throw "trust-zone approval-matrix report is missing trust-zone coverage."
    }
    if ($null -eq $parsed.approval_matrix -or @($parsed.approval_matrix).Count -lt 4) {
        throw "trust-zone approval-matrix report is missing approval-matrix coverage."
    }

    Write-Host "trust_zone_approval_matrix_check.ps1 self-test passed."
}
finally {
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
