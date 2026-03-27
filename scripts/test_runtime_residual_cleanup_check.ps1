$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$testRoot = Join-Path $workspaceRoot (".tmp\runtime_residual_cleanup_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    $reportPath = Join-Path $testRoot "runtime_residual_cleanup_report.json"
    & "$PSScriptRoot\runtime_residual_cleanup_check.ps1" -ReportPath $reportPath

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "Runtime residual cleanup report was not generated."
    }
    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$parsed.passed) {
        throw "Runtime residual cleanup report indicates failure."
    }
    if ($parsed.check -ne "runtime_residual_cleanup_check") {
        throw "Unexpected check id in runtime residual cleanup report."
    }

    Write-Host "runtime_residual_cleanup_check.ps1 self-test passed."
}
finally {
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
