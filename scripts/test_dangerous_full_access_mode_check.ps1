$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$testRoot = Join-Path $workspaceRoot (".tmp\dangerous_full_access_mode_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    $reportPath = Join-Path $testRoot "dangerous_full_access_mode_report.json"
    & "$PSScriptRoot\dangerous_full_access_mode_check.ps1" -ReportPath $reportPath

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "dangerous full-access mode report was not generated."
    }
    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$parsed.passed) {
        throw "dangerous full-access mode report indicates failure."
    }
    if ($parsed.check -ne "dangerous_full_access_mode_check") {
        throw "Unexpected check id in dangerous full-access mode report."
    }
    if ($null -eq $parsed.controls -or [string]::IsNullOrWhiteSpace([string]$parsed.controls.dangerous_controls_env)) {
        throw "dangerous full-access mode report is missing dangerous-controls env contract."
    }
    if (-not [bool]$parsed.panel_agent_contract_verified) {
        throw "dangerous full-access mode report did not verify panel-agent contract markers."
    }

    Write-Host "dangerous_full_access_mode_check.ps1 self-test passed."
}
finally {
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
