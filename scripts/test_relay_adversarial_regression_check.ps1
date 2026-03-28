$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$testRoot = Join-Path $workspaceRoot (".tmp\relay_adversarial_regression_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    $reportPath = Join-Path $testRoot "relay_adversarial_regression_report.json"
    & "$PSScriptRoot\relay_adversarial_regression_check.ps1" -ReportPath $reportPath

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "relay adversarial regression report was not generated."
    }

    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$parsed.passed) {
        throw "relay adversarial regression report indicates failure."
    }
    if ($parsed.check -ne "relay_adversarial_regression_check") {
        throw "Unexpected check id in relay adversarial regression report."
    }
    if ($null -eq $parsed.checks -or @($parsed.checks).Count -lt 9) {
        throw "relay adversarial regression report is missing expected check coverage."
    }

    Write-Host "relay_adversarial_regression_check.ps1 self-test passed."
}
finally {
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
