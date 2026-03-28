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
    $nonExactChecks = [System.Collections.Generic.List[string]]::new()
    $broadFilterChecks = [System.Collections.Generic.List[string]]::new()
    $unqualifiedSelectorChecks = [System.Collections.Generic.List[string]]::new()
    foreach ($check in @($parsed.checks)) {
        $command = [string]$check.command
        if ($command -notlike "cargo test *") {
            continue
        }
        if ($command -notmatch "\s--\s--exact$") {
            $nonExactChecks.Add([string]$check.name) | Out-Null
            continue
        }
        if ($command -match "\s([A-Za-z0-9_:]+)\s--\s--exact$") {
            $selector = [string]$matches[1]
            if ($selector.EndsWith("_")) {
                $broadFilterChecks.Add([string]$check.name) | Out-Null
            }
            if ($selector -notmatch "::") {
                $unqualifiedSelectorChecks.Add([string]$check.name) | Out-Null
            }
        }
        else {
            $nonExactChecks.Add([string]$check.name) | Out-Null
        }
    }
    if ($nonExactChecks.Count -gt 0) {
        throw ("relay adversarial regression checks must pin exact test names (-- --exact). Non-exact checks: " + ($nonExactChecks -join ", "))
    }
    if ($broadFilterChecks.Count -gt 0) {
        throw ("relay adversarial regression checks must not use broad trailing-underscore selectors. Offending checks: " + ($broadFilterChecks -join ", "))
    }
    if ($unqualifiedSelectorChecks.Count -gt 0) {
        throw ("relay adversarial regression checks must use fully-qualified Rust test selectors (<module>::<tests>::<name>) to avoid zero-test passes. Offending checks: " + ($unqualifiedSelectorChecks -join ", "))
    }

    Write-Host "relay_adversarial_regression_check.ps1 self-test passed."
}
finally {
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
