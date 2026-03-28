$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$testRoot = Join-Path $workspaceRoot (".tmp\third_party_bypass_lane_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    $reportPath = Join-Path $testRoot "third_party_bypass_lane_report.json"
    & "$PSScriptRoot\third_party_bypass_lane_check.ps1" -ReportPath $reportPath

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "third-party bypass lane report was not generated."
    }
    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$parsed.passed) {
        throw "third-party bypass lane report indicates failure."
    }
    if ($parsed.check -ne "third_party_bypass_lane_check") {
        throw "Unexpected check id in third-party bypass lane report."
    }
    if ($null -eq $parsed.controls -or -not [bool]$parsed.controls.extension_manifest_security_revalidated_on_restore) {
        throw "third-party bypass lane report is missing restore-path manifest revalidation control."
    }

    Write-Host "third_party_bypass_lane_check.ps1 self-test passed."
}
finally {
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
