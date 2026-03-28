$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$testRoot = Join-Path $workspaceRoot (".tmp\silent_network_host_escalation_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    $reportPath = Join-Path $testRoot "silent_network_host_escalation_report.json"
    & "$PSScriptRoot\silent_network_host_escalation_check.ps1" -ReportPath $reportPath

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "silent network/host escalation report was not generated."
    }
    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$parsed.passed) {
        throw "silent network/host escalation report indicates failure."
    }
    if ($parsed.check -ne "silent_network_host_escalation_check") {
        throw "Unexpected check id in silent network/host escalation report."
    }
    if ($null -eq $parsed.controls -or $parsed.controls.remote_egress_default -ne "disabled_without_explicit_opt_in") {
        throw "silent network/host escalation report is missing remote egress default contract."
    }

    Write-Host "silent_network_host_escalation_check.ps1 self-test passed."
}
finally {
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
