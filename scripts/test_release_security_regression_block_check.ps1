$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Write-MockReport {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Check,
        [Parameter(Mandatory = $true)][bool]$Passed
    )

    $payload = [ordered]@{
        schema_version = 1
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        check = $Check
        passed = $Passed
    }
    $payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8
}

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$testRoot = Join-Path $workspaceRoot (".tmp\release_security_regression_block_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    Write-MockReport -Path (Join-Path $testRoot "trust_zone_approval_matrix_report.json") -Check "trust_zone_approval_matrix_check" -Passed $true
    Write-MockReport -Path (Join-Path $testRoot "dangerous_full_access_mode_report.json") -Check "dangerous_full_access_mode_check" -Passed $true
    Write-MockReport -Path (Join-Path $testRoot "silent_network_host_escalation_report.json") -Check "silent_network_host_escalation_check" -Passed $true
    Write-MockReport -Path (Join-Path $testRoot "third_party_bypass_lane_report.json") -Check "third_party_bypass_lane_check" -Passed $true
    Write-MockReport -Path (Join-Path $testRoot "crypto_design_note_report.json") -Check "crypto_design_note_check" -Passed $true
    @{
        schema_version = 1
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        check = "relay_green_regression_suite_check"
        passed = $true
        checks = @(
            @{ name = "trust_zone_approval_matrix"; passed = $true },
            @{ name = "dangerous_full_access_mode"; passed = $true },
            @{ name = "silent_network_host_escalation"; passed = $true },
            @{ name = "third_party_bypass_lane"; passed = $true },
            @{ name = "crypto_design_note"; passed = $true }
        )
    } | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath (Join-Path $testRoot "relay_green_regression_suite_report.json") -Encoding UTF8
    @{
        schema_version = 1
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        gate_passed = $true
        artifacts = @(
            @{ name = "relay_green_regression_suite_report"; passed = $true }
        )
    } | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath (Join-Path $testRoot "p0_acceptance_evidence_bundle.json") -Encoding UTF8

    $reportPath = Join-Path $testRoot "release_security_regression_block_report.json"
    & "$PSScriptRoot\release_security_regression_block_check.ps1" `
        -ArtifactRoot $testRoot `
        -ReportPath $reportPath

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "release security-regression block report was not generated."
    }
    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$parsed.passed) {
        throw "release security-regression block report indicates failure."
    }
    if ($parsed.check -ne "release_security_regression_block_check") {
        throw "Unexpected check id in release security-regression block report."
    }

    @{
        schema_version = 1
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        gate_passed = $false
        artifacts = @()
    } | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath (Join-Path $testRoot "p0_acceptance_evidence_bundle.json") -Encoding UTF8

    $negativeReportPath = Join-Path $testRoot "release_security_regression_block_report_negative.json"
    & "$PSScriptRoot\release_security_regression_block_check.ps1" `
        -ArtifactRoot $testRoot `
        -ReportPath $negativeReportPath `
        -FailOnFindings:$false

    $negative = Get-Content -LiteralPath $negativeReportPath -Raw | ConvertFrom-Json
    if ([bool]$negative.passed) {
        throw "release security-regression block should fail when p0 bundle gate_passed is false."
    }
    $matched = $false
    foreach ($finding in @($negative.findings | ForEach-Object { [string]$_ })) {
        if ($finding -like "p0_acceptance_evidence_bundle:*") {
            $matched = $true
            break
        }
    }
    if (-not $matched) {
        throw "release security-regression block should include p0_acceptance_evidence_bundle finding."
    }

    Write-Host "release_security_regression_block_check.ps1 self-test passed."
}
finally {
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
