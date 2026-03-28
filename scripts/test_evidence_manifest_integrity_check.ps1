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
$testRoot = Join-Path $workspaceRoot (".tmp\evidence_manifest_integrity_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    Write-MockReport -Path (Join-Path $testRoot "trust_zone_approval_matrix_report.json") -Check "trust_zone_approval_matrix_check" -Passed $true
    Write-MockReport -Path (Join-Path $testRoot "dangerous_full_access_mode_report.json") -Check "dangerous_full_access_mode_check" -Passed $true
    Write-MockReport -Path (Join-Path $testRoot "silent_network_host_escalation_report.json") -Check "silent_network_host_escalation_check" -Passed $true
    Write-MockReport -Path (Join-Path $testRoot "third_party_bypass_lane_report.json") -Check "third_party_bypass_lane_check" -Passed $true
    Write-MockReport -Path (Join-Path $testRoot "crypto_design_note_report.json") -Check "crypto_design_note_check" -Passed $true
    Write-MockReport -Path (Join-Path $testRoot "relay_green_regression_suite_report.json") -Check "relay_green_regression_suite_check" -Passed $true
    @{
        schema_version = 1
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        gate_passed = $true
        artifacts = @(
            @{ name = "relay_green_regression_suite_report"; passed = $true }
        )
    } | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath (Join-Path $testRoot "p0_acceptance_evidence_bundle.json") -Encoding UTF8

    $reportPath = Join-Path $testRoot "evidence_manifest_integrity_report.json"
    $manifestPath = Join-Path $testRoot "evidence_integrity_manifest.json"

    & "$PSScriptRoot\evidence_manifest_integrity_check.ps1" `
        -ArtifactRoot $testRoot `
        -ReportPath $reportPath `
        -ManifestPath $manifestPath

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "evidence manifest integrity report was not generated."
    }
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        throw "evidence integrity manifest was not generated."
    }

    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$parsed.passed) {
        throw "evidence manifest integrity report indicates failure."
    }
    if ($parsed.check -ne "evidence_manifest_integrity_check") {
        throw "Unexpected check id in evidence manifest integrity report."
    }
    if ([string]::IsNullOrWhiteSpace([string]$parsed.manifest_sha256)) {
        throw "evidence manifest integrity report is missing manifest hash."
    }

    Remove-Item -LiteralPath (Join-Path $testRoot "crypto_design_note_report.json") -Force
    $negativeReportPath = Join-Path $testRoot "evidence_manifest_integrity_report_negative.json"
    & "$PSScriptRoot\evidence_manifest_integrity_check.ps1" `
        -ArtifactRoot $testRoot `
        -ReportPath $negativeReportPath `
        -ManifestPath $manifestPath `
        -FailOnFindings:$false

    $negative = Get-Content -LiteralPath $negativeReportPath -Raw | ConvertFrom-Json
    if ([bool]$negative.passed) {
        throw "evidence manifest integrity check should fail when a required artifact is missing."
    }
    $matched = $false
    foreach ($finding in @($negative.findings | ForEach-Object { [string]$_ })) {
        if ($finding -like "crypto_design_note_report:*") {
            $matched = $true
            break
        }
    }
    if (-not $matched) {
        throw "evidence manifest integrity findings should include missing crypto_design_note_report."
    }

    Write-Host "evidence_manifest_integrity_check.ps1 self-test passed."
}
finally {
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
