$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Write-MockReport {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Check,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [Parameter(Mandatory = $false)][bool]$IncludeApplies = $false,
        [Parameter(Mandatory = $false)][bool]$Applies = $true
    )

    $payload = [ordered]@{
        schema_version = 1
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        check = $Check
        passed = $Passed
    }
    if ($IncludeApplies) {
        $payload.applies = $Applies
    }
    $payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8
}

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$testRoot = Join-Path $workspaceRoot (".tmp\relay_green_regression_suite_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    Write-MockReport -Path (Join-Path $testRoot "relay_adversarial_regression_report.json") -Check "relay_adversarial_regression_check" -Passed $true
    Write-MockReport -Path (Join-Path $testRoot "relay_adversarial_corpus_report.json") -Check "relay_adversarial_corpus_check" -Passed $true
    Write-MockReport -Path (Join-Path $testRoot "runtime_update_chain_integrity_report.json") -Check "runtime_update_chain_integrity_check" -Passed $true -IncludeApplies $true -Applies $true
    Write-MockReport -Path (Join-Path $testRoot "release_candidate_secret_leak_report.json") -Check "release_candidate_secret_leak_check" -Passed $true
    Write-MockReport -Path (Join-Path $testRoot "incident_response_quarantine_report.json") -Check "incident_response_quarantine_check" -Passed $true
    Write-MockReport -Path (Join-Path $testRoot "model_provider_trust_policy_report.json") -Check "model_provider_trust_policy_check" -Passed $true
    Write-MockReport -Path (Join-Path $testRoot "dangerous_action_reauth_report.json") -Check "dangerous_action_reauth_check" -Passed $true
    Write-MockReport -Path (Join-Path $testRoot "trust_zone_approval_matrix_report.json") -Check "trust_zone_approval_matrix_check" -Passed $true
    Write-MockReport -Path (Join-Path $testRoot "dangerous_full_access_mode_report.json") -Check "dangerous_full_access_mode_check" -Passed $true
    Write-MockReport -Path (Join-Path $testRoot "silent_network_host_escalation_report.json") -Check "silent_network_host_escalation_check" -Passed $true
    Write-MockReport -Path (Join-Path $testRoot "third_party_bypass_lane_report.json") -Check "third_party_bypass_lane_check" -Passed $true
    Write-MockReport -Path (Join-Path $testRoot "crypto_design_note_report.json") -Check "crypto_design_note_check" -Passed $true

    $reportPath = Join-Path $testRoot "relay_green_regression_suite_report.json"
    & "$PSScriptRoot\relay_green_regression_suite_check.ps1" `
        -ArtifactRoot $testRoot `
        -ReportPath $reportPath

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "relay green-regression suite report was not generated."
    }
    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$parsed.passed) {
        throw "relay green-regression suite report indicates failure."
    }
    if ($parsed.check -ne "relay_green_regression_suite_check") {
        throw "Unexpected check id in relay green-regression suite report."
    }
    if ($null -eq $parsed.checks -or @($parsed.checks).Count -lt 12) {
        throw "relay green-regression suite report is missing expected coverage."
    }

    Write-MockReport -Path (Join-Path $testRoot "model_provider_trust_policy_report.json") -Check "model_provider_trust_policy_check" -Passed $false

    $negativeReportPath = Join-Path $testRoot "relay_green_regression_suite_report_negative.json"
    & "$PSScriptRoot\relay_green_regression_suite_check.ps1" `
        -ArtifactRoot $testRoot `
        -ReportPath $negativeReportPath `
        -FailOnFindings:$false

    $negativeParsed = Get-Content -LiteralPath $negativeReportPath -Raw | ConvertFrom-Json
    if ([bool]$negativeParsed.passed) {
        throw "relay green-regression suite should fail when one report indicates failure."
    }
    $negativeFindings = @($negativeParsed.findings | ForEach-Object { [string]$_ })
    $matched = $false
    foreach ($finding in $negativeFindings) {
        if ($finding -like "model_provider_trust_policy:*") {
            $matched = $true
            break
        }
    }
    if (-not $matched) {
        throw "relay green-regression suite should include model_provider_trust_policy finding."
    }

    Write-Host "relay_green_regression_suite_check.ps1 self-test passed."
}
finally {
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
