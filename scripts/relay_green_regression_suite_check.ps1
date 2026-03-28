param(
    [switch]$FailOnFindings = $true,
    [string]$ReportPath = "",
    [string]$ArtifactRoot = "",
    [switch]$RequireRuntimeUpdateApplicability = $false
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
    $ArtifactRoot = Join-Path $workspaceRoot ".tmp\security"
}
if (-not (Test-Path -LiteralPath $ArtifactRoot)) {
    New-Item -ItemType Directory -Path $ArtifactRoot -Force | Out-Null
}
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $ArtifactRoot "relay_green_regression_suite_report.json"
}

$requiredReports = @(
    [PSCustomObject]@{
        name = "relay_adversarial_regression"
        path = Join-Path $ArtifactRoot "relay_adversarial_regression_report.json"
        expected_check = "relay_adversarial_regression_check"
        require_applies = $false
    },
    [PSCustomObject]@{
        name = "relay_adversarial_corpus"
        path = Join-Path $ArtifactRoot "relay_adversarial_corpus_report.json"
        expected_check = "relay_adversarial_corpus_check"
        require_applies = $false
    },
    [PSCustomObject]@{
        name = "runtime_update_chain_integrity"
        path = Join-Path $ArtifactRoot "runtime_update_chain_integrity_report.json"
        expected_check = "runtime_update_chain_integrity_check"
        require_applies = $RequireRuntimeUpdateApplicability
    },
    [PSCustomObject]@{
        name = "release_candidate_secret_leak"
        path = Join-Path $ArtifactRoot "release_candidate_secret_leak_report.json"
        expected_check = "release_candidate_secret_leak_check"
        require_applies = $false
    },
    [PSCustomObject]@{
        name = "incident_response_quarantine"
        path = Join-Path $ArtifactRoot "incident_response_quarantine_report.json"
        expected_check = "incident_response_quarantine_check"
        require_applies = $false
    },
    [PSCustomObject]@{
        name = "model_provider_trust_policy"
        path = Join-Path $ArtifactRoot "model_provider_trust_policy_report.json"
        expected_check = "model_provider_trust_policy_check"
        require_applies = $false
    },
    [PSCustomObject]@{
        name = "dangerous_action_reauth"
        path = Join-Path $ArtifactRoot "dangerous_action_reauth_report.json"
        expected_check = "dangerous_action_reauth_check"
        require_applies = $false
    },
    [PSCustomObject]@{
        name = "trust_zone_approval_matrix"
        path = Join-Path $ArtifactRoot "trust_zone_approval_matrix_report.json"
        expected_check = "trust_zone_approval_matrix_check"
        require_applies = $false
    },
    [PSCustomObject]@{
        name = "dangerous_full_access_mode"
        path = Join-Path $ArtifactRoot "dangerous_full_access_mode_report.json"
        expected_check = "dangerous_full_access_mode_check"
        require_applies = $false
    },
    [PSCustomObject]@{
        name = "silent_network_host_escalation"
        path = Join-Path $ArtifactRoot "silent_network_host_escalation_report.json"
        expected_check = "silent_network_host_escalation_check"
        require_applies = $false
    },
    [PSCustomObject]@{
        name = "third_party_bypass_lane"
        path = Join-Path $ArtifactRoot "third_party_bypass_lane_report.json"
        expected_check = "third_party_bypass_lane_check"
        require_applies = $false
    },
    [PSCustomObject]@{
        name = "crypto_design_note"
        path = Join-Path $ArtifactRoot "crypto_design_note_report.json"
        expected_check = "crypto_design_note_check"
        require_applies = $false
    }
)

$results = @()
$findings = [System.Collections.Generic.List[string]]::new()

foreach ($spec in $requiredReports) {
    $present = Test-Path -LiteralPath $spec.path
    $passed = $present
    $detail = ""
    $parsed = $null
    $applies = $null

    if (-not $present) {
        $passed = $false
        $detail = "required report missing"
    }
    else {
        try {
            $parsed = Get-Content -LiteralPath $spec.path -Raw | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $parsed.schema_version) {
                $passed = $false
                $detail = "report missing schema_version"
            }
            elseif ($spec.expected_check -ne [string]$parsed.check) {
                $passed = $false
                $detail = "unexpected check id '$($parsed.check)'"
            }
            elseif ($null -eq $parsed.passed) {
                $passed = $false
                $detail = "report missing passed field"
            }
            elseif (-not [bool]$parsed.passed) {
                $passed = $false
                $detail = "report indicates failure"
            }
            else {
                if ($null -ne $parsed.PSObject.Properties["applies"]) {
                    $applies = [bool]$parsed.applies
                }
                if ($spec.require_applies -and -not [bool]$applies) {
                    $passed = $false
                    $detail = "report is not applicable but applicability is required"
                }
            }
        }
        catch {
            $passed = $false
            $detail = "report parse error: $($_.Exception.Message)"
        }
    }

    if (-not $passed) {
        $findings.Add("$($spec.name): $detail") | Out-Null
    }

    $results += [PSCustomObject]@{
        name = $spec.name
        path = $spec.path
        expected_check = $spec.expected_check
        present = $present
        passed = $passed
        applies = $applies
        detail = $detail
    }
}

$report = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    workspace_root = $workspaceRoot
    check = "relay_green_regression_suite_check"
    suite = "plan_a_p3_green_regression_suite"
    artifact_root = $ArtifactRoot
    require_runtime_update_applicability = [bool]$RequireRuntimeUpdateApplicability
    passed = ($findings.Count -eq 0)
    checks = $results
    findings_count = $findings.Count
    findings = @($findings)
}

$reportParent = Split-Path -Parent $ReportPath
if (-not [string]::IsNullOrWhiteSpace($reportParent) -and -not (Test-Path -LiteralPath $reportParent)) {
    New-Item -ItemType Directory -Path $reportParent -Force | Out-Null
}
$report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $ReportPath -Encoding UTF8

if ($findings.Count -gt 0) {
    Write-Host "Relay green-regression suite findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "relay green-regression suite check failed"
    }
}
else {
    Write-Host "Relay green-regression suite check passed: $ReportPath"
}
