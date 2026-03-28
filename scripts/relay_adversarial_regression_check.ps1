param(
    [switch]$FailOnFindings = $true,
    [string]$ReportPath = ""
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $workspaceRoot ".tmp\security"
if (-not (Test-Path -LiteralPath $artifactRoot)) {
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
}
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $artifactRoot "relay_adversarial_regression_report.json"
}

$checks = @(
    @{
        name = "attestation_verifier_rejection_is_fail_closed"
        threat_class = "attestation_bypass"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "verify_attestation_fails_closed_when_verifier_rejects_evidence")
    },
    @{
        name = "measurement_prefix_mismatch_is_fail_closed"
        threat_class = "measurement_spoofing"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "verify_attestation_rejects_unexpected_measurement_prefix")
    },
    @{
        name = "release_binding_changes_on_policy_identity_change"
        threat_class = "policy_binding_tampering"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "release_binding_changes_when_policy_identity_changes")
    },
    @{
        name = "policy_identity_is_stable_for_equivalent_metadata"
        threat_class = "policy_identity_confusion"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "policy_identity_is_stable_for_equivalent_metadata_order")
    },
    @{
        name = "provider_adapter_rejects_replay_bad_attestation_and_insecure_transport"
        threat_class = "replay_and_transport_downgrade"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "confidential_chat_rejects_")
    },
    @{
        name = "provider_route_blocks_non_allowlisted_provider"
        threat_class = "provider_allowlist_bypass"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "chat_task_remote_api_is_blocked_by_provider_allowlist_policy")
    },
    @{
        name = "provider_route_blocks_model_risk_tier_violations"
        threat_class = "model_risk_tier_bypass"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "chat_task_remote_api_is_blocked_by_model_risk_tier_policy")
    },
    @{
        name = "confidential_relay_is_blocked_while_quarantine_active"
        threat_class = "quarantine_bypass"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "confidential_chat_task_is_blocked_when_quarantine_mode_enabled")
    },
    @{
        name = "extensions_and_mcp_are_frozen_during_quarantine"
        threat_class = "extension_path_bypass"
        command = "cargo"
        args = @("test", "-p", "control_plane", "quarantine_mode_blocks_")
    }
)

$results = @()
$findings = [System.Collections.Generic.List[string]]::new()

foreach ($check in $checks) {
    $start = Get-Date
    $errorText = ""
    $passed = $false
    try {
        & $check.command @($check.args)
        $passed = ($LASTEXITCODE -eq 0)
        if (-not $passed) {
            $errorText = "command exited with code $LASTEXITCODE"
        }
    }
    catch {
        $passed = $false
        $errorText = $_.Exception.Message
    }
    $durationMs = [int][Math]::Round(((Get-Date) - $start).TotalMilliseconds)

    if (-not $passed) {
        $findings.Add("$($check.name): $errorText") | Out-Null
    }

    $results += [PSCustomObject]@{
        name = $check.name
        threat_class = $check.threat_class
        command = "$($check.command) $($check.args -join ' ')"
        passed = $passed
        duration_ms = $durationMs
        detail = $errorText
    }
}

$report = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    workspace_root = $workspaceRoot
    check = "relay_adversarial_regression_check"
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
    Write-Host "Relay adversarial regression findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "relay adversarial regression check failed"
    }
}
else {
    Write-Host "Relay adversarial regression check passed: $ReportPath"
}
