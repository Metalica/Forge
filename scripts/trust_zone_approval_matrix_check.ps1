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
    $ReportPath = Join-Path $artifactRoot "trust_zone_approval_matrix_report.json"
}

$checks = @(
    @{
        name = "runtime_registry_local_api_hardening_unit_tests"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "local_api_hardening::tests::")
    },
    @{
        name = "runtime_registry_data_governance_unit_tests"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "data_governance::tests::")
    },
    @{
        name = "runtime_registry_model_provider_trust_policy_unit_tests"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "model_provider_trust_policy::tests::")
    },
    @{
        name = "runtime_registry_incident_response_quarantine_unit_tests"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "incident_response_quarantine::tests::")
    },
    @{
        name = "dangerous_action_reauth_contract_selftest"
        command = "powershell"
        args = @("-ExecutionPolicy", "Bypass", "-File", (Join-Path $PSScriptRoot "test_dangerous_action_reauth_check.ps1"))
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
        command = "$($check.command) $($check.args -join ' ')"
        passed = $passed
        duration_ms = $durationMs
        detail = $errorText
    }
}

$trustZones = @(
    [PSCustomObject]@{
        id = "trusted_workspace_local"
        boundary = "execution_plane::workspace canonical root and sandbox checks"
        trust_level = "trusted"
        escalation = "blocked_without_policy"
    },
    [PSCustomObject]@{
        id = "instruction_and_metadata_inputs"
        boundary = "AGENTS/docs/memory/manifests/tool output"
        trust_level = "untrusted_by_default"
        escalation = "blocked_without_policy"
    },
    [PSCustomObject]@{
        id = "extension_and_mcp_surface"
        boundary = "control_plane extension host + MCP scoped token lane"
        trust_level = "restricted"
        escalation = "explicit_approval_required"
    },
    [PSCustomObject]@{
        id = "remote_provider_egress"
        boundary = "runtime_registry provider routes and data-governance checks"
        trust_level = "restricted"
        escalation = "export_approval_and_policy_required"
    },
    [PSCustomObject]@{
        id = "incident_quarantine_recovery"
        boundary = "quarantine mode recovery endpoint allowlist"
        trust_level = "emergency_only"
        escalation = "re_attestation_and_reverification_required"
    }
)

$approvalMatrix = @(
    [PSCustomObject]@{
        action = "extension_overbroad_enablement"
        required_controls = @(
            "signed_manifest",
            "requested_permissions_granted",
            "explicit_overbroad_approval"
        )
        evidence = "control_plane::extension_host overbroad approval checks"
    },
    [PSCustomObject]@{
        action = "remote_egress_for_restricted_workspace"
        required_controls = @(
            "workspace_classification_gate",
            "export_approval_gate",
            "dlp_pattern_gate"
        )
        evidence = "runtime_registry::data_governance enforcement path"
    },
    [PSCustomObject]@{
        action = "trust_policy_change"
        required_controls = @(
            "admin_reauth",
            "dual_control",
            "typed_confirmation",
            "change_reason_evidence"
        )
        evidence = "policy_integrity_drift_check approval workflow"
    },
    [PSCustomObject]@{
        action = "quarantine_exit"
        required_controls = @(
            "tamper_evident_digest",
            "reattestation",
            "reverification"
        )
        evidence = "incident_response_quarantine release gates"
    },
    [PSCustomObject]@{
        action = "confidential_fallback_to_remote"
        required_controls = @(
            "explicit_one_shot_consent",
            "visible_status_banner",
            "audit_evidence"
        )
        evidence = "ui_shell confidential relay fallback consent handling"
    }
)

$report = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    workspace_root = $workspaceRoot
    check = "trust_zone_approval_matrix_check"
    contract_id = "forge_trust_zone_approval_matrix_v1"
    frozen_at_utc = "2026-03-28T00:00:00Z"
    trust_zones = $trustZones
    approval_matrix = $approvalMatrix
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
    Write-Host "Trust-zone approval-matrix findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "trust-zone approval-matrix check failed"
    }
}
else {
    Write-Host "Trust-zone approval-matrix check passed: $ReportPath"
}
