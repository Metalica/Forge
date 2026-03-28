param(
    [switch]$SkipDependencyAudit = $false
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

& "$PSScriptRoot\bootstrap_env.ps1"
$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$securityArtifactRoot = Join-Path $workspaceRoot ".tmp\security"
if (-not (Test-Path $securityArtifactRoot)) {
    New-Item -ItemType Directory -Path $securityArtifactRoot -Force | Out-Null
}

function Ensure-PolicyIntegrityKey {
    param(
        [Parameter(Mandatory = $true)][string]$KeyPath,
        [Parameter(Mandatory = $true)][string]$EnvName
    )

    $existing = [Environment]::GetEnvironmentVariable($EnvName, "Process")
    if (-not [string]::IsNullOrWhiteSpace($existing)) {
        return
    }

    if (Test-Path -LiteralPath $KeyPath) {
        $persisted = (Get-Content -LiteralPath $KeyPath -Raw).Trim()
        if (-not [string]::IsNullOrWhiteSpace($persisted)) {
            [Environment]::SetEnvironmentVariable($EnvName, $persisted, "Process")
            return
        }
    }

    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    $generated = [Convert]::ToBase64String($bytes)
    Set-Content -LiteralPath $KeyPath -Value $generated -Encoding UTF8
    [Environment]::SetEnvironmentVariable($EnvName, $generated, "Process")
}

& "$PSScriptRoot\process_cmdline_secret_scan.ps1" -ReportPath (Join-Path $securityArtifactRoot "process_cmdline_secret_scan_report.json")
& "$PSScriptRoot\process_dumpability_scan.ps1" -ReportPath (Join-Path $securityArtifactRoot "process_dumpability_scan_report.json")
& "$PSScriptRoot\coredump_profile_scan.ps1" -ReportPath (Join-Path $securityArtifactRoot "coredump_profile_scan_report.json")
& "$PSScriptRoot\telemetry_split_redaction_check.ps1"
& "$PSScriptRoot\kek_custody_matrix_check.ps1"
& "$PSScriptRoot\deep_linux_sandbox_profile_check.ps1" -ReportPath (Join-Path $securityArtifactRoot "deep_linux_sandbox_profile_report.json")
& "$PSScriptRoot\runtime_residual_cleanup_check.ps1" -ReportPath (Join-Path $securityArtifactRoot "runtime_residual_cleanup_report.json")
& "$PSScriptRoot\dangerous_action_reauth_check.ps1" -ReportPath (Join-Path $securityArtifactRoot "dangerous_action_reauth_report.json")
& "$PSScriptRoot\trust_zone_approval_matrix_check.ps1" -ReportPath (Join-Path $securityArtifactRoot "trust_zone_approval_matrix_report.json")
& "$PSScriptRoot\dangerous_full_access_mode_check.ps1" -ReportPath (Join-Path $securityArtifactRoot "dangerous_full_access_mode_report.json")
& "$PSScriptRoot\data_governance_egress_check.ps1" -ReportPath (Join-Path $securityArtifactRoot "data_governance_egress_report.json")
& "$PSScriptRoot\incident_response_quarantine_check.ps1" -ReportPath (Join-Path $securityArtifactRoot "incident_response_quarantine_report.json")
& "$PSScriptRoot\model_provider_trust_policy_check.ps1" -ReportPath (Join-Path $securityArtifactRoot "model_provider_trust_policy_report.json")
& "$PSScriptRoot\forensic_reset_quarantine_drill_check.ps1" -ReportPath (Join-Path $securityArtifactRoot "forensic_reset_quarantine_drill_report.json")
& "$PSScriptRoot\relay_adversarial_regression_check.ps1" -ReportPath (Join-Path $securityArtifactRoot "relay_adversarial_regression_report.json")
& "$PSScriptRoot\relay_adversarial_corpus_check.ps1" -ReportPath (Join-Path $securityArtifactRoot "relay_adversarial_corpus_report.json")
& "$PSScriptRoot\relay_attack_corpus_maintenance_check.ps1" -ReportPath (Join-Path $securityArtifactRoot "relay_attack_corpus_maintenance_report.json")
& "$PSScriptRoot\boot_host_integrity_check.ps1" -ReportPath (Join-Path $securityArtifactRoot "boot_host_integrity_report.json")
& "$PSScriptRoot\artifact_supply_chain_integrity_check.ps1" `
    -ReportPath (Join-Path $securityArtifactRoot "artifact_supply_chain_integrity_report.json") `
    -SbomPath (Join-Path $securityArtifactRoot "forge_workspace_sbom.json")
& "$PSScriptRoot\runtime_update_chain_integrity_check.ps1" `
    -ReportPath (Join-Path $securityArtifactRoot "runtime_update_chain_integrity_report.json")
& "$PSScriptRoot\release_candidate_secret_leak_check.ps1" `
    -ReportPath (Join-Path $securityArtifactRoot "release_candidate_secret_leak_report.json")
& "$PSScriptRoot\relay_green_regression_suite_check.ps1" `
    -ReportPath (Join-Path $securityArtifactRoot "relay_green_regression_suite_report.json")
& "$PSScriptRoot\linux_integrity_enforcement_check.ps1" -ReportPath (Join-Path $securityArtifactRoot "linux_integrity_enforcement_report.json")

$policyBaselinePath = Join-Path $securityArtifactRoot "policy_integrity_baseline.json"
$policyReportPath = Join-Path $securityArtifactRoot "policy_integrity_drift_report.json"
$policyQuarantineMarkerPath = Join-Path $securityArtifactRoot "QUARANTINE_MODE.flag"
$policyIntegrityKeyPath = Join-Path $securityArtifactRoot "policy_integrity_key.b64"
Ensure-PolicyIntegrityKey -KeyPath $policyIntegrityKeyPath -EnvName "FORGE_POLICY_INTEGRITY_KEY_B64"
if (-not (Test-Path -LiteralPath $policyBaselinePath)) {
    & "$PSScriptRoot\policy_integrity_drift_check.ps1" `
        -Mode Baseline `
        -BaselinePath $policyBaselinePath `
        -ReportPath $policyReportPath `
        -QuarantineMarkerPath $policyQuarantineMarkerPath `
        -SigningKeyEnv "FORGE_POLICY_INTEGRITY_KEY_B64"
}
& "$PSScriptRoot\policy_integrity_drift_check.ps1" `
    -Mode Verify `
    -BaselinePath $policyBaselinePath `
    -ReportPath $policyReportPath `
    -QuarantineMarkerPath $policyQuarantineMarkerPath `
    -SigningKeyEnv "FORGE_POLICY_INTEGRITY_KEY_B64" `
    -FailOnDrift:$false
& "$PSScriptRoot\policy_integrity_continuous_monitor.ps1" `
    -Mode RunOnce `
    -BaselinePath $policyBaselinePath `
    -ReportPath $policyReportPath `
    -QuarantineMarkerPath $policyQuarantineMarkerPath `
    -MonitorReportPath (Join-Path $securityArtifactRoot "policy_integrity_continuous_report.json") `
    -SigningKeyEnv "FORGE_POLICY_INTEGRITY_KEY_B64" `
    -FailOnDrift:$false

& "$PSScriptRoot\test_runtime_secure_backup_import.ps1"
& "$PSScriptRoot\test_policy_integrity_drift_check.ps1"
& "$PSScriptRoot\test_policy_integrity_continuous_monitor.ps1"
& "$PSScriptRoot\test_deep_linux_sandbox_profile_check.ps1"
& "$PSScriptRoot\test_runtime_residual_cleanup_check.ps1"
& "$PSScriptRoot\test_dangerous_action_reauth_check.ps1"
& "$PSScriptRoot\test_trust_zone_approval_matrix_check.ps1"
& "$PSScriptRoot\test_dangerous_full_access_mode_check.ps1"
& "$PSScriptRoot\test_data_governance_egress_check.ps1"
& "$PSScriptRoot\test_incident_response_quarantine_check.ps1"
& "$PSScriptRoot\test_forensic_reset_quarantine_drill_check.ps1"
& "$PSScriptRoot\test_model_provider_trust_policy_check.ps1"
& "$PSScriptRoot\test_relay_adversarial_regression_check.ps1"
& "$PSScriptRoot\test_relay_adversarial_corpus_check.ps1"
& "$PSScriptRoot\test_relay_attack_corpus_maintenance_check.ps1"
& "$PSScriptRoot\test_boot_host_integrity_check.ps1"
& "$PSScriptRoot\test_artifact_supply_chain_integrity_check.ps1"
& "$PSScriptRoot\test_runtime_update_chain_integrity_check.ps1"
& "$PSScriptRoot\test_release_candidate_secret_leak_check.ps1"
& "$PSScriptRoot\test_relay_green_regression_suite_check.ps1"
& "$PSScriptRoot\test_linux_integrity_enforcement_check.ps1"
& "$PSScriptRoot\test_release_security_regression_block_check.ps1"

& "$PSScriptRoot\p0_acceptance_evidence_bundle.ps1"
& "$PSScriptRoot\release_security_regression_block_check.ps1" -ReportPath (Join-Path $securityArtifactRoot "release_security_regression_block_report.json")

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $false)][string[]]$Arguments = @()
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $Command $($Arguments -join ' ')"
    }
}

Write-Host "Running rustfmt check..."
Invoke-Checked -Command "cargo" -Arguments @("fmt", "--all", "--", "--check")

Write-Host "Running clippy..."
Invoke-Checked -Command "cargo" -Arguments @("clippy", "--workspace", "--all-targets", "--", "-D", "warnings")

Write-Host "Running tests..."
Invoke-Checked -Command "cargo" -Arguments @("test", "--workspace")

if (-not $SkipDependencyAudit) {
    if (Get-Command cargo-audit -ErrorAction SilentlyContinue) {
        Write-Host "Running cargo-audit..."
        $cargoAuditArgs = @(
            "audit",
            "--deny",
            "warnings"
        )
        Invoke-Checked -Command "cargo" -Arguments $cargoAuditArgs
    }
    else {
        throw "cargo-audit not found. Install with: cargo install cargo-audit"
    }

    if (Get-Command cargo-deny -ErrorAction SilentlyContinue) {
        Write-Host "Running cargo-deny..."
        Invoke-Checked -Command "cargo" -Arguments @("deny", "check", "advisories", "bans", "sources")
    }
    else {
        throw "cargo-deny not found. Install with: cargo install cargo-deny"
    }
}

Write-Host "Security check completed."
