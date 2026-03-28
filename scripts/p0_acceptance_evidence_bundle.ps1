param(
    [switch]$FailOnFindings = $true
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $workspaceRoot ".tmp\security"
$bundlePath = Join-Path $artifactRoot "p0_acceptance_evidence_bundle.json"
$argon2Path = Join-Path $artifactRoot "argon2id_benchmark_report.json"
$noncePath = Join-Path $artifactRoot "nonce_uniqueness_report.json"
$policyBaselinePath = Join-Path $artifactRoot "policy_integrity_baseline.json"
$policyReportPath = Join-Path $artifactRoot "policy_integrity_drift_report.json"
$policyQuarantineMarkerPath = Join-Path $artifactRoot "QUARANTINE_MODE.flag"
$policyIntegrityKeyPath = Join-Path $artifactRoot "policy_integrity_key.b64"

if (-not (Test-Path $artifactRoot)) {
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
}

function Ensure-Report {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][scriptblock]$Generator
    )
    if (Test-Path $Path) {
        return
    }
    & $Generator
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

Ensure-Report -Path (Join-Path $artifactRoot "secret_leak_report.json") -Generator {
    & "$PSScriptRoot\secrets_scan.ps1" -ReportPath (Join-Path $artifactRoot "secret_leak_report.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "telemetry_scan_report.json") -Generator {
    & "$PSScriptRoot\telemetry_scan.ps1" -ReportPath (Join-Path $artifactRoot "telemetry_scan_report.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "process_cmdline_secret_scan_report.json") -Generator {
    & "$PSScriptRoot\process_cmdline_secret_scan.ps1" -ReportPath (Join-Path $artifactRoot "process_cmdline_secret_scan_report.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "process_dumpability_scan_report.json") -Generator {
    & "$PSScriptRoot\process_dumpability_scan.ps1" -ReportPath (Join-Path $artifactRoot "process_dumpability_scan_report.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "coredump_profile_scan_report.json") -Generator {
    & "$PSScriptRoot\coredump_profile_scan.ps1" -ReportPath (Join-Path $artifactRoot "coredump_profile_scan_report.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "deep_linux_sandbox_profile_report.json") -Generator {
    & "$PSScriptRoot\deep_linux_sandbox_profile_check.ps1" -ReportPath (Join-Path $artifactRoot "deep_linux_sandbox_profile_report.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "runtime_residual_cleanup_report.json") -Generator {
    & "$PSScriptRoot\runtime_residual_cleanup_check.ps1" -ReportPath (Join-Path $artifactRoot "runtime_residual_cleanup_report.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "dangerous_action_reauth_report.json") -Generator {
    & "$PSScriptRoot\dangerous_action_reauth_check.ps1" -ReportPath (Join-Path $artifactRoot "dangerous_action_reauth_report.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "data_governance_egress_report.json") -Generator {
    & "$PSScriptRoot\data_governance_egress_check.ps1" -ReportPath (Join-Path $artifactRoot "data_governance_egress_report.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "incident_response_quarantine_report.json") -Generator {
    & "$PSScriptRoot\incident_response_quarantine_check.ps1" `
        -ReportPath (Join-Path $artifactRoot "incident_response_quarantine_report.json") `
        -EvidenceDigestPath (Join-Path $artifactRoot "incident_quarantine_evidence_digest.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "model_provider_trust_policy_report.json") -Generator {
    & "$PSScriptRoot\model_provider_trust_policy_check.ps1" -ReportPath (Join-Path $artifactRoot "model_provider_trust_policy_report.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "relay_adversarial_regression_report.json") -Generator {
    & "$PSScriptRoot\relay_adversarial_regression_check.ps1" -ReportPath (Join-Path $artifactRoot "relay_adversarial_regression_report.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "relay_adversarial_corpus_report.json") -Generator {
    & "$PSScriptRoot\relay_adversarial_corpus_check.ps1" -ReportPath (Join-Path $artifactRoot "relay_adversarial_corpus_report.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "boot_host_integrity_report.json") -Generator {
    & "$PSScriptRoot\boot_host_integrity_check.ps1" -ReportPath (Join-Path $artifactRoot "boot_host_integrity_report.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "artifact_supply_chain_integrity_report.json") -Generator {
    & "$PSScriptRoot\artifact_supply_chain_integrity_check.ps1" `
        -ReportPath (Join-Path $artifactRoot "artifact_supply_chain_integrity_report.json") `
        -SbomPath (Join-Path $artifactRoot "forge_workspace_sbom.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "linux_integrity_enforcement_report.json") -Generator {
    & "$PSScriptRoot\linux_integrity_enforcement_check.ps1" -ReportPath (Join-Path $artifactRoot "linux_integrity_enforcement_report.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "telemetry_split_redaction_report.json") -Generator {
    & "$PSScriptRoot\telemetry_split_redaction_check.ps1"
}
Ensure-Report -Path (Join-Path $artifactRoot "kek_custody_matrix.json") -Generator {
    & "$PSScriptRoot\kek_custody_matrix_check.ps1"
}
Ensure-PolicyIntegrityKey -KeyPath $policyIntegrityKeyPath -EnvName "FORGE_POLICY_INTEGRITY_KEY_B64"
Ensure-Report -Path $policyBaselinePath -Generator {
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
Ensure-Report -Path (Join-Path $artifactRoot "policy_integrity_continuous_report.json") -Generator {
    & "$PSScriptRoot\policy_integrity_continuous_monitor.ps1" `
        -Mode RunOnce `
        -BaselinePath $policyBaselinePath `
        -ReportPath $policyReportPath `
        -QuarantineMarkerPath $policyQuarantineMarkerPath `
        -MonitorReportPath (Join-Path $artifactRoot "policy_integrity_continuous_report.json") `
        -SigningKeyEnv "FORGE_POLICY_INTEGRITY_KEY_B64" `
        -FailOnDrift:$false
}

& cargo run -p forge_security --bin argon2id_bench_report -- --out $argon2Path --runs 4
if ($LASTEXITCODE -ne 0) {
    throw "argon2id benchmark report generation failed"
}

$nonceCommand = "cargo test -p forge_security persisted_encryption_nonces_are_unique_across_records"
& cargo test -p forge_security persisted_encryption_nonces_are_unique_across_records
$noncePassed = ($LASTEXITCODE -eq 0)
$nonceReport = [PSCustomObject]@{
    schema_version    = 1
    generated_at_utc  = (Get-Date).ToUniversalTime().ToString("o")
    test_name         = "persisted_encryption_nonces_are_unique_across_records"
    command           = $nonceCommand
    passed            = $noncePassed
}
$nonceReport | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $noncePath -Encoding UTF8
if (-not $noncePassed) {
    throw "nonce uniqueness regression test failed"
}

$artifactSpecs = @(
    @{ name = "secret_leak_report"; path = (Join-Path $artifactRoot "secret_leak_report.json"); requirePassed = $true },
    @{ name = "telemetry_scan_report"; path = (Join-Path $artifactRoot "telemetry_scan_report.json"); requirePassed = $true },
    @{ name = "process_cmdline_secret_scan_report"; path = (Join-Path $artifactRoot "process_cmdline_secret_scan_report.json"); requirePassed = $true },
    @{ name = "process_dumpability_scan_report"; path = (Join-Path $artifactRoot "process_dumpability_scan_report.json"); requirePassed = $true },
    @{ name = "coredump_profile_scan_report"; path = (Join-Path $artifactRoot "coredump_profile_scan_report.json"); requirePassed = $true },
    @{ name = "deep_linux_sandbox_profile_report"; path = (Join-Path $artifactRoot "deep_linux_sandbox_profile_report.json"); requirePassed = $true },
    @{ name = "runtime_residual_cleanup_report"; path = (Join-Path $artifactRoot "runtime_residual_cleanup_report.json"); requirePassed = $true },
    @{ name = "dangerous_action_reauth_report"; path = (Join-Path $artifactRoot "dangerous_action_reauth_report.json"); requirePassed = $true },
    @{ name = "data_governance_egress_report"; path = (Join-Path $artifactRoot "data_governance_egress_report.json"); requirePassed = $true },
    @{ name = "incident_response_quarantine_report"; path = (Join-Path $artifactRoot "incident_response_quarantine_report.json"); requirePassed = $true },
    @{ name = "model_provider_trust_policy_report"; path = (Join-Path $artifactRoot "model_provider_trust_policy_report.json"); requirePassed = $true },
    @{ name = "relay_adversarial_regression_report"; path = (Join-Path $artifactRoot "relay_adversarial_regression_report.json"); requirePassed = $true },
    @{ name = "relay_adversarial_corpus_report"; path = (Join-Path $artifactRoot "relay_adversarial_corpus_report.json"); requirePassed = $true },
    @{ name = "boot_host_integrity_report"; path = (Join-Path $artifactRoot "boot_host_integrity_report.json"); requirePassed = $true },
    @{ name = "artifact_supply_chain_integrity_report"; path = (Join-Path $artifactRoot "artifact_supply_chain_integrity_report.json"); requirePassed = $true },
    @{ name = "linux_integrity_enforcement_report"; path = (Join-Path $artifactRoot "linux_integrity_enforcement_report.json"); requirePassed = $true },
    @{ name = "telemetry_split_redaction_report"; path = (Join-Path $artifactRoot "telemetry_split_redaction_report.json"); requirePassed = $true },
    @{ name = "broker_audit_events"; path = (Join-Path $artifactRoot "broker_audit_events.json"); requirePassed = $false },
    @{ name = "provider_adapter_audit_events"; path = (Join-Path $artifactRoot "provider_adapter_audit_events.json"); requirePassed = $false },
    @{ name = "kek_custody_matrix"; path = (Join-Path $artifactRoot "kek_custody_matrix.json"); requirePassed = $false },
    @{ name = "incident_quarantine_evidence_digest"; path = (Join-Path $artifactRoot "incident_quarantine_evidence_digest.json"); requirePassed = $false },
    @{ name = "argon2id_benchmark_report"; path = $argon2Path; requirePassed = $false },
    @{ name = "nonce_uniqueness_report"; path = $noncePath; requirePassed = $true },
    @{ name = "policy_integrity_drift_report"; path = $policyReportPath; requirePassed = $false },
    @{ name = "policy_integrity_continuous_report"; path = (Join-Path $artifactRoot "policy_integrity_continuous_report.json"); requirePassed = $true }
)

$artifactRows = @()
$gatePassed = $true

foreach ($spec in $artifactSpecs) {
    $present = Test-Path $spec.path
    $parsed = $null
    $passed = $present
    $detail = ""

    if (-not $present) {
        $passed = $false
        $detail = "artifact missing"
    }
    else {
        try {
            $raw = Get-Content -LiteralPath $spec.path -Raw -ErrorAction Stop
            $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
            if ($spec.requirePassed) {
                if ($null -eq $parsed.passed) {
                    $passed = $false
                    $detail = "artifact missing passed flag"
                }
                elseif (-not [bool]$parsed.passed) {
                    $passed = $false
                    $detail = "artifact reported failure"
                }
            }
            if ($passed -and $null -eq $parsed.schema_version) {
                $passed = $false
                $detail = "artifact missing schema_version"
            }
            if ($passed -and $spec.name -eq "policy_integrity_drift_report") {
                if ($null -eq $parsed.signature_valid) {
                    $passed = $false
                    $detail = "policy integrity report missing signature_valid"
                }
                elseif (-not [bool]$parsed.signature_valid) {
                    $passed = $false
                    $detail = "policy integrity signature validation failed"
                }
                elseif ([bool]$parsed.quarantine_required) {
                    $passed = $false
                    $detail = "policy integrity drift check requires quarantine"
                }
            }
        }
        catch {
            $passed = $false
            $detail = "artifact parse error: $($_.Exception.Message)"
        }
    }

    $artifactRows += [PSCustomObject]@{
        name = $spec.name
        path = $spec.path
        present = $present
        passed = $passed
        detail = $detail
    }

    if (-not $passed) {
        $gatePassed = $false
    }
}

$bundle = [PSCustomObject]@{
    schema_version   = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    artifact_root    = $artifactRoot
    gate_passed      = $gatePassed
    artifacts        = $artifactRows
}

$bundle | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $bundlePath -Encoding UTF8

if (-not $gatePassed) {
    Write-Host "P0 acceptance evidence bundle contains failing artifacts:"
    foreach ($row in $artifactRows | Where-Object { -not $_.passed }) {
        Write-Host " - $($row.name): $($row.detail)"
    }
    if ($FailOnFindings) {
        throw "P0 acceptance evidence bundle failed"
    }
}
else {
    Write-Host "P0 acceptance evidence bundle generated: $bundlePath"
}
