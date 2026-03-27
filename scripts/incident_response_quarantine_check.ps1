param(
    [switch]$FailOnFindings = $true,
    [string]$ReportPath = "",
    [string]$EvidenceBundlePath = "",
    [string]$EvidenceDigestPath = "",
    [switch]$SkipEvidenceBundleGeneration = $false
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $workspaceRoot ".tmp\security"
if (-not (Test-Path -LiteralPath $artifactRoot)) {
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
}
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $artifactRoot "incident_response_quarantine_report.json"
}
if ([string]::IsNullOrWhiteSpace($EvidenceBundlePath)) {
    $EvidenceBundlePath = Join-Path $artifactRoot "p0_acceptance_evidence_bundle.json"
}
if ([string]::IsNullOrWhiteSpace($EvidenceDigestPath)) {
    $EvidenceDigestPath = Join-Path $artifactRoot "incident_quarantine_evidence_digest.json"
}

if (-not (Test-Path -LiteralPath $EvidenceBundlePath) -and -not $SkipEvidenceBundleGeneration) {
    & "$PSScriptRoot\p0_acceptance_evidence_bundle.ps1"
}

$evidenceDigest = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    evidence_bundle_path = $EvidenceBundlePath
    sha256 = ""
}

if (Test-Path -LiteralPath $EvidenceBundlePath) {
    $hash = Get-FileHash -LiteralPath $EvidenceBundlePath -Algorithm SHA256
    $evidenceDigest.sha256 = $hash.Hash.ToLowerInvariant()
}

$digestParent = Split-Path -Parent $EvidenceDigestPath
if (-not [string]::IsNullOrWhiteSpace($digestParent) -and -not (Test-Path -LiteralPath $digestParent)) {
    New-Item -ItemType Directory -Path $digestParent -Force | Out-Null
}
$evidenceDigest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $EvidenceDigestPath -Encoding UTF8

$checks = @(
    @{
        name = "runtime_registry_incident_quarantine_unit_tests"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "incident_response_quarantine::tests::")
    },
    @{
        name = "provider_adapter_quarantine_recovery_allowlist_test"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "chat_task_remote_api_is_blocked_in_quarantine_mode_when_endpoint_not_recovery_allowlisted")
    },
    @{
        name = "provider_adapter_confidential_relay_quarantine_block_test"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "confidential_chat_task_is_blocked_when_quarantine_mode_enabled")
    },
    @{
        name = "extension_host_quarantine_freeze_enable_test"
        command = "cargo"
        args = @("test", "-p", "control_plane", "quarantine_mode_blocks_extension_enablement")
    },
    @{
        name = "extension_host_quarantine_freeze_mcp_test"
        command = "cargo"
        args = @("test", "-p", "control_plane", "quarantine_mode_blocks_mcp_issue_and_authorization")
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

$report = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    workspace_root = $workspaceRoot
    check = "incident_response_quarantine_check"
    controls = [PSCustomObject]@{
        quarantine_mode_env = "FORGE_QUARANTINE_MODE"
        recovery_allowlist_env = "FORGE_QUARANTINE_RECOVERY_ENDPOINTS"
        freeze_envs = @(
            "FORGE_QUARANTINE_EXTENSIONS_FROZEN",
            "FORGE_QUARANTINE_MCP_FROZEN"
        )
        cleanup_envs = @(
            "FORGE_QUARANTINE_SECRET_HANDLES_REVOKED",
            "FORGE_QUARANTINE_CACHES_INVALIDATED",
            "FORGE_QUARANTINE_MEMORY_LANES_INVALIDATED"
        )
        relay_block_env = "FORGE_QUARANTINE_RELAY_BLOCKED"
        release_gates = @(
            "FORGE_QUARANTINE_REATTESTED",
            "FORGE_QUARANTINE_REVERIFIED"
        )
    }
    evidence_bundle_path = $EvidenceBundlePath
    evidence_digest_path = $EvidenceDigestPath
    evidence_sha256 = $evidenceDigest.sha256
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
    Write-Host "Incident-response quarantine findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "incident response quarantine check failed"
    }
}
else {
    Write-Host "Incident-response quarantine check passed: $ReportPath"
}
