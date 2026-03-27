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
    $ReportPath = Join-Path $artifactRoot "data_governance_egress_report.json"
}

$checks = @(
    @{
        name = "runtime_registry_data_governance_unit_tests"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "data_governance::tests::")
    },
    @{
        name = "provider_adapter_dlp_block_test"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "chat_task_remote_api_is_blocked_by_data_governance_dlp_policy")
    },
    @{
        name = "provider_adapter_export_approval_test"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "chat_task_remote_api_requires_export_approval_for_restricted_workspace")
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
    check = "data_governance_egress_check"
    controls = [PSCustomObject]@{
        workspace_classification_env = "FORGE_WORKSPACE_CLASSIFICATION"
        remote_egress_gate_env = "FORGE_ALLOW_REMOTE_EGRESS"
        export_approval_env = "FORGE_EXPORT_APPROVED"
        dlp_patterns_env = "FORGE_DLP_BLOCK_PATTERNS"
        retention_days_env = "FORGE_WORKSPACE_RETENTION_DAYS"
    }
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
    Write-Host "Data-governance egress findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "data governance egress check failed"
    }
}
else {
    Write-Host "Data-governance egress check passed: $ReportPath"
}
