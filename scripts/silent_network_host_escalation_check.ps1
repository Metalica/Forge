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
    $ReportPath = Join-Path $artifactRoot "silent_network_host_escalation_report.json"
}

$checks = @(
    @{
        name = "runtime_registry_remote_egress_default_fail_closed_test"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "remote_egress_default_is_fail_closed_for_all_workspace_classes")
    },
    @{
        name = "provider_adapter_export_approval_test"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "chat_task_remote_api_requires_export_approval_for_restricted_workspace")
    },
    @{
        name = "control_plane_skill_sandbox_network_default_deny_test"
        command = "cargo"
        args = @("test", "-p", "control_plane", "prepare_launch_blocks_network_by_default")
    },
    @{
        name = "control_plane_extension_enable_requires_permissions_test"
        command = "cargo"
        args = @("test", "-p", "control_plane", "enabling_requires_requested_permissions")
    },
    @{
        name = "runtime_registry_minimal_inherited_env_allowlist_test"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "minimal_inherited_environment_")
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
    check = "silent_network_host_escalation_check"
    controls = [PSCustomObject]@{
        remote_egress_gate_env = "FORGE_ALLOW_REMOTE_EGRESS"
        remote_egress_default = "disabled_without_explicit_opt_in"
        export_approval_env = "FORGE_EXPORT_APPROVED"
        workspace_classification_env = "FORGE_WORKSPACE_CLASSIFICATION"
        skill_network_default = "deny"
        extension_enablement_requires_permissions = $true
        runtime_minimal_env_allowlist = $true
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
    Write-Host "Silent network/host escalation findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "silent network/host escalation check failed"
    }
}
else {
    Write-Host "Silent network/host escalation check passed: $ReportPath"
}
