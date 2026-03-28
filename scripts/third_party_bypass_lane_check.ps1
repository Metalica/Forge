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
    $ReportPath = Join-Path $artifactRoot "third_party_bypass_lane_report.json"
}

$checks = @(
    @{
        name = "runtime_registry_local_api_allowlist_query_bypass_test"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "hardening_blocks_allowlist_bypass_when_allowed_path_appears_only_in_query")
    },
    @{
        name = "provider_adapter_policy_telemetry_bypass_route_test"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "local_api_hardening_blocks_policy_and_telemetry_bypass_routes")
    },
    @{
        name = "provider_adapter_direct_db_surface_bypass_route_test"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "local_api_hardening_blocks_direct_db_surface_routes")
    },
    @{
        name = "control_plane_mcp_scope_audience_enforcement_test"
        command = "cargo"
        args = @("test", "-p", "control_plane", "mcp_scoped_token_authorization_enforces_scope_and_audience")
    },
    @{
        name = "control_plane_mcp_scope_declaration_enforcement_test"
        command = "cargo"
        args = @("test", "-p", "control_plane", "mcp_token_issue_blocks_undeclared_scopes")
    },
    @{
        name = "control_plane_bridge_session_binding_test"
        command = "cargo"
        args = @("test", "-p", "control_plane", "issue_fails_when_session_extension_mismatches")
    },
    @{
        name = "control_plane_snapshot_restore_manifest_bypass_test"
        command = "cargo"
        args = @("test", "-p", "control_plane", "restore_snapshot_unsigned_manifest_is_isolated_fail_closed")
    },
    @{
        name = "control_plane_snapshot_restore_permission_bypass_test"
        command = "cargo"
        args = @("test", "-p", "control_plane", "restore_snapshot_enabled_state_requires_granted_permissions")
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
    check = "third_party_bypass_lane_check"
    controls = [PSCustomObject]@{
        local_api_bridge_policy_enforcement = $true
        extension_manifest_security_revalidated_on_restore = $true
        extension_permission_requirements_revalidated_on_restore = $true
        mcp_scoped_token_and_audience_enforcement = $true
        mcp_bridge_session_extension_binding = $true
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
    Write-Host "Third-party bypass lane findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "third-party bypass lane check failed"
    }
}
else {
    Write-Host "Third-party bypass lane check passed: $ReportPath"
}
