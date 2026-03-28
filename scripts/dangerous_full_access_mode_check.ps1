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
    $ReportPath = Join-Path $artifactRoot "dangerous_full_access_mode_report.json"
}

$checks = @(
    @{
        name = "ui_shell_dangerous_extension_controls_flag_test"
        command = "cargo"
        args = @("test", "-p", "ui_shell", "dangerous_extension_controls_flag_is_opt_in_only")
    },
    @{
        name = "control_plane_overbroad_approval_required_test"
        command = "cargo"
        args = @("test", "-p", "control_plane", "overbroad_manifest_requires_explicit_approval")
    },
    @{
        name = "control_plane_destructive_risk_class_enforcement_test"
        command = "cargo"
        args = @("test", "-p", "control_plane", "destructive_tool_scope_is_blocked_when_policy_risk_class_is_not_destructive")
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

$panelAgentPath = Join-Path $workspaceRoot "crates\ui_shell\src\app\panel_agent.rs"
$panelAgentContractVerified = $false
if (-not (Test-Path -LiteralPath $panelAgentPath)) {
    $findings.Add("panel_agent source missing: $panelAgentPath") | Out-Null
}
else {
    $panelAgentRaw = Get-Content -LiteralPath $panelAgentPath -Raw
    if ($panelAgentRaw -notmatch "FORGE_ENABLE_DANGEROUS_EXTENSION_CONTROLS") {
        $findings.Add("panel_agent missing FORGE_ENABLE_DANGEROUS_EXTENSION_CONTROLS gate") | Out-Null
    }
    if ($panelAgentRaw -notmatch "dangerous extension controls are disabled in normal UX") {
        $findings.Add("panel_agent missing normal-UX dangerous-controls block message") | Out-Null
    }
    if ($findings.Count -eq 0) {
        $panelAgentContractVerified = $true
    }
}

$report = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    workspace_root = $workspaceRoot
    check = "dangerous_full_access_mode_check"
    controls = [PSCustomObject]@{
        dangerous_controls_env = "FORGE_ENABLE_DANGEROUS_EXTENSION_CONTROLS"
        dangerous_controls_default = "disabled"
        bulk_permission_grant_policy = "blocked_in_normal_ux"
        overbroad_approval_policy = "blocked_in_normal_ux"
    }
    panel_agent_path = $panelAgentPath
    panel_agent_contract_verified = $panelAgentContractVerified
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
    Write-Host "Dangerous full-access mode findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "dangerous full-access mode check failed"
    }
}
else {
    Write-Host "Dangerous full-access mode check passed: $ReportPath"
}
