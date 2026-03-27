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
    $ReportPath = Join-Path $artifactRoot "model_provider_trust_policy_report.json"
}

$checks = @(
    @{
        name = "runtime_registry_model_provider_trust_unit_tests"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "model_provider_trust_policy::tests::")
    },
    @{
        name = "provider_adapter_allowlist_enforcement_test"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "chat_task_remote_api_is_blocked_by_provider_allowlist_policy")
    },
    @{
        name = "provider_adapter_model_risk_tier_enforcement_test"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "chat_task_remote_api_is_blocked_by_model_risk_tier_policy")
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
    check = "model_provider_trust_policy_check"
    controls = [PSCustomObject]@{
        provider_allowlist_env = "FORGE_PROVIDER_ALLOWLIST[_<WORKSPACE>]"
        max_model_risk_tier_env = "FORGE_MAX_MODEL_RISK_TIER[_<WORKSPACE>]"
        signed_sources_env = "FORGE_SIGNED_SOURCE_IDS"
        signed_source_required_env = "FORGE_REQUIRE_SIGNED_MODEL_SOURCES"
        local_manifest_verified_env = "FORGE_LOCAL_MODEL_MANIFEST_VERIFIED_SOURCES"
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
    Write-Host "Model/provider trust policy findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "model/provider trust policy check failed"
    }
}
else {
    Write-Host "Model/provider trust policy check passed: $ReportPath"
}
