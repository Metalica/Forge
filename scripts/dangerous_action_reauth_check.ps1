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
    $ReportPath = Join-Path $artifactRoot "dangerous_action_reauth_report.json"
}

$checks = @(
    @{
        name = "runtime_secure_backup_import_reauth_and_typed_confirmation"
        command = "powershell"
        args = @("-ExecutionPolicy", "Bypass", "-File", (Join-Path $PSScriptRoot "test_runtime_secure_backup_import.ps1"))
    },
    @{
        name = "policy_integrity_drift_reauth_dual_control"
        command = "powershell"
        args = @("-ExecutionPolicy", "Bypass", "-File", (Join-Path $PSScriptRoot "test_policy_integrity_drift_check.ps1"))
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
    check = "dangerous_action_reauth_check"
    required_actions = @(
        "secret_export",
        "runtime_import",
        "trust_policy_change"
    )
    preferred_phishing_resistant_auth_env = "FORGE_REQUIRE_PHISHING_RESISTANT_AUTH"
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
    Write-Host "Dangerous-action re-auth findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "dangerous action re-auth check failed"
    }
}
else {
    Write-Host "Dangerous-action re-auth check passed: $ReportPath"
}
