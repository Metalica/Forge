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
    $ReportPath = Join-Path $artifactRoot "deep_linux_sandbox_profile_report.json"
}

$checks = @(
    @{
        name = "process_hardening_unit_tests"
        command = "cargo"
        args = @("test", "-p", "forge_security", "process_hardening::tests::")
    },
    @{
        name = "runtime_process_hardening_launch_validation"
        command = "cargo"
        args = @("test", "-p", "runtime_registry", "launch_request_with_secret_handle_reference_is_allowed")
    }
)

$results = @()
$findings = [System.Collections.Generic.List[string]]::new()

foreach ($check in $checks) {
    $errorText = ""
    $passed = $false
    $started = Get-Date
    try {
        $commandArgs = @($check.args)
        & $check.command @commandArgs
        $passed = ($LASTEXITCODE -eq 0)
        if (-not $passed) {
            $errorText = "command exited with code $LASTEXITCODE"
        }
    }
    catch {
        $passed = $false
        $errorText = $_.Exception.Message
    }
    $durationMs = [int][Math]::Round(((Get-Date) - $started).TotalMilliseconds)

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
    check = "deep_linux_sandbox_profile_check"
    strict_seccomp_env = [Environment]::GetEnvironmentVariable("FORGE_REQUIRE_LINUX_SECCOMP_PROFILE", "Process")
    strict_landlock_env = [Environment]::GetEnvironmentVariable("FORGE_REQUIRE_LINUX_LANDLOCK", "Process")
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
    Write-Host "Deep Linux sandbox profile findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "deep linux sandbox profile check failed"
    }
}
else {
    Write-Host "Deep Linux sandbox profile check passed: $ReportPath"
}
