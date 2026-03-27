param(
    [ValidateSet("RunOnce", "Monitor")]
    [string]$Mode = "RunOnce",
    [string]$BaselinePath = "",
    [string]$ReportPath = "",
    [string]$QuarantineMarkerPath = "",
    [string]$MonitorReportPath = "",
    [string]$SigningKeyEnv = "FORGE_POLICY_INTEGRITY_KEY_B64",
    [int]$IntervalSeconds = 120,
    [int]$Iterations = 0,
    [switch]$FailOnDrift = $true
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Resolve-WorkspaceRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Resolve-Defaults {
    $workspaceRoot = Resolve-WorkspaceRoot
    $artifactRoot = Join-Path $workspaceRoot ".tmp\security"
    Ensure-Directory -Path $artifactRoot

    if ([string]::IsNullOrWhiteSpace($BaselinePath)) {
        $script:BaselinePath = Join-Path $artifactRoot "policy_integrity_baseline.json"
    }
    if ([string]::IsNullOrWhiteSpace($ReportPath)) {
        $script:ReportPath = Join-Path $artifactRoot "policy_integrity_drift_report.json"
    }
    if ([string]::IsNullOrWhiteSpace($QuarantineMarkerPath)) {
        $script:QuarantineMarkerPath = Join-Path $artifactRoot "QUARANTINE_MODE.flag"
    }
    if ([string]::IsNullOrWhiteSpace($MonitorReportPath)) {
        $script:MonitorReportPath = Join-Path $artifactRoot "policy_integrity_continuous_report.json"
    }
}

function Invoke-VerifyCycle {
    & "$PSScriptRoot\policy_integrity_drift_check.ps1" `
        -Mode Verify `
        -BaselinePath $BaselinePath `
        -ReportPath $ReportPath `
        -QuarantineMarkerPath $QuarantineMarkerPath `
        -SigningKeyEnv $SigningKeyEnv `
        -FailOnDrift:$FailOnDrift
    $parsed = Get-Content -LiteralPath $ReportPath -Raw | ConvertFrom-Json
    return [PSCustomObject]@{
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        signature_valid = [bool]$parsed.signature_valid
        drift_count = [int]$parsed.drift_count
        quarantine_required = [bool]$parsed.quarantine_required
    }
}

function Write-MonitorReport {
    param(
        [Parameter(Mandatory = $true)][object[]]$Cycles,
        [Parameter(Mandatory = $true)][bool]$Passed
    )
    $report = [PSCustomObject]@{
        schema_version = 1
        mode = $Mode
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        baseline_path = $BaselinePath
        report_path = $ReportPath
        quarantine_marker_path = $QuarantineMarkerPath
        fail_on_drift = [bool]$FailOnDrift
        interval_seconds = $IntervalSeconds
        iterations_requested = $Iterations
        iterations_executed = $Cycles.Count
        passed = $Passed
        cycles = $Cycles
    }
    $parent = Split-Path -Parent $MonitorReportPath
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        Ensure-Directory -Path $parent
    }
    $report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $MonitorReportPath -Encoding UTF8
}

Resolve-Defaults

if (-not (Test-Path -LiteralPath $BaselinePath)) {
    throw "Policy integrity baseline is missing at '$BaselinePath'."
}

$cycles = @()
$maxCycles = if ($Mode -eq "RunOnce") { 1 } elseif ($Iterations -gt 0) { $Iterations } else { [int]::MaxValue }
$passed = $true

for ($index = 0; $index -lt $maxCycles; $index++) {
    try {
        $cycle = Invoke-VerifyCycle
        $cycles += $cycle
        if ($cycle.quarantine_required) {
            $passed = $false
            if ($FailOnDrift) {
                break
            }
        }
    }
    catch {
        $cycles += [PSCustomObject]@{
            generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
            signature_valid = $false
            drift_count = -1
            quarantine_required = $true
            error = $_.Exception.Message
        }
        $passed = $false
        if ($FailOnDrift) {
            break
        }
    }

    if ($Mode -eq "RunOnce") {
        break
    }
    Start-Sleep -Seconds $IntervalSeconds
}

Write-MonitorReport -Cycles $cycles -Passed $passed

if (-not $passed -and $FailOnDrift) {
    throw "Policy integrity continuous monitor detected drift; see $MonitorReportPath"
}

Write-Host "Policy integrity continuous monitor report written: $MonitorReportPath"
