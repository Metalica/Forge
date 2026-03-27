param(
    [switch]$AllowMissingToolchain = $false,
    [switch]$SkipDependencyAudit = $false
)

$ErrorActionPreference = "Stop"

& "$PSScriptRoot\bootstrap_env.ps1"
$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$securityArtifactRoot = Join-Path $workspaceRoot ".tmp\security"
if (-not (Test-Path $securityArtifactRoot)) {
    New-Item -ItemType Directory -Path $securityArtifactRoot -Force | Out-Null
}

& "$PSScriptRoot\path_guard.ps1"
& "$PSScriptRoot\toolchain_guard.ps1" -AllowMissing:$AllowMissingToolchain
& "$PSScriptRoot\secrets_scan.ps1" -ReportPath (Join-Path $securityArtifactRoot "secret_leak_report.json")
& "$PSScriptRoot\telemetry_scan.ps1" -ReportPath (Join-Path $securityArtifactRoot "telemetry_scan_report.json")
& "$PSScriptRoot\security_check.ps1" -SkipDependencyAudit:$SkipDependencyAudit

Write-Host "Phase 0 checks completed."
