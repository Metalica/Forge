param(
    [switch]$AllowMissingToolchain = $false,
    [switch]$SkipDependencyAudit = $false
)

$ErrorActionPreference = "Stop"

& "$PSScriptRoot\bootstrap_env.ps1"
& "$PSScriptRoot\path_guard.ps1"
& "$PSScriptRoot\toolchain_guard.ps1" -AllowMissing:$AllowMissingToolchain
& "$PSScriptRoot\secrets_scan.ps1"
& "$PSScriptRoot\telemetry_scan.ps1"
& "$PSScriptRoot\security_check.ps1" -SkipDependencyAudit:$SkipDependencyAudit

Write-Host "Phase 0 checks completed."
