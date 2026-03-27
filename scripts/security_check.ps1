param(
    [switch]$SkipDependencyAudit = $false
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

& "$PSScriptRoot\bootstrap_env.ps1"
$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$securityArtifactRoot = Join-Path $workspaceRoot ".tmp\security"
if (-not (Test-Path $securityArtifactRoot)) {
    New-Item -ItemType Directory -Path $securityArtifactRoot -Force | Out-Null
}

& "$PSScriptRoot\process_cmdline_secret_scan.ps1" -ReportPath (Join-Path $securityArtifactRoot "process_cmdline_secret_scan_report.json")
& "$PSScriptRoot\process_dumpability_scan.ps1" -ReportPath (Join-Path $securityArtifactRoot "process_dumpability_scan_report.json")
& "$PSScriptRoot\coredump_profile_scan.ps1" -ReportPath (Join-Path $securityArtifactRoot "coredump_profile_scan_report.json")
& "$PSScriptRoot\telemetry_split_redaction_check.ps1"
& "$PSScriptRoot\kek_custody_matrix_check.ps1"
& "$PSScriptRoot\p0_acceptance_evidence_bundle.ps1"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $false)][string[]]$Arguments = @()
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $Command $($Arguments -join ' ')"
    }
}

Write-Host "Running rustfmt check..."
Invoke-Checked -Command "cargo" -Arguments @("fmt", "--all", "--", "--check")

Write-Host "Running clippy..."
Invoke-Checked -Command "cargo" -Arguments @("clippy", "--workspace", "--all-targets", "--", "-D", "warnings")

Write-Host "Running tests..."
Invoke-Checked -Command "cargo" -Arguments @("test", "--workspace")

if (-not $SkipDependencyAudit) {
    if (Get-Command cargo-audit -ErrorAction SilentlyContinue) {
        Write-Host "Running cargo-audit..."
        $cargoAuditArgs = @(
            "audit",
            "--deny",
            "warnings"
        )
        Invoke-Checked -Command "cargo" -Arguments $cargoAuditArgs
    }
    else {
        throw "cargo-audit not found. Install with: cargo install cargo-audit"
    }

    if (Get-Command cargo-deny -ErrorAction SilentlyContinue) {
        Write-Host "Running cargo-deny..."
        Invoke-Checked -Command "cargo" -Arguments @("deny", "check", "advisories", "bans", "sources")
    }
    else {
        throw "cargo-deny not found. Install with: cargo install cargo-deny"
    }
}

Write-Host "Security check completed."
