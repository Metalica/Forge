param(
    [switch]$SkipDependencyAudit = $false
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

& "$PSScriptRoot\bootstrap_env.ps1"
& "$PSScriptRoot\process_cmdline_secret_scan.ps1"
& "$PSScriptRoot\coredump_profile_scan.ps1"
& "$PSScriptRoot\broker_audit_export_check.ps1"

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
