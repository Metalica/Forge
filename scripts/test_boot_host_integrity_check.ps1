$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Set-Or-ClearProcessEnv {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][string]$Value
    )
    if ($null -eq $Value) {
        [Environment]::SetEnvironmentVariable($Name, $null, "Process")
    }
    else {
        [Environment]::SetEnvironmentVariable($Name, $Value, "Process")
    }
}

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$testRoot = Join-Path $workspaceRoot (".tmp\boot_host_integrity_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

$originalState = [Environment]::GetEnvironmentVariable("FORGE_HOST_INTEGRITY_STATE", "Process")
$originalRequireTrusted = [Environment]::GetEnvironmentVariable("FORGE_REQUIRE_HOST_INTEGRITY_TRUSTED", "Process")
$originalHighTrustMode = [Environment]::GetEnvironmentVariable("FORGE_HIGH_TRUST_MODE", "Process")

try {
    $reportPath = Join-Path $testRoot "boot_host_integrity_report.json"
    & "$PSScriptRoot\boot_host_integrity_check.ps1" -ReportPath $reportPath

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "boot/host integrity report was not generated."
    }
    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if ($parsed.check -ne "boot_host_integrity_check") {
        throw "Unexpected check id in boot/host integrity report."
    }
    if ($null -eq $parsed.schema_version) {
        throw "boot/host integrity report missing schema_version."
    }

    Set-Or-ClearProcessEnv -Name "FORGE_HOST_INTEGRITY_STATE" -Value "degraded"
    Set-Or-ClearProcessEnv -Name "FORGE_REQUIRE_HOST_INTEGRITY_TRUSTED" -Value "1"
    Set-Or-ClearProcessEnv -Name "FORGE_HIGH_TRUST_MODE" -Value "1"

    $negativePath = Join-Path $testRoot "boot_host_integrity_report_negative.json"
    & "$PSScriptRoot\boot_host_integrity_check.ps1" -ReportPath $negativePath -FailOnFindings:$false
    $negative = Get-Content -LiteralPath $negativePath -Raw | ConvertFrom-Json
    if ([bool]$negative.passed) {
        throw "Expected degraded override scenario to fail boot/host integrity check."
    }
    if ([int]$negative.findings_count -lt 1) {
        throw "Expected findings in degraded override scenario."
    }

    Write-Host "boot_host_integrity_check.ps1 self-test passed."
}
finally {
    Set-Or-ClearProcessEnv -Name "FORGE_HOST_INTEGRITY_STATE" -Value $originalState
    Set-Or-ClearProcessEnv -Name "FORGE_REQUIRE_HOST_INTEGRITY_TRUSTED" -Value $originalRequireTrusted
    Set-Or-ClearProcessEnv -Name "FORGE_HIGH_TRUST_MODE" -Value $originalHighTrustMode
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
