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
$testRoot = Join-Path $workspaceRoot (".tmp\linux_integrity_enforcement_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

$originalRequireAll = [Environment]::GetEnvironmentVariable("FORGE_REQUIRE_LINUX_INTEGRITY_ENFORCEMENT", "Process")

try {
    $reportPath = Join-Path $testRoot "linux_integrity_enforcement_report.json"
    & "$PSScriptRoot\linux_integrity_enforcement_check.ps1" -ReportPath $reportPath

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "linux integrity enforcement report was not generated."
    }
    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if ($parsed.check -ne "linux_integrity_enforcement_check") {
        throw "Unexpected check id in linux integrity enforcement report."
    }
    if ($null -eq $parsed.schema_version) {
        throw "linux integrity enforcement report missing schema_version."
    }

    if (-not $IsLinux) {
        Set-Or-ClearProcessEnv -Name "FORGE_REQUIRE_LINUX_INTEGRITY_ENFORCEMENT" -Value "1"
        $negativePath = Join-Path $testRoot "linux_integrity_enforcement_negative.json"
        & "$PSScriptRoot\linux_integrity_enforcement_check.ps1" `
            -ReportPath $negativePath `
            -FailOnFindings:$false
        $negative = Get-Content -LiteralPath $negativePath -Raw | ConvertFrom-Json
        if ([bool]$negative.passed) {
            throw "Expected strict Linux integrity requirement to fail on non-linux host."
        }
    }

    Write-Host "linux_integrity_enforcement_check.ps1 self-test passed."
}
finally {
    Set-Or-ClearProcessEnv -Name "FORGE_REQUIRE_LINUX_INTEGRITY_ENFORCEMENT" -Value $originalRequireAll
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
