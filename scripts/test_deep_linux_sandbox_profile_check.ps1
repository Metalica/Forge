$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$testRoot = Join-Path $workspaceRoot (".tmp\deep_linux_sandbox_profile_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    $reportPath = Join-Path $testRoot "deep_linux_sandbox_profile_report.json"
    & "$PSScriptRoot\deep_linux_sandbox_profile_check.ps1" -ReportPath $reportPath

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "Deep Linux sandbox profile report was not generated."
    }
    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$parsed.passed) {
        throw "Deep Linux sandbox profile report indicates failure."
    }
    if ($parsed.check -ne "deep_linux_sandbox_profile_check") {
        throw "Unexpected check id in deep Linux sandbox profile report."
    }

    Write-Host "deep_linux_sandbox_profile_check.ps1 self-test passed."
}
finally {
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
