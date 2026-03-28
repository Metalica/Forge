$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$testRoot = Join-Path $workspaceRoot (".tmp\dangerous_action_reauth_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    $reportPath = Join-Path $testRoot "dangerous_action_reauth_report.json"
    & "$PSScriptRoot\dangerous_action_reauth_check.ps1" -ReportPath $reportPath

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "dangerous-action re-auth report was not generated."
    }
    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$parsed.passed) {
        throw "dangerous-action re-auth report indicates failure."
    }
    if ($parsed.check -ne "dangerous_action_reauth_check") {
        throw "Unexpected check id in dangerous-action re-auth report."
    }
    $requiredActions = @($parsed.required_actions | ForEach-Object { [string]$_ })
    if ($requiredActions -notcontains "forensic_reset_bypass") {
        throw "dangerous-action re-auth report is missing forensic_reset_bypass required action."
    }
    if ($null -eq $parsed.action_coverage -or [string]::IsNullOrWhiteSpace([string]$parsed.action_coverage.forensic_reset_bypass)) {
        throw "dangerous-action re-auth report is missing forensic_reset_bypass action coverage mapping."
    }

    Write-Host "dangerous_action_reauth_check.ps1 self-test passed."
}
finally {
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
