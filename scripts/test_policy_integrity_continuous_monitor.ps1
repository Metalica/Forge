$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function New-RandomBase64Key {
    param([int]$Length = 32)
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    return [Convert]::ToBase64String($bytes)
}

function Get-RelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$BasePath,
        [Parameter(Mandatory = $true)][string]$TargetPath
    )
    $base = (Resolve-Path -LiteralPath $BasePath).Path.TrimEnd("\")
    $target = (Resolve-Path -LiteralPath $TargetPath).Path
    $baseUri = New-Object System.Uri(($base + "\"))
    $targetUri = New-Object System.Uri($target)
    $relativeUri = $baseUri.MakeRelativeUri($targetUri)
    return [System.Uri]::UnescapeDataString($relativeUri.ToString()).Replace("/", "\")
}

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$testRoot = Join-Path $workspaceRoot (".tmp\policy_integrity_continuous_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    $watchedFile = Join-Path $testRoot "watched_policy.json"
    Set-Content -LiteralPath $watchedFile -Value '{"policy":"v1"}' -Encoding UTF8
    $relativeWatched = (Get-RelativePath -BasePath $workspaceRoot -TargetPath $watchedFile).Replace("\", "/")

    $baselinePath = Join-Path $testRoot "baseline.json"
    $verifyReportPath = Join-Path $testRoot "verify_report.json"
    $monitorReportPath = Join-Path $testRoot "continuous_report.json"
    $markerPath = Join-Path $testRoot "QUARANTINE_MODE.flag"

    $signingEnv = "FORGE_POLICY_INTEGRITY_KEY_B64"
    [Environment]::SetEnvironmentVariable($signingEnv, (New-RandomBase64Key), "Process")

    & "$PSScriptRoot\policy_integrity_drift_check.ps1" `
        -Mode Baseline `
        -PolicyVersion 1 `
        -BaselinePath $baselinePath `
        -ReportPath $verifyReportPath `
        -QuarantineMarkerPath $markerPath `
        -WatchPaths @($relativeWatched) `
        -SigningKeyEnv $signingEnv

    & "$PSScriptRoot\policy_integrity_continuous_monitor.ps1" `
        -Mode RunOnce `
        -BaselinePath $baselinePath `
        -ReportPath $verifyReportPath `
        -QuarantineMarkerPath $markerPath `
        -MonitorReportPath $monitorReportPath `
        -SigningKeyEnv $signingEnv

    $monitor = Get-Content -LiteralPath $monitorReportPath -Raw | ConvertFrom-Json
    if (-not [bool]$monitor.passed) {
        throw "Continuous monitor expected to pass before drift."
    }
    if ([int]$monitor.iterations_executed -ne 1) {
        throw "Continuous monitor RunOnce should execute exactly one cycle."
    }

    Set-Content -LiteralPath $watchedFile -Value '{"policy":"v2"}' -Encoding UTF8

    & "$PSScriptRoot\policy_integrity_continuous_monitor.ps1" `
        -Mode RunOnce `
        -BaselinePath $baselinePath `
        -ReportPath $verifyReportPath `
        -QuarantineMarkerPath $markerPath `
        -MonitorReportPath $monitorReportPath `
        -SigningKeyEnv $signingEnv `
        -FailOnDrift:$false

    $monitorDrift = Get-Content -LiteralPath $monitorReportPath -Raw | ConvertFrom-Json
    if ([bool]$monitorDrift.passed) {
        throw "Continuous monitor should report failure after intentional drift."
    }
    if (-not (Test-Path -LiteralPath $markerPath)) {
        throw "Continuous monitor should keep quarantine marker after drift."
    }

    Write-Host "policy_integrity_continuous_monitor.ps1 self-test passed."
}
finally {
    [Environment]::SetEnvironmentVariable("FORGE_POLICY_INTEGRITY_KEY_B64", $null, "Process")
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
