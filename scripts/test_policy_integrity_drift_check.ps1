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
$testRoot = Join-Path $workspaceRoot (".tmp\policy_integrity_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    $watchedA = Join-Path $testRoot "watched_a.json"
    $watchedB = Join-Path $testRoot "watched_b.json"
    Set-Content -LiteralPath $watchedA -Value '{"policy":"v1"}' -Encoding UTF8
    Set-Content -LiteralPath $watchedB -Value '{"relay":"enabled"}' -Encoding UTF8

    $relativeA = (Get-RelativePath -BasePath $workspaceRoot -TargetPath $watchedA).Replace("\", "/")
    $relativeB = (Get-RelativePath -BasePath $workspaceRoot -TargetPath $watchedB).Replace("\", "/")
    $baselinePath = Join-Path $testRoot "baseline.json"
    $reportPath = Join-Path $testRoot "report.json"
    $markerPath = Join-Path $testRoot "QUARANTINE_MODE.flag"

    $signingEnv = "FORGE_POLICY_INTEGRITY_KEY_B64"
    $adminEnv = "FORGE_ADMIN_REAUTH_CODE"
    $dualEnv = "FORGE_ADMIN_DUAL_CONTROL_CODE"
    $adminCode = "forge-admin-selftest-code"
    $dualCode = "forge-dual-selftest-code"
    [Environment]::SetEnvironmentVariable($signingEnv, (New-RandomBase64Key), "Process")
    [Environment]::SetEnvironmentVariable($adminEnv, $adminCode, "Process")
    [Environment]::SetEnvironmentVariable($dualEnv, $dualCode, "Process")

    & "$PSScriptRoot\policy_integrity_drift_check.ps1" `
        -Mode Baseline `
        -PolicyVersion 1 `
        -BaselinePath $baselinePath `
        -ReportPath $reportPath `
        -QuarantineMarkerPath $markerPath `
        -WatchPaths @($relativeA, $relativeB) `
        -SigningKeyEnv $signingEnv

    & "$PSScriptRoot\policy_integrity_drift_check.ps1" `
        -Mode Verify `
        -BaselinePath $baselinePath `
        -ReportPath $reportPath `
        -QuarantineMarkerPath $markerPath `
        -SigningKeyEnv $signingEnv

    Set-Content -LiteralPath $watchedA -Value '{"policy":"v2"}' -Encoding UTF8
    & "$PSScriptRoot\policy_integrity_drift_check.ps1" `
        -Mode Verify `
        -BaselinePath $baselinePath `
        -ReportPath $reportPath `
        -QuarantineMarkerPath $markerPath `
        -SigningKeyEnv $signingEnv `
        -FailOnDrift:$false

    if (-not (Test-Path -LiteralPath $markerPath)) {
        throw "Expected quarantine marker after intentional drift."
    }

    $mismatchBlocked = $false
    try {
        & "$PSScriptRoot\policy_integrity_drift_check.ps1" `
            -Mode ApproveBaselineUpdate `
            -PolicyVersion 2 `
            -BaselinePath $baselinePath `
            -ReportPath $reportPath `
            -QuarantineMarkerPath $markerPath `
            -WatchPaths @($relativeA, $relativeB) `
            -SigningKeyEnv $signingEnv `
            -AdminReauthEnv $adminEnv `
            -AdminReauthCode $adminCode `
            -DualControlEnv $dualEnv `
            -DualControlCode $dualCode `
            -ChangeReason "Rotate policy baseline after approved trust-state update" `
            -TypedConfirmation "wrong confirmation"
    }
    catch {
        $mismatchBlocked = $true
    }
    if (-not $mismatchBlocked) {
        throw "ApproveBaselineUpdate should fail when typed confirmation is wrong."
    }

    & "$PSScriptRoot\policy_integrity_drift_check.ps1" `
        -Mode ApproveBaselineUpdate `
        -PolicyVersion 2 `
        -BaselinePath $baselinePath `
        -ReportPath $reportPath `
        -QuarantineMarkerPath $markerPath `
        -WatchPaths @($relativeA, $relativeB) `
        -SigningKeyEnv $signingEnv `
        -AdminReauthEnv $adminEnv `
        -AdminReauthCode $adminCode `
        -DualControlEnv $dualEnv `
        -DualControlCode $dualCode `
        -ChangeReason "Rotate policy baseline after approved trust-state update" `
        -TypedConfirmation "I UNDERSTAND FORGE POLICY CHANGE"

    & "$PSScriptRoot\policy_integrity_drift_check.ps1" `
        -Mode Verify `
        -BaselinePath $baselinePath `
        -ReportPath $reportPath `
        -QuarantineMarkerPath $markerPath `
        -SigningKeyEnv $signingEnv

    if (Test-Path -LiteralPath $markerPath) {
        throw "Quarantine marker should be cleared after verified baseline update."
    }

    Write-Host "policy_integrity_drift_check.ps1 self-test passed."
}
finally {
    [Environment]::SetEnvironmentVariable("FORGE_POLICY_INTEGRITY_KEY_B64", $null, "Process")
    [Environment]::SetEnvironmentVariable("FORGE_ADMIN_REAUTH_CODE", $null, "Process")
    [Environment]::SetEnvironmentVariable("FORGE_ADMIN_DUAL_CONTROL_CODE", $null, "Process")
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
