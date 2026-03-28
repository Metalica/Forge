$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$testRoot = Join-Path $workspaceRoot (".tmp\release_candidate_secret_leak_selftest_" + [guid]::NewGuid().ToString("N"))
$candidateId = "selftest-rc"
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    $reportPath = Join-Path $testRoot "release_candidate_secret_leak_report.json"
    $retentionRoot = Join-Path $testRoot "release_candidates"

    & "$PSScriptRoot\release_candidate_secret_leak_check.ps1" `
        -ReportPath $reportPath `
        -CandidateId $candidateId `
        -RetentionRoot $retentionRoot

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "release-candidate secret leak report was not generated."
    }

    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$parsed.passed) {
        throw "release-candidate secret leak report indicates failure."
    }
    if ($parsed.check -ne "release_candidate_secret_leak_check") {
        throw "Unexpected check id in release-candidate secret leak report."
    }
    if ([string]$parsed.candidate_id -ne $candidateId) {
        throw "Unexpected candidate id in release-candidate secret leak report."
    }
    if ($null -eq $parsed.checks -or @($parsed.checks).Count -lt 2) {
        throw "release-candidate secret leak report is missing expected check coverage."
    }

    $candidateRoot = Join-Path $retentionRoot $candidateId
    $retentionManifestPath = Join-Path $candidateRoot "retention_manifest.json"
    if (-not (Test-Path -LiteralPath $retentionManifestPath)) {
        throw "release-candidate retention manifest was not generated."
    }
    $retentionManifest = Get-Content -LiteralPath $retentionManifestPath -Raw | ConvertFrom-Json
    if ($null -eq $retentionManifest.artifacts -or @($retentionManifest.artifacts).Count -lt 2) {
        throw "release-candidate retention manifest is missing expected artifacts."
    }

    Write-Host "release_candidate_secret_leak_check.ps1 self-test passed."
}
finally {
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
