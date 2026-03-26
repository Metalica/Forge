$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Get-TempRootPath {
    $candidates = @(
        $env:TEMP,
        $env:TMP,
        [System.IO.Path]::GetTempPath()
    )
    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            return $candidate
        }
    }
    return (Join-Path $PSScriptRoot "..\.tmp")
}

$tempRoot = Get-TempRootPath
$root = Join-Path $tempRoot ("forge_phase4_confidential_gate_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $root -Force | Out-Null
try {
    & "$PSScriptRoot\phase4_confidential_adoption_gate.ps1" `
        -OutputDir $root `
        -Iterations 4 `
        -ChatBaseDelayMs 4 `
        -ChatTokensPerMsDivisor 12 `
        -VerifierDelayMs 2 `
        -SmallOverheadMaxPercent 60 `
        -MediumOverheadMaxPercent 40 `
        -LargeOverheadMaxPercent 25

    $bundle = Get-ChildItem -Path $root -File -Filter "phase4-confidential-adoption-gate-*.json" |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $bundle) {
        throw "phase4 confidential adoption gate bundle was not generated"
    }

    $rawArtifact = Get-Content $bundle.FullName -Raw
    if ($rawArtifact -match "\bInfinity\b") {
        throw "phase4 confidential adoption artifact contains non-JSON Infinity token"
    }
    $artifact = $rawArtifact | ConvertFrom-Json
    if ($null -eq $artifact.workloads -or $artifact.workloads.Count -ne 3) {
        throw "expected three workload rows in phase4 confidential artifact"
    }
    if ($null -eq $artifact.decision -or $null -eq $artifact.decision.reasons) {
        throw "decision reasons missing from phase4 confidential artifact"
    }
    if ($null -eq $artifact.artifacts.gate_summary_markdown) {
        throw "summary markdown path missing from phase4 confidential artifact"
    }
    if (-not (Test-Path $artifact.artifacts.gate_summary_markdown)) {
        throw "summary markdown file missing: $($artifact.artifacts.gate_summary_markdown)"
    }

    Write-Host "phase4_confidential_adoption_gate.ps1 self-test passed."
}
finally {
    Remove-Item -Path $root -Recurse -Force -ErrorAction SilentlyContinue
}
