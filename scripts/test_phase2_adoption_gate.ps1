$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$root = Join-Path $env:TEMP ("forge_phase2_adoption_gate_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $root -Force | Out-Null
try {
    $allocatorJson = Join-Path $root "allocator-smoke.json"

    & "$PSScriptRoot\allocator_benchmark.ps1" `
        -QueueIterations 160 `
        -AgentIterations 160 `
        -IndexDocuments 64 `
        -IndexTokens 40 `
        -IndexRetainedDocuments 12 `
        -OutputJsonPath $allocatorJson

    & "$PSScriptRoot\phase2_adoption_gate.ps1" `
        -OutputDir $root `
        -SkipAllocatorBenchmark `
        -AllocatorBenchmarkJsonPath $allocatorJson `
        -IoIterations 12000 `
        -IndexDocuments 96 `
        -IndexTokens 56 `
        -IndexRetainedDocuments 20

    $bundle = Get-ChildItem -Path $root -File -Filter "phase2-adoption-gate-*.json" |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $bundle) {
        throw "phase2 adoption gate bundle was not generated"
    }
    $rawArtifact = Get-Content $bundle.FullName -Raw
    if ($rawArtifact -match "\bInfinity\b") {
        throw "phase2 adoption gate artifact contains non-JSON Infinity token"
    }
    $artifact = $rawArtifact | ConvertFrom-Json
    if ($null -eq $artifact.selected_defaults) {
        throw "selected_defaults missing from phase2 adoption artifact"
    }
    if ($null -eq $artifact.rollback_toggles) {
        throw "rollback_toggles missing from phase2 adoption artifact"
    }
    if ($null -eq $artifact.benchmark_deltas.allocator.policy) {
        throw "allocator policy guardrails missing from phase2 adoption artifact"
    }
    if ($null -eq $artifact.benchmark_deltas.io -or $null -eq $artifact.benchmark_deltas.lmdb) {
        throw "io/lmdb benchmark deltas missing from phase2 adoption artifact"
    }
    if ($null -eq $artifact.rationale -or $artifact.rationale.Count -lt 2) {
        throw "rationale section missing from phase2 adoption artifact"
    }

    Write-Host "phase2_adoption_gate.ps1 self-test passed."
}
finally {
    Remove-Item -Path $root -Recurse -Force -ErrorAction SilentlyContinue
}
