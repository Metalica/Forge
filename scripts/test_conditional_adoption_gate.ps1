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
$root = Join-Path $tempRoot ("forge_conditional_gate_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $root -Force | Out-Null
try {
    & "$PSScriptRoot\conditional_adoption_gate.ps1" `
        -OutputDir $root `
        -Iterations 8 `
        -OpenVinoMinThroughputGainPercent 5 `
        -ThpMinThroughputGainPercent 4 `
        -PressureMinP95ImprovementPercent 4 `
        -PressureMinAvgImprovementPercent 4 `
        -OpenBlasMinThroughputGainPercent 4 `
        -BlisMinThroughputGainPercent 4

    $bundle = Get-ChildItem -Path $root -File -Filter "conditional-adoption-gate-*.json" |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $bundle) {
        throw "conditional adoption gate bundle was not generated"
    }

    $rawArtifact = Get-Content $bundle.FullName -Raw
    if ($rawArtifact -match "\bInfinity\b") {
        throw "conditional adoption artifact contains non-JSON Infinity token"
    }
    $artifact = $rawArtifact | ConvertFrom-Json
    if ($null -eq $artifact.workloads -or $artifact.workloads.Count -ne 13) {
        throw "expected thirteen workload rows in conditional artifact"
    }
    if ($null -eq $artifact.decisions.openvino_backend) {
        throw "openvino decision missing from conditional artifact"
    }
    if ($null -eq $artifact.decisions.transparent_huge_pages) {
        throw "transparent_huge_pages decision missing from conditional artifact"
    }
    if ($null -eq $artifact.decisions.zswap -or $null -eq $artifact.decisions.zram) {
        throw "zswap/zram decisions missing from conditional artifact"
    }
    if ($null -eq $artifact.decisions.openblas_backend -or $null -eq $artifact.decisions.blis_backend) {
        throw "openblas/blis decisions missing from conditional artifact"
    }
    if ($null -eq $artifact.decisions.perf_profiler -or $null -eq $artifact.decisions.tracy_profiler) {
        throw "perf/tracy decisions missing from conditional artifact"
    }
    if ($null -eq $artifact.decisions.autofdo_optimizer -or $null -eq $artifact.decisions.bolt_optimizer) {
        throw "autofdo/bolt decisions missing from conditional artifact"
    }
    if ($null -eq $artifact.decisions.ispc_kernels) {
        throw "ispc decision missing from conditional artifact"
    }
    if ($null -eq $artifact.decisions.highway_simd -or $null -eq $artifact.decisions.rust_arch_simd) {
        throw "highway/rust-arch-simd decisions missing from conditional artifact"
    }
    if ($null -eq $artifact.decisions.rayon_parallelism) {
        throw "rayon decision missing from conditional artifact"
    }
    if ($null -eq $artifact.recommended_env_flags.OPENVINO_BENCHMARK_OK) {
        throw "recommended env flag OPENVINO_BENCHMARK_OK missing"
    }
    if ($null -eq $artifact.recommended_env_flags.OPENBLAS_BENCHMARK_OK -or $null -eq $artifact.recommended_env_flags.BLIS_BENCHMARK_OK) {
        throw "recommended env flags for openblas/blis missing"
    }
    if ($null -eq $artifact.recommended_env_flags.PERF_BENCHMARK_OK -or $null -eq $artifact.recommended_env_flags.TRACY_BENCHMARK_OK) {
        throw "recommended env flags for perf/tracy missing"
    }
    if ($null -eq $artifact.recommended_env_flags.AUTOFDO_BENCHMARK_OK -or $null -eq $artifact.recommended_env_flags.BOLT_BENCHMARK_OK) {
        throw "recommended env flags for autofdo/bolt missing"
    }
    if ($null -eq $artifact.recommended_env_flags.ISPC_BENCHMARK_OK) {
        throw "recommended env flag ISPC_BENCHMARK_OK missing"
    }
    if ($null -eq $artifact.recommended_env_flags.HIGHWAY_BENCHMARK_OK -or $null -eq $artifact.recommended_env_flags.RUST_ARCH_SIMD_BENCHMARK_OK) {
        throw "recommended env flags for highway/rust-arch-simd missing"
    }
    if ($null -eq $artifact.recommended_env_flags.RAYON_BENCHMARK_OK) {
        throw "recommended env flag RAYON_BENCHMARK_OK missing"
    }
    if ($null -eq $artifact.selected_defaults.openblas_backend -or $null -eq $artifact.selected_defaults.blis_backend) {
        throw "selected defaults for openblas/blis missing"
    }
    if ($null -eq $artifact.selected_defaults.profiling_mode) {
        throw "selected default profiling_mode missing"
    }
    if ($null -eq $artifact.selected_defaults.release_optimization_mode) {
        throw "selected default release_optimization_mode missing"
    }
    if ($null -eq $artifact.selected_defaults.ispc_kernels) {
        throw "selected default ispc_kernels missing"
    }
    if ($null -eq $artifact.selected_defaults.highway_simd -or $null -eq $artifact.selected_defaults.rust_arch_simd) {
        throw "selected defaults for highway/rust-arch-simd missing"
    }
    if ($null -eq $artifact.selected_defaults.rayon_parallelism) {
        throw "selected default rayon_parallelism missing"
    }
    if ($null -eq $artifact.artifacts.gate_summary_markdown) {
        throw "summary markdown path missing from conditional artifact"
    }
    if (-not (Test-Path $artifact.artifacts.gate_summary_markdown)) {
        throw "summary markdown file missing: $($artifact.artifacts.gate_summary_markdown)"
    }

    Write-Host "conditional_adoption_gate.ps1 self-test passed."
}
finally {
    Remove-Item -Path $root -Recurse -Force -ErrorAction SilentlyContinue
}
