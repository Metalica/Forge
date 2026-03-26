param(
    [string]$OutputDir = "",
    [string]$BenchmarkJsonPath = "",
    [int]$Iterations = 24,
    [int]$OpenVinoBaselineLatencyUs = 11500,
    [int]$OpenVinoCandidateLatencyUs = 9100,
    [int]$ThpBaselineLatencyUs = 4200,
    [int]$ThpCandidateLatencyUs = 3600,
    [int]$PressureBaselineLatencyUs = 6900,
    [int]$PressureCandidateLatencyUs = 5400,
    [int]$OpenBlasBaselineLatencyUs = 5600,
    [int]$OpenBlasCandidateLatencyUs = 4800,
    [int]$BlisBaselineLatencyUs = 5300,
    [int]$BlisCandidateLatencyUs = 4600,
    [int]$PerfBaselineLatencyUs = 4700,
    [int]$PerfCandidateLatencyUs = 4000,
    [int]$TracyBaselineLatencyUs = 4500,
    [int]$TracyCandidateLatencyUs = 3900,
    [int]$AutoFdoBaselineLatencyUs = 4200,
    [int]$AutoFdoCandidateLatencyUs = 3600,
    [int]$BoltBaselineLatencyUs = 4000,
    [int]$BoltCandidateLatencyUs = 3450,
    [int]$IspcBaselineLatencyUs = 3800,
    [int]$IspcCandidateLatencyUs = 3200,
    [int]$HighwayBaselineLatencyUs = 3600,
    [int]$HighwayCandidateLatencyUs = 3150,
    [int]$RustArchSimdBaselineLatencyUs = 3500,
    [int]$RustArchSimdCandidateLatencyUs = 3050,
    [int]$RayonBaselineLatencyUs = 3900,
    [int]$RayonCandidateLatencyUs = 3350,
    [int]$OpenVinoMinThroughputGainPercent = 15,
    [int]$ThpMinThroughputGainPercent = 8,
    [int]$PressureMinP95ImprovementPercent = 10,
    [int]$PressureMinAvgImprovementPercent = 8,
    [int]$OpenBlasMinThroughputGainPercent = 8,
    [int]$BlisMinThroughputGainPercent = 8,
    [int]$PerfMinThroughputGainPercent = 8,
    [int]$TracyMinThroughputGainPercent = 8,
    [int]$AutoFdoMinThroughputGainPercent = 8,
    [int]$BoltMinThroughputGainPercent = 8,
    [int]$IspcMinThroughputGainPercent = 8,
    [int]$HighwayMinThroughputGainPercent = 8,
    [int]$RustArchSimdMinThroughputGainPercent = 8,
    [int]$RayonMinThroughputGainPercent = 8
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Get-CargoExecutablePath {
    $cargoCommand = Get-Command cargo -ErrorAction SilentlyContinue
    if ($null -ne $cargoCommand -and -not [string]::IsNullOrWhiteSpace($cargoCommand.Source)) {
        return $cargoCommand.Source
    }

    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($env:CARGO)) {
        $candidates += $env:CARGO
    }
    if (-not [string]::IsNullOrWhiteSpace($env:CARGO_HOME)) {
        $candidates += (Join-Path $env:CARGO_HOME "bin/cargo")
        $candidates += (Join-Path $env:CARGO_HOME "bin/cargo.exe")
    }
    if (-not [string]::IsNullOrWhiteSpace($HOME)) {
        $candidates += (Join-Path $HOME ".cargo/bin/cargo")
        $candidates += (Join-Path $HOME ".cargo/bin/cargo.exe")
    }
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $candidates += (Join-Path $env:USERPROFILE ".cargo/bin/cargo")
        $candidates += (Join-Path $env:USERPROFILE ".cargo/bin/cargo.exe")
    }

    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -Path $candidate)) {
            return $candidate
        }
    }

    return $null
}

$script:CargoExecutable = Get-CargoExecutablePath

function Invoke-CargoCommand {
    param(
        [Parameter(Mandatory = $true)][string[]]$CargoArgs
    )

    if ([string]::IsNullOrWhiteSpace($script:CargoExecutable)) {
        return [PSCustomObject]@{
            ExitCode = 127
            Output = @()
            ErrorText = "cargo executable was not found on PATH or common rustup locations"
        }
    }

    $output = @()
    $errorText = ""
    $exitCode = 0
    $nativeErrorPreferenceVar = Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue
    if ($null -ne $nativeErrorPreferenceVar) {
        $previousNativeErrorPreference = [bool]$PSNativeCommandUseErrorActionPreference
        $PSNativeCommandUseErrorActionPreference = $false
    }
    try {
        $output = & $script:CargoExecutable @CargoArgs 2>&1
        $exitCode = $LASTEXITCODE
    }
    catch {
        $errorText = $_.Exception.Message
        if ($LASTEXITCODE -is [int] -and $LASTEXITCODE -ne 0) {
            $exitCode = $LASTEXITCODE
        }
        else {
            $exitCode = 1
        }
    }
    finally {
        if ($null -ne $nativeErrorPreferenceVar) {
            $PSNativeCommandUseErrorActionPreference = $previousNativeErrorPreference
        }
    }

    return [PSCustomObject]@{
        ExitCode = $exitCode
        Output = $output
        ErrorText = $errorText
    }
}

function Write-MarkdownSummary {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Artifact
    )

    $lines = @()
    $lines += "# Conditional Performance Gate Summary"
    $lines += ""
    $lines += "- Generated (UTC): $($Artifact.generated_at_utc)"
    $lines += "- Gate passed: $($Artifact.gate_passed)"
    $lines += "- Synthetic harness: $($Artifact.benchmark_profile.synthetic)"
    $lines += ""
    $lines += "## Workload deltas"
    foreach ($row in $Artifact.workloads) {
        $lines += "- $($row.name): throughput_gain=$([math]::Round([double]$row.delta.throughput_gain_percent, 2))% avg_latency_improvement=$([math]::Round([double]$row.delta.avg_latency_improvement_percent, 2))% p95_latency_improvement=$([math]::Round([double]$row.delta.p95_latency_improvement_percent, 2))%"
    }
    $lines += ""
    $lines += "## Feature decisions"
    $lines += "- openvino_backend: passed=$($Artifact.decisions.openvino_backend.passed) required=$($Artifact.decisions.openvino_backend.required_percent)%"
    $lines += "- transparent_huge_pages: passed=$($Artifact.decisions.transparent_huge_pages.passed) required=$($Artifact.decisions.transparent_huge_pages.required_percent)%"
    $lines += "- zswap: passed=$($Artifact.decisions.zswap.passed) required_avg=$($Artifact.decisions.zswap.required_avg_percent)% required_p95=$($Artifact.decisions.zswap.required_p95_percent)%"
    $lines += "- zram: passed=$($Artifact.decisions.zram.passed) required_avg=$($Artifact.decisions.zram.required_avg_percent)% required_p95=$($Artifact.decisions.zram.required_p95_percent)%"
    $lines += "- openblas_backend: passed=$($Artifact.decisions.openblas_backend.passed) required=$($Artifact.decisions.openblas_backend.required_percent)%"
    $lines += "- blis_backend: passed=$($Artifact.decisions.blis_backend.passed) required=$($Artifact.decisions.blis_backend.required_percent)%"
    $lines += "- perf_profiler: passed=$($Artifact.decisions.perf_profiler.passed) required=$($Artifact.decisions.perf_profiler.required_percent)%"
    $lines += "- tracy_profiler: passed=$($Artifact.decisions.tracy_profiler.passed) required=$($Artifact.decisions.tracy_profiler.required_percent)%"
    $lines += "- autofdo_optimizer: passed=$($Artifact.decisions.autofdo_optimizer.passed) required=$($Artifact.decisions.autofdo_optimizer.required_percent)%"
    $lines += "- bolt_optimizer: passed=$($Artifact.decisions.bolt_optimizer.passed) required=$($Artifact.decisions.bolt_optimizer.required_percent)%"
    $lines += "- ispc_kernels: passed=$($Artifact.decisions.ispc_kernels.passed) required=$($Artifact.decisions.ispc_kernels.required_percent)%"
    $lines += "- highway_simd: passed=$($Artifact.decisions.highway_simd.passed) required=$($Artifact.decisions.highway_simd.required_percent)%"
    $lines += "- rust_arch_simd: passed=$($Artifact.decisions.rust_arch_simd.passed) required=$($Artifact.decisions.rust_arch_simd.required_percent)%"
    $lines += "- rayon_parallelism: passed=$($Artifact.decisions.rayon_parallelism.passed) required=$($Artifact.decisions.rayon_parallelism.required_percent)%"
    $lines += ""
    $lines += "## Recommended evidence flags"
    foreach ($prop in $Artifact.recommended_env_flags.PSObject.Properties) {
        $lines += "- $($prop.Name)=$($prop.Value)"
    }
    $lines += ""
    $lines += "## Rollback toggles"
    foreach ($toggle in $Artifact.rollback_toggles) {
        $lines += "- $toggle"
    }
    $lines += ""
    $lines += "## Decision reasons"
    foreach ($reason in $Artifact.decision.reasons) {
        $lines += "- $reason"
    }

    $lines -join [Environment]::NewLine | Set-Content -Path $Path -Encoding UTF8
}

& "$PSScriptRoot\bootstrap_env.ps1"

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$defaultOutputDir = Join-Path -Path "$PSScriptRoot\.." -ChildPath ".tmp\benchmarks\conditional"
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = $defaultOutputDir
}
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}
if ([string]::IsNullOrWhiteSpace($BenchmarkJsonPath)) {
    $BenchmarkJsonPath = Join-Path $OutputDir "conditional-benchmark-$timestamp.json"
}
$bundleJsonPath = Join-Path $OutputDir "conditional-adoption-gate-$timestamp.json"
$bundleMarkdownPath = Join-Path $OutputDir "conditional-adoption-gate-$timestamp.md"

$run = Invoke-CargoCommand -CargoArgs @(
    "run",
    "-p", "control_plane",
    "--release",
    "--quiet",
    "--bin", "conditional_gate_bench",
    "--",
    "--iterations", "$Iterations",
    "--openvino-baseline-latency-us", "$OpenVinoBaselineLatencyUs",
    "--openvino-candidate-latency-us", "$OpenVinoCandidateLatencyUs",
    "--thp-baseline-latency-us", "$ThpBaselineLatencyUs",
    "--thp-candidate-latency-us", "$ThpCandidateLatencyUs",
    "--pressure-baseline-latency-us", "$PressureBaselineLatencyUs",
    "--pressure-candidate-latency-us", "$PressureCandidateLatencyUs",
    "--openblas-baseline-latency-us", "$OpenBlasBaselineLatencyUs",
    "--openblas-candidate-latency-us", "$OpenBlasCandidateLatencyUs",
    "--blis-baseline-latency-us", "$BlisBaselineLatencyUs",
    "--blis-candidate-latency-us", "$BlisCandidateLatencyUs",
    "--perf-baseline-latency-us", "$PerfBaselineLatencyUs",
    "--perf-candidate-latency-us", "$PerfCandidateLatencyUs",
    "--tracy-baseline-latency-us", "$TracyBaselineLatencyUs",
    "--tracy-candidate-latency-us", "$TracyCandidateLatencyUs",
    "--autofdo-baseline-latency-us", "$AutoFdoBaselineLatencyUs",
    "--autofdo-candidate-latency-us", "$AutoFdoCandidateLatencyUs",
    "--bolt-baseline-latency-us", "$BoltBaselineLatencyUs",
    "--bolt-candidate-latency-us", "$BoltCandidateLatencyUs",
    "--ispc-baseline-latency-us", "$IspcBaselineLatencyUs",
    "--ispc-candidate-latency-us", "$IspcCandidateLatencyUs",
    "--highway-baseline-latency-us", "$HighwayBaselineLatencyUs",
    "--highway-candidate-latency-us", "$HighwayCandidateLatencyUs",
    "--rust-arch-simd-baseline-latency-us", "$RustArchSimdBaselineLatencyUs",
    "--rust-arch-simd-candidate-latency-us", "$RustArchSimdCandidateLatencyUs",
    "--rayon-baseline-latency-us", "$RayonBaselineLatencyUs",
    "--rayon-candidate-latency-us", "$RayonCandidateLatencyUs",
    "--openvino-min-throughput-gain-percent", "$OpenVinoMinThroughputGainPercent",
    "--thp-min-throughput-gain-percent", "$ThpMinThroughputGainPercent",
    "--pressure-min-p95-improvement-percent", "$PressureMinP95ImprovementPercent",
    "--pressure-min-avg-improvement-percent", "$PressureMinAvgImprovementPercent",
    "--openblas-min-throughput-gain-percent", "$OpenBlasMinThroughputGainPercent",
    "--blis-min-throughput-gain-percent", "$BlisMinThroughputGainPercent",
    "--perf-min-throughput-gain-percent", "$PerfMinThroughputGainPercent",
    "--tracy-min-throughput-gain-percent", "$TracyMinThroughputGainPercent",
    "--autofdo-min-throughput-gain-percent", "$AutoFdoMinThroughputGainPercent",
    "--bolt-min-throughput-gain-percent", "$BoltMinThroughputGainPercent",
    "--ispc-min-throughput-gain-percent", "$IspcMinThroughputGainPercent",
    "--highway-min-throughput-gain-percent", "$HighwayMinThroughputGainPercent",
    "--rust-arch-simd-min-throughput-gain-percent", "$RustArchSimdMinThroughputGainPercent",
    "--rayon-min-throughput-gain-percent", "$RayonMinThroughputGainPercent"
)
if ($run.ExitCode -ne 0) {
    $snippet = @($run.Output | Select-Object -Last 12)
    if ($snippet.Count -gt 0) {
        $detail = $snippet -join [Environment]::NewLine
    }
    elseif (-not [string]::IsNullOrWhiteSpace($run.ErrorText)) {
        $detail = $run.ErrorText
    }
    else {
        $detail = "no output captured"
    }
    throw "conditional benchmark failed (exit code $($run.ExitCode)): $detail"
}

$jsonLine = $run.Output |
    Where-Object { $_ -is [string] -and $_.TrimStart().StartsWith("{") } |
    Select-Object -Last 1
if ([string]::IsNullOrWhiteSpace($jsonLine)) {
    throw "conditional benchmark did not emit a JSON payload"
}
$benchmark = $jsonLine | ConvertFrom-Json
$jsonLine | Set-Content -Path $BenchmarkJsonPath -Encoding UTF8

$openvinoDefault = if ($benchmark.decisions.openvino_backend.passed) { "Auto" } else { "Disabled" }
$linuxMemoryDefault = if (
    $benchmark.decisions.transparent_huge_pages.passed -and
    $benchmark.decisions.zswap.passed -and
    $benchmark.decisions.zram.passed
) { "Auto" } else { "Disabled" }
$openBlasDefault = if ($benchmark.decisions.openblas_backend.passed) { "Auto" } else { "Disabled" }
$blisDefault = if ($benchmark.decisions.blis_backend.passed) { "Auto" } else { "Disabled" }
$profilingDefault = if (
    $benchmark.decisions.perf_profiler.passed -and
    $benchmark.decisions.tracy_profiler.passed
) { "Auto" } else { "Disabled" }
$releaseOptimizationDefault = if (
    $benchmark.decisions.autofdo_optimizer.passed -and
    $benchmark.decisions.bolt_optimizer.passed
) { "Auto" } else { "Disabled" }
$ispcDefault = if ($benchmark.decisions.ispc_kernels.passed) { "Auto" } else { "Disabled" }
$highwayDefault = if ($benchmark.decisions.highway_simd.passed) { "Auto" } else { "Disabled" }
$rustArchSimdDefault = if ($benchmark.decisions.rust_arch_simd.passed) { "Auto" } else { "Disabled" }
$rayonDefault = if ($benchmark.decisions.rayon_parallelism.passed) { "Auto" } else { "Disabled" }

$artifact = [PSCustomObject]@{
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    gate_passed = [bool]$benchmark.decision.passed
    benchmark_profile = [PSCustomObject]@{
        synthetic = [bool]$benchmark.profile.synthetic
        iterations = [int]$benchmark.iterations
    }
    workloads = $benchmark.workloads
    decisions = $benchmark.decisions
    recommended_env_flags = $benchmark.recommended_env_flags
    selected_defaults = [PSCustomObject]@{
        openvino_backend = $openvinoDefault
        linux_memory_tuning_profile = $linuxMemoryDefault
        openblas_backend = $openBlasDefault
        blis_backend = $blisDefault
        profiling_mode = $profilingDefault
        release_optimization_mode = $releaseOptimizationDefault
        ispc_kernels = $ispcDefault
        highway_simd = $highwayDefault
        rust_arch_simd = $rustArchSimdDefault
        rayon_parallelism = $rayonDefault
    }
    rollback_toggles = @(
        "set OPENVINO_BENCHMARK_OK=0",
        "set THP_BENCHMARK_OK=0",
        "set ZSWAP_BENCHMARK_OK=0",
        "set ZRAM_BENCHMARK_OK=0",
        "set OPENBLAS_BENCHMARK_OK=0",
        "set BLIS_BENCHMARK_OK=0",
        "set PERF_BENCHMARK_OK=0",
        "set TRACY_BENCHMARK_OK=0",
        "set AUTOFDO_BENCHMARK_OK=0",
        "set BOLT_BENCHMARK_OK=0",
        "set ISPC_BENCHMARK_OK=0",
        "set HIGHWAY_BENCHMARK_OK=0",
        "set RUST_ARCH_SIMD_BENCHMARK_OK=0",
        "set RAYON_BENCHMARK_OK=0"
    )
    rationale = @(
        "The conditional stack remains fail-closed unless benchmark evidence flags are explicitly set.",
        "Gate output provides reproducible workload deltas and recommended evidence flags for OpenVINO, Linux memory tuning controls, dense-math backends, profiling tools, release optimizers, SIMD paths, and Rayon parallelism."
    )
    decision = $benchmark.decision
    artifacts = [PSCustomObject]@{
        benchmark_raw_json = $BenchmarkJsonPath
        gate_bundle_json = $bundleJsonPath
        gate_summary_markdown = $bundleMarkdownPath
    }
}

$artifact | ConvertTo-Json -Depth 12 | Set-Content -Path $bundleJsonPath -Encoding UTF8
Write-MarkdownSummary -Path $bundleMarkdownPath -Artifact $artifact

Write-Host "Conditional adoption gate artifact saved to: $bundleJsonPath"
Write-Host "Conditional adoption gate summary saved to: $bundleMarkdownPath"
Write-Host "Gate passed: $($artifact.gate_passed)"
