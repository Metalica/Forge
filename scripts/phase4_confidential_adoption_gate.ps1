param(
    [string]$OutputDir = "",
    [string]$BenchmarkJsonPath = "",
    [int]$Iterations = 12,
    [int]$ChatBaseDelayMs = 6,
    [int]$ChatTokensPerMsDivisor = 16,
    [int]$VerifierDelayMs = 3,
    [int]$SmallMaxTokens = 128,
    [int]$MediumMaxTokens = 512,
    [int]$LargeMaxTokens = 2048,
    [int]$SmallOverheadMaxPercent = 30,
    [int]$MediumOverheadMaxPercent = 20,
    [int]$LargeOverheadMaxPercent = 12
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
    $lines += "# Phase 4 Confidential Adoption Gate Summary"
    $lines += ""
    $lines += "- Generated (UTC): $($Artifact.generated_at_utc)"
    $lines += "- Gate passed: $($Artifact.gate_passed)"
    $lines += "- Benchmark profile: chat_base_delay_ms=$($Artifact.benchmark_profile.chat_base_delay_ms), verifier_delay_ms=$($Artifact.benchmark_profile.verifier_delay_ms)"
    $lines += ""
    $lines += "## Workload overhead"
    foreach ($row in $Artifact.workloads) {
        $lines += "- $($row.name): routed_avg_ms=$($row.routed.avg_ms), confidential_avg_ms=$($row.confidential.avg_ms), overhead=$($row.overhead.percent)% (max=$($row.overhead.max_allowed_percent)%, passed=$($row.overhead.threshold_passed))"
    }
    $lines += ""
    $lines += "## Decision reasons"
    foreach ($reason in $Artifact.decision.reasons) {
        $lines += "- $reason"
    }
    $lines += ""
    $lines += "## Rollback toggles"
    $lines += "- confidential_relay: set feature policy to Disabled"
    $lines += "- allow_remote_fallback: set to false in .forge_chat_confidential.json"
    $lines += "- localhost benchmark override: unset CONFIDENTIAL_ALLOW_INSECURE_LOCALHOST_HTTP"
    $lines += ""
    $lines += "## Artifact paths"
    $lines += "- benchmark_raw_json: $($Artifact.artifacts.benchmark_raw_json)"
    $lines += "- gate_bundle_json: $($Artifact.artifacts.gate_bundle_json)"

    $lines -join [Environment]::NewLine | Set-Content -Path $Path -Encoding UTF8
}

& "$PSScriptRoot\bootstrap_env.ps1"

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$defaultOutputDir = Join-Path -Path "$PSScriptRoot\.." -ChildPath ".tmp\benchmarks\phase4"
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = $defaultOutputDir
}
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}
if ([string]::IsNullOrWhiteSpace($BenchmarkJsonPath)) {
    $BenchmarkJsonPath = Join-Path $OutputDir "confidential-relay-benchmark-$timestamp.json"
}
$bundleJsonPath = Join-Path $OutputDir "phase4-confidential-adoption-gate-$timestamp.json"
$bundleMarkdownPath = Join-Path $OutputDir "phase4-confidential-adoption-gate-$timestamp.md"

$env:CONFIDENTIAL_ALLOW_INSECURE_LOCALHOST_HTTP = "1"
$run = Invoke-CargoCommand -CargoArgs @(
    "run",
    "-p", "runtime_registry",
    "--release",
    "--quiet",
    "--bin", "confidential_relay_gate_bench",
    "--",
    "--iterations", "$Iterations",
    "--chat-base-delay-ms", "$ChatBaseDelayMs",
    "--chat-tokens-per-ms-divisor", "$ChatTokensPerMsDivisor",
    "--verifier-delay-ms", "$VerifierDelayMs",
    "--small-max-tokens", "$SmallMaxTokens",
    "--medium-max-tokens", "$MediumMaxTokens",
    "--large-max-tokens", "$LargeMaxTokens",
    "--small-overhead-max-percent", "$SmallOverheadMaxPercent",
    "--medium-overhead-max-percent", "$MediumOverheadMaxPercent",
    "--large-overhead-max-percent", "$LargeOverheadMaxPercent"
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
    throw "phase4 confidential benchmark failed (exit code $($run.ExitCode)): $detail"
}

$jsonLine = $run.Output |
    Where-Object { $_ -is [string] -and $_.TrimStart().StartsWith("{") } |
    Select-Object -Last 1
if ([string]::IsNullOrWhiteSpace($jsonLine)) {
    throw "phase4 confidential benchmark did not emit a JSON payload"
}

$benchmark = $jsonLine | ConvertFrom-Json
$jsonLine | Set-Content -Path $BenchmarkJsonPath -Encoding UTF8

$artifact = [PSCustomObject]@{
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    gate_passed = [bool]$benchmark.decision.passed
    benchmark_profile = [PSCustomObject]@{
        iterations = [int]$benchmark.iterations
        chat_base_delay_ms = [int]$benchmark.profile.chat_base_delay_ms
        verifier_delay_ms = [int]$benchmark.profile.verifier_delay_ms
        chat_tokens_per_ms_divisor = [int]$benchmark.profile.chat_tokens_per_ms_divisor
    }
    workloads = $benchmark.workloads
    decision = $benchmark.decision
    selected_defaults = [PSCustomObject]@{
        confidential_relay_feature = "enabled"
        allow_remote_fallback_default = $false
    }
    rollback_toggles = @(
        "set feature `confidential_relay` to Disabled",
        "set `allow_remote_fallback` to false in .forge_chat_confidential.json",
        "unset CONFIDENTIAL_ALLOW_INSECURE_LOCALHOST_HTTP after benchmark runs"
    )
    rationale = @(
        "Confidential relay overhead is benchmarked against ordinary routed remote baseline per workload.",
        "Phase 4 gate passes only when configured overhead thresholds are met and trend remains bounded across workload sizes."
    )
    artifacts = [PSCustomObject]@{
        benchmark_raw_json = $BenchmarkJsonPath
        gate_bundle_json = $bundleJsonPath
        gate_summary_markdown = $bundleMarkdownPath
    }
}

$artifact | ConvertTo-Json -Depth 12 | Set-Content -Path $bundleJsonPath -Encoding UTF8
Write-MarkdownSummary -Path $bundleMarkdownPath -Artifact $artifact

Write-Host "Phase 4 confidential adoption gate artifact saved to: $bundleJsonPath"
Write-Host "Phase 4 confidential adoption gate summary saved to: $bundleMarkdownPath"
Write-Host "Gate passed: $($artifact.gate_passed)"
