param(
    [string]$OutputDir = "",
    [string]$AllocatorBenchmarkJsonPath = "",
    [string]$IoLmdbBenchmarkJsonPath = "",
    [switch]$SkipAllocatorBenchmark = $false,
    [switch]$SkipIoLmdbBenchmark = $false,
    [int]$AllocatorQueueIterations = 20000,
    [int]$AllocatorAgentIterations = 18000,
    [int]$AllocatorIndexDocuments = 1200,
    [int]$AllocatorIndexTokens = 192,
    [int]$AllocatorIndexRetainedDocuments = 96,
    [int]$IoIterations = 250000,
    [int]$IndexDocuments = 900,
    [int]$IndexTokens = 144,
    [int]$IndexRetainedDocuments = 96,
    [string]$DefaultAllocatorFeature = "allocator-mimalloc",
    [int]$AllocatorMinTotalWinsLead = 2,
    [double]$AllocatorMinAvgThroughputGainPercent = 3.0,
    [double]$AllocatorMinAvgP95LatencyImprovementPercent = 0.0,
    [double]$AllocatorMaxAvgFragmentationRegressionPercent = 5.0,
    [double]$IoThroughputFloorPercent = -10.0,
    [double]$LmdbThroughputFloorPercent = -20.0
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Invoke-CargoCommand {
    param(
        [Parameter(Mandatory = $true)][string[]]$CargoArgs
    )

    $output = $null
    $errorText = ""
    try {
        $output = & cargo @CargoArgs 2>&1
    }
    catch {
        $errorText = $_.Exception.Message
    }

    return [PSCustomObject]@{
        ExitCode = $LASTEXITCODE
        Output = $output
        ErrorText = $errorText
    }
}

function Get-PercentDelta {
    param(
        [Parameter(Mandatory = $true)][double]$Candidate,
        [Parameter(Mandatory = $true)][double]$Baseline
    )
    if ([math]::Abs($Baseline) -lt [double]::Epsilon) {
        return 0.0
    }
    return (($Candidate - $Baseline) / $Baseline) * 100.0
}

function Get-InversePercentDelta {
    param(
        [Parameter(Mandatory = $true)][double]$Candidate,
        [Parameter(Mandatory = $true)][double]$Baseline
    )
    if ([math]::Abs($Baseline) -lt [double]::Epsilon) {
        return 0.0
    }
    return (($Baseline - $Candidate) / $Baseline) * 100.0
}

function Select-AllocatorDecision {
    param(
        [Parameter(Mandatory = $true)]$AllocatorArtifact,
        [Parameter(Mandatory = $true)][string]$DefaultAllocator,
        [int]$MinTotalWinsLead = 2,
        [double]$MinAvgThroughputGainPercent = 3.0,
        [double]$MinAvgP95LatencyImprovementPercent = 0.0,
        [double]$MaxAvgFragmentationRegressionPercent = 5.0
    )

    $rows = @($AllocatorArtifact.comparison | Where-Object { $_.status -eq "ok" })
    if ($rows.Count -eq 0) {
        throw "allocator artifact has no successful comparison rows"
    }

    $allocators = @($rows | Select-Object -ExpandProperty allocator -Unique)
    $workloads = @($rows | Select-Object -ExpandProperty workload -Unique)
    $scoreByAllocator = @{}
    foreach ($allocator in $allocators) {
        $scoreByAllocator[$allocator] = [PSCustomObject]@{
            wins_throughput = 0
            wins_latency = 0
            wins_fragmentation = 0
            total_wins = 0
            avg_throughput = 0.0
            avg_p95_latency = 0.0
            avg_fragmentation = 0.0
        }
    }

    foreach ($workload in $workloads) {
        $slice = @($rows | Where-Object { $_.workload -eq $workload })
        if ($slice.Count -eq 0) {
            continue
        }
        $throughputWinner = $slice | Sort-Object throughput_ops_per_sec -Descending | Select-Object -First 1
        $latencyWinner = $slice | Sort-Object p95_latency_us | Select-Object -First 1
        $fragmentationWinner = $slice | Sort-Object fragmentation_permille | Select-Object -First 1
        $scoreByAllocator[$throughputWinner.allocator].wins_throughput += 1
        $scoreByAllocator[$latencyWinner.allocator].wins_latency += 1
        $scoreByAllocator[$fragmentationWinner.allocator].wins_fragmentation += 1
    }

    foreach ($allocator in $allocators) {
        $slice = @($rows | Where-Object { $_.allocator -eq $allocator })
        $avgThroughput = ($slice | Measure-Object -Property throughput_ops_per_sec -Average).Average
        $avgLatency = ($slice | Measure-Object -Property p95_latency_us -Average).Average
        $avgFragmentation = ($slice | Measure-Object -Property fragmentation_permille -Average).Average
        $scoreByAllocator[$allocator].avg_throughput = [double]$avgThroughput
        $scoreByAllocator[$allocator].avg_p95_latency = [double]$avgLatency
        $scoreByAllocator[$allocator].avg_fragmentation = [double]$avgFragmentation
        $scoreByAllocator[$allocator].total_wins =
            $scoreByAllocator[$allocator].wins_throughput +
            $scoreByAllocator[$allocator].wins_latency +
            $scoreByAllocator[$allocator].wins_fragmentation
    }

    $ranked = @(
        $allocators |
            Sort-Object `
                @{Expression = { $scoreByAllocator[$_].total_wins }; Descending = $true }, `
                @{Expression = { $scoreByAllocator[$_].avg_throughput }; Descending = $true }, `
                @{Expression = { $scoreByAllocator[$_].avg_p95_latency }; Descending = $false }
    )

    $selected = $ranked[0]
    $selectionMode = "best-ranked"
    $policyNotes = @()
    $defaultPresent = $allocators -contains $DefaultAllocator
    $challenger = $null
    $challengerWinsLead = 0
    $challengerThroughputGainPercent = 0.0
    $challengerP95ImprovementPercent = 0.0
    $challengerFragmentationRegressionPercent = 0.0
    $fragmentationGuardrailPassed = $true
    $policyPassed = $true

    if (-not $defaultPresent) {
        $selectionMode = "best-ranked-default-missing"
        $policyNotes += "default allocator $DefaultAllocator not present in benchmark rows"
    }
    elseif ($selected -eq $DefaultAllocator) {
        $selectionMode = "default-ranked-first"
        $policyNotes += "default allocator $DefaultAllocator remained top ranked"
    }
    else {
        $selectionMode = "guardrail-evaluated"
        $challenger = $selected
        $baselineScore = $scoreByAllocator[$DefaultAllocator]
        $challengerScore = $scoreByAllocator[$challenger]
        $challengerWinsLead = [int]($challengerScore.total_wins - $baselineScore.total_wins)
        $challengerThroughputGainPercent = Get-PercentDelta `
            -Candidate $challengerScore.avg_throughput `
            -Baseline $baselineScore.avg_throughput
        $challengerP95ImprovementPercent = Get-InversePercentDelta `
            -Candidate $challengerScore.avg_p95_latency `
            -Baseline $baselineScore.avg_p95_latency
        if ($baselineScore.avg_fragmentation -le 0.0) {
            if ($challengerScore.avg_fragmentation -le 0.0) {
                $challengerFragmentationRegressionPercent = 0.0
                $fragmentationGuardrailPassed = $true
            }
            else {
                # Keep artifact JSON strict by avoiding Infinity serialization.
                $challengerFragmentationRegressionPercent = 1000000000.0
                $fragmentationGuardrailPassed = $false
                $policyNotes += "default allocator baseline fragmentation is near-zero; challenger introduced non-zero fragmentation"
            }
        }
        else {
            $challengerFragmentationRegressionPercent = Get-PercentDelta `
                -Candidate $challengerScore.avg_fragmentation `
                -Baseline $baselineScore.avg_fragmentation
            $fragmentationGuardrailPassed = ($challengerFragmentationRegressionPercent -le $MaxAvgFragmentationRegressionPercent)
        }

        $policyPassed =
            ($challengerWinsLead -ge $MinTotalWinsLead) -and
            ($challengerThroughputGainPercent -ge $MinAvgThroughputGainPercent) -and
            ($challengerP95ImprovementPercent -ge $MinAvgP95LatencyImprovementPercent) -and
            $fragmentationGuardrailPassed
        if ($policyPassed) {
            $policyNotes += "challenger $challenger cleared conservative guardrails against $DefaultAllocator"
        }
        else {
            $selected = $DefaultAllocator
            $policyNotes += "challenger $challenger did not clear conservative guardrails; retaining default allocator $DefaultAllocator"
        }
    }

    return [PSCustomObject]@{
        selected = $selected
        scores = $scoreByAllocator
        ranked = $ranked
        policy = [PSCustomObject]@{
            selection_mode = $selectionMode
            default_allocator = $DefaultAllocator
            default_present = $defaultPresent
            challenger_allocator = $challenger
            challenger_total_wins_lead = $challengerWinsLead
            challenger_avg_throughput_gain_percent = [double]$challengerThroughputGainPercent
            challenger_avg_p95_latency_improvement_percent = [double]$challengerP95ImprovementPercent
            challenger_avg_fragmentation_regression_percent = [double]$challengerFragmentationRegressionPercent
            required_guardrails = [PSCustomObject]@{
                min_total_wins_lead = $MinTotalWinsLead
                min_avg_throughput_gain_percent = $MinAvgThroughputGainPercent
                min_avg_p95_latency_improvement_percent = $MinAvgP95LatencyImprovementPercent
                max_avg_fragmentation_regression_percent = $MaxAvgFragmentationRegressionPercent
            }
            fragmentation_guardrail_passed = $fragmentationGuardrailPassed
            passed = $policyPassed
            notes = $policyNotes
        }
    }
}

function Write-MarkdownSummary {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Artifact
    )

    $lines = @()
    $lines += "# Phase 2 Adoption Gate Summary"
    $lines += ""
    $lines += "- Generated (UTC): $($Artifact.generated_at_utc)"
    $lines += "- Gate passed: $($Artifact.gate_passed)"
    $lines += ""
    $lines += "## Selected defaults"
    $lines += "- allocator feature: $($Artifact.selected_defaults.allocator_feature)"
    $lines += "- io policy mode: $($Artifact.selected_defaults.io_policy_mode)"
    $lines += "- lmdb feature state: $($Artifact.selected_defaults.lmdb_feature_state)"
    $lines += ""
    $lines += "## Adoption decisions"
    $lines += "- io_uring: $($Artifact.adoption_decisions.io_uring.decision) ($($Artifact.adoption_decisions.io_uring.reason))"
    $lines += "- lmdb_metadata: $($Artifact.adoption_decisions.lmdb_metadata.decision) ($($Artifact.adoption_decisions.lmdb_metadata.reason))"
    $lines += ""
    $lines += "## Benchmark deltas"
    $lines += "- io throughput delta (%): $($Artifact.benchmark_deltas.io.throughput_percent)"
    $lines += "- io p95 latency improvement (%): $($Artifact.benchmark_deltas.io.p95_latency_improvement_percent)"
    $lines += "- lmdb throughput delta (%): $($Artifact.benchmark_deltas.lmdb.throughput_percent)"
    $lines += "- lmdb p95 latency improvement (%): $($Artifact.benchmark_deltas.lmdb.p95_latency_improvement_percent)"
    $lines += "- lmdb fragmentation improvement (%): $($Artifact.benchmark_deltas.lmdb.fragmentation_improvement_percent)"
    $lines += ""
    $lines += "## Allocator policy"
    $lines += "- selection mode: $($Artifact.benchmark_deltas.allocator.policy.selection_mode)"
    $lines += "- default allocator: $($Artifact.benchmark_deltas.allocator.policy.default_allocator)"
    $lines += "- challenger allocator: $($Artifact.benchmark_deltas.allocator.policy.challenger_allocator)"
    $lines += "- guardrails passed: $($Artifact.benchmark_deltas.allocator.policy.passed)"
    $lines += ""
    $lines += "## Rollback toggles"
    $lines += "- allocator: config allocator -> mimalloc"
    $lines += "- io_uring: set feature policy to Disabled"
    $lines += "- lmdb_metadata: set feature policy to Disabled"
    $lines += ""
    $lines += "## Rationale"
    foreach ($reason in $Artifact.rationale) {
        $lines += "- $reason"
    }

    $lines -join [Environment]::NewLine | Set-Content -Path $Path -Encoding UTF8
}

& "$PSScriptRoot\bootstrap_env.ps1"

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$defaultOutputDir = Join-Path -Path "$PSScriptRoot\.." -ChildPath ".tmp\benchmarks\phase2"
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = $defaultOutputDir
}
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

if ([string]::IsNullOrWhiteSpace($AllocatorBenchmarkJsonPath)) {
    $AllocatorBenchmarkJsonPath = Join-Path $OutputDir "allocator-benchmark-$timestamp.json"
}
if ([string]::IsNullOrWhiteSpace($IoLmdbBenchmarkJsonPath)) {
    $IoLmdbBenchmarkJsonPath = Join-Path $OutputDir "io-lmdb-benchmark-$timestamp.json"
}

if (-not $SkipAllocatorBenchmark) {
    & "$PSScriptRoot\allocator_benchmark.ps1" `
        -QueueIterations $AllocatorQueueIterations `
        -AgentIterations $AllocatorAgentIterations `
        -IndexDocuments $AllocatorIndexDocuments `
        -IndexTokens $AllocatorIndexTokens `
        -IndexRetainedDocuments $AllocatorIndexRetainedDocuments `
        -OutputJsonPath $AllocatorBenchmarkJsonPath
}
elseif (-not (Test-Path $AllocatorBenchmarkJsonPath)) {
    throw "allocator benchmark artifact missing: $AllocatorBenchmarkJsonPath"
}

if (-not $SkipIoLmdbBenchmark) {
    $run = Invoke-CargoCommand -CargoArgs @(
        "run",
        "-p", "execution_plane",
        "--release",
        "--quiet",
        "--bin", "io_lmdb_gate_bench",
        "--features", "io-uring",
        "--",
        "--io-iterations", "$IoIterations",
        "--index-documents", "$IndexDocuments",
        "--index-tokens", "$IndexTokens",
        "--index-retained-documents", "$IndexRetainedDocuments"
    )
    if ($run.ExitCode -ne 0) {
        $snippet = $run.Output | Select-Object -Last 12
        throw "io/lmdb gate benchmark run failed: $($snippet -join [Environment]::NewLine)"
    }
    $jsonLine = $run.Output |
        Where-Object { $_ -and $_.Trim().StartsWith("{") -and $_.Trim().EndsWith("}") } |
        Select-Object -Last 1
    if ([string]::IsNullOrWhiteSpace($jsonLine)) {
        throw "io/lmdb gate benchmark did not emit a JSON payload"
    }
    $jsonLine | Set-Content -Path $IoLmdbBenchmarkJsonPath -Encoding UTF8
}
elseif (-not (Test-Path $IoLmdbBenchmarkJsonPath)) {
    throw "io/lmdb benchmark artifact missing: $IoLmdbBenchmarkJsonPath"
}

$allocatorArtifact = Get-Content $AllocatorBenchmarkJsonPath -Raw | ConvertFrom-Json
$ioLmdbArtifact = Get-Content $IoLmdbBenchmarkJsonPath -Raw | ConvertFrom-Json

$allocatorDecision = Select-AllocatorDecision `
    -AllocatorArtifact $allocatorArtifact `
    -DefaultAllocator $DefaultAllocatorFeature `
    -MinTotalWinsLead $AllocatorMinTotalWinsLead `
    -MinAvgThroughputGainPercent $AllocatorMinAvgThroughputGainPercent `
    -MinAvgP95LatencyImprovementPercent $AllocatorMinAvgP95LatencyImprovementPercent `
    -MaxAvgFragmentationRegressionPercent $AllocatorMaxAvgFragmentationRegressionPercent
$selectedAllocator = $allocatorDecision.selected
$allocatorPolicy = $allocatorDecision.policy

$ioDelta = $ioLmdbArtifact.io.delta
$lmdbDelta = $ioLmdbArtifact.lmdb.delta

$ioSelectionCount = [int]$ioLmdbArtifact.io.candidate.io_uring_selection_count
$ioThroughputDelta = [double]$ioDelta.throughput_percent
$ioDefault = "PreferIoUring"
$ioDecision = "adopted"
$ioDecisionReason = "io_uring selected and throughput floor met"
if ($ioSelectionCount -le 0) {
    $ioDefault = "Disabled"
    $ioDecision = "rejected-unsupported"
    $ioDecisionReason = "io_uring fast path was not selected on this host; explicit safe default Disabled recorded"
}
elseif ($ioThroughputDelta -lt $IoThroughputFloorPercent) {
    $ioDefault = "Disabled"
    $ioDecision = "rejected-performance"
    $ioDecisionReason = ("io_uring throughput delta {0:N2}% fell below floor {1:N2}% so safe default Disabled was selected" -f `
        $ioThroughputDelta, `
        $IoThroughputFloorPercent)
}

$lmdbThroughputDelta = [double]$lmdbDelta.throughput_percent
$lmdbDefault = "Enabled"
$lmdbDecision = "adopted"
$lmdbDecisionReason = "lmdb throughput floor met; default Enabled selected"
if ($lmdbThroughputDelta -lt $LmdbThroughputFloorPercent) {
    $lmdbDefault = "Disabled"
    $lmdbDecision = "rejected-performance"
    $lmdbDecisionReason = ("lmdb throughput delta {0:N2}% fell below floor {1:N2}% so explicit safe default Disabled was selected" -f `
        $lmdbThroughputDelta, `
        $LmdbThroughputFloorPercent)
}

$rationale = @(
    ("allocator selection uses conservative default-biased guardrails against $($allocatorPolicy.default_allocator); selected $selectedAllocator"),
    ("allocator guardrails: mode={0}, challenger={1}, wins-lead={2} (min {3}), throughput-gain={4:N2}% (min {5:N2}%), p95-improvement={6:N2}% (min {7:N2}%), fragmentation-regression={8:N2}% (max {9:N2}%), passed={10}" -f `
        $allocatorPolicy.selection_mode, `
        $allocatorPolicy.challenger_allocator, `
        $allocatorPolicy.challenger_total_wins_lead, `
        $allocatorPolicy.required_guardrails.min_total_wins_lead, `
        $allocatorPolicy.challenger_avg_throughput_gain_percent, `
        $allocatorPolicy.required_guardrails.min_avg_throughput_gain_percent, `
        $allocatorPolicy.challenger_avg_p95_latency_improvement_percent, `
        $allocatorPolicy.required_guardrails.min_avg_p95_latency_improvement_percent, `
        $allocatorPolicy.challenger_avg_fragmentation_regression_percent, `
        $allocatorPolicy.required_guardrails.max_avg_fragmentation_regression_percent, `
        $allocatorPolicy.passed),
    ("io delta throughput={0:N2}% p95-improvement={1:N2}% with io_uring selections={2}" -f $ioDelta.throughput_percent, $ioDelta.p95_latency_improvement_percent, $ioLmdbArtifact.io.candidate.io_uring_selection_count),
    ("io decision: {0} ({1})" -f $ioDecision, $ioDecisionReason),
    ("lmdb delta throughput={0:N2}% p95-improvement={1:N2}% fragmentation-improvement={2:N2}%" -f $lmdbDelta.throughput_percent, $lmdbDelta.p95_latency_improvement_percent, $lmdbDelta.fragmentation_improvement_percent),
    ("lmdb decision: {0} ({1})" -f $lmdbDecision, $lmdbDecisionReason),
    "rollback remains available via allocator config key and feature-policy states for io_uring/lmdb_metadata"
)

$gatePassed = `
    ($ioDecisionReason.Length -gt 0) -and `
    ($lmdbDecisionReason.Length -gt 0) -and `
    ($lmdbDefault -ne "Auto")

$artifact = [PSCustomObject]@{
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    inputs = [PSCustomObject]@{
        allocator_benchmark_json = $AllocatorBenchmarkJsonPath
        io_lmdb_benchmark_json = $IoLmdbBenchmarkJsonPath
    }
    benchmark_deltas = [PSCustomObject]@{
        allocator = [PSCustomObject]@{
            selected = $selectedAllocator
            ranked = $allocatorDecision.ranked
            scores = $allocatorDecision.scores
            policy = $allocatorPolicy
        }
        io = [PSCustomObject]@{
            throughput_percent = [double]$ioDelta.throughput_percent
            p95_latency_improvement_percent = [double]$ioDelta.p95_latency_improvement_percent
        }
        lmdb = [PSCustomObject]@{
            throughput_percent = [double]$lmdbDelta.throughput_percent
            p95_latency_improvement_percent = [double]$lmdbDelta.p95_latency_improvement_percent
            fragmentation_improvement_percent = [double]$lmdbDelta.fragmentation_improvement_percent
        }
    }
    selected_defaults = [PSCustomObject]@{
        allocator_feature = $selectedAllocator
        io_policy_mode = $ioDefault
        lmdb_feature_state = $lmdbDefault
    }
    adoption_decisions = [PSCustomObject]@{
        io_uring = [PSCustomObject]@{
            decision = $ioDecision
            reason = $ioDecisionReason
            io_uring_selection_count = $ioSelectionCount
            throughput_floor_percent = [double]$IoThroughputFloorPercent
        }
        lmdb_metadata = [PSCustomObject]@{
            decision = $lmdbDecision
            reason = $lmdbDecisionReason
            throughput_floor_percent = [double]$LmdbThroughputFloorPercent
        }
    }
    rollback_toggles = [PSCustomObject]@{
        allocator = [PSCustomObject]@{
            config_key = "allocator"
            safe_value = "mimalloc"
            supported_values = @("mimalloc", "jemalloc", "snmalloc")
        }
        io_uring = [PSCustomObject]@{
            feature_key = "io_uring"
            safe_state = "Disabled"
            default_state = $ioDefault
        }
        lmdb_metadata = [PSCustomObject]@{
            feature_key = "lmdb_metadata"
            safe_state = "Disabled"
            default_state = $lmdbDefault
        }
    }
    rationale = $rationale
    gate_passed = $gatePassed
}

$bundleJsonPath = Join-Path $OutputDir "phase2-adoption-gate-$timestamp.json"
$bundleMdPath = Join-Path $OutputDir "phase2-adoption-gate-$timestamp.md"

$artifact | ConvertTo-Json -Depth 16 | Set-Content -Path $bundleJsonPath -Encoding UTF8
Write-MarkdownSummary -Path $bundleMdPath -Artifact $artifact

Write-Host ""
Write-Host "Phase 2 adoption gate artifact saved to: $bundleJsonPath"
Write-Host "Phase 2 adoption gate summary saved to: $bundleMdPath"
Write-Host "Selected defaults: allocator=$selectedAllocator io=$ioDefault lmdb=$lmdbDefault"
Write-Host "Gate passed: $gatePassed"
