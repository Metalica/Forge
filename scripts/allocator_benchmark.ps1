param(
    [int]$QueueIterations = 20000,
    [int]$QueueWorkers = 16,
    [int]$QueueWindow = 96,
    [int]$AgentIterations = 18000,
    [int]$AgentWindow = 128,
    [int]$IndexDocuments = 1200,
    [int]$IndexTokens = 192,
    [int]$IndexRetainedDocuments = 96,
    [string]$OutputJsonPath = "",
    [switch]$AllowPartialResults = $false,
    [switch]$SelfTestJemallocRepair = $false
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

function Get-JemallocSearchRoots {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot
    )

    $roots = @(
        (Join-Path $RepoRoot "target"),
        $RepoRoot
    )

    if (-not [string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
        try {
            $resolvedTargetDir = (Resolve-Path $env:CARGO_TARGET_DIR -ErrorAction Stop).Path
            $roots += $resolvedTargetDir
        }
        catch {
            $roots += $env:CARGO_TARGET_DIR
        }
    }

    return $roots |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path $_) } |
        Select-Object -Unique
}

function Repair-JemallocArchiveAlias {
    param(
        [string[]]$SearchRoots = @()
    )

    if ($SearchRoots.Count -eq 0) {
        $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
        $searchRoots = Get-JemallocSearchRoots -RepoRoot $repoRoot
    }
    else {
        $searchRoots = $SearchRoots |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path $_) } |
            Select-Object -Unique
    }

    $jemallocLibs = @()
    foreach ($root in $searchRoots) {
        $jemallocLibs += Get-ChildItem -Path $root -Recurse -File -Filter "jemalloc.lib" -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match "tikv-jemalloc-sys-" }
    }

    $jemallocLibs = $jemallocLibs | Sort-Object -Property FullName -Unique
    $repairedCount = 0
    foreach ($jemallocLib in $jemallocLibs) {
        $gnuArchive = Join-Path $jemallocLib.DirectoryName "libjemalloc.a"
        if (-not (Test-Path $gnuArchive)) {
            Copy-Item -Path $jemallocLib.FullName -Destination $gnuArchive -Force
            $repairedCount += 1
        }
    }

    return [PSCustomObject]@{
        candidates = $jemallocLibs.Count
        repaired = $repairedCount
    }
}

function Assert-Condition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Invoke-JemallocRepairSelfTest {
    $root = Join-Path $env:TEMP ("forge_jemalloc_repair_selftest_" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    try {
        $canonicalDir = Join-Path $root "target\x86_64-pc-windows-gnu\release\build\tikv-jemalloc-sys-abcd1234\out\build\lib"
        $flattenedDir = Join-Path $root "targetx86_64-pc-windows-gnudebugbuildtikv-jemalloc-sys-efgh5678out\lib"
        New-Item -ItemType Directory -Path $canonicalDir -Force | Out-Null
        New-Item -ItemType Directory -Path $flattenedDir -Force | Out-Null

        Set-Content -Path (Join-Path $canonicalDir "jemalloc.lib") -Value "mock-lib" -Encoding ascii
        Set-Content -Path (Join-Path $flattenedDir "jemalloc.lib") -Value "mock-lib" -Encoding ascii

        $first = Repair-JemallocArchiveAlias -SearchRoots @($root)
        Assert-Condition -Condition ($first.candidates -eq 2) -Message "expected 2 jemalloc.lib candidates in self-test"
        Assert-Condition -Condition ($first.repaired -eq 2) -Message "expected both jemalloc alias files to be repaired in first pass"
        Assert-Condition -Condition (Test-Path (Join-Path $canonicalDir "libjemalloc.a")) -Message "missing canonical libjemalloc.a alias after repair"
        Assert-Condition -Condition (Test-Path (Join-Path $flattenedDir "libjemalloc.a")) -Message "missing flattened libjemalloc.a alias after repair"

        $second = Repair-JemallocArchiveAlias -SearchRoots @($root)
        Assert-Condition -Condition ($second.candidates -eq 2) -Message "expected stable candidate count on second pass"
        Assert-Condition -Condition ($second.repaired -eq 0) -Message "expected idempotent second pass with no additional repairs"

        Write-Host "Jemalloc repair self-test passed (candidates=2, first_repaired=2, second_repaired=0)."
    }
    finally {
        Remove-Item -Path $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-AllocatorBenchmarkRun {
    param(
        [Parameter(Mandatory = $true)][string]$AllocatorFeature,
        [Parameter(Mandatory = $true)][bool]$NoDefaultFeatures
    )

    $cargoArgs = @(
        "run",
        "-p", "execution_plane",
        "--release",
        "--quiet",
        "--bin", "allocator_bench"
    )
    if ($NoDefaultFeatures) {
        $cargoArgs += "--no-default-features"
    }
    $cargoArgs += @(
        "--features", $AllocatorFeature,
        "--",
        "--queue-iterations", "$QueueIterations",
        "--queue-workers", "$QueueWorkers",
        "--queue-window", "$QueueWindow",
        "--agent-iterations", "$AgentIterations",
        "--agent-window", "$AgentWindow",
        "--index-documents", "$IndexDocuments",
        "--index-tokens", "$IndexTokens",
        "--index-retained-documents", "$IndexRetainedDocuments"
    )

    Write-Host "Running allocator benchmark for $AllocatorFeature ..."
    if ($AllocatorFeature -eq "allocator-jemalloc") {
        $initialRepair = Repair-JemallocArchiveAlias
        if ($initialRepair.repaired -gt 0) {
            Write-Host "Prepared jemalloc GNU archive aliases before run ($($initialRepair.repaired) repaired)."
        }
    }
    $run = Invoke-CargoCommand -CargoArgs $cargoArgs
    $output = $run.Output
    $errorText = $run.ErrorText

    if ($run.ExitCode -ne 0 -and $AllocatorFeature -eq "allocator-jemalloc") {
        $combinedText = (($output | Out-String) + [Environment]::NewLine + $errorText)
        $isLikelyLinkFailure = $combinedText -match "native static library" -or $combinedText -match "jemalloc"
        if ($isLikelyLinkFailure) {
            for ($attempt = 1; $attempt -le 3 -and $run.ExitCode -ne 0; $attempt++) {
                $patchResult = Repair-JemallocArchiveAlias
                if ($patchResult.repaired -gt 0) {
                    Write-Host "Applied Windows GNU jemalloc archive alias fix ($($patchResult.repaired) repaired); retrying $AllocatorFeature (attempt $attempt/3) ..."
                }
                elseif ($patchResult.candidates -gt 0) {
                    Write-Host "Jemalloc archive aliases already present across $($patchResult.candidates) candidate library paths; retrying $AllocatorFeature (attempt $attempt/3) ..."
                }
                else {
                    Write-Host "No jemalloc.lib candidates discovered yet; retrying $AllocatorFeature (attempt $attempt/3) ..."
                }

                $run = Invoke-CargoCommand -CargoArgs $cargoArgs
                $output = $run.Output
                $errorText = $run.ErrorText
                if ($run.ExitCode -eq 0) {
                    break
                }

                $combinedText = (($output | Out-String) + [Environment]::NewLine + $errorText)
                $isLikelyLinkFailure = $combinedText -match "native static library" -or $combinedText -match "jemalloc"
                if (-not $isLikelyLinkFailure) {
                    break
                }
            }
        }
    }

    if ($run.ExitCode -ne 0) {
        if (-not $AllowPartialResults) {
            throw "Allocator benchmark command failed for $AllocatorFeature"
        }
        if ([string]::IsNullOrWhiteSpace($errorText)) {
            $errorText = ($output | Select-Object -Last 8) -join [Environment]::NewLine
        }
        return [PSCustomObject]@{
            allocator = $AllocatorFeature
            status = "failed"
            error = $errorText
            workloads = @()
        }
    }

    $jsonLine = $output |
        Where-Object { $_ -and $_.Trim().StartsWith("{") -and $_.Trim().EndsWith("}") } |
        Select-Object -Last 1
    if ([string]::IsNullOrWhiteSpace($jsonLine)) {
        if (-not $AllowPartialResults) {
            throw "Could not parse benchmark JSON output for $AllocatorFeature"
        }
        return [PSCustomObject]@{
            allocator = $AllocatorFeature
            status = "failed"
            error = "Missing JSON payload from allocator benchmark run"
            workloads = @()
        }
    }

    $report = $jsonLine | ConvertFrom-Json
    if ($null -eq $report -or $null -eq $report.workloads) {
        if (-not $AllowPartialResults) {
            throw "Malformed benchmark payload for $AllocatorFeature"
        }
        return [PSCustomObject]@{
            allocator = $AllocatorFeature
            status = "failed"
            error = "Malformed benchmark JSON payload"
            workloads = @()
        }
    }
    $report | Add-Member -NotePropertyName "status" -NotePropertyValue "ok" -Force
    return $report
}

function Get-WorkloadMetric {
    param(
        [Parameter(Mandatory = $true)]$Report,
        [Parameter(Mandatory = $true)][string]$WorkloadName
    )

    if ($Report.status -ne "ok") {
        return $null
    }
    $metric = $Report.workloads | Where-Object { $_.name -eq $WorkloadName } | Select-Object -First 1
    if ($null -eq $metric) {
        throw "Missing workload '$WorkloadName' in allocator report '$($Report.allocator)'"
    }
    return $metric
}

if ($SelfTestJemallocRepair) {
    Invoke-JemallocRepairSelfTest
    return
}

& "$PSScriptRoot\bootstrap_env.ps1"

$reports = @(
    Invoke-AllocatorBenchmarkRun -AllocatorFeature "allocator-mimalloc" -NoDefaultFeatures:$false
    Invoke-AllocatorBenchmarkRun -AllocatorFeature "allocator-jemalloc" -NoDefaultFeatures:$true
    Invoke-AllocatorBenchmarkRun -AllocatorFeature "allocator-snmalloc" -NoDefaultFeatures:$true
)

$comparisonRows = @()
$workloads = @("queue", "agent", "indexing")
foreach ($workload in $workloads) {
    foreach ($report in $reports) {
        $metric = Get-WorkloadMetric -Report $report -WorkloadName $workload
        if ($null -eq $metric) {
            $comparisonRows += [PSCustomObject]@{
                workload                 = $workload
                allocator                = $report.allocator
                status                   = $report.status
                throughput_ops_per_sec   = [double]0
                p95_latency_us           = [uint64]0
                fragmentation_permille   = [uint64]0
                fragmentation_percent    = [double]0
                peak_reserved_bytes      = [uint64]0
            }
            continue
        }
        $comparisonRows += [PSCustomObject]@{
            workload                 = $workload
            allocator                = $report.allocator
            status                   = $report.status
            throughput_ops_per_sec   = [double]$metric.throughput_ops_per_sec
            p95_latency_us           = [uint64]$metric.p95_latency_us
            fragmentation_permille   = [uint64]$metric.fragmentation_permille
            fragmentation_percent    = [math]::Round(([double]$metric.fragmentation_permille / 10.0), 2)
            peak_reserved_bytes      = [uint64]$metric.peak_reserved_bytes
        }
    }
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$defaultOutputDir = Join-Path -Path "$PSScriptRoot\.." -ChildPath ".tmp\benchmarks\allocator"
if (-not (Test-Path $defaultOutputDir)) {
    New-Item -ItemType Directory -Path $defaultOutputDir -Force | Out-Null
}

$resolvedOutputPath = $OutputJsonPath
if ([string]::IsNullOrWhiteSpace($resolvedOutputPath)) {
    $resolvedOutputPath = Join-Path -Path $defaultOutputDir -ChildPath "allocator-benchmark-$timestamp.json"
}
else {
    $outputDirectory = Split-Path -Path $resolvedOutputPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path $outputDirectory)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    }
}

$artifact = [PSCustomObject]@{
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    queue_iterations = $QueueIterations
    queue_workers = $QueueWorkers
    queue_window = $QueueWindow
    agent_iterations = $AgentIterations
    agent_window = $AgentWindow
    index_documents = $IndexDocuments
    index_tokens = $IndexTokens
    index_retained_documents = $IndexRetainedDocuments
    runs = $reports
    comparison = $comparisonRows
}

$artifact | ConvertTo-Json -Depth 12 | Set-Content -Path $resolvedOutputPath -Encoding UTF8

Write-Host ""
Write-Host "Allocator benchmark summary (throughput higher is better, p95 latency lower is better):"
foreach ($workload in $workloads) {
    Write-Host ""
    Write-Host "Workload: $workload"
    $comparisonRows |
        Where-Object { $_.workload -eq $workload } |
        Sort-Object -Property throughput_ops_per_sec -Descending |
        Format-Table allocator, status, throughput_ops_per_sec, p95_latency_us, fragmentation_percent -AutoSize
}

$failedRuns = $reports | Where-Object { $_.status -ne "ok" }
if ($failedRuns.Count -gt 0) {
    Write-Host ""
    Write-Host "Allocator runs with failures:"
    foreach ($failed in $failedRuns) {
        Write-Host "- $($failed.allocator): $($failed.error)"
    }
}

Write-Host ""
Write-Host "Allocator benchmark artifact saved to: $resolvedOutputPath"
