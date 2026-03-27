param(
    [string]$BenchmarkJsonPath = "",
    [string]$OutputPath = "",
    [switch]$FailOnFindings = $true
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Resolve-BenchmarkPath {
    param(
        [Parameter(Mandatory = $true)][string]$WorkspaceRoot,
        [string]$ProvidedPath
    )

    if (-not [string]::IsNullOrWhiteSpace($ProvidedPath)) {
        $resolved = Resolve-Path -LiteralPath $ProvidedPath -ErrorAction Stop
        return $resolved.Path
    }

    $phase4Dir = Join-Path $WorkspaceRoot ".tmp\benchmarks\phase4"
    if (-not (Test-Path -LiteralPath $phase4Dir)) {
        throw "phase4 benchmark directory missing: $phase4Dir (provide -BenchmarkJsonPath)"
    }

    $latest = Get-ChildItem -LiteralPath $phase4Dir -File -Filter "confidential-relay-benchmark-*.json" |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $latest) {
        throw "no phase4 benchmark artifact found in $phase4Dir (provide -BenchmarkJsonPath)"
    }
    return $latest.FullName
}

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$benchmarkPath = Resolve-BenchmarkPath -WorkspaceRoot $workspaceRoot -ProvidedPath $BenchmarkJsonPath

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $workspaceRoot ".tmp\security\relay_attestation_verification_report.json"
}

$outputDirectory = Split-Path -Parent $OutputPath
if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

$raw = Get-Content -LiteralPath $benchmarkPath -Raw -ErrorAction Stop
if ([string]::IsNullOrWhiteSpace($raw)) {
    throw "phase4 benchmark JSON is empty: $benchmarkPath"
}

try {
    $benchmark = $raw | ConvertFrom-Json -ErrorAction Stop
}
catch {
    throw "phase4 benchmark JSON parse failed at ${benchmarkPath}: $($_.Exception.Message)"
}

$findings = @()
if ($benchmark.benchmark -ne "phase4_confidential_relay_gate") {
    $findings += "unexpected benchmark kind: expected phase4_confidential_relay_gate got '$($benchmark.benchmark)'"
}

$decisionPassed = $false
if ($null -eq $benchmark.decision -or $null -eq $benchmark.decision.passed) {
    $findings += "decision.passed missing from benchmark payload"
}
else {
    $decisionPassed = [bool]$benchmark.decision.passed
    if (-not $decisionPassed) {
        $findings += "phase4 benchmark decision passed=false"
    }
}

$workloads = @()
$sourceWorkloads = @($benchmark.workloads)
if ($sourceWorkloads.Count -eq 0) {
    $findings += "benchmark workloads list is empty"
}

foreach ($row in $sourceWorkloads) {
    $name = [string]$row.name
    if ([string]::IsNullOrWhiteSpace($name)) {
        $name = "unknown"
        $findings += "workload row is missing name"
    }

    $sampleCount = 0
    try {
        $sampleCount = [int]$row.sample_count
    }
    catch {
        $findings += "workload $name has invalid sample_count"
    }

    if ($null -eq $row.confidential) {
        $findings += "workload $name missing confidential metrics block"
        continue
    }

    $verifyAvgMs = 0
    try {
        $verifyAvgMs = [int]$row.confidential.verify_avg_ms
    }
    catch {
        $findings += "workload $name has invalid verify_avg_ms"
    }
    $verifyP95Ms = 0
    try {
        $verifyP95Ms = [int]$row.confidential.verify_p95_ms
    }
    catch {
        $findings += "workload $name has invalid verify_p95_ms"
    }
    $relayAvgMs = 0
    try {
        $relayAvgMs = [int]$row.confidential.relay_avg_ms
    }
    catch {
        $findings += "workload $name has invalid relay_avg_ms"
    }
    $relayP95Ms = 0
    try {
        $relayP95Ms = [int]$row.confidential.relay_p95_ms
    }
    catch {
        $findings += "workload $name has invalid relay_p95_ms"
    }
    $totalPathAvgMs = 0
    try {
        $totalPathAvgMs = [int]$row.confidential.total_path_avg_ms
    }
    catch {
        $findings += "workload $name has invalid total_path_avg_ms"
    }
    $totalPathP95Ms = 0
    try {
        $totalPathP95Ms = [int]$row.confidential.total_path_p95_ms
    }
    catch {
        $findings += "workload $name has invalid total_path_p95_ms"
    }

    if ($verifyAvgMs -le 0) {
        $findings += "workload $name verify_avg_ms must be > 0 to prove attestation path executed"
    }
    if ($verifyP95Ms -le 0) {
        $findings += "workload $name verify_p95_ms must be > 0 to prove attestation path executed"
    }

    $verifySharePct = 0.0
    if ($totalPathAvgMs -gt 0) {
        $verifySharePct = [Math]::Round(($verifyAvgMs * 100.0) / $totalPathAvgMs, 2)
    }

    $workloads += [PSCustomObject]@{
        name = $name
        sample_count = $sampleCount
        verify_avg_ms = $verifyAvgMs
        verify_p95_ms = $verifyP95Ms
        relay_avg_ms = $relayAvgMs
        relay_p95_ms = $relayP95Ms
        total_path_avg_ms = $totalPathAvgMs
        total_path_p95_ms = $totalPathP95Ms
        verify_share_pct_of_total = $verifySharePct
    }
}

$gatePassed = $findings.Count -eq 0
$report = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    benchmark_source_path = $benchmarkPath
    decision_passed = $decisionPassed
    attestation_verification = [PSCustomObject]@{
        workload_count = $workloads.Count
        workloads = $workloads
    }
    findings = $findings
    gate_passed = $gatePassed
}

$report | ConvertTo-Json -Depth 12 | Set-Content -Path $OutputPath -Encoding UTF8

if ($gatePassed) {
    Write-Host "Relay attestation verification report check passed: $OutputPath"
}
else {
    Write-Host "Relay attestation verification report findings:"
    $findings | ForEach-Object { Write-Host " - $_" }
    if ($FailOnFindings) {
        throw "relay attestation verification report check failed"
    }
}
