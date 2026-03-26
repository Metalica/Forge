param(
    [switch]$FailOnFindings = $true
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $workspaceRoot ".tmp\security"
$artifactPath = Join-Path $artifactRoot "argon2id_benchmark_report.json"

if (-not (Test-Path $artifactRoot)) {
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
}

& cargo run -p forge_security --bin argon2id_bench_report -- --out $artifactPath --runs 12
if ($LASTEXITCODE -ne 0) {
    throw "argon2id benchmark report generation failed"
}

if (-not (Test-Path $artifactPath)) {
    throw "argon2id benchmark artifact missing at $artifactPath"
}

$raw = Get-Content -LiteralPath $artifactPath -Raw -ErrorAction Stop
if ([string]::IsNullOrWhiteSpace($raw)) {
    throw "argon2id benchmark artifact is empty"
}

$parsed = $null
try {
    $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
}
catch {
    throw "argon2id benchmark artifact is invalid JSON: $($_.Exception.Message)"
}

$findings = @()
if ($null -eq $parsed.schema_version) {
    $findings += "missing schema_version"
}
if ($null -eq $parsed.runs_per_profile -or [int]$parsed.runs_per_profile -le 0) {
    $findings += "runs_per_profile must be positive"
}
if ($null -eq $parsed.profiles -or $parsed.profiles.Count -lt 1) {
    $findings += "benchmark profiles are missing"
}
else {
    foreach ($profile in $parsed.profiles) {
        if ([string]::IsNullOrWhiteSpace($profile.name)) {
            $findings += "profile with empty name"
            continue
        }
        if ([double]$profile.avg_ms -le 0 -or [double]$profile.p95_ms -le 0) {
            $findings += "profile '$($profile.name)' has non-positive timing values"
        }
        if ([double]$profile.max_ms -lt [double]$profile.min_ms) {
            $findings += "profile '$($profile.name)' has max_ms lower than min_ms"
        }
    }
}

if ($findings.Count -gt 0) {
    Write-Host "Argon2id benchmark report findings:"
    $findings | ForEach-Object { Write-Host " - $_" }
    if ($FailOnFindings) {
        throw "argon2id benchmark report validation failed"
    }
}
else {
    Write-Host "Argon2id benchmark report check passed: $artifactPath"
}
