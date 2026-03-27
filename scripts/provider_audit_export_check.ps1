param(
    [switch]$FailOnFindings = $true
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $workspaceRoot ".tmp\security"
$artifactPath = Join-Path $artifactRoot "provider_adapter_audit_events.json"

if (-not (Test-Path $artifactRoot)) {
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
}

& cargo run -p runtime_registry --bin provider_audit_export -- --out $artifactPath
if ($LASTEXITCODE -ne 0) {
    throw "provider adapter audit export failed"
}

if (-not (Test-Path $artifactPath)) {
    throw "provider adapter audit artifact missing at $artifactPath"
}

$raw = Get-Content -LiteralPath $artifactPath -Raw -ErrorAction Stop
if ([string]::IsNullOrWhiteSpace($raw)) {
    throw "provider adapter audit artifact is empty"
}

$parsed = $null
try {
    $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
}
catch {
    throw "provider adapter audit artifact is invalid JSON: $($_.Exception.Message)"
}

if ($null -eq $parsed.schema_version) {
    throw "provider adapter audit artifact missing schema_version"
}

$findings = @()
$sensitivePatterns = @(
    "sk-[A-Za-z0-9._-]{12,}",
    "(?i)authorization\s*[:=]?\s*bearer\s+[A-Za-z0-9._-]{12,}",
    "(?i)bearer\s+[A-Za-z0-9._-]{16,}"
)

foreach ($pattern in $sensitivePatterns) {
    if ([regex]::IsMatch($raw, $pattern)) {
        $findings += "raw artifact matches sensitive pattern [$pattern]"
    }
}

if ($findings.Count -gt 0) {
    Write-Host "Provider adapter audit export findings:"
    $findings | ForEach-Object { Write-Host " - $_" }
    if ($FailOnFindings) {
        throw "provider adapter audit export redaction check failed"
    }
}
else {
    Write-Host "Provider adapter audit export check passed: $artifactPath"
}
