param(
    [switch]$FailOnFindings = $true
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $workspaceRoot ".tmp\security"
$artifactPath = Join-Path $artifactRoot "kek_custody_matrix.json"

if (-not (Test-Path $artifactRoot)) {
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
}

$args = @(
    "run",
    "-p",
    "forge_security",
    "--bin",
    "kek_custody_matrix_report",
    "--",
    "--out",
    $artifactPath
)

if (-not [string]::IsNullOrWhiteSpace($env:FORGE_LINUX_KEK_TPM2_CONTEXT)) {
    $args += @("--linux-tpm2-context-path", $env:FORGE_LINUX_KEK_TPM2_CONTEXT)
}
if (-not [string]::IsNullOrWhiteSpace($env:FORGE_LINUX_KEK_KEYRING_SERIAL)) {
    $args += @("--linux-keyring-serial", $env:FORGE_LINUX_KEK_KEYRING_SERIAL)
}
if (-not [string]::IsNullOrWhiteSpace($env:FORGE_LINUX_KEK_SECRET_SERVICE_REF)) {
    $args += @("--linux-secret-service-ref", $env:FORGE_LINUX_KEK_SECRET_SERVICE_REF)
}

& cargo @args
if ($LASTEXITCODE -ne 0) {
    throw "kek custody matrix report generation failed"
}

if (-not (Test-Path $artifactPath)) {
    throw "kek custody matrix artifact missing at $artifactPath"
}

$raw = Get-Content -LiteralPath $artifactPath -Raw -ErrorAction Stop
$parsed = $null
try {
    $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
}
catch {
    throw "kek custody matrix artifact is invalid JSON: $($_.Exception.Message)"
}

$findings = @()
if ($null -eq $parsed.schema_version) {
    $findings += "missing schema_version"
}
if ($null -eq $parsed.linux) {
    $findings += "missing linux custody report"
}
else {
    $baseline = @($parsed.linux.baseline_order)
    $expected = @("linux-tpm2", "linux-keyring", "linux-secret-service")
    if ($baseline.Count -ne $expected.Count) {
        $findings += "linux baseline_order length mismatch"
    }
    else {
        for ($i = 0; $i -lt $expected.Count; $i++) {
            if ($baseline[$i] -ne $expected[$i]) {
                $findings += "linux baseline_order mismatch at index $i"
                break
            }
        }
    }
}

if ($null -eq $parsed.argon2id_policy -or $parsed.argon2id_policy -notlike "*fallback*") {
    $findings += "argon2id fallback policy marker missing"
}

if ($findings.Count -gt 0) {
    Write-Host "KEK custody matrix findings:"
    $findings | ForEach-Object { Write-Host " - $_" }
    if ($FailOnFindings) {
        throw "kek custody matrix validation failed"
    }
}
else {
    Write-Host "KEK custody matrix check passed: $artifactPath"
}
