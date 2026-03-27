param(
    [switch]$FailOnFindings = $true,
    [string]$ReportPath = "",
    [string]$SbomPath = ""
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Get-EnvFlag {
    param([Parameter(Mandatory = $true)][string]$Name)
    $raw = [Environment]::GetEnvironmentVariable($Name, "Process")
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $false
    }
    $normalized = $raw.Trim().ToLowerInvariant()
    return $normalized -in @("1", "true", "yes", "on")
}

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $started = Get-Date
    $passed = $false
    $detail = ""
    try {
        & $Command @Arguments | Out-Host
        $passed = ($LASTEXITCODE -eq 0)
        if (-not $passed) {
            $detail = "command exited with code $LASTEXITCODE"
        }
    }
    catch {
        $passed = $false
        $detail = $_.Exception.Message
    }
    $durationMs = [int][Math]::Round(((Get-Date) - $started).TotalMilliseconds)
    return [PSCustomObject]@{
        name = $Name
        command = "$Command $($Arguments -join ' ')"
        passed = $passed
        duration_ms = $durationMs
        detail = $detail
    }
}

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $workspaceRoot ".tmp\security"
if (-not (Test-Path -LiteralPath $artifactRoot)) {
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
}
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $artifactRoot "artifact_supply_chain_integrity_report.json"
}
if ([string]::IsNullOrWhiteSpace($SbomPath)) {
    $SbomPath = Join-Path $artifactRoot "forge_workspace_sbom.json"
}

$findings = [System.Collections.Generic.List[string]]::new()

$signatureChecks = @(
    (Invoke-CheckedCommand -Name "extension_signed_manifest_gate_tests" -Command "cargo" -Arguments @("test", "-p", "control_plane", "extension_host::tests::enabling_"))
)
foreach ($row in $signatureChecks) {
    if (-not [bool]$row.passed) {
        $findings.Add("$($row.name): $($row.detail)") | Out-Null
    }
}

$sbomParent = Split-Path -Parent $SbomPath
if (-not [string]::IsNullOrWhiteSpace($sbomParent) -and -not (Test-Path -LiteralPath $sbomParent)) {
    New-Item -ItemType Directory -Path $sbomParent -Force | Out-Null
}

$sbomGenerated = $false
$sbomPackageCount = 0
try {
    $sbomRaw = (& cargo metadata --format-version 1 --locked --no-deps | Out-String)
    Set-Content -LiteralPath $SbomPath -Value $sbomRaw -Encoding UTF8
    $sbomParsed = $sbomRaw | ConvertFrom-Json -ErrorAction Stop
    $sbomPackageCount = @($sbomParsed.packages).Count
    if ($sbomPackageCount -le 0) {
        $findings.Add("SBOM generation produced no packages") | Out-Null
    }
    else {
        $sbomGenerated = $true
    }
}
catch {
    $findings.Add("SBOM generation failed: $($_.Exception.Message)") | Out-Null
}

$artifactSpecs = @(
    @{ name = "cargo_lock"; path = (Join-Path $workspaceRoot "Cargo.lock"); required = $true },
    @{ name = "workspace_cargo_toml"; path = (Join-Path $workspaceRoot "Cargo.toml"); required = $true },
    @{ name = "forge_exe"; path = (Join-Path $workspaceRoot "Forge.exe"); required = $false }
)

$artifactDigests = @()
foreach ($spec in $artifactSpecs) {
    $exists = Test-Path -LiteralPath $spec.path
    if (-not $exists) {
        if ([bool]$spec.required) {
            $findings.Add("required artifact missing: $($spec.name) at $($spec.path)") | Out-Null
        }
        $artifactDigests += [PSCustomObject]@{
            name = $spec.name
            path = $spec.path
            required = [bool]$spec.required
            present = $false
            sha256 = $null
            bytes = 0
        }
        continue
    }

    $hash = Get-FileHash -LiteralPath $spec.path -Algorithm SHA256
    $size = (Get-Item -LiteralPath $spec.path).Length
    $artifactDigests += [PSCustomObject]@{
        name = $spec.name
        path = $spec.path
        required = [bool]$spec.required
        present = $true
        sha256 = $hash.Hash.ToLowerInvariant()
        bytes = [int64]$size
    }
}

$requireSlsa = Get-EnvFlag -Name "FORGE_REQUIRE_SLSA_PROVENANCE"
$provenancePath = [Environment]::GetEnvironmentVariable("FORGE_SLSA_PROVENANCE_PATH", "Process")
$provenanceValid = $false
$provenanceDetail = ""
if (-not [string]::IsNullOrWhiteSpace($provenancePath)) {
    if (-not (Test-Path -LiteralPath $provenancePath)) {
        $provenanceDetail = "provenance path missing: $provenancePath"
    }
    else {
        try {
            $provenance = Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json -ErrorAction Stop
            $predicateType = [string]$provenance.predicateType
            $subjectCount = @($provenance.subject).Count
            if ($predicateType.ToLowerInvariant().Contains("slsa") -and $subjectCount -gt 0) {
                $provenanceValid = $true
                $provenanceDetail = "predicateType=$predicateType subjects=$subjectCount"
            }
            else {
                $provenanceDetail = "provenance payload missing SLSA predicateType or subject entries"
            }
        }
        catch {
            $provenanceDetail = "provenance parse failed: $($_.Exception.Message)"
        }
    }
}
elseif ($requireSlsa) {
    $provenanceDetail = "FORGE_REQUIRE_SLSA_PROVENANCE=1 but FORGE_SLSA_PROVENANCE_PATH is unset"
}

if ($requireSlsa -and -not $provenanceValid) {
    $findings.Add("SLSA provenance requirement failed: $provenanceDetail") | Out-Null
}

$requireCosign = Get-EnvFlag -Name "FORGE_REQUIRE_SIGSTORE_COSIGN"
$cosignAvailable = ($null -ne (Get-Command cosign -ErrorAction SilentlyContinue))
$cosignVersion = ""
if ($requireCosign) {
    if (-not $cosignAvailable) {
        $findings.Add("FORGE_REQUIRE_SIGSTORE_COSIGN=1 but cosign binary is unavailable") | Out-Null
    }
    else {
        try {
            $cosignVersion = (& cosign version 2>&1 | Out-String).Trim()
        }
        catch {
            $findings.Add("cosign invocation failed: $($_.Exception.Message)") | Out-Null
        }
    }
}

$passed = ($findings.Count -eq 0)
$report = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    workspace_root = $workspaceRoot
    check = "artifact_supply_chain_integrity_check"
    signature_checks = $signatureChecks
    sbom = [PSCustomObject]@{
        path = $SbomPath
        generated = $sbomGenerated
        package_count = $sbomPackageCount
    }
    artifact_hashes = $artifactDigests
    slsa_provenance = [PSCustomObject]@{
        required = $requireSlsa
        path = if ([string]::IsNullOrWhiteSpace($provenancePath)) { $null } else { $provenancePath }
        valid = $provenanceValid
        detail = $provenanceDetail
    }
    sigstore_cosign = [PSCustomObject]@{
        required = $requireCosign
        available = $cosignAvailable
        version = if ([string]::IsNullOrWhiteSpace($cosignVersion)) { $null } else { $cosignVersion }
    }
    passed = $passed
    findings_count = $findings.Count
    findings = @($findings)
}

$reportParent = Split-Path -Parent $ReportPath
if (-not [string]::IsNullOrWhiteSpace($reportParent) -and -not (Test-Path -LiteralPath $reportParent)) {
    New-Item -ItemType Directory -Path $reportParent -Force | Out-Null
}
$report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $ReportPath -Encoding UTF8

if ($findings.Count -gt 0) {
    Write-Host "Artifact/supply-chain integrity findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "artifact/supply-chain integrity check failed"
    }
}
else {
    Write-Host "Artifact/supply-chain integrity check passed: $ReportPath"
}
