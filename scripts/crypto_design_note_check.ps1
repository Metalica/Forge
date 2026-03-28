param(
    [switch]$FailOnFindings = $true,
    [string]$ReportPath = "",
    [string]$DesignNotePath = ""
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $workspaceRoot ".tmp\security"
if (-not (Test-Path -LiteralPath $artifactRoot)) {
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
}
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $artifactRoot "crypto_design_note_report.json"
}
if ([string]::IsNullOrWhiteSpace($DesignNotePath)) {
    $DesignNotePath = Join-Path $workspaceRoot "docs\FORGE_CRYPTO_DESIGN_NOTE.md"
}

$findings = [System.Collections.Generic.List[string]]::new()
$sectionsVerified = @()
$sha256 = ""

if (-not (Test-Path -LiteralPath $DesignNotePath)) {
    $findings.Add("design note missing: $DesignNotePath") | Out-Null
}
else {
    $raw = Get-Content -LiteralPath $DesignNotePath -Raw
    $requiredPatterns = @(
        "^# Forge Crypto Design Note",
        "^## 1\. Scope and Security Goals",
        "^## 2\. Threat Model",
        "^## 3\. Secret Custody and Delivery",
        "^## 4\. Envelope Encryption and KEK Model",
        "^## 5\. Algorithms and Parameter Baseline",
        "^## 6\. Integrity, Signing, and Release Binding",
        "^## 7\. Rotation, Revocation, and Recovery",
        "^## 8\. Evidence and Audit Artifacts"
    )
    foreach ($pattern in $requiredPatterns) {
        if ([regex]::IsMatch($raw, $pattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)) {
            $sectionsVerified += $pattern
        }
        else {
            $findings.Add("design note missing required section pattern: $pattern") | Out-Null
        }
    }

    $algorithmKeywords = @("AES-256", "Argon2id", "Ed25519", "SHA-256")
    foreach ($keyword in $algorithmKeywords) {
        if ($raw -notmatch [regex]::Escape($keyword)) {
            $findings.Add("design note missing algorithm keyword: $keyword") | Out-Null
        }
    }

    $hash = Get-FileHash -LiteralPath $DesignNotePath -Algorithm SHA256
    $sha256 = $hash.Hash.ToLowerInvariant()
}

$report = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    workspace_root = $workspaceRoot
    check = "crypto_design_note_check"
    design_note_path = $DesignNotePath
    sha256 = $sha256
    required_sections = @(
        "scope_and_security_goals",
        "threat_model",
        "secret_custody_and_delivery",
        "envelope_encryption_and_kek_model",
        "algorithms_and_parameter_baseline",
        "integrity_signing_release_binding",
        "rotation_revocation_recovery",
        "evidence_and_audit_artifacts"
    )
    sections_verified_count = $sectionsVerified.Count
    passed = ($findings.Count -eq 0)
    findings_count = $findings.Count
    findings = @($findings)
}

$reportParent = Split-Path -Parent $ReportPath
if (-not [string]::IsNullOrWhiteSpace($reportParent) -and -not (Test-Path -LiteralPath $reportParent)) {
    New-Item -ItemType Directory -Path $reportParent -Force | Out-Null
}
$report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $ReportPath -Encoding UTF8

if ($findings.Count -gt 0) {
    Write-Host "Crypto design note findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "crypto design note check failed"
    }
}
else {
    Write-Host "Crypto design note check passed: $ReportPath"
}
