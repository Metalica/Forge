param(
    [switch]$FailOnFindings = $true,
    [string]$ReportPath = "",
    [string]$ManifestPath = "",
    [string]$ArtifactRoot = ""
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
    $ArtifactRoot = Join-Path $workspaceRoot ".tmp\security"
}
if (-not (Test-Path -LiteralPath $ArtifactRoot)) {
    New-Item -ItemType Directory -Path $ArtifactRoot -Force | Out-Null
}
if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $ArtifactRoot "evidence_integrity_manifest.json"
}
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $ArtifactRoot "evidence_manifest_integrity_report.json"
}

$requiredArtifacts = @(
    [PSCustomObject]@{
        name = "trust_zone_approval_matrix_report"
        path = Join-Path $ArtifactRoot "trust_zone_approval_matrix_report.json"
    },
    [PSCustomObject]@{
        name = "dangerous_full_access_mode_report"
        path = Join-Path $ArtifactRoot "dangerous_full_access_mode_report.json"
    },
    [PSCustomObject]@{
        name = "silent_network_host_escalation_report"
        path = Join-Path $ArtifactRoot "silent_network_host_escalation_report.json"
    },
    [PSCustomObject]@{
        name = "third_party_bypass_lane_report"
        path = Join-Path $ArtifactRoot "third_party_bypass_lane_report.json"
    },
    [PSCustomObject]@{
        name = "crypto_design_note_report"
        path = Join-Path $ArtifactRoot "crypto_design_note_report.json"
    },
    [PSCustomObject]@{
        name = "relay_green_regression_suite_report"
        path = Join-Path $ArtifactRoot "relay_green_regression_suite_report.json"
    },
    [PSCustomObject]@{
        name = "p0_acceptance_evidence_bundle"
        path = Join-Path $ArtifactRoot "p0_acceptance_evidence_bundle.json"
    }
)

$findings = [System.Collections.Generic.List[string]]::new()
$entries = @()

foreach ($artifact in $requiredArtifacts) {
    $present = Test-Path -LiteralPath $artifact.path
    $hash = ""
    $bytes = 0
    $schemaVersion = $null
    $reportPassed = $null
    $detail = ""

    if (-not $present) {
        $findings.Add("$($artifact.name): required artifact missing") | Out-Null
        $detail = "required artifact missing"
    }
    else {
        try {
            $fileItem = Get-Item -LiteralPath $artifact.path -ErrorAction Stop
            $bytes = [int64]$fileItem.Length
            $hash = (Get-FileHash -LiteralPath $artifact.path -Algorithm SHA256).Hash.ToLowerInvariant()

            $parsed = Get-Content -LiteralPath $artifact.path -Raw | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $parsed.schema_version) {
                $findings.Add("$($artifact.name): schema_version missing") | Out-Null
                $detail = "schema_version missing"
            }
            else {
                $schemaVersion = $parsed.schema_version
            }

            if ($null -ne $parsed.PSObject.Properties["passed"]) {
                $reportPassed = [bool]$parsed.passed
                if (-not $reportPassed) {
                    $findings.Add("$($artifact.name): report passed=false") | Out-Null
                    if ([string]::IsNullOrWhiteSpace($detail)) {
                        $detail = "report passed=false"
                    }
                }
            }
            elseif ($null -ne $parsed.PSObject.Properties["gate_passed"]) {
                $reportPassed = [bool]$parsed.gate_passed
                if (-not $reportPassed) {
                    $findings.Add("$($artifact.name): report gate_passed=false") | Out-Null
                    if ([string]::IsNullOrWhiteSpace($detail)) {
                        $detail = "report gate_passed=false"
                    }
                }
            }
        }
        catch {
            $findings.Add("$($artifact.name): parse/hash error: $($_.Exception.Message)") | Out-Null
            if ([string]::IsNullOrWhiteSpace($detail)) {
                $detail = "parse/hash error"
            }
        }
    }

    $entries += [PSCustomObject]@{
        name = $artifact.name
        path = $artifact.path
        present = $present
        sha256 = $hash
        bytes = $bytes
        schema_version = $schemaVersion
        report_passed = $reportPassed
        detail = $detail
    }
}

$manifest = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    check = "evidence_manifest_integrity_check"
    artifact_root = $ArtifactRoot
    hash_algorithm = "sha256"
    entries = $entries
}
$manifestParent = Split-Path -Parent $ManifestPath
if (-not [string]::IsNullOrWhiteSpace($manifestParent) -and -not (Test-Path -LiteralPath $manifestParent)) {
    New-Item -ItemType Directory -Path $manifestParent -Force | Out-Null
}
$manifest | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $ManifestPath -Encoding UTF8
$manifestSha256 = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()

$report = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    workspace_root = $workspaceRoot
    check = "evidence_manifest_integrity_check"
    artifact_root = $ArtifactRoot
    manifest_path = $ManifestPath
    manifest_sha256 = $manifestSha256
    required_artifacts = @($requiredArtifacts | ForEach-Object { [string]$_.name })
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
    Write-Host "Evidence-manifest integrity findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "evidence manifest integrity check failed"
    }
}
else {
    Write-Host "Evidence-manifest integrity check passed: $ReportPath"
}
