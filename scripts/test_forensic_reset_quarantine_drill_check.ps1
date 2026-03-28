$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$testRoot = Join-Path $workspaceRoot (".tmp\forensic_reset_quarantine_drill_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    $evidenceBundlePath = Join-Path $testRoot "p0_acceptance_evidence_bundle.json"
    Set-Content -LiteralPath $evidenceBundlePath -Value '{"schema_version":1,"gate_passed":true}' -Encoding UTF8
    $evidenceSha = (Get-FileHash -LiteralPath $evidenceBundlePath -Algorithm SHA256).Hash.ToLowerInvariant()

    $digestPath = Join-Path $testRoot "incident_quarantine_evidence_digest.json"
    [PSCustomObject]@{
        schema_version = 1
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        evidence_bundle_path = $evidenceBundlePath
        sha256 = $evidenceSha
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $digestPath -Encoding UTF8

    $dangerousReportPath = Join-Path $testRoot "dangerous_action_reauth_report.json"
    [PSCustomObject]@{
        schema_version = 1
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        check = "dangerous_action_reauth_check"
        passed = $true
        required_actions = @(
            "secret_export",
            "runtime_import",
            "trust_policy_change",
            "forensic_reset_bypass"
        )
        checks = @(
            [PSCustomObject]@{
                name = "runtime_secure_backup_import_reauth_and_typed_confirmation"
                passed = $true
            },
            [PSCustomObject]@{
                name = "policy_integrity_drift_reauth_dual_control"
                passed = $true
            }
        )
    } | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $dangerousReportPath -Encoding UTF8

    $incidentReportPath = Join-Path $testRoot "incident_response_quarantine_report.json"
    [PSCustomObject]@{
        schema_version = 1
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        check = "incident_response_quarantine_check"
        passed = $true
        evidence_sha256 = $evidenceSha
        controls = [PSCustomObject]@{
            release_gates = @(
                "FORGE_QUARANTINE_REATTESTED",
                "FORGE_QUARANTINE_REVERIFIED"
            )
        }
    } | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $incidentReportPath -Encoding UTF8

    $reportPath = Join-Path $testRoot "forensic_reset_quarantine_drill_report.json"
    & "$PSScriptRoot\forensic_reset_quarantine_drill_check.ps1" `
        -ArtifactRoot $testRoot `
        -ReportPath $reportPath `
        -DangerousActionReportPath $dangerousReportPath `
        -IncidentReportPath $incidentReportPath `
        -EvidenceDigestPath $digestPath

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "forensic reset/quarantine drill report was not generated."
    }
    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$parsed.passed) {
        throw "forensic reset/quarantine drill report indicates failure."
    }
    if ($parsed.check -ne "forensic_reset_quarantine_drill_check") {
        throw "Unexpected check id in forensic reset/quarantine drill report."
    }
    if ($null -eq $parsed.scenarios -or @($parsed.scenarios).Count -lt 3) {
        throw "forensic reset/quarantine drill report is missing expected scenario coverage."
    }

    $brokenIncident = Get-Content -LiteralPath $incidentReportPath -Raw | ConvertFrom-Json
    $brokenIncident.evidence_sha256 = "0" * 64
    $brokenIncident | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $incidentReportPath -Encoding UTF8

    $negativeReportPath = Join-Path $testRoot "forensic_reset_quarantine_drill_report_negative.json"
    & "$PSScriptRoot\forensic_reset_quarantine_drill_check.ps1" `
        -ArtifactRoot $testRoot `
        -ReportPath $negativeReportPath `
        -DangerousActionReportPath $dangerousReportPath `
        -IncidentReportPath $incidentReportPath `
        -EvidenceDigestPath $digestPath `
        -FailOnFindings:$false

    $negativeParsed = Get-Content -LiteralPath $negativeReportPath -Raw | ConvertFrom-Json
    if ([bool]$negativeParsed.passed) {
        throw "forensic reset/quarantine drill should fail when evidence digest is mismatched."
    }
    $negativeFindings = @($negativeParsed.findings | ForEach-Object { [string]$_ })
    $hasDigestFinding = $false
    foreach ($finding in $negativeFindings) {
        if ($finding -like "quarantine_evidence_digest_drill:*") {
            $hasDigestFinding = $true
            break
        }
    }
    if (-not $hasDigestFinding) {
        throw "forensic reset/quarantine drill should record digest mismatch finding."
    }

    Write-Host "forensic_reset_quarantine_drill_check.ps1 self-test passed."
}
finally {
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
