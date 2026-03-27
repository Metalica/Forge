$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$testRoot = Join-Path $workspaceRoot (".tmp\incident_response_quarantine_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    $reportPath = Join-Path $testRoot "incident_response_quarantine_report.json"
    $evidenceBundlePath = Join-Path $testRoot "p0_acceptance_evidence_bundle.json"
    $evidenceDigestPath = Join-Path $testRoot "incident_quarantine_evidence_digest.json"

    Set-Content -LiteralPath $evidenceBundlePath -Value '{"schema_version":1,"gate_passed":true}' -Encoding UTF8

    & "$PSScriptRoot\incident_response_quarantine_check.ps1" `
        -ReportPath $reportPath `
        -EvidenceBundlePath $evidenceBundlePath `
        -EvidenceDigestPath $evidenceDigestPath `
        -SkipEvidenceBundleGeneration

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "incident-response quarantine report was not generated."
    }
    if (-not (Test-Path -LiteralPath $evidenceDigestPath)) {
        throw "incident-response quarantine evidence digest was not generated."
    }
    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$parsed.passed) {
        throw "incident-response quarantine report indicates failure."
    }
    if ($parsed.check -ne "incident_response_quarantine_check") {
        throw "Unexpected check id in incident-response quarantine report."
    }
    if ([string]::IsNullOrWhiteSpace([string]$parsed.evidence_sha256)) {
        throw "incident-response quarantine report is missing evidence_sha256."
    }

    Write-Host "incident_response_quarantine_check.ps1 self-test passed."
}
finally {
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
