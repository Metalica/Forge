param(
    [switch]$FailOnFindings = $true,
    [string]$ReportPath = "",
    [string]$ArtifactRoot = "",
    [string]$DangerousActionReportPath = "",
    [string]$IncidentReportPath = "",
    [string]$EvidenceDigestPath = ""
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
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $ArtifactRoot "forensic_reset_quarantine_drill_report.json"
}
if ([string]::IsNullOrWhiteSpace($DangerousActionReportPath)) {
    $DangerousActionReportPath = Join-Path $ArtifactRoot "dangerous_action_reauth_report.json"
}
if ([string]::IsNullOrWhiteSpace($IncidentReportPath)) {
    $IncidentReportPath = Join-Path $ArtifactRoot "incident_response_quarantine_report.json"
}
if ([string]::IsNullOrWhiteSpace($EvidenceDigestPath)) {
    $EvidenceDigestPath = Join-Path $ArtifactRoot "incident_quarantine_evidence_digest.json"
}

$findings = [System.Collections.Generic.List[string]]::new()
$scenarioResults = @()
$dangerousReport = $null
$incidentReport = $null
$digestReport = $null

if (-not (Test-Path -LiteralPath $DangerousActionReportPath)) {
    $findings.Add("dangerous-action report missing: $DangerousActionReportPath") | Out-Null
}
else {
    try {
        $dangerousReport = Get-Content -LiteralPath $DangerousActionReportPath -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $findings.Add("dangerous-action report parse error: $($_.Exception.Message)") | Out-Null
    }
}

if (-not (Test-Path -LiteralPath $IncidentReportPath)) {
    $findings.Add("incident-response report missing: $IncidentReportPath") | Out-Null
}
else {
    try {
        $incidentReport = Get-Content -LiteralPath $IncidentReportPath -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $findings.Add("incident-response report parse error: $($_.Exception.Message)") | Out-Null
    }
}

if (-not (Test-Path -LiteralPath $EvidenceDigestPath)) {
    $findings.Add("incident quarantine evidence digest missing: $EvidenceDigestPath") | Out-Null
}
else {
    try {
        $digestReport = Get-Content -LiteralPath $EvidenceDigestPath -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $findings.Add("incident quarantine evidence digest parse error: $($_.Exception.Message)") | Out-Null
    }
}

$dangerousScenarioPassed = $false
$dangerousScenarioDetail = ""
if ($null -ne $dangerousReport) {
    $requiredDangerousChecks = @(
        "runtime_secure_backup_import_reauth_and_typed_confirmation",
        "policy_integrity_drift_reauth_dual_control"
    )
    $dangerousCheckNames = @(@($dangerousReport.checks) | ForEach-Object { [string]$_.name })
    $missingDangerousChecks = @($requiredDangerousChecks | Where-Object { $dangerousCheckNames -notcontains $_ })
    if ($dangerousReport.check -ne "dangerous_action_reauth_check") {
        $dangerousScenarioDetail = "unexpected dangerous-action check id '$($dangerousReport.check)'"
    }
    elseif (-not [bool]$dangerousReport.passed) {
        $dangerousScenarioDetail = "dangerous-action report indicates failure"
    }
    elseif ($missingDangerousChecks.Count -gt 0) {
        $dangerousScenarioDetail = "missing dangerous-action drill checks: $($missingDangerousChecks -join ', ')"
    }
    else {
        $requiredActions = @(
            @($dangerousReport.required_actions) |
            ForEach-Object { [string]$_ } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
        $requiredActionSet = @("secret_export", "runtime_import", "trust_policy_change", "forensic_reset_bypass")
        $missingActions = @($requiredActionSet | Where-Object { $requiredActions -notcontains $_ })
        if ($missingActions.Count -gt 0) {
            $legacyForensicTagOnlyMissing = ($missingActions.Count -eq 1 -and $missingActions[0] -eq "forensic_reset_bypass")
            if ($legacyForensicTagOnlyMissing) {
                $dangerousScenarioPassed = $true
                $dangerousScenarioDetail = "legacy dangerous-action report is missing explicit forensic_reset_bypass action tag; inferred from runtime secure backup/import drill coverage"
            }
            else {
                $dangerousScenarioDetail = "dangerous-action report missing required action tags: $($missingActions -join ', ')"
            }
        }
        else {
            $dangerousScenarioPassed = $true
        }
    }
}
else {
    $dangerousScenarioDetail = "dangerous-action report unavailable"
}
if (-not $dangerousScenarioPassed) {
    $findings.Add("forensic_reset_reauth_drill: $dangerousScenarioDetail") | Out-Null
}
$scenarioResults += [PSCustomObject]@{
    scenario = "forensic_reset_reauth_drill"
    passed = $dangerousScenarioPassed
    detail = $dangerousScenarioDetail
}

$quarantineScenarioPassed = $false
$quarantineScenarioDetail = ""
if ($null -ne $incidentReport) {
    $requiredReleaseGates = @("FORGE_QUARANTINE_REATTESTED", "FORGE_QUARANTINE_REVERIFIED")
    $releaseGates = @(
        @($incidentReport.controls.release_gates) |
        ForEach-Object { [string]$_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    $missingReleaseGates = @($requiredReleaseGates | Where-Object { $releaseGates -notcontains $_ })
    if ($incidentReport.check -ne "incident_response_quarantine_check") {
        $quarantineScenarioDetail = "unexpected incident-response check id '$($incidentReport.check)'"
    }
    elseif (-not [bool]$incidentReport.passed) {
        $quarantineScenarioDetail = "incident-response report indicates failure"
    }
    elseif ($missingReleaseGates.Count -gt 0) {
        $quarantineScenarioDetail = "incident-response report missing release gate env markers: $($missingReleaseGates -join ', ')"
    }
    else {
        $quarantineScenarioPassed = $true
    }
}
else {
    $quarantineScenarioDetail = "incident-response report unavailable"
}
if (-not $quarantineScenarioPassed) {
    $findings.Add("quarantine_mode_drill: $quarantineScenarioDetail") | Out-Null
}
$scenarioResults += [PSCustomObject]@{
    scenario = "quarantine_mode_drill"
    passed = $quarantineScenarioPassed
    detail = $quarantineScenarioDetail
}

$digestScenarioPassed = $false
$digestScenarioDetail = ""
if ($null -ne $digestReport -and $null -ne $incidentReport) {
    $digestSha = [string]$digestReport.sha256
    if ([string]::IsNullOrWhiteSpace($digestSha)) {
        $digestScenarioDetail = "evidence digest sha256 is empty"
    }
    elseif ($digestSha -notmatch "^[0-9a-f]{64}$") {
        $digestScenarioDetail = "evidence digest sha256 is not a 64-char lowercase hex value"
    }
    elseif ([string]$incidentReport.evidence_sha256 -ne $digestSha) {
        $digestScenarioDetail = "incident-response report evidence_sha256 does not match digest report"
    }
    else {
        $digestScenarioPassed = $true
    }
}
else {
    $digestScenarioDetail = "evidence digest or incident-response report unavailable"
}
if (-not $digestScenarioPassed) {
    $findings.Add("quarantine_evidence_digest_drill: $digestScenarioDetail") | Out-Null
}
$scenarioResults += [PSCustomObject]@{
    scenario = "quarantine_evidence_digest_drill"
    passed = $digestScenarioPassed
    detail = $digestScenarioDetail
}

$report = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    workspace_root = $workspaceRoot
    check = "forensic_reset_quarantine_drill_check"
    dangerous_action_report_path = $DangerousActionReportPath
    incident_response_report_path = $IncidentReportPath
    evidence_digest_path = $EvidenceDigestPath
    passed = ($findings.Count -eq 0)
    scenarios = $scenarioResults
    findings_count = $findings.Count
    findings = @($findings)
}

$reportParent = Split-Path -Parent $ReportPath
if (-not [string]::IsNullOrWhiteSpace($reportParent) -and -not (Test-Path -LiteralPath $reportParent)) {
    New-Item -ItemType Directory -Path $reportParent -Force | Out-Null
}
$report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $ReportPath -Encoding UTF8

if ($findings.Count -gt 0) {
    Write-Host "Forensic reset + quarantine drill findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "forensic reset + quarantine drill check failed"
    }
}
else {
    Write-Host "Forensic reset + quarantine drill check passed: $ReportPath"
}
