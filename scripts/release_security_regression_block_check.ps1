param(
    [switch]$FailOnFindings = $true,
    [string]$ReportPath = "",
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
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $ArtifactRoot "release_security_regression_block_report.json"
}

$requiredReports = @(
    [PSCustomObject]@{
        name = "trust_zone_approval_matrix"
        path = Join-Path $ArtifactRoot "trust_zone_approval_matrix_report.json"
        expected_check = "trust_zone_approval_matrix_check"
    },
    [PSCustomObject]@{
        name = "dangerous_full_access_mode"
        path = Join-Path $ArtifactRoot "dangerous_full_access_mode_report.json"
        expected_check = "dangerous_full_access_mode_check"
    },
    [PSCustomObject]@{
        name = "relay_green_regression_suite"
        path = Join-Path $ArtifactRoot "relay_green_regression_suite_report.json"
        expected_check = "relay_green_regression_suite_check"
    },
    [PSCustomObject]@{
        name = "silent_network_host_escalation"
        path = Join-Path $ArtifactRoot "silent_network_host_escalation_report.json"
        expected_check = "silent_network_host_escalation_check"
    },
    [PSCustomObject]@{
        name = "third_party_bypass_lane"
        path = Join-Path $ArtifactRoot "third_party_bypass_lane_report.json"
        expected_check = "third_party_bypass_lane_check"
    },
    [PSCustomObject]@{
        name = "crypto_design_note"
        path = Join-Path $ArtifactRoot "crypto_design_note_report.json"
        expected_check = "crypto_design_note_check"
    },
    [PSCustomObject]@{
        name = "evidence_manifest_integrity"
        path = Join-Path $ArtifactRoot "evidence_manifest_integrity_report.json"
        expected_check = "evidence_manifest_integrity_check"
    }
)

$results = @()
$findings = [System.Collections.Generic.List[string]]::new()

foreach ($spec in $requiredReports) {
    $present = Test-Path -LiteralPath $spec.path
    $passed = $present
    $detail = ""
    $parsed = $null

    if (-not $present) {
        $passed = $false
        $detail = "required report missing"
    }
    else {
        try {
            $parsed = Get-Content -LiteralPath $spec.path -Raw | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $parsed.schema_version) {
                $passed = $false
                $detail = "report missing schema_version"
            }
            elseif ([string]$parsed.check -ne $spec.expected_check) {
                $passed = $false
                $detail = "unexpected check id '$($parsed.check)'"
            }
            elseif ($null -eq $parsed.passed) {
                $passed = $false
                $detail = "report missing passed field"
            }
            elseif (-not [bool]$parsed.passed) {
                $passed = $false
                $detail = "report indicates failure"
            }
        }
        catch {
            $passed = $false
            $detail = "report parse error: $($_.Exception.Message)"
        }
    }

    if (-not $passed) {
        $findings.Add("$($spec.name): $detail") | Out-Null
    }

    $results += [PSCustomObject]@{
        name = $spec.name
        path = $spec.path
        expected_check = $spec.expected_check
        present = $present
        passed = $passed
        detail = $detail
    }
}

$bundlePath = Join-Path $ArtifactRoot "p0_acceptance_evidence_bundle.json"
$bundlePresent = Test-Path -LiteralPath $bundlePath
$bundlePassed = $bundlePresent
$bundleDetail = ""
if (-not $bundlePresent) {
    $bundlePassed = $false
    $bundleDetail = "p0 acceptance evidence bundle missing"
}
else {
    try {
        $bundle = Get-Content -LiteralPath $bundlePath -Raw | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $bundle.schema_version) {
            $bundlePassed = $false
            $bundleDetail = "bundle missing schema_version"
        }
        elseif ($null -eq $bundle.gate_passed) {
            $bundlePassed = $false
            $bundleDetail = "bundle missing gate_passed"
        }
        elseif (-not [bool]$bundle.gate_passed) {
            $bundlePassed = $false
            $bundleDetail = "bundle gate_passed is false"
        }
        elseif ($null -eq $bundle.artifacts -or @($bundle.artifacts).Count -eq 0) {
            $bundlePassed = $false
            $bundleDetail = "bundle artifacts list is empty"
        }
    }
    catch {
        $bundlePassed = $false
        $bundleDetail = "bundle parse error: $($_.Exception.Message)"
    }
}
if (-not $bundlePassed) {
    $findings.Add("p0_acceptance_evidence_bundle: $bundleDetail") | Out-Null
}

$relayReportPath = Join-Path $ArtifactRoot "relay_green_regression_suite_report.json"
$relayCoverageOk = $false
$relayCoverageDetail = ""
if (Test-Path -LiteralPath $relayReportPath) {
    try {
        $relay = Get-Content -LiteralPath $relayReportPath -Raw | ConvertFrom-Json -ErrorAction Stop
        $relayChecks = @($relay.checks | ForEach-Object { [string]$_.name })
        $requiredRelayChecks = @(
            "trust_zone_approval_matrix",
            "dangerous_full_access_mode",
            "silent_network_host_escalation",
            "third_party_bypass_lane",
            "crypto_design_note"
        )
        $missingRelayChecks = @($requiredRelayChecks | Where-Object { $relayChecks -notcontains $_ })
        if ($missingRelayChecks.Count -gt 0) {
            $relayCoverageOk = $false
            $relayCoverageDetail = "relay suite missing required checks: $($missingRelayChecks -join ', ')"
        }
        else {
            $relayCoverageOk = $true
        }
    }
    catch {
        $relayCoverageOk = $false
        $relayCoverageDetail = "relay suite parse error: $($_.Exception.Message)"
    }
}
else {
    $relayCoverageOk = $false
    $relayCoverageDetail = "relay suite report missing for coverage assertion"
}
if (-not $relayCoverageOk) {
    $findings.Add("relay_green_regression_coverage: $relayCoverageDetail") | Out-Null
}

$report = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    workspace_root = $workspaceRoot
    check = "release_security_regression_block_check"
    suite = "full_security_regression_release_block"
    artifact_root = $ArtifactRoot
    reports = $results
    p0_bundle = [PSCustomObject]@{
        path = $bundlePath
        present = $bundlePresent
        passed = $bundlePassed
        detail = $bundleDetail
    }
    relay_coverage = [PSCustomObject]@{
        required = @(
            "trust_zone_approval_matrix",
            "dangerous_full_access_mode",
            "silent_network_host_escalation",
            "third_party_bypass_lane",
            "crypto_design_note"
        )
        passed = $relayCoverageOk
        detail = $relayCoverageDetail
    }
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
    Write-Host "Release security-regression block findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "release security regression block check failed"
    }
}
else {
    Write-Host "Release security-regression block check passed: $ReportPath"
}
