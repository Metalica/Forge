param(
    [switch]$FailOnFindings = $true,
    [string]$ReportPath = "",
    [string]$CandidateId = "",
    [string]$RetentionRoot = ""
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Invoke-LeakCheck {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$CheckReportPath
    )

    $started = Get-Date
    $detail = ""
    $passed = $false
    $checkObj = $null
    try {
        & $ScriptPath -ReportPath $CheckReportPath -FailOnFindings:$false
        if (-not (Test-Path -LiteralPath $CheckReportPath)) {
            $detail = "check report missing"
        }
        else {
            $checkObj = Get-Content -LiteralPath $CheckReportPath -Raw | ConvertFrom-Json -ErrorAction Stop
            $passed = [bool]$checkObj.passed
            if (-not $passed) {
                $detail = "underlying check reported findings"
            }
        }
    }
    catch {
        $passed = $false
        $detail = $_.Exception.Message
    }
    $durationMs = [int][Math]::Round(((Get-Date) - $started).TotalMilliseconds)

    return [PSCustomObject]@{
        name = $Name
        script = $ScriptPath
        report_path = $CheckReportPath
        passed = $passed
        duration_ms = $durationMs
        detail = $detail
        findings_count = if ($null -ne $checkObj -and $null -ne $checkObj.findings_count) { [int]$checkObj.findings_count } else { $null }
    }
}

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $workspaceRoot ".tmp\security"
if (-not (Test-Path -LiteralPath $artifactRoot)) {
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
}

if ([string]::IsNullOrWhiteSpace($CandidateId)) {
    $envCandidateId = [Environment]::GetEnvironmentVariable("FORGE_RELEASE_CANDIDATE_ID", "Process")
    if ([string]::IsNullOrWhiteSpace($envCandidateId)) {
        $CandidateId = "rc-" + (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
    }
    else {
        $CandidateId = $envCandidateId.Trim()
    }
}

if ([string]::IsNullOrWhiteSpace($RetentionRoot)) {
    $RetentionRoot = Join-Path $artifactRoot "release_candidates"
}
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $artifactRoot "release_candidate_secret_leak_report.json"
}

$candidateRoot = Join-Path $RetentionRoot $CandidateId
if (-not (Test-Path -LiteralPath $candidateRoot)) {
    New-Item -ItemType Directory -Path $candidateRoot -Force | Out-Null
}

$checkDefinitions = @(
    [PSCustomObject]@{
        name = "repo_secrets_scan"
        script = Join-Path $PSScriptRoot "secrets_scan.ps1"
        report = Join-Path $candidateRoot "secret_leak_report.json"
    },
    [PSCustomObject]@{
        name = "process_cmdline_secret_scan"
        script = Join-Path $PSScriptRoot "process_cmdline_secret_scan.ps1"
        report = Join-Path $candidateRoot "process_cmdline_secret_scan_report.json"
    }
)

$findings = [System.Collections.Generic.List[string]]::new()
$checkResults = @()
foreach ($check in $checkDefinitions) {
    $result = Invoke-LeakCheck -Name $check.name -ScriptPath $check.script -CheckReportPath $check.report
    $checkResults += $result
    if (-not [bool]$result.passed) {
        $suffix = if ([string]::IsNullOrWhiteSpace([string]$result.detail)) { "failed" } else { $result.detail }
        $findings.Add("$($check.name): $suffix") | Out-Null
    }
}

$artifacts = @()
foreach ($check in $checkResults) {
    $exists = Test-Path -LiteralPath $check.report_path
    $sha256 = $null
    $bytes = 0
    if ($exists) {
        $sha256 = (Get-FileHash -LiteralPath $check.report_path -Algorithm SHA256).Hash.ToLowerInvariant()
        $bytes = [int64](Get-Item -LiteralPath $check.report_path).Length
    }
    $artifacts += [PSCustomObject]@{
        name = $check.name
        path = $check.report_path
        present = $exists
        sha256 = $sha256
        bytes = $bytes
    }
}

$retentionManifestPath = Join-Path $candidateRoot "retention_manifest.json"
$retentionManifest = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    check = "release_candidate_secret_leak_check"
    candidate_id = $CandidateId
    artifacts = $artifacts
}
$retentionManifest | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $retentionManifestPath -Encoding UTF8

$passed = ($findings.Count -eq 0)
$report = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    workspace_root = $workspaceRoot
    check = "release_candidate_secret_leak_check"
    candidate_id = $CandidateId
    retention_root = $RetentionRoot
    candidate_root = $candidateRoot
    retention_manifest_path = $retentionManifestPath
    checks = $checkResults
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
    Write-Host "Release-candidate secret leak findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "release-candidate secret leak check failed"
    }
}
else {
    Write-Host "Release-candidate secret leak check passed: $ReportPath"
}
