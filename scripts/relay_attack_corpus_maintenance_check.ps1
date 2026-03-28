param(
    [switch]$FailOnFindings = $true,
    [string]$ReportPath = "",
    [string]$CorpusReportPath = "",
    [string]$CorpusRoot = "",
    [string]$ManifestPath = "",
    [int]$MaxCorpusAgeDays = 90,
    [string[]]$RequiredThreatClasses = @(
        "prompt_injection",
        "secret_leak",
        "token_confusion",
        "cache_poisoning",
        "relay_fallback_abuse",
        "telemetry_leak",
        "memory_poisoning",
        "path_traversal"
    )
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $workspaceRoot ".tmp\security"
if (-not (Test-Path -LiteralPath $artifactRoot)) {
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
}
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $artifactRoot "relay_attack_corpus_maintenance_report.json"
}
if ([string]::IsNullOrWhiteSpace($CorpusReportPath)) {
    $CorpusReportPath = Join-Path $artifactRoot "relay_adversarial_corpus_report.json"
}
if ([string]::IsNullOrWhiteSpace($CorpusRoot)) {
    $CorpusRoot = Join-Path $PSScriptRoot "fixtures\relay_adversarial_corpus"
}
if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $CorpusRoot "manifest.json"
}

$findings = [System.Collections.Generic.List[string]]::new()
$manifest = $null
$corpusReport = $null
$manifestThreatClasses = @()
$reportThreatClasses = @()
$manifestAgeDays = $null

if (-not (Test-Path -LiteralPath $ManifestPath)) {
    $findings.Add("manifest missing: $ManifestPath") | Out-Null
}
else {
    try {
        $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $findings.Add("manifest parse error: $($_.Exception.Message)") | Out-Null
    }
}

if (-not (Test-Path -LiteralPath $CorpusReportPath)) {
    $findings.Add("corpus integrity report missing: $CorpusReportPath") | Out-Null
}
else {
    try {
        $corpusReport = Get-Content -LiteralPath $CorpusReportPath -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $findings.Add("corpus integrity report parse error: $($_.Exception.Message)") | Out-Null
    }
}

if ($null -ne $manifest) {
    if ([int]$manifest.schema_version -ne 1) {
        $findings.Add("unsupported manifest schema_version: $($manifest.schema_version)") | Out-Null
    }

    $entries = @($manifest.entries)
    if ($entries.Count -eq 0) {
        $findings.Add("manifest contains no corpus entries") | Out-Null
    }

    $manifestThreatClasses = @(
        $entries |
        ForEach-Object { [string]$_.threat_class } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
    )

    $duplicateIds = @(
        $entries |
        Group-Object -Property id |
        Where-Object { $_.Count -gt 1 } |
        Select-Object -ExpandProperty Name
    )
    if ($duplicateIds.Count -gt 0) {
        $findings.Add("manifest contains duplicate entry ids: $($duplicateIds -join ', ')") | Out-Null
    }

    $duplicatePaths = @(
        $entries |
        Group-Object -Property path |
        Where-Object { $_.Count -gt 1 } |
        Select-Object -ExpandProperty Name
    )
    if ($duplicatePaths.Count -gt 0) {
        $findings.Add("manifest contains duplicate fixture paths: $($duplicatePaths -join ', ')") | Out-Null
    }

    if ([string]::IsNullOrWhiteSpace([string]$manifest.generated_at_utc)) {
        $findings.Add("manifest is missing generated_at_utc") | Out-Null
    }
    else {
        $generatedAt = $null
        try {
            $generatedAt = [DateTimeOffset]::Parse([string]$manifest.generated_at_utc, [System.Globalization.CultureInfo]::InvariantCulture)
        }
        catch {
            $findings.Add("manifest generated_at_utc parse error: $($_.Exception.Message)") | Out-Null
        }

        if ($null -ne $generatedAt) {
            $now = [DateTimeOffset]::UtcNow
            $manifestAgeDays = [Math]::Round(($now - $generatedAt.ToUniversalTime()).TotalDays, 3)
            if ($manifestAgeDays -gt $MaxCorpusAgeDays) {
                $findings.Add("attack corpus manifest is stale (age_days=$manifestAgeDays, max_allowed_days=$MaxCorpusAgeDays)") | Out-Null
            }
            if ($manifestAgeDays -lt -1) {
                $findings.Add("attack corpus manifest timestamp appears in the future (age_days=$manifestAgeDays)") | Out-Null
            }
        }
    }
}

if ($null -ne $corpusReport) {
    if ($corpusReport.check -ne "relay_adversarial_corpus_check") {
        $findings.Add("unexpected corpus report check id: $($corpusReport.check)") | Out-Null
    }
    if ($null -eq $corpusReport.schema_version) {
        $findings.Add("corpus report missing schema_version") | Out-Null
    }
    if (-not [bool]$corpusReport.passed) {
        $findings.Add("corpus integrity report indicates failure") | Out-Null
    }
    $reportThreatClasses = @(
        @($corpusReport.threat_classes) |
        ForEach-Object { [string]$_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
    )
}

$requiredThreatClassSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($threatClass in $RequiredThreatClasses) {
    if (-not [string]::IsNullOrWhiteSpace([string]$threatClass)) {
        $requiredThreatClassSet.Add(([string]$threatClass).Trim()) | Out-Null
    }
}
$missingThreatClasses = @()
foreach ($requiredThreatClass in $requiredThreatClassSet) {
    if ($manifestThreatClasses -notcontains $requiredThreatClass) {
        $missingThreatClasses += $requiredThreatClass
    }
}
if ($missingThreatClasses.Count -gt 0) {
    $findings.Add("required threat classes missing from corpus manifest: $($missingThreatClasses -join ', ')") | Out-Null
}

if ($manifestThreatClasses.Count -gt 0 -and $reportThreatClasses.Count -gt 0) {
    $manifestOnly = @($manifestThreatClasses | Where-Object { $reportThreatClasses -notcontains $_ })
    $reportOnly = @($reportThreatClasses | Where-Object { $manifestThreatClasses -notcontains $_ })
    if ($manifestOnly.Count -gt 0 -or $reportOnly.Count -gt 0) {
        $findings.Add("corpus report threat classes do not match manifest (manifest_only=$($manifestOnly -join ', '); report_only=$($reportOnly -join ', '))") | Out-Null
    }
}

$report = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    workspace_root = $workspaceRoot
    check = "relay_attack_corpus_maintenance_check"
    corpus_root = $CorpusRoot
    manifest_path = $ManifestPath
    corpus_report_path = $CorpusReportPath
    max_corpus_age_days = $MaxCorpusAgeDays
    manifest_age_days = $manifestAgeDays
    required_threat_classes = @($requiredThreatClassSet)
    observed_threat_classes = $manifestThreatClasses
    missing_threat_classes = @($missingThreatClasses)
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
    Write-Host "Relay attack-corpus maintenance findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "relay attack-corpus maintenance check failed"
    }
}
else {
    Write-Host "Relay attack-corpus maintenance check passed: $ReportPath"
}
