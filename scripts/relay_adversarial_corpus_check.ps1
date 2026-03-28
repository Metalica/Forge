param(
    [switch]$FailOnFindings = $true,
    [string]$ReportPath = "",
    [string]$CorpusRoot = "",
    [string]$ManifestPath = ""
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $workspaceRoot ".tmp\security"
if (-not (Test-Path -LiteralPath $artifactRoot)) {
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
}
if ([string]::IsNullOrWhiteSpace($CorpusRoot)) {
    $CorpusRoot = Join-Path $PSScriptRoot "fixtures\relay_adversarial_corpus"
}
if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $CorpusRoot "manifest.json"
}
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $artifactRoot "relay_adversarial_corpus_report.json"
}

$results = @()
$findings = [System.Collections.Generic.List[string]]::new()
$extraFiles = [System.Collections.Generic.List[string]]::new()
$threatClasses = @()
$entryCount = 0
$allowedPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$allowedPaths.Add("manifest.json") | Out-Null

function Get-RelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$BasePath,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $baseUri = New-Object System.Uri(($BasePath.TrimEnd("\") + "\"))
    $pathUri = New-Object System.Uri($Path)
    return [System.Uri]::UnescapeDataString($baseUri.MakeRelativeUri($pathUri).ToString()).Replace("/", "\")
}

if (-not (Test-Path -LiteralPath $CorpusRoot)) {
    $findings.Add("corpus root missing: $CorpusRoot") | Out-Null
}
if (-not (Test-Path -LiteralPath $ManifestPath)) {
    $findings.Add("manifest missing: $ManifestPath") | Out-Null
}

$manifest = $null
if ($findings.Count -eq 0) {
    try {
        $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $findings.Add("manifest parse error: $($_.Exception.Message)") | Out-Null
    }
}

$entries = @()
if ($null -ne $manifest) {
    if ([int]$manifest.schema_version -ne 1) {
        $findings.Add("unsupported manifest schema_version: $($manifest.schema_version)") | Out-Null
    }
    $entries = @($manifest.entries)
    if ($entries.Count -eq 0) {
        $findings.Add("manifest has no entries") | Out-Null
    }
}

foreach ($entry in $entries) {
    $entryId = [string]$entry.id
    $threatClass = [string]$entry.threat_class
    $relativePath = ([string]$entry.path).Replace("/", "\").TrimStart("\")
    $expectedSha256 = ([string]$entry.sha256).ToLowerInvariant()
    $observedSha256 = ""
    $exists = $false
    $hashMatch = $false
    $detail = ""

    if ([string]::IsNullOrWhiteSpace($entryId)) {
        $entryId = "unknown"
    }
    if ([string]::IsNullOrWhiteSpace($relativePath)) {
        $detail = "manifest entry path is empty"
    }
    else {
        $allowedPaths.Add($relativePath) | Out-Null
        $entryPath = Join-Path $CorpusRoot $relativePath
        $exists = Test-Path -LiteralPath $entryPath
        if (-not $exists) {
            $detail = "fixture missing: $relativePath"
        }
        else {
            $observedSha256 = (Get-FileHash -LiteralPath $entryPath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ([string]::IsNullOrWhiteSpace($expectedSha256)) {
                $detail = "expected sha256 missing in manifest"
            }
            else {
                $hashMatch = ($observedSha256 -eq $expectedSha256)
                if (-not $hashMatch) {
                    $detail = "fixture hash mismatch"
                }
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($threatClass)) {
        $threatClasses += $threatClass
    }

    $entryPassed = ($exists -and $hashMatch -and [string]::IsNullOrWhiteSpace($detail))
    if (-not $entryPassed) {
        $findings.Add("${entryId}: $detail") | Out-Null
    }

    $results += [PSCustomObject]@{
        id = $entryId
        threat_class = $threatClass
        relative_path = $relativePath
        expected_sha256 = $expectedSha256
        observed_sha256 = $observedSha256
        exists = $exists
        hash_match = $hashMatch
        passed = $entryPassed
        detail = $detail
    }
}

if (Test-Path -LiteralPath $CorpusRoot) {
    $allFiles = @(Get-ChildItem -LiteralPath $CorpusRoot -File -Recurse)
    foreach ($file in $allFiles) {
        $relativeFilePath = Get-RelativePath -BasePath $CorpusRoot -Path $file.FullName
        if (-not $allowedPaths.Contains($relativeFilePath)) {
            $extraFiles.Add($relativeFilePath) | Out-Null
        }
    }
}

if ($extraFiles.Count -gt 0) {
    $findings.Add("unexpected corpus files present: $($extraFiles -join ', ')") | Out-Null
}

$entryCount = @($entries).Count
$threatClasses = @($threatClasses | Sort-Object -Unique)

$report = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    workspace_root = $workspaceRoot
    check = "relay_adversarial_corpus_check"
    corpus_root = $CorpusRoot
    manifest_path = $ManifestPath
    corpus_entry_count = $entryCount
    threat_classes = $threatClasses
    files_checked_count = @($results).Count
    extra_files = @($extraFiles)
    passed = ($findings.Count -eq 0)
    checks = $results
    findings_count = $findings.Count
    findings = @($findings)
}

$reportParent = Split-Path -Parent $ReportPath
if (-not [string]::IsNullOrWhiteSpace($reportParent) -and -not (Test-Path -LiteralPath $reportParent)) {
    New-Item -ItemType Directory -Path $reportParent -Force | Out-Null
}
$report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $ReportPath -Encoding UTF8

if ($findings.Count -gt 0) {
    Write-Host "Relay adversarial corpus findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "relay adversarial corpus check failed"
    }
}
else {
    Write-Host "Relay adversarial corpus check passed: $ReportPath"
}
