$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$sourceCorpusRoot = Join-Path $PSScriptRoot "fixtures\relay_adversarial_corpus"
$testRoot = Join-Path $workspaceRoot (".tmp\relay_attack_corpus_maintenance_selftest_" + [guid]::NewGuid().ToString("N"))
$testCorpusRoot = Join-Path $testRoot "relay_adversarial_corpus"
New-Item -ItemType Directory -Path $testCorpusRoot -Force | Out-Null

try {
    Copy-Item -Path (Join-Path $sourceCorpusRoot "*") -Destination $testCorpusRoot -Recurse -Force

    $manifestPath = Join-Path $testCorpusRoot "manifest.json"
    $corpusReportPath = Join-Path $testRoot "relay_adversarial_corpus_report.json"
    $reportPath = Join-Path $testRoot "relay_attack_corpus_maintenance_report.json"

    & "$PSScriptRoot\relay_adversarial_corpus_check.ps1" `
        -CorpusRoot $testCorpusRoot `
        -ManifestPath $manifestPath `
        -ReportPath $corpusReportPath

    & "$PSScriptRoot\relay_attack_corpus_maintenance_check.ps1" `
        -ManifestPath $manifestPath `
        -CorpusReportPath $corpusReportPath `
        -ReportPath $reportPath `
        -MaxCorpusAgeDays 365

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "relay attack-corpus maintenance report was not generated."
    }
    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$parsed.passed) {
        throw "relay attack-corpus maintenance report indicates failure."
    }
    if ($parsed.check -ne "relay_attack_corpus_maintenance_check") {
        throw "Unexpected check id in relay attack-corpus maintenance report."
    }
    if ($null -eq $parsed.missing_threat_classes -or @($parsed.missing_threat_classes).Count -ne 0) {
        throw "relay attack-corpus maintenance report indicates missing threat-class coverage."
    }

    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $manifest.generated_at_utc = (Get-Date).ToUniversalTime().AddDays(-120).ToString("o")
    $manifest | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    $staleReportPath = Join-Path $testRoot "relay_attack_corpus_maintenance_report_stale.json"
    & "$PSScriptRoot\relay_attack_corpus_maintenance_check.ps1" `
        -ManifestPath $manifestPath `
        -CorpusReportPath $corpusReportPath `
        -ReportPath $staleReportPath `
        -MaxCorpusAgeDays 30 `
        -FailOnFindings:$false

    $staleParsed = Get-Content -LiteralPath $staleReportPath -Raw | ConvertFrom-Json
    if ([bool]$staleParsed.passed) {
        throw "relay attack-corpus maintenance should fail for stale manifest age."
    }
    $staleFindings = @($staleParsed.findings | ForEach-Object { [string]$_ })
    $hasStaleFinding = $false
    foreach ($finding in $staleFindings) {
        if ($finding -like "*stale*") {
            $hasStaleFinding = $true
            break
        }
    }
    if (-not $hasStaleFinding) {
        throw "relay attack-corpus maintenance stale finding was not recorded."
    }

    Write-Host "relay_attack_corpus_maintenance_check.ps1 self-test passed."
}
finally {
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
