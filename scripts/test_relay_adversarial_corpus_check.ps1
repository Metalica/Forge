$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$sourceCorpusRoot = Join-Path $PSScriptRoot "fixtures\relay_adversarial_corpus"
$testRoot = Join-Path $workspaceRoot (".tmp\relay_adversarial_corpus_selftest_" + [guid]::NewGuid().ToString("N"))
$testCorpusRoot = Join-Path $testRoot "relay_adversarial_corpus"
New-Item -ItemType Directory -Path $testCorpusRoot -Force | Out-Null

try {
    Copy-Item -Path (Join-Path $sourceCorpusRoot "*") -Destination $testCorpusRoot -Recurse -Force

    $reportPath = Join-Path $testRoot "relay_adversarial_corpus_report.json"
    $manifestPath = Join-Path $testCorpusRoot "manifest.json"

    & "$PSScriptRoot\relay_adversarial_corpus_check.ps1" `
        -ReportPath $reportPath `
        -CorpusRoot $testCorpusRoot `
        -ManifestPath $manifestPath

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "relay adversarial corpus report was not generated."
    }

    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$parsed.passed) {
        throw "relay adversarial corpus report indicates failure."
    }
    if ($parsed.check -ne "relay_adversarial_corpus_check") {
        throw "Unexpected check id in relay adversarial corpus report."
    }
    if ([int]$parsed.corpus_entry_count -lt 8) {
        throw "relay adversarial corpus report is missing expected fixture coverage."
    }

    $tamperedPath = Join-Path $testCorpusRoot "secret_leak_exfil_prompt.txt"
    Add-Content -LiteralPath $tamperedPath -Value "tampered"

    $tamperedReportPath = Join-Path $testRoot "relay_adversarial_corpus_report_tampered.json"
    & "$PSScriptRoot\relay_adversarial_corpus_check.ps1" `
        -FailOnFindings:$false `
        -ReportPath $tamperedReportPath `
        -CorpusRoot $testCorpusRoot `
        -ManifestPath $manifestPath

    $tamperedParsed = Get-Content -LiteralPath $tamperedReportPath -Raw | ConvertFrom-Json
    if ([bool]$tamperedParsed.passed) {
        throw "relay adversarial corpus check did not fail after fixture tampering."
    }
    if ([int]$tamperedParsed.findings_count -lt 1) {
        throw "relay adversarial corpus tamper findings were not recorded."
    }

    Write-Host "relay_adversarial_corpus_check.ps1 self-test passed."
}
finally {
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
