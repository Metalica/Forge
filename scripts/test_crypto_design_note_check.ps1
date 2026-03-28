$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$testRoot = Join-Path $workspaceRoot (".tmp\crypto_design_note_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    $designNotePath = Join-Path $testRoot "FORGE_CRYPTO_DESIGN_NOTE.md"
    @'
# Forge Crypto Design Note
## 1. Scope and Security Goals
## 2. Threat Model
## 3. Secret Custody and Delivery
## 4. Envelope Encryption and KEK Model
## 5. Algorithms and Parameter Baseline
AES-256 Argon2id Ed25519 SHA-256
## 6. Integrity, Signing, and Release Binding
## 7. Rotation, Revocation, and Recovery
## 8. Evidence and Audit Artifacts
'@ | Set-Content -LiteralPath $designNotePath -Encoding UTF8

    $reportPath = Join-Path $testRoot "crypto_design_note_report.json"
    & "$PSScriptRoot\crypto_design_note_check.ps1" `
        -DesignNotePath $designNotePath `
        -ReportPath $reportPath

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "crypto design note report was not generated."
    }
    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$parsed.passed) {
        throw "crypto design note report indicates failure."
    }
    if ($parsed.check -ne "crypto_design_note_check") {
        throw "Unexpected check id in crypto design note report."
    }

    @'
# Forge Crypto Design Note
## 1. Scope and Security Goals
## 2. Threat Model
AES-256 Argon2id Ed25519 SHA-256
'@ | Set-Content -LiteralPath $designNotePath -Encoding UTF8

    $negativeReportPath = Join-Path $testRoot "crypto_design_note_report_negative.json"
    & "$PSScriptRoot\crypto_design_note_check.ps1" `
        -DesignNotePath $designNotePath `
        -ReportPath $negativeReportPath `
        -FailOnFindings:$false

    $negative = Get-Content -LiteralPath $negativeReportPath -Raw | ConvertFrom-Json
    if ([bool]$negative.passed) {
        throw "crypto design note check should fail when required sections are missing."
    }
    $matched = $false
    foreach ($finding in @($negative.findings | ForEach-Object { [string]$_ })) {
        if ($finding -like "design note missing required section pattern:*") {
            $matched = $true
            break
        }
    }
    if (-not $matched) {
        throw "crypto design note check should include missing required section findings."
    }

    $missingPath = Join-Path $testRoot "MISSING_FORGE_CRYPTO_DESIGN_NOTE.md"
    $missingReportPath = Join-Path $testRoot "crypto_design_note_report_missing.json"
    & "$PSScriptRoot\crypto_design_note_check.ps1" `
        -DesignNotePath $missingPath `
        -ReportPath $missingReportPath
    $missing = Get-Content -LiteralPath $missingReportPath -Raw | ConvertFrom-Json
    if (-not [bool]$missing.passed) {
        throw "crypto design note check should pass in default local-only mode when note file is missing."
    }
    if ([bool]$missing.applies) {
        throw "crypto design note check should report applies=false when note file is missing in local-only mode."
    }

    $strictMissingReportPath = Join-Path $testRoot "crypto_design_note_report_missing_strict.json"
    & "$PSScriptRoot\crypto_design_note_check.ps1" `
        -DesignNotePath $missingPath `
        -ReportPath $strictMissingReportPath `
        -RequireDesignNote `
        -FailOnFindings:$false
    $strictMissing = Get-Content -LiteralPath $strictMissingReportPath -Raw | ConvertFrom-Json
    if ([bool]$strictMissing.passed) {
        throw "crypto design note check should fail in strict mode when note file is missing."
    }

    Write-Host "crypto_design_note_check.ps1 self-test passed."
}
finally {
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
