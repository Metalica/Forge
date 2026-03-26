param(
    [switch]$FailOnFindings = $true
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $workspaceRoot ".tmp\security"
$artifactPath = Join-Path $artifactRoot "nonce_uniqueness_report.json"
$testFilter = "persisted_encryption_nonces_are_unique_across_records"
$commandText = "cargo test -p forge_security $testFilter"

if (-not (Test-Path $artifactRoot)) {
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
}

& cargo test -p forge_security $testFilter
$passed = ($LASTEXITCODE -eq 0)

$report = [ordered]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    test_name = $testFilter
    command = $commandText
    passed = $passed
}
$encoded = $report | ConvertTo-Json -Depth 5
Set-Content -LiteralPath $artifactPath -Value $encoded -Encoding UTF8

if ($passed) {
    Write-Host "Broker nonce uniqueness check passed: $artifactPath"
}
else {
    Write-Host "Broker nonce uniqueness check failed: $artifactPath"
    if ($FailOnFindings) {
        throw "broker nonce uniqueness regression check failed"
    }
}
