$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Set-Or-ClearProcessEnv {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][string]$Value
    )
    if ($null -eq $Value) {
        [Environment]::SetEnvironmentVariable($Name, $null, "Process")
    }
    else {
        [Environment]::SetEnvironmentVariable($Name, $Value, "Process")
    }
}

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$testRoot = Join-Path $workspaceRoot (".tmp\artifact_supply_chain_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

$originalRequireSlsa = [Environment]::GetEnvironmentVariable("FORGE_REQUIRE_SLSA_PROVENANCE", "Process")
$originalSlsaPath = [Environment]::GetEnvironmentVariable("FORGE_SLSA_PROVENANCE_PATH", "Process")

try {
    $reportPath = Join-Path $testRoot "artifact_supply_chain_integrity_report.json"
    $sbomPath = Join-Path $testRoot "forge_workspace_sbom.json"

    & "$PSScriptRoot\artifact_supply_chain_integrity_check.ps1" `
        -ReportPath $reportPath `
        -SbomPath $sbomPath

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "artifact/supply-chain report was not generated."
    }
    if (-not (Test-Path -LiteralPath $sbomPath)) {
        throw "SBOM artifact was not generated."
    }

    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$parsed.passed) {
        throw "artifact/supply-chain report indicates failure in default mode."
    }
    if ($parsed.check -ne "artifact_supply_chain_integrity_check") {
        throw "Unexpected check id in artifact/supply-chain report."
    }

    $provenancePath = Join-Path $testRoot "sample_slsa_provenance.json"
    @'
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v1",
  "subject": [
    { "name": "Forge.exe", "digest": { "sha256": "abc123" } }
  ]
}
'@ | Set-Content -LiteralPath $provenancePath -Encoding UTF8

    Set-Or-ClearProcessEnv -Name "FORGE_REQUIRE_SLSA_PROVENANCE" -Value "1"
    Set-Or-ClearProcessEnv -Name "FORGE_SLSA_PROVENANCE_PATH" -Value $provenancePath

    $strictPath = Join-Path $testRoot "artifact_supply_chain_integrity_strict.json"
    & "$PSScriptRoot\artifact_supply_chain_integrity_check.ps1" `
        -ReportPath $strictPath `
        -SbomPath (Join-Path $testRoot "forge_workspace_sbom_strict.json")

    $strict = Get-Content -LiteralPath $strictPath -Raw | ConvertFrom-Json
    if (-not [bool]$strict.passed) {
        throw "Strict SLSA mode should pass with valid provenance payload."
    }

    Set-Or-ClearProcessEnv -Name "FORGE_SLSA_PROVENANCE_PATH" -Value (Join-Path $testRoot "missing.json")
    $negativePath = Join-Path $testRoot "artifact_supply_chain_integrity_negative.json"
    & "$PSScriptRoot\artifact_supply_chain_integrity_check.ps1" `
        -ReportPath $negativePath `
        -SbomPath (Join-Path $testRoot "forge_workspace_sbom_negative.json") `
        -FailOnFindings:$false

    $negative = Get-Content -LiteralPath $negativePath -Raw | ConvertFrom-Json
    if ([bool]$negative.passed) {
        throw "Expected strict SLSA mode to fail when provenance file is missing."
    }

    Write-Host "artifact_supply_chain_integrity_check.ps1 self-test passed."
}
finally {
    Set-Or-ClearProcessEnv -Name "FORGE_REQUIRE_SLSA_PROVENANCE" -Value $originalRequireSlsa
    Set-Or-ClearProcessEnv -Name "FORGE_SLSA_PROVENANCE_PATH" -Value $originalSlsaPath
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
