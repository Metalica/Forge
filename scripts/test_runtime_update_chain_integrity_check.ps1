$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Compute-HmacSha256 {
    param(
        [Parameter(Mandatory = $true)][byte[]]$KeyBytes,
        [Parameter(Mandatory = $true)][string]$Text
    )
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($KeyBytes)
    try {
        return $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
    }
    finally {
        $hmac.Dispose()
    }
}

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
$testRoot = Join-Path $workspaceRoot (".tmp\runtime_update_chain_integrity_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

$originalRequireSignature = [Environment]::GetEnvironmentVariable("FORGE_REQUIRE_RUNTIME_UPDATE_SIGNATURE", "Process")
$originalSigningKey = [Environment]::GetEnvironmentVariable("FORGE_RUNTIME_MANIFEST_SIGNING_KEY_B64", "Process")

try {
    $releasesRoot = Join-Path $testRoot "releases"
    $runtimeRoot = Join-Path $testRoot "runtime\llama.cpp"
    $quarantineMarkerPath = Join-Path $testRoot "QUARANTINE_RUNTIME_UPDATE_CHAIN.flag"
    New-Item -ItemType Directory -Path $releasesRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null

    $releaseTag = "v0.test"
    $releaseRoot = Join-Path $releasesRoot $releaseTag
    $sourceRoot = Join-Path $releaseRoot "extracted\llama-v0.test-bin-win-cpu-x64"
    New-Item -ItemType Directory -Path $sourceRoot -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $sourceRoot "llama-server.exe") -Value "binary-content" -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $sourceRoot "ggml-model.txt") -Value "model-content" -Encoding UTF8

    $manifestPath = Join-Path $releaseRoot "manifest.json"
    $manifestRows = @(
        [PSCustomObject]@{
            release_tag = $releaseTag
            asset_name = "llama-v0.test-bin-win-cpu-x64.zip"
            download_url = "https://example.invalid/llama-v0.test-bin-win-cpu-x64.zip"
            file_path = (Join-Path $releaseRoot "downloads\llama-v0.test-bin-win-cpu-x64.zip")
            file_size_bytes = 1234
            sha256 = "abc123"
        }
    )
    $manifestRows | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath (Join-Path $releaseRoot "manifest.json.sha256") -Value $manifestHash -Encoding UTF8

    $keyBytes = New-Object byte[] 32
    for ($i = 0; $i -lt $keyBytes.Length; $i++) {
        $keyBytes[$i] = ($i + 7) % 256
    }
    $keyB64 = [Convert]::ToBase64String($keyBytes)
    $signature = Compute-HmacSha256 -KeyBytes $keyBytes -Text $manifestHash
    $signaturePayload = [PSCustomObject]@{
        schema_version = 1
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        algorithm = "hmac-sha256"
        digest_sha256 = $manifestHash
        signature_b64 = [Convert]::ToBase64String($signature)
        signing_key_env = "FORGE_RUNTIME_MANIFEST_SIGNING_KEY_B64"
    }
    $signaturePayload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $releaseRoot "manifest.signature.json") -Encoding UTF8

    Copy-Item -Path (Join-Path $sourceRoot "*") -Destination $runtimeRoot -Recurse -Force
    $backupPath = Join-Path $testRoot "runtime_backup\llama.cpp.prev"
    New-Item -ItemType Directory -Path $backupPath -Force | Out-Null

    $selection = [PSCustomObject]@{
        release_tag = $releaseTag
        profile = "win-cpu"
        backend = "cpu"
        platform = "windows"
        source_path = $sourceRoot
        activated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        backup_path = $backupPath
    }
    $selection | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $runtimeRoot "runtime_selection.json") -Encoding UTF8

    Set-Or-ClearProcessEnv -Name "FORGE_REQUIRE_RUNTIME_UPDATE_SIGNATURE" -Value "1"
    Set-Or-ClearProcessEnv -Name "FORGE_RUNTIME_MANIFEST_SIGNING_KEY_B64" -Value $keyB64

    $reportPath = Join-Path $testRoot "runtime_update_chain_integrity_report.json"
    & "$PSScriptRoot\runtime_update_chain_integrity_check.ps1" `
        -ReportPath $reportPath `
        -ReleasesRoot $releasesRoot `
        -RuntimeRoot $runtimeRoot `
        -QuarantineMarkerPath $quarantineMarkerPath

    if (-not (Test-Path -LiteralPath $reportPath)) {
        throw "runtime update-chain integrity report was not generated."
    }
    $parsed = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$parsed.passed) {
        throw "runtime update-chain integrity report indicates failure in valid scenario."
    }
    if ([bool]$parsed.quarantine_required) {
        throw "runtime update-chain check should not require quarantine in valid scenario."
    }
    if (Test-Path -LiteralPath $quarantineMarkerPath) {
        throw "runtime update-chain quarantine marker should not exist in valid scenario."
    }

    Add-Content -LiteralPath (Join-Path $runtimeRoot "ggml-model.txt") -Value "tampered"
    $negativePath = Join-Path $testRoot "runtime_update_chain_integrity_report_negative.json"
    & "$PSScriptRoot\runtime_update_chain_integrity_check.ps1" `
        -FailOnFindings:$false `
        -ReportPath $negativePath `
        -ReleasesRoot $releasesRoot `
        -RuntimeRoot $runtimeRoot `
        -QuarantineMarkerPath $quarantineMarkerPath

    $negative = Get-Content -LiteralPath $negativePath -Raw | ConvertFrom-Json
    if ([bool]$negative.passed) {
        throw "runtime update-chain check did not fail after runtime tampering."
    }
    if (-not [bool]$negative.quarantine_required) {
        throw "runtime update-chain check should require quarantine after runtime tampering."
    }
    if (-not (Test-Path -LiteralPath $quarantineMarkerPath)) {
        throw "runtime update-chain quarantine marker missing after runtime tampering."
    }

    Write-Host "runtime_update_chain_integrity_check.ps1 self-test passed."
}
finally {
    Set-Or-ClearProcessEnv -Name "FORGE_REQUIRE_RUNTIME_UPDATE_SIGNATURE" -Value $originalRequireSignature
    Set-Or-ClearProcessEnv -Name "FORGE_RUNTIME_MANIFEST_SIGNING_KEY_B64" -Value $originalSigningKey
    Remove-Item -Path $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
