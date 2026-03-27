$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function New-RandomBase64Key {
    param([int]$Length = 32)
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    return [Convert]::ToBase64String($bytes)
}

function Get-TempRootPath {
    $candidates = @(
        $env:TEMP,
        $env:TMP,
        [System.IO.Path]::GetTempPath()
    )
    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            return $candidate
        }
    }
    return (Join-Path $PSScriptRoot "..\.tmp")
}

$tempRoot = Get-TempRootPath
$root = Join-Path $tempRoot ("forge_runtime_secure_backup_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $root -Force | Out-Null

try {
    $sourcePath = Join-Path $root "source_runtime"
    $restorePath = Join-Path $root "restored_runtime"
    $quarantineRoot = Join-Path $root "quarantine"
    $bundlePath = Join-Path $root "runtime_backup_bundle.json"
    $tamperedBundlePath = Join-Path $root "runtime_backup_bundle_tampered.json"
    $rewrapMarkerPath = Join-Path $root "runtime_restore_rewrap_required.json"
    $rewrapAckPath = Join-Path $root "runtime_restore_rewrap_ack.json"

    New-Item -ItemType Directory -Path $sourcePath -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $sourcePath "nested") -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $sourcePath "llama-server.exe") -Value "binary-placeholder" -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $sourcePath "nested\runtime_selection.json") -Value '{"profile":"win-cpu"}' -Encoding UTF8

    $encryptionEnv = "FORGE_BACKUP_AES256_KEY_B64"
    $signingEnv = "FORGE_BACKUP_SIGNING_KEY_B64"
    $liveKekEnv = "FORGE_SECRET_BROKER_KEK_B64"
    $adminReauthEnv = "FORGE_ADMIN_REAUTH_CODE"
    $adminDualEnv = "FORGE_ADMIN_DUAL_CONTROL_CODE"
    $adminReauthCode = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([guid]::NewGuid().ToString("N")))
    $adminDualCode = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([guid]::NewGuid().ToString("N")))
    if ($adminDualCode -eq $adminReauthCode) {
        $adminDualCode = $adminDualCode + "_dual"
    }
    [Environment]::SetEnvironmentVariable($encryptionEnv, (New-RandomBase64Key), "Process")
    [Environment]::SetEnvironmentVariable($signingEnv, (New-RandomBase64Key), "Process")
    [Environment]::SetEnvironmentVariable($liveKekEnv, (New-RandomBase64Key), "Process")
    [Environment]::SetEnvironmentVariable($adminReauthEnv, $adminReauthCode, "Process")
    [Environment]::SetEnvironmentVariable($adminDualEnv, $adminDualCode, "Process")

    & "$PSScriptRoot\runtime_secure_backup_import.ps1" `
        -Mode Export `
        -SourcePath $sourcePath `
        -BundlePath $bundlePath `
        -EncryptionKeyEnv $encryptionEnv `
        -SigningKeyEnv $signingEnv `
        -LiveKekEnv $liveKekEnv `
        -AdminReauthEnv $adminReauthEnv `
        -AdminReauthCode $adminReauthCode `
        -DualControlEnv $adminDualEnv `
        -DualControlCode $adminDualCode `
        -ActionReason "selftest export validation" `
        -TypedConfirmation "I APPROVE FORGE SECRET EXPORT"

    if (-not (Test-Path -LiteralPath $bundlePath)) {
        throw "Secure runtime backup bundle was not generated."
    }

    & "$PSScriptRoot\runtime_secure_backup_import.ps1" `
        -Mode Import `
        -BundlePath $bundlePath `
        -RestorePath $restorePath `
        -QuarantineRoot $quarantineRoot `
        -EncryptionKeyEnv $encryptionEnv `
        -SigningKeyEnv $signingEnv `
        -LiveKekEnv $liveKekEnv `
        -RewrapMarkerPath $rewrapMarkerPath `
        -AdminReauthEnv $adminReauthEnv `
        -AdminReauthCode $adminReauthCode `
        -DualControlEnv $adminDualEnv `
        -DualControlCode $adminDualCode `
        -ActionReason "selftest import validation" `
        -TypedConfirmation "I APPROVE FORGE RUNTIME IMPORT"

    $restoredBinary = Join-Path $restorePath "llama-server.exe"
    $restoredMetadata = Join-Path $restorePath "nested\runtime_selection.json"
    if (-not (Test-Path -LiteralPath $restoredBinary)) {
        throw "Restored runtime binary is missing."
    }
    if (-not (Test-Path -LiteralPath $restoredMetadata)) {
        throw "Restored runtime metadata file is missing."
    }
    if (-not (Test-Path -LiteralPath $rewrapMarkerPath)) {
        throw "Post-restore rewrap marker was not generated."
    }

    $ackBlocked = $false
    try {
        & "$PSScriptRoot\runtime_secure_backup_import.ps1" `
            -Mode AcknowledgeRewrap `
            -RewrapMarkerPath $rewrapMarkerPath `
            -RewrapAckPath $rewrapAckPath `
            -AdminReauthEnv $adminReauthEnv `
            -AdminReauthCode $adminReauthCode `
            -ActionReason "selftest acknowledge validation" `
            -TypedConfirmation "wrong confirmation"
    }
    catch {
        $ackBlocked = $true
    }
    if (-not $ackBlocked) {
        throw "AcknowledgeRewrap should fail when typed confirmation is wrong."
    }

    & "$PSScriptRoot\runtime_secure_backup_import.ps1" `
        -Mode AcknowledgeRewrap `
        -RewrapMarkerPath $rewrapMarkerPath `
        -RewrapAckPath $rewrapAckPath `
        -AdminReauthEnv $adminReauthEnv `
        -AdminReauthCode $adminReauthCode `
        -ActionReason "selftest acknowledge validation" `
        -TypedConfirmation "I COMPLETED FORGE BROKER REWRAP"

    if (Test-Path -LiteralPath $rewrapMarkerPath) {
        throw "Rewrap marker should be removed after acknowledgment."
    }
    if (-not (Test-Path -LiteralPath $rewrapAckPath)) {
        throw "Rewrap acknowledgment artifact is missing."
    }

    Copy-Item -LiteralPath $bundlePath -Destination $tamperedBundlePath -Force
    $tampered = Get-Content -LiteralPath $tamperedBundlePath -Raw | ConvertFrom-Json
    $cipher = [string]$tampered.ciphertext_b64
    if ($cipher.Length -lt 2) {
        throw "Unexpected ciphertext size in generated bundle."
    }
    $replacement = if ($cipher.Substring(0, 1) -eq "A") { "B" } else { "A" }
    $tampered.ciphertext_b64 = ($replacement + $cipher.Substring(1))
    $tampered | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $tamperedBundlePath -Encoding UTF8

    $tamperBlocked = $false
    try {
        & "$PSScriptRoot\runtime_secure_backup_import.ps1" `
            -Mode Import `
            -BundlePath $tamperedBundlePath `
            -RestorePath (Join-Path $root "tampered_restore") `
            -QuarantineRoot $quarantineRoot `
            -EncryptionKeyEnv $encryptionEnv `
            -SigningKeyEnv $signingEnv `
            -LiveKekEnv $liveKekEnv `
            -AdminReauthEnv $adminReauthEnv `
            -AdminReauthCode $adminReauthCode `
            -DualControlEnv $adminDualEnv `
            -DualControlCode $adminDualCode `
            -ActionReason "selftest tamper validation" `
            -TypedConfirmation "I APPROVE FORGE RUNTIME IMPORT"
    }
    catch {
        $tamperBlocked = $true
    }
    if (-not $tamperBlocked) {
        throw "Tampered runtime backup bundle import was expected to fail."
    }

    $sameKey = New-RandomBase64Key
    [Environment]::SetEnvironmentVariable($encryptionEnv, $sameKey, "Process")
    [Environment]::SetEnvironmentVariable($signingEnv, $sameKey, "Process")
    $keyReuseBlocked = $false
    try {
        & "$PSScriptRoot\runtime_secure_backup_import.ps1" `
            -Mode Export `
            -SourcePath $sourcePath `
            -BundlePath (Join-Path $root "runtime_backup_bundle_key_reuse.json") `
            -EncryptionKeyEnv $encryptionEnv `
            -SigningKeyEnv $signingEnv `
            -LiveKekEnv $liveKekEnv `
            -AdminReauthEnv $adminReauthEnv `
            -AdminReauthCode $adminReauthCode `
            -DualControlEnv $adminDualEnv `
            -DualControlCode $adminDualCode `
            -ActionReason "selftest key reuse validation" `
            -TypedConfirmation "I APPROVE FORGE SECRET EXPORT"
    }
    catch {
        $keyReuseBlocked = $true
    }
    if (-not $keyReuseBlocked) {
        throw "Export should fail when backup encryption/signing keys reuse the same key material."
    }

    Write-Host "runtime_secure_backup_import.ps1 self-test passed."
}
finally {
    [Environment]::SetEnvironmentVariable("FORGE_BACKUP_AES256_KEY_B64", $null, "Process")
    [Environment]::SetEnvironmentVariable("FORGE_BACKUP_SIGNING_KEY_B64", $null, "Process")
    [Environment]::SetEnvironmentVariable("FORGE_SECRET_BROKER_KEK_B64", $null, "Process")
    [Environment]::SetEnvironmentVariable("FORGE_ADMIN_REAUTH_CODE", $null, "Process")
    [Environment]::SetEnvironmentVariable("FORGE_ADMIN_DUAL_CONTROL_CODE", $null, "Process")
    Remove-Item -Path $root -Recurse -Force -ErrorAction SilentlyContinue
}
