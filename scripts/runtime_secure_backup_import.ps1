param(
    [ValidateSet("Export", "Import", "AcknowledgeRewrap")]
    [string]$Mode = "Export",
    [string]$SourcePath = "E:\Forge\runtimes\llama.cpp",
    [string]$BundlePath = "",
    [string]$RestorePath = "E:\Forge\runtimes\llama.cpp",
    [string]$QuarantineRoot = "E:\Forge\.tmp\security\runtime_restore_quarantine",
    [string]$EncryptionKeyEnv = "FORGE_BACKUP_AES256_KEY_B64",
    [string]$SigningKeyEnv = "FORGE_BACKUP_SIGNING_KEY_B64",
    [string]$LiveKekEnv = "FORGE_SECRET_BROKER_KEK_B64",
    [string]$RewrapMarkerPath = "",
    [string]$RewrapAckPath = "",
    [string]$AdminReauthEnv = "FORGE_ADMIN_REAUTH_CODE",
    [string]$AdminReauthCode = "",
    [string]$DualControlEnv = "FORGE_ADMIN_DUAL_CONTROL_CODE",
    [string]$DualControlCode = "",
    [string]$ActionReason = "",
    [string]$RequirePhishingResistantAuthEnv = "FORGE_REQUIRE_PHISHING_RESISTANT_AUTH",
    [string]$PhishingResistantAuthEnv = "FORGE_ADMIN_WEBAUTHN_ASSERTION",
    [string]$TypedConfirmation = "",
    [string]$RequiredTypedConfirmation = "",
    [switch]$AllowKeyReuse = $false
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Resolve-WorkspaceRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Resolve-CanonicalPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Resolve-Path -LiteralPath $Path).Path
}

function Resolve-DefaultSecurityPath {
    param([Parameter(Mandatory = $true)][string]$LeafName)
    $workspaceRoot = Resolve-WorkspaceRoot
    $securityRoot = Join-Path $workspaceRoot ".tmp\security"
    Ensure-Directory -Path $securityRoot
    return Join-Path $securityRoot $LeafName
}

function Resolve-PathForWrite {
    param([Parameter(Mandatory = $true)][string]$Path)
    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        Ensure-Directory -Path $parent
    }
    return [System.IO.Path]::GetFullPath($Path)
}

function Get-EnvFlag {
    param([Parameter(Mandatory = $true)][string]$Name)
    $raw = [Environment]::GetEnvironmentVariable($Name, "Process")
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $false
    }
    $normalized = $raw.Trim().ToLowerInvariant()
    return $normalized -in @("1", "true", "yes", "on")
}

function Resolve-RequiredTypedConfirmationForMode {
    param([Parameter(Mandatory = $true)][string]$CurrentMode)
    if (-not [string]::IsNullOrWhiteSpace($RequiredTypedConfirmation)) {
        return $RequiredTypedConfirmation
    }
    if ($CurrentMode -eq "Export") {
        return "I APPROVE FORGE SECRET EXPORT"
    }
    if ($CurrentMode -eq "Import") {
        return "I APPROVE FORGE RUNTIME IMPORT"
    }
    return "I COMPLETED FORGE BROKER REWRAP"
}

function Assert-DangerousActionAuthorization {
    param(
        [Parameter(Mandatory = $true)][string]$ActionName,
        [Parameter(Mandatory = $true)][string]$ModeName,
        [Parameter(Mandatory = $true)][string]$PrimaryReauthEnvName,
        [Parameter(Mandatory = $true)][string]$PrimaryReauthCode,
        [Parameter(Mandatory = $false)][switch]$RequireDualControl,
        [Parameter(Mandatory = $false)][string]$DualControlEnvName = "",
        [Parameter(Mandatory = $false)][string]$DualControlCodeValue = ""
    )
    if ([string]::IsNullOrWhiteSpace($ActionReason)) {
        throw "Dangerous action '$ActionName' requires a non-empty action reason."
    }

    $expectedPrimary = [Environment]::GetEnvironmentVariable($PrimaryReauthEnvName, "Process")
    if ([string]::IsNullOrWhiteSpace($expectedPrimary)) {
        throw "Dangerous action '$ActionName' requires configured admin re-auth env '$PrimaryReauthEnvName'."
    }
    if ($PrimaryReauthCode -ne $expectedPrimary) {
        throw "Dangerous action '$ActionName' admin re-auth verification failed."
    }

    if ($RequireDualControl) {
        if ([string]::IsNullOrWhiteSpace($DualControlEnvName)) {
            throw "Dangerous action '$ActionName' dual-control env name cannot be empty."
        }
        $expectedDual = [Environment]::GetEnvironmentVariable($DualControlEnvName, "Process")
        if ([string]::IsNullOrWhiteSpace($expectedDual)) {
            throw "Dangerous action '$ActionName' requires configured dual-control env '$DualControlEnvName'."
        }
        if ($DualControlCodeValue -ne $expectedDual) {
            throw "Dangerous action '$ActionName' dual-control verification failed."
        }
        if ($DualControlCodeValue -eq $PrimaryReauthCode) {
            throw "Dangerous action '$ActionName' requires distinct primary and dual-control codes."
        }
    }

    if (Get-EnvFlag -Name $RequirePhishingResistantAuthEnv) {
        $assertion = [Environment]::GetEnvironmentVariable($PhishingResistantAuthEnv, "Process")
        if ([string]::IsNullOrWhiteSpace($assertion)) {
            throw "Dangerous action '$ActionName' requires phishing-resistant authenticator evidence env '$PhishingResistantAuthEnv'."
        }
    }

    $requiredConfirmation = Resolve-RequiredTypedConfirmationForMode -CurrentMode $ModeName
    if ($TypedConfirmation -ne $requiredConfirmation) {
        throw "Typed confirmation mismatch. Expected '$requiredConfirmation'."
    }
}

function New-RandomBytes {
    param([Parameter(Mandatory = $true)][int]$Count)
    $buffer = New-Object byte[] $Count
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($buffer)
    }
    finally {
        $rng.Dispose()
    }
    return $buffer
}

function Get-RequiredKeyBytes {
    param(
        [Parameter(Mandatory = $true)][string]$EnvName,
        [Parameter(Mandatory = $true)][int]$ExpectedBytes
    )

    $raw = [Environment]::GetEnvironmentVariable($EnvName)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Required key env '$EnvName' is missing or empty."
    }

    try {
        $decoded = [Convert]::FromBase64String($raw.Trim())
    }
    catch {
        throw "Key env '$EnvName' is not valid base64."
    }

    if ($decoded.Length -ne $ExpectedBytes) {
        throw "Key env '$EnvName' must decode to $ExpectedBytes bytes."
    }
    return $decoded
}

function Get-DirectoryManifest {
    param([Parameter(Mandatory = $true)][string]$RootPath)
    $root = (Get-Item -LiteralPath $RootPath).FullName.TrimEnd("\")
    $files = Get-ChildItem -LiteralPath $root -File -Recurse | Sort-Object FullName
    $rows = @()
    foreach ($file in $files) {
        if ($file.FullName.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            $relative = $file.FullName.Substring($root.Length).TrimStart("\", "/").Replace("\", "/")
        }
        else {
            throw "File escaped source root while building backup manifest: $($file.FullName)"
        }
        $hash = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256
        $rows += [PSCustomObject]@{
            path = $relative
            sha256 = $hash.Hash.ToLowerInvariant()
            size_bytes = [int64]$file.Length
        }
    }
    return $rows
}

function Protect-BackupPayload {
    param(
        [Parameter(Mandatory = $true)][byte[]]$PlainBytes,
        [Parameter(Mandatory = $true)][byte[]]$KeyBytes
    )

    $iv = New-RandomBytes -Count 16
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $KeyBytes
    $aes.IV = $iv
    try {
        $encryptor = $aes.CreateEncryptor()
        try {
            $cipher = $encryptor.TransformFinalBlock($PlainBytes, 0, $PlainBytes.Length)
        }
        finally {
            $encryptor.Dispose()
        }
    }
    finally {
        $aes.Dispose()
    }

    return [PSCustomObject]@{
        iv = $iv
        ciphertext = $cipher
    }
}

function Unprotect-BackupPayload {
    param(
        [Parameter(Mandatory = $true)][byte[]]$InitializationVector,
        [Parameter(Mandatory = $true)][byte[]]$Ciphertext,
        [Parameter(Mandatory = $true)][byte[]]$KeyBytes
    )

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $KeyBytes
    $aes.IV = $InitializationVector
    try {
        $decryptor = $aes.CreateDecryptor()
        try {
            $plain = $decryptor.TransformFinalBlock($Ciphertext, 0, $Ciphertext.Length)
        }
        finally {
            $decryptor.Dispose()
        }
    }
    finally {
        $aes.Dispose()
    }
    return $plain
}

function Get-SigningPayloadText {
    param(
        [Parameter(Mandatory = $true)][string]$MetadataCanonicalJson,
        [Parameter(Mandatory = $true)][string]$IvB64,
        [Parameter(Mandatory = $true)][string]$CiphertextB64
    )
    return "$MetadataCanonicalJson`n$IvB64`n$CiphertextB64"
}

function Compute-HmacSha256 {
    param(
        [Parameter(Mandatory = $true)][byte[]]$KeyBytes,
        [Parameter(Mandatory = $true)][string]$Text
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($KeyBytes)
    try {
        return $hmac.ComputeHash($bytes)
    }
    finally {
        $hmac.Dispose()
    }
}

function Compare-ByteArraysFixedTime {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
    )
    if ($Left.Length -ne $Right.Length) {
        return $false
    }
    $diff = 0
    for ($idx = 0; $idx -lt $Left.Length; $idx++) {
        $diff = $diff -bor ($Left[$idx] -bxor $Right[$idx])
    }
    return ($diff -eq 0)
}

function Convert-ToHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return ([System.BitConverter]::ToString($Bytes)).Replace("-", "").ToLowerInvariant()
}

function Get-Sha256HexForBytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($Bytes)
    }
    finally {
        $sha.Dispose()
    }
    return Convert-ToHex -Bytes $hash
}

function Assert-BackupKeyHierarchySeparation {
    param(
        [Parameter(Mandatory = $true)][byte[]]$EncryptionKeyBytes,
        [Parameter(Mandatory = $true)][byte[]]$SigningKeyBytes,
        [Parameter(Mandatory = $true)][string]$EncryptionEnvName,
        [Parameter(Mandatory = $true)][string]$SigningEnvName,
        [Parameter(Mandatory = $true)][string]$LiveKekEnvName,
        [Parameter(Mandatory = $false)][switch]$AllowReuse
    )

    if ($AllowReuse) {
        return
    }

    if (Compare-ByteArraysFixedTime -Left $EncryptionKeyBytes -Right $SigningKeyBytes) {
        throw "Backup key hierarchy violation: encryption key env '$EncryptionEnvName' and signing key env '$SigningEnvName' must not reuse the same key material."
    }

    if (-not [string]::IsNullOrWhiteSpace($LiveKekEnvName)) {
        $liveRaw = [Environment]::GetEnvironmentVariable($LiveKekEnvName)
        if (-not [string]::IsNullOrWhiteSpace($liveRaw)) {
            try {
                $liveBytes = [Convert]::FromBase64String($liveRaw.Trim())
                if ($liveBytes.Length -eq 32) {
                    if (Compare-ByteArraysFixedTime -Left $EncryptionKeyBytes -Right $liveBytes) {
                        throw "Backup key hierarchy violation: encryption backup key must not equal live KEK env '$LiveKekEnvName'."
                    }
                    if (Compare-ByteArraysFixedTime -Left $SigningKeyBytes -Right $liveBytes) {
                        throw "Backup key hierarchy violation: signing backup key must not equal live KEK env '$LiveKekEnvName'."
                    }
                }
            }
            catch {
                # If the optional live KEK env is malformed, we do not block backup flows.
            }
        }
    }
}

function Write-RewrapMarker {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$BundlePathCanonical,
        [Parameter(Mandatory = $true)][string]$RestorePathCanonical,
        [Parameter(Mandatory = $true)][string]$LiveKekEnvName
    )
    $resolvedPath = Resolve-PathForWrite -Path $Path
    $payload = [ordered]@{
        schema_version = 1
        marker_type = "runtime_restore_rewrap_required"
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        bundle_path = $BundlePathCanonical
        restore_path = $RestorePathCanonical
        live_kek_env = $LiveKekEnvName
        status = "pending"
        next_step = "run broker_rewrap to migrate restored secret material from backup-key hierarchy to live KEK hierarchy, then acknowledge completion"
    }
    $payload | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $resolvedPath -Encoding UTF8
    return $resolvedPath
}

function Write-RewrapAcknowledgement {
    param(
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [Parameter(Mandatory = $true)][string]$AckPath
    )
    if (-not (Test-Path -LiteralPath $MarkerPath)) {
        throw "Rewrap marker not found at '$MarkerPath'."
    }
    $requiredConfirmation = Resolve-RequiredTypedConfirmationForMode -CurrentMode "AcknowledgeRewrap"
    if ($TypedConfirmation -ne $requiredConfirmation) {
        throw "Typed confirmation mismatch. Expected '$requiredConfirmation'."
    }

    $marker = Get-Content -LiteralPath $MarkerPath -Raw | ConvertFrom-Json
    $ackPayload = [ordered]@{
        schema_version = 1
        ack_type = "runtime_restore_rewrap_completed"
        acknowledged_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        marker_path = (Resolve-Path -LiteralPath $MarkerPath).Path
        marker_generated_at_utc = [string]$marker.generated_at_utc
        restore_path = [string]$marker.restore_path
        bundle_path = [string]$marker.bundle_path
        typed_confirmation = $TypedConfirmation
        status = "acknowledged"
    }
    $ackPathCanonical = Resolve-PathForWrite -Path $AckPath
    $ackPayload | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $ackPathCanonical -Encoding UTF8
    Remove-Item -LiteralPath $MarkerPath -Force -ErrorAction SilentlyContinue
    return $ackPathCanonical
}

function Expand-ArchiveSafely {
    param(
        [Parameter(Mandatory = $true)][byte[]]$ArchiveBytes,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $destinationCanonical = [System.IO.Path]::GetFullPath($DestinationPath)
    if (-not $destinationCanonical.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $destinationCanonical = $destinationCanonical + [System.IO.Path]::DirectorySeparatorChar
    }

    $memoryStream = New-Object System.IO.MemoryStream(, $ArchiveBytes)
    try {
        $archive = [System.IO.Compression.ZipArchive]::new(
            $memoryStream,
            [System.IO.Compression.ZipArchiveMode]::Read,
            $false
        )
        try {
            foreach ($entry in $archive.Entries) {
                $entryPath = ($entry.FullName -replace "\\", "/").Trim()
                if ([string]::IsNullOrWhiteSpace($entryPath)) {
                    continue
                }
                $isDirectory = $entryPath.EndsWith("/")
                if ($isDirectory) {
                    $entryPath = $entryPath.TrimEnd("/")
                }
                Assert-ManifestPathSafe -RelativePath $entryPath

                $destinationCandidate = Join-Path $DestinationPath $entryPath
                $destinationCandidateCanonical = [System.IO.Path]::GetFullPath($destinationCandidate)
                if (-not $destinationCandidateCanonical.StartsWith(
                        $destinationCanonical,
                        [System.StringComparison]::OrdinalIgnoreCase
                    )) {
                    throw "Archive extraction attempted to escape quarantine destination: $entryPath"
                }

                if ($isDirectory) {
                    Ensure-Directory -Path $destinationCandidateCanonical
                    continue
                }

                $destinationParent = Split-Path -Parent $destinationCandidateCanonical
                if (-not [string]::IsNullOrWhiteSpace($destinationParent)) {
                    Ensure-Directory -Path $destinationParent
                }
                $entryStream = $entry.Open()
                try {
                    $fileStream = [System.IO.File]::Open(
                        $destinationCandidateCanonical,
                        [System.IO.FileMode]::Create,
                        [System.IO.FileAccess]::Write,
                        [System.IO.FileShare]::None
                    )
                    try {
                        $entryStream.CopyTo($fileStream)
                    }
                    finally {
                        $fileStream.Dispose()
                    }
                }
                finally {
                    $entryStream.Dispose()
                }
            }
        }
        finally {
            $archive.Dispose()
        }
    }
    finally {
        $memoryStream.Dispose()
    }
}

function Assert-ManifestPathSafe {
    param(
        [Parameter(Mandatory = $true)][string]$RelativePath
    )
    if ([string]::IsNullOrWhiteSpace($RelativePath)) {
        throw "Manifest contains empty relative path."
    }
    if ([System.IO.Path]::IsPathRooted($RelativePath)) {
        throw "Manifest path must be relative: $RelativePath"
    }
    if ($RelativePath.Contains("..")) {
        throw "Manifest path traversal is not allowed: $RelativePath"
    }
}

function Resolve-ManifestCandidatePath {
    param(
        [Parameter(Mandatory = $true)][string]$QuarantineRoot,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )
    $direct = Join-Path $QuarantineRoot $RelativePath
    if (Test-Path -LiteralPath $direct -PathType Leaf) {
        return (Resolve-CanonicalPath -Path $direct)
    }

    $matches = @()
    $topLevelDirs = Get-ChildItem -LiteralPath $QuarantineRoot -Directory -ErrorAction SilentlyContinue
    foreach ($dir in $topLevelDirs) {
        $candidate = Join-Path $dir.FullName $RelativePath
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $matches += (Resolve-CanonicalPath -Path $candidate)
        }
    }

    if ($matches.Count -eq 1) {
        return $matches[0]
    }
    if ($matches.Count -gt 1) {
        throw "Manifest path resolves ambiguously inside quarantine root: $RelativePath"
    }
    return $null
}

function Export-SecureBackupBundle {
    Assert-DangerousActionAuthorization `
        -ActionName "secret_export" `
        -ModeName "Export" `
        -PrimaryReauthEnvName $AdminReauthEnv `
        -PrimaryReauthCode $AdminReauthCode `
        -RequireDualControl `
        -DualControlEnvName $DualControlEnv `
        -DualControlCodeValue $DualControlCode

    $workspaceRoot = Resolve-WorkspaceRoot
    $source = Resolve-CanonicalPath -Path $SourcePath
    if (-not (Test-Path -LiteralPath $source -PathType Container)) {
        throw "Source path is not a directory: $source"
    }

    $encryptionKey = Get-RequiredKeyBytes -EnvName $EncryptionKeyEnv -ExpectedBytes 32
    $signingKey = Get-RequiredKeyBytes -EnvName $SigningKeyEnv -ExpectedBytes 32
    Assert-BackupKeyHierarchySeparation `
        -EncryptionKeyBytes $encryptionKey `
        -SigningKeyBytes $signingKey `
        -EncryptionEnvName $EncryptionKeyEnv `
        -SigningEnvName $SigningKeyEnv `
        -LiveKekEnvName $LiveKekEnv `
        -AllowReuse:$AllowKeyReuse

    if ([string]::IsNullOrWhiteSpace($BundlePath)) {
        $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
        $BundlePath = Join-Path $workspaceRoot ".tmp\security\runtime_secure_backup_$stamp.json"
    }
    $bundleParent = Split-Path -Parent $BundlePath
    Ensure-Directory -Path $bundleParent

    $manifest = Get-DirectoryManifest -RootPath $source
    $tempZipPath = Join-Path ([System.IO.Path]::GetTempPath()) ("forge_runtime_secure_backup_" + [guid]::NewGuid().ToString("N") + ".zip")
    try {
        Compress-Archive -Path (Join-Path $source "*") -DestinationPath $tempZipPath -Force
        $plainBytes = [System.IO.File]::ReadAllBytes($tempZipPath)

        $sealed = Protect-BackupPayload -PlainBytes $plainBytes -KeyBytes $encryptionKey
        $ivB64 = [Convert]::ToBase64String($sealed.iv)
        $ciphertextB64 = [Convert]::ToBase64String($sealed.ciphertext)

        $metadata = [ordered]@{
            schema_version = 1
            bundle_type = "runtime_secure_backup"
            created_at_utc = (Get-Date).ToUniversalTime().ToString("o")
            source_path = $source
            encryption = "aes-256-cbc"
            signing = "hmac-sha256"
            encryption_key_env = $EncryptionKeyEnv
            signing_key_env = $SigningKeyEnv
            backup_key_hierarchy = [ordered]@{
                key_separation_enforced = (-not $AllowKeyReuse)
                live_kek_env_reference = $LiveKekEnv
                encryption_key_fingerprint_sha256 = (Get-Sha256HexForBytes -Bytes $encryptionKey)
                signing_key_fingerprint_sha256 = (Get-Sha256HexForBytes -Bytes $signingKey)
            }
            post_restore_requirement = "run broker_rewrap for backup-key to live-kek migration when secrets are restored"
            manifest = $manifest
        }
        $metadataCanonicalJson = ($metadata | ConvertTo-Json -Depth 16 -Compress)
        $signingPayload = Get-SigningPayloadText `
            -MetadataCanonicalJson $metadataCanonicalJson `
            -IvB64 $ivB64 `
            -CiphertextB64 $ciphertextB64
        $signature = Compute-HmacSha256 -KeyBytes $signingKey -Text $signingPayload

        $bundle = [ordered]@{
            metadata_canonical_json = $metadataCanonicalJson
            iv_b64 = $ivB64
            ciphertext_b64 = $ciphertextB64
            signature_b64 = [Convert]::ToBase64String($signature)
        }
        $bundle | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $BundlePath -Encoding UTF8
    }
    finally {
        Remove-Item -LiteralPath $tempZipPath -ErrorAction SilentlyContinue
    }

    Write-Host "runtime secure backup bundle exported: $BundlePath"
}

function Import-SecureBackupBundle {
    Assert-DangerousActionAuthorization `
        -ActionName "runtime_import" `
        -ModeName "Import" `
        -PrimaryReauthEnvName $AdminReauthEnv `
        -PrimaryReauthCode $AdminReauthCode `
        -RequireDualControl `
        -DualControlEnvName $DualControlEnv `
        -DualControlCodeValue $DualControlCode

    $workspaceRoot = Resolve-WorkspaceRoot
    if ([string]::IsNullOrWhiteSpace($BundlePath)) {
        throw "BundlePath is required for import mode."
    }
    $bundleCanonicalPath = Resolve-CanonicalPath -Path $BundlePath
    $bundleRaw = Get-Content -LiteralPath $bundleCanonicalPath -Raw | ConvertFrom-Json

    $metadataCanonicalJson = [string]$bundleRaw.metadata_canonical_json
    if ([string]::IsNullOrWhiteSpace($metadataCanonicalJson)) {
        throw "Bundle is missing metadata_canonical_json."
    }
    $metadata = $metadataCanonicalJson | ConvertFrom-Json
    if ($metadata.schema_version -ne 1) {
        throw "Unsupported bundle schema version: $($metadata.schema_version)"
    }

    $encryptionKey = Get-RequiredKeyBytes -EnvName $EncryptionKeyEnv -ExpectedBytes 32
    $signingKey = Get-RequiredKeyBytes -EnvName $SigningKeyEnv -ExpectedBytes 32
    Assert-BackupKeyHierarchySeparation `
        -EncryptionKeyBytes $encryptionKey `
        -SigningKeyBytes $signingKey `
        -EncryptionEnvName $EncryptionKeyEnv `
        -SigningEnvName $SigningKeyEnv `
        -LiveKekEnvName $LiveKekEnv `
        -AllowReuse:$AllowKeyReuse

    $iv = [Convert]::FromBase64String([string]$bundleRaw.iv_b64)
    $ciphertext = [Convert]::FromBase64String([string]$bundleRaw.ciphertext_b64)
    $signature = [Convert]::FromBase64String([string]$bundleRaw.signature_b64)

    $signingPayload = Get-SigningPayloadText `
        -MetadataCanonicalJson $metadataCanonicalJson `
        -IvB64 ([string]$bundleRaw.iv_b64) `
        -CiphertextB64 ([string]$bundleRaw.ciphertext_b64)
    $expectedSignature = Compute-HmacSha256 -KeyBytes $signingKey -Text $signingPayload

    if (-not (Compare-ByteArraysFixedTime -Left $signature -Right $expectedSignature)) {
        throw "Bundle signature verification failed."
    }

    $plainBytes = Unprotect-BackupPayload -InitializationVector $iv -Ciphertext $ciphertext -KeyBytes $encryptionKey

    $quarantineRootResolved = if ([string]::IsNullOrWhiteSpace($QuarantineRoot)) {
        Join-Path $workspaceRoot ".tmp\security\runtime_restore_quarantine"
    } else {
        $QuarantineRoot
    }
    Ensure-Directory -Path $quarantineRootResolved
    $quarantineDir = Join-Path $quarantineRootResolved ("restore_" + [guid]::NewGuid().ToString("N"))
    Ensure-Directory -Path $quarantineDir
    $quarantineCanonical = Resolve-CanonicalPath -Path $quarantineDir

    try {
        Expand-ArchiveSafely -ArchiveBytes $plainBytes -DestinationPath $quarantineCanonical

        $manifestSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $metadata.manifest) {
            $relativePath = [string]$entry.path
            Assert-ManifestPathSafe -RelativePath $relativePath
            if (-not $manifestSet.Add($relativePath)) {
                throw "Manifest contains duplicate path entry: $relativePath"
            }
        }

        foreach ($entry in $metadata.manifest) {
            $relativePath = [string]$entry.path
            Assert-ManifestPathSafe -RelativePath $relativePath

            $candidateCanonical = Resolve-ManifestCandidatePath `
                -QuarantineRoot $quarantineCanonical `
                -RelativePath $relativePath
            if ($null -eq $candidateCanonical) {
                throw "Manifest file missing after quarantine restore: $relativePath"
            }
            if (-not $candidateCanonical.StartsWith($quarantineCanonical, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Manifest path escaped quarantine root: $relativePath"
            }

            $hash = (Get-FileHash -LiteralPath $candidateCanonical -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($hash -ne [string]$entry.sha256) {
                throw "Manifest hash mismatch for $relativePath"
            }
        }

        $extractedFiles = Get-ChildItem -LiteralPath $quarantineCanonical -File -Recurse
        foreach ($file in $extractedFiles) {
            $relative = $file.FullName.Substring($quarantineCanonical.Length).TrimStart("\", "/").Replace("\", "/")
            if ($manifestSet.Contains($relative)) {
                continue
            }
            $parts = $relative -split "/", 2
            if ($parts.Length -eq 2 -and $manifestSet.Contains($parts[1])) {
                continue
            }
            else {
                throw "Quarantine extraction produced unexpected file not listed in manifest: $relative"
            }
        }

        $restoreParent = Split-Path -Parent $RestorePath
        Ensure-Directory -Path $restoreParent

        $backupPath = $null
        if (Test-Path -LiteralPath $RestorePath) {
            $backupRoot = Join-Path $restoreParent "backups\runtime_secure_import"
            Ensure-Directory -Path $backupRoot
            $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
            $backupPath = Join-Path $backupRoot $stamp
            Move-Item -LiteralPath $RestorePath -Destination $backupPath -Force
        }

        Move-Item -LiteralPath $quarantineCanonical -Destination $RestorePath -Force

        if ([string]::IsNullOrWhiteSpace($RewrapMarkerPath)) {
            $RewrapMarkerPath = Resolve-DefaultSecurityPath -LeafName "runtime_restore_rewrap_required.json"
        }
        $rewrapMarker = Write-RewrapMarker `
            -Path $RewrapMarkerPath `
            -BundlePathCanonical $bundleCanonicalPath `
            -RestorePathCanonical ([System.IO.Path]::GetFullPath($RestorePath)) `
            -LiveKekEnvName $LiveKekEnv

        Write-Host "runtime secure backup imported: $RestorePath"
        if ($backupPath) {
            Write-Host "previous runtime moved to backup: $backupPath"
        }
        Write-Host "post-restore rewrap required marker written: $rewrapMarker"
    }
    finally {
        if (Test-Path -LiteralPath $quarantineCanonical) {
            Remove-Item -LiteralPath $quarantineCanonical -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Acknowledge-RewrapCompletion {
    Assert-DangerousActionAuthorization `
        -ActionName "kek_rewrap_acknowledgement" `
        -ModeName "AcknowledgeRewrap" `
        -PrimaryReauthEnvName $AdminReauthEnv `
        -PrimaryReauthCode $AdminReauthCode

    if ([string]::IsNullOrWhiteSpace($RewrapMarkerPath)) {
        $RewrapMarkerPath = Resolve-DefaultSecurityPath -LeafName "runtime_restore_rewrap_required.json"
    }
    if ([string]::IsNullOrWhiteSpace($RewrapAckPath)) {
        $RewrapAckPath = Resolve-DefaultSecurityPath -LeafName "runtime_restore_rewrap_acknowledged.json"
    }
    $ackPath = Write-RewrapAcknowledgement -MarkerPath $RewrapMarkerPath -AckPath $RewrapAckPath
    Write-Host "post-restore rewrap acknowledged: $ackPath"
}

if ($Mode -eq "Export") {
    Export-SecureBackupBundle
}
elseif ($Mode -eq "Import") {
    Import-SecureBackupBundle
}
elseif ($Mode -eq "AcknowledgeRewrap") {
    Acknowledge-RewrapCompletion
}
