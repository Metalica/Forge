param(
    [ValidateSet("Export", "Import")]
    [string]$Mode = "Export",
    [string]$SourcePath = "E:\Forge\runtimes\llama.cpp",
    [string]$BundlePath = "",
    [string]$RestorePath = "E:\Forge\runtimes\llama.cpp",
    [string]$QuarantineRoot = "E:\Forge\.tmp\security\runtime_restore_quarantine",
    [string]$EncryptionKeyEnv = "FORGE_BACKUP_AES256_KEY_B64",
    [string]$SigningKeyEnv = "FORGE_BACKUP_SIGNING_KEY_B64"
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

function Export-SecureBackupBundle {
    $workspaceRoot = Resolve-WorkspaceRoot
    $source = Resolve-CanonicalPath -Path $SourcePath
    if (-not (Test-Path -LiteralPath $source -PathType Container)) {
        throw "Source path is not a directory: $source"
    }

    $encryptionKey = Get-RequiredKeyBytes -EnvName $EncryptionKeyEnv -ExpectedBytes 32
    $signingKey = Get-RequiredKeyBytes -EnvName $SigningKeyEnv -ExpectedBytes 32

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
    $tempZipPath = Join-Path ([System.IO.Path]::GetTempPath()) ("forge_runtime_secure_restore_" + [guid]::NewGuid().ToString("N") + ".zip")

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
        [System.IO.File]::WriteAllBytes($tempZipPath, $plainBytes)
        Expand-Archive -LiteralPath $tempZipPath -DestinationPath $quarantineCanonical -Force

        foreach ($entry in $metadata.manifest) {
            $relativePath = [string]$entry.path
            Assert-ManifestPathSafe -RelativePath $relativePath

            $candidatePath = Join-Path $quarantineCanonical $relativePath
            if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
                throw "Manifest file missing after quarantine restore: $relativePath"
            }

            $candidateCanonical = Resolve-CanonicalPath -Path $candidatePath
            if (-not $candidateCanonical.StartsWith($quarantineCanonical, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Manifest path escaped quarantine root: $relativePath"
            }

            $hash = (Get-FileHash -LiteralPath $candidateCanonical -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($hash -ne [string]$entry.sha256) {
                throw "Manifest hash mismatch for $relativePath"
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

        Write-Host "runtime secure backup imported: $RestorePath"
        if ($backupPath) {
            Write-Host "previous runtime moved to backup: $backupPath"
        }
    }
    finally {
        Remove-Item -LiteralPath $tempZipPath -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $quarantineCanonical) {
            Remove-Item -LiteralPath $quarantineCanonical -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

if ($Mode -eq "Export") {
    Export-SecureBackupBundle
}
elseif ($Mode -eq "Import") {
    Import-SecureBackupBundle
}
