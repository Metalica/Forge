param(
    [switch]$FailOnFindings = $true,
    [string]$ReportPath = "",
    [string]$ReleasesRoot = "E:\Forge\lamma.cpp\releases",
    [string]$RuntimeRoot = "E:\Forge\runtimes\llama.cpp",
    [string]$QuarantineMarkerPath = "",
    [switch]$RequireSignature = $false,
    [string]$ManifestSigningKeyEnv = "FORGE_RUNTIME_MANIFEST_SIGNING_KEY_B64"
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Get-EnvFlag {
    param([Parameter(Mandatory = $true)][string]$Name)
    $raw = [Environment]::GetEnvironmentVariable($Name, "Process")
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $false
    }
    $normalized = $raw.Trim().ToLowerInvariant()
    return $normalized -in @("1", "true", "yes", "on")
}

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

function Compare-ByteArraysFixedTime {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
    )
    if ($Left.Length -ne $Right.Length) {
        return $false
    }
    $diff = 0
    for ($i = 0; $i -lt $Left.Length; $i++) {
        $diff = $diff -bor ($Left[$i] -bxor $Right[$i])
    }
    return ($diff -eq 0)
}

function Get-RelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$BasePath,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $baseUri = [System.Uri]($BasePath.TrimEnd("\") + "\")
    $pathUri = [System.Uri]$Path
    return [System.Uri]::UnescapeDataString($baseUri.MakeRelativeUri($pathUri).ToString()).Replace("/", "\")
}

function Get-FileDigestMap {
    param(
        [Parameter(Mandatory = $true)][string]$RootPath,
        [string[]]$ExcludeRelativePaths = @()
    )
    $excludeSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($path in $ExcludeRelativePaths) {
        $excludeSet.Add($path.Replace("/", "\")) | Out-Null
    }

    $map = @{}
    $files = @(Get-ChildItem -LiteralPath $RootPath -File -Recurse -ErrorAction SilentlyContinue)
    foreach ($file in $files) {
        $relative = Get-RelativePath -BasePath $RootPath -Path $file.FullName
        if ($excludeSet.Contains($relative)) {
            continue
        }
        $hash = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256
        $map[$relative] = $hash.Hash.ToLowerInvariant()
    }
    return $map
}

function Add-Finding {
    param(
        [Parameter(Mandatory = $true)]$Sink,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if ($null -eq $Sink) {
        throw "finding sink is null"
    }
    $Sink.Add($Message) | Out-Null
}

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $workspaceRoot ".tmp\security"
if (-not (Test-Path -LiteralPath $artifactRoot)) {
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
}
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $artifactRoot "runtime_update_chain_integrity_report.json"
}
if ([string]::IsNullOrWhiteSpace($QuarantineMarkerPath)) {
    $QuarantineMarkerPath = Join-Path $artifactRoot "QUARANTINE_RUNTIME_UPDATE_CHAIN.flag"
}

$findings = [System.Collections.Generic.List[string]]::new()
$signatureRequired = ($RequireSignature.IsPresent -or (Get-EnvFlag -Name "FORGE_REQUIRE_RUNTIME_UPDATE_SIGNATURE"))
$signingKeyB64 = [Environment]::GetEnvironmentVariable($ManifestSigningKeyEnv, "Process")
$signingKeyBytes = $null
if (-not [string]::IsNullOrWhiteSpace($signingKeyB64)) {
    try {
        $signingKeyBytes = [Convert]::FromBase64String($signingKeyB64.Trim())
    }
    catch {
        Add-Finding -Sink $findings -Message "invalid base64 in signing key env ${ManifestSigningKeyEnv}: $($_.Exception.Message)"
    }
}
elseif ($signatureRequired) {
    Add-Finding -Sink $findings -Message "runtime update signature required but signing key env '${ManifestSigningKeyEnv}' is unset"
}

$metadataPath = Join-Path $RuntimeRoot "runtime_selection.json"
$applies = Test-Path -LiteralPath $metadataPath
$metadata = $null
$releaseTag = ""
$releaseRoot = ""
$manifestPath = ""
$manifestShaPath = ""
$manifestSignaturePath = ""
$manifestSha256 = ""
$manifestHashValid = $false
$manifestSignatureValid = $false
$manifestSignatureDetail = ""
$rollbackPath = ""
$rollbackAvailable = $false
$postInstallDiff = [PSCustomObject]@{
    source_file_count = 0
    runtime_file_count = 0
    missing_in_runtime = @()
    extra_in_runtime = @()
    hash_mismatch = @()
}

if ($applies) {
    try {
        $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Add-Finding -Sink $findings -Message "runtime selection metadata parse failed: $($_.Exception.Message)"
    }

    if ($null -ne $metadata) {
        $releaseTag = [string]$metadata.release_tag
        if ([string]::IsNullOrWhiteSpace($releaseTag)) {
            Add-Finding -Sink $findings -Message "runtime selection metadata missing release_tag"
        }
        else {
            $releaseRoot = Join-Path $ReleasesRoot $releaseTag
            $manifestPath = Join-Path $releaseRoot "manifest.json"
            $manifestShaPath = Join-Path $releaseRoot "manifest.json.sha256"
            $manifestSignaturePath = Join-Path $releaseRoot "manifest.signature.json"

            if (-not (Test-Path -LiteralPath $manifestPath)) {
                Add-Finding -Sink $findings -Message "release manifest missing: $manifestPath"
            }
            else {
                $manifestSha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
                if (-not (Test-Path -LiteralPath $manifestShaPath)) {
                    Add-Finding -Sink $findings -Message "release manifest digest missing: $manifestShaPath"
                }
                else {
                    $manifestShaLine = (Get-Content -LiteralPath $manifestShaPath -Raw).Trim()
                    $expectedManifestSha = ""
                    $shaMatch = [regex]::Match($manifestShaLine, "[A-Fa-f0-9]{64}")
                    if ($shaMatch.Success) {
                        $expectedManifestSha = $shaMatch.Value.ToLowerInvariant()
                    }
                    if ([string]::IsNullOrWhiteSpace($expectedManifestSha)) {
                        Add-Finding -Sink $findings -Message "release manifest digest file has no SHA256 value: $manifestShaPath"
                    }
                    elseif ($expectedManifestSha -ne $manifestSha256) {
                        Add-Finding -Sink $findings -Message "release manifest digest mismatch: expected=$expectedManifestSha observed=$manifestSha256"
                    }
                    else {
                        $manifestHashValid = $true
                    }
                }

                if (Test-Path -LiteralPath $manifestSignaturePath) {
                    try {
                        $signature = Get-Content -LiteralPath $manifestSignaturePath -Raw | ConvertFrom-Json -ErrorAction Stop
                        $signatureDigest = ([string]$signature.digest_sha256).ToLowerInvariant()
                        $signatureB64 = [string]$signature.signature_b64
                        $signatureAlgorithm = ([string]$signature.algorithm).ToLowerInvariant()
                        if ($signatureAlgorithm -ne "hmac-sha256") {
                            Add-Finding -Sink $findings -Message "unsupported manifest signature algorithm: $signatureAlgorithm"
                        }
                        elseif ($signatureDigest -ne $manifestSha256) {
                            Add-Finding -Sink $findings -Message "manifest signature digest mismatch: signed=$signatureDigest observed=$manifestSha256"
                        }
                        elseif ($null -eq $signingKeyBytes) {
                            $manifestSignatureDetail = "signature present but signing key unavailable for verification"
                            if ($signatureRequired) {
                                Add-Finding -Sink $findings -Message "runtime update signature required but signature cannot be verified without signing key"
                            }
                        }
                        else {
                            $actualSig = [Convert]::FromBase64String($signatureB64)
                            $expectedSig = Compute-HmacSha256 -KeyBytes $signingKeyBytes -Text $manifestSha256
                            if (-not (Compare-ByteArraysFixedTime -Left $actualSig -Right $expectedSig)) {
                                Add-Finding -Sink $findings -Message "manifest signature verification failed"
                            }
                            else {
                                $manifestSignatureValid = $true
                                $manifestSignatureDetail = "verified"
                            }
                        }
                    }
                    catch {
                        Add-Finding -Sink $findings -Message "manifest signature parse/verification failed: $($_.Exception.Message)"
                    }
                }
                elseif ($signatureRequired) {
                    Add-Finding -Sink $findings -Message "runtime update signature required but manifest signature file is missing: $manifestSignaturePath"
                }
                else {
                    $manifestSignatureDetail = "signature file absent (optional mode)"
                }
            }
        }

        $rollbackPath = [string]$metadata.backup_path
        if (-not [string]::IsNullOrWhiteSpace($rollbackPath)) {
            $rollbackAvailable = (Test-Path -LiteralPath $rollbackPath)
            if (-not $rollbackAvailable) {
                Add-Finding -Sink $findings -Message "rollback backup path missing: $rollbackPath"
            }
        }

        $sourcePathRaw = [string]$metadata.source_path
        $sourcePath = $sourcePathRaw
        if (-not [System.IO.Path]::IsPathRooted($sourcePath) -and -not [string]::IsNullOrWhiteSpace($releaseRoot)) {
            $sourcePath = Join-Path $releaseRoot ("extracted\" + $sourcePathRaw)
        }

        if ([string]::IsNullOrWhiteSpace($sourcePath) -or -not (Test-Path -LiteralPath $sourcePath)) {
            Add-Finding -Sink $findings -Message "runtime source path missing for post-install diff: $sourcePath"
        }
        elseif (-not (Test-Path -LiteralPath $RuntimeRoot)) {
            Add-Finding -Sink $findings -Message "runtime root missing for post-install diff: $RuntimeRoot"
        }
        else {
            $sourceMap = Get-FileDigestMap -RootPath $sourcePath
            $runtimeMap = Get-FileDigestMap -RootPath $RuntimeRoot -ExcludeRelativePaths @("runtime_selection.json")
            $postInstallDiff.source_file_count = $sourceMap.Count
            $postInstallDiff.runtime_file_count = $runtimeMap.Count

            $missingInRuntime = [System.Collections.Generic.List[string]]::new()
            $extraInRuntime = [System.Collections.Generic.List[string]]::new()
            $hashMismatch = [System.Collections.Generic.List[string]]::new()

            foreach ($key in $sourceMap.Keys) {
                if (-not $runtimeMap.ContainsKey($key)) {
                    $missingInRuntime.Add($key) | Out-Null
                    continue
                }
                if ($runtimeMap[$key] -ne $sourceMap[$key]) {
                    $hashMismatch.Add($key) | Out-Null
                }
            }
            foreach ($key in $runtimeMap.Keys) {
                if (-not $sourceMap.ContainsKey($key)) {
                    $extraInRuntime.Add($key) | Out-Null
                }
            }

            $postInstallDiff = [PSCustomObject]@{
                source_file_count = $sourceMap.Count
                runtime_file_count = $runtimeMap.Count
                missing_in_runtime = @($missingInRuntime | Sort-Object)
                extra_in_runtime = @($extraInRuntime | Sort-Object)
                hash_mismatch = @($hashMismatch | Sort-Object)
            }

            if ($missingInRuntime.Count -gt 0 -or $extraInRuntime.Count -gt 0 -or $hashMismatch.Count -gt 0) {
                Add-Finding -Sink $findings -Message "post-install runtime diff detected (missing=$($missingInRuntime.Count), extra=$($extraInRuntime.Count), hash_mismatch=$($hashMismatch.Count))"
            }
        }
    }
}

$quarantineRequired = ($applies -and $findings.Count -gt 0)
if ($quarantineRequired) {
    $markerPayload = [PSCustomObject]@{
        schema_version = 1
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        check = "runtime_update_chain_integrity_check"
        release_tag = $releaseTag
        findings_count = $findings.Count
        findings = @($findings)
    }
    $markerParent = Split-Path -Parent $QuarantineMarkerPath
    if (-not [string]::IsNullOrWhiteSpace($markerParent) -and -not (Test-Path -LiteralPath $markerParent)) {
        New-Item -ItemType Directory -Path $markerParent -Force | Out-Null
    }
    $markerPayload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $QuarantineMarkerPath -Encoding UTF8
}
elseif (Test-Path -LiteralPath $QuarantineMarkerPath) {
    Remove-Item -LiteralPath $QuarantineMarkerPath -Force -ErrorAction SilentlyContinue
}

$passed = ($findings.Count -eq 0)
$report = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    workspace_root = $workspaceRoot
    check = "runtime_update_chain_integrity_check"
    applies = $applies
    runtime_root = $RuntimeRoot
    metadata_path = $metadataPath
    releases_root = $ReleasesRoot
    release_tag = if ([string]::IsNullOrWhiteSpace($releaseTag)) { $null } else { $releaseTag }
    manifest = [PSCustomObject]@{
        path = if ([string]::IsNullOrWhiteSpace($manifestPath)) { $null } else { $manifestPath }
        digest_path = if ([string]::IsNullOrWhiteSpace($manifestShaPath)) { $null } else { $manifestShaPath }
        signature_path = if ([string]::IsNullOrWhiteSpace($manifestSignaturePath)) { $null } else { $manifestSignaturePath }
        sha256 = if ([string]::IsNullOrWhiteSpace($manifestSha256)) { $null } else { $manifestSha256 }
        hash_valid = $manifestHashValid
        signature_required = $signatureRequired
        signature_valid = $manifestSignatureValid
        signature_detail = if ([string]::IsNullOrWhiteSpace($manifestSignatureDetail)) { $null } else { $manifestSignatureDetail }
    }
    rollback = [PSCustomObject]@{
        backup_path = if ([string]::IsNullOrWhiteSpace($rollbackPath)) { $null } else { $rollbackPath }
        backup_available = $rollbackAvailable
    }
    post_install_diff = $postInstallDiff
    quarantine_required = $quarantineRequired
    quarantine_marker_path = $QuarantineMarkerPath
    passed = $passed
    findings_count = $findings.Count
    findings = @($findings)
}

$reportParent = Split-Path -Parent $ReportPath
if (-not [string]::IsNullOrWhiteSpace($reportParent) -and -not (Test-Path -LiteralPath $reportParent)) {
    New-Item -ItemType Directory -Path $reportParent -Force | Out-Null
}
$report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $ReportPath -Encoding UTF8

if ($findings.Count -gt 0) {
    Write-Host "Runtime update-chain integrity findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "runtime update-chain integrity check failed"
    }
}
else {
    if ($applies) {
        Write-Host "Runtime update-chain integrity check passed: $ReportPath"
    }
    else {
        Write-Host "Runtime update-chain integrity check not applicable (no active runtime metadata): $ReportPath"
    }
}
