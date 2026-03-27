param(
    [ValidateSet("Baseline", "Verify", "ApproveBaselineUpdate")]
    [string]$Mode = "Verify",
    [string]$BaselinePath = "",
    [string]$ReportPath = "",
    [string]$QuarantineMarkerPath = "",
    [string[]]$WatchPaths = @(
        ".forge_feature_policy.json",
        ".forge_confidential_relay.json",
        ".forge_chat_confidential.json",
        ".forge_extension_host.json",
        ".forge_runtime_registry.json",
        ".forge_source_registry.json"
    ),
    [string]$SigningKeyEnv = "FORGE_POLICY_INTEGRITY_KEY_B64",
    [int]$PolicyVersion = 1,
    [switch]$FailOnDrift = $true,
    [string]$TypedConfirmation = "",
    [string]$RequiredTypedConfirmation = "I UNDERSTAND FORGE POLICY CHANGE",
    [string]$AdminReauthCode = "",
    [string]$AdminReauthEnv = "FORGE_ADMIN_REAUTH_CODE"
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

function Resolve-DefaultPaths {
    $workspaceRoot = Resolve-WorkspaceRoot
    $artifactRoot = Join-Path $workspaceRoot ".tmp\security"
    Ensure-Directory -Path $artifactRoot

    if ([string]::IsNullOrWhiteSpace($BaselinePath)) {
        $script:BaselinePath = Join-Path $artifactRoot "policy_integrity_baseline.json"
    }
    if ([string]::IsNullOrWhiteSpace($ReportPath)) {
        $script:ReportPath = Join-Path $artifactRoot "policy_integrity_drift_report.json"
    }
    if ([string]::IsNullOrWhiteSpace($QuarantineMarkerPath)) {
        $script:QuarantineMarkerPath = Join-Path $artifactRoot "QUARANTINE_MODE.flag"
    }
}

function Get-SigningKeyBytes {
    param([Parameter(Mandatory = $true)][string]$EnvName)
    $raw = [Environment]::GetEnvironmentVariable($EnvName)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Required signing key env '$EnvName' is missing."
    }
    try {
        $decoded = [Convert]::FromBase64String($raw.Trim())
    }
    catch {
        throw "Signing key env '$EnvName' is not valid base64."
    }
    if ($decoded.Length -lt 32) {
        throw "Signing key env '$EnvName' must decode to at least 32 bytes."
    }
    return $decoded
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

function Resolve-WatchedEntries {
    param(
        [Parameter(Mandatory = $true)][string]$WorkspaceRoot,
        [Parameter(Mandatory = $true)][string[]]$RelativePaths
    )
    $entries = @()
    $normalized = @()
    foreach ($relative in ($RelativePaths | Sort-Object -Unique)) {
        $clean = $relative.Replace("/", "\").TrimStart("\")
        $normalized += $clean.Replace("\", "/")
        $absolute = Join-Path $WorkspaceRoot $clean
        if (Test-Path -LiteralPath $absolute -PathType Leaf) {
            $hash = (Get-FileHash -LiteralPath $absolute -Algorithm SHA256).Hash.ToLowerInvariant()
            $file = Get-Item -LiteralPath $absolute
            $entries += [PSCustomObject]@{
                path = $clean.Replace("\", "/")
                present = $true
                sha256 = $hash
                size_bytes = [int64]$file.Length
                last_write_utc = $file.LastWriteTimeUtc.ToString("o")
            }
        }
        else {
            $entries += [PSCustomObject]@{
                path = $clean.Replace("\", "/")
                present = $false
                sha256 = ""
                size_bytes = 0
                last_write_utc = ""
            }
        }
    }
    return [PSCustomObject]@{
        entries = $entries
        normalized_paths = $normalized
    }
}

function Build-BaselineCanonicalJson {
    param(
        [Parameter(Mandatory = $true)][string]$WorkspaceRoot,
        [Parameter(Mandatory = $true)][int]$Version,
        [Parameter(Mandatory = $true)][string[]]$RelativePaths
    )
    $resolved = Resolve-WatchedEntries -WorkspaceRoot $WorkspaceRoot -RelativePaths $RelativePaths
    $baseline = [ordered]@{
        schema_version = 1
        policy_version = $Version
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        workspace_root = $WorkspaceRoot
        watched_paths = $resolved.normalized_paths
        entries = $resolved.entries
    }
    return ($baseline | ConvertTo-Json -Depth 16 -Compress)
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Payload
    )
    $parent = Split-Path -Parent $Path
    Ensure-Directory -Path $parent
    $Payload | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Write-QuarantineMarker {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Reason
    )
    $marker = [ordered]@{
        schema_version = 1
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        quarantine_required = $true
        reason = $Reason
    }
    Write-JsonFile -Path $Path -Payload $marker
}

Resolve-DefaultPaths
$workspaceRoot = Resolve-WorkspaceRoot
$signingKey = Get-SigningKeyBytes -EnvName $SigningKeyEnv

if ($Mode -eq "Baseline" -or $Mode -eq "ApproveBaselineUpdate") {
    if ($Mode -eq "ApproveBaselineUpdate") {
        if ($TypedConfirmation -ne $RequiredTypedConfirmation) {
            throw "Typed confirmation mismatch. Expected: '$RequiredTypedConfirmation'"
        }

        $expectedAdminCode = [Environment]::GetEnvironmentVariable($AdminReauthEnv)
        if ([string]::IsNullOrWhiteSpace($expectedAdminCode)) {
            throw "Admin re-auth env '$AdminReauthEnv' is not set."
        }
        if ([string]::IsNullOrWhiteSpace($AdminReauthCode) -or $AdminReauthCode -ne $expectedAdminCode) {
            throw "Admin re-auth code verification failed."
        }

        if (Test-Path -LiteralPath $BaselinePath) {
            $previousBaseline = Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json
            $previousCanonical = [string]$previousBaseline.baseline_canonical_json
            if (-not [string]::IsNullOrWhiteSpace($previousCanonical)) {
                $previousData = $previousCanonical | ConvertFrom-Json
                if ($PolicyVersion -le [int]$previousData.policy_version) {
                    throw "PolicyVersion must increase monotonically (previous=$($previousData.policy_version), requested=$PolicyVersion)."
                }
            }
        }
    }

    $canonical = Build-BaselineCanonicalJson -WorkspaceRoot $workspaceRoot -Version $PolicyVersion -RelativePaths $WatchPaths
    $signature = Compute-HmacSha256 -KeyBytes $signingKey -Text $canonical
    $bundle = [ordered]@{
        baseline_canonical_json = $canonical
        signature_b64 = [Convert]::ToBase64String($signature)
        signing_key_env = $SigningKeyEnv
    }
    Write-JsonFile -Path $BaselinePath -Payload $bundle

    $report = [ordered]@{
        schema_version = 1
        mode = $Mode
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        baseline_path = $BaselinePath
        quarantine_required = $false
        policy_version = $PolicyVersion
        admin_reauth = if ($Mode -eq "ApproveBaselineUpdate") { "verified" } else { "not-required" }
    }
    Write-JsonFile -Path $ReportPath -Payload $report
    Write-Host "policy integrity baseline written: $BaselinePath"
    exit 0
}

if (-not (Test-Path -LiteralPath $BaselinePath)) {
    throw "Baseline file is missing: $BaselinePath"
}

$baselineBundle = Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json
$baselineCanonical = [string]$baselineBundle.baseline_canonical_json
if ([string]::IsNullOrWhiteSpace($baselineCanonical)) {
    throw "Baseline bundle is missing baseline_canonical_json."
}

$expectedSig = Compute-HmacSha256 -KeyBytes $signingKey -Text $baselineCanonical
$actualSig = [Convert]::FromBase64String([string]$baselineBundle.signature_b64)
$signatureValid = Compare-ByteArraysFixedTime -Left $expectedSig -Right $actualSig

$baselineData = $baselineCanonical | ConvertFrom-Json
$watched = @($baselineData.watched_paths)
$current = Resolve-WatchedEntries -WorkspaceRoot $workspaceRoot -RelativePaths $watched
$currentMap = @{}
foreach ($entry in $current.entries) {
    $currentMap[[string]$entry.path] = $entry
}

$drifts = @()
foreach ($expected in $baselineData.entries) {
    $path = [string]$expected.path
    $actual = $currentMap[$path]
    if ($null -eq $actual) {
        $drifts += [PSCustomObject]@{
            path = $path
            reason = "missing from current scan"
            expected_present = [bool]$expected.present
            actual_present = $false
            expected_sha256 = [string]$expected.sha256
            actual_sha256 = ""
        }
        continue
    }
    if ([bool]$expected.present -ne [bool]$actual.present) {
        $drifts += [PSCustomObject]@{
            path = $path
            reason = "presence mismatch"
            expected_present = [bool]$expected.present
            actual_present = [bool]$actual.present
            expected_sha256 = [string]$expected.sha256
            actual_sha256 = [string]$actual.sha256
        }
        continue
    }
    if ([bool]$expected.present -and [string]$expected.sha256 -ne [string]$actual.sha256) {
        $drifts += [PSCustomObject]@{
            path = $path
            reason = "sha256 drift"
            expected_present = $true
            actual_present = $true
            expected_sha256 = [string]$expected.sha256
            actual_sha256 = [string]$actual.sha256
        }
    }
}

$quarantineRequired = (-not $signatureValid) -or ($drifts.Count -gt 0)
if ($quarantineRequired) {
    $reason = if (-not $signatureValid) {
        "baseline signature verification failed"
    }
    else {
        "integrity drift detected in watched policy surfaces"
    }
    Write-QuarantineMarker -Path $QuarantineMarkerPath -Reason $reason
}
elseif (Test-Path -LiteralPath $QuarantineMarkerPath) {
    Remove-Item -LiteralPath $QuarantineMarkerPath -Force -ErrorAction SilentlyContinue
}

$report = [ordered]@{
    schema_version = 1
    mode = "Verify"
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    baseline_path = $BaselinePath
    signature_valid = $signatureValid
    drift_count = $drifts.Count
    quarantine_required = $quarantineRequired
    quarantine_marker_path = $QuarantineMarkerPath
    drifts = $drifts
}
Write-JsonFile -Path $ReportPath -Payload $report

if ($quarantineRequired -and $FailOnDrift) {
    throw "Policy integrity drift verification failed; quarantine marker created."
}

Write-Host "policy integrity drift check passed: $ReportPath"
