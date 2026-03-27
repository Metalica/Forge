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
    [string]$AdminReauthEnv = "FORGE_ADMIN_REAUTH_CODE",
    [string]$DualControlCode = "",
    [string]$DualControlEnv = "FORGE_ADMIN_DUAL_CONTROL_CODE",
    [string]$ChangeReason = "",
    [int]$MinChangeReasonLength = 12
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

function Build-EntryMap {
    param([Parameter(Mandatory = $true)][object[]]$Entries)
    $map = @{}
    foreach ($entry in $Entries) {
        $path = [string]$entry.path
        $map[$path] = $entry
    }
    return $map
}

function Build-TrustStateDiff {
    param(
        [Parameter(Mandatory = $true)][object[]]$PreviousEntries,
        [Parameter(Mandatory = $true)][object[]]$NextEntries
    )
    $previousMap = Build-EntryMap -Entries $PreviousEntries
    $nextMap = Build-EntryMap -Entries $NextEntries
    $allPaths = @($previousMap.Keys + $nextMap.Keys | Sort-Object -Unique)
    $changes = @()
    foreach ($path in $allPaths) {
        $previous = $previousMap[$path]
        $next = $nextMap[$path]
        if ($null -eq $previous -and $null -ne $next) {
            $changes += [PSCustomObject]@{
                path = $path
                change = "added"
                previous_present = $false
                next_present = [bool]$next.present
                previous_sha256 = ""
                next_sha256 = [string]$next.sha256
            }
            continue
        }
        if ($null -ne $previous -and $null -eq $next) {
            $changes += [PSCustomObject]@{
                path = $path
                change = "removed"
                previous_present = [bool]$previous.present
                next_present = $false
                previous_sha256 = [string]$previous.sha256
                next_sha256 = ""
            }
            continue
        }
        if ([bool]$previous.present -ne [bool]$next.present) {
            $changes += [PSCustomObject]@{
                path = $path
                change = "presence_changed"
                previous_present = [bool]$previous.present
                next_present = [bool]$next.present
                previous_sha256 = [string]$previous.sha256
                next_sha256 = [string]$next.sha256
            }
            continue
        }
        if ([string]$previous.sha256 -ne [string]$next.sha256) {
            $changes += [PSCustomObject]@{
                path = $path
                change = "sha256_changed"
                previous_present = [bool]$previous.present
                next_present = [bool]$next.present
                previous_sha256 = [string]$previous.sha256
                next_sha256 = [string]$next.sha256
            }
        }
    }
    return $changes
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
    $previousData = $null
    if ($Mode -eq "ApproveBaselineUpdate") {
        if ($TypedConfirmation -ne $RequiredTypedConfirmation) {
            throw "Typed confirmation mismatch. Expected: '$RequiredTypedConfirmation'"
        }
        if ([string]::IsNullOrWhiteSpace($ChangeReason) -or $ChangeReason.Trim().Length -lt $MinChangeReasonLength) {
            throw "ChangeReason is required and must be at least $MinChangeReasonLength characters for policy approvals."
        }

        $expectedAdminCode = [Environment]::GetEnvironmentVariable($AdminReauthEnv)
        if ([string]::IsNullOrWhiteSpace($expectedAdminCode)) {
            throw "Admin re-auth env '$AdminReauthEnv' is not set."
        }
        if ([string]::IsNullOrWhiteSpace($AdminReauthCode) -or $AdminReauthCode -ne $expectedAdminCode) {
            throw "Admin re-auth code verification failed."
        }
        $expectedDualControlCode = [Environment]::GetEnvironmentVariable($DualControlEnv)
        if ([string]::IsNullOrWhiteSpace($expectedDualControlCode)) {
            throw "Dual-control env '$DualControlEnv' is not set."
        }
        if ([string]::IsNullOrWhiteSpace($DualControlCode) -or $DualControlCode -ne $expectedDualControlCode) {
            throw "Dual-control verification failed."
        }
        if ($DualControlCode -eq $AdminReauthCode) {
            throw "Dual-control code must be distinct from the primary admin re-auth code."
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

    $baselineData = $canonical | ConvertFrom-Json
    $trustStateDiff = @()
    if ($Mode -eq "ApproveBaselineUpdate" -and $null -ne $previousData) {
        $trustStateDiff = Build-TrustStateDiff `
            -PreviousEntries @($previousData.entries) `
            -NextEntries @($baselineData.entries)
    }

    $report = [ordered]@{
        schema_version = 1
        mode = $Mode
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        baseline_path = $BaselinePath
        quarantine_required = $false
        policy_version = $PolicyVersion
        admin_reauth = if ($Mode -eq "ApproveBaselineUpdate") { "verified-dual-control" } else { "not-required" }
        dual_control = if ($Mode -eq "ApproveBaselineUpdate") { "verified" } else { "not-required" }
        change_reason = if ($Mode -eq "ApproveBaselineUpdate") { $ChangeReason.Trim() } else { "" }
        trust_state_diff_count = $trustStateDiff.Count
        trust_state_diff = $trustStateDiff
        approval_evidence = if ($Mode -eq "ApproveBaselineUpdate") {
            "Allowed because typed confirmation, primary admin re-auth, and dual-control code verification all succeeded; trust-state diff captured for operator review."
        } else {
            ""
        }
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
$trustStateDiff = Build-TrustStateDiff -PreviousEntries @($baselineData.entries) -NextEntries @($current.entries)
$drifts = @()
foreach ($change in $trustStateDiff) {
    $reason = switch ([string]$change.change) {
        "added" { "missing from baseline" }
        "removed" { "missing from current scan" }
        "presence_changed" { "presence mismatch" }
        default { "sha256 drift" }
    }
    $drifts += [PSCustomObject]@{
        path = [string]$change.path
        reason = $reason
        expected_present = [bool]$change.previous_present
        actual_present = [bool]$change.next_present
        expected_sha256 = [string]$change.previous_sha256
        actual_sha256 = [string]$change.next_sha256
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
