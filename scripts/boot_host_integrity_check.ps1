param(
    [switch]$FailOnFindings = $true,
    [string]$ReportPath = ""
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

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $workspaceRoot ".tmp\security"
if (-not (Test-Path -LiteralPath $artifactRoot)) {
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
}
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $artifactRoot "boot_host_integrity_report.json"
}

$platform = if ($IsWindows) {
    "windows"
}
elseif ($IsLinux) {
    "linux"
}
elseif ($IsMacOS) {
    "macos"
}
else {
    "unknown"
}

$findings = [System.Collections.Generic.List[string]]::new()

$secureBootSupported = $false
$secureBootEnabled = $false
$secureBootEvidence = ""
$tpmPresent = $false
$tpmReady = $false
$tpmEvidence = ""
$measuredBootAvailable = $false
$measuredBootEvidence = ""

if ($IsWindows) {
    $confirmSecureBoot = Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    if ($null -ne $confirmSecureBoot) {
        $secureBootSupported = $true
        try {
            $secureBootEnabled = [bool](Confirm-SecureBootUEFI)
            $secureBootEvidence = "Confirm-SecureBootUEFI"
        }
        catch {
            $secureBootEvidence = "Confirm-SecureBootUEFI error: $($_.Exception.Message)"
        }
    }
    else {
        $secureBootEvidence = "Confirm-SecureBootUEFI unavailable"
    }

    $getTpm = Get-Command Get-Tpm -ErrorAction SilentlyContinue
    if ($null -ne $getTpm) {
        try {
            $tpm = Get-Tpm
            $tpmPresent = [bool]$tpm.TpmPresent
            $tpmReady = [bool]$tpm.TpmReady
            $tpmEvidence = "Get-Tpm"
        }
        catch {
            $tpmEvidence = "Get-Tpm error: $($_.Exception.Message)"
        }
    }
    else {
        $tpmEvidence = "Get-Tpm unavailable"
    }

    $mbPath = "C:\Windows\Logs\MeasuredBoot"
    $measuredBootAvailable = Test-Path -LiteralPath $mbPath
    $measuredBootEvidence = $mbPath
}
elseif ($IsLinux) {
    $secureBootSupported = Test-Path -LiteralPath "/sys/firmware/efi"
    $secureBootVar = Get-ChildItem -LiteralPath "/sys/firmware/efi/efivars" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "SecureBoot-*" } |
        Select-Object -First 1
    if ($null -ne $secureBootVar) {
        try {
            $secureBootRaw = [System.IO.File]::ReadAllBytes($secureBootVar.FullName)
            if ($secureBootRaw.Length -ge 5) {
                $secureBootEnabled = ($secureBootRaw[4] -eq 1)
                $secureBootEvidence = $secureBootVar.FullName
            }
        }
        catch {
            $secureBootEvidence = "SecureBoot efivar read error: $($_.Exception.Message)"
        }
    }
    elseif ($secureBootSupported) {
        $secureBootEvidence = "SecureBoot efivar missing"
    }
    else {
        $secureBootEvidence = "/sys/firmware/efi missing"
    }

    $tpmPresent = Test-Path -LiteralPath "/sys/class/tpm/tpm0"
    $tpmReady = $tpmPresent
    $tpmEvidence = "/sys/class/tpm/tpm0"
    $measuredBootPath = "/sys/kernel/security/tpm0/binary_bios_measurements"
    $measuredBootAvailable = Test-Path -LiteralPath $measuredBootPath
    $measuredBootEvidence = $measuredBootPath
}
else {
    $secureBootEvidence = "secure boot probe not implemented for this platform"
    $tpmEvidence = "tpm probe not implemented for this platform"
    $measuredBootEvidence = "measured boot probe not implemented for this platform"
}

$integrityState = "unknown"
$integrityStateSource = "heuristic"
$overrideStateRaw = [Environment]::GetEnvironmentVariable("FORGE_HOST_INTEGRITY_STATE", "Process")
if (-not [string]::IsNullOrWhiteSpace($overrideStateRaw)) {
    $normalizedState = $overrideStateRaw.Trim().ToLowerInvariant()
    switch ($normalizedState) {
        "trusted" {
            $integrityState = "trusted"
            $integrityStateSource = "env_override"
        }
        "degraded" {
            $integrityState = "degraded"
            $integrityStateSource = "env_override"
        }
        "unknown" {
            $integrityState = "unknown"
            $integrityStateSource = "env_override"
        }
        default {
            $findings.Add("FORGE_HOST_INTEGRITY_STATE must be one of trusted|degraded|unknown when set") | Out-Null
            $integrityState = "unknown"
            $integrityStateSource = "env_override_invalid"
        }
    }
}
else {
    if ($secureBootEnabled -and $tpmReady -and $measuredBootAvailable) {
        $integrityState = "trusted"
    }
    elseif (($secureBootSupported -and -not $secureBootEnabled) -or ($tpmPresent -and -not $tpmReady)) {
        $integrityState = "degraded"
    }
    else {
        $integrityState = "unknown"
    }
}

$requireTrustedHost = Get-EnvFlag -Name "FORGE_REQUIRE_HOST_INTEGRITY_TRUSTED"
$highTrustSecretMode = Get-EnvFlag -Name "FORGE_HIGH_TRUST_SECRET_MODE"
$highTrustRelayMode = (Get-EnvFlag -Name "FORGE_CONFIDENTIAL_RELAY_REQUIRED") -or (Get-EnvFlag -Name "FORGE_HIGH_TRUST_MODE")
$highTrustRequested = $highTrustSecretMode -or $highTrustRelayMode

if ($requireTrustedHost -and $integrityState -ne "trusted") {
    $findings.Add("host integrity state is '$integrityState' but trusted state is required for high-trust mode") | Out-Null
}

if ($highTrustRequested -and $integrityState -ne "trusted") {
    $findings.Add("high-trust secret/relay mode requested while host integrity state is '$integrityState'") | Out-Null
}

$tpmSealedContext = [Environment]::GetEnvironmentVariable("FORGE_LINUX_KEK_TPM2_CONTEXT", "Process")
if ($highTrustSecretMode -and $IsLinux -and [string]::IsNullOrWhiteSpace($tpmSealedContext)) {
    $findings.Add("high-trust secret mode requested on Linux without FORGE_LINUX_KEK_TPM2_CONTEXT configured") | Out-Null
}

$report = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    workspace_root = $workspaceRoot
    check = "boot_host_integrity_check"
    platform = $platform
    host_integrity_state = $integrityState
    host_integrity_state_source = $integrityStateSource
    secure_boot = [PSCustomObject]@{
        supported = $secureBootSupported
        enabled = $secureBootEnabled
        evidence = $secureBootEvidence
    }
    tpm = [PSCustomObject]@{
        present = $tpmPresent
        ready = $tpmReady
        evidence = $tpmEvidence
        tpm_sealed_release_context = if ([string]::IsNullOrWhiteSpace($tpmSealedContext)) { $null } else { $tpmSealedContext }
    }
    measured_boot = [PSCustomObject]@{
        available = $measuredBootAvailable
        evidence = $measuredBootEvidence
    }
    high_trust = [PSCustomObject]@{
        require_trusted_host = $requireTrustedHost
        secret_mode_requested = $highTrustSecretMode
        relay_mode_requested = $highTrustRelayMode
        requested = $highTrustRequested
    }
    passed = ($findings.Count -eq 0)
    findings_count = $findings.Count
    findings = @($findings)
}

$reportParent = Split-Path -Parent $ReportPath
if (-not [string]::IsNullOrWhiteSpace($reportParent) -and -not (Test-Path -LiteralPath $reportParent)) {
    New-Item -ItemType Directory -Path $reportParent -Force | Out-Null
}
$report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $ReportPath -Encoding UTF8

if ($findings.Count -gt 0) {
    Write-Host "Boot/host integrity findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "boot/host integrity check failed"
    }
}
else {
    Write-Host "Boot/host integrity check passed: $ReportPath"
}
