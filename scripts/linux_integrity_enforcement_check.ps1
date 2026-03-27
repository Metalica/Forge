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
    $ReportPath = Join-Path $artifactRoot "linux_integrity_enforcement_report.json"
}

$requireAll = Get-EnvFlag -Name "FORGE_REQUIRE_LINUX_INTEGRITY_ENFORCEMENT"
$requireFsVerity = $requireAll -or (Get-EnvFlag -Name "FORGE_REQUIRE_LINUX_FS_VERITY")
$requireDmVerity = $requireAll -or (Get-EnvFlag -Name "FORGE_REQUIRE_LINUX_DM_VERITY")
$requireIma = $requireAll -or (Get-EnvFlag -Name "FORGE_REQUIRE_LINUX_IMA_APPRAISAL")
$requireIpe = $requireAll -or (Get-EnvFlag -Name "FORGE_REQUIRE_LINUX_IPE_APPRAISAL")

$findings = [System.Collections.Generic.List[string]]::new()
$platform = if ($IsLinux) { "linux" } elseif ($IsWindows) { "windows" } elseif ($IsMacOS) { "macos" } else { "unknown" }

$fsVerityAvailable = $false
$fsVerityEvidence = ""
$dmVerityAvailable = $false
$dmVerityEvidence = ""
$imaAvailable = $false
$imaEvidence = ""
$ipeAvailable = $false
$ipeEvidence = ""

if ($IsLinux) {
    $fsVerityCommand = Get-Command fsverity -ErrorAction SilentlyContinue
    $fsVerityAvailable = ($null -ne $fsVerityCommand) -or (Test-Path -LiteralPath "/sys/fs/verity")
    $fsVerityEvidence = if ($null -ne $fsVerityCommand) {
        $fsVerityCommand.Source
    }
    else {
        "/sys/fs/verity"
    }

    $dmsetup = Get-Command dmsetup -ErrorAction SilentlyContinue
    $dmTargetsOutput = ""
    if ($null -ne $dmsetup) {
        try {
            $dmTargetsOutput = (& dmsetup targets 2>&1 | Out-String)
        }
        catch {
            $dmTargetsOutput = ""
        }
    }
    $dmVerityAvailable = (Test-Path -LiteralPath "/sys/module/dm_verity") -or ($dmTargetsOutput -match "(?im)^\s*verity\b")
    $dmVerityEvidence = if ($dmVerityAvailable -and (Test-Path -LiteralPath "/sys/module/dm_verity")) {
        "/sys/module/dm_verity"
    }
    elseif ($dmTargetsOutput -match "(?im)^\s*verity\b") {
        "dmsetup targets includes verity"
    }
    else {
        "dmsetup targets"
    }

    $imaPolicyPath = "/sys/kernel/security/ima/policy"
    $imaAvailable = Test-Path -LiteralPath $imaPolicyPath
    $imaEvidence = $imaPolicyPath

    $lsmPath = "/sys/kernel/security/lsm"
    $lsmRaw = ""
    if (Test-Path -LiteralPath $lsmPath) {
        try {
            $lsmRaw = (Get-Content -LiteralPath $lsmPath -Raw -ErrorAction Stop).Trim().ToLowerInvariant()
        }
        catch {
            $lsmRaw = ""
        }
    }
    $ipeAvailable = (Test-Path -LiteralPath "/sys/kernel/security/ipe") -or ($lsmRaw -match "(^|,)ipe(,|$)")
    $ipeEvidence = if (Test-Path -LiteralPath "/sys/kernel/security/ipe") {
        "/sys/kernel/security/ipe"
    }
    else {
        $lsmPath
    }
}
else {
    $fsVerityEvidence = "non-linux host"
    $dmVerityEvidence = "non-linux host"
    $imaEvidence = "non-linux host"
    $ipeEvidence = "non-linux host"
}

if (-not $IsLinux -and ($requireFsVerity -or $requireDmVerity -or $requireIma -or $requireIpe)) {
    $findings.Add("Linux integrity enforcement strict mode requested on non-linux host") | Out-Null
}
if ($requireFsVerity -and -not $fsVerityAvailable) {
    $findings.Add("required fs-verity capability is unavailable") | Out-Null
}
if ($requireDmVerity -and -not $dmVerityAvailable) {
    $findings.Add("required dm-verity capability is unavailable") | Out-Null
}
if ($requireIma -and -not $imaAvailable) {
    $findings.Add("required IMA appraisal capability is unavailable") | Out-Null
}
if ($requireIpe -and -not $ipeAvailable) {
    $findings.Add("required IPE appraisal capability is unavailable") | Out-Null
}

$report = [PSCustomObject]@{
    schema_version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    workspace_root = $workspaceRoot
    check = "linux_integrity_enforcement_check"
    platform = $platform
    requirements = [PSCustomObject]@{
        require_all = $requireAll
        fs_verity = $requireFsVerity
        dm_verity = $requireDmVerity
        ima_appraisal = $requireIma
        ipe_appraisal = $requireIpe
    }
    capabilities = [PSCustomObject]@{
        fs_verity = [PSCustomObject]@{
            available = $fsVerityAvailable
            evidence = $fsVerityEvidence
        }
        dm_verity = [PSCustomObject]@{
            available = $dmVerityAvailable
            evidence = $dmVerityEvidence
        }
        ima_appraisal = [PSCustomObject]@{
            available = $imaAvailable
            evidence = $imaEvidence
        }
        ipe_appraisal = [PSCustomObject]@{
            available = $ipeAvailable
            evidence = $ipeEvidence
        }
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
    Write-Host "Linux integrity enforcement findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "linux integrity enforcement check failed"
    }
}
else {
    Write-Host "Linux integrity enforcement check passed: $ReportPath"
}
