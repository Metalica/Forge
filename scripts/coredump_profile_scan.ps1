param(
    [int]$FailOnFindings = 1,
    [string]$ReportPath = ""
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$findings = [System.Collections.Generic.List[string]]::new()

function Add-Finding {
    param([Parameter(Mandatory = $true)][string]$Message)
    $findings.Add($Message) | Out-Null
}

if ($IsLinux) {
    $ulimitOutput = & sh -lc "ulimit -c" 2>$null
    $ulimitExit = $LASTEXITCODE
    if ($ulimitExit -ne 0) {
        Add-Finding "unable to read Linux core-dump ulimit (sh exit code $ulimitExit)"
    }
    else {
        $coreLimit = "$ulimitOutput".Trim()
        if ($coreLimit -ne "0") {
            Add-Finding "Linux core-dump size limit is '$coreLimit' (expected 0 for secret-bearing flows)"
        }
    }

    $corePatternPath = "/proc/sys/kernel/core_pattern"
    if (Test-Path $corePatternPath) {
        $corePattern = (Get-Content $corePatternPath -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($null -ne $corePattern) {
            $patternText = "$corePattern".Trim()
            if ($patternText -eq "") {
                Add-Finding "Linux core_pattern is empty; expected explicit coredump policy"
            }
        }
    }
}
elseif ($IsWindows) {
    $localDumpsPath = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"
    if (Test-Path $localDumpsPath) {
        $props = Get-ItemProperty -Path $localDumpsPath -ErrorAction SilentlyContinue
        if ($null -ne $props) {
            $dumpType = $props.DumpType
            if ($null -eq $dumpType) {
                Add-Finding "Windows WER LocalDumps is configured but DumpType is unset (explicit disable expected)"
            }
            elseif ([int]$dumpType -ne 0) {
                Add-Finding "Windows WER LocalDumps DumpType=$dumpType (expected 0 or disabled for secret-bearing flows)"
            }
        }
        else {
            Add-Finding "Windows WER LocalDumps is present but unreadable"
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
    $reportDir = Split-Path -Parent $ReportPath
    if (-not [string]::IsNullOrWhiteSpace($reportDir) -and -not (Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }
    $report = [PSCustomObject]@{
        schema_version   = 1
        generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        check            = "coredump_profile_scan"
        findings_count   = $findings.Count
        findings         = @($findings)
        passed           = ($findings.Count -eq 0)
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
}

if ($findings.Count -gt 0) {
    Write-Host "Core dump profile findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings -ne 0) {
        exit 1
    }
    exit 0
}

Write-Host "Core dump profile check passed."
exit 0
