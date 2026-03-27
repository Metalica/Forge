param(
    [switch]$FailOnFindings = $true,
    [string]$ReportPath = ""
)

$ErrorActionPreference = "Stop"

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$findings = [System.Collections.Generic.List[string]]::new()

function Add-Finding {
    param([Parameter(Mandatory = $true)][string]$Message)
    $findings.Add($Message) | Out-Null
}

function Test-IsForgeScopedProcess {
    param([Parameter(Mandatory = $true)][string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return $false
    }
    $workspaceEscaped = [regex]::Escape($workspaceRoot)
    return [regex]::IsMatch($CommandLine, $workspaceEscaped, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

if ($IsLinux -and (Test-Path "/proc")) {
    $procDirs = Get-ChildItem -Path "/proc" -Directory -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match "^\d+$"
    }
    foreach ($dir in $procDirs) {
        $cmdlinePath = Join-Path $dir.FullName "cmdline"
        $statusPath = Join-Path $dir.FullName "status"
        if (-not (Test-Path $cmdlinePath) -or -not (Test-Path $statusPath)) {
            continue
        }

        try {
            $rawCmd = Get-Content -LiteralPath $cmdlinePath -Raw -ErrorAction Stop
            $cmd = $rawCmd -replace "`0", " "
            if (-not (Test-IsForgeScopedProcess -CommandLine $cmd)) {
                continue
            }

            $statusText = Get-Content -LiteralPath $statusPath -Raw -ErrorAction Stop
            $match = [regex]::Match($statusText, "(?m)^Dumpable:\s*(\d+)\s*$")
            if (-not $match.Success) {
                Add-Finding "pid=$($dir.Name) missing Dumpable field in /proc status"
                continue
            }

            $dumpable = [int]$match.Groups[1].Value
            if ($dumpable -ne 0) {
                Add-Finding "pid=$($dir.Name) Dumpable=$dumpable for Forge-scoped process (expected 0)"
            }
        }
        catch {
            continue
        }
    }
}
elseif ($IsWindows) {
    Write-Host "Process dumpability scan skipped: Linux /proc Dumpable signal is not available on Windows."
}
else {
    Write-Host "Process dumpability scan skipped: unsupported platform."
}

if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
    $reportDir = Split-Path -Parent $ReportPath
    if (-not [string]::IsNullOrWhiteSpace($reportDir) -and -not (Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }
    $report = [PSCustomObject]@{
        schema_version    = 1
        generated_at_utc  = (Get-Date).ToUniversalTime().ToString("o")
        workspace_root    = $workspaceRoot
        check             = "process_dumpability_scan"
        findings_count    = $findings.Count
        findings          = @($findings)
        passed            = ($findings.Count -eq 0)
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
}

if ($findings.Count -gt 0) {
    Write-Host "Process dumpability findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "Process dumpability scan failed."
    }
}
else {
    Write-Host "Process dumpability scan passed (no findings)."
}
