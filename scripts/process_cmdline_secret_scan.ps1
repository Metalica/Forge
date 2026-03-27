param(
    [switch]$FailOnFindings = $true,
    [string]$ReportPath = ""
)

$ErrorActionPreference = "Stop"
$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$isWindowsHost = $false
if ($null -ne $IsWindows -and $IsWindows) {
    $isWindowsHost = $true
}
elseif ($env:OS -eq "Windows_NT") {
    $isWindowsHost = $true
}

$patterns = @(
    "sk-[A-Za-z0-9]{20,}",
    "(?i)(api[-_ ]?key|access[-_ ]?token|auth[-_ ]?token|password)\s*[:=]\s*[^\s]+",
    "(?i)authorization\s*[:=]\s*bearer\s+[A-Za-z0-9._-]{16,}",
    "(?i)bearer\s+[A-Za-z0-9._-]{24,}"
)

function Test-CommandLine {
    param(
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [Parameter(Mandatory = $true)][string]$ProcessLabel
    )

    $findings = @()
    foreach ($pattern in $patterns) {
        if ([regex]::IsMatch($CommandLine, $pattern)) {
            $clipped = if ($CommandLine.Length -gt 220) {
                $CommandLine.Substring(0, 220) + "..."
            }
            else {
                $CommandLine
            }
            $findings += "$ProcessLabel => pattern [$pattern] => $clipped"
            break
        }
    }
    return $findings
}

function Test-IsForgeScopedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$CommandLine
    )
    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return $false
    }
    $workspaceEscaped = [regex]::Escape($workspaceRoot)
    return [regex]::IsMatch($CommandLine, $workspaceEscaped, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

$results = @()

if ($isWindowsHost) {
    $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    foreach ($process in $processes) {
        $cmd = [string]$process.CommandLine
        if ([string]::IsNullOrWhiteSpace($cmd)) {
            continue
        }
        if (-not (Test-IsForgeScopedProcess -CommandLine $cmd)) {
            continue
        }
        $label = "pid=$($process.ProcessId) name=$($process.Name)"
        $results += Test-CommandLine -CommandLine $cmd -ProcessLabel $label
    }
}
elseif (Test-Path "/proc") {
    $procDirs = Get-ChildItem -Path "/proc" -Directory -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match "^\d+$"
    }
    foreach ($dir in $procDirs) {
        $pid = $dir.Name
        $cmdlinePath = Join-Path $dir.FullName "cmdline"
        if (-not (Test-Path $cmdlinePath)) {
            continue
        }
        try {
            $raw = Get-Content -LiteralPath $cmdlinePath -Raw -ErrorAction Stop
            $cmd = $raw -replace "`0", " "
            if ([string]::IsNullOrWhiteSpace($cmd)) {
                continue
            }
            if (-not (Test-IsForgeScopedProcess -CommandLine $cmd)) {
                continue
            }
            $label = "pid=$pid"
            $results += Test-CommandLine -CommandLine $cmd -ProcessLabel $label
        }
        catch {
            continue
        }
    }
}
else {
    Write-Host "Process cmdline secret scan skipped: unsupported platform."
    $results = @()
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
        check             = "process_cmdline_secret_scan"
        findings_count    = $results.Count
        findings          = @($results | Sort-Object -Unique)
        passed            = ($results.Count -eq 0)
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
}

if ($results.Count -gt 0) {
    Write-Host "Potential secret-bearing process command lines detected:"
    $results | Sort-Object -Unique | ForEach-Object { Write-Host $_ }
    if ($FailOnFindings) {
        throw "Process cmdline secret scan failed."
    }
}
else {
    Write-Host "Process cmdline secret scan passed (no findings)."
}
