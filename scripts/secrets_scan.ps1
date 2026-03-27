param(
    [switch]$FailOnFindings = $true,
    [string]$ReportPath = ""
)

$ErrorActionPreference = "Stop"

$patterns = @(
    "AKIA[0-9A-Z]{16}",
    "-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----",
    "xox[baprs]-[0-9A-Za-z-]{10,}",
    "ghp_[A-Za-z0-9]{36}",
    "sk-[A-Za-z0-9]{20,}"
)

$includeGlobs = @("*.rs", "*.toml", "*.yml", "*.yaml", "*.json", "*.ts", "*.js", "*.py", "*.ps1")
$excludeGlobs = @("*.md", "*.txt")

$results = @()
if (Get-Command rg -ErrorAction SilentlyContinue) {
    foreach ($pattern in $patterns) {
        $args = @("--line-number", "--pcre2")
        foreach ($glob in $includeGlobs) {
            $args += @("--glob", $glob)
        }
        foreach ($glob in $excludeGlobs) {
            $args += @("--glob", "!$glob")
        }
        $args += @("--", $pattern, ".")
        $matches = & rg @args 2>$null
        if ($LASTEXITCODE -eq 0 -and $matches) {
            $results += $matches
        }
    }
}
else {
    $candidateFiles = Get-ChildItem -Path . -Recurse -File | Where-Object {
        $name = $_.Name
        ($includeGlobs | ForEach-Object { $name -like $_ }) -contains $true -and
        -not (($excludeGlobs | ForEach-Object { $name -like $_ }) -contains $true)
    }

    foreach ($file in $candidateFiles) {
        foreach ($pattern in $patterns) {
            $matches = Select-String -Path $file.FullName -Pattern $pattern
            foreach ($match in $matches) {
                $results += "$($match.Path):$($match.LineNumber):$($match.Line.Trim())"
            }
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
        check            = "secrets_scan"
        findings_count   = $results.Count
        findings         = @($results | Sort-Object -Unique)
        passed           = ($results.Count -eq 0)
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
}

if ($results.Count -gt 0) {
    Write-Host "Potential secrets detected:"
    $results | Sort-Object -Unique | ForEach-Object { Write-Host $_ }
    if ($FailOnFindings) {
        throw "Secrets scan failed."
    }
}
else {
    Write-Host "Secrets scan passed (no findings)."
}
