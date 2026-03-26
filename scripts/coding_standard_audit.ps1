param(
    [string]$Root = "E:\Forge",
    [string]$OutputMarkdown = "",
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$targets = @("crates")
$excludeGlobs = @("!target/**", "!third_party/**", "!lamma.cpp/**")

function Build-GlobArgs {
    $args = @()
    foreach ($glob in $excludeGlobs) {
        $args += @("--glob", $glob)
    }
    return $args
}

function Count-Pattern {
    param(
        [string]$Pattern,
        [string[]]$Paths
    )
    $args = @("-n") + (Build-GlobArgs) + @($Pattern) + $Paths
    $results = & rg @args 2>$null
    if ($LASTEXITCODE -eq 0) {
        return (($results | Measure-Object).Count)
    }
    if ($LASTEXITCODE -eq 1) {
        return 0
    }
    throw "rg failed for pattern: $Pattern"
}

function Find-GenericModuleNames {
    $files = & rg --files (Build-GlobArgs) @targets 2>$null
    if ($LASTEXITCODE -ne 0) { throw "rg --files failed" }
    $matches = $files | rg "(utils|helpers|common|misc|temp|stuff|manager|final_manager)\.rs$" 2>$null
    if ($LASTEXITCODE -eq 0) {
        return @($matches)
    }
    if ($LASTEXITCODE -eq 1) {
        return @()
    }
    throw "rg failed for module-name scan"
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$unwrapExpectCount = Count-Pattern "\bunwrap\(|\bexpect\(" $targets
$unitStringCount = Count-Pattern "Result<\s*\(\s*\)\s*,\s*String\s*>" $targets
$unsafeTokenCount = Count-Pattern "\bunsafe\b" $targets
$envVarCount = Count-Pattern "std::env::var\(|env::var\(" $targets
$genericModules = Find-GenericModuleNames

$largestFiles = Get-ChildItem -Recurse (Join-Path $Root "crates") -Filter *.rs |
    ForEach-Object {
        [PSCustomObject]@{
            Lines = (Get-Content $_.FullName).Count
            Path = $_.FullName
        }
    } |
    Sort-Object Lines -Descending |
    Select-Object -First 10

$summary = [PSCustomObject]@{
    generated_at = $timestamp
    unwrap_expect_count = $unwrapExpectCount
    result_unit_string_count = $unitStringCount
    unsafe_token_count = $unsafeTokenCount
    env_var_access_count = $envVarCount
    generic_module_name_count = @($genericModules).Count
}

if (-not $Quiet) {
    Write-Host "Coding standard audit summary"
    Write-Host "generated_at: $($summary.generated_at)"
    Write-Host "unwrap_expect_count: $($summary.unwrap_expect_count)"
    Write-Host "result_unit_string_count: $($summary.result_unit_string_count)"
    Write-Host "unsafe_token_count: $($summary.unsafe_token_count)"
    Write-Host "env_var_access_count: $($summary.env_var_access_count)"
    Write-Host "generic_module_name_count: $($summary.generic_module_name_count)"
}

if ($OutputMarkdown -ne "") {
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# Forge Coding Standard Audit")
    $lines.Add("")
    $lines.Add("Generated: $($summary.generated_at)")
    $lines.Add("")
    $lines.Add("## Summary")
    $lines.Add("")
    $lines.Add("- unwrap/expect usages: $($summary.unwrap_expect_count)")
    $lines.Add("- Result<(), String> signatures: $($summary.result_unit_string_count)")
    $lines.Add("- unsafe token occurrences: $($summary.unsafe_token_count)")
    $lines.Add("- env var access callsites: $($summary.env_var_access_count)")
    $lines.Add("- generic module-name file matches: $($summary.generic_module_name_count)")
    $lines.Add("")
    $lines.Add("## Largest Rust Files (Top 10)")
    $lines.Add("")
    foreach ($row in $largestFiles) {
        $lines.Add("- $($row.Lines) lines - $($row.Path)")
    }

    if (@($genericModules).Count -gt 0) {
        $lines.Add("")
        $lines.Add("## Generic Module Name Matches")
        $lines.Add("")
        foreach ($item in $genericModules) {
            $lines.Add("- $item")
        }
    }

    $dir = Split-Path -Parent $OutputMarkdown
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
    $lines -join "`n" | Set-Content -Path $OutputMarkdown
    if (-not $Quiet) {
        Write-Host "Wrote markdown report: $OutputMarkdown"
    }
}
