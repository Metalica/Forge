param(
    [string]$ReleasesRoot = "E:\Forge\lamma.cpp\releases",
    [string]$Tag = "",
    [string]$Profile = "win-cpu",
    [string]$RuntimeRoot = "E:\Forge\runtimes\llama.cpp",
    [switch]$ListProfiles = $false
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Resolve-ReleaseTag {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [string]$RequestedTag
    )

    if (-not [string]::IsNullOrWhiteSpace($RequestedTag)) {
        $candidate = Join-Path $Root $RequestedTag
        if (-not (Test-Path -Path $candidate)) {
            throw "Requested release tag was not found under releases root: $RequestedTag"
        }
        return $RequestedTag
    }

    $latest = Get-ChildItem -Path $Root -Directory -ErrorAction SilentlyContinue |
        Sort-Object -Property LastWriteTime -Descending |
        Select-Object -First 1
    if ($null -eq $latest) {
        throw "No release tags found under: $Root"
    }
    return [string]$latest.Name
}

function Get-ProfileMap {
    param([Parameter(Mandatory = $true)][string]$ResolvedTag)

    return @(
        [PSCustomObject]@{ id = "win-cpu"; source_dir = "llama-$ResolvedTag-bin-win-cpu-x64"; backend = "cpu"; platform = "windows" }
        [PSCustomObject]@{ id = "win-cuda-12.4"; source_dir = "llama-$ResolvedTag-bin-win-cuda-12.4-x64"; backend = "cuda"; platform = "windows" }
        [PSCustomObject]@{ id = "win-cuda-13.1"; source_dir = "llama-$ResolvedTag-bin-win-cuda-13.1-x64"; backend = "cuda"; platform = "windows" }
        [PSCustomObject]@{ id = "win-cudart-cuda-12.4"; source_dir = "cudart-llama-bin-win-cuda-12.4-x64"; backend = "cuda"; platform = "windows" }
        [PSCustomObject]@{ id = "win-cudart-cuda-13.1"; source_dir = "cudart-llama-bin-win-cuda-13.1-x64"; backend = "cuda"; platform = "windows" }
        [PSCustomObject]@{ id = "win-hip-radeon"; source_dir = "llama-$ResolvedTag-bin-win-hip-radeon-x64"; backend = "hip"; platform = "windows" }
        [PSCustomObject]@{ id = "linux-cpu"; source_dir = "llama-$ResolvedTag-bin-ubuntu-x64"; backend = "cpu"; platform = "linux" }
        [PSCustomObject]@{ id = "linux-vulkan"; source_dir = "llama-$ResolvedTag-bin-ubuntu-vulkan-x64"; backend = "vulkan"; platform = "linux" }
        [PSCustomObject]@{ id = "linux-rocm-7.2"; source_dir = "llama-$ResolvedTag-bin-ubuntu-rocm-7.2-x64"; backend = "hip"; platform = "linux" }
    )
}

& "$PSScriptRoot\bootstrap_env.ps1"

$resolvedTag = Resolve-ReleaseTag -Root $ReleasesRoot -RequestedTag $Tag
$profiles = Get-ProfileMap -ResolvedTag $resolvedTag
$extractedRoot = Join-Path $ReleasesRoot "$resolvedTag\extracted"

if ($ListProfiles) {
    $profiles | ForEach-Object {
        $sourcePath = Join-Path $extractedRoot $_.source_dir
        [PSCustomObject]@{
            profile = $_.id
            platform = $_.platform
            backend = $_.backend
            source_exists = Test-Path -Path $sourcePath
            source_path = $sourcePath
        }
    } | Format-Table -AutoSize
    exit 0
}

$selectedProfile = $profiles | Where-Object { $_.id -eq $Profile } | Select-Object -First 1
if ($null -eq $selectedProfile) {
    $available = ($profiles.id | Sort-Object) -join ", "
    throw "Unknown profile '$Profile'. Available profiles: $available"
}

$sourcePath = Join-Path $extractedRoot $selectedProfile.source_dir
if (-not (Test-Path -Path $sourcePath)) {
    throw "Profile source folder is missing: $sourcePath"
}

$sourceServer = Join-Path $sourcePath "llama-server.exe"
if (-not (Test-Path -Path $sourceServer)) {
    $sourceServer = Join-Path $sourcePath "llama-server"
}
if (-not (Test-Path -Path $sourceServer)) {
    Write-Warning "No llama-server binary found in selected profile path; activation will continue but runtime start may fail."
}

$runtimeParent = Split-Path -Parent $RuntimeRoot
Ensure-Directory -Path $runtimeParent

$stagingRoot = "$RuntimeRoot.staging"
$backupRoot = Join-Path $runtimeParent "backups\llama.cpp"
if (Test-Path -Path $stagingRoot) {
    Remove-Item -Path $stagingRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $stagingRoot -Force | Out-Null
Copy-Item -Path (Join-Path $sourcePath "*") -Destination $stagingRoot -Recurse -Force

$backupPath = $null
if (Test-Path -Path $RuntimeRoot) {
    Ensure-Directory -Path $backupRoot
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
    $backupPath = Join-Path $backupRoot $stamp
    Move-Item -Path $RuntimeRoot -Destination $backupPath -Force
}
Move-Item -Path $stagingRoot -Destination $RuntimeRoot -Force

$metadataPath = Join-Path $RuntimeRoot "runtime_selection.json"
$metadata = [ordered]@{
    release_tag = $resolvedTag
    profile = [string]$selectedProfile.id
    backend = [string]$selectedProfile.backend
    platform = [string]$selectedProfile.platform
    source_path = $sourcePath
    activated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    backup_path = $backupPath
}
$metadata | ConvertTo-Json -Depth 4 | Set-Content -Path $metadataPath -Encoding UTF8

Write-Host "Activated llama.cpp runtime profile."
Write-Host "release: $resolvedTag"
Write-Host "profile: $($selectedProfile.id)"
Write-Host "runtime: $RuntimeRoot"
Write-Host "metadata: $metadataPath"
if ($backupPath) {
    Write-Host "backup: $backupPath"
}
