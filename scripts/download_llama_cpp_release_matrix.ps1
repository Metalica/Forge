param(
    [string]$DestinationRoot = "E:\Forge\lamma.cpp",
    [string]$Tag = "",
    [switch]$SkipExtract = $false
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true
$ProgressPreference = "SilentlyContinue"

function Invoke-GitHubApi {
    param([Parameter(Mandatory = $true)][string]$Uri)
    return Invoke-RestMethod -Uri $Uri -Headers @{ "User-Agent" = "forge-codex" }
}

function Get-TargetRelease {
    param([string]$RequestedTag)
    if (-not [string]::IsNullOrWhiteSpace($RequestedTag)) {
        return Invoke-GitHubApi -Uri "https://api.github.com/repos/ggml-org/llama.cpp/releases/tags/$RequestedTag"
    }
    $releases = Invoke-GitHubApi -Uri "https://api.github.com/repos/ggml-org/llama.cpp/releases"
    $stable = @($releases | Where-Object { -not $_.prerelease -and -not $_.draft })
    if ($stable.Count -eq 0) {
        throw "No stable llama.cpp releases found."
    }
    return $stable[0]
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Get-NormalizedFullPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [System.IO.Path]::GetFullPath($Path)
}

function Assert-PathWithinRoot {
    param(
        [Parameter(Mandatory = $true)][string]$RootPath,
        [Parameter(Mandatory = $true)][string]$CandidatePath
    )
    $rootCanonical = Get-NormalizedFullPath -Path $RootPath
    $candidateCanonical = Get-NormalizedFullPath -Path $CandidatePath
    if (-not $rootCanonical.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $rootCanonical += [System.IO.Path]::DirectorySeparatorChar
    }
    if (-not $candidateCanonical.StartsWith($rootCanonical, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Extraction path escapes root boundary. root=$rootCanonical candidate=$candidateCanonical"
    }
}

function Assert-ExtractedTreeSafe {
    param([Parameter(Mandatory = $true)][string]$RootPath)
    $rootCanonical = Get-NormalizedFullPath -Path $RootPath
    $entries = Get-ChildItem -Path $RootPath -Recurse -Force -ErrorAction SilentlyContinue
    foreach ($entry in $entries) {
        $entryPath = [string]$entry.FullName
        Assert-PathWithinRoot -RootPath $rootCanonical -CandidatePath $entryPath

        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Extraction blocked: reparse point/symlink entry detected at $entryPath"
        }

        $linkTypeProp = $entry.PSObject.Properties["LinkType"]
        if ($null -ne $linkTypeProp -and $linkTypeProp.Value -eq "HardLink") {
            throw "Extraction blocked: hardlink entry detected at $entryPath"
        }
    }
}

function Expand-ArchiveArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][string]$OutputRoot
    )
    $name = [IO.Path]::GetFileName($ArchivePath)
    $baseName = $name -replace "\.tar\.gz$", "" -replace "\.zip$", ""
    $outDir = Join-Path $OutputRoot $baseName
    Assert-PathWithinRoot -RootPath $OutputRoot -CandidatePath $outDir
    Ensure-Directory -Path $outDir

    if ($name.EndsWith(".zip")) {
        Expand-Archive -Path $ArchivePath -DestinationPath $outDir -Force
        Assert-ExtractedTreeSafe -RootPath $outDir
        return
    }
    if ($name.EndsWith(".tar.gz")) {
        $tarOutput = & tar -xf $ArchivePath -C $outDir 2>&1
        $tarExit = $LASTEXITCODE
        if ($tarExit -ne 0) {
            $tarText = ($tarOutput | Out-String)
            $symlinkError =
                $tarText -match "Can't create" -and
                $tarText -match "Invalid argument"
            if ($symlinkError) {
                Write-Warning "tar extraction encountered symlink limitations on this host and continued with regular files: $name"
            }
            else {
                throw "tar extraction failed for $name (exit code $tarExit): $tarText"
            }
        }
        Assert-ExtractedTreeSafe -RootPath $outDir
        Repair-LinuxSoAliases -Root $outDir
        return
    }
}

function Repair-LinuxSoAliases {
    param([Parameter(Mandatory = $true)][string]$Root)

    $versionedLibs = Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "\.so\.[0-9]" }
    foreach ($lib in $versionedLibs) {
        $baseName = $lib.Name -replace "\.so\..*$", ".so"
        $basePath = Join-Path $lib.DirectoryName $baseName
        if (-not (Test-Path -Path $basePath)) {
            Copy-Item -Path $lib.FullName -Destination $basePath -Force
        }
    }
}

& "$PSScriptRoot\bootstrap_env.ps1"

Ensure-Directory -Path $DestinationRoot
$release = Get-TargetRelease -RequestedTag $Tag
$tagName = [string]$release.tag_name
if ([string]::IsNullOrWhiteSpace($tagName)) {
    throw "Resolved release has no tag_name."
}

$releaseRoot = Join-Path $DestinationRoot "releases\$tagName"
$downloadsDir = Join-Path $releaseRoot "downloads"
$extractDir = Join-Path $releaseRoot "extracted"
Ensure-Directory -Path $releaseRoot
Ensure-Directory -Path $downloadsDir
Ensure-Directory -Path $extractDir

$targetAssetNames = @(
    # Windows CPU
    "llama-$tagName-bin-win-cpu-x64.zip",
    # Windows CUDA (old/new)
    "llama-$tagName-bin-win-cuda-12.4-x64.zip",
    "llama-$tagName-bin-win-cuda-13.1-x64.zip",
    # Windows CUDA with bundled cudart (old/new)
    "cudart-llama-bin-win-cuda-12.4-x64.zip",
    "cudart-llama-bin-win-cuda-13.1-x64.zip",
    # Windows HIP Radeon (closest available to ROCm on Windows)
    "llama-$tagName-bin-win-hip-radeon-x64.zip",
    # Linux CPU/Vulkan/ROCm 7.2
    "llama-$tagName-bin-ubuntu-x64.tar.gz",
    "llama-$tagName-bin-ubuntu-vulkan-x64.tar.gz",
    "llama-$tagName-bin-ubuntu-rocm-7.2-x64.tar.gz"
)

$assetsByName = @{}
foreach ($asset in @($release.assets)) {
    $assetsByName[[string]$asset.name] = $asset
}

$selected = @()
$missing = @()
foreach ($name in $targetAssetNames) {
    if ($assetsByName.ContainsKey($name)) {
        $selected += $assetsByName[$name]
    }
    else {
        $missing += $name
    }
}

if ($missing.Count -gt 0) {
    Write-Warning ("Some expected assets are missing from release {0}:`n- {1}" -f $tagName, ($missing -join "`n- "))
}

if ($selected.Count -eq 0) {
    throw "No target assets resolved for release $tagName."
}

$manifestRows = @()
foreach ($asset in $selected) {
    $assetName = [string]$asset.name
    $assetUrl = [string]$asset.browser_download_url
    $targetPath = Join-Path $downloadsDir $assetName
    Write-Host "Downloading $assetName ..."
    Invoke-WebRequest -Uri $assetUrl -OutFile $targetPath

    if (-not $SkipExtract) {
        Write-Host "Extracting $assetName ..."
        Expand-ArchiveArtifact -ArchivePath $targetPath -OutputRoot $extractDir
    }

    $hash = Get-FileHash -Path $targetPath -Algorithm SHA256
    $manifestRows += [PSCustomObject]@{
        release_tag = $tagName
        asset_name = $assetName
        download_url = $assetUrl
        file_path = $targetPath
        file_size_bytes = (Get-Item $targetPath).Length
        sha256 = $hash.Hash
    }
}

# Source archive for build-your-own variants (e.g., Linux CUDA, Windows Vulkan).
$sourceZipPath = Join-Path $downloadsDir "llama-$tagName-source.zip"
Write-Host "Downloading source zip for $tagName ..."
Invoke-WebRequest -Uri ([string]$release.zipball_url) -OutFile $sourceZipPath
if (-not $SkipExtract) {
    Write-Host "Extracting source zip ..."
    Expand-ArchiveArtifact -ArchivePath $sourceZipPath -OutputRoot $extractDir
}
$sourceHash = Get-FileHash -Path $sourceZipPath -Algorithm SHA256
$manifestRows += [PSCustomObject]@{
    release_tag = $tagName
    asset_name = "source-zipball"
    download_url = [string]$release.zipball_url
    file_path = $sourceZipPath
    file_size_bytes = (Get-Item $sourceZipPath).Length
    sha256 = $sourceHash.Hash
}

$manifestPath = Join-Path $releaseRoot "manifest.json"
$manifestRows | ConvertTo-Json -Depth 6 | Set-Content -Path $manifestPath -Encoding UTF8

Write-Host ""
Write-Host "llama.cpp release matrix download complete."
Write-Host "release: $tagName"
Write-Host "root: $releaseRoot"
Write-Host "manifest: $manifestPath"
Write-Host "note: if Linux CUDA or Windows Vulkan binaries are needed and not present in release assets, build from source zip in extracted/."
