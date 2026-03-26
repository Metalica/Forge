param(
    [Parameter(Mandatory = $false)]
    [string[]]$PathsToCheck = @(),
    [switch]$RequireRepoOnEDrive = $true
)

$ErrorActionPreference = "Stop"

function Assert-AllowedPath {
    param([Parameter(Mandatory = $true)][string]$PathValue)

    $resolved = [System.IO.Path]::GetFullPath($PathValue)
    if ($resolved -match '^[cCdD]:\\') {
        throw "Drive policy violation: '$resolved' is outside E:\."
    }
}

$repoRoot = (Get-Location).Path
if ($RequireRepoOnEDrive -and -not ($repoRoot -match '^[eE]:\\')) {
    throw "Repository must be located on E:\. Current location: $repoRoot"
}

if ($PathsToCheck.Count -eq 0) {
    $PathsToCheck = @($repoRoot)
}

foreach ($candidate in $PathsToCheck) {
    Assert-AllowedPath -PathValue $candidate
}

Write-Host "Path guard passed for $($PathsToCheck.Count) path(s)."

