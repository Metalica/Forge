param(
    [switch]$AllowMissing = $false
)

$ErrorActionPreference = "Stop"

$requiredRoots = @(
    "E:\Rust",
    "E:\Python",
    "E:\mingw64"
)

$missing = @()
foreach ($root in $requiredRoots) {
    if (-not (Test-Path -Path $root)) {
        $missing += $root
    }
}

$requiredExecutables = @(
    "E:\Python\python.exe",
    "E:\mingw64\bin\gcc.exe",
    "E:\mingw64\bin\dlltool.exe",
    "E:\Rust\cargo\bin\cargo.exe",
    "E:\Rust\cargo\bin\rustc.exe"
)

foreach ($exe in $requiredExecutables) {
    if (-not (Test-Path -Path $exe)) {
        $missing += $exe
    }
}

$toolchainList = & "E:\Rust\cargo\bin\rustup.exe" toolchain list 2>$null
if ($LASTEXITCODE -ne 0 -or -not ($toolchainList -match "stable-x86_64-pc-windows-gnu")) {
    $missing += "rustup toolchain stable-x86_64-pc-windows-gnu"
}

if ($missing.Count -gt 0) {
    $message = "Missing required toolchain paths: $($missing -join ', ')"
    if ($AllowMissing) {
        Write-Warning $message
    }
    else {
        throw $message
    }
}

Write-Host "Toolchain guard completed."
