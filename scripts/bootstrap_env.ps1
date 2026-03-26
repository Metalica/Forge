$ErrorActionPreference = "Stop"

$isWindowsHost = $false
if (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) {
    $isWindowsHost = [bool]$IsWindows
}
elseif ($PSVersionTable.PSEdition -eq "Desktop") {
    $isWindowsHost = $true
}
elseif ($env:OS -eq "Windows_NT") {
    $isWindowsHost = $true
}

if (-not $isWindowsHost) {
    Write-Host "Forge environment bootstrap skipped: non-Windows host."
    return
}

$env:RUST_HOME = "E:\Rust"
$env:PYTHON_HOME = "E:\Python"
$env:MINGW64_HOME = "E:\mingw64"
$env:MINGW64_BIN = "E:\mingw64\bin"
$env:GIT_HOME = "E:\Git"
$env:GIT_BIN = "E:\Git\bin"
$env:GIT_USR_BIN = "E:\Git\usr\bin"
$env:CC = "$($env:MINGW64_BIN)\gcc.exe"
$env:CXX = "$($env:MINGW64_BIN)\g++.exe"
$env:AR = "$($env:MINGW64_BIN)\ar.exe"
$env:DLLTOOL = "$($env:MINGW64_BIN)\dlltool.exe"
$env:CC_x86_64_pc_windows_gnu = $env:CC
$env:CXX_x86_64_pc_windows_gnu = $env:CXX
$env:AR_x86_64_pc_windows_gnu = $env:AR

$env:CARGO_HOME = "E:\Rust\cargo"
$env:RUSTUP_HOME = "E:\Rust\rustup"
$env:RUSTUP_TOOLCHAIN = "stable-x86_64-pc-windows-gnu"
$env:TMP = "E:\Forge\.tmp"
$env:TEMP = "E:\Forge\.tmp"

$requiredDirs = @(
    $env:RUST_HOME,
    $env:PYTHON_HOME,
    $env:MINGW64_HOME,
    $env:CARGO_HOME,
    $env:RUSTUP_HOME,
    $env:TMP
)

foreach ($dir in $requiredDirs) {
    if (-not (Test-Path -Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

$requiredTools = @(
    $env:CC,
    $env:CXX,
    $env:AR,
    $env:DLLTOOL
)
foreach ($tool in $requiredTools) {
    if (-not (Test-Path -Path $tool)) {
        throw "Forge toolchain bootstrap failed: missing required tool $tool"
    }
}

if (Test-Path -Path $env:GIT_USR_BIN) {
    if (-not ($env:PATH -split ";" | Where-Object { $_ -eq $env:GIT_USR_BIN })) {
        $env:PATH = "$($env:GIT_USR_BIN);$($env:PATH)"
    }
}

if (Test-Path -Path $env:GIT_BIN) {
    if (-not ($env:PATH -split ";" | Where-Object { $_ -eq $env:GIT_BIN })) {
        $env:PATH = "$($env:GIT_BIN);$($env:PATH)"
    }
}

if (Test-Path -Path $env:MINGW64_BIN) {
    if (-not ($env:PATH -split ";" | Where-Object { $_ -eq $env:MINGW64_BIN })) {
        $env:PATH = "$($env:MINGW64_BIN);$($env:PATH)"
    }
}

Write-Host "Forge environment bootstrapped for E-drive execution."
