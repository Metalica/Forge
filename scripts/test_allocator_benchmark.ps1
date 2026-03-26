$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

& "$PSScriptRoot\allocator_benchmark.ps1" -SelfTestJemallocRepair

Write-Host "allocator_benchmark.ps1 self-test suite passed."
