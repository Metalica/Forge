$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Get-TempRootPath {
    $candidates = @(
        $env:TEMP,
        $env:TMP,
        [System.IO.Path]::GetTempPath()
    )
    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            return $candidate
        }
    }
    return (Join-Path $PSScriptRoot "..\.tmp")
}

$tempRoot = Get-TempRootPath
$root = Join-Path $tempRoot ("forge_relay_attestation_report_selftest_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $root -Force | Out-Null

try {
    $benchmarkPath = Join-Path $root "confidential-relay-benchmark-selftest.json"
    $reportPath = Join-Path $root "relay_attestation_verification_report.json"

    $benchmark = [PSCustomObject]@{
        benchmark = "phase4_confidential_relay_gate"
        generated_at_unix_ms = 1700000000000
        iterations = 4
        profile = [PSCustomObject]@{
            chat_base_delay_ms = 4
            chat_tokens_per_ms_divisor = 12
            verifier_delay_ms = 2
            localhost_http_override_env = "CONFIDENTIAL_ALLOW_INSECURE_LOCALHOST_HTTP"
            localhost_http_override_enabled = $true
        }
        workloads = @(
            [PSCustomObject]@{
                name = "small"
                max_tokens = 128
                sample_count = 4
                routed = [PSCustomObject]@{ avg_ms = 12; p95_ms = 15 }
                confidential = [PSCustomObject]@{
                    avg_ms = 15
                    p95_ms = 18
                    verify_avg_ms = 2
                    verify_p95_ms = 3
                    relay_avg_ms = 11
                    relay_p95_ms = 14
                    total_path_avg_ms = 15
                    total_path_p95_ms = 18
                }
                overhead = [PSCustomObject]@{
                    avg_ms = 3
                    percent = 25
                    max_allowed_percent = 60
                    threshold_passed = $true
                }
            },
            [PSCustomObject]@{
                name = "medium"
                max_tokens = 512
                sample_count = 4
                routed = [PSCustomObject]@{ avg_ms = 25; p95_ms = 30 }
                confidential = [PSCustomObject]@{
                    avg_ms = 30
                    p95_ms = 36
                    verify_avg_ms = 3
                    verify_p95_ms = 5
                    relay_avg_ms = 23
                    relay_p95_ms = 28
                    total_path_avg_ms = 30
                    total_path_p95_ms = 36
                }
                overhead = [PSCustomObject]@{
                    avg_ms = 5
                    percent = 20
                    max_allowed_percent = 40
                    threshold_passed = $true
                }
            },
            [PSCustomObject]@{
                name = "large"
                max_tokens = 2048
                sample_count = 4
                routed = [PSCustomObject]@{ avg_ms = 80; p95_ms = 90 }
                confidential = [PSCustomObject]@{
                    avg_ms = 86
                    p95_ms = 95
                    verify_avg_ms = 4
                    verify_p95_ms = 6
                    relay_avg_ms = 67
                    relay_p95_ms = 74
                    total_path_avg_ms = 86
                    total_path_p95_ms = 95
                }
                overhead = [PSCustomObject]@{
                    avg_ms = 6
                    percent = 8
                    max_allowed_percent = 25
                    threshold_passed = $true
                }
            }
        )
        decision = [PSCustomObject]@{
            passed = $true
            reasons = @("all confidential overhead thresholds passed")
        }
    }

    $benchmark | ConvertTo-Json -Depth 12 | Set-Content -Path $benchmarkPath -Encoding UTF8

    & "$PSScriptRoot\relay_attestation_report_check.ps1" `
        -BenchmarkJsonPath $benchmarkPath `
        -OutputPath $reportPath

    if (-not (Test-Path $reportPath)) {
        throw "relay attestation verification report was not generated"
    }

    $report = Get-Content $reportPath -Raw | ConvertFrom-Json
    if (-not [bool]$report.gate_passed) {
        throw "relay attestation report gate_passed expected true"
    }
    if ($report.attestation_verification.workload_count -ne 3) {
        throw "relay attestation report expected three workloads"
    }

    Write-Host "relay_attestation_report_check.ps1 self-test passed."
}
finally {
    Remove-Item -Path $root -Recurse -Force -ErrorAction SilentlyContinue
}
