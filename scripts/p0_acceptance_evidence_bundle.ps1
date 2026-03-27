param(
    [switch]$FailOnFindings = $true
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $workspaceRoot ".tmp\security"
$bundlePath = Join-Path $artifactRoot "p0_acceptance_evidence_bundle.json"
$argon2Path = Join-Path $artifactRoot "argon2id_benchmark_report.json"
$noncePath = Join-Path $artifactRoot "nonce_uniqueness_report.json"

if (-not (Test-Path $artifactRoot)) {
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
}

function Ensure-Report {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][scriptblock]$Generator
    )
    if (Test-Path $Path) {
        return
    }
    & $Generator
}

Ensure-Report -Path (Join-Path $artifactRoot "secret_leak_report.json") -Generator {
    & "$PSScriptRoot\secrets_scan.ps1" -ReportPath (Join-Path $artifactRoot "secret_leak_report.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "telemetry_scan_report.json") -Generator {
    & "$PSScriptRoot\telemetry_scan.ps1" -ReportPath (Join-Path $artifactRoot "telemetry_scan_report.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "process_cmdline_secret_scan_report.json") -Generator {
    & "$PSScriptRoot\process_cmdline_secret_scan.ps1" -ReportPath (Join-Path $artifactRoot "process_cmdline_secret_scan_report.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "process_dumpability_scan_report.json") -Generator {
    & "$PSScriptRoot\process_dumpability_scan.ps1" -ReportPath (Join-Path $artifactRoot "process_dumpability_scan_report.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "coredump_profile_scan_report.json") -Generator {
    & "$PSScriptRoot\coredump_profile_scan.ps1" -ReportPath (Join-Path $artifactRoot "coredump_profile_scan_report.json")
}
Ensure-Report -Path (Join-Path $artifactRoot "telemetry_split_redaction_report.json") -Generator {
    & "$PSScriptRoot\telemetry_split_redaction_check.ps1"
}
Ensure-Report -Path (Join-Path $artifactRoot "kek_custody_matrix.json") -Generator {
    & "$PSScriptRoot\kek_custody_matrix_check.ps1"
}

& cargo run -p forge_security --bin argon2id_bench_report -- --out $argon2Path --runs 4
if ($LASTEXITCODE -ne 0) {
    throw "argon2id benchmark report generation failed"
}

$nonceCommand = "cargo test -p forge_security persisted_encryption_nonces_are_unique_across_records"
& cargo test -p forge_security persisted_encryption_nonces_are_unique_across_records
$noncePassed = ($LASTEXITCODE -eq 0)
$nonceReport = [PSCustomObject]@{
    schema_version    = 1
    generated_at_utc  = (Get-Date).ToUniversalTime().ToString("o")
    test_name         = "persisted_encryption_nonces_are_unique_across_records"
    command           = $nonceCommand
    passed            = $noncePassed
}
$nonceReport | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $noncePath -Encoding UTF8
if (-not $noncePassed) {
    throw "nonce uniqueness regression test failed"
}

$artifactSpecs = @(
    @{ name = "secret_leak_report"; path = (Join-Path $artifactRoot "secret_leak_report.json"); requirePassed = $true },
    @{ name = "telemetry_scan_report"; path = (Join-Path $artifactRoot "telemetry_scan_report.json"); requirePassed = $true },
    @{ name = "process_cmdline_secret_scan_report"; path = (Join-Path $artifactRoot "process_cmdline_secret_scan_report.json"); requirePassed = $true },
    @{ name = "process_dumpability_scan_report"; path = (Join-Path $artifactRoot "process_dumpability_scan_report.json"); requirePassed = $true },
    @{ name = "coredump_profile_scan_report"; path = (Join-Path $artifactRoot "coredump_profile_scan_report.json"); requirePassed = $true },
    @{ name = "telemetry_split_redaction_report"; path = (Join-Path $artifactRoot "telemetry_split_redaction_report.json"); requirePassed = $true },
    @{ name = "broker_audit_events"; path = (Join-Path $artifactRoot "broker_audit_events.json"); requirePassed = $false },
    @{ name = "provider_adapter_audit_events"; path = (Join-Path $artifactRoot "provider_adapter_audit_events.json"); requirePassed = $false },
    @{ name = "kek_custody_matrix"; path = (Join-Path $artifactRoot "kek_custody_matrix.json"); requirePassed = $false },
    @{ name = "argon2id_benchmark_report"; path = $argon2Path; requirePassed = $false },
    @{ name = "nonce_uniqueness_report"; path = $noncePath; requirePassed = $true }
)

$artifactRows = @()
$gatePassed = $true

foreach ($spec in $artifactSpecs) {
    $present = Test-Path $spec.path
    $parsed = $null
    $passed = $present
    $detail = ""

    if (-not $present) {
        $passed = $false
        $detail = "artifact missing"
    }
    else {
        try {
            $raw = Get-Content -LiteralPath $spec.path -Raw -ErrorAction Stop
            $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
            if ($spec.requirePassed) {
                if ($null -eq $parsed.passed) {
                    $passed = $false
                    $detail = "artifact missing passed flag"
                }
                elseif (-not [bool]$parsed.passed) {
                    $passed = $false
                    $detail = "artifact reported failure"
                }
            }
            if ($passed -and $null -eq $parsed.schema_version) {
                $passed = $false
                $detail = "artifact missing schema_version"
            }
        }
        catch {
            $passed = $false
            $detail = "artifact parse error: $($_.Exception.Message)"
        }
    }

    $artifactRows += [PSCustomObject]@{
        name = $spec.name
        path = $spec.path
        present = $present
        passed = $passed
        detail = $detail
    }

    if (-not $passed) {
        $gatePassed = $false
    }
}

$bundle = [PSCustomObject]@{
    schema_version   = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    artifact_root    = $artifactRoot
    gate_passed      = $gatePassed
    artifacts        = $artifactRows
}

$bundle | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $bundlePath -Encoding UTF8

if (-not $gatePassed) {
    Write-Host "P0 acceptance evidence bundle contains failing artifacts:"
    foreach ($row in $artifactRows | Where-Object { -not $_.passed }) {
        Write-Host " - $($row.name): $($row.detail)"
    }
    if ($FailOnFindings) {
        throw "P0 acceptance evidence bundle failed"
    }
}
else {
    Write-Host "P0 acceptance evidence bundle generated: $bundlePath"
}
