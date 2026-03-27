param(
    [switch]$FailOnFindings = $true
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $workspaceRoot ".tmp\security"
$brokerArtifact = Join-Path $artifactRoot "broker_audit_events.json"
$providerArtifact = Join-Path $artifactRoot "provider_adapter_audit_events.json"
$reportPath = Join-Path $artifactRoot "telemetry_split_redaction_report.json"

if (-not (Test-Path $artifactRoot)) {
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
}

& "$PSScriptRoot\broker_audit_export_check.ps1" -FailOnFindings:$FailOnFindings
& "$PSScriptRoot\provider_audit_export_check.ps1" -FailOnFindings:$FailOnFindings

$findings = [System.Collections.Generic.List[string]]::new()
$sensitivePatterns = @(
    "sk-[A-Za-z0-9._-]{12,}",
    "(?i)authorization\s*[:=]?\s*bearer\s+[A-Za-z0-9._-]{12,}",
    "(?i)bearer\s+[A-Za-z0-9._-]{16,}"
)

$logPath = Join-Path $workspaceRoot "forge.exe.log"
if (Test-Path $logPath) {
    $rawLog = Get-Content -LiteralPath $logPath -Raw -ErrorAction SilentlyContinue
    if (-not [string]::IsNullOrWhiteSpace($rawLog)) {
        foreach ($pattern in $sensitivePatterns) {
            if ([regex]::IsMatch($rawLog, $pattern)) {
                $findings.Add("forge.exe.log contains sensitive telemetry content pattern [$pattern]") | Out-Null
            }
        }
    }
}

$report = [PSCustomObject]@{
    schema_version   = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    channels         = @(
        [PSCustomObject]@{
            channel = "security_events"
            source = "forge_security::broker"
            artifact = $brokerArtifact
            redaction_required = $true
            persistence_scope = "local"
        },
        [PSCustomObject]@{
            channel = "runtime_resource_events"
            source = "runtime_registry::local_api_hardening"
            artifact = $providerArtifact
            redaction_required = $true
            persistence_scope = "local"
        },
        [PSCustomObject]@{
            channel = "content_traces"
            source = "ui_shell::forge.exe.log"
            artifact = $logPath
            redaction_required = $true
            persistence_scope = "local_raw_default"
        }
    )
    findings         = @($findings)
    passed           = ($findings.Count -eq 0)
}

$report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $reportPath -Encoding UTF8

if ($findings.Count -gt 0) {
    Write-Host "Telemetry split/redaction findings:"
    foreach ($finding in $findings) {
        Write-Host " - $finding"
    }
    if ($FailOnFindings) {
        throw "telemetry split/redaction contract check failed"
    }
}
else {
    Write-Host "Telemetry split/redaction check passed: $reportPath"
}
