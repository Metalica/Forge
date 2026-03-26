param(
    [string]$LlamaServerPath = "E:\Forge\runtimes\llama.cpp\llama-server.exe",
    [string]$ModelPath = "E:\Forge\models\default.gguf",
    [string]$ServerHost = "127.0.0.1",
    [int]$Port = 8080,
    [int]$CtxSize = 2048,
    [int]$Threads = 8,
    [int]$GpuLayers = 0,
    [int]$BatchSize = 512,
    [string]$Prompt = "Reply with: forge_phase1_e2e_ok",
    [int]$PredictTokens = 32,
    [int]$StartupTimeoutSeconds = 180,
    [int]$RequestTimeoutSeconds = 90,
    [switch]$UseExistingServer = $false,
    [switch]$KeepServerRunning = $false
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Test-TcpEndpointOpen {
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][int]$PortNumber,
        [int]$TimeoutMs = 1200
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($HostName, $PortNumber, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return $false
        }
        $null = $client.EndConnect($async)
        return $client.Connected
    }
    catch {
        return $false
    }
    finally {
        try {
            $client.Close()
        }
        catch {
        }
    }
}

function Wait-ServerReady {
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][int]$PortNumber,
        [Parameter(Mandatory = $true)][datetime]$DeadlineUtc,
        $Process = $null
    )

    while ((Get-Date).ToUniversalTime() -lt $DeadlineUtc) {
        if ($null -ne $Process -and $Process.HasExited) {
            throw "llama.cpp server process exited before becoming ready (exit code $($Process.ExitCode))"
        }
        if (Test-TcpEndpointOpen -HostName $HostName -PortNumber $PortNumber) {
            return
        }
        Start-Sleep -Milliseconds 750
    }

    throw "timed out waiting for llama.cpp endpoint $HostName`:$PortNumber to become reachable"
}

function Invoke-CompletionWithWarmupRetry {
    param(
        [Parameter(Mandatory = $true)][string]$CompletionUri,
        [Parameter(Mandatory = $true)][string]$RequestBody,
        [Parameter(Mandatory = $true)][int]$RequestTimeoutSeconds,
        [Parameter(Mandatory = $true)][datetime]$DeadlineUtc
    )

    while ((Get-Date).ToUniversalTime() -lt $DeadlineUtc) {
        try {
            return Invoke-RestMethod `
                -Uri $CompletionUri `
                -Method Post `
                -ContentType "application/json" `
                -Body $RequestBody `
                -TimeoutSec $RequestTimeoutSeconds
        }
        catch {
            $statusCode = $null
            if ($_.Exception -and $_.Exception.Response) {
                try {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }
                catch {
                }
            }

            $details = ""
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                $details = [string]$_.ErrorDetails.Message
            }
            elseif ($_.Exception -and $_.Exception.Message) {
                $details = [string]$_.Exception.Message
            }

            $isWarmupUnavailable = $false
            if ($statusCode -eq 503) {
                $isWarmupUnavailable = $true
            }
            elseif ($details -match "Loading model" -or $details -match "unavailable_error") {
                $isWarmupUnavailable = $true
            }

            if ($isWarmupUnavailable) {
                Start-Sleep -Seconds 1
                continue
            }

            throw
        }
    }

    throw "timed out waiting for llama.cpp completion endpoint to become ready (model warmup not complete)"
}

function Get-CompletionText {
    param([Parameter(Mandatory = $true)]$Response)

    if ($null -eq $Response) {
        return ""
    }
    if ($Response.PSObject.Properties.Name -contains "content") {
        return [string]$Response.content
    }
    if ($Response.PSObject.Properties.Name -contains "response") {
        return [string]$Response.response
    }
    if (
        ($Response.PSObject.Properties.Name -contains "choices") -and
        $null -ne $Response.choices -and
        $Response.choices.Count -gt 0
    ) {
        $first = $Response.choices[0]
        if ($first.PSObject.Properties.Name -contains "text") {
            return [string]$first.text
        }
        if (
            ($first.PSObject.Properties.Name -contains "message") -and
            ($first.message.PSObject.Properties.Name -contains "content")
        ) {
            return [string]$first.message.content
        }
    }
    return ""
}

function Get-DefaultGgufModelPath {
    $modelsRoot = "E:\Forge\models"
    if (-not (Test-Path -Path $modelsRoot)) {
        return $null
    }
    $candidates = Get-ChildItem -Path $modelsRoot -File -Filter "*.gguf" -ErrorAction SilentlyContinue |
        Sort-Object -Property FullName
    if ($null -eq $candidates -or $candidates.Count -eq 0) {
        return $null
    }
    return $candidates[0].FullName
}

function Resolve-LlamaServerPath {
    param([Parameter(Mandatory = $true)][string]$PreferredPath)

    $candidates = @(
        $PreferredPath,
        "E:\Forge\runtimes\llama.cpp\llama-server.exe",
        "E:\Forge\runtimes\llama.cpp\llama-server",
        "E:\Forge\runtimes\llama.cpp\bin\llama-server.exe",
        "E:\Forge\runtimes\llama.cpp\bin\llama-server"
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

    foreach ($candidate in $candidates) {
        if (Test-Path -Path $candidate) {
            return $candidate
        }
    }
    return $null
}

& "$PSScriptRoot\bootstrap_env.ps1"

$process = $null
$startedServer = $false
try {
    if (-not $UseExistingServer) {
        $resolvedServerPath = Resolve-LlamaServerPath -PreferredPath $LlamaServerPath
        if ([string]::IsNullOrWhiteSpace($resolvedServerPath)) {
            throw "llama-server binary was not found. Checked expected locations under E:\\Forge\\runtimes\\llama.cpp. Use -UseExistingServer if llama.cpp is already running."
        }

        $resolvedModelPath = $ModelPath
        if (-not (Test-Path -Path $resolvedModelPath)) {
            $discoveredModelPath = Get-DefaultGgufModelPath
            if (-not [string]::IsNullOrWhiteSpace($discoveredModelPath)) {
                $resolvedModelPath = $discoveredModelPath
                Write-Host "Model path auto-selected: $resolvedModelPath"
            }
            else {
                throw "model file was not found at: $ModelPath, and no .gguf files were found under E:\\Forge\\models"
            }
        }

        $launchArgs = @(
            "--model", $resolvedModelPath,
            "--host", $ServerHost,
            "--port", "$Port",
            "--ctx-size", "$CtxSize",
            "--threads", "$Threads",
            "--n-gpu-layers", "$GpuLayers",
            "--batch-size", "$BatchSize"
        )
        $process = Start-Process -FilePath $resolvedServerPath -ArgumentList $launchArgs -PassThru -WindowStyle Hidden
        $startedServer = $true
    }

    $deadline = (Get-Date).ToUniversalTime().AddSeconds($StartupTimeoutSeconds)
    Wait-ServerReady -HostName $ServerHost -PortNumber $Port -DeadlineUtc $deadline -Process $process

    $payload = @{
        prompt = $Prompt
        n_predict = $PredictTokens
        stream = $false
    }
    $completionUri = "http://$ServerHost`:$Port/completion"
    $response = Invoke-CompletionWithWarmupRetry `
        -CompletionUri $completionUri `
        -RequestBody ($payload | ConvertTo-Json -Compress) `
        -RequestTimeoutSeconds $RequestTimeoutSeconds `
        -DeadlineUtc ((Get-Date).ToUniversalTime().AddSeconds($StartupTimeoutSeconds))

    $text = Get-CompletionText -Response $response
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw "completion request succeeded but no supported text field was returned"
    }

    $trimmed = $text.Trim()
    if ($trimmed.Length -gt 240) {
        $trimmed = $trimmed.Substring(0, 240) + "..."
    }

    Write-Host "Phase 1 llama.cpp end-to-end validation passed."
    Write-Host "Endpoint: $ServerHost`:$Port"
    Write-Host "Completion preview: $trimmed"
}
finally {
    if ($startedServer -and -not $KeepServerRunning -and $null -ne $process) {
        try {
            if (-not $process.HasExited) {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
        }
    }
}
