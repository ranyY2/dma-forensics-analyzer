[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ApiBaseUrl,
    [Parameter(Mandatory = $true)]
    [string]$ScanId,
    [Parameter(Mandatory = $true)]
    [string]$UploadToken,
    [ValidateSet('QUICK','DEEP','FULL')]
    [string]$Mode = 'QUICK',
    [string]$OutputDirectory = (Join-Path (Get-Location) 'dma-scan-output')
)

$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot '..\src\DmaForensics.Core.psm1'
Import-Module $modulePath -Force
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$scan = Get-ForensicScan -Mode $Mode
$payload = [ordered]@{
    schema_version = 1
    scan = [ordered]@{
        scan_id = $ScanId
        start_time = $scan.StartTimeUtc
        end_time = $scan.EndTimeUtc
        scanner_version = $scan.ToolVersion
        scan_mode = $scan.ScanMode
    }
    system = @{}
    security = @{}
    pci_devices = @($scan.Artifacts | Where-Object Category -eq 'PCI_DEVICE')
    drivers = @($scan.Artifacts | Where-Object Category -eq 'DRIVER_FILE')
    kernel_events = @()
    device_history = @()
    execution_artifacts = @()
    event_logs = @()
    timeline = @($scan.Timeline)
    findings = @($scan.Findings)
    statistics = $scan.Summary
}

$json = $payload | ConvertTo-Json -Depth 20 -Compress
$uri = '{0}/api/v1/scans/{1}/results' -f $ApiBaseUrl.TrimEnd('/'), $ScanId
$response = Invoke-RestMethod -Uri $uri -Method Post -Headers @{ Authorization = "Bearer $UploadToken" } -ContentType 'application/json' -Body $json
$jsonPath = Join-Path $OutputDirectory ('{0}.json' -f $ScanId)
Set-Content -LiteralPath $jsonPath -Value $json -Encoding UTF8

Write-Output ('Upload abgeschlossen: {0} ({1})' -f $response.status, $response.result_hash)
Write-Output ('Lokales Paket: {0}' -f $jsonPath)
