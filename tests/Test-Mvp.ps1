[CmdletBinding()]
param(
    [string]$ProjectRoot = $(if ($PSScriptRoot) { Split-Path $PSScriptRoot -Parent } else { (Get-Location).Path })
)

$ErrorActionPreference = 'Stop'
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
$modulePath = Join-Path $ProjectRoot 'src\DmaForensics.Core.psm1'
Import-Module $modulePath -Force
$scan = Get-ForensicScan -Mode QUICK

if (-not $scan.ReadOnly) { throw 'Scan must be read-only.' }
if (@($scan.Artifacts).Count -lt 1) { throw 'Expected at least one artifact.' }
if (@($scan.Artifacts | Where-Object Category -eq 'PCI_DEVICE').Count -lt 1) { throw 'Expected PCI artifacts.' }
if (@($scan.Artifacts | Where-Object Category -eq 'SECURITY_POSTURE').Count -ne 1) { throw 'Expected one security posture artifact.' }
if (@($scan.Timeline).Count -lt 0) { throw 'Timeline count must be non-negative.' }
if ($scan.Limitations.Count -lt 1) { throw 'Expected explicit limitations.' }

Write-Output ('PASS: artifacts={0}; timeline={1}; findings={2}; readOnly={3}' -f @($scan.Artifacts).Count, @($scan.Timeline).Count, @($scan.Findings).Count, $scan.ReadOnly)
