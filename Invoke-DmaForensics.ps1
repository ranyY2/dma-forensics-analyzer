[CmdletBinding()]
param(
    [ValidateSet('QUICK','DEEP','FULL')]
    [string]$Mode = 'QUICK',
    [string]$OutputDirectory = (Join-Path (Get-Location) 'output'),
    [switch]$NoHtml
)

$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot 'src\DmaForensics.Core.psm1'
Import-Module $modulePath -Force
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$scan = Get-ForensicScan -Mode $Mode
$baseName = 'dma-forensics-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss')
$jsonPath = Join-Path $OutputDirectory "$baseName.json"
$csvPath = Join-Path $OutputDirectory "$baseName-timeline.csv"
$evidencePath = Join-Path $OutputDirectory "$baseName-evidence.json"
$scan | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
$scan.Timeline | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
[pscustomobject]@{ ScanId = $scan.ScanId; ComputerName = $scan.ComputerName; ToolVersion = $scan.ToolVersion; Artifacts = @($scan.Artifacts).Count; TimelineEvents = @($scan.Timeline).Count; Findings = @($scan.Findings).Count; ReadOnly = $scan.ReadOnly } | ConvertTo-Json | Set-Content -LiteralPath $evidencePath -Encoding UTF8

if (-not $NoHtml) {
    $htmlPath = Join-Path $OutputDirectory "$baseName.html"
    $rows = foreach ($finding in @($scan.Findings)) {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f [System.Net.WebUtility]::HtmlEncode($finding.Severity), [System.Net.WebUtility]::HtmlEncode($finding.Category), [System.Net.WebUtility]::HtmlEncode($finding.Artifact), [System.Net.WebUtility]::HtmlEncode($finding.WhyFlagged), [System.Net.WebUtility]::HtmlEncode($finding.PossibleLegitimateExplanation)
    }
    $summary = $scan.Summary | ConvertTo-Html -Fragment
    $html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>DMA Forensics Report</title>
<style>body{font-family:Segoe UI, sans-serif;background:#111827;color:#e5e7eb;margin:2rem}main{max-width:1200px;margin:auto}h1{color:#93c5fd}table{width:100%;border-collapse:collapse;background:#1f2937}th,td{padding:.65rem;border:1px solid #374151;text-align:left;vertical-align:top}th{color:#bfdbfe}code{color:#d1fae5}.note{padding:1rem;border-left:4px solid #fbbf24;background:#292524}</style>
</head><body><main><h1>DMA Forensics Report</h1><p>Computer: <code>$($scan.ComputerName)</code> | Mode: <code>$($scan.ScanMode)</code> | Scan ID: <code>$($scan.ScanId)</code></p><div class="note">Read-only defensive analysis. No single artifact proves DMA cheating. Findings require manual review and correlation.</div><h2>Summary</h2>$summary<h2>Findings</h2><table><tr><th>Severity</th><th>Category</th><th>Artifact</th><th>Why flagged</th><th>Possible legitimate explanation</th></tr>$($rows -join '')</table><h2>Limitations</h2><ul>$(($scan.Limitations | ForEach-Object { "<li>$([System.Net.WebUtility]::HtmlEncode($_))</li>" }) -join '')</ul></main></body></html>
"@
    Set-Content -LiteralPath $htmlPath -Value $html -Encoding UTF8
}

Write-Host "Scan abgeschlossen (read-only): $($scan.ScanId)"
Write-Host "Artefakte: $(@($scan.Artifacts).Count) | Timeline: $(@($scan.Timeline).Count) | Findings: $(@($scan.Findings).Count)"
Write-Host "JSON: $jsonPath"
Write-Host "CSV:  $csvPath"
if (-not $NoHtml) { Write-Host "HTML: $(Join-Path $OutputDirectory "$baseName.html")" }
