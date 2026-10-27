[CmdletBinding()]
param(
    [ValidateSet('QUICK','DEEP','FULL')]
    [string]$Mode = 'QUICK',
    [string]$OutputDirectory = (Join-Path (Get-Location) 'output')
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$script:ScanJob = $null
$script:ScanAngle = 0
$script:ScanRunning = $false
$script:StartedAt = $null
$script:ReportPath = $null

function ConvertTo-Color([string]$Hex) {
    [System.Drawing.ColorTranslator]::FromHtml($Hex)
}

function New-UiLabel([string]$Text, [int]$Size, [string]$Color, [bool]$Bold = $false) {
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.ForeColor = ConvertTo-Color $Color
    $label.Font = New-Object System.Drawing.Font('Segoe UI', $Size, $(if ($Bold) { [System.Drawing.FontStyle]::Bold } else { [System.Drawing.FontStyle]::Regular }))
    $label.AutoSize = $true
    return $label
}

function Set-ScanStatus([string]$Title, [string]$Detail) {
    $statusTitle.Text = $Title
    $statusDetail.Text = $Detail
}

function Add-ScanLog([string]$Level, [string]$Message) {
    if (-not $liveLog) { return }
    $liveLog.AppendText("[$(Get-Date -Format 'HH:mm:ss')] [$Level]  $Message`r`n")
    $liveLog.SelectionStart = $liveLog.TextLength
    $liveLog.ScrollToCaret()
}

function Start-ForensicScan {
    if ($script:ScanJob -and $script:ScanJob.State -eq 'Running') { return }

    $scanMode = [string]$modeSelect.SelectedItem
    $script:ScanRunning = $true
    $script:StartedAt = Get-Date
    $script:ReportPath = $null
    $startButton.Enabled = $false
    $openReportButton.Enabled = $false
    $deviceGrid.Rows.Clear()
    $liveLog.Clear()
    $artifactValue.Text = '--'
    $timelineValue.Text = '--'
    $findingValue.Text = '--'
    $elapsedValue.Text = '00:00'
    $healthValue.Text = 'Scan läuft'
    $deviceCountValue.Text = '--'
    $totalArtifactsValue.Text = '--'
    $lastScanValue.Text = 'Läuft gerade'
    $progressBar.Style = 'Marquee'
    $progressBar.MarqueeAnimationSpeed = 25
    $startButton.Text = 'SCAN LÄUFT'
    $stopButton.Enabled = $true
    Set-ScanStatus 'Scan läuft' 'Read-only Analyse der lokalen Geräte- und Treibermetadaten'
    $activityLabel.Text = 'Inventar wird gesammelt'
    Add-ScanLog 'INFO' "Read-only Scan gestartet (Modus: $scanMode)"

    $modulePath = Join-Path $PSScriptRoot 'DmaForensics.Core.Source.psm1'
    $scanScript = {
        param($CorePath, $RequestedMode, $Destination)
        $ErrorActionPreference = 'Stop'
        Import-Module $CorePath -Force
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        $scan = Get-ForensicScan -Mode $RequestedMode
        $baseName = 'dma-forensics-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss')
        $jsonPath = Join-Path $Destination "$baseName.json"
        $csvPath = Join-Path $Destination "$baseName-timeline.csv"
        $evidencePath = Join-Path $Destination "$baseName-evidence.json"
        $htmlPath = Join-Path $Destination "$baseName.html"
        $scan | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
        @($scan.Timeline) | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
        [pscustomobject]@{
            ScanId = $scan.ScanId
            ComputerName = $scan.ComputerName
            ToolVersion = $scan.ToolVersion
            Artifacts = @($scan.Artifacts).Count
            TimelineEvents = @($scan.Timeline).Count
            Findings = @($scan.Findings).Count
            ReadOnly = $scan.ReadOnly
        } | ConvertTo-Json | Set-Content -LiteralPath $evidencePath -Encoding UTF8

        $rows = foreach ($finding in @($scan.Findings)) {
            '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f [System.Net.WebUtility]::HtmlEncode($finding.Severity), [System.Net.WebUtility]::HtmlEncode($finding.Category), [System.Net.WebUtility]::HtmlEncode($finding.Artifact), [System.Net.WebUtility]::HtmlEncode($finding.WhyFlagged), [System.Net.WebUtility]::HtmlEncode($finding.PossibleLegitimateExplanation)
        }
        $summary = $scan.Summary | ConvertTo-Html -Fragment
        $html = @"
<!doctype html><html lang="de"><head><meta charset="utf-8"><title>DMA Forensics Report</title><style>body{font-family:Segoe UI,sans-serif;background:#10191e;color:#e8eeeb;margin:2rem}main{max-width:1200px;margin:auto}h1{color:#57d8bb}table{width:100%;border-collapse:collapse;background:#172329}th,td{padding:.65rem;border:1px solid #2c3b40;text-align:left;vertical-align:top}th{color:#f1bd73}.note{padding:1rem;border-left:4px solid #f1bd73;background:#252923}</style></head><body><main><h1>DMA Forensics Report</h1><p>Computer: $($scan.ComputerName) | Mode: $($scan.ScanMode) | Scan ID: $($scan.ScanId)</p><div class="note">Read-only defensive analysis. No single artifact proves DMA cheating.</div><h2>Summary</h2>$summary<h2>Findings</h2><table><tr><th>Severity</th><th>Category</th><th>Artifact</th><th>Why flagged</th><th>Possible legitimate explanation</th></tr>$($rows -join '')</table><h2>Limitations</h2><ul>$(($scan.Limitations | ForEach-Object { "<li>$([System.Net.WebUtility]::HtmlEncode($_))</li>" }) -join '')</ul></main></body></html>
"@
        Set-Content -LiteralPath $htmlPath -Value $html -Encoding UTF8
        [pscustomobject]@{ Scan = $scan; HtmlPath = $htmlPath }
    }
    $script:ScanJob = Start-Job -ScriptBlock $scanScript -ArgumentList $modulePath, $scanMode, $OutputDirectory
    $animationTimer.Start()
    $jobTimer.Start()
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'DMA Forensics Analyzer'
$form.StartPosition = 'CenterScreen'
$form.Size = New-Object System.Drawing.Size(1120, 760)
$form.MinimumSize = New-Object System.Drawing.Size(920, 650)
$form.BackColor = ConvertTo-Color '#10191E'
$form.ForeColor = ConvertTo-Color '#E8EEEB'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 10)

$header = New-Object System.Windows.Forms.Panel
$header.Dock = 'Top'
$header.Height = 82
$header.BackColor = ConvertTo-Color '#172329'
$header.Padding = New-Object System.Windows.Forms.Padding(28, 16, 28, 12)
$form.Controls.Add($header)

$brand = New-UiLabel 'DMA' 22 '#57D8BB' $true
$brand.Location = New-Object System.Drawing.Point(28, 21)
$header.Controls.Add($brand)
$brandName = New-UiLabel 'FORENSICS   /   LOCAL SCANNER' 10 '#AAB8B4' $true
$brandName.Location = New-Object System.Drawing.Point(91, 30)
$header.Controls.Add($brandName)
$readonlyBadge = New-UiLabel 'READ-ONLY' 9 '#F1BD73' $true
$readonlyBadge.AutoSize = $false
$readonlyBadge.TextAlign = 'MiddleCenter'
$readonlyBadge.Size = New-Object System.Drawing.Size(100, 28)
$readonlyBadge.Anchor = 'Top,Right'
$readonlyBadge.Location = New-Object System.Drawing.Point(970, 26)
$header.Controls.Add($readonlyBadge)

$content = New-Object System.Windows.Forms.TableLayoutPanel
$content.Dock = 'Fill'
$content.Padding = New-Object System.Windows.Forms.Padding(24)
$content.ColumnCount = 2
$content.RowCount = 1
$content.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 62)))
$content.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 38)))
$content.BackColor = ConvertTo-Color '#10191E'
$form.Controls.Add($content)

$scannerPanel = New-Object System.Windows.Forms.Panel
$scannerPanel.Dock = 'Fill'
$scannerPanel.BackColor = ConvertTo-Color '#172329'
$scannerPanel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 12, 0)
$scannerPanel.Padding = New-Object System.Windows.Forms.Padding(26)
$content.Controls.Add($scannerPanel, 0, 0)

$resultsPanel = New-Object System.Windows.Forms.Panel
$resultsPanel.Dock = 'Fill'
$resultsPanel.BackColor = ConvertTo-Color '#172329'
$resultsPanel.Margin = New-Object System.Windows.Forms.Padding(12, 0, 0, 0)
$resultsPanel.Padding = New-Object System.Windows.Forms.Padding(24)
$content.Controls.Add($resultsPanel, 1, 0)

$eyebrow = New-UiLabel 'DEVICE INTEGRITY / WINDOWS' 9 '#57D8BB' $true
$eyebrow.Location = New-Object System.Drawing.Point(26, 24)
$scannerPanel.Controls.Add($eyebrow)
$headline = New-UiLabel 'System scan' 25 '#E8EEEB' $true
$headline.Location = New-Object System.Drawing.Point(25, 47)
$scannerPanel.Controls.Add($headline)
$description = New-UiLabel 'PCIe, Treiber und Windows-Sicherheitsstatus' 10 '#AAB8B4'
$description.Location = New-Object System.Drawing.Point(27, 87)
$scannerPanel.Controls.Add($description)

$radar = New-Object System.Windows.Forms.Panel
$radar.Height = 310
$radar.Dock = 'Top'
$radar.Top = 112
$radar.BackColor = ConvertTo-Color '#172329'
$radar.Add_Paint({
    param($control, $paintArgs)
    $graphics = $paintArgs.Graphics
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $centerX = [int]($control.ClientSize.Width / 2)
    $centerY = [int]($control.ClientSize.Height / 2)
    $radius = [Math]::Min(116, [Math]::Min($centerX - 18, $centerY - 18))
    $ringPen = New-Object System.Drawing.Pen((ConvertTo-Color '#34464A'), 1)
    foreach ($scale in @(1.0, 0.72, 0.44)) {
        $diameter = [int](2 * $radius * $scale)
        $graphics.DrawEllipse($ringPen, $centerX - $diameter / 2, $centerY - $diameter / 2, $diameter, $diameter)
    }
    for ($tick = 0; $tick -lt 360; $tick += 15) {
        $angle = $tick * [Math]::PI / 180
        $inner = $radius - 5
        $outer = $radius + 1
        $graphics.DrawLine($ringPen, [single]($centerX + [Math]::Cos($angle) * $inner), [single]($centerY + [Math]::Sin($angle) * $inner), [single]($centerX + [Math]::Cos($angle) * $outer), [single]($centerY + [Math]::Sin($angle) * $outer))
    }
    if ($script:ScanRunning) {
        $sweepPen = New-Object System.Drawing.Pen((ConvertTo-Color '#57D8BB'), 2)
        $sweepPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
        $sweepRadians = $script:ScanAngle * [Math]::PI / 180
        $graphics.DrawLine($sweepPen, $centerX, $centerY, [single]($centerX + [Math]::Cos($sweepRadians) * $radius), [single]($centerY + [Math]::Sin($sweepRadians) * $radius))
        $sweepPen.Dispose()
    }
    $coreBrush = New-Object System.Drawing.SolidBrush((ConvertTo-Color '#57D8BB'))
    $graphics.FillEllipse($coreBrush, $centerX - 5, $centerY - 5, 10, 10)
    $ringPen.Dispose()
    $coreBrush.Dispose()
})
$scannerPanel.Controls.Add($radar)

$statusTitle = New-UiLabel 'Bereit für den Scan' 14 '#E8EEEB' $true
$statusTitle.Location = New-Object System.Drawing.Point(27, 425)
$scannerPanel.Controls.Add($statusTitle)
$statusDetail = New-UiLabel 'Lokale Analyse · keine Datenübertragung' 9 '#AAB8B4'
$statusDetail.Location = New-Object System.Drawing.Point(27, 452)
$scannerPanel.Controls.Add($statusDetail)
$activityLabel = New-UiLabel 'Warte auf Start' 9 '#F1BD73'
$activityLabel.Location = New-Object System.Drawing.Point(27, 478)
$scannerPanel.Controls.Add($activityLabel)

$modeSelect = New-Object System.Windows.Forms.ComboBox
$modeSelect.DropDownStyle = 'DropDownList'
$modeSelect.Items.AddRange([object[]]@('QUICK', 'DEEP', 'FULL'))
$modeSelect.SelectedItem = $Mode
$modeSelect.BackColor = ConvertTo-Color '#10191E'
$modeSelect.ForeColor = ConvertTo-Color '#E8EEEB'
$modeSelect.FlatStyle = 'Flat'
$modeSelect.Size = New-Object System.Drawing.Size(130, 36)
$modeSelect.Location = New-Object System.Drawing.Point(27, 526)
$scannerPanel.Controls.Add($modeSelect)

$startButton = New-Object System.Windows.Forms.Button
$startButton.Text = 'SCAN STARTEN'
$startButton.FlatStyle = 'Flat'
$startButton.FlatAppearance.BorderSize = 0
$startButton.BackColor = ConvertTo-Color '#57D8BB'
$startButton.ForeColor = ConvertTo-Color '#10191E'
$startButton.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$startButton.Size = New-Object System.Drawing.Size(190, 40)
$startButton.Anchor = 'Bottom,Right'
$startButton.Location = New-Object System.Drawing.Point(398, 518)
$scannerPanel.Controls.Add($startButton)
$startButton.Add_Click({ Start-ForensicScan })

$resultsTitle = New-UiLabel 'Scan overview' 17 '#E8EEEB' $true
$resultsTitle.Location = New-Object System.Drawing.Point(24, 25)
$resultsPanel.Controls.Add($resultsTitle)
$computerCaption = New-UiLabel 'DIESER COMPUTER' 8 '#AAB8B4' $true
$computerCaption.Location = New-Object System.Drawing.Point(25, 63)
$resultsPanel.Controls.Add($computerCaption)
$computerValue = New-UiLabel $env:COMPUTERNAME 11 '#F1BD73' $true
$computerValue.Location = New-Object System.Drawing.Point(25, 83)
$resultsPanel.Controls.Add($computerValue)

$metricLabels = @(
    @{ Caption = 'ARTIFACTS'; Value = '--'; Y = 135 },
    @{ Caption = 'TIMELINE EVENTS'; Value = '--'; Y = 213 },
    @{ Caption = 'FINDINGS'; Value = '--'; Y = 291 },
    @{ Caption = 'ELAPSED'; Value = '00:00'; Y = 369 }
)
foreach ($metric in $metricLabels) {
    $caption = New-UiLabel $metric.Caption 8 '#AAB8B4' $true
    $caption.Location = New-Object System.Drawing.Point(25, $metric.Y)
    $resultsPanel.Controls.Add($caption)
    $value = New-UiLabel $metric.Value 22 '#E8EEEB' $true
    $value.Location = New-Object System.Drawing.Point(25, ($metric.Y + 21))
    $resultsPanel.Controls.Add($value)
    switch ($metric.Caption) {
        'ARTIFACTS' { $artifactValue = $value }
        'TIMELINE EVENTS' { $timelineValue = $value }
        'FINDINGS' { $findingValue = $value }
        'ELAPSED' { $elapsedValue = $value }
    }
}

$findingHeading = New-UiLabel 'REVIEW QUEUE' 8 '#AAB8B4' $true
$findingHeading.Location = New-Object System.Drawing.Point(25, 450)
$resultsPanel.Controls.Add($findingHeading)
$findingList = New-Object System.Windows.Forms.ListBox
$findingList.BorderStyle = 'None'
$findingList.BackColor = ConvertTo-Color '#172329'
$findingList.ForeColor = ConvertTo-Color '#F1BD73'
$findingList.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$findingList.Location = New-Object System.Drawing.Point(24, 472)
$findingList.Size = New-Object System.Drawing.Size(340, 76)
$findingList.Anchor = 'Bottom,Left,Right'
$findingList.Items.Add('Noch keine Findings geladen') | Out-Null
$resultsPanel.Controls.Add($findingList)

$openReportButton = New-Object System.Windows.Forms.Button
$openReportButton.Text = 'REPORT ÖFFNEN'
$openReportButton.FlatStyle = 'Flat'
$openReportButton.FlatAppearance.BorderColor = ConvertTo-Color '#46575A'
$openReportButton.BackColor = ConvertTo-Color '#172329'
$openReportButton.ForeColor = ConvertTo-Color '#E8EEEB'
$openReportButton.Size = New-Object System.Drawing.Size(150, 34)
$openReportButton.Anchor = 'Bottom,Right'
$openReportButton.Location = New-Object System.Drawing.Point(214, 558)
$openReportButton.Enabled = $false
$resultsPanel.Controls.Add($openReportButton)
$openReportButton.Add_Click({ if ($script:ReportPath -and (Test-Path -LiteralPath $script:ReportPath)) { Start-Process $script:ReportPath } })

$footer = New-Object System.Windows.Forms.Label
$footer.Text = 'Read-only defensive analysis  ·  Keine Einzelbeobachtung ist ein Beweis'
$footer.Dock = 'Bottom'
$footer.Height = 30
$footer.TextAlign = 'MiddleCenter'
$footer.ForeColor = ConvertTo-Color '#73827F'
$footer.Font = New-Object System.Drawing.Font('Segoe UI', 8)
$footer.BackColor = ConvertTo-Color '#10191E'
$form.Controls.Add($footer)

$animationTimer = New-Object System.Windows.Forms.Timer
$animationTimer.Interval = 45
$animationTimer.Add_Tick({
    if ($script:ScanRunning) {
        $script:ScanAngle = ($script:ScanAngle + 4) % 360
        $progressBar.Refresh()
        if ($script:StartedAt) { $elapsedValue.Text = (Get-Date).Subtract($script:StartedAt).ToString('mm\:ss') }
    }
})

$jobTimer = New-Object System.Windows.Forms.Timer
$jobTimer.Interval = 500
$jobTimer.Add_Tick({
    if (-not $script:ScanJob) { return }
    if ($script:ScanJob.State -eq 'Running') { return }
    $jobTimer.Stop()
    $animationTimer.Stop()
    $script:ScanRunning = $false
    $progressBar.MarqueeAnimationSpeed = 0
    $progressBar.Style = 'Continuous'
    $progressBar.Value = 100
    $startButton.Enabled = $true
    $startButton.Text = 'SCAN ERNEUT STARTEN'
    $stopButton.Enabled = $false
    try {
        if ($script:ScanJob.State -ne 'Completed') {
            $reason = $script:ScanJob.ChildJobs[0].JobStateInfo.Reason
            if (-not $reason) { $reason = 'Der Scan wurde unerwartet beendet.' }
            throw $reason
        }
        $result = Receive-Job -Job $script:ScanJob -ErrorAction Stop | Select-Object -Last 1
        if (-not $result -or -not $result.Scan) { throw 'Der Scan hat keine Ergebnisse zurückgegeben.' }
        $scan = $result.Scan
        $script:ReportPath = $result.HtmlPath
        $artifactValue.Text = [string]@($scan.Artifacts).Count
        $timelineValue.Text = [string]@($scan.Timeline).Count
        $findingValue.Text = [string]@($scan.Findings).Count
        $totalArtifactsValue.Text = [string]@($scan.Artifacts).Count
        $deviceArtifacts = @($scan.Artifacts | Where-Object Category -eq 'PCI_DEVICE')
        $deviceCountValue.Text = [string]$deviceArtifacts.Count
        $lastScanValue.Text = 'Gerade eben'
        $healthValue.Text = if ($scan.Findings.Count) { 'Review erforderlich' } else { 'Scan abgeschlossen' }
        $activityLabel.Text = "Scan-ID  $($scan.ScanId)"
        Set-ScanStatus 'Scan abgeschlossen' 'Ergebnisse lokal gespeichert · keine Datenübertragung'
        $deviceGrid.Rows.Clear()
        $rowNumber = 0
        foreach ($deviceArtifact in $deviceArtifacts) {
            $rowNumber++
            $deviceData = $deviceArtifact.Data
            $deviceName = if ($deviceData.FriendlyName) { [string]$deviceData.FriendlyName } else { [string]$deviceArtifact.Artifact }
            $vendorDevice = 'VEN {0} / DEV {1}' -f $deviceData.VendorId, $deviceData.DeviceId
            $deviceGrid.Rows.Add($rowNumber, $deviceName, $vendorDevice, [string]$deviceData.Status) | Out-Null
        }
        Add-ScanLog 'INFO' ("Erfasst: {0} Artefakte, {1} PCI/PnP-Geräte, {2} Timeline-Ereignisse" -f @($scan.Artifacts).Count, $deviceArtifacts.Count, @($scan.Timeline).Count)
        foreach ($timelineItem in @($scan.Timeline | Select-Object -First 8)) {
            Add-ScanLog 'SCAN' ("{0} · {1}" -f $timelineItem.Category, $timelineItem.Event)
        }
        foreach ($finding in @($scan.Findings | Select-Object -First 4)) {
            Add-ScanLog $finding.Severity ("{0} · {1}" -f $finding.Category, $finding.Artifact)
        }
        $openReportButton.Enabled = Test-Path -LiteralPath $script:ReportPath
    } catch {
        Set-ScanStatus 'Scan fehlgeschlagen' 'Details stehen in der Fehlermeldung.'
        Add-ScanLog 'ERROR' $_.Exception.Message
        $activityLabel.Text = 'Bitte Scan erneut starten'
    } finally {
        if ($script:ScanJob) { Remove-Job -Job $script:ScanJob -Force -ErrorAction SilentlyContinue }
        $script:ScanJob = $null
    }
})

$form.Add_FormClosed({
    $animationTimer.Stop()
    $jobTimer.Stop()
    if ($script:ScanJob -and $script:ScanJob.State -eq 'Running') { Stop-Job -Job $script:ScanJob -ErrorAction SilentlyContinue }
    if ($script:ScanJob) { Remove-Job -Job $script:ScanJob -Force -ErrorAction SilentlyContinue }
})

function New-MetricCard([string]$Caption, [string]$Value, [string]$Detail) {
    $panel = New-Object System.Windows.Forms.Panel
    $panel.Dock = 'Fill'
    $panel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 0)
    $panel.BackColor = ConvertTo-Color '#11121B'
    $panel.BorderStyle = 'FixedSingle'
    $captionLabel = New-UiLabel $Caption 8 '#A9A3BF' $true
    $captionLabel.Location = New-Object System.Drawing.Point(12, 9)
    $panel.Controls.Add($captionLabel)
    $valueLabel = New-UiLabel $Value 16 '#E9E4F5' $true
    $valueLabel.Location = New-Object System.Drawing.Point(12, 27)
    $panel.Controls.Add($valueLabel)
    $detailLabel = New-UiLabel $Detail 8 '#817B98'
    $detailLabel.Location = New-Object System.Drawing.Point(12, 56)
    $panel.Controls.Add($detailLabel)
    [pscustomobject]@{ Panel = $panel; Value = $valueLabel; Detail = $detailLabel }
}

while ($form.Controls.Count -gt 0) { $form.Controls[0].Dispose() }
$form.Text = 'DMA Scanner | Read-only Forensics'
$form.StartPosition = 'CenterScreen'
$form.Size = New-Object System.Drawing.Size(1360, 800)
$form.MinimumSize = New-Object System.Drawing.Size(1120, 700)
$form.BackColor = ConvertTo-Color '#090A11'
$form.ForeColor = ConvertTo-Color '#E9E4F5'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$form.AutoScaleMode = 'Dpi'

$root = New-Object System.Windows.Forms.TableLayoutPanel
$root.Dock = 'Fill'
$root.Margin = New-Object System.Windows.Forms.Padding(0)
$root.Padding = New-Object System.Windows.Forms.Padding(0)
$root.ColumnCount = 2
$root.RowCount = 2
$root.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 194)))
$root.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 68)))
$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$root.BackColor = ConvertTo-Color '#090A11'
$form.Controls.Add($root)

$topbar = New-Object System.Windows.Forms.Panel
$topbar.Dock = 'Fill'
$topbar.BackColor = ConvertTo-Color '#0D0D17'
$topbar.Padding = New-Object System.Windows.Forms.Padding(22, 8, 22, 8)
$topbar.BorderStyle = 'FixedSingle'
$root.Controls.Add($topbar, 0, 0)
$root.SetColumnSpan($topbar, 2)
$brand = New-UiLabel 'DMA Scanner' 20 '#B96CFF' $true
$brand.Location = New-Object System.Drawing.Point(20, 8)
$topbar.Controls.Add($brand)
$brandSubtitle = New-UiLabel 'PCIe  ·  TREIBER  ·  READ-ONLY' 8 '#827B9C' $true
$brandSubtitle.Location = New-Object System.Drawing.Point(22, 39)
$topbar.Controls.Add($brandSubtitle)
$versionLabel = New-UiLabel 'LOCAL SCANNER  /  v0.2.0' 8 '#A9A3BF' $true
$versionLabel.Anchor = 'Top,Right'
$versionLabel.Location = New-Object System.Drawing.Point(1145, 24)
$topbar.Controls.Add($versionLabel)

$sidebar = New-Object System.Windows.Forms.Panel
$sidebar.Dock = 'Fill'
$sidebar.BackColor = ConvertTo-Color '#0C0D15'
$sidebar.Padding = New-Object System.Windows.Forms.Padding(12, 18, 12, 12)
$sidebar.BorderStyle = 'FixedSingle'
$root.Controls.Add($sidebar, 0, 1)
$navBrand = New-UiLabel 'WORKSPACE' 8 '#746D8D' $true
$navBrand.Location = New-Object System.Drawing.Point(13, 12)
$sidebar.Controls.Add($navBrand)
$navFlow = New-Object System.Windows.Forms.FlowLayoutPanel
$navFlow.Dock = 'Top'
$navFlow.Location = New-Object System.Drawing.Point(10, 40)
$navFlow.Height = 210
$navFlow.FlowDirection = 'TopDown'
$navFlow.WrapContents = $false
$navFlow.BackColor = ConvertTo-Color '#0C0D15'
$sidebar.Controls.Add($navFlow)
$navButtons = New-Object System.Collections.Generic.List[System.Windows.Forms.Button]
foreach ($nav in @(@{ Text = '◈  Übersicht'; Tag = 'Overview' }, @{ Text = '⌕  Scan'; Tag = 'Scan' }, @{ Text = '▦  Geräte'; Tag = 'Devices' }, @{ Text = '≡  Live-Log'; Tag = 'Logs' })) {
    $navButton = New-Object System.Windows.Forms.Button
    $navButton.Text = $nav.Text
    $navButton.Tag = $nav.Tag
    $navButton.Size = New-Object System.Drawing.Size(166, 42)
    $navButton.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 5)
    $navButton.FlatStyle = 'Flat'
    $navButton.FlatAppearance.BorderSize = 0
    $navButton.TextAlign = 'MiddleLeft'
    $navButton.Padding = New-Object System.Windows.Forms.Padding(12, 0, 0, 0)
    $navButton.ForeColor = ConvertTo-Color '#ADA6C4'
    $navButton.BackColor = ConvertTo-Color '#0C0D15'
    $navButton.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    if ($nav.Tag -eq 'Scan') {
        $navButton.BackColor = ConvertTo-Color '#241532'
        $navButton.ForeColor = ConvertTo-Color '#D69BFF'
    }
    $navButton.Add_Click({
        param($clickedButton, $clickArgs)
        foreach ($item in $navButtons) {
            $item.BackColor = ConvertTo-Color '#0C0D15'
            $item.ForeColor = ConvertTo-Color '#ADA6C4'
        }
        $clickedButton.BackColor = ConvertTo-Color '#241532'
        $clickedButton.ForeColor = ConvertTo-Color '#D69BFF'
        switch ([string]$clickedButton.Tag) {
            'Overview' { $healthValue.Focus() }
            'Scan' { $modeSelect.Focus() }
            'Devices' { $deviceGrid.Focus() }
            'Logs' { $liveLog.Focus() }
        }
    })
    $navButtons.Add($navButton)
    $navFlow.Controls.Add($navButton)
}
$sidebarNote = New-UiLabel "LOKALE ANALYSE`r`nKeine Datenübertragung" 8 '#746D8D'
$sidebarNote.Location = New-Object System.Drawing.Point(13, 585)
$sidebar.Controls.Add($sidebarNote)

$main = New-Object System.Windows.Forms.TableLayoutPanel
$main.Dock = 'Fill'
$main.Padding = New-Object System.Windows.Forms.Padding(12)
$main.ColumnCount = 1
$main.RowCount = 3
$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 88)))
$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 53)))
$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 47)))
$main.BackColor = ConvertTo-Color '#090A11'
$root.Controls.Add($main, 1, 1)

$metrics = New-Object System.Windows.Forms.TableLayoutPanel
$metrics.Dock = 'Fill'
$metrics.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 10)
$metrics.ColumnCount = 4
$metrics.RowCount = 1
for ($column = 0; $column -lt 4; $column++) {
    $metrics.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 25)))
}
$healthCard = New-MetricCard 'SCAN-GESUNDHEIT' 'Bereit' 'Read-only · lokal'
$deviceCard = New-MetricCard 'VERBUNDENE GERÄTE' '0' 'PCI/PnP Inventar'
$lastScanCard = New-MetricCard 'LETZTER SCAN' 'Noch keiner' 'Warte auf Start'
$artifactCard = New-MetricCard 'ERFASSTE ARTEFAKTE' '0' 'JSON · CSV · HTML'
$healthValue = $healthCard.Value
$deviceCountValue = $deviceCard.Value
$lastScanValue = $lastScanCard.Value
$totalArtifactsValue = $artifactCard.Value
$metrics.Controls.Add($healthCard.Panel, 0, 0)
$metrics.Controls.Add($deviceCard.Panel, 1, 0)
$metrics.Controls.Add($lastScanCard.Panel, 2, 0)
$metrics.Controls.Add($artifactCard.Panel, 3, 0)
$main.Controls.Add($metrics, 0, 0)

$workspace = New-Object System.Windows.Forms.TableLayoutPanel
$workspace.Dock = 'Fill'
$workspace.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 10)
$workspace.ColumnCount = 2
$workspace.RowCount = 1
$workspace.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 56)))
$workspace.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 44)))
$configurationPanel = New-Object System.Windows.Forms.Panel
$configurationPanel.Dock = 'Fill'
$configurationPanel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
$configurationPanel.Padding = New-Object System.Windows.Forms.Padding(14)
$configurationPanel.BackColor = ConvertTo-Color '#11121B'
$configurationPanel.BorderStyle = 'FixedSingle'
$workspace.Controls.Add($configurationPanel, 0, 0)
$controlPanel = New-Object System.Windows.Forms.Panel
$controlPanel.Dock = 'Fill'
$controlPanel.Margin = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
$controlPanel.Padding = New-Object System.Windows.Forms.Padding(14)
$controlPanel.BackColor = ConvertTo-Color '#11121B'
$controlPanel.BorderStyle = 'FixedSingle'
$workspace.Controls.Add($controlPanel, 1, 0)
$main.Controls.Add($workspace, 0, 1)

$configLayout = New-Object System.Windows.Forms.TableLayoutPanel
$configLayout.Dock = 'Fill'
$configLayout.ColumnCount = 1
$configLayout.RowCount = 5
$configLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 27)))
$configLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 24)))
$configLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 54)))
$configLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 25)))
$configLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$configurationPanel.Controls.Add($configLayout)
$configTitle = New-UiLabel 'SCAN-KONFIGURATION' 12 '#C479FF' $true
$configLayout.Controls.Add($configTitle, 0, 0)
$configSubtitle = New-UiLabel 'Read-only Inventar und Geräte-Metadaten' 8 '#89829F'
$configLayout.Controls.Add($configSubtitle, 0, 1)
$modeRow = New-Object System.Windows.Forms.Panel
$modeRow.Dock = 'Fill'
$modeCaption = New-UiLabel 'Scan-Modus' 9 '#B7AFCB' $true
$modeCaption.Location = New-Object System.Drawing.Point(0, 5)
$modeRow.Controls.Add($modeCaption)
$modeSelect = New-Object System.Windows.Forms.ComboBox
$modeSelect.DropDownStyle = 'DropDownList'
$modeSelect.Items.AddRange([object[]]@('QUICK', 'DEEP', 'FULL'))
$modeSelect.SelectedItem = $Mode
$modeSelect.BackColor = ConvertTo-Color '#0A0B12'
$modeSelect.ForeColor = ConvertTo-Color '#E9E4F5'
$modeSelect.FlatStyle = 'Flat'
$modeSelect.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$modeSelect.Location = New-Object System.Drawing.Point(100, 1)
$modeSelect.Size = New-Object System.Drawing.Size(190, 30)
$modeSelect.Anchor = 'Top,Left,Right'
$modeRow.Controls.Add($modeSelect)
$configLayout.Controls.Add($modeRow, 0, 2)
$sourceTitle = New-UiLabel 'ERFASSTE QUELLEN' 8 '#89829F' $true
$configLayout.Controls.Add($sourceTitle, 0, 3)
$sourceFlow = New-Object System.Windows.Forms.FlowLayoutPanel
$sourceFlow.Dock = 'Fill'
$sourceFlow.FlowDirection = 'TopDown'
$sourceFlow.WrapContents = $false
$sourceFlow.BackColor = ConvertTo-Color '#11121B'
foreach ($source in @('PCI/PnP Geräte und Steckplätze', 'Treiber-Dateien und Signaturen', 'SetupAPI Installationsverlauf', 'Windows Sicherheitsstatus')) {
    $sourceLine = New-UiLabel "●   $source" 9 '#C8C1D8'
    $sourceLine.Margin = New-Object System.Windows.Forms.Padding(0, 3, 0, 3)
    $sourceFlow.Controls.Add($sourceLine)
}
$configLayout.Controls.Add($sourceFlow, 0, 4)

$controlLayout = New-Object System.Windows.Forms.TableLayoutPanel
$controlLayout.Dock = 'Fill'
$controlLayout.ColumnCount = 1
$controlLayout.RowCount = 7
$controlLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 27)))
$controlLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 27)))
$controlLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 26)))
$controlLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 21)))
$controlLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 28)))
$controlLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$controlLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 42)))
$controlPanel.Controls.Add($controlLayout)
$controlTitle = New-UiLabel 'SCAN-STEUERUNG' 12 '#C479FF' $true
$controlLayout.Controls.Add($controlTitle, 0, 0)
$statusTitle = New-UiLabel 'Bereit für den Scan' 12 '#E9E4F5' $true
$controlLayout.Controls.Add($statusTitle, 0, 1)
$statusDetail = New-UiLabel 'Lokale Analyse · keine Datenübertragung' 8 '#89829F'
$controlLayout.Controls.Add($statusDetail, 0, 2)
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Dock = 'Fill'
$progressBar.Style = 'Continuous'
$progressBar.Value = 0
$controlLayout.Controls.Add($progressBar, 0, 3)
$stageRow = New-Object System.Windows.Forms.TableLayoutPanel
$stageRow.Dock = 'Fill'
$stageRow.ColumnCount = 2
$stageRow.RowCount = 1
$stageRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 68)))
$stageRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 32)))
$activityLabel = New-UiLabel 'Warte auf Start' 8 '#B9B0CE'
$stageRow.Controls.Add($activityLabel, 0, 0)
$elapsedValue = New-UiLabel '00:00' 8 '#C479FF' $true
$elapsedValue.TextAlign = 'MiddleRight'
$elapsedValue.Dock = 'Fill'
$stageRow.Controls.Add($elapsedValue, 1, 0)
$controlLayout.Controls.Add($stageRow, 0, 4)
$summaryRow = New-Object System.Windows.Forms.TableLayoutPanel
$summaryRow.Dock = 'Fill'
$summaryRow.ColumnCount = 3
$summaryRow.RowCount = 1
foreach ($column in 1..3) { $summaryRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 33.33))) }
$artifactValue = New-UiLabel 'Artefakte  --' 8 '#A9A3BF'
$timelineValue = New-UiLabel 'Timeline  --' 8 '#A9A3BF'
$findingValue = New-UiLabel 'Findings  --' 8 '#A9A3BF'
$summaryRow.Controls.Add($artifactValue, 0, 0)
$summaryRow.Controls.Add($timelineValue, 1, 0)
$summaryRow.Controls.Add($findingValue, 2, 0)
$controlLayout.Controls.Add($summaryRow, 0, 5)
$buttonRow = New-Object System.Windows.Forms.FlowLayoutPanel
$buttonRow.Dock = 'Fill'
$buttonRow.FlowDirection = 'LeftToRight'
$buttonRow.WrapContents = $false
$buttonRow.BackColor = ConvertTo-Color '#11121B'
$startButton = New-Object System.Windows.Forms.Button
$startButton.Text = 'SCAN STARTEN'
$startButton.Size = New-Object System.Drawing.Size(150, 34)
$startButton.Margin = New-Object System.Windows.Forms.Padding(0, 2, 8, 0)
$startButton.FlatStyle = 'Flat'
$startButton.FlatAppearance.BorderSize = 0
$startButton.BackColor = ConvertTo-Color '#B55CFF'
$startButton.ForeColor = ConvertTo-Color '#100A18'
$startButton.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$buttonRow.Controls.Add($startButton)
$startButton.Add_Click({ Start-ForensicScan })
$stopButton = New-Object System.Windows.Forms.Button
$stopButton.Text = 'STOP'
$stopButton.Size = New-Object System.Drawing.Size(68, 34)
$stopButton.Margin = New-Object System.Windows.Forms.Padding(0, 2, 8, 0)
$stopButton.FlatStyle = 'Flat'
$stopButton.FlatAppearance.BorderColor = ConvertTo-Color '#3B3150'
$stopButton.BackColor = ConvertTo-Color '#171521'
$stopButton.ForeColor = ConvertTo-Color '#BDB6CF'
$stopButton.Enabled = $false
$buttonRow.Controls.Add($stopButton)
$stopButton.Add_Click({
    if ($script:ScanJob -and $script:ScanJob.State -eq 'Running') {
        Stop-Job -Job $script:ScanJob -ErrorAction SilentlyContinue
        $jobTimer.Stop()
        $animationTimer.Stop()
        $script:ScanRunning = $false
        $progressBar.Style = 'Continuous'
        $progressBar.MarqueeAnimationSpeed = 0
        $progressBar.Value = 0
        $startButton.Enabled = $true
        $startButton.Text = 'SCAN STARTEN'
        $stopButton.Enabled = $false
        Set-ScanStatus 'Scan abgebrochen' 'Es wurden keine weiteren Daten gesammelt.'
        Add-ScanLog 'WARN' 'Scan durch Benutzer abgebrochen.'
        Remove-Job -Job $script:ScanJob -Force -ErrorAction SilentlyContinue
        $script:ScanJob = $null
    }
})
$openReportButton = New-Object System.Windows.Forms.Button
$openReportButton.Text = 'REPORT'
$openReportButton.Size = New-Object System.Drawing.Size(82, 34)
$openReportButton.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 0)
$openReportButton.FlatStyle = 'Flat'
$openReportButton.FlatAppearance.BorderColor = ConvertTo-Color '#3B3150'
$openReportButton.BackColor = ConvertTo-Color '#171521'
$openReportButton.ForeColor = ConvertTo-Color '#CDBCE8'
$openReportButton.Enabled = $false
$buttonRow.Controls.Add($openReportButton)
$openReportButton.Add_Click({ if ($script:ReportPath -and (Test-Path -LiteralPath $script:ReportPath)) { Start-Process $script:ReportPath } })
$controlLayout.Controls.Add($buttonRow, 0, 6)

$bottom = New-Object System.Windows.Forms.TableLayoutPanel
$bottom.Dock = 'Fill'
$bottom.ColumnCount = 2
$bottom.RowCount = 1
$bottom.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 57)))
$bottom.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 43)))
$bottom.BackColor = ConvertTo-Color '#090A11'
$main.Controls.Add($bottom, 0, 2)

$devicePanel = New-Object System.Windows.Forms.Panel
$devicePanel.Dock = 'Fill'
$devicePanel.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
$devicePanel.Padding = New-Object System.Windows.Forms.Padding(12)
$devicePanel.BackColor = ConvertTo-Color '#11121B'
$devicePanel.BorderStyle = 'FixedSingle'
$bottom.Controls.Add($devicePanel, 0, 0)
$logPanel = New-Object System.Windows.Forms.Panel
$logPanel.Dock = 'Fill'
$logPanel.Margin = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
$logPanel.Padding = New-Object System.Windows.Forms.Padding(12)
$logPanel.BackColor = ConvertTo-Color '#11121B'
$logPanel.BorderStyle = 'FixedSingle'
$bottom.Controls.Add($logPanel, 1, 0)

$deviceLayout = New-Object System.Windows.Forms.TableLayoutPanel
$deviceLayout.Dock = 'Fill'
$deviceLayout.ColumnCount = 1
$deviceLayout.RowCount = 2
$deviceLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 30)))
$deviceLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$devicePanel.Controls.Add($deviceLayout)
$deviceTitle = New-UiLabel 'VERBUNDENE GERÄTE' 10 '#C479FF' $true
$deviceLayout.Controls.Add($deviceTitle, 0, 0)
$deviceGrid = New-Object System.Windows.Forms.DataGridView
$deviceGrid.Dock = 'Fill'
$deviceGrid.ReadOnly = $true
$deviceGrid.AllowUserToAddRows = $false
$deviceGrid.AllowUserToDeleteRows = $false
$deviceGrid.AllowUserToResizeRows = $false
$deviceGrid.RowHeadersVisible = $false
$deviceGrid.AutoSizeColumnsMode = 'Fill'
$deviceGrid.SelectionMode = 'FullRowSelect'
$deviceGrid.MultiSelect = $false
$deviceGrid.BackgroundColor = ConvertTo-Color '#0D0E16'
$deviceGrid.BorderStyle = 'None'
$deviceGrid.GridColor = ConvertTo-Color '#282337'
$deviceGrid.EnableHeadersVisualStyles = $false
$deviceGrid.ColumnHeadersDefaultCellStyle.BackColor = ConvertTo-Color '#171521'
$deviceGrid.ColumnHeadersDefaultCellStyle.ForeColor = ConvertTo-Color '#BCA9D8'
$deviceGrid.DefaultCellStyle.BackColor = ConvertTo-Color '#0D0E16'
$deviceGrid.DefaultCellStyle.ForeColor = ConvertTo-Color '#D9D3E5'
$deviceGrid.DefaultCellStyle.SelectionBackColor = ConvertTo-Color '#352044'
$deviceGrid.DefaultCellStyle.SelectionForeColor = ConvertTo-Color '#F2E8FF'
$deviceGrid.RowTemplate.Height = 26
foreach ($column in @(@('number', '#'), @('device', 'Gerätename'), @('vendor', 'Vendor / ID'), @('status', 'Status'))) {
    $deviceGrid.Columns.Add([string]$column[0], [string]$column[1]) | Out-Null
}
$deviceGrid.Rows.Add('--', 'Noch kein Scan', '--', 'Bereit') | Out-Null
$deviceLayout.Controls.Add($deviceGrid, 0, 1)

$logLayout = New-Object System.Windows.Forms.TableLayoutPanel
$logLayout.Dock = 'Fill'
$logLayout.ColumnCount = 1
$logLayout.RowCount = 2
$logLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 30)))
$logLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$logPanel.Controls.Add($logLayout)
$logTitle = New-UiLabel 'LIVE-LOG' 10 '#C479FF' $true
$logLayout.Controls.Add($logTitle, 0, 0)
$liveLog = New-Object System.Windows.Forms.RichTextBox
$liveLog.Dock = 'Fill'
$liveLog.ReadOnly = $true
$liveLog.BorderStyle = 'None'
$liveLog.BackColor = ConvertTo-Color '#0D0E16'
$liveLog.ForeColor = ConvertTo-Color '#B9AED0'
$liveLog.Font = New-Object System.Drawing.Font('Consolas', 8)
$liveLog.DetectUrls = $false
$logLayout.Controls.Add($liveLog, 0, 1)
Add-ScanLog 'INFO' 'DMA Scanner bereit. Read-only Modus aktiv.'

[void]$form.Add_Shown({ Start-ForensicScan })
[void]$form.ShowDialog()