Set-StrictMode -Version Latest

$script:ToolVersion = '0.2.0'

function New-Artifact {
    param(
        [string]$Category,
        [string]$Source,
        [string]$Path,
        [string]$Timestamp,
        [string]$Artifact,
        [hashtable]$Data = @{},
        [string]$Explanation = '',
        [string]$Confidence = 'INFO'
    )

    [pscustomobject]@{
        Category = $Category
        Source = $Source
        Path = $Path
        Timestamp = $Timestamp
        Artifact = $Artifact
        Explanation = $Explanation
        Confidence = $Confidence
        Data = [pscustomobject]$Data
    }
}

function Get-Sha256Safe {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { return $null }
}

function Get-SignatureSafe {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        return [pscustomobject]@{
            Status = [string]$signature.Status
            Signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
            Issuer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Issuer } else { $null }
        }
    } catch { return $null }
}

function Get-OptionalProperty {
    param([object]$Object, [string]$Name)
    if ($Object -and $Object.PSObject.Properties[$Name]) { return $Object.PSObject.Properties[$Name].Value }
    return $null
}

function Get-PciArtifacts {
    $artifacts = [System.Collections.Generic.List[object]]::new()
    $devices = @(Get-CimInstance Win32_PnPEntity -Filter "PNPDeviceID LIKE 'PCI%'" -ErrorAction SilentlyContinue)
    $signed = @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue)
    $signedById = @{}
    foreach ($driver in $signed) {
        if ($driver.DeviceID) { $signedById[[string]$driver.DeviceID] = $driver }
    }

    foreach ($device in $devices) {
        $driver = $signedById[[string]$device.PNPDeviceID]
        $hardwareIds = @($device.HardwareID)
        $compatibleIds = @($device.CompatibleID)
        $vendor = if ($device.PNPDeviceID -match 'VEN_([0-9A-Fa-f]{4})') { $Matches[1].ToUpperInvariant() } else { $null }
        $product = if ($device.PNPDeviceID -match 'DEV_([0-9A-Fa-f]{4})') { $Matches[1].ToUpperInvariant() } else { $null }
        $driverPath = if ($driver -and $driver.PSObject.Properties['DriverPath']) { [string]$driver.DriverPath } else { $null }
        $signature = Get-SignatureSafe $driverPath
        $explanation = 'Aktuelles PCI/PnP-Geraet; dies ist ein Inventarhinweis und kein Cheat-Beweis.'
        $data = @{
            DeviceInstanceId = [string]$device.PNPDeviceID
            HardwareIds = $hardwareIds
            CompatibleIds = $compatibleIds
            VendorId = $vendor
            DeviceId = $product
            Revision = [string](Get-OptionalProperty $device 'Revision')
            ClassGuid = [string](Get-OptionalProperty $device 'ClassGuid')
            FriendlyName = [string](Get-OptionalProperty $device 'Name')
            Manufacturer = [string](Get-OptionalProperty $device 'Manufacturer')
            Status = [string](Get-OptionalProperty $device 'Status')
            ConfigManagerErrorCode = Get-OptionalProperty $device 'ConfigManagerErrorCode'
            DriverProvider = if ($driver -and $driver.PSObject.Properties['DriverProviderName']) { [string]$driver.DriverProviderName } else { $null }
            DriverVersion = if ($driver -and $driver.PSObject.Properties['DriverVersion']) { [string]$driver.DriverVersion } else { $null }
            DriverDate = if ($driver -and $driver.PSObject.Properties['DriverDate']) { [string]$driver.DriverDate } else { $null }
            DriverPath = $driverPath
            SignatureStatus = if ($signature) { $signature.Status } else { $null }
            SignatureSigner = if ($signature) { $signature.Signer } else { $null }
        }
        $artifacts.Add((New-Artifact 'PCI_DEVICE' 'Win32_PnPEntity/Win32_PnPSignedDriver' $driverPath $null ([string](Get-OptionalProperty $device 'Name')) $data $explanation 'INFO'))
    }

    $slots = @(Get-CimInstance Win32_SystemSlot -ErrorAction SilentlyContinue)
    foreach ($slot in $slots) {
        $artifacts.Add((New-Artifact 'PCI_SLOT' 'Win32_SystemSlot' $null $null ([string]$slot.SlotDesignation) @{
            SlotDesignation = [string]$slot.SlotDesignation
            CurrentUsage = $slot.CurrentUsage
            Status = [string]$slot.Status
            Description = [string]$slot.Description
        } 'Von der Firmware gemeldeter System-Steckplatz; nicht zwingend die vollstaendige physische PCIe-Anzahl.' 'INFO'))
    }
    return $artifacts
}

function Get-SetupApiArtifacts {
    param([ValidateSet('QUICK','DEEP','FULL')][string]$Mode)
    $path = Join-Path $env:windir 'INF\setupapi.dev.log'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return @() }
    $maxLines = if ($Mode -eq 'QUICK') { 3000 } elseif ($Mode -eq 'DEEP') { 25000 } else { 100000 }
    $lines = @(Get-Content -LiteralPath $path -Tail $maxLines -ErrorAction SilentlyContinue)
    $artifacts = [System.Collections.Generic.List[object]]::new()
    $current = $null
    foreach ($line in $lines) {
        if ($line -match '^>>>\s+\[(?<section>[^\]]+)\]') {
            $current = @{ Section = $Matches.section.Trim(); Timestamp = $null; DeviceInstanceId = $null; Lines = [System.Collections.Generic.List[string]]::new() }
        }
        if ($current) {
            $current.Lines.Add($line)
            if ($line -match 'Section start\s+(?<date>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)') {
                $current.Timestamp = $Matches.date
            }
            if ($line -match "Device '(?<id>[^']+)'") {
                $current.DeviceInstanceId = $Matches.id
            }
            if ($line -match 'Exit status:\s+(?<status>[^]]+)') {
                $data = @{ Section = $current.Section; DeviceInstanceId = $current.DeviceInstanceId; Status = $Matches.status.Trim(); Raw = ($current.Lines | Select-Object -Last 12) }
                $name = if ($current.DeviceInstanceId) { $current.DeviceInstanceId } else { $current.Section }
                $artifacts.Add((New-Artifact 'DEVICE_INSTALLATION' 'setupapi.dev.log' $path $current.Timestamp $name $data 'Windows SetupAPI protokolliert eine Geraeteinstallationsphase; normale Treiberupdates sind eine moegliche Erklaerung.' 'INFO'))
                $current = $null
            }
        }
    }
    return $artifacts
}

function Get-SecurityPostureArtifacts {
    $artifacts = [System.Collections.Generic.List[object]]::new()
    $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $deviceGuard = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    $secureBoot = $null
    try { $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $secureBoot = $null }
    $artifacts.Add((New-Artifact 'SECURITY_POSTURE' 'Win32_DeviceGuard/Confirm-SecureBootUEFI' $null $null 'Windows DMA-/Virtualisierungs-Schutzlage' @{
        ComputerName = $env:COMPUTERNAME
        Manufacturer = [string]$computer.Manufacturer
        Model = [string]$computer.Model
        WindowsCaption = [string]$os.Caption
        WindowsBuild = [string]$os.BuildNumber
        SecureBoot = $secureBoot
        VirtualizationBasedSecurityStatus = if ($deviceGuard) { $deviceGuard.VirtualizationBasedSecurityStatus } else { $null }
        SecurityServicesRunning = if ($deviceGuard) { @($deviceGuard.SecurityServicesRunning) } else { @() }
        SecurityServicesConfigured = if ($deviceGuard) { @($deviceGuard.SecurityServicesConfigured) } else { @() }
    } 'Security Posture beschreibt Schutzkonfigurationen. Sie ist kein Nachweis fuer Cheating.' 'INFO'))
    return $artifacts
}

function Get-DriverArtifacts {
    param([ValidateSet('QUICK','DEEP','FULL')][string]$Mode)
    $roots = @((Join-Path $env:windir 'System32\drivers'))
    if ($Mode -ne 'QUICK') { $roots += (Join-Path $env:windir 'System32\DriverStore\FileRepository') }
    $fileLimit = if ($Mode -eq 'FULL') { 2000 } else { 300 }
    $files = foreach ($root in $roots) {
        if (Test-Path -LiteralPath $root) {
            Get-ChildItem -LiteralPath $root -Filter '*.sys' -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First $fileLimit
        }
    }
    $artifacts = [System.Collections.Generic.List[object]]::new()
    foreach ($file in @($files)) {
        $signature = Get-SignatureSafe $file.FullName
        $version = $file.VersionInfo
        $confidence = if ($signature -and $signature.Status -ne 'Valid') { 'LOW' } else { 'INFO' }
        $explanation = if ($confidence -eq 'LOW') { 'Treiberdatei hat keinen gueltigen Authenticode-Status; legitime Entwicklungs- oder OEM-Szenarien bleiben moeglich.' } else { 'Installierte Treiberdatei mit Metadaten.' }
        $artifacts.Add((New-Artifact 'DRIVER_FILE' 'FileSystem/Authenticode' $file.FullName $file.LastWriteTimeUtc.ToString('o') $file.Name @{
            Size = $file.Length
            Sha256 = Get-Sha256Safe $file.FullName
            SignatureStatus = if ($signature) { $signature.Status } else { $null }
            Signer = if ($signature) { $signature.Signer } else { $null }
            CompanyName = [string]$version.CompanyName
            ProductName = [string]$version.ProductName
            OriginalFilename = [string]$version.OriginalFilename
            FileVersion = [string]$version.FileVersion
            CreationTimeUtc = $file.CreationTimeUtc.ToString('o')
            LastWriteTimeUtc = $file.LastWriteTimeUtc.ToString('o')
        } $explanation $confidence))
    }
    return $artifacts
}

function Get-ForensicScan {
    param([ValidateSet('QUICK','DEEP','FULL')][string]$Mode = 'QUICK')
    $started = [DateTime]::UtcNow
    $artifacts = [System.Collections.Generic.List[object]]::new()
    foreach ($artifact in @(Get-PciArtifacts)) { $artifacts.Add($artifact) }
    foreach ($artifact in @(Get-SecurityPostureArtifacts)) { $artifacts.Add($artifact) }
    foreach ($artifact in @(Get-SetupApiArtifacts $Mode)) { $artifacts.Add($artifact) }
    foreach ($artifact in @(Get-DriverArtifacts $Mode)) { $artifacts.Add($artifact) }

    $timeline = foreach ($artifact in $artifacts | Where-Object { $_.Timestamp }) {
        [pscustomobject]@{ Timestamp = $artifact.Timestamp; Category = $artifact.Category; Source = $artifact.Source; Event = $artifact.Artifact; Device = Get-OptionalProperty $artifact.Data 'DeviceInstanceId'; File = $artifact.Path; Confidence = $artifact.Confidence }
    }
    $findings = foreach ($artifact in $artifacts | Where-Object { $_.Confidence -in @('LOW','MEDIUM','HIGH','CRITICAL') }) {
        [pscustomobject]@{ Severity = $artifact.Confidence; Category = $artifact.Category; Artifact = $artifact.Artifact; WhyFlagged = $artifact.Explanation; WhyItMatters = 'Erfordert Kontext und Korrelation mit unabhaengigen Quellen.'; PossibleLegitimateExplanation = 'OEM-Treiber, Capture Card, Entwicklungsboard, Virtualisierung oder normales Treiberupdate.'; Confidence = $artifact.Confidence; Source = $artifact.Source; Path = $artifact.Path }
    }
    [pscustomobject]@{
        ScanId = [guid]::NewGuid().ToString()
        StartTimeUtc = $started.ToString('o')
        EndTimeUtc = [DateTime]::UtcNow.ToString('o')
        ComputerName = $env:COMPUTERNAME
        ToolVersion = $script:ToolVersion
        ScanMode = $Mode
        ReadOnly = $true
        Artifacts = @($artifacts)
        Timeline = @($timeline)
        Findings = @($findings)
        Summary = [pscustomobject]@{ Critical = @($findings | Where-Object Severity -eq 'CRITICAL').Count; High = @($findings | Where-Object Severity -eq 'HIGH').Count; Medium = @($findings | Where-Object Severity -eq 'MEDIUM').Count; Low = @($findings | Where-Object Severity -eq 'LOW').Count; Info = @($artifacts | Where-Object Confidence -eq 'INFO').Count }
        Limitations = @('Keine einzelne Beobachtung beweist DMA-Cheating.', 'Win32_SystemSlot kann physische PCIe-Slots unvollstaendig melden.', 'Nicht verfuegbare oder geloeschte Logs werden als Collection Gap behandelt.')
    }
}

Export-ModuleMember -Function Get-ForensicScan
