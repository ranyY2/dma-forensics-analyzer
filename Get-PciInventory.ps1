[CmdletBinding()]
param(
    [switch]$Json
)

$slots = @(Get-CimInstance -ClassName Win32_SystemSlot -ErrorAction SilentlyContinue |
    Select-Object SlotDesignation, CurrentUsage, Status, Description)
$devices = @(Get-CimInstance -ClassName Win32_PnPEntity -Filter "PNPDeviceID LIKE 'PCI%'" -ErrorAction SilentlyContinue |
    Select-Object Name, Manufacturer, Status, PNPDeviceID, ConfigManagerErrorCode)

$result = [ordered]@{
    SlotCountReportedByFirmware = $slots.Count
    Slots = $slots
    PciDeviceCount = $devices.Count
    Devices = $devices
    Warning = 'Win32_SystemSlot kann die tatsaechliche Anzahl physischer PCIe-Slots unvollstaendig melden.'
}

if ($Json) {
    $result | ConvertTo-Json -Depth 5
    exit 0
}

Write-Host "Gemeldete System-Steckplaetze: $($slots.Count)"
if ($slots.Count -eq 0) {
    Write-Host '  Keine Steckplatzinformationen von der Firmware gemeldet.'
} else {
    foreach ($slot in $slots) {
        $designation = if ($slot.SlotDesignation) { $slot.SlotDesignation } else { '(ohne Bezeichnung)' }
        $usage = if ($null -ne $slot.CurrentUsage) { $slot.CurrentUsage } else { 'unbekannt' }
        $status = if ($slot.Status) { $slot.Status } else { 'unbekannt' }
        Write-Host "  - $designation | Nutzung: $usage | Status: $status"
    }
}

Write-Host "`nGefundene PCI-Geraete: $($devices.Count)"
foreach ($device in $devices) {
    $name = if ($device.Name) { $device.Name } else { '(ohne Namen)' }
    $manufacturer = if ($device.Manufacturer) { $device.Manufacturer } else { 'Hersteller unbekannt' }
    $status = if ($device.Status) { $device.Status } else { 'unbekannt' }
    $error = if ($device.ConfigManagerErrorCode -and $device.ConfigManagerErrorCode -ne 0) {
        " | Fehlercode: $($device.ConfigManagerErrorCode)"
    } else { '' }
    Write-Host "  - $name | $manufacturer | $status$error"
    Write-Host "    $($device.PNPDeviceID)"
}

Write-Host "`nHinweis: Win32_SystemSlot ist eine Firmware-/Treiberinventur."
Write-Host 'Windows kann damit die tatsaechliche Anzahl physischer PCIe-Slots unvollstaendig melden.'
Write-Host 'Fuer eine verlaessliche Gesamtzahl bitte zusaetzlich das Mainboard-Handbuch pruefen.'
