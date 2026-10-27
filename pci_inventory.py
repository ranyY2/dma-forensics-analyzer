#!/usr/bin/env python3
"""Inventarisiert PCI-Geraete und von Windows gemeldete System-Steckplaetze."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from typing import Any


POWERSHELL_SCRIPT = r"""
$slots = @(Get-CimInstance -ClassName Win32_SystemSlot -ErrorAction SilentlyContinue |
    Select-Object SlotDesignation, CurrentUsage, Status, Description)
$devices = @(Get-CimInstance -ClassName Win32_PnPEntity -Filter "PNPDeviceID LIKE 'PCI%'" -ErrorAction SilentlyContinue |
    Select-Object Name, Manufacturer, Status, PNPDeviceID, ConfigManagerErrorCode)
[PSCustomObject]@{ Slots = $slots; Devices = $devices } | ConvertTo-Json -Depth 4 -Compress
"""


def run_powershell() -> dict[str, Any]:
    executable = shutil.which("powershell") or shutil.which("pwsh")
    if executable is None:
        raise RuntimeError("PowerShell wurde nicht gefunden.")

    result = subprocess.run(
        [executable, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", POWERSHELL_SCRIPT],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or "Unbekannter PowerShell-Fehler"
        raise RuntimeError(message)
    if not result.stdout.strip():
        return {"Slots": [], "Devices": []}

    data = json.loads(result.stdout)
    # ConvertTo-Json gibt bei genau einem Objekt kein Array zurueck.
    for key in ("Slots", "Devices"):
        value = data.get(key)
        if value is None:
            data[key] = []
        elif not isinstance(value, list):
            data[key] = [value]
    return data


def print_report(data: dict[str, Any]) -> None:
    slots = data["Slots"]
    devices = data["Devices"]

    print(f"Gemeldete System-Steckplaetze: {len(slots)}")
    if slots:
        for slot in slots:
            designation = slot.get("SlotDesignation") or "(ohne Bezeichnung)"
            usage = slot.get("CurrentUsage")
            status = slot.get("Status") or "unbekannt"
            print(f"  - {designation} | Nutzung: {usage if usage is not None else 'unbekannt'} | Status: {status}")
    else:
        print("  Keine Steckplatzinformationen von der Firmware gemeldet.")

    print(f"\nGefundene PCI-Geraete: {len(devices)}")
    for device in devices:
        name = device.get("Name") or "(ohne Namen)"
        status = device.get("Status") or "unbekannt"
        manufacturer = device.get("Manufacturer") or "Hersteller unbekannt"
        device_id = device.get("PNPDeviceID") or "ID unbekannt"
        error_code = device.get("ConfigManagerErrorCode")
        error = f" | Fehlercode: {error_code}" if error_code not in (None, 0) else ""
        print(f"  - {name} | {manufacturer} | {status}{error}")
        print(f"    {device_id}")

    print("\nHinweis: Win32_SystemSlot ist eine Firmware-/Treiberinventur.")
    print("Windows kann damit die tatsaechliche Anzahl physischer PCIe-Slots unvollstaendig melden.")
    print("Fuer eine verlaessliche Gesamtzahl bitte zusaetzlich das Mainboard-Handbuch pruefen.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Zeigt PCI-Geraete und von Windows gemeldete Slots.")
    parser.add_argument("--json", action="store_true", help="Gibt die Rohdaten als JSON aus.")
    args = parser.parse_args()

    try:
        data = run_powershell()
    except (RuntimeError, json.JSONDecodeError) as error:
        print(f"Fehler: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print_report(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
