# Forensische Artefakt-Matrix

| Artifact | Location | Proves | Does not prove | Reliability | Retention | False positives | Collection |
|---|---|---|---|---|---|---|---|
| Aktuelles PCI/PnP-Geraet | CIM `Win32_PnPEntity`, Registry Enum | Geraet ist/war im Windows-PnP-Kontext bekannt | DMA-Nutzung, Cheat-Absicht | Hoch fuer aktuellen Zustand | Aktuell, Registry teils historisch | Capture Card, NVMe, NIC, Thunderbolt, FPGA | Read-only CIM + Registry |
| System-Slot | CIM `Win32_SystemSlot` | Firmware meldet einen Slot | Vollstaendige physische Slot-Anzahl | Niedrig bis mittel | Firmwareabhaengig | OEM-Firmware meldet nur Teilmenge | Read-only CIM |
| SetupAPI-Installation | `C:\Windows\INF\setupapi.dev.log` | Windows hat eine Installation bearbeitet | Dauerhafte Nutzung oder Absicht | Mittel bis hoch | Rotation/Neuinstallation | Treiberupdates, normale Peripherie | Read-only Textparser |
| Treiberdatei | System32\drivers, DriverStore | Datei und Metadaten existieren | Geladene Nutzung ohne Laufzeitbeleg | Mittel | Dateisystemabhaengig | OEM, Debugging, Entwicklung | Hash + `Get-AuthenticodeSignature` |
| Treiberservice | `HKLM\SYSTEM\...\Services` | Service-Konfiguration existiert | Service wurde geladen oder ist boesartig | Mittel | Registry | Software- und Hardwaretools | Read-only Registry |
| Eventlog | `System32\winevt\Logs`, `Get-WinEvent` | Ereignis wurde aufgezeichnet | Nicht aufgezeichnete Aktivitaet | Hoch pro Event | Retention/Manipulation | Provider-Rauschen | XML Event API |
| Prefetch | `C:\Windows\Prefetch` | Programm lief unter Windows Prefetch-Bedingungen | Exakte Absicht oder vollstaendige Ausfuehrungshistorie | Mittel | OS-/Volumeabhaengig | Normale Tools, Cacheverhalten | Read-only Metadaten |
| Security Posture | CIM/Registry/SystemInfo | Schutzoption war konfiguriert | Cheat oder Hardwaremissbrauch | Hoch fuer Konfiguration | Aktueller Zustand | Firmware-/Policy-Unterschiede | Read-only CIM/Registry |
| Zeitkorrelation | Zentrale Timeline | Mehrere Quellen liegen zeitlich nah | Kausalitaet ohne weitere Belege | Abhaengig von Quellen | Abhaengig von Quellen | Clock drift, Updates, Bootvorgaenge | UTC-Normalisierung |

## Bewertungsgrenzen

- `INFO`: Kontext ohne Auffaelligkeit.
- `LOW`: schwache Auffaelligkeit, alternative Erklaerung wahrscheinlich.
- `MEDIUM`: mehrere passende Indikatoren, aber plausible legitime Erklaerung.
- `HIGH`: mehrere unabhaengige Quellen mit engem Zeitbezug.
- `CRITICAL`: sehr starke korrelierte Evidenz, manuelle Beweissicherung erforderlich; kein automatischer Cheat-Beweis.
