# Research-Ergebnisse

## Belastbare Aussagen

| Quelle | Aussage | Grenze |
|---|---|---|
| Windows PnP/CIM (`Win32_PnPEntity`, `Win32_SystemSlot`) | Liefert aktuelle PnP-Geraete und von Firmware gemeldete System-Slots. | Historische Geraete und physische Slot-Anzahl koennen unvollstaendig sein. |
| `C:\Windows\INF\setupapi.dev.log` | Dokumentiert viele Geraeteinstallationen, INF-Auswahl und Installationsfehler. | Rotiert/fehlt moeglicherweise; Textformat ist versions- und sprachabhaengig. |
| Windows Event Log / `Get-WinEvent` | Liefert Provider, Channel, Event-ID, Record-ID, Zeit und XML-Daten. | Retention, Berechtigungen und geloeschte Logs beeinflussen die Aussagekraft. |
| Windows Treibersignatur | Signatur verknuepft Paketintegritaet und Publisher-Kontext; Kernel-Treiber muessen unter normalen Bedingungen signiert sein. | Eine gueltige Signatur beweist keine Legitimitat der Nutzung. |
| Kernel DMA Protection / VBS / HVCI | Beschreibt die konfigurierte Schutzlage des Systems. | Schutzlage ist Security Posture, kein Nachweis fuer Cheating. |
| `wevtutil` | Kann Log-Konfiguration lesen sowie Logs lesen/exportieren. | Der Analyzer darf keine mutierenden Befehle wie `cl` oder `sl` verwenden. |

## Quellen

- Microsoft Learn, Driver Signing: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing
- Microsoft Learn, `wevtutil`: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
- Microsoft Learn, Windows Driver Kit und SetupAPI-Dokumentation: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/
- Microsoft Learn, Kernel DMA Protection: https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection
- Velociraptor Documentation, Artefakt- und Timeline-Konzepte: https://docs.velociraptor.app/

## Methodische Regeln

1. Alle Collector arbeiten read-only und speichern Quelle, Erfassungszeit und Rohdaten soweit sinnvoll.
2. Aktuelle Hardware, historische Installationen, Treiber, Ausfuehrung und Logs werden getrennt erfasst.
3. Ein einzelner unbekannter PCI-Eintrag, ein unsignierter Treiber oder deaktivierter DMA-Schutz erzeugt niemals automatisch einen Cheat-Befund.
4. `CRITICAL` bedeutet starke korrelierte Evidenz und immer manuelle Pruefung, niemals Beweis.
5. Zeitstempel werden auf UTC normalisiert; die Originalzeit bleibt erhalten.
6. Fehlende Quellen werden als Collection Gap dokumentiert und nicht als Beweis interpretiert.
